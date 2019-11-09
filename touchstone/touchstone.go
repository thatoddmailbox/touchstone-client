package touchstone

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"github.com/thatoddmailbox/touchstone-client/duo"
	"golang.org/x/net/html"
)

// base touchstone url
const baseURLString = "https://idp.mit.edu/"

// we need somewhere to start the process
const authStartURL = "https://student.mit.edu/"

// regex to parse duo info
var duoInitRegex = regexp.MustCompile("Duo\\.init\\(\\{\\n\\s+'host': \"(.*)\",\\n\\s+'sig_request': \"(.*)\",\\n\\s+'post_action': \"(.*)\"\\n")

// A Client handles authentication to Touchstone, and can then be used to authenticate to SSO-enabled services.
type Client struct {
	HTTPClient   *http.Client
	sigRequest   string
	conversation string
}

// NewClient creates a new Touchstone client.
func NewClient() *Client {
	cookieJar, _ := cookiejar.New(nil)
	return NewClientWithHTTPClient(&http.Client{
		Jar: cookieJar,
	})
}

// NewClientWithHTTPClient creates a new Touchstone client, using the provided *http.Client.
func NewClientWithHTTPClient(httpClient *http.Client) *Client {
	return &Client{
		HTTPClient: httpClient,
	}
}

// BeginUsernamePasswordAuth starts the Touchstone authentication process with a Kerberos username and password.
func (c *Client) BeginUsernamePasswordAuth(username string, password string) (*duo.Challenge, error) {
	redirectResp, err := c.HTTPClient.Get(authStartURL)
	if err != nil {
		return nil, err
	}

	baseURL, err := url.Parse(baseURLString)
	if err != nil {
		return nil, err
	}

	if redirectResp.Request.URL.Host != baseURL.Host {
		return nil, fmt.Errorf("touchstone: auth start page redirected to unknown host '%s', expected '%s'", redirectResp.Request.URL.Host, baseURL.Host)
	}

	loginDoc, err := html.Parse(redirectResp.Body)
	if err != nil {
		return nil, err
	}

	// get the login form
	// TODO: make this code suck less
	loginBody := loginDoc.FirstChild.NextSibling.FirstChild.NextSibling.NextSibling
	loginBox := loginBody.FirstChild.NextSibling.NextSibling.NextSibling
	certLoginForm := loginBox.FirstChild.NextSibling.NextSibling.NextSibling
	usernamePasswordLoginForm := certLoginForm.NextSibling.NextSibling

	inputs := map[string]string{}

	// get all inputs
	var f func(*html.Node)
	f = func(n *html.Node) {
		// check for different form
		if n.Type == html.ElementNode && n.Data == "form" {
			foundID := false
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == "loginform" {
					foundID = true
					break
				}
			}

			if !foundID {
				// we escaped, stop
				return
			}
		}

		// get input
		if n.Type == html.ElementNode && n.Data == "input" {
			name := ""
			value := ""
			inputType := ""
			for _, attr := range n.Attr {
				if attr.Key == "name" {
					name = attr.Val
				}
				if attr.Key == "value" {
					value = attr.Val
				}
				if attr.Key == "type" {
					inputType = attr.Val
				}
			}

			if inputType != "submit" {
				inputs[name] = value
			}
		}

		// continue
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(usernamePasswordLoginForm)

	formAction := ""
	for _, attr := range usernamePasswordLoginForm.Attr {
		if attr.Key == "action" {
			formAction = attr.Val
		}
	}

	err = redirectResp.Body.Close()
	if err != nil {
		return nil, err
	}

	// ok, now make the request
	formData := url.Values{}
	for key, val := range inputs {
		formData.Add(key, val)
	}
	formData.Set("j_username", username)
	formData.Set("j_password", password)
	loginResp, err := c.HTTPClient.PostForm(formAction, formData)
	if err != nil {
		return nil, err
	}

	duoBody, err := ioutil.ReadAll(loginResp.Body)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(string(duoBody), "Duo second-factor authentication is required.") {
		// didn't work, oof
		return nil, ErrBadCreds
	}

	captureGroups := duoInitRegex.FindAllStringSubmatch(string(duoBody), -1)[0]

	host := captureGroups[1]
	sigRequest := captureGroups[2]
	postAction := captureGroups[3]

	err = loginResp.Body.Close()
	if err != nil {
		return nil, err
	}

	c.conversation = formData.Get("conversation")
	c.sigRequest = sigRequest

	return duo.BeginChallenge(c.HTTPClient, loginResp.Request.URL.String(), host, sigRequest, postAction)
}

// CompleteAuthWithDuo uses the given duo.FinalResponse to finish the Touchstone authnetication process.
func (c *Client) CompleteAuthWithDuo(final *duo.FinalResponse) error {
	if !strings.HasPrefix(final.Parent, baseURLString) {
		return ErrBadParent
	}

	sigs := strings.Split(c.sigRequest, ":")
	appSig := sigs[1]

	redirectResp, err := c.HTTPClient.PostForm(final.Parent, url.Values{
		"conversation": []string{c.conversation},
		"sig_response": []string{final.Cookie + ":" + appSig},
	})
	if err != nil {
		return err
	}

	if redirectResp.StatusCode != http.StatusOK {
		return ErrServer
	}

	return nil
}

// AuthenticateToResource uses the Client's Touchstone session to authenticate to the given resource.
func (c *Client) AuthenticateToResource(resourceURL string) (*http.Response, error) {
	tsHandleResp, err := c.HTTPClient.Get(resourceURL)
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(tsHandleResp.Request.URL.String(), baseURLString) {
		// no need to authenticate
		return tsHandleResp, nil
	}

	tsHandleDoc, err := html.Parse(tsHandleResp.Body)
	if err != nil {
		return nil, err
	}

	action := ""
	method := ""
	formData := url.Values{}

	var f func(*html.Node)
	f = func(n *html.Node) {
		// check for different form
		if n.Type == html.ElementNode {
			if n.Data == "form" {
				for _, attr := range n.Attr {
					if attr.Key == "action" {
						action = attr.Val
					} else if attr.Key == "method" {
						method = attr.Val
					}
				}
			} else if n.Data == "input" {
				name := ""
				for _, attr := range n.Attr {
					if attr.Key == "name" {
						name = attr.Val
					} else if attr.Key == "value" {
						formData.Add(name, attr.Val)
					}
				}
			}
		}

		// continue
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(tsHandleDoc)

	if strings.ToLower(method) != "post" {
		return nil, ErrUnknownResponse
	}

	err = tsHandleResp.Body.Close()
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.PostForm(action, formData)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
