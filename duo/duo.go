package duo

import (
	"encoding/json"
	htmlEncode "html"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var fieldsetRegex = regexp.MustCompile("<fieldset data-device-index=\"(.*)\" class=\"hidden\">([\\w\\W]*?)<\\/fieldset>")
var inputRegex = regexp.MustCompile("<input type=\"hidden\" name=\"(.*)\" value=\"(.*)\">")

// An Challenge is a 2FA request from Duo.
type Challenge struct {
	Devices []Device
	Methods []Method

	c            *http.Client
	hiddenInputs url.Values
	host         string
	txid         string
}

// A Device is a device that can be used with a Method.
type Device struct {
	Index        string
	FriendlyName string
}

// A Method is a method that can be used to complete a Challenge.
type Method struct {
	FriendlyName string
	DeviceName   string
	DeviceIndex  string
}

// A ChallengeResponse is returned after a Challenge's Method is completed.
type ChallengeResponse struct {
	StatusCode string `json:"status_code"`
	Result     string `json:"result"`
	ResultURL  string `json:"result_url"`
	Parent     string `json:"parent"`
	Reason     string `json:"reason"`
	Status     string `json:"status"`
}

type challengeResponseWrapper struct {
	Response ChallengeResponse `json:"response"`
	Stat     string            `json:"stat"`
}

// A StatusResponse is returned after a Challenge's Method is started.
type StatusResponse struct {
	StatusCode string `json:"status_code"`
	Status     string `json:"status"`
}

type statusResponseWrapper struct {
	Response StatusResponse `json:"response"`
	Stat     string         `json:"stat"`
}

// A FinalResponse is returned after a Challenge is completed, and it can be used to finish the authentication process.
type FinalResponse struct {
	Parent string `json:"parent"`
	Cookie string `json:"cookie"`
}

type finalResponseWrapper struct {
	Response FinalResponse `json:"response"`
	Stat     string        `json:"stat"`
}

type promptResponse struct {
	TxID string `json:"txid"`
}

type promptResponseWrapper struct {
	Response promptResponse `json:"response"`
	Stat     string         `json:"stat"`
}

func parseAttrs(z *html.Tokenizer) map[string]string {
	attrs := map[string]string{}
	for {
		key, val, more := z.TagAttr()

		attrs[string(key)] = string(val)

		if !more {
			break
		}
	}
	return attrs
}

// BeginChallenge starts handling a Duo authentication request.
func BeginChallenge(c *http.Client, parent string, host string, sigRequest string, postAction string) (*Challenge, error) {
	v := "2.6"

	sigs := strings.Split(sigRequest, ":")
	txSig := sigs[0]

	parentURL, err := url.Parse(parent)
	if err != nil {
		return nil, err
	}

	referer := parentURL.Scheme + "://" + parentURL.Host + "/"

	duoAuthRequestURL := "https://" + host + "/frame/web/v1/auth"
	duoAuthRequestURL += "?" + url.Values{
		"tx":     []string{txSig},
		"parent": []string{parent},
		"v":      []string{v},
	}.Encode()

	duoAuthRequestData := url.Values{}
	duoAuthRequestData.Add("tx", txSig)
	duoAuthRequestData.Add("parent", parent)
	duoAuthRequestData.Add("referer", referer)
	duoAuthRequestData.Add("java_version", "")
	duoAuthRequestData.Add("flash_version", "")
	duoAuthRequestData.Add("screen_resolution_width", "1920")
	duoAuthRequestData.Add("screen_resolution_height", "1080")
	duoAuthRequestData.Add("color_depth", "24")
	duoAuthRequestData.Add("is_cef_browser", "false")
	duoAuthRequestData.Add("is_ipad_os", "false")

	duoPromptReq, err := http.NewRequest("POST", duoAuthRequestURL, strings.NewReader(duoAuthRequestData.Encode()))
	if err != nil {
		return nil, err
	}

	duoPromptReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	duoPromptReq.Header.Add("Referer", duoAuthRequestURL)

	duoPromptResp, err := c.PostForm(duoAuthRequestURL, duoAuthRequestData)
	if err != nil {
		return nil, err
	}

	duoPromptBody, err := ioutil.ReadAll(duoPromptResp.Body)
	if err != nil {
		return nil, err
	}

	err = duoPromptResp.Body.Close()
	if err != nil {
		return nil, err
	}

	methodStringsForDevice := map[string][]string{}

	// get fieldsets
	fieldsets := fieldsetRegex.FindAllStringSubmatch(string(duoPromptBody), -1)
	for _, fieldsetGroups := range fieldsets {
		deviceIndex := fieldsetGroups[1]
		contents := fieldsetGroups[2]

		// get hidden inputs
		inputs := inputRegex.FindAllStringSubmatch(contents, -1)

		methodStringsForDevice[deviceIndex] = []string{}

		for _, inputGroups := range inputs {
			if inputGroups[1] == "factor" {
				methodStringsForDevice[deviceIndex] = append(methodStringsForDevice[deviceIndex], htmlEncode.UnescapeString(inputGroups[2]))
			}
		}
	}

	hiddenInputs := url.Values{}
	inputs := inputRegex.FindAllStringSubmatch(string(duoPromptBody), -1)
	for _, inputGroups := range inputs {
		if inputGroups[1] != "factor" {
			hiddenInputs.Add(inputGroups[1], htmlEncode.UnescapeString(inputGroups[2]))
		}
	}

	// get device list
	devices := []Device{}
	z := html.NewTokenizer(strings.NewReader(string(duoPromptBody)))
	foundSelect := false
	deviceIndex := ""
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken {
			tagName, _ := z.TagName()
			if string(tagName) == "select" {
				attrs := parseAttrs(z)
				if attrs["name"] == "device" {
					foundSelect = true
					continue
				}
			}

			if foundSelect {
				if string(tagName) == "option" {
					attrs := parseAttrs(z)
					deviceIndex = attrs["value"]
				}
			}
		} else if tt == html.EndTagToken {
			if foundSelect {
				tagName, _ := z.TagName()
				if string(tagName) == "select" {
					// done
					break
				}
			}
		} else if tt == html.TextToken {
			if deviceIndex != "" {
				devices = append(devices, Device{
					Index:        deviceIndex,
					FriendlyName: string(z.Text()),
				})
				deviceIndex = ""
			}
		}
	}

	methods := []Method{}
	if len(devices) > 0 {
		for _, device := range devices {
			for _, method := range methodStringsForDevice[device.Index] {
				methods = append(methods, Method{
					FriendlyName: method,
					DeviceName:   device.FriendlyName,
					DeviceIndex:  device.Index,
				})
			}
		}
	}

	return &Challenge{
		Devices: devices,
		Methods: methods,

		c:            c,
		hiddenInputs: hiddenInputs,
		host:         host,
	}, nil
}

// StartMethod starts the authentication process with the given Method.
func (c *Challenge) StartMethod(method *Method) (*StatusResponse, error) {
	sid := c.hiddenInputs.Get("sid")

	promptURL := "https://" + c.host + "/frame/prompt"
	promptResp, err := c.c.PostForm(promptURL, url.Values{
		"sid":              []string{sid},
		"device":           []string{method.DeviceIndex},
		"factor":           []string{method.FriendlyName},
		"out_of_date":      []string{""},
		"days_out_of_date": []string{""},
		"days_to_block":    []string{""},
	})
	if err != nil {
		return nil, err
	}

	promptRespData := promptResponseWrapper{}
	err = json.NewDecoder(promptResp.Body).Decode(&promptRespData)
	if err != nil {
		return nil, err
	}

	err = promptResp.Body.Close()
	if err != nil {
		return nil, err
	}

	if promptRespData.Stat != "OK" {
		return nil, ErrDuoServer
	}

	statusURL := "https://" + c.host + "/frame/status"

	statusResp, err := c.c.PostForm(statusURL, url.Values{
		"sid":  []string{sid},
		"txid": []string{promptRespData.Response.TxID},
	})
	if err != nil {
		return nil, err
	}

	c.txid = promptRespData.Response.TxID

	statusRespData := statusResponseWrapper{}
	err = json.NewDecoder(statusResp.Body).Decode(&statusRespData)
	if err != nil {
		return nil, err
	}

	err = statusResp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &statusRespData.Response, nil
}

// WaitForCompletion waits for the Challenge's authentication process to complete.
func (c *Challenge) WaitForCompletion() (*FinalResponse, *ChallengeResponse, error) {
	statusURL := "https://" + c.host + "/frame/status"

	completionResp, err := c.c.PostForm(statusURL, url.Values{
		"sid":  []string{c.hiddenInputs.Get("sid")},
		"txid": []string{c.txid},
	})
	if err != nil {
		return nil, nil, err
	}

	completionRespData := challengeResponseWrapper{}
	err = json.NewDecoder(completionResp.Body).Decode(&completionRespData)
	if err != nil {
		return nil, nil, err
	}

	err = completionResp.Body.Close()
	if err != nil {
		return nil, nil, err
	}

	if completionRespData.Response.Result == "SUCCESS" {
		// it worked, so do the final request
		finalResp, err := c.c.PostForm("https://"+c.host+completionRespData.Response.ResultURL, url.Values{
			"sid": []string{c.hiddenInputs.Get("sid")},
		})
		if err != nil {
			return nil, nil, err
		}

		finalRespData := finalResponseWrapper{}
		err = json.NewDecoder(finalResp.Body).Decode(&finalRespData)
		if err != nil {
			return nil, nil, err
		}

		err = finalResp.Body.Close()
		if err != nil {
			return nil, nil, err
		}

		return &finalRespData.Response, &completionRespData.Response, nil
	}

	return nil, &completionRespData.Response, nil
}
