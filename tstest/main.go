package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/AlecAivazis/survey"
	"github.com/thatoddmailbox/touchstone-client/duo"
	"github.com/thatoddmailbox/touchstone-client/touchstone"
)

func main() {
	log.Println("tstest")

	username := ""
	survey.AskOne(&survey.Input{
		Message: "Enter username:",
	}, &username)
	password := ""
	survey.AskOne(&survey.Password{
		Message: "Enter password:",
	}, &password)

	c := touchstone.NewClient()
	challenge, err := c.BeginUsernamePasswordAuth(username, password)
	if err != nil {
		panic(err)
	}

	methodStrings := []string{}
	for _, method := range challenge.Methods {
		methodStrings = append(methodStrings, method.FriendlyName+" to "+method.DeviceName)
	}

	methodString := ""
	prompt := &survey.Select{
		Message: "Choose a 2FA method:",
		Options: methodStrings,
	}
	survey.AskOne(prompt, &methodString)

	var method *duo.Method
	for i, checkMethodString := range methodStrings {
		if checkMethodString == methodString {
			method = &challenge.Methods[i]
		}
	}

	if method == nil {
		log.Fatal("You must choose a method to continue.")
	}

	status, err := challenge.StartMethod(method)
	if err != nil {
		panic(err)
	}

	log.Println(status.Status)

	final, response, err := challenge.WaitForCompletion()
	if err != nil {
		panic(err)
	}

	log.Println(response.Status)

	if final == nil {
		// the status from above has the details
		os.Exit(1)
	}

	err = c.CompleteAuthWithDuo(final)
	if err != nil {
		panic(err)
	}

	resourceResp, err := c.AuthenticateToResource("https://student.mit.edu/cgi-bin/shrwssor.sh")
	if err != nil {
		panic(err)
	}

	resourceBody, err := ioutil.ReadAll(resourceResp.Body)
	if err != nil {
		panic(err)
	}

	log.Println(string(resourceBody))
}
