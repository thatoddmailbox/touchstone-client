# touchstone-client
This library is a Go client for the [MIT Touchstone](https://idp.mit.edu/) authentication provider. It supports logging in via a Kerberos username and password and completing the Duo two-factor authentication step. (though only Duo Push really works) It's useful for automating access to Touchstone-protected resources that don't have an API.

You can see an example usage of the library in the "tstest" folder, which will prompt you for username, password, and Duo, and then use that to get your current registration information from WebSIS.

For more information, see the documentation of the [touchstone](https://godoc.org/github.com/thatoddmailbox/touchstone-client/touchstone) and [duo](https://godoc.org/github.com/thatoddmailbox/touchstone-client/duo) packages.