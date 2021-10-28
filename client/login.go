package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"

	"golang.org/x/crypto/ssh/terminal"
)

const DefaultUsageLine = "login [username]"
const DefaultShortDescription = "login as user and save authentication data"
const DefaultLongDescriptionFormat = `
Will authenticate user via OAuth2 password grant flow if available. Requires user to enter username and password. The authentication data is saved in "%v".

The optional username argument can specify the user that to log in as otherwise it uses the current os user.

For more about knox, see https://github.com/pinterest/knox.

See also: knox help auth
	`
const DefaultTokenFileLocation = ".knox_user_auth"

func NewLoginCommand(
	oauthTokenEndpoint string,
	oauthClientID string,
	tokenFileLocation string,
	usageLine string,
	shortDescription string,
	longDescription string) *Command {

	runLoginAugmented := func(cmd *Command, args []string) {
		runLogin(cmd, oauthClientID, tokenFileLocation, oauthTokenEndpoint, args)
	}

	if tokenFileLocation == "" {
		tokenFileLocation = DefaultTokenFileLocation
	}
	if !filepath.IsAbs(tokenFileLocation) {
		currentUser, err := user.Current()
		if err != nil {
			fatalf("Error getting OS user:" + err.Error())
		}

		tokenFileLocation = path.Join(currentUser.HomeDir, tokenFileLocation)
	}

	if usageLine == "" {
		usageLine = DefaultUsageLine
	}
	if shortDescription == "" {
		shortDescription = DefaultShortDescription
	}
	if longDescription == "" {
		longDescription = fmt.Sprintf(DefaultLongDescriptionFormat, tokenFileLocation)
	}

	return &Command{
		UsageLine: DefaultUsageLine,
		Short:     DefaultShortDescription,
		Long:      longDescription,
		Run:       runLoginAugmented,
	}
}

type authTokenResp struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

func runLogin(
	cmd *Command,
	oauthClientID string,
	tokenFileLocation string,
	oauthTokenEndpoint string,
	args []string) ([]byte, error) {
	var username string
	u, err := user.Current()
	if err != nil {
		fatalf("Error getting OS user:" + err.Error())
	}
	switch len(args) {
	case 0:
		username = u.Username
	case 1:
		username = args[0]
	default:
		fatalf("Invalid arguments. See 'knox login -h'")
	}

	fmt.Println("Please enter your password:")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fatalf("Problem getting password:" + err.Error())
	}

	resp, err := http.PostForm(oauthTokenEndpoint,
		url.Values{
			"grant_type": {"password"},
			"client_id":  {oauthClientID},
			"username":   {username},
			"password":   {string(password)},
		})
	if err != nil {
		fatalf("Error connecting to auth:" + err.Error())
	}
	var authResp authTokenResp
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fatalf("Failed to read data" + err.Error())
	}
	err = json.Unmarshal(data, &authResp)
	if err != nil {
		fatalf("Unexpected response from auth" + err.Error() + "data: " + string(data))
	}
	if authResp.Error != "" {
		fatalf("Fail to authenticate: %q", authResp.Error)
	}

	err = ioutil.WriteFile(tokenFileLocation, data, 0600)
	if err != nil {
		fatalf("Failed to write auth data to file" + err.Error())
	}

	return data, err
}
