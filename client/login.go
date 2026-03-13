package client

import (
	"encoding/json"
	"fmt"
	"io"
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

	runLoginAugmented := func(cmd *Command, args []string) *ErrorStatus {
		return runLogin(cmd, oauthClientID, tokenFileLocation, oauthTokenEndpoint, args)
	}

	if tokenFileLocation == "" {
		tokenFileLocation = DefaultTokenFileLocation
	}
	if !filepath.IsAbs(tokenFileLocation) {
		currentUser, err := user.Current()
		if err != nil {
			fatalf("error getting OS user: %v", err)
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
	args []string) *ErrorStatus {
	var username string
	u, err := user.Current()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error getting OS user: %w", err), false}
	}
	switch len(args) {
	case 0:
		username = u.Username
	case 1:
		username = args[0]
	default:
		return &ErrorStatus{fmt.Errorf("invalid arguments; see 'knox login -h'"), false}
	}

	fmt.Println("Please enter your password:")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return &ErrorStatus{fmt.Errorf("problem getting password: %w", err), false}
	}

	resp, err := http.PostForm(oauthTokenEndpoint,
		url.Values{
			"grant_type": {"password"},
			"client_id":  {oauthClientID},
			"username":   {username},
			"password":   {string(password)},
		})
	if err != nil {
		// this is not Knox server error, thus assigning serverError as false
		return &ErrorStatus{fmt.Errorf("error connecting to auth: %w", err), false}
	}
	var authResp authTokenResp
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("failed to read data: %w", err), false}
	}
	err = json.Unmarshal(data, &authResp)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("unexpected response from auth: %w, data: %s", err, string(data)), false}
	}
	if authResp.Error != "" {
		return &ErrorStatus{fmt.Errorf("failed to authenticate: %q", authResp.Error), false}
	}

	err = os.WriteFile(tokenFileLocation, data, 0600)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("failed to write auth data to file: %w", err), false}
	}

	return nil
}
