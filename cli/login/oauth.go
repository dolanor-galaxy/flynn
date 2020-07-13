package login

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"

	controller "github.com/flynn/flynn/controller/client"
	"github.com/flynn/flynn/pkg/random"
	"github.com/flynn/go-docopt"
	"golang.org/x/oauth2"
)

const (
	oauthHostPort      = "127.0.0.1:8085"
	oobRedirectURI     = "urn:ietf:wg:oauth:2.0:oob"
	issuerMetadataPath = "/.well-known/oauth-authorization-server"
)

// REAUTH
// - if only one configured issuer, default, otherwise print options and require CLI flag
// - follow login logic to get refresh token for client, exit

func Run(args *docopt.Args, client controller.Client) error {
	// - if matching refresh token, attempt to get audiences and then jump to cluster selection

	oob := useOOB(args)
	metadataURL, clientID, err := buildMetadataURL(args.String["<issuer>"])
	if err != nil {
		return err
	}
	if clientID == "" {
		return fmt.Errorf("issuer URL is missing client_id parameter")
	}
	metadata, err := getMetadata(metadataURL)
	if err != nil {
		return err
	}

	config := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:   metadata.AuthorizationEndpoint,
			TokenURL:  metadata.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	var code *codeInfo
	if oob {
		code, err = loginOOB(config)
	} else {
		code, err = loginAuto(config)
	}
	if err != nil {
		return err
	}

	// - exchange code for refresh token
	// - if cluster/name specified, get access token
	// - if not, get audiences list
	// - present numbered list of clusters
	// - after selection ask for cluster name
	// - get accesss token and attempt to ping cluster
	// - save cluster config and refresh token to file
	// - if more clusters, ask again

	return nil
}

func loginOOB(config *oauth2.Config) (*codeInfo, error) {
	config.RedirectURL = oobRedirectURI
	info := buildAuthCodeURL(config)
	fmt.Printf("To login, open the URL below and then paste the resulting code here:\n  %s\nCode: ", info.URL)

	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		info.Code = strings.TrimSpace(s.Text())
	} else {
		return nil, fmt.Errorf("error reading code: %s", s.Err())
	}

	fmt.Printf("\n\n")

	return info, nil
}

func loginAuto(config *oauth2.Config) (*codeInfo, error) {
	config.RedirectURL = "http://" + oauthHostPort + "/"
	info := buildAuthCodeURL(config)

	waitForCode, err := listenForCode(info.State)
	if err != nil {
		fmt.Printf("Error starting automatic code listener: %s\nFalling back to out-of-band code.\n\n")
		return loginOOB(config)
	}

	doneCh := make(chan error)
	go func() {
		var err error
		info.Code, err = waitForCode()
		doneCh <- err
	}()

	if err := openURL(info.URL); err != nil {
		fmt.Printf("Unable to open browser, open this URL or re-run this command with --oob-fallback\n  %s\n\n", info.URL)
	} else {
		fmt.Printf("Your browser has been opened to this URL, waiting for authentication to complete...\n  %s\n\n", info.URL)
	}

	return info, <-doneCh
}

func buildAuthCodeURL(config *oauth2.Config) *codeInfo {
	res := &codeInfo{
		Nonce:    random.Base64(32),
		Verifier: random.Base64(32),
	}
	if config.RedirectURL != oobRedirectURI {
		res.State = random.Base64(32)
	}
	challBytes := sha256.Sum256([]byte(res.Verifier))
	res.URL = config.AuthCodeURL(res.State,
		oauth2.SetAuthURLParam("nonce", res.Nonce),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", strings.TrimRight(base64.URLEncoding.EncodeToString(challBytes[:]), "=")),
	)
	return res
}

func exchangeAuthCode(ctx context.Context, config *oauth2.Config, info *codeInfo) (*oauth2.Token, error) {
	t, err := config.Exchange(ctx, info.Code, oauth2.SetAuthURLParam("code_verifier", info.Verifier))
	if err != nil {
		return nil, err
	}
	nonce, ok := t.Extra("nonce").(string)
	if !ok || nonce != info.Nonce {
		return nil, fmt.Errorf("oauth2 auth response has invalid nonce, expected %q, got %q", info.Nonce, nonce)
	}

	return t, nil
}

type codeInfo struct {
	URL      string
	Verifier string
	State    string
	Nonce    string
	Code     string
}

type issuerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	AudiencesEndpoint     string `json:"audiences_endpoint"`
}

func getMetadata(u string) (*issuerMetadata, error) {
	res, err := http.Get(u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, &url.Error{
			Op:  "GET",
			URL: u,
			Err: fmt.Errorf("unexpected status %d", res.StatusCode),
		}
	}

	data := &issuerMetadata{}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(data); err != nil {
		return nil, &url.Error{
			Op:  "GET",
			URL: u,
			Err: fmt.Errorf("error parsing JSON: %s", err),
		}
	}
	return data, nil
}

func buildMetadataURL(issuer string) (metadataURL, clientID string, err error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", "", fmt.Errorf("invalid issuer URL: %s", err)
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("invalid issuer URL: scheme must be https")
	}

	if u.Path == "" || u.Path == "/" {
		u.Path = issuerMetadataPath
	} else {
		u.Path = path.Join(issuerMetadataPath, u.Path)
	}

	clientID = u.Query().Get("client_id")
	u.RawQuery = ""

	return u.String(), clientID, nil
}

func openURL(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = oauthErrFallback
	}
	return err
}

var oauthErrFallback = errors.New("oob fallback")

func useOOB(args *docopt.Args) bool {
	if args.Bool["--oob-code"] {
		return true
	}
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return true
		}
	}
	return false
}

func listenForCode(state string) (func() (string, error), error) {
	l, err := net.Listen("tcp", oauthHostPort)
	if err != nil {
		return nil, err
	}

	return func() (code string, err error) {
		http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<p>Flynn authentication redirect received, close this page and return to the CLI.</p>"))
			l.Close()
			if errCode := r.FormValue("error"); errCode != "" {
				msg := "error from oauth server: " + errCode

				if errDesc := r.FormValue("error_description"); errDesc != "" {
					msg += ": " + errDesc
				}
				if errURI := r.FormValue("error_uri"); errURI != "" {
					msg += " - " + errURI
				}
				err = errors.New(msg)
				return
			}
			if resState := r.FormValue("state"); state != resState {
				err = fmt.Errorf("invalid state in oauth code redirect, wanted %q, got %q", state, resState)
			}
			code = r.FormValue("code")
			if code == "" {
				err = fmt.Errorf("missing code in oauth redirect, got %q", r.URL.RawQuery)
			}
		}))

		return code, err
	}, nil
}

// AUTH LOGIC
// - get tokens from cache file
// - if access token expired or expiring soon, renew and save
// - if refresh token expired, print error with reauth message
// - make API request
