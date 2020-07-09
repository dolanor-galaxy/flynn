package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"

	controller "github.com/flynn/flynn/controller/client"
	"github.com/flynn/go-docopt"
)

const oauthHostPort = "127.0.0.1:8085"

func init() {
	register("login", runLogin, `
usage: flynn login [--controller-url <controller-url>] [--cluster-name <cluster-name>] [--oob-code] [[<issuer-url> [<client-id>]]

Authenticate. With no arguments or an existing issuer URL, re-authenticates.

Options:
	-c --controller-url  the controller URL for the cluster to add
	-n --cluster-name    the name of the cluster to add (will prompt if not provided)
	--oob-code           do not attempt to use a browser and local HTTP listener for OAuth

Examples:

	$ flynn limit
	web:     cpu=1000  temp_disk=100MB  max_fd=10000  memory=1GB
	worker:  cpu=1000  temp_disk=100MB  max_fd=10000  memory=1GB
`)
}

// LOGIN
// - if matching refresh token, attempt to get audiences and then jump to cluster selection
// - listen on port (8085)
// - if no browser or listen fails or flag, use copy/paste UI (set redirect_uri to urn:ietf:wg:oauth:2.0:oob)
// - build redirect URI
// - print message with URL
// - attempt to spawn browser with redirect URI
// - wait for HTTP request with redirect back
// - if error, print
// - exchange code for refresh token
// - if cluster/name specified, get access token
// - if not, get audiences list
// - present numbered list of clusters
// - after selection ask for cluster name
// - get accesss token and attempt to ping cluster
// - save cluster config and refresh token to file
// - if more clusters, ask again

// REAUTH
// - if only one configured issuer, default, otherwise print options and require CLI flag
// - follow login logic to get refresh token for client, exit

func runLogin(args *docopt.Args, client controller.Client) error {

	return nil
}

var oauthErrFallback = errors.New("oob fallback")

func useOAuthOOB(args *docopt.Args) bool {
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

func listenForOAuthCode() (code string, err error) {
	l, err := net.Listen("tcp", oauthHostPort)
	if err != nil {
		return "", oauthErrFallback
	}

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
		code = r.FormValue("code")
		if code == "" {
			err = fmt.Errorf("missing code in oauth redirect, got %s", r.URL.RawQuery)
		}
	}))

	return code, err
}

// AUTH LOGIC
// - get tokens from cache file
// - if access token expired or expiring soon, renew and save
// - if refresh token expired, print error with reauth message
// - make API request
