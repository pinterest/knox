package server

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/context"
	"github.com/pinterest/knox"
	"github.com/pinterest/knox/log"
	"github.com/pinterest/knox/server/auth"
)

type contextKey int

const (
	apiErrorContext contextKey = iota
	principalContext
	paramsContext
	dbContext
	idContext
)

// GetAPIError gets the HTTP error that will be returned from the server.
func GetAPIError(r *http.Request) *HTTPError {
	if rv := context.Get(r, apiErrorContext); rv != nil {
		return rv.(*HTTPError)
	}
	return nil
}

func setAPIError(r *http.Request, val *HTTPError) {
	context.Set(r, apiErrorContext, val)
}

// GetPrincipal gets the principal authenticated through the authentication decorator
func GetPrincipal(r *http.Request) knox.Principal {
	ctx := getOrInitializePrincipalContext(r)
	return ctx.GetCurrentPrincipal()
}

// SetPrincipal sets the principal authenticated through the authentication decorator.
// For security reasons, this method will only set the Principal in the context for
// the first invocation. Subsequent invocations WILL cause a panic.
func SetPrincipal(r *http.Request, val knox.Principal) {
	ctx := getOrInitializePrincipalContext(r)
	ctx.SetCurrentPrincipal(val)
}

// GetParams gets the parameters for the request through the parameters context.
func GetParams(r *http.Request) map[string]string {
	if rv := context.Get(r, paramsContext); rv != nil {
		return rv.(map[string]string)
	}
	return nil
}

func setParams(r *http.Request, val map[string]string) {
	context.Set(r, paramsContext, val)
}

func getDB(r *http.Request) KeyManager {
	if rv := context.Get(r, dbContext); rv != nil {
		return rv.(KeyManager)
	}
	return nil
}

func setDB(r *http.Request, val KeyManager) {
	context.Set(r, dbContext, val)
}

func getOrInitializePrincipalContext(r *http.Request) auth.PrincipalContext {
	if ctx := context.Get(r, principalContext); ctx != nil {
		return ctx.(auth.PrincipalContext)
	}
	ctx := auth.NewPrincipalContext(r)
	context.Set(r, principalContext, ctx)
	return ctx
}

// GetRouteID gets the short form function name for the route being called. Used for logging/metrics.
func GetRouteID(r *http.Request) string {
	if rv := context.Get(r, idContext); rv != nil {
		return rv.(string)
	}
	return ""
}

func setRouteID(r *http.Request, val string) {
	context.Set(r, idContext, val)
}

// AddHeader adds a HTTP header to the response
func AddHeader(k, v string) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(k, v)
			f(w, r)
		}
	}
}

// Logger logs the request and response information in json format to the logger given.
func Logger(logger *log.Logger) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f(w, r)
			p := GetPrincipal(r)
			params := GetParams(r)
			apiError := GetAPIError(r)
			agent := r.Header.Get("User-Agent")
			if agent == "" {
				agent = "unknown"
			}
			e := &reqLog{
				Type:       "access",
				StatusCode: 200,
				Request:    buildRequest(r, p, params),
				UserAgent:  agent,
			}
			if apiError != nil {
				e.Code = apiError.Subcode
				e.StatusCode = HTTPErrMap[apiError.Subcode].Code
				e.Msg = apiError.Message
			}
			logger.OutputJSON(e)
		}
	}
}

type reqLog struct {
	Type       string  `json:"type"`
	Code       int     `json:"code"`
	StatusCode int     `json:"status_code"`
	Request    request `json:"request"`
	Msg        string  `json:"msg"`
	UserAgent  string  `json:"userAgent"`
}

type request struct {
	Method             string            `json:"method"`
	Path               string            `json:"path"`
	Parameters         map[string]string `json:"parameters"`
	ParsedQuery        map[string]string `json:"parsed_query_string"`
	Principal          string            `json:"principal"`
	FallbackPrincipals []string          `json:"fallback_principals"`
	AuthType           string            `json:"auth_type"`
	RequestURI         string            `json:"request_uri"`
	RemoteAddr         string            `json:"remote_addr"`
	TLSServer          string            `json:"tls_server"`
	TLSCipher          uint16            `json:"tls_cipher"`
	TLSVersion         uint16            `json:"tls_version"`
	TLSResumed         bool              `json:"tls_resumed"`
	TLSUnique          []byte            `json:"tls_session_id"`
}

func scrub(params map[string]string) map[string]string {
	// Don't log any secret information (cause its secret)
	if _, ok := params["data"]; ok {
		params["data"] = "<DATA>"
	}
	return params
}

func buildRequest(req *http.Request, p knox.Principal, params map[string]string) request {
	params = scrub(params)

	r := request{
		Method:     req.Method,
		Parameters: params,
		RemoteAddr: req.RemoteAddr,
	}
	if qs, ok := params["queryString"]; ok {
		keyMap, _ := url.ParseQuery(qs)
		m := map[string]string{}
		for k := range keyMap {
			for _, v := range keyMap[k] {
				m[k] = v
			}
		}
		r.ParsedQuery = m
	}
	if req.URL != nil {
		r.Path = req.URL.Path
	}
	if p != nil {
		r.Principal = p.GetID()
		r.AuthType = p.Type()
		if mux, ok := p.(knox.PrincipalMux); ok {
			r.FallbackPrincipals = mux.GetIDs()
		}
	} else {
		r.Principal = ""
		r.AuthType = ""
	}
	if req.TLS != nil {
		r.TLSServer = req.TLS.ServerName
		r.TLSCipher = req.TLS.CipherSuite
		r.TLSVersion = req.TLS.Version
		r.TLSResumed = req.TLS.DidResume
		r.TLSUnique = req.TLS.TLSUnique
	}
	return r
}

// ProviderMatcher is a function that determines whether or not the specified
// authentication provider is suitable for the specified HTTP request. It is
// expected to return a boolean value detailing whether or not the specified
// provider is a match and is also expected to return any applicable
// authentication payload that would then be passed to the provider.
type ProviderMatcher func(provider auth.Provider, request *http.Request) (providerSupportsRequest bool, authenticationPayload string)

// Authentication sets the principal or returns an error if the principal cannot be authenticated.
func Authentication(providers []auth.Provider, matcher ProviderMatcher) func(http.HandlerFunc) http.HandlerFunc {
	if matcher == nil {
		matcher = providerMatch
	}

	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var defaultPrincipal knox.Principal
			allPrincipals := map[string]knox.Principal{}
			errReturned := fmt.Errorf("No matching authentication providers found")

			for _, p := range providers {
				if match, payload := matcher(p, r); match {
					principal, errAuthenticate := p.Authenticate(payload, r)
					if errAuthenticate != nil {
						errReturned = errAuthenticate
						continue
					}
					if defaultPrincipal == nil {
						// First match is considered the default principal to use.
						defaultPrincipal = principal
					}

					// We record the name of the provider to be used in logging, so we can record
					// information about which provider authenticated which principal later on.
					allPrincipals[p.Name()] = principal
				}
			}
			if defaultPrincipal == nil {
				WriteErr(errF(knox.UnauthenticatedCode, errReturned.Error()))(w, r)
				return
			}

			SetPrincipal(r, knox.NewPrincipalMux(defaultPrincipal, allPrincipals))
			f(w, r)
			return
		}
	}
}

func providerMatch(provider auth.Provider, request *http.Request) (providerSupportsRequest bool, payload string) {
	authorizationHeaderValue := request.Header.Get("Authorization")

	if len(authorizationHeaderValue) > 2 && authorizationHeaderValue[0] == provider.Version() && authorizationHeaderValue[1] == provider.Type() {
		return true, authorizationHeaderValue[2:]
	}
	return false, ""
}

func parseParams(parameters []Parameter) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var ps = make(map[string]string)
			for _, p := range parameters {
				if s, ok := p.Get(r); ok {
					ps[p.Name()] = s
				}
			}
			setParams(r, ps)
			f(w, r)
		}
	}
}

func setupRoute(id string, m KeyManager) func(http.HandlerFunc) http.HandlerFunc {
	return func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			setDB(r, m)
			setRouteID(r, id)
			f(w, r)
		}
	}
}
