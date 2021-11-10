package server

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/log"
	"github.com/pinterest/knox/server/keydb"
)

// HTTPError is the error type with knox err subcode and message for logging purposes
type HTTPError struct {
	Subcode int
	Message string
}

// errF is a convience method to make an httpError.
func errF(c int, m string) *HTTPError {
	return &HTTPError{c, m}
}

// httpErrResp contain the http codes and messages to be returned back to clients.
type httpErrResp struct {
	Code    int
	Message string
}

// HTTPErrMap is a mapping from err subcodes to the http err response that will be returned.
var HTTPErrMap = map[int]*httpErrResp{
	knox.NoKeyIDCode:                   {http.StatusBadRequest, "Missing Key ID"},
	knox.InternalServerErrorCode:       {http.StatusInternalServerError, "Internal Server Error"},
	knox.KeyIdentifierExistsCode:       {http.StatusBadRequest, "Key identifer exists"},
	knox.KeyVersionDoesNotExistCode:    {http.StatusNotFound, "Key version does not exist"},
	knox.KeyIdentifierDoesNotExistCode: {http.StatusNotFound, "Key identifer does not exist"},
	knox.UnauthenticatedCode:           {http.StatusUnauthorized, "User or machine is not authenticated"},
	knox.UnauthorizedCode:              {http.StatusForbidden, "User or machine not authorized"},
	knox.NotYetImplementedCode:         {http.StatusNotImplemented, "Not yet implemented"},
	knox.NotFoundCode:                  {http.StatusNotFound, "Route not found"},
	knox.NoKeyDataCode:                 {http.StatusBadRequest, "Missing Key Data"},
	knox.BadRequestDataCode:            {http.StatusBadRequest, "Bad request format"},
	knox.BadKeyFormatCode:              {http.StatusBadRequest, "Key ID contains unsupported characters"},
	knox.BadPrincipalIdentifier:        {http.StatusBadRequest, "Invalid principal identifier"},
}

func combine(f, g func(http.HandlerFunc) http.HandlerFunc) func(http.HandlerFunc) http.HandlerFunc {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return f(g(h))
	}
}

// GetRouter creates the mux router that serves knox routes.
// All routes are declared in this file. Each handler itself takes in the db and
// auth provider interfaces and returns a handler that the is processed through
// the API Middleware.
func GetRouter(
	cryptor keydb.Cryptor,
	db keydb.DB,
	decorators [](func(http.HandlerFunc) http.HandlerFunc),
	additionalRoutes []Route) (*mux.Router, error) {

	existingRouteIds := map[string]Route{}
	existingRouteMethodAndPaths := map[string]map[string]Route{}
	allRoutes := append(routes[:], additionalRoutes[:]...)

	for _, route := range allRoutes {
		if _, routeExists := existingRouteIds[route.Id]; routeExists {
			return nil, fmt.Errorf(
				"There are ID conflicts for the route with ID: '%v'",
				route.Id,
			)
		}
		childMap, methodExists := existingRouteMethodAndPaths[route.Method]
		if !methodExists {
			childMap := map[string]Route{
				route.Path: route,
			}
			existingRouteMethodAndPaths[route.Method] = childMap
		} else {
			if conflictingRoute, pathExists := childMap[route.Path]; pathExists {
				return nil, fmt.Errorf(
					"There are Method/Path conflicts for the following Route IDs: ('%v' and '%v')",
					conflictingRoute.Id, route.Id,
				)
			}
		}

		existingRouteMethodAndPaths[route.Method][route.Path] = route
		existingRouteIds[route.Id] = route
	}

	r := mux.NewRouter()

	decorator := func(f http.HandlerFunc) http.HandlerFunc { return f }
	for i := range decorators {
		j := len(decorators) - i - 1
		decorator = combine(decorators[j], decorator)
	}

	m := NewKeyManager(cryptor, db)

	r.NotFoundHandler = setupRoute("404", m)(decorator(writeErr(errF(knox.NotFoundCode, ""))))

	for _, route := range allRoutes {
		addRoute(r, route, decorator, m)
	}
	return r, nil
}

func addRoute(
	router *mux.Router,
	route Route,
	routeDecorator func(f http.HandlerFunc) http.HandlerFunc,
	keyManager KeyManager) {
	handler := setupRoute(route.Id, keyManager)(parseParams(route.Parameters)(routeDecorator(route.ServeHTTP)))
	router.Handle(route.Path, handler).Methods(route.Method)
}

// Parameter is an interface through which route-specific Knox API Parameters
// can be specified
type Parameter interface {
	Name() string
	Get(r *http.Request) (string, bool)
}

// UrlParameter is an implementation of the Parameter interface that extracts
// parameter values from the URL as referenced in section 3.3 of RFC2396.
type UrlParameter string

// Get returns the value of the URL parameter
func (p UrlParameter) Get(r *http.Request) (string, bool) {
	s, ok := mux.Vars(r)[string(p)]
	return s, ok
}

// Name defines the URL-embedded key that this parameter maps to
func (p UrlParameter) Name() string {
	return string(p)
}

// RawQueryParameter is an implementation of the Parameter interface that
// extracts the complete query string from the request URL
// as referenced in section 3.4 of RFC2396.
type RawQueryParameter string

// Get returns the value of the entire query string
func (p RawQueryParameter) Get(r *http.Request) (string, bool) {
	return r.URL.RawQuery, true
}

// Name represents the key-name that will be set for the raw query string
// in the `parameters` map of the route handler function.
func (p RawQueryParameter) Name() string {
	return string(p)
}

// QueryParameter is an implementation of the Parameter interface that extracts
// specific parameter values from the query string of the request URL
// as referenced in section 3.4 of RFC2396.
type QueryParameter string

// Get returns the value of the query string parameter
func (p QueryParameter) Get(r *http.Request) (string, bool) {
	val, ok := r.URL.Query()[string(p)]
	if !ok {
		return "", false
	}
	return val[0], true
}

// Name defines the URL-embedded key that this parameter maps to
func (p QueryParameter) Name() string {
	return string(p)
}

// PostParameter is an implementation of the Parameter interface that
// extracts values embedded in the web form transmitted in the
// request body
type PostParameter string

// Get returns the value of the appropriate parameter from the request body
func (p PostParameter) Get(r *http.Request) (string, bool) {
	err := r.ParseForm()
	if err != nil {
		return "", false
	}
	k, ok := r.PostForm[string(p)]
	if !ok {
		return "", ok
	}
	return k[0], ok
}

// Name represents the key corresponding to this parameter in the request form
func (p PostParameter) Name() string {
	return string(p)
}

// Route is a struct that defines a path and method-specific
// HTTP route on the Knox server
type Route struct {
	// Handler represents the handler function that is responsible for serving
	// this route
	Handler func(db KeyManager, principal knox.Principal, parameters map[string]string) (interface{}, *HTTPError)

	// Id represents A unique string identifier that represents this specific
	// route
	Id string

	// Path represents the relative HTTP path (or prefix) that must be specified
	//  in order to invoke this route
	Path string

	// Method represents the HTTP method that must be specified in order to
	// invoke this route
	Method string

	// Parameters is an array that represents the route-specific parameters
	// that will be passed to the handler function
	Parameters []Parameter
}

func writeErr(apiErr *HTTPError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := new(knox.Response)
		hostname, err := os.Hostname()
		if err != nil {
			panic("Hostname is required:" + err.Error())
		}
		resp.Host = hostname
		resp.Timestamp = time.Now().UnixNano()
		resp.Status = "error"
		resp.Code = apiErr.Subcode
		resp.Message = apiErr.Message
		code := HTTPErrMap[apiErr.Subcode].Code
		w.WriteHeader(code)
		setAPIError(r, apiErr)

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			// It is unclear what to do here since the server failed to write the response.
			log.Println(err.Error())
		}
	}
}

func writeData(w http.ResponseWriter, data interface{}) {
	r := new(knox.Response)
	r.Message = ""
	r.Code = knox.OKCode
	r.Status = "ok"
	hostname, err := os.Hostname()
	if err != nil {
		panic("Hostname is required:" + err.Error())
	}
	r.Host = hostname
	r.Timestamp = time.Now().UnixNano()
	r.Data = data
	if err := json.NewEncoder(w).Encode(r); err != nil {
		// It is unclear what to do here since the server failed to write the response.
		log.Println(err.Error())
	}
}

// ServeHTTP runs API middleware and calls the underlying handler function.
func (r Route) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	db := getDB(req)
	principal := GetPrincipal(req)
	ps := GetParams(req)
	data, err := r.Handler(db, principal, ps)

	if err != nil {
		writeErr(err)(w, req)
	} else {
		writeData(w, data)
	}
}

// Users besides creator who have default access to all keys.
// This is by default empty and should be expanded by the main function.
var defaultAccess []knox.Access

// AddDefaultAccess adds an access to every created key.
func AddDefaultAccess(a *knox.Access) {
	defaultAccess = append(defaultAccess, *a)
}

// Extra validators to apply on principals submitted to Knox.
var extraPrincipalValidators []knox.PrincipalValidator

// AddPrincipalValidator applies additional, custom validation on principals
// submitted to Knox for adding into ACLs. Can be used to set custom business
// logic for e.g. what kind of machine or service prefixes are acceptable.
func AddPrincipalValidator(validator knox.PrincipalValidator) {
	extraPrincipalValidators = append(extraPrincipalValidators, validator)
}

// newKeyVersion creates a new KeyVersion with correctly set defaults.
func newKeyVersion(d []byte, s knox.VersionStatus) knox.KeyVersion {
	version := knox.KeyVersion{}
	version.Data = d
	version.Status = s
	version.CreationTime = time.Now().UnixNano()
	// This is only 63 bits of randomness, but it appears to be the fastest way.
	version.ID = uint64(rand.Int63())
	return version
}

// NewKey creates a new Key with correctly set defaults.
func newKey(id string, acl knox.ACL, d []byte, u knox.Principal) knox.Key {
	key := knox.Key{}
	key.ID = id

	creatorAccess := knox.Access{ID: u.GetID(), AccessType: knox.Admin, Type: knox.User}
	key.ACL = acl.Add(creatorAccess)
	for _, a := range defaultAccess {
		key.ACL = key.ACL.Add(a)
	}

	key.VersionList = []knox.KeyVersion{newKeyVersion(d, knox.Primary)}
	key.VersionHash = key.VersionList.Hash()
	return key
}
