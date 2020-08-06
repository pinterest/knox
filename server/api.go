package server

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/log"
	"github.com/pinterest/knox/server/keydb"
)

// httpError is the error type with knox err subcode and message for logging purposes
type httpError struct {
	Subcode int
	Message string
}

// errF is a convience method to make an httpError.
func errF(c int, m string) *httpError {
	return &httpError{c, m}
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
func GetRouter(cryptor keydb.Cryptor, db keydb.DB, decorators [](func(http.HandlerFunc) http.HandlerFunc)) *mux.Router {

	r := mux.NewRouter()

	decorator := func(f http.HandlerFunc) http.HandlerFunc { return f }
	for i := range decorators {
		j := len(decorators) - i - 1
		decorator = combine(decorators[j], decorator)
	}

	m := NewKeyManager(cryptor, db)

	r.NotFoundHandler = setupRoute("404", m)(decorator(writeErr(errF(knox.NotFoundCode, ""))))
	for _, route := range routes {
		handler := setupRoute(route.id, m)(parseParams(route.parameters)(decorator(route.ServeHTTP)))
		r.Handle(route.path, handler).Methods(route.method)
	}
	return r
}

type parameter interface {
	name() string
	get(r *http.Request) (string, bool)
}

type urlParameter string

// Get returns the url
func (p urlParameter) get(r *http.Request) (string, bool) {
	s, ok := mux.Vars(r)[string(p)]
	return s, ok
}

func (p urlParameter) name() string {
	return string(p)
}

type rawQueryParameter string

func (p rawQueryParameter) get(r *http.Request) (string, bool) {
	return r.URL.RawQuery, true
}

func (p rawQueryParameter) name() string {
	return string(p)
}

type queryParameter string

func (p queryParameter) get(r *http.Request) (string, bool) {
	val, ok := r.URL.Query()[string(p)]
	if !ok {
		return "", false
	}
	return val[0], true
}

func (p queryParameter) name() string {
	return string(p)
}

type postParameter string

func (p postParameter) get(r *http.Request) (string, bool) {
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

func (p postParameter) name() string {
	return string(p)
}

type route struct {
	handler    func(db KeyManager, principal knox.Principal, parameters map[string]string) (interface{}, *httpError)
	id         string
	path       string
	method     string
	parameters []parameter
}

func writeErr(apiErr *httpError) http.HandlerFunc {
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
func (r route) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	db := getDB(req)
	principal := GetPrincipal(req)
	ps := GetParams(req)
	data, err := r.handler(db, principal, ps)

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
