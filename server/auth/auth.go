package auth

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/pinterest/knox"
	"github.com/spiffe/go-spiffe/uri"
)

// Provider is used for authenticating requests via the authentication decorator.
type Provider interface {
	Authenticate(token string, r *http.Request) (knox.Principal, error)
	Version() byte
	Type() byte
}

func verifyCertificate(r *http.Request, cas *x509.CertPool,
	timeFunc func() time.Time) (*x509.Certificate, error) {
	certs := r.TLS.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("auth: No peer certs configured")
	}
	opts := x509.VerifyOptions{
		Roots:         cas,
		CurrentTime:   timeFunc(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to verify client's certificate: " + err.Error())
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("auth: No cert chains could be verified")
	}
	return certs[0], nil
}

// NewMTLSAuthProvider initializes a chain of trust with given CA certificates
func NewMTLSAuthProvider(CAs *x509.CertPool) *MTLSAuthProvider {
	return &MTLSAuthProvider{
		CAs:  CAs,
		time: time.Now,
	}
}

// MTLSAuthProvider does authentication by verifying TLS certs against a collection of root CAs
type MTLSAuthProvider struct {
	CAs  *x509.CertPool
	time func() time.Time
}

// Version is set to 0 for MTLSAuthProvider
func (p *MTLSAuthProvider) Version() byte {
	return '0'
}

// Type is set to t for MTLSAuthProvider
func (p *MTLSAuthProvider) Type() byte {
	return 't'
}

// Authenticate performs TLS based Authentication for the MTLSAuthProvider
func (p *MTLSAuthProvider) Authenticate(token string, r *http.Request) (knox.Principal, error) {
	cert, err := verifyCertificate(r, p.CAs, p.time)
	if err != nil {
		return nil, err
	}

	// Check the CN matches the token
	err = cert.VerifyHostname(token)
	if err != nil {
		return nil, err
	}

	return NewMachine(token), nil
}

// NewSpiffeAuthProvider initializes a chain of trust with given CA certificates,
// identical to the MTLS provider except the principal is a Spiffe ID instead
// of a hostname and the CN of the cert is ignored.
func NewSpiffeAuthProvider(CAs *x509.CertPool) *SpiffeProvider {
	return &SpiffeProvider{
		CAs:  CAs,
		time: time.Now,
	}
}

// SpiffeProvider does authentication by verifying TLS certs against a collection of root CAs
type SpiffeProvider struct {
	CAs  *x509.CertPool
	time func() time.Time
}

// Version is set to 0 for SpiffeProvider
func (p *SpiffeProvider) Version() byte {
	return '0'
}

// Type is set to s for SpiffeProvider
func (p *SpiffeProvider) Type() byte {
	return 's'
}

// Authenticate performs TLS based Authentication and extracts the Spiffe URI extension
func (p *SpiffeProvider) Authenticate(token string, r *http.Request) (knox.Principal, error) {
	cert, err := verifyCertificate(r, p.CAs, p.time)
	if err != nil {
		return nil, err
	}

	// Extract the Spiffe URI extension from the certificate
	spiffeURIs, err := uri.GetURINamesFromCertificate(cert)
	if err != nil {
		return nil, err
	}
	if len(spiffeURIs) > 1 {
		return nil, fmt.Errorf("auth: more than one service identity specified in certificate")
	}
	splits := strings.SplitN(spiffeURIs[0][9:], "/", 2)
	if len(splits) != 2 {
		return nil, fmt.Errorf("auth: invalid service ID format")
	}
	return NewService(splits[0], splits[1]), nil
}

// GitHubProvider implements user authentication through github.com
type GitHubProvider struct {
	client httpClient
}

// NewGitHubProvider initializes GitHubProvider with an HTTP client with a timeout
func NewGitHubProvider(httpTimeout time.Duration) *GitHubProvider {
	return &GitHubProvider{&http.Client{Timeout: httpTimeout}}
}

// Version is set to 0 for GitHubProvider
func (p *GitHubProvider) Version() byte {
	return '0'
}

// Type is set to u for GitHubProvider since it authenticates users
func (p *GitHubProvider) Type() byte {
	return 'u'
}

// Authenticate uses the token to get user data from github.com
func (p *GitHubProvider) Authenticate(token string, r *http.Request) (knox.Principal, error) {
	user := &GitHubLoginFormat{}
	if err := p.getAPI("https://api.github.com/user", token, user); err != nil {
		return nil, err
	}

	groupsJSON := &GitHubOrgFormat{}
	if err := p.getAPI("https://api.github.com/user/orgs", token, groupsJSON); err != nil {
		return nil, err
	}
	groups := make([]string, len(*groupsJSON))
	for i, g := range *groupsJSON {
		groups[i] = g.Name
	}

	return NewUser(user.Name, groups), nil
}

func (p *GitHubProvider) getAPI(url, token string, v interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("API request returned status: %s", resp.Status)
	}
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	return decoder.Decode(v)
}

// GitHubLoginFormat specifies the json return format for /user field.
type GitHubLoginFormat struct {
	Name string `json:"login"`
}

// GitHubOrgFormat specifies the JSON return format for /user/org.
type GitHubOrgFormat []GitHubLoginFormat

type httpClient interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// IsUser returns true if the principal is a user.
func IsUser(p knox.Principal) bool {
	_, ok := p.(user)
	return ok
}

// IsService returns true if the principal is a service.
func IsService(p knox.Principal) bool {
	_, ok := p.(service)
	return ok
}

type stringSet map[string]struct{}

func (s *stringSet) memberOf(e string) bool {
	_, ok := map[string]struct{}(*s)[e]
	return ok
}

func setFromList(groups []string) *stringSet {
	var t = stringSet(map[string]struct{}{})
	for _, g := range groups {
		t[g] = struct{}{}
	}
	return &t
}

// NewUser creates a user principal with the given auth Provider.
func NewUser(id string, groups []string) knox.Principal {
	return user{id, *setFromList(groups)}
}

// NewMachine creates a machine principal with the given auth Provider.
func NewMachine(id string) knox.Principal {
	return machine(id)
}

// NewService creates a service principal with the given auth Provider.
func NewService(domain string, path string) knox.Principal {
	return service{domain, path}
}

// User represents an LDAP user and the AuthProvider to allow group information
type user struct {
	ID     string
	groups stringSet
}

func (u user) inGroup(g string) bool {
	return u.groups.memberOf(g)
}

func (u user) GetID() string {
	return u.ID
}

// CanAccess determines if a User can access an object represented by the ACL
// with a certain AccessType. It compares LDAP username and LDAP group.
func (u user) CanAccess(acl knox.ACL, t knox.AccessType) bool {
	for _, a := range acl {
		switch a.Type {
		case knox.User:
			if a.ID == u.ID && a.AccessType.CanAccess(t) {
				return true
			}
		case knox.UserGroup:
			if u.inGroup(a.ID) && a.AccessType.CanAccess(t) {
				return true
			}
		}
	}
	return false
}

// Machine represents a given machine by their hostname.
type machine string

func (m machine) GetID() string {
	return string(m)
}

// CanAccess determines if a Machine can access an object represented by the ACL
// with a certain AccessType. It compares Machine hostname and hostname prefix.
func (m machine) CanAccess(acl knox.ACL, t knox.AccessType) bool {
	for _, a := range acl {
		switch a.Type {
		case knox.Machine:
			if a.ID == string(m) && a.AccessType.CanAccess(t) {
				return true
			}
		case knox.MachinePrefix:
			// TODO(devinlundberg): Investigate security implications of this
			if strings.HasPrefix(string(m), a.ID) && a.AccessType.CanAccess(t) {
				return true
			}
		}
	}
	return false
}

// Service represents a given service from a trust domain
type service struct {
	domain string
	id     string
}

// GetID converts the internal representation into a SPIFFE id
func (s service) GetID() string {
	return "spiffe://" + s.domain + "/" + s.id
}

// CanAccess determines if a Service can access an object represented by the ACL
// with a certain AccessType. It compares Service id and id prefix.
func (s service) CanAccess(acl knox.ACL, t knox.AccessType) bool {
	for _, a := range acl {
		switch a.Type {
		case knox.Service:
			if a.ID == string(s.GetID()) && a.AccessType.CanAccess(t) {
				return true
			}
		}
	}
	return false
}

type mockHTTPClient struct{}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	resp := &http.Response{}
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	a := req.Header.Get("Authorization")
	if a == "" || a == "Bearer notvalid" {
		resp.StatusCode = 400
		resp.Status = "400 Unauthorized"

		return resp, nil
	}
	switch req.URL.Path {
	case "/user":
		data := "{\"login\":\"testuser\"}"
		resp.Body = ioutil.NopCloser(bytes.NewBufferString(data))
		resp.StatusCode = 200
		return resp, nil
	case "/user/orgs":
		data := "[{\"login\":\"testgroup\"}]"
		resp.Body = ioutil.NopCloser(bytes.NewBufferString(data))
		resp.StatusCode = 200
		return resp, nil
	default:
		resp.StatusCode = 404
		resp.Status = "404 Not found"
		return resp, nil
	}

}

// MockGitHubProvider returns a mocked out authentication header with a simple mock "server".
// If there exists an authorization header with user token that does not equal 'notvalid', it will log in as 'testuser'.
func MockGitHubProvider() *GitHubProvider {
	return &GitHubProvider{&mockHTTPClient{}}
}
