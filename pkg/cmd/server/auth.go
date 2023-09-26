package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticatorunion "k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authorizerunion "k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"
)

// https://www.rfc-editor.org/rfc/rfc2617.html#section-2
// https://datatracker.ietf.org/doc/html/rfc7235
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

type BasicAuthUser struct {
	Name     string
	Password string
	UID      string
	Groups   []string
	Extra    map[string][]string
}

type BasicAuthnAuthzer struct {
	BasicRealm string
	BasicUsers map[string]*BasicAuthUser
}

func NewBasicAuthnAuthzer() *BasicAuthnAuthzer {
	return &BasicAuthnAuthzer{
		BasicRealm: "testrealm",
		BasicUsers: map[string]*BasicAuthUser{
			"testusername": &BasicAuthUser{
				Name:     "testusername",
				Password: "testpassword",
				UID:      uuid.New().String(),
				Groups:   []string{"testgroup"},
			},
		},
	}
}

func (auth *BasicAuthnAuthzer) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	klog.V(4).InfoS("AuthenticateRequest", "URI", req.RequestURI, "Header", req.Header)
	// when not proxying, check basic auth
	if req.Header.Get("X-Remote-User") == "" && req.Header.Get("X-Remote-Group") == "" {
		username, password, ok := req.BasicAuth()
		if !ok {
			return nil, false, fmt.Errorf("BasicAuth required")
		}
		klog.V(4).InfoS("BasicAuth", "username", username, "passsword", password)
		basic, found := auth.BasicUsers[username]
		if basic == nil || !found {
			klog.V(4).InfoS("UserNotFound", "username", username)
			return nil, false, fmt.Errorf("UserNotFound username=%v", username)
		} else if basic.Password != password {
			klog.V(4).InfoS("WrongPassword", "username", username)
			return nil, false, fmt.Errorf("WrongPassword username=%v", username)
		} else {
			info := &user.DefaultInfo{
				Name:   basic.Name,
				UID:    basic.UID,
				Groups: basic.Groups,
				Extra:  basic.Extra,
			}
			return &authenticator.Response{User: info}, true, nil
		}
	}
	return nil, false, nil
}

func (auth *BasicAuthnAuthzer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	klog.V(4).InfoS("Authorize", "ctx", ctx, "attr", attr)
	userinfo := attr.GetUser()
	if userinfo == nil {
		//klog.V(4).InfoS("NoUser")
		return authorizer.DecisionNoOpinion, "", nil //"Error", errors.New("no user on request.")
	}
	username := userinfo.GetName()
	basic, found := auth.BasicUsers[username]
	if basic == nil || !found {
		//klog.V(4).InfoS("UserNotFound", "username", username)
		return authorizer.DecisionNoOpinion, "", nil //Error", errors.New("user not found")
	}
	//TODO: check verb ...
	klog.V(4).InfoS("UserFound", "username", username)

	return authorizer.DecisionAllow, "", nil
}

// See AuthorizeClientBearerToken
func AuthorizeBasicAuth(authn *server.AuthenticationInfo, authz *server.AuthorizationInfo) {
	basicAuthnAuthzer := NewBasicAuthnAuthzer()
	authn.Authenticator = authenticatorunion.NewFailOnError(basicAuthnAuthzer, authn.Authenticator)
	authz.Authorizer = authorizerunion.New(authz.Authorizer, basicAuthnAuthzer)
}
