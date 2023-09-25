package server

import (
	"context"
	"errors"
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
	BasicUsers map[string]*BasicAuthUser
}

func NewBasicAuthnAuthzer() *BasicAuthnAuthzer {
	return &BasicAuthnAuthzer{
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
	if req.Header.Get("X-RemoteUser") == "" && req.Header.Get("X-RemoteGroup") == "" {
		username, password, ok := req.BasicAuth()
		if ok {
			klog.V(4).InfoS("BasicAuth", "username", username, "passsword", password)
			basic, found := auth.BasicUsers[username]
			if basic == nil || !found {
				klog.V(4).InfoS("UserNotFound", "username", username)
			} else if basic.Password != password {
				klog.V(4).InfoS("WrongPassword", "username", username)
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
	}
	return nil, false, nil
}

func (auth *BasicAuthnAuthzer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	klog.V(4).InfoS("Authorize", "ctx", ctx, "attr", attr)
	userinfo := attr.GetUser()
	if userinfo == nil {
		klog.V(4).InfoS("NoUser")
		return authorizer.DecisionNoOpinion, "Error", errors.New("no user on request.")
	}
	username := userinfo.GetName()
	basic, found := auth.BasicUsers[username]
	if basic == nil || !found {
		klog.V(4).InfoS("UserNotFound", "username", username)
		return authorizer.DecisionNoOpinion, "Error", errors.New("user not found")
	}
	//TODO: check verb ...

	return authorizer.DecisionAllow, "", nil
}

// See AuthorizeClientBearerToken
func AuthorizeBasicAuth(authn *server.AuthenticationInfo, authz *server.AuthorizationInfo) {
	basicAuthnAuthzer := NewBasicAuthnAuthzer()
	authn.Authenticator = authenticatorunion.New(basicAuthnAuthzer, authn.Authenticator)
	authz.Authorizer = authorizerunion.New(authz.Authorizer, basicAuthnAuthzer)
}
