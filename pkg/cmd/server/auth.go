package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticatorunion "k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	authorizerunion "k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/apiserver/pkg/endpoints/filterlatency"
	genericapifilters "k8s.io/apiserver/pkg/endpoints/filters"
	genericfeatures "k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/server"
	genericfilters "k8s.io/apiserver/pkg/server/filters"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	flowcontrolrequest "k8s.io/apiserver/pkg/util/flowcontrol/request"
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
	BasicRealm       string
	BasicUsers       map[string]*BasicAuthUser
	AlwaysAllowPaths map[string]bool
}

func NewBasicAuthnAuthzer(alwaysAllowPaths []string) *BasicAuthnAuthzer {
	m := make(map[string]bool, 3)
	for _, p := range alwaysAllowPaths {
		m[strings.TrimPrefix(p, "/")] = true
	}
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
		AlwaysAllowPaths: m,
	}
}

func (auth *BasicAuthnAuthzer) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	klog.V(4).InfoS("AuthenticateRequest", "URI", req.RequestURI, "Header", req.Header)
	// when not proxying, check basic auth except always allow paths
	if !auth.AlwaysAllowPaths[strings.TrimPrefix(req.RequestURI, "/")] && req.Header.Get("X-Remote-User") == "" && req.Header.Get("X-Remote-Group") == "" {
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
	if auth.AlwaysAllowPaths[strings.TrimPrefix(attr.GetPath(), "/")] {
		return authorizer.DecisionAllow, "", nil
	}
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
func AuthorizeBasicAuth(authn *server.AuthenticationInfo, authz *server.AuthorizationInfo, delegate *genericoptions.DelegatingAuthorizationOptions) *BasicAuthnAuthzer {
	basicAuthnAuthzer := NewBasicAuthnAuthzer(delegate.AlwaysAllowPaths)
	authn.Authenticator = authenticatorunion.NewFailOnError(basicAuthnAuthzer, authn.Authenticator)
	authz.Authorizer = authorizerunion.New(authz.Authorizer, basicAuthnAuthzer)
	return basicAuthnAuthzer
}

// WithFailedBasicAuth
func WithFailedBasicAuth(failedHandler http.Handler, basicAuthnAuthzer *BasicAuthnAuthzer) http.Handler {
	if basicAuthnAuthzer == nil {
		return failedHandler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("X-Remote-User") == "" && req.Header.Get("X-Remote-Group") == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", basicAuthnAuthzer.BasicRealm))
		}
		failedHandler.ServeHTTP(w, req)
	})
}

// See DefaultBuildHandlerChain
func BasicAuthBuildHandlerChain(basicAuthnAuthzer *BasicAuthnAuthzer, apiHandler http.Handler, c *server.Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, "authorization")

	if c.FlowControl != nil {
		workEstimatorCfg := flowcontrolrequest.DefaultWorkEstimatorConfig()
		requestWorkEstimator := flowcontrolrequest.NewWorkEstimator(
			c.StorageObjectCountTracker.Get, c.FlowControl.GetInterestedWatchCount, workEstimatorCfg)
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl, requestWorkEstimator)
		handler = filterlatency.TrackStarted(handler, "priorityandfairness")
	} else {
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, "impersonation")

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)
	handler = filterlatency.TrackStarted(handler, "audit")

	failedHandler := genericapifilters.Unauthorized(c.Serializer)
	failedHandler = WithFailedBasicAuth(failedHandler, basicAuthnAuthzer)
	failedHandler = genericapifilters.WithFailedAuthenticationAudit(failedHandler, c.AuditBackend, c.AuditPolicyRuleEvaluator)

	failedHandler = filterlatency.TrackCompleted(failedHandler)
	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences)
	handler = filterlatency.TrackStarted(handler, "authentication")

	handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")

	// WithTimeoutForNonLongRunningRequests will call the rest of the request handling in a go-routine with the
	// context with deadline. The go-routine can keep running, while the timeout logic will return a timeout to the client.
	handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc)

	handler = genericapifilters.WithRequestDeadline(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator,
		c.LongRunningFunc, c.Serializer, c.RequestTimeout)
	handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.HandlerChainWaitGroup)
	if c.SecureServing != nil && !c.SecureServing.DisableHTTP2 && c.GoawayChance > 0 {
		handler = genericfilters.WithProbabilisticGoaway(handler, c.GoawayChance)
	}
	handler = genericapifilters.WithAuditAnnotations(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator)
	handler = genericapifilters.WithWarningRecorder(handler)
	handler = genericapifilters.WithCacheControl(handler)
	handler = genericfilters.WithHSTS(handler, c.HSTSDirectives)
	//c.lifecycleSignals is private!
	//if c.ShutdownSendRetryAfter {
	//	handler = genericfilters.WithRetryAfter(handler, c.lifecycleSignals.NotAcceptingNewRequest.Signaled())
	//}
	handler = genericfilters.WithHTTPLogging(handler)
	if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIServerTracing) {
		handler = genericapifilters.WithTracing(handler, c.TracerProvider)
	}
	handler = genericapifilters.WithLatencyTrackers(handler)
	handler = genericapifilters.WithRequestInfo(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithRequestReceivedTimestamp(handler)
	//c.lifecycleSignals is private!
	//handler = genericapifilters.WithMuxAndDiscoveryComplete(handler, c.lifecycleSignals.MuxAndDiscoveryComplete.Signaled())
	handler = genericfilters.WithPanicRecovery(handler, c.RequestInfoResolver)
	handler = genericapifilters.WithAuditID(handler)
	return handler
}
