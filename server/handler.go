package server

import (
	"log"
	"net/http"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
)

// ClientInfoHandler get client info from request
type ClientInfoHandler func(r *http.Request) (clientID, clientSecret string, err error)

// ClientAuthorizedHandler check the client allows to use this authorization grant type
type ClientAuthorizedHandler func(clientID string, grant oauth2.GrantType) (allowed bool, err error)

// ClientScopeHandler check the client allows to use scope
type ClientScopeHandler func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error)

// UserAuthorizationHandler get user id from request authorization
type UserAuthorizationHandler func(w http.ResponseWriter, r *http.Request) (userID string, err error)

// PasswordAuthorizationHandler get user id from username and password
type PasswordAuthorizationHandler func(username, password string) (userID string, err error)

// RefreshingScopeHandler check the scope of the refreshing token
type RefreshingScopeHandler func(tgr *oauth2.TokenGenerateRequest, oldScope string) (allowed bool, err error)

// RefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
type RefreshingValidationHandler func(ti oauth2.TokenInfo) (allowed bool, err error)

// ResponseErrorHandler response error handing
type ResponseErrorHandler func(re *errors.Response)

// InternalErrorHandler internal error handing
type InternalErrorHandler func(err error) (re *errors.Response)

// AuthorizeScopeHandler set the authorized scope
type AuthorizeScopeHandler func(w http.ResponseWriter, r *http.Request) (scope string, err error)

// AccessTokenExpHandler set expiration date for the access token
type AccessTokenExpHandler func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error)

// ExtensionFieldsHandler in response to the access token with the extension of the field
type ExtensionFieldsHandler func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{})

// ResponseTokenHandler response token handing
type ResponseTokenHandler func(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error

// ClientFormHandler get client data from form
func ClientFormHandler(r *http.Request) (string, string, error) {
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		return "", "", errors.ErrInvalidClient
	}
	clientSecret := r.Form.Get("client_secret")
	return clientID, clientSecret, nil
}

// ClientBasicHandler get client data from basic authorization
func ClientBasicHandler(r *http.Request) (string, string, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		log.Println("333333333")
		return "", "", errors.ErrInvalidClient
	}
	return username, password, nil
}
