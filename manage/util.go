package manage

import (
	"net/url"
	"strings"

	"github.com/go-oauth2/oauth2/v4/errors"
)

// ValidateURIHandler validates that redirectURI is contained in baseURI
type ValidateURIHandler func(baseURI, redirectURI string) error

// DefaultValidateURI validates that redirectURI is contained in baseURI
func DefaultValidateURI(baseURI string, redirectURI string) error {
	base, err := url.Parse(baseURI)
	if err != nil {
		return err
	}

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(redirect.Host, base.Host) {
		return errors.ErrInvalidRedirectURI
	}
	return nil
}
