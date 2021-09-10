package oauth2

import (
	"context"
	"net/http"
	"time"
)

// GenerateBasic provide the basis of the generated token data
	type	GenerateBasic struct {
		Client    ClientInfo
		UserID    string
		CreateAt  time.Time
		TokenInfo TokenInfo
		Request   *http.Request
	}

	// AuthorizeGenerate generate the authorization code interface
	type AuthorizeGenerate interface {
		Token(ctx context.Context, data *GenerateBasic) (code string, err error)
	}

	// AccessGenerate generate the access and refresh tokens interface
	type AccessGenerate interface {
		Token(ctx context.Context, data *GenerateBasic, isGenRefresh bool) (access, refresh string, err error)
	}

