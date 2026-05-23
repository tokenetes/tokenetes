package subjecttokenhandler

import (
	"context"
	"errors"
	"fmt"

	"github.com/tokenetes/tokenetes/pkg/common"
	"go.uber.org/zap"
)

type SubjectTokens struct {
	OIDC       *OIDCToken       `json:"OIDC,omitempty"`
	SelfSigned *SelfSignedToken `json:"selfSigned,omitempty"`
}

type OIDCToken struct {
	ClientID    string `json:"clientId"`
	ProviderURL string `json:"providerURL"`
}

type SelfSignedToken struct {
	Validation    bool   `json:"validation"`
	JWKSSEndpoint string `json:"jwksEndpoint"`
}

// TokenHandler verifies a subject token and returns its parsed claims.
type TokenHandler interface {
	VerifyAndParse(ctx context.Context, token string) (interface{}, error)
}

type TokenHandlers struct {
	oIDCTokenHandler       TokenHandler
	selfSignedTokenHandler TokenHandler
}

func NewTokenHandlers(subjectTokens SubjectTokens, logger *zap.Logger) *TokenHandlers {
	handlers := &TokenHandlers{}

	if subjectTokens.OIDC != nil {
		handlers.oIDCTokenHandler = NewOIDCTokenHandler(subjectTokens.OIDC, logger)
	}

	if subjectTokens.SelfSigned != nil {
		handlers.selfSignedTokenHandler = NewSelfSignedTokenHandler(subjectTokens.SelfSigned, logger)
	}

	return handlers
}

func (t *TokenHandlers) GetHandler(tokenType common.TokenType) (TokenHandler, error) {
	switch tokenType {
	case common.OIDC_ID_TOKEN_TYPE:
		if t.oIDCTokenHandler != nil {
			return t.oIDCTokenHandler, nil
		}

		return nil, errors.New("configuration not provided for OIDC subject token")
	case common.SELF_SIGNED_TOKEN_TYPE:
		if t.selfSignedTokenHandler != nil {
			return t.selfSignedTokenHandler, nil
		}

		return nil, errors.New("configuration not provided for self-signed subject token")

	default:
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}
}
