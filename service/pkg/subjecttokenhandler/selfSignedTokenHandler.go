package subjecttokenhandler

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tokenetes/tokenetes/pkg/tokeneteserrors"
	"go.uber.org/zap"
)

type SelfSignedTokenHandler struct {
	validate     bool
	jwksEndpoint string
	logger       *zap.Logger
}

func NewSelfSignedTokenHandler(selfSignedConfig *SelfSignedToken, logger *zap.Logger) *SelfSignedTokenHandler {
	selfSignedTokenHandler := SelfSignedTokenHandler{validate: selfSignedConfig.Validation, jwksEndpoint: selfSignedConfig.JWKSSEndpoint, logger: logger}

	if !selfSignedTokenHandler.validate {
		selfSignedTokenHandler.logger.Warn("Self-signed JWT validation is disabled; this poses a security risk")
	}

	return &selfSignedTokenHandler
}

func (s *SelfSignedTokenHandler) VerifyAndParse(ctx context.Context, token string) (interface{}, error) {
	if s.validate {
		jwks, err := fetchJWKS(s.jwksEndpoint)
		if err != nil {
			return nil, err
		}

		keyFunc := func(t *jwt.Token) (interface{}, error) {
			if kid, ok := t.Header["kid"].(string); !ok {
				return nil, fmt.Errorf("kid header not found in token")
			} else {
				key, ok := jwks.LookupKeyID(kid)
				if !ok {
					return nil, fmt.Errorf("unable to find key with kid %s", kid)
				}

				var publicKey interface{}
				if err := key.Raw(&publicKey); err != nil {
					return nil, fmt.Errorf("unable to get raw public key: %v", err)
				}

				return publicKey, nil
			}
		}

		parsedToken, err := jwt.Parse(token, keyFunc)
		if err != nil {
			return nil, fmt.Errorf("error verifying token: %v", err)
		}

		if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			return claims, nil
		}

		return nil, tokeneteserrors.ErrInvalidSubjectTokenClaims
	} else {
		s.logger.Warn("Parsing token without validating; this poses a security risk")

		parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("error parsing token: %v", err)
		}

		if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			return claims, nil
		}

		return nil, tokeneteserrors.ErrInvalidSubjectTokenClaims
	}
}

func fetchJWKS(jwksEndpointURL string) (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	set, err := jwk.Fetch(ctx, jwksEndpointURL)
	if err != nil {
		return nil, err
	}

	return set, nil
}
