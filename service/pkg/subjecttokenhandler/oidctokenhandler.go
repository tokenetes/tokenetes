package subjecttokenhandler

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/tokenetes/tokenetes/pkg/tokeneteserrors"
	"go.uber.org/zap"
)

const OIDC_PROVIDER_INITILIZATION_MAX_RETRIES = 5

type OIDCTokenHandler struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCTokenHandler(oidcConfig *OIDCToken, logger *zap.Logger) *OIDCTokenHandler {
	provider := getOIDCProvider(oidcConfig.ProviderURL, logger)

	verifier := provider.Verifier(&oidc.Config{
		ClientID: oidcConfig.ClientID,
	})

	return &OIDCTokenHandler{verifier: verifier}
}

func (o *OIDCTokenHandler) VerifyAndParse(ctx context.Context, token string) (interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	idToken, err := o.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	var claims jwt.MapClaims

	if err := idToken.Claims(&claims); err != nil {
		return nil, tokeneteserrors.ErrInvalidSubjectTokenClaims
	}

	return claims, nil
}

func getOIDCProvider(oidcIssuer string, logger *zap.Logger) *oidc.Provider {
	delay := time.Second

	for i := 0; i < OIDC_PROVIDER_INITILIZATION_MAX_RETRIES; i++ {
		ctx := context.Background()

		provider, err := oidc.NewProvider(ctx, oidcIssuer)
		if err == nil {
			logger.Info("Successfully connected to the OIDC provider.")

			return provider
		}

		logger.Error("Failed to connect to the OIDC provider.",
			zap.Int("attempt", i+1),
			zap.String("retrying_in", delay.String()),
			zap.Error(err))
		time.Sleep(delay)

		delay *= 2
	}

	logger.Error(fmt.Sprintf("Failed to connect to the OIDC provider after %d attempts", OIDC_PROVIDER_INITILIZATION_MAX_RETRIES))

	panic(fmt.Sprintf("failed to connect to the OIDC provider after %d attempts", OIDC_PROVIDER_INITILIZATION_MAX_RETRIES))
}
