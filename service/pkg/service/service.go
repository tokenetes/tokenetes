package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tokenetes/tokenetes/pkg/common"
	"github.com/tokenetes/tokenetes/pkg/generationrules/v1alpha1"
	"github.com/tokenetes/tokenetes/pkg/keys"
	"github.com/tokenetes/tokenetes/pkg/tokeneteserrors"
	"go.uber.org/zap"
)

type Service struct {
	generationRules *v1alpha1.GenerationRulesImp
	logger          *zap.Logger
}

func NewService(generationRules *v1alpha1.GenerationRulesImp, logger *zap.Logger) *Service {
	return &Service{
		generationRules: generationRules,
		logger:          logger,
	}
}

const (
	TOKEN_JWT_HEADER = "txn_token"
)

type TokenResponse struct {
	TokenType       string           `json:"token_type"`
	IssuedTokenType common.TokenType `json:"issued_token_type"`
	AccessToken     string           `json:"access_token"`
}

func (s *Service) GetJwks() jwk.Set {
	return keys.GetJWKS()
}

func (s *Service) GenerateTxnToken(ctx context.Context, txnTokenRequest *common.TokenRequest) (*TokenResponse, error) {
	subjectTokenHandler, err := s.generationRules.GetSubjectTokenHandler(txnTokenRequest.SubjectTokenType)
	if err != nil {
		s.logger.Error("Failed to get subject token handler.", zap.String("subject-token-type", string(txnTokenRequest.SubjectTokenType)), zap.Error(err))

		return &TokenResponse{}, err
	}

	subjectTokenClaims, err := subjectTokenHandler.VerifyAndParse(ctx, txnTokenRequest.SubjectToken)
	if err != nil {
		s.logger.Error("Failed to verify and parse subject token.", zap.Error(err))

		return &TokenResponse{}, err
	}

	subject, err := s.generationRules.ResolveSub(subjectTokenClaims)
	if err != nil {
		s.logger.Error("Failed to resolve sub from subject token claims.", zap.Error(err))

		return &TokenResponse{}, err
	}

	s.logger.Info("Successfully verified subject token.", zap.Any("subject", subject))

	purp, adz, err := s.generationRules.ConstructPurpAndAzd(txnTokenRequest)
	if err != nil {
		s.logger.Error("Failed to generate scope and authorization details for a request.", zap.Error(err))

		return &TokenResponse{}, err
	}

	accessEvaluation, err := s.generationRules.EvaluateAccess(txnTokenRequest, subjectTokenClaims)
	if err != nil {
		s.logger.Error("Error evaluating access.", zap.Error(err))

		return &TokenResponse{}, err
	}

	if !accessEvaluation {
		s.logger.Error("Access Denied.",
			zap.Any("subject", subject),
			zap.Any("purp", purp),
		)

		return &TokenResponse{}, tokeneteserrors.ErrAccessDenied
	}

	s.logger.Info("Access authorized for request.", zap.Any("subject", subject), zap.String("purp", purp))

	txnID, err := uuid.NewRandom()
	if err != nil {
		s.logger.Error("Error generating transaction id.")

		return &TokenResponse{}, err
	}

	tokenLifetime, err := s.generationRules.GetTokenLifetime()
	if err != nil {
		s.logger.Error("Error generating token lifetime.", zap.Error(err))

		return &TokenResponse{}, err
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":  s.generationRules.GetIssuer(),
		"iat":  time.Now().Unix(),
		"aud":  s.generationRules.GetAudience(),
		"exp":  time.Now().Add(tokenLifetime).Unix(),
		"txn":  txnID,
		"sub":  subject,
		"purp": purp,
		"azd":  adz,
		"rctx": txnTokenRequest.RequestContext,
	})

	newToken.Header["typ"] = TOKEN_JWT_HEADER
	newToken.Header["kid"] = keys.GetKid()

	privateKey := keys.GetPrivateKey()

	tokenString, err := newToken.SignedString(privateKey)
	if err != nil {
		s.logger.Error("Failed to sign txn token.", zap.Error(err))

		return &TokenResponse{}, err
	}

	tokenResponse := &TokenResponse{
		TokenType:       "N_A",
		IssuedTokenType: common.TXN_TOKEN_TYPE,
		AccessToken:     tokenString,
	}

	return tokenResponse, nil
}

func (s *Service) GetGenerationRules() (json.RawMessage, error) {
	return s.generationRules.GetRulesJSON()
}
