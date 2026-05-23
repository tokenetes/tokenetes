package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/tokenetes/tokenetes/pkg/accessevaluation"
	"github.com/tokenetes/tokenetes/pkg/common"
	"github.com/tokenetes/tokenetes/pkg/logging"
	"github.com/tokenetes/tokenetes/pkg/subjecttokenhandler"
	"github.com/tokenetes/tokenetes/pkg/tokeneteserrors"
	"github.com/tokenetes/tokenetes/utils"

	"errors"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
)

type TokenetesConfigToken struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	LifeTime string `json:"lifeTime"`
	// Sub is a literal or `${subjectToken.<gjsonPath>}` expression; see README.
	Sub string `json:"sub"`
}

type TokenetesConfigGenerationRule struct {
	Token                               *TokenetesConfigToken                 `json:"token"`
	SubjectTokens                       *subjecttokenhandler.SubjectTokens    `json:"subjectTokens"`
	AccessEvaluationAPI                 *accessevaluation.AccessEvaluationAPI `json:"accessEvaluationAPI"`
	TokenGenerationAuthorizedServiceIds []string                              `json:"tokenGenerationAuthorizedServiceIds"`
}

type DynamicMap struct {
	Map map[string]interface{} `json:"-"`
}

func (in *DynamicMap) MarshalJSON() ([]byte, error) {
	return json.Marshal(in.Map)
}

func (in *DynamicMap) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &in.Map)
}

type TraTGenerationRule struct {
	TraTName         string            `json:"traTName"`
	Path             string            `json:"path"`
	Method           common.HttpMethod `json:"method"`
	Purp             string            `json:"purp"`
	AzdMapping       AzdMapping        `json:"azdmapping,omitempty"`
	AccessEvaluation *DynamicMap       `json:"accessEvaluation,omitempty"`
}

type AzdMapping map[string]AzdField
type AzdField struct {
	Required bool   `json:"required"`
	Value    string `json:"value"`
}

type IndexedTraTsGenerationRules map[common.HttpMethod]map[string]*TraTGenerationRule

type GenerationRules struct {
	TokenetesConfigGenerationRule *TokenetesConfigGenerationRule `json:"tokenetesConfigGenerationRule"`
	TraTsGenerationRules          map[string]*TraTGenerationRule `json:"traTsGenerationRules"`
}

func NewGenerationRules() *GenerationRules {
	return &GenerationRules{
		TokenetesConfigGenerationRule: &TokenetesConfigGenerationRule{},
		TraTsGenerationRules:          make(map[string]*TraTGenerationRule),
	}
}

type GenerationRulesImp struct {
	generationRules             *GenerationRules
	indexedTraTsGenerationRules IndexedTraTsGenerationRules
	subjectTokenHandlers        *subjecttokenhandler.TokenHandlers
	accessevaluator             *accessevaluation.AccessEvaluator
	httpClient                  *http.Client
	mu                          sync.RWMutex
}

func NewGenerationRulesImp(httpClient *http.Client) *GenerationRulesImp {
	indexedTraTsGenerationRules := make(IndexedTraTsGenerationRules)

	for _, method := range common.HttpMethodList {
		indexedTraTsGenerationRules[method] = make(map[string]*TraTGenerationRule)
	}

	return &GenerationRulesImp{
		generationRules:             NewGenerationRules(),
		indexedTraTsGenerationRules: indexedTraTsGenerationRules,
		httpClient:                  httpClient,
	}
}

// write lock should be taken my method calling indexTraTsGenerationRules.
func (gri *GenerationRulesImp) indexTraTsGenerationRules() {
	indexedTraTsGenerationRules := make(IndexedTraTsGenerationRules)

	for _, method := range common.HttpMethodList {
		indexedTraTsGenerationRules[method] = make(map[string]*TraTGenerationRule)
	}

	for _, traTGenerationRules := range gri.generationRules.TraTsGenerationRules {
		indexedTraTsGenerationRules[traTGenerationRules.Method][traTGenerationRules.Path] = traTGenerationRules
	}

	gri.indexedTraTsGenerationRules = indexedTraTsGenerationRules
}

func (gri *GenerationRulesImp) UpsertTraTRule(traTGenerationRule TraTGenerationRule) error {
	gri.mu.Lock()
	defer gri.mu.Unlock()

	if _, exist := gri.indexedTraTsGenerationRules[traTGenerationRule.Method]; !exist {
		return fmt.Errorf("invalid HTTP method: %s", string(traTGenerationRule.Method))
	}

	gri.generationRules.TraTsGenerationRules[traTGenerationRule.TraTName] = &traTGenerationRule

	gri.indexTraTsGenerationRules()

	return nil
}

func (gri *GenerationRulesImp) DeleteTrat(tratName string) {
	gri.mu.Lock()
	defer gri.mu.Unlock()

	delete(gri.generationRules.TraTsGenerationRules, tratName)

	gri.indexTraTsGenerationRules()
}

func (gri *GenerationRulesImp) UpdateTokenetesConfigRule(generationTokenetesConfigRule TokenetesConfigGenerationRule) {
	gri.mu.Lock()
	defer gri.mu.Unlock()

	gri.generationRules.TokenetesConfigGenerationRule = &generationTokenetesConfigRule

	if generationTokenetesConfigRule.SubjectTokens == nil {
		gri.subjectTokenHandlers = nil
	} else {
		gri.subjectTokenHandlers = subjecttokenhandler.NewTokenHandlers(*generationTokenetesConfigRule.SubjectTokens, logging.GetLogger("subject-token-handler"))
	}

	if generationTokenetesConfigRule.AccessEvaluationAPI == nil {
		gri.accessevaluator = nil
	} else {
		gri.accessevaluator = accessevaluation.NewAccessEvaluator(*generationTokenetesConfigRule.AccessEvaluationAPI, gri.httpClient, logging.GetLogger("access-evaluator"))
	}
}

func (gri *GenerationRulesImp) GetRulesJSON() (json.RawMessage, error) {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	jsonData, err := json.Marshal(gri.generationRules)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// Read lock should be take by the function calling matchRule.
func (gri *GenerationRulesImp) matchRule(path string, method common.HttpMethod) (*TraTGenerationRule, map[string]string, error) {
	methodRuleMap, ok := gri.indexedTraTsGenerationRules[method]
	if !ok {
		return nil, nil, fmt.Errorf("invalid HTTP method: %s", string(method))
	}

	for pattern, rule := range methodRuleMap {
		regexPattern := convertToRegex(pattern)
		re := regexp.MustCompile(regexPattern)

		if re.MatchString(path) {
			matches := re.FindStringSubmatch(path)
			names := re.SubexpNames()

			pathParameters := make(map[string]string)

			for i, name := range names {
				if i != 0 && name != "" {
					pathParameters[name] = matches[i]
				}
			}

			return rule, pathParameters, nil
		}
	}

	return nil, nil, errors.New("no matching rule found")
}

func convertToRegex(template string) string {
	r := strings.NewReplacer("{#", "(?P<", "}", ">[^/]+)")

	return "^" + r.Replace(template) + "$"
}

func (gri *GenerationRulesImp) ConstructPurpAndAzd(txnTokenRequest *common.TokenRequest) (string, map[string]interface{}, error) {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	path := txnTokenRequest.RequestDetails.Path
	method := txnTokenRequest.RequestDetails.Method

	input := make(map[string]interface{})
	input["body"] = txnTokenRequest.RequestDetails.Body
	input["headers"] = txnTokenRequest.RequestDetails.Headers
	input["queryParameters"] = txnTokenRequest.RequestDetails.QueryParameters

	generationTraTRule, pathParameter, err := gri.matchRule(path, method)
	if err != nil {
		return "", nil, fmt.Errorf("error matching generation rule for %s path and %s method: %w", path, string(method), err)
	}

	for par, val := range pathParameter {
		input[par] = val
	}

	if generationTraTRule.AzdMapping == nil {
		return generationTraTRule.Purp, nil, nil
	}

	azd, err := gri.computeAzd(generationTraTRule.AzdMapping, input)
	if err != nil {
		return "", nil, fmt.Errorf("error computing azd from generation trat rule for %s path and %s method: %w", path, string(method), err)
	}

	return generationTraTRule.Purp, azd, nil
}

// Read lock should be take by the function calling computeAzd.
func (gri *GenerationRulesImp) computeAzd(azdMapping AzdMapping, input map[string]interface{}) (map[string]interface{}, error) {
	azd := make(map[string]interface{})

	jsonInput, err := marshalToJson(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input to JSON: %w", err)
	}

	for key, azdField := range azdMapping {
		valueSpec := azdField.Value

		if strings.HasPrefix(valueSpec, "${") && strings.HasSuffix(valueSpec, "}") {
			path := strings.TrimSuffix(strings.TrimPrefix(valueSpec, "${"), "}")
			value := extractValueFromJson(jsonInput, path)

			if value == nil {
				return nil, fmt.Errorf("failed to extract value for key %s from path %s", key, path)
			}

			azd[key] = value
		} else {
			azd[key] = valueSpec
		}
	}

	return azd, nil
}

func extractValueFromJson(jsonStr string, path string) interface{} {
	result := gjson.Get(jsonStr, path)

	if result.Exists() {
		return result.Value()
	}

	return nil
}

func marshalToJson(data map[string]interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func (gri *GenerationRulesImp) GetIssuer() string {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	return gri.generationRules.TokenetesConfigGenerationRule.Token.Issuer
}

func (gri *GenerationRulesImp) GetAudience() string {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	return gri.generationRules.TokenetesConfigGenerationRule.Token.Audience
}

func (gri *GenerationRulesImp) GetSub() string {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	if gri.generationRules.TokenetesConfigGenerationRule == nil ||
		gri.generationRules.TokenetesConfigGenerationRule.Token == nil {
		return ""
	}

	return gri.generationRules.TokenetesConfigGenerationRule.Token.Sub
}

// ResolveSub resolves the configured `token.sub` expression against the verified subject token claims.
func (gri *GenerationRulesImp) ResolveSub(claims interface{}) (interface{}, error) {
	subExpr := gri.GetSub()
	if subExpr == "" {
		return nil, errors.New("`sub` is not configured in TokenetesConfig.token")
	}

	if !strings.HasPrefix(subExpr, "${") || !strings.HasSuffix(subExpr, "}") {
		return subExpr, nil
	}

	expr := strings.TrimSuffix(strings.TrimPrefix(subExpr, "${"), "}")

	const prefix = "subjectToken."
	if !strings.HasPrefix(expr, prefix) {
		return nil, fmt.Errorf("invalid sub expression %q: must be a literal or start with `${subjectToken.`", subExpr)
	}

	path := strings.TrimPrefix(expr, prefix)
	if path == "" {
		return nil, fmt.Errorf("invalid sub expression %q: missing claim path after `subjectToken.`", subExpr)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject token claims: %w", err)
	}

	result := gjson.GetBytes(claimsJSON, path)
	if !result.Exists() {
		return nil, fmt.Errorf("%w: path %q (from sub expression %q)", tokeneteserrors.ErrSubjectFieldNotFound, path, subExpr)
	}

	return result.Value(), nil
}

func (gri *GenerationRulesImp) GetTokenLifetime() (time.Duration, error) {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	duration, err := time.ParseDuration(gri.generationRules.TokenetesConfigGenerationRule.Token.LifeTime)
	if err != nil {
		return 0, fmt.Errorf("error parsing token lifetime: %v", err)
	}

	return duration, nil
}

func (gri *GenerationRulesImp) EvaluateAccess(txnTokenRequest *common.TokenRequest, subjectTokenClaims interface{}) (bool, error) {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	if gri.accessevaluator == nil {
		return true, nil
	}

	generationTraTRule, pathParameter, err := gri.matchRule(txnTokenRequest.RequestDetails.Path, txnTokenRequest.RequestDetails.Method)
	if err != nil {
		return false, fmt.Errorf("error matching generation rule for %s path and %s method: %w", txnTokenRequest.RequestDetails.Path, string(txnTokenRequest.RequestDetails.Method), err)
	}

	return gri.accessevaluator.Evaluate(generationTraTRule.AccessEvaluation.Map, subjectTokenClaims, txnTokenRequest.RequestDetails, txnTokenRequest.RequestContext, pathParameter)
}

func (gri *GenerationRulesImp) GetSubjectTokenHandler(tokenType common.TokenType) (subjecttokenhandler.TokenHandler, error) {
	return gri.subjectTokenHandlers.GetHandler(tokenType)
}

func (gri *GenerationRulesImp) GetTokenGenerationAuthorizedServiceIds() ([]spiffeid.ID, error) {
	if gri.generationRules.TokenetesConfigGenerationRule == nil {
		return []spiffeid.ID{}, nil
	}

	stringIDs := gri.generationRules.TokenetesConfigGenerationRule.TokenGenerationAuthorizedServiceIds
	spiffeIDs := make([]spiffeid.ID, 0, len(stringIDs))

	for _, idStr := range stringIDs {
		id, err := spiffeid.FromString(idStr)
		if err != nil {
			return nil, err
		}

		spiffeIDs = append(spiffeIDs, id)
	}

	return spiffeIDs, nil
}

func (gri *GenerationRulesImp) UpdateCompleteRules(generationRules *GenerationRules) {
	gri.mu.Lock()
	defer gri.mu.Unlock()

	gri.generationRules = generationRules

	if gri.generationRules.TokenetesConfigGenerationRule != nil {
		if gri.generationRules.TokenetesConfigGenerationRule.SubjectTokens == nil {
			gri.subjectTokenHandlers = nil
		} else {
			gri.subjectTokenHandlers = subjecttokenhandler.NewTokenHandlers(*gri.generationRules.TokenetesConfigGenerationRule.SubjectTokens, logging.GetLogger("subject-token-handler"))
		}

		if gri.generationRules.TokenetesConfigGenerationRule.AccessEvaluationAPI == nil {
			gri.accessevaluator = nil
		} else {
			gri.accessevaluator = accessevaluation.NewAccessEvaluator(*gri.generationRules.TokenetesConfigGenerationRule.AccessEvaluationAPI, gri.httpClient, logging.GetLogger("access-evaluator"))
		}
	}

	gri.indexTraTsGenerationRules()
}

func (generationRules *GenerationRules) ComputeStableHash() (string, error) {
	data, err := json.Marshal(generationRules)
	if err != nil {
		return "", fmt.Errorf("failed to marshal rules: %w", err)
	}

	var jsonData interface{}

	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal for canonicalization: %w", err)
	}

	canonicalizedData, err := utils.CanonicalizeJSON(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	hash := sha256.Sum256([]byte(canonicalizedData))

	return hex.EncodeToString(hash[:]), nil
}

func (gri *GenerationRulesImp) GetGenerationRulesHash() (string, error) {
	gri.mu.RLock()
	defer gri.mu.RUnlock()

	return gri.generationRules.ComputeStableHash()
}
