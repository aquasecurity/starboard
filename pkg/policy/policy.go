package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	keyPrefixPolicy  = "policy."
	keyPrefixLibrary = "library."
	keySuffixKinds   = ".kinds"
	keySuffixRego    = ".rego"
)

const (
	kindAny      = "*"
	kindWorkload = "Workload"
)

// Metadata describes policy metadata.
type Metadata struct {
	ID          string
	Title       string
	Severity    v1alpha1.Severity
	Type        string
	Description string
}

// NewMetadata constructs new Metadata based on raw values.
func NewMetadata(values map[string]interface{}) (Metadata, error) {
	if values == nil {
		return Metadata{}, errors.New("values must not be nil")
	}
	severityString, err := requiredStringValue(values, "severity")
	if err != nil {
		return Metadata{}, err
	}
	severity, err := v1alpha1.StringToSeverity(severityString)
	if err != nil {
		return Metadata{}, fmt.Errorf("failed parsing severity: %w", err)
	}
	id, err := requiredStringValue(values, "id")
	if err != nil {
		return Metadata{}, err
	}
	title, err := requiredStringValue(values, "title")
	if err != nil {
		return Metadata{}, err
	}
	policyType, err := requiredStringValue(values, "type")
	if err != nil {
		return Metadata{}, err
	}
	description, err := requiredStringValue(values, "description")
	if err != nil {
		return Metadata{}, err
	}

	return Metadata{
		Severity:    severity,
		ID:          id,
		Title:       title,
		Type:        policyType,
		Description: description,
	}, nil
}

// Result describes result of evaluating a policy.
type Result struct {
	Message string
}

// NewResult constructs new Result based on raw values.
func NewResult(values map[string]interface{}) (Result, error) {
	if values == nil {
		return Result{}, errors.New("values must not be nil")
	}
	message, err := requiredStringValue(values, "msg")
	if err != nil {
		return Result{}, err
	}
	return Result{
		Message: message,
	}, nil
}

type Policies struct {
	data map[string]string
}

func NewPolicies(data map[string]string) *Policies {
	return &Policies{
		data: data,
	}
}

func (p *Policies) Libraries() map[string]string {
	libs := make(map[string]string)
	for key, value := range p.data {
		if !strings.HasPrefix(key, keyPrefixLibrary) {
			continue
		}
		if !strings.HasSuffix(key, keySuffixRego) {
			continue
		}
		libs[key] = value
	}
	return libs
}

func (p *Policies) PoliciesByKind(kind string) (map[string]string, error) {
	policies := make(map[string]string)
	for key, value := range p.data {
		if strings.HasSuffix(key, keySuffixRego) && strings.HasPrefix(key, keyPrefixPolicy) {
			// Check if kinds were defined for this policy
			kindsKey := strings.TrimSuffix(key, keySuffixRego) + keySuffixKinds
			if _, ok := p.data[kindsKey]; !ok {
				return nil, fmt.Errorf("kinds not defined for policy: %s", key)
			}
		}

		if !strings.HasSuffix(key, keySuffixKinds) {
			continue
		}
		for _, k := range strings.Split(value, ",") {
			if k == kindWorkload && !kube.IsWorkload(kind) {
				continue
			}
			if k != kindAny && k != kindWorkload && k != kind {
				continue
			}

			policyKey := strings.TrimSuffix(key, keySuffixKinds) + keySuffixRego
			var ok bool

			policies[policyKey], ok = p.data[policyKey]
			if !ok {
				return nil, fmt.Errorf("expected policy not found: %s", policyKey)
			}
		}
	}
	return policies, nil
}

func (p *Policies) Hash(kind string) (string, error) {
	modules, err := p.ModulesByKind(kind)
	if err != nil {
		return "", err
	}
	return kube.ComputeHash(modules), nil
}

func (p *Policies) ModulesByKind(kind string) (map[string]string, error) {
	modules, err := p.PoliciesByKind(kind)
	if err != nil {
		return nil, err
	}
	for key, value := range p.Libraries() {
		modules[key] = value
	}
	return modules, nil
}

func (p *Policies) Applicable(resource client.Object) (bool, string, error) {
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return false, "", errors.New("resource kind must not be blank")
	}
	policies, err := p.PoliciesByKind(resourceKind)
	if err != nil {
		return false, "", err
	}
	if len(policies) == 0 {
		return false, fmt.Sprintf("no policies found for kind %s", resource.GetObjectKind().GroupVersionKind().Kind), nil
	}
	return true, "", nil
}

// Eval evaluates Rego policies with Kubernetes resource client.Object as input.
//
// TODO(danielpacak) Compile and cache prepared queries to make Eval more efficient.
//                   We can reuse prepared queries so long policies do not change.
func (p *Policies) Eval(ctx context.Context, resource client.Object) ([]v1alpha1.Check, error) {
	if resource == nil {
		return nil, fmt.Errorf("resource must not be nil")
	}
	resourceKind := resource.GetObjectKind().GroupVersionKind().Kind
	if resourceKind == "" {
		return nil, fmt.Errorf("resource kind must not be blank")
	}

	checks := make([]v1alpha1.Check, 0)

	policies, err := p.PoliciesByKind(resourceKind)
	if err != nil {
		return nil, fmt.Errorf("failed listing policies by kind: %s: %w", resourceKind, err)
	}

	for policyName, policyCode := range policies {
		parsedModules := make(map[string]*ast.Module)

		for libraryName, libraryCode := range p.Libraries() {
			var parsedLibrary *ast.Module
			parsedLibrary, err = ast.ParseModule(libraryName, libraryCode)
			if err != nil {
				return nil, fmt.Errorf("failed parsing Rego library: %s: %w", libraryName, err)
			}
			parsedModules[libraryName] = parsedLibrary
		}

		parsedPolicy, err := ast.ParseModule(policyName, policyCode)
		if err != nil {
			return nil, fmt.Errorf("failed parsing Rego policy: %s: %w", policyName, err)
		}
		parsedModules[policyName] = parsedPolicy

		compiler := ast.NewCompiler()
		compiler.Compile(parsedModules)
		if compiler.Failed() {
			return nil, fmt.Errorf("failed compiling Rego policy: %s: %w", policyName, compiler.Errors)
		}

		metadataQuery := fmt.Sprintf("md = %s.__rego_metadata__", parsedPolicy.Package.Path.String())
		metadata, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(metadataQuery),
		).Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed evaluating Rego metadata rule: %s: %w", metadataQuery, err)
		}

		metadataResult, hasMetadataResult := hasBinding(metadata, "md")

		if !hasMetadataResult {
			return nil, fmt.Errorf("failed parsing policy metadata: %s", policyName)
		}

		md, err := NewMetadata(metadataResult)
		if err != nil {
			return nil, fmt.Errorf("failed parsing policy metadata: %s: %w", policyName, err)
		}

		denyQuery := fmt.Sprintf("%s.deny[res]", parsedPolicy.Package.Path.String())
		deny, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(denyQuery),
			rego.Input(resource),
		).Eval(ctx)

		if err != nil {
			return nil, fmt.Errorf("failed evaluating Rego deny rule: %s: %w", denyQuery, err)
		}

		denyResults, hasDenyResults := hasBindings(deny, "res")
		if hasDenyResults {
			denyChecks, err := valuesToChecks(md, denyResults)
			if err != nil {
				return nil, fmt.Errorf("failed parsing deny rule result: %s: %w", denyQuery, err)
			}
			checks = append(checks, denyChecks...)
			continue
		}

		warnQuery := fmt.Sprintf("%s.warn[res]", parsedPolicy.Package.Path.String())
		warn, err := rego.New(
			rego.Compiler(compiler),
			rego.Query(warnQuery),
			rego.Input(resource),
		).Eval(ctx)

		if err != nil {
			return nil, fmt.Errorf("failed evaluating Rego warn rule: %s: %w", warnQuery, err)
		}

		warnResults, hasWarnResults := hasBindings(warn, "res")
		if hasWarnResults {
			warnChecks, err := valuesToChecks(md, warnResults)
			if err != nil {
				return nil, fmt.Errorf("failed parsing warn rule result: %s: %w", warnQuery, err)
			}
			checks = append(checks, warnChecks...)
			continue
		}

		checks = append(checks, v1alpha1.Check{
			Success:     true,
			ID:          md.ID,
			Title:       md.Title,
			Severity:    md.Severity,
			Category:    md.Type,
			Description: md.Description,
		})
	}

	return checks, nil
}

func hasBinding(rs rego.ResultSet, key string) (map[string]interface{}, bool) {
	if rs == nil || len(rs) == 0 {
		return nil, false
	}
	binding, ok := rs[0].Bindings[key]
	return binding.(map[string]interface{}), ok
}

func hasBindings(rs rego.ResultSet, key string) ([]map[string]interface{}, bool) {
	if rs == nil || len(rs) == 0 {
		return nil, false
	}
	var values []map[string]interface{}

	for _, r := range rs {
		binding, ok := r.Bindings[key]
		if !ok {
			continue
		}
		value, ok := binding.(map[string]interface{})
		if !ok {
			continue
		}
		values = append(values, value)
	}
	return values, len(rs) == len(values)
}

func requiredStringValue(values map[string]interface{}, key string) (string, error) {
	value, ok := values[key]
	if !ok {
		return "", fmt.Errorf("required key not found: %s", key)
	}
	if value == nil {
		return "", fmt.Errorf("required value is nil for key: %s", key)
	}
	valueString, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("expected string got %T for key: %s", value, key)
	}
	if valueString == "" {
		return "", fmt.Errorf("required value is blank for key: %s", key)
	}
	return valueString, nil
}

func valuesToChecks(md Metadata, values []map[string]interface{}) ([]v1alpha1.Check, error) {
	var checks []v1alpha1.Check
	var messages []string

	for _, value := range values {
		result, err := NewResult(value)
		if err != nil {
			return nil, err
		}
		messages = append(messages, result.Message)
	}

	checks = append(checks, v1alpha1.Check{
		Success:     false,
		ID:          md.ID,
		Title:       md.Title,
		Severity:    md.Severity,
		Category:    md.Type,
		Description: md.Description,
		Messages:    messages,
	})
	return checks, nil
}
