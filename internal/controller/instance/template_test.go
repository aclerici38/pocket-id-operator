package instance

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	pocketidinternalv1alpha1 "github.com/aclerici38/pocket-id-operator/api/v1alpha1"
)

func findServicePort(ports []corev1.ServicePort, name string) *corev1.ServicePort {
	for i := range ports {
		if ports[i].Name == name {
			return &ports[i]
		}
	}
	return nil
}

func TestBuildServiceSpec_NoTemplate(t *testing.T) {
	inst := minimalInstance()

	spec := buildServiceSpec(inst)

	if spec.Selector["app.kubernetes.io/name"] != appName {
		t.Errorf("missing app.kubernetes.io/name selector")
	}
	if spec.Selector["app.kubernetes.io/instance"] != inst.Name {
		t.Errorf("missing app.kubernetes.io/instance selector")
	}
	http := findServicePort(spec.Ports, "http")
	if http == nil || http.Port != 1411 {
		t.Fatalf("expected http port 1411, got %+v", spec.Ports)
	}
}

func TestBuildServiceSpec_MetricsPort(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Metrics = &pocketidinternalv1alpha1.MetricsConfig{Enabled: true, Port: 9000}

	spec := buildServiceSpec(inst)

	metrics := findServicePort(spec.Ports, "metrics")
	if metrics == nil || metrics.Port != 9000 {
		t.Fatalf("expected metrics port 9000, got %+v", spec.Ports)
	}
}

func TestBuildServiceSpec_TemplateFieldsPassThrough(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.ServiceTemplate = &corev1.ServiceSpec{
		Type:            corev1.ServiceTypeLoadBalancer,
		SessionAffinity: corev1.ServiceAffinityClientIP,
		Ports: []corev1.ServicePort{
			{Name: "extra", Port: 8080, Protocol: corev1.ProtocolTCP},
		},
	}

	spec := buildServiceSpec(inst)

	if spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("type: got %q, want LoadBalancer", spec.Type)
	}
	if spec.SessionAffinity != corev1.ServiceAffinityClientIP {
		t.Errorf("sessionAffinity not passed through: %q", spec.SessionAffinity)
	}
	// Operator http port and user's extra port both present
	if findServicePort(spec.Ports, "http") == nil {
		t.Error("operator http port missing")
	}
	if findServicePort(spec.Ports, "extra") == nil {
		t.Error("user's extra port missing")
	}
}

func TestBuildServiceSpec_OperatorFieldsWin(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.ServiceTemplate = &corev1.ServiceSpec{
		// User attempts to override the operator-managed selector and http port
		Selector: map[string]string{"app.kubernetes.io/name": "evil"},
		Ports: []corev1.ServicePort{
			{Name: "http", Port: 9999},
		},
	}

	spec := buildServiceSpec(inst)

	if spec.Selector["app.kubernetes.io/name"] != appName {
		t.Errorf("operator selector should win, got %q", spec.Selector["app.kubernetes.io/name"])
	}
	http := findServicePort(spec.Ports, "http")
	if http == nil || http.Port != 1411 {
		t.Errorf("operator http port should win, got %+v", http)
	}
	if len(spec.Ports) != 1 {
		t.Errorf("expected http port to be merged by name, got %d ports", len(spec.Ports))
	}
}

func TestBuildHTTPRouteSpec_DefaultRuleAlwaysFirst(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Route = &pocketidinternalv1alpha1.HTTPRouteConfig{
		Enabled:    true,
		ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
	}

	spec := buildHTTPRouteSpec(inst)

	if len(spec.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(spec.Rules))
	}
	refs := spec.Rules[0].BackendRefs
	if len(refs) != 1 || string(refs[0].Name) != inst.Name {
		t.Errorf("default backend ref should target %q, got %+v", inst.Name, refs)
	}
	if refs[0].Port == nil || *refs[0].Port != 1411 {
		t.Errorf("default backend port should be 1411, got %+v", refs[0].Port)
	}
}

func TestBuildHTTPRouteSpec_TemplateRulesAppended(t *testing.T) {
	inst := minimalInstance()
	pathPrefix := gatewayv1.PathMatchPathPrefix
	custom := "/custom"
	inst.Spec.Route = &pocketidinternalv1alpha1.HTTPRouteConfig{
		Enabled:    true,
		ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
		Template: &gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{
						{Path: &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: &custom}},
					},
				},
			},
		},
	}

	spec := buildHTTPRouteSpec(inst)

	if len(spec.Rules) != 2 {
		t.Fatalf("expected 2 rules (default + template), got %d", len(spec.Rules))
	}
	// Default backend rule stays first
	if len(spec.Rules[0].BackendRefs) != 1 || string(spec.Rules[0].BackendRefs[0].Name) != inst.Name {
		t.Errorf("default rule should be first, got %+v", spec.Rules[0])
	}
	// Template rule appended after
	if len(spec.Rules[1].Matches) != 1 {
		t.Errorf("template rule should be appended, got %+v", spec.Rules[1])
	}
}

func TestBuildHTTPRouteSpec_ParentRefsFromConfigWin(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Route = &pocketidinternalv1alpha1.HTTPRouteConfig{
		Enabled:    true,
		ParentRefs: []gatewayv1.ParentReference{{Name: "config-gateway"}},
		Template: &gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "template-gateway"}},
			},
		},
	}

	spec := buildHTTPRouteSpec(inst)

	if len(spec.ParentRefs) != 1 || string(spec.ParentRefs[0].Name) != "config-gateway" {
		t.Errorf("config parentRefs should win, got %+v", spec.ParentRefs)
	}
}

func TestBuildHTTPRouteSpec_HostnamesFromAppURL(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.AppURL = "https://id.example.com"
	inst.Spec.Route = &pocketidinternalv1alpha1.HTTPRouteConfig{
		Enabled:    true,
		ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
	}

	spec := buildHTTPRouteSpec(inst)

	if len(spec.Hostnames) != 1 || spec.Hostnames[0] != "id.example.com" {
		t.Errorf("hostname should derive from appUrl, got %+v", spec.Hostnames)
	}
}

func TestBuildHTTPRouteSpec_ExplicitHostnamesWin(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.AppURL = "https://id.example.com"
	inst.Spec.Route = &pocketidinternalv1alpha1.HTTPRouteConfig{
		Enabled:    true,
		ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
		Hostnames:  []gatewayv1.Hostname{"explicit.example.com"},
	}

	spec := buildHTTPRouteSpec(inst)

	if len(spec.Hostnames) != 1 || spec.Hostnames[0] != "explicit.example.com" {
		t.Errorf("explicit hostnames should win over appUrl, got %+v", spec.Hostnames)
	}
}

func TestBuildHTTPRouteSpec_TemplateHostnamesKeptWhenNoneSet(t *testing.T) {
	inst := minimalInstance()
	inst.Spec.Route = &pocketidinternalv1alpha1.HTTPRouteConfig{
		Enabled:    true,
		ParentRefs: []gatewayv1.ParentReference{{Name: "gateway"}},
		Template: &gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"template.example.com"},
		},
	}

	spec := buildHTTPRouteSpec(inst)

	if len(spec.Hostnames) != 1 || spec.Hostnames[0] != "template.example.com" {
		t.Errorf("template hostnames should be kept when no config/appUrl, got %+v", spec.Hostnames)
	}
}
