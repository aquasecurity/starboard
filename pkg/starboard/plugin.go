package starboard

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PluginContext is plugin's execution context within the Starboard toolkit.
// The context is used to grant access to other methods so that this plugin
// can interact with the toolkit.
type PluginContext interface {
	// GetName returns the name of the plugin.
	GetName() string
	// GetConfig returns the v1.ConfigMap object that holds configuration settings of the plugin.
	GetConfig() (*corev1.ConfigMap, error)
	// GetNamespace return the name of the K8s Namespace where Starboard creates Jobs
	// and other helper objects.
	GetNamespace() string
	// GetServiceAccountName return the name of the K8s Service Account used to run workloads
	// created by Starboard.
	GetServiceAccountName() string
}

// GetPluginConfigMapName returns the name of a ConfigMap used to configure a plugin
// with the given name.
func GetPluginConfigMapName(pluginName string) string {
	return "starboard-" + strings.ToLower(pluginName) + "-config"
}

type pluginContext struct {
	name               string
	client             client.Client
	namespace          string
	serviceAccountName string
}

func (p *pluginContext) GetName() string {
	return p.name
}

func (p *pluginContext) GetConfig() (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	err := p.client.Get(context.Background(), types.NamespacedName{
		Namespace: p.namespace,
		Name:      fmt.Sprintf("starboard-%s-config", strings.ToLower(p.GetName())),
	}, cm)
	return cm.DeepCopy(), err
}

func (p *pluginContext) GetNamespace() string {
	return p.namespace
}

func (p *pluginContext) GetServiceAccountName() string {
	return p.serviceAccountName
}

type PluginContextBuilder struct {
	ctx *pluginContext
}

func NewPluginContext() *PluginContextBuilder {
	return &PluginContextBuilder{
		ctx: &pluginContext{},
	}
}

func (b *PluginContextBuilder) WithName(name string) *PluginContextBuilder {
	b.ctx.name = name
	return b
}

func (b *PluginContextBuilder) WithClient(client client.Client) *PluginContextBuilder {
	b.ctx.client = client
	return b
}

func (b *PluginContextBuilder) WithNamespace(namespace string) *PluginContextBuilder {
	b.ctx.namespace = namespace
	return b
}

func (b *PluginContextBuilder) WithServiceAccountName(name string) *PluginContextBuilder {
	b.ctx.serviceAccountName = name
	return b
}

func (b *PluginContextBuilder) Build() PluginContext {
	return b.ctx
}
