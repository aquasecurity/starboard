package starboard

// PluginContext is plugin's execution context within the Starboard toolkit.
// The context is used to grant access to other methods so that this plugin
// can interact with the toolkit.
type PluginContext interface {
	// GetNamespace return the name of the K8s Namespace where Starboard creates Jobs
	// and other helper objects.
	GetNamespace() string
	// GetServiceAccountName return the name of the K8s Service Account used to run workloads
	// created by Starboard.
	GetServiceAccountName() string
}

type pluginContext struct {
	namespace          string
	serviceAccountName string
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
