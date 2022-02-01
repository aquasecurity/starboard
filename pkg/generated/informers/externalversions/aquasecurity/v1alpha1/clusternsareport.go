// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	aquasecurityv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	versioned "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"
	internalinterfaces "github.com/aquasecurity/starboard/pkg/generated/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/aquasecurity/starboard/pkg/generated/listers/aquasecurity/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ClusterNsaReportInformer provides access to a shared informer and lister for
// ClusterNsaReports.
type ClusterNsaReportInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ClusterNsaReportLister
}

type clusterNsaReportInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewClusterNsaReportInformer constructs a new informer for ClusterNsaReport type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewClusterNsaReportInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredClusterNsaReportInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredClusterNsaReportInformer constructs a new informer for ClusterNsaReport type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredClusterNsaReportInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AquasecurityV1alpha1().ClusterNsaReports().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.AquasecurityV1alpha1().ClusterNsaReports().Watch(context.TODO(), options)
			},
		},
		&aquasecurityv1alpha1.ClusterNsaReport{},
		resyncPeriod,
		indexers,
	)
}

func (f *clusterNsaReportInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredClusterNsaReportInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *clusterNsaReportInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&aquasecurityv1alpha1.ClusterNsaReport{}, f.defaultInformer)
}

func (f *clusterNsaReportInformer) Lister() v1alpha1.ClusterNsaReportLister {
	return v1alpha1.NewClusterNsaReportLister(f.Informer().GetIndexer())
}