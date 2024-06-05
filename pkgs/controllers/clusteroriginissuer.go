package controllers

import (
	"context"
	"fmt"

	"github.com/cloudflare/origin-ca-issuer/internal/cfapi"
	v1 "github.com/cloudflare/origin-ca-issuer/pkgs/apis/v1"
	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ClusterOriginIssuerController implements a controller that watches for changes
// to OriginIssuer resources.
type ClusterOriginIssuerController struct {
	client.Client
	Reader                   client.Reader
	ClusterResourceNamespace string
	Log                      logr.Logger
	Clock                    clock.Clock
	Factory                  cfapi.Factory
}

//go:generate controller-gen rbac:roleName=originissuer-control paths=./. output:rbac:artifacts:config=../../deploy/rbac

// +kubebuilder:rbac:groups=cert-manager.k8s.cloudflare.com,resources=clusteroriginissuers,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=cert-manager.k8s.cloudflare.com,resources=clusteroriginissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile reconciles ClusterOriginIssuer resources by managing Cloudflare API provisioners.
func (r *ClusterOriginIssuerController) Reconcile(ctx context.Context, iss *v1.ClusterOriginIssuer) (reconcile.Result, error) {
	log := r.Log.WithValues("namespace", iss.Namespace, "clusteroriginissuer", iss.Name)

	if err := validateOriginIssuer(iss.Spec); err != nil {
		log.Error(err, "failed to validate ClusterOriginIssuer resource")

		return reconcile.Result{}, err
	}

	secret := core.Secret{}
	secretNamespaceName := types.NamespacedName{
		Namespace: r.ClusterResourceNamespace,
		Name:      iss.Spec.Auth.ServiceKeyRef.Name,
	}

	if err := r.Reader.Get(ctx, secretNamespaceName, &secret); err != nil {
		log.Error(err, "failed to retieve ClusterOriginIssuer auth secret", "namespace", secretNamespaceName.Namespace, "name", secretNamespaceName.Name)

		if apierrors.IsNotFound(err) {
			_ = r.setStatus(ctx, iss, v1.ConditionFalse, "NotFound", fmt.Sprintf("Failed to retrieve auth secret: %v", err))
		} else {
			_ = r.setStatus(ctx, iss, v1.ConditionFalse, "Error", fmt.Sprintf("Failed to retrieve auth secret: %v", err))
		}

		return reconcile.Result{}, err
	}

	_, ok := secret.Data[iss.Spec.Auth.ServiceKeyRef.Key]
	if !ok {
		err := fmt.Errorf("secret %s does not contain key %q", secret.Name, iss.Spec.Auth.ServiceKeyRef.Key)
		log.Error(err, "failed to retrieve ClusterOriginIssuer auth secret")
		_ = r.setStatus(ctx, iss, v1.ConditionFalse, "NotFound", fmt.Sprintf("Failed to retrieve auth secret: %v", err))

		return reconcile.Result{}, err
	}

	return reconcile.Result{}, r.setStatus(ctx, iss, v1.ConditionTrue, "Verified", "ClusterOriginIssuer verified and ready to sign certificates")
}

// setStatus is a helper function to set the Issuer status condition with reason and message, and update the API.
func (r *ClusterOriginIssuerController) setStatus(ctx context.Context, iss *v1.ClusterOriginIssuer, status v1.ConditionStatus, reason, message string) error {
	SetIssuerStatusCondition(&iss.Status, v1.ConditionReady, status, r.Log, r.Clock, reason, message)

	return r.Client.Status().Update(ctx, iss)
}
