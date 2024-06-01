package controllers

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmgen "github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/cloudflare/origin-ca-issuer/internal/cfapi"
	v1 "github.com/cloudflare/origin-ca-issuer/pkgs/apis/v1"
	"gotest.tools/v3/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	fakeClock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestCertificateRequestReconcile(t *testing.T) {
	if err := cmapi.AddToScheme(scheme.Scheme); err != nil {
		t.Fatal(err)
	}

	if err := v1.AddToScheme(scheme.Scheme); err != nil {
		t.Fatal(err)
	}

	clock := fakeClock.NewFakeClock(time.Now().Truncate(time.Second))
	now := metav1.NewTime(clock.Now())

	cmutil.Clock = clock

	tests := []struct {
		name          string
		objects       []runtime.Object
		signer        SignerFunc
		expected      cmapi.CertificateRequestStatus
		error         string
		namespaceName types.NamespacedName
	}{
		{
			name: "working",
			objects: []runtime.Object{
				cmgen.CertificateRequest("foobar",
					cmgen.SetCertificateRequestNamespace("default"),
					cmgen.SetCertificateRequestDuration(&metav1.Duration{Duration: 7 * 24 * time.Hour}),
					cmgen.SetCertificateRequestCSR((func() []byte {
						csr, _, err := cmgen.CSR(x509.ECDSA)
						if err != nil {
							t.Fatalf("creating CSR: %s", err)
						}

						return csr
					})()),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "foobar",
						Kind:  "OriginIssuer",
						Group: "cert-manager.k8s.cloudflare.com",
					}),
				),
				&v1.OriginIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foobar",
						Namespace: "default",
					},
					Spec: v1.OriginIssuerSpec{
						Auth: v1.OriginIssuerAuthentication{
							ServiceKeyRef: v1.SecretKeySelector{
								Name: "service-key-issuer",
								Key:  "key",
							},
						},
					},
					Status: v1.OriginIssuerStatus{
						Conditions: []v1.OriginIssuerCondition{
							{
								Type:   v1.ConditionReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service-key-issuer",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"key": []byte("djEuMC0weDAwQkFCMTBD"),
					},
				},
			},
			signer: SignerFunc(func(ctx context.Context, sr *cfapi.SignRequest) (*cfapi.SignResponse, error) {
				return &cfapi.SignResponse{
					Id:          "1",
					Certificate: "bogus",
					Hostnames:   []string{"example.com"},
					Expiration:  time.Time{},
					Type:        "colemak",
					Validity:    0,
					CSR:         "foobar",
				}, nil
			}),
			expected: cmapi.CertificateRequestStatus{
				Conditions: []cmapi.CertificateRequestCondition{
					{
						Type:               cmapi.CertificateRequestConditionReady,
						Status:             cmmeta.ConditionTrue,
						LastTransitionTime: &now,
						Reason:             "Issued",
						Message:            "Certificate issued",
					},
				},
				Certificate: []byte("bogus"),
			},
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foobar",
			},
		},
		{
			name: "requeue after API error",
			objects: []runtime.Object{
				cmgen.CertificateRequest("foobar",
					cmgen.SetCertificateRequestNamespace("default"),
					cmgen.SetCertificateRequestDuration(&metav1.Duration{Duration: 7 * 24 * time.Hour}),
					cmgen.SetCertificateRequestCSR((func() []byte {
						csr, _, err := cmgen.CSR(x509.ECDSA)
						if err != nil {
							t.Fatalf("creating CSR: %s", err)
						}

						return csr
					})()),
					cmgen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
						Name:  "foobar",
						Kind:  "OriginIssuer",
						Group: "cert-manager.k8s.cloudflare.com",
					}),
				),
				&v1.OriginIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foobar",
						Namespace: "default",
					},
					Spec: v1.OriginIssuerSpec{
						Auth: v1.OriginIssuerAuthentication{
							ServiceKeyRef: v1.SecretKeySelector{
								Name: "service-key-issuer",
								Key:  "key",
							},
						},
					},
					Status: v1.OriginIssuerStatus{
						Conditions: []v1.OriginIssuerCondition{
							{
								Type:   v1.ConditionReady,
								Status: v1.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "service-key-issuer",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"key": []byte("djEuMC0weDAwQkFCMTBD"),
					},
				},
			},
			signer: SignerFunc(func(ctx context.Context, sr *cfapi.SignRequest) (*cfapi.SignResponse, error) {
				return nil, &cfapi.APIError{
					Code:    1100,
					Message: "Failed to write certificate to Database",
					RayID:   "7d3eb086eedab98e",
				}
			}),
			namespaceName: types.NamespacedName{
				Namespace: "default",
				Name:      "foobar",
			},
			error: "unable to sign request: Cloudflare API Error code=1100 message=Failed to write certificate to Database ray_id=7d3eb086eedab98e",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithRuntimeObjects(tt.objects...).
				WithStatusSubresource(&cmapi.CertificateRequest{}).
				Build()

			controller := &CertificateRequestController{
				Client: client,
				Reader: client,
				Log:    logf.Log,
				Factory: cfapi.FactoryFunc(func(serviceKey []byte) (cfapi.Interface, error) {
					return tt.signer, nil
				}),
			}

			_, err := reconcile.AsReconciler(client, controller).Reconcile(context.Background(), reconcile.Request{
				NamespacedName: tt.namespaceName,
			})

			if err != nil {
				assert.Error(t, err, tt.error)
			} else {
				assert.NilError(t, err)
			}

			got := &cmapi.CertificateRequest{}
			assert.NilError(t, client.Get(context.TODO(), tt.namespaceName, got))
			assert.DeepEqual(t, got.Status, tt.expected)
		})
	}
}

type SignerFunc func(context.Context, *cfapi.SignRequest) (*cfapi.SignResponse, error)

func (f SignerFunc) Sign(ctx context.Context, req *cfapi.SignRequest) (*cfapi.SignResponse, error) {
	return f(ctx, req)
}
