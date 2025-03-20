package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/applicationcredentials"
	keystonecommon "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1" // for GetKeystoneAPI, etc.
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	ctrlLog "sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconciler
type ApplicationCredentialReconciler struct {
	client.Client
	Kclient kubernetes.Interface
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

// +kubebuilder:rbac:groups=keystone.openstack.org,resources=applicationcredentials,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=applicationcredentials/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=applicationcredentials/finalizers,verbs=update;patch
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;create;update;delete;patch

func (r *ApplicationCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.GetLogger(ctx)

	instance := &keystonev1.ApplicationCredential{}
	if err := r.Client.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	helperObj, err := helper.NewHelper(
		instance,
		r.Client,
		r.Kclient,
		r.Scheme,
		logger,
	)
	if err != nil {
		return ctrl.Result{}, err
	}

	// initialize conditions if needed
	isNew := instance.Status.Conditions == nil
	if isNew {
		instance.Status.Conditions = condition.Conditions{}
	}
	savedConditions := instance.Status.Conditions.DeepCopy()

	// always patch on exit
	defer func() {
		condition.RestoreLastTransitionTimes(&instance.Status.Conditions, savedConditions)
		if instance.Status.Conditions.IsUnknown(condition.ReadyCondition) {
			instance.Status.Conditions.Set(instance.Status.Conditions.Mirror(condition.ReadyCondition))
		}
		_ = helperObj.PatchInstance(ctx, instance)
	}()

	// ensure ReadyCondition in init
	condList := condition.CreateList(
		condition.UnknownCondition(condition.ReadyCondition, condition.InitReason, condition.ReadyInitMessage),
	)
	instance.Status.Conditions.Init(&condList)

	// handle deletion
	if !instance.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, instance, helperObj)
	}

	return r.reconcileNormal(ctx, instance, helperObj)
}

// reconcileNormal
func (r *ApplicationCredentialReconciler) reconcileNormal(
	ctx context.Context,
	instance *keystonev1.ApplicationCredential,
	helperObj *helper.Helper,
) (ctrl.Result, error) {

	logger := r.GetLogger(ctx)

	// finalize
	if controllerutil.AddFinalizer(instance, fmt.Sprintf("%s-%s", helperObj.GetFinalizer(), instance.Name)) {
		if err := r.Update(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
		// short-circuit so next pass sees finalizer
		return ctrl.Result{}, nil
	}

	// fetch keystoneAPI
	keystoneAPI, err := keystonecommon.GetKeystoneAPI(ctx, helperObj, instance.Namespace, nil)
	if err != nil {
		logger.Info("KeystoneAPI not found, requeue", "error", err)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if !keystoneAPI.IsReady() {
		logger.Info("KeystoneAPI not ready, requeue")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// check if AC is missing
	if instance.Status.ACID == "" || r.isExpiringSoon(instance) {
		logger.Info("AC missing or expiring soon, proceed with creation")

		userID, err := r.findUserIDAsAdmin(ctx, helperObj, keystoneAPI, instance.Spec.UserName)
		if err != nil {
			logger.Error(err, "Failed to find user ID")
			return ctrl.Result{}, err
		}
		logger.Info("Got user ID", "userName", instance.Spec.UserName, "userID", userID)

		userOS, ctrlResult, err := keystonecommon.GetUserServiceClient(ctx, helperObj, keystoneAPI, instance.Spec.UserName)
		if err != nil {
			return ctrlResult, err
		}
		if ctrlResult != (ctrl.Result{}) {
			return ctrlResult, nil
		}

		newID, newSecret, err := r.createACInKeystone(logger, userOS.GetOSClient(), userID, instance)
		if err != nil {
			logger.Error(err, "AppCred creation failed")
			// set condition to error
			instance.Status.Conditions.Set(condition.FalseCondition(
				condition.ReadyCondition,
				condition.ErrorReason,
				condition.SeverityWarning,
				"Failed to create app cred",
				err.Error(),
			))
			return ctrl.Result{}, err
		}
		logger.Info("Created AC in Keystone", "ACID", newID)

		secretName := fmt.Sprintf("%s-secret", instance.Name)
		if err := r.ensureACSecret(ctx, helperObj, instance, secretName, newID, newSecret); err != nil {
			logger.Error(err, "Failed to store AC in secret")
			return ctrl.Result{}, err
		}

		instance.Status.ACID = newID
		instance.Status.SecretName = secretName

		instance.Status.Conditions.MarkTrue(condition.ReadyCondition, "ApplicationCredential is ready")
		// patch .status so that next pass sees ACID
		if patchErr := helperObj.PatchInstance(ctx, instance); patchErr != nil {
			return ctrl.Result{}, patchErr
		}

		logger.Info("Patched CR status with ACID, short-circuiting this pass")

		// to avoid re-run in same pass, explicitly re-fetch the CR so we see updated resourceVersion
		if err := r.Client.Get(ctx, types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, instance); err == nil {
			logger.Info("Re-fetched CR, now ACID is", "ACID", instance.Status.ACID)
		}

		return ctrl.Result{}, nil

	} else {
		// AC already exists
		logger.Info("AC is up to date", "ACID", instance.Status.ACID)
		instance.Status.Conditions.MarkTrue(condition.ReadyCondition, "AC is up to date")
		if err := helperObj.PatchInstance(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
}

// reconcileDelete
func (r *ApplicationCredentialReconciler) reconcileDelete(
	ctx context.Context,
	instance *keystonev1.ApplicationCredential,
	helperObj *helper.Helper,
) (ctrl.Result, error) {

	logger := r.GetLogger(ctx)

	if instance.Status.ACID != "" {
		// revoke
		keystoneAPI, err := keystonecommon.GetKeystoneAPI(ctx, helperObj, instance.Namespace, nil)
		if err == nil && keystoneAPI.IsReady() {
			userID, userErr := r.findUserIDAsAdmin(ctx, helperObj, keystoneAPI, instance.Spec.UserName)
			if userErr == nil {
				userOS, ctrlResult, getErr := keystonecommon.GetUserServiceClient(ctx, helperObj, keystoneAPI, instance.Spec.UserName)
				if getErr == nil && ctrlResult == (ctrl.Result{}) && userOS != nil {
					delErr := applicationcredentials.Delete(userOS.GetOSClient(), userID, instance.Status.ACID).ExtractErr()
					if delErr != nil {
						if _, is404 := delErr.(gophercloud.ErrDefault404); is404 {
							logger.Info("AC not found, ignoring", "ACID", instance.Status.ACID)
						} else {
							logger.Error(delErr, "Failed to delete AC", "ACID", instance.Status.ACID)
						}
					} else {
						logger.Info("Deleted AC from Keystone", "ACID", instance.Status.ACID)
					}
				}
			}
		}
	}

	// remove finalizer
	controllerutil.RemoveFinalizer(
		instance,
		fmt.Sprintf("%s-%s", helperObj.GetFinalizer(), instance.Name),
	)
	if err := r.Update(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// createACInKeystone
func (r *ApplicationCredentialReconciler) createACInKeystone(
	logger logr.Logger,
	identClient *gophercloud.ServiceClient,
	userID string,
	ac *keystonev1.ApplicationCredential,
) (string, string, error) {

	createOpts := applicationcredentials.CreateOpts{
		Name:         ac.Name,
		Description:  fmt.Sprintf("Created by operator for user %s", ac.Spec.UserName),
		Unrestricted: false,
	}

	res, err := applicationcredentials.Create(identClient, userID, createOpts).Extract()
	if err != nil {
		return "", "", fmt.Errorf("failed to create AC for user %s: %w", ac.Spec.UserName, err)
	}

	return res.ID, res.Secret, nil
}

// ensureACSecret
func (r *ApplicationCredentialReconciler) ensureACSecret(
	ctx context.Context,
	h *helper.Helper,
	ac *keystonev1.ApplicationCredential,
	secretName, acID, acSecret string,
) error {
	data := map[string]string{
		"AC_ID":     acID,
		"AC_SECRET": acSecret,
	}
	tmpl := []util.Template{{
		Name:       secretName,
		Namespace:  ac.Namespace,
		Type:       util.TemplateTypeNone,
		CustomData: data,
	}}
	return oko_secret.EnsureSecrets(ctx, h, ac, tmpl, nil)
}

// findUserIDAsAdmin
func (r *ApplicationCredentialReconciler) findUserIDAsAdmin(
	ctx context.Context,
	h *helper.Helper,
	keystoneAPI *keystonecommon.KeystoneAPI,
	userName string,
) (string, error) {

	logger := r.GetLogger(ctx)
	adminOS, ctrlRes, err := keystonecommon.GetAdminServiceClient(ctx, h, keystoneAPI)
	if err != nil {
		return "", err
	}
	if ctrlRes != (ctrl.Result{}) {
		return "", fmt.Errorf("admin client not ready")
	}

	userObj, err := adminOS.GetUser(logger, userName, "Default")
	if err != nil {
		return "", fmt.Errorf("cannot find user %s: %w", userName, err)
	}

	return userObj.ID, nil
}

// isExpiringSoon
func (r *ApplicationCredentialReconciler) isExpiringSoon(ac *keystonev1.ApplicationCredential) bool {
	// implement if needed
	return false
}

func (r *ApplicationCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&keystonev1.ApplicationCredential{}).
		//TODO: Check if we must to watch the secret
		// .Owns(&corev1.Secret{}).WithEventFilter(...)
		Complete(r)
}

func (r *ApplicationCredentialReconciler) GetLogger(ctx context.Context) logr.Logger {
	return ctrlLog.FromContext(ctx).WithName("ApplicationCredentialReconciler")
}
