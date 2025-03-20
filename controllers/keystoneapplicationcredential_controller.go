package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/applicationcredentials"
	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	oko_secret "github.com/openstack-k8s-operators/lib-common/modules/common/secret"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"

	openstack "github.com/openstack-k8s-operators/lib-common/modules/openstack"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// -- Static errors for lint rule err113 ---------------------------------------

var (
	errNoIdentityClient       = errors.New("no identity client found in OpenStack object")
	errNoIdentityClientDelete = errors.New("no identity client found for deleteApplicationCredential")
	errUserNotFound           = errors.New("keystone user not found in domain")
)

// ----------------------------------------------------------------------------

// ApplicationCredentialReconciler reconciles an ApplicationCredential object
type ApplicationCredentialReconciler struct {
	client.Client
	Kclient kubernetes.Interface
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

// GetLogger returns a logger object with a logging prefix
func (r *ApplicationCredentialReconciler) GetLogger(ctx context.Context) logr.Logger {
	return log.FromContext(ctx).WithName("Controllers").WithName("AppCredReconciler")
}

// +kubebuilder:rbac:groups=keystone.openstack.org,resources=applicationcredentials,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=applicationcredentials/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=keystone.openstack.org,resources=applicationcredentials/finalizers,verbs=update;patch

func (r *ApplicationCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, _err error) {
	logger := r.GetLogger(ctx)

	// Fetch the AC instance
	instance := &keystonev1.ApplicationCredential{}
	err := r.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
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

	// Initialize status conditions if nil
	isNewInstance := instance.Status.Conditions == nil
	if isNewInstance {
		instance.Status.Conditions = condition.Conditions{}
	}

	savedConditions := instance.Status.Conditions.DeepCopy()

	// Always patch the instance status when exiting this function so we can
	// persist any changes.
	defer func() {
		condition.RestoreLastTransitionTimes(&instance.Status.Conditions, savedConditions)
		if instance.Status.Conditions.IsUnknown(condition.ReadyCondition) {
			instance.Status.Conditions.Set(instance.Status.Conditions.Mirror(condition.ReadyCondition))
		}
		patchErr := helperObj.PatchInstance(ctx, instance)
		if patchErr != nil {
			_err = patchErr
			return
		}
	}()

	// Initialize the Ready condition to Unknown if not set
	cl := condition.CreateList(
		condition.UnknownCondition(condition.ReadyCondition, condition.InitReason, condition.ReadyInitMessage),
	)
	instance.Status.Conditions.Init(&cl)

	// If deletion is requested, do finalizer logic
	if !instance.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, instance, helperObj)
	}

	return r.reconcileNormal(ctx, instance, helperObj)
}

func (r *ApplicationCredentialReconciler) reconcileNormal(
	ctx context.Context,
	instance *keystonev1.ApplicationCredential,
	helperObj *helper.Helper,
) (ctrl.Result, error) {

	logger := log.FromContext(ctx)

	// Add finalizer if not present
	if controllerutil.AddFinalizer(instance, fmt.Sprintf("%s-%s", helperObj.GetFinalizer(), instance.Name)) {
		if err := r.Update(ctx, instance); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Find the KeystoneAPI in this namespace
	keystoneAPI, err := keystonev1.GetKeystoneAPI(ctx, helperObj, instance.Namespace, map[string]string{})
	if err != nil {
		logger.Info("KeystoneAPI not found or error occurred, requeueing...")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}
	if !keystoneAPI.IsReady() {
		logger.Info("KeystoneAPI is not ready, requeueing...")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Build admin client to talk to Keystone
	osClient, ctrlResult, err := keystonev1.GetAdminServiceClient(ctx, helperObj, keystoneAPI)
	if err != nil {
		return ctrlResult, err
	}
	if ctrlResult != (ctrl.Result{}) {
		// Requeue if the helper function indicates we need to
		return ctrlResult, nil
	}

	// Check if we need to create or rotate
	if instance.Status.ACID == "" || r.isExpiringSoon(instance) {
		newID, newSecret, err := r.createOrRotateACInKeystone(logger, osClient, instance)
		if err != nil {
			return ctrl.Result{}, err
		}

		// Store ID & secret in K8s Secret
		secretName := instance.Name + "-secret"
		if err := r.ensureACSecret(ctx, helperObj, instance, secretName, newID, newSecret); err != nil {
			return ctrl.Result{}, err
		}

		instance.Status.ACID = newID
		instance.Status.SecretName = secretName
	}

	instance.Status.Conditions.MarkTrue(condition.ReadyCondition, "ApplicationCredential is ready")
	return ctrl.Result{}, nil
}

func (r *ApplicationCredentialReconciler) reconcileDelete(
	ctx context.Context,
	instance *keystonev1.ApplicationCredential,
	helperObj *helper.Helper,
) (ctrl.Result, error) {

	logger := log.FromContext(ctx)
	if instance.Status.ACID != "" {
		// If we have an AC, try to revoke it
		keystoneAPI, err := keystonev1.GetKeystoneAPI(ctx, helperObj, instance.Namespace, map[string]string{})
		if err == nil && keystoneAPI.IsReady() {
			osClient, ctrlResult, getErr := keystonev1.GetAdminServiceClient(ctx, helperObj, keystoneAPI)
			if getErr == nil && ctrlResult == (ctrl.Result{}) {
				// Attempt to delete
				delErr := r.deleteApplicationCredential(logger, osClient, instance.Spec.UserName, instance.Status.ACID)
				if delErr != nil {
					logger.Error(delErr, "Failed to delete AC from Keystone")
				}
			}
		}
	}

	// Remove finalizer
	controllerutil.RemoveFinalizer(instance, helperObj.GetFinalizer())
	if err := r.Update(ctx, instance); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// createOrRotateACInKeystone uses gophercloud to create (or rotate) an AC
func (r *ApplicationCredentialReconciler) createOrRotateACInKeystone(
	log logr.Logger,
	os *openstack.OpenStack,
	ac *keystonev1.ApplicationCredential,
) (string, string, error) {

	identClient := os.GetOSClient()
	if identClient == nil {
		return "", "", fmt.Errorf("failed to rotate AC: %w", errNoIdentityClient)
	}

	// Lookup user via openstack.go -> GetUser()
	userObj, err := os.GetUser(log, ac.Spec.UserName, "default")
	if err != nil {
		// If "user not found" or multiple user error
		if strings.Contains(err.Error(), openstack.UserNotFound) {
			return "", "", fmt.Errorf("failed to get user in domain=default user=%s: %w", ac.Spec.UserName, errUserNotFound)
		}
		return "", "", fmt.Errorf("failed to get user: %w", err)
	}
	userID := userObj.ID

	// Build CreateOpts
	createOpts := applicationcredentials.CreateOpts{
		Name:         ac.Name,
		Description:  "Generated by AC operator",
		Unrestricted: false,
		// TODO: handle roles or expiration if needed
	}

	// Call gophercloud to create the AC
	createdAC, cErr := applicationcredentials.Create(identClient, userID, createOpts).Extract()
	if cErr != nil {
		return "", "", fmt.Errorf("failed to create AC for user %s: %w", ac.Spec.UserName, cErr)
	}

	log.Info("Created new ApplicationCredential",
		"acID", createdAC.ID,
		"userID", userID,
		"serviceUser", ac.Spec.UserName,
	)

	return createdAC.ID, createdAC.Secret, nil
}

// deleteApplicationCredential calls gophercloud to delete an AC
func (r *ApplicationCredentialReconciler) deleteApplicationCredential(
	log logr.Logger,
	os *openstack.OpenStack,
	userName, acID string,
) error {

	identClient := os.GetOSClient()
	if identClient == nil {
		return fmt.Errorf("failed to delete AC: %w", errNoIdentityClientDelete)
	}

	// get user to get userID
	userObj, err := os.GetUser(log, userName, "default")
	if err != nil && !strings.Contains(err.Error(), openstack.UserNotFound) {
		return fmt.Errorf("could not get user %s: %w", userName, err)
	}
	if userObj == nil {
		// user does not exist -> skip
		log.Info("User not found, skipping AC deletion", "userName", userName)
		return nil
	}
	userID := userObj.ID

	delErr := applicationcredentials.Delete(identClient, userID, acID).ExtractErr()
	if delErr != nil {
		return fmt.Errorf("failed to delete AC %s: %w", acID, delErr)
	}
	log.Info("Deleted ApplicationCredential", "acID", acID, "userID", userID)
	return nil
}

// ensureACSecret uses EnsureSecrets from lib-common to store AC ID & secret
func (r *ApplicationCredentialReconciler) ensureACSecret(
	ctx context.Context,
	helperObj *helper.Helper,
	ac *keystonev1.ApplicationCredential,
	secretName, acID, acSecret string,
) error {
	data := map[string]string{
		"AC_ID":     acID,
		"AC_SECRET": acSecret,
	}

	tmpl := []util.Template{
		{
			Name:       secretName,
			Namespace:  ac.Namespace,
			Type:       util.TemplateTypeNone,
			CustomData: data,
		},
	}

	err := oko_secret.EnsureSecrets(ctx, helperObj, ac, tmpl, nil)
	if err != nil {
		return fmt.Errorf("failed to ensure AC secret: %w", err)
	}
	return nil
}

// isExpiringSoon - placeholder for rotation logic
func (r *ApplicationCredentialReconciler) isExpiringSoon(_ *keystonev1.ApplicationCredential) bool {
	// if AC has expiration, implement check here
	return false
}

// SetupWithManager sets up the controller with the Manager
func (r *ApplicationCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&keystonev1.ApplicationCredential{}).
		Complete(r)
}
