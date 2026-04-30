/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	keystonev1 "github.com/openstack-k8s-operators/keystone-operator/api/v1beta1"
	dataplanev1 "github.com/openstack-k8s-operators/openstack-operator/api/dataplane/v1beta1"
)

func TestIsEDPMConsumerAC(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"ac-nova", true},
		{"ac-ceilometer", true},
		{"ac-barbican", false},
		{"ac-heat", false},
		{"ac-glance", false},
		{"nova", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEDPMConsumerAC(tt.name); got != tt.want {
				t.Errorf("isEDPMConsumerAC(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsACStillInUseByNodeSets(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = keystonev1.AddToScheme(scheme)
	_ = dataplanev1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	baseTime := time.Now()

	tests := []struct {
		name           string
		nodesets       []*dataplanev1.OpenStackDataPlaneNodeSet
		wantStillInUse bool
		wantInfoSubstr string
		wantErr        bool
	}{
		{
			name:           "no nodesets exist",
			nodesets:       nil,
			wantStillInUse: false,
			wantErr:        false,
		},
		{
			name: "nodeset with partial update blocks cleanup",
			nodesets: []*dataplanev1.OpenStackDataPlaneNodeSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-nodeset",
						Namespace: "test",
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-0": {},
							"compute-1": {},
							"compute-2": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: &dataplanev1.SecretDeploymentStatus{
							AllNodesUpdated: false,
							TotalNodes:      3,
							UpdatedNodes:    2,
						},
					},
				},
			},
			wantStillInUse: true,
			wantInfoSubstr: "2/3 nodes updated",
			wantErr:        false,
		},
		{
			name: "nodeset with all nodes updated allows cleanup",
			nodesets: []*dataplanev1.OpenStackDataPlaneNodeSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "test-nodeset",
						Namespace:         "test",
						CreationTimestamp: metav1.Time{Time: baseTime},
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-0": {},
							"compute-1": {},
							"compute-2": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: &dataplanev1.SecretDeploymentStatus{
							AllNodesUpdated: true,
							TotalNodes:      3,
							UpdatedNodes:    3,
						},
					},
				},
			},
			wantStillInUse: false,
			wantErr:        false,
		},
		{
			name: "nodeset with nil SecretDeployment status blocks cleanup",
			nodesets: []*dataplanev1.OpenStackDataPlaneNodeSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "uninitialized-nodeset",
						Namespace: "test",
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-0": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: nil,
					},
				},
			},
			wantStillInUse: true,
			wantErr:        true,
		},
		{
			name: "multiple nodesets one incomplete blocks cleanup",
			nodesets: []*dataplanev1.OpenStackDataPlaneNodeSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "complete-nodeset",
						Namespace: "test",
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-0": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: &dataplanev1.SecretDeploymentStatus{
							AllNodesUpdated: true,
							TotalNodes:      1,
							UpdatedNodes:    1,
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "incomplete-nodeset",
						Namespace: "test",
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-1": {},
							"compute-2": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: &dataplanev1.SecretDeploymentStatus{
							AllNodesUpdated: false,
							TotalNodes:      2,
							UpdatedNodes:    1,
						},
					},
				},
			},
			wantStillInUse: true,
			wantInfoSubstr: "1/2 nodes updated",
			wantErr:        false,
		},
		{
			name: "multiple nodesets all complete allows cleanup",
			nodesets: []*dataplanev1.OpenStackDataPlaneNodeSet{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nodeset-a",
						Namespace: "test",
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-0": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: &dataplanev1.SecretDeploymentStatus{
							AllNodesUpdated: true,
							TotalNodes:      1,
							UpdatedNodes:    1,
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nodeset-b",
						Namespace: "test",
					},
					Spec: dataplanev1.OpenStackDataPlaneNodeSetSpec{
						Nodes: map[string]dataplanev1.NodeSection{
							"compute-1": {},
							"compute-2": {},
						},
					},
					Status: dataplanev1.OpenStackDataPlaneNodeSetStatus{
						SecretDeployment: &dataplanev1.SecretDeploymentStatus{
							AllNodesUpdated: true,
							TotalNodes:      2,
							UpdatedNodes:    2,
						},
					},
				},
			},
			wantStillInUse: false,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []runtime.Object{}
			for _, ns := range tt.nodesets {
				objs = append(objs, ns)
			}

			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objs...).
				Build()

			reconciler := &ApplicationCredentialReconciler{
				Client: cl,
			}

			stillInUse, info, err := reconciler.isACStillInUseByNodeSets(
				context.Background(),
				"test",
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("isACStillInUseByNodeSets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if stillInUse != tt.wantStillInUse {
				t.Errorf("isACStillInUseByNodeSets() stillInUse = %v, want %v", stillInUse, tt.wantStillInUse)
			}

			if tt.wantInfoSubstr != "" {
				if info == "" {
					t.Errorf("isACStillInUseByNodeSets() info is empty, want substring %q", tt.wantInfoSubstr)
				} else if !strings.Contains(info, tt.wantInfoSubstr) {
					t.Errorf("isACStillInUseByNodeSets() info = %q, want substring %q", info, tt.wantInfoSubstr)
				}
			}
		})
	}
}
