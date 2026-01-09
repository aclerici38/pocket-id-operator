/*
Copyright 2026.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetConditions returns a pointer to the Conditions slice for PocketIDUser
func (u *PocketIDUser) GetConditions() *[]metav1.Condition {
	return &u.Status.Conditions
}

// GetConditions returns a pointer to the Conditions slice for PocketIDUserGroup
func (g *PocketIDUserGroup) GetConditions() *[]metav1.Condition {
	return &g.Status.Conditions
}

// GetConditions returns a pointer to the Conditions slice for PocketIDOIDCClient
func (c *PocketIDOIDCClient) GetConditions() *[]metav1.Condition {
	return &c.Status.Conditions
}

// GetConditions returns a pointer to the Conditions slice for PocketIDInstance
func (i *PocketIDInstance) GetConditions() *[]metav1.Condition {
	return &i.Status.Conditions
}
