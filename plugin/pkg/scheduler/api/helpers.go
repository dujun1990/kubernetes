/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package api

import (
	"encoding/json"
	"fmt"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/util/sets"
)

// NodeSelectorRequirementsAsSelector converts the []NodeSelectorRequirement api type into a struct that implements
// labels.Selector
func NodeSelectorRequirementsAsSelector(nsm []NodeSelectorRequirement) (labels.Selector, error) {
	if nsm == nil || len(nsm) == 0 {
		return labels.Nothing(), nil
	}
	selector := labels.NewSelector()
	for _, expr := range nsm {
		var op labels.Operator
		switch expr.Operator {
		case NodeSelectorOpIn:
			op = labels.InOperator
		case NodeSelectorOpNotIn:
			op = labels.NotInOperator
		case NodeSelectorOpExists:
			op = labels.ExistsOperator
		case NodeSelectorOpDoesNotExist:
			op = labels.DoesNotExistOperator
		case NodeSelectorOpGt:
			op = labels.GreaterThanOperator
		case NodeSelectorOpLt:
			op = labels.LessThanOperator
		default:
			return nil, fmt.Errorf("%q is not a valid node selector operator", expr.Operator)
		}
		r, err := labels.NewRequirement(expr.Key, op, sets.NewString(expr.Values...))
		if err != nil {
			return nil, err
		}
		selector = selector.Add(*r)
	}
	return selector, nil
}

// GetAffinityFromPod gets the json serialized affinity data from Pod.Annotations
// and converts it to the Affinity type in scheduler api.
func GetAffinityFromPod(pod *api.Pod) (Affinity, error) {
	var affinity Affinity
	if len(pod.Annotations) > 0 && len(pod.Annotations[AffinityAnnotationKey]) > 0 {
		err := json.Unmarshal([]byte(pod.Annotations[AffinityAnnotationKey]), &affinity)
		if err != nil {
			return affinity, err
		}
	}
	return affinity, nil
}
