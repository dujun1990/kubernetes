/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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
	"reflect"
	"testing"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/labels"
)

func TestNodeSelectorRequirementsAsSelector(t *testing.T) {
	matchExpressions := []NodeSelectorRequirement{{
		Key:      "foo",
		Operator: NodeSelectorOpIn,
		Values:   []string{"bar", "baz"},
	}}
	mustParse := func(s string) labels.Selector {
		out, e := labels.Parse(s)
		if e != nil {
			panic(e)
		}
		return out
	}
	tc := []struct {
		in        []NodeSelectorRequirement
		out       labels.Selector
		expectErr bool
	}{
		{in: nil, out: labels.Nothing()},
		{in: []NodeSelectorRequirement{}, out: labels.Nothing()},
		{
			in:  matchExpressions,
			out: mustParse("foo in (baz,bar)"),
		},
		{
			in: []NodeSelectorRequirement{{
				Key:      "foo",
				Operator: NodeSelectorOpExists,
				Values:   []string{"bar", "baz"},
			}},
			expectErr: true,
		},
		{
			in: []NodeSelectorRequirement{{
				Key:      "foo",
				Operator: NodeSelectorOpGt,
				Values:   []string{"1.1"},
			}},
			out: mustParse("foo>1.1"),
		},
		{
			in: []NodeSelectorRequirement{{
				Key:      "bar",
				Operator: NodeSelectorOpLt,
				Values:   []string{"7.1"},
			}},
			out: mustParse("bar<7.1"),
		},
	}

	for i, tc := range tc {
		out, err := NodeSelectorRequirementsAsSelector(tc.in)
		if err == nil && tc.expectErr {
			t.Errorf("[%v]expected error but got none.", i)
		}
		if err != nil && !tc.expectErr {
			t.Errorf("[%v]did not expect error but got: %v", i, err)
		}
		if !reflect.DeepEqual(out, tc.out) {
			t.Errorf("[%v]expected:\n\t%+v\nbut got:\n\t%+v", i, tc.out, out)
		}
	}
}

func TestGetAffinityFromPod(t *testing.T) {
	testCases := []struct {
		pod       *api.Pod
		expectErr bool
	}{
		{
			pod:       &api.Pod{},
			expectErr: false,
		},
		{
			pod: &api.Pod{
				ObjectMeta: api.ObjectMeta{
					Annotations: map[string]string{
						AffinityAnnotationKey: `
						{"nodeAffinity": { "requiredDuringSchedulingIgnoredDuringExecution": {
							"nodeSelectorTerms": [{
								"matchExpressions": [{
									"key": "foo",
									"operator": "In",
									"values": ["value1", "value2"]
								}]
							}]
						}}}`,
					},
				},
			},
			expectErr: false,
		},
		{
			pod: &api.Pod{
				ObjectMeta: api.ObjectMeta{
					Annotations: map[string]string{
						AffinityAnnotationKey: `
						{"nodeAffinity": { "requiredDuringSchedulingIgnoredDuringExecution": {
							"nodeSelectorTerms": [{
								"matchExpressions": [{
									"key": "foo",
						`,
					},
				},
			},
			expectErr: true,
		},
	}

	for i, tc := range testCases {
		_, err := GetAffinityFromPod(tc.pod)
		if err == nil && tc.expectErr {
			t.Errorf("[%v]expected error but got none.", i)
		}
		if err != nil && !tc.expectErr {
			t.Errorf("[%v]did not expect error but got: %v", i, err)
		}
	}
}
