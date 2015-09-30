#!/bin/bash

# Copyright 2014 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SSH_OPTS="-oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oLogLevel=ERROR"

INSTANCE_PREFIX=kubernetes

# Master Configurations
export MASTER=${KUBE_MASTER-"root@2.2.2.186"}
export MASTER_IP=${MASTER#*@}
MASTER_TAG="${INSTANCE_PREFIX}-master"
MASTER_NAME="${INSTANCE_PREFIX}-master"

# Node Configurations
export NUM_MINIONS=${NUM_MINIONS-"1"}
export NODES=${NODES:-"root@2.2.2.185"}
NODES_TAG="${INSTANCE_PREFIX}-node"
NODES_NAME=($(eval echo ${INSTANCE_PREFIX}-node-{1..${NUM_MINIONS}}))

# Cluster IP Address Range
SERVICE_CLUSTER_IP_RANGE="10.247.0.0/16"

# Admission Controllers to invoke prior to persisting objects in cluster
ADMISSION_CONTROL=NamespaceLifecycle,LimitRanger,SecurityContextDeny,ServiceAccount,DenyEscalatingExec,ResourceQuota

# Optional: Install Kubernetes UI
ENABLE_CLUSTER_UI="${KUBE_ENABLE_CLUSTER_UI:-true}"

# Optional: Cluster monitoring to setup as part of the cluster bring up:
#   none     - No cluster monitoring setup
#   influxdb - Heapster, InfluxDB, and Grafana
#   google   - Heapster, Google Cloud Monitoring, and Google Cloud Logging
ENABLE_CLUSTER_MONITORING="${KUBE_ENABLE_CLUSTER_MONITORING:-influxdb}"

# Optional: Install node logging
ENABLE_NODE_LOGGING=false
LOGGING_DESTINATION=elasticsearch

# Optional: When set to true, Elasticsearch and Kibana will be setup as part of the cluster bring up.
ENABLE_CLUSTER_LOGGING=false
ELASTICSEARCH_LOGGING_REPLICAS=1
