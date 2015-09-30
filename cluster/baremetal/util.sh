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

# A library of helper functions and constant for the local config.

# Use the config file specified in $KUBE_CONFIG_FILE, or default to
# config-default.sh.

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
source "${KUBE_ROOT}/cluster/baremetal/${KUBE_CONFIG_FILE-"config-default.sh"}"
source "${KUBE_ROOT}/cluster/common.sh"

# Create a temp dir that'll be deleted at the end of this bash session.
#
# Vars set:
#   KUBE_TEMP
function ensure-temp-dir {
    if [[ -z ${KUBE_TEMP-} ]]; then
        KUBE_TEMP=$(mktemp -d -t kubernetes.XXXXXX)
        echo "KUBE_TEMP:${KUBE_TEMP}"
        trap 'rm -rf "${KUBE_TEMP}"' EXIT
    fi
}

function json_val () {
    python -c 'import json,sys;obj=json.load(sys.stdin);print obj'$1'';
}

# Verify prereqs
function verify-prereqs {
    echo "===> verify-prereqs: TODO"
}

# Verify and find the various tar files that we are going to use on the server.
#
# Vars set:
#   SERVER_BINARY_TAR
#   SALT_TAR
function find-release-tars {
    SERVER_BINARY_TAR="${KUBE_ROOT}/server/kubernetes-server-linux-amd64.tar.gz"
    if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
        SERVER_BINARY_TAR="${KUBE_ROOT}/_output/release-tars/kubernetes-server-linux-amd64.tar.gz"
    fi
    if [[ ! -f "$SERVER_BINARY_TAR" ]]; then
        echo "!!! Cannot find kubernetes-server-linux-amd64.tar.gz"
        exit 1
    fi

    SALT_TAR="${KUBE_ROOT}/server/kubernetes-salt.tar.gz"
    if [[ ! -f "$SALT_TAR" ]]; then
        SALT_TAR="${KUBE_ROOT}/_output/release-tars/kubernetes-salt.tar.gz"
    fi
    if [[ ! -f "$SALT_TAR" ]]; then
        echo "!!! Cannot find kubernetes-salt.tar.gz"
        exit 1
    fi
}

# Detect the information about the minions
#
# Assumed vars:
#   MINION_NAMES
#   ZONE
# Vars set:
#
function detect-minions () {
    echo "===> TODO: Detect Minions"
}

# Detect the IP for the master
#
# Assumed vars:
#   MASTER_NAME
#   ZONE
# Vars set:
#   KUBE_MASTER
#   KUBE_MASTER_IP
function detect-master () {
    echo "===> TODO: Detect Master"
}

function provision-master {
    # Build up start up script for master
    echo "--> Building up start up script for master"
    (
        echo "#!/bin/bash"
        echo "readonly MASTER_NAME='${MASTER_NAME}'"
        echo "readonly MASTER_IP='${MASTER_IP}'"
        echo "readonly KUBE_USER='${KUBE_USER:-}'"
        echo "readonly KUBE_PASSWORD='${KUBE_PASSWORD:-}'"
        echo "readonly KUBELET_TOKEN='${KUBELET_TOKEN:-}'"
        echo "readonly KUBE_PROXY_TOKEN='${KUBE_PROXY_TOKEN:-}'"
        echo "readonly ADMISSION_CONTROL='${ADMISSION_CONTROL:-}'"
        echo "readonly SERVICE_CLUSTER_IP_RANGE='${SERVICE_CLUSTER_IP_RANGE}'"
        echo "readonly ENABLE_CLUSTER_UI='${ENABLE_CLUSTER_UI}'"
        echo "readonly ENABLE_CLUSTER_MONITORING='${ENABLE_CLUSTER_MONITORING}'"
        echo "readonly ENABLE_CLUSTER_LOGGING='${ENABLE_NODE_LOGGING:-false}'"
        echo "readonly ENABLE_NODE_LOGGING='${ENABLE_NODE_LOGGING:-false}'"
        echo "readonly LOGGING_DESTINATION='${LOGGING_DESTINATION:-}'"
        echo "readonly ELASTICSEARCH_LOGGING_REPLICAS='${ELASTICSEARCH_LOGGING_REPLICAS:-1}'"
        grep -v "^#" "${KUBE_ROOT}/cluster/baremetal/templates/common.sh"
        grep -v "^#" "${KUBE_ROOT}/cluster/baremetal/templates/create-dynamic-files.sh"
        grep -v "^#" "${KUBE_ROOT}/cluster/baremetal/templates/install-release.sh"
        grep -v "^#" "${KUBE_ROOT}/cluster/baremetal/templates/salt-master.sh"
    ) > "${KUBE_TEMP}/master-start.sh"

    # remote login to MASTER and use sudo to configue k8s master
    ssh ${SSH_OPTS} -t ${MASTER_IP} "mkdir -p /var/cache/kubernetes-install"
    scp -r ${SSH_OPTS} ${KUBE_TEMP}/master-start.sh ${SERVER_BINARY_TAR} ${SALT_TAR} ${MASTER_IP}:/var/cache/kubernetes-install
    ssh -t ${MASTER_IP} "cd /var/cache/kubernetes-install; chmod +x master-start.sh; sudo ./master-start.sh"
}

function provision-minion {
    #Build up start up script for minions
    currentnode=${1-}
    currentnode_ip=${currentnode#*@}
    echo "--> Building up start up script for minions"
    i=${2-}
    (
        echo "#!/bin/bash"
        echo "MASTER_NAME='${MASTER_NAME}'"
        echo "MASTER_IP='${MASTER_IP}'"
        echo "NODE_IP='${currentnode_ip}'"
        grep -v "^#" "${KUBE_ROOT}/cluster/baremetal/templates/common.sh"
        grep -v "^#" "${KUBE_ROOT}/cluster/baremetal/templates/salt-minion.sh"
    ) > "${KUBE_TEMP}/minion-start-${i}.sh"

    # remote login to MASTER and use sudo to configue k8s master
    ssh $SSH_OPTS -t $currentnode "mkdir -p /var/cache/kubernetes-install"
    scp -r $SSH_OPTS ${KUBE_TEMP}/minion-start-${i}.sh  $currentnode:/var/cache/kubernetes-install
    ssh -t $currentnode "cd /var/cache/kubernetes-install; chmod +x minion-start-${i}.sh; sudo ./minion-start-${i}.sh"
}

# Instantiate a kubernetes cluster
#
# Assumed vars
#   KUBE_ROOT
#   <Various vars set in config file>
function kube-up {

    # Verify whether the release file exist
    find-release-tars

    # Create the temp directory
    ensure-temp-dir

    # Auto generate the password
    get-password

    # Auto generate the tokens
    get-tokens

    # Provision Kubernetes Master
    provision-master

    # Provision kubernetes Node
    i=0
    for currentnode in ${NODES}; do
    {
        echo "Provision NODE IP = ${currentnode}"
        provision-minion ${currentnode}
    }
    ((i=i+1))
    done

    detect-master
}

# Delete a kubernetes cluster
function kube-down {
    echo "===> TODO: Bringing Down CLuster"
}

function validate-cluster {
    echo "===> TODO: validate-cluster"
}

# Execute prior to running tests to build a release if required for env.
#
# Assumed Vars:
#   KUBE_ROOT
function test-build-release {
    # Make a release
    "${KUBE_ROOT}/build/release.sh"
}

# SSH to a node by name ($1) and run a command ($2).
function ssh-to-node {
    local node="$1"
    local cmd="$2"
    ssh --ssh_arg "-o LogLevel=quiet" "${node}" "${cmd}"
}

# Restart the kube-proxy on a node ($1)
function restart-kube-proxy {
    ssh-to-node "$1" "sudo /etc/init.d/kube-proxy restart"
}

# Restart the kube-proxy on the master ($1)
function restart-apiserver {
    ssh-to-node "$1" "sudo /etc/init.d/kube-apiserver restart"
}

# Ensure that we have a password created for validating to the master.  Will
# read from kubeconfig current-context if available.
#
# Vars set:
#   KUBE_USER
#   KUBE_PASSWORD
function get-password {
  get-kubeconfig-basicauth
  if [[ -z "${KUBE_USER}" || -z "${KUBE_PASSWORD}" ]]; then
    KUBE_USER=admin
    KUBE_PASSWORD=$(python -c 'import string,random; print "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))')
  fi
}

function get-tokens() {
  KUBELET_TOKEN=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null)
  KUBE_PROXY_TOKEN=$(dd if=/dev/urandom bs=128 count=1 2>/dev/null | base64 | tr -d "=+/" | dd bs=32 count=1 2>/dev/null)
}
