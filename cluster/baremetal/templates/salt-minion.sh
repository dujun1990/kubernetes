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

# exit on any error
set -e

# Setup hosts file to support ping by hostname to master
if [[ ! "$(cat /etc/hosts | grep $MASTER_NAME)" ]]; then
  echo "Adding $MASTER_NAME to hosts file"
  echo "$MASTER_IP $MASTER_NAME" >> /etc/hosts
fi

mkdir -p /etc/salt/minion.d
echo "master: $MASTER_NAME" > /etc/salt/minion.d/master.conf

cat <<EOF >/etc/salt/minion.d/log-level-debug.conf
log_level: debug
log_level_logfile: debug
EOF

cat <<EOF >/etc/salt/minion.d/grains.conf
grains:
  roles:
    - kubernetes-pool
  cloud: baremetal
  api_servers: $MASTER_NAME
  hostname_overlay: $NODE_IP
EOF

# Placeholder for any other manifests that may be per-node.
mkdir -p /etc/kubernetes/manifests

install-salt

# Wait a few minutes and trigger another Salt run to better recover from
# any transient errors.
echo "Sleeping 10"
sleep 10
salt-call state.highstate || true