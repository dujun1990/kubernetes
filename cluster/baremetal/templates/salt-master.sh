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

# Setup hosts file to support ping by hostname to master
if [[ ! "$(cat /etc/hosts | grep $MASTER_NAME)" ]]; then
  echo "Adding $MASTER_NAME to hosts file"
  echo "$MASTER_IP $MASTER_NAME" >> /etc/hosts
fi

# Set Salt Master Configuration
mkdir -p /etc/salt/master.d
cat <<EOF >/etc/salt/master.d/auto-accept.conf
auto_accept: True
EOF

cat <<EOF >/etc/salt/master.d/reactor.conf
# React to new minions starting by running highstate on them.
reactor:
  - 'salt/minion/*/start':
  - /srv/reactor/highstate-new.sls
EOF

cat <<EOF >/etc/salt/master.d/log-level-debug.conf
log_level: debug
log_level_logfile: debug
EOF

# Set Salt Minion Configuration with role kubernetes-master
mkdir -p /etc/salt/minion.d
echo "master: $MASTER_NAME" > /etc/salt/minion.d/master.conf

cat <<EOF >/etc/salt/minion.d/grains.conf
grains:
  roles:
    - kubernetes-master
  cloud: baremetal
  api_servers: $MASTER_NAME
EOF

cat <<EOF >/etc/salt/minion.d/log-level-debug.conf
log_level: debug
log_level_logfile: debug
EOF

if [[ ! $(which salt-master) ]]; then
  install-salt --master
fi

# Wait a few minutes and trigger another Salt run to better recover from
# any transient errors.
echo "Sleeping 10"
sleep 10
salt-call state.highstate || true
