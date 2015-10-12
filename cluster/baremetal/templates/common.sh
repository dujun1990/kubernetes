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

# Install salt from GCS.  See README.md for instructions on how to update these
# debs.
#
# $1 If set to --master, also install the master
export http_proxy="http://9.91.13.41:8081"
export https_proxy="https://9.91.13.41:8081"
export no_proxy=localhost,127.0.0.1,10.*

install-salt() {

  # TODO: Only for Ubuntu, need add support for CentOS
  echo deb http://ppa.launchpad.net/saltstack/salt/ubuntu `lsb_release -sc` main | tee /etc/apt/sources.list.d/saltstack.list
  wget -q -O- "http://keyserver.ubuntu.com:11371/pks/lookup?op=get&search=0x4759FA960E27C0A6" | apt-key add -

  apt-get update

  if [[ ${1-} == '--master' ]]; then
    apt-get install -y salt-master salt-minion
  else
    apt-get install -y salt-minion
  fi
}
