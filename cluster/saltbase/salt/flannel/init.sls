{% if pillar.get('is_systemd') %}
{% set flannel_client_environment_file = '/etc/sysconfig/flannel' %}
{% set flannel_server_environment_file = '/etc/sysconfig/flannel-server' %}
{% else %}
{% set flannel_client_environment_file = '/etc/default/flannel' %}
{% set flannel_server_environment_file = '/etc/default/flannel-server' %}
{% endif %}

flannel-tar:
  archive.extracted:
    - name: /usr/local/src
    - source: https://github.com/coreos/flannel/releases/download/v0.5.3/flannel-0.5.3-linux-amd64.tar.gz
    - source_hash: md5=2a82ed82a37d71c85586977f0e475b70
    - archive_format: tar
    - tar_options: v
    - if_missing: /usr/local/src/flannel-0.5.3/

flannel-symlink:
  file.symlink:
    - name: /usr/local/bin/flanneld
    - target: /usr/local/src/flannel-0.5.3/flanneld
    - force: true
    - watch:
      - archive: flannel-tar

{% if grains['roles'][0] == 'kubernetes-master' %}
flannel-etcd-config:
  cmd.script:
    - source: salt://flannel/config-etcd.sh
    - args: {{ pillar.get('flannel-net') }}
    - require:
      - service: flannel-etcd

{{ flannel_server_environment_file }}:
  file.managed:
    - source: salt://flannel/server-default
    - template: jinja
    - user: root
    - group: root
    - mode: 644

/etc/init.d/flannel-server:
  file.managed:
    - source: salt://flannel/server-initd
    - user: root
    - group: root
    - mode: 755

flannel-server:
  service.running:
    - enable: True
    - watch:
      - file: /usr/local/bin/flanneld
      - file: /etc/init.d/flannel-server
      - file: {{ flannel_server_environment_file }}
    - require:
      - cmd: flannel-etcd-config
{% endif %}

{{ flannel_client_environment_file }}:
  file.managed:
    - source: salt://flannel/client-default
    - template: jinja
    - user: root
    - group: root
    - mode: 644

/etc/init.d/flannel:
  file.managed:
    - source: salt://flannel/client-initd
    - user: root
    - group: root
    - mode: 755

flannel:
  service.running:
    - enable: True
    - watch:
      - file: /usr/local/bin/flanneld
      - file: /etc/init.d/flannel
      - file: {{ flannel_client_environment_file }}
{% if grains['roles'][0] == 'kubernetes-master' %}
    - require:
      - service: flannel-server
{% endif %}

#/var/run/flannel/network.json:
#  file.managed:
#    - source: salt://flannel/network.json
#    - makedirs: True
#    - user: root
#    - group: root
#    - mode: 755