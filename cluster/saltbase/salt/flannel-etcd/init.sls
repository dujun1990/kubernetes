{% if pillar.get('is_systemd') %}
{% set environment_file = '/etc/sysconfig/flannel-etcd' %}
{% else %}
{% set environment_file = '/etc/default/flannel-etcd' %}
{% endif %}

{{ environment_file }}:
  file.managed:
    - source: salt://flannel-etcd/default
    - template: jinja
    - user: root
    - group: root
    - mode: 644

flannel-etcd-tar:
  archive.extracted:
    - name: /usr/local/src
    - source: http://github.com/coreos/etcd/releases/download/v2.0.12/etcd-v2.0.12-linux-amd64.tar.gz
    - source_hash: md5=4431688d9dd4937f53f8b4dcbecf4665
    - archive_format: tar
    - tar_options: v
    - if_missing: /usr/local/src/etcd-v2.0.12-linux-amd64/

flannel-etcd-symlink:
  file.symlink:
    - name: /usr/local/bin/flannel-etcd
    - target: /usr/local/src/etcd-v2.0.12-linux-amd64/etcd
    - force: true
    - watch:
        - archive: flannel-etcd-tar

flannel-etcdctl-symlink:
  file.symlink:
    - name: /usr/local/bin/etcdctl
    - target: /usr/local/src/etcd-v2.0.12-linux-amd64/etcdctl
    - force: true
    - watch:
        - archive: flannel-etcd-tar

/etc/init.d/flannel-etcd:
  file.managed:
    - source: salt://flannel-etcd/initd
    - user: root
    - group: root
    - mode: 755

flannel-etcd:
  service.running:
    - enable: True
    - watch:
      - file: /usr/local/bin/flannel-etcd
      - file: /etc/init.d/flannel-etcd
      - file: {{ environment_file }}