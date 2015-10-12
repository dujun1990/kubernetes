ETCD_SERVERS="http://127.0.0.1:4002"
FLANNEL_NET=${1:-"192.168.0.0/16"}

while true; do
if etcdctl --no-sync -C ${ETCD_SERVERS} get /coreos.com/network/config >/dev/null 2>&1; then
  break
else
  etcdctl --no-sync -C ${ETCD_SERVERS} mk /coreos.com/network/config "{\"Network\":\"${FLANNEL_NET}\"}" >/dev/null 2>&1
  sleep 3
fi
done