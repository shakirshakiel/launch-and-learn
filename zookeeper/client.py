import signal
from kazoo.client import KazooClient
from kazoo.recipe.watchers import ChildrenWatch

zoo_path = '/root'
zk = KazooClient(hosts='192.168.199.21:2181,192.168.199.22:2181,192.168.199.23:2181')
zk.start()
zk.ensure_path(zoo_path)

@zk.ChildrenWatch(zoo_path)
def child_watch_func(children):
    print("List of Children %s" % children)

while True:
    signal.pause()
