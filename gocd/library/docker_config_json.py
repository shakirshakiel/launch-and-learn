#!/usr/bin/python

from ansible.module_utils.basic import *
import json

class JsonWrapper:

    def __init__(self, path):
        self.path = path

    def read(self):
        with open(self.path, 'r') as f:
            data = json.load(f)
        return data

    def write(self, data):
        with open(self.path, 'w') as f:
            json.dump(data, f, indent=4)

class DockerConfigJson:

    def __init__(self, path, http_proxy, https_proxy, no_proxy):
        self.path = path
        self.json_wrapper = JsonWrapper(path)
        self.data = self.json_wrapper.read()
        self.http_proxy = http_proxy
        self.https_proxy = https_proxy
        self.no_proxy = no_proxy

    def current_http_proxy(self):
        return self.current_proxy_value('httpProxy')

    def current_https_proxy(self):
        return self.current_proxy_value('httpsProxy')

    def current_no_proxy(self):
        return self.current_proxy_value('noProxy')

    def current_proxy_value(self, proxy_key):
        value = None
        if 'proxies' in self.data and 'default' in self.data['proxies'] and proxy_key in self.data['proxies']['default']:
            value = self.data['proxies']['default'][proxy_key]
        return value

    def changed(self):
        return self.http_proxy != self.current_http_proxy() or self.https_proxy != self.current_https_proxy() or self.no_proxy != self.current_no_proxy()

    def change(self):
        if not 'proxies' in self.data:
            self.data['proxies'] = {}
        if not 'default' in self.data['proxies']:
            self.data['proxies']['default'] = {}

        self.data['proxies']['default']['httpProxy'] = self.http_proxy
        self.data['proxies']['default']['httpsProxy'] = self.https_proxy
        self.data['proxies']['default']['noProxy'] = self.no_proxy

        self.json_wrapper.write(self.data)

def main():
    fields = {
        "http_proxy": {"required": True, "type": "str"},
        "https_proxy": {"required": True, "type": "str"},
        "no_proxy": {"required": True, "type": "str"},
        "path": {"required": True, "type": "str"}
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    path = module.params['path']
    http_proxy = module.params['http_proxy']
    https_proxy = module.params['https_proxy']
    no_proxy = module.params['no_proxy']

    dockerConfigJson = DockerConfigJson(path, http_proxy, https_proxy, no_proxy)
    changed = dockerConfigJson.changed()

    if module.check_mode:
        module.exit_json(changed=changed)

    if changed:
        dockerConfigJson.change()

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
