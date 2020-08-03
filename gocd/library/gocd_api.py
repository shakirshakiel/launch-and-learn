#!/usr/bin/python

from ansible.module_utils.basic import *
import json
import requests
import copy
import pdb

RESOURCE_TYPE = 'resource'
NON_RESOURCE_TYPE = 'non-resource'

CONFIGS = {
    'artifacts': {
        'entity_path': '/go/api/admin/config/server/artifact_config',
        'Accept': 'application/vnd.go.cd.v1+json',
        'type': NON_RESOURCE_TYPE
    },
    'authorization': {
        'entity_path': '/go/api/admin/security/auth_configs',
        'Accept': 'application/vnd.go.cd.v2+json',
        'type': RESOURCE_TYPE
    },
    'backup': {
        'entity_path': '/go/api/config/backup',
        'Accept': 'application/vnd.go.cd.v1+json',
        'type': NON_RESOURCE_TYPE
    },
    'default_job_timeout': {
        'entity_path': '/go/api/admin/config/server/default_job_timeout',
        'Accept': 'application/vnd.go.cd.v1+json',
        'type': NON_RESOURCE_TYPE
    },
    'pipeline_groups': {
        'entity_path': '/go/api/admin/pipeline_groups',
        'comparison_keys_ignore': ['pipelines'],
        'Accept': 'application/vnd.go.cd.v1+json',
        'type': RESOURCE_TYPE
    },
    'roles': {
        'entity_path': '/go/api/admin/security/roles',
        'Accept': 'application/vnd.go.cd.v3+json',
        'type': RESOURCE_TYPE
    },
    'site_urls': {
        'entity_path': '/go/api/admin/config/server/site_urls',
        'Accept': 'application/vnd.go.cd.v1+json',
        'type': NON_RESOURCE_TYPE
    },
    'system_admins': {
        'entity_path': '/go/api/admin/security/system_admins',
        'Accept': 'application/vnd.go.cd.v2+json',
        'type': NON_RESOURCE_TYPE
    }

}

CONFIG_TYPES = CONFIGS.keys()
RESOURCES = [i for i in CONFIG_TYPES if CONFIGS[i]['type'] == RESOURCE_TYPE ]
NON_RESOURCES = [i for i in CONFIG_TYPES if CONFIGS[i]['type'] == NON_RESOURCE_TYPE ]


class GocdApiRequest:

    def __init__(self, config_type, domain, entity_id = None, username = None, password = None):
        self.config_type = config_type
        self.domain = domain
        self.username = username
        self.password = password
        self.entity_id = entity_id
        self.__auth = requests.auth.HTTPBasicAuth(self.username, self.password)

    def get_entity(self):
        url = self.entity_url()
        headers = {
            'Accept': CONFIGS[self.config_type]['Accept']
        }
        params = self.basic_params()
        params['headers'] = headers
        result = requests.get(url, **params)
        return result

    def post_entity(self, data):
        url = self.collection_url()
        headers = {
            'Accept': CONFIGS[self.config_type]['Accept'],
            'Content-Type': 'application/json'
        }
        params = self.basic_params()
        params['headers'] = headers
        result = requests.post(url, json.dumps(data), **params)
        return result

    def put_entity(self, etag, data):
        url = self.entity_url()
        headers = {
            'Accept': CONFIGS[self.config_type]['Accept'],
            'Content-Type': 'application/json'
        }
        if etag is not None or etag != '':
            headers['If-Match'] = etag

        params = self.basic_params()
        params['headers'] = headers
        result = requests.put(url, json.dumps(data), **params)
        return result

    def delete_entity(self):
        url = self.entity_url()
        headers = {
            'Accept': CONFIGS[self.config_type]['Accept']
        }
        params = self.basic_params()
        params['headers'] = headers
        result = requests.delete(url, **params)
        return result

    def entity_url(self):
        url = "{}{}".format(self.domain, CONFIGS[self.config_type]['entity_path'])
        if self.entity_id is not None:
            if not url.endswith("/"):
                url += "/"
            url = "{}{}".format(url, self.entity_id)
        return url

    def collection_url(self):
        return "{}{}".format(self.domain, CONFIGS[self.config_type]['entity_path'])

    def basic_params(self):
        params = dict()
        if self.is_auth_not_required():
            return params

        params['auth'] = self.__auth
        return params

    def is_auth_not_required(self):
        if self.username is None and self.password is None:
            return True
        headers = {
            'Accept': 'application/vnd.go.cd.v1+json',
            'Content-Type': 'application/json'
        }
        data = {
            "value": "test"
        }
        url = "{}{}".format(self.domain, "/go/api/admin/encrypt")
        response = requests.post(url, json.dumps(data), auth=self.__auth, headers=headers)
        return response.status_code == 401 and response.json()['message'].startswith('Basic authentication credentials are not required')


class GocdApiService:

    def __init__(self, config_type, domain, entity_id, username, password, data, state):
        self.config_type = config_type
        self.domain = domain
        self.entity_id = entity_id
        self.username = username
        self.password = password
        self.data = data
        self.state = state

    def gocd_api_request(self):
        return GocdApiRequest(self.config_type, self.domain, self.entity_id, self.username, self.password)

    def create(self):
        return self.gocd_api_request().post_entity(self.data)

    def update(self):
        result = self.gocd_api_request().get_entity()
        etag = self.__sanitized_etag(result.headers)
        return self.gocd_api_request().put_entity(etag, self.data)

    def delete(self):
        return self.gocd_api_request().delete_entity()

    def should_create(self):
        if self.config_type in NON_RESOURCES or self.state == "absent":
            return False

        result = self.gocd_api_request().get_entity()
        if result.status_code == 200:
            return False

        return True

    def should_update(self):
        if self.state == "absent":
            return False

        result = self.gocd_api_request().get_entity()
        if result.status_code != 200:
            return False

        if self.is_data_same(result.json()):
            return False

        return True

    def should_delete(self):
        result = self.gocd_api_request().get_entity()
        if self.state == "absent" and result.status_code == 200:
            return True
        return False

    def is_data_same(self, other_data):
        other_data_copy = copy.deepcopy(other_data)
        if '_links' in other_data_copy:
            other_data_copy.pop('_links')
        if 'comparison_keys_ignore' in CONFIGS[self.config_type]:
            for i in CONFIGS[self.config_type]['comparison_keys_ignore']:
                if i in other_data_copy:
                    other_data_copy.pop(i)

        other_data_copy = self.__remove_empty_fields(other_data_copy)
        return self.data == other_data_copy

    # Ref: https://gist.github.com/tianchu/f7835b08d7c788b79ade
    def __remove_empty_fields(self, data_):
        if isinstance(data_, dict):
            keys = list(data_.keys())
            for key in keys:
                value = data_[key]

                if isinstance(value, dict) or isinstance(value, list):
                    value = self.__remove_empty_fields(value)

                if value in ["", None, [], {}]:
                    del data_[key]

        elif isinstance(data_, list):
            for index in reversed(range(len(data_))):
                value = data_[index]

                if isinstance(value, dict) or isinstance(value, list):
                    value = self.__remove_empty_fields(value)

                if value in ["", None, [], {}]:
                    data_.pop(index)

        return data_

    def __sanitized_etag(self, headers):
        if 'ETag' not in headers:
            return None
        return headers['ETag'].replace('"', '')


def main():
    fields = dict(
        domain=dict(required=True, type="str"),
        config_type=dict(required=True, type="str"),
        entity_id=dict(required=False, type="str"),
        username=dict(required=False, type="str"),
        password=dict(required=False, type="str", no_log=True),
        data=dict(required=True, type="dict"),
        state=dict(required=False, type="str", default='present', choices=['absent', 'present']),
    )

    module = AnsibleModule(argument_spec=fields,
                           required_together=[['username', 'password']],
                           required_if=[["config_type", i, ["entity_id"]] for i in RESOURCES],
                           supports_check_mode=True)

    domain = module.params['domain']
    config_type = module.params['config_type']
    entity_id = module.params['entity_id']
    data = module.params['data']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']

    gocdApiService = GocdApiService(config_type, domain, entity_id, username, password, data, state)
    if gocdApiService.should_create():
        if module.check_mode:
            module.exit_json(changed=True)
        result = gocdApiService.create()
        meta = {"new": result.json()}
        module.exit_json(changed=True, meta=meta)

    if gocdApiService.should_update():
        if module.check_mode:
            module.exit_json(changed=True)
        result = gocdApiService.update()
        meta = {"update": result.json()}
        module.exit_json(changed=True, meta=meta)

    if gocdApiService.should_delete():
        if module.check_mode:
            module.exit_json(changed=True)
        result = gocdApiService.delete()
        meta = {"delete": result.json()}
        module.exit_json(changed=True, meta=meta)

    module.exit_json(changed=False)


if __name__ == '__main__':
    main()