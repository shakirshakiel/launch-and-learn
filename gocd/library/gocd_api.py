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
        'entity_path': '/go/api/admin/security/auth_configs/',
        'collection_path': '/go/api/admin/security/auth_configs',
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
        'entity_path': '/go/api/admin/pipeline_groups/',
        'collection_path': '/go/api/admin/pipeline_groups',
        'Accept': 'application/vnd.go.cd.v1+json',
        'type': RESOURCE_TYPE
    },
    'roles': {
        'entity_path': '/go/api/admin/security/roles/',
        'collection_path': '/go/api/admin/security/roles',
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

    config_type = module.params['config_type']
    if config_type in RESOURCES:
        handle_resource_type(module)

    if config_type in NON_RESOURCES:
        handle_non_resource_type(module)

def handle_resource_type(module):
    domain = module.params['domain']
    config_type = module.params['config_type']
    entity_id = module.params['entity_id']
    data = module.params['data']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']

    entity_url = "{}{}{}".format(domain, CONFIGS[config_type]['entity_path'], entity_id)
    collection_url = "{}{}".format(domain, CONFIGS[config_type]['collection_path'])
    accept = CONFIGS[config_type]['Accept']
    auth = requests.auth.HTTPBasicAuth(username, password)

    get_result = get_entity(entity_url, auth, accept)

    if state == "absent":
        if get_result.status_code != 200:
            module.exit_json(changed=False)

        delete_result = delete_entity(entity_url, auth, accept)
        module.exit_json(changed=True, meta=delete_result.json())

    if get_result.status_code != 200:
        if module.check_mode:
            module.exit_json(changed=True)
        post_result = post_entity(collection_url, auth, accept, data)
        module.exit_json(changed=True, meta=post_result.json())

    if can_skip_update(get_result, data):
        module.exit_json(changed=False, meta=get_result.json())

    if module.check_mode:
        module.exit_json(changed=True, meta=get_result.json())

    etag = etag_from_header(get_result)
    put_result = put_entity(entity_url, auth, accept, etag, data)
    module.exit_json(changed=True, meta=put_result.json())

def handle_non_resource_type(module):
    domain = module.params['domain']
    config_type = module.params['config_type']
    data = module.params['data']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']

    entity_url = "{}{}".format(domain, CONFIGS[config_type]['entity_path'])
    accept = CONFIGS[config_type]['Accept']
    auth = requests.auth.HTTPBasicAuth(username, password)

    get_result = get_entity(entity_url, auth, accept)

    if state == "absent":
        if get_result.status_code != 200:
            module.exit_json(changed=False)

        delete_result = delete_entity(entity_url, auth, accept)
        module.exit_json(changed=True, meta=delete_result.json())

    if can_skip_update(get_result, data):
        module.exit_json(changed=False, meta=get_result.json())

    if module.check_mode:
        module.exit_json(changed=True, meta=get_result.json())

    etag = etag_from_header(get_result)
    put_result = put_entity(entity_url, auth, accept, etag, data)
    module.exit_json(changed=True, meta=put_result.json())

def get_entity(url, auth, accept):
    headers = {
        'Accept': accept
    }
    result = requests.get(url, headers=headers, auth=auth)
    if auth_not_required(result):
        result = requests.get(url, headers=headers)
    return result

def post_entity(url, auth, accept, data):
    headers = {
        'Accept': accept,
        'Content-Type': 'application/json'
    }
    result = requests.post(url, json.dumps(data), auth=auth, headers=headers)
    if auth_not_required(result):
        result = requests.post(url, json.dumps(data), headers=headers)
    return result

def put_entity(url, auth, accept, etag, data):
    headers = {
        'Accept': accept,
        'Content-Type': 'application/json',
        'If-Match': etag
    }
    result = requests.put(url, json.dumps(data), auth=auth, headers=headers)
    if auth_not_required(result):
        result = requests.put(url, json.dumps(data), headers=headers)
    return result

def delete_entity(url, auth, accept):
    headers = {
        'Accept': accept
    }
    result = requests.delete(url, headers=headers, auth=auth)
    if auth_not_required(result):
        result = requests.delete(url, headers=headers)
    return result

def etag_from_header(get_result):
    etag = ''
    if 'ETag' in get_result.headers:
        etag = get_result.headers['ETag'].replace('"', '')
    return etag

def can_skip_update(get_result, data):
    get_data = get_data_from_response(get_result.json())
    return data == get_data

def get_data_from_response(get_response):
    get_data = copy.deepcopy(get_response)
    get_data.pop('_links')
    return {k:v for k,v in get_data.items() if v is not None}

def auth_not_required(response):
    return response.status_code == 401 and response.json()['message'].startswith('Basic authentication credentials are not required')

if __name__ == '__main__':
    main()