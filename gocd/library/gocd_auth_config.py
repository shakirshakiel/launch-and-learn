#!/usr/bin/python

from ansible.module_utils.basic import *
import json
import requests
import copy
import pdb

def main():
    fields = dict(
        domain= dict(required=True, type="str"),
        get_path= dict(required=True, type="str"),
        data= dict(required=True, type="dict"),
        post_path= dict(required=False, type="str"),
        username= dict(required=False, type="str"),
        password= dict(required=False, type="str"),
        state=dict(required=False, type="str", default='present', choices=['absent', 'present']),
    )

    module = AnsibleModule(argument_spec=fields,
                           required_together=[['username', 'password']],
                           no_log=['password'],
                           supports_check_mode=True)
    domain = module.params['domain']
    get_path = module.params['get_path']
    post_path = module.params['post_path']
    data = module.params['data']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']
    auth = requests.auth.HTTPBasicAuth(username, password)

    get_result = get_entity(domain, get_path, auth)

    if state == "absent":
        if get_result.status_code != 200:
            module.exit_json(changed=False)

        delete_result = delete_entity(domain, get_path, auth)
        module.exit_json(changed=True, meta=delete_result.json())

    if get_result.status_code != 200:
        if module.check_mode:
            module.exit_json(changed=True)
        post_result = post_entity(domain, post_path, auth, data)
        module.exit_json(changed=True, meta=post_result.json())

    if can_skip_update(get_result, data):
        module.exit_json(changed=False, meta=get_result.json())

    if module.check_mode:
        module.exit_json(changed=True, meta=get_result.json())

    etag = etag_from_header(get_result)
    put_result = put_entity(domain, get_path, auth, etag, data)
    module.exit_json(changed=True, meta=put_result.json())

def get_entity(domain, path, auth):
    url = "{}{}".format(domain, path)
    headers = {
        'Accept': 'application/vnd.go.cd.v2+json'
    }
    result = requests.get(url, headers=headers, auth=auth)
    if auth_not_required(result):
        result = requests.get(url, headers=headers)
    return result

def post_entity(domain, path, auth, data):
    url = "{}{}".format(domain, path)
    headers = {
        'Accept': 'application/vnd.go.cd.v2+json',
        'Content-Type': 'application/json'
    }
    result = requests.post(url, json.dumps(data), auth=auth, headers=headers)
    if auth_not_required(result):
        result = requests.post(url, json.dumps(data), headers=headers)
    return result

def put_entity(domain, path, auth, etag, data):
    url = "{}{}".format(domain, path)
    headers = {
        'Accept': 'application/vnd.go.cd.v2+json',
        'Content-Type': 'application/json',
        'If-Match': etag
    }
    result = requests.put(url, json.dumps(data), auth=auth, headers=headers)
    if auth_not_required(result):
        result = requests.put(url, json.dumps(data), headers=headers)
    return result

def delete_entity(domain, path, auth):
    url = "{}{}".format(domain, path)
    headers = {
        'Accept': 'application/vnd.go.cd.v2+json'
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