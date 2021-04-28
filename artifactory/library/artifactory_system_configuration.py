#!/usr/bin/python

from ansible.module_utils.basic import *
import json
import requests
import copy
import pdb
import xmltodict
import yaml


class ArtifactoryApiRequest:

    def __init__(self, domain, username, password):
        self.domain = domain
        self.username = username
        self.password = password

    def get_entity(self):
        url = self.url()
        params = self.basic_params()
        result = requests.get(url, **params)
        return result

    def patch_entity(self, data):
        url = self.url()
        params = self.basic_params()
        headers = {
            'Content-Type': 'application/yaml'
        }
        params['headers'] = headers
        result = requests.patch(url, data, **params)
        return result

    def url(self):
        url = "{}{}".format(self.domain, "/api/system/configuration")
        return url

    def basic_params(self):
        params = dict()
        params['auth'] = requests.auth.HTTPBasicAuth(self.username, self.password)
        return params


class ArtifactoryLdapApiService:

    def __init__(self, domain, username, password, ldap_setting, ldap_group_setting, state):
        self.domain = domain
        self.username = username
        self.password = password
        self.ldap_setting = ldap_setting
        self.ldap_group_setting = ldap_group_setting
        self.state = state

    def artifactory_api_request(self):
        return ArtifactoryApiRequest(self.domain, self.username, self.password)

    def get_ldap_configs(self):
        entity = self.artifactory_api_request().get_entity()
        xml = xmltodict.parse(entity.content)
        ldap_settings = json.loads(json.dumps(xml['config']['security']['ldapSettings']))
        ldap_group_settings = json.loads(json.dumps(xml['config']['security']['ldapGroupSettings']))
        return ldap_settings, ldap_group_settings

    def should_update(self):
        if self.state == "absent":
            return False
        ldap_settings, ldap_group_settings = self.get_ldap_configs()
        if ldap_settings is not None and \
                'ldapSetting' in ldap_settings and \
                ldap_settings['ldapSetting'] == self.ldap_setting and \
                ldap_group_settings is not None and \
                'ldapGroupSetting' in ldap_group_settings and \
                ldap_group_settings['ldapGroupSetting'] == self.ldap_group_setting:
            return False
        return True

    def should_delete(self):
        ldap_settings, ldap_group_settings = self.get_ldap_configs()
        if self.state == "absent" and (ldap_settings is not None or ldap_group_settings is not None):
            return True
        return False

    def update(self):
        ldap_setting = copy.deepcopy(self.ldap_setting)
        ldap_group_setting = copy.deepcopy(self.ldap_group_setting)

        ldap_name = ldap_setting.pop('key')
        ldap_group_name = ldap_group_setting.pop('name')
        data = {
            "security": {
                "ldapSettings": {
                    ldap_name: ldap_setting
                },
                "ldapGroupSettings": {
                    ldap_group_name: ldap_group_setting
                }
            }
        }
        return self.artifactory_api_request().patch_entity(yaml.dump(data))

    def delete(self):
        data = {
            "security": {
                "ldapSettings": None,
                "ldapGroupSettings": None
            }
        }
        return self.artifactory_api_request().patch_entity(yaml.dump(data))

class ArtifactoryBackupApiService:

    def __init__(self, domain, username, password, data, state):
        self.domain = domain
        self.username = username
        self.password = password
        self.data = data
        self.state = state

    def artifactory_api_request(self):
        return ArtifactoryApiRequest(self.domain, self.username, self.password)

    def get_backup_configs(self):
        entity = self.artifactory_api_request().get_entity()
        xml = xmltodict.parse(entity.content)
        backups = json.loads(json.dumps(xml['config']['backups']))
        return backups

    def is_data_same(self, remote_data, local_data):
        if len(remote_data) != len(local_data):
            return False

        remote_data_copy = copy.deepcopy(remote_data)
        local_data_copy = copy.deepcopy(local_data)
        sorter = lambda x: x.get('key')
        remote_data_copy.sort(key=sorter)
        local_data_copy.sort(key=sorter)

        for item in remote_data_copy:
            if item['excludedRepositories'] is not None:
                item['excludedRepositories'] = item['excludedRepositories']['repositoryRef']
                item['excludedRepositories'].sort()

        for item in local_data_copy:
            if item['excludedRepositories'] is not None:
                item['excludedRepositories'].sort()

        return local_data_copy == remote_data_copy

    def should_update(self):
        if self.state == "absent":
            return False
        backups = self.get_backup_configs()
        if backups is not None and \
                'backup' in backups and \
                self.is_data_same(backups['backup'], self.data['backups']):
            return False
        return True

    def should_delete(self):
        backups = self.get_backup_configs()
        if self.state == "absent" and 'backup' in backups and len(backups['backup']) > 0:
            return True
        return False

    def update(self):
        other_data = copy.deepcopy(self.data)
        backups_data = other_data['backups']
        data = {"backups": {}}
        for i in backups_data:
            backup_name = i.pop('key')
            data["backups"][backup_name] = i
        return self.artifactory_api_request().patch_entity(yaml.dump(data))

    def delete(self):
        data = {
            "backups": None
        }
        return self.artifactory_api_request().patch_entity(yaml.dump(data))

def main():
    fields = dict(
        domain=dict(required=True, type="str"),
        username=dict(required=True, type="str"),
        password=dict(required=True, type="str", no_log=True),
        config_type=dict(required=True, type="str", choices=['ldap', 'backups']),
        data=dict(required=True, type="dict"),
        state=dict(required=False, type="str", default='present', choices=['absent', 'present']),
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    domain = module.params['domain']
    username = module.params['username']
    password = module.params['password']
    config_type = module.params['config_type']
    data = module.params['data']
    state = module.params['state']

    artifactory_api_service = None

    if config_type == "ldap":
        if 'ldapSetting' not in data or 'ldapGroupSetting' not in data:
            module.fail_json(msg="ldapSetting and ldapGroupSetting in data are mandatory", changed=False)
        artifactory_api_service = ArtifactoryLdapApiService(domain, username, password, data['ldapSetting'], data['ldapGroupSetting'], state)

    if config_type == 'backups':
        if 'backups' not in data:
            module.fail_json(msg="backups in data is mandatory", changed=False)
        artifactory_api_service = ArtifactoryBackupApiService(domain, username, password, data, state)

    if artifactory_api_service.should_update():
        if module.check_mode:
            module.exit_json(changed=True)
        result = artifactory_api_service.update()
        meta = {"update": result.content}
        module.exit_json(changed=True, meta=meta)

    if artifactory_api_service.should_delete():
        if module.check_mode:
            module.exit_json(changed=True)
        result = artifactory_api_service.delete()
        meta = {"delete": result.content}
        module.exit_json(changed=True, meta=meta)

    module.exit_json(changed=False)


if __name__ == '__main__':
    main()
