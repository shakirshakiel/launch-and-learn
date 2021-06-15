import pytest
from unittest import mock
from unittest.mock import MagicMock, patch, DEFAULT
import requests
import requests_mock
import artifactory_system_configuration


class TestArtifactoryApiRequest:
    DOMAIN = 'http://localhost:8082/artifactory'
    USERNAME = "admin"
    PASSWORD = "admin"
    TEST_PATH = "/test"

    # url

    def test_url_should_return_url_with_path(self):
        artifactory_api_request = artifactory_system_configuration.ArtifactoryApiRequest(self.DOMAIN, self.USERNAME,
                                                                                         self.PASSWORD)
        assert artifactory_api_request.url() == "http://localhost:8082/artifactory/api/system/configuration"

    def test_url_should_return_url_with_fixed_double_slash_in_path(self):
        assert artifactory_system_configuration.ArtifactoryApiRequest(self.DOMAIN, self.USERNAME, self.PASSWORD).url() \
               == "http://localhost:8082/artifactory/api/system/configuration"
        assert artifactory_system_configuration.ArtifactoryApiRequest(self.DOMAIN + '/', self.USERNAME,
                                                                      self.PASSWORD).url() \
               == "http://localhost:8082/artifactory/api/system/configuration"

    # basic_params

    def test_basic_params_should_return_auth_heaers(self):
        artifactory_api_request = artifactory_system_configuration.ArtifactoryApiRequest(self.DOMAIN, self.USERNAME,
                                                                                         self.PASSWORD)
        params = artifactory_api_request.basic_params()

        assert 'auth' in params
        assert params['auth'] == requests.auth.HTTPBasicAuth(self.USERNAME, self.PASSWORD)

    # GET Requests

    @patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    url=MagicMock(return_value="http://domain/path")
                    )
    def test_get_entity(self):
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('GET', "http://domain/path",
                                      json=response_json,
                                      status_code=200)
            artifactory_api_request = artifactory_system_configuration.ArtifactoryApiRequest(self.DOMAIN,
                                                                                             self.USERNAME,
                                                                                             self.PASSWORD)
            get_result = artifactory_api_request.get_entity()
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    # PUT Requests

    @patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    url=MagicMock(return_value="http://domain/path")
                    )
    def test_patch_entity(self):
        data = {'data-key': 'data-value'}
        request_headers = {
            'Content-Type': 'application/yaml'
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('PATCH', "http://domain/path",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            artifactory_api_request = artifactory_system_configuration.ArtifactoryApiRequest(self.DOMAIN,
                                                                                             self.USERNAME,
                                                                                             self.PASSWORD)
            put_result = artifactory_api_request.patch_entity(data)
            assert put_result.status_code == 200
            assert put_result.json() == response_json


class TestArtifactoryLdapApiService:
    DOMAIN = 'http://localhost:8082/artifactory'
    USERNAME = "admin"
    PASSWORD = "admin"

    LDAP_SETTING = {
        "key": "prod-ldap",
        "ldapUrl": "ldap://ldap.forumsys.com"
    }
    LDAP_GROUP_SETTING = {
        "name": "prod-ldap-group",
        "groupBaseDn": "dc=example,dc=com"
    }
    DATA = """security:
  ldapGroupSettings:
    prod-ldap-group:
      groupBaseDn: dc=example,dc=com
  ldapSettings:
    prod-ldap:
      ldapUrl: ldap://ldap.forumsys.com
"""

    # get_ldap_configs

    def test_artifactory_api_service_should_get_ldap_configs(self):
        xml_data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<config xmlns="http://artifactory.jfrog.org/xsd/3.1.11">
    <security>
        <ldapSettings>
            <ldapSetting>
                <key>prod-ldap</key>
                <ldapUrl>ldap://ldap.forumsys.com</ldapUrl>
            </ldapSetting>
        </ldapSettings>
        <ldapGroupSettings>
             <ldapGroupSetting>
                <name>prod-ldap-group</name>
                <groupBaseDn>dc=example,dc=com</groupBaseDn>
              </ldapGroupSetting>
        </ldapGroupSettings>
    </security>
</config>        
        """
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(content=xml_data)
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            ldap_settings, ldap_group_settings = artifactory_api_service.get_ldap_configs()

            assert ldap_settings == {"ldapSetting": self.LDAP_SETTING}
            assert ldap_group_settings == {"ldapGroupSetting": self.LDAP_GROUP_SETTING}

    # should_update

    def test_artifactory_api_service_should_update_returns_false_if_state_is_absent(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            assert not artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_false_if_settings_are_same(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert not artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_ldap_settings_is_none(self):
        ldap_settings = None
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_ldap_settings_key_is_none(self):
        ldap_settings = {'ldapSetting': None}
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_ldap_settings_are_different(self):
        ldap_settings = {'ldapSetting': {"key": "prod-ldap2", "ldapUrl": "ldap://ldap.forumsys.com"}}
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_ldap_group_settings_is_none(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = None
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_ldap_group_settings_key_is_none(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = {'ldapGroupSetting': None}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_ldap_group_settings_are_different(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = {'ldapGroupSetting': {"name": "prod-ldap-group2", "groupBaseDn": "dc=example,dc=com"}}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert artifactory_api_service.should_update()

    #  Update

    def test_artifactory_api_service_should_update(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest, patch_entity=DEFAULT) as values:
            values['patch_entity'].return_value = dict(a='b')
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            result = artifactory_api_service.update()

            values['patch_entity'].assert_called_with(self.DATA)
            assert result == dict(a='b')

    # should_delete

    def test_artifactory_api_service_should_delete_returns_true_if_state_is_absent_and_settings_present(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            assert artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_true_if_only_ldap_setting_is_none(self):
        ldap_settings = None
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            assert artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_true_if_only_ldap_group_setting_is_none(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = None
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            assert artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_false_if_both_settings_are_none(self):
        ldap_settings = None
        ldap_group_settings = None
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            assert not artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_true_if_state_is_present(self):
        ldap_settings = {'ldapSetting': self.LDAP_SETTING}
        ldap_group_settings = {'ldapGroupSetting': self.LDAP_GROUP_SETTING}
        with patch.multiple(artifactory_system_configuration.ArtifactoryLdapApiService,
                            get_ldap_configs=DEFAULT) as values:
            values['get_ldap_configs'].return_value = ldap_settings, ldap_group_settings
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "present")
            assert not artifactory_api_service.should_delete()

    # delete

    def test_artifactory_api_service_should_delete(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest, patch_entity=DEFAULT) as values:
            data = """security:
  ldapGroupSettings: null
  ldapSettings: null
"""
            values['patch_entity'].return_value = dict(a='b')
            artifactory_api_service = artifactory_system_configuration.ArtifactoryLdapApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.LDAP_SETTING,
                                                                                                 self.LDAP_GROUP_SETTING,
                                                                                                 "absent")
            result = artifactory_api_service.delete()

            values['patch_entity'].assert_called_with(data)
            assert result == dict(a='b')


class TestArtifactoryProxyApiService:
    DOMAIN = 'http://localhost:8082/artifactory'
    USERNAME = "admin"
    PASSWORD = "admin"

    PROXIES = [
        {
            "key": "defaultProxy",
            "host": "proxy.test.com"
        }
    ]
    DATA = """proxies:
  defaultProxy:
    host: proxy.test.com
"""

    # get_proxy_configs

    def test_artifactory_api_service_should_get_proxy_configs(self):
        xml_data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<config xmlns="http://artifactory.jfrog.org/xsd/3.1.11">
    <proxies>
        <proxy>
            <key>defaultProxy</key>
            <host>proxy.test.com</host>
        </proxy>
    </proxies>
</config>        
        """
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(content=xml_data)
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "present")
            proxies = artifactory_api_service.get_proxy_configs()

            assert proxies['proxy'] == self.PROXIES

    def test_artifactory_api_service_should_get_proxy_configs_should_return_none(self):
        xml_data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<config xmlns="http://artifactory.jfrog.org/xsd/3.1.11">
    <proxies/>
</config>        
        """
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(content=xml_data)
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "present")
            proxies = artifactory_api_service.get_proxy_configs()

            assert proxies is None

    def test_artifactory_api_service_should_get_proxy_configs_for_multiple_proxies(self):
        xml_data = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<config xmlns="http://artifactory.jfrog.org/xsd/3.1.11">
    <proxies>
        <proxy>
            <key>defaultProxy</key>
            <host>proxy.test.com</host>
        </proxy>
        <proxy>
            <key>defaultProxy2</key>
            <host>proxy.test2.com</host>
        </proxy>
    </proxies>
</config>        
        """
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(content=xml_data)
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "present")
            proxies = artifactory_api_service.get_proxy_configs()
            assert proxies['proxy'] == [{"key": "defaultProxy", "host": "proxy.test.com"},
                                        {"key": "defaultProxy2", "host": "proxy.test2.com"}]

    # should_update

    def test_artifactory_api_service_should_update_returns_false_if_state_is_absent(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryProxyApiService,
                            get_proxy_configs=DEFAULT) as values:
            values['get_proxy_configs'].return_value = {"proxy": self.PROXIES}
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "absent")
            assert not artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_false_if_proxies_are_same(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryProxyApiService,
                            get_proxy_configs=DEFAULT) as values:
            values['get_proxy_configs'].return_value = {"proxy": self.PROXIES}
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "present")
            assert not artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_true_if_proxies_are_different(self):
        proxies = [{"key": "defaultProxy", "host": "proxy2.test.com"}]

        with patch.multiple(artifactory_system_configuration.ArtifactoryProxyApiService,
                            get_proxy_configs=DEFAULT) as values:
            values['get_proxy_configs'].return_value = {"proxy": self.PROXIES}
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  proxies,
                                                                                                  "present")
            assert artifactory_api_service.should_update()

    #  Update

    def test_artifactory_api_service_should_update(self):
        data = """proxies:
  defaultProxy:
    host: proxy.test.com
  defaultProxy2:
    host: proxy2.test.com
"""
        proxies = [{"key": "defaultProxy", "host": "proxy.test.com"},
                   {"key": "defaultProxy2", "host": "proxy2.test.com"}]
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest, patch_entity=DEFAULT) as values:
            values['patch_entity'].return_value = dict(a='b')
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  proxies,
                                                                                                  "present")
            result = artifactory_api_service.update()

            values['patch_entity'].assert_called_with(data)
            assert result == dict(a='b')

    # should_delete

    def test_artifactory_api_service_should_delete_returns_true_if_state_is_absent_and_proxies_present(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryProxyApiService,
                            get_proxy_configs=DEFAULT) as values:
            values['get_proxy_configs'].return_value = {"proxy": self.PROXIES}
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "absent")
            assert artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_false_if_proxies_are_not_present(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryProxyApiService,
                            get_proxy_configs=DEFAULT) as values:
            values['get_proxy_configs'].return_value = None
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                  self.USERNAME,
                                                                                                  self.PASSWORD,
                                                                                                  self.PROXIES,
                                                                                                  "absent")
            assert not artifactory_api_service.should_delete()


    # delete

    def test_artifactory_api_service_should_delete(self):
        with patch.multiple(artifactory_system_configuration.ArtifactoryApiRequest, patch_entity=DEFAULT) as values:
            data = """proxies: null\n"""
            values['patch_entity'].return_value = dict(a='b')
            artifactory_api_service = artifactory_system_configuration.ArtifactoryProxyApiService(self.DOMAIN,
                                                                                                 self.USERNAME,
                                                                                                 self.PASSWORD,
                                                                                                 self.PROXIES,
                                                                                                 "absent")
            result = artifactory_api_service.delete()

            values['patch_entity'].assert_called_with(data)
            assert result == dict(a='b')
