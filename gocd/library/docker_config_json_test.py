import pytest
from unittest.mock import patch, DEFAULT
import docker_config_json

class TestDockerConfigJson:

    PATH = "dummy_path"
    HTTP_PROXY = "http://proxy.example.com"
    HTTPS_PROXY = "https://proxy.example.com"
    NO_PROXY = ".example.com"
    DATA_WITH_PROXIES = {
        "proxies": {
            "default": {
                "httpProxy": HTTP_PROXY,
                "httpsProxy": HTTPS_PROXY,
                "noProxy": NO_PROXY
            }
        }
    }

    def test_current_proxy_value_from_json(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = self.DATA_WITH_PROXIES

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, self.NO_PROXY)
            assert dockerConfigJson.current_http_proxy() == self.HTTP_PROXY
            assert dockerConfigJson.current_https_proxy() == self.HTTPS_PROXY
            assert dockerConfigJson.current_no_proxy() == self.NO_PROXY

    def test_current_proxy_from_json_when_proxies_field_is_not_present(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = {}

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, self.NO_PROXY)
            assert dockerConfigJson.current_http_proxy() is None
            assert dockerConfigJson.current_https_proxy() is None
            assert dockerConfigJson.current_no_proxy() is None

    def test_current_proxy_from_json_when_default_field_in_proxies_is_not_present(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = {"proxies": {}}

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, self.NO_PROXY)
            assert dockerConfigJson.current_http_proxy() is None
            assert dockerConfigJson.current_https_proxy() is None
            assert dockerConfigJson.current_no_proxy() is None

    def test_current_proxy_from_json_when_proxy_field_is_not_present(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = {"proxies": {"default": {}}}

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, self.NO_PROXY)
            assert dockerConfigJson.current_http_proxy() is None
            assert dockerConfigJson.current_https_proxy() is None
            assert dockerConfigJson.current_no_proxy() is None

    def test_changed_should_return_false_when_there_is_no_change(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = self.DATA_WITH_PROXIES

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, self.NO_PROXY)
            assert dockerConfigJson.changed() is False

    def test_changed_should_return_true_when_http_proxy_is_changed(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = self.DATA_WITH_PROXIES

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, "http://newproxy.example.com", self.HTTPS_PROXY, self.NO_PROXY)
            assert dockerConfigJson.changed() is True

    def test_changed_should_return_true_when_https_proxy_is_changed(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = self.DATA_WITH_PROXIES

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, "https://newproxy.example.com", self.NO_PROXY)
            assert dockerConfigJson.changed() is True

    def test_changed_should_return_true_when_no_proxy_is_changed(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT) as values:
            values['read'].return_value = self.DATA_WITH_PROXIES

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, "localhost,127.0.0.1")
            assert dockerConfigJson.changed() is True

    def test_change_should_write_to_json(self):
        with patch.multiple(docker_config_json.JsonWrapper, read=DEFAULT, write=DEFAULT) as values:
            values['read'].return_value = {}

            dockerConfigJson = docker_config_json.DockerConfigJson(self.PATH, self.HTTP_PROXY, self.HTTPS_PROXY, self.NO_PROXY)
            dockerConfigJson.change()

            values['write'].assert_called_with(self.DATA_WITH_PROXIES)

