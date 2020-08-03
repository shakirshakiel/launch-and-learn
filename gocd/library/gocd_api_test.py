import base64
import pytest
from unittest import mock
from unittest.mock import MagicMock, patch, DEFAULT
import requests
import requests_mock
import gocd_api


class TestGocdConfigs:
    def test_config_resources(self):
        assert gocd_api.RESOURCES == ['authorization', 'pipeline_groups', 'roles']

    def test_config_non_resources(self):
        assert gocd_api.NON_RESOURCES == ['artifacts', 'backup', 'default_job_timeout', 'site_urls', 'system_admins']


class TestGocdApi:
    DOMAIN = 'http://localhost:8153'
    CONFIG_TYPE = 'test'
    TEST_ENTITY_PATH = '/go/api/admin/test'
    ACCEPT_HEADER = 'application/vnd.go.cd.v1+json'
    ENTITY_ID = 1
    TEST_ENTITY_PATH_CONFIG = {
        CONFIG_TYPE: {
            'entity_path': TEST_ENTITY_PATH,
            'Accept': ACCEPT_HEADER,
            'type': 'resource',
            'comparison_keys_ignore': ['ignore_1', 'ignore_2']
        }
    }
    TEST_NON_RESOURCE_ENTITY_PATH_CONFIG = {
        CONFIG_TYPE: {
            'entity_path': TEST_ENTITY_PATH,
            'Accept': ACCEPT_HEADER,
            'type': 'non-resource'
        }
    }
    USERNAME = "gocd"
    PASSWORD = "gocd"

    # entity_url tests

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_entity_url_should_return_url_without_entity_id(self):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN)
        assert gocd_api_request.entity_url() == "{}{}".format(self.DOMAIN, self.TEST_ENTITY_PATH)

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_entity_url_should_return_url_with_entity_id(self):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
        assert gocd_api_request.entity_url() == "{}{}/{}".format(self.DOMAIN, self.TEST_ENTITY_PATH, self.ENTITY_ID)

    @patch("gocd_api.CONFIGS", {CONFIG_TYPE: {'entity_path': TEST_ENTITY_PATH + "/"}})
    def test_entity_url_should_return_url_with_entity_id_when_entity_path_has_trailing_slash(self):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
        assert gocd_api_request.entity_url() == "{}{}/{}".format(self.DOMAIN, self.TEST_ENTITY_PATH, self.ENTITY_ID)

    # collection_url tests

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_collection_url(self):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
        assert gocd_api_request.collection_url() == "{}{}".format(self.DOMAIN, self.TEST_ENTITY_PATH)

    # basic_params tests

    @patch.object(gocd_api.GocdApiRequest, "is_auth_not_required", return_value=True)
    def test_basic_params_should_return_params_without_auth_key_when_username_and_password_are_none(self, mock):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
        params = gocd_api_request.basic_params()
        assert 'auth' not in params

    @patch.object(gocd_api.GocdApiRequest, "is_auth_not_required", return_value=False)
    def test_basic_params_should_return_params_with_auth_key_when_username_and_password_are_none(self, mock):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD)
        params = gocd_api_request.basic_params()
        assert 'auth' in params
        assert params['auth'] == requests.auth.HTTPBasicAuth(self.USERNAME, self.PASSWORD)

    # is_auth_not_required tests

    def test_is_auth_not_required_should_return_true_when_username_and_password_are_none(self):
        gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
        assert gocd_api_request.is_auth_not_required()

    def test_is_auth_not_required_should_return_true_when_status_code_of_encrypt_api_is_401_with_message(self):
        authorization = str(base64.b64encode("{}:{}".format(self.USERNAME, self.PASSWORD).encode("utf-8")), 'utf-8')
        request_headers = {
            'Accept': 'application/vnd.go.cd.v1+json',
            'Content-Type': 'application/json',
            'Authorization': "Basic {}".format(authorization)
        }

        with requests_mock.Mocker() as mock:
            mock.register_uri('POST',
                              "{}{}".format(self.DOMAIN, "/go/api/admin/encrypt"),
                              request_headers=request_headers,
                              json={
                                  "message": "Basic authentication credentials are not required, since security has been disabled on this server."
                              },
                              status_code=401)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD)
            assert gocd_api_request.is_auth_not_required()

    def test_is_auth_not_required_should_return_false_when_status_code_of_encrypt_api_is_not_401(self):
        authorization = str(base64.b64encode("{}:{}".format(self.USERNAME, self.PASSWORD).encode("utf-8")), 'utf-8')
        request_headers = {
            'Accept': 'application/vnd.go.cd.v1+json',
            'Content-Type': 'application/json',
            'Authorization': "Basic {}".format(authorization)
        }

        with requests_mock.Mocker() as mock:
            mock.register_uri('POST',
                              "{}{}".format(self.DOMAIN, "/go/api/admin/encrypt"),
                              request_headers=request_headers,
                              json={"value": "AES:encrypted-text"},
                              status_code=200)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD)
            assert not gocd_api_request.is_auth_not_required()

    def test_is_auth_not_required_should_return_false_when_status_code_of_encrypt_api_is_401_but_incorrect_message(
            self):
        authorization = str(base64.b64encode("{}:{}".format(self.USERNAME, self.PASSWORD).encode("utf-8")), 'utf-8')
        request_headers = {
            'Accept': 'application/vnd.go.cd.v1+json',
            'Content-Type': 'application/json',
            'Authorization': "Basic {}".format(authorization)
        }

        with requests_mock.Mocker() as mock:
            mock.register_uri('POST',
                              "{}{}".format(self.DOMAIN, "/go/api/admin/encrypt"),
                              request_headers=request_headers,
                              json={"message": "Incorrect"},
                              status_code=401)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD)
            assert not gocd_api_request.is_auth_not_required()

    # Get Requests

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    @patch.multiple(gocd_api.GocdApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    entity_url=MagicMock(return_value="http://entity_url/entity_id")
                    )
    def test_get_entity(self):
        request_headers = {
            'Accept': self.ACCEPT_HEADER,
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('GET', "http://entity_url/entity_id",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
            get_result = gocd_api_request.get_entity()
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    # Post Requests

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    @patch.multiple(gocd_api.GocdApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    collection_url=MagicMock(return_value="http://entity_url/entity_id")
                    )
    def test_post_entity(self):
        data = {'data-key': 'data-value'}
        request_headers = {
            'Accept': self.ACCEPT_HEADER,
            'Content-Type': 'application/json'
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('POST', "http://entity_url/entity_id",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
            get_result = gocd_api_request.post_entity(data)
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    # Put Requests

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    @patch.multiple(gocd_api.GocdApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    entity_url=MagicMock(return_value="http://entity_url/entity_id")
                    )
    def test_put_entity_with_etag(self):
        data = {'data-key': 'data-value'}
        etag = 'etag'
        request_headers = {
            'Accept': self.ACCEPT_HEADER,
            'Content-Type': 'application/json',
            'If-Match': etag
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('PUT', "http://entity_url/entity_id",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
            get_result = gocd_api_request.put_entity(etag, data)
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    @patch.multiple(gocd_api.GocdApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    entity_url=MagicMock(return_value="http://entity_url/entity_id")
                    )
    def test_put_entity_without_etag(self):
        data = {'data-key': 'data-value'}
        etag = None
        request_headers = {
            'Accept': self.ACCEPT_HEADER,
            'Content-Type': 'application/json',
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('PUT', "http://entity_url/entity_id",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
            get_result = gocd_api_request.put_entity(etag, data)
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    # Delete Requests

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    @patch.multiple(gocd_api.GocdApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    entity_url=MagicMock(return_value="http://entity_url/entity_id")
                    )
    def test_delete_entity(self):
        request_headers = {
            'Accept': self.ACCEPT_HEADER,
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('DELETE', "http://entity_url/entity_id",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            gocd_api_request = gocd_api.GocdApiRequest(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID)
            get_result = gocd_api_request.delete_entity()
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    # GocdApiService

    @patch.object(gocd_api.GocdApiRequest, "post_entity", return_value=dict(a='b'))
    def test_gocd_api_service_should_create(self, mock_method):
        data = dict(x='y')
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, data, 'present')
        result = gocd_api_service.create()
        assert result == dict(a='b')
        mock_method.assert_called_with(data)

    def test_gocd_api_service_should_update_when_etag_is_not_present(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT, put_entity=DEFAULT) as values:
            headers = dict(some_header='some-value')
            data = dict(x='y')
            put_data = dict(put_key='put-value')

            values['get_entity'].return_value.headers = headers
            values['put_entity'].return_value = put_data

            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, data, 'present')
            result = gocd_api_service.update()

            assert result == put_data
            values['put_entity'].assert_called_with(None, data)

    def test_gocd_api_service_should_update_when_etag_is_present(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT, put_entity=DEFAULT) as values:
            etag = 'abcdefgh-kjlkm'
            headers = {'ETag': etag}
            data = dict(x='y')
            put_data = dict(put_key='put-value')

            values['get_entity'].return_value.headers = headers
            values['put_entity'].return_value = put_data

            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, data, 'present')
            result = gocd_api_service.update()

            assert result == put_data
            values['put_entity'].assert_called_with(etag, data)

    @patch.object(gocd_api.GocdApiRequest, "delete_entity", return_value=dict(a='b'))
    def test_gocd_api_service_should_delete(self, mock_method):
        data = dict(x='y')
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, data, 'present')
        result = gocd_api_service.delete()
        assert result == dict(a='b')

    # Should create

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_create_returns_false_if_state_is_absent(self):
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, None, 'absent')
        assert not gocd_api_service.should_create()

    @patch("gocd_api.CONFIGS", TEST_NON_RESOURCE_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_create_returns_false_if_resource_is_a_non_resource(self):
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, None, 'absent')
        assert not gocd_api_service.should_create()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_create_returns_false_if_resource_already_exists(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 200
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, None, 'present')
            assert not gocd_api_service.should_create()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_create_returns_true_if_resource_does_not_exist(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 404
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, None, 'present')
            assert gocd_api_service.should_create()

    # Should update

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_update_returns_false_if_state_is_absent(self):
        data = dict(x='y')
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, data, 'absent')
        assert not gocd_api_service.should_update()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_update_returns_false_if_resource_does_not_exist(self):
        data = dict(x='y')
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 404
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, data, 'present')
            assert not gocd_api_service.should_update()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_update_returns_false_if_resource_already_exists_and_data_is_same(self):
        data = dict(x='y')
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 200
            values['get_entity'].return_value.json.return_value = dict(x='y', _links='links')
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, data, 'present')
            assert not gocd_api_service.should_update()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_update_returns_true_if_resource_already_exists_and_data_is_different(self):
        data = dict(x='y')
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 200
            values['get_entity'].return_value.json.return_value = dict(x1='y1')
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, data, 'present')
            assert gocd_api_service.should_update()

    # Should delete

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_delete_returns_false_if_state_is_present(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 200
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, None, 'present')
            assert not gocd_api_service.should_delete()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_delete_returns_false_if_resource_does_not_exist(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 404
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, None, 'absent')
            assert not gocd_api_service.should_delete()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_should_delete_returns_true_if_resource_exist_and_state_is_absent(self):
        with patch.multiple(gocd_api.GocdApiRequest, get_entity=DEFAULT) as values:
            values['get_entity'].return_value.status_code = 200
            gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                       self.PASSWORD, None, 'absent')
            assert gocd_api_service.should_delete()

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_is_data_same_should_return_true_if_data_is_same(self):
        other_data = {
            "location": {
                "city": "",
                "state": None,
                "tags": []
            },
            "name": "Nick's Caffee",
            "reviews": [{}]
        }
        data = {"name": "Nick's Caffee"}
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, data, 'absent')
        assert gocd_api_service.is_data_same(other_data)

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_is_data_same_should_return_true_if_data_is_same_after_removing_ignore_keys(self):
        other_data = {
            "location": {
                "city": "",
                "state": None,
                "tags": []
            },
            "name": "Nick's Caffee",
            "reviews": [{}],
            "ignore_2": [{"x": "y"}, {"x1": "y1"}],
            "_links": "links"
        }
        data = {"name": "Nick's Caffee"}
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, data, 'absent')
        assert gocd_api_service.is_data_same(other_data)

    @patch("gocd_api.CONFIGS", TEST_ENTITY_PATH_CONFIG)
    def test_gocd_api_service_is_data_same_should_return_false_if_data_is_not_same_after_removing_ignore_keys(self):
        other_data = {
            "location": {
                "city": "",
                "state": None,
                "tags": []
            },
            "name": "Nick's Caffee Shop",
            "reviews": [{}],
            "ignore_2": [{"x": "y"}, {"x1": "y1"}],
            "_links": "links"
        }
        data = {"name": "Nick's Caffee"}
        gocd_api_service = gocd_api.GocdApiService(self.CONFIG_TYPE, self.DOMAIN, self.ENTITY_ID, self.USERNAME,
                                                   self.PASSWORD, data, 'absent')
        assert not gocd_api_service.is_data_same(other_data)
