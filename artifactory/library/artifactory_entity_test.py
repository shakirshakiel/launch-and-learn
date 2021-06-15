import pytest
from unittest import mock
from unittest.mock import MagicMock, patch, DEFAULT
import requests
import requests_mock
import copy
import artifactory_entity


class TestArtifactoryApiRequest:
    DOMAIN = 'http://localhost:8082/artifactory'
    USERNAME = "admin"
    PASSWORD = "admin"
    TEST_PATH = "/test"

    # url

    def test_url_should_return_url_with_path(self):
        artifactory_api_request = artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, self.TEST_PATH, self.USERNAME,
                                                                           self.PASSWORD)
        assert artifactory_api_request.url() == "http://localhost:8082/artifactory/test"

    def test_url_should_return_url_with_fixed_double_slash_in_path(self):
        assert artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, "test", self.USERNAME, self.PASSWORD).url() \
               == "http://localhost:8082/artifactory/test"
        assert artifactory_entity.ArtifactoryApiRequest(self.DOMAIN + '/', self.TEST_PATH, self.USERNAME,
                                                        self.PASSWORD).url() \
               == "http://localhost:8082/artifactory/test"
        assert artifactory_entity.ArtifactoryApiRequest(self.DOMAIN + '/', "test", self.USERNAME, self.PASSWORD).url() \
               == "http://localhost:8082/artifactory/test"

    # basic_params

    def test_basic_params_should_return_auth_heaers(self):
        artifactory_api_request = artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, self.TEST_PATH, self.USERNAME,
                                                                           self.PASSWORD)
        params = artifactory_api_request.basic_params()

        assert 'auth' in params
        assert params['auth'] == requests.auth.HTTPBasicAuth(self.USERNAME, self.PASSWORD)

    # GET Requests

    @patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    url=MagicMock(return_value="http://domain/path")
                    )
    def test_get_entity(self):
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('GET', "http://domain/path",
                                      json=response_json,
                                      status_code=200)
            artifactory_api_request = artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, self.TEST_PATH,
                                                                               self.USERNAME, self.PASSWORD)
            get_result = artifactory_api_request.get_entity()
            assert get_result.status_code == 200
            assert get_result.json() == response_json

    # POST Requests

    @patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    url=MagicMock(return_value="http://domain/path")
                    )
    def test_post_entity(self):
        data = {'data-key': 'data-value'}
        request_headers = {
            'Content-Type': 'application/json'
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('POST', "http://domain/path",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            artifactory_api_request = artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, self.TEST_PATH,
                                                                               self.USERNAME, self.PASSWORD)
            post_result = artifactory_api_request.post_entity(data)
            assert post_result.status_code == 200
            assert post_result.json() == response_json

    # PUT Requests

    @patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    url=MagicMock(return_value="http://domain/path")
                    )
    def test_put_entity(self):
        data = {'data-key': 'data-value'}
        request_headers = {
            'Content-Type': 'application/json'
        }
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('PUT', "http://domain/path",
                                      request_headers=request_headers,
                                      json=response_json,
                                      status_code=200)
            artifactory_api_request = artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, self.TEST_PATH,
                                                                               self.USERNAME, self.PASSWORD)
            put_result = artifactory_api_request.put_entity(data)
            assert put_result.status_code == 200
            assert put_result.json() == response_json

    # DELETE Requests

    @patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                    basic_params=MagicMock(return_value=dict()),
                    url=MagicMock(return_value="http://domain/path")
                    )
    def test_delete_entity(self):
        response_json = {'key': 'value'}
        with requests_mock.Mocker() as request_mock:
            request_mock.register_uri('DELETE', "http://domain/path",
                                      json=response_json,
                                      status_code=200)
            artifactory_api_request = artifactory_entity.ArtifactoryApiRequest(self.DOMAIN, self.TEST_PATH,
                                                                               self.USERNAME, self.PASSWORD)
            delete_result = artifactory_api_request.delete_entity()
            assert delete_result.status_code == 200
            assert delete_result.json() == response_json


class TestArtifactoryApiService:
    DOMAIN = 'http://localhost:8082/artifactory'
    USERNAME = "admin"
    PASSWORD = "admin"
    TEST_PATH = "/test"

    TEST_REPO_PACKAGE_TYPE = "alpine"
    TEST_REPO_DATA = {"packageType": TEST_REPO_PACKAGE_TYPE, 'key': 'sample-repo'}

    TEST_ENTITY_TYPE = "test-entity"
    TEST_DATA = {"test-key": "test-value"}

    STATE = "present"

    # is_repo_type

    def test_is_repo_type_should_return_True_if_repository_type(self):
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                        self.USERNAME,
                                                        self.PASSWORD, self.TEST_REPO_DATA, self.STATE).is_repo_type()
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.REMOTE_REPOSITORY_TYPE,
                                                        self.USERNAME,
                                                        self.PASSWORD, self.TEST_REPO_DATA, self.STATE).is_repo_type()
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.VIRTUAL_REPOSITORY_TYPE,
                                                        self.USERNAME,
                                                        self.PASSWORD, self.TEST_REPO_DATA, self.STATE).is_repo_type()

    def test_is_repo_type_should_return_False_if_not_a_repository_type(self):
        assert not artifactory_entity.ArtifactoryApiService(self.DOMAIN, "RANDOM_ENTITY_TYPE", self.USERNAME,
                                                            self.PASSWORD, self.TEST_DATA, self.STATE).is_repo_type()

    # full_data

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {TEST_ENTITY_TYPE: {"default_key": "default_value"}})
    def test_should_return_default_values_in_full_data(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                           self.USERNAME, self.PASSWORD, self.TEST_DATA,
                                                                           self.STATE)
        full_data = artifactory_api_service.full_data()
        assert full_data == {"default_key": "default_value", "test-key": "test-value"}

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {TEST_ENTITY_TYPE: {"default_key": "default_value"}})
    def test_should_return_data_provided_in_full_data(self):
        data = copy.deepcopy(self.TEST_DATA)
        data['default_key'] = 'data_value'

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                           self.USERNAME, self.PASSWORD, data,
                                                                           self.STATE)
        full_data = artifactory_api_service.full_data()
        assert full_data == {"default_key": "data_value", "test-key": "test-value"}

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_should_return_default_values_for_repo_type_in_full_data(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        full_data = artifactory_api_service.full_data()
        assert full_data == {"default_key": "default_value", "packageType": self.TEST_REPO_PACKAGE_TYPE,
                             'key': 'sample-repo'}

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {"default_key": "overridden_value"}}})
    def test_should_return_overridden_values_for_repo_type_in_full_data(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        full_data = artifactory_api_service.full_data()
        assert full_data == {"default_key": "overridden_value", "packageType": self.TEST_REPO_PACKAGE_TYPE,
                             'key': 'sample-repo'}

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {"default_key": "overridden_value"}}})
    def test_should_return_data_provided_for_repo_type_in_full_data(self):
        data = copy.deepcopy(self.TEST_REPO_DATA)
        data['default_key'] = 'data_value'

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD, data,
                                                                           self.STATE)
        full_data = artifactory_api_service.full_data()
        assert full_data == {"default_key": "data_value", "packageType": self.TEST_REPO_PACKAGE_TYPE,
                             'key': 'sample-repo'}

    # artifactory_api_request

    def test_should_return_artifactory_api_request_with_proper_path_for_repo_type(self):
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                        self.USERNAME, self.PASSWORD, self.TEST_REPO_DATA,
                                                        self.STATE).artifactory_api_request().path == "/api/repositories/sample-repo"
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.REMOTE_REPOSITORY_TYPE,
                                                        self.USERNAME, self.PASSWORD, self.TEST_REPO_DATA,
                                                        self.STATE).artifactory_api_request().path == "/api/repositories/sample-repo"
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.VIRTUAL_REPOSITORY_TYPE,
                                                        self.USERNAME, self.PASSWORD, self.TEST_REPO_DATA,
                                                        self.STATE).artifactory_api_request().path == "/api/repositories/sample-repo"

    def test_should_return_artifactory_api_request_with_proper_path_for_group_type(self):
        data = {"name": "group1"}
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.GROUP_TYPE, self.USERNAME,
                                                        self.PASSWORD, data,
                                                        self.STATE).artifactory_api_request().path == "/api/security/groups/group1"

    def test_should_return_artifactory_api_request_with_proper_path_for_permission_type(self):
        data = {"name": "permission1"}
        assert artifactory_entity.ArtifactoryApiService(self.DOMAIN, artifactory_entity.PERMISSION_TYPE, self.USERNAME,
                                                        self.PASSWORD, data,
                                                        self.STATE).artifactory_api_request().path == "/api/security/permissions/permission1"

    # should_create

    def test_artifactory_api_service_should_create_returns_false_if_state_is_absent(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               "absent")
            assert not artifactory_api_service.should_create()

    def test_artifactory_api_service_should_create_returns_false_if_status_code_is_200(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(status_code=200)
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               self.STATE)
            assert not artifactory_api_service.should_create()

    def test_artifactory_api_service_should_create_returns_true_if_status_code_is_404(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(status_code=404)
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               self.STATE)
            assert artifactory_api_service.should_create()

    # Create

    @patch("artifactory_entity.ENTITY_DEFAULTS", {TEST_ENTITY_TYPE: {"default_key": "default_value"}})
    def test_artifactory_api_service_should_create(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest, put_entity=DEFAULT) as values:
            values['put_entity'].return_value = dict(a='b')

            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               self.STATE)
            result = artifactory_api_service.create()
            assert result == dict(a='b')
            values['put_entity'].assert_called_with({"default_key": "default_value", "test-key": "test-value"})

    # should_update

    def test_artifactory_api_service_should_update_returns_false_if_state_is_absent(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               "absent")
        assert not artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_false_if_status_code_is_not_200(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(status_code=404)
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               self.STATE)
            assert not artifactory_api_service.should_update()

    def test_artifactory_api_service_should_update_returns_false_if_status_code_is_200_and_data_is_same(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest, get_entity=DEFAULT) as api_request_values:
            with patch.multiple(artifactory_entity.ArtifactoryApiService, is_data_same=DEFAULT) as service_values:

                response_data = {'test-key': 'test-value'}
                response_mock = MagicMock(status_code=200)
                attrs = {'json.return_value': response_data}
                response_mock.configure_mock(**attrs)

                api_request_values['get_entity'].return_value = response_mock
                service_values['is_data_same'].return_value = True

                artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                                   self.USERNAME, self.PASSWORD,
                                                                                   self.TEST_DATA,
                                                                                   self.STATE)
                updated = artifactory_api_service.should_update()
                service_values['is_data_same'].assert_called_with(response_data)

                assert not updated

    def test_artifactory_api_service_should_update_returns_false_if_status_code_is_200_and_data_is_different(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest, get_entity=DEFAULT) as api_request_values:
            with patch.multiple(artifactory_entity.ArtifactoryApiService, is_data_same=DEFAULT) as service_values:

                response_data = {'test-key': 'test-value'}
                response_mock = MagicMock(status_code=200)
                attrs = {'json.return_value': response_data}
                response_mock.configure_mock(**attrs)

                api_request_values['get_entity'].return_value = response_mock
                service_values['is_data_same'].return_value = False

                artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                                   self.USERNAME, self.PASSWORD,
                                                                                   self.TEST_DATA,
                                                                                   self.STATE)
                updated = artifactory_api_service.should_update()
                service_values['is_data_same'].assert_called_with(response_data)

                assert updated

    # Update

    @patch("artifactory_entity.ENTITY_DEFAULTS", {TEST_ENTITY_TYPE: {"default_key": "default_value"}})
    def test_artifactory_api_service_should_update(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest, post_entity=DEFAULT) as values:
            values['post_entity'].return_value = dict(a='b')

            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               self.STATE)
            result = artifactory_api_service.update()
            assert result == dict(a='b')
            values['post_entity'].assert_called_with({"default_key": "default_value", "test-key": "test-value"})

    @patch("artifactory_entity.ENTITY_DEFAULTS", {artifactory_entity.PERMISSION_TYPE: {"default_key": "default_value"}})
    def test_artifactory_api_service_should_update_permission_type_by_calling_create(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest, put_entity=DEFAULT) as values:
            values['put_entity'].return_value = dict(a='b')

            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                               artifactory_entity.PERMISSION_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               {"name": "permission1"},
                                                                               self.STATE)
            result = artifactory_api_service.update()
            assert result == dict(a='b')
            values['put_entity'].assert_called_with({"default_key": "default_value", "name": "permission1"})

    # should_delete

    def test_artifactory_api_service_should_delete_returns_false_if_state_is_present(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(status_code=404)
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               "present")
            assert not artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_false_if_state_is_absent_and_status_code_is_not_200(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(status_code=404)
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               "absent")
            assert not artifactory_api_service.should_delete()

    def test_artifactory_api_service_should_delete_returns_true_if_state_is_absent_and_status_code_is_200(self):
        with patch.multiple(artifactory_entity.ArtifactoryApiRequest,
                            get_entity=DEFAULT) as values:
            values['get_entity'].return_value = MagicMock(status_code=200)
            artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                               self.USERNAME, self.PASSWORD,
                                                                               self.TEST_DATA,
                                                                               "absent")
            assert artifactory_api_service.should_delete()

    # Delete

    @patch.object(artifactory_entity.ArtifactoryApiRequest, "delete_entity", return_value=dict(a='b'))
    def test_artifactory_api_service_should_delete(self, mock_method):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN, self.TEST_ENTITY_TYPE,
                                                                           self.USERNAME, self.PASSWORD, self.TEST_DATA,
                                                                           self.STATE)
        result = artifactory_api_service.delete()
        assert result == dict(a='b')

    # Is data same
    # Local repo

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_data_same_should_return_true_if_data_are_same_for_local_repo(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        other_data = {"default_key": "default_value", "packageType": self.TEST_REPO_PACKAGE_TYPE, 'key': 'sample-repo'}
        assert artifactory_api_service.is_data_same(other_data)

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.LOCAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_data_same_should_return_false_if_data_are_different_for_local_repo(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.LOCAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        other_data = {"default_key": "value", "packageType": self.TEST_REPO_PACKAGE_TYPE, 'key': 'sample-repo'}
        assert not artifactory_api_service.is_data_same(other_data)

    # Remote repo

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.REMOTE_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.REMOTE_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_data_same_should_return_true_if_data_are_same_for_remote_repo(self):
        data = copy.deepcopy(self.TEST_REPO_DATA)
        data["rclass"] = "remote"
        data["description"] = "Sample repo"

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.REMOTE_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           data, self.STATE)

        other_data = {"default_key": "default_value", "packageType": self.TEST_REPO_PACKAGE_TYPE, 'rclass': "remote",
                      'key': 'sample-repo', 'description': "Sample repo (local file cache)"}
        assert artifactory_api_service.is_data_same(other_data)

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.REMOTE_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.REMOTE_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_data_same_should_return_false_if_data_are_different_for_remote_repo(self):
        data = copy.deepcopy(self.TEST_REPO_DATA)
        data["rclass"] = "remote"
        data["description"] = "Alpine repo"

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.REMOTE_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        other_data = {"default_key": "default_value", "packageType": self.TEST_REPO_PACKAGE_TYPE, 'rclass': "remote",
                      'key': 'sample-repo', 'description': "Sample repo (local file cache)"}
        assert not artifactory_api_service.is_data_same(other_data)

    # Virtual repo

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.VIRTUAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.VIRTUAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_data_same_should_return_true_if_data_are_same_for_virtual_repo(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.VIRTUAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        other_data = {"default_key": "default_value", "packageType": self.TEST_REPO_PACKAGE_TYPE, 'key': 'sample-repo'}
        assert artifactory_api_service.is_data_same(other_data)

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.VIRTUAL_REPOSITORY_TYPE: {"default_key": "default_value"}})
    @patch("artifactory_entity.REPO_OVERRIDES",
           {artifactory_entity.VIRTUAL_REPOSITORY_TYPE: {TEST_REPO_PACKAGE_TYPE: {}}})
    def test_data_same_should_return_false_if_data_are_different_for_virtual_repo(self):
        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.VIRTUAL_REPOSITORY_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           self.TEST_REPO_DATA, self.STATE)
        other_data = {"default_key": "value", "packageType": self.TEST_REPO_PACKAGE_TYPE, 'key': 'sample-repo'}
        assert not artifactory_api_service.is_data_same(other_data)

    # Permissions

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.PERMISSION_TYPE: {"default_key": "default_value"}})
    def test_data_same_should_return_true_if_data_are_same_for_permissions(self):
        data = {'repositories': ['repo-a', 'repo-b'],
                'principals':
                    {
                        'groups': {
                            'mathematicians': ['r', 'd', 'w'],
                            'scientists': ['m', 'n']
                        }
                    }
                }

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.PERMISSION_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           data, self.STATE)
        other_data = {
            "default_key": "default_value",
            'repositories': ['repo-b', 'repo-a'],
            'principals':
                {
                    'groups': {
                        'mathematicians': ['d', 'w', 'r'],
                        'scientists': ['n', 'm']
                    }
                }

        }
        assert artifactory_api_service.is_data_same(other_data)

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.PERMISSION_TYPE: {"default_key": "default_value"}})
    def test_data_same_should_return_false_if_repo_data_are_different_for_permissions(self):
        data = {'repositories': ['repo-a'],
                'principals':
                    {
                        'groups': {
                            'mathematicians': ['r', 'd', 'w'],
                            'scientists': ['m', 'n']
                        }
                    }
                }

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.PERMISSION_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           data, self.STATE)
        other_data = {
            "default_key": "default_value",
            'repositories': ['repo-b', 'repo-a'],
            'principals':
                {
                    'groups': {
                        'mathematicians': ['d', 'w', 'r'],
                        'scientists': ['n', 'm']
                    }
                }

        }
        assert not artifactory_api_service.is_data_same(other_data)

    @patch("artifactory_entity.ENTITY_DEFAULTS",
           {artifactory_entity.PERMISSION_TYPE: {"default_key": "default_value"}})
    def test_data_same_should_return_false_if_group_data_are_different_for_permissions(self):
        data = {'repositories': ['repo-a'],
                'principals':
                    {
                        'groups': {
                            'mathematicians': ['r', 'd', 'w'],
                        }
                    }
                }

        artifactory_api_service = artifactory_entity.ArtifactoryApiService(self.DOMAIN,
                                                                           artifactory_entity.PERMISSION_TYPE,
                                                                           self.USERNAME, self.PASSWORD,
                                                                           data, self.STATE)
        other_data = {
            "default_key": "default_value",
            'repositories': ['repo-b', 'repo-a'],
            'principals':
                {
                    'groups': {
                        'mathematicians': ['d', 'w', 'r'],
                        'scientists': ['n', 'm']
                    }
                }

        }
        assert not artifactory_api_service.is_data_same(other_data)
