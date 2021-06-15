#!/usr/bin/python

from ansible.module_utils.basic import *
import json
import requests
import copy

LOCAL_REPOSITORY_TYPE = "local_repository"
REMOTE_REPOSITORY_TYPE = "remote_repository"
VIRTUAL_REPOSITORY_TYPE = "virtual_repository"
GROUP_TYPE = "groups"
PERMISSION_TYPE = "permissions"

REPO_TYPES = [LOCAL_REPOSITORY_TYPE, REMOTE_REPOSITORY_TYPE, VIRTUAL_REPOSITORY_TYPE]
ENTITY_TYPES = REPO_TYPES + [GROUP_TYPE, PERMISSION_TYPE]

ENTITY_DEFAULTS = {
    LOCAL_REPOSITORY_TYPE: {
        "key": "",
        "packageType": "",
        "description": "",
        "notes": "",
        "includesPattern": "**/*",
        "excludesPattern": "",
        "repoLayoutRef": "simple-default",
        "enableComposerSupport": False,
        "enableNuGetSupport": False,
        "enableGemsSupport": False,
        "enableNpmSupport": False,
        "enableBowerSupport": False,
        "enableCocoaPodsSupport": False,
        "enableConanSupport": False,
        "enableDebianSupport": False,
        "debianTrivialLayout": False,
        "enablePypiSupport": False,
        "enablePuppetSupport": False,
        "enableDockerSupport": False,
        "dockerApiVersion": "V2",
        "blockPushingSchema1": True,
        "forceNugetAuthentication": False,
        "enableVagrantSupport": False,
        "enableGitLfsSupport": False,
        "enableDistRepoSupport": False,
        "priorityResolution": False,
        "checksumPolicyType": "client-checksums",
        "handleReleases": True,
        "handleSnapshots": True,
        "maxUniqueSnapshots": 0,
        "maxUniqueTags": 0,
        "snapshotVersionBehavior": "unique",
        "suppressPomConsistencyChecks": True,
        "blackedOut": False,
        "propertySets": [],
        "archiveBrowsingEnabled": False,
        "calculateYumMetadata": False,
        "enableFileListsIndexing": False,
        "yumRootDepth": 0,
        "dockerTagRetention": 1,
        "xrayIndex": False,
        "cargoAnonymousAccess": False,
        "downloadRedirect": False,
        "cdnRedirect": False,
        "enabledChefSupport": False,
        "rclass": "local"
    },
    REMOTE_REPOSITORY_TYPE: {
        "key": "",
        "packageType": "",
        "description": "",
        "notes": "",
        "includesPattern": "**/*",
        "excludesPattern": "",
        "repoLayoutRef": "simple-default",
        "enableComposerSupport": False,
        "enableNuGetSupport": False,
        "enableGemsSupport": False,
        "enableNpmSupport": False,
        "enableBowerSupport": False,
        "enableCocoaPodsSupport": False,
        "enableConanSupport": False,
        "enableDebianSupport": False,
        "debianTrivialLayout": False,
        "enablePypiSupport": False,
        "enablePuppetSupport": False,
        "enableDockerSupport": False,
        "dockerApiVersion": "V2",
        "blockPushingSchema1": True,
        "forceNugetAuthentication": False,
        "enableVagrantSupport": False,
        "enableGitLfsSupport": False,
        "enableDistRepoSupport": False,
        "priorityResolution": False,
        "url": "",
        "username": "",
        "password": "",
        "proxy": "defaultProxy",
        "handleReleases": True,
        "handleSnapshots": True,
        "suppressPomConsistencyChecks": True,
        "remoteRepoChecksumPolicyType": "generate-if-absent",
        "hardFail": False,
        "offline": False,
        "blackedOut": False,
        "storeArtifactsLocally": True,
        "socketTimeoutMillis": 15000,
        "localAddress": "",
        "retrievalCachePeriodSecs": 7200,
        "assumedOfflinePeriodSecs": 300,
        "missedRetrievalCachePeriodSecs": 1800,
        "unusedArtifactsCleanupPeriodHours": 0,
        "fetchJarsEagerly": False,
        "fetchSourcesEagerly": False,
        "shareConfiguration": False,
        "synchronizeProperties": False,
        "maxUniqueSnapshots": 0,
        "maxUniqueTags": 0,
        "propertySets": [],
        "archiveBrowsingEnabled": False,
        "listRemoteFolderItems": True,
        "rejectInvalidJars": False,
        "allowAnyHostAuth": False,
        "enableCookieManagement": False,
        "enableTokenAuthentication": False,
        "propagateQueryParams": False,
        "blockMismatchingMimeTypes": True,
        "mismatchingMimeTypesOverrideList": "",
        "bypassHeadRequests": False,
        "contentSynchronisation": {
            "enabled": False,
            "statistics": {
                "enabled": False
            },
            "properties": {
                "enabled": False
            },
            "source": {
                "originAbsenceDetection": False
            }
        },
        "externalDependenciesEnabled": False,
        "xrayIndex": False,
        "cargoAnonymousAccess": False,
        "downloadRedirect": False,
        "cdnRedirect": False,
        "enabledChefSupport": False,
        "rclass": "remote"
    },
    VIRTUAL_REPOSITORY_TYPE: {
        "key": "",
        "packageType": "",
        "description": "",
        "notes": "",
        "includesPattern": "**/*",
        "excludesPattern": "",
        "repoLayoutRef": "simple-default",
        "enableComposerSupport": False,
        "enableNuGetSupport": False,
        "enableGemsSupport": False,
        "enableNpmSupport": False,
        "enableBowerSupport": False,
        "enableCocoaPodsSupport": False,
        "enableConanSupport": False,
        "enableDebianSupport": False,
        "debianTrivialLayout": False,
        "enablePypiSupport": False,
        "enablePuppetSupport": False,
        "enableDockerSupport": False,
        "dockerApiVersion": "V2",
        "blockPushingSchema1": True,
        "forceNugetAuthentication": False,
        "enableVagrantSupport": False,
        "enableGitLfsSupport": False,
        "enableDistRepoSupport": False,
        "priorityResolution": False,
        "repositories": [],
        "artifactoryRequestsCanRetrieveRemoteArtifacts": False,
        "resolveDockerTagsByTimestamp": False,
        "keyPair": "",
        "pomRepositoryReferencesCleanupPolicy": "discard_active_reference",
        "externalDependenciesEnabled": False,
        "virtualRetrievalCachePeriodSecs": 7200,
        "forceMavenAuthentication": False,
        "debianDefaultArchitectures": "i386,amd64",
        "enabledChefSupport": False,
        "cargoAnonymousAccess": False,
        "rclass": "virtual"
    },
    GROUP_TYPE: {
        "name": "",
        "description": "Description",
        "autoJoin": False,
        "realm": "ldap",
        "realmAttributes": "",
        "adminPrivileges": False,
        "policyManager": False,
        "watchManager": False,
        "reportsManager": False
    },
    PERMISSION_TYPE: {
        "name": "",
        "includesPattern": "**",
        "excludesPattern": "",
        "repositories": [],
        "principals": {
            "groups": {}
        }
    }
}

REPO_OVERRIDES = {
    LOCAL_REPOSITORY_TYPE: {
        "alpine": {},
        "cocoapods": {
            "enableCocoaPodsSupport": True
        },
        "conda": {},
        "cran": {},
        "debian": {
            "enableDebianSupport": True,
            "optionalIndexCompressionFormats": ["bz2"]
        },
        "docker": {
            "enableDockerSupport": True
        },
        "gems": {
            "enableGemsSupport": True
        },
        "generic": {},
        "go": {
            "repoLayoutRef": "go-default"
        },
        "gradle": {
            "repoLayoutRef": "maven-2-default"
        },
        "helm": {},
        "maven": {
            "repoLayoutRef": "maven-2-default",
            "suppressPomConsistencyChecks": False,
        },
        "npm": {
            "repoLayoutRef": "npm-default",
            "enableNpmSupport": True,
        },
        "pypi": {
            "enablePypiSupport": True,
        },
        "rpm": {
            "calculateYumMetadata": True,
            "yumGroupFileNames": "groups.xml"
        }
    },
    REMOTE_REPOSITORY_TYPE: {
        "alpine": {},
        "cocoapods": {
            "enableCocoaPodsSupport": True,
            "listRemoteFolderItems": False,
            "externalDependenciesPatterns": ["**"]
        },
        "conda": {},
        "cran": {},
        "debian": {
            "enableDebianSupport": True,
        },
        "docker": {
            "enableDockerSupport": True,
            "retrievalCachePeriodSecs": 21600,
            "listRemoteFolderItems": False,
            "enableTokenAuthentication": True,
            "externalDependenciesPatterns": ["**"]
        },
        "gems": {
            "enableGemsSupport": True,
            "listRemoteFolderItems": False,
        },
        "generic": {},
        "go": {
            "repoLayoutRef": "go-default",
            "listRemoteFolderItems": False,
        },
        "gradle": {
            "repoLayoutRef": "maven-2-default",
            "suppressPomConsistencyChecks": False,
        },
        "helm": {},
        "maven": {
            "repoLayoutRef": "maven-2-default",
            "suppressPomConsistencyChecks": False,
        },
        "npm": {
            "repoLayoutRef": "npm-default",
            "enableNpmSupport": True,
            "listRemoteFolderItems": False,
        },
        "pypi": {
            "enablePypiSupport": True,
            "listRemoteFolderItems": False,
            "pyPIRepositorySuffix": "simple",
        },
        "rpm": {}
    },
    VIRTUAL_REPOSITORY_TYPE: {
        "alpine": {},
        "cocoapods": {},
        "conda": {},
        "cran": {},
        "debian": {
            "enableDebianSupport": True,
            "optionalIndexCompressionFormats": ["bz2"],
        },
        "docker": {
            "enableDockerSupport": True,
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "gems": {
            "enableGemsSupport": True,
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "generic": {
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "go": {
            "repoLayoutRef": "go-default",
            "externalDependenciesEnabled": True,
            "externalDependenciesPatterns": [
                "**/github.com/**",
                "**/go.googlesource.com/**",
                "**/gopkg.in/**",
                "**/golang.org/**",
                "**/k8s.io/**"
            ],
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "gradle": {
            "repoLayoutRef": "maven-2-default",
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "helm": {},
        "maven": {
            "repoLayoutRef": "maven-2-default",
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "npm": {
            "repoLayoutRef": "npm-default",
            "enableNpmSupport": True,
            "externalDependenciesPatterns": ["**"],
        },
        "pypi": {
            "enablePypiSupport": True,
            "virtualRetrievalCachePeriodSecs": 600,
        },
        "rpm": {}
    }
}


class ArtifactoryApiRequest:

    def __init__(self, domain, path, username, password):
        self.domain = domain
        self.path = path
        self.username = username
        self.password = password

    def get_entity(self):
        url = self.url()
        params = self.basic_params()
        result = requests.get(url, **params)
        return result

    def post_entity(self, data):
        url = self.url()
        headers = {
            'Content-Type': 'application/json'
        }
        params = self.basic_params()
        params['headers'] = headers
        result = requests.post(url, json.dumps(data), **params)
        return result

    def put_entity(self, data):
        url = self.url()
        headers = {
            'Content-Type': 'application/json'
        }
        params = self.basic_params()
        params['headers'] = headers
        result = requests.put(url, json.dumps(data), **params)
        return result

    def delete_entity(self):
        url = self.url()
        params = self.basic_params()
        result = requests.delete(url, **params)
        return result

    def url(self):
        domain = self.domain[:-1] if self.domain.endswith("/") else self.domain
        path = self.path[1:] if self.path.startswith("/") else self.path

        return "{}/{}".format(domain, path)

    def basic_params(self):
        params = dict()
        params['auth'] = requests.auth.HTTPBasicAuth(self.username, self.password)
        return params


class ArtifactoryApiService:

    def __init__(self, domain, entity_type, username, password, data, state):
        self.domain = domain
        self.entity_type = entity_type
        self.username = username
        self.password = password
        self.data = data
        self.state = state

    def is_repo_type(self):
        return self.entity_type in REPO_TYPES

    def full_data(self):
        full_data = copy.deepcopy(ENTITY_DEFAULTS[self.entity_type])
        if self.is_repo_type():
            package_type = self.data['packageType']
            full_data.update(REPO_OVERRIDES[self.entity_type][package_type])
        full_data.update(self.data)
        return full_data

    def artifactory_api_request(self):
        path = None
        if self.is_repo_type():
            path = "/api/repositories/{}".format(self.data['key'])
        if self.entity_type == GROUP_TYPE:
            path = "/api/security/groups/{}".format(self.data['name'])
        if self.entity_type == PERMISSION_TYPE:
            path = "/api/security/permissions/{}".format(self.data['name'])
        return ArtifactoryApiRequest(self.domain, path, self.username, self.password)

    def create(self):
        return self.artifactory_api_request().put_entity(self.full_data())

    def update(self):
        if self.entity_type == PERMISSION_TYPE:
            return self.create()
        return self.artifactory_api_request().post_entity(self.full_data())

    def delete(self):
        return self.artifactory_api_request().delete_entity()

    def should_create(self):
        if self.state == "absent":
            return False

        result = self.artifactory_api_request().get_entity()
        if result.status_code == 200:
            return False
        return True

    def should_update(self):
        if self.state == "absent":
            return False

        result = self.artifactory_api_request().get_entity()
        if result.status_code != 200:
            return False

        if self.is_data_same(result.json()):
            return False

        return True

    def should_delete(self):
        result = self.artifactory_api_request().get_entity()
        if self.state == "absent" and result.status_code == 200:
            return True
        return False

    def is_data_same(self, other_data):
        data_copy = self.full_data()
        if self.is_repo_type() and "rclass" in data_copy and data_copy["rclass"] == "remote":
            data_copy["description"] = "{} {}".format(data_copy["description"], "(local file cache)")
        other_data_copy = copy.deepcopy(other_data)

        if self.entity_type == PERMISSION_TYPE:
            data_copy['repositories'].sort()
            other_data_copy['repositories'].sort()

            if 'groups' in data_copy['principals'] and 'groups' in other_data_copy['principals']:
                for i in data_copy['principals']['groups']:
                    data_copy['principals']['groups'][i].sort()
                for j in data_copy['principals']['groups']:
                    other_data_copy['principals']['groups'][j].sort()
        return data_copy == other_data_copy


def main():
    fields = dict(
        domain=dict(required=True, type="str"),
        entity_type=dict(required=False, type="str", choices=ENTITY_TYPES),
        username=dict(required=True, type="str"),
        password=dict(required=True, type="str", no_log=True),
        data=dict(required=True, type="dict"),
        state=dict(required=False, type="str", default='present', choices=['absent', 'present']),
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    domain = module.params['domain']
    entity_type = module.params['entity_type']
    username = module.params['username']
    password = module.params['password']
    data = module.params['data']
    state = module.params['state']

    if entity_type in REPO_TYPES and 'key' not in data:
        module.fail_json(msg="Key in data is mandatory for {}".format(entity_type), changed=False)

    artifactory_api_service = ArtifactoryApiService(domain, entity_type, username, password, data, state)
    if artifactory_api_service.should_create():
        if module.check_mode:
            module.exit_json(changed=True)
        result = artifactory_api_service.create()
        meta = {"new": result.content}
        module.exit_json(changed=True, meta=meta)

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
