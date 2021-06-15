import pytest
import custom

class TestFilters:

    def test_server_healthy_should_return_true(self):
        json = {
            "router": {
                "node_id": "localhost.localdomain",
                "state": "HEALTHY",
                "message": "OK"
            },
            "services": [
                {
                    "service_id": "jfac@01f87tyhy6kyr61h65wtxj0r1m",
                    "node_id": "localhost.localdomain",
                    "state": "HEALTHY",
                    "message": "OK"
                },
                {
                    "service_id": "jfevt@01f87tyhy6kyr61h65wtxj0r1m",
                    "node_id": "localhost.localdomain",
                    "state": "HEALTHY",
                    "message": "OK"
                }
            ]
        }
        assert custom.server_healthy(json)

    def test_server_healthy_should_return_false_if_router_is_unhealthy(self):
        json = {
            "router": {
                "node_id": "localhost.localdomain",
                "state": "UNHEALTHY",
                "message": "OK"
            },
            "services": [
                {
                    "service_id": "jfac@01f87tyhy6kyr61h65wtxj0r1m",
                    "node_id": "localhost.localdomain",
                    "state": "HEALTHY",
                    "message": "OK"
                },
                {
                    "service_id": "jfevt@01f87tyhy6kyr61h65wtxj0r1m",
                    "node_id": "localhost.localdomain",
                    "state": "HEALTHY",
                    "message": "OK"
                }
            ]
        }
        assert not custom.server_healthy(json)

    def test_server_healthy_should_return_false_if_one_service_is_unhealthy(self):
        json = {
            "router": {
                "node_id": "localhost.localdomain",
                "state": "HEALTHY",
                "message": "OK"
            },
            "services": [
                {
                    "service_id": "jfac@01f87tyhy6kyr61h65wtxj0r1m",
                    "node_id": "localhost.localdomain",
                    "state": "UNHEALTHY",
                    "message": "OK"
                },
                {
                    "service_id": "jfevt@01f87tyhy6kyr61h65wtxj0r1m",
                    "node_id": "localhost.localdomain",
                    "state": "HEALTHY",
                    "message": "OK"
                }
            ]
        }
        assert not custom.server_healthy(json)
