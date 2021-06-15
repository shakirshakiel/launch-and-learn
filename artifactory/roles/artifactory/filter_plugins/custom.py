def server_healthy(json):
    if json['router']['state'] != 'HEALTHY':
        return False
    for service in json['services']:
        if service['state'] != 'HEALTHY':
            return False
    return True

class FilterModule(object):
    def filters(self):
        return {
            "server_healthy": server_healthy
        }
