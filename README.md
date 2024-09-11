# simple docker machine driver for timeweb.cloud

#### Use with rancher (add to local cluster)
```yaml
apiVersion: management.cattle.io/v3
kind: NodeDriver
metadata:
  annotations:
    privateCredentialFields: cloudToken
  name: timeweb
spec:
  active: true
  addCloudCredential: false
  builtin: false
  checksum: ''
  description: ''
  displayName: timeweb
  externalId: ''
  uiUrl: ''
  url: https://github.com/Negashev/docker-machine-driver-timeweb/releases/download/0.0.1/docker-machine-driver-timeweb-linux-amd64.tgz
  whitelistDomains: []
```