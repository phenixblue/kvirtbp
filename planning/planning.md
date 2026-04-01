# CLI Planning

## Initial prompt

I want to build a plan for creating a Golang based CLI tool that allows a user to run a series of checks against a running Kubernetes cluster with KubeVirt installed/enabled to verify adherence to defined best practices for Production Readiness, Security, Availability, etc. The best practices should be codified in some way (maybe Rego/OPA) to allow for ease of policy creation/flexibility. The CLI shoudl use common utilities and frameworks from the open source software community and be inline with standards from the CNCF/Kubernetes community. It should work for any conformant k8s cluster


## Ideas for other/future features

- Capture snap type tarball of information from a running cluster
- Ability to watch web app to import/display captured info from snap. Should be a visual representation of the cluster that a user can click through and view at any level
- Kind cluster setup wirth KubeVirt and VM's deployed for testing
- Add infro from Portworx checks/recs
- Add brew tap/packaging