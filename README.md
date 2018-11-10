# quickstart-aws-eks

This is a work in progress framework for building quick starts on kubernetes. 

Aims to provide:

* 3 possible entry points: 
  * new vpc and EKS cluster
  * existing vpc new eks cluster
  * existing vpc and kubernetes cluster
* Custom resource types:
  * KubeManifest - create, update, delete kubernetes resources using kubernetes manifests natively in CloudFormation. 
  Can auto-generate names, and provides metadata in kubernetea api response as return values
  * Helm - use cloudformation to install applications using helm charts. supports custom repos, and passing values to 
  charts. output includes release name, and names of all created resources.
* stabilise resources - wait for resources to complete before returning, this enables timing to be controlled between 
dependent application components
* Usable as a submodule, base for kubernetes applications
* Provide a bastion host already configured with kubectl, helm and kubeconfig
* Creates EKS cluster and node group including a role that has access to the cluster and can be assumed by lambda

## Testing

1. create EC2 Keypair
1. Set `KeyPairName` as a [global taskcat override](https://aws-quickstart.github.io/input-files.html#parm-override)
1. deploy `aws-eks-master.template.yaml` using taskcat `cd quickstart-aws-eks ; taskcat -v -n -c ./ci/config.yml`
1. launch example workload template `example-workload.template.yaml`, needed parameters can be retrieved from outputs of 
the master stack
1. ssh into bastion host, validate that example `ConfigMap` (created by kubernetes manifest) and 
`service-catalog` (created by helm install) have installed correctly
 
## Using as submodule

You can use the `aws-eks-master.template.yaml` and `aws-eks-master-existing-vpc.template.yaml` files as a starting point 
for building your own templates, updating the paths in both to point to the eks submodule for all needed templates and 
adding a workload template to `aws-eks-master-existing-vpc.template.yaml` (can use `example-workload.template.yaml` as a 
starting point for this).
