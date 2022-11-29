# Cloud Security Design and Implementation

## Cloud Computing

### Roles

* Cloud Service Provider: AWS, Google, Microsoft
* Cloud Customer: users
* Cloud Service Partner: consultant (independent or from provider)
* Managed service providers (MSP): external consultant who support with security

### Terms

* **Scalability**
  * horizontal: adding more of the same configured systems
  * vertical: increase resources for an existing system
* **Elasticity**: increasing and decreasing capacity on demand
* **Measured Service**: customers only pay for what they use

### Service Types

* **PaaS**: Platform as a service
* **SaaS**: Software as a service
* **FaaS**: Function as a service
* **SECaaS**: Security as a service

### Security Providers

#### MSSP (Managed security service providers)

* scope
  * own complete security for an organisation
  * one task (log monitoring, firewall, identity&access management)
* Cloud Access security brokers (**CASBs**)
  * network-based: between user and cloud
    * monitoring
    * requests can be blocked
  * API-based: queries cloud service from within
    * not real time
    * can not block requests
* service agreement recommended

## Virtualisation

### Type 1 hypervisor

* runs on hardware
* guest VMs run on hypervisor

### Type 2 hypervisor

* hypervisor is a regular application that runs on an OS
* guest VMs run on hypervisor
* examples: VirtualBox, Parallels

### Security Issues

* isolation is critical
* each server must only have access to dedicated resources
* VM escape tries to break out of the guest environment
* VM Sprawl: unused and unmaintained servers laying around

## Building Blocks

### Compute

* create and run virtual servers
* create servers in different zones (if one zone goes down, other servers remain online)

### Storage

#### Block Storage

* virtual hard disk drives
* paid for the total allocated size
* types: magnetic, SSD

#### Object Storage

* individual files
* pay per use (IO operations)
* types: regular, high availability, archive

#### Security

* permissions on objects/volumes
* encryption at rest
* replicate copy to different regions
  * response time
  * backups / archive

### Networking

* **Virtual Private Cloud (VPC)** = virtual LANs 
* Firewall rules control traffic between VPCs
* subnets can be isolated or connected to the internet
* VPC endpoints allow connecting VPCs to services or other VPCs without the Internet
* **Software-defined networking (SDN)**: use infrastructure as code to create networks
* **Software-defined visibility (SDV)**: analyse traffic using APIs from SP

### Databases

* Run DB on virtual server: administration and management done by client
* Manages DB service: client choses DB engine and virtual hardware
* Cloud-native DB: requires retooling existing applications

### Orchestration

* = automated workflows for cloud management
* infrastructure as code: configuration or scripted API calls create entire systems
* third-party tools available: support 1+ cloud provider


### Containers

* = lightweight applications virtualisation
* containers only contain application code and dependencies
* containers use host OS
* same as VMs: isolation is critical

## Cloud Reference Architecture

* framework for providers, customers, and partners to communicate rules and responsibilities
* it's a starting point for an organisation to begin with
* aligns with Cloud Controls Matrix (CCM)

### Deployment Model

#### Public Cloud

* shared infrastructure (multi-tenancy)

#### Private Cloud

* dedicated cloud infrastructure

#### Hybrid Cloud

* combination of public and private
* some services from public, others from private

#### Community Cloud

* not often used
* shared private cloud with related entities

### Edge & fog computing

#### Edge

* using processor power within a sensor when uploading full data would im impractical
* after initial processing, upload result (subset of data) to cloud
* example: agricultural or satellites

#### Fog computing

* gateway devices are collecting data from IoT devices
* gateway performs computation before uploading result to cloud

### Security & Privacy in cloud

* addition to CIA triangle: **privacy**
* ensuring the rights of confidentiality of users against cloud providers / partners
* 3 new concerns
  * audit-ability: directly or via third part
  * governance: oversight
  * regulatory oversight: same rules/compliance apply as for on-premise

### Data sovereignty

* local laws apply to data stored in a country
* cloud provider should put storage location in writing
* encrypt data in case a government gains access to it

### Operational Concerns

#### Factors for operation

* availability: how much uptime is promised for a service?
* resiliency: how much failures can a system tolerate?
* performance: how much demand can be handled?
* SLAs for these metrics should exist
* how does scheduled maintenance affect a business?

#### Reversibility

* can the move to the cloud be reversed?
* can a different vendor be selected?

#### Portability

* avoid vendor lock-in
* can a workload be moved to a different vendor

#### Interoperability

* will solutions build with different cloud providers work together?

## Cloud Security Controls

#### Firewall

* in a cloud environment, a firewall can not be accessed directly
* network **security groups** act as IaaS firewall
* SGs work on level
  * network
  * session
  * transport layer
* SGs control traffic from Internet and VPC or between VPCs
* Customers are responsible for SG rules

### Application Security

* similar to on-premise controls
* **Firewall** => *Security Groups*
* **TLS** => TLS via *managing certificates*
* **Encryption of data at rest** => *option when creating a volume*
* **Application Virtualisation** => *service by provider* (e.g. Amazon AppStream)
* principle of *defence in depth*: create overlapping security controls

### Provider Security Controls

#### 3 types

* cloud-native controls
  * easy to use
  * tightly integrated
* third-party solutions
  * often usable with different providers
  * can be more expensive
* combination of those

#### Controls

* **resource policy** limit what a user can do
  * how much money they can spend
  * what instances to terminate
  * what services they have access to
* **transit gateway**: link on-premise to the cloud
* **secret management**: protect keys and credentials