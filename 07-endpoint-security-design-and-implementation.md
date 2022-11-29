#Endpoint Security: Design and Implementation

## Host Security

### OS security

#### General

* limit administrative access (e.g. via *Group Policy Objects* [**GPOs**])
* apply security patches for OS and applications ASAP
* make sure that patches are applied properly

#### Hardening

* removing all un-used services/components: reducing the attack surface
* lock down host firewall
* disable default accounts/passwords
* compare settings against best practices

### Malware prevention

* = malicious software
* 4 types
  * virus
  * worms
  * trojan horse
  * spyware
* **Endpoint Detection and Response (EDR)**
  * memory and processor use
  * network usage
  * real-time detection of malware
  * uses agents installed on clients
  * sandboxing: run executable in a sandbox to test what it's doing
* **Spam Filtering**

### Application Control

* whitelisting and blacklisting applications on endpoints
* aka *allow list* and *deny list*
* application control logs should be collected by **SIEM**
* apply updates for applications
* use *host software baselining*

### Host-based network security controls

#### Firewalls

* **network firewalls**
  * sit between internal network and external (e.g. Internet)
  * are hardware systems
  * regulate traffic in to and out of the internal network, but not traffic inside the internal network
* **host firewalls**
  * are software
  * run on a client
  * may be part of the OS
  * controls any connection to be made the the host (from anywhere)
* **next-generation firewalls**
  * more advanced
  * can take a given user and his behaviour into account
* **Intrusion Detection System (IDS)** detect suspicious activity and alert administrators
* **Intrusion Prevention System (IPS)** block suspicious network activity

### File Integrity Monitoring

* system hashes important files
* scans are run regularly and if the hash of a file has changed, an alert is triggered
* violation has to be analysed (e.g. did it happen after applying patches?)
* FIM systems may be required for compliance (e.g. PCI)

### Data loss prevention (DLP)

* prevent accidental lost and theft
* 2 types

#### host-based DLP

* use agent running on a client
* detect sensitive information in files on a hard drive
* can prevent the usage of swappable media

#### network-based DLP

* can block traffic
* can encrypt content before sending it (e.g. email)

#### Can perform two actions

* use **pattern matching** to detect sensitive data
* **detect watermarks** added by a DLP and alarms

## Hardware Security

### Encryption

* allow storing/sending data in/over public media
* individual files can be encrypted
* **full-disk encryption (FDE)** protects confidentiality when a computer is lost or stolen
* **Hardware Security Module (HSM)** is dedicated hardware for encryption/decryption and storing keys
* **Trusted Platform Modules (TPMs)** stores the key for an encrypted drive
* **Self-encryption drive (SED)** is a standalone hardware-solution for encrypted storage

### Hardware and firmware security

* **Unified Extendable Firmware Interface (UEFI)** is the successor of BIOS
* BIOS contains public key as part of software
* Signature is checked for BIOS updates

#### Complete secure boot process
1. **Secure Boot**: verifies the OS's bootloader digital signature against signature from manufacturer
1. **Trusted Boot**
   1. Bootloader now verifies the signature of the OS kernel
   1. Kernel will then verify boot drivers and startup files
   1. Before loading drivers, Early Launch Anti-Malware (**ELAM**) will check all drivers

1. **Measured Boot**: making sure hat no changes have occurred to this computer (by comparing hashes of everything)
1. **Remote attestation**: verification server verifies the boot report and compares it against a known trusted version

#### Electromagnetic Interference

* EM waves cause disruption to hardware
* Electromagnetic pulses (EMP) can destroy hardware

#### Peripherals

* can have security issues: e.g. USB sticks may be used to extract data
* modern **printers** are computers
  * use operating system
  * run web server
  * store print jobs on disk or in memory
  * should accept encrypted traffic to prevent eavesdropping

## Configuration Management

### Change Management

#### Request for Change (RFC)

* document contains: description, impact, risk, rollback, ...
* changes must be approved
* routine changes might be pre-approved

### Configuration Management

* tracking installed software on a device
  * OS settings
  * inventory of software
* **baselining**
  * provide a configuration snapshot
  * snapshot of a running system can be compared against a master system to identify illegal changes
* versioning (e.g. semantic versioning)
* artefacts: e.g. diagrams
* device configuration should be standardised
  * naming convention
  * IP addressing scheme

### Physical asset management

#### Device management

* inventory process should follow the lifecycle of a device
* when order is **placed**: inventory item should be *created*
* order is **delivered**: update to *received*
* **asset tag** should be attached on device
* configured device is **delivered to end user**: update *ownership*
* when device is returned to IT: re-use or destroy

#### Media management

* only track media for highly sensitive data

## Embedded System Security

### Industrial Control Systems (ICS)

#### Attract attackers

* dramatic implications if system goes down
* often not well secured
* less likely to be current on patches

#### Types

* Supervisory control and data acquisition (**SCADA**)
  * remote monitoring
  * remote telemetry (sensors) report to control systems
  * multiple points of attack
  * run complex manufacturing processes
* Distributed control systems (**DCS**s)
  * control processes
  * use *sensors* and *feedback systems*
  * multiple points of attack
* Programmable logic controllers (**PLC**s)
  * special-purpose computers for IO
  * ensure un-interrupted processing
  * have a "Human to Machine" interface
  * often use "Modbus" protocol via serial port


### Internet of Things

* smart devices are computer-controlled and network-connected hardware
* challenges for IoT devices
  * consumer have issues patching OS
  * connect to the same network as computers in the house
  * connect back to cloud services for command & control
* devices are everywhere
  * wearables
  * surveillance systems

### Securing smart devices

* disable weak defaults (e.g. admin password)
* patch and update software regularly
* enable **firmware version control** process
* if patching is not possible, use a security wrappers that only allows whitelisted traffic to a device

### Secure networking for smart devices

* put smart devices in a seperate network
* have a seperate network for embedded devices that's behind a firewall
* (secure mainframes as well)

### Embedded Systems

* **System on a chip** (**SoC**)
  * CPU
  * clock
  * memory
  * wifi
* **Field-programmable gate arrays** (**FPGA**s) allow reprogramming
* **Real-time operating systems (RTOSs)** provide resources to the system with highest demand
* **CAN Bus** used for communication between embedded devices

### Communication for embedded devices

* when WIFI is unavailable, **cellular networks** can be used
* SIM card needed (digital cards are available)
* **Zigbee and Z-Wave** are used for short-range home automation communication
* **Radio frequency** in remote locations

## Scripting and CLI

### Shell and script environments

* scripts contain pre-written code to execute OS commands
* **SSH** uses TCP port 22 to connect to remote Linux systems securely
* **PowerShell** is used to automate a Windows system
* **Python** can also be used to write scripts

### File manipulation

* `cat`: display file content
* `head`: displays the beginning of a file (10 default)
* `tail`: displays the ending of a file (10 default)
* `grep`: searches for content in a file
* `logger`: add content the system log 

### Linux file permissions

#### Owership

* a file belongs to both
  * user
  * group
* `chown` changes the user owner of a file
* `chgrp` changes the group owner of a file
* `chmod` changes the permission on a file

#### Permissions

* File permissions
  * `r`: read
  * `w`: write
  * `x`: execute
* File Ownership
  * `u`: User Owner
  * `g`: Group Owner
  * `o`: Others
* command: `chmod <ownership><+ | -><permissions> <file>`  
