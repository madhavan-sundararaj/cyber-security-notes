# Operations and Incident Response

## Incident Response Programs

### Build an incident response program

* aligned with *NIST standard SP 800-61*
* having a plan is great when disaster strikes
* elements
  * statement of purpose
  * strategies & goals
  * approach to incident response
  * communication with other groups
  * approval of senior leadership
* templates available as a start

### Creating an incident response team

* members must be available 24/7
* rotation needed for vacation/sick leave
* members
  * management
  * IT security
  * SME
  * legal
  * HR
  * physical security
* team should train regularly and test the plan
* IR Service Provider
  * can help out the team
  * should be chosen and contracted in advance

### Incident Response Plan

* = consits of several plans to handle the various stages of the incident
* plans can be combined into a single document
* 4 components
  1. Communication
  1. Stakeholder Management
  1. Business continuity (BC)
  1. Disaster Recovery (DR)


#### Communication Plan

* limit communication to trusted parties (to avoid leaking information)
* involving law enforcement might lead to details being made public
* legal team should advise about laws and regulations
* make sure secure channels exist for sharing information internally and externally

#### Stakeholder Management

#### Business Continuity

#### Disaster Recovery

#### COOP: continuity of operation planning

* can be used in addition to the 4 components listed above
* US-government sponsored program that is part of the national continuity program
* required for government agencies
* 4 phases:
  1. Readiness and Preparedness
  1. Activation and Relocation
  1. Continuity of Operations
  1. Reconstitution


### Incident identification

* robust monitoring is a must!
* sources
  * IDS/IPS
  * Firewalls
  * Authentication systems
  * Vulnerability scanners
  * System event logs
* **Security Incident and Event Management (SIEM)**
  * centralised log repository
  * analyse for incidents based on rules and algorithm
  * can alert users
* first repot might come from outside the organisation
* very first thing to do: *isolate* the affected system(s)

### Escalation and notification

* process
  1. evaluation severity
  1. escalate to appropriate level
  1. notify stakeholders
* triage
  * **low**
    * minimal potential
    * handled by first responders
    * no after-hour response
  * **medium**
    * significant potential
    * trigger response team
    * notify management
  * **high**
    * critical damage to information or systems
    * full response: active entire response team
    * immediate notification of management

### Mitigation

* goal: control damage and loss
* 6 criteria for a containment strategy
  1. *damage potential*:  how much data can be stolen/destroyed?
  1. *evidence preservation*: can we still store/collect evidence?
  1. *service availability*: will containment make a service unavailable?
  1. *resource requirements*: how long will it take to contain the system(s)? How many people are needed to implement this?
  1. *expected effectiveness*: will this fully contain the system or just partially?
  1. *solution time frame*: for how long will the strategy be in place?
* attacker will notice once the containment implementation begins
  * attackers might destroy evidence
  * attackers might cause as much damage in the remaining time
* mitigation should end with stability
  * business should function again
  * danger should be averted

### Containment techniques

* active phase with the goal to limit the damage
* 3 activities
  1. **segmentation**: move compromised systems into a quarantine network 
  1. **isolation**: disconnect the quarantined network from all others but Internet
  1. **removal**: cut off all access to the quarantined network
* trade-off between disruption and safety

### Incident eradication and recovery

* goals
  * remove all traces of an incident
  * restore normal operations
* reconstruct a compromised system
  * avoid missing backdoors
  * reset to factory default for hardware
  * fix the security issue that allowed attacker to access system
* if vulnerabilities were used to get access
  * check whitelist/blacklist
  * verify access controls
  * firewall rules
  * mobile device management
  * update/revoke compromised digital certificate

### Validation

* verify secure configuration of every system in the network (focus on those that were involved in compromise)
* run vulnerability scans
* review accounts (make sure only authorised accounts exist) and check permissions
* make sure all systems are logging into SIEM
* validate the all capabilities have been restored

### Post-incident activities

#### Lessons learned

* invite everybody involved to think about
  * their role
  * the team
  * processes and technologies used
* invite facilitator (neutral party) to lead the session
* run session timely after incident
* document findings for suggested improvements
* update incident response plan (if needed)

#### Incident Summary Report

* technical document
* describes the response efforts
* can be used for training purposes

#### Evidence retention

* check with legal if evidence should be stored
* store securely

### Incident response exercise

* tabletop: team members are given a scenario and asked how they would respond and what they would need; similar to a brain-storming session.
* read-throughs: copies are provided to team members and asked for feedback
* walk-throughs: the team goes through a scenario step by step. 
* simulation
  * use a scenario to test the incident response
  * how would each member react?
  * can involve hands-on exercises

## Attack Frameworks

### MITRE ATT&CK

* = **A**dversarial **T**actics, **T**echniques & **C**ommon **K**nowledge
* table of attack techniques: column represents a **tactic**

### Diamond Model

* aims to think of intrusion from different angles 
* 4 core features
  * **adversary** = attacker
  * **victim** (system or organisation)
  * **capability** = what can the attacker use to attack?
  * **infrastructure** = what resources does the attacker have? Can be own or stolen
* an incident can be followed by both the infrastructure or the capability
* other fatures
  * timestamp
  * phase
  * result
  * direction (infra > vicitm or victim > infra [e.g. via social engineering on an employee])
  * methodology
  * resources

### Cyber kill chain analysis

* Lockheed Martin's idea to model the phases of an attack
* focuses on APTs
* 7 phases
  1. Reconnaissance (active or passive)
  1. Weaponization
  1. Delivery
  1.  Exploitation 
  1.  Installation
  1.  Command & Control
  1.  Actions on objectives

## Incident Investigation

### Logging security information

* logs are created on various levels
  * DNS
  * network / netflow
  * application (installed apps)
  * system (OS)
  * Web application
  * authentication
  * VoIP (data using SIP)
  * Dump files (memory)
  * Vulnerability scan
* logs are usually deleted after a while

#### Syslog

##### Parts

* **header** (timestamp and source address)
* **facility** (source of the sending system) - number
* **severity** (0..7 the bigger, the less sever. 2 is critical)
* **message** (any string content)

##### Standards

* `Syslog` supported by Linux, text based
* `syslog-ng`: security and reliable delivery
* `Rsyslog`: even better than the others
* `journalctl`: uses binary format

#### Tagging

* messages can be tagged by
  * name of application
  * user
  * more (other meta data)

#### NXLog

* centralises seperate logs
* cross-platform tool (Windows and Linux)

### Security Information and Event Management (SIEM)

* central, secure **collection point**: messages can be send here where they are stored and available
* use of **artificial intelligence** can be used to detect patterns
* uses **log correlation** to find security incidents

### Security Orchestration Automation Response (SOAR)

* = a better SIEM

* **playbooks**: processed-focus responses to events both automated and for humans
* **runbooks**: automated response to events that perform actions and notify humans

### Cloud Audits and Investigation

* a customer can not investigate a cloud provider's datacentre
* instead, different audit reports are used

#### Service Organisation Control (SOC) reports

* category 1: provides assurance for *financial* audit
* category 2: provide **high-level** assurance of CIA controls (not widely shared)
* category 3: provide **low-level** assurance of CIA controls (publicly shared)
* types (for SOC 1 and 2)
  * type 1: describes the controls that are in place and if they make sense
  * type 2: same as type 1, but the controls have been tested by the auditor
* standards for SOC
  * USA: **SSAE 18**
  * internationally: **ISAE 3402**

## Forensic Techniques

### Conducting investigations

1. Operational: examining and fixing operational issues; no high standards of evidence; *BAU*
2. Criminal: extremely high standards of evidence; *beyond a reasonable doubt* (no other conclusion possible than that person committed a crime)
3. Civil: dispute between two parties (e.g. if action agreed up were done; violation of law, but not criminal); *preponderance of the evidence*; evidence demonstrate more likely that one party is right
4. Regulatory: violation of administrative law or industry standards

### Evidence types

1. **Real evidence**: objects like computers and other hardware
2. **Documentary** evidence: documents or system logs
   Rules to be followed for use in court
   * **authentication rule**: documents must be *authenticated*. Somebody must testify, e.g. a cyber security investigator must demonstrate
   * **best evidence rule**: original is superior to copies
   * **parol evidence rule**: when two parties agree on, the written agreement is assumed to be complete
3. **Testimonial**: statements by witnesses under oath
   * *direct evidence*: based upon observations
   * *expert opinion*: drawn conclusions based on other evidence

### Forensics Introduction

* Collect, preserve and analyse digital evidence
* Investigators must never alter evidence.
* Volatility order
  1. Network traffic
  2. Memory
  2. System and process data
  2. Files (temp files first)
  2. Logs
  2. Archived records
* Timestamps are important, but make sure that it's comparable to a reliable source ("time offset")

### System and file forensics

* Create a copy (image) of a drive, instead of working with the original
* Generate a hash of the image, print it and store it with the original hardware in a sealed container
* forensics should only be done by experts in order not to damage the evidence

### File carving

* = process of restoring deleted files on a drive
* restoration possible since files are marked as deleted, but the contents remain in unallocated disk space
* `bulk_extractor` is one tool that can restore files and filter for specific file types
* `WinHex` is a hex editor that can be used to read and modify restored files

### Creating an image

* Linux: `dd` tool with `if` (input file) and `of` (output file) parameters
* Windows: `FTK Imager` GUI app to create disk images

### Forensics Toolkit

* Hardware: high RAM, powerful CPU and lots of storage
* Software
  * analysis: `FTK`, `EnCase` etc.
  * cryptographic: `md5sum`, `shasum`
  * log viewers
* heaps of removable medias
* write blockers
* documentation
  * incident response plan
  * chain of custody forms
  * incident forms
  * call list / escalation list

### Operation system analysis

* _live analysis_ = analysing a running system
* contents in memory might change very quickly; memory dump tool (e.g. `FTK Imager`) can save it for later
* swap files / page files may contain portions of the memory that were written to disk

#### Sysinternals

* = collection of useful tools for Windows
* now part of Microsoft
* contains of
  * `AccessEnum` = shows permissions assigned to users or groups of each file / folder
  * `Autoruns` = shows all programs that start automatically Windows starts
  * `Process Explorer` = displays all running processes
  * `TCPView` = lists all active network connections

### Password forensics

#### Linux
* hashed passwords are stored in `/etc/passwd`
  * file must be accessible widely
  * brute-force attack possible
* passwords can be moved to `/etc/shadow`
  * access to this file can restricted

#### Cracking passwords

* brute force: trying all combinations 
* dictionary attack
* hybrid attack (dictionary + combinations)
* rainbow table attacks use pre-created lookup tables of MD5 hashes

### Network forensics

* all network communications can be intercepted / tapped

#### Protocol Analyser

* _Wireshark_: powerful protocol analyser that logs every packets sent
* logging every packet uses a lot of space and is noisy

#### NetFlow

* = network flow: high-level information
* source and destinationIP addresses and ports
* timestamp
* amount of data transfered
* captured by routers or firewalls

### Software forensics

* software code might be used as evidence
* two uses
  *  intellectual property dispute: origins of software code
  * origins of malware
  * email header metadata
