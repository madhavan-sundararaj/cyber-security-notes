# Threats, Attacks and Vulnerabilities

## Malware (= malicious software)

* propagation mechanism: how the software spreads
* payload: malicious action

### Examples of malware

 * **Viruses**
    * spreads by human action
    * anti-virus software identifies viruses based on their code
* **Worms**: spreads without humans (they spread by using vulnerabilities)
*  **Trojan** horses
  * propagation mechanism is a useful software that's installed by a human
  * application control solutions mitigate the risk
  * Remote Access Trojans (**RAT**): provide attacker with remote control

### Malware Payloads

* **adware**: displaying ads on the user's screen, embed them in websites or changes the search agent
* **spyware**
  * gathers information without the user's consent 
  * keylogger / keystroke loggers: steals account information
  * monitors web browsing
  * searching drives / cloud storage
* **ransomware**
  * blocks access to computer or files
  * restores access after payment
* **crypto malware**: uses infected computer to mine crypto currency

### Preventing Malware

* educate the users
* install anti-virus software
* keep OS/software up to date

### Backdoors

* provide access that bypasses regular/secure access
* often put in place by developers on purpose
  * for debugging systems
  * to help users that are locked themselves out
* are dangerous if hackers know them
* examples
  * hard-coded accounts
  * default passwords (that are never changed)
  * undocumented channels

### Logic Bombs

* Malware that enables themselves automatically under circumstances
  * certain date and time
  * when a check fails (e.g. person not on payroll any longer)

### Rootkit

* escalate privileges to root
* attacker needs to login to a regular account first
* payload
  * backdoors
  * botnet agents
  * adware/spyware
  * but also anti-theft

### Fileless viruses

* never write to disk
* operate in memory only
* examples
  * macro virus
  * JS code that uses browser vulnerabilities
  * Windows registry

### Botnet

* list of infected computers
* access to botnet is sold/rented to
  * perform attacks against systems
  * mine crypto currencies
  * send SPAM
  * perform DDoS attacks
  * do brute-force attacks
* are controlled by a control server
* indirect & redundant control mechanisms, like
  * IRC
  * Twitter
  * peer to peer within the botnet

### Malicious script execution

* types
  * shell scripts: command line (e.g. bash / PowerShell)
  * application scripts: part of a software (e.g. macros like VBA)
  * programming languages: JS / Python
* are used for regular tasks, but also by attackers

## Understanding Attackers

### Parameters of adversaries

* external / external
* skills
* access to resources
* motivation
* intent

### Types

* *script kiddies*: unskilled, lone wolf (just able to use existing attacks)
* *hacktivists*: any skill, has political/social agenda
* *organised crime*: have resources to hire skilled hackers; aim for ranso
*  *corporate espionage*: spying one competitors
* *nation states*: sponsor APT (advanced persistent threat) groups

### Hat colours for identifying

* *white hats*: operate with permission and good intent
* *black hats*: operate without permission and malicious intent
* *grey hats*: operate without permission, but good intent

### Insiders

* are more dangerous due too knowledge and access
* often happens at high levels (IT, executives)
* regular account can be lifted by using privilege escalation
* outsiders might support insiders to perform attacks
* mitigation
  * background checks
  * principle of least privileged
  * two-person controls for sensitive operations
  * mandatory vacation for critical staff
* Shadow IT: insiders bring hardware into network that's not allowed

### Attack Vectors

* email: messages can contain attachments or links to malicious websites
* social media: (same as email)
* removable media
  * USB sticks spread malware when inserted.
  * card skimmers can clone cards while the card is used
* cloud services: e.g. accidentally published API keys, files with improper permissions
* direct access to hardware
  * ethernet port in offie building
  * tampering with hardware that's being delivered to the company
* wifi

### Zero-day Vulnerability

* = security flaw in a system that's unknown to the vendor
* no patch exists yet, so all installations are vulnerable
* regular process
  * discover vulnerability
  * let vendor know and give time to roll out patch
  * document vulnerability in public
* window of vulnerability: time between discovery and availability of a patch

## Threat Intelligence

* = staying up to date on cybersecurity threats by
  * education
  * integrate information
* threat intelligence solutions can be directly integrated into software (e.g. firewalls)
* factors to reate a source
  * timeliness
  * accuracy
  * reliability

### Managing threat indicators

* information that describes a threat actor by	
  * IP addresses
  * file signatures
  * communication patterns
* 3 frameworks defined by the Department of Homeland Security for sharing information in an automated way
  * *Cyber Observable eXpression* (**CybOX**): schema to classify threats
  * *Structured Threat Information eXpression* (**STIX**): uses CyBOX to create a file
  * *Trusted Automated eXchange of Indicator Information* (**TAXII**): exchanges STIX files
* OpenIOC: another standard to defining threats

### Intelligence Sharing

* teams interested in security information
  * incident response
  * vulnerability management
  * risk management
  * security engineering
  * detection & monitoring
* ISAC: Information Sharing & Analysis Center
  * share information across different organisations
  * confidentially
  * IASAC exist for different industries
  * are non-profit

### Threat Research

* **Reputational Threat Research**: based on known facts (IP address, domain, ...)
* **Behavioural Threat Research**: based on activity pattern

### Identifying threats

* 3 structured approaches
  * *asset* focus: e.g. web server, wifi, ...
  * *threat* focus: e.g. contractors,  partners, ...
  * *service* focus: e.g. how can a public API be used?

### Automating threat intelligence

* example 1: blacklisting IPs reported by an external service
  * to avoid blocking causing issues, instead of blocking alerting is possible as phase 1 of automation
* example 2: incident response
  * automated data enrichment when an attack is detected
  * data is collected and appended to the incident report

### Threat hunting

* preventing all attacks is impossible: "assumption of compromise"
* threat hunting = systematic approach to find indicators of compromise
* process
  * think like an adversary
  * hypothesis: an attacker used this way to get in
  * define indicators: what traces would be in our system if that worked?
  * find proof for indicators
  * if found: move to incident response

## Social Engineering Attacks

### Social Engineering

* Definition: 
* 6 tactics
  * authority and trust
  * intimidation
  * consensus/social proof
  * scarcity
  * urgency
  * familiarity/liking
* Solution: educate staff about SE and how to react to it

#### Impersonation Attacks

#### Spam

* Definition: unwanted messages for marketing and identity fraud purposes
* Phishing
  * messages try to trick user into getting access to systems
  * links in emails lead to fake websites that will store access information
* Spear Phishing
  * targeted attack to small group
  * personalised emails are created for that group
  * invoice spam: fake invoices are sent to accounting for the chance they might get paid
  * Whaling: spear phishing on executives, e.g. sending fake court messages that contain a link to a fake website

##### Pharming

* fake websites that look like the original and have a similar URL

##### vishing
* voice phishing
##### Smihsing
* SPAM/phishing via text message or other message systems
##### Spoofing:
* faking an identity

### Identity fraud and pretexting

* = stealing the identity of an individual to
  * open accounts in their names
  * perform crimes
  * steal funds
* Pretexting attack
  * attacker contacts a company impersonating a consumer
  * public information (e.g. on social media) can be used to answer security questions
* Watering hole attacks
  * is a client-side attack performed using a website
  * process
    * a website is compromised
    * a client exploit is selected that will connect the client's system to a botnet
    * malware is put on the infected website
    * wait until client systems connect to the botnet
  * strategies to prevent
    * keep browser up to date
    * look carefully at warnings/messages from browser
    * keep website safe and secure

#### Physical social engineering

* shoulder surfing
  * look at other people's screen and note access information
  * preventing: be aware of surroundings and use a privacy filter on screen
* dumpster diving
  * harvest thrown-out hardware or papers and look for stored information
  * preventing: securely delete file or destroy media before dumping hardware
* tailgating
  * entering a building without using a swipe card
  * preventing: educate staff

## Common Attacks

#### Password attacks

* on Linux `/etc/passwd` contains hashed passwords - `/etc/shadow` can also contain the hashes so that only `root` can access it
* hash function
  * creates a fixed-length output
  * every change in input must create different output
  * must be irreversible
  * should be stable: no two inputs should have the same output
* 4 Cracking a password
  * brute force: try all possible combinations
    * offline against stolen file
    * online against a web site
  * dictionary: try English words
  * hybrid: dictionary + variations (e.g. adding a year)
  * rainbow table: using precomputed hashes
* Sometimes passwords should only be one factor in a multi-factor authentication system

#### Password spraying

* list of commonly used passwords is used for as many accounts as possible
* only possible if system allows weak passwords (list of common passwords)
* stopped with: multi-factor authentication

#### Credential stuffing

* uses the fact that user re-using passwords on multiple sites
* Step 1: hack a low secure site
* Step 2: use the stolen credentials for a high secure site
* stopped with: multi-factor authentication

##### Artificial Intelligence

* 3 Types

  * Descriptive Analytics: describe existing data 
  * Predictive Analytics: predict future events based on data
  * Prescriptive Analytics: optimise behaviour by simulating scenarios

* Adversarial AI: attacks against AI

  * stealing algorithms
  * inject data into training process
  * fooling an algorithm


## Understanding Vulnerability Types

### Impact

#### CIA Triade

* **Confidentiality**: protecting information and system from unauthorised access
* **Integrity**: protecting information and systems from unauthorised changes
* **Availability**: authorised people can always access information and systems

#### Categorising risks

* financial: monetary damage due to replacing/repairing damaged data
* reputational: loss of good will of stakeholders
* strategic: competition might gain valuable insights to company
* operational: slow down of business or preventing day-to-day operations
* compliance: sanctions/fines due to breaking laws

###Supply Chain Vulnerabilities

* hardware might be intercepted and modified to allow unauthorised access after integration
* attacker might now about security issues in hardware/software
* sometimes it's not clear which hardware/software is used in a product (e.g. embedded OS)

#### Product lifecycle

* end-of-sale: no longer sold, but support is ongoing
* end-of-support: no support, but maybe still supplying patches
* end-of-life: no patches are supplied, even if new security holes are discovered

### Configuration Vulnerability

### Unchanged factory configuration
  * default permissions
  * default passwords
  * dangerous system with embedded computers are used that are not monitored by IT

#### Cryptographic issues
  * weak cipher
  * weak protocols
  * poor key management
  * certificate management

#### Patch management
  * OS
  * applications
  * firmware

#### Account management
  * principle of least principle: only provide the minimum permissions needed

### Architectural Vulnerabilities

* security must be part of the design
* it's impossible to "add security" later
* business process: who has access to information and how to train those people?
* **system sprawl**: unmanaged (un-patched) devices are added to a system, but not disconnected when no longer needed

## Vulnerability Scanning

### Patching Process

1. Vulnerability is discovered
2. Developers fix it
3. Vendor releases a patch
4. Administrators apply the patch

### Vulnerability Management

* is needed because multiple vendors release patches on different dates and the status of various system needs to be tracked
* reasons for a management system
  * system security
  * corporate policy
  * regulatory requirements
  * *PCI DSS* for handling credit cards
  * *FISMA* when working with US government
* performs 3 type of tests
  * network vulnerability scans
  * application scans
  * Web application scans

### Scan Targets

* asset inventory
  * list of system that can be scanned
  * system can discover systems if no inventory exists
* 3 categories for each asset
  * impact: what data is stored?
  * likelihood: how exposed is this system?
  * criticality: how important is it?

### Scan Configuration

* IP address ranges
* can run on a scheduler
* types of pings
* ports to scan
* rate limiting

### Scan Results (server-based)

* depends on where the scanner lives
  * inside DMZ
  * in internal network
  * outside the network
* each configuration offers different perspectives

#### Alternatives to server-based

* Agent-based scanning (= software is installed on server)
* credentialed scanning (= server-based scanner gets credentials to access a system)

### SCAP (Security Content Automation Protocol)

* standard to describe environments, vulnerabilities and remediation steps
* 6 components
  * CVSS: Common Vulnerability Scoring System 
  * CCE: Common Configuration Enumeration
  * CPE: Common Platform Enumeration
  * CVE: Common Vulnerabilities and Exposures
  *  XCCDF:  Extensible Configuration Checklist Description Format
  *  OVAL: Open Vulnerability and Assessment Language

#### CVSS: Common Vulnerability Scoring System
  * is a score from 0 to 10 to rate a V.
* **8 metrics**
* first 4 describe **exploitability**
* second 4 describe **impact**
* AV: Attack Vector
    1. P: physical
    2. L: local
    3. A: Adjacent Network
    4. N: Network
* AC: Attack Complexity
    * H: high (requires knowledge/skills)
    * L: low (possible by anybody)
* PR: Privileges Required
    * H: high (admin/root account needed)
    * L: low (basic user account needed)
    * N: none (no access needed)
* UI: User Interaction
    * R: required (user needs to perform action)
    * N: none (no user needed)
* C: Confidentiality
    * N: none (no impact)
    * L: low (access to some information possible)
    * H: high (all information compromised)
* I: Integrity
    * N: none (no impact)
    * L: low (modification of some content possible)
    * H: high (all information compromised)
* A: Availibility
    * N: none (no impact)
    * L : low (performance degraded)
    * H: high (system shut down)
* S: Scope
    * C: changed (V can affect other components)
    * U: unchanged (V only affects one system)
#### CVSS Rating Scale

 * 0: none
 * 0.1 - 3.9: low
 * 4.0 - 6.9: medium
 * 7.0 - 8.9: high
 * 9.0 - 10.0: critical

#### Analysing reports

* 5 factors to triage
  * V. severity
  * System criticality
  * Information sensitivity
  * Remediation difficulty
  * System exposure
* Validation first! (does this V. even exist?)
  * is it a false positive?
  * is is a known issue? (e.g. an accepted risk)

#### Correlating Results

* PCI DSS only allows for up to 3.9
* watch for trends in scan results
* cross-reference internal documentation

## Penetration Testing and Exercises

### Penetration Testing

* goal: figure out if an attack can get through the system
  (= the security controls are defeated)
* before starting (should be written down)
  * what systems should be tested?
  * what methods are allowed?
* types of test
  * **white box**: attacker has insider knowledge
  * **grey box**: attacker has _some_ knowledge about system
  * **black box**: attacker has no information
* process
  1. **pre-engagement** interactions: scope of test, objectives/goals, type (see above)
  1. **reconnaissance** (Open Source Intelligence Gathering): finding out information about company / target system using
     1. search engines
     1. whois
     1. social engineering
     1. internal footprinting: ping, port scanning, packet sniffing
     1. dumpster diving
     1. tailgating
  1. **Thread modelling and vulnerability identification**: find targets and attack vectors
     1. business assets (employee data, customer data, technical data)
     1. threats: internal and external
  1. **Exploitation**: test the exploits found in previous step
     1. network attacks
     1. social engineering
     1. physical attacks
     1. Web application attacks
  1. **Post-exploitation, risk analysis & recommendations**: document methods used
     1. value the compromised systems and captured data
     1. document how to fix security holes and vulnerabilities
     1. cleanup: remove scripts, backdoors, reset configuration, remove accounts created
  1. **Reporting**: create recommendations
* pivot: after getting into one system attack another system from the hacked host
* persistence: installing tools on (at least) on compromised system and use that as a base for further attacks to the system (even if the initial vulnerability has been fixed)
* pen tests are labour intensive and expensive
* reconnaissance phase?

### Bug Bounty

* attract skilled attackers to your systems
* attackers can practice/train and earn money
* organisations can learn from successful attacks and adept accordingly
* vendors can create a bug bounty program

### Cybersecurity exercises

* competition style format
* teams
  * red: attackers
  * blue: defenders - often get a head start to secure system
  * white: observers/judges
* goal: combine knowledge from both sides during a lessons-learned session after the exercise
