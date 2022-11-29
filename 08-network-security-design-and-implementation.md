# Network Security: Design and Implementation

## TCP/IP Networking

#### TCP

* = Transmission Control Protocol
* transport layer protocol
* connection-oriented protocol
* stateful protocol, that uses 3-way handshake to establish connection
  1. client sends `SYN`
  1. server responds with `SYN/ACK`
  1. client responds with `ACK`

#### UDP

* = User Datagram Protocol
* transport layer protocol
* stateless protocol
* used for real-time streaming of data

#### IP

* = Internet Protocol
* network layer protocol
* connectionless
* routing information across networks
* provides the addressing scheme: IP addresses

#### OSI Model

* *Application Layer*: User programs (e.g. web browser)
* *Presentation Layer*: data translation and encryption (how is a char represented)
* *Session Layer*: **API**s, **socket**s
* *Transport Layer*: **TCP** and **UDP**
* *Network Layer*:  **IP**, ICMP
* *Data Link Layer*: Data transfer between two nodes (e.g. switch that connects a computer with a network)
* *Physical Layer*: Wires, radio, optics

### IP addresses and DHCP

* IPv4 use 4 blocks of 8 bits: 0..255 numbers (dotted quad notation)
* IPv6 use 8 groups of 4 hex digits (128 bits)
* NAT (network address translation)
  * IP address must be unique in a network
  * private IP addresses can be re-used in different networks
  * router/firewall translate those addresses 
* Subnets
  * Network address (e.g. `192.168`)
  * Host address (e.g. `1.100`)
* two types of addresses
  * static: fixed, static value (used for server)
  * dynamic: use DHCP to get an IP from a pool (used for clients)

### Domain name system (DNS)

* resolves a name for an IP address
* uses port 53
* DNS resolution is based on a hierarchy
  * local DNS
  * provider DNS
  * authority DNS
* `dig` performs a lookup manually
* DNS can be used to block content, so changing the DNS server can avoid this
* *DNS poisoning* is inserting false DNS records into intermediate DNS servers
* *DNSSEC* is DNS with certificates

### Network ports

* each port is used by a single application (e.g. `80` for _http_)
* range: 0..65,535 (16bit binary number)
* types
  * **well-known ports**: `0` to `1,023` (common applications, assigned by Internet authorities)
  * **registered ports**: `1,024` to `49,151` (be be used by anybody for permanent use)
  * **dynamic ports** : `49,152` to `65,535` (on a temporary basis)
* ports for exam
  * **unsecure**
    * FTP: 21
    * HTTP: 80
    * Telnet: 23
  * **secure**
    * HTTPS: 443
    * SSH: 22
  * **other**
    * RDP: 3389
    * POP: 110
    * IMAP: 143
    * NetBIOS: 137, 138, 139

### Internet Control Message Protocol (ICMP)

* = housekeeping protocol
* `ping` used to check if system is available
  * sender: `ICMP ECHO REQUEST`
  * receiver: `ICMP ECHO REPLY`
* `traceroute` shows the path over the network between two systems
* more functions available (redirects, time exceeded, destination unreachable, ...)

## Secure Network Design

### Security Zones

#### Network Border Firewall

* Trust is based on zone in that a system is placed in
  1. **Internet Zone** (or other untrusted)
  2. **Internal Zone (Intranet)**: can be further sub-divided
  3. **Demilitarised zone (DMZ)**
     *  for applications must accept connection from outside (e.g. Web server, email)
     *  systems have a higher risk of being compromised
* this system is not longer widely used today, instead _Zero Trust_ is followed

#### 3 special purpose networks

* **Extranet**: intranet segment that's open to external users
* **Honeynet**: fake networks that attract attackers
* **Ad Hoc Network**: temporary networks that may bypass security controls (often they live longer than expected)

#### Terms

* **East-West Traffic**: traffic between system within the data centre
* **North-South Traffic**: traffic between systems in the data centre and the Internet

### VLANs and network segmentation

* allows grouping of related systems (regardless of physical location)
* VLANs extend the broadcast domain = users can contact each other as if they were on the same switch
* connection happens on layer 2 (without routing and firewall)
* process
  1. enable VLAN trunking
  1. assign a switch port to a VLAN

### Security device placement

#### Firewall

* at the perimeter: separating DMZ, internal network, and Internet
* between endpoint network and wireless network

#### Port taps

* SPAN port on switches provide a copy of all traffic that's passing through a switch
* port mirroring allows traffic monitoring, but only for a single switch port

#### Security Information and Event Management

* use more than one collector
* correlation engine
  * analyses the data
  * should be placed in a protected network

#### Content filters

* should be put in the DMZ
* add a layer of isolation

#### VPN Concentrator

* should be put on their own VLAN
* aggregate remote user connections

#### Load Balancer

* distribute traffic among multiple servers
* should be placed in DMZ

#### SSL Accelerator

* help out with encryption/decryption
* support Web servers
* should be placed in DMZ

#### DDoS Mitigation Tool

* as close to the Internet connection as possible
* should be provided by ISP (traffic can be blocked before it reaches network)

### Software-defined networking (SDN)

* network setup
  * *control plane*: handles routing and switching decisions
  * *data plane*: moves packages around, based on the instructions by control pane
* SDN separates the control plane from data plan
* SDN makes a network programmable (e.g. providing an  application dynamically get more bandwidth)
* SDN can increase security
  * infected switch port can be removed from network
  * fine-grain configuration; strong network segmentation
* SND might increase complexity

## Network Security Devices

### Switches

* have ports to connect devices
* SPAN port to copy data to
* work on layer 2 (some can work on layer 3)
* forward traffic to a device with a specific MAC address
* **Wireless access points (WAPs)**
  * use radio waves
  * has a wired connection to a switch

### Routers

* connect networks together
* can use **access control list** (stateless inspection) for security

### Bridges

* work on layer 2
* connect two networks together

### Firewalls

* use rules that contain
  * source system address
  * destination system address
  * port and protocol
  * action: allow / deny (core principle: **implicit deny**)
* often sit between internal network and Internet
* two systems
  * host firewall
  * server firewall
* **stateful** / **stateless**
  * stateless: each packet is analysed independently
  * stateful: only the first packet is analysed between two systems and then all the others are accepted
* deployment options
  * network / hardware firewall (using closed source software)
  * host-based /software firewall (open source solutions available)
  * for network firewall: hardware appliance or virtual appliance
* **next-generation firewalls (NGFWs)** take into account
  * time of day
  * user's identity
* other roles
  * **NAT gateway**: map IP addresses between private and public
  * **content filtering**: using URLs
  * **Web application firewalls**: understand HTTP and look for attacks

### Proxy servers

* sit between client and server
* 3 types
  * reverse proxy
    * proxy sits on the remote network
    * many web servers are connected to one proxy server
    * client is not aware of the proxy
  * forward proxy
    * proxy sits on the client's network, server is not aware of the proxy
    * **performance**: content can be cached in proxy
    * **anonymity**: servers don't get to know details about end user
    * **filtering**: content filtering possible
  * transparent / inline proxy (or "forced proxy")
    * intercept requests without knowledge of client _and_ server
    * doesn't work with TSL
* proxies can handle everything, not just web traffic

### Load balancer

* distribute the load across several web servers
* IP of load balancer is used for DNS
* **autoscaling**: being able to add more servers automatically if demand increases
* security functions
  * SSL cer management
  * URL filtering
* **routing options**
  * *round-robin*: each server the same amount of requests
  * *advanced scheduling*: using server's status (e.g. CPU load) to distribute requests
* **sticky-session / session persistence**: the same user must access the same server after logging in
* are a single point of failure
* 2 ways to run them
  * active-active mode
    * two instances of LBs run in parallel
    * if one fails, the other is still up but performance will be lower
  * active-passive
    * one LB is active, while the other is monitoring its health
    * if the active goes down, the other LB starts working

### VPNs and VPN concentrators

* Two use cases
  * **Site-to-Site VPN**: connect two offices securely
  *   **Remote Access VPN**: allow remote workers to access network via public connection
* endpoints
  *   Firewalls
  *   Routers
  *   Servers
  *   VPN concentrators: can manage high-bandwidth traffic
*   VPNs create a virtual (encrypted) tunnel over the Internet
* **IPSec (Internet Protocol Security)**
  *   was used to create a tunnel
  *   works on layer 3 by default
  *   Layer 2 Tunneling Protocol (L2TP)
  *   might be blocked by firewalls
  *   hard to configure
  *   used for site-to-site VPN
* **SSL/TLS VPN**
  *   works on layer 7
  *   used for remote-access VPN
* 2 tunneling approaches
  *   **Full-Tunnel VPN**: every traffic goes through VPN
  *   **Split-Tunnel VPN**: only some systems use VPN, other traffic uses local network

### Network intrusion detection and preventing

* **Intrusion Detection system (IDS)**
  * is passive, only monitors traffic
  * can alert when attack is detected
* **Prevention system (IPS)**
  * is active
  * can block traffic
* two types for detecting attacks
  * *Signature Detection System* / *Rule-based detection*
    * has a database of known attacks
    * lower false-positive rate
    * can not protect against new attacks, that are not yet part of DB
  * *Anomaly Detection System* / *behaviour-detection* / *heuristic approaches*
    * builds a model of "normal" activity
    * analyses patterns (e.g. time of day and location)
    * often application-aware
    * potential higher false-positive rate
* Deployment
  * **in-band** / **inline**
    * traffic goes through IPS
    * single point of failure
    * can block traffic
  * **out-of-band** / **passive**
    * connects to SPN port
    * is not single point of failure
    * can't block initial traffic, but can request to block future traffic

### Protocol Analysers

* see individual packets
* tools for troubleshooting or security incidents
* 2 tools based on the library _libpcap_
  * Wireshark
  * `tcpdump`
* `tcpreplay`: can edit and replay traffic

### Unified threat management (UTM)

* is a single hardware device that contains several functions
  * basic functions
    * protecting network
    * blocking traffic
    * routing traffic from Internet
  * advanced functions
    * VPN
    * Intrusion detection
    * Intrusion prevention
  * additional features
    * URL filtering
    * content inspection
    * malware inspection
    * Email and spam filtering
* UTM devices require regular monitoring
* best suited for small businesses

## Network Security Techniques

### Restricting network access
* **Rule based** restrictions: list allowed/forbidden activities for a network
* **Role bases**: access is based on an individual
* **Time based**
* **Location based**

### Network access control (NAC)

* intercepts traffic and verifies it *system* and *user* are authorised
* uses `802.1x` protocol
* roles
  * device that wants to connect needs to run a software: *supplicant* 
  * *authenticator*: switch / wireless controller
  * *authentication server*
* process
  * *supplicant* provides credentials to authenticator
  * *authenticator* uses RADIUS to forward the credentials to authentication server
  * *server* responds with RADIUS accept / RADIUS reject
* NAC roles
  * user and devices authentication: as described above
  * role-based access: placing the user on a specific network based on role
  * posture checking
    * criteria
      * host firewall
      * system is patched
      * anti-virus software running and up to date
    * process
      * if failed: quarantine VLAN to make system secure
      * if successful: access granted to designated VLAN
    * agents running on a device to verify
    * agent-less: scanning device from outside
    * types
      * inline: enforces decision to quarantine / grant access
      * out of band: examines if device is secure, but leaves decision to other system

### Firewall rule management

* default deny if no matching rule found
* firewalls can easily contain 100s or 1,000s of rules
* common errors
  * **shadowed rules**
    * rule will never be executed, because it's "too low" in the list
    * fix: put more specific rules on top of general rules
  * **promiscuous rules** allow more access than needed du to typo or mistake
  * **orphaned rules**: rules still exist, even if a system is no longer in used; dangerous if IP addresses are re-used

### Router configuration security

* can filter traffic in order to reduce load of firewalls
* Router Access Control Lists
  * standard: block traffic based on source IP address
  * extended: based on source IP, destination IP and protocols
* router can perform QoS controls

### Switch configuration security

* physical security of hardware (since switches are used in many locations)
* **VLAN Pruning**: only use expose a WLAN on a switch if it's required to do so
* **VLAN Trunk Negotiation**: deny automatic VLAN trunk negotiation
* **Port Security**: limit the MAC addresses used on a switch port
  * *static*: manually configure valid MAC addresses for each port
  * *dynamic* / *sticky*: save the first MAC address on each port and restrict access to that address
* **DHCP Snooping**: inspect DHCP messages and validate sender and payload

### Maintaining network availability

* flooding attacks
  * SYN flood
    * initiating a three-way handshake, but never finishing it
    * results in firewall state tables filling up
  * MAC flood: attempting to overflow switch's MAC address table
* routing loops attacks
  * attempting a *broadcast storm* (no capacity left for regular use)
  * Spanning Tree Protocol (STP) prevent broadcast storms

### Network monitoring

* **firewall logs** (details about attempted connection, timestamp, rule used)
* **Network Flow Data** includes the summary of some network traffic
  * source / destination systems
  * ports used
  * timestamps
  * amount of data transferred
* **SIEM** systems automate log analysis based on data from 
  * firewalls
  * network devices
  * servers
  * applications

### Simple Network Management Protocol (SNMP)

* enables remote monitoring and configuration
* 3 components
  * *managed devices* (routers, switches, WPA, firewalls, ...)
  * *agent*: software that runs on the device to communicate to system
  * *network management system*
* commands
  * `GetRequest`: read configuration, activity, etc. (responds with `Response`)
  * `SetRequest`: update configuration on device
  * `SNMP Trap`: devices report to management system
* **SNMPv3** should be used, no earlier version!

### Isolating sensitive systems

* a compromise in a low-security system should not effect high-security systems (networks, servers, etc.)
* individual zones creates overhead, but are very safe
* **jump box** / **jump hosts** / **jump servers**
  * = servers to connect to a specific security zone
  * connect to two networks (e.g. internal network **and** DMZ)

### Deception technologies

* **Darknets**
  * unused, but monitored space
  * if activity is detected here, it's a attacker or misconfigured system
* **Honeyfiles**: fake data that looks like sensitive information to attract attackers
* **Honeypots**:
  * systems put on a system to attract attackers (may contain Honeyfiles)
  * are monitored carefully
  * can trigger alerts immediately
* **Honeynets**: several honeypots
* **DNS Sinkhole**
  * use the server names of command&control servers
  * re-route traffic to avoid it from reaching them

## Transport Encryption

### TLS

* is a process to use encrypted communication over an insecure/public networks
* uses existing ciphers
* process
  1. client asks server to use TLS and provides a list of supported ciphers
  1. server
    * chooses a cipher
    * provides certificate
  1. client
    * verifies signature on certificate with CSA
      * domain name matches
      * certificate is not expired
      * certificate has not been revoked
    * creates a random symmetric encryption key ("session key" / "ephemeral key")
    * encrypts the session key *using the server's public key*
    * sends the encrypted session key to server
  1. server *decrypts session key with private key*
  1. secure communication can now start using the session key
1. problem: security tools can not see content of end-to-end encrypted traffic
1. **SSL Inspection**: "friendly" man-in-the-middle attack to inspect traffic

### IPsec

* adds security to TCP/IP by providing two protocol
* **Encapsulating Security Payload (ESP)**
  * secures the _payload_
  * adds **confidentiality**
  * ensures **integrity**
* **Authentication Header (AH)**
  * secures _payload_ **and** _headers_ of a packet
  * ensures **integrity**
* a single communication can used both protocols together
* **Security Association (SA)**
  * list of ciphers / hash functions that are supported by client and server
  * the strongest algorithm is selected
* VPN
  * *Site-to-Site VPN (tunnel mode)*: two networks are connected, but traffic is going through VPN tunnel
  * *End-User VPN (transport mode)*: encrypted network access for a single user

### Securing common protocols

* `https` adds TLS to web browsing
* `ssh` should be used instead of `telnet` (which was not encrypting traffic)
* Alternatives to FTP
  * `ftps` adds TLS to `ftp`
  * `sftp` transfers files over SSH once a connection is established
  * `scp` also uses SSH
* Void and video should use TLS, too: **Secure RTP** instead of RTP
* **Network Time Protocol** has issues, use  `NTPsec` instead
* Email
  * POP: 110 => 995
  * IMAP: 143 => 993
  * SMTP: 25 => 465
* Email content can be encrypted with `S/MIME`
* `DNSSEC` instead of `DNS`
* `LDAPS` instead of `LDAP`

## Wireless Networking

### Encryption

* = takes insecure medium (radio wave) and makes it secure
* Wired Equivalent Privacy (WEP) is no longer secure
* **Wi-fi Protected Access (WPA)**
  * first version
    * used TKIP to rapidly rotate encryption keys
    * no longer secure
  * **WPA2**
    * upgrade to WPA
    * uses AES encryption
    * CCM protocol
    * *still secure*
  * **WPA3**
    * supports CCMP
    * SAE protocol for key exchange (based on Diffie-Hellman)
    * *secure*

### Wireless authentication

#### Pre-shared keys
* = Wi-fi passwords
* PBKDF2 to convert a ASCII password to a strong key
* changing key is hard work
* no identification of an individual user

#### Enterprise Authentication
* individual credentials
* 3 available protocols
  1. **Lightweight EAP (LEAP)**
    * relies on MS-CHAP
    * *no longer secure*
  1. **Extensible Authentication Protocol (EAP)**
    * with TLS: **secure**
    * EAP-TTLS **secure**
    * EAP-FAST **secure**
    * EAP-MD5 *unsecure*
  1. **Protected EAP (PEAP)**: uses a TLS tunnel for communication

#### Captive portals

* authenticate via a Web front-end

### Wireless signal propagation

* **omnidirectional antennas** send signals in all directions
* **directional antennas** create a point-to-point connection
* 802.11ac *beamforming* steer the data to the device
* placement is best done after a site survey to measure signal strengths
* Wi-fi standards support using channels
* power level of each AP can be adjusted (automatically)

### Wireless networking equipment

* *Fat Access Point*: hardware + software
* *Thin Access Point*: rely on wireless controllers
* *Wireless controllers* manage and configure APs
* Wi-Fi Analysers: software tools for testing and examining Wi-Fis

## Network attacks
### Denial-of-Service attacks (DoS attacks)

* make a resource unavailable for legitimate use
* works by sending a large number of requests to overload a system
* disadvantages for attackers
  * require a large network
  * can be stopped by blocking IP addresses

### Distributed Denial-of-Service attacks (DDos attacks)

* use a botnet to spam a system
* therefore, use several IP addresses
* *Smurf Attack*: Botnet using Echo Requests to overload a system
* *Amplified DDoS attack*
  * sending a small request from controlling system to infected systems
  * infected systems produce requests the result in a large reply
  * `amplification = reply / request`
* targets
  * networks
  * applications
  * operational technologies
* fighting DDoS with ISP or third parties (e.g. Akamai)

### Eavesdropping Attack

* if attacker gets access to a network, they might be able to listen to communication (communication path is compromised)
* types
  * network device tapping
  * DNS poisoning
  * ARP poisoning
* _on-path_ attacks
  * **Man-in-the-Middle Attack**: the *initial request* is intercepted and passed through the attacker
  * **Man-in-the-brower attack**: a plugin or modified browser relays communication
* *replay attack*
  * uses recorded data to re-send data to a server
  * credentials are still encrypted
  * token or timestamp can prevent this kind of attack
* **SSL Stripping**
  1. attacker intercepts the initial (http) request
  2. server forwards to the https site via 302
  3. attacker uses https to communicate with the server, but http with the client

### DNS attacks

#### DNS poisoning

* DNS uses a hierarchy to lookup domain names
* attacker inserts a fake DNS server in the chain
* attacker uses a fake website to steal information

#### URL squatting

* registering domain names that are similar to the target
* fake website is used instead of real website

#### Domain Hijacking Attack

* take over control over a domain
* a fake website steals information

#### URL Redirection

* inserting a JS or HTML snippet that forwards a user to a different URL

### Layer 2 attacks

* **(Address Resolution Protocol) ARP** maps IP addressed to MAC addressed
* **ARP poisoning**
  * works on a local network
  * tricks the hub/switch to route traffic to an attacker
  * attacker can then perform a man-in-the-middle attack
* **MAC Flooding**
  * spamming a switch with MAC addresses until the memory overflows
  * goal: old entries are removed
  * switch will broadcast traffic if receiver is unknown
  * attacker on a different port can eavesdrop 

### Network address spoofing

* MAC addresses and IP addressed can be changed on a device
* networks should not rely on specific IP addresses or MAC addresses
* **Ingress Filtering**
  * blocks traffic that contained spoofed source addressed
  * internal addresses should never appear on traffic coming from outside the internal network!
* **Outbound Filtering**
  * watches for traffic for *source addresses* that don't belong to the organisation
  * system is potentially being used for a DDoS attack

### Wireless attacks

#### Wired Equivalent Privacy (WEP)

* is insecure due to the implementation of the initialisation vector (using RC4)
* Wi-Fi Protected Access (WPA) uses *Temporal Key Integrity Protocol (TKIP)* to avoid this
* hashing in TKIP is insecure
* WPA2 and WPA3 are **secure**

####Wi-Fi Protected Setup (WPS)

* allows quick connection to a Wi-Fi by
  * pressing a button
  * entering a 8-digit PIN
* flaw in WPS PIN (only 11,000 guesses)
* PIN can not be changed
* WPS should be disabled

### Propagation attacks

* **Jamming & Interference**: preventing communication by broadcasting on the frequencies used by Wi-Fi
* **Wardriving**: scanning for Wi-Fis while driving
* **Warflying**: scanning using a drone

### Preventing rouges and evil twins

* **Rouge access points**
  * = connecting an unauthorised WPA to the network
  * WPAs can bypass authentication
  * can interfere with channels in use by enterprise WPAs
  * *Intrusion detection systems* can find those
* **Evil Twins**
  * fake WAPs target users who think they connect to the desired system instead

### Disassociation attacks

* a WPA can send a **deauthentication frame** to a client to force it to re-authenticate
* this command can be issued by an attacker using the source IP address of the WAP
* two goals
  * *gather cryptographic information* when the client re-authenticates
  * *DoS attack*: preventing the client from using the Wi-Fi

### Bluetooth and NFC attacks

* **Bluejacking**: sending spam messages to a device
* **Bluesnarfing**: forces pairing between to devices

### RFID security

* RFID chip activates when scanned
* strong authentication and encryption required when using RFID systems

## Mobile Device Security

### Security Controls

* **access controls**
  * *passcode*: use complex alphanumeric passcodes instead of 4-digit PINs
  * *biometric authentication*: fingerprint, facial recognition
* *full-device encryption* (enabled by default)
* *remote wiping technology*
* lock automatically after inactivity
* lock out users if passcode is tried too often
* hardware security modules on a microSD card
* SE Android built on SE Linux

### Mobile device management (MDM)

* like *ActiveDirectory for mobile devices*
* often part of **Unified Endpoint Management (UEM)** solutions
* allow *device configuration* (preventing users from modifying security settings)
* allows control of the data stored on device
* application control: whitelist or blacklist
* containerisation / storage segmentation on a device
* content filter to prevent accessing un-authorised content

### Mobile device tracking

* Mobile devices inventory with **asset tracking software**
* Geolocation tracking on devices
* Geofencing can alert when a device leaves a specific area

### Mobile application security

* application control policies: blacklist/whitelist
* applications that *access company data* should use *authentication*
* ideally: rely on central authentication
* often apps rely on external providers (Google, Facebook, Twitter)
* all sensitive information should be encrypted (in transit, at rest, in memory)
* GPS/geotagging might expose company locations

### Mobile security enforcement

* **side loading**: installing apps from third-party app stores
* **jailbreaking**: install a patched/unofficial version of iOS
* firmware / OS must up to date
* **MDM** can *restrict device features*
  * camera
  * messaging
  * external media / USB
  * microphone
  * GPS tagging
  * tethering / Wi-Fi usage
  * mobile payments

### Bring your own device (BYOD)

* one issue: ownership
  * old: device, data and support owned by company
  * new
    * device: employee
    * data: mix of employee and company
    * it: company
* legal / privacy issues: what monitoring is in place on a personal device?
* guidelines
  * **onboarding**: making sure that a device meets security requirements
  * **offboarding**: removing company information from a device and unlink accounts
* standardisation of hardware and software is more difficult or impossible with BYOD

### Mobile deployment models

* *choose your own device*: leave employees the choice of hardware
* *Company owned, personally enabled (COPE)*: allowing personal use on a corporate device
* *Virtual Desktop Infrastructure*: desktop run on data centres or the cloud

## Network Tools

### Ping

* asks if a system is available via _ICMP Echo Request_
* remote system _might_ respond with _ICMOP Echo Reply_
* `hping` allows to customise the package used for `ping`
* `pathping`: Windows tool that combines `ping` and `tracert`

### Traceroute

* traces the path between two systems
* some systems in the route chose not to identify themselves
* contains latency for each system on the route
* `traceroute` on Mac/Linux and `tracert` on Windows

### DNS tools

* `dig`: performs DNS lookup on Mac/Linux
* `dnslookup`: same for Windows
* `whois`: discovers ownership of IP address or domain names
* Reverse whois (e.g. `viewdns.info`): finds all domain names registered to an email address 

### ifconfig / ipconfig

* `ifconfig` displays and configures a network interface on Mac/Linux
* `ipconfig`: same for Windows
* `route` displays routing information

### netstat

* `netstat` displays the active network connections on Mac/Windows
* `ss`: same for Linux

### netcat

* tool to allow opening a connection via CLI
* sends a command to the connected system that must comply to the chosen protocol

### ARP

* `arp` translates a IP address to a MAC address
* same CLI tool name for all OS

### curl

* `curl` retrieves data from the Internet via CLI
* has special function to receive binary data: `--output <filename>`
* can also be used to just see the HTTP headers (via `-I`)


### theHarvester

* searches the Internet for information about a Domain name
* finds email addresses, hosts and more

### cuckoo

* is a sandbox that allows to test suspicious files
* analyses execute files, documents, emails and websites
* traces API calls and captures network traffic
* analyses memory usage
* works on Windows/Mac/Linux and Android

### Port scanners

* find all open ports on a system
* open ports can provide information about the OS in use
* open ports are attack entry points

### Vulnerability scanners

* perform vulnerability tests on each service that is enabled on the target system
* example: **Nessus**
* `Sn1per`: automates penetration testing
