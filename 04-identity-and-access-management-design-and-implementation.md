# Identity and Access Management: Design and Implementation

## Introduction

### AAA

* **Identification**: claiming to be a person/entity
* **Authentication**: providing proof that user is the identity they claim
* **Authorisation**: verifying that the user has access/permission
* **Accounting**: creating a "trail" of user actions in log files

### Usernames and access cards

* usernames are not secret
* access card types
  * magnetic swipe cards (can be copied easily)
  * smart cards that need to be inserted into a reader
  * contactless smart cards work in proximity to a reader

### Biometrics

* are based on physical characteristics of a person
* properties
  * ideally small false acceptance rate
  * ideally small false rejection rate
  * should be not "creepy"
* types
  * retina scan
  * fingerprint
  * face recognition
  * voice print

## Authentication

### 3 factors

* something you **know**: a password or security question
* something you **have**: a token or smart card
* something **about** you: biometric attribute

### 4 Insecure attributes

* somewhere you are: location
* something you an do: typing pattern
* something you exhibit
* someone you know

### Errors in in authentication

* False acceptance rate (**FAR**)
* False rejection rate (**FRR**)
* both factors should be **looked at simultaneously** to measure how well a system works
* crossover error rate (**CER**) ("sweet spot"): both rates have the same value

### Multifactor authentication

* a single factor has drawbacks that be be used against it
* combining two (or more different factors)
  * makes security much stronger!
  * e.g. password + token
  * two of the same category doesn't make it multifactor

### Something you have

* 2 types of tokens
  * Hardware token
    * have to be carried around by each user
    * are expensive to hand out
  * Soft token/Software token
    * run as an app on a user's smart phone
    * cheap to roll out
* token generate codes known as "one time passwords"
* 2 protocols
  * HOTP
    * = HMAC-based on-time password
    * generated using a counter on device
    * code changes when button is pressed
    * code is valid until it is used
  * TOTP
    * = time-based one-time password
    * generated using current time
    * code is valid for a few seconds
    * devices with TOTP need to have the time in sync with the server
* other solutions
  * SMS: insecure, since phone numbers can be moved around
  * smart phone app using push notification (secure)
  * smart cards
* backup code in case access to device is no longer possible
  * dangerous, because it falls back to "something you know"

### Password authentication protocols

#### **PAP**: Password Authentication Protocol
  * both client & server know the password
  * client send username + password
  * server validates it
  * password is sent unencrypted!
  * this protocol should not be used, unless the transmission is encrypted by another system
#### **CHAP**: Challenge Handshake Protocol
  * secure alternative to PAP
  * both client & server know the password
  * instead of sending the password, server send a random value ("challenge") to client
  * client combines challenge with password and hashes the value
  * client sends hash to server
  * server computes the hash and compare is against the data from client
  * if identical: client is authenticated
  * can be used today
  * MS-CHAP and MS-CHAPv2 are no longer secure, though

### Single sign-on and federation

* both have the same goal: reduce number of identities that a user must have to access various systems

#### Federation

* federation identity management systems share identity information across different systems
* examples
  * Google Login
  * Facebook
  * Twitter

#### Single Sign-On (SSO)

* sessions are shared across systems
* process
  * the first SSO-enabled system starts login process
  * session persists until it expires
  * no further login needed, session is re-used by other system

#### Trust Relationships

* Direction
  * one-way: trust goes only in one direction
  * two-way: two system trust each other mutually
* Transitive/Intransitive
  * transitive
    * A => B
    * B => C
    * A => C
  * non-transitive
    * A => B
    * B => C
    * A does not trust C!

### RADIUS & TACACS

* both are AAA protocols

#### RADIUS

* is a client-server system
* process
  * end user sends connection requests to RADIUS CLIENT
  * RADIUS client sends access request to RADIUS server
  * RADIUS server send authentication request to external directory (e.g. LDAP or Active Directory)
* still used today
* uses UDP (which is connectionless)
* most data on RADIUS is unencrypted



#### TACAS

* alternative to RADIUS
* early versions (no longer in use today)
  * original TACAS uses UDP
  * xTACAS
* TACAS+
  * current standard 
  * uses TCP
  * fully encrypted
  * still in use

### Kerberos & LDAP

#### Kerberos

* provides
  * authentication
  * authorisation
  * available on
    * Linux
    * Windows
* is a ticket-based authentication system
* Port: 88

#### LDAP

* is a protocol for access control
* shares information about users and their authorisation in a standardised way
* can be used to query Microsoft Active Directory
* Port: 389 (unencrypted) or 636 (encrypted)

#### NTLM

* = NT LAN Manager
* was standard on Windows for authorisation (before Kerberos)
* disadvantages
  * weak encryption
  * vulnerable to "pass the hash" attack
* should not be used any more

### SAML

* = Security Assertion Markup Language
* used to implement SSO using Web browsers
* 3 actors
  * **principal**: end user
  * **identity provider**: organisation providing proof of identity
  * **service provider**: resource that the end user wants to use
* process
  * principal visits service provider
  * service provider redirects to SSO on identity provider
  * identity provider creates XHTML response specific for that service provider
  * principal uses that response to get a "security assertion" from service provider
  * service provider validates request and creates "security context" with the service and redirects user to service
  * principal requests resource
* advantages
  * one authenticated, session lasts and avoid re-authentication
  * service provider can use identity without having access to user's password

### OAuth & OpenID Connect

#### OAuth

* is an **authorisation** protocol!
* manages permission from one service to access another

#### OpenID Connect

* is an **authentication** protocol that uses OAuth
* it's the provider that helps users proof their identity to other services

### Certificate-based authentication

#### Certificates

* provide authentication for
  * SSH
  * smart cards
  * computers / network access (802.1x)
* provide a trusted copy of a public key to third parties
* process
  * user makes connection to server
  * server sends a random challenge message
  * user encrypts content with private key and sends it back
  * server decrypts message with public key
  * if decrypted message is identical with challenge plaintext: access granted
* this process can be automated (since no human needs to enter a password)
* for SSH: private keys must have strict permissions (600)
* CA can be used to have the public key signed (provided proof of identity)

## Authorisation

### Access Control Systems

#### Mandatory Access Controls (MAC)

  * enforced by the operating system
  * resources are labeled and only users with at least that level of permission have access
  * users can not adjust those authorisations
  * implemented by SELinux (kernel module)

#### Discretionary Access Controls (DAC)

  * allows users to setup/change permissions on resources themselves
* owner have discretion to grant access
* NTFS access control list is a DAC

#### Access Control List

* permission types
  * full access
  * read
  * read  + execute
  * write
  * modify: delete + read + execute

#### Advanced Concepts

* **Implicit deny**
  * everything that's not allowed is forbidden
  * example: firewall (if no matching rule is found, request is blocked)
* **role-based** access control
  * job-based roles are created and permissions attached
  * users can be assigned a role
  * _all_ users with a given role update automatically
* **attribute-based** access control (**ABAC**): 
  * access based on characteristics of a user
  * attributes can be used as conditions that must be all true
  * examples
    * *is manager of X*
    * *location*
    * *time of day*

#### Database access controls

* in MS SQL server, database users can be managed by
  * *SQL Server Authentication*: inside the DB server
  * *Windows Authentication* mode: use OS for user account
  * *Mixed Authentication*: uses both
* role-based authorisation
* account-based authorisation

## Account Management

### Account Types

* **user account**: used for every day (regular permissions and monitoring)
* **privileged account**
  * administrative rights (strong logging & controls)
  * should only be used for specific tasks
  * account elevation possible to "step up" to privileged access
* **guest account**
  * temporary access to resources
  * tied to individual
* **shared/generic account**
  * used by more than one person (= no accountability)
  * not recommended
* **service account**
  * used by a system
  * are privileged
  * should not be allowed to login interactively

### Account Policies

* Group Policy Object (GPO)
  * groups of configuration settings
  * can be applied to Domains/user groups
* Password Policy
  * length: 8+ characters
  * different types of characters
  * lock out policy after a number of login attempts
  * automated password-recovery system

### Managing Roles

* roles group permissions together
* a single users can have 1+ roles and will "inherit" the permissions
* if a group is changed, permissions to all users update
* if a user is removed from a role, they will lose permissions granted by the role
* roles replace the need for shared account

### Account Monitoring

* **Inaccurate Permissions**
  * causes
    * prevent users from doing work
    * violate least privilege
  * to prevent
    * perform account audits with managers
    * use external auditors to approve privileges of each user
* **Unauthorised Use**
  * causes
    * somebody else is using the account
    * account holder is using privileges for somebody else
  * to prevent
    * monitor account continuously 
    * alert when
      * location is strange (impossible travel time login)
      * unusual network location
      * unusual time-of-day logins
      * deviations from normal behaviour
      * high volumne of data transfer
* Tools to support monitoring
  * geotagging (tag login with location)
  * geofencing: only allowing access from one location

### Privileged Access Management

#### Password Vaulting

* secure, encrypted repository for storing passwords
* nobody knows the value of a password for a privileged account
* user will log into the vault and vault then will log in

#### Command Proxying

* account manager will get the command
* verify that the user is authorised
* perform the command  in the user's name

#### Monitoring

* logs every activity of a user in a privileged session

#### Credential Management

* password rotation or swapping access keys

#### Emergency Access Workflow

* account manager can by bypassed
* with special approval
* workflow should be logged

### Provisioning and Deprovisioning

* each account has a lifecycle
* when a new user joins, an account will be created
* when a user leaves
  * account should be disabled and authorisation must be revoked
  * this must happen quickly to prevent possible revenge
* two scenarios
  * *routine workflow:* disabling an account on a scheduled basis
  * *emergency workflow*: immediately suspending an account (when things to bad)
