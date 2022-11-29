# Secure Code Design and Implementation

## Software Development Lifecycle

### Software platforms

* endpoint device: standalone, self-contained application
* client/server application: client native application & server
* Web applications: browser & server
* mobile endpoints: can be endpoint apps or client/server
* embedded devices

### Software developing methodologies

* developers translate requirements into design
* 3 methodology
  * **waterfall**: linear process, can only backtrack one step
  * **spiral model**: 4 phases that are iteratively started
    1. gather requirements
    2. risk assessment
    3. development & testing
    4.  planning for future development
  * **scrum**: many small iterations with incremental development
    * 4 values that guide the process
    * early & continuous delivery
    * working software from the start
    * business & tech working together
    * self-organising teams

### Maturity models

* Capability Maturity Model Integrated (CMMI) with 5 levels
  1. **Inital**: getting started with formal development (delayed, over budget)
  2. **Managed**: some basic processes (e.g. re-using code, configuration measurement, project monitoring/planning, requirements management)
  3. **Defined**: formal, documented practices, project management
  4. **Quantitatively Managed**: measures are used to evaluate progress
  5. **Optimising**: continuous improvement
* **IDEAL** Model is focussed on the process to improve the organisation
  1. Initiating
  2. Diagnosing
  3. Establishing
  4. Action
  5. Learning

### Change management

* when software is in production, work is not done
* bugfixes or new features are added to existing software
* 3 elements of control
  * **Request control**: how are requests for changes managed? Priorisation & Evaluation
  * **Change control**: RFC document is submitted for review to the advisory board. Helping to understand why the change is needed and impact.
  * **Release control**: development and QA according to the requirements/RFC. Release manager puts code into production.
* Code environments
  * dev
  * test
  * staging
  * prod

### DevOps (Development Operations)

* is trying to resolve the conflict between devs and operations: one side is constantly adding changes while the other is working on keeping the system stable
* goal: collaboration
* embrace automation
* rapide release of code in a stable environment

#### Infrastructure as code

* resources and configurations are code that's under code control
* server configuration is decoupled from actual hardware
* advantages
  * scalability
  * less user error: servers are never changed, code is changed
  * easier testing

#### Security Automation: DevSecOps

* = using DevOps techniques for cyber security

#### DevOps Tools

* continuous validation
* c. integration
* c. delivery
* c. deployment
* c. monitoring

## Software QA

### Code Review

* dev examines the code written by another dev
* Fagan inspection: formal process
  1. Planning: materials, participants, scheduling
  2. Overview: roles are giving and introduction into code base
  3. Preparation: notes and quick overview
  4. Meeting: devs raise issues they discovered earlier
  5. Rework: devs who wrote it make changes (return to step 1 if needed)
  6. Follow-up: review leader confirms that all defects were corrected

### Software Testing

* **Software model validation**: building the _right_ software?
* **Software verification**: are we building the software _right_?

* **stress testing/load testing**: simulating real-world load
* **User Acceptance Testing (UAT)**: end users will verify that the software works as expected
* **Regression Testing**: making sure that no side effects (bugs) are introduced

### Code Security Testing

* **static testing**: tools look at code without running it
* **dynamic testing**: code is executed and analysed
* **synthetic transactions**: scripting to enter input and compare this against expected output

### Fuzz Testing

* = messing with the input to cause crashes or get access
* developer-supplied input
* developer-supplied script
* generation fuzzing: random input or based on spec
* mutation fuzzing: taking "real" inputs and modifying them

### Code Repositories

* store code securely
* provide version control
* coordinate changes from multiple developers
* automated auditing and logging changes
* it's possible to accidentally expose secrets (e.g. keys) to code repositories

### Application Management

* white list: only allow installing/running apps that are in the list
* black list: block some apps from running/installing
* AppLocker: Windows tool for allowing/denying execution of apps
* Application Control logs should feed into _Security Information Event Management_ system
* Host Software Baselining: making sure that only the expected apps run on a machine

### Third-party code

* libraries: shared code that perform related function
* external libraries can contain vulnerabilities and should have the same level of testing as in-house
* shared code create share vulnerabilities
* API
* SDK

## Application Attacks

OWASP (Open Web Application Security Project) contains list of top 10 security issues

1. Injection Flaws: e.g. SQL injection
2. Broken authentication: e.g. session hijacking
3. Sensitive data exposure: files are made public or not encrypted in transit
4. XML External Entities (XXE)
5. Broken access control: backend code does not check if current user has access to requested resource
6. Security Misconfiguration
7. Cross site scripting (XSS): execute any code by passing malicious payload to website
8. Insecure Deserialisation: remote code execution due to bugs
9. Using Components with known vulnerabilities: exploit using known bugs
10. Insufficient logging & monitoring: lack of logging to determine attacks