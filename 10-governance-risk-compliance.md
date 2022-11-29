# Governance, Risk, and Compliance

## Risk Analysis

### Risk Assessment

#### Terms

* **threat**: external force trying to attack organisation (thread vector: method used to get to target)
* **vulnerability**: weaknesses in systems; should be found and fixed
* **risks** = vulnerability + threat

#### Ranking

* risk should be rated on **likelihood** + **impact** 
* likelihood: how often does this occur?
* impact: how much damage can happen?

#### Categories

* qualitative: subjective judgment (low, medium, high)
* quantitative: use metrics to rank

### Quantitative Risk Assessment

* **Asset Value (AV)**: what does the asset cost in $?
  * original cost
  * depreciated cost (cost as of today)
  * replacement cost: current cost to replace asset
* **Exposure Factor (EF)**: how much of the asset will be damaged (in %)?
* **Single-Loss Expectancy (SLE)**: actual damage over *one time* (=impact)
  SLE = AV × EV
* **Annualised Rate of Occurrence (ARO)**: number of times a risk is expected *per year*
* **Annualised Loss Expectancy (ALE)**: how much is this going to cost *per year* in $?
  ALE = ARO × SLE
* **Mean Time to Failure (MTTF)**: asset can not be fixed; *when* will it break?
* **Mean Time Between Failures (MTBF)**: how much time passed *between two failures*?
* **Mean Time to Repair (MTTR)**: how *long* is the asset out of service to be *repaired*?

### Risk types

* **internal**: humans inside the organisation doing bad things; can be mitigated by internal controls
* **external**: threat comes from outside the organisation; likelihood of attacks being successful can be reduced
* **multiparty**: if ISP is compromised, all customers are in danger
* **legacy risk**: old systems are often not supported with updates/patches
* **intellectual property**: theft of IP damages companies
* **software license compliance**: use monitoring software to scan for license issues

### Information classification

* based on **criticality** and **sensitivity** of information
* customer data has impact on customers, not only the organisation
  * PII
  * payment
  * health
* classification is used for
  * encryption
  * labelling (add markings)
  * disposal procedures
  * cloud usage

## Risk Management

### 4 Risk Treatment Options

* **avoidance**: changing business practices (e.g. choose a data centre outside a flood zone)
* **transference**: offloading impact of the risk (e.g. moving financial damage to other companies by buying insurance)
* **mitigation**: implementing controls to reduce likelihood or impact of risk
* **acceptance**: some risks can not be avoided without compromising business activities

#### Controls

* **Inherent risk**: initial risks that exists without any control
* overall risk is still reduced, but the remaining risks are divided into
  * *residual risk*
  * *control risk*
* **risk appetite** is the term to define how much risk an organisation is willing to accept
  `residual risk + control risk < risk appetite`

### Security Controls

#### 3 goals

* *reduce likelihood* of risk occurring
* *minimise impact*
* *detect* security *issues*

##### Defense in depth

* if more than one control is used for the same objective
* = overlapping controls

##### Categorising

* by **type/purpose**
* by **mechanism**
* overlapping possible

#### 6 Control types

* **preventive**: stop security issue from occurring (e.g. a firewall stopping traffic)
* **detective**: identify when an issue has occurred (intrusion detection system)
* **corrective**: restores/recovers issues that have occurred (e.g. restoring a backup)
* **deterrent**: prevent an attacker from even trying (e.g. guard dogs)
* **physical**: impact the physical world (e.g. fences)
* **compensating**: additional control to cover for an issue with another control

#### 3 mechanisms

* **technical**: use of *technology* (e.g. firewall, encryption, DLS, ...)
* **operational**: processes performed *by humans* (log monitoring, security training, ...)
* **managerial**: improve the security of the process itself (risk assessment, security consideration in change management)

### Ongoing risk management

* **risk control assessment**: point in time analysis
  * risks facing an org
  * controls to manage it
* **control assessments**: test functioning and effectiveness of controls

### Risk Management Frameworks

#### NIST SP 800-37
  * mandatory for government systems
  * adopted by private corporation, too
##### Process
1. **Categorise IT systems** using information from two categories
   * *architectural description* (reference models, business processes)
   * *organisational inputs* (laws, policies)
1. **Select** security controls
1. **Implement** security controls
1. **Assess** security controls
1. **Authorise** security controls
1. **Monitor** security controls (ongoing, if issues are detected, restart cycle)

### Control Frameworks

* **COBIT** (Control Objectives for IT)
* **ISO 27001**: Cybersecurity control objectives
* **ISO 27002**: Cybersecurity control implementations
* **ISO 27701**: Privacy controls
* **ISO 31000**: risk management
* **NIST 800-53**: mandatory for US federal agencies, organisations may adopt it
* **NIST Cybersecurity Framework (CSF)**: common language for cybersecurity risks

### Risk visibility and reporting

= results are documented and tracked over time

#### Risk Register / Risk Log

##### Contents

* description
* category
* probability and impact
* rating
* management actions

##### Sources

* risk assessment
* audits
* team member output
* threat intelligence

#### Threat Intelligence

* = sharing risk information
* can be purchased
* via sharing consortium

#### Risk Matrix / Heat Map

* x-axis: likelihood
* y-axis: impact
* steps: low/medium/high

### Data security roles

* **data controller / data owner**
  * determines the reason for processing
  * directs the methods of processing
  * has overall responsibility
  * is also responsible for privacy
* **data processor**
  * service provider that processes information on behalf of controller
  * is also responsible for privacy
* **data steward**
  * handles day-to-day governance activities
  * is delegated responsibility by owners
* **data custodian**
  * individuals who store and process information
  * often IT staff members
  * handles encryption, access controls, ...

**GDPR** requires a person to be a **data protection officer** (DPO).

## Supply Chain Risk

### Managing vendor relationships

* vendor **security policies** should be _at least_ as good as the organisation's
* Vendor Life Cycle
  1. Selection
  1. Onboarding
  1. Monitoring
  1. Offboarding

### Vendor Agreements

* **NDAs (nondisclosure agreements)**: keep information confidential
* **SLR: service-level requirements**
  * system response time
  * availability
  * data preservation
* **SLA: service-level agreement**
  * written contract
  * conditions & services
  * penalties to be paid
* **MOU: memorandum of understanding**
* **BPA: business partnership agreement**
* **ISA: Interconnection security agreement**
* **MSA: Master service agreement**
* **SOW: Statement of work**

### Vendor information management

* agreement should contain **data ownership**
* customer should **retain uninhibited** data ownership
* vendor should only perform activities **on behalf of the customer**
* vendor must **delete customer information** after the contract ended
* vendor should **not share data** with third parties without consent of the customer
* vendor should **take care of potential data loss**

### Audits and assessments

#### Audit

* requested by regulator / executive / board of directors
* follows a formal standard and planned test
* 2 types
  * **internal**: same organisation that is being audited
  * **external**: independent firms
* have a scope
* **gap analysis**: what is missing and needs to be done?

#### Assessment

* done by organisation's IT staff
* ensure that processes are working as they should
* example: user access reviews

### Cloud Audits

* the scope of an audit now includes the cloud provider's control
* cloud providers provide their own audit, known as **SOC: Service Organisation Control** Reports

#### SOC 1

* used for financial audits

#### SOC 2

* evaluate CIA controls
* not shared widely

#### SOC 3

* evaluate CIA controls
* only high-level information
* shared widely / **for public!**

##### SOC 1 and 2 types

* Type 1: describes the controls that are in place + auditor's opinion if they make sense
* Type 2: describe the controls + auditor verifies that they are working

## Security Policies

### Security Policy Framework

* a framework is made up of 4 documents
  1. policies
  1. standards
  1. guidelines
  1. procedures

### Security Policies

* foundation for security program
* developed over time
* compliance with policies is **mandatory**
* approval at highes level of org
* should be "up to date", so avoid very specific information

### Security Standards

* provide specific details on controls
* derive authority from policies
* **mandatory**

#### Benchmarks

* are often used "as is" or referenced or adopted
* e.g. **CIS**, or vendor-specific

### Guidelines

* provide advice
* follow best practices
* compliance is **optional**

### Procedures

* are step-by-step guides for an activity
* compliance is mandatory _or_ optional

### Data Security Policy

#### Data storage

  *   locations (e.g. no cloud!)
  * access controls for accessing data
  * encryption (e.g. based on location)

#### Data Transmission

  *   what data can be transmitted over which networks
  * encryption
  * transmission mechanism

#### Lifecycle

  * data disposal: how to wipe storage media?
  * data retention
    * minimum storage (e.g. related to tax laws)
    * maximum storage (e.g. payment information)

## Privacy and Compliance

### Legal and compliance risks

* what laws and regulations apply?
  * state the company resides in
  * data of the customer from another state
* regulations come from
  * national/state laws
  * industries (e.g. PCI DSS apply worldwide)
* work with an attorney

### Data privacy

* **PHI**: protected health information (data governed under *HIPAA*)
* **PII**: personal identifiable information

#### 10 GAPP principles
1. **Management**: have policies, procedures, and governance to protect privacy
1. **Notice**: data subject must be informed that their data is being collected
1. **Choice and Consent**: get consent for collection/use/storing of data
1. **Collection**: org must only collect information for purposes disclosed in privacy notice
1. **Use, Retention, and Disposal**: use data only for disclosed purpose and dispose if no longer needed
1. **Access**: data subjects should review and update personal information
1. **Disclosure to third parties**: only share if that's consistent with privacy notice and consent was granted
1. **Security**: keep data safe from unauthorised access
1. **Quality**: make sure that information is accurate, complete, and relevant
1. **Monitoring and Enforcement**: monitor compliance with privacy policy and provide dispute mechanism

### Data breaches

#### Consequences

* Reputational damage
* Identity theft
* Fines
* Intellectual property theft

#### Rules

* Industry specific
  * HIPAA
  * SOX
  * PCI DSS
* Jurisdictionan
  * GDPR
  * state-specific laws

#### Common PII elements (exposed in the breach)

* driver license number
* social security number
* bank account number
* (more possible)

#### Steps to take

* inform victims about incident
* notify government
* provide notice to general public

## Privacy Enhancing Technologies

### Data anonymisation

* **de-identifying** removes obvious identifiers
  * name
  * social security number
* **birthday problem**
  * with enough data points a person can be identified
  * e.g. ZIP code + day of birth + gender = 87 uniqueness
* better: use **anonymisation**!
  1. **ask experts** to analyse data set and verify it's possible to identify an individual
  1. **safe harbor approach**: *remove 18 data elements*

### Data obfuscation

* = transform data where it's impossible to retrieve the original data
* tools
  * **hashing**: apply a one-way-function to get the hashed value
  * **tokenization**: replace sensitive values with a random identifier (needs a lookup table)
  * **masking**: redact sensitive information from file / data set

### Security Awareness and Training

#### Security Education

* Why? A single user can bypass security controls
* training should be customised based on roles
* **Training**
  * prove detailed information
  * educate users
* **Awareness**
  * remind users about what they have learned
  * keep security on mind
* **Types**
  * on-site classes
  * integration with existing practices (e.g. onboarding)
  * online learning
  * vendor-provided classroom training

#### User habits

* goal: replace risky habits with good security practices
* **password security**: no re-use, strong passwords
* **clean desk policy**: store, transmit and destroy sensitive information
* **reminder of NDA**
* **physical security controls**: no tailgating, always use badge
* **BYOD policy**: acceptable use policy + security requirements
* **social media + peer-to-peer networks**

#### Separation of duties

* reduce risk that a single user can perform a harmful action
* permissions should be held by two different humans
* example for **separation of responsibilities** 
  * one accountant can create a new vendor
  * another accountant can authorise payments to vendors
* two-person control / dual control
  * two humans must authorise a single action
  * example: launching a nuclear missile or a check needs to be signed by two accountants

