1. IAM users, groups, roles, and policies
    - In an account we have users, groups, roles, and policies
    - we have a group and can assign users to groups and can assign permissions to user (policies)
    - Policies define the permissions for the identities or resources they are associated with.
    - Identity-based policies can be applied to users, groups, and roles
    - Users gain permissions applied to the group through a policy
    - Roles are used for delegation and are assumed.
    - Groups:
        - Groups are a collection of users
        - Users can be members of up to 10 groups.
        - Reason to use groups is to apply permissions to users using policies.
    - Roles:
        - IAM role is an IAM identity that has specific permissions
        - Roles are assumed by users, applications, and services.
        - Once assumed, the identity "becomes" the role and gain the roles permissions.
        - Use cases:
            - Cross account access:  User in one account needs to access resource in another account.
                - User A in account A needs to access a resource in account B.  User A must have an identity based policy in account A, there will be an sts:AssumeRole that allows this user to access a *role* in account B.  That role wil will have a *trust policy* (allows user from account A to assume role) and a *permissions policy* (this is also attached to the role and allows access to the actual resource).
            - *External* cross account access
                - All things above, but also must attach the external account number to the principle of the *trust policy*.
            - Delegation of aws services:
                - Ec2 with an *instance profile*.  The instance profile has a *trust policy* and a *permissions policy*.  
                - *Trust policies* determine who can assume the role.

    - Policies:
        - Policies are documents that define permissions and are written in json.
        - All permissions are implicitly DENIED by default.  (You must explicitly allow something)
    - Two types of policies
        - Identity-based policies can be applied to users, groups, and roles.
        - Resource-based policies apply to resources such as s3 buckets or DynamoDB tables.
    - Root user
        - the account with full permissions
    - Regular users
        - up to 5000 individual users can be created
        - They have no permissions by default

2. STS security token service
    - Two pieces to an IAM role:
        - Trust policy:
            - Controls who can assume a specific role.
            - Trust policy should have the following:
                Effect: Allow/Deny
                Principal
                    service: ec2.amazon.com, s3.amazon.com, ebs.amazon.com ect
                Action: "sts:AssumeRole" <-- Here is where STS is called out.
        - Permissions policy
    - Temporary credentials are used with identity federation, delegation, cross-account access and IAM roles

3. IAM Access Control
    - Identity based policies
        - controls actions an identity can perform on resources and under what conditions.
        - Can be attached to a user, group, or role
        - Types
            - aws managed: created and managed by AWS
            - customer managed: customer managed by customers
        - Can be attached to multiple types at once, identity policies could be attached to user, group, and role all at the same time.
    - Resource based policies
        - You can tell a RESOURCE based policy if it has a PRINCIPLE attached to it.
            - Could be a * meaning any user or role ect.  Or you could put a specific user or role in there.
        - Attached to resources such as S3 bucket.
        - Resource based policies grant the specified PRINCIPLE(role, user), the PERMISSION, to perform specific ACTION on RESOURCE.
        - What is meant by video 19, 3:47 related to IAM role with a trust policy and permissions policy.
    - IAM permissions boundaries
        - Sets the maximum permissions an identity based policy can grant to an IAM entity.
    - SCP
        - Specify the max permissions for an OU
    - Session policies 
        - Used with assumeRole* API actions

4. RBAC
    - Role based access control
    - May have groups where we place users of similar types together and place permissions policies to the group.

5. ABAC
    - Attribute based access control
    - Tags could be used for this behavior.  Based on tags you get X permissions.
        - A conditional statement would need to be used that checks for the tags in question.

6. Permissions boundaries
    - Can be applied to USERS and ROLES
    - Adds a layer to your already granted permissions.  If you have access to a dynamodb based on a resource policy, you'd need your permissions boundary to also allow you access to dynamo.  If it wasn't included on the perm boundary you couldn't access it.  It looks like two layers of permissions.  You still need actual permissions to an object, but you also need it added to the boundary as well just stating you can do some specific action.

7. Evaluation Logic

    ![eval logic](images/policyeval.png)

8. Determination rules
    - By default all requests are IMPLICITLY denied.
    - Explicit allow in an identity based or resource based policy OVERRIDES the default mentioned above.
    - Permissions boundary, SCP, or session policy could override the allow actions with an implicitly deny.
    - EXPLICIT denies in ANY policy overrides ANY allow.
    
9. IAM policy structure
    - effect: allow or deny
    - action: element with the specific api action which you are allowing or denying
    - resource: ARN of the resource you want to take action against.
    - condition: (optional) when should this policy have action taken against it.

10. IAM best practices
    - Secure or delete ROOT user access keys.
    - Create individual IAM users.
    - Use groups to assign permission to IAM users.
    - Grant least privilege.
    - Get started using permissions with AWS managed policies.
    - Use customer managed policies instead of INLINE policies.
    - Enable MFA.
    - Use roles for applications that run on EC2 instances.
    - Use roles to delegate permissions.
    - Rotate creds regularly.
    - Remove unnecessary creds.
    - Use policies condition for extra security
    - Monitor activity in your account.

Organizations and Control Tower

1. Organizations
    - Consolidates multiple AWS accounts into organizations so you can create and centrally manage them.
    - Two features
        - Consolidated billing within the "management account".
        - All features - SCP's and tag policies.
    - Consolidated billing
        - Paying account: Independent and unable to access resources of other account.
        - Linked account: all linked accounts are independent.
2. Control tower
    - Sits on top of Organizations.
    - Creates a "landing zone" whish is a well architected multi-account baseline.
    - Guardrails, used for governance and compliance.
        - Preventative guardrails are based on SCPs and disallow API actions.
        - Detective guardrails implemented using Config and Lambda functions and monitor compliance.
        - Root user in the *management* account can perform actions that guardrails would normally disallow.

Infrastructure Security

1. VPC
    - Use multiple HA for high availability.
    - Control traffic with security groups and network acl's.
    - Use IAM policies to control access to resources.
    - Use cloudWatch to monitor VPC components.
    - Use flow logs to capture network traffic.
    - Separate your infrastructure with VPC's.
    - Further isolate tiers of an application through subnets.
    - Use privatelink to keep traffic private.
    - Use private subnets if instances should not be accessed directly from the internet.
    - Use egress-only internet gateway for ipv6 outbound connections (Does not accept incoming connection attempts).
2. Stateful and stateless firewalls
    - Stateful firewalls allow return traffic.
    - Stateless firewalls will checks both directions of traffic, neither traffic flow is tracked.
3. Network ACL/Security groups
    - Security groups
        - Applied to the ENI of a resources.
        - Only have allow rules (does not have deny rules except for the implicit deny.)
        - Has both inbound and outbound rules.
    - NACL
        - Stateless
        - Processed in order of rules.
4. VPC Peering
    - Keeps traffic private between internal VPC resources.
    - Must not have overlapping CIDR blocks.
    - Does not support transitive peering.  Every VPC that wants to talk must be peered.
5. VPC endpoints
    - Allows users to connect to 'public' resources, privately.
    - Creates an ENI in the subnet where your resources are located and need connectivity from.
    - Need to add security group to add more granular security.
6. VPC gateway endpoints
    - No ENI created, route table entry created.
    - Populated with a prefix list of the IP's of the public resources.
    - Only works with s3 and dynamodb.
    - Can add VPC endpoint policies to add more secure connectivity.
7. VPC Flow logs
    - Traffic capture of traffic going to or from your network resources.
    - Stored in CloudWatch logs or S3.
    - Can be captured from VPC, Subnet, or Network Interface.
    - Access Keys and IAM roles
        - Access keys
            - Associated with an IAM account.
            - AK use permissions assigned to the IAM user.
            - AK are stored on the file system of the EC2.
        - Instance profile
            - Connects an IAM role to the Ec2.
            - Role can be assumed by the Ec2.
            - Gains permissions based on the policy assigned to the role.
            - No creds stored on the Ec2.
8. Amazon Inspector
    - Runs assessments that check for security.
    - Can run on schedule.
    - Agent based application runs on Ec2 host.
    - Network assessment doesn't require agent.
    - Network assessment
        - Checks what ports are open outside the VPC.
        - If agent installed, can find processes reachable on ports.
        - Pricing model based on number of *assessments* completed.
    - Host assessments
        - CVE harding best practices.
        - requires the agent.
        - Pricing model based on number of *assessments* completed.
9. Systems manager session manager
    - Remote management of instances without logging into servers
    - removes need for ssh
    - granular permissions with IAM
    - can store session logs in S3 and output in cloudwatch logs
    - require IAM permissions for EC2 to access SSM, S3, Cloudwatch logs.
10. OpenSearch
    - Cluster can be deployed intra-VPC or publicly accessible.
    - Cannot switch from private to public endpoint or vice versa.
    - Cannot launch on VPC using dedicated tenancy.
    - Cannot move between VPC's but you can change the subnet and security group settings.
    - Ingesting data:
        - Kinesis data firehose.
        - Logstash
        - Elasticsearch/open search API
11. Redshift
    - Fully managed data warehouse.
    - Uses SQL and BI tools.
    - Online analytics processing (OLAP).
    - Must create cluster subnet group and provide VPC ID and list of subnets in your VPC.
    - For public cluster, specify an *elastic* IP to use.
    - Must enable *DNS resolution* and *DNS hostnames* to connect to public cluster using private IP.
    - Use security groups to control access to database ports.
12. Config
    - Evaluates configurations against desired settings.
    - Get snapshot of current configs associated with AWS account.
    - Retrieve configs of resources that exist in account.
    - Retrieve historical configs.
    - Receive notifications when resources are created, modified, deleted.
    - View relationships between resources.

Edge security
1. DNS and DNS routing

2. CloudFront
    - Signed URL
        - Provides more control over access to content.
        - Can be used to specify beginning/end date and time, IP addresses, and range of users.
        - 1 signed URL per file.
            - If more than one file needs distribution you may want to use signed cookies to avoid overhead.
    - Signed cookies
        - Use them when you don't want to change URLs
        - Use when you want to provide access to multiple restricted files.
    - OAI
        - Special type of "user".
        - Generated by the cloudfront distribution.
        - Update the "principle" to be the OAI.
    - ALB
        - Ways to secure ALB from cloud front...
            - SSL from client to CF distribution > SSL from CF distribution to ALB.
            - CF could also generate a custom header on clients behest.  If customer header is missing connection from ALB is rejected.
    - Additional security features
        - WAF ACL could be attached to CloudFront distribution.
        - Field level encryption can protect sensitive data through the entire app stack.
        - Geo restriction.
    - SSL/TLS
        - Can issue SSL certification through ACM certificate manager
        - Must be issued through us-east-1, however.
        - CloudFront is a global service.
        - certificate could also be issued from third party.
        - default CloudFront domain name can be changed using CNAMES
        - S3 has its own certificate
        - Origin certificates must be public certificates.
    - SNI (Server Name Indication)
        - Method allows you to have multiple SSL/TLS certificates which correspond to different domain names attached to the same IP address on cloudfront.
        - Normally you would need a unique IP for each domain/certificate.

3. Lambda@Edge
    - node.js or python functions to customize the the content cloudfront delivers.
    - executes functions closer to the viewer.
    - **Exam type questions**
        - Can run these functions during the following lifecycle events of a request.
            - After CF receives a request from viewer (viewer request)
            - Before CF forwards to origin (origin request)
            - After CF receives the response from the origin(origin response)
            - Before CF forwards the response to the viewer (viewer response)
4. WAF
    - Lets you create rules to filter web traffic using rules like IP addresses, headers, body, and custom URI's.
    - **Exam type question**
        - You can create rules to block common web exploits like *SQL injection*, and *cross site scripting*.
    - You can put WAF in front of...
        - CloudFront
        - ALB
        - API Gateway
        - AWS AppSync
    - Technical details about WAF
        - Rules: contains a statement that defines the inspection criteria and the action to take if successful match.
        - Rule groups: TODO
        - Rule action: 
            - Count: counts the request but doesn't block or allow.  Just continues processing remaining rules.
            - Allow: allows request
            - Block: Blocks the request with a 403.
        - IP Sets: A collection of IP addresses that you can use as part of a rule statement.
        - Regex pattern sets: A collection of regex that you can use in a rule statement.
        - Match: statements compare web request or origin against conditions you provide.
5. AWS Shield
    - Protects against DDOS attacks.
    - Protects web applications, always running, does in line mitigation.
    - Minimizes down time and latency.
    - Two tiers: Standard and Advanced.
    - Integrated into CloudFront.
6. AWS Network Firewall
    - Technical details
        - Stateful and stateless
        - Intrusion Prevention System
        - Web filtering
    - Works with Firewall Manager for centrally applying policies across accounts/VPCs
    - Under the hood, uses VPC endpoint and a Gateway Load Balancer.
    - Must deploy in a dedicated firewall subnet so proper routing can be applied.
    - Allocate a subnet per AZ.
7. AWS Route 53 Resolver DNS Firewall
    - Filter and regulate outbound DNS traffic for VPCs.
    - Helps prevent DNS infiltration of data.
    - Monitor and control domains that can be queried.
    - Use Firewall manager to configure and manage DNS firewalls.
    - Management can span VPC's and accounts in AWS Organizations.
    
Data and Application Protection

1. Encryption at rest/in transit
    - In transit - data moving through the network.  
        - VPN's, SSL, TLS ect.
    - At rest - When stored on a file system somewhere.
        - Encrypted volumes, encrypted S3 buckets, databases with encryption.
    - Asymmetric Encryption
        - AKA public key cryptography.
        - Message encrypted with public key and then decrypted by a private key.
        - Messages encrypted with private key can be decrypted with public key.
    - Symmetric Encryption
        - No public or private keys.
        - One key on both ends that encrypts and decrypts the data.
2. ACM (AWS Certificate Manager)
    - Used for encryption *IN TRANSIT*, NOT encryption at rest.
    - Create, store, renew SSL/TLS X.509 certificates.
    - Supports single domain, multiple domains names and wildcards.
    - Integrations:
        - ELB, CloudFront, ELastic Beanstalk, Nitro Enclave, CloudFormation
    - Public certificates are signed by AWS public certificate authority.
    - Can create private CA with ACM.
    - Can issue private certificates.
    - Can import from third party issues.

3. Key manage service (KMS)
    - Used for encryption *AT REST*, not in transit.
    - Create symmetric and asymmetric encryption keys.
    - KMS keys protected by hardware security modules (HSM)
    - There are customer created keys and AWS created keys or AWS managed keys if you prefer.
    - KMS keys are the primary resource in AWS KMS.
    - *Previously known as customer master keys or CMKs*
    - KMS key contains the key material used to encrypt and decrypt data.
    - By default - KMS creates the key material for KMS key.
    - You COULD import your own key material if you prefer.
    - KMS can encrypt data up to 4kb in size.
    - Can generate, encrypt and decrypt Data Encryption Keys (DEKs)
        - Used for encrypting LARGE volumes of data.
    - Key stores:
        - External
            - Can be stored outside AWS.
            - Can create key in KMS external key store (XKS)
            - Keys are stored and generated in external key manager.
            - XKS, key material never leaves your HSM.
        - Custom
            - Can create keys in CloudHSM customer key store.
            - Keys generated and stored in CLoudHSM cluster you own and manage.
            - Cryptographic operations performed solely in CloudHSM cluster owned and managed by you.
            - *Not applicable for asymmetric KMS keys*
    - AWS managed keys
        - Created and managed by AWS, integrated with KMS.
        - User cannot manage these keys at all.
        - Cannot use them in cryptographic operations directly.  The AWS service uses them on users behalf.
    - Data encryption keys
        - Encrypts large amounts of data.
        - Can use keys to generate, encrypt and decrypt data keys.
        - KMS does not store, manage or track your data keys.
        - User must use and manage data keys outside of KMS.
    - Rotation of keys
        - Key type:
            - Customer managed key: Can view: yes, can manage: yes, automatic rotation: Optional every 365 days.
            - AWS managed key: can view: yes, can manage: no, automatic rotation: Required every 365 days.
            - AWS owned key: can view: no, can manage: no, automatic rotation: Varies
        - Rotation:
            - Properties of the key do not change when rotation occurs.
            - Don't need to change application or aliases that refer to the key ID or ARN of the key.
            - If enabled AWS rotates yearly.
            - Not supported for the following KMS keys:
                - Asymmetric KMS keys
                - HMAC keys
                - custom key stores
                - imported key material
            - Manual rotation:
                - manual rotation includes creating a new key with different key id
                - must update applications with new key id
                - can use alias to represent key so you don't need to modify application code.
    - *Exam type questions*
        - Sharing snapshots with another account requires you add *decrypt* and *CreateGrant* permissions.
        - ksm:ViaService condition can be used to limit key usage to specific AWS services.
        - cryptographic erasure means removing the ability to decrypt data.
        - must "DeleteImportedKeyMaterial" API to remove key material.
        - InvalidKeyId when using SSM parameter store indicates KMS key not enabled.
        - Know difference between AWS managed and customer managed KMS keys and automatic vs manual rotation.
4. Cloud HSM
    - Stands for Cloud Hardware Security Module
    - Generate and use your own encryption keys.
    - Runs in your own VPC.
    - FIPS 140-2 level 3 validated HSM.
    - AWS managed service.
    - Retain control of your encryption keys.  AWS has no visibility of your encryption keys.
    - Use cases:
        - Offload SSL/TLS processing from web servers.
        - Protect private keys for certificate authority.
        - Store master key for transparent data encryption.
        - Custom key store for KMS

5. Securing data on volume stores (EBS, S3, EFS)
    - S3
        - Server side encryption with S3 managed keys (SSE-S3)
            - Encryption and decryption takes place ON S3 itself.
            - How
                - S3 managed keys
                - Unique object keys
                - Master key
                - AES 256
        - Server side encryption with AWS KMS managed keys (SSE-KMS)
            - Encryption and decryption happens on the S3 side.
                - How
                    - KMS managed keys
                    - KMS key can be customer generated
        - Server-side encryption, client provided keys (SSE-C)
            - Encryption and decryption happens on the S3 side.
            - How
                - Client managed keys
                - Not stored on AWS
        - Client-side encryption
            - Encryption happens on the client side, not the server side.
            - How
                - Client managed keys
                - NOt stored on AWS.
                - Could use a KMS key
        - S3 Default encryption
            - Set default encryption so all new objects are encrypted when stored in the bucket.
            - Encrypted using server-side encryption.
            - Encrypts objects before saving to disk and decrypts upon download.
            - No change to encryption of objects that existed in bucket before encryption was enabled.
        - S3 Glacier Vault Lock
            - Vault lock enforces compliance controls for S3 glacier vaults with a lock policy.
            - Can specify things like a WORM policy.
            - Locks cannot be changed once set.
        - S3 Glacier Vault Access Policy
            - Resource based policy that can be used to manage permissions to the vault itself.
            - Create one vault access policy for each vault to manage permissions.
    - EBS
        - Encryption will affect the following:
            - Data is encrypted at rest and in transit.
            - Snapshots of encrypted volumes are also encrypted.
            - Traffic between AZ's is encrypted.
        - AMIs and Snapshots
            - If creating a snap shot of a volume: Encryption state (encrypted or unencrypted) is retained and stays in the region.
            - If attempting to encrypt an unencrypted snapshot: you can convert an unencrypted to encrypted and can change regions.
            - If attempting to convert unencrypted snapshot to encrypted volume: can be encrypted and can change AZ.
            - If attempting to create an encrypted snapshot and convert to encrypted AMI: can be shared with other accounts (with a custom KMS key only), key must have *Decrypt* and *CreateGrant* permissions.  But AMI cannot be shared publicly.
            - If attempting to copy one encrypted ami to another encrypted ami: can be done, you can change the encryption key and you can change regions.
    - EFS
        - Files systems are mounted using the *NFS* protocol.
        - Many instances can mount a file system within and across VPCs.
        - Can mount file systems from on-premises servers over DirectConnect (DX) or VPN.
        - Only works with Linux instances.
        - *Encryption at rest can ONLY be enabled when the file system is created.*
        - *Encryption in transit is enabled when mounting the file system.*
6. DynamoDB and RDS
    - DynamoDB
        - Data encrypted at rest.
        - Supports AWS owned KMS, AWS managed KMS, Customer managed KMS.
        - Supports *identity-based* policies.
    - RDS security
        - RDS runs on instances within a VPC.
        - Encryption at rest can be enabled if desired.
        - Can ONLY enable encryption once RDS DB instances has been created.
        - DB instances cannot be modified to disable encryption if encryption has been enabled.
        - AES 256
        - Oracle and SQL support TDS (Transparent Data Encryption)
        - KMS used for managing encryption keys.
        - Read replica
            - Can't mix and match unencrypted DB instances, if main DB is encrypted read replica must be encrypted.  If main is unencrypted read replica must be unencrypted.
            - Same KMS key is used if its in the same region as primary.
            - If read replica in different region, different KMS key used.
            - Cannot restored unencrypted backup or snapshot to encrypted instance.
        - How could you migrate an RDS instance from unencrypted to encrypted...
            - RDS unencrypted > Create unencrypted snapshot of EBS volume > Copy the snapshot but change the status to encrypted > restore the snapshot to a new RDS instance with encrypted snapshot copy.
7. SSM Parameter store
    - Storage for configuration data and secrets.
    - Highly scalable, available, and durable.
    - Store values as plaintext or encrypted data.
    - Reference values by using the unique name (Key, Value)
    - No native rotation of keys (unlike AWS secrets manager)

8. Secrets manager
    - Offers automatic rotation of creds.
    - Supports the following technologies
        - RDS: MySQL, PostgreSQL, Aurora
        - Redshift
        - DocumentDB

9. AWS Signer
    - Used to ensure trust and integrity of code.
    - Code validated against digital signature.
    - Only trusted code will run in lambda functions.
    - Creates digitally signed package for deployment.
    - *IAM policies can enforce that functions can be created only if code signing enabled.*
    - *If developer leaves org, revoke all versions of the signing profile so code cannot run.*

Logging, monitoring, auditing

1. CloudWatch/EventBridge/CloudTrail
    - Cloudwatch Metrics
        - Time ordered data points sent to cloudwatch
        - Ec2 sends metrics every 5 minutes by default (this is free monitoring)
        - Detailed monitoring can send every 1 minute (costs additional charges)
        - Install *unified agent* to get system level metrics from Ec2 and on-prem servers.
            - System metrics including things like: *memory* and *disk usage*
    - Cloudwatch Alarms
        - Monitoring of metrics and initiate actions.
        - Alarm types:
            - Metric alarm:
                - Perform an action based on metric.
            - Composite alarm:
                - Use rule expression and takes into account multiple alarms.
        - Alarm state
            - OK: within threshold
            - ALARM: out of threshold
            - INSUFFICIENT_DATA: not enough data
    - Cloudwatch Logs
        - Centralized system and application logs.
    - CloudWatch Eventbridge (legacy 'Events')
        - Stream of system events describing changes changes to AWS resources
        - Cannot trigger actions from here.
        - Flow:
            - Event occurs from a resource > sends event to "EventBridge" event bus > Rules get evaluated > Data sent to a service to be processed.
    - CloudTrail
        - Logs API activity for auditing
        - *By default, management events are logged and retained for 90 days*
        - *Logs sent to S3 have indefinite retention*
            - Log files sent to S3 can use *integrity validation*, which checks if logs have been tampered with.
        - Can be within a region or all regions.
        - Cloudwatch events can be triggered based on API calls in CloudTrail.
        - Events can be streamed to cloudwatch logs.
        - Event types:
            - Management events
                - Management operations performed on resources.
            - Data events
                - Resource operations performed on or in resource.
            - Insights events
                - Identify and respond to unusual activity associated with "write" operations.
2. Directory services
    - AWS managed microsoft AD.
        - HA pair of windows server 2012 domain controllers (DC)
        - Alternatively you can use on-prem AD instances.
        - Can create one or two way trust relationship between AWS managed AD and on-prem AD if desired.
    - ADSync
        - Active Directory synchronization, is used to synchronize user accounts and identity information between on-premises Active Directory and cloud-based identity platforms like Azure Active Directory (Azure AD). It ensures consistent and up-to-date user identities across both environments, enabling single sign-on, centralized identity management, seamless integration, and hybrid identity scenarios.
    - ADFS
        - Active Directory Federation Services is a Microsoft service that enables Single Sign-On (SSO) and federation between organizations. It allows users to access multiple applications and services using a single set of credentials. Integrates with Active Directory, and supports the SAML protocol for secure communication. It provides web-based SSO, supports customizations, and facilitates secure identity exchange between organizations.
    - AD Connector
        - Connect on-prem AD with AD Connector service.
    - Identity Federation
        - Identity providers
            - User accounts
        - Service providers
        - AWS Single sign-on
            - More of an enterprise solution.
            - Central management for federated access.
            - Attach multiple AWS accounts and business applications
            - Identities can be in AWS SSO.
            - Works with many IdPs
            - Permissions assigned base on group membership in IdP
        - Cognito
            - Federated support for web and mobile apps
            - Sign in and sign up
            - Sign in with social IdP's
            - Supports SAML 2.0
            - User pools
                - A directory for managing sign-in and sign-up for mobile applications.
            - Identity pool
                - Identity can come from Cognito user pool or identity provider.
                - Identity pools are used to obtain temporary, limited privilege creds for services.
                - Identity pools use STS to obtain the creds.
                - IAM role assumed providing access to the service.
            - Cognito in action:
                1. Client talks with cognito user pool
                2. Cognito responds with JWT
                3. JWT passed to API gateway.
                4. API gateway then passes to lambda function
            - Important differentiator
                - User pools contains the identity, the identity pool are how you get the credentials to access AWS resources.
            
        - IAM
            - Can use separate SAML 2.0
            - Enables access control using federated user attributes
            - Identity federation in action:
                1. Client initiates communication with IdP
                2. IdP brokers communication to Identity store (LDAP)
                3. IdP returns SAML assertion to client.
                4. Client calls application with the 'sts:AssumeRoleWithSAML'
                5. AWS returns temp creds (as you would expect with sts).
                6. You can then access the resource in AWS.
        - SSO
            - Can be an identity store, alternatively you can use AD, or providers using SAML protocol.
            - you can create accounts within SSO

Incident response and data analysis

1. Security management and support
    - Security hub
        - View of security alerts and security posture *across accounts*
        - Aggregates and prioritizes security alerts from those accounts.
        - Continuously monitors environment.
        - Validates environments against:
            - AWS foundational security best practices
            - CIS AWS Foundations benchmark
            - PCI DSS
    - Security bulletins
        - Publishes security and privacy events affecting services.
    - Trust and safety team
        - POC if resources are being abused.
2. Pen testing
    - Resources you can test against:
        - Ec2
        - Nat gateway
        - ELB (Elastic load balancer)
        - RDS
        - CloudFront
        - Aurora
        - API gateway
        - Lambda/lambda@edge
        - Lightsail
        - Elastic beanstalk
    Not allowed:
        - DNS zone walking
        - DOS, DDOS, Simulated DOS, Simulated DDoS port flooding
        - Protocol flooding
        - Request flooding
3. Incident response plans
    - Based on the Cloud adoption framework
        - Four areas of focus:
            - Educate
            - Prepare (People)
            - Prepare (Technology)
            - Simulate
            - Iterate
4. AWS artifact
    - Gives access to AWS security and compliance reports and online agreements.
        - Service Organization Control reports
        - Payment card industry reports
5. Detecting and respond
    - Amazon Detective
        - Analyze and investigate root cause of security issues.
        - Pulls data from AWS resources.
        - Uses ML
        - Data sources can include Flow logs, CloudTrail, and GuardDuty
    - GuardDuty
        - Intelligent threat detection.
        - Detects account, instance and bucket compromise, along with reconnaissance .
        - Continuous monitoring for:
            - CloudTrail management events
            - CloudTrail s3 data events.
            - Flow logs
            - DNS logs
    - Macie
        - Machine learning and pattern matching for sensitive data in S3.
        - Can identify the following
            - PII
            - PHI
            - Regulatory Documents
            - API keys
            - secret keys
6. Athena
    - Optimize for performance
        - Partition your data.
        - Bucket your data in a single partition.
        - Use compression.
        - Optimize file sizes.
        - Optimize columnar data store generation.
        - Optimize ORDER BY and GROUP BY
        - Use approximate functions
        - Only include columns you need.
7. Glue
    - Fully managed ETL service.
    - Prepares data for analytics.
    - Discovers data and associated metadata.
    - Works with data lakes, warehouses and stores.








