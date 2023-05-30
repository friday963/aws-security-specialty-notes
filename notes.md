1. IAM users, groups, roles, and policies
    - In an account we have users, groups, roles, and policies
    - we have a group and can assign users to groups and can assign permissions to user (policies)
    - Policies define the permissions for the identities or resources they are associated with.
    - Identitiy-based policies can be applied to users, groups, and roles
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
        - All permissions are implicityly DENIED by default.  (You must explicitly allow something)
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
        - Resource based policies grant the specified PRINCIPLE(role, user), the PERMISSION, to perform specifix ACTION on RESOURCE.
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
    - Permissions boundary, SCP, or session policy could override the allow actions with an implicity deny.
    - EXPLICIT denies in ANY policy overrides ANY allow.
    
9. IAM policy structure
    - effect: allow or deny
    - action: element with the specific api action which you are allowing or denying
    - resource: ARN of the resource you want to take action against.
    - condition: (optional) when should this policy have action taken against it.

10. IAM best practices
    - Secure or delete ROOT user access keys.
    - Create individual IAM users.
    - Use groups to assin permission to IAM users.
    - Grant least privilege.
    - Get started using permissions with AWS maanged policies.
    - Use customer managed policies instead of INLINE policies.
    - Enable MFA.
    - Use roles for aplications that run on EC2 instances.
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
        - Preventitive guardrails are based on SCPs and disallow API actions.
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
    - Use egress-only internet gateway for ipv6 outbound connections (Does not accesspt incoming connection attempts).
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
        - Proccessed in order of rules.
4. VPC Peering
    - Keeps traffic private between internal VPC resources.
    - Must not have overlapping CIDR blocks.
    - Does not support transitive peering.  Every VPC that wants to talk must be peered.
5. VPC endpoints
    - Allows users to connect to 'public' resources, privately.
    - Creates an ENI in the subnet where your resources are located and neeed connectivity from.
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
    - Cluster can be deployed intra-VPC or publicly accesible.
    - Cannot switch from private to public endpoint or vica versa.
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
    - Evalutes configurations against desired settings.
    - Get snapshot of current configs associated with AWS account.
    - Retrieve configs of resources that exist in account.
    - Retrieve historical configs.
    - Receive notifications when resources are created, modified, deleted.
    - View relationships between resources.

Edge security
1. DNS and DNS routing

2. CloudFront
    - 



