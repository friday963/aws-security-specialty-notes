IAM

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