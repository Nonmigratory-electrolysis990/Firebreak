# Azure Security

## DO

- **Use Azure RBAC** with least-privilege role assignments. Prefer built-in roles scoped to specific resources over broad subscription-level assignments.
- **Store secrets in Azure Key Vault**. Reference them in App Service configuration with `@Microsoft.KeyVault(SecretUri=...)` syntax.
- **Use Managed Identity** for service-to-service auth. System-assigned for single-resource access, user-assigned for shared identity across resources.
- **Configure Network Security Groups (NSGs)** on every subnet. Deny all inbound by default, allow only required ports from specific sources.
- **Enable Microsoft Entra ID (Azure AD)** for all user and service authentication. Use Conditional Access policies for MFA and location-based restrictions.
- **Enable Defender for Cloud** with enhanced security features. Review and remediate the Secure Score recommendations.
- **Enable diagnostic logging** on all resources and send logs to Log Analytics Workspace for centralized monitoring and alerting.

## DON'T

- Assign `Owner` or `Contributor` at the subscription level for application service principals. Scope to the specific resource group.
- Store connection strings or secrets in App Service application settings without Key Vault references. Settings are visible in the portal.
- Use shared access keys for Storage Accounts when Managed Identity with RBAC is available. Keys grant full account access.
- Leave NSG rules with `Any` source on management ports (3389/RDP, 22/SSH). Use Azure Bastion or JIT VM access.
- Disable Defender for Cloud recommendations without documenting the risk acceptance.
- Use classic deployment resources — they don't support RBAC, Managed Identity, or modern security controls.
- Allow public network access to PaaS services (SQL Database, Storage, Key Vault) without Private Endpoints.

## Common AI Mistakes

- Hardcoding a Storage Account connection string with the account key in application config committed to git.
- Creating an App Service with a system-assigned Managed Identity but then hardcoding Key Vault credentials anyway.
- Assigning `Contributor` role at the subscription level to a CI/CD service principal "so deployments work."
- Leaving Azure SQL with "Allow Azure services" firewall rule enabled, which allows any Azure service (including other tenants) to connect.
- Using Shared Access Signatures (SAS) with no expiry or overly broad permissions instead of RBAC with Managed Identity.
