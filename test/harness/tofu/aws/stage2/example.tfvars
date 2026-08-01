# Example inputs for stage2. The driver generates the real file from
# test/harness/state/gcp-stage1.json and test/harness/state/azure-stage1.json;
# this exists to document the mapping and to make the module runnable by hand.
#
#   tofu -chdir=test/harness/tofu/aws/stage2 apply -var-file=generated.tfvars
#
# Field mapping:
#   gcp_issuer_url            <- gcp-stage1.json   .issuer_url
#   gcp_source_sa_unique_id   <- gcp-stage1.json   .source_sa_unique_id
#   azure_aks_oidc_issuer_url <- azure-stage1.json .aks_oidc_issuer_url
#   azure_subject             <- azure-stage1.json .subject
#
# A jq one-liner that renders it:
#
#   jq -n --slurpfile g ../../../state/gcp-stage1.json \
#         --slurpfile a ../../../state/azure-stage1.json \
#         --arg run_id "$RUN_ID" '{
#           run_id: $run_id,
#           gcp_issuer_url: $g[0].issuer_url,
#           gcp_source_sa_unique_id: $g[0].source_sa_unique_id,
#           azure_aks_oidc_issuer_url: $a[0].aks_oidc_issuer_url,
#           azure_subject: $a[0].subject
#         }' > generated.tfvars.json

run_id      = "20260705-abc123"
name_prefix = "cloud-auth-test"
region      = "us-east-1"

# --- GCP source facts ---
gcp_issuer_url = "https://accounts.google.com"

# The SERVICE ACCOUNT'S NUMERIC UNIQUE ID, not its email. Getting this wrong
# does not weaken the trust (it just never matches), but it does mean row 1 of
# the pair matrix fails with an unhelpful AccessDenied.
gcp_source_sa_unique_id = "109876543210987654321"

# --- Azure source facts ---
# Copy verbatim from azure-stage1.json, trailing slash included.
azure_aks_oidc_issuer_url = "https://eastus.oic.prod-aks.azure.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/11111111-2222-3333-4444-555555555555/"
azure_subject             = "system:serviceaccount:cloud-auth-test:verifier"
