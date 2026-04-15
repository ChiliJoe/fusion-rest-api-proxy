# fusion-rest-api-proxy

An OCI Function that serves as the backend for an OCI API Gateway, acting as a transparent proxy to Fusion REST API endpoints.

For each incoming request, the function:
1. Retrieves a private key and passphrase from OCI Vault.
2. Creates a signed JWT user-assertion (RS256) using the caller's identity.
3. Exchanges the JWT for an OAuth access token via OCI IAM (jwt-bearer grant).
4. Proxies the request to the Fusion target endpoint with the access token.
5. Rewrites backend URLs in the response body to API Gateway frontend URLs.
6. Returns the transformed response to the original caller.

---

## Prerequisites

### Key Pair and Signing Certificate

Generate an RSA key pair and a self-signed certificate. The private key is stored in OCI Vault; the certificate is uploaded to the OCI IAM Confidential Application as a trusted signing key.

#### 1. Generate a passphrase-protected RSA private key

```bash
openssl genrsa -aes256 -passout pass:<your-passphrase> -out private.pem 2048
```

#### 2. Generate a self-signed certificate from the private key

OCI IAM requires a certificate (not a bare public key) when registering a JWT signing key. The certificate is self-signed — its validity period and subject DN are informational only.

```bash
openssl req -new -x509 -key private.pem \
  -passin pass:<your-passphrase> \
  -days 3650 \
  -subj "/CN=fusion-rest-api-proxy" \
  -out certificate.pem
```

#### 3. Store the private key and passphrase in OCI Vault

Create two **Base64 Secret Bundle** secrets in OCI Vault:

| Secret | Content |
|--------|---------|
| Private key | Full contents of `private.pem` (including `-----BEGIN ENCRYPTED PRIVATE KEY-----` header/footer) |
| Key passphrase | The passphrase string used in step 1 |

Note the OCID of each secret — they are set as the `PRIVATE_KEY_OCID` and `PRIVATE_KEY_PP_OCID` config parameters.

#### 4. Register the certificate in OCI IAM

In the OCI IAM Confidential Application, under **OAuth Configuration → JWT Signing Certificates**, upload `certificate.pem`. Set the **Key ID** field to a short identifier of your choice — this value must match the `JWT_KID` function config parameter.

### OCI IAM Confidential Application

Register a Confidential Application in OCI IAM (IDCS) with:
- Grant type: **JWT Assertion** (jwt-bearer)
- The self-signed certificate from the step above added as a trusted signing certificate
- Appropriate OAuth scopes configured

Note the **Client ID** and **Client Secret** — used as `JWT_ISSUER` and `JWT_CLIENT_SECRET_OCID`.

### OCI API Gateway

Configure an API Gateway deployment with a route that:
- Sets the `x-target-endpoint` header to the Fusion backend URL for the route
- Sets the `x-username` header to the authenticated user's identity

---

## Minimum IAM Policy

The OCI Function requires a Dynamic Group to be granted permission to read Vault secrets at runtime. No other OCI SDK calls are made.

### Step 1 — Create a Dynamic Group

Create a Dynamic Group that matches the function resource, for example:

```
resource.type = 'fnfunc' AND resource.compartment.id = '<compartment-ocid>'
```

Or to match a specific function:

```
resource.id = '<function-ocid>'
```

### Step 2 — Create an IAM Policy

Grant the Dynamic Group read access to secrets in the compartment where the Vault secrets reside:

```
Allow dynamic-group <dynamic-group-name> to read secret-bundles in compartment <compartment-name>
```

If the Vault secrets are in a different compartment from the function, replace `<compartment-name>` with the compartment containing the secrets.

No additional policies are required.

---

## Configuration Parameters

Set these values on the function after deployment. All parameters are required.

| Parameter | Description | Example |
|-----------|-------------|---------|
| `JWT_CLIENT_ID` | OCI IAM Confidential App Client ID — used for HTTP Basic Auth in the token exchange | `some_client_id` |
| `JWT_ISSUER` | *(optional)* JWT `iss` claim. Defaults to `https://identity.oraclecloud.com/` - this is the default issuer if using Fusion IAM | `https://identity.oraclecloud.com/` |
| `JWT_KID` | Key ID placed in the JWT `kid` header — identifies the signing key registered in OCI IAM | `my-signing-key-1` |
| `JWT_AUDIENCE` | JWT `aud` claim value — typically the Fusion tenant base URL | `https://xxxx.fa.us2.oraclecloud.com` |
| `JWT_SCOPE` | OAuth scope requested in the token exchange | `/` |
| `JWT_CLIENT_SECRET_OCID` | OCID of the Vault secret containing the OCI IAM Confidential App Client Secret | `ocid1.vaultsecret.oc1...` |
| `OCI_IAM_BASE_URL` | OCI IAM tenant base URL | `https://idcs-abc123.identity.oraclecloud.com:443` |
| `PRIVATE_KEY_OCID` | OCID of the Vault secret containing the RSA private key PEM | `ocid1.vaultsecret.oc1...` |
| `PRIVATE_KEY_PP_OCID` | OCID of the Vault secret containing the private key passphrase | `ocid1.vaultsecret.oc1...` |

---

## Resource Sizing

### Memory

The recommended memory allocation is **256 MB**, which is also the value set in `func.yaml`.

| Component | Approx. footprint |
|-----------|-------------------|
| Python 3.12 runtime | ~25–35 MB |
| OCI SDK (`oci`) | ~40–60 MB |
| `cryptography` | ~15–25 MB |
| `fdk`, `PyJWT`, `requests` | ~5–10 MB |
| **Baseline total** | **~85–130 MB** |

The remaining ~126 MB of headroom covers response body buffering (Fusion paginated responses can be several hundred KB) and peak allocations during RSA signing. 128 MB risks OOM due to the OCI SDK footprint alone; 512 MB provides no practical benefit for this workload.

---

## Deployment

### 1. Deploy the function

```bash
fn deploy --app <app-name>
```

### 2. Set configuration parameters

```bash
APP=<app-name>
FN=fusion-rest-api-proxy

fn config function $APP $FN JWT_CLIENT_ID            "<client-id>"
fn config function $APP $FN JWT_ISSUER              "<issuer>"
fn config function $APP $FN JWT_KID                 "<key-id>"
fn config function $APP $FN JWT_AUDIENCE             "<iam-base-url>"
fn config function $APP $FN JWT_SCOPE               "<scope>"
fn config function $APP $FN JWT_CLIENT_SECRET_OCID  "<vault-secret-ocid>"
fn config function $APP $FN OCI_IAM_BASE_URL        "<iam-base-url>"
fn config function $APP $FN PRIVATE_KEY_OCID        "<vault-secret-ocid>"
fn config function $APP $FN PRIVATE_KEY_PP_OCID     "<vault-secret-ocid>"
```

### 3. Verify

Invoke the function via the API Gateway with a request that includes the `x-username` and `x-target-endpoint` headers. A successful response will have the backend URL replaced with the API Gateway frontend URL in any links within the response body.
