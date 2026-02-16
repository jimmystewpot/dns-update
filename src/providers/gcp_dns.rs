use std::{borrow::Cow, time::Duration};

use crate::{http::HttpClientBuilder, DnsRecord, DnsRecordType, Error, IntoFqdn};
use serde::{Deserialize, Serialize};

/// Configuration for the Google Cloud DNS provider.
///
/// `managed_zone` accepts either a GCP managed zone ID (e.g. "my-zone-id") or
/// a domain name (e.g. "example.com"). When a domain name is provided, set
/// `discover_domain` to `true` so the provider resolves it to a zone ID via the
/// API at runtime. When a zone ID is provided directly, leave `discover_domain`
/// as `false` (the default) to skip the lookup.
///
/// Authentication is resolved in order:
///   1. `access_token` / `GCP_ACCESS_TOKEN` — a pre-minted Bearer token.
///   2. `service_account_key` / `GCP_SERVICE_ACCOUNT_KEY` — the raw JSON string
///      of a Google service account key. The provider signs a JWT and exchanges
///      it for an access token via Google's OAuth2 endpoint.
///
/// All fields fall back to environment variables when `None`:
///   GCP_PROJECT_ID, GCP_MANAGED_ZONE, GCP_ACCESS_TOKEN,
///   GCP_SERVICE_ACCOUNT_KEY, GCP_DISCOVER_DOMAIN
#[derive(Clone, Default)]
pub struct GcpDnsConfig {
    pub project_id: Option<String>,
    /// GCP managed zone ID, or a domain name when `discover_domain` is `true`.
    pub managed_zone: Option<String>,
    /// A pre-minted Bearer token. Takes priority over `service_account_key`.
    pub access_token: Option<String>,
    /// Raw JSON string of a Google service account key. When provided (and no
    /// `access_token` is set), the provider signs a JWT and exchanges it for an
    /// access token automatically.
    pub service_account_key: Option<String>,
    /// When `true`, treat `managed_zone` as a domain name and resolve the zone
    /// ID from the Google Cloud DNS API. When `false` (default), treat
    /// `managed_zone` as a literal zone ID.
    pub discover_domain: Option<bool>,
    pub timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct GcpDnsProvider {
    client_builder: HttpClientBuilder,
    project_id: String,
    managed_zone: Option<String>,
    discover_domain: bool,
    base_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ResourceRecordSet {
    name: String,
    #[serde(rename = "type")]
    rr_type: String,
    ttl: i64,
    rrdatas: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Change {
    #[serde(skip_serializing_if = "Option::is_none")]
    additions: Option<Vec<ResourceRecordSet>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deletions: Option<Vec<ResourceRecordSet>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ManagedZone {
    id: String,
    name: String,
    #[serde(rename = "dnsName")]
    dns_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ManagedZonesListResponse {
    #[serde(rename = "managedZones")]
    managed_zones: Vec<ManagedZone>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ResourceRecordSetsListResponse {
    rrsets: Vec<ResourceRecordSet>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ChangeResponse {
    status: String,
}

fn env_or_file(key: &str) -> Option<String> {
    let file_key = format!("{key}_FILE");
    if let Ok(path) = std::env::var(file_key) {
        if !path.is_empty() {
            if let Ok(value) = std::fs::read_to_string(path) {
                let value = value.trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    std::env::var(key).ok().and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

impl GcpDnsProvider {
    pub(crate) async fn new(config: GcpDnsConfig) -> crate::Result<Self> {
        let project_id = config
            .project_id
            .or_else(|| env_or_file("GCP_PROJECT_ID"))
            .ok_or_else(|| Error::Parse("Missing GCP project ID".to_string()))?;

        let discover_domain = config
            .discover_domain
            .or_else(|| env_or_file("GCP_DISCOVER_DOMAIN").and_then(|v| v.parse().ok()))
            .unwrap_or(false);

        let managed_zone = config
            .managed_zone
            .or_else(|| env_or_file("GCP_MANAGED_ZONE"));

        // When discover_domain is false the managed_zone must be a zone ID.
        if !discover_domain && managed_zone.is_none() {
            return Err(Error::Parse(
                "Missing GCP managed zone ID (set managed_zone or GCP_MANAGED_ZONE, \
                 or enable discover_domain to resolve from a domain name)"
                    .to_string(),
            ));
        }

        let access_token = config
            .access_token
            .or_else(|| env_or_file("GCP_ACCESS_TOKEN"));

        let service_account_key = config
            .service_account_key
            .or_else(|| env_or_file("GCP_SERVICE_ACCOUNT_KEY"));

        let token = if let Some(token) = access_token {
            token
        } else if let Some(sa_json) = service_account_key {
            exchange_service_account_token(&sa_json).await?
        } else {
            return Err(Error::Parse(
                "Missing GCP credentials (set access_token / GCP_ACCESS_TOKEN, \
                 or service_account_key / GCP_SERVICE_ACCOUNT_KEY)"
                    .to_string(),
            ));
        };

        let builder = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_timeout(config.timeout);

        Ok(Self {
            client_builder: builder,
            project_id,
            managed_zone,
            discover_domain,
            base_url: "https://dns.googleapis.com".to_string(),
        })
    }

    async fn resolve_managed_zone(&self, origin: &str) -> crate::Result<String> {
        let dns_name = if origin.ends_with('.') {
            origin.to_string()
        } else {
            format!("{}.", origin)
        };
        let url = format!(
            "{}/dns/v1/projects/{}/managedZones?dnsName={}",
            self.base_url, self.project_id, dns_name
        );
        let resp: ManagedZonesListResponse = self
            .client_builder
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Api(format!("Failed to list managed zones: {e}")))?;
        let zone = resp
            .managed_zones
            .into_iter()
            .find(|z| z.dns_name.trim_end_matches('.') == origin.trim_end_matches('.'))
            .ok_or(Error::NotFound)?;
        Ok(zone.id)
    }

    async fn ensure_zone(&self, origin_str: &str) -> crate::Result<String> {
        if self.discover_domain {
            self.resolve_managed_zone(origin_str).await
        } else {
            // Safe: constructor validates managed_zone is Some when discover_domain is false.
            Ok(self.managed_zone.clone().unwrap_or_default())
        }
    }

    async fn list_rrsets(
        &self,
        origin_str: &str,
        name: &str,
        rr_type: &str,
    ) -> crate::Result<Vec<ResourceRecordSet>> {
        let zone = self.ensure_zone(origin_str).await?;
        let url = format!(
            "{}/dns/v1/projects/{}/managedZones/{}/rrsets?name={}&type={}",
            self.base_url, self.project_id, zone, name, rr_type
        );
        let resp: ResourceRecordSetsListResponse = self
            .client_builder
            .get(url)
            .send_with_retry(3)
            .await
            .map_err(|e| Error::Api(format!("Failed to list rrsets: {e}")))?;
        Ok(resp.rrsets)
    }

    async fn submit_change(&self, origin_str: &str, change: Change) -> crate::Result<()> {
        let zone = self.ensure_zone(origin_str).await?;
        let url = format!(
            "{}/dns/v1/projects/{}/managedZones/{}/changes",
            self.base_url, self.project_id, zone
        );
        let body = serde_json::to_string(&change)
            .map_err(|e| Error::Serialize(format!("Failed to serialize change: {e}")))?;
        let _: ChangeResponse = self
            .client_builder
            .post(url)
            .with_raw_body(body)
            .send_with_retry(3)
            .await
            .map_err(|e| Error::Api(format!("Failed to submit change: {e}")))?;
        Ok(())
    }

    pub(crate) async fn create(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = normalize_name(name.into_fqdn());
        let origin_str = origin.into_fqdn().into_owned();
        let (rrset, _) = build_rrset(&name, record, ttl);
        let change = Change {
            additions: Some(vec![rrset]),
            deletions: None,
        };
        self.submit_change(&origin_str, change).await
    }

    pub(crate) async fn update(
        &self,
        name: impl IntoFqdn<'_>,
        record: DnsRecord,
        ttl: u32,
        origin: impl IntoFqdn<'_>,
    ) -> crate::Result<()> {
        let name = normalize_name(name.into_fqdn());
        let (new_rrset, rr_type) = build_rrset(&name, record, ttl);
        let origin_str = origin.into_fqdn().into_owned();
        let existing = self
            .list_rrsets(&origin_str, &name, rr_type)
            .await?
            .into_iter()
            .find(|rr| rr.name.trim_end_matches('.') == name.trim_end_matches('.'));
        let change = if let Some(old_rrset) = existing {
            Change {
                additions: Some(vec![new_rrset]),
                deletions: Some(vec![old_rrset]),
            }
        } else {
            Change {
                additions: Some(vec![new_rrset]),
                deletions: None,
            }
        };
        self.submit_change(&origin_str, change).await
    }

    pub(crate) async fn delete(
        &self,
        name: impl IntoFqdn<'_>,
        origin: impl IntoFqdn<'_>,
        record_type: DnsRecordType,
    ) -> crate::Result<()> {
        let name = normalize_name(name.into_fqdn());
        let rr_type = dns_record_type_str(&record_type);
        let origin_str = origin.into_fqdn().into_owned();
        let existing = self
            .list_rrsets(&origin_str, &name, rr_type)
            .await?
            .into_iter()
            .find(|rr| rr.name.trim_end_matches('.') == name.trim_end_matches('.'));
        if let Some(rrset) = existing {
            let change = Change {
                additions: None,
                deletions: Some(vec![rrset]),
            };
            self.submit_change(&origin_str, change).await
        } else {
            Err(Error::NotFound)
        }
    }
}

fn normalize_name(name: Cow<'_, str>) -> String {
    if name.ends_with('.') {
        name.into_owned()
    } else {
        format!("{}.", name)
    }
}

/// Maps a `DnsRecordType` enum (used by `delete`) to the Google DNS type string.
fn dns_record_type_str(rt: &DnsRecordType) -> &'static str {
    match rt {
        DnsRecordType::A => "A",
        DnsRecordType::AAAA => "AAAA",
        DnsRecordType::CNAME => "CNAME",
        DnsRecordType::NS => "NS",
        DnsRecordType::MX => "MX",
        DnsRecordType::TXT => "TXT",
        DnsRecordType::SRV => "SRV",
    }
}

/// Decomposes a `DnsRecord` into its type string and rrdatas for the Google
/// Cloud DNS ResourceRecordSet payload.
fn build_rrset(name: &str, record: DnsRecord, ttl: u32) -> (ResourceRecordSet, &'static str) {
    let (rrdatas, rr_type) = match record {
        DnsRecord::A { content } => (vec![content.to_string()], "A"),
        DnsRecord::AAAA { content } => (vec![content.to_string()], "AAAA"),
        DnsRecord::CNAME { content } => (vec![content], "CNAME"),
        DnsRecord::NS { content } => (vec![content], "NS"),
        DnsRecord::MX { content, priority } => (vec![format!("{priority} {content}")], "MX"),
        DnsRecord::TXT { content } => (vec![format!("\"{}\"", content)], "TXT"),
        DnsRecord::SRV {
            content,
            priority,
            weight,
            port,
        } => (vec![format!("{priority} {weight} {port} {content}")], "SRV"),
    };
    (
        ResourceRecordSet {
            name: name.to_string(),
            rr_type: rr_type.to_string(),
            ttl: ttl as i64,
            rrdatas,
        },
        rr_type,
    )
}

/// Google OAuth2 token response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Parses a service account JSON string, builds a signed JWT, and exchanges it
/// for a short-lived access token via Google's OAuth2 token endpoint.
///
/// The JWT is signed with RS256 using the private key embedded in the service
/// account JSON. Only the `https://www.googleapis.com/auth/ndev.clouddns.readwrite`
/// scope is requested.
async fn exchange_service_account_token(sa_json: &str) -> crate::Result<String> {
    let sa: serde_json::Value = serde_json::from_str(sa_json)
        .map_err(|e| Error::Parse(format!("Invalid service account JSON: {e}")))?;

    let client_email = sa
        .get("client_email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Parse("Missing client_email in service account key".into()))?;

    let private_key_pem = sa
        .get("private_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Parse("Missing private_key in service account key".into()))?;

    let token_uri = sa
        .get("token_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("https://oauth2.googleapis.com/token");

    let scope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Parse(format!("System clock error: {e}")))?
        .as_secs();

    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": scope,
        "aud": token_uri,
        "iat": now,
        "exp": now + 3600,
    });

    let signed_jwt = sign_jwt(&header, &claims, private_key_pem)?;

    let body = serde_urlencoded::to_string([
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &signed_jwt),
    ])
    .map_err(|e| Error::Serialize(format!("Failed to encode token request: {e}")))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Client(format!("Failed to build HTTP client: {e}")))?;

    let resp = client
        .post(token_uri)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| Error::Api(format!("Token exchange request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        return Err(Error::Api(format!(
            "Token exchange failed (HTTP {status}): {text}"
        )));
    }

    let text = resp
        .text()
        .await
        .map_err(|e| Error::Api(format!("Failed to read token response: {e}")))?;
    let token_resp: TokenResponse = serde_json::from_str(&text)
        .map_err(|e| Error::Serialize(format!("Failed to parse token response: {e}")))?;

    Ok(token_resp.access_token)
}

/// Signs a JWT (header + claims) with RS256 using the PEM-encoded private key.
fn sign_jwt(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    private_key_pem: &str,
) -> crate::Result<String> {
    use aws_lc_rs::signature::{self, KeyPair, RsaKeyPair};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    let der_bytes = pem_to_der(private_key_pem)?;
    let key_pair = RsaKeyPair::from_pkcs8(&der_bytes)
        .map_err(|e| Error::Parse(format!("Invalid RSA private key: {e}")))?;

    let mut sig = vec![0u8; key_pair.public_key().modulus_len()];
    key_pair
        .sign(
            &signature::RSA_PKCS1_SHA256,
            &aws_lc_rs::rand::SystemRandom::new(),
            signing_input.as_bytes(),
            &mut sig,
        )
        .map_err(|e| Error::Parse(format!("JWT signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Strips PEM headers/footers and base64-decodes the body to raw DER bytes.
fn pem_to_der(pem: &str) -> crate::Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    STANDARD
        .decode(b64)
        .map_err(|e| Error::Parse(format!("Failed to decode PEM private key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn create_test_provider(server: &Server, config: GcpDnsConfig) -> GcpDnsProvider {
        // Create provider with mock server URL
        let token = config
            .access_token
            .clone()
            .unwrap_or_else(|| "token".to_string());
        let builder = HttpClientBuilder::default()
            .with_header("Authorization", format!("Bearer {token}"))
            .with_timeout(config.timeout);
        GcpDnsProvider {
            client_builder: builder,
            project_id: config.project_id.unwrap(),
            managed_zone: config.managed_zone,
            discover_domain: config.discover_domain.unwrap_or(false),
            base_url: server.url(),
        }
    }

    #[test]
    fn converts_mx_record() {
        let record = DnsRecord::MX {
            content: "mail.example.com.".into(),
            priority: 10,
        };
        let (rrset, rr_type) = build_rrset("test.example.com.", record, 300);
        assert_eq!(rr_type, "MX");
        assert_eq!(rrset.rr_type, "MX");
        assert_eq!(rrset.rrdatas, vec!["10 mail.example.com."]);
    }

    #[test]
    fn converts_txt_record() {
        let record = DnsRecord::TXT {
            content: "hello world".into(),
        };
        let (rrset, rr_type) = build_rrset("test.example.com.", record, 300);
        assert_eq!(rr_type, "TXT");
        assert_eq!(rrset.rr_type, "TXT");
        assert_eq!(rrset.rrdatas, vec!["\"hello world\""]);
    }

    #[tokio::test]
    async fn test_create_success() {
        let mut server = Server::new_async().await;
        let change_body = serde_json::json!({
            "status": "pending"
        });
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/my-project/managedZones/test-zone/changes",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&change_body).unwrap())
            .create_async()
            .await;

        let config = GcpDnsConfig {
            project_id: Some("my-project".to_string()),
            managed_zone: Some("test-zone".to_string()),
            access_token: Some("token".to_string()),
            service_account_key: None,
            discover_domain: Some(false),
            timeout: None,
        };
        let provider = create_test_provider(&server, config);
        let record = DnsRecord::A {
            content: "1.2.3.4".parse().unwrap(),
        };
        provider
            .create("test.example.com", record, 300, "example.com")
            .await
            .unwrap();

        change_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_discover_zone_success() {
        let mut server = Server::new_async().await;
        let zones_body = serde_json::json!({
            "managedZones": [{
                "id": "discovered-zone",
                "name": "discovered-zone",
                "dnsName": "example.com."
            }]
        });
        let change_body = serde_json::json!({
            "status": "pending"
        });
        let zones_mock = server
            .mock("GET", "/dns/v1/projects/my-project/managedZones")
            .match_query("dnsName=example.com.")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&zones_body).unwrap())
            .create_async()
            .await;
        let change_mock = server
            .mock(
                "POST",
                "/dns/v1/projects/my-project/managedZones/discovered-zone/changes",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&change_body).unwrap())
            .create_async()
            .await;

        let config = GcpDnsConfig {
            project_id: Some("my-project".to_string()),
            managed_zone: None, // No managed zone; will be discovered
            access_token: Some("token".to_string()),
            service_account_key: None,
            discover_domain: Some(true),
            timeout: None,
        };
        let provider = create_test_provider(&server, config);
        let record = DnsRecord::A {
            content: "1.2.3.4".parse().unwrap(),
        };
        provider
            .create("test.example.com", record, 300, "example.com")
            .await
            .unwrap();

        zones_mock.assert_async().await;
        change_mock.assert_async().await;
    }

    const TEST_RSA_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQD3xCXiE5loFSHD\n\
0OZHoDRwjvr7QzI/OpZhQEvSB+fmjix6r1BeytJfjQ/O+IQgKssMZpJA3nRrbvsN\n\
NT2yXKhDT1LWQ+03bYSsMm8ni/PUFBO9nUoM/DI9mkeu6Rq6T/esEdNjcbl9qmg5\n\
aPq2xER9X3cTkrqOpZB/q5t7ofYqjkjmZyaTd9U+MsyMyPu0lKLXXgILTLxBkW+L\n\
pPXM8MXiO1E+WRme5MLRZG0LIYGQ4ltKKSJv5pR+QE5oZqtWVH69wPbhYHpQVgV5\n\
NZph7MHWBvOLsFQJqvjiKd2G8Gi7E3sVV5k0lKTXGeTamZPr2HQ2zW7MgfVQOSok\n\
eEKnaQnDAgMBAAECggEAXLZhxKC34Voy+c60NO4uYUYnhZkl9sIKHpcMKCo8LSpb\n\
W4c5qFb19LpYxYZ6Dn1k4J2LMcnsP31WZSFcll8Uuac3pKTjYb/SCwuOS3qTwXLH\n\
1kbCvGwssp+GHl3s2fXthE5hTw9xrSP0fzMYygZUaKOt772SoKk0komZE2DOOCqs\n\
gAaO1M1XLun9m4sh+u4tW3l69mIeZgGQ2nCICdmLm+fIeOrZ23UGp1EgEyiXEw8C\n\
DNRIJ9uk4CNi0tGZOUBj3jM9LjoSWqk8TLrnEO7gGUGHlbKRmQBHPfpTvhKPrMLn\n\
KBQIb4GKWMyyQ7E92Fo9c86WiiP+R+GigAmIkPrVoQKBgQD+IESXlVL9w0OUChck\n\
mgorPfEHVKrWLlLYWJYlLsJWPFfdotmaQs2V7CnHrNBUgSB5Jvq4znOQufXi+2mV\n\
OIe8ufYUMbBOydh0fhkeGe7/RCTeB0aCDEgT1DOrW3HRg3m1pkH8J3VNxWFzfnBJ\n\
4oOKdgAoz7XDu4J4EXaZUmIFowKBgQD5l9/FhFXE8XOSKkzb0PMivUev0goA7EKz\n\
J6o5qp0C5TZenNCwXLvWpnuWgW6bM5ftkd4PD4vCAj5E4gf39F8hvpIT8AwG4H6M\n\
SfhnwopEqKzfgkWStpiDD7BKBM30oH2Xk2OhAy9NhkK6JZjEO+hYO8MTfJH7SgYT\n\
IktD+Y/tYQKBgQDitiDbZsFCWMhaMuJQqgf2ae000AkUyQDpt6ZDh8KiMnVk6lrd\n\
L0m/vY/MblTxfr1cuDSnWK9q5ywBErAwCt21teVeQLH8qEAuNSztWM+J9d46Ih15\n\
+cD3x7FM52jUNEoJj0iAzybsefGlmqBMmgMmLH2Z6yxKcWdE/Ldks0V1pwKBgQCb\n\
gYRqC4lkqwrWhoRccFML0eJYKQUSjiEAfjYQt7wbkbPOPuXG/AAMPK3Dl+DR0dNW\n\
sQspVwY8WilxwWI1mouq+pEI2wajQjuWLIAYJZ0AKheLKh8uyZU8EwpDE7s+LsAR\n\
MENijhlqs7vfPo1vteONFa709Sf+6J/gS/2Y3GRQAQKBgQCaQSgrQgZUiCWrlujT\n\
yNB8JpQmz20m64hBQVNikDi5lFQujnWAhul6f8HJzq5VCu/NmNI6xKsRjombNn56\n\
mOF6Gcxpr60lqcm5UngeI/1VhlEagxNpw4sTOxliTHPTchVEEnSeQcobaXr57Xqg\n\
DBJ9XSCQipmUFj/Rpr8uyFHYhQ==\n\
-----END PRIVATE KEY-----";

    #[test]
    fn test_pem_to_der() {
        let der = pem_to_der(TEST_RSA_KEY_PEM).unwrap();
        assert!(!der.is_empty());
        // PKCS#8 DER starts with a SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_sign_jwt() {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let claims = serde_json::json!({
            "iss": "test@example.iam.gserviceaccount.com",
            "scope": "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": 1000000,
            "exp": 1003600,
        });
        let jwt = sign_jwt(&header, &claims, TEST_RSA_KEY_PEM).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");
        assert!(!parts[2].is_empty(), "signature must not be empty");
    }

    #[tokio::test]
    async fn test_service_account_token_exchange() {
        let mut server = Server::new_async().await;
        let token_mock = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token":"mocked-token","token_type":"Bearer","expires_in":3600}"#)
            .create_async()
            .await;

        let sa_json = serde_json::json!({
            "type": "service_account",
            "client_email": "test@example.iam.gserviceaccount.com",
            "private_key": TEST_RSA_KEY_PEM,
            "token_uri": format!("{}/token", server.url()),
        });

        let token = exchange_service_account_token(&sa_json.to_string())
            .await
            .unwrap();
        assert_eq!(token, "mocked-token");
        token_mock.assert_async().await;
    }
}
