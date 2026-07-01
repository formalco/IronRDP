use std::sync::Arc;

use ironrdp_async::NetworkClient;
use ironrdp_connector::sspi::credssp::{
    CredSspServer, CredentialsProxy, ServerError, ServerMode, ServerState, TsRequest,
};
use ironrdp_connector::sspi::generator::{Generator, GeneratorState};
use ironrdp_connector::sspi::{self, AuthIdentity, KerberosServerConfig, NegotiateConfig, NetworkRequest, Username};
use ironrdp_connector::{
    ConnectorError, ConnectorErrorKind, ConnectorResult, ServerName, Written, custom_err, general_err,
};
use ironrdp_core::{WriteBuf, other_err};
use ironrdp_pdu::PduHint;
use ironrdp_pdu::rdp::client_info::Credentials;
use tracing::debug;

/// Resolves candidate credentials for CredSSP/NLA from the presented username.
///
/// The NTLM verifier tries each candidate until one matches; return an empty
/// `Vec` to reject. Called synchronously in the sans-I/O acceptor, so it must
/// not block.
pub trait CredsspCandidateProvider: Send + Sync {
    fn candidates(&self, username: &str, domain: Option<&str>) -> Vec<Credentials>;
}

#[derive(Debug)]
pub(crate) enum CredsspState {
    Ongoing,
    Finished,
    ServerError(sspi::Error),
}

#[derive(Clone, Copy, Debug)]
struct CredsspTsRequestHint;

const CREDSSP_TS_REQUEST_HINT: CredsspTsRequestHint = CredsspTsRequestHint;

impl PduHint for CredsspTsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp_core::DecodeResult<Option<(bool, usize)>> {
        match TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(other_err!("CredsspTsRequestHint", source: e)),
        }
    }
}

pub type CredsspProcessGenerator<'a> =
    Generator<'a, NetworkRequest, sspi::Result<Vec<u8>>, Result<ServerState, ServerError>>;

/// Credentials for the CredSSP verifier: a pre-loaded identity or a resolver.
enum CredentialSource {
    Static(AuthIdentity),
    Dynamic(Arc<dyn CredsspCandidateProvider>),
}

impl core::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Static(identity) => f.debug_tuple("Static").field(identity).finish(),
            Self::Dynamic(_) => f.debug_tuple("Dynamic").finish(),
        }
    }
}

#[derive(Debug)]
pub struct CredsspSequence {
    /// Built lazily from builder by [CredsspSequence::ensure_server], once the
    /// client's first token reveals which security mechanism it uses.
    server: Option<CredSspServer<CredentialsProxyImpl>>,
    builder: Option<ServerBuilder>,
    state: CredsspState,
}

/// Inputs retained to build the [CredSspServer] lazily, once the client's first
/// CredSSP token reveals which security mechanism it uses.
#[derive(Debug)]
struct ServerBuilder {
    credentials: CredentialsProxyImpl,
    public_key: Vec<u8>,
    client_computer_name: String,
    krb_config: Option<KerberosServerConfig>,
}

#[derive(Debug)]
struct CredentialsProxyImpl {
    source: CredentialSource,
}

impl CredentialsProxy for CredentialsProxyImpl {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> std::io::Result<Self::AuthenticationData> {
        self.auth_data_candidates_by_user(username)?
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("no credentials for user"))
    }

    fn auth_data_candidates_by_user(&mut self, username: &Username) -> std::io::Result<Vec<Self::AuthenticationData>> {
        match &self.source {
            CredentialSource::Static(identity) => {
                if username.account_name() != identity.username.account_name() {
                    return Err(std::io::Error::other("invalid username"));
                }
                let mut data = identity.clone();
                // keep the original user/domain
                data.username = username.clone();
                Ok(vec![data])
            }
            CredentialSource::Dynamic(provider) => provider
                .candidates(username.account_name(), username.domain_name())
                .into_iter()
                .map(|c| {
                    Ok(AuthIdentity {
                        username: Username::new(&c.username, c.domain.as_deref())
                            .map_err(|e| std::io::Error::other(e.to_string()))?,
                        password: c.password.into(),
                    })
                })
                .collect(),
        }
    }

    fn auth_data(&mut self) -> Result<Vec<Self::AuthenticationData>, std::io::Error> {
        match &self.source {
            CredentialSource::Static(identity) => Ok(vec![identity.clone()]),
            CredentialSource::Dynamic(_) => Ok(Vec::new()),
        }
    }
}

pub(crate) async fn resolve_generator(
    generator: &mut CredsspProcessGenerator<'_>,
    network_client: &mut impl NetworkClient,
) -> Result<ServerState, ServerError> {
    let mut state = generator.start();

    loop {
        match state {
            GeneratorState::Suspended(request) => {
                let response = network_client.send(&request).await.map_err(|err| ServerError {
                    ts_request: None,
                    error: sspi::Error::new(sspi::ErrorKind::InternalError, err),
                })?;
                state = generator.resume(Ok(response));
            }
            GeneratorState::Completed(client_state) => break client_state,
        }
    }
}

impl CredsspSequence {
    pub fn next_pdu_hint(&self) -> ConnectorResult<Option<&dyn PduHint>> {
        match &self.state {
            CredsspState::Ongoing => Ok(Some(&CREDSSP_TS_REQUEST_HINT)),
            CredsspState::Finished => Ok(None),
            CredsspState::ServerError(err) => Err(custom_err!("Credssp server error", err.clone())),
        }
    }

    pub fn init(
        creds: &AuthIdentity,
        client_computer_name: ServerName,
        public_key: Vec<u8>,
        krb_config: Option<KerberosServerConfig>,
    ) -> ConnectorResult<Self> {
        Self::init_impl(
            CredentialSource::Static(creds.clone()),
            client_computer_name,
            public_key,
            krb_config,
        )
    }

    /// Like [CredsspSequence::init], but resolves candidates at authentication
    /// time through a [CredsspCandidateProvider].
    pub fn init_with_provider(
        provider: Arc<dyn CredsspCandidateProvider>,
        client_computer_name: ServerName,
        public_key: Vec<u8>,
        krb_config: Option<KerberosServerConfig>,
    ) -> ConnectorResult<Self> {
        Self::init_impl(
            CredentialSource::Dynamic(provider),
            client_computer_name,
            public_key,
            krb_config,
        )
    }

    fn init_impl(
        source: CredentialSource,
        client_computer_name: ServerName,
        public_key: Vec<u8>,
        krb_config: Option<KerberosServerConfig>,
    ) -> ConnectorResult<Self> {
        Ok(Self {
            server: None,
            builder: Some(ServerBuilder {
                credentials: CredentialsProxyImpl { source },
                public_key,
                client_computer_name: client_computer_name.into_inner(),
                krb_config,
            }),
            state: CredsspState::Ongoing,
        })
    }

    /// Builds the CredSSP server from the client's first token.
    ///
    /// A Kerberos config selects SPNEGO/Negotiate. Otherwise the mechanism is
    /// taken from the token: a raw NTLM message (the NTLMSSP signature) uses
    /// NTLM directly, anything else is treated as SPNEGO wrapping NTLM, which is
    /// what Windows clients send. This lets the acceptor serve them without a
    /// Kerberos KDC.
    ///
    /// Does nothing once the server has been built.
    fn ensure_server(&mut self, first_token: &[u8]) -> ConnectorResult<()> {
        let Some(ServerBuilder {
            credentials,
            public_key,
            client_computer_name,
            krb_config,
        }) = self.builder.take()
        else {
            return Ok(());
        };

        let server_mode = match krb_config {
            Some(krb_config) => ServerMode::Negotiate(NegotiateConfig {
                protocol_config: Box::new(krb_config),
                package_list: None,
                client_computer_name,
            }),
            None if client_sent_raw_ntlm(first_token) => {
                ServerMode::Ntlm(sspi::ntlm::NtlmConfig::new(client_computer_name))
            }
            None => ServerMode::Negotiate(NegotiateConfig {
                protocol_config: Box::new(sspi::ntlm::NtlmConfig::new(client_computer_name.clone())),
                package_list: None,
                client_computer_name,
            }),
        };

        self.server = Some(
            CredSspServer::new(public_key, credentials, server_mode)
                .map_err(|e| ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e)))?,
        );

        Ok(())
    }

    /// Returns Some(ts_request) when a TS request is received from client,
    pub fn decode_client_message(&mut self, input: &[u8]) -> ConnectorResult<Option<TsRequest>> {
        match self.state {
            CredsspState::Ongoing => {
                let message = TsRequest::from_buffer(input).map_err(|e| custom_err!("TsRequest", e))?;
                debug!(?message, "Received");
                self.ensure_server(message.nego_tokens.as_deref().unwrap_or_default())?;
                Ok(Some(message))
            }
            _ => Err(general_err!(
                "attempted to feed client request to CredSSP sequence in an unexpected state"
            )),
        }
    }

    /// # Panics
    ///
    /// Panics if called before [CredsspSequence::decode_client_message], which
    /// builds the CredSSP server from the client's first token.
    pub fn process_ts_request(&mut self, request: TsRequest) -> CredsspProcessGenerator<'_> {
        self.server
            .as_mut()
            .expect("CredSSP server is built from the client's first message before processing")
            .process(request)
    }

    pub fn handle_process_result(
        &mut self,
        result: Result<ServerState, ServerError>,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let (ts_request, next_state) = match result {
            Ok(ServerState::ReplyNeeded(ts_request)) => (Some(ts_request), CredsspState::Ongoing),
            Ok(ServerState::Finished(_id)) => (None, CredsspState::Finished),
            Err(err) => (
                err.ts_request.map(|ts_request| *ts_request),
                CredsspState::ServerError(err.error),
            ),
        };

        self.state = next_state;
        if let Some(ts_request) = ts_request {
            debug!(?ts_request, "Send");
            let length = usize::from(ts_request.buffer_len());
            let unfilled_buffer = output.unfilled_to(length);

            ts_request
                .encode_ts_request(unfilled_buffer)
                .map_err(|e| custom_err!("TsRequest", e))?;

            output.advance(length);

            Ok(Written::from_size(length)?)
        } else {
            Ok(Written::Nothing)
        }
    }
}

/// Whether the client's first CredSSP token is a raw NTLM message rather than
/// an SPNEGO token. A raw NTLM message begins with the NTLMSSP\0 signature;
/// SPNEGO/GSS-API tokens begin with the ASN.1 application tag 0x60. Anything
/// that isn't a raw NTLM message is treated as SPNEGO.
fn client_sent_raw_ntlm(first_token: &[u8]) -> bool {
    first_token.starts_with(b"NTLMSSP\0")
}

#[cfg(test)]
mod tests {
    use super::client_sent_raw_ntlm;

    #[test]
    fn raw_ntlm_negotiate_message_is_detected() {
        // NTLM NEGOTIATE_MESSAGE: "NTLMSSP\0" signature followed by message type 1.
        assert!(client_sent_raw_ntlm(b"NTLMSSP\x00\x01\x00\x00\x00"));
    }

    #[test]
    fn spnego_token_is_not_raw_ntlm() {
        // SPNEGO NegTokenInit: GSS-API application tag 0x60, then the SPNEGO OID
        // (1.3.6.1.5.5.2).
        let spnego = [0x60, 0x82, 0x01, 0x95, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        assert!(!client_sent_raw_ntlm(&spnego));
    }

    #[test]
    fn empty_token_is_not_raw_ntlm() {
        assert!(!client_sent_raw_ntlm(&[]));
    }
}
