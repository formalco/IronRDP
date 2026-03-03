use std::sync::Arc;

use ironrdp_async::NetworkClient;
use ironrdp_connector::sspi::credssp::{
    CredSspServer, CredentialsProxy, ServerError, ServerMode, ServerState, TsRequest,
};
use ironrdp_connector::sspi::generator::{Generator, GeneratorState};
use ironrdp_connector::sspi::ntlm::NtlmConfig;
use ironrdp_connector::sspi::{self, AuthIdentity, KerberosServerConfig, NegotiateConfig, NetworkRequest, Username};
use ironrdp_connector::{
    custom_err, general_err, ConnectorError, ConnectorErrorKind, ConnectorResult, ServerName, Written,
};
use ironrdp_core::{other_err, WriteBuf};
use ironrdp_pdu::rdp::client_info::Credentials;
use ironrdp_pdu::PduHint;
use tracing::debug;

/// Dynamic credential provider for RDP authentication.
///
/// Used for both security paths:
/// - CredSSP/NLA: candidates are fed to the NTLM verifier
/// - TLS-only: client credentials from `ClientInfoPdu` are compared against candidates
///
/// Return an empty `Vec` to reject the user.
pub trait CredentialProvider: Send + Sync {
    fn get_credentials(&self, username: &str, domain: Option<&str>) -> Vec<Credentials>;
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

enum CredentialSource {
    Static(AuthIdentity),
    Dynamic(Arc<dyn CredentialProvider>),
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
                data.username = username.clone();
                Ok(vec![data])
            }
            CredentialSource::Dynamic(provider) => {
                let creds = provider.get_credentials(
                    username.account_name(),
                    username.domain_name().as_deref(),
                );
                creds
                    .into_iter()
                    .map(|c| {
                        let u = Username::new(&c.username, c.domain.as_deref())
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                        Ok(AuthIdentity {
                            username: u,
                            password: c.password.into(),
                        })
                    })
                    .collect()
            }
        }
    }

    fn auth_data(&mut self) -> std::io::Result<Vec<Self::AuthenticationData>> {
        match &self.source {
            CredentialSource::Static(identity) => Ok(vec![identity.clone()]),
            CredentialSource::Dynamic(_) => Ok(Vec::new()),
        }
    }
}

#[derive(Debug)]
pub struct CredsspSequence {
    server: CredSspServer<CredentialsProxyImpl>,
    state: CredsspState,
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

    pub fn init_with_provider(
        provider: Arc<dyn CredentialProvider>,
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
        let client_computer_name = client_computer_name.into_inner();
        let credentials = CredentialsProxyImpl { source };

        let server_mode = if let Some(krb_config) = krb_config {
            ServerMode::Negotiate(NegotiateConfig {
                protocol_config: Box::new(krb_config),
                package_list: None,
                client_computer_name,
            })
        } else {
            ServerMode::Ntlm(NtlmConfig::new(client_computer_name))
        };

        let server = CredSspServer::new(public_key, credentials, server_mode)
            .map_err(|e| ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e)))?;

        let sequence = Self {
            server,
            state: CredsspState::Ongoing,
        };

        Ok(sequence)
    }

    /// Returns Some(ts_request) when a TS request is received from client,
    pub fn decode_client_message(&mut self, input: &[u8]) -> ConnectorResult<Option<TsRequest>> {
        match self.state {
            CredsspState::Ongoing => {
                let message = TsRequest::from_buffer(input).map_err(|e| custom_err!("TsRequest", e))?;
                debug!(?message, "Received");
                Ok(Some(message))
            }
            _ => Err(general_err!(
                "attempted to feed client request to CredSSP sequence in an unexpected state"
            )),
        }
    }

    pub fn process_ts_request(&mut self, request: TsRequest) -> CredsspProcessGenerator<'_> {
        self.server.process(request)
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
