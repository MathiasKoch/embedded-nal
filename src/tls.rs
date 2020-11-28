use crate::{Dns, TcpStack};
use core::convert::{TryFrom, TryInto};
use heapless::{consts, Vec};

/// An X509 certificate.
#[derive(Debug, Copy, Clone)]
pub enum Certificate<'a> {
    Pem(&'a [u8]),
    Der(&'a [u8]),
}

#[derive(Debug, Copy, Clone)]
pub struct Identity<'a> {
    cert: Certificate<'a>,
    chain: Certificate<'a>,
}

/// SSL/TLS protocol versions.
#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    /// The SSL 3.0 protocol.
    ///
    /// # Warning
    ///
    /// SSL 3.0 has severe security flaws, and should not be used unless absolutely necessary. If
    /// you are not sure if you need to enable this protocol, you should not.
    Sslv3,
    /// The TLS 1.0 protocol.
    Tlsv10,
    /// The TLS 1.1 protocol.
    Tlsv11,
    /// The TLS 1.2 protocol.
    Tlsv12,
    #[doc(hidden)]
    __NonExhaustive,
}

pub struct TlsSocket<T>(T);

impl<T> core::ops::Deref for TlsSocket<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// This trait is implemented by TCP/IP stacks with Tls capability.
pub trait Tls: TcpStack + Dns {
    type Error;
    type TlsConnector;

    /// Connect securely to the given remote host and port.
    fn connect<S>(
        &self,
        socket: <Self as TcpStack>::TcpSocket,
        connector: Self::TlsConnector,
    ) -> Result<TlsSocket<<Self as TcpStack>::TcpSocket>, <Self as Tls>::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct TlsConnectorConfig<'a, CTX> {
    context: Option<CTX>,
    identity: Option<Identity<'a>>,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
    root_certificates: Vec<Certificate<'a>, consts::U10>,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    use_sni: bool,
}

impl<'a, CTX> TlsConnectorConfig<'a, CTX> {
    pub fn context(&mut self) -> &mut Option<CTX> {
        &mut self.context
    }

    pub fn identity(&mut self) -> &mut Option<Identity<'a>> {
        &mut self.identity
    }

    pub fn min_protocol(&self) -> Protocol {
        self.min_protocol.unwrap_or(Protocol::Tlsv10)
    }

    pub fn max_protocol(&self) -> Protocol {
        self.max_protocol.unwrap_or(Protocol::Tlsv12)
    }

    pub fn root_certificates(&mut self) -> &mut Vec<Certificate<'a>, consts::U10> {
        &mut self.root_certificates
    }

    pub fn accept_invalid_certs(&self) -> bool {
        self.accept_invalid_certs
    }

    pub fn accept_invalid_hostnames(&self) -> bool {
        self.accept_invalid_hostnames
    }

    pub fn use_sni(&self) -> bool {
        self.use_sni
    }
}

/// A builder for `TlsConnector`s.
#[derive(Clone, Debug, Default)]
pub struct TlsConnectorBuilder<'a>(TlsConnectorConfig<'a, ()>);

impl<'a> TlsConnectorBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    fn context<CTX>(&mut self, context: CTX) -> TlsConnectorConfig<'a, CTX> {
        TlsConnectorConfig {
            context: context.into(),
            identity: self.0.identity.take(),
            min_protocol: self.0.min_protocol.take(),
            max_protocol: self.0.max_protocol.take(),
            root_certificates: self.0.root_certificates.clone(),
            accept_invalid_certs: self.0.accept_invalid_certs,
            accept_invalid_hostnames: self.0.accept_invalid_hostnames,
            use_sni: self.0.use_sni,
        }
    }

    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(&mut self, identity: Identity<'a>) -> &mut Self {
        self.0.identity.replace(identity);
        self
    }

    /// Sets the minimum supported protocol version.
    ///
    /// The method is opional. Unless explicitly called with a specific protocol version, it enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Protocol::Tlsv10`.
    pub fn min_protocol_version(&mut self, protocol: Protocol) -> &mut Self {
        self.0.min_protocol.replace(protocol);
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Protocol) -> &mut Self {
        self.0.max_protocol.replace(protocol);
        self
    }

    /// Adds a certificate to the set of roots that the connector will trust.
    ///
    /// The connector will use the system's trust root by default. This method can be used to add
    /// to that set when communicating with servers not trusted by the system.
    ///
    /// Defaults to an empty set.
    pub fn root_certificate(&mut self, cert: Certificate<'a>) -> &mut Self {
        self.0
            .root_certificates
            .push(cert)
            .expect("cannot add the CA cert exceeding the capacity");
        self
    }

    /// Controls the use of certificate validation.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid certificates are trusted, *any*
    /// certificate for *any* site will be trusted for use. This includes expired certificates. This introduces
    /// significant vulnerabilities, and should only be used as a last resort.
    pub fn danger_accept_invalid_certs(&mut self, accept_invalid_certs: bool) -> &mut Self {
        self.0.accept_invalid_certs = accept_invalid_certs;
        self
    }

    /// Controls the use of Server Name Indication (SNI).
    ///
    /// Defaults to `true`.
    pub fn use_sni(&mut self, use_sni: bool) -> &mut Self {
        self.0.use_sni = use_sni;
        self
    }

    /// Controls the use of hostname verification.
    ///
    /// Defaults to `false`.
    ///
    /// # Warning
    ///
    /// You should think very carefully before using this method. If invalid hostnames are trusted, *any* valid
    /// certificate for *any* site will be trusted for use. This introduces significant vulnerabilities, and should
    /// only be used as a last resort.
    pub fn danger_accept_invalid_hostnames(&mut self, accept_invalid_hostnames: bool) -> &mut Self {
        self.0.accept_invalid_hostnames = accept_invalid_hostnames;
        self
    }

    pub fn build<'b, CTX, CONN>(&'b mut self, ctx: CTX) -> Result<CONN, CONN::Error>
    where
        CONN: TryFrom<TlsConnectorConfig<'a, CTX>>,
    {
        self.context(ctx).try_into()
    }
}
