use no_std_net::{IpAddr, SocketAddr};
/// An X509 certificate.
#[derive(Clone)]
enum Certificate<'a> {
    Pem(&'a [u8]),
    Der(&'a [u8]),
}

#[derive(Clone)]
pub struct Identity<'a> {
    // pkey: PKey<Private>,
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
    /// The TLS 1.3 protocol.
    Tlsv13,
    #[doc(hidden)]
    __NonExhaustive,
}

pub struct TlsSocket<T>(T);

impl<T> TlsSocket<T> {
    pub fn socket(&self) -> &T {
        &self.0
    }
}
pub trait Ssl: TcpStack + Dns {
    type Error: Debug;
    fn connect_ssl(&self, socket: <Self as TcpStack>::TcpSocket, connector: TlsConnector, domain: &str, port: u16) -> 
        Result<TlsSocket<<Self as TcpStack>::TcpSocket>, Self::Error>;

}
/// A builder for `TlsConnector`s.
pub struct TlsConnectorBuilder<'a> {
    identity: Option<Identity<'a>>,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
    root_certificates: Certificate<'a>,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    use_sni: bool,
}

impl<'a> TlsConnectorBuilder<'a> {
    /// Sets the identity to be used for client certificate authentication.
    pub fn identity(&mut self, identity: Identity) -> &mut TlsConnectorBuilder {
        self.identity = Some(identity);
        self
    }

    /// Sets the minimum supported protocol version.
    ///
    /// A value of `None` enables support for the oldest protocols supported by the implementation.
    ///
    /// Defaults to `Some(Protocol::Tlsv10)`.
    pub fn min_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsConnectorBuilder {
        self.min_protocol = protocol;
        self
    }

    /// Sets the maximum supported protocol version.
    ///
    /// A value of `None` enables support for the newest protocols supported by the implementation.
    ///
    /// Defaults to `None`.
    pub fn max_protocol_version(&mut self, protocol: Option<Protocol>) -> &mut TlsConnectorBuilder {
        self.max_protocol = protocol;
        self
    }

    /// Adds a certificate to the set of roots that the connector will trust.
    ///
    /// The connector will use the system's trust root by default. This method can be used to add
    /// to that set when communicating with servers not trusted by the system.
    ///
    /// Defaults to an empty set.
    pub fn add_root_certificate(&mut self, cert: Certificate) -> &mut TlsConnectorBuilder {
        self.root_certificates.push(cert);
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
    pub fn danger_accept_invalid_certs(
        &mut self,
        accept_invalid_certs: bool,
    ) -> &mut TlsConnectorBuilder {
        self.accept_invalid_certs = accept_invalid_certs;
        self
    }

    /// Controls the use of Server Name Indication (SNI).
    ///
    /// Defaults to `true`.
    pub fn use_sni(&mut self, use_sni: bool) -> &mut TlsConnectorBuilder {
        self.use_sni = use_sni;
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
    pub fn danger_accept_invalid_hostnames(
        &mut self,
        accept_invalid_hostnames: bool,
    ) -> &mut TlsConnectorBuilder {
        self.accept_invalid_hostnames = accept_invalid_hostnames;
        self
    }

    /// Creates a new `TlsConnector`.
    pub fn build(&self) -> TlsConnector {
        TlsConnector::new(self)
    }
}


#[derive(Clone)]
pub struct TlsConnector {
    identity: Option<Identity<'a>>,
    min_protocol: Option<Protocol>,
    max_protocol: Option<Protocol>,
    root_certificates: Certificate<'a>,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
    use_sni: bool,
}

impl<'a> TlsConnector {

    pub fn new(builder : TlsConnectorBuilder) -> Self{
        Self{
            identity : builder.identity, 
            min_protocol : builder.min_protocol, 
            max_protocol : builder.max_protocol, 
            root_certificates : builder.root_certificates, 
            accept_invalid_certs : builder.accept_invalid_certs, 
            accept_invalid_hostnames : builder.accept_invalid_hostnames, 
            use_sni : builder.use_sni, 
        }
    }

    pub fn identity(&self) -> Option<Identity<'a>>{
        self.identity
    }

    pub fn min_protocol(&self) -> Option<Protocol>{
        self.min_protocol
    }

    pub fn max_protocol(&self) -> Option<Protocol>{
        self.max_protocol
    }

    pub fn root_certificates(&self) -> Certificate<'a>{
        self.root_certificates
    }

    pub fn accept_invalid_certs(&self) -> bool{
        self.accept_invalid_certs
    }

    pub fn accept_invalid_hostnames(&self) -> bool{
        self.accept_invalid_hostnames
    }

    pub fn use_sni(&self) -> bool{
        self.use_sni
    }
}
