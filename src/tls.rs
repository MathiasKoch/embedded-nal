use crate::{addr::HostSocketAddr, AddrType, Dns, TcpClientStack};
use core::convert::{TryFrom, TryInto};
use heapless::{consts, Vec};

/// An X509 public key certificate.
#[derive(Debug, Copy, Clone)]
pub enum X509<'a> {
	Pem(&'a [u8]),
	Der(&'a [u8]),
}

impl<'a> X509<'a> {
	/// Deserializes a PEM-encoded X509 structure.
	/// The input should have a header of `-----BEGIN CERTIFICATE-----`.
	pub fn from_pem(pem: &'a [u8]) -> Self {
		Self::Pem(pem)
	}

	/// Deserializes a DER-encoded X509 structure.
	pub fn from_der(der: &'a [u8]) -> Self {
		Self::Der(der)
	}

	pub fn as_bytes(&self) -> &'a [u8] {
		match self {
			Self::Pem(bytes) => bytes,
			Self::Der(bytes) => bytes
		}
	}

	pub fn len(&self) -> usize {
		match self {
			Self::Pem(bytes) => bytes.len(),
			Self::Der(bytes) => bytes.len()
		}
	}
}

#[derive(Debug, Copy, Clone)]
pub struct Certificate<'a>(X509<'a>);

impl<'a> Certificate<'a> {
	/// Deserializes a PEM-encoded X509 structure to a `Certificate`.
	/// The input should have a header of `-----BEGIN CERTIFICATE-----`.
	pub fn from_pem(pem: &'a [u8]) -> Self {
		Self(X509::from_pem(pem))
	}

	/// Deserializes a DER-encoded X509 structure to a `Certificate`.
	pub fn from_der(der: &'a [u8]) -> Self {
		Self(X509::from_der(der))
	}

	pub fn as_bytes(&self) -> &'a [u8] {
		self.0.as_bytes()
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}
}

#[derive(Debug, Copy, Clone)]
pub enum Private {}
#[derive(Debug, Copy, Clone)]
pub enum Public {}

#[derive(Debug, Copy, Clone)]
pub struct PKey<'a, T>(&'a [u8], Option<&'a [u8]>, core::marker::PhantomData<T>);


impl<'a> PKey<'a, Private> {
	pub fn new_private(key: &'a [u8], password: Option<&'a [u8]>) -> Self {
		PKey(key, password, core::marker::PhantomData)
	}
}

impl<'a, T> PKey<'a, T> {
	pub fn as_bytes(&self) -> &'a [u8] {
		self.0
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}
}

/// An identity
#[derive(Debug, Clone)]
pub struct Identity<'a> {
	pkey: PKey<'a, Private>,
	cert: X509<'a>,
	// chain: Vec<X509<'a>, consts::U10>,
}

impl<'a> Identity<'a> {
	pub fn new(cert: X509<'a>, private_key: PKey<'a, Private>) -> Self {
		Identity {
			cert,
			pkey: private_key,
		}
	}

	pub fn private_key(&self) -> &PKey<'a, Private> {
		&self.pkey
	}

	pub fn cert(&self) -> &X509<'a> {
		&self.cert
	}
}

/// SSL/TLS protocol versions.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Protocol {
	/// The SSL 3.0 protocol.
	///
	/// # Warning
	///
	/// SSL 3.0 has severe security flaws, and should not be used unless
	/// absolutely necessary. If you are not sure if you need to enable this
	/// protocol, you should not.
	Sslv3 = 0,
	/// The TLS 1.0 protocol (default).
	Tlsv10 = 1,
	/// The TLS 1.1 protocol.
	Tlsv11 = 2,
	/// The TLS 1.2 protocol.
	Tlsv12 = 3,
}

impl Default for Protocol {
	fn default() -> Self {
		Self::Tlsv10
	}
}

trait DnsTls: Tls + Dns {
	fn connect(
		&self,
		socket: &mut <Self as TcpClientStack>::TcpSocket,
		hostname: &str,
		connector: &Self::TlsConnector,
	) -> nb::Result<(), <Self as Tls>::Error>;
}

impl<T> DnsTls for T
where
	T: Tls + Dns,
	<T as Dns>::Error: Into<<T as Tls>::Error>,
{
	fn connect(
		&self,
		socket: &mut <Self as TcpClientStack>::TcpSocket,
		addr: &str,
		connector: &Self::TlsConnector,
	) -> nb::Result<(), <Self as Tls>::Error> {
		// TODO: Document and verify `addr`
		let mut iter = addr.rsplitn(2, ':');
		let hostname = iter.next().unwrap();
		let port = iter.next().map(|p| p.parse().unwrap()).unwrap();

		let remote = Dns::get_host_by_name(self, hostname, AddrType::IPv4).map_err(|e| e.into())?;
		Tls::connect(self, socket, HostSocketAddr::new(remote, port), connector)
	}
}

/// This trait extends implementer of TCP/IP stacks with Tls capability.
pub trait Tls: TcpClientStack {
	type Error: From<<Self as TcpClientStack>::Error>;
	type TlsConnector;

	/// Connect securely to the given remote host and port.
	fn connect(
		&self,
		socket: &mut <Self as TcpClientStack>::TcpSocket,
		remote: HostSocketAddr,
		connector: &Self::TlsConnector,
	) -> nb::Result<(), <Self as Tls>::Error>;
}

// A collection of TLS configuration options plus a user-defined contextual
// data.
//
// Given a network driver implementation, say `Imp`, assume that it wants the
// configuration bits found in this struct for starting TLS connection.
//
// Provide a TLS connector type that represents the outcome of the configuration
// your driver performs and implement `TryFrom<TlsConnectorConfig<'a, Imp>>` for
// it. Then end users can start the connection by <Advertise what it has to
// offer>.
#[derive(Clone, Debug, Default)]
pub struct TlsConnectorConfig<'a, CTX> {
	context: CTX,
	identity: Option<Identity<'a>>,
	min_protocol: Protocol,
	max_protocol: Option<Protocol>,
	root_certificates: Vec<Certificate<'a>, consts::U10>,
	accept_invalid_certs: bool,
	accept_invalid_hostnames: bool,
	use_sni: bool,
}

impl<'a, CTX> TlsConnectorConfig<'a, CTX> {
	/// Returns a reference to `CTX` which has been passed to the `build` method
	/// earlier.
	pub fn context(&self) -> &CTX {
		&self.context
	}

	/// Returns an identity.
	pub fn identity(&self) -> &Option<Identity<'a>> {
		&self.identity
	}

	/// Returns the minimum supported protocol version.
	pub fn min_protocol(&self) -> &Protocol {
		&self.min_protocol
	}

	/// Returns the maximum supported protocol version.
	pub fn max_protocol(&self) -> &Option<Protocol> {
		&self.max_protocol
	}

	pub fn root_certificates(&self) -> &Vec<Certificate<'a>, consts::U10> {
		&self.root_certificates
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
			min_protocol: self.0.min_protocol,
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
	/// The method is optional. Unless explicitly called with a specific
	/// protocol version, it enables support for the oldest protocols supported
	/// by the implementation.
	///
	/// Defaults to `Protocol::Tlsv10`.
	pub fn min_protocol_version(&mut self, protocol: Protocol) -> &mut Self {
		self.0.min_protocol = protocol;
		self
	}

	/// Sets the maximum supported protocol version.
	///
	/// A value of `None` enables support for the newest protocols supported by
	/// the implementation.
	///
	/// Defaults to `None`.
	pub fn max_protocol_version(&mut self, protocol: Protocol) -> &mut Self {
		self.0.max_protocol.replace(protocol);
		self
	}

	/// Adds a certificate to the set of roots that the connector will trust.
	///
	/// The connector will use the system's trust root by default. This method
	/// can be used to add to that set when communicating with servers not
	/// trusted by the system.
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
	/// You should think very carefully before using this method. If invalid
	/// certificates are trusted, *any* certificate for *any* site will be
	/// trusted for use. This includes expired certificates. This introduces
	/// significant vulnerabilities, and should only be used as a last resort.
	pub fn danger_accept_invalid_certs(&mut self, accept_invalid_certs: bool) -> &mut Self {
		self.0.accept_invalid_certs = accept_invalid_certs;
		self
	}

	/// Controls the use of Server Name Indication (SNI).
	///
	/// Defaults to `true`, if hostname is available, either explicitly or
	/// through `Dns`.
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
	/// You should think very carefully before using this method. If invalid
	/// hostnames are trusted, *any* valid certificate for *any* site will be
	/// trusted for use. This introduces significant vulnerabilities, and should
	/// only be used as a last resort.
	pub fn danger_accept_invalid_hostnames(&mut self, accept_invalid_hostnames: bool) -> &mut Self {
		self.0.accept_invalid_hostnames = accept_invalid_hostnames;
		self
	}

	pub fn build<'b, CTX, CONN>(&'b mut self, ctx: &'b CTX) -> Result<CONN, CONN::Error>
	where
		CONN: TryFrom<TlsConnectorConfig<'a, &'b CTX>>,
	{
		self.context(ctx).try_into()
	}
}
