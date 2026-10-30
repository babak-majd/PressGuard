<?php
/**
 * Minimal ACME v2 client (Let's Encrypt).
 *
 * @package PressGuard
 */

namespace PressGuard\Core\Ssl;

defined( 'ABSPATH' ) || exit;

/**
 * A compact, dependency-free ACME v2 client built on OpenSSL + the WP HTTP API.
 * Supports account registration, orders, the HTTP-01 and DNS-01 challenge data,
 * CSR finalization and certificate download. Uses an RSA account key with
 * RS256 JWS. Network/protocol errors throw RuntimeException so the caller can
 * surface a clear message.
 *
 * Production directory: https://acme-v02.api.letsencrypt.org/directory
 * Staging (for testing): https://acme-staging-v02.api.letsencrypt.org/directory
 */
final class Acme {

	/**
	 * Account private key (PEM).
	 *
	 * @var string
	 */
	private $account_key;

	/**
	 * ACME directory URL.
	 *
	 * @var string
	 */
	private $directory_url;

	/**
	 * Cached directory resource map.
	 *
	 * @var array|null
	 */
	private $directory = null;

	/**
	 * Most recent replay nonce.
	 *
	 * @var string
	 */
	private $nonce = '';

	/**
	 * Account URL (kid) after registration.
	 *
	 * @var string
	 */
	private $kid = '';

	/**
	 * Constructor.
	 *
	 * @param string $account_key_pem Account private key (PEM).
	 * @param string $directory_url   ACME directory URL.
	 */
	public function __construct( $account_key_pem, $directory_url ) {
		$this->account_key   = $account_key_pem;
		$this->directory_url = $directory_url;
	}

	/**
	 * Generate a fresh RSA private key (PEM) — for the account or a certificate.
	 *
	 * @param int $bits Key size.
	 * @return string PEM.
	 */
	public static function generate_rsa_key( $bits = 2048 ) {
		$res = openssl_pkey_new(
			array(
				'private_key_bits' => $bits,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
			)
		);
		openssl_pkey_export( $res, $pem );
		return $pem;
	}

	/**
	 * base64url encode.
	 *
	 * @param string $data Raw.
	 * @return string
	 */
	public static function b64( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * The account public JWK.
	 *
	 * @return array
	 */
	private function jwk() {
		$details = openssl_pkey_get_details( openssl_pkey_get_private( $this->account_key ) );
		return array(
			'e'   => self::b64( $details['rsa']['e'] ),
			'kty' => 'RSA',
			'n'   => self::b64( $details['rsa']['n'] ),
		);
	}

	/**
	 * The JWK SHA-256 thumbprint (for key authorizations).
	 *
	 * @return string
	 */
	public function thumbprint() {
		$jwk = $this->jwk();
		// Canonical JSON: keys sorted, no whitespace.
		$json = '{"e":"' . $jwk['e'] . '","kty":"RSA","n":"' . $jwk['n'] . '"}';
		return self::b64( hash( 'sha256', $json, true ) );
	}

	/**
	 * The key authorization for a challenge token.
	 *
	 * @param string $token Challenge token.
	 * @return string
	 */
	public function key_authorization( $token ) {
		return $token . '.' . $this->thumbprint();
	}

	/**
	 * For DNS-01: the TXT value is the base64url SHA-256 of the key auth.
	 *
	 * @param string $token Challenge token.
	 * @return string
	 */
	public function dns_txt_value( $token ) {
		return self::b64( hash( 'sha256', $this->key_authorization( $token ), true ) );
	}

	/**
	 * Load the ACME directory.
	 *
	 * @return array
	 */
	private function directory() {
		if ( null === $this->directory ) {
			$res             = $this->http_get( $this->directory_url );
			$this->directory = json_decode( $res['body'], true );
			if ( ! is_array( $this->directory ) ) {
				throw new \RuntimeException( 'Invalid ACME directory response.' );
			}
		}
		return $this->directory;
	}

	/**
	 * Fetch a fresh nonce.
	 */
	private function refresh_nonce() {
		$dir = $this->directory();
		$res = wp_remote_head( $dir['newNonce'], array( 'timeout' => 20 ) );
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( 'Failed to get ACME nonce.' );
		}
		$this->nonce = wp_remote_retrieve_header( $res, 'replay-nonce' );
	}

	/**
	 * Sign and send a JWS request.
	 *
	 * @param string            $url     Target URL.
	 * @param array|string|null $payload Payload (array to JSON; '' for POST-as-GET; null = {}).
	 * @return array{status:int,headers:array,body:string,location:string}
	 */
	private function signed_request( $url, $payload = null ) {
		if ( '' === $this->nonce ) {
			$this->refresh_nonce();
		}

		$protected = array(
			'alg'   => 'RS256',
			'nonce' => $this->nonce,
			'url'   => $url,
		);
		if ( '' !== $this->kid ) {
			$protected['kid'] = $this->kid;
		} else {
			$protected['jwk'] = $this->jwk();
		}

		$protected64 = self::b64( wp_json_encode( $protected ) );
		if ( '' === $payload || ( is_array( $payload ) && empty( $payload ) && null !== $payload ) ) {
			$payload64 = '';
		} else {
			$payload64 = self::b64( is_array( $payload ) ? wp_json_encode( $payload ) : (string) $payload );
		}

		$signature = '';
		openssl_sign( $protected64 . '.' . $payload64, $signature, openssl_pkey_get_private( $this->account_key ), 'SHA256' );

		$body = wp_json_encode(
			array(
				'protected' => $protected64,
				'payload'   => $payload64,
				'signature' => self::b64( $signature ),
			)
		);

		$res = wp_remote_post(
			$url,
			array(
				'timeout' => 30,
				'headers' => array( 'Content-Type' => 'application/jose+json' ),
				'body'    => $body,
			)
		);
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( 'ACME request failed: ' . $res->get_error_message() );
		}

		// Every ACME response carries the next nonce.
		$this->nonce = wp_remote_retrieve_header( $res, 'replay-nonce' );

		return array(
			'status'   => (int) wp_remote_retrieve_response_code( $res ),
			'headers'  => wp_remote_retrieve_headers( $res ),
			'body'     => wp_remote_retrieve_body( $res ),
			'location' => wp_remote_retrieve_header( $res, 'location' ),
		);
	}

	/**
	 * Plain GET helper.
	 *
	 * @param string $url URL.
	 * @return array{status:int,body:string}
	 */
	private function http_get( $url ) {
		$res = wp_remote_get( $url, array( 'timeout' => 20 ) );
		if ( is_wp_error( $res ) ) {
			throw new \RuntimeException( 'ACME GET failed: ' . $res->get_error_message() );
		}
		return array(
			'status' => (int) wp_remote_retrieve_response_code( $res ),
			'body'   => wp_remote_retrieve_body( $res ),
		);
	}

	/**
	 * Register (or reuse) the ACME account.
	 *
	 * @param string $email Contact email.
	 */
	public function register_account( $email ) {
		$dir = $this->directory();
		$res = $this->signed_request(
			$dir['newAccount'],
			array(
				'termsOfServiceAgreed' => true,
				'contact'              => array( 'mailto:' . $email ),
			)
		);
		if ( $res['status'] >= 400 ) {
			throw new \RuntimeException( 'ACME account registration failed: ' . $res['body'] );
		}
		$this->kid = $res['location'];
	}

	/**
	 * Create a new order for the given domains.
	 *
	 * @param string[] $domains Domains.
	 * @return array{order:array,order_url:string}
	 */
	public function new_order( array $domains ) {
		$dir         = $this->directory();
		$identifiers = array();
		foreach ( $domains as $d ) {
			$identifiers[] = array(
				'type'  => 'dns',
				'value' => $d,
			);
		}
		$res = $this->signed_request( $dir['newOrder'], array( 'identifiers' => $identifiers ) );
		if ( $res['status'] >= 400 ) {
			throw new \RuntimeException( 'ACME new order failed: ' . $res['body'] );
		}
		return array(
			'order'     => json_decode( $res['body'], true ),
			'order_url' => $res['location'],
		);
	}

	/**
	 * Fetch an authorization object (POST-as-GET).
	 *
	 * @param string $url Authorization URL.
	 * @return array
	 */
	public function get_authorization( $url ) {
		$res = $this->signed_request( $url, '' );
		return json_decode( $res['body'], true );
	}

	/**
	 * Tell the ACME server a challenge is ready to validate.
	 *
	 * @param string $challenge_url Challenge URL.
	 * @return array
	 */
	public function notify_ready( $challenge_url ) {
		$res = $this->signed_request( $challenge_url, array() );
		return json_decode( $res['body'], true );
	}

	/**
	 * Poll an authorization until valid/invalid.
	 *
	 * @param string $url     Authorization URL.
	 * @param int    $tries   Max polls.
	 * @return string Final status.
	 */
	public function poll_authorization( $url, $tries = 15 ) {
		for ( $i = 0; $i < $tries; $i++ ) {
			$authz  = $this->get_authorization( $url );
			$status = $authz['status'] ?? 'pending';
			if ( 'pending' !== $status && 'processing' !== $status ) {
				return $status;
			}
			sleep( 2 );
		}
		return 'timeout';
	}

	/**
	 * Build a DER CSR for the domains using the given certificate key.
	 *
	 * @param string[] $domains  Domains (first is CN).
	 * @param string   $cert_key Certificate private key (PEM).
	 * @return string DER-encoded CSR.
	 */
	public static function make_csr( array $domains, $cert_key ) {
		$san = array();
		foreach ( $domains as $d ) {
			$san[] = 'DNS:' . $d;
		}

		$config = array( 'digest_alg' => 'sha256' );
		$dn     = array( 'commonName' => $domains[0] );

		// SAN via a temporary openssl config.
		$conf = tempnam( sys_get_temp_dir(), 'pg_csr' );
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			$conf,
			"[req]\ndistinguished_name=dn\nreq_extensions=v3_req\n[dn]\n[v3_req]\nsubjectAltName=" . implode( ',', $san ) . "\n"
		);
		$config['config'] = $conf;

		$csr = openssl_csr_new( $dn, $cert_key, $config );
		@unlink( $conf ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink

		if ( ! $csr ) {
			throw new \RuntimeException( 'Failed to generate CSR.' );
		}

		openssl_csr_export( $csr, $csr_pem );
		// Convert PEM CSR to DER.
		$der = self::pem_to_der( $csr_pem, 'CERTIFICATE REQUEST' );
		return $der;
	}

	/**
	 * Finalize the order with the CSR, then poll + download the certificate.
	 *
	 * @param array  $order    Order object.
	 * @param string $cert_key Certificate private key (PEM).
	 * @param string[] $domains Domains.
	 * @return string Certificate chain (PEM).
	 */
	public function finalize_and_download( $order, $cert_key, array $domains ) {
		$der = self::make_csr( $domains, $cert_key );
		$res = $this->signed_request( $order['finalize'], array( 'csr' => self::b64( $der ) ) );
		if ( $res['status'] >= 400 ) {
			throw new \RuntimeException( 'ACME finalize failed: ' . $res['body'] );
		}

		$order_url = $res['location'];
		$cert_url  = '';
		for ( $i = 0; $i < 15; $i++ ) {
			$poll = $this->signed_request( $order_url, '' );
			$obj  = json_decode( $poll['body'], true );
			if ( 'valid' === ( $obj['status'] ?? '' ) && ! empty( $obj['certificate'] ) ) {
				$cert_url = $obj['certificate'];
				break;
			}
			if ( 'invalid' === ( $obj['status'] ?? '' ) ) {
				throw new \RuntimeException( 'ACME order became invalid.' );
			}
			sleep( 2 );
		}
		if ( '' === $cert_url ) {
			throw new \RuntimeException( 'Certificate was not issued in time.' );
		}

		$cert = $this->signed_request( $cert_url, '' );
		return $cert['body'];
	}

	/**
	 * Convert a PEM block to raw DER.
	 *
	 * @param string $pem   PEM text.
	 * @param string $label Block label.
	 * @return string
	 */
	private static function pem_to_der( $pem, $label ) {
		$pem = preg_replace( '/-----BEGIN ' . $label . '-----|-----END ' . $label . '-----|\s+/', '', $pem );
		return base64_decode( $pem ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	}
}
