<?php
/**
 * Cookie-keeping HTTP client for the end-to-end suite (curl, redirects not followed).
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

namespace MaxtDesign\Mfa\Tests\E2e;

// phpcs:ignoreFile

final class Browser {

	/** @var array<string, string> */
	public array $cookies = array();

	/**
	 * Every URL requested and every redirect target seen.
	 *
	 * @var string[]
	 */
	public array $history = array();

	public function __construct( private readonly string $base ) {
	}

	/**
	 * @param array<string, string|int> $form
	 */
	public function get( string $path ): Response {
		return $this->run( $this->handle( 'GET', $path, array() ) );
	}

	/**
	 * @param array<string, string|int> $form
	 */
	public function post( string $path, array $form ): Response {
		return $this->run( $this->handle( 'POST', $path, $form ) );
	}

	/**
	 * Sends several POSTs at the same time with the current cookies.
	 *
	 * @param array<int, array{string, array<string, string|int>}> $requests
	 * @return Response[]
	 */
	public function post_concurrently( array $requests ): array {
		$multi   = curl_multi_init();
		$handles = array();
		foreach ( $requests as $i => list( $path, $form ) ) {
			$handles[ $i ] = $this->handle( 'POST', $path, $form );
			curl_multi_add_handle( $multi, $handles[ $i ] );
		}
		do {
			$status = curl_multi_exec( $multi, $running );
			if ( $running ) {
				curl_multi_select( $multi, 1.0 );
			}
		} while ( $running && CURLM_OK === $status );

		$responses = array();
		foreach ( $handles as $i => $handle ) {
			$responses[ $i ] = $this->parse( (string) curl_multi_getcontent( $handle ), (int) curl_getinfo( $handle, CURLINFO_RESPONSE_CODE ), (int) curl_getinfo( $handle, CURLINFO_HEADER_SIZE ) );
			curl_multi_remove_handle( $multi, $handle );
		}
		curl_multi_close( $multi );

		return $responses;
	}

	public function has_cookie_prefix( string $prefix ): bool {
		foreach ( $this->cookies as $name => $value ) {
			if ( str_starts_with( $name, $prefix ) && '' !== $value ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param array<string, string|int> $form
	 */
	private function handle( string $method, string $path, array $form ): \CurlHandle {
		$url             = str_starts_with( $path, 'http' ) ? $path : rtrim( $this->base, '/' ) . '/' . ltrim( $path, '/' );
		$this->history[] = $url;
		$handle          = curl_init( $url );
		$pairs  = array();
		foreach ( $this->cookies as $name => $value ) {
			$pairs[] = $name . '=' . $value;
		}
		curl_setopt_array(
			$handle,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HEADER         => true,
				CURLOPT_FOLLOWLOCATION => false,
				CURLOPT_TIMEOUT        => 30,
				CURLOPT_CUSTOMREQUEST  => $method,
				CURLOPT_COOKIE         => implode( '; ', $pairs ),
			)
		);
		if ( 'POST' === $method ) {
			curl_setopt( $handle, CURLOPT_POSTFIELDS, http_build_query( $form ) );
		}
		return $handle;
	}

	private function run( \CurlHandle $handle ): Response {
		$raw = curl_exec( $handle );
		if ( ! is_string( $raw ) ) {
			throw new \RuntimeException( 'HTTP request failed: ' . curl_error( $handle ) );
		}
		return $this->parse( $raw, (int) curl_getinfo( $handle, CURLINFO_RESPONSE_CODE ), (int) curl_getinfo( $handle, CURLINFO_HEADER_SIZE ) );
	}

	private function parse( string $raw, int $status, int $header_size ): Response {
		$head    = substr( $raw, 0, $header_size );
		$body    = substr( $raw, $header_size );
		$headers = array();
		$set     = array();
		foreach ( preg_split( '/\r?\n/', $head ) ?: array() as $line ) {
			if ( ! str_contains( $line, ':' ) ) {
				continue;
			}
			list( $name, $value ) = array_map( 'trim', explode( ':', $line, 2 ) );
			$lower                = strtolower( $name );
			if ( 'set-cookie' === $lower ) {
				$set[] = $value;
				$this->store_cookie( $value );
			} else {
				$headers[ $lower ] = $value;
			}
		}
		if ( isset( $headers['location'] ) ) {
			$this->history[] = $headers['location'];
		}
		return new Response( $status, $headers, $body, $set );
	}

	private function store_cookie( string $header ): void {
		list( $name, $value ) = self::cookie_pair( $header );
		if ( self::cookie_is_live( $header ) ) {
			$this->cookies[ $name ] = $value;
		} else {
			unset( $this->cookies[ $name ] );
		}
	}

	/**
	 * @return array{string, string}
	 */
	public static function cookie_pair( string $header ): array {
		$first = explode( ';', $header, 2 )[0];
		list( $name, $value ) = array_pad( explode( '=', $first, 2 ), 2, '' );
		return array( trim( $name ), trim( $value ) );
	}

	/**
	 * False for a Set-Cookie that deletes the cookie (empty value or a past expiry).
	 */
	public static function cookie_is_live( string $header ): bool {
		list( , $value ) = self::cookie_pair( $header );
		if ( '' === $value || 'deleted' === $value ) {
			return false;
		}
		foreach ( array_slice( array_map( 'trim', explode( ';', $header ) ), 1 ) as $attribute ) {
			if ( 0 === stripos( $attribute, 'expires=' ) ) {
				$when = strtotime( substr( $attribute, 8 ) );
				if ( false !== $when && $when < time() ) {
					return false;
				}
			}
			if ( 0 === stripos( $attribute, 'max-age=' ) && (int) substr( $attribute, 8 ) <= 0 ) {
				return false;
			}
		}
		return true;
	}
}

final class Response {
	/**
	 * @param array<string, string> $headers
	 * @param string[]              $set_cookies
	 */
	public function __construct(
		public readonly int $status,
		public readonly array $headers,
		public readonly string $body,
		public readonly array $set_cookies
	) {
	}

	public function location(): string {
		return $this->headers['location'] ?? '';
	}

	public function sets_cookie_prefix( string $prefix ): bool {
		foreach ( $this->set_cookies as $cookie ) {
			if ( str_starts_with( $cookie, $prefix ) && Browser::cookie_is_live( $cookie ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Value of a named input in the body.
	 */
	public function input( string $name ): string {
		if ( 1 !== preg_match( '/<input[^>]*name="' . preg_quote( $name, '/' ) . '"[^>]*value="([^"]*)"/', $this->body, $m )
			&& 1 !== preg_match( '/<input[^>]*value="([^"]*)"[^>]*name="' . preg_quote( $name, '/' ) . '"/', $this->body, $m ) ) {
			throw new \RuntimeException( "No input {$name} in response ({$this->status}):
" . substr( strip_tags( $this->body ), 0, 600 ) );
		}
		return html_entity_decode( $m[1], ENT_QUOTES );
	}

	public function form_token(): string {
		if ( 1 !== preg_match( '/name="mdmfa_form" value="([0-9a-f]{64})"/', $this->body, $m ) ) {
			throw new \RuntimeException( "No mdmfa_form token in response ({$this->status}):\n" . substr( strip_tags( $this->body ), 0, 600 ) );
		}
		return $m[1];
	}
}
