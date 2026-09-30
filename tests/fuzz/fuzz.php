<?php
/**
 * Seeded mutation fuzzer for the WebAuthn parsers (plan 12, P5 DoD). Starts from real
 * ceremony bytes (three algorithms, registration and assertion), mutates them (bit flips,
 * byte writes, inserts, deletes, truncation, CBOR length bumps, splices), and feeds every
 * parser and both ceremonies. Allowed outcomes: a normal return or a
 * VerificationException. Any other throwable, any PHP warning or notice, or an input that
 * takes longer than MAX_MS is a failure: the reproducer is printed and the exit code is 1.
 *
 * Usage: php tests/fuzz/fuzz.php [iterations=20000] [seed=random]
 *
 * @package MaxtDesign\Mfa
 */

declare(strict_types=1);

// phpcs:ignoreFile

define( 'ABSPATH', sys_get_temp_dir() . '/mdmfa-fuzz/' );
require dirname( __DIR__, 2 ) . '/vendor/autoload.php';

use MaxtDesign\Mfa\Support\Base64Url;
use MaxtDesign\Mfa\Tests\Support\VirtualAuthenticator;
use MaxtDesign\Mfa\WebAuthn\AuthenticatorData;
use MaxtDesign\Mfa\WebAuthn\Cbor;
use MaxtDesign\Mfa\WebAuthn\ClientData;
use MaxtDesign\Mfa\WebAuthn\CoseKey;
use MaxtDesign\Mfa\WebAuthn\CredentialJson;
use MaxtDesign\Mfa\WebAuthn\VerificationException;
use MaxtDesign\Mfa\WebAuthn\Verifier;

const MAX_MS = 250;
const RP     = 'shop.example';
const ORIGIN = 'https://shop.example';

$iterations = (int) ( $argv[1] ?? 20000 );
$seed       = isset( $argv[2] ) ? (int) $argv[2] : random_int( 1, PHP_INT_MAX >> 1 );
mt_srand( $seed );

set_error_handler(
	static function ( int $severity, string $message, string $file, int $line ): bool {
		throw new ErrorException( $message, 0, $severity, $file, $line );
	}
);

// Corpus: real bytes for every structure the parsers see.
$challenge = str_repeat( "\x42", 32 );
$corpus    = array();
$keys      = array();
foreach ( array( -7, -257, -8 ) as $alg ) {
	$a      = new VirtualAuthenticator( $alg );
	$create = json_decode(
		$a->create(
			array(
				'rp'        => array( 'id' => RP, 'name' => 'Shop' ),
				'user'      => array( 'id' => Base64Url::encode( random_bytes( 32 ) ), 'name' => 'u', 'displayName' => 'u' ),
				'challenge' => Base64Url::encode( $challenge ),
			),
			ORIGIN
		),
		true
	);
	$get    = json_decode( $a->get( array( 'rpId' => RP, 'challenge' => Base64Url::encode( $challenge ) ), ORIGIN ), true );
	$att    = (string) Base64Url::decode( $create['response']['attestationObject'] );
	$corpus['attestationObject'][] = $att;
	$corpus['authData'][]          = (string) Base64Url::decode( $get['response']['authenticatorData'] );
	$corpus['cose'][]              = $a->cose();
	$corpus['clientData'][]        = (string) Base64Url::decode( $create['response']['clientDataJSON'] );
	$corpus['credentialJson'][]    = json_encode( $create );
	$corpus['credentialJson'][]    = json_encode( $get );
	$keys[]                        = array( $a->cose(), $get );
}
// The attested authData inside each attestationObject is its own corpus entry.
foreach ( $corpus['attestationObject'] as $att ) {
	$decoded                = Cbor::decode( $att );
	$corpus['authData'][]   = $decoded['authData']->bytes;
}

$targets = array(
	'cbor'           => static fn ( string $in ) => Cbor::decode( $in ),
	'authData'       => static fn ( string $in ) => AuthenticatorData::parse( $in ),
	'cose'           => static fn ( string $in ) => CoseKey::from_cbor( $in )->loads(),
	'clientData'     => static fn ( string $in ) => ClientData::verify( $in, 'webauthn.create', $challenge, array( ORIGIN ) ),
	'credentialJson' => static fn ( string $in ) => array( CredentialJson::assertion( $in ), CredentialJson::registration( $in ) ),
	'register'       => static fn ( string $in ) => Verifier::register( $corpus['clientData'][0], $in, $challenge, RP, array( ORIGIN ), false ),
	'assert'         => static function ( string $in ) use ( $keys, $challenge ) {
		$c = CredentialJson::assertion( json_encode( $keys[0][1] ) );
		return Verifier::assert( $keys[0][0], 0, $c->client_data_json, $in, $c->signature, $challenge, RP, array( ORIGIN ), false );
	},
);
$sources = array(
	'cbor'           => array_merge( $corpus['attestationObject'], $corpus['cose'] ),
	'authData'       => $corpus['authData'],
	'cose'           => $corpus['cose'],
	'clientData'     => $corpus['clientData'],
	'credentialJson' => $corpus['credentialJson'],
	'register'       => $corpus['attestationObject'],
	'assert'         => $corpus['authData'],
);

/**
 * One random mutation (sometimes several stacked).
 */
function mutate( string $input, array $pool ): string {
	$rounds = mt_rand( 1, 4 );
	for ( $r = 0; $r < $rounds; $r++ ) {
		$len = strlen( $input );
		$pos = $len > 0 ? mt_rand( 0, $len - 1 ) : 0;
		switch ( mt_rand( 0, 8 ) ) {
			case 0: // Bit flip.
				if ( $len ) {
					$input[ $pos ] = chr( ord( $input[ $pos ] ) ^ ( 1 << mt_rand( 0, 7 ) ) );
				}
				break;
			case 1: // Random byte.
				if ( $len ) {
					$input[ $pos ] = chr( mt_rand( 0, 255 ) );
				}
				break;
			case 2: // Interesting byte: CBOR heads with large or indefinite lengths.
				if ( $len ) {
					$interesting   = array( 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x3b, 0x5a, 0x5b, 0x5f, 0x7a, 0x7f, 0x9a, 0x9b, 0x9f, 0xba, 0xbb, 0xbf, 0xc2, 0xf9, 0xfb, 0xff, 0x00, 0x80 );
					$input[ $pos ] = chr( $interesting[ array_rand( $interesting ) ] );
				}
				break;
			case 3: // Insert random bytes.
				$input = substr( $input, 0, $pos ) . random_bytes( mt_rand( 1, 8 ) ) . substr( $input, $pos );
				break;
			case 4: // Delete a run.
				$input = substr( $input, 0, $pos ) . substr( $input, $pos + mt_rand( 1, 16 ) );
				break;
			case 5: // Truncate.
				$input = substr( $input, 0, $pos );
				break;
			case 6: // Duplicate a chunk.
				$input = substr( $input, 0, $pos ) . substr( $input, $pos, mt_rand( 1, 32 ) ) . substr( $input, $pos );
				break;
			case 7: // Splice with another corpus entry.
				$other = $pool[ array_rand( $pool ) ];
				$input = substr( $input, 0, $pos ) . substr( $other, mt_rand( 0, max( 0, strlen( $other ) - 1 ) ) );
				break;
			default: // 16-bit length field bump.
				if ( $len > 1 ) {
					$input = substr( $input, 0, $pos ) . pack( 'n', mt_rand( 0, 0xFFFF ) ) . substr( $input, $pos + 2 );
				}
		}
	}
	return $input;
}

$started   = microtime( true );
$accepted  = 0;
$rejected  = 0;
$slowest   = 0.0;
$names     = array_keys( $targets );
for ( $i = 0; $i < $iterations; $i++ ) {
	$name  = $names[ $i % count( $names ) ];
	$pool  = $sources[ $name ];
	$input = mutate( $pool[ array_rand( $pool ) ], $pool );
	$t0    = microtime( true );
	try {
		( $targets[ $name ] )( $input );
		++$accepted;
	} catch ( VerificationException $e ) {
		++$rejected;
	} catch ( Throwable $e ) {
		fwrite( STDERR, sprintf( "CRASH target=%s seed=%d iteration=%d\n%s: %s\ninput(hex)=%s\n", $name, $seed, $i, get_class( $e ), $e->getMessage(), bin2hex( $input ) ) );
		exit( 1 );
	}
	$ms      = ( microtime( true ) - $t0 ) * 1000;
	$slowest = max( $slowest, $ms );
	if ( $ms > MAX_MS ) {
		fwrite( STDERR, sprintf( "HANG target=%s seed=%d iteration=%d took %.1f ms\ninput(hex)=%s\n", $name, $seed, $i, $ms, bin2hex( $input ) ) );
		exit( 1 );
	}
}

printf(
	"FUZZ PASSED: %d iterations, seed %d, %d targets, %d accepted, %d rejected, 0 crashes, 0 hangs, slowest %.1f ms, %.1f s, peak memory %.1f MB\n",
	$iterations,
	$seed,
	count( $targets ),
	$accepted,
	$rejected,
	$slowest,
	microtime( true ) - $started,
	memory_get_peak_usage( true ) / 1048576
);
