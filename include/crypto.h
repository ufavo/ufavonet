/*
 * Cryptography abstraction header.
 * Copyright (C) 2026  Luiz Gustavo Sassanovicz Borsoi
 *
 * This file is part of Ufavonet.
 *
 * Ufavonet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Ufavonet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef __ufavonet_crypto_h__
#define __ufavonet_crypto_h__

#include "packet.h"
#include <sodium.h>

enum {
	ECRYPTO_ALGO_aes256gcm = 0,
	ECRYPTO_ALGO_aegis128l,
	ECRYPTO_ALGO_xchacha20poly1305_ietf,

	ECRYPTO_ALGO_COUNT
};

enum {
	/* Encryption failed */
	ECRYPTO_ERR_ENCRYPT = 100,
	/* Decryption failed. Maybe corrupted, not intended for this recipient or tampered. */
	ECRYPTO_ERR_DECRYPT,
	/* Cipher not implemented / unknown */
	ECRYPTO_ERR_CIPHER,
};

#define CRYPTO_MAX(x,y) ((x)>(y)?(x):(y))

#define CRYPTO_AEAD_DATA_MAX_BYTES \
	CRYPTO_MAX(crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_KEYBYTES, \
	CRYPTO_MAX(crypto_aead_aegis128l_NPUBBYTES + crypto_aead_aegis128l_KEYBYTES, \
	crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_KEYBYTES \
))

#define CRYPTO_AEAD_NONCE_MAX_BYTES \
	CRYPTO_MAX(crypto_aead_aes256gcm_NPUBBYTES, \
	CRYPTO_MAX(crypto_aead_aegis128l_NPUBBYTES, \
	crypto_aead_xchacha20poly1305_ietf_NPUBBYTES \
))

#define CRYPTO_AEAD_ABYTES_MAX \
	CRYPTO_MAX(crypto_aead_aes256gcm_ABYTES, \
	CRYPTO_MAX(crypto_aead_aegis128l_ABYTES, \
	crypto_aead_xchacha20poly1305_ietf_ABYTES \
))

typedef struct {
	uint8_t type;
	/* nonce bytes followed by key bytes */
	uint8_t data[CRYPTO_AEAD_DATA_MAX_BYTES];
} cipher_ctx_t;

typedef struct {
	uint8_t pk[crypto_box_PUBLICKEYBYTES];
	uint8_t sk[crypto_box_SECRETKEYBYTES];
} crypto_keypair_t;

/* Initializes libsodium.
 * Should be called at least once but can be called multiple times, even after success.
 * Returns 1 on success and 0 on failure.
 * On success, libsodium functions and other `crypto_` functions defined in this header can be used.
 * It's not necessary to call this function if the usage of crypto functions happens after successfully initializing 
 * at least one `netconn_t` from `net` header as it calls this function internally. */
int crypto_init() __attribute__((warn_unused_result));

const char *crypto_cipher_name(uint8_t c);
size_t 		crypto_cipher_mac_size(uint8_t c);
size_t 		crypto_cipher_nonce_size(uint8_t c);
size_t 		crypto_cipher_key_size(uint8_t c);

/* Reads whatever is left to be read from packet `pkt_in`, encrypts with `pk` and writes the encrypted result to `pkt_out`.
 * Internally uses libsodium's `crypto_box_seal` function.
 * If encrypting the entire packet is desired make sure to rewind the `pkt_in` packet before calling this function.
 * Returns EPACKET_ERR_NONE on success. Otherwise ECRYPTO_ERR_ENCRYPT, or other `EPACKET_ERR_*` error. */
int		crypto_encrypt_packet_with_public_key(packet_t *restrict pkt_in, packet_t *restrict pkt_out, const uint8_t *restrict pk);

/* Reads the encrypted payload from packet `pkt_in`, decrypts with `kp` and writes the decrypted result to `pkt_out`.
 * Internally uses libsodium's `crypto_box_seal_open` function.
 * Returns EPACKET_ERR_NONE on success. Otherwise ECRYPTO_ERR_DECRYPT, or other `EPACKET_ERR_*` error. */
int		crypto_decrypt_packet_with_keypair(packet_t *restrict pkt_in, packet_t *restrict pkt_out, const crypto_keypair_t *restrict kp);

void	crypto_nonce_add(cipher_ctx_t *restrict ctx, uint64_t value);
void	crypto_nonce_sub(cipher_ctx_t *restrict ctx, uint64_t value);

/* Reads whatever is left to be read from packet `pkt_in`, encrypts with `ctx` and writes the encrypted result to `pkt_out`.
 * Internally uses one of libsodium's `crypto_aead_*` functions depending on `ctx->type`.
 * If encrypting the entire packet is desired make sure to rewind the `pkt_in` packet before calling this function.
 * Returns EPACKET_ERR_NONE on success. Otherwise ECRYPTO_ERR_ENCRYPT, ECRYPTO_ERR_CIPHER, or other `EPACKET_ERR_*` error.
 * Content present in `pkt_out` up to the packet's current index is treated as additional unencrypted data (authenticated) and must be present during decryption. */
int		crypto_encrypt_packet(cipher_ctx_t *restrict ctx, packet_t *restrict pkt_in, packet_t *restrict pkt_out);

/* Reads the encrypted payload from packet `pkt_in`, decrypts with `ctx` and writes the decrypted result to `pkt_out`.
 * Internally uses one of libsodium's `crypto_aead_*` functions depending on `ctx->type`.
 * Returns EPACKET_ERR_NONE on success. Otherwise ECRYPTO_ERR_DECRYPT, ECRYPTO_ERR_CIPHER, or other `EPACKET_ERR_*` error.
 * Content present in `pkt_out` up to the packet's current index is treated as additional unencrypted data (authenticated) and must be the same as encryption. */
int		crypto_decrypt_packet(cipher_ctx_t *restrict ctx, packet_t *restrict pkt_in, packet_t *restrict pkt_out);

/* Benchmarks all available algorithms (encrypt only) `itercnt` times each and returns an internal static ptr to a null terminated vector.
 * The vector is sorted from the fastest to slowest `ECRYPTO_ALGO_* + 1`. */
const uint8_t 	*crypto_cipher_benchmark(uint32_t itercnt);

#endif
