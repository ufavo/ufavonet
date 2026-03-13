/*
 * Cryptography abstraction implementation.
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
#include "utime.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/packet.h"
#include "_packet.h"
#include <errno.h>
#include "_hooks.h"


#include "../include/crypto.h"
#include <sodium.h>
#include <string.h>

#if defined(__linux__)
# include <fcntl.h>
# include <unistd.h>
# include <sys/ioctl.h>
# include <linux/random.h>
#endif

inline int
crypto_init()
{
	int n, ret;
	for (n = 0, ret = -1; (ret = sodium_init()) == -1 && n < 10; n++) {
		/* 100ms */
		utime_usleep(1000 * 100);
	}
	if (ret == -1) {
		ulogf_err("Failed to initialize libsodium after 10 attempts.");
		/* sodium_init() stalling on Linux
		 * https://doc.libsodium.org/doc/usage#sodium_init-stalling-on-linux */
#if defined(__linux__) && defined(RNDGETENTCNT)
		int fd;
		int c;

		if ((fd = open("/dev/random", O_RDONLY)) != -1) {
			if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
				ulogf_err("%s",
			  "This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
			  "Upgrading the kernel, installing the rng-utils/rng-tools, jitterentropy-rngd or haveged packages may help.\n"
			  "On virtualized Linux environments, also consider using virtio-rng.\n"
			  "The lib will not start until enough entropy has been collected.\n"
			  "See: https://doc.libsodium.org/doc/usage#sodium_init-stalling-on-linux");
			}
			(void) close(fd);
		}
#endif
		return 0;
	}
	return 1;
}

inline const char *
crypto_cipher_name(uint8_t c)
{
	switch (c) {
		case ECRYPTO_ALGO_aes256gcm:
			return "AES256-GCM";
		case ECRYPTO_ALGO_aegis128l:
			return "AEGIS-128L";
		case ECRYPTO_ALGO_xchacha20poly1305_ietf:
			return "XChaCha20-Poly1305";
		default:
			break;
	}
	return "Unknown";
}

inline size_t
crypto_cipher_mac_size(uint8_t c)
{
	switch (c) {
		case ECRYPTO_ALGO_aes256gcm:
			return crypto_aead_aes256gcm_ABYTES;
		case ECRYPTO_ALGO_aegis128l:
			return crypto_aead_aegis128l_ABYTES;
		case ECRYPTO_ALGO_xchacha20poly1305_ietf:
			return crypto_aead_xchacha20poly1305_ietf_ABYTES;
		default:
			break;
	}
	return 0;
}

inline size_t
crypto_cipher_nonce_size(uint8_t c)
{
	switch (c) {
		case ECRYPTO_ALGO_aes256gcm:
			return crypto_aead_aes256gcm_NPUBBYTES;
		case ECRYPTO_ALGO_aegis128l:
			return crypto_aead_aegis128l_NPUBBYTES;
		case ECRYPTO_ALGO_xchacha20poly1305_ietf:
			return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
		default:
			break;
	}
	return 0;
}

inline size_t
crypto_cipher_key_size(uint8_t c)
{
	switch (c) {
		case ECRYPTO_ALGO_aes256gcm:
			return crypto_aead_aes256gcm_KEYBYTES;
		case ECRYPTO_ALGO_aegis128l:
			return crypto_aead_aegis128l_KEYBYTES;
		case ECRYPTO_ALGO_xchacha20poly1305_ietf:
			return crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
		default:
			break;
	}
	return 0;
}

#define _boilerplate_pkt_encrypt(pkt_in, pkt_out, overhead_bytes) \
	int err; \
	size_t m_len = (pkt_in->length - pkt_in->index); \
\
	/* write msg length */ \
	err = packet_w_vlen29(pkt_out, m_len); \
	if (err) return err; \
\
	/* get ptr to write the encrypted payload */ \
	void *out = NULL; \
	err = packet_w_deferred(pkt_out, m_len + (overhead_bytes), &out); \
	if (err) return err

#define _boilerplate_pkt_decrypt(pkt_in, pkt_out) \
	int err; \
	uint32_t m_len = 0; \
\
	/* read msg length */ \
	err = packet_r_vlen29(pkt_in, &m_len); \
	if (err) return err; \
\
	/* get ptr to write the decrypted message */ \
	void *out = NULL; \
	err = packet_w_deferred(pkt_out, m_len, &out); \
	if (err) return err

inline int
crypto_encrypt_packet_with_public_key(packet_t *restrict pkt_in, packet_t *restrict pkt_out, const uint8_t *restrict pk)
{
	_boilerplate_pkt_encrypt(pkt_in, pkt_out, crypto_box_SEALBYTES);
	if (crypto_box_seal(out, pkt_in->data + pkt_in->index, m_len, pk)) {
		ulog_errno("Failed to encrypt payload");
		return ECRYPTO_ERR_ENCRYPT;
	}
	return err;
}

inline int
crypto_decrypt_packet_with_keypair(packet_t *restrict pkt_in, packet_t *restrict pkt_out, const crypto_keypair_t *restrict kp)
{
	_boilerplate_pkt_decrypt(pkt_in, pkt_out);
	if (crypto_box_seal_open(out, pkt_in->data + pkt_in->index, m_len + crypto_box_SEALBYTES, kp->pk, kp->sk)) {
		ulogf_err("Failed to decrypt: corrupted message or not intended for this recipient");
		return ECRYPTO_ERR_DECRYPT;
	}
	return err;
}


static inline int
crypto_encrypt(cipher_ctx_t *restrict ctx, const void *restrict in, size_t in_len, const void *in_add_data, size_t in_add_data_len, void *restrict out)
{
	int ret = 0;
	switch (ctx->type) {
		case ECRYPTO_ALGO_aes256gcm:
			ret = crypto_aead_aes256gcm_encrypt(out, NULL, in, in_len, in_add_data, in_add_data_len, NULL, ctx->data, ctx->data + crypto_cipher_nonce_size(ctx->type));
			break;

		case ECRYPTO_ALGO_aegis128l:
			ret = crypto_aead_aegis128l_encrypt(out, NULL, in, in_len, in_add_data, in_add_data_len, NULL, ctx->data, ctx->data + crypto_cipher_nonce_size(ctx->type));
			break;

		case ECRYPTO_ALGO_xchacha20poly1305_ietf:
			ret = crypto_aead_xchacha20poly1305_ietf_encrypt(out, NULL, in, in_len, in_add_data, in_add_data_len, NULL, ctx->data, ctx->data + crypto_cipher_nonce_size(ctx->type));
			break;

		default:
			ulogf_wrn("Unable to encrypt. Unknown cipher.");
			return ECRYPTO_ERR_CIPHER;
	}
	if (ret) {
		ulogf_wrn("Encrypt failed (%s)", crypto_cipher_name(ctx->type));
		return ECRYPTO_ERR_ENCRYPT;
	}
	return 0;
}

static inline int
crypto_decrypt(cipher_ctx_t *restrict ctx, const void *restrict in, size_t in_len, const void *in_add_data, size_t in_add_data_len, void *restrict out)
{
	int ret = 0;
	switch (ctx->type) {
		case ECRYPTO_ALGO_aes256gcm:
			ret = crypto_aead_aes256gcm_decrypt(out, NULL, NULL, in, in_len, in_add_data, in_add_data_len, ctx->data, ctx->data + crypto_cipher_nonce_size(ctx->type));
			break;

		case ECRYPTO_ALGO_aegis128l:
			ret = crypto_aead_aegis128l_decrypt(out, NULL, NULL, in, in_len, in_add_data, in_add_data_len, ctx->data, ctx->data + crypto_cipher_nonce_size(ctx->type));
			break;

		case ECRYPTO_ALGO_xchacha20poly1305_ietf:
			ret = crypto_aead_xchacha20poly1305_ietf_decrypt(out, NULL, NULL, in, in_len, in_add_data, in_add_data_len, ctx->data, ctx->data + crypto_cipher_nonce_size(ctx->type));
			break;

		default:
			ulogf_wrn("Unable to decrypt. Unknown cipher.");
			return ECRYPTO_ERR_CIPHER;
	}
	if (ret) {
		ulogf_wrn("Decrypt failed (%s)", crypto_cipher_name(ctx->type));
		return ECRYPTO_ERR_DECRYPT;
	}
	return ret;
}

inline void
crypto_nonce_add(cipher_ctx_t *restrict ctx, uint64_t value)
{
	uint8_t inc[CRYPTO_AEAD_NONCE_MAX_BYTES];
	sodium_memzero(inc, sizeof(inc));
	memcpy(inc, &value, sizeof(value));
	sodium_add(ctx->data, inc, crypto_cipher_nonce_size(ctx->type));
}

inline void
crypto_nonce_sub(cipher_ctx_t *restrict ctx, uint64_t value)
{
	uint8_t inc[CRYPTO_AEAD_NONCE_MAX_BYTES];
	sodium_memzero(inc, sizeof(inc));
	memcpy(inc, &value, sizeof(value));
	sodium_sub(ctx->data, inc, crypto_cipher_nonce_size(ctx->type));
}

inline int
crypto_encrypt_packet(cipher_ctx_t *restrict ctx, packet_t *restrict pkt_in, packet_t *restrict pkt_out)
{
	_boilerplate_pkt_encrypt(pkt_in, pkt_out, crypto_cipher_mac_size(ctx->type));
	void *add_data = NULL;
	size_t add_data_len = 0;
	if (pkt_out->index > 0) {
		add_data = pkt_out->data;
		add_data_len = pkt_out->index - m_len - crypto_cipher_mac_size(ctx->type);
	}
	return crypto_encrypt(ctx, pkt_in->data + pkt_in->index, m_len, add_data, add_data_len, out) * 100;
}

inline int
crypto_decrypt_packet(cipher_ctx_t *restrict ctx, packet_t *restrict pkt_in, packet_t *restrict pkt_out)
{
	_boilerplate_pkt_decrypt(pkt_in, pkt_out);
	void *add_data = NULL;
	size_t add_data_len = 0;
	if (pkt_in->index > 0) {
		add_data = pkt_in->data;
		add_data_len = pkt_in->index;
	}
	return crypto_decrypt(ctx, pkt_in->data + pkt_in->index, m_len + crypto_cipher_mac_size(ctx->type), add_data, add_data_len, out) * 100;
}

const uint8_t *
crypto_cipher_benchmark(uint32_t itercnt)
{
	static uint8_t 	cipherv[ECRYPTO_ALGO_COUNT + 1];
	int_fast64_t 	timev[ECRYPTO_ALGO_COUNT] = {0};

	memset(cipherv, 0, sizeof(cipherv));

	cipher_ctx_t ctx;
	randombytes_buf(&ctx, sizeof(ctx));

	uint8_t msg[512];
	randombytes_buf(msg, sizeof(msg));

	uint8_t out[sizeof(msg) + CRYPTO_AEAD_ABYTES_MAX];

	ulogf_inf("Benchmarking cipher algorithms... (for each cipher, encrypt %zu bytes %"PRIu32" times)", sizeof(msg), itercnt);

	uint8_t i, j;
	for (i = 0; i < ECRYPTO_ALGO_COUNT; i++) {
		ctx.type = i;
		int_fast64_t result;
		if (crypto_encrypt(&ctx, msg, sizeof(msg), NULL, 0, out)) {
			ulogf_wrn("%s failed (not supported by hardware?)", crypto_cipher_name(i));
			result = INT_FAST64_MAX;
			goto insert;
		}

		uint32_t n;
		utime_t t = {0};
		utime_remaining(&t, 0);
		
		for (n = 0; n < itercnt; n++) {
			crypto_encrypt(&ctx, msg, sizeof(msg), NULL, 0, out);
		}

		result = -utime_remaining(&t, 0);
		ulogf_inf("%s took %.03lfms", crypto_cipher_name(i), (double)result / 1000.0);

insert:
		/* insertion sort */
		for (j = i; j > 0 && timev[j-1] > result; j--) {
			timev[j] = timev[j-1];
			cipherv[j] = cipherv[j-1];
		}
		timev[j] = result;
		cipherv[j] = i+1;
	}

	/* remove failures */
	for (i = 0; i < ECRYPTO_ALGO_COUNT; i++)
		if (timev[i] == INT_FAST64_MAX)
			cipherv[i] = 0;

	return cipherv;
}
