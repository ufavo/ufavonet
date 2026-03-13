/*
 * Handshake implementation.
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
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "_hooks.h"
#include "_packet.h"
#include "_crypto.h"
#include "handshake.h"

#define HANDSHAKE_RANDOM_SIZE 180

enum {
	EOP_GET_PUBLIC_KEY = 0,
	EOP_SETUP,
};

int
handshake_server_onestep(packet_t 				*restrict pkt_in,
						 packet_t 				*restrict pkt_out,
						 const crypto_keypair_t *restrict keypair,
						 const uint8_t 			*restrict prefered_ciphers,
						 crypto_ctx_t 			*restrict out,
						 uint16_t 				local_tick,
						 uint16_t 				client_remote_tick,
						 uint8_t 				allow_pk_distribution)
{
	if (packet_get_readable(pkt_in) == 0)
		return EHANDSHAKE_ERR_INPUT;

	int err = 0;
	uint8_t op = UINT8_MAX;
	packet_r_8_t(pkt_in, &op);
	if (op == EOP_GET_PUBLIC_KEY) {
		if (!allow_pk_distribution) {
			ulogf_inf("Client asked for public key. Refusing.");
			return EHANDSHAKE_ERR_REFUSED;
		}
		ulogf_dbg("Client asked for public key");
		err = packet_w_8_t(pkt_out, &op);
		if (err) return EHANDSHAKE_ERR_INTERNAL;
		err = packet_w(pkt_out, keypair->pk, sizeof(keypair->pk));
		if (err) return EHANDSHAKE_ERR_INTERNAL;
		return 0;
	} else if (op != EOP_SETUP) {
		return EHANDSHAKE_ERR_INPUT;
	}
	ulogf_inf("Secure setup");

	err = packet_w_8_t(pkt_out, &op);
	if (err) return EHANDSHAKE_ERR_INTERNAL;

	uint8_t buf[(HANDSHAKE_RANDOM_SIZE*2) + ECRYPTO_ALGO_COUNT + 1];
	packet_t tmp;
	_packet_init_from_buf(&tmp, buf, sizeof(buf));

	/* decrypt */
	err = crypto_decrypt_packet_with_keypair(pkt_in, &tmp, keypair);
	if (err == ECRYPTO_ERR_DECRYPT) return EHANDSHAKE_ERR_DECRYPT;
	else if (err) return EHANDSHAKE_ERR_INTERNAL;
	packet_rewind(&tmp);

	/* read ciphers */
	uint8_t cipher = 0;
	uint8_t cipher_idx = 0;
	do {
		do {
			err = packet_r_8_t(&tmp, &cipher);
			if (err) return EHANDSHAKE_ERR_INPUT;
			
			if (cipher == prefered_ciphers[cipher_idx]) {
				ulogf_inf("Chosen cipher: %s", crypto_cipher_name(cipher-1));
				/* skip all bytes up to the first zero */
				for (cipher_idx = cipher; cipher_idx && !err; err = packet_r_8_t(&tmp, &cipher_idx));
				if (err) return EHANDSHAKE_ERR_INPUT;
				goto after_cipher;
			}
		} while (cipher);
		packet_rewind(&tmp);
	} while (prefered_ciphers[++cipher_idx] && !cipher);

	if (!cipher) {
		ulogf_inf("No ciphers in common with the client. Unable to complete handshake.");
		return EHANDSHAKE_ERR_CIPHERS;
	}

after_cipher:
	/* set cipher algorithm */
	out->rx.type = out->tx.type = cipher - 1;

	/* read credentials */
	err = packet_r(&tmp, out->tx.data, sizeof(out->tx.data));
	if (err) return EHANDSHAKE_ERR_INPUT;
	err = packet_r(&tmp, out->rx.data, sizeof(out->rx.data));
	if (err) return EHANDSHAKE_ERR_INPUT;

	err = packet_r(&tmp, &out->auth_tx, sizeof(out->auth_tx));
	if (err) return EHANDSHAKE_ERR_INPUT;
	err = packet_r(&tmp, &out->auth_rx, sizeof(out->auth_rx));
	if (err) return EHANDSHAKE_ERR_INPUT;

	uint32_t available = tmp.length - tmp.index;
	if (available > 20)
		available = 20;
	else if (available <= 0)
		return EHANDSHAKE_ERR_CHECKBYTES;
	
	/* write checkbytes */
	err = packet_w(pkt_out, tmp.data + tmp.length - available, available);
	if (err) return EHANDSHAKE_ERR_INTERNAL;

	/* write cipher choice */
	err = packet_w_8_t(pkt_out, &cipher);
	if (err) return EHANDSHAKE_ERR_INTERNAL;

	/* write tick start */
	err = packet_w_16_t(pkt_out, &local_tick);
	if (err) return EHANDSHAKE_ERR_INTERNAL;

	/* write client remote tick */
	err = packet_w_16_t(pkt_out, &client_remote_tick);
	if (err) return EHANDSHAKE_ERR_INTERNAL;

	ulogf_inf("Handshake succeeded");
	ulogf_dbg("Start with nonces RX: %"PRIu8", TX: %"PRIu8, out->rx.data[0], out->tx.data[0]);
	return 1;
}

int
handshake_client_step(handshake_t 		*restrict ctx,
					  packet_t 			*restrict pkt_in,
					  packet_t 			*restrict pkt_out,
					  uint8_t 			*restrict server_pk,
					  const uint8_t 	*restrict prefered_ciphers,
					  crypto_ctx_t 		*restrict out_crypto,
					  uint16_t 			*restrict out_server_start_tick,
					  uint16_t 			*restrict out_client_start_tick)
{
	int err = 0;

	if (ctx->step == 0) {
		uint8_t op = UINT8_MAX;
		if (pkt_in->length == 0) {
			if (sodium_is_zero(server_pk, crypto_box_PUBLICKEYBYTES)) {
				ulogf_ntc("Dont have server pk. Asking for it.");
				op = EOP_GET_PUBLIC_KEY;
				ctx->asked_pk = 1;
				err = packet_w_8_t(pkt_out, &op);
				if (err) return EHANDSHAKE_ERR_INTERNAL;
				return 0;
			}

		} else if (ctx->asked_pk) {
			/* Read public key */
			uint8_t op = UINT8_MAX;
			packet_r_8_t(pkt_in, &op);
			if (op == EOP_GET_PUBLIC_KEY) {
				err = packet_r(pkt_in, server_pk, crypto_box_PUBLICKEYBYTES);
				if (err) return EHANDSHAKE_ERR_INPUT;
			} else {
				return EHANDSHAKE_ERR_INPUT;
			}
		} else {
			ulogf_ntc("Didn't asked for server's public key");
			return EHANDSHAKE_ERR_INPUT;
		}

		op = EOP_SETUP;
		err = packet_w_8_t(pkt_out, &op);
		if (err) return EHANDSHAKE_ERR_INTERNAL;
		
		ulogf_ntc("Secure setup");

		assert(HANDSHAKE_RANDOM_SIZE < (sizeof(out_crypto->rx.data)*2) + sizeof(ctx->checkbytes) + (sizeof(out_crypto->auth_rx) * 2)? !"Not enough random bytes" : 1);

		uint8_t buf[HANDSHAKE_RANDOM_SIZE + ECRYPTO_ALGO_COUNT + 1];
		packet_t tmp;
		_packet_init_from_buf(&tmp, buf, sizeof(buf));

		/* write null terminated list of prefered ciphers */
		do {
			err = packet_w_8_t(&tmp, prefered_ciphers);
			if (err) return EHANDSHAKE_ERR_INTERNAL;
		} while (*prefered_ciphers++);
		

		/* generate credentials and checkbytes */
		void *_credentials = NULL;
		err = packet_w_deferred(&tmp, HANDSHAKE_RANDOM_SIZE, &_credentials);
		if (err) return EHANDSHAKE_ERR_INTERNAL;
		randombytes_buf(_credentials, HANDSHAKE_RANDOM_SIZE);
		

		/* store credentials */
		uint8_t *credentials = _credentials;
		
		memcpy(out_crypto->rx.data, credentials, sizeof(out_crypto->rx.data));
		memcpy(out_crypto->tx.data, credentials + sizeof(out_crypto->rx.data), sizeof(out_crypto->tx.data));

		memcpy(&out_crypto->auth_rx, credentials + sizeof(out_crypto->rx.data) + sizeof(out_crypto->tx.data), sizeof(out_crypto->auth_rx));
		memcpy(&out_crypto->auth_tx, credentials + sizeof(out_crypto->rx.data) + sizeof(out_crypto->tx.data) + sizeof(out_crypto->auth_rx), sizeof(out_crypto->auth_tx));
		
		ulogf_dbg("Generated nonces RX: %"PRIu8", TX: %"PRIu8, out_crypto->rx.data[0], out_crypto->tx.data[0]);

		/* store checkbytes (last 20 bytes) */
		memcpy(ctx->checkbytes, (uint8_t *)credentials + HANDSHAKE_RANDOM_SIZE - sizeof(ctx->checkbytes), sizeof(ctx->checkbytes));

		/* encrypt */
		packet_rewind(&tmp);
		err = crypto_encrypt_packet_with_public_key(&tmp, pkt_out, server_pk);
		if (err) return EHANDSHAKE_ERR_INTERNAL;

		ctx->step++;
		return 0;

	} else if (ctx->step == 1) {

		size_t readable = packet_get_readable(pkt_in);
		if (readable < 1)
			return EHANDSHAKE_ERR_INPUT;
		
		uint8_t op = UINT8_MAX;
		packet_r_8_t(pkt_in, &op);
		if (op != EOP_SETUP) return EHANDSHAKE_ERR_INPUT;

		/* check if the required data is avaliable ahead of time */
		if (--readable < sizeof(ctx->checkbytes) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t))
			return EHANDSHAKE_ERR_INPUT;

		/* verify checkbytes */
		if (memcmp(ctx->checkbytes, pkt_in->data + pkt_in->index, sizeof(ctx->checkbytes)) != 0)
			return EHANDSHAKE_ERR_CHECKBYTES;
		packet_skip(pkt_in, sizeof(ctx->checkbytes));

		/* read cipher choice */
		packet_r_8_t(pkt_in, &out_crypto->rx.type);
		out_crypto->rx.type--;
		out_crypto->tx.type = out_crypto->rx.type;
		ulogf_inf("Chosen cipher: %s", crypto_cipher_name(out_crypto->rx.type));
	
		if (out_crypto->rx.type >= (uint8_t)ECRYPTO_ALGO_COUNT) {
			out_crypto->rx.type = out_crypto->tx.type = 0;
			ulogf_wrn("Received invalid cipher choice during handshake");
			return EHANDSHAKE_ERR_CIPHERS;
		}

		/* read server local tick (at the moment the server gave it's OK) */
		packet_r_16_t(pkt_in, out_server_start_tick);

		/* read client local tick in the server (at the moment the server gave it's OK) */
		packet_r_16_t(pkt_in, out_client_start_tick);
		
		ulogf_ntc("Handshake succeeded");
		ctx->step++;
		return 1;
	}
	return 0;
}
