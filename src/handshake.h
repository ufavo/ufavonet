/*
 * Handshake header.
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
#ifndef _handshake_h_
#define _handshake_h_

#include <stdint.h>
#include "../include/packet.h"
#include "_crypto.h"

typedef struct {
	uint8_t step;
	uint8_t asked_pk;
	uint8_t checkbytes[20];
} handshake_t;

enum {
	EHANDSHAKE_ERR_INTERNAL		= -200,
	EHANDSHAKE_ERR_INPUT		= -201,
	EHANDSHAKE_ERR_CHECKBYTES	= -202,
	EHANDSHAKE_ERR_CIPHERS	 	= -203,
	EHANDSHAKE_ERR_DECRYPT	 	= -204,
	EHANDSHAKE_ERR_REFUSED		= -205,
};

int
handshake_server_onestep(packet_t 				*restrict pkt_in,
						 packet_t 				*restrict pkt_out,
						 const crypto_keypair_t *restrict keypair,
						 const uint8_t 			*restrict prefered_ciphers,
						 crypto_ctx_t 			*restrict out,
						 uint16_t 				local_tick,
						 uint16_t 				client_remote_tick,
						 uint8_t 				allow_pk_distribution);


int
handshake_client_step(handshake_t 		*restrict ctx,
					  packet_t 			*restrict pkt_in,
					  packet_t 			*restrict pkt_out,
					  uint8_t 			*restrict server_pk,
					  const uint8_t 	*restrict prefered_ciphers,
					  crypto_ctx_t 		*restrict out_crypto,
					  uint16_t 			*restrict out_server_start_tick,
					  uint16_t 			*restrict out_client_start_tick);

#endif
