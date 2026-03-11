/*
 * Cryptography abstraction internal header.
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
#ifndef __ufavonet_crypto_internal_h__
#define __ufavonet_crypto_internal_h__

#include "../include/crypto.h"

typedef struct {
	uint8_t 	key[crypto_shorthash_KEYBYTES];
	uint64_t	nonce;
} shortauth_ctx_t;

typedef struct {
	cipher_ctx_t 	rx;
	cipher_ctx_t 	tx;
	shortauth_ctx_t auth_rx;
	shortauth_ctx_t auth_tx;
} crypto_ctx_t;

#endif
