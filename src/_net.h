/*
 * Net internal header.
 * Copyright (C) 2023  Luiz Gustavo Sassanovicz Borsoi
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
#ifndef _net_internal_h_
#define _net_internal_h_

#include <stdint.h>

enum {
	ETYPE_SERVER = 0,
	ETYPE_CLIENT
};

enum {
	EPROT_STATUS_SIZE = 3,
	
	EPROT_STATUS_CONNECT = 0,
	EPROT_STATUS_CONNECTED,
	EPROT_STATUS_DISCONNECT,

	/* those must be swapped to one of the 3 above on arrival */
	EPROT_STATUS_CONNECTED_MTU_DISCOVERY,
	EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY,
	/* discovering and replying to a discovery at the same time */
	EPROT_STATUS_CONNECTED_MTU_DISCOVERY_REPLY_DISCOVERY,

	/* not sent through network */
	EPROT_STATUS_DISCONNECT_PENDING
};

enum {
	EHANDSHAKE_STATUS_NONE = 0,
	EHANDSHAKE_STATUS_TICK_SYNC,
	EHANDSHAKE_STATUS_SERVER_OK,
	EHANDSHAKE_STATUS_CLIENT_OK,
};

enum {
	EMTU_STATUS_DISCOVERY_UP = 0,
	EMTU_STATUS_DISCOVERY_DOWN,
	EMTU_STATUS_OK,
};

#define SERVER_BUFFER_LEN UINT16_MAX

#define SOCKADDR_TO_KEY(sockaddr) \
    ((((uint64_t)(sockaddr.sin_addr.s_addr)) << 16) | \
     ((uint64_t)(sockaddr.sin_port)))

typedef struct {
	uint16_t 	tick;
	uint16_t 	mtu;
	uint16_t 	mtu_reply;
	union frag_shared {
		uint8_t 	noresp;
		uint8_t 	frag_first_diff;
	} frag_shared;
	uint8_t 	status;
	uint8_t 	secure;
	uint8_t 	round_trip_flag;
	uint8_t 	round_trip_flag_echo;
	uint8_t 	frag_flag;
	uint8_t 	payload_padding;
} conn_header_t;

static inline int32_t
tick_diff(uint16_t x, uint16_t y)
{
	int32_t z = x - y;
	return z > 32768? z - 65536 : (z < -32768? z + 65536 : z);
}

#endif
