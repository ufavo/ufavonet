/*
 * Network messaging header.
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

#ifndef __ufavonet_netmsg_h__
#define __ufavonet_netmsg_h__

#include "../include/packet.h"

#define NETMSG_MAX_SEND_PACK_CNT 126

enum {
	ENETMSG_ERR_NONE = 0,
	ENETMSG_ERR_NONE_AGAIN,
	ENETMSG_ERR_INVALID = -EPACKET_ERR_OUT_OF_BOUNDS,
	ENETMSG_ERR_MEM = -EPACKET_ERR_OUT_OF_MEMORY,
};

typedef struct {
	packet_t 	*restrict pkt;

	uint8_t 	acknowledged_id_start;
	uint8_t 	acknowledged_count;

	uint8_t 	next_available_pack_id;
	uint8_t 	has_new_msg, needs_to_send_ack;
	uint8_t 	unpack_cnt, pack_cnt;
	uint8_t 	pack_cooldown_ticks;
	uint32_t 	pkt_length_at_max_send_pack;
} netmsg_ctx_t;


int32_t	netmsg_init(netmsg_ctx_t *restrict ctx, uint32_t prealloc_packet_bytes);
void	netmsg_reset(netmsg_ctx_t *restrict ctx);
void	netmsg_deinit(netmsg_ctx_t *restrict ctx);

int32_t	netmsg_pack(netmsg_ctx_t *restrict ctx, packet_t *restrict p, uint8_t round_trip_ticks);
int32_t	netmsg_unpack_next(netmsg_ctx_t *restrict ctx, packet_t *restrict p, void **out, uint32_t *out_size);

int32_t	netmsg_enqueue(netmsg_ctx_t *restrict ctx, const void *data, const uint32_t size);

#endif
