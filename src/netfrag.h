/*
 * Network fragmentation header.
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
#ifndef _netfrag_h_
#define _netfrag_h_

#include "_net.h"
#include <stdint.h>
#include <stddef.h>
#include "_packet.h"

enum {
	EFRAG_FLAG_SIZE_BITS = 2,

	EFRAG_FLAG_NONE = 0,
	EFRAG_FLAG_MIDDLE,
	EFRAG_FLAG_FIRST,
	EFRAG_FLAG_LAST,
};

enum {
	ENETFRAG_OK = 0,
	ENETFRAG_ERROR,
	ENETFRAG_VIOLATION,

	ENETFRAG_DONE,
};

typedef struct {
	uint8_t *arr;
	size_t 	size;
	size_t 	length;
} bitarr_t;

typedef struct {
	conn_header_t first_header;
	uint8_t 	drop_flag;
	uint32_t 	size;

	uint32_t 	last_middle_piece_size;

	uint32_t 	piece_count;
	uint32_t 	piece_avail;
	bitarr_t 	piece_slots;
	packet_t	pkt;
} netfrag_builder_t;

typedef struct {
	size_t max_size;
	netfrag_builder_t fv[3];
} netfrag_multibuilder_t;

typedef struct {
	packet_t *pkt_in;
	packet_t *pkt_frag_out;
	uint32_t frag_size;
	uint32_t frag_idx;
} netfrag_slicer_t;

/* `first_diff` tells the slicer how many bytes larger (positive values) or smaller (negative values) the first fragment can be in comparision with `frag_size`.
 * To rebuild the slices, the builder must be called with the same `first_diff` value */
uint8_t netfrag_slice_next(netfrag_slicer_t *restrict ctx, int32_t first_diff);

int	netfrag_multibuilder_init(netfrag_multibuilder_t *restrict ctx, uint32_t max_pkt_size, uint32_t prealloc_pkt_size, uint32_t min_frag_size);
void netfrag_multibuilder_deinit(netfrag_multibuilder_t *restrict ctx);
int netfrag_multibuilder_reconstruct(netfrag_multibuilder_t *restrict ctx, packet_t *restrict pkt_frag_in, int32_t first_diff, conn_header_t *restrict h, packet_t **out_pkt);
int netfrag_multibuilder_being_dropped(netfrag_multibuilder_t *restrict ctx, uint16_t tick);

#endif
