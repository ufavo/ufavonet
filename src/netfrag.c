/*
 * Network fragmentation implementation.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/packet.h"
#include "_hooks.h"
#include "netfrag.h"

static inline void
bitarr_set_all(bitarr_t *restrict arr, int high)
{
	memset(arr->arr, high, arr->size);
}

static inline int
bitarr_set(bitarr_t *restrict arr, size_t idx, uint8_t high)
{
	const size_t byte_idx = idx >> 3;
	const size_t bit_idx = idx & 7;

	if (byte_idx >= arr->size) {
		size_t new_size = byte_idx + 8;
		void *tmp = urealloc(arr->arr, new_size);
		if (!tmp) {
			ulogf_err("realloc failed");
			return 0;
		}
		arr->arr = tmp;
		memset(arr->arr + arr->size, 0, new_size - arr->size);
		arr->size = new_size;
	}
	
	if (arr->length <= idx)
		arr->length = idx+1;

	uint8_t b = 1 << bit_idx;
	arr->arr[byte_idx] = (arr->arr[byte_idx] & ~b) | (high * b);
	return 1;
}

static inline uint8_t
bitarr_get(bitarr_t *restrict arr, size_t idx)
{
	if (idx >= arr->length) return 0;
	
	const size_t byte_idx = idx >> 3;
	const size_t bit_idx = idx & 7;

	return (arr->arr[byte_idx] >> bit_idx) & 1;
}

static inline int
_packet_builder_update(netfrag_builder_t *restrict ctx, packet_t *restrict pkt_frag_in, conn_header_t *restrict h, int32_t first_diff, size_t max_size, packet_t **out_pkt)
{
	uint32_t metadata;
	
	size_t index = 0;
	size_t slot_index = 0;

	if (packet_r_32_t(pkt_frag_in, &metadata)) {
		ulogf_err("Failed to read fragment metadata. Dropping packet");
		ctx->drop_flag = 1;
		return ENETFRAG_OK;
	}

	size_t piece_size = pkt_frag_in->length - pkt_frag_in->index;

	if (!piece_size) {
		ulogf_wrn("Received an empty fragment");
		return ENETFRAG_VIOLATION;
	}

	switch (h->frag_flag) {
		case EFRAG_FLAG_MIDDLE:
			/* metadata: index of this piece -1 */
			metadata++;
			index = piece_size * metadata;
			index += first_diff;
			slot_index = metadata + 1;
			/* all pieces flagged as middle must have the same size */
			if (ctx->last_middle_piece_size && piece_size != ctx->last_middle_piece_size) {
				ulogf_wrn("Dropping packet. Got a middle piece with invalid size");
				return ENETFRAG_OK;
			}
			ctx->last_middle_piece_size = piece_size;
			if (ctx->piece_count * piece_size > max_size) {
				ulogf_wrn("Dropping packet. Exceeds max size");
				ctx->drop_flag = 1;
				return ENETFRAG_OK;
			}
			break;
		case EFRAG_FLAG_FIRST:
			/* metadata: number of pieces */
			ctx->piece_count = metadata;
			ulogf_dbg("Packet being reassembled claims to be split into %"PRIu32" pieces", ctx->piece_count);
			index = 0;
			slot_index = 0;
			/* store first header */
			ctx->first_header = *h;
			break;
		case EFRAG_FLAG_LAST:
			/* metadata: position of this piece in the buffer */
			index = metadata;
			ctx->size = metadata + piece_size;
			slot_index = 1;
			break;
	}

	if (index + piece_size > max_size) {
		ulogf_wrn("Dropping packet. Exceeds max size");
		ctx->drop_flag = 1;
		return ENETFRAG_OK;
	}

	/* already has this piece */
	if (bitarr_get(&ctx->piece_slots, slot_index))
		return ENETFRAG_OK;

	if (index + piece_size > UINT32_MAX)
		return ENETFRAG_VIOLATION;

	/* write piece to final pkt */
	ctx->pkt.index = index;
	if (packet_rw_packet(pkt_frag_in, &ctx->pkt, piece_size) != EPACKET_ERR_NONE)
		return ENETFRAG_ERROR;

	/* done */
	if (ctx->piece_count && ++ctx->piece_avail == ctx->piece_count) {
		ulogf_dbg("Successfully reassembled fragmented packet");
		*h = ctx->first_header;
		ctx->pkt.length = ctx->size;
		packet_rewind(&ctx->pkt);
		*out_pkt = &ctx->pkt;
		return ENETFRAG_DONE;
	}
	
	/* flag slot */
	if (!bitarr_set(&ctx->piece_slots, slot_index, 1))
		return ENETFRAG_ERROR;

	return ENETFRAG_OK;
}

#define ceil_int_division(A,B) (((A) + ((B)-1)) / (B))

inline uint8_t
netfrag_slice_next(netfrag_slicer_t *restrict ctx, int32_t first_diff)
{
	if (ctx->pkt_in->index >= ctx->pkt_in->length) return EFRAG_FLAG_NONE;

	uint32_t avail = ctx->pkt_in->length - ctx->pkt_in->index;
	uint32_t frag_size = ctx->frag_size - sizeof(uint32_t);
	uint32_t metadata = ctx->frag_idx++;

	uint8_t flag = EFRAG_FLAG_MIDDLE;

	if (ctx->frag_idx == 1) {
		/* first metadata: number of pieces */
		flag = EFRAG_FLAG_FIRST;
		uint32_t middle_size = frag_size;
		frag_size += first_diff;
		metadata = ceil_int_division(avail - frag_size, middle_size) + 1;
		ulogf_dbg("Write piece count: %"PRIu32, metadata);
	} else {
		/* middle metadata: index of this piece -1 */
		metadata--;
//		ulogf_dbg("slice: middle slot: %"PRIu32, metadata);
	}


	if (avail <= frag_size) {
		/* last metadata: position of this piece in the buffer */
		metadata = (frag_size * (ctx->frag_idx-1)) + first_diff;// (metadata+1) * frag_size;
		frag_size = avail;

		/* This state should be avoided at a higher level */
		assert_dbg(flag != EFRAG_FLAG_FIRST);
		flag = EFRAG_FLAG_LAST;
	}

	packet_w_32_t(ctx->pkt_frag_out, &metadata);
	packet_w(ctx->pkt_frag_out, ctx->pkt_in->data + ctx->pkt_in->index, frag_size);
	ctx->pkt_in->index += frag_size;

	/* determine what kind of frag is the next one */
	avail = ctx->pkt_in->length - ctx->pkt_in->index;
	frag_size = ctx->frag_size - sizeof(uint32_t);
	return flag == EFRAG_FLAG_LAST? EFRAG_FLAG_NONE : (avail <= frag_size? EFRAG_FLAG_LAST : EFRAG_FLAG_MIDDLE);
}

inline int
netfrag_multibuilder_init(netfrag_multibuilder_t *restrict ctx, uint32_t max_pkt_size, uint32_t prealloc_pkt_size, uint32_t min_frag_size)
{
	memset(ctx, 0, sizeof(*ctx));
	const int_fast32_t n = sizeof(ctx->fv) / sizeof(*ctx->fv);
	int_fast32_t i, j;

	size_t slots_size = 0;

	if (max_pkt_size && min_frag_size) {
		slots_size = (max_pkt_size / min_frag_size) >> 3;
		if (slots_size == 0)
			slots_size++;
		ulogf_dbg("Init with bit vector of size %zu. Up to %zu pieces.", slots_size, slots_size * 8);
	}

	for (i = 0; i < n; i++) {
		ctx->fv[i].pkt.realloc_allowed = 1;
		ctx->fv[i].first_header.tick = i;

		if (slots_size) {
			ctx->fv[i].piece_slots.arr = umalloc(slots_size);
			if (!ctx->fv[i].piece_slots.arr)
				goto cleanup;
		}

		if (prealloc_pkt_size) {
			ctx->fv[i].pkt.data = umalloc(prealloc_pkt_size);
			if (!ctx->fv[i].pkt.data) {
				ufree(ctx->fv[i].piece_slots.arr);
				goto cleanup;
			}
		}

		ctx->fv[i].pkt.size = prealloc_pkt_size;
		ctx->fv[i].piece_slots.size = slots_size;
	}
	ctx->max_size = max_pkt_size;
	return 1;

cleanup:
	ulogf_err("Failed to prealloc memory for netfrag_multibuilder_t");
	for (j = 0; j < i; j++) {
		ufree(ctx->fv[j].pkt.data);
		ufree(ctx->fv[j].piece_slots.arr);
	}
	return 0;
}

inline void
netfrag_multibuilder_deinit(netfrag_multibuilder_t *restrict ctx)
{
	const int_fast32_t n = sizeof(ctx->fv) / sizeof(*ctx->fv);
	int_fast32_t i;
	
	for (i = 0; i < n; i++) {
		ufree(ctx->fv[i].pkt.data);
		ufree(ctx->fv[i].piece_slots.arr);
	}
}

inline int
netfrag_multibuilder_being_dropped(netfrag_multibuilder_t *restrict ctx, uint16_t tick)
{
	const int_fast32_t n = sizeof(ctx->fv) / sizeof(*ctx->fv);
	int_fast32_t i;
	
	for (i = 0; i < n; i++) {
		if (ctx->fv[i].first_header.tick == tick)
			return ctx->fv[i].drop_flag;
	}

	return 0;
}

inline int
netfrag_multibuilder_reconstruct(netfrag_multibuilder_t *restrict ctx, packet_t *restrict pkt_frag_in, int32_t first_diff, conn_header_t *restrict h, packet_t **out_pkt)
{
	const int_fast32_t n = sizeof(ctx->fv) / sizeof(*ctx->fv);

	int_fast32_t i, j, k;
	for (i = j = k = 0; i < n; i++) {
		if (ctx->fv[i].first_header.tick == h->tick) {
			return _packet_builder_update(ctx->fv + i, pkt_frag_in, h, first_diff, ctx->max_size, out_pkt);
		}

		/* Find the oldest slot (to be replaced/dropped) */
		int_fast32_t diff = tick_diff(ctx->fv[i].first_header.tick, h->tick);
		if (diff > j) {
			j = diff;
			k = i;
		}
	}
	
	if (ctx->fv[k].piece_count != ctx->fv[k].piece_avail)
		ulogf_wrn("Dropping fragmented packet. Tick: %"PRIu16, ctx->fv[k].first_header.tick);

	ctx->fv[k].first_header.tick = h->tick;
	ctx->fv[k].drop_flag = 0;
	ctx->fv[k].piece_count = 0;
	ctx->fv[k].piece_avail = 0;
	ctx->fv[k].size = 0;
	ctx->fv[k].last_middle_piece_size = 0;
	bitarr_set_all(&ctx->fv[k].piece_slots, 0);
	return _packet_builder_update(ctx->fv + k, pkt_frag_in, h, first_diff, ctx->max_size, out_pkt);
}
