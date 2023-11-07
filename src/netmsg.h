/*
 * Network messaging implementation.
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

#ifndef _netmsg_h_
#define _netmsg_h_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/packet.h"
#include "../include/net.h"

struct message {
	struct message 	*next, *prev;
	packet_t 		*packet;
	int 			submsg_count;
	uint8_t 		id;
	uint32_t 		iid;
};

struct msg_handle {
	struct message 	*send, *pool, *queue, *current;
	uint8_t 		last_recv, last_id, last_ack, send_count, recv_count;
	uint32_t 		pool_count, queue_count, last_iid;
	packet_t 		*msg_read_pkt;
};

#define SENDCOUNTMAX 128

static inline struct msg_handle *
msghandle_init()
{
	struct msg_handle *hmsg = malloc(sizeof(struct msg_handle));
	if (hmsg == NULL) {
		return NULL;
	}
	memset(hmsg, 0, sizeof(struct msg_handle));
	hmsg->msg_read_pkt = packet_init();
	if (hmsg->msg_read_pkt == NULL) {
		free(hmsg);
		return NULL;
	}
	hmsg->send = NULL;
	hmsg->pool = NULL;
	hmsg->queue = NULL;
	hmsg->current = NULL;
	return hmsg;
}

#define LL_FREEALL(head) \
	for(msg = head; msg != NULL; ) { \
		msg2 = msg->next; \
		packet_free(&msg->packet); \
		free(msg); \
		msg = msg2; \
	}

static inline void
msghandle_free(struct msg_handle **h)
{
	struct message *msg, *msg2;
	if (h == NULL)
		return;
	if (*h == NULL)
		return;

	packet_free(&(*h)->msg_read_pkt);
	LL_FREEALL((*h)->send);
	LL_FREEALL((*h)->pool);
	LL_FREEALL((*h)->queue);
	/* `current` does not need to be freed as it's always in one of the lists */
	free(*h);
	*h = NULL;
}

#define LL_REMOVE(head,msg) \
	if (head == msg) { \
		if (msg->next != NULL) { \
			msg->next->prev = head->prev; \
		} \
		head = msg->next; \
	} else { \
		if (msg->prev != NULL) { \
			msg->prev->next = msg->next; \
		} \
		if (msg->next != NULL) { \
			msg->next->prev = msg->prev; \
		} else { \
			head->prev = msg->prev; \
		} \
	} \
	if (msg != NULL) { \
		msg->next = msg->prev = NULL; \
	}

#define LL_ADD(head,msg) \
	msg->next = head; \
	msg->prev = msg; \
	if (head != NULL) { \
		msg->prev = head->prev; \
		head->prev = msg; \
	} \
	head = msg;

#define LL_ADDTOEND(head,msg) \
	msg->next = NULL; \
	if (head == NULL) { \
		head = msg; \
	} else { \
		msg->prev = head->prev; \
		head->prev->next = msg; \
	} \
	head->prev = msg;

static inline void
msg_onreceive_process(packet_t *p_in, struct msg_handle *hmsg, netconn_t *conn, void *userdata, struct srvevents *srvevents, struct clievents *clievents, netsrvclient_t *client)
{
	struct message 	*msg, *msg2;
	uint8_t 		hasmsg = 0, msg_ack, msg_id;
	uint32_t 		submsgcount, msglen, j;
	int 			i;

	packet_r_bits(p_in, &hasmsg, 1);
	if (hasmsg == 0) {
		return;
	}
	/* Handle message acknowledgment */
	packet_r_8_t(p_in, &msg_ack);
	for (msg = hmsg->send; msg != NULL; ) {
		msg2 = msg->next;
		i = msg_ack - msg->id;
		if (i > 128) { i -= 256; } else if (i < -128) { i += 256; }
		if (i >= 0) {
			/* the message was acknowledged. Move back to the pool */
			LL_REMOVE(hmsg->send, msg);	
			LL_ADD(hmsg->pool, msg);
			hmsg->pool_count++;
			hmsg->send_count--;
			if (srvevents != NULL) {
				if (srvevents->onmessageack != NULL)
					srvevents->onmessageack(conn, userdata, msg->iid, client);
			} else if (clievents != NULL) {
				if (clievents->onmessageack != NULL)
					clievents->onmessageack(conn, userdata, msg->iid);
			}
		}
		msg = msg2;
	}
	/* If queue has messages, move them to send list */
	for (msg = hmsg->queue; msg != NULL && hmsg->send_count < SENDCOUNTMAX; ) {
		LL_REMOVE(hmsg->queue, msg);
		LL_ADDTOEND(hmsg->send, msg);
		hmsg->queue_count--;
		hmsg->send_count++;
		msg = hmsg->queue;
	}
	/* Handle incoming messages */
	packet_r_8_t(p_in, &hmsg->recv_count);
	for (i = 0; i < hmsg->recv_count; i++) {
		packet_r_8_t(p_in, &msg_id);
		packet_r_vlen29(p_in, &submsgcount);
		if (msg_id == (uint8_t)(hmsg->last_ack + 1)) {
			for (j = 0; j < submsgcount; j++) {
				packet_r_vlen29(p_in, &msglen);
				packet_rewind(hmsg->msg_read_pkt);
				packet_set_buff(hmsg->msg_read_pkt, ((uint8_t *)packet_get_buff(p_in)) + packet_get_index(p_in), msglen);
				packet_set_length(hmsg->msg_read_pkt, msglen);
				packet_skip(p_in, msglen);
				if (srvevents != NULL) {
					if (srvevents->onreceivemsg != NULL)
						srvevents->onreceivemsg(conn, userdata, hmsg->msg_read_pkt, client);
				} else if (clievents != NULL) {
					if (clievents->onreceivemsg != NULL)
						clievents->onreceivemsg(conn, userdata, hmsg->msg_read_pkt);
				}
			}
			hmsg->last_ack++;
		} else {
			/* skip */
			for (j = 0; j < submsgcount; j++) {
				packet_r_vlen29(p_in, &msglen);
				packet_skip(p_in, msglen);
			}
		}
	}
}

static inline void
msg_onsend_process(packet_t *p_out, struct msg_handle *hmsg)
{
	struct message 	*msg;

	hmsg->current = NULL;
	if (hmsg->send_count == 0 && hmsg->recv_count == 0) {
		/* nothing to send/acknowledge */
		packet_w_bits(p_out, 0, 1);
		return;
	}
	packet_w_bits(p_out, 1, 1);

	/* send acknowledgment */
	packet_w_8_t(p_out, &hmsg->last_ack);

	/* send messages */
	packet_w_8_t(p_out, &hmsg->send_count);
	for (msg = hmsg->send; msg != NULL; msg = msg->next) {
		packet_w_8_t(p_out, &msg->id);
		packet_w_vlen29(p_out, msg->submsg_count);
		packet_w(p_out, packet_get_buff(msg->packet), packet_get_length(msg->packet));
	}

	hmsg->recv_count = 0;
}

static inline uint32_t
message_send(struct msg_handle *hmsg, const void *buffer, const uint32_t size)
{
	if (hmsg->current == NULL) {
		if (hmsg->pool == NULL) {
			hmsg->current = malloc(sizeof(struct message));
			hmsg->current->packet = packet_init();
			if (hmsg->current->packet == NULL) {
				return 1;
			}
		} else {
			hmsg->current = hmsg->pool;
			LL_REMOVE(hmsg->pool, hmsg->pool);
			packet_rewind(hmsg->current->packet);
		}
		hmsg->last_id++;
		hmsg->last_iid++;
		hmsg->current->id = hmsg->last_id;
		hmsg->current->iid = hmsg->last_iid;
		hmsg->current->submsg_count = 0;
		hmsg->current->next = hmsg->current->prev = NULL;
		if (hmsg->send_count == SENDCOUNTMAX) {
			LL_ADDTOEND(hmsg->queue, hmsg->current);
			hmsg->queue_count++;
		} else {
			LL_ADDTOEND(hmsg->send, hmsg->current);
			hmsg->send_count++;
		}
	}

	packet_w_vlen29(hmsg->current->packet, size);
	packet_w(hmsg->current->packet, buffer, size);
	hmsg->current->submsg_count++;

	return hmsg->current->iid;
}
#endif
