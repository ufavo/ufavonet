/*
 * Network messaging internal interface.
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

struct msg_handle *msghandle_init(void);
void msghandle_free(struct msg_handle **h);
void msg_onreceive_process(packet_t *p_in, struct msg_handle *hmsg, netconn_t *conn, void *userdata, struct srvevents *srvevents, struct clievents *clievents, netsrvclient_t *client);
void msg_onsend_process(packet_t *p_out, struct msg_handle *hmsg);
uint32_t message_send(struct msg_handle *hmsg, const void *buffer, const uint32_t size);
