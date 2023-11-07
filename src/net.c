/*
 * Networking implementation.
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


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#define SOCKET_INVALID (int)INVALID_SOCKET
#define SOCKETWOULDBLOCK (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINVAL)
#else
#define SOCKET_INVALID -1
#define SOCKET_ERROR -1
#define SOCKETWOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <errno.h>

#include "../include/packet.h"
#include "../include/net.h"

#include "../modules/uthash/src/uthash.h"

#include "_netmsg.h"


enum network_message
{
	/* the number of bits needed to represent the biggest message */
	MESSAGE_SIZE_BITS_CLI = 2,
	MESSAGE_SIZE_BITS_SRV = 2,
	
	/* messages that can be sent by a client to a server*/
	CLI_NONE = 0,
	CLI_NOTICE_CONNECTING,
	CLI_NOTICE_DISCONNECT,
	CLI_NOTICE_RESET_TICK_COUNT,
	
	/* messages that can be sent by a server to a client*/
	SRV_NONE = 0,
	SRV_PENDING_CONNECTION,
	SRV_NOTICE_KICK,
	SRV_REQUEST_RESET_TICK_COUNT,
};

#define SERVER_BUFFER_LEN UINT16_MAX

#define SOCKADDR_TO_KEY(sockaddr) \
    ((((uint64_t)(sockaddr.sin_addr.s_addr)) << 16) | \
     ((uint64_t)(sockaddr.sin_port)))

/* struct that holds common data */
struct conncommon {
	uint16_t 				cur_remote_tick;
	uint16_t 				n_local_tick_noresp;
	uint16_t 				expected_remote_tick;
	enum network_message 	msg;
};

/* struct that represents a client in the server */
struct srvclient {
	struct conncommon 			common;
	enum netconn_kick_reason 	kick_reason;
	struct sockaddr_in			sockaddr;
	struct msg_handle 			*msghandle;
	void 						*userdata;

	/* Hash table stuff */
	uint64_t 		id;
	UT_hash_handle 	hh;
};

/* struct that holds data needed by a client */
struct cliconn {
	struct clievents 	events;
	struct conncommon 	common;	
	struct sockaddr_in 	sockaddr_server;
	struct msg_handle 	*msghandle;
};

/* struct that holds data needed by a server */
struct srvconn {
	uint_fast8_t 		is_closing;
	struct srvevents 	events;
	struct srvclient 	*connected_clients;
};

/* struct that represents a connection, be it a server or a client. */
struct netconn {
	packet_t 			*in_packet;
	packet_t 			*out_packet;
	uint8_t 			in_buffer[SERVER_BUFFER_LEN];
	uint8_t 			out_buffer[SERVER_BUFFER_LEN];
	int 				fd;

	uint16_t 			local_tick;
	struct netstats 	stats;
	struct netsettings 	settings;
	union {
		struct srvconn 	srv;
		struct cliconn 	cli;
	} data;
	void 				*userdata;
};

void
diep(char *s)
{
	#ifdef _WIN32
	printf("WSAERROR=%d\n", WSAGetLastError());
	#endif
	perror(s);
	exit(1);
}

#define NETCONN_INIT_COMMON(conn) \
	(conn)->local_tick = 0; \
	(conn)->in_packet = packet_init_from_buff((conn)->in_buffer, SERVER_BUFFER_LEN); \
	(conn)->out_packet = packet_init_from_buff((conn)->out_buffer, SERVER_BUFFER_LEN); \
	(conn)->settings = settings; \
	(conn)->userdata = userdata; \
	/* stats */ \
	(conn)->stats.total_sent_bytes = 0; \
	(conn)->stats.total_received_bytes = 0;

#define SRVCLIENT_FREE(conn, tmp_client, client, kick_reason) \
	(conn)->data.srv.events.ondisconnect(conn, (conn)->userdata, kick_reason, client, &((client)->userdata)); \
	tmp_client = client; \
	client = (client)->hh.next; \
	HASH_DEL((conn)->data.srv.connected_clients, tmp_client); \
	msghandle_free(&((tmp_client)->msghandle)); \
	free(tmp_client);

netconn_t *
server_init(in_addr_t ip, in_port_t port, const struct srvevents events, const struct netsettings settings, void *userdata)
{
	netconn_t 				*conn = malloc(sizeof(netconn_t));
	struct sockaddr_in 		sockaddr_server = {0};

	/* obtain socket */
	if ( (conn->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_INVALID ) {
		diep("socket");
		free(conn);
		return NULL;
	}

	/* set fd as non-blocking */
#ifdef _WIN32
	u_long mode = 1;
	if (ioctlsocket(conn->fd, FIONBIO, &mode) == SOCKET_ERROR) {
		diep("ioctlsocket");
		free(conn);
		return NULL;
	}
#else	
	int flags = fcntl(conn->fd, F_GETFL);
	fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);
#endif

	/* bind */
	sockaddr_server.sin_family = AF_INET; /* IPv4 */
	sockaddr_server.sin_port = port;
	sockaddr_server.sin_addr.s_addr = ip;

	if ( bind(conn->fd, (struct sockaddr *)&sockaddr_server, sizeof(sockaddr_server)) == SOCKET_ERROR) {
		diep("bind");
		free(conn);
		return NULL;
	}

	/* initialize common stuff */
	NETCONN_INIT_COMMON(conn);

	/* initialize srv specific stuff */
	conn->data.srv.is_closing = 0;
	conn->data.srv.events = events;
	conn->data.srv.connected_clients = NULL;

	return conn;
}

void
server_free(netconn_t **conn)
{
	if (conn == NULL)
		return;
	if (*conn == NULL)
		return;

	netconn_t 			*c = *conn;
	struct srvclient 	*client, *tmpcli;

	if (HASH_COUNT(c->data.srv.connected_clients) > 0) {
		/* if for some reason the server is not empty */
		for (client = c->data.srv.connected_clients; client != NULL; ) {
			/* free client */
			SRVCLIENT_FREE(c, tmpcli, client, EKICK_SERVER_CLOSING);
		}
	}
#ifdef _WIN32
	closesocket(c->fd);
#else
	close(c->fd);
#endif
	packet_free(&c->in_packet);
	packet_free(&c->out_packet);
	free(c);
	*conn = NULL;
}

void
client_free(netconn_t **conn)
{
	if (conn == NULL)
		return;
	if (*conn == NULL)
		return;

	netconn_t 			*c = *conn;
#ifdef _WIN32
	closesocket(c->fd);
#else
	close(c->fd);
#endif
	packet_free(&c->in_packet);
	packet_free(&c->out_packet);
	msghandle_free(&c->data.cli.msghandle);	
	free(c);
	*conn = NULL;

}

netconn_t *
client_init(in_addr_t ip, in_port_t port, const struct clievents events, const struct netsettings settings, void *userdata)
{
	netconn_t 	*conn = malloc(sizeof(netconn_t));
	
	static const struct sockaddr_in emptyaddr = {0};
	conn->data.cli.sockaddr_server = emptyaddr;

	if ( (conn->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_INVALID ) {
		diep("socket");
		free(conn);
		return NULL;
	}

	/* set fd as non-blocking */
#ifdef _WIN32
	u_long mode = 1;
	if (ioctlsocket(conn->fd, FIONBIO, &mode) == SOCKET_ERROR) {
		diep("ioctlsocket");
		free(conn);
		return NULL;
	}
#else
	int flags = fcntl(conn->fd, F_GETFL);
	fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK);
#endif

	/* initialize cli specific stuff */
	conn->data.cli.sockaddr_server.sin_family = AF_INET;
	conn->data.cli.sockaddr_server.sin_port = port;
	conn->data.cli.sockaddr_server.sin_addr.s_addr = ip;

	conn->data.cli.events = events;
	conn->data.cli.common.msg = CLI_NOTICE_CONNECTING;
	conn->data.cli.common.expected_remote_tick = 0;
	conn->data.cli.common.cur_remote_tick = 0;
	conn->data.cli.common.n_local_tick_noresp = 0;

	conn->data.cli.msghandle = msghandle_init();

	/* initialize common stuff */
	NETCONN_INIT_COMMON(conn);

	/* prepare first packet */
	packet_w_16_t(conn->out_packet, &conn->local_tick);
	packet_w_bits(conn->out_packet, conn->data.cli.common.msg, MESSAGE_SIZE_BITS_CLI);
	conn->data.cli.events.onconnect(conn, conn->userdata, conn->in_packet, conn->out_packet);
	return conn;
}

#define SENDTO(fd,buff,length,sockaddr_in,socklen) \
	conn->stats.total_sent_bytes += length; \
	if (sendto(fd, (const char *)buff, length, 0, (struct sockaddr *)&sockaddr_in, socklen) == -1) { \
		if (SOCKETWOULDBLOCK) { \
			/* OS or network cant keep up (tick rate too high / too many clients / low network bandwidth). */ \
			fprintf(stderr,"sendto would block. OS or network can't keep up\n"); \
		} else { \
			/* some other problem */ \
			perror("sendto()"); \
		} \
	}

/* a given tick is valid if (tick > last tick) && (tick <= expected + margin && tick >= expected - margin)  */
#define IF_WHITHIN_EXPECTED(tick,last,expected,margin,extra_condition) diff = (tick) - (expected); diff1 = (tick) - (last); \
	if (diff > 32768) { diff -= 65536; } else if (diff < -32768) { diff += 65536; } \
	if (diff1 > 32768) { diff1 -= 65536; } else if (diff1 < -32768) { diff1 += 65536; } \
	if (((diff < 0 ? -diff : diff) <= (margin) && diff1 >= 0) extra_condition )

#define SRV_KICK_CLIENT(clientptr,reason) (clientptr)->common.msg = SRV_NOTICE_KICK; (clientptr)->kick_reason = reason; (clientptr)->common.cur_remote_tick = 0;

#define SRV_CLIENT_ISCONNECTED(client) ((client)->common.msg == SRV_NONE || (client)->common.msg == SRV_REQUEST_RESET_TICK_COUNT)

void
server_process(netconn_t **__conn)
{
	ssize_t 					recvlen;
	uint64_t 					cli_id;
	struct srvclient			*client, *tmp_client;
	uint16_t		 			cli_tick;
	uint8_t 					cli_msg;
	int32_t 					diff, diff1;
	int 						err;
	struct sockaddr_in 			sockaddr_client;
	socklen_t 					socklen = sizeof(sockaddr_client);
	netconn_t 					*conn;

	if(__conn == NULL)
		return;
	if(*__conn == NULL)
		return;

	conn = *__conn;

	if (conn->data.srv.is_closing == 1) {
		/* Server is closing. 
		 * Incoming packets are ignored. 
		 * All clients common.msg should now be SRV_NOTICE_KICK. */
		if (HASH_COUNT(conn->data.srv.connected_clients) == 0) {
			conn->data.srv.events.onsrvclose(__conn, conn->userdata);
			return;
		}
		goto send_process;
	}

	/* Receive data from clients */
	while(1) {
		if ( (recvlen = recvfrom(conn->fd, (char *)conn->in_buffer, SERVER_BUFFER_LEN, 0, (struct sockaddr *)&sockaddr_client, &socklen)) == SOCKET_ERROR ) {
			if (SOCKETWOULDBLOCK) {
				/* no more datagrams */
				break;
			}
			/* error */
			diep("recvfrom()");
			continue;
		}
		conn->stats.total_received_bytes += recvlen;
		packet_rewind(conn->in_packet);
		packet_set_length(conn->in_packet, recvlen);
		err = 0;
		/* Read header */
		err += packet_r_16_t(conn->in_packet, &cli_tick);
		err += packet_r_bits(conn->in_packet, &cli_msg, MESSAGE_SIZE_BITS_CLI);
		if (err > 0) {
			/* Invalid data. Ignore. */
			continue;
		}
		/* Find client by id */
		client = NULL;
		cli_id = SOCKADDR_TO_KEY(sockaddr_client);
		HASH_FIND(hh, conn->data.srv.connected_clients, &cli_id, sizeof(cli_id), client);

		if (client == NULL) {
			if (cli_msg == CLI_NOTICE_DISCONNECT) {
				/* already disconnected client. 
				 * Send a reply letting it know that it's already considered as disconnected. */
				packet_rewind(conn->out_packet);
				packet_w_16_t(conn->out_packet, &conn->local_tick);
				packet_w_bits(conn->out_packet, SRV_NOTICE_KICK, MESSAGE_SIZE_BITS_SRV);
				packet_w_bits(conn->out_packet, EKICK_DISCONNECT, network_kick_bit_size);
				SENDTO(conn->fd,conn->out_buffer, packet_get_length(conn->out_packet), sockaddr_client, socklen)
				continue;
			}
			/* initialize client */
			client = malloc(sizeof(struct srvclient));
			client->id = cli_id;
			client->common.n_local_tick_noresp = 0;
			client->common.cur_remote_tick = 0;
			client->common.expected_remote_tick = 0;
			client->userdata = NULL;
			client->msghandle = msghandle_init();
			client->common.msg = SRV_PENDING_CONNECTION;
			memcpy(&client->sockaddr, &sockaddr_client, socklen);
			HASH_ADD(hh, conn->data.srv.connected_clients, id, sizeof(cli_id), client);

			goto pending_connection;
		} 
		if (client->common.msg == SRV_NOTICE_KICK) {
			/* the server will kick this client */
			continue;
		}

		/* Check for messages */
		if (cli_msg == CLI_NOTICE_DISCONNECT) {
			/* call ondisconnect and remove client */
			SRVCLIENT_FREE(conn, tmp_client, client, EKICK_DISCONNECT);
			continue;
		} else if (cli_msg == CLI_NOTICE_RESET_TICK_COUNT) {
			/* client notified that cli tick count was reseted */
			if (client->common.msg == SRV_REQUEST_RESET_TICK_COUNT) {
				/* if we got here chances are that the client lost connection at some point and now (super late) is recovering */
				client->common.msg = SRV_NONE;
			}
			goto applypacket;
		}

		IF_WHITHIN_EXPECTED(cli_tick, client->common.cur_remote_tick, client->common.expected_remote_tick, conn->settings.expected_tick_tolerance, && (client->common.n_local_tick_noresp <= 16384 && client->common.msg != SRV_REQUEST_RESET_TICK_COUNT)) {
applypacket:
			client->common.cur_remote_tick = cli_tick;
			client->common.expected_remote_tick = cli_tick;
			if (cli_msg == CLI_NOTICE_CONNECTING) {
				if (client->common.msg == SRV_PENDING_CONNECTION) {
pending_connection:
					/* call onconnect */
					packet_rewind(conn->out_packet);
					packet_w_16_t(conn->out_packet, &conn->local_tick);
					packet_w_bits(conn->out_packet, client->common.msg, MESSAGE_SIZE_BITS_SRV);
					switch((enum netconn_connect_result)conn->data.srv.events.onconnect(conn, conn->userdata, conn->in_packet, conn->out_packet, client, &client->userdata)) {
						case ECONNECTION_ALLOW:
							client->common.msg = SRV_NONE;
							client->common.expected_remote_tick = cli_tick;
							break;
						case ECONNECTION_REFUSE:
							SRV_KICK_CLIENT(client, EKICK_CONNECTION_REFUSED);
							break;
						case ECONNECTION_AGAIN:
							SENDTO(conn->fd,conn->out_buffer, packet_get_length(conn->out_packet), client->sockaddr, socklen);
							break;
					}
					continue;
				}
				continue;
			}
			/* call onreceive */
			msg_onreceive_process(conn->in_packet, client->msghandle, conn, conn->userdata, &conn->data.srv.events, NULL, client);
			conn->data.srv.events.onreceivepkt(conn, conn->userdata, conn->in_packet, client, client->userdata);

			client->common.n_local_tick_noresp = 0;
		} else if ( client->common.n_local_tick_noresp > 16384 ) {
			/* assuming a tickrate of 128 (very high), this client sent a message after 128 secs (2.1 mins) of no response (connection loss?), 
			 * so the packet is ignored and the message SRV_REQUEST_RESET_TICK_COUNT is sent until client responds with CLI_NOTICE_RESET_TICK_COUNT 
			 * or the connection times out */
			client->common.msg = SRV_REQUEST_RESET_TICK_COUNT;
		}
	}
send_process:
	if (conn->data.srv.events.bonsendpkt != NULL) {
		if (HASH_COUNT(conn->data.srv.connected_clients) > 0) {
			conn->data.srv.events.bonsendpkt(conn, conn->userdata, conn->data.srv.connected_clients);
		}
	}
	/* process and send data to connected clients */
	for (client = conn->data.srv.connected_clients; client != NULL; ) {
		if (client->common.n_local_tick_noresp + 1 < UINT16_MAX) {
			client->common.n_local_tick_noresp++;
		}
		if (client->common.n_local_tick_noresp == conn->settings.timeout_tick) {
			SRV_KICK_CLIENT(client, EKICK_CONNECTION_TIMEOUT);
		}
		if (client->common.msg == SRV_PENDING_CONNECTION) {
			/* is a pending connection, sendto is handled in recvfrom loop */
			if (client->common.n_local_tick_noresp == conn->settings.pending_conn_timeout_tick) {
				/* Client timed out, will be kicked in next tick */
				SRV_KICK_CLIENT(client, EKICK_CONNECTION_TIMEOUT);
			}
			goto next_send_iter;
		}

		packet_rewind(conn->out_packet);
		packet_w_16_t(conn->out_packet, &conn->local_tick);
		packet_w_bits(conn->out_packet, client->common.msg, MESSAGE_SIZE_BITS_SRV);
		
		if (client->common.msg == SRV_NOTICE_KICK) {
			/* this client is being kicked */
			if (client->common.cur_remote_tick == conn->settings.kick_notice_tick) {
				/* Kick notice already sent multiple times. 
				 * Call ondisconnect and remove client */
				SRVCLIENT_FREE(conn, tmp_client, client, client->kick_reason);
				continue;
			}
			packet_w_bits(conn->out_packet, client->kick_reason, network_kick_bit_size);
			client->common.cur_remote_tick++;
		} else {
			/* Is a connected client. Call onsend */
			client->common.expected_remote_tick++;
			msg_onsend_process(conn->out_packet, client->msghandle);
			conn->data.srv.events.onsendpkt(conn, conn->userdata, conn->out_packet, client, client->userdata);
		}
		SENDTO(conn->fd,conn->out_buffer, packet_get_length(conn->out_packet), client->sockaddr, socklen);
next_send_iter:
		/* go to next client */
		client = client->hh.next;
	}

	conn->local_tick++;
}

void
server_kick_client(netsrvclient_t *client, enum netconn_kick_reason reason)
{
	if (client == NULL)
		return;
	SRV_KICK_CLIENT(client, reason);
}

void
server_close(netconn_t *conn)
{
	if (conn == NULL) {
		return;
	}
	if (conn->data.srv.is_closing == 1) {
		/* already called */
		return;	
	}

	struct srvclient 	*client;
	if (HASH_COUNT(conn->data.srv.connected_clients) > 0) {
		for (client = conn->data.srv.connected_clients; client != NULL; client = client->hh.next) {
			/* kick all clients */
			SRV_KICK_CLIENT(client, EKICK_SERVER_CLOSING);
		}
	}
	conn->data.srv.is_closing = 1;
}

netsrvclient_t *
server_cli_get_next(netsrvclient_t *client)
{
	if (client == NULL)
		return NULL;

	netsrvclient_t *next = client->hh.next;
	while (next != NULL) {
		if (SRV_CLIENT_ISCONNECTED(next)) {
			/* it's a connected client */
			return next;
		}
		next = next->hh.next;
	}
	return NULL;
}

void *
server_cli_get_userdata(netsrvclient_t *client)
{
	if (client == NULL)
		return NULL;
	return client->userdata;
}

uint16_t
server_cli_get_port(netsrvclient_t *client)
{
	return ntohs(client->sockaddr.sin_port);
}

char *
server_cli_get_addrstr(netsrvclient_t *client)
{
	return inet_ntoa(client->sockaddr.sin_addr);
}

void
client_disconnect(netconn_t *conn)
{
	if (conn == NULL)
		return;
	conn->data.cli.common.msg = CLI_NOTICE_DISCONNECT;
}

void
client_process(netconn_t **__conn)
{
	ssize_t 					recvlen;
	uint16_t		 			srv_tick;
	uint8_t 					srv_msg;
	int32_t 					diff, diff1;
	socklen_t 					socklen;
	netconn_t 					*conn;

	if (__conn == NULL)
		return;
	if(*__conn == NULL)
		return;

	conn = *__conn;
	socklen = sizeof(conn->data.cli.sockaddr_server);
	
	if (conn->data.cli.common.msg == CLI_NOTICE_DISCONNECT) {
		if (conn->data.cli.common.n_local_tick_noresp == conn->settings.kick_notice_tick) {
			conn->data.cli.events.ondisconnect(__conn, conn->userdata, EKICK_DISCONNECT);
			return;
		}
	}

	while(1) {
		if ( (recvlen = recvfrom(conn->fd, (char *)conn->in_buffer, SERVER_BUFFER_LEN, 0, (struct sockaddr *)&conn->data.cli.sockaddr_server, &socklen)) == SOCKET_ERROR ) {
			if (SOCKETWOULDBLOCK) {
				/* no more datagrams */
				break;
			}
			/* error */
			diep("recvfrom()");
			continue;
		}
		packet_rewind(conn->in_packet);
		packet_set_length(conn->in_packet, recvlen);
		/* Read header */
		packet_r_16_t(conn->in_packet, &srv_tick);
		packet_r_bits(conn->in_packet, &srv_msg, MESSAGE_SIZE_BITS_SRV);
		
		if(conn->stats.total_received_bytes == 0) {
			conn->stats.total_received_bytes += recvlen;
			goto applypacket;
		}
		conn->stats.total_received_bytes += recvlen;

		if (srv_msg == SRV_NOTICE_KICK) {
			/* this client has been kicked. call ondisconnect */
			srv_msg = 0;
			packet_r_bits(conn->in_packet, &srv_msg, network_kick_bit_size);
			conn->data.cli.events.ondisconnect(__conn, conn->userdata, srv_msg);
			return;
		} else if (srv_msg == SRV_REQUEST_RESET_TICK_COUNT) {
			/* server wants to restart tick count. connection loss scenario */
			conn->local_tick = 0;
			conn->data.cli.common.msg = CLI_NOTICE_RESET_TICK_COUNT;
			/* force apply to be safe. */
			goto applypacket;
		}

		IF_WHITHIN_EXPECTED(srv_tick, conn->data.cli.common.cur_remote_tick, conn->data.cli.common.expected_remote_tick, conn->settings.expected_tick_tolerance,) {
applypacket:
			conn->data.cli.common.cur_remote_tick = srv_tick;
			conn->data.cli.common.expected_remote_tick = srv_tick;
			conn->data.cli.common.n_local_tick_noresp = 0;
			if (srv_msg == SRV_PENDING_CONNECTION) {
				packet_rewind(conn->out_packet);
				packet_w_16_t(conn->out_packet, &conn->local_tick);
				packet_w_bits(conn->out_packet, conn->data.cli.common.msg, MESSAGE_SIZE_BITS_CLI);
				conn->data.cli.events.onconnect(conn, conn->userdata, conn->in_packet, conn->out_packet);
				continue;
			} else if (conn->data.cli.common.msg == CLI_NOTICE_CONNECTING) {
				conn->data.cli.common.msg = CLI_NONE;
			}
			/* call onreceive */
			msg_onreceive_process(conn->in_packet, conn->data.cli.msghandle, conn, conn->userdata, NULL, &conn->data.cli.events, NULL);
			conn->data.cli.events.onreceivepkt(conn, conn->userdata, conn->in_packet);
			if (srv_msg == SRV_NONE && conn->data.cli.common.msg == CLI_NOTICE_RESET_TICK_COUNT) {
				/* clear the message being sent to server */
				conn->data.cli.common.msg = CLI_NONE;
			}
		}
	}
	if (conn->data.cli.common.msg == CLI_NOTICE_CONNECTING) {
		/* out packet already prepared. 
		 * overriding the tick number is safe (granted to be the first 2 bytes). */
		recvlen = packet_get_length(conn->out_packet);
		packet_rewind(conn->out_packet);
		packet_w_16_t(conn->out_packet, &conn->local_tick);
		packet_set_length(conn->out_packet, recvlen);
		goto send_pkt;
	}
	
	/* prepare packet */
	packet_rewind(conn->out_packet);
	packet_w_16_t(conn->out_packet, &conn->local_tick);
	packet_w_bits(conn->out_packet, conn->data.cli.common.msg, MESSAGE_SIZE_BITS_CLI);
	/* call onsend */
	if (conn->data.cli.common.msg != CLI_NOTICE_DISCONNECT) {
		msg_onsend_process(conn->out_packet, conn->data.cli.msghandle);
		conn->data.cli.events.onsendpkt(conn, conn->userdata, conn->out_packet);
	}
send_pkt:
	SENDTO(conn->fd, conn->out_buffer, packet_get_length(conn->out_packet), conn->data.cli.sockaddr_server, socklen);
	conn->data.cli.common.expected_remote_tick++;
	conn->local_tick++;
	if (conn->data.cli.common.n_local_tick_noresp == conn->settings.timeout_tick) {
		/* connection timed out. */
		conn->data.cli.events.ondisconnect(__conn, conn->userdata, EKICK_CONNECTION_TIMEOUT);
		return;
	}
	conn->data.cli.common.n_local_tick_noresp++;
}

uint16_t
client_get_external_tick(netconn_t *conn)
{
	if (conn == NULL)
		return 0;
	return conn->data.cli.common.cur_remote_tick;
}

uint16_t
server_cli_get_external_tick(netsrvclient_t *client)
{
	if (client == NULL)
		return 0;
	if (!SRV_CLIENT_ISCONNECTED(client))
		return 0;
	return client->common.cur_remote_tick;
}

uint32_t
client_sendmessage(netconn_t *conn, const void *buffer, const uint32_t size)
{
	if (conn == NULL)
		return 0;
	return message_send(conn->data.cli.msghandle, buffer, size);
}

uint32_t
server_cli_sendmessage(netsrvclient_t *client, const void *buffer, const uint32_t size)
{
	if (client == NULL)
		return 0;
	return message_send(client->msghandle, buffer, size);
}

uint16_t
conn_get_local_tick(netconn_t *conn)
{
	if (conn == NULL)
		return 0;
	return conn->local_tick;
}

const struct netstats *
conn_get_stats(netconn_t *conn)
{
	return (const struct netstats *)&conn->stats;
}
