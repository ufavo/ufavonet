/*
 * Networking interface.
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

#ifndef __UFAVONET_NET_HEADER__
#define __UFAVONET_NET_HEADER__

/* 2^3 = max 8 values */
static const int network_kick_bit_size = 3;
enum netconn_kick_reason
{
	EKICK_NONE = 0,
	/* The client notified a disconnect. */
	EKICK_DISCONNECT,
	/* Server is closing. */
	EKICK_SERVER_CLOSING,
	/* The client was unable to negotiate a connection in time. */
	EKICK_CONNECTION_TIMEOUT,
	/* The client connection request was refused by the server. */
	EKICK_CONNECTION_REFUSED,
};

enum netconn_connect_result
{
	/* Allows the connection.
	 * Sends `p_out` packet if not empty. 
	 * `userdata` is assigned to this client. */
	ECONNECTION_ALLOW,
	/* Refuses the connection.
	 * Kicks the client with `KICKINF_CONNECTION_REFUSED` message.
	 * `p_out` packet is ignored.
	 * `userdata` is assigned to this client.
	 * `ondisconnect` is called as soon as this value is returned. */
	ECONNECTION_REFUSE,
	/* Keep in pending state. 
	 * `onconnect` will be called until `CONNECTION_ALLOW` or `CONNECTION_REFUSE` is returned.
	 * Sends `out` packet if not empty.
	 * `userdata` is assigned to this client. */
	ECONNECTION_AGAIN
};

typedef struct netconn netconn_t;
typedef struct srvclient netsrvclient_t;

struct netsettings {
	/* Amount of ticks with no sucessfull authentication. 
	 * When this value is exceeded during a pending connection state the client is kicked.
	 * Should not exceed 16384 (2^14). 
	 * This setting is exclusive to server. */
	uint16_t 	pending_conn_timeout_tick;
	/* Amount of ticks with no response.
	 * As a client, when this value is exceeded, the event `ondisconnect` is called and the connection should be terminated.
	 * As a server, When this value is exceeded the client is kicked. */
	uint16_t 	timeout_tick;
	/* The maximum amount of ticks sent as kick notice (by server) or disconnect notice (client) before actually kicking the client (server) or disconnecting (client). 
	 * Half the tick rate is enough. */
	uint16_t 	kick_notice_tick;
	/* When a packet arrives it can be out of order. To determine if it should be considered, the tick number of the packet is compared against a expected value.
	 * This setting specifies the margin of the expected value.
	 * Should not exceed 16384 (2^14), as a tick number is represented with 16 bits that wraps around when the max value is reached.
	 * For a value of 10, the packet will be considered if (`arrived_tick` > `last_considered_tick`) && (`arrived_tick` <= `expected_tick` + 10 && `arrived_tick` >= `expected_tick` - 10).
	 * A value of 8192 is highly recommended. Smaller values can be a problem with poor connections. A higher value significantly increases the chances of applying the wrong packet. */
	uint16_t 	expected_tick_tolerance;
};

struct srvevents {
	/* Called during the process of connection negotiation.
	 * This is where authentication/identification/verification should happen if needed.
	 * A client is considered connected whenever `CONNECTION_ALLOW` is returned. 
	 * `userdata` can be assigned anytime `onconnect` is called. */
	int 	(*onconnect)(packet_t *p_in, packet_t *p_out, netsrvclient_t *client, void **userdata);
	/* Called when a client is kicked, disconnects or lose connection to the server. 
	 * Called even if the client has not succeded the `onconnect` process.
	 * Called once per client.
	 * This is the last call before `client` resources are released. 
	 * If `userdata` has no more references, release it's resources here. */
	void	(*ondisconnect)(int disconnect_reason, netsrvclient_t *client, void **userdata);
	/* Called during a server tick if a valid packet is available.
	 * This event is only called for clients that got approved in the `onconnect` stage. */
	void	(*onreceivepkt)(uint16_t external_tick, packet_t *p_in, netsrvclient_t *client, void *userdata);
	/* Called before the onsendpkt event occours for any client.
	 * Only called once per tick. */
	void 	(*bonsendpkt)(netsrvclient_t *first);
	/* Called every server tick.
	 * This event is only called for clients that got approved in the `onconnect` stage. */
	void  	(*onsendpkt)(uint16_t local_tick, packet_t *p_out, netsrvclient_t *client, void *userdata);
	/* Called after a `KICKINF_SERVER_CLOSING` kick happens for all connected clients.
	 * This event is triggered by a call to `server_close`. */
	void 	(*onsrvclose)(void);
};

struct clievents {
	/* Step were the connection is negotiated.
	 * Called until server accept/timeout the connection request. */
	void	(*onconnect)(packet_t *p_in, packet_t *p_out);
	/* Called when a disconnection occours. */
	void	(*ondisconnect)(int disconnect_reason);
	/* Called during a client tick if a valid packet is avaliable. */
	void	(*onreceivepkt)(uint16_t tick, packet_t *p_in);
	/* Called every client tick. */
	void	(*onsendpkt)(packet_t *p_out);
};

struct netstats {
	uint64_t 	total_received_bytes;
	uint64_t	total_sent_bytes;
};

/* Allocates a new `netconn_t` and initiates a server.
 * `ip` and `port` a#include "ufavonet/packet.h"re expected in network byte order. */
netconn_t *server_init(in_addr_t ip, in_port_t port, const struct srvevents events, const struct netsettings settings);
/* Should be executed at a constant rate, until the event `onsrvclose` is triggered.
 * Each execution is considered a server tick. 
 * If executed with a `NULL` value as `conn` nothing happens. */
void server_process(netconn_t *conn);
/* Initiate the process of closing the server.
 * After called, eventually `onsrvclose` event will be triggered. */
void server_close(netconn_t *conn);
/* Close the socket and release resources.
 * Should be called in the event `onsrvclose`. */
void server_free(netconn_t **conn);
/* Kicks the given `client` from the server it's associated with. */
void server_kick_client(netsrvclient_t *client, enum netconn_kick_reason reason);

/* Allocates a new `netconn_t` and connects to a server. 
 * `ip` and `port` are expected in network byte order. */
netconn_t *client_init(in_addr_t ip, in_port_t port, const struct clievents events, const struct netsettings settings);
/* Should be executed at a constant rate, until the event `ondisconnect` is triggered.
 * Each execution is considered a client tick. 
 * If executed with a `NULL` value as `conn` nothing happens. */
void client_process(netconn_t *conn);
/* Disconnects the client.
 * After called, eventually `ondisconnect` event will be triggered. */
void client_disconnect(netconn_t *conn);
/* Close the socket and release resources.
 * Should be called in the event `ondisconnect`. */
void client_free(netconn_t **conn);

/* return the next client, or NULL. 
 * can be used in the event `bonsendpkt` with the `first` client. */
netsrvclient_t 	*server_cli_get_next(netsrvclient_t *client);
void 			*server_cli_get_userdata(netsrvclient_t *client);
/* return the port of the client in host byte order */
uint16_t 		server_cli_get_port(netsrvclient_t *client);
/* return a pointer to the internal array containing the address of the `client` represented as a string */
char 			*server_cli_get_addrstr(netsrvclient_t *client);

const struct netstats *conn_get_stats(netconn_t *conn);
#endif
