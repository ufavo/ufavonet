/*
 * Socket abstraction.
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

#ifndef __ufavonet_usocket_h__
#define __ufavonet_usocket_h__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_utils.h"
#include "_hooks.h"

typedef union {
	struct sockaddr_in tcp_udp;
} usocket_addr_t;

typedef struct {
	uint8_t 		type;
	int 			fd;
	usocket_addr_t 	addr;
} usocket_t;

enum {
	EUSOCK_TYPE_UDP = 0,
	EUSOCK_TYPE_TCP,
	EUSOCK_TYPE_WEBSOCKET
};

static inline int
_hostname_any(const char *restrict hostname)
{
	if (!hostname)
		return 1;

	if (hostname[0] == '*')
		if (hostname[1] == '\0')
			return 1;

	if (strncmp("0.0.0.0", hostname, 8) == 0)
		return 1;

	return 0;
}

static inline int
usock_udp_init(const char *restrict hostname, uint16_t port, usocket_t *restrict out)
{
	memset(out, 0, sizeof(*out));

	if (_hostname_any(hostname))
		out->addr.tcp_udp.sin_addr.s_addr = htonl(INADDR_ANY);
	else if (!unet_gethostbyname(hostname, &out->addr.tcp_udp.sin_addr))
		return 0;
	
	if ( (out->fd = unet_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_INVALID ) {
		ulog_errno("Failed to init socket");
		return 0;
	}

	if (!unet_socket_flag_nonblocking(out->fd))
		return 0;

	out->addr.tcp_udp.sin_port = htons(port);
	out->addr.tcp_udp.sin_family = AF_INET;
	ulogf_ntc("Obtained UDP socket");
	return 1;
}

static inline int
usock_udp_bind(usocket_t *restrict sock)
{
	if ( bind(sock->fd, (struct sockaddr *)&sock->addr.tcp_udp, sizeof(sock->addr.tcp_udp)) == SOCKET_ERROR) {
		ulog_errno("Unable to bind socket to address");
		return 0;
	}
	ulogf_ntc("UDP Socket listening at %s:%d", inet_ntoa(sock->addr.tcp_udp.sin_addr), ntohs(sock->addr.tcp_udp.sin_port));
	return 1;
}

static inline void
usock_udp_deinit(usocket_t *restrict sock)
{
	unet_close(sock->fd);
}


static inline int
usock_udp_send(usocket_t *restrict sock, usocket_addr_t *restrict addr, const void *restrict ptr, size_t size)
{
	if (unet_sendto(sock->fd, ptr, size, 0, (struct sockaddr *)&addr->tcp_udp, sizeof(addr->tcp_udp)) == SOCKET_ERROR ) {
		if (SOCKETWOULDBLOCK) {
			/* OS or network cant keep up (tick rate too high / too many clients / low network bandwidth). */
			ulogf_wrn("sendto would block. OS or network can't keep up");
		} else {
			/* some other problem */
			ulog_errno("sendto");
		}
		return 0;
	}

	ulogf_dbg("Sent %lu bytes to: %s:%d", size, inet_ntoa(addr->tcp_udp.sin_addr), ntohs(addr->tcp_udp.sin_port));
	return 1;
}

static inline ssize_t
usock_udp_recv(usocket_t *restrict sock, usocket_addr_t *restrict addr, void *restrict ptr, size_t size)
{
	ssize_t recvlen;
	socklen_t socklen = sizeof(addr->tcp_udp);
	if ( (recvlen = unet_recvfrom(sock->fd, (char *)ptr, size, 0, (struct sockaddr *)&addr->tcp_udp, &socklen)) == SOCKET_ERROR ) {
		if (SOCKETWOULDBLOCK) {
			/* no more datagrams */
			return recvlen;
		}
		ulog_errno("recvfrom");
		return -1;
	}
	ulogf_dbg("Received %ld bytes from: %s:%d", recvlen, inet_ntoa(addr->tcp_udp.sin_addr), ntohs(addr->tcp_udp.sin_port));
	return recvlen;
}
/*
static inline int
usock_send(usocket_t *restrict sock, usocket_addr_t *restrict addr, const void *restrict ptr, size_t size)
{
	switch (sock->type) {
		case EUSOCK_TYPE_UDP: 		return usock_udp_send(sock, addr, ptr, size);
		case EUSOCK_TYPE_TCP: 		return 0;
		case EUSOCK_TYPE_WEBSOCKET: return 0;
	}
	return 0;
}

static inline ssize_t
usock_recv(usocket_t *restrict sock, usocket_addr_t *restrict addr, void *restrict ptr, size_t size)
{
	switch (sock->type) {
		case EUSOCK_TYPE_UDP: 		return usock_udp_recv(sock, addr, ptr, size);
		case EUSOCK_TYPE_TCP:		return -1;
		case EUSOCK_TYPE_WEBSOCKET: return -1;
	}
	return -1;
}
*/
#endif
