
#include <string.h>
#ifdef _WIN32
	#include <winsock2.h>
	#define SOCKET_INVALID (int)INVALID_SOCKET
	#define SOCKETWOULDBLOCK (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINVAL)
	#define errno WSAGetLastError()
	typedef unsigned long in_addr_t;
	typedef unsigned short in_port_t;
	typedef int socklen_t;
	static int _wsa_init = 0;
	static int _wsa_sockcnt = 0;
#else
	#define SOCKET_INVALID -1LL
	#define SOCKET_ERROR -1LL
	#define SOCKETWOULDBLOCK (errno == EAGAIN || errno == EWOULDBLOCK)
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <sys/socket.h>
	#include <fcntl.h>
	#include <netdb.h>
	#include <errno.h>
	#include <unistd.h>
#endif

#include "_hooks.h"

static inline int
unet_gethostbyname(const char *hostname, struct in_addr *_in_addr)
{
#ifdef _WIN32
	if (strcmp(hostname, "localhost") == 0) {
		*_in_addr = (struct in_addr){.s_addr = inet_addr("127.0.0.1")};
		return 1;
	}
#endif
	struct hostent *h = gethostbyname(hostname);
	if (!h) {
		ulog_errnof("Unable to resolve hostname %s", hostname);
		return 0;
	}
	*_in_addr = **(struct in_addr **)h->h_addr_list;
	ulogf_inf("Resolved %s to %s", hostname, inet_ntoa(*_in_addr));
	return 1;
}

static inline int
unet_socket_flag_nonblocking(int sockfd)
{
#ifdef _WIN32
	u_long mode = 1;
	if (ioctlsocket(sockfd, FIONBIO, &mode) == SOCKET_ERROR) {
		ulog_errno("Unable to set socket fd as non-blocking");
		return 0;
	}
#else	
	int flags = fcntl(sockfd, F_GETFL);
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		ulog_errno("Unable to set socket fd as non-blocking");
		return 0;
	}
#endif
	return 1;
}

#define unet_sendto sendto
#define unet_recvfrom recvfrom

static inline int
unet_socket(int domain, int type, int protocol)
{
	int fd = socket(domain, type, protocol);
#ifdef _WIN32
	if (fd == SOCKET_INVALID) {
		if (WSAGetLastError() == WSANOTINITIALISED) {
			// Init winsocks
			WSADATA wsa;
			if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
				ulog_errno("Failed to initialize winsock");
			} else {
				ulogf_ntc("WSAStartup succeeded");
				_wsa_init = 1;
				fd = socket(domain, type, protocol);
			}
		}
	}
	if (fd != SOCKET_ERROR)
		_wsa_sockcnt++;
#endif
	return fd;
}

static inline void
unet_close(int sockfd)
{
#ifdef _WIN32
	if (closesocket(sockfd)) {
		ulog_errno("closesocket");
	}
	if (_wsa_init && !--_wsa_sockcnt) {
		if (WSACleanup()) {
			ulog_errno("Failed to cleanup winsock");
			if (!_wsa_sockcnt) {
				ulogf_wrn("The last open socket was closed and WSACleanup failed. WSACleanup will not be called again unless another socket is opened and then closed.");
			}
		} else {
			_wsa_init = 0;
			ulogf_ntc("WSACleanup succeeded");
		}
	}
#else
	if (close(sockfd)) {
		ulog_errno("close");
	}
#endif
}
