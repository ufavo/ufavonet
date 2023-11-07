#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "include/packet.h"
#include "include/net.h"

#ifdef _WIN32
#define random() rand()
#define srandom(val) srand(val)
#endif

#define TEST(testfunc) printf(#testfunc"\t\t\t\t\t"); total++; if (testfunc == EXIT_SUCCESS) { printf("OK\n"); ok++; }

#define TEST_CMP(in,out,printtype,before_exit) if (in != out) { printf("FAILED\n%d:\tout != in (" #printtype " != " #printtype ")\n", __LINE__, out, in); before_exit; return EXIT_FAILURE; }

#define TEST_CMPSTR(in,out,printtype,before_exit) if (strcmp(in,out) != 0) { printf("FAILED\n%d:\tout != in (" #printtype " != " #printtype ")\n", __LINE__, out, in); before_exit; return EXIT_FAILURE; }


#define TEST_LOOP_COUNT	8192

int
test_packet_rw_bits()
{
	uint8_t out;
	packet_t 	*p;
	int 	i, j, k;
	int 	err;
	p = packet_init();
	k = 0;
	for (i = 0; i < 0xFF; i++) {
		for (j = 1; j <= 8; j++) {
			if ((err = packet_w_bits(p, i, j)) > 0) {
				printf("error packet_w_bits: %d\n", err);
			}
			k+=j;
		}
	}

	packet_rewind(p);	
	
	for (i = 0; i < 0xFF; i++) {
		for (j = 1; j <= 8; j++) {
			if( (err = packet_r_bits(p, &out, j)) > 0) {
				printf("error packet_w_bits: %d\n", err);
			}
			k = ((0xFF >> (8 - j)) & i);
			TEST_CMP(k,out,%d,packet_free(&p));
		}
	}
	packet_free(&p);
	return EXIT_SUCCESS;
}

int
test_packet_rw_vlen29()
{
	packet_t 	*p;
	uint32_t 	i, j;

	p = packet_init();

	for (i = 0; i < (1 << 29); i++) {
		packet_w_vlen29(p, i);
	}

	packet_rewind(p);

	for (i = 0; i < (1 << 29); i++) {
		packet_r_vlen29(p, &j);
		TEST_CMP(i, j, %d, packet_free(&p));
	}
	packet_free(&p);
	return EXIT_SUCCESS;
}

int
test_packet_all()
{
	packet_t 	*p;
	
	/* input */
	uint8_t 	in_bits_a = random() % 16;
	uint8_t 	in_bits_b = random() % 16;
	int8_t 		in_int8_a = random();
	int16_t 	in_int16_a = random();
	float 		in_float_a = random() * 0.117246f;
	int32_t 	in_int32_a = random();
	double 		in_double_a = random() * 0.2253286; 
	int64_t 	in_int64_a = random();
	char 		*in_str = "Hello packet!";
	uint32_t 	in_vlen = random() % (1 << 29);

	/* output */
	uint8_t 	out_bits_a;
	uint8_t 	out_bits_b;
	int8_t 		out_int8_a;
	int16_t 	out_int16_a;
	float 		out_float_a;
	int32_t 	out_int32_a;
	double 		out_double_a; 
	int64_t 	out_int64_a;
	char 		out_str[256];
	uint32_t 	out_vlen;

	p = packet_init();

	/* write */
	packet_w_vlen29(p, in_vlen);
	packet_w(p, in_str, strlen(in_str)+1);
	packet_w_64_t(p, &in_int64_a);
	packet_w_64_t(p, &in_double_a);
	packet_w_32_t(p, &in_int32_a);
	packet_w_32_t(p, &in_float_a);
	
	packet_w_bits(p, in_bits_a, 4);

	packet_w_16_t(p, &in_int16_a);
	packet_w_8_t(p, &in_int8_a);

	packet_w_bits(p, in_bits_b, 4);

	/* read */
	packet_rewind(p);

	packet_r_vlen29(p, &out_vlen);
	TEST_CMP(in_vlen, out_vlen, %d, packet_free(&p));
	packet_r(p, out_str, strlen(in_str)+1);
	TEST_CMPSTR(in_str, out_str, %s, packet_free(&p));
	packet_r_64_t(p, &out_int64_a);
	TEST_CMP(in_int64_a, out_int64_a, %ld, packet_free(&p));
	packet_r_64_t(p, &out_double_a);
	TEST_CMP(in_double_a, out_double_a, %lf, packet_free(&p));
	packet_r_32_t(p, &out_int32_a);
	TEST_CMP(in_int32_a, out_int32_a, %d, packet_free(&p));
	packet_r_32_t(p, &out_float_a);
	TEST_CMP(in_float_a, out_float_a, %f, packet_free(&p));
	packet_r_bits(p, &out_bits_a, 4);
	TEST_CMP(in_bits_a, out_bits_a, %d, packet_free(&p));
	packet_r_16_t(p, &out_int16_a);
	TEST_CMP(in_int16_a, out_int16_a, %d, packet_free(&p));
	packet_r_8_t(p, &out_int8_a);
	TEST_CMP(in_int8_a, out_int8_a, %d, packet_free(&p));
	packet_r_bits(p, &out_bits_b, 4);
	TEST_CMP(in_bits_b, out_bits_b, %d, packet_free(&p));

	packet_free(&p);
	return EXIT_SUCCESS;
}

/* declares a uint of n bits and write to p */
#define W_IN_OUT_UINT(type,count) uint##type##_t u_in##type[count]; uint##type##_t u_out##type = 0; \
	for(i = 0; i < count; i++) { \
		u_in##type[i] = random() % (UINT##type##_MAX); \
		packet_w_##type##_t(p, &u_in##type[i]); \
	}

#define W_IN_OUT_INT(type,count) int##type##_t in##type[count]; int##type##_t out##type = 0; \
	for(i = 0; i < count; i++) { \
		in##type[i] = (random() % (UINT##type##_MAX / 2)) * (random() % 2 == 0? 1 : -1); \
		packet_w_##type##_t(p, &in##type[i]); \
	}


#define TEST_IN_OUT_UINT(type,count,printformat) \
	for(i = 0; i < count; i++) { \
		packet_r_##type##_t(p, &u_out##type); \
		TEST_CMP(u_in##type[i],u_out##type,printformat,packet_free(&p)); \
	}

#define TEST_IN_OUT_INT(type,count,printformat) \
	for(i = 0; i < count; i++) { \
		packet_r_##type##_t(p, &out##type); \
		TEST_CMP(in##type[i],out##type,printformat,packet_free(&p)); \
	}

#define TESTPACKET_RW_N_T(n) TEST(test_packet_rw_##n##_t())

#define TESTBODY_PACKET_RW_N_T(n,printformat,extra_write,extra_read) \
	int test_packet_rw_##n##_t() { \
		int i; \
		packet_t *p = packet_init(); \
		W_IN_OUT_UINT(n, TEST_LOOP_COUNT); \
		W_IN_OUT_INT(n, TEST_LOOP_COUNT); \
		extra_write; \
		packet_rewind(p); \
		TEST_IN_OUT_UINT(n, TEST_LOOP_COUNT, printformat); \
		TEST_IN_OUT_INT(n, TEST_LOOP_COUNT, printformat); \
		extra_read; \
		packet_free(&p); \
		return EXIT_SUCCESS; \
	}

TESTBODY_PACKET_RW_N_T(8,%d,{},{})
TESTBODY_PACKET_RW_N_T(16,%d,{},{})
TESTBODY_PACKET_RW_N_T(32,%d,float in_f = 33.3498712f * (random() % 4000);float out_f = 0.0f;packet_w_32_t(p, &in_f);,{
					   packet_r_32_t(p, &out_f);
					   TEST_CMP(in_f, out_f,%f,packet_free(&p));
					   })
#ifdef _WIN_32
TESTBODY_PACKET_RW_N_T(64,%ldd, double in_d = 33.3498712f * (random() % 4000);double out_d = 0.0f; packet_w_64_t(p, &in_d);,{
					   packet_r_64_t(p, &out_d);
					   TEST_CMP(in_d, out_d,%lf,packet_free(&p));
					   })
#else
TESTBODY_PACKET_RW_N_T(64,%ld, double in_d = 33.3498712f * (random() % 4000);double out_d = 0.0f; packet_w_64_t(p, &in_d);,{
					   packet_r_64_t(p, &out_d);
					   TEST_CMP(in_d, out_d,%lf,packet_free(&p));
					   })
#endif

/* networking test */
#define NETTEST_CLI_MESSAGE "Hello from client."
#define NETTEST_SRV_MESSAGE "Hello from server."
int nettest_clistep = 0;
int nettest_srvstep = 0;
int nettest_step = 0;
int nettest_fail = 0;
char nettest_failmsg[1024];
/* client side */
void
cli_onconnect(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out)
{
	/* complete the server onconnect sum challenge */
	uint32_t x = 0, y = 0, z = 0;
	packet_r_32_t(p_in, &x);
	packet_r_32_t(p_in, &y);
	z = x + y;
	packet_w_32_t(p_out, &z);
	printf("\t[client] onconnect event got called with: %d + %d = %d\n", x, y, z);
	/* client side onconnect got called, so it's working. */
	if (nettest_clistep == 0) {
		nettest_clistep++;
	}
}
void
cli_ondisconnect(netconn_t **conn, void *userdata, int disconnect_reason)
{
	client_free(conn);
	printf("\t[client] ondisconnect got called with reason: %d\n", disconnect_reason);
}
void
cli_onreceivepkt(netconn_t *conn, void *userdata, packet_t *p_in)
{
	uint8_t len = 0;
	char msg[256];
	packet_r_8_t(p_in, &len);
	packet_r(p_in, msg, len);

	if (nettest_clistep == 1) {
		nettest_clistep++;
		printf("\t[client] onreceivepkt event got called with: %s\n", msg);
	}

	if (strcmp(msg, NETTEST_SRV_MESSAGE) != 0) {
		if (nettest_fail == 0) {
			nettest_fail = 1;
			sprintf(nettest_failmsg, "%d: cli onreceivepkt strcmp failed.\n", __LINE__);
		}
	}
}

struct serversumchallenge {
	uint32_t x;
	uint32_t y;
	uint32_t z;
};

void
cli_onsendpkt(netconn_t *conn, void *userdata, packet_t *p_out)
{
	const char *str = NETTEST_CLI_MESSAGE;
	const uint8_t len = strlen(str)+1;

	packet_w_8_t(p_out, &len);
	packet_w(p_out, str, len);

	if (nettest_clistep == 2) {
		nettest_clistep++;
		printf("\t[client] onsendpkt event got called.\n");
	}
}
/* server side */
int
onconnect(netconn_t *conn, void *userdata, packet_t *p_in, packet_t *p_out, netsrvclient_t *client, void **cliuserdata)
{
	struct serversumchallenge *challenge;
	printf("\t[server] onconnect event got called.\n");

	if (*cliuserdata == NULL) {
		printf("\t[server] onconnect setting up challenge.\n");
		/* setup a sum challenge */
		*cliuserdata = malloc(sizeof(struct serversumchallenge));
		challenge = *cliuserdata;
		challenge->x = random() % (UINT32_MAX / 4);
		challenge->y = random() % (UINT32_MAX / 4);
		challenge->z = challenge->x + challenge->y;
	} else if (packet_get_readable(p_in) >= 4) {
		/* check challenge response */
		printf("\t[server] onconnect verifying challenge response.\n");
		uint32_t cli_resp = 0;
		challenge = *cliuserdata;
		packet_r_32_t(p_in, &cli_resp);
		if (challenge->z == cli_resp) {
			free(challenge);
			*cliuserdata = NULL;
			nettest_step++;
			printf("\t[server] onconnect event allowed the connection.\n");
			return ECONNECTION_ALLOW;
		}
	}
	challenge = *cliuserdata;
	packet_w_32_t(p_out, &challenge->x);
	packet_w_32_t(p_out, &challenge->y);
	return ECONNECTION_AGAIN;
}
void
ondisconnect(netconn_t *conn, void *userdata, int disconnect_reason, netsrvclient_t *client, void **cliuserdata)
{
	printf("\t[server] ondisconnect got called with reason: %d\n", disconnect_reason);
}
void
onreceivepkt(netconn_t *conn, void *userdata, packet_t *p_in, netsrvclient_t *client, void *cliuserdata)
{
	uint8_t len = 0;
	char msg[256];
	packet_r_8_t(p_in, &len);
	packet_r(p_in, msg, len);

	printf("\t[server] onreceivepkt event got called with: %s\n", msg);
	if (strcmp(msg, NETTEST_CLI_MESSAGE) != 0) {
		if (nettest_fail == 0) {
			nettest_fail = 1;
			sprintf(nettest_failmsg, "%d: srv onreceivepkt strcmp failed.\n", __LINE__);
		}
	}
}
void
onsendpkt(netconn_t *conn, void *userdata, packet_t *p_out, netsrvclient_t *client, void *cliuserdata)
{
	const char *str = NETTEST_SRV_MESSAGE;
	const uint8_t len = strlen(str)+1;

	packet_w_8_t(p_out, &len);
	packet_w(p_out, str, len);

	printf("\t[server] onsendpkt event got called.\n");
}

void
onsrvclose(netconn_t **conn, void *userdata)
{
	printf("\t[server] onsrvclose event got called.\n");
	server_free(conn);
}

int
test_all()
{
	printf("\n");
	int i;
	/* setup settings */
	const struct netsettings settings = {
		.pending_conn_timeout_tick = 200,
		.kick_notice_tick = 10,
		.timeout_tick = 400,
		.expected_tick_tolerance = 8192,
	};
	/* setup events */
	const struct clievents clievents = { 
		.onconnect=&cli_onconnect, 
		.ondisconnect=&cli_ondisconnect, 
		.onreceivepkt=&cli_onreceivepkt,
		.onsendpkt=&cli_onsendpkt
	};
	const struct srvevents srvevents = {
		.onconnect = &onconnect,
		.ondisconnect = &ondisconnect,
		.onreceivepkt = &onreceivepkt,
		.onsendpkt = &onsendpkt,
		.onsrvclose = &onsrvclose
	};

	netconn_t *cli_info = NULL, *srv_info = NULL;
	/* initialize server and client */
	srv_info = server_init(htonl(INADDR_ANY), htons(25565), srvevents, settings, NULL);
	cli_info = client_init(inet_addr("127.0.0.1"), htons(25565), clievents, settings, NULL);

	/* process loop */
	for(i = 0; srv_info != NULL && i < 2048; i++) {
		client_process(&cli_info);
		server_process(&srv_info);
		if (nettest_clistep == 3) {
			client_disconnect(cli_info);
			nettest_clistep++;
		} else if (cli_info == NULL) {
			server_close(srv_info);
			nettest_srvstep++;
		}
		usleep(5000);	
	}
	if (srv_info != NULL) {
		server_free(&srv_info);
		client_free(&cli_info);
		printf("FAILED\n\tFailed to test all events.\n");
		return EXIT_FAILURE;
	} else if (nettest_fail == 1) {
		printf("FAILED\n%s",nettest_failmsg);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int
main()
{
	INITIALIZE_WINSOCKS();

	int total = 0, ok = 0;
	srandom(time(NULL));

	TEST(test_packet_rw_bits());
	TESTPACKET_RW_N_T(8);
	TESTPACKET_RW_N_T(16);
	TESTPACKET_RW_N_T(32);
	TESTPACKET_RW_N_T(64);
	//slow af in wine
//	TEST(test_packet_rw_vlen29());
	TEST(test_packet_all());
	TEST(test_all());
	printf("Total=%d, OK=%d\n", total, ok);

	CLEANUP_WINSOCKS();
	return 0;
}
