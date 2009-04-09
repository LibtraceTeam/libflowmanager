#ifndef TCP_REORDER_H_
#define TCP_REORDER_H_

#include <libtrace.h>

typedef enum {
	TCP_REORDER_IGNORE,
	TCP_REORDER_SYN,
	TCP_REORDER_ACK,
	TCP_REORDER_FIN,
	TCP_REORDER_RST,
	TCP_REORDER_DATA,
	TCP_REORDER_RETRANSMIT,
	TCP_REORDER_NEXT,
	TCP_REORDER_CONSUME
} tcp_reorder_t;

typedef struct tcp_pkt {

	tcp_reorder_t type;
	uint32_t seq;
	uint32_t plen;
	double ts;
	//libtrace_packet_t *packet;
	void *data;
	
	struct tcp_pkt *next;

} tcp_packet_t;

typedef struct tcp_reorder {
	
	uint32_t expected_seq;
	uint32_t list_len; 
	void *(*read_packet)(uint32_t exp, libtrace_packet_t *packet);
	void (*destroy_packet)(void *);

	tcp_packet_t *list;
	tcp_packet_t *list_end;

} tcp_packet_list_t;

tcp_packet_list_t *tcp_create_reorderer(void *(*callback)(uint32_t, libtrace_packet_t *), void (*destroy_cb)(void *));
void tcp_destroy_reorderer(tcp_packet_list_t *ord);
tcp_reorder_t tcp_reorder_packet(tcp_packet_list_t *ord,
        libtrace_packet_t *packet);
tcp_packet_t *tcp_pop_packet(tcp_packet_list_t *ord);

#endif
