#ifndef TCP_REORDER_H_
#define TCP_REORDER_H_

#include <libtrace.h>

typedef struct tcp_reorder_node {
	libtrace_packet_t *packet;
	uint32_t seq_num;
	
	struct tcp_reorder_node *next;
} tcp_reorder_node_t;

typedef struct tcp_reorder_list {
	tcp_reorder_node_t *head;
	uint32_t expected_seq;
} tcp_reorder_t;

void purge_reorder_list(tcp_reorder_t *list);
int push_tcp_packet(tcp_reorder_t *list, libtrace_packet_t *packet);
int pop_tcp_packet(tcp_reorder_t *list, libtrace_packet_t **packet);
void traverse_tcp_list(tcp_reorder_t *list);
#endif
