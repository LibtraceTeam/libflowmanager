#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <libtrace.h>

#include "tcp_reorder.h"

#define UINT32_MAX 0xffffffffUL

libtrace_t *dummy_erf = NULL;

/* Handy function for comparing sequence numbers
 * Returns the result of seq_a - seq_b
 */
static int seq_cmp (uint32_t seq_a, uint32_t seq_b) {

        if (seq_a == seq_b) return 0;


        if (seq_a > seq_b)
                return (int)(seq_a - seq_b);
        else
                return (int)(UINT32_MAX - ((seq_b - seq_a) - 1));

}


tcp_packet_list_t *tcp_create_reorderer(
		void *(*cb)(uint32_t, libtrace_packet_t *),
		void (*destroy_cb)(void *)) {
	tcp_packet_list_t *ord = 
		(tcp_packet_list_t *)malloc(sizeof(tcp_packet_list_t));
	
	ord->expected_seq = 0;
	ord->list = NULL;
	ord->list_end = NULL;
	ord->read_packet = cb;
	ord->destroy_packet = destroy_cb;
	ord->list_len = 0;

	if (!dummy_erf) {
		dummy_erf = trace_create_dead("erf:-");
	}

	assert(dummy_erf);

	return ord;
}

void tcp_destroy_reorderer(tcp_packet_list_t *ord) {

	tcp_packet_t *head = ord->list;
	tcp_packet_t *tmp;

	while (head != NULL) {
		//trace_destroy_packet(head->packet);
		if (ord->destroy_packet)
			ord->destroy_packet(head->data);
		else
			free(head->data);
		tmp = head;
		head = head->next;
		tmp->next = NULL;
		free(tmp);
	}

	free(ord);

}

static void insert_packet(tcp_packet_list_t *ord, void *packet, 
		uint32_t seq, uint32_t plen, double ts, tcp_reorder_t type) {

	tcp_packet_t *tpkt = (tcp_packet_t *)malloc(sizeof(tcp_packet_t));
	tcp_packet_t *it, *prev = NULL;

	tpkt->type = type;
	tpkt->seq = seq;
	tpkt->plen = plen;
	tpkt->data = packet;
	tpkt->ts = ts;

	if (ord->list == NULL) {
		tpkt->next = NULL;
		ord->list = tpkt;
		ord->list_end = tpkt;
		ord->list_len += 1;
		return;

	}

	/* A lot of inserts should be at the end of the list */
	it = ord->list_end;
	assert(it != NULL);

	if (seq_cmp(seq, it->seq) >= 0) {
		tpkt->next = NULL;
		it->next = tpkt;

		ord->list_end = tpkt;
		ord->list_len += 1;
		return;
	}

	/* Otherwise, find the appropriate spot for the packet in the list */
	for (it = ord->list; it != NULL; it = it->next) {
		if (seq_cmp(it->seq, seq) > 0) {
			tpkt->next = it;
			if (prev)
				prev->next = tpkt;
			else
				ord->list = tpkt;
			ord->list_len += 1;
			return;
		}
		prev = it;
	}

	assert(it != NULL);

		

}



tcp_reorder_t tcp_reorder_packet(tcp_packet_list_t *ord, 
	libtrace_packet_t *packet)
{
	libtrace_ip_t *ip;
	libtrace_tcp_t *tcp; 
	void *packet_data;
	uint32_t seq;
	uint32_t plen;
	double pkt_ts;
	tcp_reorder_t type;

	ip = trace_get_ip(packet);
	tcp = trace_get_tcp(packet);

	if (tcp == NULL)
		return TCP_REORDER_IGNORE;

	seq = ntohl(tcp->seq);
	plen = (htons(ip->ip_len) - (ip->ip_hl * 4) - (tcp->doff * 4));
	pkt_ts = trace_get_seconds(packet);

	packet_data = ord->read_packet(ord->expected_seq, packet);
	
	if (packet_data == NULL)
		return TCP_REORDER_IGNORE;
	
	if (tcp->syn) {
		type = TCP_REORDER_SYN;
		ord->expected_seq = seq;
	}

	else if (tcp->ack && !tcp->fin && plen == 0)
		type = TCP_REORDER_ACK;

	else if (seq_cmp(ord->expected_seq, seq) > 0)
		type = TCP_REORDER_RETRANSMIT;
	
	else if (tcp->fin)
		type = TCP_REORDER_FIN;
	
	else if (tcp->rst)
		type = TCP_REORDER_RST;
	
	else
		type = TCP_REORDER_DATA;
	

	insert_packet(ord, packet_data, seq, plen, pkt_ts, type);
	//printf("Inserting packet %u - size = %u - list = %u\n", seq, plen, ord->list_len);
	return type;

#if 0

	/* SYN -> initialise sequence number */
	if (tcp->syn) {
		ord->expected_seq = seq + 1;
		return TCP_REORDER_SYN;
	} 
	/* ACK + no payload (and no FIN) -> push to front of list */
	else if (tcp->ack && !tcp->fin && plen == 0) {
		return TCP_REORDER_ACK;
	}
	/* Seq < Expected = retransmit -> */
	else if (seq_cmp(ord->expected_seq, seq) > 0) {
		return TCP_REORDER_RETRANSMIT;
	}
	/* Insert into list */
	else if (seq_cmp(ord->expected_seq, seq) == 0) {
		ord->expected_seq += plen;
		return TCP_REORDER_NEXT;
	} else {
		insert_packet(ord, packet, seq);
		return TCP_REORDER_CONSUME;
	}
#endif

}



tcp_packet_t *tcp_pop_packet(tcp_packet_list_t *ord) {

	tcp_packet_t *head = ord->list;

	/* No packets remaining in the list */
	if (head == NULL)
		return NULL;

#if 0
	while (seq_cmp(head->seq, ord->expected_seq) < 0) {
		/* XXX: For now, just stop here because I'd like to look at
		 * this case more closely */
		assert(0);
	}
#endif

	if (seq_cmp(head->seq, ord->expected_seq) > 0) {
		/* Not the packet we're looking for */
		return NULL;
	}

	if (ord->list_end == head)
		ord->list_end = NULL;
	ord->list = head->next;
	ord->list_len -= 1;

	if (head->type == TCP_REORDER_SYN)
		ord->expected_seq += 1;
	if (head->type == TCP_REORDER_FIN)
		ord->expected_seq += 1;
	if (head->type == TCP_REORDER_DATA) 
		ord->expected_seq = head->seq + head->plen;
	if (head->type == TCP_REORDER_RETRANSMIT) {

		if (seq_cmp(head->seq + head->plen, ord->expected_seq) > 0) 
			ord->expected_seq = head->seq + head->plen;
	}


	//printf("Popped packet %u - expecting %u next - list = %u\n", head->seq, ord->expected_seq, ord->list_len);
	return head;
	
}

