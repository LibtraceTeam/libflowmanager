
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <libtrace.h>

#include "tcp_reorder.h"

#define UINT32_MAX 0xffffffff

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

/* Increments the expected sequence number by the original payload size
 * of the packet */
static void update_expected_seqnum(tcp_reorder_t *list, 
		libtrace_packet_t *packet) {
	int payload_size;
	libtrace_ip_t *ip = trace_get_ip(packet);
	libtrace_tcp_t *tcp = trace_get_tcp(packet);
	assert(tcp);
	
	payload_size = ntohs(ip->ip_len) - (4 * (tcp->doff + ip->ip_hl));

	list->expected_seq += payload_size;

}
	

/* Inserts a packet into a reordering list */
static tcp_reorder_node_t *insert_list(tcp_reorder_node_t *head, 
		libtrace_packet_t *packet, uint32_t seq) {
	
	if ( head == NULL || seq_cmp(head->seq_num, seq) > 0 ) {
		tcp_reorder_node_t *new_node = 
			(tcp_reorder_node_t *)malloc(sizeof(tcp_reorder_node_t));
		/* We ownz this packet now */
		new_node->packet = packet;
		new_node->seq_num = seq;
		new_node->next = head;
		return new_node;
	}

	if ( head->seq_num == seq ) {
		// duplicate!
		// XXX what if the packet is bigger or smaller than the
		// original?
		return head;
	}

	/* Recursion can be awesome */
	head->next = insert_list(head->next, packet, seq);
	return head;
}

/* Removes all packets from the reordering list, freeing all allocated
 * memory as it goes. This function should be called whenever the flow
 * that owns this list is expired / destroyed / ended, otherwise you will
 * leak packets and reordering nodes */
void purge_reorder_list(tcp_reorder_t *list) {
	tcp_reorder_node_t *head = list->head;
	tcp_reorder_node_t *tmp;
	if (list->head == NULL)
		return;

	while (head != NULL) {
		trace_destroy_packet(head->packet);
		tmp = head;
		head = head->next;
		tmp->next = NULL;
		free(tmp);
	}	
	return;
}

/* Pushes a packet onto the reordering list */	
void push_tcp_packet(tcp_reorder_t *list, libtrace_packet_t *packet) { 
	
	libtrace_tcp_t *tcp = trace_get_tcp(packet);
	uint32_t seq_num;
	if (tcp == NULL) {
		fprintf(stderr, "Warning: push_tcp_packet passed a non-TCP packet!\n");
		return;
	}

	seq_num = ntohl(tcp->seq);
	if ( seq_cmp(list->expected_seq, seq_num) > 0) {
		/* Probably a re-transmit of a packet that has been already
		 * dealt with */

		/* XXX Should check that this doesn't overlap with the
		 * expected sequence number */
		return ;
	}
	
	list->head = insert_list(list->head, packet, seq_num);
}

/* Pops the first packet off the reordering list, provided its sequence 
 * number matches the sequence number we are expecting. This function
 * will set 'packet' to point to the popped packet. If there are packets
 * in the list but the first packet does have the correct sequence number,
 * 'packet' will be set to NULL and the caller may need to create a new
 * libtrace_packet_t before they next attempt to read a packet from their 
 * trace.
 *
 * Returns 0 if no packet is available, and 1 if a packet has been popped.
 * Note that in the case of a zero return value, you still need to check 
 * whether 'packet' is NULL
 */
int pop_tcp_packet(tcp_reorder_t *list, libtrace_packet_t **packet) {
	
	tcp_reorder_node_t *head = list->head;
	if ( list->head == NULL ) {
		return 0;
	}

	
	if ( seq_cmp(head->seq_num, list->expected_seq) < 0 ) {
		/* Asked for packet after the current available
		 * packet! */
		fprintf(stderr, "Asked for packet %u, but %u is the first available packet\n", list->expected_seq, head->seq_num);
		abort();
	}
	
	if ( seq_cmp(head->seq_num, list->expected_seq) > 0 ) {
		/* missing a packet */
		*packet = NULL;
		return 0;
	}

	if (*packet != head->packet) {
		trace_destroy_packet(*packet);
		*packet = head->packet;
	}
	list->head = head->next;
	free(head);

	update_expected_seqnum(list, *packet);
	return 1;
}
