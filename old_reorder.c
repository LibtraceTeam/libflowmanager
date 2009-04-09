
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

	if (tcp->syn) {
		list->expected_seq = ntohl(tcp->seq) + 1;
		return;
	}
	
	payload_size = ntohs(ip->ip_len) - (4 * (tcp->doff + ip->ip_hl));

	/* FINs consume a sequence number */
	if (tcp->fin) {
		list->expected_seq ++;
		return;
	}
	list->expected_seq += payload_size;

}
	

/* Inserts a packet into a reordering list */
static tcp_reorder_node_t *insert_list(tcp_reorder_node_t *head, 
		libtrace_packet_t *packet, uint32_t seq, bool *dup) {
	
	if ( head == NULL || seq_cmp(head->seq_num, seq) > 0 ) {
		tcp_reorder_node_t *new_node = 
			(tcp_reorder_node_t *)malloc(sizeof(tcp_reorder_node_t));
		/* We ownz this packet now */
		new_node->packet = packet;
		new_node->seq_num = seq;
		new_node->next = head;
		return new_node;
	}

	/* We actually might want to keep duplicates, i.e. for loss detection
	 */
	
	/*
	if ( head->seq_num == seq ) {
		// duplicate!
		// XXX what if the packet is bigger or smaller than the
		// original?
		*dup = true;
		return head;
	}
	*/

	/* Recursion can be awesome */
	head->next = insert_list(head->next, packet, seq, dup);
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

/* Pushes a packet onto the reordering list 
 *
 * Returns -1 if passed a non-tcp packet
 * Returns  0 if the packet is an ACK without data 
 * Returns  1 if the packet is pushed on successfully or should be ignored 
 */	
int push_tcp_packet(tcp_reorder_t *list, libtrace_packet_t *packet) { 
	
	libtrace_ip_t *ip = trace_get_ip(packet);
	libtrace_tcp_t *tcp = trace_get_tcp(packet);
	uint32_t seq_num;
	uint32_t size;
	bool dup = false;
	
	if (tcp == NULL) {
		fprintf(stderr, "Warning: push_tcp_packet passed a non-TCP packet!\n");
		return -1;
	}

	seq_num = ntohl(tcp->seq);
	
	size = (htons(ip->ip_len) - (ip->ip_hl * 4) - (tcp->doff * 4));
	
	if (tcp->syn) {
		list->expected_seq = seq_num;
		list->head = insert_list(list->head, packet, seq_num, &dup);
		printf("SYN: %u\n", seq_num);
		return 1;
	} 
		
	if (tcp->ack && !tcp->fin) {

		/* Don't insert regular ACKs into the reordering list */
		if (size == 0)
			return 0;
	}

	
	if ( seq_cmp(list->expected_seq, seq_num) > 0) {
		/* Probably a re-transmit of a packet that has been already
		 * dealt with */

		/* XXX Should check that this doesn't overlap with the
		 * expected sequence number */
		printf("Expected %u - we have %u, return 2\n",
			list->expected_seq, seq_num);
		return 2;
	}
	
	if (seq_cmp(list->expected_seq, seq_num) == 0) {
		/* This packet is the expected next packet - tell the
		 * caller that they can use it right away rather than
		 * consuming it */
		printf("Expected %u - we have %u, return 3\n",
			list->expected_seq, seq_num);
		list->expected_seq += size;
		return 3;
	}

	printf("Adding %u - expected %u\n", seq_num, list->expected_seq);
	list->head = insert_list(list->head, packet, seq_num, &dup);
	
	
	return 1;
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
libtrace_packet_t *pop_tcp_packet(tcp_reorder_t *list) {
	
	tcp_reorder_node_t *head = list->head;
	libtrace_packet_t *packet;

	if ( list->head == NULL ) {
		return NULL;
	}


	/* Expected sequence number is higher than the first packet
	 * in the list - keep removing packets from the list until the first
	 * packet has an appropriate sequence number */

	/* XXX - should this really be occurring? */
	while (seq_cmp(head->seq_num, list->expected_seq) < 0) {
		list->head = head->next;
		free(head);
		head = list->head;
		if (head == NULL)
			return NULL;
		
		/*	
		if (head->packet == *packet)
			*packet = NULL;
		trace_destroy_packet(head->packet);
		list->head = head->next;
		free(head);
		head = list->head;
		if (head == NULL) {
			return 0;
		}
		*/
	}

	if ( seq_cmp(head->seq_num, list->expected_seq) > 0 ) {
		/* missing a packet */
		return NULL;
	}

	packet = head->packet;
	list->head = head->next;
	free(head);

	update_expected_seqnum(list, packet);
	return packet;
}

void traverse_tcp_list(tcp_reorder_t *list) {
	tcp_reorder_node_t *head = list->head;

	while (head != NULL) {
		printf("%u ", head->seq_num);
		head = head->next;
	}
	printf("\n");

}
