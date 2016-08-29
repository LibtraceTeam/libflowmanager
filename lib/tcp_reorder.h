/*
 *
 * Copyright (c) 2009-2012, 2016 The University of Waikato, Hamilton,
 * New Zealand.
 * All rights reserved.
 *
 * This file is part of libflowmanager.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libflowmanager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libflowmanager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef TCP_REORDER_H_
#define TCP_REORDER_H_

#include <libtrace.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Used to distinguish between different TCP events */
typedef enum {
	/* Not a valid TCP packet - do not attempt to reorder */
	TCP_REORDER_IGNORE,
	
	/* TCP SYN packet */
	TCP_REORDER_SYN,

	/* TCP ACK packet without piggybacked data */
	TCP_REORDER_ACK,

	/* TCP FIN packet */
	TCP_REORDER_FIN,

	/* TCP RST packet */
	TCP_REORDER_RST,

	/* TCP packet bearing payload */
	TCP_REORDER_DATA,

	/* Retransmitted TCP packet */
	TCP_REORDER_RETRANSMIT,
} tcp_reorder_t;

/* An entry in the reordering list for a TCP packet */
typedef struct tcp_pkt {

	/* The type of TCP packet */
	tcp_reorder_t type;

	/* The sequence number of the packet */
	uint32_t seq;

	/* The size of the packet payload (i.e. post-TCP header) */
	uint32_t plen;

	/* The timestamp of the packet */
	double ts;

	/* Pointer to packet data extracted via a read callback */
	void *data;
	
	/* Pointer to the next packet in the reordering list */
	struct tcp_pkt *next;

} tcp_packet_t;



/* A TCP reorderer - one is required for each half of a TCP connection */
typedef struct tcp_reorder {
	
	/* Current expected sequence number */
	uint32_t expected_seq;

	/* Number of packets in the reordering list */
	uint32_t list_len; 

	/* Read callback function for packets that are to be inserted into
	 * the reordering list */
	void *(*read_packet)(uint32_t exp, libtrace_packet_t *packet);

	/* Destroy callback function for packet data extracted using the
	 * read callback */
	void (*destroy_packet)(void *);

	/* The head of the reordering list */
	tcp_packet_t *list;

	/* The last element in the reordering list */
	tcp_packet_t *list_end;

} tcp_packet_list_t;

/* Creates and returns a new TCP reorderer
 *
 * Parameters:
 *      cb - a callback function to be called for each packet pushed onto the
 *           reorder
 *      destroy_cb - a callback function to be called whenever a packet is
 *                   removed from the reorderer
 *
 * Returns:
 *      a pointer to a newly allocated TCP reorderer
 */
tcp_packet_list_t *tcp_create_reorderer(void *(*callback)(uint32_t, 
		libtrace_packet_t *), void (*destroy_cb)(void *));

/* Destroys a TCP reorderer, freeing any resources it may be using
 *
 * Parameters:
 *      ord - the reorderer to be destroyed
 */
void tcp_destroy_reorderer(tcp_packet_list_t *ord);

/* Pushes a libtrace packet onto a TCP reorderer
 *
 * Parameters:
 *      ord - the reorderer to push the packet onto
 *      packet - the packet to push on
 *
 * Parameters:
 *      the type of the packet - if TCP_REORDER_IGNORE, the packet was not
 *      pushed on at all and should be ignored by the caller
 */
tcp_reorder_t tcp_reorder_packet(tcp_packet_list_t *ord,
        libtrace_packet_t *packet);

/* Pops the first reordered TCP packet off the reorderer's packet list. 
 *
 * Packets are only popped if they match the current expected sequence number.
 *
 * Parameters:
 *      ord - the reorderer to pop a packet from
 *
 * Returns:
 *      a pointer to the TCP packet that matches the expected sequence number.
 *      If no such packet is currently in the reordering list, NULL is 
 *      returned.
 *
 */
tcp_packet_t *tcp_pop_packet(tcp_packet_list_t *ord);

#ifdef __cplusplus
}
#endif

#endif
