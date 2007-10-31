#include <libtrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "libflowmanager.h"
#include "tcp_reorder.h"

ExpireList expire_unestab;
ExpireList expire_estab;
FlowMap flow_map;

static int next_conn_id = 0;

/* Returns a pointer to the Flow that matches the packet provided. If no such
 * Flow exists, a new Flow is created and added to the flow map before being
 * returned.
 *
 * Flow matching is only done based on a standard 5-tuple (at least for now)
 *
 * The parameter 'is_new_flow' is set to true if a new Flow had to be created.
 * It is set to false if the Flow already existed in the flow map.
 */
Flow *get_managed_flow(libtrace_packet_t *packet, bool *is_new_flow) {
	uint16_t src_port, dst_port;
	libtrace_ip_t *ip;
        FlowId pkt_id;
        Flow *new_conn;

        ip = trace_get_ip(packet);
        src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);

        if (trace_get_server_port(ip->ip_p, src_port, dst_port) == USE_SOURCE) {
                /* Server port = source port */
                pkt_id = FlowId(ip->ip_src.s_addr, ip->ip_dst.s_addr,
                                        src_port, dst_port, ip->ip_p,
                                        next_conn_id);
        } else {
                /* Server port = dest port */
                pkt_id = FlowId(ip->ip_dst.s_addr, ip->ip_src.s_addr,
                                        dst_port, src_port, ip->ip_p,
                                        next_conn_id);
        }

	FlowMap::iterator i = flow_map.find(pkt_id);
	if (i != flow_map.end()) {
		/* Found the flow in the map! */
		Flow *pkt_conn = *((*i).second);
		*is_new_flow = false;
		return pkt_conn;
	}

	/* Not in the map, create a new flow */
	new_conn = new Flow(pkt_id);
	if (ip->ip_p == 6)
		new_conn->tcp_state = TCP_STATE_NEW;
	else
		new_conn->tcp_state = TCP_STATE_NOTTCP;
	new_conn->expire_list = &expire_unestab;
	expire_unestab.push_front(new_conn);
	flow_map[new_conn->id] = expire_unestab.begin();
	next_conn_id ++;
	*is_new_flow = true;
	return new_conn;
}

/* Updates the flow state based primarily on the TCP flags */
void check_tcp_flags(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir, double ts,
		uint32_t payload_len) {
	assert(tcp);
	assert(flow);

	if (tcp->fin) {
		flow->dir_info[dir].saw_fin = true;
		/* A fin in each direction means we should be in a CLOSE
		 * state */
		if (flow->dir_info[0].saw_fin && flow->dir_info[1].saw_fin)
			flow->tcp_state = TCP_STATE_CLOSE;
		/* One fin should put us into half-close, although half-close
		 * is relatively meaningless for this library */
		else if (flow->dir_info[0].saw_fin || flow->dir_info[1].saw_fin)
		{
			if (flow->tcp_state != TCP_STATE_RESET)
				flow->tcp_state = TCP_STATE_HALFCLOSE;
		} else
			/* How can we have just observed a fin, yet not
			 * have seen a fin in at least one direction?! */
			assert(0);
		
		/* FINs with no payload consume a sequence number - not sure
		 * about FINs that do have payload attached */
		if (payload_len == 0) {
			flow->dir_info[dir].packet_list.expected_seq ++;
		}
	}

	if (tcp->syn) {
		flow->dir_info[dir].saw_syn = true;

		if (flow->dir_info[0].saw_syn && flow->dir_info[1].saw_syn)
			flow->tcp_state = TCP_STATE_ESTAB;
		else if (flow->dir_info[0].saw_syn || flow->dir_info[1].saw_syn)
			flow->tcp_state = TCP_STATE_CONN;
		else
			assert(0);
		
		/* Update our expected sequence number */
		flow->dir_info[dir].packet_list.expected_seq = 
			ntohl(tcp->seq) + 1;
		if (flow->dir_info[dir].first_pkt_ts == 0.0) 
			flow->dir_info[dir].first_pkt_ts = ts;
	}

	if (tcp->rst) {
		flow->saw_rst = true;
		flow->tcp_state = TCP_STATE_RESET;
	}
			
		
	
}

/* Updates the timeout for a Flow
 *
 * The flow state determines how long the flow has before it times out. The
 * current values are somewhat arbitrary but are intended to be as long as
 * realistically possible
 */
void update_flow_expiry_timeout(Flow *flow, double ts) {
	ExpireList *exp_list;
	switch(flow->tcp_state) {
		case TCP_STATE_RESET:
		case TCP_STATE_NEW:
		case TCP_STATE_CONN:
		case TCP_STATE_CLOSE:
			flow->expire_time = ts + 300.0;
			exp_list = &expire_unestab;
			break;
		case TCP_STATE_HALFCLOSE:
		case TCP_STATE_ESTAB:
		case TCP_STATE_NOTTCP:
			flow->expire_time = ts + 600.0;
			exp_list = &expire_estab;
			break;
			
	}
	flow->expire_list->erase(flow_map[flow->id]);
	flow->expire_list = exp_list;
	exp_list->push_front(flow);
	flow_map[flow->id] = exp_list->begin();
	
}

/* Returns the next available expired flow. Returns NULL if there are no
 * expired flows available.
 *
 * The 'force' parameter will force a flow to be expired, whether it is 
 * due to expire or not. NULL will only be returned if the expire list is empty
 * in this case. This can be used to flush the expiry list prior
 * to the calling program exiting */
static Flow *get_next_expired(ExpireList *expire, double ts, bool force) {
	ExpireList::iterator i;
	Flow *exp_flow;
	
	if (expire->empty())
		return NULL;
	
	exp_flow = expire->back();
	if (force || exp_flow->expire_time <= ts) {
		expire->pop_back();
		flow_map.erase(exp_flow->id);
		return exp_flow;
	}
	return NULL;
			
}

/* This is essentially the API-exported version of get_next_expired()
 *
 * Since we maintain two separate expiry lists, both need to be checked for
 * expirable flows before we can consider returning NULL. 
 *
 * As with get_next_expired(), the 'force' parameter will force a flow to be
 * expired, irregardless of whether it is due to expire or not 
 */
Flow *expire_next_flow(double ts, bool force) {
	Flow *exp_flow;
	
	exp_flow = get_next_expired(&expire_estab, ts, force);
	if (exp_flow != NULL)
		return exp_flow;

	return get_next_expired(&expire_unestab, ts, force);
}


/* Constructors and Destructors */
Flow::Flow(const FlowId conn_id) {
	id = conn_id;
	expire_list = NULL;
	expire_time = 0.0;
	saw_rst = false;
	tcp_state = TCP_STATE_NOTTCP;
	extension = NULL;
}

DirectionInfo::DirectionInfo() {
	packet_list.head = NULL;
	packet_list.expected_seq = 0;
	saw_fin = false;
	saw_syn = false;
	first_pkt_ts = 0.0;
}

DirectionInfo::~DirectionInfo() {
	purge_reorder_list(&packet_list);
}
