#include <libtrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "libflowmanager.h"
#include "tcp_reorder.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "libpacketdump.h"


struct lfm_config_opts {
	bool ignore_rfc1918;
};

ExpireList expire_tcp_syn;
ExpireList expire_tcp_estab;
ExpireList expire_udp;

ExpireList expired_flows;

FlowMap active_flows;
struct lfm_config_opts config = {
	0
};

static int next_conn_id = 0;

int lfm_set_config_option(lfm_config_t opt, void *value) {
	switch(opt) {
		case LFM_CONFIG_IGNORE_RFC1918:
			config.ignore_rfc1918 = *(bool *)value;
			return 1;
		
	}
	return 0;
}

static bool rfc1918_ip_addr(uint32_t ip_addr) {
	if ((ip_addr & 0x000000FF) == 0x0000000A)
		return true;
	if ((ip_addr & 0x0000FFFF) == 0x0000A8C0)
		return true;
	return false;
}

static bool rfc1918_ip(libtrace_ip_t *ip) {
	if (rfc1918_ip_addr(ip->ip_src.s_addr))
		return true;
	if (rfc1918_ip_addr(ip->ip_dst.s_addr))
		return true;
	return false;		
}

/* NOTE: ip_a and port_a must be from the same endpoint, likewise with ip_b
 * and port_b. */
Flow *lfm_find_managed_flow(uint32_t ip_a, uint32_t ip_b, uint16_t port_a, 
		uint16_t port_b, uint8_t proto) {
	
	FlowId flow_id;
	/* If we're ignoring RFC1918 addresses, there's no point 
	 * looking for a flow with an RFC1918 address */
	if (config.ignore_rfc1918 && rfc1918_ip_addr(ip_a)) 
		return NULL;
	if (config.ignore_rfc1918 && rfc1918_ip_addr(ip_b)) 
		return NULL;

	if (trace_get_server_port(proto, port_a, port_b) == USE_SOURCE) {
		flow_id = FlowId(ip_a, ip_b, port_a, port_b, proto, 0);
	} else {
		flow_id = FlowId(ip_b, ip_a, port_b, port_a, proto, 0);
	}
	FlowMap::iterator i = active_flows.find(flow_id);

	if (i == active_flows.end()) {
		return NULL;
	}
	else 
		return *((*i).second);
}

static Flow *icmp_find_original_flow(libtrace_icmp_t *icmp_hdr, uint32_t rem) {
        libtrace_ip_t *orig_ip;
        uint16_t src_port, dst_port;
        uint32_t src_ip, dst_ip;
        uint8_t proto;
        Flow *orig_flow;
        void *post_ip;
        /* Determine the flow that caused this icmp message to be sent */

        orig_ip = (libtrace_ip_t *)trace_get_payload_from_icmp(icmp_hdr, &rem);
        if (orig_ip == NULL) {
                return NULL;
        }

        src_ip = orig_ip->ip_src.s_addr;
        dst_ip = orig_ip->ip_dst.s_addr;
        proto = orig_ip->ip_p;
        rem -= (orig_ip->ip_hl * 4);
        post_ip = (char *)orig_ip + (orig_ip->ip_hl * 4);

        if (proto == 6) {
                if ( rem < 8 )
                        return NULL;
                libtrace_tcp_t *orig_tcp = (libtrace_tcp_t *)post_ip;
                src_port = orig_tcp->source;
                dst_port = orig_tcp->dest;
        } else if (proto == 17) {
                if ( rem < 8 )
                        return NULL;
                libtrace_udp_t *orig_udp = (libtrace_udp_t *)post_ip;
                src_port = orig_udp->source;
                dst_port = orig_udp->dest;
        } else {
                /* Unknown protocol */
                src_port = 0;
                dst_port = 0;
        }

        orig_flow = lfm_find_managed_flow(src_ip, dst_ip, src_port, dst_port,
                        proto);

        /* Couldn't find the original flow! */
        if (orig_flow == NULL) {
                return NULL;
        }

        return orig_flow;
}


static void icmp_error(libtrace_icmp_t *icmp_hdr, uint32_t rem) {
	Flow *orig_flow;

	orig_flow = icmp_find_original_flow(icmp_hdr, rem);
	if (orig_flow == NULL)
		return;
	/* Expire the original flow immediately */
	orig_flow->saw_rst = true; /* Not technically true :] */
	orig_flow->tcp_state = TCP_STATE_RESET;
}

/* Returns a pointer to the Flow that matches the packet provided. If no such
 * Flow exists, a new Flow is created and added to the flow map before being
 * returned.
 *
 * Flow matching is only done based on a standard 5-tuple (at least for now)
 *
 * The parameter 'is_new_flow' is set to true if a new Flow had to be created.
 * It is set to false if the Flow already existed in the flow map.
 */
Flow *lfm_match_packet_to_flow(libtrace_packet_t *packet, bool *is_new_flow) {
	uint16_t src_port, dst_port;
	uint8_t dir;
	libtrace_ip_t *ip;
        FlowId pkt_id;
        Flow *new_conn;
	ExpireList *exp_list;
	uint16_t l3_type;
	uint32_t pkt_left = 0;
	
        ip = (libtrace_ip_t *)trace_get_layer3(packet, &l3_type, &pkt_left);
	if (ip == NULL)
		return NULL;
	/* Deal with IPv4 only */
	if (l3_type != 0x8000) return NULL;
	src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);
	
	/* Ignore any RFC1918 addresses, if requested by the caller */
	if (config.ignore_rfc1918 && rfc1918_ip(ip)) {
		return NULL;
	}

	/* Force ICMP flows to have port numbers of zero, rather than
	 * whatever random values trace_get_X_port might give us */
	if (ip->ip_p == 1 && trace_get_direction(packet) == 0) {
		pkt_id = FlowId(ip->ip_src.s_addr, ip->ip_dst.s_addr,
				0, 0, ip->ip_p, next_conn_id);
	} else if (ip->ip_p == 1) {
		pkt_id = FlowId(ip->ip_dst.s_addr, ip->ip_src.s_addr,
				0, 0, ip->ip_p, next_conn_id);
	}
	
	else if (trace_get_server_port(ip->ip_p, src_port, dst_port) == USE_SOURCE) {
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

	FlowMap::iterator i = active_flows.find(pkt_id);
	if (i != active_flows.end()) {
		/* Found the flow in the map! */
		Flow *pkt_conn = *((*i).second);
		*is_new_flow = false;
		return pkt_conn;
	}

	if (ip->ip_p == 6) {
		/* TCP Flows must begin with a SYN */
		libtrace_tcp_t *tcp = trace_get_tcp(packet);
		if (!tcp)
			return NULL;
			
		if (!tcp->syn)
			return NULL;
		
		/* Avoid creating a flow based on the SYN ACK */
		if (tcp->ack)
			return NULL;
		
		new_conn = new Flow(pkt_id);
		new_conn->tcp_state = TCP_STATE_NEW;
		exp_list = &expire_tcp_syn;
	} else if (ip->ip_p == 1) {
		/* We probably don't want to treat ICMP errors as flows */
		libtrace_icmp_t *icmp_hdr;
		icmp_hdr = (libtrace_icmp_t *)trace_get_payload_from_ip(ip,
			 	NULL, &pkt_left);
		
		if (!icmp_hdr)
			return NULL;
		switch(icmp_hdr->type) {
			case 11:
				return icmp_find_original_flow(icmp_hdr, 
						pkt_left);
			case 3:
			case 4:
			case 12:
			case 31:
				icmp_error(icmp_hdr, pkt_left);
				return NULL;		
		}
		new_conn = new Flow(pkt_id);
		new_conn->tcp_state = TCP_STATE_NOTTCP;
		exp_list = &expire_udp;
	} else {
		/* Treat all non-TCP protocols as UDP for now */
		
		/* We don't have handy things like SYN flags to 
		 * mark the beginning of UDP connections */
		new_conn = new Flow(pkt_id);
		new_conn->tcp_state = TCP_STATE_NOTTCP;
		exp_list = &expire_udp;
		
	}
	
	dir = trace_get_direction(packet);
	if (new_conn->dir_info[dir].first_pkt_ts == 0.0) 
		new_conn->dir_info[dir].first_pkt_ts = trace_get_seconds(packet);
	new_conn->expire_list = exp_list;
	exp_list->push_front(new_conn);
	active_flows[new_conn->id] = exp_list->begin();
	next_conn_id ++;
	*is_new_flow = true;
	return new_conn;
}

/* Updates the flow state based primarily on the TCP flags */
void lfm_check_tcp_flags(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir, 
		double ts, uint32_t payload_len) {
	assert(tcp);
	assert(flow);

	if (tcp->fin) {
		flow->dir_info[dir].saw_fin = true;
		/* FINACK marks the conclusion of a flow */
		if (tcp->ack)
			flow->tcp_state = TCP_STATE_CLOSE;
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
void lfm_update_flow_expiry_timeout(Flow *flow, double ts) {
	ExpireList *exp_list;
	switch(flow->tcp_state) {
		case TCP_STATE_RESET:
		case TCP_STATE_CLOSE:
			/* We want to expire this as soon as possible */
			flow->expire_time = ts;
			exp_list = &expired_flows;
			break;
		
		case TCP_STATE_NEW:
		case TCP_STATE_CONN:
			flow->expire_time = ts + 240.0;
			exp_list = &expire_tcp_syn;
			break;
			
		case TCP_STATE_HALFCLOSE:
		case TCP_STATE_ESTAB:
			flow->expire_time = ts + 7440.0;
			exp_list = &expire_tcp_estab;
			break;
			
		case TCP_STATE_NOTTCP:
			flow->expire_time = ts + 120.0;
			exp_list = &expire_udp;
			break;
			
	}
	
	flow->expire_list->erase(active_flows[flow->id]);
	flow->expire_list = exp_list;
	exp_list->push_front(flow);
	active_flows[flow->id] = exp_list->begin();
	
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
		active_flows.erase(exp_flow->id);
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
Flow *lfm_expire_next_flow(double ts, bool force) {
	Flow *exp_flow;
	
	exp_flow = get_next_expired(&expire_tcp_syn, ts, force);
	if (exp_flow != NULL)
		return exp_flow;
	
	exp_flow = get_next_expired(&expire_tcp_estab, ts, force);
	if (exp_flow != NULL)
		return exp_flow;
	
	exp_flow = get_next_expired(&expire_udp, ts, force);
	if (exp_flow != NULL)
		return exp_flow;

	return get_next_expired(&expired_flows, ts, force);
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
