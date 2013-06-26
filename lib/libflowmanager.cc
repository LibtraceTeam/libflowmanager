/*
 * This file is part of libflowmanager
 *
 * Copyright (c) 2009 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *          
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND 
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libflowmanager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libflowmanager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libflowmanager; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 *
 */


#include <libtrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "libflowmanager.h"
#include "lfmplugin.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


/* Struct containing values for all the configuration options */
struct lfm_config_opts {
	
	/* If true, ignore all packets that contain RFC1918 private addresses */
	bool ignore_rfc1918;

	/* If true, do not immediately expire flows after seeing FIN ACKs in
	 * both directions - wait for a short time first */
	bool tcp_timewait;
	
	/* If true, UDP sessions for which there has been only one outbound
	 * packet will be expired much more quickly */
	bool short_udp;

	/* If true, the VLAN Id will be used to form the flow key */
	bool key_vlan;

	bool ignore_icmp_errors;

	/* IPv6 Only */
	bool disable_ipv4;

	/* IPv4 Only */
	bool disable_ipv6;

	/* Create new tcp flows even if they're not SYNs */
	bool tcp_anystart;

	lfm_plugin_id_t active_plugin;

	double fixed_expiry;

	double timewait_thresh;
};

/* Map containing all flows that are present in one of the LRUs */
FlowMap active_flows;

/* The current set of config options */
struct lfm_config_opts config = {
	false,		/* ignore RFC1918 */
	false,		/* TCP timewait */
	false,		/* Expire short-lived UDP flows quickly */
	false,		/* Use VLAN Id as part of the flow key */
	false,		/* Ignore ICMP errors that would otherwise expire a 
			   flow */
	false,		/* IPv4 Only */
	false,		/* IPv6 Only */
	false,          /* start tcp flows on anything, not just SYNs */
	LFM_PLUGIN_STANDARD, /* Use standard expiry rules */
	0,		/* Use the plugin default expiry times */
	0,		/* No timewait threshold */
};

/* Each flow has a unique ID number - it is set to the value of this variable
 * when created and next_conn_id is incremented */
static uint64_t next_conn_id = 0;

struct lfm_plugin_t *expirer = NULL;

static void load_plugin(lfm_plugin_id_t id) {

	switch(id) {
	case LFM_PLUGIN_STANDARD:
		expirer = load_standard_plugin();
		break;
	case LFM_PLUGIN_STANDARD_SHORT_UDP:
		expirer = load_shortudp_plugin();
		break;
	case LFM_PLUGIN_FIXED_INACTIVE:
		expirer = load_fixed_inactive();
		break;
	default:
		fprintf(stderr, "load_plugin: Invalid plugin ID %d\n", id);
		return;
	}

	if (expirer->set_inactivity_threshold != NULL && 
			config.fixed_expiry != 0) {
		expirer->set_inactivity_threshold(config.fixed_expiry);
	}

	if (expirer->set_timewait_threshold != NULL && 
			config.tcp_timewait != 0)
		expirer->set_timewait_threshold(config.timewait_thresh);

}

/* Sets a libflowmanager configuration option.
 *
 * Note that config options should be set BEFORE any packets are passed in
 * to other libflowmanager functions.
 *
 * Parameters:
 * 	opt - the config option that is being changed
 * 	value - the value to set the option to
 *
 * Returns:
 * 	1 if the option is set successfully, 0 otherwise
 */
int lfm_set_config_option(lfm_config_t opt, void *value) {
	if (!active_flows.empty()) {
		fprintf(stderr, "Cannot change configuration once processing has begun!\n");
		return 0;
	}
	
	switch(opt) {
	case LFM_CONFIG_IGNORE_RFC1918:
		config.ignore_rfc1918 = *(bool *)value;
		return 1;
	case LFM_CONFIG_TCP_TIMEWAIT:
		config.tcp_timewait = *(bool *)value;
		return 1;
	case LFM_CONFIG_SHORT_UDP:
		config.short_udp = *(bool *)value;
		if (config.short_udp)
			config.active_plugin = LFM_PLUGIN_STANDARD_SHORT_UDP;
		return 1;
	case LFM_CONFIG_VLAN:
		config.key_vlan = *(bool *)value;
		return 1;
	case LFM_CONFIG_IGNORE_ICMP_ERROR:
		config.ignore_icmp_errors = *(bool *)value;
		return 1;
		
	case LFM_CONFIG_DISABLE_IPV4:
		config.disable_ipv4 = *(bool *)value;
		return 1;
	case LFM_CONFIG_DISABLE_IPV6:
		config.disable_ipv6 = *(bool *)value;
		return 1;
	case LFM_CONFIG_TCP_ANYSTART:
		config.tcp_anystart = *(bool *)value;
		return 1;
	case LFM_CONFIG_EXPIRY_PLUGIN:
		config.active_plugin = *(lfm_plugin_id_t *)value;
		return 1;
	case LFM_CONFIG_FIXED_EXPIRY_THRESHOLD:
		config.fixed_expiry = *(double *)value;
		return 1;
	case LFM_CONFIG_TIMEWAIT_THRESHOLD:
		config.timewait_thresh = *(double *)value;
		return 1;
	}
	return 0;
}

/* Determines if an IP address is an RFC1918 address.
 *
 * Parameters:
 * 	ip_addr - the IP address to check
 *
 * Returns:
 * 	true if the address is an RFC1918 address, false otherwise
 */
static bool rfc1918_ip_addr(uint32_t ip_addr) {
	
	/* Check if 10.0.0.0/8 */
	if ((ip_addr & 0x000000FF) == 0x0000000A)
		return true;
	/* Check if 192.168.0.0/16 */
	if ((ip_addr & 0x0000FFFF) == 0x0000A8C0)
		return true;
        /* Check if 172.16.0.0/12 */
        if ((ip_addr & 0x0000FFFF) == 0x000010AC)
                return true;

	/* Otherwise, we're not RFC 1918 */
	return false;
}

/* Determines if either of the addresses in an IP header are RFC 1918.
 *
 * Parameters:
 * 	ip - a pointer to the IP header to be checked
 *
 * Returns:
 * 	true if either of the source or destination IP address are RFC 1918, 
 * 	false otherwise
 */
static bool rfc1918_ip(libtrace_ip_t *ip) {
	/* Check source address */
	if (rfc1918_ip_addr(ip->ip_src.s_addr))
		return true;
	/* Check dest address */
	if (rfc1918_ip_addr(ip->ip_dst.s_addr))
		return true;
	return false;		
}

/* NOTE: ip_a and port_a must be from the same endpoint, likewise with ip_b
 * and port_b. */


/* Search the active flows map for a flow matching the given 5-tuple. 
 *
 * Primarily intended for matching ICMP error packets back to the original
 * flows that they are in response to. This function can also be used to 
 * perform look-ups in the flow map without creating a new flow if no match
 * is found.
 *
 * Parameters:
 * 	ip_a - the IP address of the first endpoint
 * 	ip_b - the IP address of the second endpoint
 * 	port_a - the port number used by the first endpoint
 * 	port_b - the port number used by the second endpoint
 * 	proto - the transport protocol
 *
 * NOTE: ip_a and port_a MUST be from the same endpoint - likewise for ip_b
 * and port_b.
 *
 * Returns:
 * 	a pointer to the flow matching the provided 5-tuple, or NULL if no
 * 	matching flow is found in the active flows map.
 *
 * Bugs:
 * 	Does not support VLAN ids as part of a flow key.
 *
 */  
Flow *lfm_find_managed_flow(uint32_t ip_a, uint32_t ip_b, uint16_t port_a, 
		uint16_t port_b, uint8_t proto) {
	
	FlowId flow_id;
	/* If we're ignoring RFC1918 addresses, there's no point 
	 * looking for a flow with an RFC1918 address */
	if (config.ignore_rfc1918 && rfc1918_ip_addr(ip_a)) 
		return NULL;
	if (config.ignore_rfc1918 && rfc1918_ip_addr(ip_b)) 
		return NULL;

	/* XXX: We always are going to use a vlan id of zero. At some
	 * point this function should accept a vlan ID as a parameter */

	if (trace_get_server_port(proto, port_a, port_b) == USE_SOURCE) {
		flow_id = FlowId(ip_a, ip_b, port_a, port_b, 0, proto, 0, 0);
	} else {
		flow_id = FlowId(ip_b, ip_a, port_b, port_a, 0, proto, 0, 0);
	}
	FlowMap::iterator i = active_flows.find(flow_id);

	if (i == active_flows.end()) {
		/* Not in the map */
		return NULL;
	}
	else 
		return *((*i).second);
}

Flow *lfm_find_managed_flow6(uint8_t ip_a[16], uint8_t ip_b[16], uint16_t port_a, 
		uint16_t port_b, uint8_t proto) {
	
	FlowId flow_id;

	/* XXX: We always are going to use a vlan id of zero. At some
	 * point this function should accept a vlan ID as a parameter */

	if (trace_get_server_port(proto, port_a, port_b) == USE_SOURCE) {
		flow_id = FlowId(ip_a, ip_b, port_a, port_b, 0, proto, 0, 0);
	} else {
		flow_id = FlowId(ip_b, ip_a, port_b, port_a, 0, proto, 0, 0);
	}
	FlowMap::iterator i = active_flows.find(flow_id);

	if (i == active_flows.end()) {
		/* Not in the map */
		return NULL;
	}
	else 
		return *((*i).second);
}

/* Parses an ICMP error message to find the flow that originally triggered
 * the error.
 *
 * Parameters:
 * 	icmp_hdr - a pointer to the ICMP header from the error message
 * 	rem - the number of bytes remaining in the captured packet (including
 * 	      the ICMP header)
 *
 * Returns:
 * 	a pointer to the flow that caused the ICMP message, or NULL if the
 * 	flow cannot be found in the active flows map
 */
static Flow *icmp_find_original_flow(libtrace_icmp_t *icmp_hdr, uint32_t rem) {
        libtrace_ip_t *orig_ip;
	libtrace_ip6_t *orig_ip6 = NULL;
        uint16_t src_port, dst_port;
        uint32_t src_ip, dst_ip;
	uint8_t src_ip6[16], dst_ip6[16];
        uint8_t proto;
        Flow *orig_flow;
        void *post_ip;
        
        /* ICMP error message packets include the IP header + 8 bytes of the
	 * original packet that triggered the error in the first place.
	 *
	 * Recent WAND captures tend to keep that post-ICMP payload, so we
	 * can do match ICMP errors back to the flows that caused them */

	/* First step, see if we can access the post-ICMP payload */
	orig_ip = (libtrace_ip_t *)trace_get_payload_from_icmp(icmp_hdr, &rem);
        if (orig_ip == NULL) {
                return NULL;
        }
	if(orig_ip->ip_v == 6) {
		if (rem < sizeof(libtrace_ip6_t))
			return NULL;
		orig_ip6 = (libtrace_ip6_t*)orig_ip;
	} else {
		if (rem < sizeof(libtrace_ip_t))
			return NULL;
	}

	/* Get the IP addresses and transport protocol */
	if(orig_ip6) {
		memcpy(src_ip6, orig_ip6->ip_src.s6_addr, sizeof(src_ip6));
		memcpy(dst_ip6, orig_ip6->ip_dst.s6_addr, sizeof(dst_ip6));
		post_ip = trace_get_payload_from_ip6(orig_ip6, &proto, &rem);
	} else {
		src_ip = orig_ip->ip_src.s_addr;
		dst_ip = orig_ip->ip_dst.s_addr;
		proto = orig_ip->ip_p;
		rem -= (orig_ip->ip_hl * 4);
		post_ip = (char *)orig_ip + (orig_ip->ip_hl * 4);
	}

	/* Now try to get port numbers out of any remaining payload */
        if (proto == 6) {
		/* TCP */
                if ( rem < 8 )
                        return NULL;
                libtrace_tcp_t *orig_tcp = (libtrace_tcp_t *)post_ip;
                src_port = orig_tcp->source;
                dst_port = orig_tcp->dest;
        } else if (proto == 17) {
		/* UDP */
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

	/* We have the 5-tuple, can we find the flow? */
	if(orig_ip6)
		orig_flow = lfm_find_managed_flow6(src_ip6, dst_ip6, src_port,
						dst_port, proto);
	else
        	orig_flow = lfm_find_managed_flow(src_ip, dst_ip, src_port, dst_port,
               				         proto);

        /* Couldn't find the original flow! */
        if (orig_flow == NULL) {
                return NULL;
        }

        return orig_flow;
}

/* Process an ICMP error message, in particular find and expire the original
 * flow that caused the error
 *
 * Parameters:
 * 	icmp_hdr - a pointer to the ICMP header of the error packet
 * 	rem - the number of bytes remaining in the captured packet (including
 * 	      the ICMP header)
 *
 */
static void icmp_error(libtrace_icmp_t *icmp_hdr, uint32_t rem) {
	Flow *orig_flow;

	if (config.ignore_icmp_errors)
		return;

	orig_flow = icmp_find_original_flow(icmp_hdr, rem);
	if (orig_flow == NULL)
		return;
	
	/* Expire the original flow immediately */
	orig_flow->flow_state = FLOW_STATE_ICMPERROR;
}

/* Updates the UDP state, based on whether we're currently looking at an
 * outbound packet or not 
 *
 * Parameters:
 * 	f - the UDP flow to be updated
 * 	dir - the direction of the current packet
 */
static void update_udp_state(Flow *f, uint8_t dir) {

	/* If the packet is inbound, UDP state cannot be changed */
	if (dir == 1)
		return;

	if (!f->saw_outbound) {
		/* First outbound packet has been observed */
		f->saw_outbound = true;
	} else {
		/* This must be at least the second outbound packet, 
		 * ensure we are using standard UDP expiry rules */
		f->flow_state = FLOW_STATE_UDPLONG;
	}

}

/* Extracts the VLAN Id from a libtrace packet.
 *
 * This is a rather simplistic implementation with plenty of scope for
 * improvement.
 *
 * Parameters:
 * 	packet - the libtrace packet to extract the VLAN id from 
 *
 * Returns:
 * 	the value of the Id field in the VLAN header, if present. Otherwise,
 * 	returns 0.
 */
static uint16_t extract_vlan_id(libtrace_packet_t *packet) {

	void *ethernet = NULL;
	void *payload = NULL;
	uint16_t ethertype;
	libtrace_linktype_t linktype;
	uint32_t remaining;
	libtrace_8021q_t *vlan;
	uint16_t tag;

	/* First, find the ethernet header */
	ethernet = trace_get_layer2(packet, &linktype, &remaining);

	/* We only support VLANs over Ethernet for the moment */
	if (linktype != TRACE_TYPE_ETH)
		return 0;
	
	/* XXX I am assuming the next header will be a VLAN header */
	payload = trace_get_payload_from_layer2(ethernet, linktype,
			&ethertype, &remaining);

	if (payload == NULL || remaining == 0)
		return 0;
	
	/* XXX Only gets the topmost label */
	if (ethertype != 0x8100)
		return 0;

	vlan = (libtrace_8021q_t *)payload;
	if (remaining < 4)
		return 0;
	
	/* VLAN tags are actually 12 bits in size */
	tag = *(uint16_t *)vlan;
	tag = ntohs(tag);
	tag = tag & 0x0fff;
	return tag;

}

/* Returns a pointer to the Flow that matches the packet provided. If no such
 * Flow exists, a new Flow is created and added to the flow map before being
 * returned.
 *
 * Flow matching is typically done based on a standard 5-tuple, although I 
 * have recently added a config option for also using the VLAN id.
 *
 * Parameters:
 * 	packet - the packet that is to be matched with a flow
 * 	dir - the direction of the packet. 0 indicates outgoing, 1 indicates
 * 	      incoming.
 * 	is_new_flow - a boolean flag that is set to true by this function if
 * 	              a new flow was created for this packet. It is set to 
 * 	              false if the returned flow already existed in the flow 
 * 	              map.
 * 
 * Returns:
 * 	a pointer to the entry in the active flow map that matches the packet
 * 	provided, or NULL if the packet cannot be matched to a flow
 *
 */
Flow *lfm_match_packet_to_flow(libtrace_packet_t *packet, uint8_t dir, 
		bool *is_new_flow) {
	uint16_t src_port, dst_port;
	uint8_t trans_proto = 0;
	libtrace_ip_t *ip = NULL;
	libtrace_ip6_t *ip6 = NULL;
        FlowId pkt_id;
        Flow *new_conn;
	uint16_t l3_type;
	uint32_t pkt_left = 0;
	uint32_t rem;
	uint16_t vlan_id = 0;
	
        ip = (libtrace_ip_t *)trace_get_layer3(packet, &l3_type, &pkt_left);
	if (ip == NULL)
		return NULL;
	if(ip->ip_v == 6) {
		if(config.disable_ipv6)
			return NULL;
		ip6 = (libtrace_ip6_t*)ip;
		ip = NULL;
	} else {
		if(config.disable_ipv4)
			return NULL;
	}

	trace_get_transport(packet, &trans_proto, &rem);
	
	/* For now, deal with IPv4 only */
	if (l3_type != 0x0800 && l3_type != 0x86DD) return NULL;
	
	/* If the VLAN key option is set, we'll need the VLAN id */
	if (config.key_vlan)
		vlan_id = extract_vlan_id(packet);
	
	/* Get port numbers for our 5-tuple */
	src_port = dst_port = 0;
	src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);
	
	/* Ignore any RFC1918 addresses, if requested */
	if (l3_type == 0x0800 && config.ignore_rfc1918 && rfc1918_ip(ip)) {
		return NULL;
	}

	/* Fragmented TCP and UDP packets will have port numbers of zero. We
	 * don't do fragment reassembly, so we will want to ignore them.
	 */
	if (src_port == 0 && dst_port == 0 && (trans_proto == 6 || trans_proto == 17))
		return NULL;

	/* Generate the flow key for this packet */
	
	/* Force ICMP flows to have port numbers of zero, rather than
	 * whatever random values trace_get_X_port might give us */
	if (trans_proto == 1 && dir == 0) {
		if(ip6) 
			pkt_id = FlowId(ip6->ip_dst.s6_addr, ip6->ip_src.s6_addr,
					0, 0, trans_proto, vlan_id, next_conn_id, dir);
		else	
			pkt_id = FlowId(ip->ip_dst.s_addr, ip->ip_src.s_addr,
					0, 0, ip->ip_p, vlan_id, next_conn_id,
					dir);
	} else if (trans_proto == 1) {
		if(ip6)
			pkt_id = FlowId(ip6->ip_src.s6_addr, ip6->ip_dst.s6_addr,
					0, 0, trans_proto, vlan_id, next_conn_id, dir);
		else
			pkt_id = FlowId(ip->ip_src.s_addr, ip->ip_dst.s_addr,
					0, 0, ip->ip_p, vlan_id, next_conn_id,
					dir);
	}
	
	else if (dir == 1) {
                /* Server port = source port */
		if(ip6)
			pkt_id = FlowId(ip6->ip_src.s6_addr, ip6->ip_dst.s6_addr,
						src_port, dst_port, trans_proto,
						vlan_id, next_conn_id, dir);
		else
			pkt_id = FlowId(ip->ip_src.s_addr, ip->ip_dst.s_addr,
						src_port, dst_port, ip->ip_p,
						vlan_id, next_conn_id, dir);
        } else {
                /* Server port = dest port */
		if(ip6)
			pkt_id = FlowId(ip6->ip_dst.s6_addr, ip6->ip_src.s6_addr,
						dst_port, src_port, trans_proto,
						vlan_id, next_conn_id, dir);
		else
			pkt_id = FlowId(ip->ip_dst.s_addr, ip->ip_src.s_addr,
						dst_port, src_port, ip->ip_p,
						vlan_id, next_conn_id, dir);
        }

	/* If we don't have an expiry plugin loaded, load it now */
	if (expirer == NULL) {
		load_plugin(config.active_plugin);

		/* Slightly drastic, but if the user cocks this up it would be
		 * rude to spam them with an error message every packet
		 */
		if (expirer == NULL) {
			fprintf(stderr, "Failed to load expiry plugin for libflowmanager -- halting program\n");
			exit(1);
		}
	}

	/* Try to find the flow key in our active flows map */
	FlowMap::iterator i = active_flows.find(pkt_id);
	
	
	if (i != active_flows.end()) {
		/* Found the flow in the map! */
		Flow *pkt_conn = *((*i).second);
		
		/* Update UDP "state" */
		if (trans_proto == 17) 
			update_udp_state(pkt_conn, dir);
		
		*is_new_flow = false;
		return pkt_conn;
	}
	
	/* If we reach this point, we must be dealing with a new flow */

	if (trans_proto == 6) {
		/* TCP */
		libtrace_tcp_t *tcp = trace_get_tcp(packet);
		
		/* TCP Flows must begin with a SYN */
		if (!tcp)
			return NULL;
		
		if(!config.tcp_anystart) {
			
			if (!tcp->syn)
				return NULL;
			
			/* Avoid creating a flow based on the SYN ACK */
			if (tcp->ack)
				return NULL;
			
			/* Create new TCP flow */
			new_conn = new Flow(pkt_id);
			new_conn->flow_state = FLOW_STATE_NEW;
		} 
		
		else {
			/* Create new TCP flow */
			new_conn = new Flow(pkt_id);
			new_conn->flow_state = FLOW_STATE_ANYSTART;
		}
	}
		
	else if (trans_proto == 1) {
		/* ICMP */
		libtrace_icmp_t *icmp_hdr;
		if(ip6)
			icmp_hdr = (libtrace_icmp_t *)trace_get_payload_from_ip6(ip6,
					NULL, &pkt_left);
		else
			icmp_hdr = (libtrace_icmp_t *)trace_get_payload_from_ip(ip,
					NULL, &pkt_left);
		
		if (!icmp_hdr)
			return NULL;

		/* Deal with special ICMP messages, e.g. errors */
		switch(icmp_hdr->type) {
			/* Time exceeded is probably part of a traceroute,
			 * rather than a genuine error */
			case 11:
				return icmp_find_original_flow(icmp_hdr, 
						pkt_left);
			
			/* These cases are all ICMP errors - find and expire
			 * the original flow */
			case 3:
			case 4:
			case 12:
			case 31:
				icmp_error(icmp_hdr, pkt_left);
				return NULL;		
		}

		/* Otherwise, we must be a legit ICMP flow */
		new_conn = new Flow(pkt_id);
		new_conn->flow_state = FLOW_STATE_NONE;
	} else {
		
		/* We don't have handy things like SYN flags to 
		 * mark the beginning of UDP connections */
		new_conn = new Flow(pkt_id);
		if (trans_proto == 17) {
			/* UDP */
			
			if (dir == 0)
				new_conn->saw_outbound = true;

			new_conn->flow_state = FLOW_STATE_UDPSHORT;

		}
		else {
			/* Unknown protocol - follow the standard UDP expiry
			 * rules */
			new_conn->flow_state = FLOW_STATE_NONE;
		}
	
	}

	/* Knowing the timestamp of the first packet for a flow is very
	 * handy */
	if (dir < 2 && new_conn->dir_info[dir].first_pkt_ts == 0.0) 
		new_conn->dir_info[dir].first_pkt_ts = trace_get_seconds(packet);

	/* Append our new flow to the appropriate LRU */
	ExpireList::iterator lruloc = expirer->add_new_flow(new_conn);
	
	/* Add our flow to the active flows map (or more correctly, add the 
	 * iterator for our new flow in the LRU to the active flows map - 
	 * this makes it easy for us to find the flow in the LRU)  */
	active_flows[new_conn->id] = lruloc;

	/* Increment the counter we use to generate flow IDs */
	next_conn_id ++;

	/* Set the is_new_flow flag to true, because we have indeed created
	 * a new flow for this packet */
	*is_new_flow = true;

	return new_conn;
}

/* Examines the TCP flags in a packet and updates the flow state accordingly
 *
 * Parameters: 
 * 	flow - the flow that the TCP packet belongs to
 * 	tcp - a pointer to the TCP header in the packet
 * 	dir - the direction of the packet (0=outgoing, 1=incoming)
 * 	ts - the timestamp from the packet
 */
void lfm_check_tcp_flags(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir, 
		double ts) {
	assert(tcp);
	assert(flow);

	if (dir >= 2)
		return;

	if (tcp->fin) {
		flow->dir_info[dir].saw_fin = true;
		
		/* If we have observed FINs in both directions now, we can
		 * move into the TCP Close state */
		if (flow->dir_info[0].saw_fin && flow->dir_info[1].saw_fin)
			flow->flow_state = FLOW_STATE_CLOSE;
		/* A FIN in only one direction suggests that one end is keen
		 * to close the connection - move into a state that has a
		 * much shorter expiry time. This should help resolve issues
		 * caused by annoying TCP stacks that do not bother to respond
		 * with a FIN ACK of their own */
		else if (flow->dir_info[0].saw_fin || flow->dir_info[1].saw_fin)
			flow->flow_state = FLOW_STATE_HALFCLOSE;
	}

	if (tcp->syn) {

		flow->dir_info[dir].saw_syn = true;

		/* SYNs in both directions will put us in the TCP Established
		 * state (note that we do not wait for the final ACK in the
		 * 3-way handshake). */

		if (flow->dir_info[0].saw_syn && flow->dir_info[1].saw_syn) {
			/* Make sure this is a SYN ACK before shifting state */
			if (tcp->ack)
				flow->flow_state = FLOW_STATE_ESTAB;
		}

		/* A SYN in only one direction puts us in the TCP Connection
		 * Establishment state, i.e. the handshake */
		else if (flow->dir_info[0].saw_syn || flow->dir_info[1].saw_syn)
			flow->flow_state = FLOW_STATE_CONN;
		
		/* We can never have a flow exist without observing an initial
		 * SYN, so we should never reach a state where neither 
		 * direction has observed a SYN */	
		else
			assert(0);
	
		/* If this is the first packet observed for this direction,
		 * record the timestamp */
		if (flow->dir_info[dir].first_pkt_ts == 0.0) 
			flow->dir_info[dir].first_pkt_ts = ts;
	}

	if (tcp->rst) {
		/* RST = instant expiry */
		flow->saw_rst = true;
		flow->flow_state = FLOW_STATE_RESET;
	}
}

/* Updates the timeout for a Flow.
 *
 * The flow state determines how long the flow can be idle before it times out. 
 *
 * Many of the values are selected based on best practice for NAT devices, 
 * which tend to be quite conservative.
 *
 * Parameters:
 * 	flow - the flow that is to be updated
 * 	ts - the timestamp of the last packet observed for the flow
 */
void lfm_update_flow_expiry_timeout(Flow *flow, double ts) {
	FlowMap::iterator i = active_flows.find(flow->id);
	ExpireList::iterator lruloc;

	if (expirer == NULL)
		return;

	/* Remove the flow from its current expiry LRU */
	flow->expire_list->erase(i->second);

	lruloc = expirer->update_expiry_timeout(flow, ts);

	/* Update the entry in the flow map */
	i->second = lruloc;
	
}

/* Finds and returns the next available flow that has expired.
 *
 * Parameters:
 * 	ts - the current timestamp 
 * 	force - if true, the next flow in the LRU will be forcibly expired,
 * 		regardless of whether it was due to expire or not.
 *
 * Returns:
 * 	a flow that has expired, or NULL if there are no expired flows 
 * 	available
 */
Flow *lfm_expire_next_flow(double ts, bool force) {
	Flow *exp_flow;

	if (expirer == NULL)
		return NULL;

	exp_flow = expirer->expire_next_flow(ts, force);
	if (exp_flow) 
		active_flows.erase(exp_flow->id);
	return exp_flow;
	
}


/* Calls the provided function with each active flow as a parameter. Enables
 * programmers to do something to each active flow without needing to expire
 * the flows. An example might be to periodically grab packet and bytes counts 
 * for long-running flows.
 *
 * Parameters:
 *	func - 	the function to be called for each active flow. Takes two 
 *		parameters: the flow itself and a void pointer pointing to
 *		any additional user data required for that function. The
 *		function must return an int: -1 for error, 0 for terminate
 *		and 1 for continue
 *	data - 	the user data to be passed into each function call
 *
 * Returns:
 *	-1 if an error occurred, 1 otherwise.
 */
int lfm_foreach_flow(int (*func)(Flow *f, void *userdata), void *data) {

	FlowMap::iterator i;

	for (i = active_flows.begin(); i != active_flows.end(); i++) {
		int ret = 0;
		Flow *f = *(i->second);

		ret = func(f, data);
		if (ret == -1) 
			return -1;
		if (ret == 0)
			break;
	}
	
	return 1;
}

/* Frees the memory associated with a Flow structure - note that this does
 * NOT include any memory the user has allocated for the extension pointer!
 *
 * Basically, this is a nice replacement for the delete we used to make the 
 * user perform after they had finished with an expired flow.
 *
 * Parameters:
 *	f - the flow to be deleted
 */
void lfm_release_flow(Flow *f) {
	delete(f);
}

/* Constructors and Destructors */
Flow::Flow(const FlowId conn_id) {
	id = conn_id;
	expire_list = NULL;
	expire_time = 0.0;
	saw_rst = false;
	saw_outbound = false;
	flow_state = FLOW_STATE_NONE;
	expired = false;
	extension = NULL;
}

DirectionInfo::DirectionInfo() {
	saw_fin = false;
	saw_syn = false;
	first_pkt_ts = 0.0;
}

