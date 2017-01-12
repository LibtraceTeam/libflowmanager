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

/* Provides a simple function that autoconf can use to easily check
 * whether libflowmanager 3 is installed or not.
 */

void lfm_version_three(void) {
        return;
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

FlowManager::FlowManager() {

        this->active = new FlowMap();
        this->nextconnid = 0;
        this->expirer = NULL;

        /* Default config options... */

        /* Include flows involving RFC 1918 addresses */
        this->config.ignore_rfc1918 = false;

        /* Immediately expire flow after seeing FIN ACKs in each direction */
        this->config.tcp_timewait = false;

        /* Do not try to quickly expire single packet UDP flows */
        this->config.short_udp = false;

        /* Do not use the VLAN ID as part of the flow key */
        this->config.key_vlan = false;

        /* Expire flows if we see a corresponding ICMP error message */
        this->config.ignore_icmp_errors = false;

        /* Do NOT discard IPv4 flows */
        this->config.disable_ipv4 = false;

        /* Do NOT discard IPv6 flows */
        this->config.disable_ipv6 = false;

        /* Only create a new TCP flow if we observe a SYN */
        this->config.tcp_anystart = false;

        /* Use standard flow expiry rules */
        this->config.active_plugin = LFM_PLUGIN_STANDARD;

        /* If using a fixed expiry policy, use the default expiry time */
        this->config.fixed_expiry = 0;

        /* Time to wait before expiring a flow that has seen FIN ACKs
         * in both directions.
         */
        this->config.timewait_thresh = 0;

}

FlowManager::~FlowManager() {

        Flow *f = NULL;
        if (this->expirer) {
                while ((f = this->expireNextFlow(0, true)) != NULL) {
                        if (f->extension)
                                free(f->extension);
                        delete(f);
                }
        }
        this->active->clear();
        delete(this->active);

}


void FlowManager::loadExpiryPlugin() {
        switch(this->config.active_plugin) {
	case LFM_PLUGIN_STANDARD:
		this->expirer = load_standard_plugin();
		break;
	case LFM_PLUGIN_STANDARD_SHORT_UDP:
		this->expirer = load_shortudp_plugin();
		break;
	case LFM_PLUGIN_FIXED_INACTIVE:
		this->expirer = load_fixed_inactive();
		break;
	default:
		fprintf(stderr, "load_plugin: Invalid plugin ID %d\n",
                                this->config.active_plugin);
		return;
	}

	if (this->expirer->set_inactivity_threshold != NULL &&
			this->config.fixed_expiry != 0) {
		this->expirer->set_inactivity_threshold(this->config.fixed_expiry);
	}

	if (this->expirer->set_timewait_threshold != NULL &&
			this->config.tcp_timewait != 0)
		this->expirer->set_timewait_threshold(this->config.timewait_thresh);

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
int FlowManager::setConfigOption(lfm_config_t opt, void *value) {
	if (!this->active->empty()) {
		fprintf(stderr, "Cannot change configuration once processing has begun!\n");
		return 0;
	}

	switch(opt) {
	case LFM_CONFIG_IGNORE_RFC1918:
		this->config.ignore_rfc1918 = *(bool *)value;
		return 1;
	case LFM_CONFIG_TCP_TIMEWAIT:
		this->config.tcp_timewait = *(bool *)value;
		return 1;
	case LFM_CONFIG_SHORT_UDP:
		this->config.short_udp = *(bool *)value;
		if (this->config.short_udp)
			this->config.active_plugin = LFM_PLUGIN_STANDARD_SHORT_UDP;
		return 1;
	case LFM_CONFIG_VLAN:
		this->config.key_vlan = *(bool *)value;
		return 1;
	case LFM_CONFIG_IGNORE_ICMP_ERROR:
		this->config.ignore_icmp_errors = *(bool *)value;
		return 1;

	case LFM_CONFIG_DISABLE_IPV4:
		this->config.disable_ipv4 = *(bool *)value;
		return 1;
	case LFM_CONFIG_DISABLE_IPV6:
		this->config.disable_ipv6 = *(bool *)value;
		return 1;
	case LFM_CONFIG_TCP_ANYSTART:
		this->config.tcp_anystart = *(bool *)value;
		return 1;
	case LFM_CONFIG_EXPIRY_PLUGIN:
		this->config.active_plugin = *(lfm_plugin_id_t *)value;
		return 1;
	case LFM_CONFIG_FIXED_EXPIRY_THRESHOLD:
		this->config.fixed_expiry = *(double *)value;
		return 1;
	case LFM_CONFIG_TIMEWAIT_THRESHOLD:
		this->config.timewait_thresh = *(double *)value;
		return 1;
	}
	return 0;
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
Flow *FlowManager::findManagedFlow(uint32_t ip_a, uint32_t ip_b,
                uint16_t port_a, uint16_t port_b, uint8_t proto) {

	FlowId flow_id_first;
	FlowId flow_id_backup;
	FlowMap::iterator i;

	/* If we're ignoring RFC1918 addresses, there's no point 
	 * looking for a flow with an RFC1918 address */
	if (this->config.ignore_rfc1918 && rfc1918_ip_addr(ip_a)) 
		return NULL;
	if (this->config.ignore_rfc1918 && rfc1918_ip_addr(ip_b)) 
		return NULL;

	/* XXX: We always are going to use a vlan id of zero. At some
	 * point this function should accept a vlan ID as a parameter */

	flow_id_first = FlowId(ip_a, ip_b, port_a, port_b, 0, proto, 0, 0);
	flow_id_backup = FlowId(ip_b, ip_a, port_b, port_a, 0, proto, 0, 0);

        i = this->active->find(flow_id_first);

	if (i != this->active->end()) {
		/* Not in the map */
		return *((*i).second);
	}

        i = this->active->find(flow_id_backup);
	if (i != this->active->end()) {
		/* Not in the map */
		return *((*i).second);
	}
        return NULL;
}

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
Flow *FlowManager::findManagedFlow(uint8_t *ip_a, uint8_t *ip_b,
                uint16_t port_a, uint16_t port_b, uint8_t proto) {

	FlowId flow_id_first;
	FlowId flow_id_backup;
	FlowMap::iterator i;

	/* XXX: We always are going to use a vlan id of zero. At some
	 * point this function should accept a vlan ID as a parameter */

	flow_id_first = FlowId(ip_a, ip_b, port_a, port_b, 0, proto, 0, 0);
	flow_id_backup = FlowId(ip_b, ip_a, port_b, port_a, 0, proto, 0, 0);

        i = this->active->find(flow_id_first);

	if (i != this->active->end()) {
		/* Not in the map */
		return *((*i).second);
	}

        i = this->active->find(flow_id_backup);
	if (i != this->active->end()) {
		/* Not in the map */
		return *((*i).second);
	}
        return NULL;
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
Flow *FlowManager::findFlowFromICMP(void *icmp_hdr, uint32_t rem, bool is_v6) {
        libtrace_ip_t *orig_ip = NULL;
	libtrace_ip6_t *orig_ip6 = NULL;
        uint16_t src_port, dst_port;
        uint32_t src_ip, dst_ip;
	uint8_t src_ip6[16], dst_ip6[16];
        uint8_t proto;
        Flow *orig_flow = NULL;
        void *post_ip = NULL;

        /* ICMP error message packets include the IP header + 8 bytes of the
	 * original packet that triggered the error in the first place.
	 *
	 * Recent WAND captures tend to keep that post-ICMP payload, so we
	 * can do match ICMP errors back to the flows that caused them */

	/* First step, see if we can access the post-ICMP payload */

        if (is_v6) {
                orig_ip6 = (libtrace_ip6_t *)trace_get_payload_from_icmp6(
                                (libtrace_icmp6_t *)icmp_hdr, &rem);
        } else {
                orig_ip = (libtrace_ip_t*)trace_get_payload_from_icmp(
                                (libtrace_icmp_t *)icmp_hdr, &rem);
        }

        if (orig_ip) {
                if (rem < sizeof(libtrace_ip_t))
                        return NULL;

		src_ip = orig_ip->ip_src.s_addr;
		dst_ip = orig_ip->ip_dst.s_addr;
		proto = orig_ip->ip_p;
		rem -= (orig_ip->ip_hl * 4);
		post_ip = (char *)orig_ip + (orig_ip->ip_hl * 4);
        } else if (orig_ip6) {
                if (rem < sizeof(libtrace_ip6_t))
                        return NULL;
		memcpy(src_ip6, orig_ip6->ip_src.s6_addr, sizeof(src_ip6));
		memcpy(dst_ip6, orig_ip6->ip_dst.s6_addr, sizeof(dst_ip6));
		post_ip = trace_get_payload_from_ip6(orig_ip6, &proto, &rem);

        } else {
                return NULL;
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
	if (orig_ip6)
		orig_flow = this->findManagedFlow(src_ip6, dst_ip6, src_port,
						dst_port, proto);
	else
        	orig_flow = this->findManagedFlow(src_ip, dst_ip, src_port,
                                                dst_port, proto);

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
void FlowManager::expireICMPError(void *icmp_hdr, uint32_t rem, bool is_v6) {
	Flow *orig_flow;

	if (this->config.ignore_icmp_errors)
		return;

	orig_flow = this->findFlowFromICMP(icmp_hdr, rem, is_v6);
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
void FlowManager::updateUDPState(Flow *f, uint8_t dir) {

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
Flow *FlowManager::matchPacketToFlow(libtrace_packet_t *packet, uint8_t dir, 
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
	/* For now, deal with IPv4 only */
	if (l3_type != 0x0800 && l3_type != 0x86DD) return NULL;

	if (ip->ip_v == 6) {
		if (this->config.disable_ipv6)
			return NULL;
		ip6 = (libtrace_ip6_t*)ip;
		ip = NULL;
	} else {
		if (this->config.disable_ipv4)
			return NULL;
	}

	trace_get_transport(packet, &trans_proto, &rem);

	/* If the VLAN key option is set, we'll need the VLAN id */
	if (this->config.key_vlan)
		vlan_id = extract_vlan_id(packet);

	/* Get port numbers for our 5-tuple */
	src_port = dst_port = 0;
	src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);

	/* Ignore any RFC1918 addresses, if requested */
	if (ip && this->config.ignore_rfc1918 && rfc1918_ip(ip)) {
		return NULL;
	}

	/* Fragmented TCP and UDP packets will have port numbers of zero. We
	 * don't do fragment reassembly, so we will want to ignore them.
	 */
	if (src_port == 0 && dst_port == 0 &&
                        (trans_proto == 6 || trans_proto == 17)) {
		return NULL;
        }

	/* Generate the flow key for this packet */
	
	/* Force ICMP flows to have port numbers of zero, rather than
	 * whatever random values trace_get_X_port might give us */
	if (trans_proto == 1 && dir == 0) {
		if (ip6) {
			pkt_id = FlowId(ip6->ip_dst.s6_addr,ip6->ip_src.s6_addr,
				0, 0, trans_proto, vlan_id, this->nextconnid,
                                dir);
                }
		else {
			pkt_id = FlowId(ip->ip_dst.s_addr, ip->ip_src.s_addr,
				0, 0, ip->ip_p, vlan_id, this->nextconnid,
				dir);
                }
	} else if (trans_proto == 1) {
		if (ip6) {
			pkt_id = FlowId(ip6->ip_src.s6_addr,ip6->ip_dst.s6_addr,
				0, 0, trans_proto, vlan_id, this->nextconnid,
                                dir);
                }
		else {
			pkt_id = FlowId(ip->ip_src.s_addr, ip->ip_dst.s_addr,
					0, 0, ip->ip_p, vlan_id,
                                        this->nextconnid, dir);
                }
	}

	else if (dir == 1) {
                /* Server port = source port */
		if (ip6) {
			pkt_id = FlowId(ip6->ip_src.s6_addr,ip6->ip_dst.s6_addr,
						src_port, dst_port, trans_proto,
						vlan_id, this->nextconnid, dir);
                }
		else {
			pkt_id = FlowId(ip->ip_src.s_addr, ip->ip_dst.s_addr,
						src_port, dst_port, ip->ip_p,
						vlan_id, this->nextconnid, dir);
                }
        } else {
                /* Server port = dest port */
		if (ip6) {
			pkt_id = FlowId(ip6->ip_dst.s6_addr,
                                                ip6->ip_src.s6_addr,
						dst_port, src_port, trans_proto,
						vlan_id, this->nextconnid, dir);
                }
		else {
			pkt_id = FlowId(ip->ip_dst.s_addr, ip->ip_src.s_addr,
						dst_port, src_port, ip->ip_p,
						vlan_id, this->nextconnid, dir);
                }
        }

	/* If we don't have an expiry plugin loaded, load it now */
	if (this->expirer == NULL) {
		this->loadExpiryPlugin();

		/* Slightly drastic, but if the user cocks this up it would be
		 * rude to spam them with an error message every packet
		 */
		if (this->expirer == NULL) {
			fprintf(stderr, "Failed to load expiry plugin for libflowmanager -- halting program\n");
			exit(1);
		}
	}

	/* Try to find the flow key in our active flows map */
	FlowMap::iterator i = this->active->find(pkt_id);

	if (i != this->active->end()) {
		/* Found the flow in the map! */
		Flow *pkt_conn = *((*i).second);

//		if (trans_proto == 17) 
//			update_udp_state(pkt_conn, dir);

		*is_new_flow = false;
		return pkt_conn;
	}

	/* If we reach this point, we must be dealing with a new flow */

        /* TODO ICMPv6 */
	if (trans_proto == TRACE_IPPROTO_TCP) {
		/* TCP */
		libtrace_tcp_t *tcp = trace_get_tcp(packet);

		/* TCP Flows must begin with a SYN */
		if (!tcp)
			return NULL;

		if(!this->config.tcp_anystart) {

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

	else if (trans_proto == TRACE_IPPROTO_ICMP) {
		/* ICMP */
		libtrace_icmp_t *icmp_hdr;
                icmp_hdr = (libtrace_icmp_t *)
                                trace_get_payload_from_ip(ip,
                                NULL, &pkt_left);

		if (!icmp_hdr)
			return NULL;

		/* Deal with special ICMP messages, e.g. errors */
		switch(icmp_hdr->type) {
			/* Time exceeded is probably part of a traceroute,
			 * rather than a genuine error */
			case 11:
				return this->findFlowFromICMP(icmp_hdr, 
						pkt_left, false);

			/* These cases are all ICMP errors - find and expire
			 * the original flow */
			case 3:
			case 4:
			case 12:
			case 31:
				this->expireICMPError(icmp_hdr, pkt_left,
                                                false);
				return NULL;
		}

		/* Otherwise, we must be a legit ICMP flow */
		new_conn = new Flow(pkt_id);
		new_conn->flow_state = FLOW_STATE_NONE;
	} else {

		/* We don't have handy things like SYN flags to 
		 * mark the beginning of UDP connections */
		new_conn = new Flow(pkt_id);
		if (trans_proto == TRACE_IPPROTO_UDP) {
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
	ExpireList::iterator lruloc = this->expirer->add_new_flow(new_conn);

	/* Add our flow to the active flows map (or more correctly, add the 
	 * iterator for our new flow in the LRU to the active flows map - 
	 * this makes it easy for us to find the flow in the LRU)  */
	(*this->active)[new_conn->id] = lruloc;

	/* Increment the counter we use to generate flow IDs */
	this->nextconnid ++;

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
void FlowManager::updateTCPState(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir) {
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
void FlowManager::updateFlowExpiry(Flow *flow, libtrace_packet_t *packet,
                uint8_t dir, double ts) {
	FlowMap::iterator i = this->active->find(flow->id);
	ExpireList::iterator lruloc;

        /* If this is the first packet observed for this direction,
         * record the timestamp */
        if (flow->dir_info[dir].first_pkt_ts == 0.0)
                flow->dir_info[dir].first_pkt_ts = ts;

	if (this->expirer == NULL)
		return;

        uint8_t proto;
        uint32_t rem;
        void *trans;

        if ((trans = trace_get_transport(packet, &proto, &rem)) == NULL)
                return;

        if (proto == TRACE_IPPROTO_TCP)
                this->updateTCPState(flow, (libtrace_tcp_t *)trans, dir);

        if (proto == TRACE_IPPROTO_UDP)
                this->updateUDPState(flow, dir);

	/* Remove the flow from its current expiry LRU */
	flow->expire_list->erase(i->second);

	lruloc = this->expirer->update_expiry_timeout(flow, ts);

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
Flow *FlowManager::expireNextFlow(double ts, bool force) {
	Flow *exp_flow;

	if (this->expirer == NULL)
		return NULL;

	exp_flow = this->expirer->expire_next_flow(ts, force);
	if (exp_flow)
		this->active->erase(exp_flow->id);
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
int FlowManager::foreachFlow(int (*func)(Flow *f, void *userdata), void *data) {

	FlowMap::iterator i;

	for (i = this->active->begin(); i != this->active->end(); i++) {
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
void FlowManager::releaseFlow(Flow *f) {
	delete(f);
}

