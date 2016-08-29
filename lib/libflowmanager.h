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

#ifndef LIBFLOWMANAGER_H_
#define LIBFLOWMANAGER_H_

#include <stdio.h>

/* #include <unordered_map> */
#include <map>
#include <list>
#include <inttypes.h>

#include <libtrace.h>

#ifdef __cplusplus
extern "C" {
#endif 

/* Support configuration options for libflowmanager */
typedef enum {
	/* Ignore packets containing RFC 1918 addresses */
	LFM_CONFIG_IGNORE_RFC1918,

	/* Wait a short time before expiring flows for TCP connections that
	 * have closed via FIN packets */
	LFM_CONFIG_TCP_TIMEWAIT,

	/* Use experimental fast expiry for short-lived UDP flows */
	LFM_CONFIG_SHORT_UDP,

	/* Use VLAN Id as part of flow keys */
	LFM_CONFIG_VLAN,

	/* Ignore ICMP errors that would normally expire a flow immediately */
	LFM_CONFIG_IGNORE_ICMP_ERROR,

	/* handle IPv6 only */
	LFM_CONFIG_DISABLE_IPV4,

	/* handle IPv4 only */
	LFM_CONFIG_DISABLE_IPV6,
	
	LFM_CONFIG_TCP_ANYSTART,

	LFM_CONFIG_EXPIRY_PLUGIN,

	LFM_CONFIG_FIXED_EXPIRY_THRESHOLD,

	LFM_CONFIG_TIMEWAIT_THRESHOLD,

} lfm_config_t;

typedef enum {
	LFM_PLUGIN_STANDARD,
	LFM_PLUGIN_STANDARD_SHORT_UDP,
	LFM_PLUGIN_FIXED_INACTIVE,
} lfm_plugin_id_t;


/* We just use a standard 5-tuple as a flow key (with rudimentary support for
 * VLAN Ids) */
/* XXX: Consider expanding this to support mac addresses as well */
class FlowId {
        private:

	/* The five tuple */
	union {
        	uint32_t ip4_a;
		uint8_t ip6_a[16];
	} ip_a;
	union {
        	uint32_t ip4_b;
		uint8_t ip6_b[16];
	} ip_b;

        uint16_t port_a;
        uint16_t port_b;
        uint8_t proto;

	/* IP version, 4 or 6 */
	uint8_t ip_v;

	/* VLAN Id */
        uint16_t vlan;
	/* Unique flow ID number */
	uint64_t id_num;

	uint8_t init_dir;

        public:
        FlowId();

        FlowId(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src,
                        uint16_t port_dst, uint8_t protocol, uint16_t vlan,
			uint64_t id, uint8_t dir);

        FlowId(uint8_t ip_src[16], uint8_t ip_dst[16], uint16_t port_src,
                        uint16_t port_dst, uint8_t protocol, uint16_t vlan,
			uint64_t id, uint8_t dir);

        bool operator<(const FlowId &b) const ;
	bool operator==(const FlowId &b) const;

	/* Accessor functions */
        uint64_t get_id_num() const ;
        void get_server_ip_str(char * ret) const ;
        void get_client_ip_str(char * ret) const ;
	void get_local_ip_str(char *ret) const;
	void get_external_ip_str(char *ret) const;

        uint32_t get_server_ip() const ;
        uint8_t * get_server_ip6() const ;
	uint32_t get_client_ip() const ;
	uint8_t * get_client_ip6() const ;
	uint32_t get_local_ip() const;
	uint8_t * get_local_ip6() const;
	uint32_t get_external_ip() const;
	uint8_t * get_external_ip6() const;
	uint16_t get_server_port() const ;
        uint16_t get_client_port() const ;
	uint16_t get_local_port() const;
	uint16_t get_external_port() const;
	uint16_t get_vlan_id() const ;
        uint8_t get_protocol() const ;
        uint8_t get_ip_version() const ;

};

/* List of flow states - flow state often determines how long a flow must be
 * idle before expiring */
typedef enum {
	/* Unknown protocol - no sensible state is possible */
	FLOW_STATE_NONE,	
	
	/* New TCP connection */
	FLOW_STATE_NEW,
	
	/* Unestablished TCP connection */
	FLOW_STATE_CONN,

	/* Established TCP connection */
	FLOW_STATE_ESTAB,

	/* Half-closed TCP connection */
	FLOW_STATE_HALFCLOSE,

	/* Reset TCP connection */
	FLOW_STATE_RESET,

	/* Closed TCP connection */
	FLOW_STATE_CLOSE,

	/* UDP flow where only one outgoing packet has been observed */
	FLOW_STATE_UDPSHORT,

	/* UDP flow where multiple outgoing packets have been seen */
	FLOW_STATE_UDPLONG,

	/* Flow experienced an ICMP error */
	FLOW_STATE_ICMPERROR,


	/* A flow starting on any packet */
	FLOW_STATE_ANYSTART
} flow_state_t;

/* Data that must be stored separately for each half of the flow */
class DirectionInfo {
	public:
		double first_pkt_ts; /* Timestamp of first observed packet */
		bool saw_fin; /* Have we seen a TCP FIN in this direction */
		bool saw_syn; /* Have we seen a TCP SYN in this direction */

		DirectionInfo();
};

/* An list of flows, ordered by expire time */
typedef std::list<class Flow *> ExpireList;

class Flow {
	public:
		/* The flow key for this flow */
		FlowId id;
		
		/* Per-direction information */
		DirectionInfo dir_info[2];

		/* The LRU that the flow is currently in */
		ExpireList *expire_list; 

		/* The timestamp that the flow is due to expire */
		double expire_time;

		/* Current flow state */
		flow_state_t flow_state; 

		/* Have we seen a reset for this flow? */
		bool saw_rst;	

		/* Has the flow been expired by virtue of being idle for too
		 * long (vs a forced expiry, for instance) */
		bool expired;

		/* Has an outbound packet been observed for this flow */
		bool saw_outbound;
		
		/* Users of this library can use this pointer to store
		 * per-flow data they require above and beyond what is
		 * defined in this class definition */
		void *extension; 
		
		/* Constructor */
		Flow(const FlowId conn_id);
};

struct flowid_hash {
	size_t operator()(const FlowId &x) const{
		uint64_t key = 0;
		if (x.get_ip_version() == 4) {
			key = ((uint64_t)x.get_server_ip());
			key += ((uint64_t)x.get_client_ip());
			key *= ((uint64_t)x.get_server_port());
			key *= ((uint64_t)x.get_client_port());
		} else {
			key = x.get_server_port(); 
			key *= 0xc4ceb9fe1a85ec53;
			key += x.get_client_port();
		}
		

		//fprintf(stdout, "%lu %d\n", x.get_id_num(), (size_t)key);	
		return (size_t)key;
	}
};

/* Tried unordered map but it is surprisingly slow compared to a regular map */
//typedef std::unordered_map<FlowId, ExpireList::iterator, flowid_hash> FlowMap;



typedef std::map<FlowId, ExpireList::iterator> FlowMap;

struct lfm_plugin_t {

	lfm_plugin_id_t id;

	ExpireList::iterator (*add_new_flow) (Flow *f);
	ExpireList::iterator (*update_expiry_timeout)(Flow *f, double ts);
	Flow * (*expire_next_flow)(double ts, bool force);
	void (*set_inactivity_threshold)(double thresh);
	void (*set_timewait_threshold)(double thresh);

};

/* Search the active flows map for a flow matching the given 5-tuple
 *
 * Parameters:
 *      ip_a - the IP address of the first endpoint
 *      ip_b - the IP address of the second endpoint
 *      port_a - the port number used by the first endpoint
 *      port_b - the port number used by the second endpoint
 *      proto - the transport protocol
 *
 * Returns:
 * 	a pointer to the flow matching the provided 5-tuple, or NULL if no
 * 	matching flow exists.
 */
Flow *lfm_find_managed_flow(uint32_t ip_a, uint32_t ip_b, uint16_t port_a, 
		uint16_t port_b, uint8_t proto);

/* Returns a pointer to the Flow that matches the packet provided. If no such
 * Flow exists, a new Flow is created and added to the flow map before being
 * returned.
 *
 * Parameters:
 *      packet - the packet that is to be matched with a flow
 *      dir - the direction of the packet. 0 indicates outgoing, 1 indicates
 *            incoming.
 *      is_new_flow - a boolean flag that is set to true by this function if
 *                    a new flow was created for this packet. It is set to 
 *                    false if the returned flow already existed in the flow 
 *                    map.
 * 
 * Returns:
 *      a pointer to the entry in the active flow map that matches the packet
 *      provided, or NULL if the packet cannot be matched to a flow
 *
 */
Flow *lfm_match_packet_to_flow(libtrace_packet_t *packet, uint8_t dir, 
		bool *is_new_flow);

/* Examines the TCP flags in a packet and updates the flow state accordingly
 *
 * Parameters: 
 *      flow - the flow that the TCP packet belongs to
 *      tcp - a pointer to the TCP header in the packet
 *      dir - the direction of the packet (0=outgoing, 1=incoming)
 *      ts - the timestamp from the packet
 */
void lfm_check_tcp_flags(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir, 
		double ts);

/* Updates the timeout for a Flow.
 *
 * The flow state determines how long the flow can be idle before it times out. 
 *
 * Many of the values are selected based on best practice for NAT devices, 
 * which tend to be quite conservative.
 *
 * Parameters:
 *      flow - the flow that is to be updated
 *      ts - the timestamp of the last packet observed for the flow
 */
void lfm_update_flow_expiry_timeout(Flow *flow, double ts);


/* Finds and returns the next available flow that has expired.
 *
 * Parameters:
 *      ts - the current timestamp 
 *      force - if true, the next flow in the LRU will be forcibly expired,
 *              regardless of whether it was due to expire or not.
 *
 * Returns:
 *      a flow that has expired, or NULL if there are no expired flows 
 *      available in any of the LRUs
 *
 * NOTE: you MUST call delete() yourself on the flow that is returned by this 
 * function once you are finished with it.
 * It is also your responsibility to free any memory that is stored in the
 * "extension" pointer before deleting the flow.
 *
 */
Flow *lfm_expire_next_flow(double ts, bool force);

/* Sets a libflowmanager configuration option.
 *
 * Note that config options should be set BEFORE any packets are passed in
 * to other libflowmanager functions.
 *
 * Parameters:
 *      opt - the config option that is being changed
 *      value - the value to set the option to
 *
 * Returns:
 *      1 if the option is set successfully, 0 otherwise
 */
int lfm_set_config_option(lfm_config_t opt, void *value);

/* Calls the provided function with each active flow as a parameter. Enables
 * programmers to do something to each active flow without needing to expire
 * the flows. An example might be to periodically grab packet and bytes counts 
 * for long-running flows.
 *
 * Parameters:
 *      func -  the function to be called for each active flow. Takes two 
 *              parameters: the flow itself and a void pointer pointing to
 *              any additional user data required for that function. The
 *              function must return an int: -1 for error, 0 for terminate
 *              and 1 for continue
 *      data -  the user data to be passed into each function call
 *
 * Returns:
 *      -1 if an error occurred, 1 otherwise.
 */
int lfm_foreach_flow(int (*func)(Flow *f, void *userdata), void *data);

/* Frees the memory associated with a Flow structure - note that this does
 * NOT include any memory the user has allocated for the extension pointer!
 *
 * Basically, this is a nice replacement for the delete we used to make the 
 * user perform after they had finished with an expired flow.
 *
 * Parameters:
 *      f - the flow to be deleted
 */
void lfm_release_flow(Flow *f);

#ifdef __cplusplus
}
#endif 

#endif
