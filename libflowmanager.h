#ifndef LIBFLOWMANAGER_H_
#define LIBFLOWMANAGER_H_

#include <map>
#include <list>
#include <inttypes.h>

#include <libtrace.h>

typedef enum {
	LFM_CONFIG_IGNORE_RFC1918,
	LFM_CONFIG_TCP_TIMEWAIT,
	LFM_CONFIG_SHORT_UDP
		
} lfm_config_t;

/* We just use a standard 5-tuple as a flow key */
/* XXX: Consider expanding this to support mac addresses as well */
class FlowId {
        private:
        int cmp(const FlowId &b) const ;

        uint32_t ip_a;
        uint32_t ip_b;
        uint16_t port_a;
        uint16_t port_b;
        uint8_t proto;
        uint32_t id_num;

        public:
        FlowId();

        FlowId(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src,
                        uint16_t port_dst, uint8_t protocol, uint32_t id);

        bool operator<(const FlowId &b) const ;

        uint32_t get_id_num() const ;
        char *get_server_ip_str() const ;
        char *get_client_ip_str() const ;
        uint32_t get_server_ip() const ;
	uint32_t get_client_ip() const ;
	uint16_t get_server_port() const ;
        uint16_t get_client_port() const ;
        uint8_t get_protocol() const ;

};

/* List of TCP connection states, including a NOT TCP state which should
 * be used by all non-TCP transports 
 *
 * XXX I've started including UDP "state" in */
typedef enum {
	TCP_STATE_NOTTCP,
	TCP_STATE_NEW,
	TCP_STATE_CONN,
	TCP_STATE_ESTAB,
	TCP_STATE_HALFCLOSE,
	TCP_STATE_RESET,
	TCP_STATE_CLOSE,
	TCP_STATE_UDPSHORT,
	TCP_STATE_UDPLONG
} tcp_state_t;

/* Standard per-direction information, including the reordering list */
class DirectionInfo {
	public:
		//tcp_reorder_t packet_list;
		double first_pkt_ts;
		bool saw_fin; /* Have we seen a TCP FIN in this direction */
		bool saw_syn; /* Have we seen a TCP SYN in this direction */

		DirectionInfo();
		~DirectionInfo();
};

typedef std::list<class Flow *> ExpireList;

class Flow {
	public:
		FlowId id;
		DirectionInfo dir_info[2];
		ExpireList *expire_list; /* Which expiry list we are in */
		double expire_time;	 /* When we are due to expire */
		tcp_state_t tcp_state;
		bool saw_rst;	/* Have we seen a TCP RST for this flow */
		bool expired;
		bool saw_outbound;
		
		/* Users of this library can use this pointer to store
		 * per-flow data they require above and beyond what is
		 * defined in this class definition */
		void *extension; 
		
		Flow(const FlowId conn_id);
};

typedef std::map<FlowId, ExpireList::iterator> FlowMap;

Flow *lfm_find_managed_flow(uint32_t ip_a, uint32_t ip_b, uint16_t port_a, 
		uint16_t port_b, uint8_t proto);
Flow *lfm_match_packet_to_flow(libtrace_packet_t *packet, uint8_t dir, 
		bool *is_new_flow);
void lfm_check_tcp_flags(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir, 
		double ts);
void lfm_update_flow_expiry_timeout(Flow *flow, double ts);
Flow *lfm_expire_next_flow(double ts, bool force);
int lfm_set_config_option(lfm_config_t opt, void *value);

#endif
