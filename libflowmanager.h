#ifndef LIBFLOWMANAGER_H_
#define LIBFLOWMANAGER_H_

#include <map>
#include <list>
#include <inttypes.h>
#include "tcp_reorder.h"

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
        uint16_t get_server_port() const ;
        uint16_t get_client_port() const ;
        uint8_t get_protocol() const ;

};


typedef enum {
	TCP_STATE_NOTTCP,
	TCP_STATE_NEW,
	TCP_STATE_CONN,
	TCP_STATE_ESTAB,
	TCP_STATE_HALFCLOSE,
	TCP_STATE_RESET,
	TCP_STATE_CLOSE
} tcp_state_t;

class DirectionInfo {
	public:
		tcp_reorder_t packet_list;
		double first_pkt_ts;
		bool saw_fin;
		bool saw_syn;

		DirectionInfo();
		~DirectionInfo();
};

typedef std::list<class Flow *> ExpireList;

class Flow {
	public:
		FlowId id;
		DirectionInfo dir_info[2];
		ExpireList *expire_list;
		double expire_time;
		tcp_state_t tcp_state;
		bool saw_rst;

		void *extension;
		
		Flow(const FlowId conn_id);
};

typedef std::map<FlowId, ExpireList::iterator> FlowMap;

Flow *get_managed_flow(libtrace_packet_t *packet, bool *is_new_flow);
void check_tcp_flags(Flow *flow, libtrace_tcp_t *tcp, uint8_t dir, double ts);
void update_flow_expiry_timeout(Flow *flow, double ts);
Flow *expire_next_flow(double ts, bool force);

#endif
