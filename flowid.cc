#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libflowmanager.h"

/* Most of the code in here is just accessor functions and constructors for
 * the FlowId class - shouldn't require too much explanation */

/* Comparator function for a FlowId */
int FlowId::cmp (const FlowId &b) const {
	if (port_b != b.port_b)
		return port_b - b.port_b;
	if (port_a != b.port_a)
		return port_a - b.port_a;

	if (ip_b != b.ip_b)
		return (ip_b < b.ip_b);

	if (ip_b < b.ip_b)    return -1;
	if (ip_b > b.ip_b)    return 1;
	if (ip_a < b.ip_a)    return -1;
	if (ip_a > b.ip_a)    return 1;

	return proto - b.proto;
}

FlowId::FlowId() {
	ip_a = 0;
	ip_b = 0;
	port_a = 0;
	port_b = 0;
	proto = 0;
	id_num = 0;
}

FlowId::FlowId(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src,
		uint16_t port_dst, uint8_t protocol, uint32_t id) {
	ip_a = ip_src;
	ip_b = ip_dst;
	port_a = port_src;
	port_b = port_dst;
	proto = protocol;
	id_num = id;
}

bool FlowId::operator<(const FlowId &b) const {
       	if (port_b != b.port_b)
		return port_b < b.port_b;
	if (port_a != b.port_a)
		return port_a < b.port_a;

	if (ip_b != b.ip_b)
		return (ip_b < b.ip_b);

	if (ip_a != b.ip_a)
		return ip_a < b.ip_a;

	return proto < b.proto;

}

uint32_t FlowId::get_id_num() const {
	return id_num;
}

char * FlowId::get_server_ip_str() const {
	struct in_addr inp;
	inp.s_addr = ip_a;
	return inet_ntoa(inp);
}

char * FlowId::get_client_ip_str() const {
	struct in_addr inp;
	inp.s_addr = ip_b;
	return inet_ntoa(inp);
}

uint32_t FlowId::get_server_ip() const {
	return ip_a;
}

uint32_t FlowId::get_client_ip() const {
	return ip_b;
}

uint16_t FlowId::get_server_port() const {
	return port_a;
}

uint16_t FlowId::get_client_port() const {
	return port_b;
}

uint8_t FlowId::get_protocol() const {
	return proto;
}

