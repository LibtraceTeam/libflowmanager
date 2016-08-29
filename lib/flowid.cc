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


#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libflowmanager.h"

/* Most of the code in here is just accessor functions and constructors for
 * the FlowId class - shouldn't require too much explanation */

/* Constructor for a flow ID - set everything to zero! */
FlowId::FlowId() {
	ip_a.ip4_a = 0;
	ip_b.ip4_b = 0;
	port_a = 0;
	port_b = 0;
	proto = 0;
	vlan = 0;
	id_num = 0;
	ip_v = 4;
	init_dir = 0;
}

/* A more useful constructor where we're provided with the values for the
 * flow key */
FlowId::FlowId(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src,
		uint16_t port_dst, uint8_t protocol, uint16_t vlan_id,
		uint64_t id, uint8_t dir) {
	ip_a.ip4_a = ip_src;
	ip_b.ip4_b = ip_dst;
	port_a = port_src;
	port_b = port_dst;
	proto = protocol;
	vlan = vlan_id;
	id_num = id;
	ip_v = 4;
	init_dir = dir;
}

FlowId::FlowId(uint8_t ip_src[16], uint8_t ip_dst[16], uint16_t port_src,
		uint16_t port_dst, uint8_t protocol, uint16_t vlan_id,
		uint64_t id, uint8_t dir) {
	memcpy(ip_a.ip6_a, ip_src, sizeof(ip_a.ip6_a));
	memcpy(ip_b.ip6_b, ip_dst, sizeof(ip_b.ip6_b));
	port_a = port_src;
	port_b = port_dst;
	proto = protocol;
	vlan = vlan_id;
	id_num = id;
	ip_v = 6;
	init_dir = dir;

	/*
	printf("Flow ID: ");
	for (int i = 0; i < 16; i++) {
		printf("%02x:", ip_a.ip6_a[i]);
	}
	printf(" ");

	for (int i = 0; i < 16; i++) {
		printf("%02x:", ip_a.ip6_a[i]);
	}

	printf(" %d %d\n", port_a, port_b);
	*/
}

bool FlowId::operator==(const FlowId &b) const {
	if (port_b != b.port_b)
		return false;
	if (port_a != b.port_a)
		return false;
	if (ip_v != b.ip_v)
		return false;
	
	if(ip_v == 6) {
		int i;
		for(i=0;i<16;i++) {
			if(ip_a.ip6_a[i] != b.ip_a.ip6_a[i])
				return false;
		}
		for(i=0;i<16;i++) {
			if(ip_b.ip6_b[i] != b.ip_b.ip6_b[i])
				return false;
		}
	} else {
		if (ip_b.ip4_b != b.ip_b.ip4_b)
			return false;

		if (ip_a.ip4_a != b.ip_a.ip4_a)
			return false;
	}
	if (vlan != b.vlan)
		return false;
	
	return proto == b.proto;
}

/* 'less-than' operator for comparing Flow Ids */
bool FlowId::operator<(const FlowId &b) const {
       	if (port_b != b.port_b)
		return port_b < b.port_b;
	if (port_a != b.port_a)
		return port_a < b.port_a;

	if (ip_v != b.ip_v)
		return ip_v < b.ip_v;

	/* replace with memcmp */
	if(ip_v == 6) {
		int i;
		
		
		for(i=0;i<16;i++) {
			if(ip_a.ip6_a[i] != b.ip_a.ip6_a[i])
				return (ip_a.ip6_a[i] < b.ip_a.ip6_a[i]);
		}
		for(i=0;i<16;i++) {
			if(ip_b.ip6_b[i] != b.ip_b.ip6_b[i])
				return (ip_b.ip6_b[i] < b.ip_b.ip6_b[i]);
		}
	} else {
		if (ip_b.ip4_b != b.ip_b.ip4_b)
			return (ip_b.ip4_b < b.ip_b.ip4_b);

		if (ip_a.ip4_a != b.ip_a.ip4_a)
			return ip_a.ip4_a < b.ip_a.ip4_a;
	}
	if (vlan != b.vlan)
		return vlan < b.vlan;
	
	return proto < b.proto;

}

/* Accessor functions for the various parts of the flow ID */
uint16_t FlowId::get_vlan_id() const {
	return vlan;
}

uint64_t FlowId::get_id_num() const {
	return id_num;
}

/* Provides a string representation of the server IP */
void FlowId::get_server_ip_str(char * ret) const {
	if(ip_v == 4) {
		struct in_addr inp;
		if (init_dir == 0)
			inp.s_addr = ip_a.ip4_a;
		else
			inp.s_addr = ip_b.ip4_b;

		/* NOTE: the returned string is statically allocated - use it
		 * or lose it! */
		strcpy(ret, inet_ntoa(inp));
		return;
	} else {
		struct in6_addr inp;
		if (init_dir == 0)
			memcpy(inp.s6_addr, ip_a.ip6_a, sizeof(ip_a.ip6_a));
		else
			memcpy(inp.s6_addr, ip_b.ip6_b, sizeof(ip_b.ip6_b));

		inet_ntop(AF_INET6, &inp, ret, INET6_ADDRSTRLEN);
		return;
	}
}

/* Provides a string representation of the client IP */
void FlowId::get_client_ip_str(char * ret) const {
	if(ret == NULL)
		return;
	if(ip_v == 4) {
		struct in_addr inp;
		if (init_dir == 0)
			inp.s_addr = ip_b.ip4_b;
		else
			inp.s_addr = ip_a.ip4_a;
		/* NOTE: the returned string is statically allocated - use it
		 * or lose it! */
		strcpy(ret, inet_ntoa(inp));
	} else {
		struct in6_addr inp;
		if (init_dir == 0)
			memcpy(inp.s6_addr, ip_b.ip6_b, sizeof(ip_b.ip6_b));
		else
			memcpy(inp.s6_addr, ip_a.ip6_a, sizeof(ip_a.ip6_a));

		inet_ntop(AF_INET6, &inp, ret, INET6_ADDRSTRLEN);
		return;
	}
}

void FlowId::get_local_ip_str(char * ret) const {
	if(ret == NULL)
		return;
	if(ip_v == 4) {
		struct in_addr inp;
		inp.s_addr = ip_b.ip4_b;
		/* NOTE: the returned string is statically allocated - use it
		 * or lose it! */
		strcpy(ret, inet_ntoa(inp));
	} else {
		struct in6_addr inp;
		memcpy(inp.s6_addr, ip_b.ip6_b, sizeof(ip_b.ip6_b));
		inet_ntop(AF_INET6, &inp, ret, INET6_ADDRSTRLEN);
	}
}

void FlowId::get_external_ip_str(char * ret) const {
	if(ret == NULL)
		return;
	if(ip_v == 4) {
		struct in_addr inp;
		inp.s_addr = ip_a.ip4_a;
		/* NOTE: the returned string is statically allocated - use it
		 * or lose it! */
		strcpy(ret, inet_ntoa(inp));
	} else {
		struct in6_addr inp;
		memcpy(inp.s6_addr, ip_a.ip6_a, sizeof(ip_a.ip6_a));
		inet_ntop(AF_INET6, &inp, ret, INET6_ADDRSTRLEN);
	}
}

uint32_t FlowId::get_server_ip() const {
	if(ip_v == 6)
		return 0;
	if (init_dir == 0)
		return ip_a.ip4_a;
	return ip_b.ip4_b;
}

uint32_t FlowId::get_local_ip() const {
	if(ip_v == 6)
		return 0;
	return ip_b.ip4_b;
}

uint32_t FlowId::get_external_ip() const {
	if(ip_v == 6)
		return 0;
	return ip_a.ip4_a;
}

uint8_t* FlowId::get_server_ip6() const {
	if(ip_v == 4)
		return 0;
	if (init_dir == 0)
		return (uint8_t*)ip_a.ip6_a;
	return (uint8_t *)ip_b.ip6_b;
}

uint8_t* FlowId::get_local_ip6() const {
	if(ip_v == 4)
		return 0;
	return (uint8_t *)ip_b.ip6_b;
}

uint8_t* FlowId::get_external_ip6() const {
	if(ip_v == 4)
		return 0;
	return (uint8_t *)ip_a.ip6_a;
}

uint32_t FlowId::get_client_ip() const {
	if(ip_v == 6)
		return 0;
	if (init_dir == 0)
		return ip_b.ip4_b;
	return ip_a.ip4_a;
}

uint8_t* FlowId::get_client_ip6() const {
	if(ip_v == 4)
		return 0;
	if (init_dir == 0)
		return (uint8_t*)ip_b.ip6_b;
	return (uint8_t *)ip_a.ip6_a;
}

uint16_t FlowId::get_server_port() const {
	if (init_dir == 0)
		return port_a;
	return port_b;
}

uint16_t FlowId::get_local_port() const {
	return port_b;
}

uint16_t FlowId::get_external_port() const {
	return port_a;
}

uint16_t FlowId::get_client_port() const {
	if (init_dir == 0)
		return port_b;
	return port_a;
}

uint8_t FlowId::get_protocol() const {
	return proto;
}

uint8_t FlowId::get_ip_version()  const {
	return ip_v;
}

