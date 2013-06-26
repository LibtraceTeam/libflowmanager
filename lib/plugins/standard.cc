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

#include <assert.h>

#include "lfmplugin.h"
#include "libflowmanager.h"

static double timewait_thresh = 0.0;
static double shortudp_thresh = 10.0;

/**********************************/
/* Expiry lists
 *
 * Each of the following lists is acting as a LRU. Because each LRU only
 * contains flows where the expiry condition is the same, we can easily
 * expire flows by popping off one end of the list until we reach a flow that
 * is not due to expire. Similarly, we can always insert at the other end and
 * remain certain that the list is maintained in order of expiry.
 *
 * It does mean that as more expiry rules are added, a new LRU has to also be
 * added to deal with it :(
 */

/* LRU for unestablished TCP flows */
static ExpireList expire_tcp_syn;

/* LRU for established TCP flows */
static ExpireList expire_tcp_estab;

/* LRU for UDP flows - a bit of a misnomer, all non-TCP flows end up in here */
static ExpireList expire_udp;

/* LRU for short-lived UDP flows (only used if the short_udp config option is
 * set) */
static ExpireList expire_udpshort;

/* LRU for all flows that met an instant expiry condition, e.g. TCP RST */
static ExpireList expired_flows;

/* LRU for TCP flows starting with anything*/
static ExpireList expire_tcp_anystart;

/* LRU for TCP flows in timewait */
static ExpireList expire_tcp_timewait;

/****************************************/

static ExpireList *determine_expirelist(Flow *f, bool udpshort) {
	ExpireList *explist = NULL;
	
	switch(f->flow_state) {
	case FLOW_STATE_NEW:
	case FLOW_STATE_CONN:
	case FLOW_STATE_HALFCLOSE:
		explist = &expire_tcp_syn;
		break;
	case FLOW_STATE_ANYSTART:
		explist = &expire_tcp_anystart;
		break;
	case FLOW_STATE_NONE:
	case FLOW_STATE_UDPLONG:
		explist = &expire_udp;
		break;
	case FLOW_STATE_UDPSHORT:
		if (udpshort)
			explist = &expire_udpshort;
		else
			explist = &expire_udp;
		break;
	case FLOW_STATE_RESET:
	case FLOW_STATE_ICMPERROR:
		explist = &expired_flows;
		break;
	case FLOW_STATE_ESTAB:
		explist = &expire_tcp_estab;
		break;
	case FLOW_STATE_CLOSE:
		if (timewait_thresh > 0)
			explist = &expire_tcp_timewait;
		else
			explist = &expired_flows;
		break;
	default:
		fprintf(stderr, "Unknown flow state: %d\n", f->flow_state);
		assert(0);	// XXX Temporary
	}
	return explist;
}

static double determine_timeout(Flow *f, double ts, bool udpshort) {

	switch(f->flow_state) {
	/* Unestablished TCP connections expire after 2 * the maximum
	 * segment lifetime (see RFC 1122).
	 *
	 * Include half-closed flows in here as well to try and expire
	 * single FIN flows more quickly
	 */
	case FLOW_STATE_NEW:
	case FLOW_STATE_CONN:
	case FLOW_STATE_HALFCLOSE:
		return ts + 240.0;

	/* Try and get rid of these reasonably quickly if we can't transition
	 * them into a genuine state */
	case FLOW_STATE_ANYSTART:
		return ts + 120.0;

	/* UDP flows expire after 2 minutes (RFC 4787) */ 
	case FLOW_STATE_NONE:
	case FLOW_STATE_UDPLONG:
		return ts + 120.0;
	
	/* If we're using the short udp plugin, try and expire any UDP flows
	 * that have not seen more than one outgoing packet very quickly. This
	 * is an experimental approach that has proved very effective in
	 * reducing the number of UDP flows cluttering up the flow map.
	 */
	case FLOW_STATE_UDPSHORT:
		if (udpshort)
			return ts + shortudp_thresh;
		else
			return ts + 120.0;
		
	/* Expire these right away! */
	case FLOW_STATE_RESET:
	case FLOW_STATE_ICMPERROR:
		return ts;
		
	/* Established TCP connections expire after 2 hours and 4 minutes of
	 * inactivity -- RFC 5382 */
	case FLOW_STATE_ESTAB:
		return ts + 7440.0;

	/* Connection is over, but we may want to keep it around a little 
	 * longer just to catch any final packets.
	 */	
	case FLOW_STATE_CLOSE:
		return ts + timewait_thresh;
	
	default:
		fprintf(stderr, "Unknown flow state: %d\n", f->flow_state);
		assert(0);	// XXX Temporary
	}
	return ts;
}

ExpireList::iterator standard_add_new_flow(Flow *f) {

	ExpireList *explist = determine_expirelist(f, false);
	f->expire_list = explist;
	explist->push_front(f);
	return explist->begin();	
}

ExpireList::iterator shortudp_add_new_flow(Flow *f) {

	ExpireList *explist = determine_expirelist(f, true);

	f->expire_list = explist;
	explist->push_front(f);
	return explist->begin();	
}

ExpireList::iterator standard_update_expiry(Flow *f, double ts) {

	ExpireList *explist = determine_expirelist(f, false);
	double timeout = determine_timeout(f, ts, false);

	f->expire_time = timeout;
	f->expire_list = explist;
	explist->push_front(f);
	return explist->begin();

}

ExpireList::iterator shortudp_update_expiry(Flow *f, double ts) {

	ExpireList *explist = determine_expirelist(f, true);
	double timeout = determine_timeout(f, ts, true);

	f->expire_time = timeout;
	f->expire_list = explist;
	explist->push_front(f);
	return explist->begin();

}

Flow *standard_expire_next(double ts, bool force) {
	Flow *exp_flow;

	/* Check each of the LRUs in turn */
        exp_flow = get_next_expired(&expire_tcp_syn, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = get_next_expired(&expire_tcp_estab, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = get_next_expired(&expire_udp, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = get_next_expired(&expire_udpshort, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = get_next_expired(&expire_tcp_anystart, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        return get_next_expired(&expired_flows, ts, force);

}

void standard_set_timewait(double thresh) {
	if (thresh < 0)
		return;
	timewait_thresh = thresh;
}

void shortudp_set_threshold(double thresh) {
	if (thresh < 0)
		return;
	shortudp_thresh = thresh;
}

static struct lfm_plugin_t standard = {
	LFM_PLUGIN_STANDARD,
	standard_add_new_flow,
	standard_update_expiry,
	standard_expire_next,
	NULL,
	standard_set_timewait,
};

static struct lfm_plugin_t shortudp = {
	LFM_PLUGIN_STANDARD_SHORT_UDP,
	shortudp_add_new_flow,
	shortudp_update_expiry,
	standard_expire_next,
	shortudp_set_threshold,
	standard_set_timewait
};


lfm_plugin_t *load_standard_plugin() {
	return &standard;
}

lfm_plugin_t *load_shortudp_plugin() {
	return &shortudp;
}
