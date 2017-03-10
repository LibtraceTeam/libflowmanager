/*
 *
 * Copyright (c) 2009-2012, 2016 The University of Waikato, Hamilton,
 * New Zealand.
 * All rights reserved.
 *
 * This file is part of libflowmanager.
 q*
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

#include <assert.h>

#include "standard.h"
#include "libflowmanager.h"


StandardExpiryManager::StandardExpiryManager() {
        this->timewait_thresh = 0.0;
        this->shortudp_thresh = 0.0;

        this->expire_tcp_syn = new ExpireList();
        this->expire_tcp_estab = new ExpireList();
        this->expire_udp = new ExpireList();
        this->expire_udpshort = new ExpireList();
        this->expire_expired_flows = new ExpireList();
        this->expire_tcp_anystart = new ExpireList();
        this->expire_tcp_timewait = new ExpireList();
}

StandardExpiryManager::~StandardExpiryManager() {

        delete(this->expire_tcp_syn);
        delete(this->expire_tcp_estab);
        delete(this->expire_tcp_anystart);
        delete(this->expire_tcp_timewait);
        delete(this->expire_udp);
        delete(this->expire_udpshort);
        delete(this->expire_expired_flows);
}


ExpireList::iterator StandardExpiryManager::addNewFlow(Flow *f) {

	ExpireList *explist = this->chooseExpiryList(f);
	f->expire_list = explist;
	explist->push_front(f);
	return explist->begin();

}

ExpireList::iterator StandardExpiryManager::updateExpiryTimeout(Flow *f, double ts) {

	ExpireList *explist = this->chooseExpiryList(f);
	double timeout = this->getTimeout(f, ts);

	f->expire_time = timeout;
	f->expire_list = explist;
	explist->push_front(f);
	return explist->begin();

}

Flow *StandardExpiryManager::expireNextFlow(double ts, bool force) {
	Flow *exp_flow;

	/* Check each of the LRUs in turn */
        exp_flow = getNextExpiredFromList(this->expire_tcp_syn, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = getNextExpiredFromList(this->expire_tcp_estab, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = getNextExpiredFromList(this->expire_udp, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = getNextExpiredFromList(this->expire_udpshort, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = getNextExpiredFromList(this->expire_tcp_anystart, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        exp_flow = getNextExpiredFromList(this->expire_tcp_timewait, ts, force);
        if (exp_flow != NULL)
                return exp_flow;

        return getNextExpiredFromList(this->expire_expired_flows, ts, force);

}

void StandardExpiryManager::setShortUdpThreshold(double thresh) {
        if (thresh < 0)
                return;
        this->shortudp_thresh = thresh;

}

void StandardExpiryManager::setTimewaitThreshold(double thresh) {
        if (thresh < 0)
                return;
        this->timewait_thresh = thresh;
}

double StandardExpiryManager::getTimeout(Flow *f, double ts) {

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

	case FLOW_STATE_UDPSHORT:
                if (this->shortudp_thresh > 0)
                        return ts + this->shortudp_thresh;
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

ExpireList *StandardExpiryManager::chooseExpiryList(Flow *f) {

	ExpireList *explist = NULL;

	switch(f->flow_state) {
	case FLOW_STATE_NEW:
	case FLOW_STATE_CONN:
	case FLOW_STATE_HALFCLOSE:
		explist = this->expire_tcp_syn;
		break;
	case FLOW_STATE_ANYSTART:
		explist = this->expire_tcp_anystart;
		break;
	case FLOW_STATE_NONE:
	case FLOW_STATE_UDPLONG:
		explist = this->expire_udp;
		break;
	case FLOW_STATE_UDPSHORT:
                if (this->shortudp_thresh > 0)
                        explist = this->expire_udpshort;
                else
                        explist = this->expire_udp;
                break;
	case FLOW_STATE_RESET:
	case FLOW_STATE_ICMPERROR:
		explist = this->expire_expired_flows;
		break;
	case FLOW_STATE_ESTAB:
		explist = this->expire_tcp_estab;
		break;
	case FLOW_STATE_CLOSE:
		if (this->timewait_thresh > 0)
			explist = this->expire_tcp_timewait;
		else
			explist = this->expire_expired_flows;
		break;
	default:
		fprintf(stderr, "Unknown flow state: %d\n", f->flow_state);
		assert(0);	// XXX Temporary
	}
	return explist;
}
