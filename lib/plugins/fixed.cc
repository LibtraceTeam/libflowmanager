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


#include "lfmplugin.h"
#include "libflowmanager.h"

static double fixed_thresh = 120.0;

/* Just one prinicipal expiry LRU, since everything is going to have the same 
 * inactivity timeout threshold
 */
static ExpireList expiry;

/* Special expiry LRU for flows that need to be expired immediately */
static ExpireList expired;

ExpireList::iterator fixed_add_new_flow(Flow *f) {

	f->expire_list = &expiry;
	expiry.push_front(f);
	return expiry.begin();
}

ExpireList::iterator fixed_update_expiry(Flow *f, double ts) {

	switch(f->flow_state) {
	case FLOW_STATE_RESET:
	case FLOW_STATE_ICMPERROR:
		f->expire_time = ts;
		f->expire_list = &expired;
		expired.push_front(f);
		return expired.begin();
	}

	f->expire_time = ts + fixed_thresh;
	f->expire_list = &expiry;
	expiry.push_front(f);
	return expiry.begin();

}

Flow *fixed_expire_next(double ts, bool force) {
	Flow *exp_flow;

	exp_flow = get_next_expired(&expiry, ts, force);
	if (exp_flow)
		return exp_flow;
	
	return get_next_expired(&expired, ts, force);
}

void fixed_set_threshold(double thresh) {
	if (thresh < 0)
		return;
	fixed_thresh = thresh;
}

static struct lfm_plugin_t fixed = {
	LFM_PLUGIN_FIXED_INACTIVE,
	fixed_add_new_flow,
	fixed_update_expiry,
	fixed_expire_next,
	fixed_set_threshold,
	NULL,
};

lfm_plugin_t *load_fixed_inactive() {
	return &fixed;
}
