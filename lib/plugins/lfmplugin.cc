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

#include <assert.h>
#include "libflowmanager.h"
#include "lfmplugin.h"

/* Finds the next available expired flow in an LRU.
 *
 * Parameters:
 *      expire - the LRU to pull an expired flow from
 *      ts - the current timestamp 
 *      force - if true, the next flow in the LRU will be forcibly expired,
 *              regardless of whether it was due to expire or not.
 *
 * Returns:
 *      the next flow to be expired from the LRU, or NULL if there are no
 *      flows available to expire.
 */
Flow *get_next_expired(ExpireList *expire, double ts, bool force) {
        ExpireList::iterator i;
        Flow *exp_flow;

        /* Ensure that there is something in the LRU */
        if (expire->empty())
                return NULL;

        /* Check if the first flow in the LRU is due to expire */
        exp_flow = expire->back();
        assert(exp_flow);
	if (exp_flow->expire_time <= ts)
                exp_flow->expired = true;

        /* If flow was due to expire (or the force expiry flag is set),
         * remove it from the LRU and flow map and return it to the caller */
        if (force || exp_flow->expired) {
                expire->pop_back();
                //active_flows.erase(exp_flow->id);
                return exp_flow;
        }

        /* Otherwise, no flows available for expiry in this LRU */
        return NULL;

}

