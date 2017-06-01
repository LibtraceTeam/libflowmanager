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


#include "fixed.h"
#include "libflowmanager.h"

FixedExpiryManager::FixedExpiryManager() {
        this->timeout_thresh = 120.0;

        this->expired = new ExpireList();
        this->stillactive = new ExpireList();
}

FixedExpiryManager::~FixedExpiryManager() {
        delete(this->expired);
        delete(this->stillactive);
}

ExpireList::iterator FixedExpiryManager::addNewFlow(Flow *f) {
        f->expire_list = this->stillactive;
        this->stillactive->push_front(f);
        return this->stillactive->begin();
}

ExpireList::iterator FixedExpiryManager::updateExpiryTimeout(Flow *f,
                double ts) {

        if (f->flow_state == FLOW_STATE_RESET ||
                        f->flow_state == FLOW_STATE_ICMPERROR) {
                f->expire_time = ts;
                f->expire_list = this->expired;
                this->expired->push_front(f);
                return this->expired->begin();
        }

        f->expire_time = ts + this->timeout_thresh;
        f->expire_list = this->stillactive;
        this->stillactive->push_front(f);
        return this->stillactive->begin();
}

Flow *FixedExpiryManager::expireNextFlow(double ts, bool force) {

        Flow *exp_flow;
        exp_flow = getNextExpiredFromList(this->stillactive, ts, force);
        if (exp_flow)
                return exp_flow;
        return getNextExpiredFromList(this->expired, ts, force);

}

void FixedExpiryManager::setTimeoutThreshold(double thresh) {
	if (thresh < 0)
		return;
	this->timeout_thresh = thresh;
}

