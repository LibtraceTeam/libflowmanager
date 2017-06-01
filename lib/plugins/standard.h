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


#include "libflowmanager.h"

class StandardExpiryManager: public ExpiryManager {

public:
        StandardExpiryManager();
        ~StandardExpiryManager();
        void setTimewaitThreshold(double thresh);
        void setShortUdpThreshold(double thresh);

        ExpireList::iterator addNewFlow(Flow *f);
        ExpireList::iterator updateExpiryTimeout(Flow *f, double ts);
        Flow *expireNextFlow(double ts, bool force);

private:
        double timewait_thresh;
        double shortudp_thresh;

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
        ExpireList *expire_tcp_syn;
        ExpireList *expire_tcp_estab;
        ExpireList *expire_udp;
        ExpireList *expire_udpshort;
        ExpireList *expire_expired_flows;
        ExpireList *expire_tcp_anystart;
        ExpireList *expire_tcp_timewait;

        ExpireList *chooseExpiryList(Flow *f);
        double getTimeout(Flow *f, double ts);

};
