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

class FixedExpiryManager: public ExpiryManager {

public:
        FixedExpiryManager();
        ~FixedExpiryManager();
        void setTimeoutThreshold(double thresh);

        ExpireList::iterator addNewFlow(Flow *f);
        ExpireList::iterator updateExpiryTimeout(Flow *f, double ts);
        Flow *expireNextFlow(double ts, bool force);

private:
        double timeout_thresh;

        ExpireList *stillactive;
        ExpireList *expired;
};
