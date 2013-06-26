/*
 * This file is part of libflowmanager
 *
 * Copyright (c) 2009-2013 The University of Waikato, Hamilton, New Zealand.
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
#ifndef LFM_PLUGIN_COMMON_H_
#define LFM_PLUGIN_COMMON_H_

#include "libflowmanager.h"

Flow *get_next_expired(ExpireList *expire, double ts, bool force);

lfm_plugin_t *load_standard_plugin();
lfm_plugin_t *load_shortudp_plugin();
lfm_plugin_t *load_fixed_inactive();

#endif
