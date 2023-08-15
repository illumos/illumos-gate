/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LINKEVENTBRIDGE_H
#define	_LINKEVENTBRIDGE_H



#include "LinkEventListener.h"

/**
 * @memo	    Bridge interface for link events
 *
 * @doc		    Used to abstract clients from the specific
 *		    underlying details of event management for
 *		    the given HBA/driver stack.
 */
class LinkEventBridge{
public:
    virtual void addListener(LinkEventListener *listener, HBAPort *port) = 0;
    virtual void removeListener(LinkEventListener *listener) = 0;
};

#endif /* _LINKEVENTBRIDGE_H */
