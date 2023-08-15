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

#ifndef	_ADAPTERADDEVENTLISTENER_H
#define	_ADAPTERADDEVENTLISTENER_H



#include "Listener.h"
#include <hbaapi.h>

/// Callback routine type
typedef void (*AdapterAddCallback) (
	    void            *data,
	    HBA_WWN         PortWWN,
	    HBA_UINT32      eventType);

/**
 * @memo	    Encapsulates the callback routine for event dispatch
 *
 * @doc		    This class encapsulates the event callback routine
 *		    registered in the public HBA API.  When dispatch
 *		    is called, the stored callback routine will be called.
 */
class AdapterAddEventListener: public Listener {
public:
    AdapterAddEventListener(AdapterAddCallback myCallback, void *data);
    virtual void dispatch(Event &event);
private:
    AdapterAddCallback callback;
};

#endif /* _ADAPTERADDEVENTLISTENER_H */
