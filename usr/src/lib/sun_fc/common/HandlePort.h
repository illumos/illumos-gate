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

#ifndef	_HANDLEPORT_H
#define	_HANDLEPORT_H



// Forward Declarations
class Handle;
class HandlePort;
class HandleNPIVPort;

#include "Lockable.h"
#include "Handle.h"
#include "HBA.h"
#include "HBAPort.h"
#include "HandleNPIVPort.h"
#include <hbaapi.h>
#include <hbaapi-sun.h>

/**
 * @memo	    Represents this handles state for each HBA port.
 *
 * @doc
 * This is required to track the state change value for
 * a given port for this open handle.  This class is used exclusivly
 * by instances of the Handle class.
 */
class HandlePort : public Lockable {
public:
    HandlePort(Handle *handle, HBA *hba, HBAPort *port);

    void		refresh();
    void		validate(uint64_t newState);
    bool		match(uint64_t portWWN);
    bool		match(int index);


    HBA_PORTATTRIBUTES		getPortAttributes();
    HBA_PORTATTRIBUTES		getDiscoveredAttributes(
				    HBA_UINT32 discoveredport);
    HBA_PORTATTRIBUTES		getDiscoveredAttributes(uint64_t wwn);
    HBA_PORTNPIVATTRIBUTES      getPortNPIVAttributes();
    uint32_t			createNPIVPort(uint64_t vnodewwn,
				    uint64_t vportwwn, uint32_t vindex);
    uint32_t			deleteNPIVPort(uint64_t vportwwn);
    HandleNPIVPort*		getHandleNPIVPortByIndex(int index);
    HandleNPIVPort*		getHandleNPIVPort(uint64_t wwn);
private:
    uint64_t		lastState;
    bool		active;
    Handle		*handle;
    HBAPort		*port;
    HBA			*hba;
    std::map<uint64_t, HandleNPIVPort*>	npivportHandles;
};

#endif /* _HANDLEPORT_H */
