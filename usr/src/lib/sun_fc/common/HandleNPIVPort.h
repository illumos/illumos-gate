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

#ifndef _HANDLENPIVPORT_H
#define	_HANDLENPIVPORT_H



// Forward Declarations
class Handle;
class HandlePort;
class HandleNPIVPort;

#include "Lockable.h"
#include "Handle.h"
#include "HandlePort.h"
#include "HBA.h"
#include "HBAPort.h"
#include "HBANPIVPort.h"
#include <hbaapi.h>
#include <hbaapi-sun.h>

/*
 * @memo            Represents this handles state for each NPIV port.
 */
class HandleNPIVPort : public Lockable {
public:
	HandleNPIVPort(Handle *handle, HandlePort *porthandle,
	    HBA *hba, HBAPort *port, HBANPIVPort *vport);

	void		refresh();
	void		validate(uint64_t newState);
	bool		match(uint64_t portWWN);
	bool		match(int index);

	HBA_NPIVATTRIBUTES	getPortAttributes();
private:
	uint64_t	lastState;
	bool		active;
	Handle		*handle;
	HandlePort	*handleport;
	HBAPort		*port;
	HBA		*hba;
	HBANPIVPort	*vport;
};

#endif /* _HANDLENPIVPORT_H */
