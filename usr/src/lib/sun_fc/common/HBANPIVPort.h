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

#ifndef _HBANPIVPORT_H
#define	_HBANPIVPORT_H



#include "Lockable.h"
#include <string>
#include <hbaapi.h>
#include <hbaapi-sun.h>

/*
 * @memo	Represents a single HBA NPIV port
 *
 */
class HBANPIVPort : public Lockable {
public:
	HBANPIVPort();
	virtual ~HBANPIVPort() {};
	bool	operator == (HBANPIVPort &comp);
	virtual std::string		getPath() = 0;
	virtual uint64_t		getNodeWWN() = 0;
	virtual uint64_t		getPortWWN() = 0;
	virtual HBA_NPIVATTRIBUTES	getPortAttributes(
					    uint64_t &stateChange) = 0;
protected:
	std::string			lookupControllerPath(std::string path);
};

#endif /* _HBANPIVPORT_H */
