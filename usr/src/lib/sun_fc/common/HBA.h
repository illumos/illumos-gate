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

#ifndef	_HBA_H
#define	_HBA_H



// Forward declarations
class HBA;
class HBAPort;

#include "Lockable.h"
#include "HBAPort.h"
#include <map>
#include <string>
#include <vector>
#include <map>
#include <hbaapi.h>
#include <hbaapi-sun.h>


/*
 * @memo	    Used to track an individual HBA
 * @see		    HBAList
 *
 * @doc		    During discovery, as HBAs are found on the system,
 *		    instances of this class will be created, and stored
 *		    in the HBAList class.
 */
class HBA : public Lockable {
public:
	HBA() {}
	virtual ~HBA();
	bool				operator == (HBA &comp);
	static const uint8_t		HBA_PORT_MAX;
	void				addPort(HBAPort* port);
	HBAPort*			getPort(uint64_t wwn);
	bool				containsWWN(uint64_t wwn);

	virtual HBA_ADAPTERATTRIBUTES	getHBAAttributes() = 0;
	virtual HBA_ADAPTERATTRIBUTES	npivGetHBAAttributes() = 0;
	void				setRNID(HBA_MGMTINFO info);
	/*
	 * Fetch the name, excluding the trailing "-" and index number
	 */
	virtual std::string		getName() = 0;

	void				validatePresent();

	HBAPort*			getPortByIndex(int index);
	uint8_t				getNumberOfPorts();

	// Utility routines: Could be moved elsewhere
	// Each routine throws exceptions on error (and logs)
	static int			_open(std::string path, int flag);
	static void			_ioctl(int fd, int type, uchar_t *arg);

private:
	std::map<uint64_t, HBAPort *>	portsByWWN;
	std::vector<HBAPort*>		portsByIndex;
};


#endif /* _HBA_H */
