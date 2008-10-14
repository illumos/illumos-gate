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

#ifndef _FCHBANPIVPORT_H
#define	_FCHBANPIVPORT_H


#include <Lockable.h>
#include "HBANPIVPort.h"
#include "HBAPort.h"
#include <Exceptions.h>
#include <string>
#include <hbaapi.h>
#include <sys/fibre-channel/fcio.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Represents a single HBA NPIV port
 */
class FCHBANPIVPort : public HBANPIVPort {
public:
	FCHBANPIVPort(std::string path);
	virtual std::string	getPath()
					{ return path; }
	virtual uint64_t	getNodeWWN()
					{ return nodeWWN; }
	virtual uint64_t	getPortWWN()
					{ return portWWN; }
	virtual HBA_NPIVATTRIBUTES	getPortAttributes(
					    uint64_t &stateChange);

private:
	std::string	path;
	uint64_t	portWWN;
	uint64_t	nodeWWN;
	static const int	MAX_FCIO_MSG_LEN;
	static void	transportError(uint32_t fcio_error, char *message);
	static void	fp_ioctl(std::string path, int cmd, fcio_t *arg);
};

#ifdef  __cplusplus
}
#endif

#endif /* _FCHBANPIVPORT_H */
