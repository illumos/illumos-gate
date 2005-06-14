/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_CSIIOCTL_H
#define	_SYS_CSIIOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * csiioctl.h
 *
 * CodeSet Independent codeset width communication between stty(1) and
 * ldterm(7M).
 *
 * CSDATA_SET	This call takes a pointer to a ldterm_cs_data_t data
 *		structure, and uses it to set the line discipline definition
 *		and also for a possible switch of the internal methods and
 *		data for the current locale's codeset.
 *
 *		When this message is reached, the ldterm(7M) will check
 *		the validity of the message and if the message contains
 *		a valid data, it will accumulate the data and switch
 *		the internal methods if necessary to support the requested
 *		codeset.
 *
 * CSDATA_GET	This call takes a pointer to a ldterm_cs_data_t structure
 *		and returns in it the codeset data info currently in use by
 *		the ldterm(7M) module.
 */

#define	CSI_IOC		(('C' | 128) << 8)
#define	CSDATA_SET	(CSI_IOC | 1)
#define	CSDATA_GET	(CSI_IOC | 2)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CSIIOCTL_H */
