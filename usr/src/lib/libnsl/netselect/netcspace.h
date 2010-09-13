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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _NSS_NETCSPACE_H
#define	_NSS_NETCSPACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct nc_data {
	char		*string;
	unsigned int	value;
};

static struct nc_data nc_semantics[] = {
	"tpi_clts",	NC_TPI_CLTS,
	"tpi_cots",	NC_TPI_COTS,
	"tpi_cots_ord",	NC_TPI_COTS_ORD,
	"tpi_raw",	NC_TPI_RAW,
	NULL,		(unsigned)-1
};

static struct nc_data nc_flag[] = {
	"-",		NC_NOFLAG,
	"v",		NC_VISIBLE,
	NULL,		(unsigned)-1
};

#define	NC_NOERROR	0
#define	NC_NOMEM	1
#define	NC_NOSET	2
#define	NC_OPENFAIL	3
#define	NC_BADLINE	4
#define	NC_NOTFOUND	5
#define	NC_NOMOREENTRIES 6

#ifdef __cplusplus
}
#endif

#endif	/* _NSS_NETCSPACE_H */
