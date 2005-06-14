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
 *	Copyright (c) 1996, by Sun Microsystems, Inc.
 *	All rights reserved.
 */


#ifndef	__CACHEMGR_H
#define	__CACHEMGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

extern int xdr_fd_result(XDR *, fd_result *);
extern int xdr_directory_obj(XDR *, directory_obj *);
extern int xdr_nis_error(XDR *, int *);
extern int xdr_nis_server(XDR *, nis_server *);

#endif	/* __CACHEMGR_H */
