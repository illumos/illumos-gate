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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_NIS_SERVLIST_H
#define	_NIS_SERVLIST_H

#include <rpcsvc/nis.h>

/* Imported from rpc.nisd/nis_proc.h */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * used for various server control options.
 */
enum NIS_SERVER_INFO	{SERVING_LIST};
enum NIS_SERVER_OP	{DIR_ADD, DIR_DELETE, DIR_INITLIST,
				DIR_GETLIST, DIR_SERVED};

int		nis_server_control(enum NIS_SERVER_INFO, enum NIS_SERVER_OP,
			void *);
int		nis_isserving(nis_object *dobj);

#ifdef	__cplusplus
}
#endif

#endif	/* _NIS_SERVLIST_H */
