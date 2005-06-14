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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFSPROV_INCLUDE_H
#define	_NFSPROV_INCLUDE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MAXSIZE 256
#define	NFS "nfs"
/*
 * This constant is the same as the NFS_PORT constant in nfs/nfs.h.  nfs/nfs.h
 * was not included because it defines some of the same data types
 * as defined in cimapi.h and therefore sets data types such as uint64 to
 * a value not expected or understood by cim.
 */
#define	NFS_PORT 2049

typedef struct {
	char	*name;
	CIMBool	isKey;
	CIMType	type;
} nfs_prov_prop_t;

typedef struct {
	char	*name;
	CIMBool	isKey;
	CIMType	type;
	char	*true_opt_value;
	char	*false_opt_value;
	char	*string_opt_value;
} nfs_prov_prop_plus_optVals_t;

#ifdef __cplusplus
}
#endif

#endif /* _NFSPROV_INCLUDE_H */
