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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_IPGPC_TABLE_H
#define	_IPP_IPGPC_TABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipp/ipgpc/classifier-objects.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for hash table data structure used to hold keys of exact
 * match selectors
 */

extern int ht_insert(table_id_t *, key_t, int);
extern int ht_retrieve(table_id_t *, int, ht_match_t *);
extern void ht_remove(table_id_t *, key_t, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_IPGPC_TABLE_H */
