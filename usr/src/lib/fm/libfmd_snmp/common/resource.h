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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RESOURCE_H
#define	_RESOURCE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <libuutil.h>

typedef struct sunFmResource_data {
	ulong_t		d_index;		/* MIB index */
	int		d_valid;		/* iteration stamp */
	uu_avl_node_t	d_fmri_avl;		/* by-FMRI AVL node */
	uu_avl_node_t	d_index_avl;		/* by-index AVL node */
	char		d_ari_fmri[256];	/* resource FMRI */
	char		d_ari_case[256];	/* resource state case UUID */
	uint_t		d_ari_flags;		/* resource flags */
} sunFmResource_data_t;

typedef struct sunFmResource_update_ctx {
	const char	*uc_host;
	uint32_t	uc_prog;
	int		uc_version;
	int		uc_all;
	ulong_t		uc_index;
	uint32_t	uc_type;
} sunFmResource_update_ctx_t;

int sunFmResourceTable_init(void);
int sunFmResourceCount_init(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _RESOURCE_H */
