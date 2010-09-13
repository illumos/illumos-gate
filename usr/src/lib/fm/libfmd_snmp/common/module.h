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

#ifndef	_MODULE_H
#define	_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <libuutil.h>

typedef struct sunFmModule_data {
	ulong_t		d_index;		/* MIB index */
	int		d_valid;		/* iteration stamp */
	uu_avl_node_t	d_name_avl;		/* by-name AVL node */
	uu_avl_node_t	d_index_avl;		/* by-index AVL node */
	char		d_ami_name[256];	/* fmd module name */
	char		d_ami_vers[256];	/* fmd module version */
	char		d_ami_desc[256];	/* fmd module description */
	uint_t		d_ami_flags;		/* fmd module flags */
} sunFmModule_data_t;

typedef struct sunFmModule_update_ctx {
	const char	*uc_host;
	uint32_t	uc_prog;
	int		uc_version;
	ulong_t		uc_index;
	int		uc_type;
} sunFmModule_update_ctx_t;

int sunFmModuleTable_init(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MODULE_H */
