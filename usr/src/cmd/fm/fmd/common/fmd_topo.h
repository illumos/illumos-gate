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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FMD_TOPO_H
#define	_FMD_TOPO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fm/libtopo.h>

#include <fmd_list.h>

extern void fmd_topo_init(void);
extern void fmd_topo_fini(void);

typedef struct fmd_topo {
	fmd_list_t ft_list;
	topo_hdl_t *ft_hdl;
	uint32_t ft_refcount;
	hrtime_t ft_time_begin;
	hrtime_t ft_time_end;
} fmd_topo_t;

extern void fmd_topo_update(boolean_t);
extern fmd_topo_t *fmd_topo_hold(void);
extern void fmd_topo_addref(fmd_topo_t *);
extern void fmd_topo_rele(fmd_topo_t *);
extern void fmd_topo_rele_hdl(topo_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _FMD_TOPO_H */
