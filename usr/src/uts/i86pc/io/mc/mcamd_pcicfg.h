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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MCAMD_PCICFG_H
#define	_MCAMD_PCICFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <mcamd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void * mc_pcicfg_hdl_t;

/*
 * MC PCI config where we have attached to an MC dev/function.
 */
extern int mc_pcicfg_setup(mc_t *, enum mc_funcnum, mc_pcicfg_hdl_t *);
extern void mc_pcicfg_teardown(mc_pcicfg_hdl_t);
extern uint32_t mc_pcicfg_get32(mc_pcicfg_hdl_t, off_t);
extern void mc_pcicfg_put32(mc_pcicfg_hdl_t cookie, off_t offset, uint32_t val);

/* MC PCI config where we have not attached to the dev/function */
extern uint32_t mc_pcicfg_get32_nohdl(mc_t *, enum mc_funcnum, off_t);
extern void mc_pcicfg_put32_nohdl(mc_t *, enum mc_funcnum, off_t, uint32_t);

#ifdef __cplusplus
}
#endif

#endif	/* _MCAMD_PCICFG_H */
