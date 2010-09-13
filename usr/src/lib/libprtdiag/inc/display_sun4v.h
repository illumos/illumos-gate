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

#ifndef	_DISPLAY_SUN4V_H
#define	_DISPLAY_SUN4V_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <picl.h>

#define	CLK_FREQ_TO_MHZ(x)	(((x) + 500000) / 1000000)
#define	MAXSTRLEN	256

#define	EM_INIT_FAIL		dgettext(TEXT_DOMAIN,\
	"picl_initialize failed: %s\n")
#define	EM_GET_ROOT_FAIL	dgettext(TEXT_DOMAIN,\
	"Getting root node failed: %s\n")

void sun4v_display_pci(picl_nodehdl_t plafh);
void sun4v_display_memoryconf();
void sun4v_display_cpu_devices(picl_nodehdl_t plafh);
int sun4v_display_cpus(picl_nodehdl_t cpuh, void* args);
void sun4v_display_diaginfo(int flag, Prom_node *root, picl_nodehdl_t plafh);
int sun4v_display(Sys_tree *, Prom_node *, int, picl_nodehdl_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _DISPLAY_SUN4V_H */
