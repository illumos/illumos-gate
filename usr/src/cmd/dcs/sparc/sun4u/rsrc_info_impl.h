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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RSRC_INFO_IMPL_H
#define	_RSRC_INFO_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <libdevinfo.h>
#include <librcm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/processor.h>
#include <config_admin.h>
#include "rsrc_info.h"

#ifdef	DEBUG
static int ri_debug = 1;
#define	dprintf(args) if (ri_debug) (void) fprintf args
#else
#define	dprintf(args)
#endif	/* DEBUG */

#define	RI_REQ_MASK		(RI_INCLUDE_UNMANAGED|RI_INCLUDE_QUERY|\
				RI_FORCE|RI_VERBOSE)

/*
 * Packing delimiters
 */
#define	RI_HDL_FLAGS		"ri.h_flags"
#define	RI_HDL_APS		"ri.h_aps"
#define	RI_HDL_CPU_CAPS		"ri.h_ccaps"
#define	RI_HDL_MEM_CAPS		"ri.h_mcaps"
#define	RI_CLIENT_T		"ri.cli_t"
#define	RI_CLIENT_USAGE_PROPS	"ri.cli_u_props"
#define	RI_CLIENT_VERB_PROPS	"ri.cli_v_props"
#define	RI_DEV_T		"ri.dev_t"
#define	RI_DEV_PROPS		"ri.dev_props"
#define	RI_DEV_CLIENTS		"ri.dev_clients"
#define	RI_AP_T			"ri.ap_t"
#define	RI_AP_PROPS		"ri.ap_props"
#define	RI_AP_CPUS		"ri.ap_cpus"
#define	RI_AP_MEMS		"ri.ap_mems"
#define	RI_AP_IOS		"ri.ap_ios"

#define	s_free(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)

struct ri_hdl {
	int		flags;
	ri_ap_t		*aps;
	ri_client_t	*cpu_cap_clients;
	ri_client_t 	*mem_cap_clients;
};

struct ri_ap {
	nvlist_t	*conf_props;
	ri_dev_t	*cpus;
	ri_dev_t	*mems;
	ri_dev_t	*ios;
	ri_ap_t		*next;
};

struct ri_dev {
	nvlist_t	*conf_props;
	ri_client_t	*rcm_clients;
	ri_dev_t	*next;
};

struct ri_client {
	nvlist_t	*usg_props;
	nvlist_t	*v_props;
	ri_client_t	*next;
};

void	ri_dev_free(ri_dev_t *);
void	ri_client_free(ri_client_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _RSRC_INFO_IMPL_H */
