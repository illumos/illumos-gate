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

#ifndef _LIBDLAGGR_H
#define	_LIBDLAGGR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file includes structures, macros and routines used by aggregation link
 * administration.
 */

#include <sys/types.h>
#include <sys/aggr.h>
#include <libdladm.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Modification flags sent with the LAIOC_MODIFY ioctl
 */
#define	DLADM_AGGR_MODIFY_POLICY		0x01
#define	DLADM_AGGR_MODIFY_MAC			0x02
#define	DLADM_AGGR_MODIFY_LACP_MODE		0x04
#define	DLADM_AGGR_MODIFY_LACP_TIMER		0x08

typedef struct dladm_aggr_port_attr_db {
	char		lp_devname[MAXNAMELEN + 1];
} dladm_aggr_port_attr_db_t;

typedef struct dladm_aggr_port_attr {
	char		lp_devname[MAXNAMELEN + 1];
	uchar_t		lp_mac[ETHERADDRL];
	aggr_port_state_t lp_state;
	aggr_lacp_state_t lp_lacp_state;
} dladm_aggr_port_attr_t;

typedef struct dladm_aggr_grp_attr {
	uint32_t	lg_key;
	uint32_t	lg_nports;
	dladm_aggr_port_attr_t *lg_ports;
	uint32_t	lg_policy;
	uchar_t		lg_mac[ETHERADDRL];
	boolean_t	lg_mac_fixed;
	aggr_lacp_mode_t lg_lacp_mode;
	aggr_lacp_timer_t lg_lacp_timer;
} dladm_aggr_grp_attr_t;

extern dladm_status_t	dladm_aggr_create(uint32_t, uint32_t,
			    dladm_aggr_port_attr_db_t *, uint32_t, boolean_t,
			    uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t,
			    boolean_t, const char *);
extern dladm_status_t	dladm_aggr_delete(uint32_t, boolean_t, const char *);
extern dladm_status_t	dladm_aggr_add(uint32_t, uint32_t,
			    dladm_aggr_port_attr_db_t *, boolean_t,
			    const char *);
extern dladm_status_t	dladm_aggr_remove(uint32_t, uint32_t,
			    dladm_aggr_port_attr_db_t *, boolean_t,
			    const char *);
extern dladm_status_t	dladm_aggr_modify(uint32_t, uint32_t, uint32_t,
			    boolean_t, uchar_t *, aggr_lacp_mode_t,
			    aggr_lacp_timer_t, boolean_t, const char *);
extern dladm_status_t	dladm_aggr_up(uint32_t, const char *);
extern dladm_status_t	dladm_aggr_down(uint32_t);

extern boolean_t	dladm_aggr_str2policy(const char *, uint32_t *);
extern char		*dladm_aggr_policy2str(uint32_t, char *);
extern boolean_t	dladm_aggr_str2macaddr(const char *, boolean_t *,
			    uchar_t *);
extern const char	*dladm_aggr_macaddr2str(unsigned char *, char *);

extern boolean_t	dladm_aggr_str2lacpmode(const char *,
			    aggr_lacp_mode_t *);
extern const char	*dladm_aggr_lacpmode2str(aggr_lacp_mode_t, char *);
extern boolean_t	dladm_aggr_str2lacptimer(const char *,
			    aggr_lacp_timer_t *);
extern const char	*dladm_aggr_lacptimer2str(aggr_lacp_timer_t, char *);

extern const char	*dladm_aggr_portstate2str(aggr_port_state_t, char *);

extern int		dladm_aggr_walk(int (*)(void *,
			    dladm_aggr_grp_attr_t *), void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLAGGR_H */
