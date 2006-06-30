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

#ifndef _LIBLAADM_H
#define	_LIBLAADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/aggr.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Modification flags sent with the LAIOC_MODIFY ioctl
 */
#define	LAADM_MODIFY_POLICY		0x01
#define	LAADM_MODIFY_MAC		0x02
#define	LAADM_MODIFY_LACP_MODE		0x04
#define	LAADM_MODIFY_LACP_TIMER		0x08

#define	LAADM_POLICY_STR_LEN		8

typedef struct laadm_port_attr_db {
	char		lp_devname[MAXNAMELEN + 1];
} laadm_port_attr_db_t;

typedef struct laadm_port_attr_sys {
	char		lp_devname[MAXNAMELEN + 1];
	uchar_t		lp_mac[ETHERADDRL];
	aggr_port_state_t lp_state;
	aggr_lacp_state_t lp_lacp_state;
} laadm_port_attr_sys_t;

typedef struct laadm_grp_attr_sys {
	uint32_t	lg_key;
	uint32_t	lg_nports;
	laadm_port_attr_sys_t *lg_ports;
	uint32_t	lg_policy;
	uchar_t		lg_mac[ETHERADDRL];
	boolean_t	lg_mac_fixed;
	aggr_lacp_mode_t lg_lacp_mode;
	aggr_lacp_timer_t lg_lacp_timer;
} laadm_grp_attr_sys_t;

/*
 * Diagnostic codes.  These supplement error messages.
 */
typedef enum {
	LAADM_DIAG_REPOSITORY_OPENFAIL  = 1,
	LAADM_DIAG_REPOSITORY_PARSEFAIL	= 2,
	LAADM_DIAG_REPOSITORY_CLOSEFAIL	= 3,
	LAADM_DIAG_INVALID_INTFNAME	= 4,
	LAADM_DIAG_INVALID_MACADDR	= 5,
	LAADM_DIAG_INVALID_KEY		= 6
} laadm_diag_t;

extern int laadm_create(uint32_t, uint32_t, laadm_port_attr_db_t *,
    uint32_t, boolean_t, uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t,
    boolean_t, const char *, laadm_diag_t *);
extern int laadm_delete(uint32_t, boolean_t, const char *,
    laadm_diag_t *);
extern int laadm_add(uint32_t, uint32_t, laadm_port_attr_db_t *,
    boolean_t, const char *, laadm_diag_t *);
extern int laadm_remove(uint32_t, uint32_t, laadm_port_attr_db_t *,
    boolean_t, const char *, laadm_diag_t *);
extern int laadm_modify(uint32_t, uint32_t, uint32_t, boolean_t,
    uchar_t *, aggr_lacp_mode_t, aggr_lacp_timer_t, boolean_t, const char *,
    laadm_diag_t *);
extern int laadm_up(uint32_t, const char *, laadm_diag_t *);
extern int laadm_down(uint32_t);

extern boolean_t laadm_str_to_policy(const char *, uint32_t *);
extern char *laadm_policy_to_str(uint32_t, char *buf);
extern boolean_t laadm_str_to_mac_addr(const char *, boolean_t *, uchar_t *);
extern const char *laadm_mac_addr_to_str(unsigned char *, char *);

extern boolean_t laadm_str_to_lacp_mode(const char *, aggr_lacp_mode_t *);
extern const char *laadm_lacp_mode_to_str(aggr_lacp_mode_t);
extern boolean_t laadm_str_to_lacp_timer(const char *, aggr_lacp_timer_t *);
extern const char *laadm_lacp_timer_to_str(aggr_lacp_timer_t);

extern int laadm_walk_sys(int (*)(void *, laadm_grp_attr_sys_t *), void *);
extern const char *laadm_diag(laadm_diag_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBLAADM_H */
