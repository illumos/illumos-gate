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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBDLETHER_H
#define	_LIBDLETHER_H

#include <sys/types.h>
#include <libdladm.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_ether_spdx_s {
	int			lesd_speed;
	link_duplex_t		lesd_duplex;
} dladm_ether_spdx_t;

typedef struct dladm_ether_attr_s {
	boolean_t		le_autoneg;
	boolean_t		le_pause;
	boolean_t		le_asmpause;
	boolean_t		le_fault;
	uint32_t		le_num_spdx;
	dladm_ether_spdx_t	*le_spdx;
} dladm_ether_attr_t;

/*
 * Supported PTYPE values
 */
#define	CURRENT	0
#define	CAPABLE	1
#define	ADV	2
#define	PEERADV	3

/* Names of the lei_attr[] PTYPE slots for use in arrays */
#define	LEI_ATTR_NAMES "current", "capable", "adv", "peeradv"

typedef struct dladm_ether_info {
	datalink_id_t		lei_linkid;
	char			lei_linkname[MAXLINKNAMELEN];
	link_state_t		lei_state;
	dladm_ether_attr_t	lei_attr[PEERADV+1];
} dladm_ether_info_t;

extern dladm_status_t	dladm_ether_info(datalink_id_t, dladm_ether_info_t *);
extern char		*dladm_ether_autoneg2str(char *, size_t,
			    dladm_ether_info_t *, int);
extern char		*dladm_ether_pause2str(char *, size_t,
			    dladm_ether_info_t *, int);
extern char		*dladm_ether_spdx2str(char *, size_t,
			    dladm_ether_info_t *, int);
extern void		dladm_ether_info_done(dladm_ether_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLETHER_H */
