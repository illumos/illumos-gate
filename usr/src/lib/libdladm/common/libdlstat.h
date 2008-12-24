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

#ifndef _LIBDLSTAT_H
#define	_LIBDLSTAT_H

/*
 * This file includes structures, macros and common routines shared by all
 * data-link administration, and routines which are used to retrieve and
 * display statistics.
 */

#include <kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LINK_REPORT	1
#define	FLOW_REPORT	2

typedef struct pktsum_s {
	hrtime_t	snaptime;
	uint64_t	ipackets;
	uint64_t	opackets;
	uint64_t	rbytes;
	uint64_t	obytes;
	uint64_t	ierrors;
	uint64_t	oerrors;
} pktsum_t;

extern void		dladm_continuous(dladm_handle_t, datalink_id_t,
			    const char *, int, int);

extern kstat_t		*dladm_kstat_lookup(kstat_ctl_t *, const char *, int,
			    const char *, const char *);
extern void		dladm_get_stats(kstat_ctl_t *, kstat_t *, pktsum_t *);
extern int		dladm_kstat_value(kstat_t *, const char *, uint8_t,
			    void *);
extern dladm_status_t	dladm_get_single_mac_stat(dladm_handle_t, datalink_id_t,
			    const char *, uint8_t, void *);

extern void		dladm_stats_total(pktsum_t *, pktsum_t *, pktsum_t *);
extern void		dladm_stats_diff(pktsum_t *, pktsum_t *, pktsum_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLSTAT_H */
