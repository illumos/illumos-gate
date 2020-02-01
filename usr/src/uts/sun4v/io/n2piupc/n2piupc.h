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

#ifndef	_N2PIUPC_H
#define	_N2PIUPC_H

/*
 * Definitions which deal with things other than registers.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sunddi.h>

#define	SUCCESS	0
#define	FAILURE	-1

#define	NAMEINST(dip)	ddi_driver_name(dip), ddi_get_instance(dip)

/* Used for data structure retrieval during kstat update. */
typedef struct n2piu_ksinfo {
	kstat_t		*cntr_ksp;
	struct n2piupc	*n2piupc_p;
	n2piu_grp_t	*grp_p;
} n2piu_ksinfo_t;

/* State structure. */
typedef struct n2piupc {
	dev_info_t	*n2piupc_dip;
	cntr_handle_t	n2piupc_handle;
	void *		n2piupc_biterr_p;
	n2piu_ksinfo_t	*n2piupc_ksinfo_p[NUM_GRPS];
} n2piupc_t;

/* Debugging facility. */
#ifdef DEBUG
extern int n2piupc_debug;
#define	N2PIUPC_DBG1 if (n2piupc_debug >= 1) printf
#define	N2PIUPC_DBG2 if (n2piupc_debug >= 2) printf
#else
#define	N2PIUPC_DBG1(...)
#define	N2PIUPC_DBG2(...)
#endif	/* DEBUG */


/* Function definitions exported among different modules. */
extern int n2piupc_kstat_init();
extern void n2piupc_kstat_fini();
extern int n2piupc_kstat_attach(n2piupc_t *n2piupc_p);
extern void n2piupc_kstat_detach(n2piupc_t *n2piupc_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _N2PIUPC_H */
