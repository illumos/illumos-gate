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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_PROJECT_H
#define	_SYS_PROJECT_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/kstat.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/rctl.h>
#include <sys/ipc_rctl.h>
#include <sys/zone.h>

typedef struct kproject_kstat {
	kstat_named_t kpk_zonename;
	kstat_named_t kpk_usage;
	kstat_named_t kpk_value;
} kproject_kstat_t;

typedef struct kproject_data {		/* Datum protected by: */
	rctl_qty_t	kpd_shmmax;	/* shm's ipcs_lock */
	ipc_rqty_t	kpd_ipc;	/* shm|sem|msg's ipcs lock */
	rctl_qty_t	kpd_locked_mem;	 /* zone_rctl_lock */
	rctl_qty_t	kpd_locked_mem_ctl; /* kpj_rctls->rcs_lock */
	rctl_qty_t	kpd_contract;	/* contract_lock */
	kmutex_t	kpd_crypto_lock;
	rctl_qty_t	kpd_crypto_mem;	/* kpd_crypto_lock above */
	rctl_qty_t	kpd_crypto_mem_ctl; /* kpj_rctls->rcs_lock */
	kstat_t		*kpd_lockedmem_kstat; /* locked memory kstat */
	kstat_t		*kpd_nprocs_kstat;
} kproject_data_t;

struct cpucap;

/*
 * The first two fields of this structure must not be reordered.
 */
typedef struct kproject {
	projid_t 	kpj_id;		/* project ID		*/
	zoneid_t	kpj_zoneid;	/* zone ID		*/
	struct zone	*kpj_zone;	/* zone pointer		*/
	uint_t		kpj_count;	/* reference counter	*/
	uint32_t	kpj_shares;	/* number of shares	*/
	rctl_set_t	*kpj_rctls;	/* resource control set */
	struct kproject	*kpj_prev;	/* previous project	*/
	struct kproject	*kpj_next;	/* next project		*/
	kproject_data_t	kpj_data;	/* subsystem-specfic data */
	kmutex_t	kpj_poolbind;	/* synchronization with pools	*/
	rctl_qty_t	kpj_nlwps;	/* protected by project's zone's */
					/* zone_nlwps_lock */
	rctl_qty_t	kpj_nlwps_ctl;	/* protected by kpj_rctls->rcs_lock */
	rctl_qty_t	kpj_ntasks;	/* protected by project's zone's */
					/* zone_nlwps_lock */
	rctl_qty_t	kpj_ntasks_ctl;	/* protected by kpj_rctls->rcs_lock */
	struct cpucap	*kpj_cpucap;	/* CPU cap data			*/
	struct klpd_reg	*kpj_klpd;	/* our extended policy */
					/* protected by klpd_mutex */
	rctl_qty_t	kpj_nprocs;	/* protected by project's zone's */
					/* zone_nlwps_lock */
	rctl_qty_t	kpj_nprocs_ctl;	/* protected by kpj_rctls->rcs_lock */
} kproject_t;

#ifdef _KERNEL

/*
 * Flags for project_hold_by_id()
 */
#define	PROJECT_HOLD_FIND	1
#define	PROJECT_HOLD_INSERT	2

void project_init(void);
kproject_t *project_hold(kproject_t *);
kproject_t *project_hold_by_id(projid_t, struct zone *, int);
void project_rele(kproject_t *);
int project_walk_all(zoneid_t, int (*)(kproject_t *, void *), void *);
projid_t curprojid(void);

extern kproject_t *proj0p;
extern rctl_hndl_t rc_project_nlwps;
extern rctl_hndl_t rc_project_nprocs;
extern rctl_hndl_t rc_project_ntasks;
extern rctl_hndl_t rc_project_locked_mem;
extern rctl_hndl_t rc_project_crypto_mem;
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROJECT_H */
