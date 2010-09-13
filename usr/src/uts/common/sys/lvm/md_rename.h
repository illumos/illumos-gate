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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MD_RENAME_H
#define	_SYS_MD_RENAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#ifdef	DEBUG
#include <sys/thread.h>
#endif
#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/lvm/mdvar.h>

/*
 * rename/exchange common definitions
 */
#define	MD_RENAME_VERSION_OFFLINE	(1)	/* top-level must be offline */
#define	MD_RENAME_VERSION_ONLINE	(2)	/* includes offline too */

/*
 * current protocol only allows offline exchange
 */
#define	MD_RENAME_VERSION	MD_RENAME_VERSION_OFFLINE

/*
 * The rename (aka. exchange) function is implemented as the
 * following set of named services. Many of these are implemented
 * generically and only overridden when a specific driver needs
 * special care.
 */

#if defined(_KERNEL)

#define	MDRNM_LIST_URFOLKS		"rename svc: list your parents"
#define	MDRNM_LIST_URSELF		"rename svc: list your self"
#define	MDRNM_LIST_URKIDS		"rename svc: list your children"

#define	MDRNM_LOCK			"rename svc: lock"
#define	MDRNM_UNLOCK			"rename svc: unlock"
#define	MDRNM_CHECK			"rename svc: check state"

/* role swappers */
#define	MDRNM_UPDATE_KIDS		"rename svc: parent update children"
#define	MDRNM_PARENT_UPDATE_TO		"rename svc: parent update to"
#define	MDRNM_SELF_UPDATE_FROM_UP	"rename svc: self update from up"
#define	MDRNM_UPDATE_SELF		"rename svc: self update self"
#define	MDRNM_SELF_UPDATE_FROM_DOWN	"rename svc: self update from down"
#define	MDRNM_CHILD_UPDATE_TO		"rename svc: child update to"
#define	MDRNM_UPDATE_FOLKS		"rename svc: child update parents"

typedef enum md_rename_role_t {
	MDRR_UNK	= 0,
	MDRR_PARENT	= 1,
	MDRR_SELF	= 2,
	MDRR_CHILD	= 3,
	MDRR_NROLES	= MDRR_CHILD
} md_renrole_t;

typedef struct md_rendelta_status {
	uint_t	spare_beg	:1;
	uint_t	locked		:1;
	uint_t	checked		:1;
	uint_t	role_swapped	:1;
	uint_t	unlocked	:1;
	uint_t	spacer		:2;
	uint_t	is_open		:1;
	uint_t	spare_end;
} md_rendstat_t;

typedef struct md_rentxn_status {
	uint_t	spare_beg	:1;
	uint_t	trans_in_stack	:1;
	uint_t	spare_end;
} md_rentstat_t;

typedef struct md_rename_transaction {
	u_longlong_t	 beginning;
	md_error_t	 mde;
	md_renop_t	 op;
	int		 revision;
	uint_t		 uflags;
	int		 rec_idx;
	mddb_recid_t	*recids;
	int		 n_recids;
	md_rentstat_t	 stat;

	struct md_rename_txn_unit_state {
		u_longlong_t	 beginning;
		minor_t		 mnum;
		mdi_unit_t	*uip;
		md_unit_t	*unp;
		key_t		 key;
		kstat_t		*kstatp;
		u_longlong_t	 end;

	}		from, to;
	u_longlong_t	end;
} md_rentxn_t;

typedef struct md_rendelta md_rendelta_t;

typedef void md_ren_void_svc_t(md_rendelta_t *, md_rentxn_t *);
typedef intptr_t md_ren_svc_t(md_rendelta_t *, md_rentxn_t *);
typedef int md_ren_list_svc_t(md_rendelta_t **, md_rentxn_t *);

typedef md_ren_void_svc_t md_ren_roleswap_svc_t;

struct md_rendelta {
	u_longlong_t		beginning;
	md_rendelta_t		*next, *prev;
	md_dev64_t		dev;
	md_renrole_t		old_role, new_role;
	md_unit_t		*unp;
	mdi_unit_t		*uip;

	md_ren_svc_t		*lock;
	md_ren_void_svc_t	*unlock;
	md_ren_svc_t		*check;
	md_ren_roleswap_svc_t	*role_swap;

	md_rendstat_t		txn_stat;
	u_longlong_t		end;
};

/* Externals from md_rename.c */
extern int md_rename(md_rename_t *, IOLOCK *);
extern md_rendelta_t *md_build_rendelta(md_renrole_t, md_renrole_t,
	md_dev64_t, md_rendelta_t *, md_unit_t *, mdi_unit_t *, md_error_t *);
extern void md_store_recid(int *, mddb_recid_t *, md_unit_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MD_RENAME_H */
