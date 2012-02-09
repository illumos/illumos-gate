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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_LDAP_GLOB_H
#define	_LDAP_GLOB_H

#include <stdio.h>
#include <rpcsvc/nis.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following may be defined and set by the application. If not,
 * we'll use local equivalents that disable the feature.
 */
extern int	verbose;
extern int	justTesting;
extern FILE	*cons;
extern int	setColumnsDuringConfig;

/*
 * Functions that reside in rpc.nisd. We provide local do-nothing-return-
 * failure incarnations that are there strictly to prevent a link error.
 * If libnisdb calls one of these, we had better be running inside rpc.nisd.
 */
extern int		update_root_object(nis_name root_dir,
				nis_object *d_obj);
extern nis_object	*get_root_object(void);
extern int		remove_root_object(nis_name root_dir,
				nis_object* d_obj);
extern int		beginTransaction(void);
extern int		abort_transaction(int xid);
extern int		endTransaction(int xid, nis_object *dirObj);
extern int		addUpdate(log_entry_t type, char *name,
				int numAttr, nis_attr *attr, nis_object *obj,
				nis_object *oldDir, uint32_t ttime);
extern int		lockTransLog(const char *msg, int wr, int trylock);
extern void		unlockTransLog(const char *msg, int wr);
extern int		__nis_lock_db_table(nis_name name, int readwrite,
						int *trylock, char *msg);
extern int		__nis_ulock_db_table(nis_name name, int readwrite,
						int remove, char *msg);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_GLOB_H */
