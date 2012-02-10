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

#include "ldap_glob.h"

/* These are the local versions we use if the app doesn't provide overrides */
int		verbose = 0;
int		justTesting = 0;
FILE		*cons = 0;
int		setColumnsDuringConfig = 0;

int
__local_update_root_object(nis_name root_dir, nis_object *d_obj) {
	return (0);
}

nis_object *
__local_get_root_object(void) {
	return (0);
}

int
__local_remove_root_object(nis_name root_dir, nis_object* d_obj) {
	return (0);
}

int
__local_beginTransaction(void) {
	return (1);
}

int
__local_abort_transaction(int xid) {
	return (0);
}

int
__local_endTransaction(int xid, nis_object *dirObj) {
	return (0);
}

int
__local_addUpdate(log_entry_t type, char *name, int numAttr, nis_attr *attr,
		nis_object *obj, nis_object *oldDir, uint32_t ttime) {
	return (-1);
}

int
__local_lockTransLog(const char *msg, int wr, int trylock) {
	return (0);
}

void
__local_unlockTransLog(const char *msg, int wr) {
}

int
__local__nis_lock_db_table(nis_name name, int readwrite, int *trylock,
				char *msg) {
	return (1);
}

int
__local__nis_ulock_db_table(nis_name name, int readwrite, int remove,
				char *msg) {
	return (1);
}

/* Weak symbol linkage allows override; default is local versions */
#pragma weak	verbose
#pragma weak	justTesting
#pragma weak	cons
#pragma weak	setColumnsDuringConfig
#pragma weak	update_root_object = __local_update_root_object
#pragma weak	get_root_object = __local_get_root_object
#pragma weak	remove_root_object = __local_remove_root_object
#pragma weak	beginTransaction = __local_beginTransaction
#pragma weak	abort_transaction = __local_abort_transaction
#pragma weak	endTransaction = __local_endTransaction
#pragma weak	addUpdate = __local_addUpdate
#pragma weak	lockTransLog = __local_lockTransLog
#pragma weak	unlockTransLog = __local_unlockTransLog
#pragma weak	__nis_lock_db_table = __local__nis_lock_db_table
#pragma weak	__nis_ulock_db_table = __local__nis_ulock_db_table
