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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__SHIM_HOOKS_H
#define	__SHIM_HOOKS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * DESCRIPTION: This file implements the hooks between old style DBM calls and
 *              the shim version of the same calls. By including this file a
 *              C files calls are diverted to the shim versions.
 *
 *		Do NOT include this in the shim code itself or you will be
 *		unable to make real dbm calls.
 *
 *		Do NOT include this in the client side NIS files.
 *
 *		One day it may be possible to implement a more elegant version
 *		of this based on the linkers 'interposition' mechanism.
 */

/*
 * Extern defs for new calls. Must have identical args to traditional version.
 */
extern void 	shim_dbm_close(DBM *db);
extern int 	shim_dbm_delete(DBM *db, datum key);
extern datum 	shim_dbm_fetch(DBM *db, datum key);
extern datum 	shim_dbm_fetch_noupdate(DBM *db, datum key);
extern datum	shim_dbm_firstkey(DBM *db);
extern datum 	shim_dbm_nextkey(DBM *db);
extern datum 	shim_dbm_do_nextkey(DBM *db, datum inkey);
extern DBM 	*shim_dbm_open(const  char  *file,  int  open_flags,
				mode_t file_mode);
extern int  	shim_dbm_store(DBM  *db,  datum  key,  datum  content,
				int store_mode);
void		shim_exit(int code);

/*
 * Externs for other function related to maps
 */
extern char	*get_map_name(DBM *);

/*
 * Hooks. Alias standard dbm call names to new calls
 */

#define	dbm_close	shim_dbm_close
#define	dbm_delete	shim_dbm_delete
#define	dbm_fetch	shim_dbm_fetch
#define	dbm_firstkey	shim_dbm_firstkey
#define	dbm_nextkey	shim_dbm_nextkey
#define	dbm_do_nextkey	shim_dbm_do_nextkey
#define	dbm_open	shim_dbm_open
#define	dbm_store	shim_dbm_store
#define	exit		shim_exit

#ifdef	__cplusplus
}
#endif

#endif	/* __SHIM_HOOKS_H */
