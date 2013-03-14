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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */
/*
 * This file contains mdb private tab completion related functions. Public
 * functions for modules are put into the module API, see mdb_modapi.h. Note
 * that the mdb_ctf_id_t value is private to mdb and not a part of the module
 * api, hence it has to stay in here.
 */

#ifndef	_MDB_TAB_H
#define	_MDB_TAB_H

#include <sys/types.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_MDB

struct mdb_tab_cookie {
	mdb_nv_t	mtc_nv;
	char		mtc_match[MDB_SYM_NAMLEN];
	char		mtc_base[MDB_SYM_NAMLEN];
	void		*mtc_cba;
};

extern mdb_tab_cookie_t *mdb_tab_init(void);
extern size_t mdb_tab_size(mdb_tab_cookie_t *);
extern const char *mdb_tab_match(mdb_tab_cookie_t *);
extern void mdb_tab_print(mdb_tab_cookie_t *);
extern void mdb_tab_fini(mdb_tab_cookie_t *);
extern int mdb_tab_complete_global(mdb_tab_cookie_t *, const char *);
extern int mdb_tab_complete_dcmd(mdb_tab_cookie_t *, const char *);
extern int mdb_tab_complete_walker(mdb_tab_cookie_t *, const char *);
extern int mdb_tab_complete_member_by_id(mdb_tab_cookie_t *, mdb_ctf_id_t,
    const char *);
extern int mdb_tab_command(mdb_tab_cookie_t *, const char *);

#endif	/* _MDB */

#ifdef	__cplusplus
}
#endif

#endif /* _MDB_TAB_H */
