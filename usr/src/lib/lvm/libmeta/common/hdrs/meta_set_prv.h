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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_META_SET_COM_H
#define	_META_SET_COM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <meta.h>
#include <ctype.h>
#include <sys/lvm/md_convert.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	RB_PREEMPT	if (md_got_sig()) goto rollback
#ifdef DEBUG
#define	RB_TEST(tstpt, tag, ep)	if (rb_test(tstpt, tag, (ep)) < 0) \
					goto rollback;
#else	/* !DEBUG */
#define	RB_TEST(tstpt, tag, ep)
#endif	/* DEBUG */

/* meta_setup.c */
extern int	procsigs(int block, sigset_t *oldsigs, md_error_t *ep);

#ifdef DEBUG
extern int	rb_test(int rbt_sel_tpt, char *rbt_sel_tag, md_error_t *ep);
#endif	/* DEBUG */

/*
 * Flag values used by the nodehasset() function.
 */
#define	NHS_N_EQ	0x00000001	/* name == */
#define	NHS_NS_EQ	0x00000002	/* name, setno == */
#define	NHS_NST_EQ	0x00000004	/* name, setno, TS == */
#define	NHS_NSTG_EQ	0x00000008	/* name, setno, TS, genid == */
#define	NHS_NST_EQ_G_GT	0x00000010	/* name, setno, TS ==, genid > */

/*
 * Node, set, and mediator names can be any printable characters
 * (isprint()) except for the characters in the #define that follows.
 */
#define	INVALID_IN_NAMES	" *?/"

/* meta_set_prv.c */
extern	int		checkdrive_onnode(mdsetname_t *sp, mddrivename_t *dnp,
			    char *node, md_error_t *ep);
extern	side_t		getnodeside(char *node, md_set_desc *sd);
extern	int		halt_set(mdsetname_t *sp, md_error_t *ep);
extern	md_drive_desc	*metadrivedesc_append(md_drive_desc **dd,
			    mddrivename_t *dnp, int dbcnt, int dbsize,
			    md_timeval32_t timestamp, ulong_t genid,
			    uint_t flags);
extern	int		nodehasset(mdsetname_t *sp, char *node,
			    uint_t match_flag, md_error_t *ep);
extern	int		nodesuniq(mdsetname_t *sp, int cnt, char **strings,
			    md_error_t *ep);
extern	int		own_set(mdsetname_t *sp, char **owner_of_set,
			    int forceflg, md_error_t *ep);
extern	void		resync_genid(mdsetname_t *sp, md_set_desc *sd,
			    ulong_t max_genid, int node_c, char **node_v);
extern	int		setup_db_bydd(mdsetname_t *sp, md_drive_desc *dd,
			    int force, md_error_t *ep);
extern	int		snarf_set(mdsetname_t *sp, bool_t stale_bool,
				md_error_t *ep);

#ifdef	__cplusplus
}
#endif

#endif	/* _META_SET_COM_H */
