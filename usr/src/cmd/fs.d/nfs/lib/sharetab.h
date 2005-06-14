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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SHARETAB_H
#define	_SHARETAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct share {
	char *sh_path;
	char *sh_res;
	char *sh_fstype;
	char *sh_opts;
	char *sh_descr;
};

struct sh_list {		/* cached share list */
	struct sh_list *shl_next;
	struct share   *shl_sh;
};

#define	SHARETAB	"/etc/dfs/sharetab"
#define	MAXBUFSIZE	65536

#define	SHOPT_RO	"ro"
#define	SHOPT_RW	"rw"

#define	SHOPT_SEC	"sec"
#define	SHOPT_SECURE	"secure"
#define	SHOPT_ROOT	"root"
#define	SHOPT_ANON	"anon"
#define	SHOPT_WINDOW	"window"
#define	SHOPT_NOSUB	"nosub"
#define	SHOPT_NOSUID	"nosuid"
#define	SHOPT_ACLOK	"aclok"
#define	SHOPT_PUBLIC	"public"
#define	SHOPT_INDEX	"index"
#define	SHOPT_LOG	"log"

/* XXX The following are added for testing volatile fh's purposes only */
#ifdef VOLATILE_FH_TEST
#define	SHOPT_VOLFH	"volfh"
#endif /* VOLATILE_FH_TEST */

int		getshare(FILE *, struct share **);
int		putshare(FILE *, struct share *);
int		remshare(FILE *, char *, int *);
char 		*getshareopt(char *, char *);
struct share	*sharedup(struct share *);
void		sharefree(struct share *);

#ifdef __cplusplus
}
#endif

#endif /* !_SHARETAB_H */
