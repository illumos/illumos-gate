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
 * Copyright 1999,2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FUNCS_H
#define	_FUNCS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	CMD_PREFIX_USER	"user"

#define	AUTH_SEP	","
#define	PROF_SEP	","
#define	ROLE_SEP	","

#define	MAX_TYPE_LENGTH	64

char *getusertype(char *cmdname);

int is_role(char *usertype);

void change_key(const char *, char *);
void addkey_args(char **, int *);
char *getsetdefval(const char *, char *);

extern int nkeys;

/* create_home() or rm_files() flags */
#define	MANAGE_ZFS_OPT	"MANAGE_ZFS="
#define	MANAGE_ZFS	1

#ifdef	__cplusplus
}
#endif

#endif	/* _FUNCS_H */
