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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MESSAGES_H
#define	_MESSAGES_H

extern void errmsg(int, ...);

/* WARNING: uid %d is reserved. */
#define	M_RESERVED		0

/* WARNING: more than NGROUPS_MAX(%d) groups specified. */
#define	M_MAXGROUPS	1

/* ERROR: invalid syntax.\nusage:  useradd ... */
#define	M_AUSAGE		2

/* ERROR: Invalid syntax.\nusage:  userdel [-r] login\n" */
#define	M_DUSAGE		3

/* ERROR: Invalid syntax.\nusage:  usermod ... */
#define	M_MUSAGE		4


/* ERROR: Unexpected failure.  Defaults unchanged. */
#define	M_FAILED	5

/* ERROR: Unable to remove files from home directory. */
#define	M_RMFILES	6

/* ERROR: Unable to remove home directory. */
#define	M_RMHOME		7

/* ERROR: Cannot update system files - login cannot be %s. */
#define	M_UPDATE		8

/* ERROR: uid %d is already in use.  Choose another. */
#define	M_UID_USED	9

/* ERROR: %s is already in use.  Choose another. */
#define	M_USED	10

/* ERROR: %s does not exist. */
#define	M_EXIST	11

/* ERROR: %s is not a valid %s.  Choose another. */
#define	M_INVALID		12

/* ERROR: %s is in use.  Cannot %s it. */
#define	M_BUSY	13

/* WARNING: %s has no permissions to use %s. */
#define	M_NO_PERM	14

/* ERROR: There is not sufficient space to move %s home directory to %s */
#define	M_NOSPACE		15

/* ERROR: %s %d is too big.  Choose another. */
#define	M_TOOBIG	16

/* ERROR: group %s does not exist.  Choose another. */
#define	M_GRP_NOTUSED	17

/* ERROR: Unable to %s: %s */
#define	M_OOPS	18

/* ERROR: %s is not a full path name.  Choose another. */
#define	M_RELPATH	19

/* ERROR: %s is the primary group name.  Choose another. */
#define	M_SAME_GRP	20

/* ERROR: Inconsistent password files.  See pwconv(1M). */
#define	M_HOSED_FILES	21

/* ERROR: %s is not a local user. */
#define	M_NONLOCAL	22

/* ERROR: Permission denied. */
#define	M_PERM_DENIED	23

/* WARNING: Group entry exceeds 2048 char: /etc/group entry truncated. */
#define	M_GROUP_ENTRY_OVF  24

/* ERROR: invalid syntax.\nusage:  roleadd ... */
#define	M_ARUSAGE		25

/* ERROR: Invalid syntax.\nusage:  roledel [-r] login\n" */
#define	M_DRUSAGE		26

/* ERROR: Invalid syntax.\nusage:  rolemod -u ... */
#define	M_MRUSAGE		27

/* ERROR: project %s does not exist.  Choose another. */
#define	M_PROJ_NOTUSED 28

/* WARNING: more than NPROJECTS_MAX(%d) projects specified. */
#define	M_MAXPROJECTS	29

/* WARNING: Project entry exceeds 512 char: /etc/project entry truncated. */
#define	M_PROJ_ENTRY_OVF  30

/* ERROR: Invalid key. */
#define	M_INVALID_KEY	31

/* ERROR: Missing value specification. */
#define	M_INVALID_VALUE	32

/* ERROR: Multiple definitions of key ``%s''. */
#define	M_REDEFINED_KEY	33

/* ERROR: Roles must be modified with rolemod */
#define	M_ISROLE	34

/* ERROR: Users must be modified with usermod */
#define	M_ISUSER	35

/* WARNING: gid %d is reserved. */
#define	M_RESERVED_GID		36

/* ERROR: Failed to read /etc/group file due to invalid entry or read error. */
#define	M_READ_ERROR	37

/* ERROR: %s is too long.  Choose another. */
#define	M_TOO_LONG	38

#endif /* _MESSAGES_H */
