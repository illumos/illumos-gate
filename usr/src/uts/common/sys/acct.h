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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_ACCT_H
#define	_SYS_ACCT_H

#include <sys/types.h>
#include <sys/types32.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Accounting structures
 */

typedef	ushort_t comp_t;		/* "floating point" */
		/* 13-bit fraction, 3-bit exponent  */

/* SVR4 acct structure */
struct acct {
	char	ac_flag;		/* Accounting flag */
	char	ac_stat;		/* Exit status */
	uid32_t	ac_uid;			/* Accounting user ID */
	gid32_t	ac_gid;			/* Accounting group ID */
	dev32_t	ac_tty;			/* control typewriter */
	time32_t ac_btime;		/* Beginning time */
	comp_t	ac_utime;		/* acctng user time in clock ticks */
	comp_t	ac_stime;		/* acctng system time in clock ticks */
	comp_t	ac_etime;		/* acctng elapsed time in clock ticks */
	comp_t	ac_mem;			/* memory usage */
	comp_t	ac_io;			/* chars transferred */
	comp_t	ac_rw;			/* blocks read or written */
	char	ac_comm[8];		/* command name */
};

/*
 * Account commands will use this header to read SVR3
 * accounting data files.
 */

struct o_acct {
	char	ac_flag;		/* Accounting flag */
	char	ac_stat;		/* Exit status */
	o_uid_t	ac_uid;			/* Accounting user ID */
	o_gid_t	ac_gid;			/* Accounting group ID */
	o_dev_t	ac_tty;			/* control typewriter */
	time32_t ac_btime;		/* Beginning time */
	comp_t	ac_utime;		/* acctng user time in clock ticks */
	comp_t	ac_stime;		/* acctng system time in clock ticks */
	comp_t	ac_etime;		/* acctng elapsed time in clock ticks */
	comp_t	ac_mem;			/* memory usage */
	comp_t	ac_io;			/* chars transferred */
	comp_t	ac_rw;			/* blocks read or written */
	char	ac_comm[8];		/* command name */
};

#if !defined(_KERNEL)
extern int acct(const char *);
#endif /* !defined(_KERNEL) */

#if defined(_KERNEL)

void	acct(char);
int	sysacct(char *);

struct vnode;
int	acct_fs_in_use(struct vnode *);
#endif

#define	AFORK	0001		/* has executed fork, but no exec */
#define	ASU	0002		/* used super-user privileges */
#define	AEXPND	0040		/* expanded acct structure */
#define	ACCTF	0300		/* record type: 00 = acct */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ACCT_H */
