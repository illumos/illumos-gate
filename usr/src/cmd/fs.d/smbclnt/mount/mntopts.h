/*
 * Copyright (c) 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)mntopts.h	8.7 (Berkeley) 3/29/95
 *	$Id: mntopts.h,v 1.4 2004/03/19 01:49:47 lindak Exp $
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CIFS_MNTOPTS_H
#define	_CIFS_MNTOPTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vfs.h>
#ifdef UNPORTED
/* In solaris this is defined in proto/root_i386/usr/include/sys/vfs.h */
struct mntopt {
	const char *m_option;	/* option name */
	int m_inverse;		/* if a negative option, e.g. "dev" */
	int m_flag;		/* bit to set, e.g. MNT_RDONLY */
	int m_altloc;		/* 1 => set bit in altflags */
};
#endif /* UNPORTED */

/* User-visible MNT_ flags. */
#define	MOPT_ASYNC		{ "async",	0, MNT_ASYNC, 0 }
#define	MOPT_NODEV		{ "dev",	1, MNT_NODEV, 0 }
#define	MOPT_NOEXEC		{ "exec",	1, MNT_NOEXEC, 0 }
#define	MOPT_NOSUID		{ "suid",	1, MNT_NOSUID, 0 }
#define	MOPT_RDONLY		{ "rdonly",	0, MNT_RDONLY, 0 }
#define	MOPT_SYNC		{ "sync",	0, MNT_SYNCHRONOUS, 0 }
#define	MOPT_UNION		{ "union",	0, MNT_UNION, 0 }
#define	MOPT_USERQUOTA		{ "userquota",	0, 0, 0 }
#define	MOPT_GROUPQUOTA		{ "groupquota",	0, 0, 0 }
#define	MOPT_BROWSE		{ "browse",	1, MNT_DONTBROWSE, 0 }
#define	MOPT_AUTOMOUNTED	{ "automounted", 0, MNT_AUTOMOUNTED, 0 }

/* Control flags. */
#define	MOPT_FORCE		{ "force",	0, MNT_FORCE, 0 }
#define	MOPT_UPDATE		{ "update",	0, MNT_UPDATE, 0 }
#define	MOPT_RO			{ "ro",		0, MNT_RDONLY, 0 }
#define	MOPT_RW			{ "rw",		1, MNT_RDONLY, 0 }

/* This is parsed by mount(1m), but is ignored by specific mount_*(1m)s. */
#define	MOPT_AUTO		{ "auto",	0, 0, 0 }

#define	MOPT_FSTAB_COMPAT						\
	MOPT_RO,							\
	MOPT_RW,							\
	MOPT_AUTO

/* Standard options which all mounts can understand. */
#define	MOPT_STDOPTS							\
	MOPT_USERQUOTA,							\
	MOPT_GROUPQUOTA,						\
	MOPT_FSTAB_COMPAT,						\
	MOPT_NODEV,							\
	MOPT_NOEXEC,							\
	MOPT_NOSUID,							\
	MOPT_RDONLY,							\
	MOPT_UNION,							\
	MOPT_BROWSE,							\
	MOPT_AUTOMOUNTED

void getmntopts(const char *, const mntopt_t *, int *, int *);

extern int getmnt_silent;

#ifdef __cplusplus
}
#endif

#endif /* _CIFS_MNTOPTS_H */
