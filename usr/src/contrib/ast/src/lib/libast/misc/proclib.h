/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * process library definitions
 */

#ifndef _PROCLIB_H
#define _PROCLIB_H

#include <ast_standards.h>
#include <ast.h>
#include <errno.h>
#include <sig.h>
#include <wait.h>

#if _lib_sigprocmask
typedef sigset_t Sig_mask_t;
#else
typedef unsigned long Sig_mask_t;
#endif

struct Mods_s;

#define _PROC_PRIVATE_ \
	struct Mod_s*	mods;		/* process modification state	*/ \
	long		flags;		/* original PROC_* flags	*/ \
	Sig_mask_t	mask;		/* original blocked sig mask	*/ \
	Sig_handler_t	sigchld;	/* PROC_FOREGROUND SIG_DFL	*/ \
	Sig_handler_t	sigint;		/* PROC_FOREGROUND SIG_IGN	*/ \
	Sig_handler_t	sigquit;	/* PROC_FOREGROUND SIG_IGN	*/

#include <proc.h>

#define proc_default	_proc_info_	/* hide external symbol		*/

extern Proc_t		proc_default;	/* first proc			*/

#ifndef errno
extern int		errno;
#endif

#endif
