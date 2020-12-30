/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
/*
 * Ksh - AT&T Labs
 * Written by David Korn
 * This file defines all the  read/write shell global variables
 */

#include	"defs.h"
#include	"jobs.h"
#include	"shlex.h"
#include	"edit.h"
#include	"timeout.h"

Shell_t			sh = {0};
struct	shared		*shgd;
#ifdef	__IMPORT__
    Shell_t		*_imp__sh = &sh;
#endif

Dtdisc_t	_Nvdisc =
{
	offsetof(Namval_t,nvname), -1 , 0, 0, 0, nv_compare
};

/* reserve room for writable state table */
char *sh_lexstates[ST_NONE] = {0};

struct jobs	job = {0};
int32_t		sh_mailchk = 600;

