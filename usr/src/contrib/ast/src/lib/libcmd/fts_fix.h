/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2011 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * -lcmd specific workaround to handle
 *	fts_namelen
 *	fts_pathlen
 *	fts_level
 * changing from [unsigned] short bit to [s]size_t
 *
 * ksh (or any other main application) that pulls in -lcmd
 * at runtime may result in old -last running with new -lcmd
 * which is not a good situation (tm)
 */

#ifndef _FTS_FIX_H
#define _FTS_FIX_H	1

#include <fts.h>

#ifdef	fts_read
#undef	fts_read
#else
#define _ast_fts_read	fts_read
#endif

#define fts_read	_fts_read

extern FTSENT*		fts_read(FTS*);

#endif
