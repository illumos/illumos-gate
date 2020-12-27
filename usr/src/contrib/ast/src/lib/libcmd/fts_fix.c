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
 *
 * probably safe to drop after 20150101
 */

#include <ast.h>
#include <fts_fix.h>

#undef	fts_read

FTSENT*
_fts_read(FTS* fts)
{
	FTSENT*		oe;

	static FTSENT*	ne;

	if ((oe = _ast_fts_read(fts)) && ast.version < 20100102L && (ne || (ne = newof(0, FTSENT, 1, 0))))
	{
		*ne = *oe;
		oe = ne;
		ne->fts_namelen = ne->_fts_namelen;
		ne->fts_pathlen = ne->_fts_pathlen;
		ne->fts_level = ne->_fts_level;
	}
	return oe;
}
