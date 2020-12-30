/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
 * AT&T Bell Laboratories
 *
 * fmtmode() and strperm() readonly data
 * for external format modes
 */

#include "modelib.h"

struct modeop	modetab[MODELEN] =
{
	0170000, 12, 0000000, 0, "-pc?d?b?-Cl?sDw?",
	0000400,  8, 0000000, 0, "-r",
	0000200,  7, 0000000, 0, "-w",
	0004000, 10, 0000100, 6, "-xSs",
	0000040,  5, 0000000, 0, "-r",
	0000020,  4, 0000000, 0, "-w",
#ifdef S_ICCTYP
	0003000,  8, 0000010, 3, "-x-xSs-x",
#else
	0002000,  9, 0000010, 3, "-xls",
#endif
	0000004,  2, 0000000, 0, "-r",
	0000002,  1, 0000000, 0, "-w",
#ifdef S_ICCTYP
	0003000,  8, 0000001, 0, "-xyY-xeE",
#else
	0001000,  8, 0000001, 0, "-xTt",
#endif
};

int	permmap[PERMLEN] =
{
	S_ISUID, X_ISUID,
	S_ISGID, X_ISGID,
	S_ISVTX, X_ISVTX,
	S_IRUSR, X_IRUSR,
	S_IWUSR, X_IWUSR,
	S_IXUSR, X_IXUSR,
	S_IRGRP, X_IRGRP,
	S_IWGRP, X_IWGRP,
	S_IXGRP, X_IXGRP,
	S_IROTH, X_IROTH,
	S_IWOTH, X_IWOTH,
	S_IXOTH, X_IXOTH
};
