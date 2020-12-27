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
 * AT&T Research
 *
 * common dirent maintenance interface
 */

#ifndef _AST_DIR_H
#define _AST_DIR_H

#include <ast_lib.h>

#if _mem_d_fileno_dirent || _mem_d_ino_dirent
#if !_mem_d_fileno_dirent
#undef	_mem_d_fileno_dirent
#define _mem_d_fileno_dirent	1
#define d_fileno		d_ino
#endif
#endif

#if _BLD_ast
#include "dirlib.h"
#else
#include <dirent.h>
#endif

#if _mem_d_fileno_dirent
#define D_FILENO(d)		((d)->d_fileno)
#endif

#if _mem_d_namlen_dirent
#define D_NAMLEN(d)		((d)->d_namlen)
#else
#define D_NAMLEN(d)		(strlen((d)->d_name))
#endif

#if _mem_d_reclen_dirent
#define D_RECLEN(d)		((d)->d_reclen)
#else
#define D_RECLEN(d)		D_RECSIZ(d,D_NAMLEN(d))
#endif

#define D_RECSIZ(d,n)		(sizeof(*(d))-sizeof((d)->d_name)+((n)+sizeof(char*))&~(sizeof(char*)-1))

/*
 * NOTE: 2003-03-27 mac osx bug symlink==DT_REG bug discovered;
 *	 the kernel *and* all directories must be fixed, so d_type
 *	 is summarily disabled until we see that happen
 */

#if _mem_d_type_dirent && defined(DT_UNKNOWN) && defined(DT_REG) && defined(DT_DIR) && defined(DT_LNK) && ! ( __APPLE__ || __MACH__ )
#define D_TYPE(d)		((d)->d_type)
#endif

#endif
