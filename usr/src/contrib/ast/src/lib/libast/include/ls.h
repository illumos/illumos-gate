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
 * AT&T Research
 *
 * ls formatter interface definitions
 */

#ifndef _LS_H
#define _LS_H

#include <ast_std.h>
#include <ast_fs.h>
#include <ast_mode.h>

/*
 * some systems (could it beee AIX) pollute the std name space
 */

#undef	fileid
#define fileid	fileID

#define LS_BLOCKSIZE	512

#define iblocks(p)	_iblocks(p)

#if _mem_st_rdev_stat
#define idevice(p)	((p)->st_rdev)
#define IDEVICE(p,v)	((p)->st_rdev=(v))
#else
#define idevice(p)	0
#define IDEVICE(p,v)
#endif

#define LS_ATIME	(1<<0)		/* list st_atime		*/
#define LS_BLOCKS	(1<<1)		/* list blocks used by file	*/
#define LS_CTIME	(1<<2)		/* list st_ctime		*/
#define LS_EXTERNAL	(1<<3)		/* st_mode is modex canonical	*/
#define LS_INUMBER	(1<<4)		/* list st_ino			*/
#define LS_LONG		(1<<5)		/* long listing			*/
#define LS_MARK		(1<<6)		/* append file name marks	*/
#define LS_NOGROUP	(1<<7)		/* omit group name for LS_LONG	*/
#define LS_NOUSER	(1<<8)		/* omit user name for LS_LONG	*/
#define LS_NUMBER	(1<<9)		/* number instead of name	*/

#define LS_USER		(1<<10)		/* first user flag bit		*/

#define LS_W_BLOCKS	6		/* LS_BLOCKS field width	*/
#define LS_W_INUMBER	9		/* LS_INUMBER field width	*/
#define LS_W_LONG	57		/* LS_LONG width (w/o names)	*/
#define LS_W_LINK	4		/* link text width (w/o names)	*/
#define LS_W_MARK	1		/* LS_MARK field width		*/
#define LS_W_NAME	9		/* group|user name field width	*/

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern off_t		_iblocks(struct stat*);
extern char*		fmtdev(struct stat*);
extern char*		fmtfs(struct stat*);
extern char*		fmtls(char*, const char*, struct stat*, const char*, const char*, int);
extern int		pathstat(const char*, struct stat*);

#undef	extern

#endif
