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
 * posix glob interface definitions with gnu extensions
 */

#ifndef _GLOB_H
#define _GLOB_H

#define GLOB_VERSION	20060717L

#include <stdlib.h>

struct dirent;
struct stat;

struct _glob_;
struct _globlist_;

typedef struct _glob_ glob_t;
typedef struct _globlist_ globlist_t;

struct _globlist_
{
	globlist_t*	gl_next;
	char*		gl_begin;
	unsigned char	gl_flags;
	char		gl_path[1];
};

struct _glob_
{
	size_t		gl_pathc;
	char**		gl_pathv;
	size_t		gl_offs;
	globlist_t*	gl_list;
	int		gl_flags;

	/* GLOB_DISC data -- memset(&gl,0,sizeof(gl)) before using! */

	const char*	gl_fignore;
	const char*	gl_suffix;
	unsigned char*	gl_intr;

	int		gl_delim;

	void*		gl_handle;
	void*		(*gl_diropen)(glob_t*, const char*);
	char*		(*gl_dirnext)(glob_t*, void*);
	void		(*gl_dirclose)(glob_t*, void*);
	int		(*gl_type)(glob_t*, const char*, int);
	int		(*gl_attr)(glob_t*, const char*, int);

	/* gnu extensions -- but how do you synthesize dirent and stat? */

	void*		(*gl_opendir)(const char*);
	struct dirent*	(*gl_readdir)(void*);
	void		(*gl_closedir)(void*);
	int		(*gl_stat)(const char*, struct stat*);
	int		(*gl_lstat)(const char*, struct stat*);

	/* ast additions */

	char*		(*gl_nextdir)(glob_t*, char*);
	unsigned long	gl_status;
	unsigned long	gl_version;
	unsigned short	gl_extra;

#ifdef _GLOB_PRIVATE_
	_GLOB_PRIVATE_
#else
	char*		gl_pad[23];
#endif

};

/* standard interface */
#define GLOB_APPEND	0x0001		/* append to previous		*/
#define GLOB_DOOFFS	0x0002		/* gl_offs defines argv offset	*/
#define GLOB_ERR	0x0004		/* abort on error		*/
#define GLOB_MARK	0x0008		/* append / to directories	*/
#define GLOB_NOCHECK	0x0010		/* nomatch is original pattern	*/
#define GLOB_NOESCAPE	0x0020		/* don't treat \ specially	*/
#define GLOB_NOSORT	0x0040		/* don't sort the list		*/

/* extended interface */
#define GLOB_STARSTAR	0x0080		/* enable [/]**[/] expansion	*/
#define GLOB_BRACE	0x0100		/* enable {...} expansion	*/
#define GLOB_ICASE	0x0200		/* ignore case on match		*/
#define GLOB_COMPLETE	0x0400		/* shell file completeion	*/
#define GLOB_AUGMENTED	0x0800		/* augmented shell patterns	*/
#define GLOB_STACK	0x1000		/* allocate on current stack	*/
#define GLOB_LIST	0x2000		/* just create gl_list		*/
#define GLOB_ALTDIRFUNC	0x4000		/* gnu discipline functions	*/
#define GLOB_DISC	0x8000		/* discipline initialized	*/

#define GLOB_GROUP	0x10000		/* REG_SHELL_GROUP		*/

/* gl_status */
#define GLOB_NOTDIR	0x0001		/* last gl_dirnext() not a dir	*/

/* gl_type return */
#define GLOB_NOTFOUND	0		/* does not exist		*/
#define GLOB_DEV	1		/* exists but not DIR EXE REG	*/
#define GLOB_DIR	2		/* directory			*/
#define GLOB_EXE	3		/* executable regular file	*/
#define GLOB_REG	4		/* regular file			*/

/* error return values */
#define GLOB_ABORTED	1
#define GLOB_NOMATCH	2
#define GLOB_NOSPACE	3
#define GLOB_INTR	4
#define GLOB_APPERR	5
#define GLOB_NOSYS	6

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int	glob(const char*, int, int(*)(const char*,int), glob_t*);
extern void	globfree(glob_t*);

#undef	extern

#endif /* _GLOB_H */
