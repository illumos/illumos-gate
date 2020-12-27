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
 * standalone mini ast+sfio interface
 */

#ifndef _AST_H
#define _AST_H		1

#include <ast_sa.h>
#include <ast_common.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define FMT_EXP_CHAR	0x020		/* expand single byte chars	*/
#define FMT_EXP_LINE	0x040		/* expand \n and \r		*/
#define FMT_EXP_WIDE	0x080		/* expand \u \U \x wide chars	*/
#define FMT_EXP_NOCR	0x100		/* skip \r			*/
#define FMT_EXP_NONL	0x200		/* skip \n			*/

#define STR_MAXIMAL	01		/* maximal match		*/
#define STR_LEFT	02		/* implicit left anchor		*/
#define STR_RIGHT	04		/* implicit right anchor	*/
#define STR_ICASE	010		/* ignore case			*/
#define STR_GROUP	020		/* (|&) inside [@|&](...) only	*/

typedef int (*Error_f)(void*, void*, int, ...);

typedef struct
{

	char*		id;

	struct
	{
	unsigned int	serial;
	unsigned int	set;
	}		locale;

	long		tmp_long;
	size_t		tmp_size;
	short		tmp_short;
	char		tmp_char;
	wchar_t		tmp_wchar;

	int		(*collate)(const char*, const char*);

	int		tmp_int;
	void*		tmp_pointer;

	int		mb_cur_max;
	int		(*mb_len)(const char*, size_t);
	int		(*mb_towc)(wchar_t*, const char*, size_t);
	size_t		(*mb_xfrm)(char*, const char*, size_t);
	int		(*mb_width)(wchar_t);
	int		(*mb_conv)(char*, wchar_t);

	unsigned int	env_serial;

	char		pad[944];

} _Ast_info_t;

#define ast		_ast_info_

#define elementsof(x)	(sizeof(x)/sizeof(x[0]))
#define integralof(x)	(((char*)(x))-((char*)0))
#define newof(p,t,n,x)	((p)?(t*)realloc((char*)(p),sizeof(t)*(n)+(x)):(t*)calloc(1,sizeof(t)*(n)+(x)))
#define oldof(p,t,n,x)	((p)?(t*)realloc((char*)(p),sizeof(t)*(n)+(x)):(t*)malloc(sizeof(t)*(n)+(x)))
#define pointerof(x)	((void*)((char*)0+(x)))
#define roundof(x,y)	(((x)+(y)-1)&~((y)-1))

#ifndef offsetof
#define offsetof(type,member) ((unsigned long)&(((type*)0)->member))
#endif

#if defined(__STDC__) || defined(__cplusplus) || defined(c_plusplus)
#define NiL			0
#define NoP(x)			(void)(x)
#else
#define NiL			((char*)0)
#define NoP(x)			(&x,1)
#endif

#define conformance(a,b)	"ast"
#define fmtident(s)		((char*)(s)+10)
#define mbchar(s)		(*s++)
#define setlocale(a,b)

#define streq(a,b)		(*(a)==*(b)&&!strcmp(a,b))
#define strneq(a,b,n)		(*(a)==*(b)&&!strncmp(a,b,n))
#define strton(s,t,b,f)		strtol(s,t,0)
#define strtonll(s,t,b,f)	strtoll(s,t,0)

#define Sfio_t		FILE

#define sfstdin		stdin
#define sfstdout	stdout
#define sfstderr	stderr

#define sfclose(f)	fclose(f)
#define sffileno(f)	fileno(f)
#define sfgetc(f)	fgetc(f)
#define sfopen(f,n,m)	fopen(n,m)
#define sfputc(f,c)	fputc(c,f)
#define sfread(f,b,n)	fread(b,n,1,f)
#define sfseek(f,p,w)	fseek(f,p,w)
#define sfset(f,v,n)
#define sfsync(f)	fflush(f)
#define sfwrite(f,b,n)	fwrite(b,n,1,f)

#define sfprintf	fprintf
#define sfsprintf	snprintf
#define sfvprintf	vfprintf

#define sfscanf		fscanf

#define sfgetr		_sf_getr

#include <sfstr.h>

extern _Ast_info_t	ast;

extern int		astwinsize(int, int*, int*);
extern int		chresc(const char*, char**);
extern char*		fmtbuf(size_t);
extern char*		fmtip4(uint32_t, int);
extern char*		sfgetr(Sfio_t*, int, int);
extern char*		strcopy(char*, const char*);
extern int		strmatch(const char*, const char*);
extern int		strtoip4(const char*, char**, uint32_t*, unsigned char*);

#endif
