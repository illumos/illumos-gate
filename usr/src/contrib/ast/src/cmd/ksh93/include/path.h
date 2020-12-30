/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
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
#pragma prototyped
#ifndef PATH_OFFSET

/*
 *	UNIX shell path handling interface
 *	Written by David Korn
 *	These are the definitions for the lexical analyzer
 */

#include	"FEATURE/options"
#include	<nval.h>
#include	"defs.h"

#if !defined(SHOPT_SPAWN)
#   if _UWIN || _use_spawnveg || !_lib_fork
#	define  SHOPT_SPAWN  1
#   endif
#endif /* !SHOPT_SPAWN */

#define PATH_PATH		0001
#define PATH_FPATH		0002
#define PATH_CDPATH		0004
#define PATH_BFPATH		0010
#define PATH_SKIP		0020
#define PATH_BUILTIN_LIB	0040
#define PATH_STD_DIR		0100	/* directory is on  $(getconf PATH) */

#define PATH_OFFSET	2		/* path offset for path_join */
#define MAXDEPTH	(sizeof(char*)==2?64:1024) /* maximum recursion depth*/

/*
 * path component structure for path searching
 */
typedef struct pathcomp
{
	struct pathcomp *next;
	int		refcount;
	dev_t		dev;
	ino_t		ino;
	time_t		mtime;
	char		*name;
	char		*lib;
	char		*bbuf;
	char		*blib;
	unsigned short	len;
	unsigned short	flags;
	Shell_t		*shp;
} Pathcomp_t;

#ifndef ARG_RAW
    struct argnod;
#endif /* !ARG_RAW */

/* pathname handling routines */
extern void		path_newdir(Shell_t*,Pathcomp_t*);
extern Pathcomp_t	*path_dirfind(Pathcomp_t*,const char*,int);
extern Pathcomp_t	*path_unsetfpath(Shell_t*);
extern Pathcomp_t	*path_addpath(Shell_t*,Pathcomp_t*,const char*,int);
extern Pathcomp_t	*path_dup(Pathcomp_t*);
extern void		path_delete(Pathcomp_t*);
extern void 		path_alias(Namval_t*,Pathcomp_t*);
extern Pathcomp_t 	*path_absolute(Shell_t*, const char*, Pathcomp_t*);
extern char 		*path_basename(const char*);
extern char 		*path_fullname(Shell_t*,const char*);
extern int 		path_expand(Shell_t*,const char*, struct argnod**);
extern void 		path_exec(Shell_t*,const char*,char*[],struct argnod*);
extern pid_t		path_spawn(Shell_t*,const char*,char*[],char*[],Pathcomp_t*,int);
#if defined(__EXPORT__) && defined(_BLD_DLL) && defined(_BLD_shell)
#   define extern __EXPORT__
#endif
extern int		path_open(Shell_t*,const char*,Pathcomp_t*);
extern Pathcomp_t 	*path_get(Shell_t*,const char*);
#undef extern
extern char 		*path_pwd(Shell_t*,int);
extern Pathcomp_t	*path_nextcomp(Shell_t*,Pathcomp_t*,const char*,Pathcomp_t*);
extern int		path_search(Shell_t*,const char*,Pathcomp_t**,int);
extern char		*path_relative(Shell_t*,const char*);
extern int		path_complete(Shell_t*,const char*, const char*,struct argnod**);
#if SHOPT_BRACEPAT
    extern int 		path_generate(Shell_t*,struct argnod*,struct argnod**);
#endif /* SHOPT_BRACEPAT */
    extern int		path_xattr(Shell_t*, const char*, char*);

/* builtin/plugin routines */
extern int		sh_addlib(Shell_t*,void*,char*,Pathcomp_t*);
extern Shbltin_f	sh_getlib(Shell_t*,char*,Pathcomp_t*);

/* constant strings needed for whence */
extern const char e_timeformat[];
extern const char e_badtformat[];
extern const char e_dot[];
extern const char e_funload[];
extern const char e_pfsh[];
extern const char e_pwd[];
extern const char e_logout[];
extern const char e_alphanum[];
extern const char e_mailmsg[];
extern const char e_suidprofile[];
extern const char e_sysprofile[];
extern const char e_traceprompt[];
extern const char e_crondir[];
#if SHOPT_SUID_EXEC
    extern const char	e_suidexec[];
#endif /* SHOPT_SUID_EXEC */
extern const char is_alias[];
extern const char is_builtin[];
extern const char is_spcbuiltin[];
extern const char is_builtver[];
extern const char is_reserved[];
extern const char is_talias[];
extern const char is_xalias[];
extern const char is_function[];
extern const char is_ufunction[];
#ifdef SHELLMAGIC
    extern const char e_prohibited[];
#endif /* SHELLMAGIC */

#if SHOPT_ACCT
#   include	"FEATURE/acct"
#   ifdef	_sys_acct
	extern void sh_accinit(void);
	extern void sh_accbegin(const char*);
	extern void sh_accend(void);
	extern void sh_accsusp(void);
#   else
#	undef	SHOPT_ACCT
#   endif	/* _sys_acct */
#endif /* SHOPT_ACCT */

#endif /*! PATH_OFFSET */
