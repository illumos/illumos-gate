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
/*
 *	UNIX shell
 *	David Korn
 *
 */
/*
 * Copyright (c) 2007, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#include	<ast.h>
#include	<sfio.h>

#ifndef IOBSIZE
#   define  IOBSIZE	(SF_BUFSIZE*sizeof(char*))
#endif /* IOBSIZE */
#define IOMAXTRY	20

#ifndef SF_CLOSING
#define SF_CLOSING	SF_CLOSE
#endif
#ifndef SF_APPENDWR
#define SF_APPENDWR	SF_APPEND
#endif

/* used for output of shell errors */
#define ERRIO		2

#define IOREAD		001
#define IOWRITE		002
#define IODUP 		004
#define IOSEEK		010
#define IONOSEEK	020
#define IOTTY 		040
#define IOCLEX 		0100
#define IOCLOSE		(IOSEEK|IONOSEEK)

#define IOSUBSHELL	0x8000	/* must be larger than any file descriptor */
#define IOPICKFD	0x10000 /* file descriptor number was selected automatically */
#define IOHERESTRING	0x20000 /* allow here documents to be string streams */

/*
 * The remainder of this file is only used when compiled with shell
 */

#if KSHELL

#ifndef ARG_RAW
    struct ionod;
#endif /* !ARG_RAW */

extern int	sh_iocheckfd(Shell_t*,int);
extern void 	sh_ioinit(Shell_t*);
extern int 	sh_iomovefd(int);
extern int	sh_iorenumber(Shell_t*,int,int);
extern void 	sh_pclose(int[]);
extern int	sh_rpipe(int[]);
extern void 	sh_iorestore(Shell_t*,int,int);
#if defined(__EXPORT__) && defined(_BLD_DLL) && defined(_BLD_shell) 
   __EXPORT__
#endif
extern Sfio_t 	*sh_iostream(Shell_t*,int);
extern int	sh_redirect(Shell_t*,struct ionod*,int);
extern void 	sh_iosave(Shell_t *, int,int,char*);
extern int	sh_get_unused_fd(Shell_t* shp, int min_fd);
extern int 	sh_iovalidfd(Shell_t*, int);
extern int 	sh_inuse(Shell_t*, int);
extern void 	sh_iounsave(Shell_t*);
extern int	sh_chkopen(const char*);
extern int	sh_ioaccess(int,int);
extern int	sh_devtofd(const char*);
extern int	sh_isdevfd(const char*);
extern int	sh_source(Shell_t*, Sfio_t*, const char*);

extern int	VALIDATE_FD(Shell_t *, int);

#define	VALIDATE_FD(shp, fd) \
	(((fd) >= (shp)->gd->lim.open_max) ? sh_iovalidfd(shp, fd) : 1)


/* the following are readonly */
extern const char	e_pexists[];
extern const char	e_query[];
extern const char	e_history[];
extern const char	e_argtype[];
extern const char	e_create[];
extern const char	e_tmpcreate[];
extern const char	e_exists[];
extern const char	e_file[];
extern const char	e_redirect[];
extern const char	e_formspec[];
extern const char	e_badregexp[];
extern const char	e_open[];
extern const char	e_notseek[];
extern const char	e_noread[];
extern const char	e_badseek[];
extern const char	e_badwrite[];
extern const char	e_badpattern[];
extern const char	e_toomany[];
extern const char	e_pipe[];
extern const char	e_unknown[];
extern const char	e_devnull[];
extern const char	e_profile[];
extern const char	e_sysprofile[];
#if SHOPT_SYSRC
extern const char	e_sysrc[];
#endif
#if SHOPT_BASH
#if SHOPT_SYSRC
extern const char	e_bash_sysrc[];
#endif
extern const char	e_bash_rc[];
extern const char	e_bash_login[];
extern const char	e_bash_logout[];
extern const char	e_bash_profile[];
#endif
extern const char	e_stdprompt[];
extern const char	e_supprompt[];
extern const char	e_ambiguous[];

#endif /* KSHELL */
