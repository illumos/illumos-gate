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
#pragma prototyped
#ifndef HIST_VERSION
/*
 *	Interface for history mechanism
 *	written by David Korn
 *
 */

#include	<ast.h>

#define HIST_CHAR	'!'
#define HIST_VERSION	1		/* history file format version no. */

typedef struct 
{
	Sfdisc_t	histdisc;	/* discipline for history */
	Sfio_t		*histfp;	/* history file stream pointer */
	char		*histname;	/* name of history file */
	int32_t		histind;	/* current command number index */
	int		histsize;	/* number of accessible history lines */
#ifdef _HIST_PRIVATE
	_HIST_PRIVATE
#endif /* _HIST_PRIVATE */
} History_t;

typedef struct
{
	int hist_command;
	int hist_line;
	int hist_char;
} Histloc_t;

/* the following are readonly */
extern const char	hist_fname[];

extern int _Hist;
#define	hist_min(hp)	((_Hist=((int)((hp)->histind-(hp)->histsize)))>=0?_Hist:0)
#define	hist_max(hp)	((int)((hp)->histind))
/* these are the history interface routines */
extern int		sh_histinit(void *);
extern void 		hist_cancel(History_t*);
extern void 		hist_close(History_t*);
extern int		hist_copy(char*, int, int, int);
extern void 		hist_eof(History_t*);
extern Histloc_t	hist_find(History_t*,char*,int, int, int);
extern void 		hist_flush(History_t*);
extern void 		hist_list(History_t*,Sfio_t*, off_t, int, char*);
extern int		hist_match(History_t*,off_t, char*, int*);
extern off_t		hist_tell(History_t*,int);
extern off_t		hist_seek(History_t*,int);
extern char 		*hist_word(char*, int, int);
#if SHOPT_ESH
    extern Histloc_t	hist_locate(History_t*,int, int, int);
#endif	/* SHOPT_ESH */

#endif /* HIST_VERSION */
