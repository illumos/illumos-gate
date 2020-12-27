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
#ifndef ARG_RAW
/*
 *	struct to hold a word argument
 *	Written by David Korn
 *
 */

#include	<stak.h>

struct ionod
{
	unsigned	iofile;
	char		*ioname;
	struct ionod	*ionxt;
	struct ionod	*iolst;
	char		*iodelim;
	off_t		iooffset;
	long		iosize;
	char		*iovname;
};

struct comnod
{
	int		comtyp;
	struct ionod	*comio;
	struct argnod	*comarg;
	struct argnod	*comset;
	void		*comnamp;
	void		*comnamq;
	void		*comstate;
	int		comline;
};

#define COMBITS		4
#define COMMSK		((1<<COMBITS)-1)
#define COMSCAN		(01<<COMBITS)
#define COMFIXED	(02<<COMBITS)

struct slnod 	/* struct for link list of stacks */
{
	struct slnod	*slnext;
	struct slnod	*slchild;
	Stak_t		*slptr;
	/* slpad aligns struct functnod = struct slnod + 1 on some architectures */
	struct slnod	*slpad;	
};

/*
 * This struct is use to hold $* lists and arrays
 */

struct dolnod
{
	int		dolrefcnt;	/* reference count */
	int		dolmax;		/* size of dolval array */
	int		dolnum;		/* number of elements */
	int		dolbot;		/* current first element */
	struct dolnod	*dolnxt;	/* used when list are chained */
	char		*dolval[1];	/* array of value pointers */
};

/*
 * This struct is used to hold word arguments of variable size during
 * parsing and during expansion.  The flags indicate what processing
 * is required on the argument.
 */

struct argnod
{
	union
	{
		struct argnod	*ap;
		char		*cp;
	}		argnxt;
	union
	{
		struct argnod	*ap;
		char		*cp;
		int		len;
	}		argchn;
	unsigned char	argflag;
	char		argval[4];
};



/* The following should evaluate to the offset of argval in argnod */
#define ARGVAL		offsetof(struct argnod,argval[0])
#define sh_argstr(ap)	((ap)->argflag&ARG_RAW?sh_fmtq((ap)->argval):(ap)->argval)
#define ARG_SPARE 1


/* legal argument flags */
#define ARG_RAW		0x1	/* string needs no processing */
#define ARG_MAKE	0x2	/* bit set during argument expansion */
#define ARG_COMSUB	0x2	/* command sub */
#define ARG_MAC		0x4	/* string needs macro expansion */
#define	ARG_EXP		0x8	/* string needs file expansion */
#define ARG_ASSIGN	0x10	/* argument is an assignment */
#define ARG_QUOTED	0x20	/* word contained quote characters */
#define ARG_MESSAGE	0x40	/* contains international string */
#define ARG_APPEND	0x80	/* for += assignment */
/*  The following can be passed as options to sh_macexpand() */
#define ARG_ARITH	0x100	/* arithmetic expansion */
#define ARG_OPTIMIZE	0x200	/* try to optimize */
#define ARG_NOGLOB	0x400	/* no file name expansion */
#define ARG_LET		0x800	/* processing let command arguments */
#define ARG_ARRAYOK	0x1000	/* $x[sub] ==> ${x[sub]} */

extern struct dolnod	*sh_argcreate(char*[]);
extern char 		*sh_argdolminus(void*);
extern int		sh_argopts(int,char*[],void*);


extern const char	e_heading[];
extern const char	e_off[];
extern const char	e_on[];
extern const char	e_sptbnl[];
extern const char	e_subst[];
extern const char	e_option[];
extern const char	e_exec[];
extern const char	e_devfdNN[];
extern const char	e_devfdstd[];

#endif /* ARG_RAW */
