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
#ifndef NOTSYM
/*
 *	UNIX shell
 *	Written by David Korn
 *	These are the definitions for the lexical analyzer
 */

#include	<cdt.h>
#include	"FEATURE/options"
#include	"shnodes.h"
#include	"shtable.h"
#include	"lexstates.h"


typedef struct  _shlex_
{
	Shell_t		*sh;		/* pointer to the interpreter */
	struct argnod	*arg;		/* current word */
	struct ionod	*heredoc;	/* pending here document list */
	int		token;		/* current token number */
	int		lastline;	/* last line number */
	int		lasttok;	/* previous token number */
	int		digits;		/* numerical value with word token */
	int		nonstandard;	/* nonstandard construct in profile */
	char		aliasok;	/* on when alias is legal */
	char		assignok;	/* on when name=value is legal */
	char		inexec;		/* on when processing exec */
	char		intypeset;	/* on when processing typeset */
	char		comp_assign;	/* in compound assignment */
	char		comsub;		/* parsing command substitution */
	char		noreserv;	/* reserved works not legal */
	int		inlineno;	/* saved value of sh.inlineno */
	int		firstline;	/* saved value of sh.st.firstline */
#if SHOPT_KIA
	Sfio_t		*kiafile;	/* kia output file */
	Sfio_t		*kiatmp;	/* kia reference file */
	unsigned long	script;		/* script entity number */
	unsigned long	fscript;	/* script file entity number */
	unsigned long	current;	/* current entity number */
	unsigned long	unknown;	/* <unknown> entity number */
	off_t		kiabegin;	/* offset of first entry */
	char		*scriptname;	/* name of script file */
	Dt_t		*entity_tree;	/* for entity ids */
#endif /* SHOPT_KIA */
#ifdef  _SHLEX_PRIVATE
	_SHLEX_PRIVATE
#endif
} Lex_t;

/* symbols for parsing */
#define NL		'\n'
#define NOTSYM		'!'
#define SYMRES		0400		/* reserved word symbols */
#define DOSYM		(SYMRES|01)
#define FISYM		(SYMRES|02)
#define ELIFSYM		(SYMRES|03)
#define ELSESYM		(SYMRES|04)
#define INSYM		(SYMRES|05)
#define THENSYM		(SYMRES|06)
#define DONESYM		(SYMRES|07)
#define ESACSYM		(SYMRES|010)
#define IFSYM		(SYMRES|011)
#define FORSYM		(SYMRES|012)
#define WHILESYM	(SYMRES|013)
#define UNTILSYM	(SYMRES|014)
#define CASESYM		(SYMRES|015)
#define FUNCTSYM	(SYMRES|016)
#define SELECTSYM	(SYMRES|017)
#define TIMESYM		(SYMRES|020)
#define NSPACESYM	(SYMRES|021)

#define SYMREP		01000		/* symbols for doubled characters */
#define BREAKCASESYM	(SYMREP|';')
#define ANDFSYM		(SYMREP|'&')
#define ORFSYM		(SYMREP|'|')
#define IOAPPSYM	(SYMREP|'>')
#define IODOCSYM	(SYMREP|'<')
#define EXPRSYM		(SYMREP|'(')
#define BTESTSYM 	(SYMREP|'[')
#define ETESTSYM	(SYMREP|']')

#define SYMMASK		0170000
#define SYMPIPE		010000	/* trailing '|' */
#define SYMLPAR		020000	/* trailing LPAREN */
#define SYMAMP		040000	/* trailing '&' */
#define SYMGT		0100000	/* trailing '>' */
#define SYMSEMI		0110000	/* trailing ';' */
#define SYMSHARP	0120000	/* trailing '#' */
#define IOSEEKSYM	(SYMSHARP|'<')
#define IOMOV0SYM	(SYMAMP|'<')
#define IOMOV1SYM	(SYMAMP|'>')
#define FALLTHRUSYM	(SYMAMP|';')
#define COOPSYM		(SYMAMP|'|')
#define IORDWRSYM	(SYMGT|'<')
#define IORDWRSYMT	(SYMSEMI|'<')
#define IOCLOBSYM	(SYMPIPE|'>')
#define PIPESYM2	(SYMPIPE|'&')
#define IPROCSYM	(SYMLPAR|'<')
#define OPROCSYM	(SYMLPAR|'>')
#define EOFSYM		04000	/* end-of-file */
#define TESTUNOP	04001
#define TESTBINOP	04002
#define LABLSYM		04003
#define IOVNAME		04004

/* additional parser flag, others in <shell.h> */
#define SH_EMPTY	04
#define SH_NOIO		010
#define	SH_ASSIGN	020
#define	SH_FUNDEF	040
#define SH_ARRAY	0100
#define SH_SEMI		0200	/* semi-colon after NL ok */

#define SH_COMPASSIGN	010	/* allow compound assignments only */

#if 0
typedef struct  _shlex_
{
	struct shlex_t		_shlex;
#ifdef  _SHLEX_PRIVATE
	_SHLEX_PRIVATE
#endif
} Lex_t;

#define	shlex			(((Lex_t*)(sh.lex_context))->_shlex)
#endif
extern const char		e_unexpected[];
extern const char		e_unmatched[];
extern const char		e_endoffile[];
extern const char		e_newline[];

/* odd chars */
#define LBRACE	'{'
#define RBRACE	'}'
#define LPAREN	'('
#define RPAREN	')'
#define LBRACT	'['
#define RBRACT	']'

extern int		sh_lex(Lex_t*);
extern Shnode_t		*sh_dolparen(Lex_t*);
extern Lex_t		*sh_lexopen(Lex_t*, Shell_t*, int);
extern void 		sh_lexskip(Lex_t*,int,int,int);
extern void 		sh_syntax(Lex_t*);
#if SHOPT_KIA
    extern int                  kiaclose(Lex_t *);
    extern unsigned long        kiaentity(Lex_t*, const char*,int,int,int,int,unsigned long,int,int,const char*);
#endif /* SHOPT_KIA */


#endif /* !NOTSYM */
