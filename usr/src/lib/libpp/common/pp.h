/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * preprocessor library public definitions
 */

#ifndef _PP_H
#define _PP_H

#ifdef ppsymbol
/*
 * undo old nmake cpp name-space intrusion
 * this disables __LINE__, __FILE__, __DATE__ and __TIME__
 */
#undef	ppsymbol
#undef	__LINE__
#define __LINE__	0
#undef	__FILE__
#define __FILE__	"libpp"
#undef	__DATE__
#define __DATE__	"MMM DD YYYY"
#undef	__TIME__
#define __TIME__	"HH:MM:SS"
#endif


#if PROTOMAIN
#define HASH_HEADER	int	hash_header
#define Hash_table_t	char
#define Sfio_t		char
#define CC_bel		(('A'==0301)?0057:0007)
#define CC_esc		(('A'==0301)?0047:0033)
#define CC_vt		0013
#else
#include <limits.h>
#include <hash.h>
#include <error.h>
#include <ccode.h>
#endif

#define PPDEFAULT	"pp_default.h"		/* runtime definitions	*/
#define PPPROBE		"cc"			/* default probe key	*/
#define PPSTANDARD	"/usr/include"		/* standard include dir	*/

#define PPBLKSIZ	1024			/* unit block size	*/
#define PPBAKSIZ	(1*PPBLKSIZ)		/* input pushback size	*/
#define PPBUFSIZ	(32*PPBLKSIZ)		/* io buffer size	*/
#define PPTOKSIZ	((PPBUFSIZ/2)-1)	/* max token size	*/

#define PPWRITE(n)	do{if(write(1,pp.outbuf,n)!=(n))pperror(ERROR_SYSTEM|3,"%s: write error",pp.outfile);pp.offset+=(n);pp.lastout=pp.outbuf[(n)-1];}while(0)

#define pplastout()	((pp.outp>pp.outbuf)?*(pp.outp-1):pp.lastout)
#define ppoffset()	(pp.offset+pppendout())
#define pppendout()	(pp.outp-pp.outbuf)
#define ppputchar(c)	(*pp.outp++=(c))
#define ppflushout()	do{if(pp.outp>pp.outbuf){PPWRITE(pp.outp-pp.outbuf);pp.outp=pp.outbuf;}}while(0)
#define ppcheckout()	do{if(pp.outp>pp.oute){PPWRITE(PPBUFSIZ);if(pp.outbuf==pp.outb){pp.outbuf+=PPBUFSIZ;pp.oute+=PPBUFSIZ;}else{pp.outbuf-=PPBUFSIZ;memcpy(pp.outbuf,pp.oute,pp.outp-pp.oute);pp.oute-=PPBUFSIZ;pp.outp-=2*PPBUFSIZ;}}}while(0)

#define ppsymget(t,n)	(struct ppsymbol*)hashlook(t,n,HASH_LOOKUP,NiL)
#define ppsymref(t,n)	(struct ppsymbol*)hashlook(t,n,pp.truncate?HASH_LOOKUP:HASH_LOOKUP|HASH_INTERNAL,NiL)
#define ppsymset(t,n)	(struct ppsymbol*)hashlook(t,n,HASH_CREATE|HASH_SIZE(sizeof(struct ppsymbol)),NiL)

#if CHAR_MIN < 0
#define pptype		(ppctype-(CHAR_MIN)+1)
#else
#define pptype		(ppctype)
#endif

#define C_ID		(1<<0)
#define C_DIG		(1<<1)
#define C_SPLICE	(1<<2)

#define ppisdig(c)	((pptype)[c]&C_DIG)
#define ppisid(c)	((pptype)[c]&C_ID)
#define ppisidig(c)	((pptype)[c]&(C_ID|C_DIG))
#define ppismac(c)	((pptype)[c]&(C_ID|C_DIG|C_SPLICE))
#define ppissplice(c)	((pptype)[c]&C_SPLICE)

#define setid(c)	((pptype)[c]|=C_ID)
#define clrid(c)	((pptype)[c]&=~C_ID)
#define setdig(c)	((pptype)[c]|=C_DIG)
#define setsplice(c)	((pptype)[c]|=C_SPLICE)

#define REF_CREATE	(REF_NORMAL+1)	/* include wrapper (internal)	*/
#define REF_DELETE	(REF_NORMAL+2)	/* macro definition (internal)	*/
#define REF_NORMAL	0		/* normal macro reference	*/
#define REF_IF		(-1)		/* if, ifdef, ifndef, elif	*/
#define REF_UNDEF	(-2)		/* undef			*/

#define SYM_ACTIVE	(1L<<0)		/* active macro lock		*/
#define SYM_BUILTIN	(1L<<1)		/* builtin macro		*/
#define SYM_DISABLED	(1L<<2)		/* macro expansion disabled	*/
#define SYM_EMPTY	(1L<<3)		/* allow empty/missing actuals	*/
#define SYM_FINAL	(1L<<4)		/* final hosted value		*/
#define SYM_FUNCTION	(1L<<5)		/* macro with args		*/
#define SYM_INIT	(1L<<6)		/* initialization macro		*/
#define SYM_INITIAL	(1L<<7)		/* initial hosted value		*/
#define SYM_KEYWORD	(1L<<8)		/* keyword identifier		*/
#define SYM_LEX		(1L<<9)		/* ppsymkey with lex field	*/
#define SYM_MULTILINE	(1L<<10)	/* multi-line macro		*/
#define SYM_NOEXPAND	(1L<<11)	/* no identifiers in macro body	*/
#define SYM_NOTICED	(1L<<12)	/* symbol noticed in output	*/
#define SYM_PREDEFINED	(1L<<13)	/* predefined macro		*/
#define SYM_PREDICATE	(1L<<14)	/* also a predicate		*/
#define SYM_READONLY	(1L<<15)	/* readonly macro		*/
#define SYM_REDEFINE	(1L<<16)	/* ok to redefine		*/
#define SYM_VARIADIC	(1L<<17)	/* variadic macro with args	*/
#define SYM_UNUSED	24		/* first unused symbol flag bit	*/

#define PP_ASSERT		1	/* preassert symbol		*/
#define PP_BUILTIN		2	/* #(<id>) handler		*/
#define PP_CDIR			3	/* C (vs. C++) file dirs follow	*/
#define PP_CHOP			4	/* include prefix chop		*/
#define PP_COMMENT		5	/* passed comment handler	*/
#define PP_COMPATIBILITY	6	/* old (Reiser) dialect		*/
#define PP_COMPILE		7	/* tokenize for front end	*/
#define PP_DEBUG		8	/* set debug trace level	*/
#define PP_DEFINE		9	/* predefine symbol		*/
#define PP_DEFAULT		10	/* read default include files	*/
#define PP_DIRECTIVE		11	/* initialization directive	*/
#define PP_DONE			12	/* all processing done		*/
#define PP_DUMP			13	/* do checkpoint dump		*/
#define PP_FILEDEPS		14	/* output file dependencies	*/
#define PP_FILENAME		15	/* set input file name		*/
#define PP_HOSTDIR		16	/* hosted file dirs follow	*/
#define PP_ID			17	/* add to identifier set	*/
#define PP_IGNORE		18	/* ignore this include file	*/
#define PP_IGNORELIST		19	/* include ignore list file	*/
#define PP_INCLUDE		20	/* add dir to include search	*/
#define PP_INCREF		21	/* include file push/ret handler*/
#define PP_INIT			22	/* one time initialization	*/
#define PP_INPUT		23	/* set input source file	*/
#define PP_KEYARGS		24	/* name=value macro args	*/
#define PP_LINE			25	/* line sync handler		*/
#define PP_LINEBASE		26	/* base name in line sync	*/
#define PP_LINEFILE		27	/* line sync requires file arg	*/
#define PP_LINEID		28	/* PP_LINE directive id		*/
#define PP_LINETYPE		29	/* # extra line sync type args	*/
#define PP_LOCAL		30	/* previous PP_INCLUDE for ""	*/
#define PP_MACREF		31	/* macro def/ref handler	*/
#define PP_MULTIPLE		32	/* set all files multiple	*/
#define PP_NOHASH		33	/* don't hash PP_COMPILE T_ID's	*/
#define PP_NOISE		34	/* convert T_X_* to T_NOISE	*/
#define PP_OPTION		35	/* set pragma option		*/
#define PP_OPTARG		36	/* unknown option arg handler	*/
#define PP_OUTPUT		37	/* set output file sink		*/
#define PP_PASSTHROUGH		38	/* ppcpp() expands # lines only	*/
#define PP_PEDANTIC		39	/* pedantic non-hosted warnings	*/
#define PP_PLUSCOMMENT		40	/* enable C++ comments		*/
#define PP_PLUSPLUS		41	/* tokenize for C++		*/
#define PP_POOL			42	/* pool for multiple io passes	*/
#define PP_PRAGMA		43	/* passed pragma handler	*/
#define PP_PRAGMAFLAGS		44	/* global pragma flags		*/
#define PP_PROBE		45	/* ppdefault probe key		*/
#define PP_QUOTE		46	/* add to quote set		*/
#define PP_READ			47	/* include file without output	*/
#define PP_REGUARD		48	/* file pop emits guard define	*/
#define PP_RESERVED		49	/* COMPILE reserved keyword	*/
#define PP_RESET		50	/* reset to initiali predefs	*/
#define PP_SPACEOUT		51	/* pplex returns space,newline	*/
#define PP_STANDALONE		52	/* standalone preprocessor	*/
#define PP_STANDARD		53	/* standard include dir		*/
#define PP_STRICT		54	/* strict implementation	*/
#define PP_TEST			55	/* enable (undocumented) tests	*/
#define PP_TEXT			56	/* include file with output	*/
#define PP_TRANSITION		57	/* on COMPATIBILITY boundary	*/
#define PP_TRUNCATE		58	/* truncate macro names		*/
#define PP_UNDEF		59	/* undef symbol after ppdefault	*/
#define PP_VENDOR		60	/* vendor file dirs follow	*/
#define PP_WARN			61	/* enable annoying warnings	*/

#define PP_comment		(1<<0)	/* PP_COMMENT is set		*/
#define PP_compatibility	(1<<1)	/* PP_COMPATIBILITY is set	*/
#define PP_hosted		(1<<2)	/* current file is hosted	*/
#define PP_linebase		(1<<3)	/* base name in line sync	*/
#define PP_linefile		(1<<4)	/* line sync file arg required	*/
#define PP_linehosted		(1<<5)	/* line sync hosted arg required*/
#define PP_lineignore		(1<<6)	/* line sync for ignored file	*/
#define PP_linetype		(1<<7)	/* line sync type arg required	*/
#define PP_strict		(1<<8)	/* PP_STRICT is set		*/
#define PP_transition		(1<<9)	/* PP_TRANSITION is set		*/

#define PP_deps			(1<<0)	/* generate header deps		*/
#define PP_deps_file		(1<<1)	/* write deps to separate file	*/
#define PP_deps_generated	(1<<2)	/* missing deps are generated	*/
#define PP_deps_local		(1<<3)	/* only local header deps	*/

#define PP_sync			0	/* normal line sync		*/
#define PP_sync_push		'1'	/* [3] include file push	*/
#define PP_sync_pop		'2'	/* [3] include file pop		*/
#define PP_sync_ignore		'3'	/* [3] ignored include file	*/
#define PP_sync_hosted		'3'	/* [4] hosted include file	*/

#define PP_SYNC_PUSH		(1<<0)	/* pp.incref PP_sync_push type	*/
#define PP_SYNC_POP		(1<<1)	/* pp.incref PP_sync_pop type	*/
#define PP_SYNC_IGNORE		(1<<2)	/* pp.incref PP_sync_ignore type*/
#define PP_SYNC_HOSTED		(1<<3)	/* pp.incref PP_sync_hosted type*/
#define PP_SYNC_INSERT		(1<<4)	/* pinserted by other means	*/

/*
 * numeric modifiers
 *
 * NOTE: 0400 is claimed by error in yacc
 * 	 (N_PP+30) is the largest valid pp token
 *	 free tokens start at T_TOKEN
 */

#define N_PP			0401		/* pp tokens 0401..0437	*/
#define N_NUMBER		0440		/* numbers 0440..0477	*/
#define N_TEST			(N_NUMBER|07700)/* number test mask	*/
#define N_TOKEN			0500		/* free 0500..07777	*/
#define N_WIDE			1		/* wide quoted constant	*/

/*
 * NOTE: preserve the token ranges and encodings for is*(x)
 */

#define ppisnumber(x)		(((x)&N_TEST)==N_NUMBER)
#define ppisinteger(x)		(((x)&(N_TEST|N_REAL))==N_NUMBER)
#define ppisreal(x)		(((x)&(N_TEST|N_REAL))==(N_NUMBER|N_REAL))
#define ppisassignop(x)		(((x)>=T_MPYEQ)&&((x)<=T_OREQ))
#define ppisseparate(x)		(((x)>=N_PP)&&((x)<=T_WSTRING)||((x)>=N_NUMBER)||((x)=='+')||((x)=='-'))

#define N_LONG			0001
#define N_UNSIGNED		0002		/* if ppisinteger(x)	*/
#define N_FLOAT			0002		/* if ppisreal(x)		*/

#define N_REAL			0004
#define N_OCTAL			0010
#define N_HEXADECIMAL		0020

#define N_EXPONENT		010000		/* for lexing only	*/
#define N_SIGN			020000		/* for lexing only	*/
#define N_TRAILING		040000		/* for lexing only	*/

#if !defined(T_DOUBLE)

/*
 * numeric constants
 */

#define T_DOUBLE		(N_NUMBER|N_REAL)
#define T_DOUBLE_L		(N_NUMBER|N_REAL|N_LONG)
#define T_FLOAT			(N_NUMBER|N_REAL|N_FLOAT)
#define T_DECIMAL		(N_NUMBER)
#define T_DECIMAL_L		(N_NUMBER|N_LONG)
#define T_DECIMAL_U		(N_NUMBER|N_UNSIGNED)
#define T_DECIMAL_UL		(N_NUMBER|N_UNSIGNED|N_LONG)
#define T_OCTAL			(N_NUMBER|N_OCTAL)
#define T_OCTAL_L		(N_NUMBER|N_OCTAL|N_LONG)
#define T_OCTAL_U		(N_NUMBER|N_OCTAL|N_UNSIGNED)
#define T_OCTAL_UL		(N_NUMBER|N_OCTAL|N_UNSIGNED|N_LONG)
#define T_HEXADECIMAL		(N_NUMBER|N_HEXADECIMAL)
#define T_HEXADECIMAL_L		(N_NUMBER|N_HEXADECIMAL|N_LONG)
#define T_HEXADECIMAL_U		(N_NUMBER|N_HEXADECIMAL|N_UNSIGNED)
#define T_HEXADECIMAL_UL	(N_NUMBER|N_HEXADECIMAL|N_UNSIGNED|N_LONG)
#define T_HEXDOUBLE		(N_NUMBER|N_HEXADECIMAL|N_REAL)
#define T_HEXDOUBLE_L		(N_NUMBER|N_HEXADECIMAL|N_REAL|N_LONG)

/*
 * identifier and invalid token
 */

#define T_ID			(N_PP+0)
#define T_INVALID		(N_PP+1)

/*
 * quoted constants
 */

#define T_HEADER		(N_PP+2)		/*	<..>	*/
#define T_CHARCONST		(N_PP+3)		/*	'..'	*/
#define T_WCHARCONST		(T_CHARCONST|N_WIDE)	/*	L'..'	*/
#define T_STRING		(N_PP+5)		/*	".."	*/
#define T_WSTRING		(T_STRING|N_WIDE)	/*	L".."	*/

/*
 * multichar operators
 */

#define T_PTRMEM		(N_PP+7)	/*	->	*/
#define T_ADDADD		(N_PP+8)	/*	++	*/
#define T_SUBSUB		(N_PP+9)	/*	--	*/
#define T_LSHIFT		(N_PP+10)	/*	<<	*/
#define T_RSHIFT		(N_PP+11)	/*	>>	*/
#define T_LE			(N_PP+12)	/*	<=	*/
#define T_GE			(N_PP+13)	/*	>=	*/
#define T_EQ			(N_PP+14)	/*	==	*/
#define T_NE			(N_PP+15)	/*	!=	*/
#define T_ANDAND		(N_PP+16)	/*	&&	*/
#define T_OROR			(N_PP+17)	/*	||	*/
#define T_MPYEQ			(N_PP+18)	/*	*=	*/
#define T_DIVEQ			(N_PP+19)	/*	/=	*/
#define T_MODEQ			(N_PP+20)	/*	%=	*/
#define T_ADDEQ			(N_PP+21)	/*	+=	*/
#define T_SUBEQ			(N_PP+22)	/*	-=	*/
#define T_LSHIFTEQ		(N_PP+23)	/*	<<=	*/
#define T_RSHIFTEQ		(N_PP+24)	/*	>>=	*/
#define T_ANDEQ			(N_PP+25)	/*	&=	*/
#define T_XOREQ			(N_PP+26)	/*	^=	*/
#define T_OREQ			(N_PP+27)	/*	|=	*/
#define T_TOKCAT		(N_PP+28)	/*	##	*/
#define T_VARIADIC		(N_PP+29)	/*	...	*/

/*
 * C++ tokens
 */

#define T_DOTREF		(N_TOKEN+0)	/*	.*	*/
#define T_PTRMEMREF		(N_TOKEN+1)	/*	->*	*/
#define T_SCOPE			(N_TOKEN+2)	/*	::	*/

/*
 * compiler tokens
 */

#define T_UMINUS		(N_TOKEN+3)

#endif

/*
 * start of free tokens
 */

#define T_TOKEN			(N_TOKEN+4)

struct ppdirs				/* directory list		*/
{
	char*		name;		/* directory name		*/
	struct ppdirs*	next;		/* next in list			*/

#ifdef _PP_DIRS_PRIVATE_
	_PP_DIRS_PRIVATE_
#endif

};

struct ppkeyword			/* pp keyword info		*/
{
	char*		name;		/* keyword name			*/
	int		value;		/* keyword token value		*/
};

struct ppmacro				/* pp macro info		*/
{
	int		arity;		/* # formal arguments		*/
	char*		value;		/* definition value		*/

#ifdef _PP_MACRO_PRIVATE_
	_PP_MACRO_PRIVATE_
#endif

};

struct ppsymbol				/* pp symbol info		*/
{
	HASH_HEADER;			/* hash stuff and symbol name	*/
	unsigned long	flags;		/* SYM_* status			*/
	struct ppmacro*	macro;		/* macro info			*/
	void*		value;		/* value (for other passes)	*/

#ifdef _PP_SYMBOL_PRIVATE_
	_PP_SYMBOL_PRIVATE_
#endif

};

#define _PP_CONTEXT_BASE_	((char*)&pp.lcldirs)

#define _PP_CONTEXT_PUBLIC_ \
	struct ppdirs*	lcldirs;	/* the "..." dir list		*/ \
	struct ppdirs*	stddirs;	/* next is the <...> dir list	*/ \
	int		flags;		/* PP_[a-z]* flags		*/ \
	Hash_table_t*	symtab;		/* macro and id hash table	*/

struct ppglobals			/* globals accessed by pp.*	*/
{
	const char*	version;	/* version stamp		*/
	char*		lineid;		/* line sync directive id	*/
	char*		outfile;	/* output file name		*/
	char*		pass;		/* pass name			*/
	char*		token;		/* pplex() token name		*/
	struct ppsymbol* symbol;	/* last symbol if PP_COMPILE	*/

	/* exposed for the output macros */

	char*		outb;		/* output buffer base		*/
	char*		outbuf;		/* output buffer		*/
	char*		outp;	    	/* outbuf pointer		*/
	char*		oute;	    	/* outbuf end			*/
	unsigned long	offset;		/* output offset		*/

#ifdef _PP_CONTEXT_PUBLIC_
	_PP_CONTEXT_PUBLIC_		/* public context		*/
#endif

#ifdef _PP_CONTEXT_PRIVATE_
	_PP_CONTEXT_PRIVATE_		/* library private context	*/
#endif

#ifdef _PP_GLOBALS_PRIVATE_
	_PP_GLOBALS_PRIVATE_		/* library private additions	*/
#endif

};

/*
 * library interface globals
 */

#define ppctype		_pp_ctype

extern struct ppglobals	pp;
extern char		ppctype[];

extern int		ppargs(char**, int);
extern void		ppcpp(void);
extern void		ppcomment(char*, char*, char*, int);
extern void*		ppcontext(void*, int);
extern void		pperror(int, ...);
extern void		ppincref(char*, char*, int, int);
extern void		ppinput(char*, char*, int);
extern int		pplex(void);
extern void		ppline(int, char*);
extern void		ppmacref(struct ppsymbol*, char*, int, int, unsigned long);
extern void		ppop(int, ...);
extern void		pppragma(char*, char*, char*, char*, int);
extern int		ppprintf(char*, ...);
extern int		ppsync(void);

#endif
