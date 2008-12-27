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
 * preprocessor library private definitions
 */

#ifndef _PPLIB_H
#define _PPLIB_H

/*
 * the first definitions control optional code -- 0 disables
 */

#ifndef ARCHIVE
#define ARCHIVE		1	/* -I can specify header archives	*/
#endif
#ifndef CATSTRINGS
#define CATSTRINGS	1	/* concatenate adjacent strings		*/
#endif
#ifndef CHECKPOINT
#define CHECKPOINT	1	/* checkpoint preprocessed files	*/
#endif
#ifndef COMPATIBLE
#define COMPATIBLE	1	/* enable COMPATIBILITY related code	*/
#endif
#ifndef MACKEYARGS
#define MACKEYARGS 	_BLD_DEBUG /* name=value macro formals and actuals */
#endif
#ifndef POOL
#define POOL		1	/* enable loop on input,output,error	*/
#endif
#ifndef PROTOTYPE
#define PROTOTYPE	1	/* enable ppproto code			*/
#endif

#define TRUNCLENGTH	8	/* default TRUNCATE length		*/

#if _BLD_DEBUG
#undef	DEBUG
#define DEBUG		(TRACE_message|TRACE_count|TRACE_debug)
#else
#ifndef DEBUG
#define DEBUG		(TRACE_message)
#endif
#endif

/*
 * the lower tests are transient
 */

#define TEST_count		(1L<<24)
#define TEST_hashcount		(1L<<25)
#define TEST_hashdump		(1L<<26)
#define TEST_hit		(1L<<27)
#define TEST_noinit		(1L<<28)
#define TEST_nonoise		(1L<<29)
#define TEST_noproto		(1L<<30)

#define TEST_INVERT		(1L<<31)

#define PROTO_CLASSIC		(1<<0)	/* classic to prototyped	*/
#define PROTO_DISABLE		(1<<1)	/* disable conversion		*/
#define PROTO_EXTERNALIZE	(1<<2)	/* static fun() => extern fun()	*/
#define PROTO_FORCE		(1<<3)	/* force even if no magic	*/
#define PROTO_HEADER		(1<<4)	/* header defines too		*/
#define PROTO_INCLUDE		(1<<5)	/* <prototyped.h> instead	*/
#define PROTO_INITIALIZED	(1<<6)	/* internal initialization	*/
#define PROTO_LINESYNC		(1<<7)	/* force standalone line syncs	*/
#define PROTO_NOPRAGMA		(1<<8)	/* delete pragma prototyped	*/
#define PROTO_PASS		(1<<9)	/* pass blocks if no magic	*/
#define PROTO_PLUSPLUS		(1<<10)	/* extern () -> extern (...)	*/
#define PROTO_RETAIN		(1<<11)	/* defines retained after close	*/
#define PROTO_TEST		(1<<12)	/* enable test code		*/

#define PROTO_USER		(1<<13)	/* first user flag		*/

#define SEARCH_EXISTS		0	/* ppsearch for existence	*/
#define SEARCH_HOSTED		(1<<0)	/* search hosted dirs only	*/
#define SEARCH_IGNORE		(1<<1)	/* ignore if not found		*/
#define SEARCH_INCLUDE		(1<<2)	/* ppsearch for include		*/
#define SEARCH_VENDOR		(1<<3)	/* search vendor dirs only	*/
#define SEARCH_USER		(1<<4)	/* first user flag		*/

#define STYLE_gnu		(1<<0)	/* gnu style args		*/

#define IN_c			(1<<0)	/* C language file		*/
#define IN_defguard		(1<<1)	/* did multiple include check	*/
#define IN_disable		(1<<2)	/* saved state&DISABLE		*/
#define IN_endguard		(1<<3)	/* did multiple include check	*/
#define IN_eof			(1<<4)	/* reached EOF			*/
#define IN_expand		(1<<5)	/* ppexpand buffer		*/
#define IN_flush		(1<<6)	/* flush stdout on file_refill()*/
#define IN_hosted		(1<<7)	/* saved mode&HOSTED		*/
#define IN_ignoreline		(1<<8)	/* ignore #line until file	*/
#define IN_newline		(1<<9)	/* newline at end of last fill	*/
#define IN_noguard		(1<<10)	/* no multiple include guard	*/
#define IN_prototype		(1<<11)	/* ppproto() input		*/
#define IN_regular		(1<<12)	/* regular input file		*/
#define IN_static		(1<<13)	/* static buffer - don't free	*/
#define IN_sync			(1<<14)	/* line sync required on pop	*/
#define IN_tokens		(1L<<15)/* non-space tokens encountered	*/

#define OPT_GLOBAL		(1<<0)	/* pp: pass optional		*/
#define OPT_PASS		(1<<1)	/* pass on			*/

struct ppsymbol;
struct ppindex;

typedef char*	(*PPBUILTIN)(char*, const char*, const char*);
typedef void	(*PPCOMMENT)(const char*, const char*, const char*, int);
typedef void	(*PPINCREF)(const char*, const char*, int, int);
typedef void	(*PPLINESYNC)(int, const char*);
typedef void	(*PPMACREF)(struct ppsymbol*, const char*, int, int, unsigned long);
typedef int	(*PPOPTARG)(int, int, const char*);
typedef void	(*PPPRAGMA)(const char*, const char*, const char*, const char*, int);

struct ppinstk				/* input stream stack frame	*/
{
	char*		nextchr;	/* next input char (first elt)	*/
	struct ppinstk*	next;		/* next frame (for allocation)	*/
	struct ppinstk*	prev;		/* previous frame		*/
	long*		control;	/* control block level		*/
	char*		buffer;		/* buffer base pointer		*/
	char*		file;		/* saved file name		*/
	char*		prefix;		/* directory prefix		*/
	struct ppsymbol* symbol;	/* macro info			*/
#if CHECKPOINT
	struct ppindex*	index;		/* checkpoint include index	*/
	int		buflen;		/* buffer count			*/
#endif
	int		line;		/* saved line number		*/
	int		vendor;		/* saved pp.vendor		*/
	short		fd;		/* file descriptor		*/
	short		hide;		/* hide index (from pp.hide)	*/
	short		flags;		/* IN_[a-z]* flags		*/
	char		type;		/* input type			*/
};

#if MACKEYARGS
struct ppkeyarg				/* pp macro keyword arg info	*/
{
	char*		name;		/* keyword arg name		*/
	char*		value;		/* keyword arg value		*/
};
#endif

struct pplist				/* string list			*/
{
	char*		value;		/* string value			*/
	struct pplist*	next;		/* next in list			*/
};

struct oplist				/* queue op until PP_INIT	*/
{
	int		op;		/* PP_* op			*/
	char*		value;		/* op value			*/
	struct oplist*	next;		/* next op			*/
};

struct pphide				/* hidden symbol info		*/
{
	struct ppmacro*	macro;		/* saved macro info		*/
	unsigned long	flags;		/* saved symbol flags if macro	*/
	int		level;		/* nesting level		*/
};

struct ppmacstk				/* macro invocation stack frame	*/
{
	struct ppmacstk* next;		/* next frame (for allocation)	*/
	struct ppmacstk* prev;		/* previous frame		*/
	int		line;		/* line number of first arg	*/
	char*		arg[1];		/* arg text pointers		*/
};

struct ppmember				/* archive member pun on ppfile	*/
{
	struct ppdirs*	archive;	/* archive holding file		*/
	unsigned long	offset;		/* data offset			*/
	unsigned long	size;		/* data size			*/
};

struct counter				/* monitoring counters		*/
{
	int		candidate;	/* macro candidates		*/
	int		function;	/* function macros		*/
	int		macro;		/* macro hits			*/
	int		pplex;		/* pplex() calls		*/
	int		push;		/* input stream pushes		*/
	int		terminal;	/* terminal states		*/
	int		token;		/* emitted tokens		*/
};

struct pptuple				/* tuple macro			*/
{
	struct pptuple*	nomatch;	/* nomatch tuple		*/
	struct pptuple*	match;		/* match tuple			*/
	char		token[1];	/* matching token		*/
};

struct ppfileid				/* physical file id		*/
{
	unsigned long	st_dev;		/* dev				*/
	unsigned long	st_ino;		/* ino				*/
};

struct pathid				/* physical file name and id	*/
{
	char*		path;		/* file path			*/
	struct ppfileid	id;		/* file id			*/
};

#define SAMEID(a,b)	((a)->st_ino==(unsigned long)(b)->st_ino&&(a)->st_dev==(unsigned long)(b)->st_dev)
#define SAVEID(a,b)	((a)->st_ino=(unsigned long)(b)->st_ino,(a)->st_dev=(unsigned long)(b)->st_dev)

#define _PP_CONTEXT_PRIVATE_		/* ppglobals private context	*/ \
	struct ppcontext* context;	/* current context		*/ \
	long		state;		/* pp state flags		*/ \
	long		mode;		/* uncoupled pp state flags	*/ \
	long		option;		/* option flags			*/ \
	long		test;		/* implementation tests		*/ \
	struct								   \
	{								   \
	Sfio_t*		sp;		/* FILEDEPS output stream	*/ \
	long		flags;		/* PP_FILEDEPS flags		*/ \
	}		filedeps;	/* FILEDEPS info		*/ \
	struct ppdirs*	firstdir;	/* first include dir		*/ \
	struct ppdirs*	lastdir;	/* last include dir		*/ \
	int		hide;		/* current include hide index	*/ \
	int		column;		/* FILEDEPS column		*/ \
	int		pending;	/* ppline() pending output	*/ \
	char*		firstfile;	/* ppline() first file		*/ \
	char*		lastfile;	/* ppline() most recent file	*/ \
	char*		ignore;		/* include ignore list file	*/ \
	char*		probe;		/* ppdefault probe key		*/ \
	Hash_table_t*	filtab;		/* file name hash table		*/ \
	Hash_table_t*	prdtab;		/* predicate hash table		*/ \
	char*		date;		/* start date string		*/ \
	char*		time;		/* start time string		*/ \
	char*		maps;		/* directive maps		*/ \
	long		ro_state;	/* readonly state		*/ \
	long		ro_mode;	/* readonly mode		*/ \
	long		ro_option;	/* readonly option		*/ \
	struct pathid	cdir;		/* arg C dir			*/ \
	struct pathid	hostdir;	/* arg host dir			*/ \
	char*		ppdefault;	/* arg default info file	*/ \
	struct ppindex*	firstindex;	/* first include index entry	*/ \
	struct ppindex*	lastindex;	/* last include index entry	*/ \
	struct oplist*	firstop;	/* first arg op			*/ \
	struct oplist*	lastop;		/* last arg op			*/ \
	struct oplist*	firsttx;	/* first text file		*/ \
	struct oplist*	lasttx;		/* last text file		*/ \
	unsigned char	arg_file;	/* arg file index		*/ \
	unsigned char	arg_mode;	/* arg mode			*/ \
	unsigned char	arg_style;	/* arg style			*/ \
	unsigned char	c;		/* arg C state			*/ \
	unsigned char	hosted;		/* arg hosted state		*/ \
	unsigned char	ignoresrc;	/* arg ignore source state	*/ \
	unsigned char	initialized;	/* arg initialized state	*/ \
	unsigned char	standalone;	/* arg standalone state		*/ \
	unsigned char	spare_1;	/* padding spare		*/

#define _PP_GLOBALS_PRIVATE_		/* ppglobals private additions	*/ \
	char*		checkpoint;	/* checkpoint version		*/ \
	int		constack;	/* pp.control size		*/ \
	struct ppinstk*	in;		/* input stream stack pointer	*/ \
	char*		addp;	    	/* addbuf pointer		*/ \
	char*		args;		/* predicate args		*/ \
	char*		addbuf;		/* ADD buffer			*/ \
	char*		catbuf;		/* catenation buffer		*/ \
	char*		hdrbuf;		/* HEADEREXPAND buffer		*/ \
	char*		hidebuf;	/* pp:hide buffer		*/ \
	char*		path;		/* full path of last #include	*/ \
	char*		tmpbuf;		/* very temporary buffer	*/ \
	char*		valbuf;		/* builtin macro value buffer	*/ \
	char*		optflags;	/* OPT_* flags indexed by X_*	*/ \
	int		lastout;	/* last output char		*/ \
		/* the rest are implicitly initialized */ \
	char*		include;	/* saved path of last #include	*/ \
	char*		prefix;		/* current directory prefix	*/ \
	struct ppmember* member;	/* include archive member data	*/ \
	int		hidden;		/* hidden newline count		*/ \
	int		hiding;		/* number of symbols in hiding	*/ \
	int		level;		/* pplex() recursion level	*/ \
	struct								   \
	{								   \
	int		input;		/* pool input			*/ \
	int		output;		/* pool output			*/ \
	}		pool;		/* loop on input,output,error	*/ \
	struct								   \
	{								   \
	long		ro_state;	/* original pp.ro_state		*/ \
	long		ro_mode;	/* original pp.ro_mode		*/ \
	long		ro_option;	/* original pp.ro_option	*/ \
	int		on;		/* PP_RESET enabled		*/ \
	Hash_table_t*	symtab;		/* original pp.symtab scope	*/ \
	}		reset;		/* PP_RESET state		*/ \
	int		truncate;	/* identifier truncation length	*/ \
	struct ppmacstk* macp;		/* top of macro actual stack	*/ \
	char*		maxmac;		/* maximum size of macro stack	*/ \
	char*		mactop;		/* top of current macro frame	*/ \
	char*		toknxt;		/* '\0' of pp.token		*/ \
	long*		control;	/* control block flags pointer	*/ \
	long*		maxcon;		/* max control block frame	*/ \
	struct oplist*	chop;		/* include prefix chop list	*/ \
	struct ppfile*	insert;		/* inserted line sync file	*/ \
	struct ppfile*	original;	/* original include name	*/ \
	struct ppdirs*	found;		/* last successful ppsearch dir	*/ \
	int		vendor;		/* vendor includes only		*/ \
	Hash_table_t*	dirtab;		/* directive hash table		*/ \
	Hash_table_t*	strtab;		/* string hash table		*/ \
	PPBUILTIN	builtin;	/* builtin macro handler	*/ \
	PPCOMMENT	comment;	/* pass along comments		*/ \
	PPINCREF	incref;		/* include file push/return	*/ \
	PPLINESYNC	linesync;	/* pass along line sync info	*/ \
	PPLINESYNC	olinesync;	/* original linesync value	*/ \
	PPMACREF	macref;		/* called on macro def/ref	*/ \
	PPOPTARG	optarg;		/* unknown option arg handler	*/ \
	PPPRAGMA	pragma;		/* pass along unknown pragmas	*/ \
	struct counter	counter;	/* monitoring counters		*/ \
	char		funbuf[256];	/* last __FUNCTION__		*/

#define _PP_SYMBOL_PRIVATE_		/* ppsymbol private additions	*/ \
	struct pphide*	hidden;		/* hidden symbol info		*/

#if MACKEYARGS
#define _PP_MACRO_PRIVATE_		/* ppmacro private additions	*/ \
	struct pptuple*	tuple;		/* tuple macro			*/ \
	union								   \
	{								   \
	char*		formal;		/* normal formals list		*/ \
	struct ppkeyarg* key;		/* keyword formals table	*/ \
	}		args;		/* macro args info		*/ \
	int		size;		/* body size			*/
#define formals		args.formal	/* formal argument list		*/
#define formkeys	args.key	/* formal keyword argument list	*/
#else
#define _PP_MACRO_PRIVATE_		/* ppmacro private additions	*/ \
	struct pptuple*	tuple;		/* tuple macro			*/ \
	char*		formals;	/* formal argument list		*/ \
	int		size;		/* body size			*/
#endif

#define _PP_DIRS_PRIVATE_		/* ppdirs private additions	*/ \
	unsigned char	c;		/* files here are C language	*/ \
	unsigned char	index;		/* prefix,local,standard index	*/ \
	unsigned char	type;		/* dir type			*/ \
	union								   \
	{								   \
	char*		buffer;		/* TYPE_BUFFER buffer		*/ \
	Sfio_t*		sp;		/* archive stream		*/ \
	struct ppdirs*	subdir;		/* subdir list			*/ \
	}		info;		/* type info			*/ \
	struct ppfileid	id;		/* directory id			*/ \

#if !PROTOMAIN
#include <ast.h>
#include <error.h>
#endif

#undef	newof
#define newof(p,t,n,x)	((p)?(t*)realloc((char*)(p),sizeof(t)*(n)+(x)):(t*)calloc(1,sizeof(t)*(n)+(x)))

#include "pp.h"
#include "ppdef.h"
#include "ppkey.h"

#undef	setstate			/* random clash!		*/

/*
 * DEBUG is encoded with the following bits
 */

#define TRACE_message		01
#define TRACE_count		02
#define TRACE_debug		04

#if DEBUG && !lint
#define	PANIC		(ERROR_PANIC|ERROR_SOURCE|ERROR_SYSTEM),__FILE__,__LINE__
#else
#define	PANIC		ERROR_PANIC
#endif

#if DEBUG & TRACE_count
#define count(x)	pp.counter.x++
#else
#define count(x)
#endif

#if DEBUG & TRACE_message
#define message(x)	do { if (tracing) error x; } while (0)
#else
#define message(x)
#endif

#if DEBUG & TRACE_debug
#define debug(x)	do { if (tracing) error x; } while (0)
#else
#define debug(x)
#endif

/*
 * note that MEMCPY advances the associated pointers
 */

#define MEMCPY(to,fr,n) \
	do switch(n) \
	{ default : memcpy(to,fr,n); to += n; fr += n; break; \
	  case  7 : *to++ = *fr++; \
	  case  6 : *to++ = *fr++; \
	  case  5 : *to++ = *fr++; \
	  case  4 : *to++ = *fr++; \
	  case  3 : *to++ = *fr++; \
	  case  2 : *to++ = *fr++; \
	  case  1 : *to++ = *fr++; \
	  case  0 : break; \
	} while (0)

#define NEWDIRECTIVE	(-1)

#undef	dirname
#undef	error

#define dirname(x)	ppkeyname(x,1)
#define error		pperror
#define keyname(x)	ppkeyname(x,0)
#define nextframe(m,p)	(m->next=m+(p-(char*)m+sizeof(struct ppmacstk)-1)/sizeof(struct ppmacstk)+1)
#define popframe(m)	(m=m->prev)
#define pptokchr(c)	pptokstr(NiL,(c))
#define pushcontrol()	do { if (pp.control++ >= pp.maxcon) ppnest(); } while (0)
#define pushframe(m)	(m->next->prev=m,m=m->next)
#define setmode(m,v)	((v)?(pp.mode|=(m)):(pp.mode&=~(m)))
#define setoption(m,v)	((v)?(pp.option|=(m)):(pp.option&=~(m)))
#define setstate(s,v)	((v)?(pp.state|=(s)):(pp.state&=~(s)))
#define tracing		(error_info.trace<0)

#define ppgetfile(x)	((struct ppfile*)hashlook(pp.filtab,x,HASH_LOOKUP,NiL))
#define ppsetfile(x)	((struct ppfile*)hashlook(pp.filtab,x,HASH_CREATE|HASH_SIZE(sizeof(struct ppfile)),NiL))

#define ppkeyget(t,n)	(struct ppsymkey*)hashlook(t,n,HASH_LOOKUP,NiL)
#define ppkeyref(t,n)	(struct ppsymkey*)hashlook(t,n,HASH_LOOKUP|HASH_INTERNAL,NiL)
#define ppkeyset(t,n)	(struct ppsymkey*)hashlook(t,n,HASH_CREATE|HASH_SIZE(sizeof(struct ppsymkey)),NiL)

#define MARK		'@'		/* internal mark		*/
#define ARGOFFSET	'1'		/* macro arg mark offset	*/

#define STRAPP(p,v,r)	do{r=(v);while((*p++)=(*r++));}while(0)
#define STRCOPY(p,v,r)	do{r=(v);while((*p++)=(*r++));p--;}while(0)
#define STRCOPY2(p,r)	do{while((*p++)=(*r++));p--;}while(0)

#define SETFILE(p,v)	(p+=sfsprintf(p,16,"%c%c%lx%c",MARK,'F',(long)v,MARK))
#define SETLINE(p,v)	(p+=sfsprintf(p,16,"%c%c%lx%c",MARK,'L',(long)v,MARK))

#define peekchr()	(*pp.in->nextchr)
#define ungetchr(c)	(*--pp.in->nextchr=(c))

#define MAXID		255		/* maximum identifier size	*/
#define MAXTOKEN	PPTOKSIZ	/* maximum token size		*/
#define MAXFORMALS	64		/* maximum number macro formals	*/
#define MAXHIDDEN	8		/* ppline if hidden>=MAXHIDDEN	*/
#define DEFMACSTACK	(MAXFORMALS*32*32)/* default macstack size	*/

#define FSM_COMPATIBILITY	1	/* compatibility mode		*/
#define FSM_IDADD	2		/* add to identifer set		*/
#define FSM_IDDEL	3		/* delete from identifer set	*/
#define FSM_INIT	4		/* initilize			*/
#define FSM_MACRO	5		/* add new macro		*/
#define FSM_OPSPACE	6		/* handle <binop><space>=	*/
#define FSM_PLUSPLUS	7		/* C++ lexical analysis		*/
#define FSM_QUOTADD	8		/* add to quote set		*/
#define FSM_QUOTDEL	9		/* delete from quote set	*/

#define IN_TOP		01		/* top level -- directives ok	*/

#define IN_BUFFER	(2|IN_TOP)	/* buffer of lines		*/
#define IN_COPY		2		/* macro arg (copied)		*/
#define IN_EXPAND	4		/* macro arg (expanded)		*/
#define IN_FILE		(4|IN_TOP)	/* file				*/
#define IN_INIT		(6|IN_TOP)	/* initialization IN_BUFFER	*/
#define IN_MACRO	8		/* macro text			*/
#define IN_MULTILINE	(8|IN_TOP)	/* multi-line macro text	*/
#define IN_QUOTE	10		/* "..." macro arg (copied)	*/
#define IN_RESCAN	(10|IN_TOP)	/* directive rescan buffer	*/
#define IN_SQUOTE	12		/* '...' macro arg (copied)	*/
#define IN_STRING	14		/* string			*/

#define INC_CLEAR	((struct ppsymbol*)0)
#define INC_IGNORE	((struct ppsymbol*)pp.addbuf)
#define INC_TEST	((struct ppsymbol*)pp.catbuf)

#define INC_BOUND(n)	(1<<(n))
#define INC_MEMBER(n)	(1<<((n)+INC_MAX))
#define INC_PREFIX	0
#define INC_LOCAL	1
#define INC_STANDARD	2
#define INC_VENDOR	3
#define INC_MAX		4
#define INC_SELF	(1<<(2*INC_MAX+0))
#define INC_EXISTS	(1<<(2*INC_MAX+1))
#define INC_LISTED	(1<<(2*INC_MAX+2))
#define INC_MAPALL	(1<<(2*INC_MAX+3))
#define INC_MAPHOSTED	(1<<(2*INC_MAX+4))
#define INC_MAPNOHOSTED	(1<<(2*INC_MAX+5))
#define INC_MAPNOLOCAL	(1<<(2*INC_MAX+6))
#define INC_HOSTED	(1<<(2*INC_MAX+7))

#define TYPE_ARCHIVE	(1<<0)
#define TYPE_BUFFER	(1<<1)
#define TYPE_CHECKPOINT	(1<<2)
#define TYPE_DIRECTORY	(1<<3)
#define TYPE_HOSTED	(1<<4)
#define TYPE_INCLUDE	(1<<5)
#define TYPE_VENDOR	(1<<6)

#define TOK_BUILTIN	(1<<0)		/* last token was #(		*/
#define TOK_FORMAL	(1<<1)		/* last token was arg formal id	*/
#define TOK_ID		(1<<2)		/* last token was identifier	*/
#define TOK_TOKCAT	(1<<3)		/* last token was ##		*/

#define HADELSE		(1<<0)		/* already had else part	*/
#define KEPT		(1<<1)		/* already kept part of block	*/
#define SKIP		(1<<2)		/* skip this block		*/
#define BLOCKBITS	3		/* block flag bits		*/

#define SETIFBLOCK(p)	(*(p)=(*((p)-1)&SKIP)|((long)error_info.line<<BLOCKBITS))
#define GETIFLINE(p)	((*(p)>>BLOCKBITS)&((1L<<(sizeof(long)*CHAR_BIT-BLOCKBITS))-1))

#define PUSH(t,p)		\
	do \
	{ \
		count(push); \
		if (!pp.in->next) \
		{ \
			pp.in->next = newof(0, struct ppinstk, 1, 0); \
			pp.in->next->prev = pp.in; \
		} \
		p = pp.in = pp.in->next; \
		p->type = t; \
		p->flags = 0; \
	} while (0)

#define PUSH_BUFFER(f,p,n)		\
	pppush(IN_BUFFER,f,p,n)

#define PUSH_COPY(p,n)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_COPY, cur); \
		cur->line = error_info.line; \
		error_info.line = n; \
		cur->nextchr = p; \
		cur->prev->symbol->flags &= ~SYM_DISABLED; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_EXPAND(p,n)	\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_EXPAND, cur); \
		cur->line = error_info.line; \
		error_info.line = n; \
		cur->prev->symbol->flags &= ~SYM_DISABLED; \
		cur->buffer = cur->nextchr = ppexpand(p); \
		if (!(cur->prev->symbol->flags & SYM_MULTILINE)) \
			cur->prev->symbol->flags |= SYM_DISABLED; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_FILE(f,d)	\
	pppush(IN_FILE,f,NiL,d)

#define PUSH_INIT(f,p)	\
	pppush(IN_INIT,f,p,1)

#define PUSH_MACRO(p)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_MACRO, cur); \
		cur->symbol = p; \
		cur->nextchr = p->macro->value; \
		p->flags |= SYM_DISABLED; \
		if (p->flags & SYM_FUNCTION) pushframe(pp.macp); \
		pp.state &= ~NEWLINE; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_TUPLE(p,v)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_MACRO, cur); \
		cur->symbol = p; \
		cur->nextchr = v; \
		p->flags |= SYM_DISABLED; \
		pp.state &= ~NEWLINE; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_MULTILINE(p)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		register int			n; \
		PUSH(IN_MULTILINE, cur); \
		cur->symbol = p; \
		cur->flags |= IN_defguard|IN_endguard|IN_noguard; \
		pushcontrol(); \
		cur->control = pp.control; \
		*pp.control = 0; \
		cur->file = error_info.file; \
		n = strlen(error_info.file) + strlen(((struct ppsymbol*)p)->name) + 24; \
		error_info.file = cur->buffer = newof(0, char, n, 0); \
		sfsprintf(error_info.file, n, "%s:%s,%d", cur->file, p->name, error_info.line); \
		cur->line = error_info.line; \
		error_info.line = 1; \
		cur->nextchr = p->macro->value; \
		if (p->flags & SYM_FUNCTION) pushframe(pp.macp); \
		pp.state &= ~NEWLINE; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_QUOTE(p,n)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_QUOTE, cur); \
		cur->nextchr = p; \
		pp.state |= QUOTE; \
		cur->line = error_info.line; \
		error_info.line = n; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_RESCAN(p)	\
	pppush(IN_RESCAN,NiL,p,0)

#define PUSH_SQUOTE(p,n)	\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_SQUOTE, cur); \
		cur->nextchr = p; \
		pp.state |= SQUOTE; \
		cur->line = error_info.line; \
		error_info.line = n; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_STRING(p)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_STRING, cur); \
		cur->nextchr = p; \
		if (pp.state & DISABLE) cur->flags |= IN_disable; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define PUSH_LINE(p)		\
	do \
	{ \
		register struct ppinstk*	cur; \
		PUSH(IN_STRING, cur); \
		cur->nextchr = p; \
		pp.state |= DISABLE|NOSPACE|PASSEOF|STRIP; \
		debug((-7, "PUSH in=%s next=%s", ppinstr(pp.in), pptokchr(*pp.in->nextchr))); \
	} while (0)

#define POP_LINE()		\
	do \
	{ \
		debug((-7, "POP  in=%s", ppinstr(pp.in))); \
		pp.in = pp.in->prev; \
		pp.state &= ~(DISABLE|NOSPACE|PASSEOF|STRIP); \
	} while (0)

struct ppcontext			/* pp context			*/
{
	_PP_CONTEXT_PUBLIC_
	_PP_CONTEXT_PRIVATE_
};

struct ppfile				/* include file info		*/
{
	HASH_HEADER;			/* this is a hash bucket too	*/
	struct ppsymbol* guard;		/* guard symbol			*/
	struct ppfile*	bound[INC_MAX];	/* include bindings		*/
	int		flags;		/* INC_* flags			*/
};

#if CHECKPOINT

struct ppindex				/* checkpoint include index	*/
{
	struct ppindex*	next;		/* next in list			*/
	struct ppfile*	file;		/* include file			*/
	unsigned long	begin;		/* beginning output offset	*/
	unsigned long	end;		/* ending output offset		*/
};

#endif

struct ppsymkey				/* pun for SYM_KEYWORD lex val	*/
{
	struct ppsymbol	sym;		/* symbol as usual		*/
	int		lex;		/* lex value for SYM_KEYWORD	*/
};

#if PROTOMAIN && PROTO_STANDALONE

#if defined(__STDC__) || defined(__cplusplus) || defined(c_plusplus)
#define NiL		0
#define NoP(x)		(&x,1)
#else
#define NiL		((char*)0)
#define NoP(x)
#endif

#define newof(p,t,n,x)	((p)?(t*)realloc((char*)(p),sizeof(t)*(n)+(x)):(t*)calloc(1,sizeof(t)*(n)+(x)))

#define _PP_DELAY_	#

_PP_DELAY_ ifdef __STDC__

_PP_DELAY_ include <stdlib.h>
_PP_DELAY_ include <unistd.h>
_PP_DELAY_ include <time.h>
_PP_DELAY_ include <string.h>

_PP_DELAY_ else

_PP_DELAY_ define size_t		int

extern void*		realloc(void*, size_t);
extern void*		calloc(size_t, size_t);
extern char*		ctime(time_t*);
extern void		free(void*);

_PP_DELAY_ ifndef O_RDONLY

extern int		access(const char*, int);
extern int		close(int);
extern int		creat(const char*, int);
extern void		exit(int);
extern int		link(const char*, const char*);
extern int		open(const char*, int, ...);
extern int		read(int, void*, int);
extern time_t		time(time_t*);
extern int		unlink(const char*);
extern int		write(int, const void*, int);

_PP_DELAY_ endif

_PP_DELAY_ endif

#else

/*
 * library implementation globals
 */

#define ppassert	_pp_assert
#define ppbuiltin	_pp_builtin
#define ppcall		_pp_call
#define ppcontrol	_pp_control
#define ppdump		_pp_dump
#define ppexpand	_pp_expand
#define ppexpr		_pp_expr
#define ppfsm		_pp_fsm
#define ppinmap		_pp_inmap
#define ppinstr		_pp_instr
#define ppkeyname	_pp_keyname
#define pplexmap	_pp_lexmap
#define pplexstr	_pp_lexstr
#define ppload		_pp_load
#define ppmodestr	_pp_modestr
#define ppmultiple	_pp_multiple
#define ppnest		_pp_nest
#define ppoption	_pp_option
#define ppoptionstr	_pp_optionstr
#define pppclose	_pp_pclose
#define pppdrop		_pp_pdrop
#define pppopen		_pp_popen
#define pppread		_pp_pread
#define pppredargs	_pp_predargs
#define pppush		_pp_push
#define pprefmac	_pp_refmac
#define ppsearch	_pp_search
#define ppstatestr	_pp_statestr
#define pptokstr	_pp_tokstr
#define pptrace		_pp_trace

#endif

extern void		ppassert(int, char*, char*);
extern void		ppbuiltin(void);
extern int		ppcall(struct ppsymbol*, int);
extern int		ppcontrol(void);
extern void		ppdump(void);
extern char*		ppexpand(char*);
extern long		ppexpr(int*);
extern void		ppfsm(int, char*);
extern char*		ppinstr(struct ppinstk*);
extern char*		ppkeyname(int, int);
extern char*		pplexstr(int);
extern void		ppload(char*);
extern void		ppmapinclude(char*, char*);
extern char*		ppmodestr(long);
extern int		ppmultiple(struct ppfile*, struct ppsymbol*);
extern void		ppnest(void);
extern int		ppoption(char*);
extern char*		ppoptionstr(long);
extern void		pppclose(char*);
extern int		pppdrop(char*);
extern char*		pppopen(char*, int, char*, char*, char*, char*, int);
extern int		pppread(char*);
extern int		pppredargs(void);
extern void		pppush(int, char*, char*, int);
extern struct ppsymbol*	pprefmac(char*, int);
extern int		ppsearch(char*, int, int);
extern char*		ppstatestr(long);
extern char*		pptokstr(char*, int);
extern void		pptrace(int);

#if _std_malloc

#include <vmalloc.h>

#undef	free
#define free(p)	 	vmfree(Vmregion,(void*)p)
#undef	newof
#define newof(p,t,n,x)	vmnewof(Vmregion,p,t,n,x)
#undef	oldof
#define oldof(p,t,n,x)	vmoldof(Vmregion,p,t,n,x)
#undef	strdup
#define strdup(s)	vmstrdup(Vmregion,s)

#endif

#endif
