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
 * regex library interface
 */

#ifdef	_AST_STD_I
#define _REGEX_H	-1
#define regex_t		int
#define regmatch_t	int
#endif
#ifndef _REGEX_H
#define _REGEX_H	1
#undef	regex_t
#undef	regmatch_t

#include <ast_common.h>
#include <ast_wchar.h>
#include <ast_api.h>

#define REG_VERSION	20100930L

/* regcomp flags */

#define REG_AUGMENTED	0x00000001	/* enable ! & < >		*/
#define REG_EXTENDED	0x00000002	/* enable ( | )			*/
#define REG_ICASE	0x00000004	/* ignore case in match		*/
#define REG_NEWLINE	0x00000008	/* ^/$ match embedded \n	*/
#define REG_NOSUB	0x00000010	/* don't report subexp matches	*/
#define REG_SHELL	0x00000020	/* shell pattern syntax		*/

/* nonstandard regcomp flags */

#define REG_LEFT	0x00000100	/* implicit ^...		*/
#define REG_LITERAL	0x00000200	/* no operators			*/
#define REG_MINIMAL	0x00000400	/* minimal match		*/
#define REG_NULL	0x00000800	/* allow null patterns		*/
#define REG_RIGHT	0x00001000	/* implicit ...$		*/
#define REG_LENIENT	0x00002000	/* look the other way		*/
#define REG_ESCAPE	0x00004000	/* \ escapes delimiter in [...]	*/
#define REG_FIRST	0x00008000	/* first match found will do	*/
#define REG_MULTIPLE	0x00010000	/* multiple \n sep patterns	*/
#define REG_DISCIPLINE	0x00020000	/* regex_t.re_disc is valid	*/
#define REG_SPAN	0x00040000	/* . matches \n			*/
#define REG_COMMENT	0x00080000	/* ignore pattern space & #...\n*/
#define REG_MULTIREF	0x00100000	/* multiple digit backrefs	*/
#define REG_MUSTDELIM	0x08000000	/* all delimiters required	*/
#define REG_DELIMITED	0x10000000	/* pattern[0] is delimiter	*/
#define REG_CLASS_ESCAPE 0x80000000	/* \ escapes in [...]		*/

#define REG_SHELL_DOT	0x00200000	/* explicit leading . match	*/
#define REG_SHELL_ESCAPED 0x00400000	/* \ not special		*/
#define REG_SHELL_GROUP	0x20000000	/* (|&) inside [@|&](...) only	*/
#define REG_SHELL_PATH	0x00800000	/* explicit / match		*/

#define REG_REGEXP	0x40000000	/* <regexp.h> compatibility	*/

/* regexec flags */

#define REG_NOTBOL	0x00000040	/* ^ is not a special char	*/
#define REG_NOTEOL	0x00000080	/* $ is not a special char	*/

/* nonstandard regexec flags */

#define REG_INVERT	0x01000000	/* invert regrexec match sense	*/
#define REG_STARTEND	0x02000000	/* subject==match[0].rm_{so,eo} */
#define REG_ADVANCE	0x04000000	/* advance match[0].rm_{so,eo}	*/

/* regalloc flags */

#define REG_NOFREE	0x00000001	/* don't free			*/

/* regsub flags */

#define REG_SUB_ALL	0x00000001	/* substitute all occurrences	*/
#define REG_SUB_LOWER	0x00000002	/* substitute to lower case	*/
#define REG_SUB_UPPER	0x00000004	/* substitute to upper case	*/
#define REG_SUB_PRINT	0x00000010	/* internal no-op		*/
#define REG_SUB_NUMBER	0x00000020	/* internal no-op		*/
#define REG_SUB_STOP	0x00000040	/* internal no-op		*/
#define REG_SUB_WRITE	0x00000080	/* internal no-op		*/
#define REG_SUB_LAST	0x00000100	/* last substitution option	*/
#define REG_SUB_FULL	0x00000200	/* fully delimited		*/
#define REG_SUB_USER	0x00001000	/* first user flag bit		*/

/* regex error codes */

#define REG_ENOSYS	(-1)		/* not supported		*/
#define REG_NOMATCH	1		/* regexec didn't match		*/
#define REG_BADPAT	2		/* invalid regular expression	*/
#define REG_ECOLLATE	3		/* invalid collation element	*/
#define REG_ECTYPE	4		/* invalid character class	*/
#define REG_EESCAPE	5		/* trailing \ in pattern	*/
#define REG_ESUBREG	6		/* invalid \digit backreference	*/
#define REG_EBRACK	7		/* [...] imbalance		*/
#define REG_EPAREN	8		/* \(...\) or (...) imbalance	*/
#define REG_EBRACE	9		/* \{...\} or {...} imbalance	*/
#define REG_BADBR	10		/* invalid {...} digits		*/
#define REG_ERANGE	11		/* invalid [...] range endpoint	*/
#define REG_ESPACE	12		/* out of space			*/
#define REG_BADRPT	13		/* unary op not preceded by re	*/
#define REG_ENULL	14		/* empty subexpr in pattern	*/
#define REG_ECOUNT	15		/* re component count overflow	*/
#define REG_BADESC	16		/* invalid \char escape		*/
#define REG_VERSIONID	17		/* version id (pseudo error)	*/
#define REG_EFLAGS	18		/* flags conflict		*/
#define REG_EDELIM	19		/* invalid or omitted delimiter	*/
#define REG_PANIC	20		/* unrecoverable internal error	*/

struct regex_s; typedef struct regex_s regex_t;
struct regdisc_s; typedef struct regdisc_s regdisc_t;

typedef int (*regclass_t)(int);
typedef uint32_t regflags_t;
typedef int (*regerror_t)(const regex_t*, regdisc_t*, int, ...);
typedef void* (*regcomp_t)(const regex_t*, const char*, size_t, regdisc_t*);
typedef int (*regexec_t)(const regex_t*, void*, const char*, size_t, const char*, size_t, char**, regdisc_t*);
typedef void* (*regresize_t)(void*, void*, size_t);
typedef int (*regrecord_t)(void*, const char*, size_t);

#if ASTAPI(20120528)
typedef ssize_t regoff_t;
#else
typedef int regoff_t;
#endif

typedef struct regmatch_s
{
	regoff_t	rm_so;		/* offset of start		*/
	regoff_t	rm_eo;		/* offset of end		*/
} regmatch_t;

typedef struct regsub_s
{
	regflags_t	re_flags;	/* regsubcomp() flags		*/
	char*		re_buf;		/* regsubexec() output buffer	*/
	size_t		re_len;		/* re_buf length		*/
	int		re_min;		/* regsubcomp() min matches	*/
#ifdef _REG_SUB_PRIVATE_
	_REG_SUB_PRIVATE_
#endif
} regsub_t;

struct regdisc_s
{
	unsigned long	re_version;	/* discipline version		*/
	regflags_t	re_flags;	/* discipline flags		*/
	regerror_t	re_errorf;	/* error function		*/
	int		re_errorlevel;	/* errorf level			*/
	regresize_t	re_resizef;	/* alloc/free function		*/
	void*		re_resizehandle;/* resizef handle		*/
	regcomp_t	re_compf;	/* (?{...}) compile function	*/
	regexec_t	re_execf;	/* (?{...}) execute function	*/
	unsigned char*	re_map;		/* external to native ccode map	*/
};

typedef struct regstat_s
{
	regflags_t	re_flags;	/* REG_*			*/
	ssize_t		re_min;		/* min anchored match length	*/
	ssize_t		re_max;		/* max anchored match length	*/
	ssize_t		re_record;	/* regrexec() match length	*/
	regflags_t	re_info;	/* REG_* info			*/
} regstat_t;

struct regex_s
{
	size_t		re_nsub;	/* number of subexpressions	*/
	struct reglib_s*re_info;	/* library private info		*/
	size_t		re_npat;	/* number of pattern chars used	*/
	regdisc_t*	re_disc;	/* REG_DISCIPLINE discipline	*/
	regsub_t*	re_sub;		/* regsubcomp() data		*/
};

#define reginit(disc)	(memset(disc,0,sizeof(*(disc))),(disc)->re_version=REG_VERSION)

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int	regcomp(regex_t*, const char*, regflags_t);
extern size_t	regerror(int, const regex_t*, char*, size_t);
extern int	regexec(const regex_t*, const char*, size_t, regmatch_t*, regflags_t);
extern void	regfree(regex_t*);

/* nonstandard hooks */

#define _REG_cache	1	/* have regcache()			*/
#define _REG_class	1	/* have regclass()			*/
#define _REG_collate	1	/* have regcollate(), regclass()	*/
#define _REG_comb	1	/* have regcomb()			*/
#define _REG_decomp	1	/* have regdecomp()			*/
#define _REG_dup	1	/* have regdup()			*/
#define _REG_fatal	1	/* have regfatal(), regfatalpat()	*/
#define _REG_ncomp	1	/* have regncomp()			*/
#define _REG_nexec	1	/* have regnexec()			*/
#define _REG_rexec	1	/* have regrexec(), regrecord()		*/
#define _REG_stat	1	/* have regstat()			*/
#define _REG_subcomp	1	/* have regsubcomp(), regsubexec()	*/

extern regclass_t regclass(const char*, char**);
extern int	regaddclass(const char*, regclass_t);
extern int	regcollate(const char*, char**, char*, size_t, wchar_t*);
extern int	regcomb(regex_t*, regex_t*);
extern size_t	regdecomp(regex_t*, regflags_t, char*, size_t);
extern int	regdup(regex_t*, regex_t*);
extern int	regncomp(regex_t*, const char*, size_t, regflags_t);
extern int	regnexec(const regex_t*, const char*, size_t, size_t, regmatch_t*, regflags_t);
extern void	regfatal(regex_t*, int, int);
extern void	regfatalpat(regex_t*, int, int, const char*);
extern int	regrecord(const regex_t*);
extern int	regrexec(const regex_t*, const char*, size_t, size_t, regmatch_t*, regflags_t, int, void*, regrecord_t);
extern regstat_t* regstat(const regex_t*);

extern regex_t*	regcache(const char*, regflags_t, int*);

extern int	regsubcomp(regex_t*, const char*, const regflags_t*, int, regflags_t);
extern int	regsubexec(const regex_t*, const char*, size_t, regmatch_t*);
extern int	regsubflags(regex_t*, const char*, char**, int, const regflags_t*, int*, regflags_t*);
extern void	regsubfree(regex_t*);

/* obsolete hooks */

#ifndef _SFIO_H
struct _sfio_s;
#endif

extern void	regalloc(void*, regresize_t, regflags_t);
extern int	regsub(const regex_t*, struct _sfio_s*, const char*, const char*, size_t, regmatch_t*, regflags_t);

#undef	extern

#endif
