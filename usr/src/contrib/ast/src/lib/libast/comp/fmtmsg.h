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
 * fmtmsg interface definitions
 */

#ifndef _FMTMSG_H
#define _FMTMSG_H

#define	MM_VERB_ENV	"MSGVERB"	/* keyword filter env var	*/
#define	MM_SEVERITY_ENV	"SEV_LEVEL"	/* alternate severity env var	*/

/* max component length */

#define MM_LABEL_1_MAX	10		/* label field 1 length		*/
#define MM_LABEL_2_MAX	14		/* label field 2 length		*/

/* classification type */

#define	MM_HARD		0x00000001L	/* hardware			*/
#define	MM_SOFT		0x00000002L	/* software			*/
#define	MM_FIRM		0x00000004L	/* firmware			*/

/* classification source */

#define	MM_APPL		0x00000010L	/* application			*/
#define MM_UTIL		0x00000020L	/* utility			*/
#define	MM_OPSYS	0x00000040L	/* kernel			*/

/* classification display */

#define	MM_PRINT	0x00000100L	/* stderr			*/
#define	MM_CONSOLE	0x00000200L	/* console			*/

/* classification status */

#define	MM_RECOVER	0x00001000L	/* recoverable			*/
#define	MM_NRECOV	0x00002000L	/* non-recoverable		*/

/* severity */

#define MM_NOSEV	0x0		/* no severity			*/
#define	MM_HALT		0x1		/* severe fault			*/
#define	MM_ERROR	0x2		/* fault			*/
#define	MM_WARNING	0x4		/* could be a problem		*/
#define	MM_INFO		0x8		/* not an error (noise?)	*/

/* fmtmsg return value */

#define	MM_OK		0		/* succeeded			*/
#define	MM_NOTOK	3		/* failed completely		*/
#define	MM_NOMSG	1		/* stderr message failed	*/
#define MM_NOCON	2		/* console message failed	*/

/* null argument values -- 0 just doesn't get any respect */

#define MM_NULLLBL	(char*)0	/* label			*/
#define MM_NULLSEV	0		/* severity			*/
#define	MM_NULLMC	0L		/* class			*/
#define MM_NULLTXT	(char*)0	/* text				*/
#define MM_NULLACT	(char*)0	/* action			*/
#define MM_NULLTAG	(char*)0	/* tag				*/

#ifdef MM_TABLES

/* encoding support */

typedef struct
{
	const char*	name;
	const char*	display;
	unsigned int	value;
} MM_table_t;

#define mm_class	_mm_class
#define mm_severity	_mm_severity()
#define mm_verb		_mm_verb

#define MM_all		0xff
#define MM_action	0x01
#define MM_class	0x02
#define MM_label	0x04
#define MM_severity	0x08
#define MM_source	0x10
#define MM_status	0x20
#define MM_tag		0x40
#define MM_text		0x80

#define MM_default	(MM_action|MM_label|MM_severity|MM_tag|MM_text)

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif
#if !_BLD_ast && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern const MM_table_t		mm_class[];
extern const MM_table_t		mm_verb[];

#undef	extern

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern const MM_table_t*	mm_severity;

#undef	extern

#endif

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int	fmtmsg(long, const char*, int, const char*, const char*, const char*);

#undef	extern

#endif
