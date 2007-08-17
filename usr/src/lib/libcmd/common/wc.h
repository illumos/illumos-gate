/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1992-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Bell Laboratories
 *
 * header for wc library interface
 */

#ifndef _WC_H
#define _WC_H

#include <ast.h>

#define WC_LINES	0x01
#define WC_WORDS	0x02
#define WC_CHARS	0x04
#define WC_MBYTE	0x08
#define WC_LONGEST	0x10
#define WC_QUIET	0x20

typedef struct
{
	signed char space[1<<CHAR_BIT];
	Sfoff_t words;
	Sfoff_t lines;
	Sfoff_t chars;
	Sfoff_t longest;
	int	mode;
} Wc_t;

#define wc_count	_cmd_wccount
#define wc_init		_cmd_wcinit

extern Wc_t*		wc_init(int);
extern int		wc_count(Wc_t*, Sfio_t*, const char*);

#endif /* _WC_H */
