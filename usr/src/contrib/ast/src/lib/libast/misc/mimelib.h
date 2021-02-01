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
 * mime/mailcap internal interface
 */

#ifndef _MIMELIB_H
#define _MIMELIB_H	1

#include <ast.h>
#include <cdt.h>
#include <magic.h>
#include <tok.h>

struct Mime_s;

typedef void (*Free_f)(struct Mime_s*);

#define _MIME_PRIVATE_ \
	Mimedisc_t*	disc;		/* mime discipline		*/ \
	Dtdisc_t	dict;		/* cdt discipline		*/ \
	Magicdisc_t	magicd;		/* magic discipline		*/ \
	Dt_t*		cap;		/* capability tree		*/ \
	Sfio_t*		buf;		/* string buffer		*/ \
	Magic_t*	magic;		/* mimetype() magic handle	*/ \
	Free_f		freef;		/* avoid magic lib if possible	*/ \

#include <mime.h>
#include <ctype.h>

#endif
