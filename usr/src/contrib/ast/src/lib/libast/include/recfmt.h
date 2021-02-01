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
 * Glenn Fowler
 * AT&T Research
 *
 * record format interface
 */

#ifndef _RECFMT_H
#define _RECFMT_H		1

#include <ast.h>

typedef uint32_t Recfmt_t;

#define REC_delimited		0
#define REC_fixed		1
#define REC_variable		2
#define REC_method		14
#define REC_none		15

#define REC_M_path		0
#define REC_M_data		1

#define RECTYPE(f)		(((f)>>28)&((1<<4)-1))

#define REC_D_TYPE(d)		((REC_delimited<<28)|((d)&((1<<8)-1)))
#define REC_D_DELIMITER(f)	((f)&((1<<8)-1))

#define REC_F_TYPE(s)		((REC_fixed<<28)|((s)&((1<<28)-1)))
#define REC_F_SIZE(f)		((f)&((1<<28)-1))

#define REC_U_TYPE(t,a)		(((t)<<28)|((a)&((1<<28)-1)))
#define REC_U_ATTRIBUTES(f)	((f)&~((1<<28)-1))

#define REC_V_TYPE(h,o,z,l,i)	((REC_variable<<28)|((h)<<23)|((o)<<19)|(((z)-1)<<18)|((l)<<17)|((i)<<16))
#define REC_V_RECORD(f,s)	(((f)&(((1<<16)-1)<<16))|(s))
#define REC_V_HEADER(f)		(((f)>>23)&((1<<5)-1))
#define REC_V_OFFSET(f)		(((f)>>19)&((1<<4)-1))
#define REC_V_LENGTH(f)		((((f)>>18)&1)+1)
#define REC_V_LITTLE(f)		(((f)>>17)&1)
#define REC_V_INCLUSIVE(f)	(((f)>>16)&1)
#define REC_V_SIZE(f)		((f)&((1<<16)-1))
#define REC_V_ATTRIBUTES(f)	((f)&~((1<<16)-1))

#define REC_M_TYPE(i)		((REC_method<<28)|(i))
#define REC_M_INDEX(f)		((f)&((1<<28)-1))

#define REC_N_TYPE()		0xffffffff

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern char*		fmtrec(Recfmt_t, int);
extern Recfmt_t		recfmt(const void*, size_t, off_t);
extern Recfmt_t		recstr(const char*, char**);
extern ssize_t		reclen(Recfmt_t, const void*, size_t);

#undef	extern

#endif
