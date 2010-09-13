/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * virtual db file directory entry constants
 */

#ifndef VDB_MAGIC

#define VDB_MAGIC	"vdb"

#define VDB_DIRECTORY	"DIRECTORY"
#define VDB_UNION	"UNION"
#define VDB_DATE	"DATE"
#define VDB_MODE	"MODE"

#define VDB_DELIMITER	';'
#define VDB_IGNORE	'_'
#define VDB_FIXED	10
#define VDB_LENGTH	((int)sizeof(VDB_DIRECTORY)+2*(VDB_FIXED+1))
#define VDB_OFFSET	((int)sizeof(VDB_DIRECTORY))
#define VDB_SIZE	(VDB_OFFSET+VDB_FIXED+1)

#endif
