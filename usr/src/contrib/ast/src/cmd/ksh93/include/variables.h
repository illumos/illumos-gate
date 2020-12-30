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

#ifndef SH_VALNOD

#include        <option.h>
#include        "FEATURE/options"
#include        "FEATURE/dynamic"

/* The following defines are coordinated with data in data/variables.c */

#define	PATHNOD		(shgd->bltin_nodes)
#define PS1NOD		(shgd->bltin_nodes+1)
#define PS2NOD		(shgd->bltin_nodes+2)
#define IFSNOD		(shgd->bltin_nodes+3)
#define PWDNOD		(shgd->bltin_nodes+4)
#define HOME		(shgd->bltin_nodes+5)
#define MAILNOD		(shgd->bltin_nodes+6)
#define REPLYNOD	(shgd->bltin_nodes+7)
#define SHELLNOD	(shgd->bltin_nodes+8)
#define EDITNOD		(shgd->bltin_nodes+9)
#define MCHKNOD		(shgd->bltin_nodes+10)
#define RANDNOD		(shgd->bltin_nodes+11)
#define ENVNOD		(shgd->bltin_nodes+12)
#define HISTFILE	(shgd->bltin_nodes+13)
#define HISTSIZE	(shgd->bltin_nodes+14)
#define HISTEDIT	(shgd->bltin_nodes+15)
#define HISTCUR		(shgd->bltin_nodes+16)
#define FCEDNOD		(shgd->bltin_nodes+17)
#define CDPNOD		(shgd->bltin_nodes+18)
#define MAILPNOD	(shgd->bltin_nodes+19)
#define PS3NOD		(shgd->bltin_nodes+20)
#define OLDPWDNOD	(shgd->bltin_nodes+21)
#define VISINOD		(shgd->bltin_nodes+22)
#define COLUMNS		(shgd->bltin_nodes+23)
#define LINES		(shgd->bltin_nodes+24)
#define PPIDNOD		(shgd->bltin_nodes+25)
#define L_ARGNOD	(shgd->bltin_nodes+26)
#define TMOUTNOD	(shgd->bltin_nodes+27)
#define SECONDS		(shgd->bltin_nodes+28)
#define LINENO		(shgd->bltin_nodes+29)
#define OPTARGNOD	(shgd->bltin_nodes+30)
#define OPTINDNOD	(shgd->bltin_nodes+31)
#define PS4NOD		(shgd->bltin_nodes+32)
#define FPATHNOD	(shgd->bltin_nodes+33)
#define LANGNOD		(shgd->bltin_nodes+34)
#define LCALLNOD	(shgd->bltin_nodes+35)
#define LCCOLLNOD	(shgd->bltin_nodes+36)
#define LCTYPENOD	(shgd->bltin_nodes+37)
#define LCMSGNOD	(shgd->bltin_nodes+38)
#define LCNUMNOD	(shgd->bltin_nodes+39)
#define FIGNORENOD	(shgd->bltin_nodes+40)
#define VERSIONNOD	(shgd->bltin_nodes+41)
#define JOBMAXNOD	(shgd->bltin_nodes+42)
#define DOTSHNOD	(shgd->bltin_nodes+43)
#define ED_CHRNOD	(shgd->bltin_nodes+44)
#define ED_COLNOD	(shgd->bltin_nodes+45)
#define ED_TXTNOD	(shgd->bltin_nodes+46)
#define ED_MODENOD	(shgd->bltin_nodes+47)
#define SH_NAMENOD	(shgd->bltin_nodes+48)
#define SH_SUBSCRNOD	(shgd->bltin_nodes+49)
#define SH_VALNOD	(shgd->bltin_nodes+50)
#define SH_VERSIONNOD	(shgd->bltin_nodes+51)
#define SH_DOLLARNOD	(shgd->bltin_nodes+52)
#define SH_MATCHNOD	(shgd->bltin_nodes+53)
#define SH_COMMANDNOD	(shgd->bltin_nodes+54)
#define SH_PATHNAMENOD	(shgd->bltin_nodes+55)
#define SH_FUNNAMENOD	(shgd->bltin_nodes+56)
#define SH_SUBSHELLNOD	(shgd->bltin_nodes+57)
#define SH_LEVELNOD	(shgd->bltin_nodes+58)
#define SH_LINENO	(shgd->bltin_nodes+59)
#define SH_STATS	(shgd->bltin_nodes+60)
#define SH_MATHNOD	(shgd->bltin_nodes+61)
#define SH_JOBPOOL	(shgd->bltin_nodes+62)
#define SHLVL		(shgd->bltin_nodes+63)
#if SHOPT_FS_3D
#   define VPATHNOD	(shgd->bltin_nodes+64)
#   define NFS_3D	1
#else
#   define NFS_3D	0
#endif /* SHOPT_FS_3D */
#if SHOPT_VPIX
#   define DOSPATHNOD	(shgd->bltin_nodes+64+NFS_3D)
#   define VPIXNOD	(shgd->bltin_nodes+65+NFS_3D)
#   define NVPIX	(NFS_3D+2)
#else
#   define NVPIX	NFS_3D
#endif /* SHOPT_VPIX */
#ifdef apollo
#   define SYSTYPENOD	(shgd->bltin_nodes+63+NVPIX)
#endif /* apollo */

#endif /* SH_VALNOD */
