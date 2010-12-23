/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This is where all the interfaces that are internal to libadm
 * which do not have a better home live
 */

#ifndef	_LIBADM_H
#define	_LIBADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <valtools.h>
#include <stdio.h>
#include <pkginfo.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int ckquit;
extern int ckwidth;
extern int ckindent;

extern int _getvol(char *, char *, int, char *, char *);
extern CKMENU *allocmenu(char *, int);
extern int ckdate(char *, char *, char *, char *, char *, char *);
extern int ckdate_err(char *, char *);
extern int ckdate_hlp(char *, char *);
extern int ckdate_val(char *, char *);
extern int ckgid(char *, short, char *, char *, char *, char *);
extern int ckgid_dsp(void);
extern void ckgid_err(int, char *);
extern void ckgid_hlp(int, char *);
extern int ckgid_val(char *);
extern int ckgrpfile(void);
extern int ckint(long *, short, char *, char *, char *, char *);
extern void ckint_err(short, char *);
extern void ckint_hlp(short, char *);
extern int ckint_val(char *, short);
extern void ckitem_err(CKMENU *, char *);
extern void ckitem_hlp(CKMENU *, char *);
extern int ckitem(CKMENU *, char **, short, char *, char *, char *, char *);
extern int ckkeywd(char *, char **, char *, char *, char *, char *);
extern int ckpath(char *, int, char *, char *, char *, char *);
extern void ckpath_err(int, char *, char *);
extern void ckpath_hlp(int, char *);
extern int ckpath_stx(int);
extern int ckpath_val(char *, int);
extern int ckpwdfile(void);
extern int ckrange(long *, long, long, short, char *, char *, char *, char *);
extern void ckrange_err(long, long, int, char *);
extern void ckrange_hlp(long, long, int, char *);
extern int ckrange_val(long, long, int, char *);
extern int ckstr(char *, char **, int, char *, char *, char *, char *);
extern void ckstr_err(char **, int, char *, char *);
extern void ckstr_hlp(char **, int, char *);
extern int ckstr_val(char **, int, char *);
extern int cktime(char *, char *, char *, char *, char *, char *);
extern int cktime_val(char *, char *);
extern int cktime_err(char *, char *);
extern int cktime_hlp(char *, char *);
extern int ckuid(char *, short, char *, char *, char *, char *);
extern int ckuid_dsp(void);
extern void ckuid_err(short, char *);
extern void ckuid_hlp(int, char *);
extern int ckuid_val(char *);
extern int ckyorn(char *, char *, char *, char *, char *);
extern void ckyorn_err(char *);
extern void ckyorn_hlp(char *);
extern int ckyorn_val(char *);
extern void doremovecmd(char *, int);
extern int fpkginfo(struct pkginfo *, char *);
extern char *fpkginst(char *, ...);
extern char *fpkgparam(FILE *, char *);
extern char *get_PKGADM(void);
extern char *get_PKGLOC(void);
extern char *get_PKGOLD(void);
extern int getinput(char *);
extern char *getfullblkname(char *);
extern char *getfullrawname(char *);
extern int pkginfofind(char *, char *, char *);
extern FILE *pkginfopen(char *, char *);
extern void puterror(FILE *, char *, char *);
extern void puthelp(FILE *, char *, char *);
extern void putprmpt(FILE *, char *, char **, char *);
extern int puttext(FILE *, char *, int, int);
extern void printmenu(CKMENU *);
extern int setinvis(CKMENU *, char *);
extern int setitem(CKMENU *, char *);
extern void set_PKGADM(char *);
extern void set_PKGLOC(char *);
extern void set_PKGpaths(char *);
extern void set_ABI_namelngth(void);
extern int get_ABI_namelngth(void);
extern void set_install_root(char *path);
extern char *get_install_root(void);


#ifdef	__cplusplus
}
#endif

#endif /* _LIBADM_H */
