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
 * generate mode features
 */

#include "limits.h"

#include "FEATURE/param"

#include <modecanon.h>

int
main()
{
	int	n;
	int	idperm;
	int	idtype;

	idperm = idtype = 1;
#ifndef S_ITYPE
#ifdef	S_IFMT
	printf("#define S_ITYPE(m)	((m)&S_IFMT)\n");
#else
	printf("#define S_ITYPE(m)	((m)&~S_IPERM)\n");
#endif
#endif
#ifdef S_ISBLK
	if (!S_ISBLK(X_IFBLK)) idtype = 0;
#else
#ifdef S_IFBLK
	printf("#define S_ISBLK(m)	(S_ITYPE(m)==S_IFBLK)\n");
#else
	printf("#define S_ISBLK(m)	0\n");
#endif
#endif
#ifdef S_ISCHR
	if (!S_ISCHR(X_IFCHR)) idtype = 0;
#else
#ifdef S_IFCHR
	printf("#define S_ISCHR(m)	(S_ITYPE(m)==S_IFCHR)\n");
#else
	printf("#define S_ISCHR(m)	0\n");
#endif
#endif
#ifdef S_ISCTG
	if (!S_ISCTG(X_IFCTG)) idtype = 0;
#else
#ifdef S_IFCTG
	printf("#define S_ISCTG(m)	(S_ITYPE(m)==S_IFCTG)\n");
#endif
#endif
#ifdef S_ISDIR
	if (!S_ISDIR(X_IFDIR)) idtype = 0;
#else
#ifdef S_IFDIR
	printf("#define S_ISDIR(m)	(S_ITYPE(m)==S_IFDIR)\n");
#else
	printf("#define S_ISDIR(m)	0\n");
#endif
#endif
#ifdef S_ISFIFO
	if (!S_ISFIFO(X_IFIFO)) idtype = 0;
#else
#ifdef S_IFIFO
	printf("#define S_ISFIFO(m)	(S_ITYPE(m)==S_IFIFO)\n");
#else
	printf("#define S_ISFIFO(m)	0\n");
#endif
#endif
#ifdef S_ISLNK
	if (!S_ISLNK(X_IFLNK)) idtype = 0;
#else
#ifdef S_IFLNK
	printf("#define S_ISLNK(m)	(S_ITYPE(m)==S_IFLNK)\n");
#else
	printf("#define S_ISLNK(m)	0\n");
#endif
#endif
#ifdef S_ISREG
	if (!S_ISREG(X_IFREG)) idtype = 0;
#else
#ifdef S_IFREG
	printf("#define S_ISREG(m)	(S_ITYPE(m)==S_IFREG)\n");
#else
	printf("#define S_ISREG(m)	0\n");
#endif
#endif
#ifdef S_ISSOCK
	if (!S_ISSOCK(X_IFSOCK)) idtype = 0;
#else
#ifdef S_IFSOCK
	printf("#define S_ISSOCK(m)	(S_ITYPE(m)==S_IFSOCK)\n");
#endif
#endif
	printf("\n");
#ifndef S_IPERM
	printf("#define S_IPERM		(S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)\n");
#endif
#ifndef S_ISUID
	printf("#define S_ISUID		0%04o\n", X_ISUID);
#else
	if (S_ISUID != X_ISUID) idperm = 0;
#endif
#ifndef S_ISGID
	printf("#define S_ISGID		0%04o\n", X_ISGID);
#else
	if (S_ISGID != X_ISGID) idperm = 0;
#endif
#ifndef S_ISVTX
	printf("#define S_ISVTX		0%04o\n", X_ISVTX);
#else
	if (S_ISVTX != X_ISVTX) idperm = 0;
#endif
#ifndef S_IRUSR
	printf("#define S_IRUSR		0%04o\n", X_IRUSR);
#else
	if (S_IRUSR != X_IRUSR) idperm = 0;
#endif
#ifndef S_IWUSR
	printf("#define S_IWUSR		0%04o\n", X_IWUSR);
#else
	if (S_IWUSR != X_IWUSR) idperm = 0;
#endif
#ifndef S_IXUSR
	printf("#define S_IXUSR		0%04o\n", X_IXUSR);
#else
	if (S_IXUSR != X_IXUSR) idperm = 0;
#endif
#ifndef S_IRGRP
	printf("#define S_IRGRP		0%04o\n", X_IRGRP);
#else
	if (S_IRGRP != X_IRGRP) idperm = 0;
#endif
#ifndef S_IWGRP
	printf("#define S_IWGRP		0%04o\n", X_IWGRP);
#else
	if (S_IWGRP != X_IWGRP) idperm = 0;
#endif
#ifndef S_IXGRP
	printf("#define S_IXGRP		0%04o\n", X_IXGRP);
#else
	if (S_IXGRP != X_IXGRP) idperm = 0;
#endif
#ifndef S_IROTH
	printf("#define S_IROTH		0%04o\n", X_IROTH);
#else
	if (S_IROTH != X_IROTH) idperm = 0;
#endif
#ifndef S_IWOTH
	printf("#define S_IWOTH		0%04o\n", X_IWOTH);
#else
	if (S_IWOTH != X_IWOTH) idperm = 0;
#endif
#ifndef S_IXOTH
	printf("#define S_IXOTH		0%04o\n", X_IXOTH);
#else
	if (S_IXOTH != X_IXOTH) idperm = 0;
#endif
#ifndef S_IRWXU
	printf("#define S_IRWXU		(S_IRUSR|S_IWUSR|S_IXUSR)\n");
#endif
#ifndef S_IRWXG
	printf("#define S_IRWXG		(S_IRGRP|S_IWGRP|S_IXGRP)\n");
#endif
#ifndef S_IRWXO
	printf("#define S_IRWXO		(S_IROTH|S_IWOTH|S_IXOTH)\n");
#endif
	printf("\n");
	if (idperm) printf("#define _S_IDPERM	1\n");
	if (idtype) printf("#define _S_IDTYPE	1\n");
	printf("\n");
#ifdef BUFFERSIZE
	n = BUFFERSIZE;
#else
#ifdef MAXBSIZE
	n = MAXBSIZE;
#else
#ifdef SBUFSIZE
	n = SBUFSIZE;
#else
#ifdef BUFSIZ
	n = BUFSIZ;
#else
	if (sizeof(char*) > 4) n = 8192;
	else if (sizeof(char*) < 4) n = 512;
	else n = 4096;
#endif
#endif
#endif
#endif
	printf("#define BUFFERSIZE	%u\n", n);
	printf("\n");
	return 0;
}
