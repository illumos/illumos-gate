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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/
/*	Copyright (c) 1999 by Sun Microsystems, Inc. */
/*	All rights reserved. */


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.18	*/
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/fs/s5ino.h>
#include <sys/stat.h>
#include <sys/fs/s5param.h>
#include <sys/fs/s5filsys.h>
#include <sys/fs/s5macros.h>
#include <sys/sysmacros.h>
#include <pwd.h>
#include <fcntl.h>
#include "acctdef.h"

#ifndef Fs2BLK
#define Fs2BLK	0
#endif


#define BLOCK		512	/* Block size for reporting */

#define		NINODE		2048

struct	filsys	sblock;
struct	dinode	dinode[NINODE];

int	VERBOSE = 0;
FILE	*ufd = 0;
int	index;
unsigned ino, nfiles;

struct acct  {
	uid_t	uid;
	long	usage;
	char	name [NSZ+1];
} userlist[MAXUSERS];

char	*ignlist[MAXIGN];
int	igncnt = {0};

char	*cmd;

unsigned hash();
main(argc, argv)
int argc;
char **argv;
{
	extern	int	optind;
	extern	char	*optarg;
	register c;
	register FILE	*fd;
	register	rfd;
	struct	stat	sb;
	int	sflg = {FALSE};
	char 	*pfile = NULL;
	int	errfl = {FALSE};

	cmd = argv[0];
	while((c = getopt(argc, argv, "vu:p:si:")) != EOF) switch(c) {
	case 's':
		sflg = TRUE;
		break;
	case 'v':
		VERBOSE = 1;
		break;
	case 'i':
		ignore(optarg);
		break;
	case 'u':
		ufd = fopen(optarg, "a");
		break;
	case 'p':
		pfile = optarg;
		break;
	case '?':
		errfl++;
		break;
	}
	if(errfl) {
		fprintf(stderr, "Usage: %s [-sv] [-p pw_file] [-u file] [-i ignlist] [file ...]\n", cmd);
		exit(10);
	}

	hashinit();
	if(sflg == TRUE) {
		if(optind == argc){
			adduser(stdin);
		} else {
			for( ; optind < argc; optind++) {
				if( (fd = fopen(argv[optind], "r")) == NULL) {
					fprintf(stderr, "%s: Cannot open %s\n", cmd, argv[optind]);
					continue;
				}
				adduser(fd);
				fclose(fd);
			}
		}
	}
	else {
		setup(pfile);
		for( ; optind < argc; optind++) {
			if( (rfd = open(argv[optind], O_RDONLY)) < 0) {
				fprintf(stderr, "%s: Cannot open %s\n", cmd, argv[optind]);
				continue;
			}
			if(fstat(rfd, &sb) >= 0){
				if ( (sb.st_mode & S_IFMT) == S_IFCHR ||
				     (sb.st_mode & S_IFMT) == S_IFBLK ) {
					ilist(argv[optind], rfd);
				} else {
					fprintf(stderr, "%s: %s is not a special file -- ignored\n", cmd, argv[optind]);
				}
			} else {
				fprintf(stderr, "%s: Cannot stat %s\n", cmd, argv[optind]);
			}
			close(rfd);
		}
	}
	output();
	exit(0);
}

adduser(fd)
register FILE	*fd;
{
	uid_t	usrid;
	long	blcks;
	char	login[NSZ+10];

	while(fscanf(fd, "%ld %s %ld\n", &usrid, login, &blcks) == 3) {
		if( (index = hash(usrid)) == FAIL) return(FAIL);
		if(userlist[index].uid == UNUSED) {
			userlist[index].uid = usrid;
			(void) strncpy(userlist[index].name, login, NSZ);
		}
		userlist[index].usage += blcks;
	}
}

ilist(file, fd)
char	*file;
register fd;
{
	register dev_t	dev;
	register i, j;
	int	inopb, inoshift, fsinos, bsize;

	if (fd < 0 ) {
		return (FAIL);
	}

	sync();

	/* Fake out block size to be 512 */
	dev = 512;

	/* Read in super-block of filesystem */
	bread(fd, 1, &sblock, sizeof(sblock), dev);

	/* Check for filesystem names to ignore */
	if(!todo(sblock.s_fname))
		return;
	/* Check for size of filesystem to be 512 or 1K */
	if (sblock.s_magic == FsMAGIC )
		switch (sblock.s_type) {
			case Fs1b:
				bsize = 512;
				inoshift = 3;
				fsinos = (((2)&~07)+1);
				break;
			case Fs2b:
				bsize = 1024;
				inoshift = 4;
				fsinos = (((2)&~017)+1);
				break;
			case Fs4b:
				bsize = 2048;
				inoshift = 5;
				fsinos = (((2)&~037)+1);
				break;
		}

	inopb = bsize/sizeof(struct dinode);


	nfiles = (sblock.s_isize-2) * inopb;
	dev = (dev_t)bsize;

	/* Determine physical block 2 */
	i = (daddr_t)(((unsigned)(fsinos)+(2*inopb-1)) >> inoshift);

	/* Start at physical block 2, inode list */
	for (ino = 0; ino < nfiles; i += NINODE/inopb) {
		bread(fd, i, dinode, sizeof(dinode), dev);
		for (j = 0; j < NINODE && ino++ < nfiles; j++)
			if (dinode[j].di_mode & S_IFMT)
				if(count(j, dev) == FAIL) {
					if(VERBOSE)
						fprintf(stderr,"BAD UID: file system = %s, inode = %u, uid = %ld\n",
					    	file, ino, dinode[j].di_uid);
					if(ufd)
						fprintf(ufd, "%s %u %ld\n", file, ino, dinode[j].di_uid);
				}
	}
	return (0);
}

ignore(str)
register char	*str;
{
	char	*skip();

	for( ; *str && igncnt < MAXIGN; str = skip(str), igncnt++)
		ignlist[igncnt] = str;
	if(igncnt == MAXIGN) {
		fprintf(stderr, "%s: ignore list overflow. Recompile with larger MAXIGN\n", cmd);
	}
}
bread(fd, bno, buf, cnt, dev)
register fd;
register unsigned bno;
register struct  dinode  *buf;
register dev_t dev;
{
	lseek(fd, (long)bno*dev, 0);
	if (read(fd, buf, cnt) != cnt)
	{
		fprintf(stderr, "%s: read error %u\n", cmd, bno);
		exit(1);
	}
}

count(j, dev)
register j;
register dev_t dev;
{
	long	blocks();

	if ( dinode[j].di_nlink == 0 || dinode[j].di_mode == 0 )
		return(SUCCEED);
	if( (index = hash(dinode[j].di_uid)) == FAIL || userlist[index].uid == UNUSED )
		return (FAIL);
	userlist[index].usage += blocks(j, dev);
	return (SUCCEED);
}


output()
{
	for (index=0; index < MAXUSERS ; index++)
		if ( userlist[index].uid != UNUSED && userlist[index].usage != 0 )
			printf("%ld	%s	%ld\n",
			    userlist[index].uid,
			    userlist[index].name,
			    userlist[index].usage);
}

#define SNGLIND(dev)	(dev/sizeof(daddr_t))
#define DBLIND(dev)	((dev/sizeof(daddr_t))*(dev/sizeof(daddr_t)))
#define	TRPLIND(dev)	((dev/sizeof(daddr_t))*(dev/sizeof(daddr_t))*(dev/sizeof(daddr_t)))

long
blocks(j, dev)
register int j;
register dev_t dev;
{
	register long blks;

	blks = (dinode[j].di_size + dev - 1)/dev;
	if(blks > 10) {
		blks += (blks-10+SNGLIND(dev)-1)/SNGLIND(dev);
		blks += (blks-10-SNGLIND(dev)+DBLIND(dev)-1)/DBLIND(dev);
		blks += (blks-10-SNGLIND(dev)-DBLIND(dev)+TRPLIND(dev)-1)/TRPLIND(dev);
	}
	if(dev != BLOCK) {
		blks = (blks+BLOCK/dev)*(dev/BLOCK);
	}
	return(blks);
}

unsigned
hash(j)
uid_t j;
{
	register unsigned start;
	register unsigned circle;
	circle = start = (unsigned)j % MAXUSERS;
	do
	{
		if ( userlist[circle].uid == j || userlist[circle].uid == UNUSED )
			return (circle);
		circle = (circle + 1) % MAXUSERS;
	} while ( circle != start);
	return (FAIL);
}

hashinit() {
	for(index=0; index < MAXUSERS ; index++)
	{
		userlist[index].uid = UNUSED;
		userlist[index].usage = 0;
		userlist[index].name[0] = '\0';
	}
}


static FILE *pwf = NULL;

setup(pfile)
char	*pfile;
{
	register struct passwd	*pw;
	void end_pwent();
	struct passwd *	(*getpw)();
	void	(*endpw)();

	if (pfile) {
		if( !stpwent(pfile)) {
			fprintf(stderr, "%s: Cannot open %s\n", cmd, pfile);
			exit(5);
		}
		getpw = fgetpwent;
		endpw = end_pwent;
	} else {
		setpwent();
		getpw = getpwent;
		endpw = endpwent;
	}
	while ( (pw=getpw(pwf)) != NULL )
	{
		if ( (index=hash(pw->pw_uid)) == FAIL )
		{
			fprintf(stderr,"%s: INCREASE SIZE OF MAXUSERS\n", cmd);
			return (FAIL);
		}
		if ( userlist[index].uid == UNUSED )
		{
			userlist[index].uid = pw->pw_uid;
			(void) strncpy(userlist[index].name, pw->pw_name, NSZ);
		}
	}

	endpw();
}

todo(fname)
register char	*fname;
{
	register	i;

	for(i = 0; i < igncnt; i++) {
		if(strncmp(fname, ignlist[i], 6) == 0) return(FALSE);
	}
	return(TRUE);
}

char	*
skip(str)
register char	*str;
{
	while(*str) {
		if(*str == ' ' ||
		    *str == ',') {
			*str = '\0';
			str++;
			break;
		}
		str++;
	}
	return(str);
}


stpwent(pfile)
register char *pfile;
{
	if(pwf == NULL)
		pwf = fopen(pfile, "r");
	else
		rewind(pwf);
	return(pwf != NULL);
}

void
end_pwent()
{
	if(pwf != NULL) {
		(void) fclose(pwf);
		pwf = NULL;
	}
}

