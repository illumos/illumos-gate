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
 * Copyright cw1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*      @(#)dlist_proto.c 1.1 90/01/22 SMI      */
#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

char token[BUFSIZ];

mkdlist_proto()
{
}

#ifdef notskip
descend()
{
	int ibc = 0;
	int i, f, c;

	getstr();
	in.i_mode = gmode(token[0], "-bcd", IFREG, IFBLK, IFCHR, IFDIR);
	in.i_mode |= gmode(token[1], "-u", 0, ISUID, 0, 0);
	in.i_mode |= gmode(token[2], "-g", 0, ISGID, 0, 0);
	for (i = 3; i < 6; i++) {
		c = token[i];
		if (c < '0' || c > '7') {
			printf("%c/%s: bad octal mode digit\n", c, token);
			errs++;
			c = 0;
		}
		in.i_mode |= (c-'0')<<(15-3*i);
	}
	in.i_uid = getnum(); in.i_gid = getnum();
	for (i = 0; i < fs->fs_bsize; i++)
		buf[i] = 0;
	for (i = 0; i < NINDIR(fs); i++)
		ib[i] = (daddr_t)0;
	in.i_nlink = 1;
	in.i_size = 0;
	for (i = 0; i < NDADDR; i++)
		in.i_db[i] = (daddr_t)0;
	for (i = 0; i < NIADDR; i++)
		in.i_ib[i] = (daddr_t)0;
	if (par != (struct inode *)0) {
		ialloc(&in);
	} else {
		par = &in;
		i = itod(fs, ROOTINO);
		rdfs(fsbtodb(fs, i), fs->fs_bsize, (char *)inos);
		dip = &inos[ROOTINO % INOPB(fs)];
		in.i_number = ROOTINO;
		in.i_nlink = dip->di_nlink;
		in.i_size = dip->di_size;
		in.i_db[0] = dip->di_db[0];
		rdfs(fsbtodb(fs, in.i_db[0]), fs->fs_bsize, buf);
	}

	switch (in.i_mode&IFMT) {

	case IFREG:
		getstr();
		f = open(token, 0);
		if (f < 0) {
			printf("%s: cannot open\n", token);
			errs++;
			break;
		}
		while ((i = read(f, buf, (int)fs->fs_bsize)) > 0) {
			in.i_size += i;
			newblk(buf, &ibc, ib, (int)blksize(fs, &in, ibc));
		}
		close(f);
		break;

	case IFBLK:
	case IFCHR:
		/*
		 * special file
		 * content is maj/min types
		 */

		i = getnum() & 0377;
		f = getnum() & 0377;
		in.i_rdev = (i << 8) | f;
		break;

	case IFDIR:
		/*
		 * directory
		 * put in extra links
		 * call recursively until
		 * name of "$" found
		 */

		if (in.i_number != ROOTINO) {
			par->i_nlink++;
			in.i_nlink++;
			entry(&in, in.i_number, ".", buf);
			entry(&in, par->i_number, "..", buf);
		}
		for (;;) {
			getstr();
			if (token[0]=='$' && token[1]=='\0')
				break;
			entry(&in, (ino_t)(ino+1), token, buf);
			descend(&in);
		}
		if (in.i_number != ROOTINO)
			newblk(buf, &ibc, ib, (int)blksize(fs, &in, 0));
		else
			wtfs(fsbtodb(fs, in.i_db[0]), (int)fs->fs_bsize, buf);
		break;
	}
	iput(&in, &ibc, ib);
}

/*ARGSUSED*/
gmode(c, s, m0, m1, m2, m3)
	char c, *s;
{
	int i;

	for (i = 0; s[i]; i++)
		if (c == s[i])
			return((&m0)[i]);
	printf("%c/%s: bad mode\n", c, token);
	errs++;
	return(0);
}

long
getnum()
{
	int i, c;
	long n;

	getstr();
	n = 0;
	i = 0;
	for (i = 0; c=token[i]; i++) {
		if (c<'0' || c>'9') {
			printf("%s: bad number\n", token);
			errs++;
			return((long)0);
		}
		n = n*10 + (c-'0');
	}
	return(n);
}

getstr()
{
	int i, c;

loop:
	switch (c = getc(proto)) {

	case ' ':
	case '\t':
	case '\n':
		goto loop;

	case EOF:
		printf("Unexpected EOF\n");
		exit(31+1);

	case ':':
		while (getc(proto) != '\n')
			;
		goto loop;

	}
	i = 0;
	do {
		token[i++] = c;
		c = getc(proto);
	} while (c != ' ' && c != '\t' && c != '\n' && c != '\0');
	token[i] = 0;
}

#endif
