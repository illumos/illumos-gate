/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Label a file system volume.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <locale.h>

#define	bcopy(f, t, n)    (void) memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/vnode.h>
#include <fcntl.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>

static void usage();
static void label(char *, char *, char *);

static union sbtag {
	char		dummy[SBSIZE];
	struct fs	sblk;
} sb_un, altsb_un;

#define	sblock sb_un.sblk
#define	altsblock altsb_un.sblk

extern int	optind;
extern char	*optarg;

int
main(int argc, char *argv[])
{
	int		opt;
	char		*special = NULL;
	char		*fsname = NULL;
	char		*volume = NULL;

	while ((opt = getopt(argc, argv, "o:")) != EOF) {
		switch (opt) {

		case 'o':	/* specific options (none defined yet) */
			break;

		case '?':
			usage();
		}
	}
	if (optind > (argc - 1)) {
		usage();
	}
	argc -= optind;
	argv = &argv[optind];
	special = argv[0];
	if (argc > 1) {
		fsname = argv[1];
		if (strlen(fsname) > 6) {
			(void) fprintf(stderr, gettext("labelit: "));
			(void) fprintf(stderr,
		gettext("fsname can not be longer than 6 characters\n"));
			exit(31+1);
		}
	}
	if (argc > 2) {
		volume = argv[2];
		if (strlen(volume) > 6) {
			(void) fprintf(stderr, gettext("labelit: "));
			(void) fprintf(stderr,
		gettext("volume can not be longer than 6 characters\n"));
			exit(31+1);
		}
	}
	label(special, fsname, volume);
	return	(0);
}

void
usage()
{

	(void) fprintf(stderr, gettext(
	"ufs usage: labelit [-F ufs] [gen opts] special [fsname volume]\n"));
	exit(31+1);
}

void
label(char *special, char *fsname, char *volume)
{
	int	f;
	int	blk;
	int	i;
	char	*p;
	offset_t offset;
	struct	fs	*fsp, *altfsp;

	if (fsname == NULL) {
		f = open64(special, O_RDONLY);
	} else {
		f = open64(special, O_RDWR);
	}
	if (f < 0) {
		(void) fprintf(stderr, gettext("labelit: "));
		perror("open");
		exit(31+1);
	}
	if (llseek(f, (offset_t)SBLOCK * DEV_BSIZE, 0) < 0) {
		(void) fprintf(stderr, gettext("labelit: "));
		perror("llseek");
		exit(31+1);
	}
	if (read(f, &sblock, SBSIZE) != SBSIZE) {
		(void) fprintf(stderr, gettext("labelit: "));
		perror("read");
		exit(31+1);
	}
	if ((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) {
		(void) fprintf(stderr, gettext("labelit: "));
		(void) fprintf(stderr,
			gettext("bad super block magic number\n"));
		exit(31+1);
	}
	if ((sblock.fs_magic == FS_MAGIC) &&
	    ((sblock.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2) &&
	    (sblock.fs_version != UFS_VERSION_MIN))) {
		(void) fprintf(stderr, gettext("labelit: "));
		(void) fprintf(stderr,
			gettext("unrecognized UFS format version: %d\n"),
			    sblock.fs_version);
		exit(31+1);
	}
	if ((sblock.fs_magic == MTB_UFS_MAGIC) &&
	    ((sblock.fs_version > MTB_UFS_VERSION_1) ||
	    (sblock.fs_version < MTB_UFS_VERSION_MIN))) {
		(void) fprintf(stderr, gettext("labelit: "));
		(void) fprintf(stderr,
			gettext("unrecognized UFS format version: %d\n"),
			    sblock.fs_version);
		exit(31+1);
	}
	fsp = &sblock;

	/*
	 * Is block layout available?
	 */

	if (sblock.fs_cpc <= 0 && (fsname || volume)) {
		(void) fprintf(stderr, gettext("labelit: "));
		(void) fprintf(stderr,
	gettext("insufficient superblock space for file system label\n"));
		return;
	}

	/*
	 * calculate the available blocks for each rotational position
	 */
	blk = sblock.fs_spc * sblock.fs_cpc / NSPF(&sblock);
	for (i = 0; i < blk; i += sblock.fs_frag)
		/* void */;
	i -= sblock.fs_frag;
	blk = i / sblock.fs_frag;
	p = (char *)&(fs_rotbl(fsp)[blk]);

	if (fsname != NULL) {
		for (i = 0; i < 14; i++)
			p[i] = '\0';
		for (i = 0; (i < 6) && (fsname[i]); i++, p++)
			*p = fsname[i];
		p++;
	}
	if (volume != NULL) {
		for (i = 0; (i < 6) && (volume[i]); i++, p++)
			*p = volume[i];
	}
	if (fsname != NULL) {
		if (llseek(f, (offset_t)SBLOCK * DEV_BSIZE, 0) < 0) {
			(void) fprintf(stderr, gettext("labelit: "));
			perror("llseek");
			exit(31+1);
		}
		if (write(f, &sblock, SBSIZE) != SBSIZE) {
			(void) fprintf(stderr, gettext("labelit: "));
			perror("write");
			exit(31+1);
		}
		for (i = 0; i < sblock.fs_ncg; i++) {
			/*
			 * In the case of multi-terabyte ufs file
			 * systems, only the first ten and last ten
			 * cylinder groups have copies of the superblock.
			 */
			if (sblock.fs_magic == MTB_UFS_MAGIC &&
			    sblock.fs_ncg > 20 &&
			    (i >= 10 && i < sblock.fs_ncg - 10))
				continue;
			offset =
			    (offset_t)cgsblock(&sblock, i) * sblock.fs_fsize;
			if (llseek(f, offset, 0) < 0) {
				(void) fprintf(stderr, gettext("labelit: "));
				perror("lseek");
				exit(31+1);
			}
			altfsp = &altsblock;
			if (read(f, &altsblock, SBSIZE) != SBSIZE) {
				(void) fprintf(stderr, gettext("labelit: "));
				perror("read");
				exit(31+1);
			}
			if ((altsblock.fs_magic != FS_MAGIC) &&
			    (altsblock.fs_magic != MTB_UFS_MAGIC)) {
			    (void) fprintf(stderr, gettext("labelit: "));
			    (void) fprintf(stderr,
		gettext("bad alternate super block(%i) magic number\n"), i);
				exit(31+1);
			}
			if ((altsblock.fs_magic == FS_MAGIC) &&
			    ((altsblock.fs_version !=
				UFS_EFISTYLE4NONEFI_VERSION_2) &&
			    (altsblock.fs_version != UFS_VERSION_MIN))) {
				(void) fprintf(stderr, gettext("labelit: "));
				(void) fprintf(stderr,
		gettext("bad alternate super block UFS format version: %d\n"),
					    altsblock.fs_version);
				exit(31+1);
			}
			if ((altsblock.fs_magic == MTB_UFS_MAGIC) &&
			    ((altsblock.fs_version > MTB_UFS_VERSION_1) ||
			    (altsblock.fs_version < MTB_UFS_VERSION_MIN))) {
				(void) fprintf(stderr, gettext("labelit: "));
				(void) fprintf(stderr,
		gettext("bad alternate super block UFS format version: %d\n"),
					    altsblock.fs_version);
				exit(31+1);
			}
			bcopy((char *)&(fs_rotbl(fsp)[blk]),
				(char *)&(fs_rotbl(altfsp)[blk]), 14);

			if (llseek(f, offset, 0) < 0) {
				(void) fprintf(stderr, gettext("labelit: "));
				perror("llseek");
			exit(31+1);
			}
			if (write(f, &altsblock, SBSIZE) != SBSIZE) {
				(void) fprintf(stderr, gettext("labelit: "));
				perror("write");
				exit(31+1);
			}
		}
	}
	p = (char *)&(fs_rotbl(fsp)[blk]);
	(void) fprintf(stderr, gettext("fsname: "));
	for (i = 0; (i < 6) && (*p); i++, p++) {
		(void) fprintf(stderr, "%c", *p);
	}
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, gettext("volume: "));
	p++;
	for (i = 0; (i < 6); i++, p++) {
		(void) fprintf(stderr, "%c", *p);
	}
	(void) fprintf(stderr, "\n");
}
