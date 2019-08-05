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
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * tunefs: change layout parameters to an existing file system.
 */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ustat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <time.h>
#include <sys/mntent.h>

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/fs/ufs_fs.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#include <sys/ustat.h>
#include <sys/filio.h>
#include <sys/fs/ufs_filio.h>

extern offset_t llseek();

union {
	struct	fs sb;
	char pad[SBSIZE];
} sbun;
#define	sblock sbun.sb

int fi;
struct ustat ustatarea;
extern int	optind;
extern char	*optarg;

static void usage();
static void getsb(struct fs *, char *);
static void bwrite(diskaddr_t, char *, int);
static void fatal();
static int bread(diskaddr_t, char *, int);
static int isnumber(char *);

extern char *getfullrawname(), *getfullblkname();

static void
searchvfstab(char **specialp)
{
	FILE *vfstab;
	struct vfstab vfsbuf;
	char *blockspecial;

	blockspecial = getfullblkname(*specialp);
	if (blockspecial == NULL)
		blockspecial = *specialp;

	if ((vfstab = fopen(VFSTAB, "r")) == NULL) {
		fprintf(stderr, "%s: ", VFSTAB);
		perror("open");
	}
	while (getvfsent(vfstab, &vfsbuf) == 0)
		if (strcmp(vfsbuf.vfs_fstype, MNTTYPE_UFS) == 0)
			if ((strcmp(vfsbuf.vfs_mountp, *specialp) == 0) ||
			    (strcmp(vfsbuf.vfs_special, *specialp) == 0) ||
			    (strcmp(vfsbuf.vfs_special, blockspecial) == 0) ||
			    (strcmp(vfsbuf.vfs_fsckdev, *specialp) == 0)) {
				*specialp = strdup(vfsbuf.vfs_special);
				return;
			}
	fclose(vfstab);
}

static void
searchmnttab(char **specialp, char **mountpointp)
{
	FILE *mnttab;
	struct mnttab mntbuf;
	char *blockspecial;

	blockspecial = getfullblkname(*specialp);
	if (blockspecial == NULL)
		blockspecial = *specialp;

	if ((mnttab = fopen(MNTTAB, "r")) == NULL)
		return;
	while (getmntent(mnttab, &mntbuf) == 0)
		if (strcmp(mntbuf.mnt_fstype, MNTTYPE_UFS) == 0)
			if ((strcmp(mntbuf.mnt_mountp, *specialp) == 0) ||
			    (strcmp(mntbuf.mnt_special, blockspecial) == 0) ||
			    (strcmp(mntbuf.mnt_special, *specialp) == 0)) {
				*specialp = strdup(mntbuf.mnt_special);
				*mountpointp = strdup(mntbuf.mnt_mountp);
				return;
			}
	fclose(mnttab);
}

int
main(int argc, char *argv[])
{
	char *special, *name, *mountpoint = NULL;
	struct stat64 st;
	int i, mountfd;
	int Aflag = 0;
	char *chg[2];
	int	opt;
	struct fiotune fiotune;


	if (argc < 3)
		usage();
	special = argv[argc - 1];

	/*
	 * For performance, don't search mnttab unless necessary
	 */

	if (stat64(special, &st) >= 0) {
		/*
		 * If mounted directory, search mnttab for special
		 */
		if ((st.st_mode & S_IFMT) == S_IFDIR) {
			if (st.st_ino == UFSROOTINO)
				searchmnttab(&special, &mountpoint);
		/*
		 * If mounted device, search mnttab for mountpoint
		 */
		} else if ((st.st_mode & S_IFMT) == S_IFBLK ||
			    (st.st_mode & S_IFMT) == S_IFCHR) {
				if (ustat(st.st_rdev, &ustatarea) >= 0)
					searchmnttab(&special, &mountpoint);
		}
	}
	/*
	 * Doesn't appear to be mounted; take ``unmounted'' path
	 */
	if (mountpoint == NULL)
		searchvfstab(&special);

	if ((special = getfullrawname(special)) == NULL) {
		fprintf(stderr, "tunefs: malloc failed\n");
		exit(32);
	}

	if (*special == '\0') {
		fprintf(stderr, "tunefs: Could not find raw device for %s\n",
		    argv[argc -1]);
		exit(32);
	}

	if (stat64(special, &st) < 0) {
		fprintf(stderr, "tunefs: "); perror(special);
		exit(31+1);
	}

	/*
	 * If a mountpoint has been found then we will ioctl() the file
	 * system instead of writing to the file system's device
	 */
	/* ustat() ok because max number of UFS inodes can fit in ino_t */
	if (ustat(st.st_rdev, &ustatarea) >= 0) {
		if (mountpoint == NULL) {
			printf("%s is mounted, can't tunefs\n", special);
			exit(32);
		}
	} else
		mountpoint = NULL;

	if ((st.st_mode & S_IFMT) != S_IFBLK &&
	    (st.st_mode & S_IFMT) != S_IFCHR)
		fatal("%s: not a block or character device", special);
	getsb(&sblock, special);
	while ((opt = getopt(argc, argv, "o:m:e:d:a:AV")) != EOF) {
		switch (opt) {

		case 'A':
			Aflag++;
			continue;

		case 'a':
			name = "maximum contiguous block count";
			if (!isnumber(optarg))
				fatal("%s: %s must be >= 1", *argv, name);
			i = atoi(optarg);
			if (i < 1)
				fatal("%s: %s must be >= 1", *argv, name);
			fprintf(stdout, "%s changes from %d to %d\n",
				name, sblock.fs_maxcontig, i);
			sblock.fs_maxcontig = i;
			continue;

		case 'd':
			sblock.fs_rotdelay = 0;
			continue;

		case 'e':
			name =
			    "maximum blocks per file in a cylinder group";
			if (!isnumber(optarg))
				fatal("%s: %s must be >= 1", *argv, name);
			i = atoi(optarg);
			if (i < 1)
				fatal("%s: %s must be >= 1", *argv, name);
			fprintf(stdout, "%s changes from %d to %d\n",
				name, sblock.fs_maxbpg, i);
			sblock.fs_maxbpg = i;
			continue;

		case 'm':
			name = "minimum percentage of free space";
			if (!isnumber(optarg))
				fatal("%s: bad %s", *argv, name);
			i = atoi(optarg);
			if (i < 0 || i > 99)
				fatal("%s: bad %s", *argv, name);
			fprintf(stdout,
				"%s changes from %d%% to %d%%\n",
				name, sblock.fs_minfree, i);
			sblock.fs_minfree = i;
			continue;

		case 'o':
			name = "optimization preference";
			chg[FS_OPTSPACE] = "space";
			chg[FS_OPTTIME] = "time";
			if (strcmp(optarg, chg[FS_OPTSPACE]) == 0)
				i = FS_OPTSPACE;
			else if (strcmp(optarg, chg[FS_OPTTIME]) == 0)
				i = FS_OPTTIME;
			else
			fatal("%s: bad %s (options are `space' or `time')",
					optarg, name);
			if (sblock.fs_optim == i) {
				fprintf(stdout,
					"%s remains unchanged as %s\n",
					name, chg[i]);
				continue;
			}
			fprintf(stdout,
				"%s changes from %s to %s\n",
				name, chg[sblock.fs_optim], chg[i]);
			sblock.fs_optim = i;
			continue;

		case 'V':
			{
				char	*opt_text;
				int	opt_count;

				(void) fprintf(stdout, "tunefs -F ufs ");
				for (opt_count = 1; opt_count < argc;
				    opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) fprintf(stdout, " %s ",
						    opt_text);
				}
				(void) fprintf(stdout, "\n");
			}
			break;

		default:
			usage();
		}
	}
	if ((argc - optind) != 1)
		usage();
	if (mountpoint) {
		mountfd = open(mountpoint, O_RDONLY);
		if (mountfd == -1) {
			perror(mountpoint);
			fprintf(stderr,
				"tunefs: can't tune %s\n", mountpoint);
			exit(32);
		}
		fiotune.maxcontig = sblock.fs_maxcontig;
		fiotune.rotdelay = sblock.fs_rotdelay;
		fiotune.maxbpg = sblock.fs_maxbpg;
		fiotune.minfree = sblock.fs_minfree;
		fiotune.optim = sblock.fs_optim;
		if (ioctl(mountfd, _FIOTUNE, &fiotune) == -1) {
			perror(mountpoint);
			fprintf(stderr,
				"tunefs: can't tune %s\n", mountpoint);
			exit(32);
		}
		close(mountfd);
	} else {
		bwrite((diskaddr_t)SBLOCK, (char *)&sblock, SBSIZE);

		if (Aflag)
			for (i = 0; i < sblock.fs_ncg; i++)
				bwrite(fsbtodb(&sblock, cgsblock(&sblock, i)),
				    (char *)&sblock, SBSIZE);
	}

	close(fi);
	return (0);
}

void
usage()
{
	fprintf(stderr, "ufs usage: tunefs tuneup-options special-device\n");
	fprintf(stderr, "where tuneup-options are:\n");
	fprintf(stderr, "\t-a maximum contiguous blocks\n");
	fprintf(stderr, "\t-d rotational delay between contiguous blocks\n");
	fprintf(stderr, "\t-e maximum blocks per file in a cylinder group\n");
	fprintf(stderr, "\t-m minimum percentage of free space\n");
	fprintf(stderr, "\t-o optimization preference (`space' or `time')\n");
	exit(31+2);
}

void
getsb(struct fs *fs, char *file)
{

	fi = open64(file, O_RDWR);
	if (fi < 0) {
		fprintf(stderr, "Cannot open ");
		perror(file);
		exit(31+3);
	}
	if (bread((diskaddr_t)SBLOCK, (char *)fs, SBSIZE)) {
		fprintf(stderr, "Bad super block ");
		perror(file);
		exit(31+4);
	}
	if ((fs->fs_magic != FS_MAGIC) && (fs->fs_magic != MTB_UFS_MAGIC)) {
		fprintf(stderr, "%s: bad magic number\n", file);
		exit(31+5);
	}
	if (fs->fs_magic == FS_MAGIC &&
	    (fs->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    fs->fs_version != UFS_VERSION_MIN)) {
		fprintf(stderr, "%s: unrecognized ufs version: %d\n", file,
		    fs->fs_version);
		exit(31+5);
	}
	if (fs->fs_magic == MTB_UFS_MAGIC &&
	    (fs->fs_version > MTB_UFS_VERSION_1 ||
	    fs->fs_version < MTB_UFS_VERSION_MIN)) {
		fprintf(stderr, "%s: unrecognized ufs version: %d\n", file,
		    fs->fs_version);
		exit(31+5);
	}
}

void
bwrite(diskaddr_t blk, char *buf, int size)
{
	if (llseek(fi, (offset_t)blk * DEV_BSIZE, 0) < 0) {
		perror("FS SEEK");
		exit(31+6);
	}
	if (write(fi, buf, size) != size) {
		perror("FS WRITE");
		exit(31+7);
	}
}

int
bread(diskaddr_t bno, char *buf, int cnt)
{
	int	i;

	if (llseek(fi, (offset_t)bno * DEV_BSIZE, 0) < 0) {
		fprintf(stderr, "bread: ");
		perror("llseek");
		return (1);
	}
	if ((i = read(fi, buf, cnt)) != cnt) {
		perror("read");
		for (i = 0; i < sblock.fs_bsize; i++)
			buf[i] = 0;
		return (1);
	}
	return (0);
}

/* VARARGS1 */
void
fatal(char *fmt, char *arg1, char *arg2)
{
	fprintf(stderr, "tunefs: ");
	fprintf(stderr, fmt, arg1, arg2);
	putc('\n', stderr);
	exit(31+10);
}


int
isnumber(char *s)
{
	int c;

	while (c = *s++)
		if (c < '0' || c > '9')
			return (0);
	return (1);
}
