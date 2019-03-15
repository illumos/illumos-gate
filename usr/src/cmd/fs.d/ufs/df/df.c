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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 * df
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/fs/ufs_fs.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#include <sys/mnttab.h>
#include <sys/mkdev.h>
#include <locale.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>

extern char	*getenv();
extern char	*getcwd();
extern char	*realpath();
extern off_t	lseek();

/*
 * Raw name to block device name translation function.
 * This comes from libadm.
 */
extern char	*getfullblkname();

static  void		usage(), pheader();
static  char		*mpath(char *);
static  char		*zap_chroot(char *);
static  char		*pathsuffix(char *, char *);
static  char		*xmalloc(unsigned int);
static  int		chroot_stat(char *, int (*)(), char *, char **);
static  int		bread(char *, int, daddr_t, char *, int);
static  int		subpath(char *, char *);
static	int		abspath(char *, char *, char *);
static  void		show_inode_usage();
static  void		dfreedev(char *);
static  void		dfreemnt(char *, struct mnttab *);
static  void		print_totals();
static  void		print_itotals();
static  void		print_statvfs(struct statvfs64 *);
static  int		mdev(char *, struct mnttab **);
static struct mntlist	*mkmntlist();
static struct mnttab	*mntdup(struct mnttab *mnt);
static struct mntlist	*findmntent(char *, struct stat64 *, struct mntlist *);

#define	bcopy(f, t, n)	memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#define	dbtok(x, b) \
	((b) < (fsblkcnt64_t)1024 ? \
	(x) / ((fsblkcnt64_t)1024 / (b)) : (x) * ((b) / (fsblkcnt64_t)1024))

int	aflag = 0;		/* even the uninteresting ones */
int	bflag = 0;		/* print only number of kilobytes free */
int	eflag = 0;		/* print only number of file entries free */
int	gflag = 0;		/* print entire statvfs structure */
int	hflag = 0;		/* don't print header */
int	iflag = 0;		/* information for inodes */
int	nflag = 0;		/* print VFStype name */
int	tflag = 0;		/* print totals */
int	errflag = 0;
int	errcode = 0;
char	*typestr = "ufs";
fsblkcnt64_t	t_totalblks, t_avail, t_free, t_used, t_reserved;
int	t_inodes, t_iused, t_ifree;

/*
 * cached information recording previous chroot history.
 */
static	char	*chrootpath;

extern	int	optind;
extern	char	*optarg;

union {
	struct fs iu_fs;
	char dummy[SBSIZE];
} sb;
#define	sblock	sb.iu_fs

/*
 * This structure is used to chain mntent structures into a list
 * and to cache stat information for each member of the list.
 */
struct mntlist {
	struct mnttab	*mntl_mnt;
	struct mntlist	*mntl_next;
	dev_t		mntl_dev;
	int		mntl_devvalid;
};

char *subopts [] = {
#define	A_FLAG		0
	"a",
#define	I_FLAG		1
	"i",
	NULL
};

int
main(int argc, char *argv[])
{
	struct mnttab		mnt;
	int			opt;
	char			*suboptions, *value;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, "beghkno:t")) != EOF) {
		switch (opt) {

		case 'b':	/* print only number of kilobytes free */
			bflag++;
			break;

		case 'e':
			eflag++; /* print only number of file entries free */
			iflag++;
			break;

		case 'g':
			gflag++;
			break;

		case 'n':
			nflag++;
			break;

		case 'k':
			break;

		case 'h':
			hflag++;
			break;

		case 'o':
			/*
			 * ufs specific options.
			 */
			suboptions = optarg;
			while (*suboptions != '\0') {
				switch (getsubopt(&suboptions,
				    subopts, &value)) {

				case I_FLAG:	/* information for inodes */
					iflag++;
					break;

				default:
					usage();
				}
			}
			break;

		case 't':		/* print totals */
			tflag++;
			break;

		case 'V':		/* Print command line */
			{
				char			*opt_text;
				int			opt_count;

				(void) fprintf(stdout, "df -F ufs ");
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

		case '?':
			errflag++;
		}
	}
	if (errflag)
		usage();
	if (gflag && iflag) {
		printf(gettext("df: '-g' and '-o i' are mutually exclusive\n"));
		exit(1);
	}
	if (bflag || eflag)
		tflag = 0;

	/*
	 * Cache CHROOT information for later use; assume that $CHROOT matches
	 * the cumulative arguments given to chroot calls.
	 */
	chrootpath = getenv("CHROOT");
	if (chrootpath != NULL && strcmp(chrootpath, "/") == 0)
		chrootpath = NULL;

	if (argc <= optind) {
		/*
		 * Take this path when "/usr/lib/fs/ufs/df" is specified, and
		 * there are no mountpoints specified.
		 * E.g., these command lines take us down this path
		 *	/usr/lib/fs/ufs/df -o i
		 *	/usr/lib/fs/ufs/df
		 */
		FILE *mtabp;

		if ((mtabp = fopen(MNTTAB, "r")) == NULL) {
			(void) fprintf(stderr, "df: ");
			perror(MNTTAB);
			exit(1);
		}
		pheader();
		while (getmntent(mtabp, &mnt) == 0) {
			if (strcmp(typestr, mnt.mnt_fstype) != 0) {
				continue;
			}
			dfreemnt(mnt.mnt_mountp, &mnt);
		}
		if (tflag)
			if (iflag)
				print_itotals();
			else
				print_totals();
		(void) fclose(mtabp);
	} else {
		int i;
		struct mntlist *mntl;
		struct stat64    *argstat;
		char **devnames;
		char *cp;

		/* Arguments are processed till optind, adjust the pointers */
		argv += optind;
		argc -= optind;

		/*
		 * Obtain stat64 information for each argument before
		 * constructing the list of mounted file systems.  This
		 * ordering forces the automounter to establish any
		 * mounts required to access the arguments, so that the
		 * corresponding mount table entries will exist when
		 * we look for them.
		 */
		argstat = (struct stat64 *)xmalloc(argc * sizeof (*argstat));
		devnames = (char **)xmalloc(argc * sizeof (char *));
		for (i = 0; i < argc; i++) {

			/*
			 * Given a raw device name, get the block device name
			 */
			cp = getfullblkname(argv[i]);
			if (cp == NULL || *cp == '\0') {
				if (cp != NULL)
					free(cp);
				cp = strdup(argv[i]);

				if (cp == NULL) {
					int j;

					fprintf(stderr, gettext(
					"df: memory allocation failure\n"));

					for (j = 0; j < i; j++)
						free(devnames[j]);
					free(devnames);
					free(argstat);
					exit(1);
				}
			}
			if (stat64(cp, &argstat[i]) < 0) {
				errcode = errno;
				/*
				 * Mark as no longer interesting.
				 */
				argv[i] = NULL;
				devnames[i] = NULL;
				free(cp);
			} else {
				devnames[i] = cp;
			}
		}

		pheader();
		aflag++;
		/*
		 * Construct the list of mounted file systems.
		 */
		mntl = mkmntlist();

		/*
		 * Iterate through the argument list, reporting on each one.
		 */
		for (i = 0; i < argc; i++) {
			struct mntlist *mlp;
			int isblk;

			/*
			 * Skip if we've already determined that we can't
			 * process it.
			 */
			if (argv[i] == NULL)
				continue;

			/*
			 * If the argument names a device, report on the file
			 * system associated with the device rather than on
			 * the one containing the device's directory entry
			 */
			cp = devnames[i];
			if ((isblk = (argstat[i].st_mode&S_IFMT) == S_IFBLK) ||
			    (argstat[i].st_mode & S_IFMT) == S_IFCHR) {
				if (isblk && strcmp(mpath(cp), "") != 0) {
					struct mnttab *mp;
					if (mdev(cp, &mp))
						return (1);
					dfreemnt(mp->mnt_mountp, mp);
				} else {
					dfreedev(cp);
				}
				free(cp);
				devnames[i] = NULL;
				continue;
			}

			/*
			 * Get this argument's corresponding mount table
			 * entry.
			 */
			mlp = findmntent(cp, &argstat[i], mntl);
			free(cp);
			devnames[i] = NULL;

			if (mlp == NULL) {
				(void) fprintf(stderr,
				gettext("Could not find mount point for %s\n"),
				    argv[i]);
				continue;
			}

			dfreemnt(mlp->mntl_mnt->mnt_mountp, mlp->mntl_mnt);
		}
		free(devnames);
		free(argstat);
	}
	return (0);
}

void
pheader()
{
	if (hflag)
		return;
	if (nflag)
		(void) printf(gettext("VFStype name - ufs\n"));
	if (iflag) {
		if (eflag)
			/*
			 * TRANSLATION_NOTE
			 * Following string is used as a table header.
			 * Translated items should start at the same
			 * columns as the original items.
			 */
			(void) printf(gettext(
"Filesystem             ifree\n"));
		else {
			/*
			 * TRANSLATION_NOTE
			 * Following string is used as a table header.
			 * Translated items should start at the same
			 * columns as the original items.
			 */
			(void) printf(gettext(
"Filesystem             iused   ifree  %%iused  Mounted on\n"));
		}
	} else {
		if (gflag)
			/*
			 * TRANSLATION_NOTE
			 * Following string is used as a table header.
			 * Translated items should start at the same
			 * columns as the original items.
			 */
			(void) printf(gettext(
"Filesystem        f_type f_fsize f_bfree f_bavail f_files f_ffree "
"f_fsid f_flag f_fstr\n"));
		else
			if (bflag)
				/*
				 * TRANSLATION_NOTE
				 * Following string is used as a table header.
				 * Translated items should start at the same
				 * columns as the original items.
				 */
				(void) printf(gettext(
"Filesystem             avail\n"));
			else {
				/*
				 * TRANSLATION_NOTE
				 * Following string is used as a table header.
				 * Translated items should start at the same
				 * columns as the original items.
				 */
				(void) printf(gettext(
"Filesystem            kbytes    used   avail capacity  Mounted on\n"));
			}
		}
}

/*
 * Report on a block or character special device. Assumed not to be
 * mounted.  N.B. checks for a valid UFS superblock.
 */
void
dfreedev(char *file)
{
	fsblkcnt64_t totalblks, availblks, avail, free, used;
	int fi;

	fi = open64(file, 0);
	if (fi < 0) {
		(void) fprintf(stderr, "df: ");
		perror(file);
		return;
	}
	if (bread(file, fi, SBLOCK, (char *)&sblock, SBSIZE) == 0) {
		(void) close(fi);
		return;
	}
	if ((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) {
		(void) fprintf(stderr, gettext(
"df: %s: not a ufs file system\n"),
		    file);
		(void) close(fi);
		return;
	}
	if (sblock.fs_magic == FS_MAGIC &&
	    (sblock.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sblock.fs_version != UFS_VERSION_MIN)) {
		(void) fprintf(stderr, gettext(
"df: %s: unrecognized version of UFS: %d\n"),
		    file, sblock.fs_version);
		(void) close(fi);
		return;
	}
	if (sblock.fs_magic == MTB_UFS_MAGIC &&
	    (sblock.fs_version > MTB_UFS_VERSION_1 ||
	    sblock.fs_version < MTB_UFS_VERSION_MIN)) {
		(void) fprintf(stderr, gettext(
"df: %s: unrecognized version of UFS: %d\n"),
		    file, sblock.fs_version);
		(void) close(fi);
		return;
	}
	(void) printf("%-20.20s", file);
	if (iflag) {
		if (eflag) {
			(void) printf("%8ld", sblock.fs_cstotal.cs_nifree);
		} else {
			show_inode_usage(
			    (fsfilcnt64_t)sblock.fs_ncg *
			    (fsfilcnt64_t)sblock.fs_ipg,
			    (fsfilcnt64_t)sblock.fs_cstotal.cs_nifree);
		}
	} else {
		totalblks = (fsblkcnt64_t)sblock.fs_dsize;
		free =
		    (fsblkcnt64_t)sblock.fs_cstotal.cs_nbfree *
		    (fsblkcnt64_t)sblock.fs_frag +
		    (fsblkcnt64_t)sblock.fs_cstotal.cs_nffree;
		used = totalblks - free;
		availblks = totalblks / (fsblkcnt64_t)100 *
		    ((fsblkcnt64_t)100 - (fsblkcnt64_t)sblock.fs_minfree);
		avail = availblks > used ? availblks - used : (fsblkcnt64_t)0;
		if (bflag) {
			(void) printf("%8lld\n", dbtok(avail,
			    (fsblkcnt64_t)sblock.fs_fsize));
		} else {
			(void) printf(" %7lld %7lld %7lld",
			    dbtok(totalblks, (fsblkcnt64_t)sblock.fs_fsize),
			    dbtok(used, (fsblkcnt64_t)sblock.fs_fsize),
			    dbtok(avail, (fsblkcnt64_t)sblock.fs_fsize));
			(void) printf("%6.0f%%",
			    availblks == 0 ? 0.0 :
			    (double)used / (double)availblks * 100.0);
			(void) printf("  ");
		}
		if (tflag) {
			t_totalblks += dbtok(totalblks,
			    (fsblkcnt64_t)sblock.fs_fsize);
			t_used += dbtok(used, (fsblkcnt64_t)sblock.fs_fsize);
			t_avail += dbtok(avail, (fsblkcnt64_t)sblock.fs_fsize);
			t_free += free;
		}
	}
	if ((!bflag) && (!eflag))
		(void) printf("  %s\n", mpath(file));
	else if (eflag)
		(void) printf("\n");
	(void) close(fi);
}

void
dfreemnt(char *file, struct mnttab *mnt)
{
	struct statvfs64 fs;

	if (statvfs64(file, &fs) < 0 &&
	    chroot_stat(file, statvfs64, (char *)&fs, &file) < 0) {
		(void) fprintf(stderr, "df: ");
		perror(file);
		return;
	}

	if (!aflag && fs.f_blocks == 0) {
		return;
	}
	if (!isatty(fileno(stdout))) {
		(void) printf("%s", mnt->mnt_special);
	} else {
		if (strlen(mnt->mnt_special) > (size_t)20) {
			(void) printf("%s\n", mnt->mnt_special);
			(void) printf("                    ");
		} else {
			(void) printf("%-20.20s", mnt->mnt_special);
		}
	}
	if (iflag) {
		if (eflag) {
			(void) printf("%8lld", fs.f_ffree);
		} else {
			show_inode_usage(fs.f_files, fs.f_ffree);
		}
	} else {
		if (gflag) {
			print_statvfs(&fs);
		} else {
			fsblkcnt64_t totalblks, avail, free, used, reserved;

			totalblks = fs.f_blocks;
			free = fs.f_bfree;
			used = totalblks - free;
			avail = fs.f_bavail;
			reserved = free - avail;
			if ((long long)avail < 0)
				avail = 0;
			if (bflag) {
				(void) printf("%8lld\n", dbtok(avail,
				    (fsblkcnt64_t)fs.f_frsize));
			} else {
				(void) printf(" %7lld %7lld %7lld",
				    dbtok(totalblks,
				    (fsblkcnt64_t)fs.f_frsize),
				    dbtok(used, (fsblkcnt64_t)fs.f_frsize),
				    dbtok(avail, (fsblkcnt64_t)fs.f_frsize));
				totalblks -= reserved;
				(void) printf("%6.0f%%",
				    totalblks == 0 ? 0.0 :
				    (double)used / (double)totalblks * 100.0);
				(void) printf("  ");
				if (tflag) {
				t_totalblks += dbtok(totalblks + reserved,
				    (fsblkcnt64_t)fs.f_bsize);
				t_reserved += reserved;
				t_used += dbtok(used,
				    (fsblkcnt64_t)fs.f_frsize);
				t_avail += dbtok(avail,
				    (fsblkcnt64_t)fs.f_frsize);
				t_free += free;
				}
			}
		}
	}
	if ((!bflag) && (!eflag) && (!gflag))
		(void) printf("  %s\n", mnt->mnt_mountp);
	else if (eflag)
		(void) printf("\n");
}

static void
show_inode_usage(fsfilcnt64_t total, fsfilcnt64_t free)
{
	fsfilcnt64_t used = total - free;
	int missing_info = ((long long)total == (long long)-1 ||
	    (long long)free == (long long)-1);

	if (missing_info)
		(void) printf("%8s", "*");
	else
		(void) printf("%8lld", used);
	if ((long long)free == (long long)-1)
		(void) printf("%8s", "*");
	else
		(void) printf(" %7lld", free);
	if (missing_info)
		(void) printf("%6s  ", "*");
	else
		(void) printf("%6.0f%% ", (double)used / (double)total * 100.0);
}

/*
 * Return the suffix of path obtained by stripping off the prefix
 * that is the value of the CHROOT environment variable.  If this
 * value isn't obtainable or if it's not a prefix of path, return NULL.
 */
static char *
zap_chroot(char *path)
{
	return (pathsuffix(path, chrootpath));
}

/*
 * Stat/statfs a file after stripping off leading directory to which we are
 * chroot'd.  Used to find the TFS mount that applies to the current
 * activated NSE environment.
 */
static int
chroot_stat(char *dir, int (*statfunc)(), char *statp, char **dirp)
{
	if ((dir = zap_chroot(dir)) == NULL)
		return (-1);
	if (dirp)
		*dirp = dir;
	return (*statfunc)(dir, statp);
}

/*
 * Given a name like /dev/dsk/c1d0s2, returns the mounted path, like /usr.
 */
char *
mpath(char *file)
{
	struct mnttab mnt;
	FILE *mnttab;
	struct stat64 device_stat, mount_stat;
	char *mname;

	mnttab = fopen(MNTTAB, "r");
	if (mnttab == NULL) {
		return ("");
	}
	mname = "";
	while ((getmntent(mnttab, &mnt)) == 0) {
		if (strcmp(mnt.mnt_fstype, MNTTYPE_UFS) != 0) {
			continue;
		}
		if (strcmp(file, mnt.mnt_special) == 0) {
			if (stat64(mnt.mnt_mountp, &mount_stat) != 0)
				continue;
			if (stat64(mnt.mnt_special, &device_stat) != 0)
				continue;

			if (device_stat.st_rdev == mount_stat.st_dev) {
				mname = mnt.mnt_mountp;
				break;
			}
		}
	}
	fclose(mnttab);
	return (mname);
}

/*
 * Given a special device, return mnttab entry
 * Returns 0 on success
 */

int
mdev(char *spec, struct mnttab **mntbp)
{
	FILE *mntp;
	struct mnttab mnt;

	if ((mntp = fopen(MNTTAB, "r")) == 0) {
		(void) fprintf(stderr, "df: ");
		perror(MNTTAB);
		return (1);
	}

	while (getmntent(mntp, &mnt) == 0) {
		if (strcmp(spec, mnt.mnt_special) == 0) {
			(void) fclose(mntp);
			*mntbp =  mntdup(&mnt);
			return (0);
		}
	}
	(void) fclose(mntp);
	(void) fprintf(stderr, "df : couldn't find mnttab entry for %s", spec);
	return (1);
}

/*
 * Find the entry in mlist that corresponds to the file named by path
 * (i.e., that names a mount table entry for the file system in which
 * path lies).  The pstat argument must point to stat information for
 * path.
 *
 * Return the entry or NULL if there's no match.
 *
 * As it becomes necessary to obtain stat information about previously
 * unexamined mlist entries, gather the information and cache it with the
 * entries.
 *
 * The routine's strategy is to convert path into its canonical, symlink-free
 * representation canon (which will require accessing the file systems on the
 * branch from the root to path and thus may cause the routine to hang if any
 * of them are inaccessible) and to use it to search for a mount point whose
 * name is a substring of canon and whose corresponding device matches that of
 * canon.  This technique avoids accessing unnecessary file system resources
 * and thus prevents the program from hanging on inaccessible resources unless
 * those resources are necessary for accessing path.
 */
static struct mntlist *
findmntent(char *path, struct stat64 *pstat, struct mntlist *mlist)
{
	static char		cwd[MAXPATHLEN];
	char			canon[MAXPATHLEN];
	char			scratch[MAXPATHLEN];
	struct mntlist *mlp;

	/*
	 * If path is relative and we haven't already determined the current
	 * working directory, do so now.  Calculating the working directory
	 * here lets us do the work once, instead of (potentially) repeatedly
	 * in realpath().
	 */
	if (*path != '/' && cwd[0] == '\0') {
		if (getcwd(cwd, MAXPATHLEN) == NULL) {
			cwd[0] = '\0';
			return (NULL);
		}
	}

	/*
	 * Find an absolute pathname in the native file system name space that
	 * corresponds to path, stuffing it into canon.
	 *
	 * If CHROOT is set in the environment, assume that chroot($CHROOT)
	 * (or an equivalent series of calls) was executed and convert the
	 * path to the equivalent name in the native file system's name space.
	 * Doing so allows direct comparison with the names in mtab entires,
	 * which are assumed to be recorded relative to the native name space.
	 */
	if (abspath(cwd, path, scratch) < 0)
		return (NULL);
	if (strcmp(scratch, "/") == 0 && chrootpath != NULL) {
		/*
		 * Force canon to be in canonical form; if the result from
		 * abspath was "/" and chrootpath isn't the null string, we
		 * must strip off a trailing slash.
		 */
		scratch[0] = '\0';
	}
	(void) sprintf(canon, "%s%s", chrootpath ? chrootpath : "", scratch);

again:
	for (mlp = mlist; mlp; mlp = mlp->mntl_next) {
		struct mnttab *mnt = mlp->mntl_mnt;

		/*
		 * Ignore uninteresting mounts.
		 */
		if (strcmp(mnt->mnt_fstype, typestr) != 0)
			continue;

		/*
		 * The mount entry covers some prefix of the file.
		 * See whether it's the entry for the file system
		 * containing the file by comparing device ids.
		 */
		if (mlp->mntl_dev == NODEV) {
			struct stat64 fs_sb;

			if (stat64(mnt->mnt_mountp, &fs_sb) < 0 &&
			    chroot_stat(mnt->mnt_mountp, stat64, (char *)&fs_sb,
			    (char **)NULL) < 0) {
				continue;
			}
			mlp->mntl_dev = fs_sb.st_dev;
		}

		if (pstat->st_dev == mlp->mntl_dev)
			return (mlp);
	}

	return (NULL);
}

/*
 * Convert the path given in raw to canonical, absolute, symlink-free
 * form, storing the result in the buffer named by canon, which must be
 * at least MAXPATHLEN bytes long.  "wd" contains the current working
 * directory; accepting this value as an argument lets our caller cache
 * the value, so that realpath (called from this routine) doesn't have
 * to recalculate it each time it's given a relative pathname.
 *
 * Return 0 on success, -1 on failure.
 */
static int
abspath(char *wd, char *raw, char *canon)
{
	char		absbuf[MAXPATHLEN];

	/*
	 * Preliminary sanity check.
	 */
	if (wd == NULL || raw == NULL || canon == NULL)
		return (-1);

	/*
	 * If the path is relative, convert it to absolute form,
	 * using wd if it's been supplied.
	 */
	if (raw[0] != '/') {
		char	*limit = absbuf + sizeof (absbuf);
		char	*d;

		/* Fill in working directory. */
		if (strlcpy(absbuf, wd, sizeof (absbuf)) >= sizeof (absbuf))
			return (-1);

		/* Add separating slash. */
		d = absbuf + strlen(absbuf);
		if (d < limit)
			*d++ = '/';

		/* Glue on the relative part of the path. */
		while (d < limit && (*d++ = *raw++))
			continue;

		raw = absbuf;
	}

	/*
	 * Call realpath to canonicalize and resolve symlinks.
	 */
	return (realpath(raw, canon) == NULL ? -1 : 0);
}

/*
 * Return a pointer to the trailing suffix of full that follows the prefix
 * given by pref.  If pref isn't a prefix of full, return NULL.  Apply
 * pathname semantics to the prefix test, so that pref must match at a
 * component boundary.
 */
static char *
pathsuffix(char *full, char *pref)
{
	int preflen;

	if (full == NULL || pref == NULL)
		return (NULL);

	preflen = strlen(pref);
	if (strncmp(pref, full, preflen) != 0)
		return (NULL);

	/*
	 * pref is a substring of full.  To be a subpath, it cannot cover a
	 * partial component of full.  The last clause of the test handles the
	 * special case of the root.
	 */
	if (full[preflen] != '\0' && full[preflen] != '/' && preflen > 1)
		return (NULL);

	if (preflen == 1 && full[0] == '/')
		return (full);
	else
		return (full + preflen);
}

/*
 * Return zero iff the path named by sub is a leading subpath
 * of the path named by full.
 *
 * Treat null paths as matching nothing.
 */
static int
subpath(char *full, char *sub)
{
	return (pathsuffix(full, sub) == NULL);
}

offset_t llseek();

int
bread(char *file, int fi, daddr_t bno, char *buf, int cnt)
{
	int n;

	(void) llseek(fi, (offset_t)bno * DEV_BSIZE, 0);
	if ((n = read(fi, buf, cnt)) < 0) {
		/* probably a dismounted disk if errno == EIO */
		if (errno != EIO) {
			(void) fprintf(stderr, gettext("df: read error on "));
			perror(file);
			(void) fprintf(stderr, "bno = %ld\n", bno);
		} else {
			(void) fprintf(stderr, gettext(
"df: premature EOF on %s\n"), file);
			(void) fprintf(stderr,
			"bno = %ld expected = %d count = %d\n", bno, cnt, n);
		}
		return (0);
	}
	return (1);
}

char *
xmalloc(unsigned int size)
{
	char *ret;
	char *malloc();

	if ((ret = (char *)malloc(size)) == NULL) {
		(void) fprintf(stderr, gettext("umount: ran out of memory!\n"));
		exit(1);
	}
	return (ret);
}

struct mnttab *
mntdup(struct mnttab *mnt)
{
	struct mnttab *new;

	new = (struct mnttab *)xmalloc(sizeof (*new));

	new->mnt_special =
	    (char *)xmalloc((unsigned)(strlen(mnt->mnt_special) + 1));
	(void) strcpy(new->mnt_special, mnt->mnt_special);

	new->mnt_mountp =
	    (char *)xmalloc((unsigned)(strlen(mnt->mnt_mountp) + 1));
	(void) strcpy(new->mnt_mountp, mnt->mnt_mountp);

	new->mnt_fstype =
	    (char *)xmalloc((unsigned)(strlen(mnt->mnt_fstype) + 1));
	(void) strcpy(new->mnt_fstype, mnt->mnt_fstype);

	if (mnt->mnt_mntopts != NULL) {
		new->mnt_mntopts =
		    (char *)xmalloc((unsigned)(strlen(mnt->mnt_mntopts) + 1));
		(void) strcpy(new->mnt_mntopts, mnt->mnt_mntopts);
	} else {
		new->mnt_mntopts = NULL;
	}

#ifdef never
	new->mnt_freq = mnt->mnt_freq;
	new->mnt_passno = mnt->mnt_passno;
#endif /* never */

	return (new);
}

void
usage()
{

	(void) fprintf(stderr, gettext(
"ufs usage: df [generic options] [-o i] [directory | special]\n"));
	exit(1);
}

struct mntlist *
mkmntlist()
{
	FILE *mounted;
	struct mntlist *mntl;
	struct mntlist *mntst = NULL;
	struct extmnttab mnt;

	if ((mounted = fopen(MNTTAB, "r")) == NULL) {
		(void) fprintf(stderr, "df : ");
		perror(MNTTAB);
		exit(1);
	}
	resetmnttab(mounted);
	while (getextmntent(mounted, &mnt, sizeof (struct extmnttab)) == 0) {
		mntl = (struct mntlist *)xmalloc(sizeof (*mntl));
		mntl->mntl_mnt = mntdup((struct mnttab *)(&mnt));
		mntl->mntl_next = mntst;
		mntl->mntl_devvalid = 1;
		mntl->mntl_dev = makedev(mnt.mnt_major, mnt.mnt_minor);
		mntst = mntl;
	}
	(void) fclose(mounted);
	return (mntst);
}

void
print_statvfs(struct statvfs64 *fs)
{
	int	i;

	for (i = 0; i < FSTYPSZ; i++)
		(void) printf("%c", fs->f_basetype[i]);
	(void) printf(" %7d %7lld %7lld",
	    fs->f_frsize,
	    fs->f_blocks,
	    fs->f_bavail);
	(void) printf(" %7lld %7lld %7d",
	    fs->f_files,
	    fs->f_ffree,
	    fs->f_fsid);
	(void) printf(" 0x%x ",
	    fs->f_flag);
	for (i = 0; i < 14; i++)
		(void) printf("%c",
		    (fs->f_fstr[i] == '\0') ? ' ' : fs->f_fstr[i]);
	printf("\n");
}

void
print_totals()
{
	/*
	 * TRANSLATION_NOTE
	 * Following string is used as a table header.
	 * Translated items should start at the same
	 * columns as the original items.
	 */
	(void) printf(gettext("Totals              %8lld %7lld %7lld"),
	    t_totalblks, t_used, t_avail);
	(void) printf("%6.0f%%\n",
	    (t_totalblks - t_reserved) == (fsblkcnt64_t)0 ?
	    0.0 :
	    (double)t_used / (double)(t_totalblks - t_reserved) * 100.0);
}

void
print_itotals()
{
	/*
	 * TRANSLATION_NOTE
	 * Following string is used as a table header.
	 * Translated items should start at the same
	 * columns as the original items.
	 */
	(void) printf(gettext("Totals              %8d %7d%6.0f%%\n"),
	    t_iused,
	    t_ifree,
	    t_inodes == 0 ? 0.0 : (double)t_iused / (double)t_inodes * 100.0);
}
