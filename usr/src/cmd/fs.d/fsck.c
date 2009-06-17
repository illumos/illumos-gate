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
/*	  All Rights Reserved  	*/

#include	<stdio.h>
#include	<errno.h>
#include	<limits.h>
#include	<fcntl.h>
#include	<string.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/wait.h>
#include	<sys/vfstab.h>
#include	<sys/mntent.h>
#include	<sys/sysmacros.h>
#include	<locale.h>
#include	<libintl.h>
#include	<sys/dkio.h>

#define	DEV_BSIZE	512
#define	ARGV_MAX	16
#define	FSTYPE_MAX	8
#define	VFS_PATH	"/usr/lib/fs"
#define	VFS_PATH2	"/etc/fs"

#define	CHECK(xx, yy)\
	if (xx == (yy)-1) {\
		fprintf(stderr, gettext("%s: too many arguments\n"), myname); \
		usage(); \
	}
#define	OPTION(flag)\
		options++; \
		nargv[nargc++] = flag; \
		CHECK(nargc, ARGV_MAX); \
		break
#define	OPTARG(flag)\
		nargv[nargc++] = flag; \
		CHECK(nargc, ARGV_MAX); \
		if (optarg) {\
			nargv[nargc++] = optarg; \
			CHECK(nargc, ARGV_MAX); \
		}\
		break


int	nrun, ndisks;
int	maxrun = 8;	/* should be based on the machine resources */

extern char	*default_fstype();

int	nargc = 2;
int	options = 0;
int	mnt_passno = 0;
int	exitstat = 0;
int	verbose = 0;
char	*nargv[ARGV_MAX];
char	*myname, *fstype;
char	*malloc();
char	vfstab[] = VFSTAB;
char	pflg = 0, Vflg = 0;

/*
 * Keep an idea of the last device arg type as a hint to the
 * type of the next arg. In the case of mountall, it's very likely
 * to be the same type and the next entry in the file. This should
 * help speed vfstab lookups.
 */
enum dev_arg_t { UNKNOWN, SPECIAL, FSCKDEV, MOUNTPT };
enum dev_arg_t arg_hint = UNKNOWN;

static struct devlist {
	char *name;
	char *fsname;
	pid_t pid;
	struct devlist *nxt;
} *newdev(), *getdev();

/*
 * private copy vfstab functions
 */
static struct vfstab	vfsave = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};

static void usage(void);
static void fsck_dopreen(struct devlist **devp, int ndevs);
static void waiter(struct devlist **blp, struct devlist **badlist);
static void print_badlist(struct devlist *lp);
static void startdisk(struct devlist *dp);
static void do_exec(char *fstype, char *nargv[]);
static void prnt_cmd(FILE *fd, char *fstype);
static void vfserror(int flag);

static int
vfdup(struct vfstab *vp)
{
	if (vfsave.vfs_special != NULL) {
		free(vfsave.vfs_special);
		vfsave.vfs_special = NULL;
	}
	if ((vp->vfs_special != NULL) &&
	    ((vfsave.vfs_special = strdup(vp->vfs_special)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	if (vfsave.vfs_fsckdev != NULL) {
		free(vfsave.vfs_fsckdev);
		vfsave.vfs_fsckdev = NULL;
	}
	if ((vp->vfs_fsckdev != NULL) &&
	    ((vfsave.vfs_fsckdev = strdup(vp->vfs_fsckdev)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	if (vfsave.vfs_mountp != NULL) {
		free(vfsave.vfs_mountp);
		vfsave.vfs_mountp = NULL;
	}
	if ((vp->vfs_mountp != NULL) &&
	    ((vfsave.vfs_mountp = strdup(vp->vfs_mountp)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	if (vfsave.vfs_fstype != NULL) {
		free(vfsave.vfs_fstype);
		vfsave.vfs_fstype = NULL;
	}
	if ((vp->vfs_fstype != NULL) &&
	    ((vfsave.vfs_fstype = strdup(vp->vfs_fstype)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	if (vfsave.vfs_fsckpass != NULL) {
		free(vfsave.vfs_fsckpass);
		vfsave.vfs_fsckpass = NULL;
	}
	if ((vp->vfs_fsckpass != NULL) &&
	    ((vfsave.vfs_fsckpass = strdup(vp->vfs_fsckpass)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	if (vfsave.vfs_automnt != NULL) {
		free(vfsave.vfs_automnt);
		vfsave.vfs_automnt = NULL;
	}
	if ((vp->vfs_automnt != NULL) &&
	    ((vfsave.vfs_automnt = strdup(vp->vfs_automnt)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	if (vfsave.vfs_mntopts != NULL) {
		free(vfsave.vfs_mntopts);
		vfsave.vfs_mntopts = NULL;
	}
	if ((vp->vfs_mntopts != NULL) &&
	    ((vfsave.vfs_mntopts = strdup(vp->vfs_mntopts)) == NULL)) {
		perror(myname);
		return (4);	/* XXX */
	}

	*vp = vfsave;
	return (0);
}

static int
mygetvfsent(FILE *fp, struct vfstab *vp)
{
	int	error;

	if ((error = getvfsent(fp, vp)) != 0)
		return (error);
	return (vfdup(vp));
}

static int
mygetvfsany(FILE *fp, struct vfstab *vp, struct vfstab *vrefp)
{
	int	error;

	if ((error = getvfsany(fp, vp, vrefp)) != 0)
		return (error);
	return (vfdup(vp));
}

int
main(int argc, char *argv[])
{
	int	cc, ret, other_than_ufs = 0;
	int	questflg = 0, Fflg = 0, Vflg = 0, sanity = 0;
	char	*subopt;
	FILE	*fd = NULL;
	int	devfd;
	struct vfstab	vget, vref;
	struct dk_minfo dkminfo;
	int preencnt = 0;
	struct devlist *dp, *devs = NULL;
	int status;
	uint_t lbs;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	if (myname)
		myname++;
	else
		myname = argv[0];

	while ((cc = getopt(argc, argv, "?F:mnNo:vVyY")) != -1) {
		switch (cc) {
		case '?':
			questflg++;
			if (questflg > 1)
				usage();
			nargv[nargc++] = "-?";
			CHECK(nargc, ARGV_MAX);
			break;
		case 'F':
			Fflg++;
			/* check for more that one -F */
			if (Fflg > 1) {
				fprintf(stderr,
				gettext("%s: more than one fstype specified\n"),
					myname);
				usage();
			}
			fstype = optarg;
			if (strlen(fstype) > (size_t)FSTYPE_MAX) {
				fprintf(stderr,
			gettext("%s: Fstype %s exceeds %d characters\n"),
					myname, fstype, FSTYPE_MAX);
						exit(1);
			}
			break;
		case 'm':
			sanity++;
			OPTION("-m");
		case 'n':
			OPTION("-n");
		case 'N':
			OPTION("-N");
		case 'o':
			subopt = optarg;
			while (*subopt != '\0') {
				if (*subopt == 'p') {
					pflg++;
					break;
				}
				subopt++;
			}
			OPTARG("-o");
		case 'v':
			OPTION("-v");
		case 'V':
			Vflg++;
			if (Vflg > 1)
				usage();
			break;
		case 'y':
			OPTION("-y");
		case 'Y':
			OPTION("-Y");
		}
		optarg = NULL;
	}

	/* copy '--' to specific */
	if (strcmp(argv[optind-1], "--") == 0) {
		nargv[nargc++] = argv[optind-1];
		CHECK(nargc, ARGV_MAX);
	}

	if (questflg) {
		if (Fflg) {
			nargc = 2;
			nargv[nargc++] = "-?";
			nargv[nargc] = NULL;
			do_exec(fstype, nargv);
		}
		usage();
	}

	if ((sanity) && (options > 1)) {
		usage();
	}

	if (optind == argc) {	/* no device name is specified */
		if (fstype == NULL) {
			if ((argc > 2) && (sanity)) {
				usage();
			}
		}
		/*
		 * Try to check UFS filesystems first, then check other
		 * filesystems if they exist.
		 * Note: Parallel checking is only available in UFS for now.
		 */
		if (fstype == NULL || strcmp(fstype, MNTTYPE_UFS) == 0) {
			if ((fd = fopen(vfstab, "r")) == NULL) {
				fprintf(stderr,
					gettext("%s: cannot open vfstab\n"),
					myname);
				exit(1);
			}
			while ((ret = mygetvfsent(fd, &vget)) == 0) {
				if (strcmp(vget.vfs_fstype, MNTTYPE_UFS) &&
				    numbers(vget.vfs_fsckpass)) {
					other_than_ufs ++;
					continue;
				}
				if (numbers(vget.vfs_fsckpass))
					mnt_passno = atoi(vget.vfs_fsckpass);
				else
					continue;
				if (mnt_passno < 1)
					continue;
				if (pflg == 0 || mnt_passno == 1) {
					status = execute(vget.vfs_fsckdev,
					    MNTTYPE_UFS, Vflg, fd);
					/* return the highest exit code */
					if (status > exitstat)
						exitstat = status;
				} else if (preen_addev(vget.vfs_fsckdev) == 0) {
					preencnt++;
					dp = newdev(&vget);
					dp->nxt = devs;
					devs = dp;
				} else {
					/*
					 * preening setup failed, so
					 * execute serially here...
					 */
					fprintf(stderr,
					gettext("%s: preen_addev error\n"),
						myname);
					status = execute(vget.vfs_fsckdev,
					    MNTTYPE_UFS, Vflg, fd);
					/* return the highest exit code */
					if (status > exitstat)
						exitstat = status;
				}
			}
			fclose(fd);
			if (ret > 0)
				vfserror(ret);
			if (pflg && exitstat == 0) {
				fsck_dopreen(&devs, preencnt);
			}
		}
		else
			other_than_ufs = 1;

		if (other_than_ufs) {
			if ((fd = fopen(vfstab, "r")) == NULL) {
				fprintf(stderr,
					gettext("%s: cannot open vfstab\n"),
					myname);
				exit(1);
			}
			while ((ret = mygetvfsent(fd, &vget)) == 0)
				if (strcmp(vget.vfs_fstype, MNTTYPE_UFS) &&
				    numbers(vget.vfs_fsckpass) &&
				    vget.vfs_fsckdev != NULL &&
				    (fstype == NULL ||
				    strcmp(fstype, vget.vfs_fstype) == 0)) {
					status = execute(vget.vfs_fsckdev,
					    vget.vfs_fstype, Vflg, fd);
					/* return the highest exit code */
					if (status > exitstat)
						exitstat = status;
				}
			fclose(fd);
			if (ret > 0)
				vfserror(ret);
		}

	} else {	/* device name is specified */
		if (fstype == NULL && (fd = fopen(vfstab, "r")) == NULL) {
			fprintf(stderr, gettext("%s: cannot open vfstab\n"),
				myname);
			exit(1);
		}

		while (optind < argc) {
			/*
			 * If "-F FStype" is specified, use that fs type.
			 * Otherwise, determine the fs type from /etc/vfstab
			 * if the entry exists.  Otherwise, determine the
			 * local or remote fs type from /etc/default/df
			 * or /etc/dfs/fstypes respectively.
			 */
			if (fstype == NULL) {
				if ((argc > 3) && (sanity)) {
					usage();
				}
				/* must check for both special && raw devices */
				vfsnull(&vref);

				/*
				 * Find the vfstab entry for this device.
				 * arg_hint tells us what to try to match,
				 * based on the type of the last arg. If
				 * arg_hint equals UNKNOWN, then we're not
				 * sure of the type and need to fallthrough
				 * all 3 possibilities for vfstab lookup.
				 * Try it as a mountpt first, since that's
				 * what mountall gives us.
				 */
try_again:
				switch (arg_hint) {
				case UNKNOWN:
					/* FALLTHROUGH */

				case MOUNTPT:
					vref.vfs_mountp = argv[optind];
					if ((ret = mygetvfsany(fd, &vget,
						&vref)) == -1 ||
						vget.vfs_fstype == NULL) {

						vref.vfs_mountp = NULL;
						rewind(fd);

						if (arg_hint == MOUNTPT) {
							arg_hint = UNKNOWN;
							goto try_again;
						}
						/* FALLTHROUGH */
					} else {
						/* Found it */
						if (vget.vfs_fsckdev != NULL) {
							argv[optind] =
							vget.vfs_fsckdev;
						}
						arg_hint = MOUNTPT;
						break;
					}

				case FSCKDEV:
					vref.vfs_fsckdev = argv[optind];

					/*
					 * Check the media sector size
					 */
					if (((devfd = open(vref.vfs_fsckdev,
					    O_RDWR)) >= 0) && (ioctl(devfd,
					    DKIOCGMEDIAINFO, &dkminfo) !=
					    -1)) {
						lbs =  dkminfo.dki_lbsize;
						if (lbs != 0 && ISP2(lbs /
						    DEV_BSIZE) &&
						    lbs != DEV_BSIZE) {
							fprintf(stderr,
							    gettext("The device"
							    " sector size is"
							    " not supported by"
							    " fsck\n"));
							(void) close(devfd);
							exit(1);
						}
					}

					if (devfd >= 0) {
						(void) close(devfd);
					}

					if ((ret = mygetvfsany(fd, &vget,
						&vref)) == -1 ||
						vget.vfs_fstype == NULL) {

						vref.vfs_fsckdev = NULL;
						rewind(fd);

						if (arg_hint == FSCKDEV) {
							arg_hint = UNKNOWN;
							goto try_again;
						}
						/* FALLTHROUGH */
					} else {
						/* Found it */
						arg_hint = FSCKDEV;
						break;
					}

				case SPECIAL:
					vref.vfs_special = argv[optind];
					if ((ret = mygetvfsany(fd, &vget,
						&vref)) == -1 ||
						vget.vfs_fstype == NULL) {

						vref.vfs_special = NULL;
						rewind(fd);

						if (arg_hint == SPECIAL) {
							arg_hint = UNKNOWN;
							goto try_again;
						}
						/* FALLTHROUGH */
					} else {
						/* Found it */
						arg_hint = SPECIAL;
						break;
					}
				}

				if (ret == 0 && vget.vfs_fstype) {
					if ((pflg) && (strcmp(vget.vfs_fstype,
					    MNTTYPE_UFS) == 0) && (preen_addev(
					    vget.vfs_fsckdev) == 0)) {
						preencnt++;
						dp = newdev(&vget);
						dp->nxt = devs;
						devs = dp;
					} else {
						status = execute(argv[optind],
						    vget.vfs_fstype, Vflg, fd);
						if (status > exitstat)
							exitstat = status;
					}
				} else if (ret == -1 ||
				    vget.vfs_fstype == NULL) {
					fstype =
					    default_fstype(argv[optind]);
					status = execute(argv[optind], fstype,
					    Vflg, fd);
					/* return the highest exit code */
					if (status > exitstat)
						exitstat = status;
				} else
					vfserror(ret);
			} else {
				status = execute(argv[optind], fstype,
				    Vflg, NULL);
				/* return the highest exit code */
				if (status > exitstat)
					exitstat = status;
			}
			optind++;
		}
		if (fd != NULL)
			fclose(fd);
		if ((pflg) && (exitstat == 0)) {
			fsck_dopreen(&devs, preencnt);
		}
	}
	return (exitstat);
}

static void
fsck_dopreen(struct devlist **devp, int ndevs)
{
	char name[1024];
	int rc;
	int i;
	struct devlist *bl, *bdp;
	struct devlist *badlist;

	bl = badlist = NULL;
	while (ndevs > 0) {
		if (nrun > maxrun)
			waiter(&bl, &badlist);
		rc = preen_getdev(name);
		switch (rc) {
		case 0:
			break;
		case 1:
			bdp = getdev(name, devp);
			if (bdp == NULL) {
				fprintf(stderr,
					gettext("%s: unknown dev: `%s'\n"),
					myname, name);
				exit(1);
			}
			bdp->nxt = bl;
			bl = bdp;
			startdisk(bdp);
			ndevs--;
			break;
		case 2:
			waiter(&bl, &badlist);
			break;
		default:
			fprintf(stderr,
			gettext("%s: bad return `%d' from preen_getdev\n"),
				myname, rc);
			break;
		}
	}
	while (bl != NULL) {
		waiter(&bl, &badlist);
	}

	if (badlist != NULL)
		print_badlist(badlist);
}

static void
startdisk(struct devlist *dp)
{
	pid_t pid;

	nrun++;
	if ((pid = fork()) == -1) {
		perror("fork");
		exit(1);
	} else if (pid == 0) {
		exitstat = execute(dp->name, MNTTYPE_UFS, Vflg, NULL);
		exit(exitstat);
	} else {
		dp->pid = pid;
	}
}

static void
waiter(struct devlist **blp, struct devlist **badlist)
{
	pid_t curpid;
	int status;
	struct devlist *bdp, *pbdp;

	curpid = wait(&status);
	if (curpid == -1) {
		perror("wait");
		exit(1);
	}

	for (pbdp = NULL, bdp = *blp; bdp != NULL; pbdp = bdp, bdp = bdp->nxt) {
		if (bdp->pid == curpid) {
			break;
		}
	}
	if (bdp == NULL)
		return;
	nrun--;

	if (pbdp)
		pbdp->nxt = bdp->nxt;
	else
		*blp = bdp->nxt;
	preen_releasedev(bdp->name);

	if (WTERMSIG(status)) {
		printf(gettext("%s (%s): EXITED WITH SIGNAL %d\n"),
			bdp->name, bdp->fsname, WTERMSIG(status));
		status = status&0377 | 8<<8;
	}
	if (WHIBYTE(status) != 0) {
		if (WHIBYTE(status) > exitstat)
			exitstat = WHIBYTE(status);
		while (*badlist != NULL)
			badlist = &(*badlist)->nxt;
		*badlist = bdp;
		bdp->nxt = NULL;
	}
}

static void
print_badlist(struct devlist *lp)
{
	int x, len;

	printf(
gettext("\nTHE FOLLOWING FILE SYSTEM(S) HAD AN UNEXPECTED INCONSISTENCY:"));
	for (x = 3; lp != NULL; lp = lp->nxt) {
		len = strlen(lp->name) + strlen(lp->fsname) + 5;
		x += len;
		if (x >= 80) {
			printf("\n   ");
			x = len + 3;
		} else {
			printf(" ");
		}
		printf("%s (%s)%s", lp->name, lp->fsname,
		    lp->nxt ? "," : "\n");
	}
}

/*
 * allocate and initialize a `devlist' structure
 */
static
struct devlist *
newdev(struct vfstab *vfsp)
{
	struct devlist *dp;
	extern char *strdup();

	dp = (struct devlist *)malloc(sizeof (struct devlist));
	if (dp == NULL) {
		fprintf(stderr, gettext("%s: out of memory\n"), myname);
		exit(1);
	}
	dp->name = strdup(vfsp->vfs_fsckdev);
	dp->fsname = strdup(vfsp->vfs_mountp);
	if (dp->name == NULL || dp->fsname == NULL) {
		fprintf(stderr, gettext("%s: out of memory\n"), myname);
		exit(1);
	}
	return (dp);
}

/*
 * locate the devlist structure in the given list that matches `name'.
 * If found, the structure is removed from the list, and a pointer to
 * it is returned.  If not, NULL is returned.
 */
static
struct devlist *
getdev(char *name, struct devlist **list)
{
	struct devlist *p, *lp;

	for (lp = NULL, p = *list; p != NULL; lp = p, p = p->nxt) {
		if (strcmp(p->name, name) == 0)
			break;
	}

	if (p != NULL) {
		if (lp != NULL)
			lp->nxt = p->nxt;
		else
			*list = p->nxt;
	}
	return (p);
}

/* see if all numbers */
int
numbers(char *yp)
{
	if (yp == NULL)
		return (0);
	while ('0' <= *yp && *yp <= '9')
		yp++;
	if (*yp)
		return (0);
	return (1);
}

int
execute(char *fsckdev, char *fstype, int Vflg, FILE *fd)
{
	int	st;
	pid_t	fk;
	char	full_path[PATH_MAX];
	char	*vfs_path = VFS_PATH;
	int	status = 0;

	nargv[nargc] = fsckdev;

	if (Vflg) {
		prnt_cmd(stdout, fstype);
		return (0);
	}

	if (fd)
		fcntl(fileno(fd), F_SETFD, 1);	/* close on exec */

	if ((fk = fork()) == (pid_t)-1) {
		fprintf(stderr,
			gettext("%s: cannot fork.  Try again later\n"),
			myname);
		perror(myname);
		exit(1);
	}

	if (fk == 0) {
		/* Try to exec the fstype dependent portion of the fsck. */
		do_exec(fstype, nargv);
	} else {
		/* parent waits for child */
		if (wait(&st) == (pid_t)-1) {
			fprintf(stderr, gettext("%s: bad wait\n"), myname);
			perror(myname);
			exit(1);
		}

		if ((st & 0xff) == 0x7f) {
			fprintf(stderr,
				gettext("%s: warning: the following command"
				" (process %d) was stopped by signal %d\n"),
				myname, fk, (st >> 8) & 0xff);
			prnt_cmd(stderr, fstype);
			status = ((st >> 8) & 0xff) | 0x80;
		} else if (st & 0xff) {
			if (st & 0x80)
				fprintf(stderr,
				gettext("%s: warning: the following command"
				" (process %d) was terminated by signal %d"
				" and dumped core\n"),
				myname, fk, st & 0x7f);
			else
				fprintf(stderr,
				gettext("%s: warning: the following command"
				" (process %d) was terminated by signal %d\n"),
				myname, fk, st & 0x7f);

			prnt_cmd(stderr, fstype);
			status = ((st & 0xff) | 0x80);
		} else if (st & 0xff00)
			status = (st >> 8) & 0xff;
	}

	return (status);
}

static void
do_exec(char *fstype, char *nargv[])
{
	char	full_path[PATH_MAX];
	char	*vfs_path = VFS_PATH;

	if (strlen(fstype) > (size_t)FSTYPE_MAX) {
		fprintf(stderr,
			gettext("%s: Fstype %s exceeds %d characters\n"),
			myname, fstype, FSTYPE_MAX);
		exit(1);
	}
	/* build the full pathname of the fstype dependent command. */
	sprintf(full_path, "%s/%s/%s", vfs_path, fstype, myname);

	/* set the new argv[0] to the filename */
	nargv[1] = myname;
	/* Try to exec the fstype dependent portion of the fsck. */
	execv(full_path, &nargv[1]);
	if (errno == EACCES) {
		fprintf(stderr,
			gettext("%s: cannot execute %s - permission denied\n"),
			myname, full_path);
	}
	if (errno == ENOEXEC) {
		nargv[0] = "sh";
		nargv[1] = full_path;
		execv("/sbin/sh", &nargv[0]);
	}
	/* second path to try */
	vfs_path = VFS_PATH2;
	/* build the full pathname of the fstype dependent command. */
	sprintf(full_path, "%s/%s/%s", vfs_path, fstype, myname);

	/* set the new argv[0] to the filename */
	nargv[1] = myname;
	/* Try to exec the second fstype dependent portion of the fsck. */
	execv(full_path, &nargv[1]);
	if (errno == EACCES) {
		fprintf(stderr,
			gettext("%s: cannot execute %s - permission denied\n"),
			myname, full_path);
		exit(1);
	}
	if (errno == ENOEXEC) {
		nargv[0] = "sh";
		nargv[1] = full_path;
		execv("/sbin/sh", &nargv[0]);
	}
	fprintf(stderr,
		gettext("%s: operation not applicable to FSType %s\n"),
		myname, fstype);
	exit(1);
}

static void
prnt_cmd(FILE *fd, char *fstype)
{
	char	**argp;

	fprintf(fd, "%s -F %s", myname, fstype);
	for (argp = &nargv[2]; *argp; argp++)
		fprintf(fd, " %s", *argp);
	fprintf(fd, "\n");
}

static void
vfserror(int flag)
{
	switch (flag) {
	case VFS_TOOLONG:
		fprintf(stderr,
			gettext("%s: line in vfstab exceeds %d characters\n"),
			myname, VFS_LINE_MAX-2);
		break;
	case VFS_TOOFEW:
		fprintf(stderr,
			gettext("%s: line in vfstab has too few entries\n"),
			myname);
		break;
	case VFS_TOOMANY:
		fprintf(stderr,
			gettext("%s: line in vfstab has too many entries\n"),
			myname);
		break;
	}
	exit(1);
}

static void
usage(void)
{
	fprintf(stderr,
		gettext("Usage:\n%s [-F FSType] [-V] [-m] [special ...]\n"
			"%s [-F FSType] [-V] [-y|Y|n|N]"
			" [-o specific_options] [special ...]\n"),
			myname, myname);

	exit(1);
}
