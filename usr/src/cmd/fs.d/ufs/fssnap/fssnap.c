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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fssnap_if.h>
#include <sys/filio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <kstat.h>
#include <libintl.h>
#include <libdevinfo.h>
#include <sys/sysmacros.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_snap.h>

#define	SNAP_CTL_PATH	"/dev/" SNAP_CTL_NAME

#define	MAX_SUFFIX	6	/* '.' + 4 chars of number + trailing '\0' */

#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)

static int max_uniq = 9999;

void create_snap(int, char *, u_offset_t, uint_t, int, int);
void delete_snap(int);
void stats_snap(char *, char *);

int open_backpath(int, u_offset_t, char **, char **, int **);
u_offset_t spec_to_bytes(char *);
void gen_backing_store_path(char *basepath, int num, char **outpath);
void unlink_all(char *, int);
void close_all(char *, int, int *);
int open_multi_backfile(char *, int, int **, int);

void die_perror(char *);
void die_errno(int, char *, ...);
void die_create_error(int error);
void die_usage(void);
void die(char *, ...);
void warn_errno(int, char *,  ...);
void usage(void);

static char *subopts[] = {
#define	BACKPATH	(0)
	"backing-store",
#define	BACKPATH2	(1)
	"bs",
#define	BACKPATH3	(2)
	"bf",
#define	MAXSIZE		(3)
	"maxsize",
#define	CHUNKSIZE	(4)
	"chunksize",
#define	RAWFILE		(5)
	"raw",
#define	UNLINK		(6)
	"unlink",
	NULL
};

static jmp_buf err_main;
static char *progname = NULL;
static int backout_snap_fd = -1;

extern void fssnap_show_status(char *mountpoint, char *opts, int labels,
    int brief); /* in ../../fssnapsup.c */

int
main(int argc, char *argv[])
{
	int c;
	char *suboptions = NULL;
	char *value;
	int longjmp_return;

	char *volatile mountpoint = NULL;
	int volatile mountfd = -1;
	char *volatile backpath = NULL;

	int volatile delete = 0;
	int volatile stats = 0;
	u_offset_t volatile maxsize = 0;
	uint_t volatile chunksize = 0;
	int volatile rawfile = 0;
	int volatile dounlink = 0;

	if ((progname = strrchr(argv[0], '/')) != NULL)
		++progname;
	else
		progname = argv[0];

	if ((longjmp_return = setjmp(err_main)) != 0) {
		if (backout_snap_fd >= 0) {
			mountfd = backout_snap_fd;
			backout_snap_fd = -1; /* prevent infinite loop */
			delete_snap(mountfd);
		}

		return (longjmp_return);
	}

	while ((c = getopt(argc, argv, "dio:")) != EOF) {
		switch (c) {
		case 'd':
			++delete;
			break;

		case 'i':
			++stats;
			break;

		case 'o':
			suboptions = optarg;
			break;

		default:
			die_usage();
		}
	}

	/* if -i or -d are not specified then interpret the create options */
	if ((stats == 0) && (delete == 0) && (suboptions != NULL)) {
		while (*suboptions != '\0') {

			switch ((getsubopt(&suboptions, subopts, &value))) {
			case BACKPATH:
			case BACKPATH2:
			case BACKPATH3:
				if (value == NULL)
					die_usage();
				backpath = strdup(value);
				if (backpath == NULL) {
					die_perror("strdup");
				}
				break;

			case MAXSIZE:
				maxsize = spec_to_bytes(value);
				break;

			case CHUNKSIZE:
				chunksize = spec_to_bytes(value);
				break;

			case RAWFILE:
				++rawfile;
				break;

			case UNLINK:
				++dounlink;
				break;

			default:
				die_usage();
			}
		}
	}

	/* -d and -i can not be specified together or more than once each */
	if ((delete + stats) > 1)
		die_usage();

	/* If no mount point is specified then -i is the only valid option. */
	if ((optind >= argc) && (stats == 0))
		die_usage();

	/*
	 * If anything but the mount point or device is specified at the end
	 * it's an error.
	 */
	if (optind != (argc - 1)) {
		if (!stats)
			die_usage();
	} else {
		/* Otherwise, the last option is the mountpoint. */
		mountpoint = argv[optind];
		if ((mountfd = open(mountpoint, O_RDONLY)) < 0)
			die_perror(mountpoint);
	}

	if (stats != 0) {
		stats_snap(mountpoint, suboptions);
	} else if (delete != 0) {
		delete_snap(mountfd);
	} else {
		/*
		 * backpath may be invalid upon return of create_snap call.
		 */
		create_snap(mountfd, backpath, maxsize, chunksize,
		    rawfile, dounlink);
	}

	return (0);
}

void
create_snap(int mountfd, char *backpath, u_offset_t maxsize, uint_t chunksize,
    int rawfile, int dounlink)
{
	struct fiosnapcreate_multi *enable;
	int backcount;
	int ctlfd;
	char *unlinkpath = NULL;
	di_devlink_handle_t hdl;
	int *fd_array;
	u_offset_t max_bf_size;
	int save_errno;

	/*
	 * If chunksize is not a power of 2, the maximum size of a
	 * backing store file might not be UFS_MAX_SNAPBACKFILESIZE,
	 * since the size of the backing store files must be an
	 * integral number of chunks (except for the last one).  So
	 * calculate the actual maximum backing store file size.
	 * (It would be nice if we could assume that the chunksize
	 * was a power of 2, but we can't.)
	 */

	if (chunksize != 0 && !POWEROF2(chunksize))
		max_bf_size = (UFS_MAX_SNAPBACKFILESIZE/chunksize) * chunksize;
	else
		max_bf_size = UFS_MAX_SNAPBACKFILESIZE;

	/*
	 * open_backpath() only returns on success, and
	 * can change the value of backpath when backpath
	 * references a directory.
	 */
	if (backpath == NULL)
		die(gettext("No backing store path specified.\n"));
	backcount = open_backpath(mountfd, max_bf_size, &backpath,
	    &unlinkpath, &fd_array);

	/*
	 * Only need backcount - 1 spaces for fd's since
	 * fiosnapcreate_multi struct contains space for the
	 * first one.
	 */
	if ((enable = calloc(1, sizeof (struct fiosnapcreate_multi) +
	    (backcount - 1) * sizeof (int))) == NULL)
		die(gettext("Insufficient memory.\n"));

	enable->backfilecount = backcount;
	bcopy(fd_array, &(enable->backfiledesc), backcount * sizeof (int));

	enable->rootfiledesc = mountfd;

	enable->maxsize = maxsize;
	enable->chunksize = chunksize;
	enable->backfilesize = max_bf_size;

	/*
	 * enable.backfilename is advisory only.  So, we don't overflow
	 * the buffer, but we don't give an error if the backpath does not
	 * fit.  Instead, it is truncated, and the kstat shows all it can.
	 */
	if (backpath != NULL) {
		if (dounlink)
			(void) snprintf(enable->backfilename,
			    sizeof (enable->backfilename) - 1, "%s <UNLINKED>",
			    backpath);
		else
			(void) strncpy(enable->backfilename, backpath,
			    sizeof (enable->backfilename) - 1);
		enable->backfilename[sizeof (enable->backfilename)-1] = '\0';
	}

	if ((ctlfd = open(SNAP_CTL_PATH, O_RDONLY | O_EXCL)) == -1) {
		unlink_all(unlinkpath, backcount);
		die_perror(SNAP_CTL_PATH);
	}

	if (ioctl(ctlfd, _FIOSNAPSHOTCREATE_MULTI, enable) == -1) {
		unlink_all(unlinkpath, backcount);
		if (enable->error != 0) {
			die_create_error(enable->error);
		} else {
			die_perror("ioctl");
		}
	}

	backout_snap_fd = mountfd;
	if (dounlink != 0)
		unlink_all(unlinkpath, backcount);

	if (close(ctlfd) != 0) {
		save_errno = errno;
		die_errno(save_errno, gettext("close of control file (%s)"),
		    SNAP_CTL_PATH);
	}

	close_all(unlinkpath, backcount, fd_array);

	if ((hdl = di_devlink_init("fssnap", DI_MAKE_LINK)) == NULL) {
		save_errno = errno;
		warn_errno(save_errno,
		    gettext("/dev/%s/%d may not be immediately available\n"),
		    (rawfile) ? SNAP_CHAR_NAME : SNAP_BLOCK_NAME,
		    enable->snapshotnumber);
	} else {
		(void) di_devlink_fini(&hdl);
	}

	/* intentionally not internationalized */
	printf("/dev/%s/%d\n", (rawfile) ? SNAP_CHAR_NAME : SNAP_BLOCK_NAME,
	    enable->snapshotnumber);

	free(enable);
}

void
delete_snap(int mountfd)
{
	struct fiosnapdelete disable;
	int ctlfd;
	int save_errno;

	bzero(&disable, sizeof (disable));
	if ((ctlfd = open(SNAP_CTL_PATH, O_RDONLY | O_EXCL)) == -1)
		die_perror(SNAP_CTL_PATH);

	disable.rootfiledesc = mountfd;
	if (ioctl(ctlfd, _FIOSNAPSHOTDELETE, &disable) == -1) {
		if (disable.error) {
			die(gettext("error %d"), disable.error);
		} else {
			die_perror("ioctl");
		}
	}

	if (close(ctlfd) != 0) {
		save_errno = errno;
		die_errno(save_errno, gettext("close of control file (%s)"),
		    SNAP_CTL_PATH);
	}

	printf(gettext("Deleted snapshot %d.\n"), disable.snapshotnumber);
}

void
stats_snap(char *mountpath, char *opts)
{
	fssnap_show_status(mountpath, opts, ((opts != NULL) ? 0 : 1), 0);
}

/*
 * Open as many backing files as necessary for this snapshot.
 * There will be one backing file for each max_bf_size
 * number of bytes in the file system being snapped.
 * The array of file descriptors for the backing files is returned in
 * fd_array.  The number of backing files is the return value of the
 * function.  The name of the first backing file is returned in
 * unlinkpath.  The subsequent backing files are assumed to have the
 * same name as the first, but with suffixes, .2, .3, etc.
 */
int
open_backpath(int mountfd, u_offset_t max_bf_size, char **path,
    char **unlinkpath, int **fd_array)
{
	struct stat st;
	struct statvfs vfs;
	int fd, uniq, len;
	int ret_errno, i, num_back_files;
	offset_t fssize, backfilesize;
	char *locpath = NULL;
	int save_errno;

	*unlinkpath = NULL;

	/* determine size of the file system to be snapped */
	if (fstatvfs(mountfd, &vfs) == -1)
		die_perror("statvfs");

	fssize = vfs.f_blocks * vfs.f_frsize;
	num_back_files = howmany(fssize, max_bf_size);

	if (stat(*path, &st) < 0) {
		/*
		 * Since we set the file_exists_is_fatal argument to 1,
		 * if we return at all, it will be with all the backing
		 * files successfully created and opened.
		 */
		(void) open_multi_backfile(*path, num_back_files, fd_array, 1);
		*unlinkpath = strdup(*path);
		if (unlinkpath == NULL)
			die_perror("strdup");
	} else if (S_ISDIR(st.st_mode)) {
		char temppath[MAXPATHLEN];

		/* remove a trailing slash from the name */
		len = strlen(*path) - 1;
		if ((*path)[len] == '/')
			(*path)[len] = '\0';

		/* find a unique name */
		for (uniq = 0; uniq <= max_uniq; uniq++) {
			/* cannot use tempnam, since TMPDIR overrides path */
			(void) snprintf(temppath, MAXPATHLEN, "%s/snapshot%d",
			    *path, uniq);
			ret_errno = open_multi_backfile(temppath,
			    num_back_files, fd_array, 0);
			if (ret_errno == 0)
				break;
		}
		if (uniq > max_uniq) {
			die(gettext("Could not find unique name in %s"), *path);
		}
		*unlinkpath = strdup(temppath);
		free(*path);
		*path = *unlinkpath;
	} else if (S_ISREG(st.st_mode)) {
		die(gettext("%s already exists."), *path);
	} else {
		die(gettext("%s: must be either the name of a file to create "
		    "or a directory."), *path);
	}

	/*
	 * write a block to the end to bump up the file size and ensure the
	 * entire range needed can be written to.
	 */
	for (i = 0; i < num_back_files; i++) {
		fd = (*fd_array)[i];
		if (i == num_back_files - 1 && fssize % max_bf_size != 0)
			backfilesize = fssize % max_bf_size;
		else
			backfilesize = max_bf_size;
		if (llseek(fd, backfilesize - 1, SEEK_SET) == -1) {
			unlink_all(*unlinkpath, num_back_files);
			die_perror("llseek");
		}

		if (write(fd, "0", 1) == -1) {
			save_errno = errno;
			unlink_all(*unlinkpath, num_back_files);
			if (save_errno == EFBIG)
				die(gettext("File system %s "
				    "does not support large files.\n"), *path);
			else
				die_perror("write");
		}
	}
	return (num_back_files);
}

u_offset_t
spec_to_bytes(char *spec)
{
	u_offset_t base;

	base = strtoull(spec, NULL, 10);
	if ((base == 0LL) && (spec[0] != '0'))
		die(gettext("Numeric option value expected"));

	spec += strspn(spec, "0123456789");

	if ((spec == NULL) || strlen(spec) != 1)
		die(gettext("Only one of b, k, m, or g may be used"));

	switch (spec[0]) {
	case 'B':
	case 'b':
		base *= 512;
		break;
	case 'K':
	case 'k':
		base *= 1024;
		break;
	case 'M':
	case 'm':
		base *= 1024 * 1024;
		break;
	case 'G':
	case 'g':
		base *= 1024 * 1024 * 1024;
		break;
	default:
		die(gettext("Must specify one of b, k, m, or g on size"));
	}

	return (base);
}

/*
 * Make sure that the first call to gen_backing_store() in a loop
 * starts with a null pointer in the outpath argument
 * and continues to pass in that same argument until
 * the loop is complete, at which point the string
 * pointed to by that argument must be freed by the caller.
 */
void
gen_backing_store_path(char *basepath, int num, char **outpath)
{
	if (*outpath == NULL) {
		*outpath = malloc(strlen(basepath) + MAX_SUFFIX);
		if (*outpath == NULL)
			die_perror("malloc");
	}

	/*
	 * Security note:  We use strcpy here, instead of the safer
	 * strncpy, because the string pointed to by outpath has
	 * been generated by THIS code, above.  Hence it is impossible
	 * for the strcpy to overrun the buffer.
	 */
	if (num == 1)
		(void) strcpy(*outpath, basepath);
	else
		(void) sprintf(*outpath, "%s.%d", basepath, num);
}

void
unlink_all(char *unlinkpath, int count)
{
	char	*bspath = NULL;
	int 	i;
	int	save_errno;

	for (i = 1; i <= count; i++) {
		/*
		 * Make sure that the first call to gen_backing_store()
		 * starts with a null pointer in the third argument
		 * and continues to pass in that same argument until
		 * the loop is complete, at which point the string
		 * pointed to by that argument must be freed.
		 */
		gen_backing_store_path(unlinkpath, i, &bspath);
		if (unlink(bspath) < 0) {
			save_errno = errno;
			warn_errno(save_errno,
			    gettext("could not unlink %s"), bspath);
		}
	}
	free(bspath);
}

void
close_all(char *closepath, int count, int *fd_array)
{
	char	*bspath = NULL;
	int 	i;
	int	save_errno;

	for (i = 1; i <= count; i++) {
		if (close(fd_array[i - 1]) != 0) {
			save_errno = errno;
			/*
			 * Make sure that the first call to gen_backing_store()
			 * starts with a null pointer in the third argument
			 * and continues to pass in that same argument until
			 * the loop is complete, at which point the string
			 * pointed to by that argument must be freed.
			 */
			gen_backing_store_path(closepath, i, &bspath);
			die_errno(save_errno, gettext(
			    "close of backing-store (%s)"), bspath);
		}
	}
	if (bspath != NULL)
		free(bspath);
}

/*
 * Create "count" files starting with name backpath ("backpath",
 * "backpath".2, "backpath".3, etc.  When this function returns,
 * either all of the files will exist and be opened (and their
 * file descriptors will be in fd_array), or NONE of will exist
 * (if they had to be created) and opened (that is, if we created a file,
 * and then failed to create a later file, the earlier files will
 * be closed and unlinked.)
 *
 * If file_exists_is_fatal is set, it is a fatal error (resulting in
 * an error message and termination) if any of the backing files to
 * be created already exists.  Otherwise, if one of the backing
 * files already exists, we close and unlink all the files we already
 * created, and return an error to the caller, but we don't print
 * an error or terminate.
 *
 * If there is any failure other than EEXIST when attempting to
 * create the file, the routine prints an error and terminates the
 * program, regardless of the setting of file_exists_is_fatal.
 */
int
open_multi_backfile(char *backpath, int count, int **fd_array,
    int file_exists_is_fatal)
{
	char	*wpath = NULL;		/* working path */
	int	i, j, fd;
	struct stat st;
	int	stat_succeeded = 0;
	int	save_errno;

	*fd_array = (int *)malloc(count * sizeof (int));
	if (*fd_array == NULL)
		die_perror("malloc");

	for (i = 0; i < count; i++) {
		/*
		 * Make sure that the first call to gen_backing_store()
		 * starts with a null pointer in the third argument
		 * and continues to pass in that same argument until
		 * the loop is complete, at which point the string
		 * pointed to by that argument must be freed.
		 */
		gen_backing_store_path(backpath, i + 1, &wpath);
		if (stat(wpath, &st) == 0)
			stat_succeeded = 1;
		else
			fd = open(wpath, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (stat_succeeded || fd < 0) {
			if (i > 0) {
				for (j = 0; j < i - 1; j++)
					(void) close((*fd_array)[j]);
				/*
				 * unlink_all's second argument is the number
				 * of files to be removed, NOT the offset
				 * into the array of fd's of the last
				 * successfully created file.
				 */
				unlink_all(backpath, i);
			}
			if (stat_succeeded || errno == EEXIST) {
				if (file_exists_is_fatal)
					die(gettext("%s exists, please specify"
					    " a nonexistent backing store."),
					    wpath);
				else
					return (1);
			} else {
					save_errno = errno;
					die_errno(save_errno,
					    gettext("Could not create"
					    " backing file %s"), wpath);
			}
		}
		(*fd_array)[i] = fd;
	}
	if (wpath != NULL)
		free(wpath);
	return (0);
}

void
die_perror(char *string)
{
	int en = errno;
	char *errstr;

	if (string == NULL) {
		string = gettext("Fatal");
	}
	errstr = strerror(en);
	if (errstr == NULL) {
		errstr = gettext("Unknown error");
	}

	fprintf(stderr, gettext("%s: %s: error %d: %s\n"),
	    progname, string, en, errstr);

	longjmp(err_main, 2);
}

void
die_usage(void)
{
	usage();

	longjmp(err_main, 1);
}

void
warn_errno(int en, char *fmt, ...)
{
	va_list ap;
	char *errstr;

	errstr = strerror(en);
	if (errstr == NULL) {
		errstr = gettext("Unknown error");
	}

	va_start(ap, fmt);
	fprintf(stderr, gettext("%s: Warning: "), progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", errstr);
	va_end(ap);
}

void
die_errno(int en, char *fmt, ...)
{
	va_list ap;
	char *errstr;

	errstr = strerror(en);
	if (errstr == NULL) {
		errstr = gettext("Unknown error");
	}

	va_start(ap, fmt);
	fprintf(stderr, gettext("%s: Fatal: "), progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", errstr);
	va_end(ap);

	longjmp(err_main, 2);
}

void
die_create_error(int error)
{
	fprintf(stderr, gettext("snapshot error: "));
	switch (error) {
	case FIOCOW_EREADONLY:
		fprintf(stderr, gettext("Read only file system\n"));
		break;
	case FIOCOW_EBUSY:
		fprintf(stderr, gettext("Snapshot already enabled\n"));
		break;
	case FIOCOW_EULOCK:
		fprintf(stderr, gettext("File system is locked\n"));
		break;
	case FIOCOW_EWLOCK:
		fprintf(stderr,
		    gettext("File system could not be write locked\n"));
		break;
	case FIOCOW_EFLUSH:
		fprintf(stderr, gettext("File system could not be flushed\n"));
		break;
	case FIOCOW_ECLEAN:
		fprintf(stderr, gettext("File system may not be stable\n"));
		break;
	case FIOCOW_ENOULOCK:
		fprintf(stderr, gettext("File system could not be unlocked\n"));
		break;
	case FIOCOW_ECHUNKSZ:
		fprintf(stderr, gettext("Chunk size must be a multiple of the "
		    "fragment size\n"));
		break;
	case FIOCOW_ECREATE:
		fprintf(stderr, gettext("Could not allocate or create "
		    "a new snapshot\n"));
		break;
	case FIOCOW_EBITMAP:
		fprintf(stderr,
		    gettext("Error scanning file system bitmaps\n"));
		break;
	case FIOCOW_EBACKFILE:
		fprintf(stderr, gettext("Invalid backing file path\n"));
		break;
	default:
		fprintf(stderr, gettext("Unknown create error\n"));
		break;
	}

	longjmp(err_main, 2);
}

void
die(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, gettext("%s: Fatal: "), progname);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);

	longjmp(err_main, 2);
}

void
usage(void)
{
	int  i;
	char *use_str[] = {
		"   %s [-F ufs] [-V] -o backing-store=path,[special_options] "
		    "/mount/point\n",
		"   %s -d [-F ufs] [-V] /mount/point | dev\n",
		"   %s -i [-F ufS] [-V] [-o special-options] /mount/point "
		    "| dev\n",
		NULL
	};
	fprintf(stderr, gettext("Usage:\n"));
	for (i = 0; use_str[i] != NULL; i++)
		fprintf(stderr, gettext(use_str[i]), progname);
}
