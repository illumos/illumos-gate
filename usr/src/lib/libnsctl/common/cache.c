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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <stdio.h>

#include "libnsctl.h"
#include <nsctl.h>


static int _nsc_open_path(nsc_fd_t *);
static int _nsc_open_check(nsc_fd_t *);


/*
 * Turn off ckdchk checking of nsc_open()'d volumes since we have no CKD
 * formatted volumes right now.  If/when we come back with CKD volumes,
 * we could do this more sanely by completing the implementation of the
 * CKD module, and having nsc_open() prevent any non-NSC_CKD_DISK open
 * of a CKD volume.
 * -- Simon, Thu Feb 18 10:49:46 GMT 1999
 */
static int ckdchk = 0;


nsc_fd_t *
nsc_open(path, flag, mode)
char *path;
int flag, mode;
{
	nsc_fd_t *fd;

	if (strlen(path) >= NSC_MAXPATH) {
		errno = ENAMETOOLONG;
		return (0);
	}

	if (!(fd = (nsc_fd_t *)calloc(1, sizeof (nsc_fd_t))))
		return (0);

	if ((mode & O_ACCMODE) == O_WRONLY) {
		mode &= ~O_ACCMODE;
		mode |= O_RDWR;
	}

	fd->sf_flag = flag;
	fd->sf_fmode = mode;

	strcpy(fd->sf_path, path);

	if (!_nsc_open_path(fd)) {
		free(fd);
		return (0);
	}

	if (ckdchk && !_nsc_open_check(fd)) {
		(void) nsc_close(fd);
		return (0);
	}

	return (fd);
}


nsc_fd_t *
nsc_fdopen(id, path, mode)
int id, mode;
char *path;
{
	struct flock lk;
	nsc_fd_t *fd;
	int i;

	if (strlen(path) >= NSC_MAXPATH) {
		errno = ENAMETOOLONG;
		return (0);
	}

	if (!(fd = (nsc_fd_t *)calloc(1, sizeof (nsc_fd_t))))
		return (0);

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;

	if (fcntl(id, F_SETLKW, &lk) < 0)
		return (0);

	i = fcntl(id, F_GETFL);

	if ((mode & O_ACCMODE) != O_RDONLY) {
		if ((i & O_ACCMODE) == O_RDONLY) {
			errno = EBADF;
			return (0);
		}
	}

	if ((mode & O_ACCMODE) != O_WRONLY) {
		if ((i & O_ACCMODE) == O_WRONLY) {
			errno = EBADF;
			return (0);
		}
	}

	mode = (i & O_ACCMODE) | (mode & ~O_ACCMODE);

	if (fcntl(id, F_SETFL, mode) < 0)
		return (0);

	if (lseek(id, 0, SEEK_SET) < 0)
		return (0);

	fd->sf_fd = id;
	fd->sf_fmode = mode;

	strcpy(fd->sf_path, path);

	return (fd);
}


static int
_nsc_open_path(fd)
nsc_fd_t *fd;
{
	struct nscioc_open op;

	memset(&op, 0, sizeof (op));

	op.flag = fd->sf_flag;
	op.mode = fd->sf_fmode;
	strcpy(op.path, fd->sf_path);

	if ((fd->sf_fd = open(_NSC_DEV_PATH, fd->sf_fmode)) < 0)
		return (0);

	if (ioctl(fd->sf_fd, NSCIOC_OPEN, &op) == 0)
		return (1);

	close(fd->sf_fd);
	return (0);
}


static int
_nsc_open_check(fd)
nsc_fd_t *fd;
{
	struct flock lk;
	char s[30];
	pid_t pid;
	int i;

	if ((fd->sf_fmode & O_ACCMODE) == O_RDONLY)
		return (1);

	if (access(_NSC_CKDCHK_PATH, X_OK) != 0)
		return (0);

	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = 0;
	lk.l_len = 0;

	if (fcntl(fd->sf_fd, F_SETLKW, &lk) < 0)
		return (0);

	if ((pid = fork()) == 0) {
		for (i = 1; i <= NSIG; i++)
			signal(i, SIG_IGN);

		for (i = fd->sf_fd; i <= 2 && (i = dup(i)) != -1; )
			fd->sf_fd = i;

		for (i = sysconf(_SC_OPEN_MAX); i >= 0; i--)
			if (i != fd->sf_fd)
				close(i);

		fcntl(fd->sf_fd, F_SETFD, 0);

		(void) open("/dev/null", 0);
		(void) open(_NSC_CKDCHK_LOG, O_WRONLY|O_CREAT|O_APPEND, 0666);
		(void) open(_NSC_CKDCHK_LOG, O_WRONLY|O_CREAT|O_APPEND, 0666);

		(void) sprintf(s, "%d", fd->sf_fd);

		(void) execl(_NSC_CKDCHK_PATH, "ckdchk", "-u", "-F",
			s, fd->sf_path, 0);

		exit(1);
	}

	return (pid != -1);
}


int
nsc_close(fd)
nsc_fd_t *fd;
{
	int rc;

	if (!fd)
		return (0);

	rc = close(fd->sf_fd);
	free(fd);

	return (rc);
}


int
nsc_reserve(fd)
nsc_fd_t *fd;
{
	return ((fd) ? ioctl(fd->sf_fd, NSCIOC_RESERVE, 0) : 0);
}


int
nsc_release(fd)
nsc_fd_t *fd;
{
	if (!fd)
		return (0);

	if (ckdchk && (fd->sf_fmode & O_ACCMODE) != O_RDONLY) {
		errno = EINVAL;
		return (-1);
	}

	return (ioctl(fd->sf_fd, NSCIOC_RELEASE, 0));
}


int
nsc_partsize(nsc_fd_t *fd, nsc_size_t *rvp)
{
	struct nscioc_partsize partsize;
	int rc;

	if (!fd)
		return (0);

	rc = ioctl(fd->sf_fd, NSCIOC_PARTSIZE, &partsize);
	if (rc != 0) {
		return (rc);
	}

	*rvp = (nsc_size_t)partsize.partsize;
	return (0);
}


int
nsc_fileno(fd)
nsc_fd_t *fd;
{
	return ((fd) ? fd->sf_fd : -1);
}


void
_nsc_nocheck()
{
	ckdchk = 0;
}


static int
_nsc_do_ioctl(cmd, arg)
int cmd;
void *arg;
{
	int fd, rc, save_errno;

	fd = open(_NSC_DEV_PATH, O_RDONLY);
	if (fd < 0)
		return (-1);

	rc = save_errno = 0;
	rc = ioctl(fd, cmd, arg);
	if (rc < 0)
		save_errno = errno;

	close(fd);

	errno = save_errno;
	return (rc);
}


/*
 * int
 * nsc_freeze(char *path)
 *	Freeze a pathname
 *
 * Calling/Exit State:
 *	Returns 0 for success, or -1 and sets errno.
 *
 * Description:
 *	This is the user level interface to the nsctl freeze operation.
 *	See uts/common/ns/nsctl/nsc_freeze.c for more information.
 */
int
nsc_freeze(path)
char *path;
{
	if (strlen(path) >= NSC_MAXPATH) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (_nsc_do_ioctl(NSCIOC_FREEZE, path));
}

/*
 * int
 * nsc_unfreeze(char *path)
 *	Unfreeze a pathname
 *
 * Calling/Exit State:
 *	Returns 0 for success, or -1 and sets errno.
 *
 * Description:
 *	This is the user level interface to the nsctl unfreeze operation.
 *	See uts/common/ns/nsctl/nsc_freeze.c for more information.
 */
int
nsc_unfreeze(path)
char *path;
{
	if (strlen(path) >= NSC_MAXPATH) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (_nsc_do_ioctl(NSCIOC_UNFREEZE, path));
}


/*
 * int
 * nsc_isfrozen(char *path)
 *	Test if a pathname is frozen
 *
 * Calling/Exit State:
 *	Returns:
 *		0	path is frozen
 *		1	path is not frozen
 *		-1	error (errno will be set)
 *
 * Description
 *	This is the user level interface to to the nsctl isfrozen operation.
 *	See uts/common/ns/nsctl/nsc_freeze.c for more information.
 */
int
nsc_isfrozen(path)
char *path;
{
	if (strlen(path) >= NSC_MAXPATH) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	return (_nsc_do_ioctl(NSCIOC_ISFROZEN, path));
}

int
nsc_gmem_sizes(int *size)
{
	return (_nsc_do_ioctl(NSCIOC_GLOBAL_SIZES, size));
}

int
nsc_gmem_data(char *addr)
{
	return (_nsc_do_ioctl(NSCIOC_GLOBAL_DATA, addr));
}

/*
 * int
 * nsc_nvclean()
 *	mark nvmem clean, to prevent a warmstart of the cache on reboot
 */
int
nsc_nvclean(int force)
{
	int cmd;

	cmd = force ? NSCIOC_NVMEM_CLEANF : NSCIOC_NVMEM_CLEAN;

	return (_nsc_do_ioctl(cmd, (void *)0));
}
