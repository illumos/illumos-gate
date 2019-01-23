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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "fcntl.h"
#include "string.h"
#include "errno.h"
#include "pwd.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "stdlib.h"
#include <stdarg.h>
#include <unistd.h>
#include "pwd.h"

#include "lp.h"

int
is_printer_uri(char *value)
{
	if (value == NULL)
		return (-1);

	if ((value[0] == '/') && (access(value, F_OK) == 0))
		return (-1); /* a valid path */

	if (strstr(value, "://") == NULL)
		return (-1); /* not in uri form */

	return (0);
}

/*
 * To avoid a race condition, chown() should always be called before
 * chmod().
 */
int
chownmod(char *path, uid_t owner, gid_t group, mode_t mode)
{
	int rc;

	if ((rc = Chown(path, owner, group)) == 0)
		rc = Chmod(path, mode);

	return (rc);
}


int
fdprintf(int fd, char *fmt, ...)
{
	char    buf[BUFSIZ];
	va_list ap;

	if (fd == 1)
		fflush(stdout);
	va_start(ap, fmt);
	vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);
	return (Write(fd, buf, (int)strlen(buf)));
}

char *
fdgets(char *buf, int len, int fd)
{
	char    tmp;
	int	count = 0;

	memset(buf, 0, len);
	while ((count < len) && (Read(fd, &tmp, 1) > 0))
		if ((buf[count++] = tmp) == '\n') break;

	if (count != 0)
		return (buf);
	return (NULL);
}

int
fdputs(char *buf, int fd)
{
	return (fdprintf(fd, "%s", buf));
}

int
fdputc(char c, int fd)
{
	if (fd == 1)
		fflush(stdout);
	return (write(fd, &c, 1));
}

int
open_locked(char *path, char *type, mode_t mode)
{
	struct flock		l;
	int			fd,
				oflag,
				create,
				truncate = 0;

	if (!path || !type) {
		errno = EINVAL;
		return (-1);
	}

#define	plus (type[1] == '+')
	switch (type[0]) {
	case 'w':
		oflag = plus? O_RDWR : O_WRONLY;
		create = 1;
		truncate = 1;
		break;
	case 'a':
		oflag = (plus? O_RDWR : O_WRONLY) | O_APPEND;
		create = 1;
		break;
	case 'r':
		oflag = plus? O_RDWR : O_RDONLY;
		create = 0;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	if ((fd = Open(path, oflag, mode)) == -1)
		if (errno == ENOENT && create) {
			int		old_umask = umask(0);
			int		save_errno;

			if ((fd = Open(path, oflag|O_CREAT, mode)) != -1)
				chown_lppath(path);
			save_errno = errno;
			if (old_umask)
				umask(old_umask);
			errno = save_errno;
		}

	if (fd == -1)
	switch (errno) {
	case ENOTDIR:
		errno = EACCES;
		/* FALLTHROUGH */
	default:
		return (-1);
	}

	l.l_type = (oflag & (O_WRONLY|O_RDWR)? F_WRLCK : F_RDLCK);
	l.l_whence = 1;
	l.l_start = 0;
	l.l_len = 0;
	if (Fcntl(fd, F_SETLK, &l) == -1) {
		/*
		 * Early UNIX op. sys. have wrong errno.
		 */
		if (errno == EACCES)
			errno = EAGAIN;
		Close(fd);
		return (-1);
	}

	if (truncate) {
		if ((lseek(fd, 0, SEEK_SET) == (off_t)-1) ||
		    (ftruncate(fd, 0) == -1)) {
			Close(fd);
			return (-1);
		}
	}

	return (fd);
}


FILE *
open_lpfile(char *path, char *type, mode_t mode)
{
	FILE		*fp = NULL;
	int		fd;

	if ((fd = open_locked(path, type, mode)) >= 0) {
		errno = 0;	/* fdopen() may fail and not set errno */
		if (!(fp = fdopen(fd, type))) {
			Close(fd);
		}
	}
	return (fp);
}
int
close_lpfile(FILE *fp)
{
	return (fclose(fp));
}

/*
 * chown_lppath()
 */

int
chown_lppath(char *path)
{
	static uid_t	lp_uid;

	static gid_t	lp_gid;

	static int	gotids = 0;

	struct passwd	*ppw;


	if (!gotids) {
		if (!(ppw = getpwnam(LPUSER)))
			ppw = getpwnam(ROOTUSER);
		endpwent();
		if (!ppw)
			return (-1);
		lp_uid = ppw->pw_uid;
		lp_gid = ppw->pw_gid;
		gotids = 1;
	}
	return (Chown(path, lp_uid, lp_gid));
}

/*
 * rmfile() - UNLINK FILE BUT NO COMPLAINT IF NOT THERE
 */

int
rmfile(char *path)
{
	return (Unlink(path) == 0 || errno == ENOENT);
}

/*
 * loadline() - LOAD A ONE-LINE CHARACTER STRING FROM FILE
 */

char *
loadline(char *path)
{
	int fd;
	register char		*ret;
	register int		len;
	char			buf[BUFSIZ];

	if ((fd = open_locked(path, "r", MODE_READ)) < 0)
		return (0);

	if (fdgets(buf, BUFSIZ, fd)) {
		if ((len = strlen(buf)) && buf[len - 1] == '\n')
			buf[--len] = 0;
		if ((ret = Malloc(len + 1)))
			strcpy(ret, buf);
	} else {
		errno = 0;
		ret = 0;
	}

	close(fd);
	return (ret);
}

/*
 * loadstring() - LOAD A CHARACTER STRING FROM FILE
 */

char *
loadstring(char *path)
{
	int fd;
	register char		*ret;
	register int		len;

	if ((fd = open_locked(path, "r", MODE_READ)) < 0)
		return (0);

	if ((ret = sop_up_rest(fd, (char *)0))) {
		if ((len = strlen(ret)) && ret[len - 1] == '\n')
			ret[len - 1] = 0;
	} else
		errno = 0;

	close(fd);
	return (ret);
}

/*
 * dumpstring() - DUMP CHARACTER STRING TO FILE
 */

int
dumpstring(char *path, char *str)
{
	int fd;

	if (!str)
		return (rmfile(path));

	if ((fd = open_locked(path, "w", MODE_READ)) < 0)
		return (-1);
	fdprintf(fd, "%s\n", str);
	close(fd);
	return (0);
}
