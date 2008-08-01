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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/mman.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>

#include <misc.h>
#include <job.h>
#include <list.h>


/*
 *	info about spool directory that we validate and fix
 */
#define	ROOT_UID	0
#define	LP_GID		8
#define	SPOOL_MODE	(S_IFDIR|S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)

/*ARGSUSED*/
int
check_client_spool(char *printer)
{
	char *dir = SPOOL_DIR;
	struct stat st;

	if ((stat(dir, &st) < 0) && (errno == ENOENT)) {
		syslog(LOG_ERR, "no spool dir, creating %s", dir);
		if (mkdir(dir, 0755) < 0) {
			syslog(LOG_ERR, "mkdir(%s): %m", dir);
			return (-1);
		}
		if (chown(dir, ROOT_UID, LP_GID) < 0) {
			syslog(LOG_ERR, "chown(%s): %m", dir);
			return (-1);
		}
		return (0);
	}
	if ((st.st_uid != ROOT_UID) || (st.st_gid != LP_GID)) {
		syslog(LOG_ERR,
			"correcting spool directory owner/group (was %d/%d)",
			st.st_uid, st.st_gid);
		if (chown(dir, ROOT_UID, LP_GID) < 0) {
			syslog(LOG_ERR, "chown(%s): %m", dir);
			return (-1);
		}
	}
	if (st.st_mode != (S_IFDIR | SPOOL_MODE)) {
		syslog(LOG_ERR,
			"spool dir (%s), incorrect permission (%0), correcting",
			dir, st.st_mode);
		if (chmod(dir, 0755) < 0) {
			syslog(LOG_ERR, "chmod(%s): %m", dir);
			return (-1);
		}
	}
	return (0);
}

int
get_lock(char *name, int write_pid)
{
	int	fd;

	syslog(LOG_DEBUG, "get_lock(%s, %d)", ((name != NULL) ? name : "NULL"),
		write_pid);
	if ((fd = open(name, O_RDWR|O_CREAT, 0640)) < 0)
		return (fd);

	if (lockf(fd, F_TLOCK, 0) < 0) {
		close(fd);
		return (-1);
	}

	if (write_pid != 0) {
		char	pid[16];

		if (ftruncate(fd, 0) < 0) {
			close(fd);
			return (-1);
		}
		if (snprintf(pid, sizeof (pid), "%d\n", (int)getpid())
			>= sizeof (pid)) {
			syslog(LOG_ERR, "get_lock: pid buffer overflow");
			return (-1);
		}
		write(fd, pid, strlen(pid));
	}
	(void) fsync(fd);

	syslog(LOG_DEBUG, "get_lock(%s, %d) - have lock",
		((name != NULL) ? name : "NULL"), write_pid);
	return (fd);
}

uid_t
get_user_id(char *name)
{
	struct passwd *p = NULL;

	if (name == NULL)
		return (-1);
	if ((p = getpwnam(name)) != NULL)
		return (p->pw_uid);
	else if ((p = getpwnam("nobody")) != NULL)
		return (p->pw_uid);
	else
		return (-2);
}


/*
 *  get_user_name()
 */
char *
get_user_name()
{
	struct passwd *p = NULL;

	if ((p = getpwuid(getuid())) != NULL)
		return (strdup(p->pw_name));
	else
		return (strdup("unknown"));
}



/*
 *  strcdup() - duplicate a string up to the first occurence of a character
 */
char *
strcdup(char *p, char c)
{
	char	*q,
		*r;

	if (p == NULL)
		return (NULL);
	if ((c == NULL) || ((q = strchr(p, c)) == NULL))
		return (strdup(p));

	if ((r = malloc((q - p) + 1)) != NULL)
		(void) strlcpy(r, p, ((q - p) + 1));
	return (r);
}


/*
 *	Should be obvious
 */
char *
strndup(char *s, int l)
{
	char *t;

	if ((s == NULL) || (l < 1))
		return (NULL);

	if ((t = malloc(l + 1)) != NULL)
		(void) strlcpy(t, s, (l + 1));
	return (t);
}


/*
 *  file_size() - need I say more
 */
int
file_size(char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return (-1);
	else
		return (st.st_size);
}


/*
 *  copy_file() - need I say more
 */
int
copy_file(char *src, char *dst)
{
	char	*buf;
	int	size;

	syslog(LOG_DEBUG, "copy_file(%s, %s)", ((src != NULL) ? src : "NULL"),
		((dst != NULL) ? dst : "NULL"));

	if ((src == NULL) || (dst == NULL))
		return (-1);

	if ((size = map_in_file(src, &buf, 1)) < 0)
		return (-1);
	if (write_buffer(dst, buf, size) < 0) {
		(void) munmap(buf, size);
		return (-1);
	}

	(void) munmap(buf, size);
	return (0);
}

int
backup_file(char *name)
{
	char buf[BUFSIZ];

	if (snprintf(buf, sizeof (buf), "%s-", name) >= sizeof (buf)) {
		syslog(LOG_ERR, "libprint:backup_file: buffer overrun");
		return (-1);
	}
	return (copy_file(name, buf));
}

/*
 *  map_in_file() - mmaps in a file into a buffer *buf.  returns the size of
 *	the mmapped buffer.
 */
int
map_in_file(const char *file, char **buf, int as_me)
{
	struct stat st;
	int	fd;

	syslog(LOG_DEBUG, "map_in_file(%s)", (file ? file : "NULL"));

	if (buf == NULL)
		return (-1);

	if (as_me != 0)
		seteuid(getuid());	/* if we are suid, lose privilege */

	if ((fd = open(file, O_RDONLY)) < 0)
		return (-1);

	if (as_me != 0)
		seteuid(0);	/* if we fail, didn't have privilege before */

	if (fstat(fd, &st) < 0) {
		close(fd);
		return (-1);
	}

	if (st.st_size == 0) {
		close(fd);
		*buf = NULL;
		return (0);
	}

	if ((*buf = mmap((caddr_t)0, (size_t)st.st_size, PROT_READ,
			(MAP_PRIVATE | MAP_NORESERVE),
			fd, (off_t)0)) == MAP_FAILED) {
		syslog(LOG_ERR, "map_in_file(%s) - mmap:%m",
			(file ? file : "NULL"));
		close(fd);
		return (-1);
	}
	close(fd);

	syslog(LOG_DEBUG, "map_in_file(%s) - size(%d), addr(0x%x)",
		(file ? file : "NULL"), st.st_size, *buf);
	return (st.st_size);
}


/*
 *  write_buffer() - writes a buffer in memory out to the file name passed in.
 *	uses mmap and ftruncate to do this.
 */
int
write_buffer(char *file, char *buf, int len)
{
	int	fd;
	char	*tmp;

	syslog(LOG_DEBUG, "write_buffer(%s, 0x%x, %d)", (file ? file : "NULL"),
		buf, len);

	if ((fd = open(file, O_CREAT|O_EXCL|O_RDWR, 0640)) < 0)
		return (-1);
	if (ftruncate(fd, len) < 0) {
		close(fd);
		return (-1);
	}
	if ((tmp = mmap((caddr_t)0, (size_t)len, PROT_READ| PROT_WRITE,
			(MAP_SHARED | MAP_NORESERVE),
			fd, (off_t)0)) == MAP_FAILED) {
		syslog(LOG_ERR, "write_buffer(%s, 0x%x, %d) - mmap:%m",
			(file ? file : "NULL"), buf, len);
		close(fd);
		return (-1);
	}
	close(fd);

	(void) memcpy(tmp, buf, len);
	(void) munmap(tmp, len);

	syslog(LOG_DEBUG, "write_buffer(%s, 0x%x, %d) - ok",
		(file ? file : "NULL"), buf, len);

	return (0);
}


/*
 *  start_daemon() - check for jobs queued, check if the lock is free.  If
 *	so, start a daemon either by forking and execing or just execing
 *	depending on the flag passed in.
 */
void
start_daemon(int do_fork)
{
	int	lock;
	job_t	**jobs = NULL;

	if ((jobs = job_list_append(NULL, NULL, NULL, SPOOL_DIR)) == NULL)
		return;

	list_iterate((void **)jobs, (VFUNC_T)job_free);
	free(jobs);

	close(lock = get_lock(MASTER_LOCK, 0));
	if (lock < 0)
		return;
	if (do_fork == 0) {
		(void) execle("/usr/lib/print/printd", MASTER_NAME, NULL, NULL);
		syslog(LOG_ERR, "start_daemon() - execl: %m");
		exit(-1);
	} else
		switch (fork()) {
		case -1:
			syslog(LOG_ERR, "start_daemon() - fork: %m");
			exit(-1);
			/* NOTREACHED */
		case 0:
			break;
		default:
			(void) execl("/usr/lib/print/printd", MASTER_NAME,
					NULL);
			syslog(LOG_ERR, "start_daemon() - execl: %m");
			exit(-1);
			/* NOTREACHED */
		}

}


/*
 *  kill_daemon() - read the master lock file and send SIGTERM to the process
 *	id stored in the file.
 */
int
kill_process(char *file)
{
	int	fd,
		pid;
	char	buf[BUFSIZ],
		*p;

	if ((fd = open(file, O_RDONLY)) < 0)
		return (-1);

	(void) memset(buf, NULL, sizeof (buf));
	if (read(fd, buf, sizeof (buf)) <= 0)
		return (-1);

	if ((p = strchr(buf, '\n')) == NULL) {	/* skip the 1st line */
		close(fd);
		return (-1);
	}
	pid = atoi(++p);		/* convert the PID */

	if ((pid < 2) || (kill(pid, SIGTERM) < 0)) {
		close(fd);
		return (-1);
	}
	close(fd);
	return (0);
}


char **
strsplit(char *string, char *seperators)
{
	char **list = NULL;
	char *where = NULL;
	char *element;

	for (element = strtok_r(string, seperators, &where); element != NULL;
	    element = strtok_r(NULL, seperators, &where))
		list = (char **)list_append((void **)list, element);

	return (list);
}
