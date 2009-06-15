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

#include <pkglib.h>

#include <alloca.h>
#include <assert.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <libintl.h>

#define	PKGADD_MAX	(512 * 1024)

#define	SADM_DIR	"/var/sadm/install"

#define	PKGSERV_PATH	"/usr/sadm/install/bin/pkgserv"

#define	ERR_PATH_TOO_BIG	"alternate root path is too long"
#define	ERR_OPEN_DOOR		"cannot open pkgserv door"
#define	ERR_START_SERVER	"cannot start pkgserv daemon: %s"
#define	ERR_START_FILTER	"cannot enumerate database entries"

struct pkg_server {
	FILE		*fp;
	char		*curbuf;
	int		buflen;
	int		door;
	boolean_t	onetime;
};

static PKGserver current_server;

static start_mode_t defmode = INVALID;
static boolean_t registered = B_FALSE;
static pid_t master_pid = -1;

static void
pkgfilename(char path[PATH_MAX], const char *root, const char *sadmdir,
    const char *file)
{
	if (snprintf(path, PATH_MAX, "%s%s/%s", root == NULL ? "" : root,
	    sadmdir == NULL ? SADM_DIR : sadmdir, file) >= PATH_MAX) {
		progerr(gettext(ERR_PATH_TOO_BIG));
		exit(99);
	}
}

static void
pkgexit_close(void)
{
	if (current_server != NULL)
		pkgcloseserver(current_server);
}

static PKGserver
pkgopenserver_i(const char *root, const char *sadmdir, boolean_t readonly,
	start_mode_t mode)
{
	PKGserver server;
	struct door_info di;
	pid_t pid;
	int stat;
	int first = B_TRUE;
	char *cmd[16];
	int args;
	char pkgdoor[PATH_MAX];
	extern char **environ;
	char *prog;
	char pidbuf[12];

	if (current_server != NULL)
		return (current_server);

	if (!registered) {
		registered = B_TRUE;
		(void) atexit(pkgexit_close);
	}
	if (readonly) {
		int fd;

		(void) strcpy(pkgdoor, "/tmp/pkgdoor.XXXXXX");
		if ((fd = mkstemp(pkgdoor)) < 0) {
			progerr(gettext(ERR_OPEN_DOOR));
			return (NULL);
		}
		(void) close(fd);
	} else {
		pkgfilename(pkgdoor, root, sadmdir, PKGDOOR);
	}

	server = malloc(sizeof (*server));

	if (server == NULL)
		goto return_null;

	server->fp = NULL;
	server->onetime = readonly;

openserver:
	server->door = open(pkgdoor, O_RDWR);

	if (server->door >= 0) {
		if (door_info(server->door, &di) == 0 && di.di_target >= 0) {
			pkgcmd_t n;
			n.cmd = PKG_NOP;
			server->buflen = 1024;
			server->curbuf = malloc(1024);
			if (server->curbuf == NULL ||
			    pkgcmd(server, &n, sizeof (n), NULL, NULL, NULL)) {
				pkgcloseserver(server);
				return (NULL);
			}
			return (current_server = server);
		}

		(void) close(server->door);
	}

	if (!first || mode == NEVER)
		goto return_null;

	first = B_FALSE;

	args = 0;
	cmd[args++] = strrchr(PKGSERV_PATH, '/') + 1;
	if (root != NULL && strcmp(root, "/") != 0) {
		cmd[args++] = "-R";
		cmd[args++] = (char *)root;
	}
	if (sadmdir != NULL && strcmp(sadmdir, SADM_DIR) != 0) {
		cmd[args++] = "-d";
		cmd[args++] = (char *)sadmdir;
	}
	if (readonly) {
		cmd[args++] = "-r";
		cmd[args++] = pkgdoor;
	}
	prog = get_prog_name();
	if (prog != NULL) {
		cmd[args++] = "-N";
		cmd[args++] = prog;
	}

	switch (mode) {
	case FLUSH_LOG:
		cmd[args++] = "-e";
		break;
	case RUN_ONCE:
		cmd[args++] = "-o";
		break;
	case PERMANENT:
		cmd[args++] = "-p";
		break;
	default:
		break;
	}

	if (master_pid != -1) {
		cmd[args++] = "-P";
		(void) snprintf(pidbuf, sizeof (pidbuf), "%d", master_pid);
		cmd[args++] = pidbuf;
	}
	cmd[args++] = NULL;
	assert(args <= sizeof (cmd)/sizeof (char *));

	if (posix_spawn(&pid, PKGSERV_PATH, NULL, NULL, cmd, environ) == 0) {
		server->onetime |= mode == RUN_ONCE;
		while (wait4(pid, &stat, 0, NULL) != -1) {
			if (WIFEXITED(stat)) {
				int s = WEXITSTATUS(stat);
				if (s == 0 || s == 1)
					if (mode == FLUSH_LOG)
						goto return_null;
					else
						goto openserver;
				if (s == 2)
					goto return_null;
				break;
			} else if (WIFSIGNALED(stat)) {
				break;
			}
		}
	}

	progerr(gettext(ERR_START_SERVER), strerror(errno));

return_null:
	if (readonly)
		(void) unlink(pkgdoor);
	free(server);
	return (NULL);
}

PKGserver
pkgopenserver(const char *root, const char *sadmdir, boolean_t ro)
{
	return (pkgopenserver_i(root, sadmdir, ro, pkgservergetmode()));
}

start_mode_t
pkgparsemode(const char *mode)
{
	if (strcasecmp(mode, MODE_PERMANENT) == 0) {
		return (PERMANENT);
	} else if (strncasecmp(mode, MODE_TIMEOUT,
	    sizeof (MODE_TIMEOUT) - 1) == 0) {
		const char *pidstr = mode + sizeof (MODE_TIMEOUT) - 1;
		if (pidstr[0] != '\0') {
			master_pid = atoi(pidstr);
			if (master_pid <= 1 || kill(master_pid, 0) != 0)
				master_pid = -1;
		}

		return (TIMEOUT);
	} else if (strcasecmp(mode, MODE_RUN_ONCE) == 0) {
		return (RUN_ONCE);
	} else {
		progerr(gettext("invalid pkgserver mode: %s"), mode);
		exit(99);
		/*NOTREACHED*/
	}
}

char *
pkgmodeargument(start_mode_t mode)
{
	static char timebuf[sizeof (PKGSERV_MODE) + sizeof (MODE_TIMEOUT) + 10];

	switch (mode) {
	case PERMANENT:
		return (PKGSERV_MODE MODE_PERMANENT);
	case TIMEOUT:
		(void) snprintf(timebuf, sizeof (timebuf),
		    PKGSERV_MODE MODE_TIMEOUT "%d",
		    (master_pid > 1 && kill(master_pid, 0) == 0) ? master_pid :
		    getpid());
		return (timebuf);
	case RUN_ONCE:
		return (PKGSERV_MODE MODE_RUN_ONCE);
	}
	progerr(gettext("Bad pkgserv mode: %d"), (int)mode);
	exit(99);
}

void
pkgserversetmode(start_mode_t mode)
{
	if (mode == DEFAULTMODE || mode == INVALID) {
		char *var = getenv(SUNW_PKG_SERVERMODE);

		if (var != NULL)
			defmode = pkgparsemode(var);
		else
			defmode = DEFAULTMODE;
	} else {
		defmode = mode;
	}
}

start_mode_t
pkgservergetmode(void)
{
	if (defmode == INVALID)
		pkgserversetmode(DEFAULTMODE);
	return (defmode);
}

void
pkgcloseserver(PKGserver server)
{

	if (server->fp != NULL)
		(void) fclose(server->fp);
	free(server->curbuf);
	if (server->onetime) {
		pkgcmd_t cmd;
		cmd.cmd = PKG_EXIT;
		(void) pkgcmd(server, &cmd, sizeof (cmd), NULL, NULL, NULL);
	}
	(void) close(server->door);
	if (server == current_server)
		current_server = NULL;
	free(server);
}

int
pkgcmd(PKGserver srv, void *cmd, size_t len, char **result, size_t *rlen,
    int *fd)
{
	door_arg_t da;

	da.data_ptr = cmd;
	da.data_size = len;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = result == NULL ? NULL : *result;
	da.rsize = rlen == NULL ? 0 : *rlen;

	if (door_call(srv->door, &da) != 0) {
		if (((pkgcmd_t *)cmd)->cmd == PKG_EXIT && errno == EINTR)
			return (0);
		return (-1);
	}

	if (da.desc_ptr != NULL) {
		int i = 0;
		if (fd != NULL)
			*fd = da.desc_ptr[i++].d_data.d_desc.d_descriptor;
		for (; i < da.desc_num; i++)
			(void) close(da.desc_ptr[i].d_data.d_desc.d_descriptor);
	}
	/* Error return */
	if (da.data_size == sizeof (int)) {
		int x = *(int *)da.data_ptr;
		if (x != 0) {
			if (result == NULL || da.rbuf != *result)
				(void) munmap(da.rbuf, da.rsize);
			return (x);
		}
	}

	/* Other result */
	if (result != NULL) {
		/* Make sure that the result is at the start of the buffer. */
		if (da.data_ptr != NULL && da.rbuf != da.data_ptr)
			(void) memmove(da.rbuf, da.data_ptr, da.data_size);
		*result = da.rbuf;
		*rlen = da.data_size;
	} else if (da.rbuf != NULL) {
		(void) munmap(da.rbuf, da.rsize);
	}
	return (0);
}

/*
 * Pkgsync:
 *	If the server is running, make sure that the contents
 *	file is written.
 *	If the server is not running, check for the log file;
 *	if there's a non-empty log file, we need to start the server
 *	as it will incorporate the log file into the contents file.
 *	And then check if the door is present.  If it doesn't, we don't
 *	need to call it.
 */

boolean_t
pkgsync_needed(const char *root, const char *sadmdir, boolean_t want_quit)
{
	struct stat pbuf;
	char pkgfile[PATH_MAX];
	boolean_t sync_needed, running;
	int fd;
	struct door_info di;

	pkgfilename(pkgfile, root, sadmdir, PKGLOG);

	sync_needed = stat(pkgfile, &pbuf) == 0 && pbuf.st_size > 0;

	if (!sync_needed && !want_quit)
		return (B_FALSE);

	pkgfilename(pkgfile, root, sadmdir, PKGDOOR);

	/* sync_needed == B_TRUE || want_quit == B_TRUE */
	running = B_FALSE;

	fd = open(pkgfile, O_RDWR);

	if (fd >= 0) {
		if (door_info(fd, &di) == 0) {
			/* It's mounted, so the server is likely there */
			running = B_TRUE;
		}
		(void) close(fd);
	}
	return (running || sync_needed);
}

int
pkgsync(const char *root, const char *sadmdir, boolean_t force_quit)
{
	void *server;
	pkgcmd_t cmd;

	/* No need to write contents file; don't start if not running */
	if (!pkgsync_needed(root, sadmdir, force_quit))
		return (0);

	server = pkgopenserver_i(root, sadmdir, B_FALSE, FLUSH_LOG);
	/*
	 * We're assuming that it started the server and exited immediately.
	 * If that didn't work, there's nothing we can do.
	 */
	if (server == NULL)
		return (0);

	cmd.cmd = force_quit ? PKG_EXIT : PKG_DUMP;

	(void) pkgcmd(server, &cmd, sizeof (cmd), NULL, NULL, NULL);
	(void) pkgcloseserver(server);
	return (0);
}

int
pkgservercommitfile(VFP_T *a_vfp, PKGserver server)
{
	size_t len = vfpGetModifiedLen(a_vfp);
	ssize_t rem = len;
	size_t off;
	pkgfilter_t *pcmd;
	char *map = a_vfp->_vfpStart;

	if (len < PKGADD_MAX)
		pcmd = alloca(sizeof (*pcmd) + len);
	else
		pcmd = alloca(sizeof (*pcmd) + PKGADD_MAX);


	off = 0;
	pcmd->cmd = PKG_ADDLINES;
	while (rem > 0) {
		char *p = map + off;
		len = rem;

		if (len >= PKGADD_MAX) {
			len = PKGADD_MAX - 1;
			while (p[len] != '\n' && len > 0)
				len--;
			if (p[len] != '\n')
				return (-1);
			len++;
		}
		(void) memcpy(&pcmd->buf[0], p, len);
		pcmd->len = len;

		if (pkgcmd(server, pcmd, sizeof (*pcmd) + len - 1,
		    NULL, NULL, NULL) != 0) {
			return (-1);
		}
		rem -= len;
		off += len;
	}
	pcmd->len = 0;
	pcmd->cmd = PKG_PKGSYNC;
	if (pkgcmd(server, pcmd, sizeof (*pcmd), NULL, NULL, NULL) != 0)
		return (-1);

	/* Mark it unmodified. */
	vfpTruncate(a_vfp);
	(void) vfpClearModified(a_vfp);

	return (0);
}

int
pkgopenfilter(PKGserver server, const char *filt)
{
	int fd;
	pkgfilter_t *pfcmd;
	int clen = filt == NULL ? 0 : strlen(filt);
	int len = sizeof (*pfcmd) + clen;

	pfcmd = alloca(len);

	if (server->fp != NULL) {
		(void) fclose(server->fp);
		server->fp = NULL;
	}

	pfcmd->cmd = PKG_FILTER;
	pfcmd->len = clen;
	if (filt != NULL)
		(void) strcpy(pfcmd->buf, filt);

	fd = -1;

	if (pkgcmd(server, pfcmd, len, NULL, NULL, &fd) != 0 || fd == -1) {
		progerr(gettext(ERR_START_FILTER));
		return (-1);
	}
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	server->fp = fdopen(fd, "r");
	if (server->fp == NULL) {
		(void) close(fd);
		progerr(gettext(ERR_START_FILTER));
		return (-1);
	}
	return (0);
}

void
pkgclosefilter(PKGserver server)
{
	if (server->fp != NULL) {
		(void) fclose(server->fp);
		server->fp = NULL;
	}
}

/*
 * Report the next entry from the contents file.
 */
char *
pkggetentry(PKGserver server, int *len, int *pathlen)
{
	int num[2];

	if (server->fp == NULL)
		return (NULL);

	if (feof(server->fp) || ferror(server->fp))
		return (NULL);

	if (fread(num, sizeof (int), 2, server->fp) != 2)
		return (NULL);

	if (num[0] > server->buflen) {
		free(server->curbuf);
		server->buflen = num[0];
		server->curbuf = malloc(server->buflen);
		if (server->curbuf == NULL)
			return (NULL);
	}
	if (fread(server->curbuf, 1, num[0], server->fp) != num[0])
		return (NULL);

	*len = num[0];
	*pathlen = num[1];

	return (server->curbuf);
}

char *
pkggetentry_named(PKGserver server, const char *path, int *len, int *pathlen)
{
	int plen = strlen(path);
	pkgfilter_t *pcmd = alloca(sizeof (*pcmd) + plen);
	char *result;
	unsigned int rlen;

	pcmd->cmd = PKG_FINDFILE;
	*pathlen = pcmd->len = plen;
	(void) memcpy(pcmd->buf, path, pcmd->len + 1);

	result = server->curbuf;
	rlen = server->buflen;

	if (pkgcmd(server, pcmd, sizeof (*pcmd) + pcmd->len,
	    &result, &rlen, NULL) != 0) {
		return (NULL);
	}
	if (rlen == 0)
		return (NULL);

	/* Result too big */
	if (result != server->curbuf) {
		free(server->curbuf);
		server->buflen = rlen;
		server->curbuf = malloc(server->buflen);
		if (server->curbuf == NULL)
			return (NULL);
		(void) memcpy(server->curbuf, result, rlen);
		(void) munmap(result, rlen);
	}
	*len = rlen;

	return (server->curbuf);
}
