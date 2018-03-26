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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Zone file descriptor support is used as a mechanism for a process inside the
 * zone to log messages to the GZ zoneadmd and also as a way to interact
 * directly with the process (via zlogin -I). The zfd thread is modeled on
 * the zcons thread so see the comment header in zcons.c for a general overview.
 * Unlike with zcons, which has a single endpoint within the zone and a single
 * endpoint used by zoneadmd, we setup multiple endpoints within the zone.
 *
 * The mode, which is controlled by the zone attribute "zlog-mode" is somewhat
 * of a misnomer since its purpose has evolved. The attribute currently
 * can have six values which are used to control:
 *    - how the zfd devices are used inside the zone
 *    - if the output on the device(s) is also teed into another stream within
 *      the zone
 *    - if we do logging in the GZ
 * See the comment on get_mode_logmax() in this file, and the comment in
 * uts/common/io/zfd.c for more details.
 *
 * Internally the zfd_mode_t struct holds the number of stdio devs (1 or 3),
 * the number of additional devs corresponding to the zone attr value and the
 * GZ logging flag.
 *
 * Note that although the mode indicates the number of devices needed, we always
 * create all possible zfd devices for simplicity.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/zfd.h>
#include <sys/mkdev.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stropts.h>
#include <thread.h>
#include <ucred.h>
#include <unistd.h>
#include <zone.h>
#include <signal.h>
#include <wchar.h>

#include <libdevinfo.h>
#include <libdevice.h>
#include <libzonecfg.h>

#include <syslog.h>
#include <sys/modctl.h>

#include "zoneadmd.h"

static zlog_t	*zlogp;
static int	shutting_down = 0;
static thread_t logger_tid;
static int	logfd = -1;
static size_t	log_sz = 0;
static size_t	log_rot_sz = 0;
static char	log_name[MAXNAMELEN] = "stdio.log";

static void rotate_log();

/*
 * The eventstream is a simple one-directional flow of messages implemented
 * with a pipe. It is used to wake up the poller when it needs to shutdown.
 */
static int eventstream[2] = {-1, -1};

#define	ZLOG_MODE		"zlog-mode"
#define	ZLOG_MAXSZ		"zlog-max-size"
#define	ZLOG_NAME		"zlog-name"
#define	ZFDNEX_DEVTREEPATH	"/pseudo/zfdnex@2"
#define	ZFDNEX_FILEPATH		"/devices/pseudo/zfdnex@2"
#define	SERVER_SOCKPATH		ZONES_TMPDIR "/%s.server_%s"
#define	ZTTY_RETRY		5

#define	NUM_ZFD_DEVS		5

typedef struct zfd_mode {
	uint_t		zmode_n_stddevs;
	uint_t		zmode_n_addl_devs;
	boolean_t	zmode_gzlogging;
} zfd_mode_t;
static zfd_mode_t mode;

/*
 * cb_data is only used by destroy_cb.
 */
struct cb_data {
	zlog_t *zlogp;
	int killed;
};

/*
 * destroy_zfd_devs() and its helper destroy_cb() tears down any zfd instances
 * associated with this zone. If things went very wrong, we might have an
 * incorrect number of instances hanging around.  This routine hunts down and
 * tries to remove all of them. Of course, if the fd is open, the instance will
 * not detach, which is a potential issue.
 */
static int
destroy_cb(di_node_t node, void *arg)
{
	struct cb_data *cb = (struct cb_data *)arg;
	char *prop_data;
	char *tmp;
	char devpath[MAXPATHLEN];
	devctl_hdl_t hdl;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "zfd_zname",
	    &prop_data) == -1)
		return (DI_WALK_CONTINUE);

	assert(prop_data != NULL);
	if (strcmp(prop_data, zone_name) != 0) {
		/* this is a zfd for a different zone */
		return (DI_WALK_CONTINUE);
	}

	tmp = di_devfs_path(node);
	(void) snprintf(devpath, sizeof (devpath), "/devices/%s", tmp);
	di_devfs_path_free(tmp);

	if ((hdl = devctl_device_acquire(devpath, 0)) == NULL) {
		zerror(cb->zlogp, B_TRUE, "WARNING: zfd %s found, "
		    "but it could not be controlled.", devpath);
		return (DI_WALK_CONTINUE);
	}
	if (devctl_device_remove(hdl) == 0) {
		cb->killed++;
	} else {
		zerror(cb->zlogp, B_TRUE, "WARNING: zfd %s found, "
		    "but it could not be removed.", devpath);
	}
	devctl_release(hdl);
	return (DI_WALK_CONTINUE);
}

static int
destroy_zfd_devs(zlog_t *zlogp)
{
	di_node_t root;
	struct cb_data cb;

	bzero(&cb, sizeof (cb));
	cb.zlogp = zlogp;

	if ((root = di_init(ZFDNEX_DEVTREEPATH, DINFOCPYALL)) == DI_NODE_NIL) {
		zerror(zlogp, B_TRUE, "di_init failed");
		return (-1);
	}

	(void) di_walk_node(root, DI_WALK_CLDFIRST, (void *)&cb, destroy_cb);

	di_fini(root);
	return (0);
}

static void
make_tty(zlog_t *zlogp, int id)
{
	int i;
	int fd = -1;
	char stdpath[MAXPATHLEN];

	/*
	 * Open the master side of the dev and issue the ZFD_MAKETTY ioctl,
	 * which will cause the the various tty-related streams modules to be
	 * pushed when the slave opens the device.
	 *
	 * In very rare cases the open returns ENOENT if devfs doesn't have
	 * everything setup yet due to heavy zone startup load. Wait for
	 * 1 sec. and retry a few times. Even if we can't setup tty mode
	 * we still move on.
	 */
	(void) snprintf(stdpath, sizeof (stdpath), "/dev/zfd/%s/master/%d",
	    zone_name, id);

	for (i = 0; !shutting_down && i < ZTTY_RETRY; i++) {
		fd = open(stdpath, O_RDWR | O_NOCTTY);
		if (fd >= 0 || errno != ENOENT)
			break;
		(void) sleep(1);
	}
	if (fd == -1) {
		zerror(zlogp, B_TRUE, "ERROR: could not open zfd %d for "
		    "zone %s to set tty mode", id, zone_name);
	} else {
		/*
		 * This ioctl can occasionally return ENXIO if devfs doesn't
		 * have everything plumbed up yet due to heavy zone startup
		 * load. Wait for 1 sec. and retry a few times before we give
		 * up.
		 */
		for (i = 0; !shutting_down && i < ZTTY_RETRY; i++) {
			if (ioctl(fd, ZFD_MAKETTY) == 0) {
				break;
			} else if (errno != ENXIO) {
				break;
			}
			(void) sleep(1);
		}
	}

	if (fd != -1)
		(void) close(fd);
}

/*
 * init_zfd_devs() drives the device-tree configuration of the zone fd devices.
 * The general strategy is to use the libdevice (devctl) interfaces to
 * instantiate all of new zone fd nodes.  We do a lot of sanity checking, and
 * are careful to reuse a dev if one exists.
 *
 * Once the devices are in the device tree, we kick devfsadm via
 * di_devlink_init() to ensure that the appropriate symlinks (to the master and
 * slave fd devices) are placed in /dev in the global zone.
 */
static int
init_zfd_dev(zlog_t *zlogp, devctl_hdl_t bus_hdl, int id)
{
	int rv = -1;
	devctl_ddef_t ddef_hdl = NULL;
	devctl_hdl_t dev_hdl = NULL;

	if ((ddef_hdl = devctl_ddef_alloc("zfd", 0)) == NULL) {
		zerror(zlogp, B_TRUE, "failed to allocate ddef handle");
		goto error;
	}

	/*
	 * Set four properties on this node; the name of the zone, the dev name
	 * seen inside the zone, a flag which lets pseudo know that it is OK to
	 * automatically allocate an instance # for this device, and the last
	 * one tells the device framework not to auto-detach this node - we
	 * need the node to still be there when we ask devfsadmd to make links,
	 * and when we need to open it.
	 */
	if (devctl_ddef_string(ddef_hdl, "zfd_zname", zone_name) == -1) {
		zerror(zlogp, B_TRUE, "failed to create zfd_zname property");
		goto error;
	}
	if (devctl_ddef_int(ddef_hdl, "zfd_id", id) == -1) {
		zerror(zlogp, B_TRUE, "failed to create zfd_id property");
		goto error;
	}
	if (devctl_ddef_int(ddef_hdl, "auto-assign-instance", 1) == -1) {
		zerror(zlogp, B_TRUE, "failed to create auto-assign-instance "
		    "property");
		goto error;
	}
	if (devctl_ddef_int(ddef_hdl, "ddi-no-autodetach", 1) == -1) {
		zerror(zlogp, B_TRUE, "failed to create ddi-no-auto-detach "
		    "property");
		goto error;
	}
	if (devctl_bus_dev_create(bus_hdl, ddef_hdl, 0, &dev_hdl) == -1) {
		zerror(zlogp, B_TRUE, "failed to create zfd node");
		goto error;
	}
	rv = 0;

error:
	if (ddef_hdl)
		devctl_ddef_free(ddef_hdl);
	if (dev_hdl)
		devctl_release(dev_hdl);
	return (rv);
}

static int
init_zfd_devs(zlog_t *zlogp, zfd_mode_t *mode)
{
	devctl_hdl_t bus_hdl = NULL;
	di_devlink_handle_t dl = NULL;
	int rv = -1;
	int i;

	/*
	 * Time to make the devices.
	 */
	if ((bus_hdl = devctl_bus_acquire(ZFDNEX_FILEPATH, 0)) == NULL) {
		zerror(zlogp, B_TRUE, "devctl_bus_acquire failed");
		goto error;
	}

	for (i = 0; i < NUM_ZFD_DEVS; i++) {
		if (init_zfd_dev(zlogp, bus_hdl, i) != 0)
			goto error;
	}

	if ((dl = di_devlink_init("zfd", DI_MAKE_LINK)) == NULL) {
		zerror(zlogp, B_TRUE, "failed to create devlinks");
		goto error;
	}

	(void) di_devlink_fini(&dl);
	rv = 0;

	if (mode->zmode_n_stddevs == 1) {
		/* We want the primary stream to look like a tty. */
		make_tty(zlogp, 0);
	}

error:
	if (bus_hdl)
		devctl_release(bus_hdl);
	return (rv);
}

static int
init_server_sock(zlog_t *zlogp, int *servfd, char *nm)
{
	int resfd = -1;
	struct sockaddr_un servaddr;

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) snprintf(servaddr.sun_path, sizeof (servaddr.sun_path),
	    SERVER_SOCKPATH, zone_name, nm);

	if ((resfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		zerror(zlogp, B_TRUE, "server setup: could not create socket");
		goto err;
	}
	(void) unlink(servaddr.sun_path);

	if (bind(resfd, (struct sockaddr *)&servaddr, sizeof (servaddr))
	    == -1) {
		zerror(zlogp, B_TRUE,
		    "server setup: could not bind to socket");
		goto err;
	}

	if (listen(resfd, 4) == -1) {
		zerror(zlogp, B_TRUE,
		    "server setup: could not listen on socket");
		goto err;
	}

	*servfd = resfd;
	return (0);

err:
	(void) unlink(servaddr.sun_path);
	if (resfd != -1)
		(void) close(resfd);
	return (-1);
}

static void
destroy_server_sock(int servfd, char *nm)
{
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), SERVER_SOCKPATH, zone_name, nm);
	(void) unlink(path);
	(void) shutdown(servfd, SHUT_RDWR);
	(void) close(servfd);
}

/*
 * Read the "ident" string from the client's descriptor; this routine also
 * tolerates being called with pid=NULL, for times when you want to "eat"
 * the ident string from a client without saving it.
 */
static int
get_client_ident(int clifd, pid_t *pid, char *locale, size_t locale_len,
    uint_t *flagsp)
{
	char buf[BUFSIZ], *bufp;
	size_t buflen = sizeof (buf);
	char c = '\0';
	int i = 0, r;
	ucred_t *cred = NULL;

	/* "eat up the ident string" case, for simplicity */
	if (pid == NULL) {
		assert(locale == NULL && locale_len == 0);
		while (read(clifd, &c, 1) == 1) {
			if (c == '\n')
				return (0);
		}
	}

	bzero(buf, sizeof (buf));
	while ((buflen > 1) && (r = read(clifd, &c, 1)) == 1) {
		buflen--;
		if (c == '\n')
			break;

		buf[i] = c;
		i++;
	}
	if (r == -1)
		return (-1);

	/*
	 * We've filled the buffer, but still haven't seen \n.  Keep eating
	 * until we find it; we don't expect this to happen, but this is
	 * defensive.
	 */
	if (c != '\n') {
		while ((r = read(clifd, &c, sizeof (c))) > 0)
			if (c == '\n')
				break;
	}

	/*
	 * Parse buffer for message of the form:
	 * IDENT <locale> <flags>
	 */
	bufp = buf;
	if (strncmp(bufp, "IDENT ", 6) != 0)
		return (-1);
	bufp += 6;

	if (getpeerucred(clifd, &cred) == 0) {
		*pid = ucred_getpid((const ucred_t *)cred);
		ucred_free(cred);
	} else {
		return (-1);
	}

	while (*bufp != '\0' && isspace(*bufp))
		bufp++;
	buflen = strlen(bufp) - 1;
	bufp[buflen - 1] = '\0';
	(void) strlcpy(locale, bufp, locale_len);

	*flagsp = atoi(&bufp[buflen]);

	return (0);
}

static int
accept_client(int servfd, pid_t *pid, char *locale, size_t locale_len,
    uint_t *flagsp)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen;
	int flags;

	clilen = sizeof (cliaddr);
	connfd = accept(servfd, (struct sockaddr *)&cliaddr, &clilen);
	if (connfd == -1)
		return (-1);
	if (pid != NULL) {
		if (get_client_ident(connfd, pid, locale, locale_len, flagsp)
		    == -1) {
			(void) shutdown(connfd, SHUT_RDWR);
			(void) close(connfd);
			return (-1);
		}
		(void) write(connfd, "OK\n", 3);
	}

	flags = fcntl(connfd, F_GETFL, 0);
	if (flags != -1)
		(void) fcntl(connfd, F_SETFL, flags | O_NONBLOCK | FD_CLOEXEC);

	return (connfd);
}

static void
reject_client(int servfd, pid_t clientpid)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen;
	char nak[MAXPATHLEN];

	clilen = sizeof (cliaddr);
	connfd = accept(servfd, (struct sockaddr *)&cliaddr, &clilen);

	/*
	 * After getting its ident string, tell client to get lost.
	 */
	if (get_client_ident(connfd, NULL, NULL, 0, NULL) == 0) {
		(void) snprintf(nak, sizeof (nak), "%lu\n",
		    clientpid);
		(void) write(connfd, nak, strlen(nak));
	}
	(void) shutdown(connfd, SHUT_RDWR);
	(void) close(connfd);
}

static int
accept_socket(int servfd, pid_t verpid)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen = sizeof (cliaddr);
	ucred_t *cred = NULL;
	pid_t rpid = -1;
	int flags;

	connfd = accept(servfd, (struct sockaddr *)&cliaddr, &clilen);
	if (connfd == -1)
		return (-1);

	/* Confirm connecting process is who we expect */
	if (getpeerucred(connfd, &cred) == 0) {
		rpid = ucred_getpid((const ucred_t *)cred);
		ucred_free(cred);
	}
	if (rpid == -1 || rpid != verpid) {
		(void) shutdown(connfd, SHUT_RDWR);
		(void) close(connfd);
		return (-1);
	}

	flags = fcntl(connfd, F_GETFL, 0);
	if (flags != -1)
		(void) fcntl(connfd, F_SETFL, flags | O_NONBLOCK | FD_CLOEXEC);

	return (connfd);
}

static void
ctlcmd_process(int sockfd, int stdoutfd, unsigned int *flags)
{
	char buf[BUFSIZ];
	int i;
	for (i = 0; i < BUFSIZ-1; i++) {
		char c;
		if (read(sockfd, &c, 1) != 1 ||
		    c == '\n' || c == '\0') {
			break;
		}
		buf[i] = c;
	}
	if (i == 0) {
		goto fail;
	}
	buf[i+1] = '\0';

	if (strncmp(buf, "TIOCSWINSZ ", 11) == 0) {
		char *next = buf + 11;
		struct winsize ws;
		errno = 0;
		ws.ws_row = strtol(next, &next, 10);
		if (errno == EINVAL) {
			goto fail;
		}
		ws.ws_col = strtol(next + 1, &next, 10);
		if (errno == EINVAL) {
			goto fail;
		}
		if (ioctl(stdoutfd, TIOCSWINSZ, &ws) == 0) {
			(void) write(sockfd, "OK\n", 3);
			return;
		}
	}
	if (strncmp(buf, "SETFLAGS ", 9) == 0) {
		char *next = buf + 9;
		unsigned int result;
		errno = 0;
		result = strtoul(next, &next, 10);
		if (errno == EINVAL) {
			goto fail;
		}
		*flags = result;
		(void) write(sockfd, "OK\n", 3);
		return;
	}
fail:
	(void) write(sockfd, "FAIL\n", 5);
}

/*
 * Check to see if the client at the other end of the socket is still alive; we
 * know it is not if it throws EPIPE at us when we try to write an otherwise
 * harmless 0-length message to it.
 */
static int
test_client(int clifd)
{
	if ((write(clifd, "", 0) == -1) && errno == EPIPE)
		return (-1);
	return (0);
}

/*
 * Modify the input string with json escapes. Since the destination can thus
 * be larger than the source, it may get truncated, although we do use a
 * larger buffer.
 */
static void
escape_json(char *sbuf, int slen, char *dbuf, int dlen)
{
	int i;
	mbstate_t mbr;
	wchar_t c;
	size_t sz;

	bzero(&mbr, sizeof (mbr));

	sbuf[slen] = '\0';
	i = 0;
	while (i < dlen && (sz = mbrtowc(&c, sbuf, MB_CUR_MAX, &mbr)) > 0) {
		switch (c) {
		case '\\':
			dbuf[i++] = '\\';
			dbuf[i++] = '\\';
			break;

		case '"':
			dbuf[i++] = '\\';
			dbuf[i++] = '"';
			break;

		case '\b':
			dbuf[i++] = '\\';
			dbuf[i++] = 'b';
			break;

		case '\f':
			dbuf[i++] = '\\';
			dbuf[i++] = 'f';
			break;

		case '\n':
			dbuf[i++] = '\\';
			dbuf[i++] = 'n';
			break;

		case '\r':
			dbuf[i++] = '\\';
			dbuf[i++] = 'r';
			break;

		case '\t':
			dbuf[i++] = '\\';
			dbuf[i++] = 't';
			break;

		default:
			if ((c >= 0x00 && c <= 0x1f) ||
			    (c > 0x7f && c <= 0xffff)) {

				i += snprintf(&dbuf[i], (dlen - i), "\\u%04x",
				    (int)(0xffff & c));
			} else if (c >= 0x20 && c <= 0x7f) {
				dbuf[i++] = 0xff & c;
			}

			break;
		}
		sbuf += sz;
	}

	if (i == dlen)
		dbuf[--i] = '\0';
	else
		dbuf[i] = '\0';
}

/*
 * We output to the log file as json.
 * ex. for string 'msg\n' on the zone's stdout:
 *    {"log":"msg\n","stream":"stdout","time":"2014-10-24T20:12:11.101973117Z"}
 *
 * We use ns in the last field of the timestamp for compatability.
 *
 * We keep track of the size of the log file and rotate it when we exceed
 * the log size limit (if one is set).
 */
static void
wr_log_msg(char *buf, int len, int from)
{
	struct timeval tv;
	int olen;
	char ts[64];
	char nbuf[BUFSIZ * 2];
	char obuf[BUFSIZ * 2];
	static boolean_t log_wr_err = B_FALSE;

	if (logfd == -1)
		return;

	escape_json(buf, len, nbuf, sizeof (nbuf));

	if (gettimeofday(&tv, NULL) != 0)
		return;
	(void) strftime(ts, sizeof (ts), "%FT%T", gmtime(&tv.tv_sec));

	olen = snprintf(obuf, sizeof (obuf),
	    "{\"log\":\"%s\",\"stream\":\"%s\",\"time\":\"%s.%ldZ\"}\n",
	    nbuf, (from == 1) ? "stdout" : "stderr", ts, tv.tv_usec * 1000);

	if (write(logfd, obuf, olen) != olen) {
		if (!log_wr_err) {
			zerror(zlogp, B_TRUE, "log file write error");
			log_wr_err = B_TRUE;
		}
		return;
	}

	log_sz += olen;
	if (log_rot_sz > 0 && log_sz >= log_rot_sz)
		rotate_log();
}

/*
 * We want to sleep for a little while but need to be responsive if the zone is
 * halting. We poll/sleep on the event stream so we can notice if we're halting.
 * Return true if halting, otherwise false.
 */
static boolean_t
halt_sleep(int slptime)
{
	struct pollfd evfd[1];

	evfd[0].fd = eventstream[1];
	evfd[0].events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;

	if (poll(evfd, 1, slptime) > 0) {
		/* zone halting */
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * This routine drives the logging and interactive I/O loop. It polls for
 * input from the zone side of the fd (output to stdout/stderr), and from the
 * client (input to the zone's stdin).  Additionally, it polls on the server
 * fd, and disconnects any clients that might try to hook up with the zone
 * while the fd's are in use.
 *
 * Data from the zone's stdout and stderr is formatted in json and written to
 * the log file whether an interactive client is connected or not.
 *
 * When the client first calls us up, it is expected to send a line giving its
 * "identity"; this consists of the string 'IDENT <pid> <locale>'. This is so
 * that we can report that the fd's are busy, along with some diagnostics
 * about who has them busy; the locale is ignore here but kept for compatability
 * with the zlogin code when running on the zone's console.
 *
 * We need to handle the case where there is no server within the zone (or
 * the server gets stuck) and data that we're writing to the zone server's
 * stdin fills the pipe. Because of the way the zfd device works writes can
 * flow into the stream and simply be dropped, if there is no server, or writes
 * could return -1 with EAGAIN if the server is stuck. Since we ignore errors
 * on the write to stdin, we won't get blocked in that case but we'd like to
 * avoid dropping initial input if the server within the zone hasn't started
 * yet. To handle this we wait to read initial input until we detect that there
 * is a server inside the zone. We have to poll for this so that we can
 * re-run the ioctl to notice when a server shows up. This poll/wait is handled
 * by halt_sleep() so that we can be responsive if the zone wants to halt.
 * We only do this check to avoid dropping initial input so it is possible for
 * the server within the zone to go away later. At that point zfd will just
 * drop any new input flowing into the stream.
 */
static void
do_zfd_io(int gzctlfd, int gzservfd, int gzerrfd, int stdinfd, int stdoutfd,
    int stderrfd)
{
	struct pollfd pollfds[8];
	char ibuf[BUFSIZ + 1];
	int cc, ret;
	int ctlfd = -1;
	int clifd = -1;
	int clierrfd = -1;
	int pollerr = 0;
	char clilocale[MAXPATHLEN];
	pid_t clipid = 0;
	uint_t flags = 0;
	boolean_t stdin_ready = B_FALSE;
	int slptime = 250;	/* initial poll sleep time in ms */

	/* client control socket, watch for read events */
	pollfds[0].fd = ctlfd;
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND |
	    POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	/* client socket, watch for read events */
	pollfds[1].fd = clifd;
	pollfds[1].events = pollfds[0].events;

	/* stdout, watch for read events */
	pollfds[2].fd = stdoutfd;
	pollfds[2].events = pollfds[0].events;

	/* stderr, watch for read events */
	pollfds[3].fd = stderrfd;
	pollfds[3].events = pollfds[0].events;

	/* the server control socket; watch for new connections */
	pollfds[4].fd = gzctlfd;
	pollfds[4].events = POLLIN | POLLRDNORM;

	/* the server stdin/out socket; watch for new connections */
	pollfds[5].fd = gzservfd;
	pollfds[5].events = POLLIN | POLLRDNORM;

	/* the server stderr socket; watch for new connections */
	pollfds[6].fd = gzerrfd;
	pollfds[6].events = POLLIN | POLLRDNORM;

	/* the eventstream; any input means the zone is halting */
	pollfds[7].fd = eventstream[1];
	pollfds[7].events = pollfds[0].events;

	while (!shutting_down) {
		pollfds[0].revents = pollfds[1].revents = 0;
		pollfds[2].revents = pollfds[3].revents = 0;
		pollfds[4].revents = pollfds[5].revents = 0;
		pollfds[6].revents = pollfds[7].revents = 0;

		ret = poll(pollfds, 8, -1);
		if (ret == -1 && errno != EINTR) {
			zerror(zlogp, B_TRUE, "poll failed");
			/* we are hosed, close connection */
			break;
		}

		/* control events from client */
		if (pollfds[0].revents &
		    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
			/* process control message */
			ctlcmd_process(ctlfd, stdoutfd, &flags);
		} else if (pollfds[0].revents) {
			/* bail if any error occurs */
			pollerr = pollfds[0].revents;
			zerror(zlogp, B_FALSE, "closing connection "
			    "with control channel, pollerr %d\n", pollerr);
			break;
		}

		/* event from client side */
		if (pollfds[1].revents) {
			if (stdin_ready) {
				if (pollfds[1].revents & (POLLIN |
				    POLLRDNORM | POLLRDBAND | POLLPRI)) {
					errno = 0;
					cc = read(clifd, ibuf, BUFSIZ);
					if (cc > 0) {
						/*
						 * See comment for this
						 * function on what happens if
						 * there is no reader in the
						 * zone. EOF is handled below.
						 */
						(void) write(stdinfd, ibuf, cc);
					}
				} else if (pollfds[1].revents & (POLLERR |
				    POLLNVAL))  {
					pollerr = pollfds[1].revents;
					zerror(zlogp, B_FALSE,
					    "closing connection "
					    "with client, pollerr %d\n",
					    pollerr);
					break;
				}

				if (pollfds[1].revents & POLLHUP) {
					if (flags & ZLOGIN_ZFD_EOF) {
						/*
						 * Let the client know. We've
						 * already serviced any pending
						 * regular input. Let the
						 * stream clear since the EOF
						 * ioctl jumps to the head.
						 */
						(void) ioctl(stdinfd, I_FLUSH);
						if (halt_sleep(250))
							break;
						(void) ioctl(stdinfd, ZFD_EOF);
					}
					break;
				}
			} else {
				if (ioctl(stdinfd, ZFD_HAS_SLAVE) == 0) {
					stdin_ready = B_TRUE;
				} else {
					/*
					 * There is nothing in the zone to read
					 * our input. Presumably the user
					 * providing input expects something to
					 * show up, but that is no guarantee.
					 * Since we haven't serviced the pending
					 * input poll yet, we don't want to
					 * immediately loop around but we also
					 * need to be responsive if the zone is
					 * halting.
					 */
					if (halt_sleep(slptime))
						break;

					if (slptime < 5000)
						slptime += 250;
				}
			}
		}

		/* event from the zone's stdout */
		if (pollfds[2].revents) {
			if (pollfds[2].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(stdoutfd, ibuf, BUFSIZ);
				/* zfd is a stream, so ignore 0 length read */
				if (cc < 0 && (errno != EINTR) &&
				    (errno != EAGAIN))
					break;
				if (cc > 0) {
					wr_log_msg(ibuf, cc, 1);

					/*
					 * Lose output if no one is listening,
					 * otherwise pass it on.
					 */
					if (clifd != -1)
						(void) write(clifd, ibuf, cc);
				}
			} else {
				pollerr = pollfds[2].revents;
				zerror(zlogp, B_FALSE,
				    "closing connection with stdout zfd, "
				    "pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from the zone's stderr */
		if (pollfds[3].revents) {
			if (pollfds[3].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(stderrfd, ibuf, BUFSIZ);
				/* zfd is a stream, so ignore 0 length read */
				if (cc < 0 && (errno != EINTR) &&
				    (errno != EAGAIN))
					break;
				if (cc > 0) {
					wr_log_msg(ibuf, cc, 2);

					/*
					 * Lose output if no one is listening,
					 * otherwise pass it on.
					 */
					if (clierrfd != -1)
						(void) write(clierrfd, ibuf,
						    cc);
				}
			} else {
				pollerr = pollfds[3].revents;
				zerror(zlogp, B_FALSE,
				    "closing connection with stderr zfd, "
				    "pollerr %d\n", pollerr);
				break;
			}
		}

		/* connect event from server control socket */
		if (pollfds[4].revents) {
			if (ctlfd != -1) {
				/*
				 * Test the client to see if it is really
				 * still alive.  If it has died but we
				 * haven't yet detected that, we might
				 * deny a legitimate connect attempt.  If it
				 * is dead, we break out; once we tear down
				 * the old connection, the new connection
				 * will happen.
				 */
				if (test_client(ctlfd) == -1) {
					break;
				}
				/* we're already handling a client */
				reject_client(gzctlfd, clipid);
			} else {
				ctlfd = accept_client(gzctlfd, &clipid,
				    clilocale, sizeof (clilocale), &flags);
				if (ctlfd != -1) {
					pollfds[0].fd = ctlfd;
				} else {
					break;
				}
			}
		}

		/* connect event from server stdin/out socket */
		if (pollfds[5].revents) {
			if (ctlfd == -1) {
				/*
				 * This shouldn't happen since the client is
				 * expected to connect on the control socket
				 * first. If we see this, tear everything down
				 * and start over.
				 */
				zerror(zlogp, B_FALSE, "GZ zfd stdin/stdout "
				    "connection attempt with no GZ control\n");
				break;
			}
			assert(clifd == -1);
			if ((clifd = accept_socket(gzservfd, clipid)) != -1) {
				/* No need to watch for other new connections */
				pollfds[5].fd = -1;
				/* Client input is of interest, though */
				pollfds[1].fd = clifd;
			} else {
				break;
			}
		}

		/* connection event from server stderr socket */
		if (pollfds[6].revents) {
			if (ctlfd == -1) {
				/*
				 * Same conditions apply to stderr as stdin/out.
				 */
				zerror(zlogp, B_FALSE, "GZ zfd stderr "
				    "connection attempt with no GZ control\n");
				break;
			}
			assert(clierrfd == -1);
			if ((clierrfd = accept_socket(gzerrfd, clipid)) != -1) {
				/* No need to watch for other new connections */
				pollfds[6].fd = -1;
			} else {
				break;
			}
		}

		/*
		 * Watch for events on the eventstream.  This is how we get
		 * notified of the zone halting, etc.  It provides us a
		 * "wakeup" from poll when important things happen, which
		 * is good.
		 */
		if (pollfds[7].revents) {
			break;
		}
	}

	if (clifd != -1) {
		(void) shutdown(clifd, SHUT_RDWR);
		(void) close(clifd);
	}

	if (clierrfd != -1) {
		(void) shutdown(clierrfd, SHUT_RDWR);
		(void) close(clierrfd);
	}
}

static int
open_fd(zlog_t *zlogp, int id, int rw)
{
	int fd;
	int flag = O_NONBLOCK | O_NOCTTY | O_CLOEXEC;
	int retried = 0;
	char stdpath[MAXPATHLEN];

	(void) snprintf(stdpath, sizeof (stdpath), "/dev/zfd/%s/master/%d",
	    zone_name, id);
	flag |= rw;

	while (!shutting_down) {
		if ((fd = open(stdpath, flag)) != -1) {
			/*
			 * Setting RPROTDIS on the stream means that the
			 * control portion of messages received (which we don't
			 * care about) will be discarded by the stream head. If
			 * we allowed such messages, we wouldn't be able to use
			 * read(2), as it fails (EBADMSG) when a message with a
			 * control element is received.
			 */
			if (ioctl(fd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to set options on zfd");
				return (-1);
			}
			return (fd);
		}

		if (retried++ > 60)
			break;

		(void) sleep(1);
	}

	zerror(zlogp, B_TRUE, "failed to open zfd");
	return (-1);
}

static void
open_logfile()
{
	char logpath[MAXPATHLEN];

	logfd = -1;
	log_sz = 0;

	(void) snprintf(logpath, sizeof (logpath), "%s/logs", zonepath);
	(void) mkdir(logpath, 0700);

	(void) snprintf(logpath, sizeof (logpath), "%s/logs/%s", zonepath,
	    log_name);

	if ((logfd = open(logpath, O_WRONLY | O_APPEND | O_CREAT,
	    0600)) == -1) {
		zerror(zlogp, B_TRUE, "failed to open log file");
	} else {
		struct stat64 sb;

		if (fstat64(logfd, &sb) == 0)
			log_sz = sb.st_size;
	}
}

static void
rotate_log()
{
	time_t t;
	struct tm gtm;
	char onm[MAXPATHLEN], rnm[MAXPATHLEN];

	if ((t = time(NULL)) == (time_t)-1 || gmtime_r(&t, &gtm) == NULL) {
		zerror(zlogp, B_TRUE, "failed to format time");
		return;
	}

	(void) snprintf(rnm, sizeof (rnm),
	    "%s/logs/%s.%d%02d%02dT%02d%02d%02dZ",
	    zonepath, log_name, gtm.tm_year + 1900, gtm.tm_mon + 1, gtm.tm_mday,
	    gtm.tm_hour, gtm.tm_min, gtm.tm_sec);
	(void) snprintf(onm, sizeof (onm), "%s/logs/%s", zonepath, log_name);

	(void) close(logfd);
	if (rename(onm, rnm) != 0)
		zerror(zlogp, B_TRUE, "failed to rotate log file");
	open_logfile();
}


/* ARGSUSED */
void
hup_handler(int i)
{
	if (logfd != -1) {
		(void) close(logfd);
		open_logfile();
	}
}

/*
 * Body of the worker thread to log the zfd's stdout and stderr to a log file
 * and to perform interactive IO to the stdin, stdout and stderr zfd's.
 *
 * The stdin, stdout and stderr are from the perspective of the process inside
 * the zone, so the zoneadmd view is opposite (i.e. we write to the stdin fd
 * and read from the stdout/stderr fds).
 */
static void
srvr(void *modearg)
{
	zfd_mode_t *mode = (zfd_mode_t *)modearg;
	int gzctlfd = -1;
	int gzoutfd = -1;
	int stdinfd = -1;
	int stdoutfd = -1;
	sigset_t blockset;
	int gzerrfd = -1;
	int stderrfd = -1;
	int flags;
	int len;
	char ibuf[BUFSIZ + 1];

	if (!shutting_down && mode->zmode_gzlogging)
		open_logfile();

	/*
	 * This thread should receive SIGHUP so that it can close the log
	 * file, and reopen it, during log rotation.
	 */
	sigset(SIGHUP, hup_handler);
	(void) sigfillset(&blockset);
	(void) sigdelset(&blockset, SIGHUP);
	(void) thr_sigsetmask(SIG_BLOCK, &blockset, NULL);

	if (!shutting_down) {
		if (pipe(eventstream) != 0) {
			zerror(zlogp, B_TRUE, "failed to open logger control "
			    "pipe");
			return;
		}
	}

	while (!shutting_down) {
		if (init_server_sock(zlogp, &gzctlfd, "ctl") == -1) {
			zerror(zlogp, B_FALSE,
			    "server setup: control socket init failed");
			goto death;
		}
		if (init_server_sock(zlogp, &gzoutfd, "out") == -1) {
			zerror(zlogp, B_FALSE,
			    "server setup: stdout socket init failed");
			goto death;
		}
		if (init_server_sock(zlogp, &gzerrfd, "err") == -1) {
			zerror(zlogp, B_FALSE,
			    "server setup: stderr socket init failed");
			goto death;
		}

		if (mode->zmode_n_stddevs == 1) {
			if ((stdinfd = open_fd(zlogp, 0, O_RDWR)) == -1) {
				goto death;
			}
			stdoutfd = stdinfd;
		} else {
			if ((stdinfd = open_fd(zlogp, 0, O_WRONLY)) == -1 ||
			    (stdoutfd = open_fd(zlogp, 1, O_RDONLY)) == -1 ||
			    (stderrfd = open_fd(zlogp, 2, O_RDONLY)) == -1) {
				goto death;
			}
		}

		do_zfd_io(gzctlfd, gzoutfd, gzerrfd, stdinfd, stdoutfd,
		    stderrfd);
death:
		destroy_server_sock(gzctlfd, "ctl");
		destroy_server_sock(gzoutfd, "out");
		destroy_server_sock(gzerrfd, "err");

		/* when shutting down, leave open until drained */
		if (!shutting_down) {
			(void) close(stdinfd);
			if (mode->zmode_n_stddevs == 3) {
				(void) close(stdoutfd);
				(void) close(stderrfd);
			}
		}
	}

	/*
	 * Attempt to drain remaining log output from the zone prior to closing
	 * the file descriptors. This helps ensure that complete logs are
	 * captured during shutdown.
	 */
	flags = fcntl(stdoutfd, F_GETFL, 0);
	if (fcntl(stdoutfd, F_SETFL, flags | O_NONBLOCK) != -1) {
		while ((len = read(stdoutfd, ibuf, BUFSIZ)) > 0)
			wr_log_msg(ibuf, len, 1);
	}
	(void) close(stdoutfd);

	if (mode->zmode_n_stddevs > 1) {
		(void) close(stdinfd);
		flags = fcntl(stderrfd, F_GETFL, 0);
		if (fcntl(stderrfd, F_SETFL, flags | O_NONBLOCK) != -1) {
			while ((len = read(stderrfd, ibuf, BUFSIZ)) > 0)
				wr_log_msg(ibuf, len, 2);
		}
		(void) close(stderrfd);
	}


	(void) close(eventstream[0]);
	eventstream[0] = -1;
	(void) close(eventstream[1]);
	eventstream[1] = -1;
	if (logfd != -1)
		(void) close(logfd);
}

/*
 * The meaning of the original legacy values for the zlog-mode evolved over
 * time, to the point where the old names no longer made sense. The current
 * values are simply positional letters used to indicate various capabilities.
 * The following table shows the meaning of the mode values, along with the
 * legacy name which we continue to support for compatability. Any future
 * capability can add a letter to the left and '-' is implied for existing
 * strings.
 *
 * zlog-mode    gz log - tty - ngz log
 * ---------    ------   ---   -------
 * gt- (int)       y      y       n
 * g-- (log)       y      n       n
 * gtn (nlint)     y      y       y
 * g-n (nolog)     y      n       y
 * -t-             n      y       n
 * ---             n      n       n
 *
 * This function also obtains a maximum log size while it is reading the
 * zone configuration.
 */
static void
get_mode_logmax(zfd_mode_t *mode)
{
	zone_dochandle_t handle;
	struct zone_attrtab attr;

	bzero(mode, sizeof (zfd_mode_t));

	if ((handle = zonecfg_init_handle()) == NULL)
		return;

	if (zonecfg_get_handle(zone_name, handle) != Z_OK)
		goto done;

	if (zonecfg_setattrent(handle) != Z_OK)
		goto done;
	while (zonecfg_getattrent(handle, &attr) == Z_OK) {
		if (strcmp(ZLOG_MODE, attr.zone_attr_name) == 0) {
			if (strcmp("g--", attr.zone_attr_value) == 0 ||
			    strncmp("log", attr.zone_attr_value, 3) == 0) {
				mode->zmode_gzlogging = B_TRUE;
				mode->zmode_n_stddevs = 3;
				mode->zmode_n_addl_devs = 0;
			} else if (strcmp("g-n", attr.zone_attr_value) == 0 ||
			    strncmp("nolog", attr.zone_attr_value, 5) == 0) {
				mode->zmode_gzlogging = B_TRUE;
				mode->zmode_n_stddevs = 3;
				mode->zmode_n_addl_devs = 2;
			} else if (strcmp("gt-", attr.zone_attr_value) == 0 ||
			    strncmp("int", attr.zone_attr_value, 3) == 0) {
				mode->zmode_gzlogging = B_TRUE;
				mode->zmode_n_stddevs = 1;
				mode->zmode_n_addl_devs = 0;
			} else if (strcmp("gtn", attr.zone_attr_value) == 0 ||
			    strncmp("nlint", attr.zone_attr_value, 5) == 0) {
				mode->zmode_gzlogging = B_TRUE;
				mode->zmode_n_stddevs = 1;
				mode->zmode_n_addl_devs = 1;
			} else if (strcmp("-t-", attr.zone_attr_value) == 0) {
				mode->zmode_gzlogging = B_FALSE;
				mode->zmode_n_stddevs = 1;
				mode->zmode_n_addl_devs = 0;
			} else if (strcmp("---", attr.zone_attr_value) == 0) {
				mode->zmode_gzlogging = B_FALSE;
				mode->zmode_n_stddevs = 3;
				mode->zmode_n_addl_devs = 0;
			}
			continue;
		}

		if (strcmp(ZLOG_MAXSZ, attr.zone_attr_name) == 0) {
			char *p;
			long lval;

			p = attr.zone_attr_value;
			lval = strtol(p, &p, 10);
			if (*p == '\0')
				log_rot_sz = (size_t)lval;
			continue;
		}

		if (strcmp(ZLOG_NAME, attr.zone_attr_name) == 0) {
			(void) strlcpy(log_name, attr.zone_attr_value,
			    sizeof (log_name));
			continue;
		}
	}
	(void) zonecfg_endattrent(handle);

done:
	zonecfg_fini_handle(handle);
}

void
create_log_thread(zlog_t *logp, zoneid_t id)
{
	int res;

	shutting_down = 0;
	zlogp = logp;

	get_mode_logmax(&mode);
	if (mode.zmode_n_stddevs == 0)
		return;

	if (init_zfd_devs(zlogp, &mode) == -1) {
		zerror(zlogp, B_FALSE,
		    "zfd setup: device initialization failed");
		return;
	}

	res = thr_create(NULL, 0, (void * (*)(void *))srvr, (void *)&mode, 0,
	    &logger_tid);
	if (res != 0) {
		zerror(zlogp, B_FALSE, "error %d creating logger thread", res);
		logger_tid = 0;
	}
}

void
destroy_log_thread()
{
	if (logger_tid != 0) {
		int stop = 1;

		shutting_down = 1;
		/* break out of poll to shutdown */
		if (eventstream[0] != -1)
			(void) write(eventstream[0], &stop, sizeof (stop));
		(void) thr_join(logger_tid, NULL, NULL);
		logger_tid = 0;
	}

	(void) destroy_zfd_devs(zlogp);
}
