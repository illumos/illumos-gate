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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Zone file descriptor support is used as a mechanism for a process inside the
 * zone to either log messages to the GZ zoneadmd or as a way to interact
 * directly with the process (via zlogin -I). The zfd thread is modeled on
 * the zcons thread so see the comment header in zcons.c for a general overview.
 * Unlike with zcons, which has a single endpoint within the zone and a single
 * endpoint used by zoneadmd, we setup multiple endpoints within the zone.
 * In the interactive mode we setup fd 0, 1 and 2 for use as stdin, stdout and
 * stderr. In the logging mode we only setup fd 1 and 2 for use as stdout and
 * stderr.
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

/*
 * The eventstream is a simple one-directional flow of messages implemented
 * with a pipe. It is used to wake up the poller when it needs to shutdown.
 */
static int eventstream[2] = {-1, -1};

#define	LOGNAME			"stdio.log"
#define	ZLOG_MODE		"zlog-mode"
#define	ZFDNEX_DEVTREEPATH	"/pseudo/zfdnex@2"
#define	ZFDNEX_FILEPATH		"/devices/pseudo/zfdnex@2"
#define	SERVER_SOCKPATH		ZONES_TMPDIR "/%s.server_sock"
#define	ZTTY_RETRY		5

typedef enum {
	ZLOG_NONE = 0,
	ZLOG_LOG,
	ZLOG_INTERACTIVE,
} zlog_mode_t;

/*
 * count_zfd_devs() and its helper count_cb() do a walk of the subtree of the
 * device tree where zfd nodes are represented. The goal is to count zfd
 * instances already setup for a zone with the given name.
 *
 * Note: this algorithm is a linear search of nodes in the zfdnex subtree
 * of the device tree, and could be a scalability problem, but I don't see
 * how to avoid it.
 */

/*
 * cb_data is shared by count_cb and destroy_cb for simplicity.
 */
struct cb_data {
	zlog_t *zlogp;
	int found;
	int killed;
};

static int
count_cb(di_node_t node, void *arg)
{
	struct cb_data *cb = (struct cb_data *)arg;
	char *prop_data;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "zfd_zname",
	    &prop_data) != -1) {
		assert(prop_data != NULL);
		if (strcmp(prop_data, zone_name) == 0) {
			cb->found++;
			return (DI_WALK_CONTINUE);
		}
	}
	return (DI_WALK_CONTINUE);
}

static int
count_zfd_devs(zlog_t *zlogp)
{
	di_node_t root;
	struct cb_data cb;

	bzero(&cb, sizeof (cb));
	cb.zlogp = zlogp;

	if ((root = di_init(ZFDNEX_DEVTREEPATH, DINFOCPYALL)) == DI_NODE_NIL) {
		zerror(zlogp, B_TRUE, "di_init failed");
		return (-1);
	}

	(void) di_walk_node(root, DI_WALK_CLDFIRST, (void *)&cb, count_cb);
	di_fini(root);
	return (cb.found);
}

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

	cb->found++;
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
 * instantiate 2 or 3 new zone fd nodes.  We do a lot of sanity checking, and
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
	 * Set four properties on this node; the first is the name of the
	 * zone; the second is a flag which lets pseudo know that it is
	 * OK to automatically allocate an instance # for this device;
	 * the third tells the device framework not to auto-detach this
	 * node-- we need the node to still be there when we ask devfsadmd
	 * to make links, and when we need to open it.
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
init_zfd_devs(zlog_t *zlogp, int start)
{
	devctl_hdl_t bus_hdl = NULL;
	di_devlink_handle_t dl = NULL;
	int rv = -1;
	int ndevs;
	int i;

	/*
	 * Don't re-setup zone fd devs if they already exist; just
	 * skip ahead to making devlinks, which we do for sanity's sake.
	 */
	ndevs = count_zfd_devs(zlogp);
	if (ndevs == (3 - start))
		goto devlinks;

	if (ndevs > 0 || ndevs == -1) {
		if (destroy_zfd_devs(zlogp) == -1)
			goto error;
	}

	/*
	 * Time to make the devices.
	 */
	if ((bus_hdl = devctl_bus_acquire(ZFDNEX_FILEPATH, 0)) == NULL) {
		zerror(zlogp, B_TRUE, "devctl_bus_acquire failed");
		goto error;
	}

	for (i = start; i < 3; i++) {
		if (init_zfd_dev(zlogp, bus_hdl, i) != 0)
			goto error;
	}

devlinks:
	if ((dl = di_devlink_init("zfd", DI_MAKE_LINK)) == NULL) {
		zerror(zlogp, B_TRUE, "failed to create devlinks");
		goto error;
	}

	(void) di_devlink_fini(&dl);
	rv = 0;

	/*
	 * We know that start is 0 when we're interactive and that is the
	 * only time we want to look like a tty.
	 */
	if (start == 0) {
		for (i = start; i < 3; i++)
			make_tty(zlogp, i);
	}

error:
	if (bus_hdl)
		devctl_release(bus_hdl);
	return (rv);
}

static int
init_server_sock(zlog_t *zlogp)
{
	int servfd;
	struct sockaddr_un servaddr;

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) snprintf(servaddr.sun_path, sizeof (servaddr.sun_path),
	    SERVER_SOCKPATH, zone_name);

	if ((servfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		zerror(zlogp, B_TRUE, "server setup: could not create socket");
		return (-1);
	}
	(void) unlink(servaddr.sun_path);

	if (bind(servfd, (struct sockaddr *)&servaddr,
	    sizeof (servaddr)) == -1) {
		zerror(zlogp, B_TRUE,
		    "server setup: could not bind to socket");
		goto out;
	}

	if (listen(servfd, 4) == -1) {
		zerror(zlogp, B_TRUE,
		    "server setup: could not listen on socket");
		goto out;
	}
	return (servfd);

out:
	(void) unlink(servaddr.sun_path);
	(void) close(servfd);
	return (-1);
}

static void
destroy_server_sock(int servfd)
{
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), SERVER_SOCKPATH, zone_name);
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
get_client_ident(int clifd, pid_t *pid, char *locale, size_t locale_len)
{
	char buf[BUFSIZ], *bufp;
	size_t buflen = sizeof (buf);
	char c = '\0';
	int i = 0, r;

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
	 * Parse buffer for message of the form: IDENT <pid> <locale>
	 */
	bufp = buf;
	if (strncmp(bufp, "IDENT ", 6) != 0)
		return (-1);
	bufp += 6;
	errno = 0;
	*pid = strtoll(bufp, &bufp, 10);
	if (errno != 0)
		return (-1);

	while (*bufp != '\0' && isspace(*bufp))
		bufp++;
	(void) strlcpy(locale, bufp, locale_len);

	return (0);
}

static int
accept_client(int servfd, pid_t *pid, char *locale, size_t locale_len)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen;
	int flags;

	clilen = sizeof (cliaddr);
	connfd = accept(servfd, (struct sockaddr *)&cliaddr, &clilen);
	if (connfd == -1)
		return (-1);
	if (get_client_ident(connfd, pid, locale, locale_len) == -1) {
		(void) shutdown(connfd, SHUT_RDWR);
		(void) close(connfd);
		return (-1);
	}
	(void) write(connfd, "OK\n", 3);

	flags = fcntl(connfd, F_GETFD, 0);
	if (flags != -1)
		(void) fcntl(connfd, F_SETFD, flags | O_NONBLOCK | FD_CLOEXEC);

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
	if (get_client_ident(connfd, NULL, NULL, 0) == 0) {
		(void) snprintf(nak, sizeof (nak), "%lu\n",
		    clientpid);
		(void) write(connfd, nak, strlen(nak));
	}
	(void) shutdown(connfd, SHUT_RDWR);
	(void) close(connfd);
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
 * This routine drives the interactive I/O loop. It polls for input from the
 * zone side of the fd (output to stdout/stderr), and from the client
 * (input to the zone's stdin).  Additionally, it polls on the server fd,
 * and disconnects any clients that might try to hook up with the zone while
 * the fd's are in use.
 *
 * When the client first calls us up, it is expected to send a line giving its
 * "identity"; this consists of the string 'IDENT <pid> <locale>'. This is so
 * that we can report that the fd's are busy, along with some diagnostics
 * about who has them busy; the locale is ignore here but kept for compatability
 * with the zlogin code when running on the zone's console.
 *
 * We need to handle the case where there is no server within the zone (or
 * the server gets stuck) and data that we're writing to the zone server's
 * stdin fills the pipe. Because open_fd() always opens non-blocking our
 * writes could return -1 with EAGAIN. Since we ignore errors on the write
 * to stdin, we won't get blocked.
 */
static void
do_zfd_io(int servfd, int stdinfd, int stdoutfd, int stderrfd)
{
	struct pollfd pollfds[5];
	char ibuf[BUFSIZ];
	int cc, ret;
	int clifd = -1;
	int pollerr = 0;
	char clilocale[MAXPATHLEN];
	pid_t clipid = 0;

	/* client, watch for read events */
	pollfds[0].fd = clifd;
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND |
	    POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	/* stdout, watch for read events */
	pollfds[1].fd = stdoutfd;
	pollfds[1].events = pollfds[0].events;

	/* stderr, watch for read events */
	pollfds[2].fd = stderrfd;
	pollfds[2].events = pollfds[0].events;

	/* the server socket; watch for events (new connections) */
	pollfds[3].fd = servfd;
	pollfds[3].events = pollfds[0].events;

	/* the eventstram; any input means the zone is halting */
	pollfds[4].fd = eventstream[1];
	pollfds[4].events = pollfds[0].events;

	while (!shutting_down) {
		pollfds[0].revents = pollfds[1].revents = 0;
		pollfds[2].revents = pollfds[3].revents = 0;
		pollfds[4].revents = 0;

		ret = poll(pollfds, 5, -1);
		if (ret == -1 && errno != EINTR) {
			zerror(zlogp, B_TRUE, "poll failed");
			/* we are hosed, close connection */
			break;
		}

		/* event from client side */
		if (pollfds[0].revents) {
			if (pollfds[0].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(clifd, ibuf, BUFSIZ);
				if (cc <= 0 && (errno != EINTR) &&
				    (errno != EAGAIN)) {
					break;
				}
				/*
				 * See comment for this function on what
				 * happens if there is no reader in the zone.
				 */
				(void) write(stdinfd, ibuf, cc);
			} else {
				pollerr = pollfds[0].revents;
				zerror(zlogp, B_FALSE, "closing connection "
				    "with client, pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from stdout */
		if (pollfds[1].revents) {
			if (pollfds[1].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(stdoutfd, ibuf, BUFSIZ);
				if (cc <= 0 && (errno != EINTR) &&
				    (errno != EAGAIN))
					break;
				/*
				 * Lose I/O if no one is listening
				 */
				if (clifd != -1 && cc > 0)
					(void) write(clifd, ibuf, cc);
			} else {
				pollerr = pollfds[1].revents;
				zerror(zlogp, B_FALSE,
				    "closing connection with stdout zfd, "
				    "pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from stderr */
		if (pollfds[2].revents) {
			if (pollfds[2].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(stderrfd, ibuf, BUFSIZ);
				if (cc <= 0 && (errno != EINTR) &&
				    (errno != EAGAIN))
					break;
				/*
				 * Lose I/O if no one is listening
				 */
				if (clifd != -1 && cc > 0)
					(void) write(clifd, ibuf, cc);
			} else {
				pollerr = pollfds[2].revents;
				zerror(zlogp, B_FALSE,
				    "closing connection with stderr zfd, "
				    "pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from server socket */
		if (pollfds[3].revents &&
		    (pollfds[3].revents & (POLLIN | POLLRDNORM))) {
			if (clifd != -1) {
				/*
				 * Test the client to see if it is really
				 * still alive.  If it has died but we
				 * haven't yet detected that, we might
				 * deny a legitimate connect attempt.  If it
				 * is dead, we break out; once we tear down
				 * the old connection, the new connection
				 * will happen.
				 */
				if (test_client(clifd) == -1) {
					break;
				}
				/* we're already handling a client */
				reject_client(servfd, clipid);

			} else if ((clifd = accept_client(servfd, &clipid,
			    clilocale, sizeof (clilocale))) != -1) {
				pollfds[0].fd = clifd;

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
		if (pollfds[4].revents) {
			break;
		}
	}

	if (clifd != -1) {
		(void) shutdown(clifd, SHUT_RDWR);
		(void) close(clifd);
	}
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

	sbuf[slen - 1] = '\0';
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
 */
static void
wr_log_msg(char *buf, int len, int from)
{
	struct timeval tv;
	int olen;
	char ts[64];
	char nbuf[BUFSIZ * 2];
	char obuf[BUFSIZ * 2];

	escape_json(buf, len, nbuf, sizeof (nbuf));

	if (gettimeofday(&tv, NULL) != 0)
		return;
	(void) strftime(ts, sizeof (ts), "%FT%T", gmtime(&tv.tv_sec));

	olen = snprintf(obuf, sizeof (obuf),
	    "{\"log\":\"%s\",\"stream\":\"%s\",\"time\":\"%s.%ldZ\"}\n",
	    nbuf, (from == 1) ? "stdout" : "stderr", ts, tv.tv_usec * 1000);

	(void) write(logfd, obuf, olen);
}

/*
 * This routine runs the log file I/O loop.  It polls for input from the
 * zone's stdout and stderr, formats the msg in json and writes it to the
 * log file.
 */
static void
do_zfd_logging(int stdoutfd, int stderrfd)
{
	struct pollfd pollfds[3];
	char ibuf[BUFSIZ];
	int cc, ret;
	int pollerr = 0;

	/* stdout, watch for read events */
	pollfds[0].fd = stdoutfd;
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND |
	    POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	/* stderr, watch for read events */
	pollfds[1].fd = stderrfd;
	pollfds[1].events = pollfds[0].events;

	/* the eventstream; any input means the zone is halting */
	pollfds[2].fd = eventstream[1];
	pollfds[2].events = pollfds[0].events;

	while (!shutting_down) {
		pollfds[0].revents = 0;
		pollfds[1].revents = 0;
		pollfds[2].revents = 0;

		ret = poll(pollfds, 3, -1);
		if (ret == -1 && errno != EINTR) {
			zerror(zlogp, B_TRUE, "poll failed");
			/* we are hosed, shutdown logger */
			break;
		}

		/* event from zone's stdout */
		if (pollfds[0].revents) {
			if (pollfds[0].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(stdoutfd, ibuf, BUFSIZ);
				if (cc <= 0 && errno != EINTR &&
				    errno != EAGAIN)
					break;
				if (cc > 0)
					wr_log_msg(ibuf, cc, 1);
			} else {
				pollerr = pollfds[0].revents;
				zerror(zlogp, B_FALSE, "closing connection "
				    "with zfd stdin, pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from zone's stderr */
		if (pollfds[1].revents) {
			if (pollfds[1].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(stderrfd, ibuf, BUFSIZ);
				if (cc <= 0 && errno != EINTR &&
				    errno != EAGAIN)
					break;
				if (cc > 0)
					wr_log_msg(ibuf, cc, 2);
			} else {
				pollerr = pollfds[1].revents;
				zerror(zlogp, B_FALSE, "closing connection "
				    "with zfd stderr, pollerr %d\n", pollerr);
				break;
			}
		}


		/*
		 * Watch for events on the eventstream. This is how we get
		 * notified of the zone halting. It provides us a "wakeup"
		 * from poll.
		 */
		if (pollfds[2].revents)
			break;
	}

	(void) close(logfd);
	logfd = -1;
}

static int
open_fd(int id)
{
	int fd;
	int flag = O_NONBLOCK | O_NOCTTY | O_CLOEXEC;
	int retried = 0;
	char stdpath[MAXPATHLEN];

	(void) snprintf(stdpath, sizeof (stdpath), "/dev/zfd/%s/master/%d",
	    zone_name, id);

	if (id == 0) {
		/* zone's stdin, so we're writing to it */
		flag |= O_WRONLY;
	} else {
		/* zone's stdout or stderr, so we're reading from it */
		flag |= O_RDONLY;
	}

	while (!shutting_down) {
		if ((fd = open(stdpath, flag)) != -1)
			return (fd);

		if (retried++ > 60)
			break;

		(void) sleep(1);
	}

	return (-1);
}

/*
 * Body of the worker thread to perform interactive IO to the stdin, stdout and
 * stderr zfd's.
 *
 * The stdin, stdout and stderr are from the perspective of the process inside
 * the zone, so the zoneadmd view is opposite (i.e. we write to the stdin fd
 * and read from the stdout/stderr fds).
 */
static void
interactive()
{
	int serverfd = -1;
	int stdinfd = -1;
	int stdoutfd = -1;
	int stderrfd = -1;

	if (pipe(eventstream) != 0) {
		zerror(zlogp, B_TRUE, "failed to open interactive control "
		    "pipe");
		return;
	}

	while (!shutting_down) {
		if ((serverfd = init_server_sock(zlogp)) == -1) {
			zerror(zlogp, B_FALSE,
			    "server setup: socket initialization failed");
			goto death;
		}

		if (!shutting_down) {
			if ((stdinfd = open_fd(0)) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to open stdin zfd");
				goto death;
			}

			/*
			 * Setting RPROTDIS on the stream means that the
			 * control portion of messages received (which we don't
			 * care about) will be discarded by the stream head. If
			 * we allowed such messages, we wouldn't be able to use
			 * read(2), as it fails (EBADMSG) when a message with a
			 * control element is received.
			 */
			if (ioctl(stdinfd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to set options on stdin zfd");
				goto death;
			}
		}

		if (!shutting_down) {
			if ((stdoutfd = open_fd(1)) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to open stdout zfd");
				goto death;
			}

			if (ioctl(stdoutfd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to set options on stdout zfd");
				goto death;
			}
		}

		if (!shutting_down) {
			if ((stderrfd = open_fd(2)) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to open stderr zfd");
				goto death;
			}

			if (ioctl(stderrfd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
				zerror(zlogp, B_TRUE,
				    "failed to set options on stderr zfd");
				goto death;
			}
		}

		do_zfd_io(serverfd, stdinfd, stdoutfd, stderrfd);
death:
		destroy_server_sock(serverfd);

		(void) close(stdinfd);
		(void) close(stdoutfd);
		(void) close(stderrfd);
	}

	(void) close(eventstream[0]);
	eventstream[0] = -1;
	(void) close(eventstream[1]);
	eventstream[1] = -1;
}

static void
open_logfile()
{
	char logpath[MAXPATHLEN];

	logfd = -1;

	(void) snprintf(logpath, sizeof (logpath), "%s/logs", zonepath);
	(void) mkdir(logpath, 0700);

	(void) snprintf(logpath, sizeof (logpath), "%s/logs/%s", zonepath,
	    LOGNAME);

	if ((logfd = open(logpath, O_WRONLY | O_APPEND | O_CREAT, 0600)) == -1)
		zerror(zlogp, B_TRUE, "failed to open log file");
}

/* ARGSUSED */
void
hup_handler(int i)
{
	(void) close(logfd);
	open_logfile();
}

/*
 * Body of the worker thread to log the zfd's stdout and stderr to a log file.
 *
 * The stdout and stderr are from the perspective of the process inside the
 * zone, so the zoneadmd view is opposite (i.e. we read from the stdout/stderr
 * fds). Since this is the logger worker we ignore the zone's stdin fd.
 */
static void
logger()
{
	int stdoutfd = -1;
	int stderrfd = -1;
	sigset_t blockset;

	if (!shutting_down) {
		open_logfile();
	}

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
			goto death;
		}
	}

	if (!shutting_down) {
		if ((stdoutfd = open_fd(1)) == -1) {
			zerror(zlogp, B_TRUE, "failed to open stdout zfd");
			goto death;
		}

		/*
		 * Setting RPROTDIS on the stream means that the control
		 * portion of messages received (which we don't care about)
		 * will be discarded by the stream head.  If we allowed such
		 * messages, we wouldn't be able to use read(2), as it fails
		 * (EBADMSG) when a message with a control element is received.
		 */
		if (ioctl(stdoutfd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
			zerror(zlogp, B_TRUE, "failed to set options on "
			    "stdout zfd");
			goto death;
		}
	}

	if (!shutting_down) {
		if ((stderrfd = open_fd(2)) == -1) {
			zerror(zlogp, B_TRUE, "failed to open stderr zfd");
			goto death;
		}

		if (ioctl(stderrfd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
			zerror(zlogp, B_TRUE, "failed to set options on "
			    "stderr zfd");
			goto death;
		}
	}

	do_zfd_logging(stdoutfd, stderrfd);

death:
	(void) close(eventstream[0]);
	eventstream[0] = -1;
	(void) close(eventstream[1]);
	eventstream[1] = -1;
	(void) close(logfd);
	(void) close(stdoutfd);
	(void) close(stderrfd);
}

static zlog_mode_t
get_logger_mode()
{
	zlog_mode_t mode = ZLOG_NONE;
	zone_dochandle_t handle;
	struct zone_attrtab attr;

	if ((handle = zonecfg_init_handle()) == NULL)
		return (mode);

	if (zonecfg_get_handle(zone_name, handle) != Z_OK)
		goto done;

	if (zonecfg_setattrent(handle) != Z_OK)
		goto done;
	while (zonecfg_getattrent(handle, &attr) == Z_OK) {
		if (strcmp(ZLOG_MODE, attr.zone_attr_name) == 0) {
			if (strncmp("log", attr.zone_attr_value, 3) == 0) {
				mode = ZLOG_LOG;
			} else if (strncmp("int",
			    attr.zone_attr_value, 3) == 0) {
				mode = ZLOG_INTERACTIVE;
			}
			break;
		}
	}
	(void) zonecfg_endattrent(handle);

done:
	zonecfg_fini_handle(handle);
	return (mode);
}

void
create_log_thread(zlog_t *logp, zoneid_t id)
{
	int res;
	int zdev_start;
	zlog_mode_t mode;
	void *(*worker) (void*);

	shutting_down = 0;
	zlogp = logp;

	mode = get_logger_mode();
	if (mode == ZLOG_NONE)
		return;

	if (mode == ZLOG_INTERACTIVE) {
		worker = (void *(*)(void *))interactive;
		zdev_start = 0;
	} else {
		worker = (void *(*)(void *))logger;
		zdev_start = 1;
	}

	if (init_zfd_devs(zlogp, zdev_start) == -1) {
		zerror(zlogp, B_FALSE,
		    "zfd setup: device initialization failed");
		return;
	}

	res = thr_create(NULL, NULL, worker, NULL, NULL, &logger_tid);
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
