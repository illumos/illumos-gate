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
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * Console support for zones requires a significant infrastructure.  The
 * core pieces are contained in this file, but other portions of note
 * are in the zlogin(1M) command, the zcons(7D) driver, and in the
 * devfsadm(1M) misc_link generator.
 *
 * Care is taken to make the console behave in an "intuitive" fashion for
 * administrators.  Essentially, we try as much as possible to mimic the
 * experience of using a system via a tip line and system controller.
 *
 * The zone console architecture looks like this:
 *
 *                                      Global Zone | Non-Global Zone
 *                        .--------------.          |
 *        .-----------.   | zoneadmd -z  |          | .--------. .---------.
 *        | zlogin -C |   |     myzone   |          | | ttymon | | syslogd |
 *        `-----------'   `--------------'          | `--------' `---------'
 *                  |       |       | |             |      |       |
 *  User            |       |       | |             |      V       V
 * - - - - - - - - -|- - - -|- - - -|-|- - - - - - -|- - /dev/zconsole - - -
 *  Kernel          V       V       | |                        |
 *               [AF_UNIX Socket]   | `--------. .-------------'
 *                                  |          | |
 *                                  |          V V
 *                                  |     +-----------+
 *                                  |     |  ldterm,  |
 *                                  |     |   etc.    |
 *                                  |     +-----------+
 *                                  |     +-[Anchor]--+
 *                                  |     |   ptem    |
 *                                  V     +-----------+
 *                           +---master---+---slave---+
 *                           |                        |
 *                           |      zcons driver      |
 *                           |    zonename="myzone"   |
 *                           +------------------------+
 *
 * There are basically two major tasks which the console subsystem in
 * zoneadmd accomplishes:
 *
 * - Setup and teardown of zcons driver instances.  One zcons instance
 *   is maintained per zone; we take advantage of the libdevice APIs
 *   to online new instances of zcons as needed.  Care is taken to
 *   prune and manage these appropriately; see init_console_dev() and
 *   destroy_console_dev().  The end result is the creation of the
 *   zcons(7D) instance and an open file descriptor to the master side.
 *   zcons instances are associated with zones via their zonename device
 *   property.  This the console instance to persist across reboots,
 *   and while the zone is halted.
 *
 * - Acting as a server for 'zlogin -C' instances.  When zlogin -C is
 *   run, zlogin connects to zoneadmd via unix domain socket.  zoneadmd
 *   functions as a two-way proxy for console I/O, relaying user input
 *   to the master side of the console, and relaying output from the
 *   zone to the user.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/zcons.h>
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

#include <libdevinfo.h>
#include <libdevice.h>
#include <libzonecfg.h>

#include <syslog.h>
#include <sys/modctl.h>

#include "zoneadmd.h"

#define	ZCONSNEX_DEVTREEPATH	"/pseudo/zconsnex@1"
#define	ZCONSNEX_FILEPATH	"/devices/pseudo/zconsnex@1"

#define	CONSOLE_SOCKPATH	ZONES_TMPDIR "/%s.console_sock"

static int	serverfd = -1;	/* console server unix domain socket fd */
char boot_args[BOOTARGS_MAX];
char bad_boot_arg[BOOTARGS_MAX];

/*
 * The eventstream is a simple one-directional flow of messages from the
 * door server to the console subsystem, implemented with a pipe.
 * It is used to wake up the console poller when it needs to take action,
 * message the user, die off, etc.
 */
static int eventstream[2];



int
eventstream_init()
{
	if (pipe(eventstream) == -1)
		return (-1);
	return (0);
}

void
eventstream_write(zone_evt_t evt)
{
	(void) write(eventstream[0], &evt, sizeof (evt));
}

static zone_evt_t
eventstream_read(void)
{
	zone_evt_t evt = Z_EVT_NULL;

	(void) read(eventstream[1], &evt, sizeof (evt));
	return (evt);
}

/*
 * count_console_devs() and its helper count_cb() do a walk of the
 * subtree of the device tree where zone console nodes are represented.
 * The goal is to count zone console instances already setup for a zone
 * with the given name.  More than 1 is anomolous, and our caller will
 * have to deal with that if we find that's the case.
 *
 * Note: this algorithm is a linear search of nodes in the zconsnex subtree
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

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "zonename",
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
count_console_devs(zlog_t *zlogp)
{
	di_node_t root;
	struct cb_data cb;

	bzero(&cb, sizeof (cb));
	cb.zlogp = zlogp;

	if ((root = di_init(ZCONSNEX_DEVTREEPATH, DINFOCPYALL)) ==
	    DI_NODE_NIL) {
		zerror(zlogp, B_TRUE, "%s failed", "di_init");
		return (-1);
	}

	(void) di_walk_node(root, DI_WALK_CLDFIRST, (void *)&cb, count_cb);
	di_fini(root);
	return (cb.found);
}

/*
 * destroy_console_devs() and its helper destroy_cb() tears down any console
 * instances associated with this zone.  If things went very wrong, we
 * might have more than one console instance hanging around.  This routine
 * hunts down and tries to remove all of them.  Of course, if the console
 * is open, the instance will not detach, which is a potential issue.
 */
static int
destroy_cb(di_node_t node, void *arg)
{
	struct cb_data *cb = (struct cb_data *)arg;
	char *prop_data;
	char *tmp;
	char devpath[MAXPATHLEN];
	devctl_hdl_t hdl;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, "zonename",
	    &prop_data) == -1)
		return (DI_WALK_CONTINUE);

	assert(prop_data != NULL);
	if (strcmp(prop_data, zone_name) != 0) {
		/* this is the console for a different zone */
		return (DI_WALK_CONTINUE);
	}

	cb->found++;
	tmp = di_devfs_path(node);
	(void) snprintf(devpath, sizeof (devpath), "/devices/%s", tmp);
	di_devfs_path_free(tmp);

	if ((hdl = devctl_device_acquire(devpath, 0)) == NULL) {
		zerror(cb->zlogp, B_TRUE, "WARNING: console %s found, "
		    "but it could not be controlled.", devpath);
		return (DI_WALK_CONTINUE);
	}
	if (devctl_device_remove(hdl) == 0) {
		cb->killed++;
	} else {
		zerror(cb->zlogp, B_TRUE, "WARNING: console %s found, "
		    "but it could not be removed.", devpath);
	}
	devctl_release(hdl);
	return (DI_WALK_CONTINUE);
}

static int
destroy_console_devs(zlog_t *zlogp)
{
	char conspath[MAXPATHLEN];
	di_node_t root;
	struct cb_data cb;
	int masterfd;
	int slavefd;

	/*
	 * Signal the master side to release its handle on the slave side by
	 * issuing a ZC_RELEASESLAVE ioctl.
	 */
	(void) snprintf(conspath, sizeof (conspath), "/dev/zcons/%s/%s",
	    zone_name, ZCONS_MASTER_NAME);
	if ((masterfd = open(conspath, O_RDWR | O_NOCTTY)) != -1) {
		(void) snprintf(conspath, sizeof (conspath), "/dev/zcons/%s/%s",
		    zone_name, ZCONS_SLAVE_NAME);
		if ((slavefd = open(conspath, O_RDWR | O_NOCTTY)) != -1) {
			if (ioctl(masterfd, ZC_RELEASESLAVE,
			    (caddr_t)(intptr_t)slavefd) != 0)
				zerror(zlogp, B_TRUE, "WARNING: error while "
				    "releasing slave handle of zone console for"
				    " %s", zone_name);
			(void) close(slavefd);
		} else {
			zerror(zlogp, B_TRUE, "WARNING: could not open slave "
			    "side of zone console for %s to release slave "
			    "handle", zone_name);
		}
		(void) close(masterfd);
	} else {
		zerror(zlogp, B_TRUE, "WARNING: could not open master side of "
		    "zone console for %s to release slave handle", zone_name);
	}

	bzero(&cb, sizeof (cb));
	cb.zlogp = zlogp;

	if ((root = di_init(ZCONSNEX_DEVTREEPATH, DINFOCPYALL)) ==
	    DI_NODE_NIL) {
		zerror(zlogp, B_TRUE, "%s failed", "di_init");
		return (-1);
	}

	(void) di_walk_node(root, DI_WALK_CLDFIRST, (void *)&cb, destroy_cb);
	if (cb.found > 1) {
		zerror(zlogp, B_FALSE, "WARNING: multiple zone console "
		    "instances detected for zone '%s'; %d of %d "
		    "successfully removed.",
		    zone_name, cb.killed, cb.found);
	}

	di_fini(root);
	return (0);
}

/*
 * init_console_dev() drives the device-tree configuration of the zone
 * console device.  The general strategy is to use the libdevice (devctl)
 * interfaces to instantiate a new zone console node.  We do a lot of
 * sanity checking, and are careful to reuse a console if one exists.
 *
 * Once the device is in the device tree, we kick devfsadm via di_init_devs()
 * to ensure that the appropriate symlinks (to the master and slave console
 * devices) are placed in /dev in the global zone.
 */
static int
init_console_dev(zlog_t *zlogp)
{
	char conspath[MAXPATHLEN];
	devctl_hdl_t bus_hdl = NULL;
	devctl_hdl_t dev_hdl = NULL;
	devctl_ddef_t ddef_hdl = NULL;
	di_devlink_handle_t dl = NULL;
	int rv = -1;
	int ndevs;
	int masterfd;
	int slavefd;
	int i;

	/*
	 * Don't re-setup console if it is working and ready already; just
	 * skip ahead to making devlinks, which we do for sanity's sake.
	 */
	ndevs = count_console_devs(zlogp);
	if (ndevs == 1) {
		goto devlinks;
	} else if (ndevs > 1 || ndevs == -1) {
		/*
		 * For now, this seems like a reasonable but harsh punishment.
		 * If needed, we could try to get clever and delete all but
		 * the console which is pointed at by the current symlink.
		 */
		if (destroy_console_devs(zlogp) == -1) {
			goto error;
		}
	}

	/*
	 * Time to make the consoles!
	 */
	if ((bus_hdl = devctl_bus_acquire(ZCONSNEX_FILEPATH, 0)) == NULL) {
		zerror(zlogp, B_TRUE, "%s failed", "devctl_bus_acquire");
		goto error;
	}
	if ((ddef_hdl = devctl_ddef_alloc("zcons", 0)) == NULL) {
		zerror(zlogp, B_TRUE, "failed to allocate ddef handle");
		goto error;
	}
	/*
	 * Set three properties on this node; the first is the name of the
	 * zone; the second is a flag which lets pseudo know that it is
	 * OK to automatically allocate an instance # for this device;
	 * the third tells the device framework not to auto-detach this
	 * node-- we need the node to still be there when we ask devfsadmd
	 * to make links, and when we need to open it.
	 */
	if (devctl_ddef_string(ddef_hdl, "zonename", zone_name) == -1) {
		zerror(zlogp, B_TRUE, "failed to create zonename property");
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
		zerror(zlogp, B_TRUE, "failed to create console node");
		goto error;
	}

devlinks:
	if ((dl = di_devlink_init("zcons", DI_MAKE_LINK)) != NULL) {
		(void) di_devlink_fini(&dl);
	} else {
		zerror(zlogp, B_TRUE, "failed to create devlinks");
		goto error;
	}

	/*
	 * Open the master side of the console and issue the ZC_HOLDSLAVE ioctl,
	 * which will cause the master to retain a reference to the slave.
	 * This prevents ttymon from blowing through the slave's STREAMS anchor.
	 */
	(void) snprintf(conspath, sizeof (conspath), "/dev/zcons/%s/%s",
	    zone_name, ZCONS_MASTER_NAME);
	if ((masterfd = open(conspath, O_RDWR | O_NOCTTY)) == -1) {
		zerror(zlogp, B_TRUE, "ERROR: could not open master side of "
		    "zone console for %s to acquire slave handle", zone_name);
		goto error;
	}
	(void) snprintf(conspath, sizeof (conspath), "/dev/zcons/%s/%s",
	    zone_name, ZCONS_SLAVE_NAME);
	if ((slavefd = open(conspath, O_RDWR | O_NOCTTY)) == -1) {
		zerror(zlogp, B_TRUE, "ERROR: could not open slave side of zone"
		    " console for %s to acquire slave handle", zone_name);
		(void) close(masterfd);
		goto error;
	}
	/*
	 * This ioctl can occasionally return ENXIO if devfs doesn't have
	 * everything plumbed up yet due to heavy zone startup load. Wait for
	 * 1 sec. and retry a few times before we fail to boot the zone.
	 */
	for (i = 0; i < 5; i++) {
		if (ioctl(masterfd, ZC_HOLDSLAVE, (caddr_t)(intptr_t)slavefd)
		    == 0) {
			rv = 0;
			break;
		} else if (errno != ENXIO) {
			break;
		}
		(void) sleep(1);
	}
	if (rv != 0)
		zerror(zlogp, B_TRUE, "ERROR: error while acquiring slave "
		    "handle of zone console for %s", zone_name);

	(void) close(slavefd);
	(void) close(masterfd);

error:
	if (ddef_hdl)
		devctl_ddef_free(ddef_hdl);
	if (bus_hdl)
		devctl_release(bus_hdl);
	if (dev_hdl)
		devctl_release(dev_hdl);
	return (rv);
}

static int
init_console_sock(zlog_t *zlogp)
{
	int servfd;
	struct sockaddr_un servaddr;

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) snprintf(servaddr.sun_path, sizeof (servaddr.sun_path),
	    CONSOLE_SOCKPATH, zone_name);

	if ((servfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		zerror(zlogp, B_TRUE, "console setup: could not create socket");
		return (-1);
	}
	(void) unlink(servaddr.sun_path);

	if (bind(servfd, (struct sockaddr *)&servaddr,
	    sizeof (servaddr)) == -1) {
		zerror(zlogp, B_TRUE,
		    "console setup: could not bind to socket");
		goto out;
	}

	if (listen(servfd, 4) == -1) {
		zerror(zlogp, B_TRUE,
		    "console setup: could not listen on socket");
		goto out;
	}
	return (servfd);

out:
	(void) unlink(servaddr.sun_path);
	(void) close(servfd);
	return (-1);
}

static void
destroy_console_sock(int servfd)
{
	char path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), CONSOLE_SOCKPATH, zone_name);
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
    int *disconnect)
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
	 * Parse buffer for message of the form:
	 * IDENT <pid> <locale> <disconnect flag>
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
	buflen = strlen(bufp) - 1;
	*disconnect = atoi(&bufp[buflen]);
	bufp[buflen - 1] = '\0';
	(void) strlcpy(locale, bufp, locale_len);

	return (0);
}

static int
accept_client(int servfd, pid_t *pid, char *locale, size_t locale_len,
    int *disconnect)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen;

	clilen = sizeof (cliaddr);
	connfd = accept(servfd, (struct sockaddr *)&cliaddr, &clilen);
	if (connfd == -1)
		return (-1);
	if (get_client_ident(connfd, pid, locale, locale_len,
	    disconnect) == -1) {
		(void) shutdown(connfd, SHUT_RDWR);
		(void) close(connfd);
		return (-1);
	}
	(void) write(connfd, "OK\n", 3);
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
	 * After hear its ident string, tell client to get lost.
	 */
	if (get_client_ident(connfd, NULL, NULL, 0, NULL) == 0) {
		(void) snprintf(nak, sizeof (nak), "%lu\n",
		    clientpid);
		(void) write(connfd, nak, strlen(nak));
	}
	(void) shutdown(connfd, SHUT_RDWR);
	(void) close(connfd);
}

static void
event_message(int clifd, char *clilocale, zone_evt_t evt, int dflag)
{
	char *str, *lstr = NULL;
	char lmsg[BUFSIZ];
	char outbuf[BUFSIZ];

	if (clifd == -1)
		return;

	switch (evt) {
	case Z_EVT_ZONE_BOOTING:
		if (*boot_args == '\0') {
			str = "NOTICE: Zone booting up";
			break;
		}
		/*LINTED*/
		(void) snprintf(lmsg, sizeof (lmsg), localize_msg(clilocale,
		    "NOTICE: Zone booting up with arguments: %s"), boot_args);
		lstr = lmsg;
		break;
	case Z_EVT_ZONE_READIED:
		str = "NOTICE: Zone readied";
		break;
	case Z_EVT_ZONE_HALTED:
		if (dflag)
			str = "NOTICE: Zone halted.  Disconnecting...";
		else
			str = "NOTICE: Zone halted";
		break;
	case Z_EVT_ZONE_REBOOTING:
		if (*boot_args == '\0') {
			str = "NOTICE: Zone rebooting";
			break;
		}
		/*LINTED*/
		(void) snprintf(lmsg, sizeof (lmsg), localize_msg(clilocale,
		    "NOTICE: Zone rebooting with arguments: %s"), boot_args);
		lstr = lmsg;
		break;
	case Z_EVT_ZONE_UNINSTALLING:
		str = "NOTICE: Zone is being uninstalled.  Disconnecting...";
		break;
	case Z_EVT_ZONE_BOOTFAILED:
		if (dflag)
			str = "NOTICE: Zone boot failed.  Disconnecting...";
		else
			str = "NOTICE: Zone boot failed";
		break;
	case Z_EVT_ZONE_BADARGS:
		/*LINTED*/
		(void) snprintf(lmsg, sizeof (lmsg),
		    localize_msg(clilocale,
		    "WARNING: Ignoring invalid boot arguments: %s"),
		    bad_boot_arg);
		lstr = lmsg;
		break;
	default:
		return;
	}

	if (lstr == NULL)
		lstr = localize_msg(clilocale, str);
	(void) snprintf(outbuf, sizeof (outbuf), "\r\n[%s]\r\n", lstr);
	(void) write(clifd, outbuf, strlen(outbuf));
}

/*
 * Check to see if the client at the other end of the socket is still
 * alive; we know it is not if it throws EPIPE at us when we try to write
 * an otherwise harmless 0-length message to it.
 */
static int
test_client(int clifd)
{
	if ((write(clifd, "", 0) == -1) && errno == EPIPE)
		return (-1);
	return (0);
}

/*
 * This routine drives the console I/O loop.  It polls for input from the
 * master side of the console (output to the console), and from the client
 * (input from the console user).  Additionally, it polls on the server fd,
 * and disconnects any clients that might try to hook up with the zone while
 * the console is in use.
 *
 * When the client first calls us up, it is expected to send a line giving
 * its "identity"; this consists of the string 'IDENT <pid> <locale>'.
 * This is so that we can report that the console is busy along with
 * some diagnostics about who has it busy; the locale is used so that
 * asynchronous messages about zone state (like the NOTICE: zone halted
 * messages) can be output in the user's locale.
 */
static void
do_console_io(zlog_t *zlogp, int consfd, int servfd)
{
	struct pollfd pollfds[4];
	char ibuf[BUFSIZ];
	int cc, ret;
	int clifd = -1;
	int pollerr = 0;
	char clilocale[MAXPATHLEN];
	pid_t clipid = 0;
	int disconnect = 0;

	/* console side, watch for read events */
	pollfds[0].fd = consfd;
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND |
	    POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	/* client side, watch for read events */
	pollfds[1].fd = clifd;
	pollfds[1].events = pollfds[0].events;

	/* the server socket; watch for events (new connections) */
	pollfds[2].fd = servfd;
	pollfds[2].events = pollfds[0].events;

	/* the eventstram; watch for events (e.g.: zone halted) */
	pollfds[3].fd = eventstream[1];
	pollfds[3].events = pollfds[0].events;

	for (;;) {
		pollfds[0].revents = pollfds[1].revents = 0;
		pollfds[2].revents = pollfds[3].revents = 0;

		ret = poll(pollfds,
		    sizeof (pollfds) / sizeof (struct pollfd), -1);
		if (ret == -1 && errno != EINTR) {
			zerror(zlogp, B_TRUE, "poll failed");
			/* we are hosed, close connection */
			break;
		}

		/* event from console side */
		if (pollfds[0].revents) {
			if (pollfds[0].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(consfd, ibuf, BUFSIZ);
				if (cc <= 0 && (errno != EINTR) &&
				    (errno != EAGAIN))
					break;
				/*
				 * Lose I/O if no one is listening
				 */
				if (clifd != -1 && cc > 0)
					(void) write(clifd, ibuf, cc);
			} else {
				pollerr = pollfds[0].revents;
				zerror(zlogp, B_FALSE,
				    "closing connection with (console) "
				    "pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from client side */
		if (pollfds[1].revents) {
			if (pollfds[1].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				errno = 0;
				cc = read(clifd, ibuf, BUFSIZ);
				if (cc <= 0 && (errno != EINTR) &&
				    (errno != EAGAIN))
					break;
				(void) write(consfd, ibuf, cc);
			} else {
				pollerr = pollfds[1].revents;
				zerror(zlogp, B_FALSE,
				    "closing connection with (client) "
				    "pollerr %d\n", pollerr);
				break;
			}
		}

		/* event from server socket */
		if (pollfds[2].revents &&
		    (pollfds[2].revents & (POLLIN | POLLRDNORM))) {
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
			    clilocale, sizeof (clilocale),
			    &disconnect)) != -1) {
				pollfds[1].fd = clifd;

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
		if (pollfds[3].revents) {
			int evt = eventstream_read();
			/*
			 * After we drain out the event, if we aren't servicing
			 * a console client, we hop back out to our caller,
			 * which will check to see if it is time to shutdown
			 * the daemon, or if we should take another console
			 * service lap.
			 */
			if (clifd == -1) {
				break;
			}
			event_message(clifd, clilocale, evt, disconnect);
			/*
			 * Special handling for the message that the zone is
			 * uninstalling; we boot the client, then break out
			 * of this function.  When we return to the
			 * serve_console loop, we will see that the zone is
			 * in a state < READY, and so zoneadmd will shutdown.
			 */
			if (evt == Z_EVT_ZONE_UNINSTALLING) {
				break;
			}
			/*
			 * Diconnect if -C and -d options were specified and
			 * zone was halted or failed to boot.
			 */
			if ((evt == Z_EVT_ZONE_HALTED ||
			    evt == Z_EVT_ZONE_BOOTFAILED) && disconnect) {
				break;
			}
		}

	}

	if (clifd != -1) {
		(void) shutdown(clifd, SHUT_RDWR);
		(void) close(clifd);
	}
}

int
init_console(zlog_t *zlogp)
{
	if (init_console_dev(zlogp) == -1) {
		zerror(zlogp, B_FALSE,
		    "console setup: device initialization failed");
		return (-1);
	}

	if ((serverfd = init_console_sock(zlogp)) == -1) {
		zerror(zlogp, B_FALSE,
		    "console setup: socket initialization failed");
		return (-1);
	}
	return (0);
}

/*
 * serve_console() is the master loop for driving console I/O.  It is also the
 * routine which is ultimately responsible for "pulling the plug" on zoneadmd
 * when it realizes that the daemon should shut down.
 *
 * The rules for shutdown are: there must be no console client, and the zone
 * state must be < ready.  However, we need to give things a chance to actually
 * get going when the daemon starts up-- otherwise the daemon would immediately
 * exit on startup if the zone was in the installed state, so we first drop
 * into the do_console_io() loop in order to give *something* a chance to
 * happen.
 */
void
serve_console(zlog_t *zlogp)
{
	int masterfd;
	zone_state_t zstate;
	char conspath[MAXPATHLEN];

	(void) snprintf(conspath, sizeof (conspath),
	    "/dev/zcons/%s/%s", zone_name, ZCONS_MASTER_NAME);

	for (;;) {
		masterfd = open(conspath, O_RDWR|O_NONBLOCK|O_NOCTTY);
		if (masterfd == -1) {
			zerror(zlogp, B_TRUE, "failed to open console master");
			(void) mutex_lock(&lock);
			goto death;
		}

		/*
		 * Setting RPROTDIS on the stream means that the control
		 * portion of messages received (which we don't care about)
		 * will be discarded by the stream head.  If we allowed such
		 * messages, we wouldn't be able to use read(2), as it fails
		 * (EBADMSG) when a message with a control element is received.
		 */
		if (ioctl(masterfd, I_SRDOPT, RNORM|RPROTDIS) == -1) {
			zerror(zlogp, B_TRUE, "failed to set options on "
			    "console master");
			(void) mutex_lock(&lock);
			goto death;
		}

		do_console_io(zlogp, masterfd, serverfd);

		/*
		 * We would prefer not to do this, but hostile zone processes
		 * can cause the stream to become tainted, and reads will
		 * fail.  So, in case something has gone seriously ill,
		 * we dismantle the stream and reopen the console when we
		 * take another lap.
		 */
		(void) close(masterfd);

		(void) mutex_lock(&lock);
		/*
		 * We need to set death_throes (see below) atomically with
		 * respect to noticing that (a) we have no console client and
		 * (b) the zone is not installed.  Otherwise we could get a
		 * request to boot during this time.  Once we set death_throes,
		 * any incoming door stuff will be turned away.
		 */
		if (zone_get_state(zone_name, &zstate) == Z_OK) {
			if (zstate < ZONE_STATE_READY)
				goto death;
		} else {
			zerror(zlogp, B_FALSE,
			    "unable to determine state of zone");
			goto death;
		}
		/*
		 * Even if zone_get_state() fails, stay conservative, and
		 * take another lap.
		 */
		(void) mutex_unlock(&lock);
	}

death:
	assert(MUTEX_HELD(&lock));
	in_death_throes = B_TRUE;
	(void) mutex_unlock(&lock);

	destroy_console_sock(serverfd);
	(void) destroy_console_devs(zlogp);
}
