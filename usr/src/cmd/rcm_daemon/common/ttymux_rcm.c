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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <synch.h>
#include <libintl.h>
#include <errno.h>
#include <libdevinfo.h>
#include <sys/uio.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <stropts.h>
#include <sys/stream.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mkdev.h>

#include <sys/param.h>
#include <sys/openpromio.h>
#include <sys/ttymuxuser.h>

#include "ttymux_rcm_impl.h"
#include "rcm_module.h"

#define	TTYMUX_OFFLINE_ERR	gettext("Resource is in use by")
#define	TTYMUX_UNKNOWN_ERR	gettext("Unknown Operation attempted")
#define	TTYMUX_ONLINE_ERR	gettext("Failed to connect under multiplexer")
#define	TTYMUX_INVALID_ERR	gettext("Invalid Operation on this resource")
#define	TTYMUX_OFFLINE_FAIL	gettext("Failed to disconnect from multiplexer")
#define	TTYMUX_MEMORY_ERR	gettext("TTYMUX: strdup failure\n")


static int  msglvl = 6;	/* print messages less than this level */
#define	TEST(cond, stmt)  { if (cond) stmt; }
#define	_msg(lvl, args)   TEST(msglvl > (lvl), trace args)

static int	oflags = O_EXCL|O_RDWR|O_NONBLOCK|O_NOCTTY;
static dev_t	cn_dev = NODEV;
static rsrc_t	*cn_rsrc = NULL;
static rsrc_t	cache_head;
static rsrc_t	cache_tail;
static mutex_t	cache_lock;
static char	muxctl[PATH_MAX] = {0};
static char	muxcon[PATH_MAX] = {0};
static int	muxfd;
static boolean_t	register_rsrcs;

/* module interface routines */
static int tty_register(rcm_handle_t *);
static int tty_unregister(rcm_handle_t *);
static int tty_getinfo(rcm_handle_t *, char *, id_t, uint_t, char **,
    char **, nvlist_t *, rcm_info_t **);
static int tty_suspend(rcm_handle_t *, char *, id_t,
    timespec_t *, uint_t, char **, rcm_info_t **);
static int tty_resume(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int tty_offline(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int tty_online(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);
static int tty_remove(rcm_handle_t *, char *, id_t, uint_t, char **,
    rcm_info_t **);

static int get_devpath(char *, char **, dev_t *);

/*
 * Module-Private data
 */
static struct rcm_mod_ops tty_ops = {
	RCM_MOD_OPS_VERSION,
	tty_register,
	tty_unregister,
	tty_getinfo,
	tty_suspend,
	tty_resume,
	tty_offline,
	tty_online,
	tty_remove,
	NULL,
	NULL
};

/*PRINTFLIKE1*/
static void
trace(char *fmt, ...)
{
	va_list args;
	char    buf[256];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(buf, sizeof (buf), fmt, args);
	va_end(args);

	if (sz < 0)
		rcm_log_message(RCM_TRACE1,
		    _("TTYMUX: vsnprintf parse error\n"));
	else if (sz > sizeof (buf)) {
		char *b = malloc(sz + 1);

		if (b != NULL) {
			va_start(args, fmt);
			sz = vsnprintf(b, sz + 1, fmt, args);
			va_end(args);
			if (sz > 0)
				rcm_log_message(RCM_TRACE1, _("%s"), b);
			free(b);
		}
	} else {
		rcm_log_message(RCM_TRACE1, _("%s"), buf);
	}
}

/*
 * CACHE MANAGEMENT
 * Resources managed by this module are stored in a list of rsrc_t
 * structures.
 */

/*
 * cache_lookup()
 *
 * Get a cache node for a resource.  Call with cache lock held.
 */
static rsrc_t *
cache_lookup(const char *resource)
{
	rsrc_t *rsrc;
	rsrc = cache_head.next;
	while (rsrc != &cache_tail) {
		if (rsrc->id && strcmp(resource, rsrc->id) == 0) {
			return (rsrc);
		}
		rsrc = rsrc->next;
	}
	return (NULL);
}

/*
 * Get a cache node for a minor node.  Call with cache lock held.
 */
static rsrc_t *
cache_lookup_bydevt(dev_t devt)
{
	rsrc_t *rsrc;
	rsrc = cache_head.next;
	while (rsrc != &cache_tail) {
		if (rsrc->dev == devt)
			return (rsrc);
		rsrc = rsrc->next;
	}
	return (NULL);
}

/*
 * free_node()
 *
 * Free a node.  Make sure it isn't in the list!
 */
static void
free_node(rsrc_t *node)
{
	if (node) {
		if (node->id) {
			free(node->id);
		}
		free(node);
	}
}

/*
 * cache_insert()
 *
 * Call with the cache_lock held.
 */
static void
cache_insert(rsrc_t *node)
{
		/* insert at the head for best performance */
		node->next = cache_head.next;
		node->prev = &cache_head;

		node->next->prev = node;
		node->prev->next = node;
}

/*
 * cache_create()
 *
 * Call with the cache_lock held.
 */
static rsrc_t *
cache_create(const char *resource, dev_t dev)
{
	rsrc_t *rsrc = malloc(sizeof (rsrc_t));

	if (rsrc != NULL) {
		if ((rsrc->id = strdup(resource)) != NULL) {
			rsrc->dev = dev;
			rsrc->flags = 0;
			rsrc->dependencies = NULL;
			cache_insert(rsrc);
		} else {
			free(rsrc);
			rsrc = NULL;
		}
	} else {
		_msg(0, ("TTYMUX: malloc failure for resource %s.\n",
		    resource));
	}
	return (rsrc);
}

/*
 * cache_get()
 *
 * Call with the cache_lock held.
 */
static rsrc_t *
cache_get(const char *resource)
{
	rsrc_t *rsrc = cache_lookup(resource);
	if (rsrc == NULL) {
		dev_t	dev;

		(void) get_devpath((char *)resource, NULL, &dev);
		rsrc = cache_create(resource, dev);
	}
	return (rsrc);
}

/*
 * cache_remove()
 *
 * Call with the cache_lock held.
 */
static void
cache_remove(rsrc_t *node)
{
	node->next->prev = node->prev;
	node->prev->next = node->next;
	node->next = NULL;
	node->prev = NULL;
}

/*
 * Open a file identified by fname with the given open flags.
 * If the request is to open a file with exclusive access and the open
 * fails then backoff exponentially and then retry the open.
 * Do not wait for longer than about a second (since this may be an rcm
 * framework thread).
 */
static int
open_file(char *fname, int flags)
{
	int		fd, cnt;
	struct timespec ts;

	if ((flags & O_EXCL) == 0)
		return (open(fname, flags));

	ts.tv_sec = 0;
	ts.tv_nsec = 16000000;	/* 16 milliseconds */

	for (cnt = 0; cnt < 5 && (fd = open(fname, flags)) == -1; cnt++) {
		(void) nanosleep(&ts, NULL);
		ts.tv_nsec *= 2;
	}
	return (fd);
}

/*
 * No-op for creating an association between a pair of resources.
 */
/*ARGSUSED*/
static int
nullconnect(link_t *link)
{
	return (0);
}

/*
 * No-op for destroying an association between a pair of resources.
 */
/*ARGSUSED*/
static int
nulldisconnect(link_t *link)
{
	return (0);
}

/*
 * Record an actual or desired association between two resources
 * identified by their rsrc_t structures.
 */
static link_t *
add_dependency(rsrc_t *user, rsrc_t *used)
{
	link_t *linkhead;
	link_t *link;

	if (user == NULL || used == NULL)
		return (NULL);

	if (user->id && used->id && strcmp(user->id, used->id) == 0) {
		_msg(2, ("TTYMUX: attempt to connect devices created by "
		    "the same driver\n"));
		return (NULL);
	}

	/*
	 * Search for all resources that this resource user is depending
	 * upon.
	 */
	linkhead = user->dependencies;
	for (link = linkhead; link != NULL; link = link->next) {
		/*
		 * Does the using resource already depends on the used
		 * resource
		 */
		if (link->used == used)
			return (link);
	}

	link = malloc(sizeof (link_t));

	if (link == NULL) {
		rcm_log_message(RCM_ERROR, _("TTYMUX: Out of memory\n"));
		return (NULL);
	}

	_msg(6, ("TTYMUX: New link user %s used %s\n", user->id, used->id));

	link->user = user;
	link->used = used;
	link->linkid = 0;
	link->state = UNKNOWN;
	link->flags = 0;

	link->connect = nullconnect;
	link->disconnect = nulldisconnect;
	link->next = linkhead;

	user->dependencies = link;

	return (link);
}

/*
 * Send an I_STR stream ioctl to a device
 */
static int
istrioctl(int fd, int cmd, void *data, int datalen, int *bytes) {
	struct strioctl ios;
	int rval;

	ios.ic_timout = 0; /* use the default */
	ios.ic_cmd = cmd;
	ios.ic_dp = (char *)data;
	ios.ic_len = datalen;

	rval = ioctl(fd, I_STR, (char *)&ios);
	if (bytes)
		*bytes = ios.ic_len;
	return (rval);
}

/*
 * Streams link the driver identified by fd underneath a mux
 * identified by ctrl_fd.
 */
static int
plink(int ctrl_fd, int fd)
{
	int linkid;

	/*
	 * pop any modules off the lower stream.
	 */
	while (ioctl(fd, I_POP, 0) == 0)
		;

	if ((linkid = ioctl(ctrl_fd, I_PLINK, fd)) < 0)
		rcm_log_message(RCM_ERROR,
		    _("TTYMUX: I_PLINK error %d.\n"), errno);
	return (linkid);
}

/*
 * Streams unlink the STREAM identified by linkid from a mux
 * identified by ctrl_fd.
 */
static int
punlink(int ctrl_fd, int linkid)
{
	if (ioctl(ctrl_fd, I_PUNLINK, linkid) < 0)
		return (errno);
	else
		return (0);
}

/*
 * Connect a pair of resources by establishing the dependency association.
 * Only works for devices that support the TTYMUX ioctls.
 */
static int
mux_connect(link_t *link)
{
	int lfd;
	int rv;
	ttymux_assoc_t as;
	uint8_t ioflags;

	_msg(6, ("TTYMUX: mux_connect (%ld:%ld<->%ld:%ld %s <-> %s\n",
		major(link->user->dev), minor(link->user->dev),
		major(link->used->dev), minor(link->used->dev),
		link->user->id, link->used->id));

	_msg(12, ("TTYMUX: struct size = %d (plen %d)\n",
	    sizeof (as), PATH_MAX));

	if (link->user->dev == NODEV || link->used->dev == NODEV) {
		/*
		 * One of the resources in the association is not
		 * present (wait for the online notification before
		 * attempting to establish the dependency association.
		 */
		return (EAGAIN);
	}
	if (major(link->user->dev) == major(link->used->dev)) {
		_msg(2, ("TTYMUX: attempt to link devices created by "
		    "the same driver\n"));
		return (EINVAL);
	}
	/*
	 * Explicitly check for attempts to plumb the system console -
	 * required becuase not all serial devices support the
	 * O_EXCL open flag.
	 */
	if (link->used->dev == cn_dev) {
		rcm_log_message(RCM_WARNING, _("TTYMUX: Request to link the "
		    " system console under another device not allowed!\n"));

		return (EPERM);
	}

	/*
	 * Ensure that the input/output mode of the dependent is reasonable
	 */
	if ((ioflags = link->flags & FORIO) == 0)
		ioflags = FORIO;

	/*
	 * Open each resource participating in the association.
	 */
	lfd  = open(link->used->id, O_EXCL|O_RDWR|O_NONBLOCK|O_NOCTTY);
	if (lfd == -1) {
		if (errno == EBUSY) {
			rcm_log_message(RCM_WARNING, _("TTYMUX: device %s is "
			    " busy - " " cannot connect to %s\n"),
			    link->used->id, link->user->id);
		} else {
			rcm_log_message(RCM_WARNING,
			    _("TTYMUX: open error %d for device %s\n"),
			    errno, link->used->id);
		}
		return (errno);
	}
	/*
	 * Note: Issuing the I_PLINK and TTYMUX_ASSOC request on the 'using'
	 * resource is more generic:
	 * 	muxfd = open(link->user->id, oflags);
	 * However using the ctl (MUXCTLLINK) node means that any current opens
	 * on the 'using' resource are uneffected.
	 */

	/*
	 * Figure out if the 'used' resource is already associated with
	 * some resource - if so tell the caller to try again later.
	 * More generally if any user or kernel thread has the resource
	 * open then the association should not be made.
	 * The ttymux driver makes this check (but it should be done here).
	 */
	as.ttymux_linkid = 0;
	as.ttymux_ldev = link->used->dev;

	if (istrioctl(muxfd, TTYMUX_GETLINK,
		(void *)&as, sizeof (as), NULL) == 0) {

		_msg(7, ("TTYMUX: %ld:%ld (%d) (udev %ld:%ld) already linked\n",
		    major(as.ttymux_ldev), minor(as.ttymux_ldev),
				as.ttymux_linkid, major(as.ttymux_udev),
				minor(as.ttymux_udev)));
		link->linkid = as.ttymux_linkid;
		if (as.ttymux_udev != NODEV) {
			(void) close(lfd);
			return (EAGAIN);
		}
	}

	/*
	 * Now link and associate the used resource under the using resource.
	 */
	as.ttymux_udev = link->user->dev;
	as.ttymux_ldev = link->used->dev;
	as.ttymux_tag = 0ul;
	as.ttymux_ioflag = ioflags;

	_msg(6, ("TTYMUX: connecting %ld:%ld to %ld:%ld\n",
		major(as.ttymux_ldev), minor(as.ttymux_ldev),
		major(as.ttymux_udev), minor(as.ttymux_udev)));

	if (as.ttymux_udev == cn_dev) {
		struct termios tc;

		if (ioctl(lfd, TCGETS, &tc) != -1) {
			tc.c_cflag |= CREAD;
			if (ioctl(lfd, TCSETSW, &tc) == -1) {
				rcm_log_message(RCM_WARNING,
				    _("TTYMUX: error %d whilst enabling the "
				    "receiver on device %d:%d\n"),
				    errno, major(as.ttymux_ldev),
				    minor(as.ttymux_ldev));
			}
		}
	}

	if (as.ttymux_linkid <= 0 && (as.ttymux_linkid =
			plink(muxfd, lfd)) <= 0) {
		rcm_log_message(RCM_WARNING,
		    _("TTYMUX: Link error %d for device %s\n"),
		    errno, link->used->id);
		rv = errno;
		goto out;
	}
	link->linkid = as.ttymux_linkid;

	_msg(6, ("TTYMUX: associating\n"));
	if (istrioctl(muxfd, TTYMUX_ASSOC, (void *)&as, sizeof (as), 0) != 0) {
		rv = errno;
		goto out;
	}
	_msg(6, ("TTYMUX: Succesfully connected %ld:%ld to %ld:%ld\n",
		major(as.ttymux_ldev), minor(as.ttymux_ldev),
		major(as.ttymux_udev), minor(as.ttymux_udev)));
	link->state = CONNECTED;
	(void) close(lfd);
	return (0);
out:
	rcm_log_message(RCM_WARNING,
	    _("TTYMUX: Error [%d] connecting %d:%d to %d:%d\n"),
	    rv, major(as.ttymux_ldev), minor(as.ttymux_ldev),
	    major(as.ttymux_udev), minor(as.ttymux_udev));

	(void) close(lfd);
	if (as.ttymux_linkid > 0) {
		/*
		 * There was an error so unwind the I_PLINK step
		 */
		if (punlink(muxfd, as.ttymux_linkid) != 0)
			rcm_log_message(RCM_WARNING,
			    _("TTYMUX: Unlink error %d (%s).\n"),
			    errno, link->used->id);
	}
	return (rv);
}

/*
 * Disconnect a pair of resources by destroying the dependency association.
 * Only works for devices that support the TTYMUX ioctls.
 */
static int
mux_disconnect(link_t *link)
{
	int rv;
	ttymux_assoc_t as;

	_msg(6, ("TTYMUX: mux_disconnect %s<->%s (%ld:%ld<->%ld:%ld)\n",
	    link->user->id, link->used->id,
	    major(link->user->dev), minor(link->user->dev),
	    major(link->used->dev), minor(link->used->dev)));

	as.ttymux_ldev = link->used->dev;

	if (istrioctl(muxfd, TTYMUX_GETLINK,
	    (void *)&as, sizeof (as), NULL) != 0) {

		_msg(1, ("TTYMUX: %ld:%ld not linked [err %d]\n",
		    major(link->used->dev), minor(link->used->dev), errno));
		return (0);

		/*
		 * Do not disassociate console resources - simply
		 * unlink them so that they remain persistent.
		 */
	} else if (as.ttymux_udev != cn_dev &&
	    istrioctl(muxfd, TTYMUX_DISASSOC, (void *)&as,
	    sizeof (as), 0) == -1) {

		rv = errno;
		rcm_log_message(RCM_WARNING,
		    _("TTYMUX: Dissassociate error %d for %s\n"),
		    rv, link->used->id);

	} else if (punlink(muxfd, as.ttymux_linkid) != 0) {
		rv = errno;
		rcm_log_message(RCM_WARNING,
		    _("TTYMUX: Error %d unlinking %d:%d\n"),
		    errno, major(link->used->dev), minor(link->used->dev));
	} else {
		_msg(6, ("TTYMUX: %s<->%s disconnected.\n",
		    link->user->id, link->used->id));

		link->state = DISCONNECTED;
		link->linkid = 0;
		rv = 0;
	}
	return (rv);
}

/* PESISTENCY */

/*
 * Given a special device file system path return the /devices path
 * and/or the device number (dev_t) of the device.
 */
static int
get_devpath(char *dev, char **cname, dev_t *devt)
{
	struct stat sb;

	if (cname != NULL)
		*cname = NULL;

	if (devt != NULL)
		*devt = NODEV;

	if (lstat(dev, &sb) < 0) {
		return (errno);
	} else if ((sb.st_mode & S_IFMT) == S_IFLNK) {
		int lsz;
		char linkbuf[PATH_MAX+1];

		if (stat(dev, &sb) < 0)
			return (errno);

		lsz = readlink(dev, linkbuf, PATH_MAX);

		if (lsz <= 0)
			return (ENODEV);
		linkbuf[lsz] = '\0';
		dev = strstr(linkbuf, "/devices");
		if (dev == NULL)
			return (ENODEV);
	}

	if (cname != NULL)
		*cname = strdup(dev);

	if (devt != NULL)
		*devt = sb.st_rdev;

	return (0);
}

/*
 * See routine locate_node
 */
static int
locate_dev(di_node_t node, di_minor_t minor, void *arg)
{
	char	*devfspath;
	char	resource[PATH_MAX];
	rsrc_t	*rsrc;

	if (di_minor_devt(minor) != (dev_t)arg)
		return (DI_WALK_CONTINUE);

	if ((devfspath = di_devfs_path(node)) == NULL)
		return (DI_WALK_TERMINATE);

	if (snprintf(resource, sizeof (resource), "/devices%s:%s",
	    devfspath, di_minor_name(minor)) > sizeof (resource)) {
		di_devfs_path_free(devfspath);
		return (DI_WALK_TERMINATE);
	}

	di_devfs_path_free(devfspath);

	rsrc = cache_lookup(resource);
	if (rsrc == NULL &&
	    (rsrc = cache_create(resource, di_minor_devt(minor))) == NULL)
		return (DI_WALK_TERMINATE);

	rsrc->dev = di_minor_devt(minor);
	rsrc->flags |= PRESENT;
	rsrc->flags &= ~UNKNOWN;
	return (DI_WALK_TERMINATE);
}

/*
 * Find a devinfo node that matches the device argument (dev).
 * This is an expensive search of the whole device tree!
 */
static rsrc_t *
locate_node(dev_t dev, di_node_t *root)
{
	rsrc_t		*rsrc;

	assert(root != NULL);

	if ((rsrc = cache_lookup_bydevt(dev)) != NULL)
		return (rsrc);

	(void) di_walk_minor(*root, NULL, 0, (void*)dev, locate_dev);

	return (cache_lookup_bydevt(dev));
}

/*
 * Search for any existing dependency relationships managed by this
 * RCM module.
 */
static int
probe_dependencies()
{
	ttymux_assocs_t	links;
	ttymux_assoc_t	*asp;
	int		cnt, n;
	rsrc_t		*ruser;
	rsrc_t		*used;
	link_t		*link;
	di_node_t	root;

	cnt = istrioctl(muxfd, TTYMUX_LIST, (void *)0, 0, 0);

	_msg(8, ("TTYMUX: Probed %d links [%d]\n", cnt, errno));

	if (cnt <= 0)
		return (0);

	if ((links.ttymux_assocs = calloc(cnt, sizeof (ttymux_assoc_t))) == 0)
		return (EAGAIN);

	links.ttymux_nlinks = cnt;

	n = istrioctl(muxfd, TTYMUX_LIST, (void *)&links, sizeof (links), 0);

	if (n == -1) {
		_msg(2, ("TTYMUX: Probe error %s\n", strerror(errno)));
		free(links.ttymux_assocs);
		return (0);
	}

	asp = (ttymux_assoc_t *)links.ttymux_assocs;

	if ((root = di_init("/", DINFOSUBTREE|DINFOMINOR)) == DI_NODE_NIL)
		return (errno);

	(void) mutex_lock(&cache_lock);
	for (; cnt--; asp++) {
		_msg(7, ("TTYMUX: Probed: %ld %ld %ld:%ld <->  %ld:%ld\n",
		    asp->ttymux_udev, asp->ttymux_ldev,
		    major(asp->ttymux_udev), minor(asp->ttymux_udev),
		    major(asp->ttymux_ldev), minor(asp->ttymux_ldev)));
		/*
		 * The TTYMUX_LIST ioctl can return links relating
		 * to potential devices. Such devices are identified
		 * in the path field.
		 */
		if (asp->ttymux_ldev == NODEV) {
			char	buf[PATH_MAX];

			if (asp->ttymux_path == NULL ||
				*asp->ttymux_path != '/')
				continue;

			if (snprintf(buf, sizeof (buf), "/devices%s",
			    asp->ttymux_path) > sizeof (buf))
				continue;

			used = cache_get(buf);
		} else {
			used = locate_node(asp->ttymux_ldev, &root);
		}
		if ((ruser = locate_node(asp->ttymux_udev, &root)) == NULL) {
			_msg(7, ("TTYMUX: Probe: %ld:%ld not present\n",
			    major(asp->ttymux_udev), minor(asp->ttymux_udev)));
			continue;
		}
		if (used == NULL) {
			_msg(7, ("TTYMUX: Probe: %ld:%ld not present\n",
			    major(asp->ttymux_ldev), minor(asp->ttymux_ldev)));
			continue;
		}
		_msg(6, ("TTYMUX: Probe: Restore %s <-> %s (id %d)\n",
		    ruser->id, used->id, asp->ttymux_linkid));

		link = add_dependency(ruser, used);

		if (link != NULL) {
			link->flags = (uint_t)asp->ttymux_ioflag;
			link->linkid = asp->ttymux_linkid;
			link->state = CONNECTED;
			link->connect = mux_connect;
			link->disconnect = mux_disconnect;
		}
	}
	di_fini(root);
	(void) mutex_unlock(&cache_lock);
	free(links.ttymux_assocs);
	return (0);
}

/*
 * A resource has become available. Re-establish any associations involving
 * the resource.
 */
static int
rsrc_available(rsrc_t *rsrc)
{
	link_t	*link;
	rsrc_t	*rs;

	if (rsrc->dev == NODEV) {
		/*
		 * Now that the resource is present obtain its device number.
		 * For this to work the node must be present in the /devices
		 * tree (see devfsadm(1M) or drvconfig(1M)).
		 * We do not use libdevinfo because the node must be present
		 * under /devices for the connect step below to work
		 * (the node needs to be opened).
		 */
		(void) get_devpath(rsrc->id, NULL, &rsrc->dev);
		if (rsrc->dev == NODEV) {
			_msg(4,
			    ("Device node %s does not exist\n", rsrc->id));
			/*
			 * What does RCM do with failed online notifications.
			 */
			return (RCM_FAILURE);
		}
	}
	for (rs  = cache_head.next; rs != &cache_tail; rs = rs->next) {
		for (link = rs->dependencies;
		    link != NULL;
		    link = link->next) {
			if (link->user == rsrc || link->used == rsrc) {
				_msg(6, ("TTYMUX: re-connect\n"));
				(void) link->connect(link);
			}
		}
	}
	return (RCM_SUCCESS);
}

/*
 * A resource is going away. Tear down any associations involving
 * the resource.
 */
static int
rsrc_unavailable(rsrc_t *rsrc)
{
	link_t	*link;
	rsrc_t	*rs;

	for (rs  = cache_head.next; rs != &cache_tail; rs = rs->next) {
		for (link = rs->dependencies;
		    link != NULL;
		    link = link->next) {
			if (link->user == rsrc || link->used == rsrc) {
				_msg(6, ("TTYMUX: unavailable %s %s\n",
				    link->user->id, link->used->id));
				(void) link->disconnect(link);
			}
		}
	}

	return (RCM_SUCCESS);
}

/*
 * Find any resources that are using a given resource (identified by
 * the rsrc argument). The search begins after the resource identified
 * by the next argument. If next is NULL start at the first resource
 * in this RCM modules resource list. If the redundancy argument is
 * greater than zero then a resource which uses rsrc will only be
 * returned if it is associated with >= redundancy dependents.
 *
 * Thus, provided that the caller keeps the list locked it can iterate
 * through all the resources in the cache that depend upon rsrc.
 */
static rsrc_t *
get_next_user(rsrc_t *next, rsrc_t *rsrc, int redundancy)
{
	rsrc_t *src;
	link_t *link;
	int	cnt = 0;
	boolean_t inuse;

	src = (next != NULL) ? next->next : cache_head.next;

	while (src != &cache_tail) {
		inuse = B_FALSE;

		for (link = src->dependencies, cnt = 0;
			link != NULL;
			link = link->next) {

			if (link->state == CONNECTED)
				cnt++;

			if (link->used == rsrc)
				inuse = B_TRUE;
		}
		if (inuse == B_TRUE &&
		    (redundancy <= 0 || cnt == redundancy)) {
			return (src);
		}

		src = src->next;
	}

	_msg(8, ("TTYMUX: count_users(%s) res %d.\n", rsrc->id, cnt));
	return (NULL);
}

/*
 * Common handler for RCM notifications.
 */
/*ARGSUSED*/
static int
rsrc_change_common(rcm_handle_t *hd, int op, const char *rsrcid, uint_t flag,
	char **reason, rcm_info_t **dependent_reason, void *arg)
{
	rsrc_t	*rsrc, *user;
	int	rv, len;
	char	*tmp = NULL;

	(void) mutex_lock(&cache_lock);
	rsrc = cache_lookup(rsrcid);
	if (rsrc == NULL) {
		/* shouldn't happen because rsrc has been registered */
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}
	if ((muxfd = open_file(muxctl, oflags)) == -1) {
		rcm_log_message(RCM_ERROR, _("TTYMUX: %s unavailable: %s\n"),
		    muxctl, strerror(errno));
		(void) mutex_unlock(&cache_lock);
		return (RCM_SUCCESS);
	}
	switch (op) {

	case TTYMUX_SUSPEND:
		rv = RCM_FAILURE;
		_msg(4, ("TTYMUX: SUSPEND %s operation refused.\n",
		    rsrc->id));
		if ((*reason = strdup(TTYMUX_INVALID_ERR)) == NULL) {
			rcm_log_message(RCM_ERROR, TTYMUX_MEMORY_ERR);
		}
		break;

	case TTYMUX_REMOVE:
		rsrc->flags |= UNKNOWN;
		rsrc->flags &= ~(PRESENT | REGISTERED);
		rv = RCM_SUCCESS;
		break;

	case TTYMUX_OFFLINE:
		user = get_next_user(NULL, rsrc, 1);
		if (flag & RCM_QUERY) {
			rv = ((flag & RCM_FORCE) || (user == NULL)) ?
						RCM_SUCCESS : RCM_FAILURE;
			if (rv == RCM_FAILURE) {
				tmp = TTYMUX_OFFLINE_ERR;
				assert(tmp != NULL);
				len = strlen(tmp) + strlen(user->id) + 2;
				if ((*reason = (char *)malloc(len)) != NULL) {
					(void) snprintf(*reason, len,
							"%s %s", tmp, user->id);
				} else {
				rcm_log_message(RCM_ERROR, TTYMUX_MEMORY_ERR);
				}
			}

		} else if (flag & RCM_FORCE) {
			rv = rsrc_unavailable(rsrc);

			if (rv == RCM_FAILURE) {
				if ((*reason = strdup(TTYMUX_OFFLINE_FAIL)) ==
								NULL) {
					rcm_log_message(RCM_ERROR,
							TTYMUX_MEMORY_ERR);
				}
			}

		} else if (user != NULL) {
			rv = RCM_FAILURE;
			tmp = TTYMUX_OFFLINE_ERR;
			assert(tmp != NULL);
			len = strlen(tmp) + strlen(user->id) + 2;
			if ((*reason = (char *)malloc(len)) != NULL) {
					(void) snprintf(*reason, len,
							"%s %s", tmp, user->id);
			} else {
				rcm_log_message(RCM_ERROR, TTYMUX_MEMORY_ERR);
			}

		} else  {
			rv = rsrc_unavailable(rsrc);
			if (rv == RCM_FAILURE) {
				if ((*reason = strdup(TTYMUX_OFFLINE_FAIL)) ==
								NULL) {
					rcm_log_message(RCM_ERROR,
							TTYMUX_MEMORY_ERR);
				}
			}
		}

		if (rv == RCM_FAILURE) {
			_msg(4, ("TTYMUX: OFFLINE %s operation refused.\n",
			    rsrc->id));

		} else {
			_msg(4, ("TTYMUX: OFFLINE %s res %d.\n", rsrc->id, rv));
		}
		break;

	case TTYMUX_RESUME:
		rv = RCM_FAILURE;
		_msg(4, ("TTYMUX: RESUME %s operation refused.\n",
		    rsrc->id));
		if ((*reason = strdup(TTYMUX_INVALID_ERR)) == NULL) {
			rcm_log_message(RCM_ERROR, TTYMUX_MEMORY_ERR);
		}
		break;

	case TTYMUX_ONLINE:
		_msg(4, ("TTYMUX: ONLINE %s res %d.\n", rsrc->id, rv));
		rv = rsrc_available(rsrc);
		if (rv == RCM_FAILURE) {
			if ((*reason = strdup(TTYMUX_ONLINE_ERR)) == NULL) {
				rcm_log_message(RCM_ERROR, TTYMUX_MEMORY_ERR);
			}
		}
		break;
	default:
		rv = RCM_FAILURE;
		if ((*reason = strdup(TTYMUX_UNKNOWN_ERR)) == NULL) {
			rcm_log_message(RCM_ERROR, TTYMUX_MEMORY_ERR);
		}
	}

	(void) close(muxfd);
	(void) mutex_unlock(&cache_lock);
	return (rv);
}

static boolean_t
find_mux_nodes(char *drv)
{
	di_node_t	root, node;
	di_minor_t	dim;
	char		*devfspath;
	char		muxctlname[] = "ctl";
	char		muxconname[] = "con";
	int		nminors = 0;

	(void) strcpy(muxctl, MUXCTLLINK);
	(void) strcpy(muxcon, MUXCONLINK);
	cn_rsrc = NULL;

	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		rcm_log_message(RCM_WARNING, _("di_init error\n"));
		return (B_FALSE);
	}

	node = di_drv_first_node(drv, root);
	if (node == DI_NODE_NIL) {
		_msg(4, ("no node for %s\n", drv));
		di_fini(root);
		return (B_FALSE);
	}
	/*
	 * If the device is not a prom node do not continue.
	 */
	if (di_nodeid(node) != DI_PROM_NODEID) {
		di_fini(root);
		return (B_FALSE);
	}
	if ((devfspath = di_devfs_path(node)) == NULL) {
		di_fini(root);
		return (B_FALSE);
	}

	/*
	 * Loop through all the minor nodes the driver (drv) looking
	 * for the ctl node (this is the device on which
	 * to issue ioctls).
	 */
	dim = DI_MINOR_NIL;
	while ((dim = di_minor_next(node, dim)) != DI_MINOR_NIL) {

		_msg(7, ("MUXNODES: minor %s\n", di_minor_name(dim)));

		if (strcmp(di_minor_name(dim), muxctlname) == 0) {
			if (snprintf(muxctl, sizeof (muxctl),
			    "/devices%s:%s", devfspath,
			    di_minor_name(dim)) > sizeof (muxctl)) {
				_msg(1, ("muxctl:snprintf error\n"));
			}
			if (++nminors == 2)
				break;
		} else if (strcmp(di_minor_name(dim), muxconname) == 0) {
			if (snprintf(muxcon, sizeof (muxcon),
			    "/devices%s:%s", devfspath,
			    di_minor_name(dim)) > sizeof (muxcon)) {
				_msg(1, ("muxcon:snprintf error\n"));
			}
			if (++nminors == 2)
				break;
		}
	}

	di_devfs_path_free(devfspath);
	di_fini(root);

	if ((muxfd = open_file(muxctl, oflags)) != -1) {

		if (istrioctl(muxfd, TTYMUX_CONSDEV, (void *)&cn_dev,
			    sizeof (cn_dev), 0) != 0) {
				cn_dev = NODEV;
		} else {
			_msg(8, ("MUXNODES: found sys console: %ld:%ld\n",
				major(cn_dev), minor(cn_dev)));

			cn_rsrc = cache_create(muxcon, cn_dev);
			if (cn_rsrc != NULL) {
				cn_rsrc->flags |= PRESENT;
				cn_rsrc->flags &= ~UNKNOWN;
			}
		}
		(void) close(muxfd);

		if (cn_dev != NODEV)
			return (B_TRUE);
	} else {
		_msg(1, ("TTYMUX: %s unavailable: %s\n",
		    muxctl, strerror(errno)));
	}

	return (B_FALSE);
}

/*
 * Update registrations, and return the ops structure.
 */
struct rcm_mod_ops *
rcm_mod_init()
{
	_msg(4, ("TTYMUX: mod_init:\n"));
	cache_head.next = &cache_tail;
	cache_head.prev = NULL;
	cache_tail.prev = &cache_head;
	cache_tail.next = NULL;
	(void) mutex_init(&cache_lock, NULL, NULL);

	/*
	 * Find the multiplexer ctl and con nodes
	 */
	register_rsrcs = find_mux_nodes(TTYMUX_DRVNAME);

	return (&tty_ops);
}

/*
 * Save state and release resources.
 */
int
rcm_mod_fini()
{
	rsrc_t	*rsrc;
	link_t	*link, *nlink;

	_msg(7, ("TTYMUX: freeing cache.\n"));
	(void) mutex_lock(&cache_lock);
	rsrc = cache_head.next;
	while (rsrc != &cache_tail) {
		cache_remove(rsrc);

		for (link = rsrc->dependencies; link != NULL; ) {
			nlink = link->next;
			free(link);
			link = nlink;
		}

		free_node(rsrc);
		rsrc = cache_head.next;
	}
	(void) mutex_unlock(&cache_lock);

	(void) mutex_destroy(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * Return a string describing this module.
 */
const char *
rcm_mod_info()
{
	return ("Serial mux device module 1.1");
}

/*
 * RCM Notification Handlers
 */

static int
tty_register(rcm_handle_t *hd)
{
	rsrc_t	*rsrc;
	link_t	*link;
	int	rv;

	if (register_rsrcs == B_FALSE)
		return (RCM_SUCCESS);

	if ((muxfd = open_file(muxctl, oflags)) == -1) {
		rcm_log_message(RCM_ERROR, _("TTYMUX: %s unavailable: %s\n"),
		    muxctl, strerror(errno));
		return (RCM_SUCCESS);
	}
	/*
	 * Search for any new dependencies since the last notification or
	 * since module was initialisated.
	 */
	(void) probe_dependencies();

	/*
	 * Search the whole cache looking for any unregistered used resources
	 * and register them. Note that the 'using resource' (a ttymux device
	 * node) is not subject to DR operations so there is no need to
	 * register them with the RCM framework.
	 */
	(void) mutex_lock(&cache_lock);
	for (rsrc  = cache_head.next; rsrc != &cache_tail; rsrc = rsrc->next) {
		_msg(6, ("TTYMUX: REGISTER rsrc %s flags %d\n",
		    rsrc->id, rsrc->flags));

		if (rsrc->dependencies != NULL &&
			(rsrc->flags & REGISTERED) == 0) {
			_msg(6, ("TTYMUX: Registering rsrc %s\n", rsrc->id));
			rv = rcm_register_interest(hd, rsrc->id, 0, NULL);
			if (rv == RCM_SUCCESS)
				rsrc->flags |= REGISTERED;
		}

		for (link = rsrc->dependencies; link != NULL;
			link = link->next) {
			if ((link->used->flags & REGISTERED) != 0)
				continue;

			_msg(6, ("TTYMUX: Registering rsrc %s\n",
			    link->used->id));
			rv = rcm_register_interest(hd, link->used->id,
				0, NULL);
			if (rv != RCM_SUCCESS)
				rcm_log_message(RCM_WARNING,
				    _("TTYMUX: err %d registering %s\n"),
				    rv, link->used->id);
			else
				link->used->flags |= REGISTERED;
		}
	}

	(void) mutex_unlock(&cache_lock);
	(void) close(muxfd);
	return (RCM_SUCCESS);
}

/*
 * Unregister all registrations.
 */
static int
tty_unregister(rcm_handle_t *hd)
{
	rsrc_t	*rsrc;

	(void) mutex_lock(&cache_lock);
	/*
	 * Search every resource in the cache and if it has been registered
	 * then unregister it from the RCM framework.
	 */
	for (rsrc  = cache_head.next; rsrc != &cache_tail; rsrc = rsrc->next) {
		if ((rsrc->flags & REGISTERED) == 0)
			continue;

		if (rcm_unregister_interest(hd, rsrc->id, 0) != RCM_SUCCESS)
			rcm_log_message(RCM_WARNING,
			    _("TTYMUX: Failed to unregister %s\n"), rsrc->id);
		else
			rsrc->flags &= ~REGISTERED;
	}
	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*
 * Report resource usage information.
 */
/*ARGSUSED*/
static int
tty_getinfo(rcm_handle_t *hd, char *rsrcid, id_t id, uint_t flag, char **info,
    char **errstr, nvlist_t *proplist, rcm_info_t **depend_info)
{
	rsrc_t	*rsrc, *user;
	char	*ru;
	size_t	sz;

	(void) mutex_lock(&cache_lock);
	rsrc = cache_lookup(rsrcid);

	if (rsrc == NULL) {
		(void) mutex_unlock(&cache_lock);
		*errstr = strdup(gettext("Unmanaged resource"));
		return (RCM_FAILURE);
	}

	ru = strdup(gettext("Resource Users"));
	user = NULL;
	while ((user = get_next_user(user, rsrc, -1)) != NULL) {
		*info = ru;
		sz = strlen(*info) + strlen(user->id) + 2;
		ru = malloc(sz);
		if (ru == NULL) {
			free(*info);
			*info = NULL;
			break;
		}
		if (snprintf(ru, sz, ": %s%s", *info, user->id) > sz) {
			_msg(4, ("tty_getinfo: snprintf error.\n"));
		}

		free(*info);
	}
	*info = ru;

	if (*info == NULL) {
		(void) mutex_unlock(&cache_lock);
		*errstr = strdup(gettext("Short of memory resources"));
		return (RCM_FAILURE);
	}

	(void) mutex_unlock(&cache_lock);
	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
tty_offline(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **reason, rcm_info_t **dependent_reason)
{
	return (rsrc_change_common(hd, TTYMUX_OFFLINE, rsrc, flags,
	    reason, dependent_reason, NULL));
}

/*ARGSUSED*/
static int
tty_remove(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **reason, rcm_info_t **dependent_reason)
{
	return (rsrc_change_common(hd, TTYMUX_REMOVE, rsrc, flags,
	    reason, dependent_reason, NULL));
}

/*ARGSUSED*/
static int
tty_suspend(rcm_handle_t *hd, char *rsrc, id_t id, timespec_t *interval,
    uint_t flag, char **reason, rcm_info_t **dependent_reason)
{
	return (rsrc_change_common(hd, TTYMUX_SUSPEND, rsrc, flag,
	    reason, dependent_reason, (void *)interval));
}

/*ARGSUSED*/
static int
tty_online(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **reason, rcm_info_t **dependent_reason)
{
	return (rsrc_change_common(hd, TTYMUX_ONLINE, rsrc, flags,
	    reason, dependent_reason, NULL));
}

/*ARGSUSED*/
static int
tty_resume(rcm_handle_t *hd, char *rsrc, id_t id, uint_t flags,
    char **reason, rcm_info_t **dependent_reason)
{
	return (rsrc_change_common(hd, TTYMUX_RESUME, rsrc, flags,
	    reason, dependent_reason, NULL));
}
