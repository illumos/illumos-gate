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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Device allocation related work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/wait.h>
#include <bsm/devalloc.h>

#define	DEALLOCATE	 "/usr/sbin/deallocate"
#define	MKDEVALLOC	"/usr/sbin/mkdevalloc"

static void _update_dev(deventry_t *, int, char *);
static int _make_db();


/*
 * _da_check_for_usb
 *	returns 1 if device pointed by 'link' is a removable hotplugged disk,
 *	else returns 0.
 */
int
_da_check_for_usb(char *link, char *root_dir)
{
	int		fd = -1;
	int		len, dstsize;
	int		removable = 0;
	int		hotpluggable = 0;
	char		*p = NULL;
	char		path[MAXPATHLEN + 4];
	char		rpath[MAXPATHLEN + 4];		/* for ",raw" */

	dstsize = sizeof (path);
	if (strcmp(root_dir, "") != 0) {
		if (strlcat(path, root_dir, dstsize) >= dstsize)
			return (0);
		len = strlen(path);
	} else {
		len = 0;
	}
	(void) snprintf(path, dstsize - len, "%s", link);
	if ((p = realpath(path, rpath)) == NULL) {
		p = path;
	} else {
		if (strstr(link, "rdsk")) {
			p = rpath;
		} else {
			(void) snprintf(path, dstsize, "%s%s", rpath, ",raw");
			p = path;
		}
	}
	if ((fd = open(p, O_RDONLY | O_NONBLOCK)) < 0)
		return (0);
	(void) ioctl(fd, DKIOCREMOVABLE, &removable);
	(void) ioctl(fd, DKIOCHOTPLUGGABLE, &hotpluggable);
	(void) close(fd);

	if (removable && hotpluggable)
		return (1);

	return (0);
}

/*
 * _reset_devalloc
 *	If device allocation is being turned on, creates device_allocate
 *	device_maps if they do not exist.
 *	Puts DEVICE_ALLOCATION=ON/OFF in device_allocate to indicate if
 *	device allocation is on/off.
 */
void
_reset_devalloc(int action)
{
	da_args	dargs;

	if (action == DA_ON)
		(void) _make_db();
	else if ((action == DA_OFF) && (open(DEVALLOC, O_RDONLY) == -1))
		return;

	if (action == DA_ON)
		dargs.optflag = DA_ON;
	else if (action == DA_OFF)
		dargs.optflag = DA_OFF | DA_ALLOC_ONLY;

	dargs.rootdir = NULL;
	dargs.devnames = NULL;
	dargs.devinfo = NULL;

	(void) da_update_device(&dargs);
}

/*
 * _make_db
 *	execs /usr/sbin/mkdevalloc to create device_allocate and
 *	device_maps.
 */
static int
_make_db()
{
	int	status;
	pid_t	pid, wpid;

	pid = vfork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		if (execl(MKDEVALLOC, MKDEVALLOC, DA_IS_LABELED, NULL) == -1)
			exit((errno == ENOENT) ? 0 : 1);
	default:
		for (;;) {
			wpid = waitpid(pid, &status, 0);
			if (wpid == (pid_t)-1) {
				if (errno == EINTR)
					continue;
				else
					return (1);
			} else {
				break;
			}
		}
		break;
	}

	return ((WIFEXITED(status) == 0) ? 1 : WEXITSTATUS(status));
}


/*
 * _update_devalloc_db
 * 	Forms allocatable device entries to be written to device_allocate and
 *	device_maps.
 */
/* ARGSUSED */
void
_update_devalloc_db(devlist_t *devlist, int devflag, int action, char *devname,
    char *root_dir)
{
	int		i;
	deventry_t	*entry = NULL, *dentry = NULL;

	if (action == DA_ADD) {
		for (i = 0; i < DA_COUNT; i++) {
			switch (i) {
			case 0:
				dentry = devlist->audio;
				break;
			case 1:
				dentry = devlist->cd;
				break;
			case 2:
				dentry = devlist->floppy;
				break;
			case 3:
				dentry = devlist->tape;
				break;
			case 4:
				dentry = devlist->rmdisk;
				break;
			default:
				return;
			}
			if (dentry)
				_update_dev(dentry, action, NULL);
		}
	} else if (action == DA_REMOVE) {
		if (devflag & DA_AUDIO)
			dentry = devlist->audio;
		else if (devflag & DA_CD)
			dentry = devlist->cd;
		else if (devflag & DA_FLOPPY)
			dentry = devlist->floppy;
		else if (devflag & DA_TAPE)
			dentry = devlist->tape;
		else if (devflag & DA_RMDISK)
			dentry = devlist->rmdisk;
		else
			return;

		for (entry = dentry; entry != NULL; entry = entry->next) {
			if (strcmp(entry->devinfo.devname, devname) == 0)
				break;
		}
		_update_dev(entry, action, devname);
	}
}

static void
_update_dev(deventry_t *dentry, int action, char *devname)
{
	da_args		dargs;
	deventry_t	newentry, *entry;

	dargs.rootdir = NULL;
	dargs.devnames = NULL;

	if (action == DA_ADD) {
		dargs.optflag = DA_ADD | DA_FORCE;
		for (entry = dentry; entry != NULL; entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
		}
	} else if (action == DA_REMOVE) {
		dargs.optflag = DA_REMOVE;
		if (dentry) {
			entry = dentry;
		} else {
			newentry.devinfo.devname = strdup(devname);
			newentry.devinfo.devtype =
			newentry.devinfo.devauths =
			newentry.devinfo.devexec =
			newentry.devinfo.devopts =
			newentry.devinfo.devlist = NULL;
			newentry.devinfo.instance = 0;
			newentry.next = NULL;
			entry = &newentry;
		}
		dargs.devinfo = &(entry->devinfo);
		(void) da_update_device(&dargs);
	}
}
