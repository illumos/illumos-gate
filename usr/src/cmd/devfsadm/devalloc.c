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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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

static char *_update_dev(deventry_t *, int, const char *, char *, char *);
static int _make_db();
extern int event_driven;


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
		return (1);
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
 *
 *      Or finds the correct entry to remove, and removes it.
 *
 *    Note: devname is a /devices link in the REMOVE case.
 */
/* ARGSUSED */
void
_update_devalloc_db(devlist_t *devlist, int devflag, int action, char *devname,
    char *root_dir)
{
	int		i;
	deventry_t	*entry = NULL, *dentry = NULL;
	char 		*typestring;
	char 		*nickname;  /* typestring + instance */

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
				(void) _update_dev(dentry, action, NULL, NULL,
				    NULL);
		}
	} else if (action == DA_REMOVE) {
		if (devflag & DA_AUDIO) {
			dentry = devlist->audio;
			typestring = DA_AUDIO_TYPE;
		} else if (devflag & DA_CD) {
			dentry = devlist->cd;
			typestring = DA_CD_TYPE;
		} else if (devflag & DA_FLOPPY) {
			dentry = devlist->floppy;
			typestring = DA_FLOPPY_TYPE;
		} else if (devflag & DA_TAPE) {
			dentry = devlist->tape;
			typestring = DA_TAPE_TYPE;
		} else if (devflag & DA_RMDISK) {
			dentry = devlist->rmdisk;
			typestring = DA_RMDISK_TYPE;
		} else
			return;

		if (event_driven) {
			nickname = _update_dev(NULL, action, typestring, NULL,
			    devname);

			if (nickname != NULL) {
				(void) da_rm_list_entry(devlist, devname,
				    devflag, nickname);
				free(nickname);
			}
			return;
		}
		/*
		 * Not reached as of now, could be reached if devfsadm is
		 * enhanced to clean up devalloc database more thoroughly.
		 * Will not reliably match for event-driven removes
		 */
		for (entry = dentry; entry != NULL; entry = entry->next) {
			if (strcmp(entry->devinfo.devname, devname) == 0)
				break;
		}
		(void) _update_dev(entry, action, NULL, devname, NULL);
	}
}

/*
 *	_update_dev: Update device_allocate and/or device_maps files
 *
 *      If adding a device:
 *	    dentry:	A linked list of allocatable devices
 *	    action:	DA_ADD or DA_REMOVE
 *	    devtype:	type of device linked list to update on removal
 *	    devname:	short name (i.e. rmdisk5, cdrom0)  of device if known
 *	    rm_link:	name of real /device from hot_cleanup
 *
 *	If the action is ADD or if the action is triggered by an event
 *      from syseventd,  read the files FIRST and treat their data as
 *      more-accurate than the dentry list, adjusting dentry contents if needed.
 *
 *	For DA_ADD, try to add each device in the list to the files.
 *
 *      If the action is DA_REMOVE and not a hotplug remove, adjust the files
 *	as indicated by the linked list.
 *
 *	RETURNS:
 *          If we successfully remove a device from the files,  returns
 *          a char * to strdup'd devname of the device removed.
 *
 *	    The caller is responsible for freeing the return value.
 *
 *	NULL for all other cases, both success and failure.
 *
 */
static char *
_update_dev(deventry_t *dentry, int action, const char *devtype, char *devname,
    char *rm_link)
{
	da_args		dargs;
	deventry_t	newentry, *entry;
	int status;

	dargs.rootdir = NULL;
	dargs.devnames = NULL;

	if (event_driven)
		dargs.optflag = DA_EVENT;
	else
		dargs.optflag = 0;

	if (action == DA_ADD) {
		dargs.optflag |= DA_ADD;
		/*
		 * Add Events do not have enough information to overrride the
		 * existing file contents.
		 */

		for (entry = dentry; entry != NULL; entry = entry->next) {
			dargs.devinfo = &(entry->devinfo);
			(void) da_update_device(&dargs);
		}
	} else if (action == DA_REMOVE) {
		dargs.optflag |= DA_REMOVE;
		if (dentry) {
			entry = dentry;
		} else if (dargs.optflag & DA_EVENT) {
			if (devname == NULL)
				newentry.devinfo.devname = NULL;
			else
				newentry.devinfo.devname = strdup(devname);
			newentry.devinfo.devtype = (char *)devtype;
			newentry.devinfo.devauths =
			    newentry.devinfo.devopts =
			    newentry.devinfo.devexec = NULL;
			newentry.devinfo.devlist = strdup(rm_link);
			newentry.devinfo.instance = 0;
			newentry.next = NULL;
			entry = &newentry;
		} else {
			newentry.devinfo.devname = strdup(devname);
			newentry.devinfo.devtype = (char *)devtype;
			newentry.devinfo.devauths =
			    newentry.devinfo.devexec =
			    newentry.devinfo.devopts =
			    newentry.devinfo.devlist = NULL;
			newentry.devinfo.instance = 0;
			newentry.next = NULL;
			entry = &newentry;
		}
		dargs.devinfo = &(entry->devinfo);
		/*
		 * da_update_device will fill in entry devname if
		 * event_driven is true and device is in the file
		 */
		status = da_update_device(&dargs);
		if (event_driven)
			if (newentry.devinfo.devlist != NULL)
				free(newentry.devinfo.devlist);
		if (status == 0)
			return (dargs.devinfo->devname);
		else free(dargs.devinfo->devname);
	}
	return (NULL);
}
