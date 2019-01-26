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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <libdevice.h>
#include <libdevinfo.h>
#define	_KERNEL
#include <sys/dditypes.h>
#include <sys/devctl.h>
#include <sys/bofi.h>

static int online_device(char *path);
static int offline_device(char *path);
static int getstate_device(char *path);
static int getnameinst(char *path, int *instance, char *name, int namelen);
static int getpath(char *path, int instance, char *name, int pathlen);

static char buffer[50*1024];

#define	CMD_TABLE_SIZE 11
#define	BOFI_ONLINE 0
#define	BOFI_OFFLINE 1
#define	BOFI_GETSTATE 2
#define	BOFI_GETPATH 3

static struct {
	char *string;
	int val;
	int devctl_val;
} cmd_table[] = {
	{"online", -1, BOFI_ONLINE},
	{"offline", -1, BOFI_OFFLINE},
	{"getstate", -1, BOFI_GETSTATE},
	{"getpath", -1, BOFI_GETPATH},
	{"broadcast", BOFI_BROADCAST, -1},
	{"clear_acc_chk", BOFI_CLEAR_ACC_CHK, -1},
	{"clear_errors", BOFI_CLEAR_ERRORS, -1},
	{"clear_errdefs", BOFI_CLEAR_ERRDEFS, -1},
	{"start", BOFI_START, -1},
	{"stop", BOFI_STOP, -1},
	{"get_handles", BOFI_GET_HANDLES, -1}
};

int
main(int argc, char **argv)
{
	struct bofi_errctl errctl;
	struct bofi_get_handles get_handles;
	int command = -1;
	int devctl_command = -1;
	int i;
	int fd;

	char buf[MAXPATHLEN];
	char path[MAXPATHLEN];

	if (argc == 3) {
		(void) strncpy(path, argv[1], MAXPATHLEN);

		for (i = 0; i < CMD_TABLE_SIZE; i++) {
			if (strcmp(argv[2], cmd_table[i].string) == 0) {
				command = cmd_table[i].val;
				devctl_command = cmd_table[i].devctl_val;
			}
		}
		switch (devctl_command) {
		case BOFI_ONLINE:
		case BOFI_OFFLINE:
		case BOFI_GETPATH:
		case BOFI_GETSTATE:
			break;
		default:
			if (getnameinst(argv[1], &errctl.instance, buf,
			    MAXPATHLEN) == -1) {
				(void) fprintf(stderr,
				    "th_manage - invalid path\n");
				exit(1);
			}
			(void) strncpy(errctl.name, buf, MAXNAMELEN);
			errctl.namesize = strlen(errctl.name);
		}
	} else if (argc == 4) {
		errctl.namesize = strlen(argv[1]);
		(void) strncpy(errctl.name, argv[1], MAXNAMELEN);
		errctl.instance = atoi(argv[2]);
		for (i = 0; i < CMD_TABLE_SIZE; i++) {
			if (strcmp(argv[3], cmd_table[i].string) == 0) {
				command = cmd_table[i].val;
				devctl_command = cmd_table[i].devctl_val;
			}
		}
		switch (devctl_command) {
		case BOFI_ONLINE:
		case BOFI_OFFLINE:
		case BOFI_GETPATH:
		case BOFI_GETSTATE:
			(void) strcpy(path, "/devices/");
			if (getpath(&path[8], errctl.instance, errctl.name,
			    MAXPATHLEN) == -1) {
				(void) fprintf(stderr,
				    "th_manage - invalid name/instance\n");
				exit(1);
			}
		default:
			break;
		}
	} else {
		(void) fprintf(stderr, "usage:\n");
		(void) fprintf(stderr,
		    "    th_manage name instance state\n");
		(void) fprintf(stderr,
		    "    th_manage path state\n");
		exit(2);
	}

	if (command == -1) {
		/*
		 * might have been a devctl command
		 */
		if (devctl_command == BOFI_ONLINE) {
			while (online_device(path) != 0) {
				(void) sleep(3);
			}
			exit(0);
		}
		if (devctl_command == BOFI_OFFLINE) {
			while (offline_device(path) != 0) {
				(void) sleep(3);
			}
			exit(0);
		}
		if (devctl_command == BOFI_GETSTATE) {
			if (getstate_device(path) != 0) {
				perror("th_manage - getstate failed");
				exit(1);
			} else {
				exit(0);
			}
		}
		if (devctl_command == BOFI_GETPATH) {
			(void) fprintf(stdout, "%s\n", path);
			exit(0);
		}
		(void) fprintf(stderr,
		    "th_manage: invalid command\n");
		(void) fprintf(stderr,
		    "     Command must be one of start, stop, broadcast, "
		    "get_handles,\n");
		(void) fprintf(stderr,
		    "     clear_acc_chk, clear_errors or clear_errdefs\n");
		exit(2);
	}
	fd = open("/devices/pseudo/bofi@0:bofi,ctl", O_RDWR);
	if (fd == -1) {
		perror("th_manage - open of bofi driver");
		exit(2);
	}
	if (command == BOFI_GET_HANDLES) {
		get_handles.namesize = errctl.namesize;
		(void) strncpy(get_handles.name, errctl.name, MAXNAMELEN);
		get_handles.instance =  errctl.instance;
		get_handles.buffer = buffer;
		get_handles.count = sizeof (buffer) - 1;
		if (ioctl(fd, command, &get_handles) == -1) {
			perror("th_manage - setting state failed");
			exit(2);
		}
		buffer[sizeof (buffer) - 1] = '\0';
		(void) fprintf(stdout, "%s", buffer);
		(void) fflush(stdout);
		exit(0);
	}
	if (errctl.instance == -1) {
		struct bofi_get_hdl_info hdli;
		struct handle_info *hip, *hp;
		int i, j, *instp;

		hdli.namesize = errctl.namesize;
		(void) strncpy(hdli.name, errctl.name, MAXNAMELEN);
		hdli.hdli = 0;
		hdli.count = 0;
		/*
		 * Ask the bofi driver for all handles created by the driver
		 * under test.
		 */
		if (ioctl(fd, BOFI_GET_HANDLE_INFO, &hdli) == -1) {
			perror("driver failed to return access handles");
			exit(1);
		}
		if (hdli.count == 0) {
			exit(0); /* no handles */
		}
		if ((hip = memalign(sizeof (void *),
		    hdli.count * sizeof (*hip))) == 0) {
			perror("out of memory");
			exit(1);
		}
		hdli.hdli = (caddr_t)hip;
		if (ioctl(fd, BOFI_GET_HANDLE_INFO, &hdli) == -1) {
			perror("couldn't obtain all handles");
			exit(1);
		}
		if ((instp = malloc((hdli.count + 1) * sizeof (*instp))) == 0) {
			perror("out of memory");
			exit(1);
		}
		*instp = -1;
		for (i = 0, hp = hip; i < hdli.count; hp++, i++) {
			for (j = 0; instp[j] != -1; j++)
				if (hp->instance == instp[j])
					break;
			if (instp[j] == -1) {
				instp[j] = hp->instance;
				instp[j+1] = -1;
			}
		}
		for (i = 0; instp[i] != -1; i++) {
			errctl.instance = instp[i];
			if (ioctl(fd, command, &errctl) == -1) {
				(void) fprintf(stderr,
				    "command failed on instance %d : %s\n",
				    errctl.instance, strerror(errno));
				exit(1);
			}
		}
	} else {
		if (ioctl(fd, command, &errctl) == -1) {
			perror("th_manage - setting state failed");
			exit(1);
		}
	}
	return (0);
}


/*
 * These functions provide access to the devctl functions,
 */
static int
online_device(char *path)
{
	devctl_hdl_t	dcp;

	if ((dcp = devctl_device_acquire(path, 0)) == NULL) {
		return (-1);
	}
	if ((devctl_device_online(dcp)) == -1) {
		devctl_release(dcp);
		return (-1);
	}
	devctl_release(dcp);
	return (0);
}


static int
offline_device(char *path)
{
	devctl_hdl_t	dcp;

	if ((dcp = devctl_device_acquire(path, 0)) == NULL) {
		return (-1);
	}
	if ((devctl_device_offline(dcp)) == -1) {
		devctl_release(dcp);
		return (-1);
	}
	devctl_release(dcp);
	return (0);
}

static int
getstate_device(char *path)
{
	devctl_hdl_t	dcp;
	uint_t		state = 0;

	if ((dcp = devctl_device_acquire(path, 0)) == NULL) {
		(void) printf("%s unknown unknown\n", path);
		return (-1);
	}
	if ((devctl_device_getstate(dcp, &state)) == -1) {
		(void) printf("%s unknown unknown\n", path);
		devctl_release(dcp);
		return (-1);
	}
	devctl_release(dcp);
	switch (state) {
	case DEVICE_DOWN:
		(void) printf("%s down not_busy\n", path);
		break;
	case DEVICE_OFFLINE:
		(void) printf("%s offline not_busy\n", path);
		break;
	case DEVICE_ONLINE:
		(void) printf("%s online not_busy\n", path);
		break;
	case (DEVICE_ONLINE | DEVICE_BUSY):
		(void) printf("%s online busy\n", path);
		break;
	case (DEVICE_DOWN | DEVICE_BUSY):
		(void) printf("%s down busy\n", path);
		break;
	default:
		(void) printf("%s unknown unknown\n", path);
		break;
	}
	return (0);
}

static int
getnameinst(char *path, int *instance, char *name, int namelen)
{
	di_node_t node;
	char *driver_name;

	if ((node = di_init(&path[8], DINFOSUBTREE)) == DI_NODE_NIL)
		return (-1);
	if ((driver_name = di_driver_name(node)) == NULL) {
		di_fini(node);
		return (-1);
	}
	*instance = di_instance(node);
	(void) strncpy(name, driver_name, namelen);
	di_fini(node);
	return (0);
}

struct walk_arg {
	char *path;
	int instance;
	char name[MAXPATHLEN];
	int found;
	int pathlen;
};

static int
walk_callback(di_node_t node, void *arg)
{
	struct walk_arg *warg = (struct walk_arg *)arg;
	char *driver_name;
	char *path;

	driver_name = di_driver_name(node);
	if (driver_name != NULL) {
		if (strcmp(driver_name, warg->name) == 0 &&
		    di_instance(node) == warg->instance) {
			path = di_devfs_path(node);
			if (path != NULL) {
				warg->found = 1;
				(void) strncpy(warg->path, path, warg->pathlen);
			}
			return (DI_WALK_TERMINATE);
		}
	}
	return (DI_WALK_CONTINUE);
}

static int
getpath(char *path, int instance, char *name, int pathlen)
{
	di_node_t node;
	struct walk_arg warg;

	warg.instance = instance;
	(void) strncpy(warg.name, name, MAXPATHLEN);
	warg.path = path;
	warg.pathlen = pathlen;
	warg.found = 0;
	if ((node = di_init("/", DINFOSUBTREE)) == DI_NODE_NIL)
		return (-1);
	if (di_walk_node(node, DI_WALK_CLDFIRST, &warg, walk_callback) == -1) {
		di_fini(node);
		return (-1);
	}
	if (warg.found == 0) {
		di_fini(node);
		return (-1);
	}
	di_fini(node);
	return (0);
}
