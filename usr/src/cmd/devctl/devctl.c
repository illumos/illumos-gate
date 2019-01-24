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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * devctl - device control utility
 *
 * to compile:
 * cc -o devctl -ldevice -ldevinfo devctl.c
 *
 * usage: devctl [-v] command [device/bus pathname]
 *
 * Commands:
 *	list		- list all controllers exporting the devctl interface
 *	online		- online a device
 *	offline		- offline a device
 *	remove		- remove a device from the device tree
 *	quiesce		- quiesce the bus
 *	unquiesce	- resume bus activity
 *	configure	- configure a bus's child devices
 *	unconfigure	- unconfigure a bus's child devices
 *	bus-reset	- reset a bus
 *	dev-reset	- reset a device
 *	bus-getstate	- return the current state of the bus
 *	dev-getstate	- return the current state of the device
 *	bus-devcreate	- create a new device, bus specific
 *	dev-raisepower		- power up a device via pm_raise_power() (pm)
 *	dev-idlecomp		- idle a device's component 0 (pm)
 *	dev-busycomp		- busy a device's component 0 (pm)
 *	dev-testbusy		- test a device's component 0's busy state (pm)
 *	dev-changepowerhigh	- power up a device via pm_power_has_changed()
 *				  (pm)
 *	dev-changepowerlow	- power off a device via pm_power_has_changed()
 *				  (pm)
 *	dev-failsuspend		- fail DDI_SUSPEND (pm)
 *	dev-changeonresume	- issue pm_power_has_changed() vs,
 *				  pm_raise_power() on device resume (pm)
 *	dev-nolowerpower	- don't call pm_lower_power() on detach (pm)
 *	dev-promprintf		- issue a prom_printf() call (pm)
 *	bus-raisepower		- power up a bus via pm_raise_power() (pm)
 *	bus-idlecomp		- idle a bus' component (pm)
 *	bus-busycomp		- busy a bus' component (pm)
 *	bus-testbusy		- test a bus' component busy state (pm)
 *	bus-changepowerhigh	- power up a bus via pm_power_has_changed() (pm)
 *	bus-changepowerlow	- power off a bus via pm_power_has_changed()
 *				  (pm)
 *	bus-failsuspend		- fail DDI_SUSPEND (pm)
 *	bus-teststrict		- test is bus driver is  strict or involved (pm)
 *	bus-noinvol		- mark idle twice when child detaches
 *
 *
 * Returns:
 *	- Success
 *	- Operation not supported by device
 *	- No Permission
 *	- No Such Device
 *
 * Examples:
 *	devctl list - list all controllers exporting a :devctl node
 *	devctl offline /dev/dsk/c0t3d0s0  - offline disk
 *	devctl dev-getstate  /devices/sbus@1f,0/espdma@e,8400000/esp@e,8800000\
 * sd@3,0
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <libdevice.h>
#include <libdevinfo.h>
#include <sys/sunddi.h>

typedef struct cmds {
	char *cmdname;
	int (*cmdf)(devctl_hdl_t);
} cmds_t;

extern int errno;

static void setpname(char *name);
static void print_bus_state(char *devname, uint_t state);
static void print_dev_state(char *devname, uint_t state);
static int dev_getstate(devctl_hdl_t);
static int bus_getstate(devctl_hdl_t);
static int bus_devcreate(devctl_hdl_t);
static void run_list_ctlrs(void);
static struct cmds *dc_cmd();
static int nexif(di_node_t din, di_minor_t dim, void *arg);
static void *s_malloc(size_t);
static void *s_realloc(void *, size_t);
static char *s_strdup(char *);
static int dev_pm_testbusy(devctl_hdl_t);
static int bus_pm_teststrict(devctl_hdl_t);

static char *devctl_device;
static char *orig_path;
static char *devctl_cmdname;
static char *progname;
static int  verbose;
static int  debug;
static char *dev_name;
static char **dev_props;

static const char *usage = "%s [-v] list | online | offline | remove |\n"
	"\tquiesce | unquiesce | configure | unconfigure |\n"
	"\t{bus,dev}-reset {bus,dev}-getstate | {bus,dev}-raisepower |\n"
	"\t{bus,dev}-idlecomp | {bus,dev}-busycomp |\n"
	"\t{bus,dev}-changepowerhigh | {bus,dev}-changepowerlow |\n"
	"\t{bus,dev}-testbusy | {bus,dev}-failsuspend | dev-changeonresume |\n"
	"\tdev-promprintf | dev-nolowerpower | bus-teststrict |\n"
	"\tbus-noinvol [/dev/... | /devices/...]\n";

static struct cmds device_cmds[] = {
	{"online", devctl_device_online},
	{"offline", devctl_device_offline},
	{"remove", devctl_device_remove},
	{"dev-reset", devctl_device_reset},
	{"dev-getstate", dev_getstate},
	{"dev-raisepower", devctl_pm_raisepower},
	{"dev-busycomp", devctl_pm_busycomponent},
	{"dev-idlecomp", devctl_pm_idlecomponent},
	{"dev-testbusy", dev_pm_testbusy},
	{"dev-changepowerlow", devctl_pm_changepowerlow},
	{"dev-changepowerhigh", devctl_pm_changepowerhigh},
	{"dev-failsuspend", devctl_pm_failsuspend},
	{"dev-changeonresume", devctl_pm_device_changeonresume},
	{"dev-promprintf", devctl_pm_device_promprintf},
	{"dev-nolowerpower", devctl_pm_device_no_lower_power},
	{NULL, NULL},
};

static struct cmds bus_cmds[] = {
	{"quiesce", devctl_bus_quiesce},
	{"unquiesce", devctl_bus_unquiesce},
	{"bus-reset", devctl_bus_reset},
	{"configure", devctl_bus_configure},
	{"unconfigure", devctl_bus_unconfigure},
	{"bus-getstate", bus_getstate},
	{"bus-devcreate", bus_devcreate},
	{"bus-raisepower", devctl_pm_raisepower},
	{"bus-busycomp", devctl_pm_busycomponent},
	{"bus-idlecomp", devctl_pm_idlecomponent},
	{"bus-changepowerlow", devctl_pm_changepowerlow},
	{"bus-changepowerhigh", devctl_pm_changepowerhigh},
	{"bus-testbusy", dev_pm_testbusy},
	{"bus-failsuspend", devctl_pm_failsuspend},
	{"bus-teststrict", bus_pm_teststrict},
	{"bus-noinvol", devctl_pm_bus_no_invol},
	{NULL, NULL},
};



int
main(int argc, char *argv[])
{
	int	c;
	int	rv;
	int	pathlen;
	struct cmds *dcmd;
	devctl_hdl_t dcp;
	struct stat stat_buf;

	setpname(argv[0]);
	while ((c = getopt(argc, argv, "vd")) != -1)  {
		switch (c)  {
		case 'v':
			++verbose;
			break;
		case 'd':
			++debug;
			(void) putenv("LIBDEVICE_DEBUG");
			break;
		default:
			(void) fprintf(stderr, usage, progname);
			exit(1);
			/*NOTREACHED*/
		}
	}

	if (optind == argc) {
		(void) fprintf(stderr, usage, progname);
		exit(-1);
	}

	devctl_cmdname = argv[optind++];

	if (strcmp(devctl_cmdname, "list") == 0) {
		run_list_ctlrs();
		exit(0);
	}

	/*
	 * any command other than "list" requires a device path
	 */
	if (((optind + 1) > argc)) {
		(void) fprintf(stderr, usage, progname);
		exit(-1);
	}

	orig_path = s_strdup(argv[optind]);
	devctl_device = s_malloc(MAXPATHLEN);
	(void) strcpy(devctl_device, orig_path);

	/*
	 * Additional properties follow for bus-devcreate
	 */
	if ((optind + 1 < argc) &&
	    strcmp(devctl_cmdname, "bus-devcreate") == 0) {
		int i;
		optind++;
		dev_name = s_strdup(argv[optind]);
		i = argc - optind;
		dev_props = s_malloc(i * sizeof (char *));
		while (--i) {
			dev_props[i - 1] = s_strdup(argv[optind + i]);
		}
	}

	/*
	 * if the device is a logical name, get the physical name
	 */
	if (lstat(orig_path, &stat_buf) == 0) {
		if (S_ISLNK(stat_buf.st_mode)) {
			if ((pathlen = readlink(orig_path, devctl_device,
			    MAXPATHLEN)) == -1)  {
				(void) fprintf(stderr,
				    "devctl: readlink(%s) - %s\n",
				    orig_path, strerror(errno));
				exit(-1);
			}
			devctl_device[pathlen] = '\0';
		}
	}

	if ((dcmd = dc_cmd(device_cmds, devctl_cmdname)) == NULL) {
		dcmd = dc_cmd(bus_cmds, devctl_cmdname);
		if (dcmd == NULL) {
			(void) fprintf(stderr, "unrecognized command (%s)\n",
			    devctl_cmdname);
			(void) fprintf(stderr, usage, progname);
			exit(1);
		} else if (strcmp(devctl_cmdname, "bus-raisepower") == 0 ||
		    strcmp(devctl_cmdname, "bus-changepowerlow") == 0 ||
		    strcmp(devctl_cmdname, "bus-changepowerhigh") == 0 ||
		    strcmp(devctl_cmdname, "bus-idlecomp") == 0 ||
		    strcmp(devctl_cmdname, "bus-busycomp") == 0 ||
		    strcmp(devctl_cmdname, "bus-testbusy") == 0 ||
		    strcmp(devctl_cmdname, "bus-failsuspend") == 0 ||
		    strcmp(devctl_cmdname, "bus-teststrict") == 0 ||
		    strcmp(devctl_cmdname, "bus-noinvol") == 0) {
			dcp = devctl_pm_bus_acquire(devctl_device, 0);
			if (dcp == NULL) {
				(void) fprintf(stderr,
				    "devctl: device_pm_bus_acquire %s - %s\n",
				    devctl_device, strerror(errno));
				exit(-1);
			}
		} else {
			dcp = devctl_bus_acquire(devctl_device, 0);
			if (dcp == NULL) {
				(void) fprintf(stderr, "devctl: bus_acquire "
				    "%s - %s\n",
				    devctl_device, strerror(errno));
				exit(-1);
			}
		}
	} else if (strcmp(devctl_cmdname, "dev-raisepower") == 0 ||
	    strcmp(devctl_cmdname, "dev-changepowerlow") == 0 ||
	    strcmp(devctl_cmdname, "dev-changepowerhigh") == 0 ||
	    strcmp(devctl_cmdname, "dev-idlecomp") == 0 ||
	    strcmp(devctl_cmdname, "dev-busycomp") == 0 ||
	    strcmp(devctl_cmdname, "dev-testbusy") == 0 ||
	    strcmp(devctl_cmdname, "dev-failsuspend") == 0 ||
	    strcmp(devctl_cmdname, "dev-changeonresume") == 0 ||
	    strcmp(devctl_cmdname, "dev-promprintf") == 0 ||
	    strcmp(devctl_cmdname, "dev-nolowerpower") == 0) {
		dcp = devctl_pm_dev_acquire(devctl_device, 0);
		if (dcp == NULL) {
			(void) fprintf(stderr,
			    "devctl: device_pm_dev_acquire %s - %s\n",
			    devctl_device, strerror(errno));
			exit(-1);
		}
	} else {
		dcp = devctl_device_acquire(devctl_device, 0);
		if (dcp == NULL) {
			(void) fprintf(stderr,
			    "devctl: device_acquire %s - %s\n",
			    devctl_device, strerror(errno));
			exit(-1);
		}
	}

	if (verbose)
		(void) printf("devctl: cmd (%s) device (%s)\n",
		    devctl_cmdname, orig_path);

	(void) fflush(NULL);	/* get output out of the way */

	rv = (dcmd->cmdf)(dcp);

	if (rv == -1) {
		perror("devctl");
		exit(-1);
	}
	return (0);
} /* main */

static int
dev_pm_testbusy(devctl_hdl_t dcp)
{
	int rv;
	uint_t *busyp;

	busyp = s_malloc(sizeof (uint_t));
	rv = devctl_pm_testbusy(dcp, busyp);
	if (rv != -1)
		(void) printf("%s: busy state %d\n", orig_path, *busyp);

	return (0);
}

static int
bus_pm_teststrict(devctl_hdl_t dcp)
{
	int rv;
	uint_t *strict;

	strict = s_malloc(sizeof (uint_t));

	rv = devctl_pm_bus_teststrict(dcp, strict);
	if (rv != -1)
		(void) printf("%s: strict %d\n", orig_path, *strict);

	return (0);
}

static int
dev_getstate(devctl_hdl_t dcp)
{
	int rv;
	uint_t state;

	rv = devctl_device_getstate(dcp, &state);
	if (rv != -1)
		print_dev_state(orig_path, state);

	return (0);
}

static int
bus_getstate(devctl_hdl_t dcp)
{
	int rv;
	uint_t state;

	rv = devctl_bus_getstate(dcp, &state);
	if (rv != -1)
		print_bus_state(orig_path, state);

	return (0);
}

/*
 * Only string property is supported now.
 * Will add more later.
 */
static void
add_prop(devctl_ddef_t ddef_hdl, char *prop_str)
{
	char *pname, *pval, *tmp;
	char **strs = NULL;
	int nstr;

	tmp = strchr(prop_str, '=');
	if (tmp == NULL) {
		(void) fprintf(stderr, "invalid property %s", prop_str);
		exit(-1);
	}

	(void) printf("prop string: %s\n", prop_str);
	pname = prop_str;
	*tmp++ = '\0';
	if (*tmp != '"') {
		(void) devctl_ddef_string(ddef_hdl, pname, tmp);
		return;
	}

	nstr = 0;
	while (*tmp != '\0') {
		pval = tmp + 1;
		tmp = strchr(pval, '"');
		if (tmp == NULL) {
			(void) fprintf(stderr, "missing quote in %s", tmp);
			exit(-1);
		}
		nstr++;
		strs = (char **)s_realloc(strs, nstr * sizeof (char *));
		strs[nstr - 1] = pval;
		*tmp++ = '\0';
		(void) printf("string[%d] = %s\n", nstr - 1, pval);
		if (*tmp)
			tmp = strchr(tmp, '"');
		if (tmp == NULL) {
			(void) fprintf(stderr, "string not ending with quote");
			exit(-1);
		}
	}

	(void) devctl_ddef_string_array(ddef_hdl, pname, nstr, strs);
	free(strs);
}

static int
bus_devcreate(devctl_hdl_t bus_dcp)
{
	int rv;
	char **propp = dev_props;
	devctl_ddef_t ddef_hdl = NULL;
	devctl_hdl_t dev_hdl = NULL;

	ddef_hdl = devctl_ddef_alloc(dev_name, 0);
	if (dev_props == NULL) {
		(void) fprintf(stderr, "dev-create: missing device props\n");
		return (-1);
	}

	while (*propp) {
		add_prop(ddef_hdl, *propp);
		propp++;
	}

	if (devctl_bus_dev_create(bus_dcp, ddef_hdl, 0, &dev_hdl)) {
		(void) fprintf(stderr,
		    "bus-devcreate: failed to create device node\n");
		rv = -1;
	} else if (devctl_get_pathname(dev_hdl, devctl_device, MAXPATHLEN)
	    == NULL) {
		(void) fprintf(stderr,
		    "bus-devcreate: failed to get device path\n");
		rv = -1;
	} else {
		(void) printf("created device %s\n", devctl_device);
		rv = 0;
	}

	devctl_ddef_free(ddef_hdl);
	if (dev_hdl)
		devctl_release(dev_hdl);

	return (rv);
}

static void
print_bus_state(char *devname, uint_t state)
{
	(void) printf("\t%s: ", devname);
	if (state == BUS_QUIESCED)
		(void) printf("Quiesced");
	else if (state == BUS_ACTIVE)
		(void) printf("Active");
	else if (state == BUS_SHUTDOWN)
		(void) printf("Shutdown");
	(void) printf("\n");
}

static void
print_dev_state(char *devname, uint_t state)
{
	(void) printf("\t%s: ", devname);
	if (state & DEVICE_ONLINE) {
		(void) printf("Online");
		if (state & DEVICE_BUSY)
			(void) printf(" Busy");
		if (state & DEVICE_DOWN)
			(void) printf(" Down");
	} else {
		if (state & DEVICE_OFFLINE) {
			(void) printf("Offline");
			if (state & DEVICE_DOWN)
				(void) printf(" Down");
		}
	}
	(void) printf("\n");
}

static void
setpname(char *name)
{
	register char *p;

	if (p = strrchr(name, '/'))
		progname = p + 1;
	else
		progname = name;
}

static struct cmds *
dc_cmd(struct cmds *cmd_tbl, char *devctl_cmdname)
{
	int i;

	for (i = 0; cmd_tbl[i].cmdname != NULL; i++) {
		if (strcasecmp(cmd_tbl[i].cmdname, devctl_cmdname) == 0)
			return (&cmd_tbl[i]);
	}

	return (NULL);
}

/*
 * list all nexus drivers exporting the :devctl minor device
 */
static void
run_list_ctlrs(void)
{
	di_node_t dinode;

	if ((dinode = di_init("/", DINFOSUBTREE|DINFOMINOR)) == NULL) {
		(void) fprintf(stderr, "%s: di_init() failed\n",
		    progname);
		exit(-1);
	}
	(void) di_walk_minor(dinode, DDI_NT_NEXUS, 0, NULL, &nexif);
	di_fini(dinode);
	exit(0);
}

/*ARGSUSED*/
static int
nexif(di_node_t din, di_minor_t dim, void *arg)
{
	char *devname;

	if ((devname = di_devfs_path(din)) != NULL) {
		(void) printf("%s%d: /devices%s\n", di_driver_name(din),
		    di_instance(din), devname);
		di_devfs_path_free(devname);
	}

	return (DI_WALK_CONTINUE);
}

void *
s_malloc(size_t len)
{
	void *buf = malloc(len);

	if (buf == NULL) {
		perror("s_malloc failed");
		exit(-1);
	}
	return (buf);
}

void *
s_realloc(void *ptr, size_t len)
{
	void *buf = realloc(ptr, len);

	if (buf == NULL) {
		perror("s_realloc failed");
		exit(-1);
	}
	return (buf);
}

char *
s_strdup(char *str)
{
	char *buf = strdup(str);

	if (buf == NULL) {
		perror("s_malloc failed");
		exit(-1);
	}
	return (buf);
}
