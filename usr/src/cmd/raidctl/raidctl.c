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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <langinfo.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ddi.h>
#include <sys/mpt/mpi.h>
#include <sys/mpt/mpi_ioc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/pci.h>
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/dkio.h>
#include <config_admin.h>
#include <sys/param.h>
#include <sys/raidioctl.h>

/*
 * list of controllers to list
 * setup like this:
 * [ctrl_num]	[status]
 *
 * where status is:
 * RAID Found,
 * No RAID Found
 * RAID not supported on this controller
 * Invalid Controller
 */

typedef enum {
	RAID_FOUND = 0x0,
	RAID_NOT_FOUND,
	RAID_NOT_SUPPORTED,
	RAID_INVALID_CTRL,
	RAID_DONT_USE
} raidctl_errno_t;

/* For no-mixup indexing of info_ctrl */
#define	INFO_CTRL	0
#define	INFO_STATUS	1

static int **info_ctrl = NULL;
/* Length of conrollers list */
static int ctrl_nums = 0;


#define	DEVDIR			"/dev/rdsk"

#define	DO_HW_RAID_NOP		-1
#define	DO_HW_RAID_INFO		0
#define	DO_HW_RAID_CREATE	1
#define	DO_HW_RAID_DELETE	2
#define	DO_HW_RAID_FLASH	3

/*
 * Error return codes
 */
#define	SUCCESS			0
#define	INVALID_ARG		1
#define	FAILURE			2

/*
 * FW Update Stuff
 */

/* signature and initial offset for PCI expansion rom images */
#define	PCIROM_SIG	0xaa55	/* offset 0h, length 2 bytes */
#define	PCIR_OFF	0x18	/* Pointer to PCI Data Structure */

/* offsets in PCI data structure header */
#define	PCIR_DEVID	0x6	/* PCI device id */
#define	PCIR_CODETYPE   0x14	/* type of code (intel/fcode) */
#define	PCIR_INDICATOR  0x15	/* "last image" indicator */

/* flags for image types */
#define	BIOS_IMAGE	0x1
#define	FCODE_IMAGE	0x2
#define	UNKNOWN_IMAGE	0x3
#define	LAST_IMAGE	0x80
#define	NOT_LAST_IMAGE	0
#define	PCI_IMAGE_UNIT_SIZE	512

/* ID's and offsets for MPT Firmware images */
#define	FW_ROM_ID			0x5aea	/* bytes 4 & 5 of file */
#define	FW_ROM_OFFSET_CHIP_TYPE		0x22	/* (U16) */
#define	FW_ROM_OFFSET_VERSION		0x24	/* (U16) */
#define	FW_ROM_OFFSET_VERSION_NAME	0x44	/* (32 U8) */

/* Key to search for when looking for fcode version */
#define	FCODE_VERS_KEY1		0x12
#define	FCODE_VERS_KEY2		0x7
#define	BIOS_STR		"LSI1030 SCSI Host Adapter BIOS  Driver: "

/* get a word from a buffer (works with non-word aligned offsets) */
#define	gw(x) (((x)[0]) + (((x)[1]) << 8))

/* Number of disks currently supported */
#define	N_DISKS		2

/*
 * Function and strings to properly localize our prompt.
 * So for example in german it would ask (ja/nein) or (yes/no) in
 * english.
 */
static int	yes(int c);
static char	yeschr[SCHAR_MAX + 2];
static char	nochr[SCHAR_MAX +2];

typedef struct raidlist {
	raid_config_t	raid_config;
	int	controller;
	char	devctl[MAXPATHLEN];
	struct raidlist *next;
} raidlist_t;

static raidlist_t	*raids;

static void
usage(char *prog_name)
{
	(void) fprintf(stderr, gettext("usage: %s\n"), prog_name);

	(void) fprintf(stderr, gettext("usage: %s -c disk1 disk2\n"),
		prog_name);
	(void) fprintf(stderr, gettext("usage: %s -d disk1\n"), prog_name);

	(void) fprintf(stderr,
		gettext("usage: %s [-f] -F image_file controller \n"),
		prog_name);

	(void) fprintf(stderr, gettext("usage: %s -l [controller...]\n"),
		prog_name);

	(void) fprintf(stderr, gettext("example:\n"));
	(void) fprintf(stderr, "%s -c c1t1d0 c1t2d0\n", prog_name);
	(void) fprintf(stderr, "%s -d c1t1d0\n", prog_name);
	(void) fprintf(stderr, "%s -F image 1\n", prog_name);

	exit(1);
}

/* Make errno message more "user friendly" */
static void
raidctl_error(char *str)
{
	switch (errno) {
	case EIO:
	case EFAULT:
		(void) fprintf(stderr,
			gettext("Error: Device inaccessible.\n"));
		break;
	case ENOTTY:
		(void) fprintf(stderr, gettext("Error: "
			"Device does not support requested action.\n"));
		break;
	default:
		perror(str);
	}
}

static int
get_link_path(const char *thing, char *buf)
{
	if (readlink(thing, buf, MAXPATHLEN) < 0)
		return (1);
	return (0);
}

static int
get_ctrl_devctl(char *ctrl, char *b)
{
	char	devctl_buf[MAXPATHLEN];
	char	*colon;

	(void) strlcpy(devctl_buf, ctrl, MAXPATHLEN);

	colon = strrchr(devctl_buf, ':');
	if (colon == NULL)
		return (1);

	*colon = 0;
	(void) snprintf(devctl_buf, MAXPATHLEN, "%s:devctl", devctl_buf);
	(void) strlcpy(b, devctl_buf, MAXPATHLEN);
	return (0);
}

static int
get_devctl(char *disk, char *b)
{
	char	buf1[MAXPATHLEN] = {0};
	char	devctl_buf[MAXPATHLEN];
	char	*slash;
	char	devname[32];

	if (get_link_path(disk, buf1))
		return (1);

	(void) strlcpy(devctl_buf, buf1, MAXPATHLEN);

	slash = strrchr(devctl_buf, '/');
	if (slash == NULL)
		return (1);

	*slash = 0;
	slash = strrchr(devctl_buf, '/');
	(void) strlcpy(devname, slash, 32);
	*slash = 0;

	(void) snprintf(devctl_buf, MAXPATHLEN, "%s%s:devctl",
		devctl_buf, devname);
	(void) strlcpy(b, devctl_buf, MAXPATHLEN);
	return (0);
}

static int
already_there(int controller)
{
	raidlist_t	*curr = raids;

	while (curr != NULL) {
		if (curr->controller == controller)
			return (1);
		curr = curr->next;
	}

	return (0);
}

/*
 * Display those controllers where RAID volumes were not found
 */
static void
print_no_raids()
{
	int i, space = 0;

	if (info_ctrl == NULL)
		return;

	for (i = 0; i < ctrl_nums; i++) {
		/* Status of '0' means RAID exists at that controller */
		if (info_ctrl[i][INFO_STATUS] == RAID_FOUND ||
		    info_ctrl[i][INFO_STATUS] == RAID_DONT_USE)
			continue;

		if (!space && raids != NULL) {
			(void) printf("\n");
			space = 1;
		}

		/* switch statement used to enable gettext()'ing of text */
		switch (info_ctrl[i][INFO_STATUS]) {
		case RAID_INVALID_CTRL:
			(void) printf(gettext("Invalid controller '%d'\n"),
				info_ctrl[i][INFO_CTRL]);
			break;
		case RAID_NOT_SUPPORTED:
			(void) printf(gettext("No RAID supported "
				"on controller '%d'\n"),
					info_ctrl[i][INFO_CTRL]);

			break;
		default:
			(void) printf(gettext("No RAID volumes found on "
				"controller '%d'\n"), info_ctrl[i][INFO_CTRL]);
		}
	}
}

static void
add_raid_to_raidlist(char *ctrl_name, int controller)
{
	raid_config_t	config;
	raidlist_t		*curr;
	char			buf[MAXPATHLEN] = {0};
	char			buf1[MAXPATHLEN] = {0};
	int			fd;
	int			i;

	if (readlink(ctrl_name, buf, sizeof (buf)) < 0)
		return;

	if (get_ctrl_devctl(buf, buf1))
		return;

	/*
	 * If "-l" was specified, then only look at those controllers
	 * listed as part of the command line input.
	 */
	if (info_ctrl != NULL) {
		int found = 0;
		for (i = 0; i < ctrl_nums; i++) {
			if (info_ctrl[i][INFO_STATUS] == RAID_DONT_USE)
				continue;
			if (controller == info_ctrl[i][INFO_CTRL]) {
				found = 1;
				break;
			}
		}
		if (!found)
			return;
	}

	fd = open(buf1, O_RDONLY);
	if (fd == -1) {
		if (info_ctrl != NULL)
			info_ctrl[i][INFO_STATUS] = RAID_INVALID_CTRL;
		return;
	}

	if (ioctl(fd, RAID_GETCONFIG, &config) < 0) {
		if (info_ctrl != NULL)
			info_ctrl[i][INFO_STATUS] = RAID_NOT_SUPPORTED;
		(void) close(fd);
		/* Fail silently */
		return;
	}
	(void) close(fd);

	if (config.ndisks == 0) {
		if (info_ctrl != NULL)
			info_ctrl[i][INFO_STATUS] = RAID_NOT_FOUND;
		return;
	}

	if (info_ctrl != NULL)
		info_ctrl[i][INFO_STATUS] = RAID_FOUND;

	if (raids == NULL) {
		raids = (raidlist_t *)malloc(sizeof (raidlist_t));
		curr = raids;
	} else {
		if (already_there(controller)) {
			return;
		}

		curr = raids;
		/* Seek to the end */
		while (curr->next != NULL)
			curr = curr->next;

		curr->next = (raidlist_t *)malloc(sizeof (raidlist_t));
		curr = curr->next;
	}
	curr->next = NULL;
	curr->controller = controller;

	(void) strlcpy(curr->devctl, buf1, sizeof (curr->devctl));
	(void) fflush(stdout);
	(void) memcpy(&curr->raid_config, &config, sizeof (raid_config_t));
}

static void
print_header()
{
	(void) printf(gettext("RAID\t\tRAID\t\tRAID\t\tDisk"));
	(void) printf("\n");
	(void) printf(gettext("Volume\t\tStatus\t\tDisk\t\tStatus"));
	(void) printf("\n");
	(void) printf("------------------------------------------------------");
	(void) printf("\n");
}

static void
print_raidconfig(int c, raid_config_t config)
{
	int	i;

	/* Get RAID Volume */
	(void) printf("c%dt%dd0\t\t", c, config.targetid);

	/* Get RAID Info */
	if (config.flags & RAID_FLAG_RESYNCING &&
	    config.state == RAID_STATE_DEGRADED) {
		(void) printf(gettext("RESYNCING\t"));
	} else if (config.state == RAID_STATE_DEGRADED) {
		(void) printf(gettext("DEGRADED\t"));
	} else if (config.state == RAID_STATE_OPTIMAL) {
		(void) printf(gettext("OK\t\t"));
	} else if (config.state == RAID_STATE_FAILED) {
		(void) printf(gettext("FAILED\t\t"));
	} else {
		(void) printf(gettext("ERROR\t\t"));
	}

	/* Get RAID Disks */
	(void) printf("c%dt%dd0\t\t", c, config.disk[0]);

	/* Get RAID Disk's Status */
	if (config.diskstatus[0] & RAID_DISKSTATUS_FAILED) {
		(void) printf(gettext("FAILED\n"));
	} else if (config.diskstatus[0] & RAID_DISKSTATUS_MISSING) {
		(void) printf(gettext("MISSING\n"));
	} else {
		(void) printf(gettext("OK\n"));
	}

	for (i = 1; i < config.ndisks; i++) {
		(void) printf("\t\t\t\tc%dt%dd0\t\t", c, config.disk[i]);
		if (config.diskstatus[i] & RAID_DISKSTATUS_FAILED) {
			(void) printf(gettext("FAILED\n"));
		} else if (config.diskstatus[i] & RAID_DISKSTATUS_MISSING) {
			(void) printf(gettext("MISSING\n"));
		} else {
			(void) printf(gettext("OK\n"));
		}
	}
}

static void
print_disklist()
{
	raidlist_t	*curr = raids;
	while (curr != NULL) {
		print_raidconfig(curr->controller, curr->raid_config);
		curr = curr->next;
	}
}

static void
free_disklist()
{
	raidlist_t	*curr = raids;

	while (curr != NULL) {
		raidlist_t	*temp;
		temp = curr;
		curr = curr->next;
		free(temp);
	}
}

static void
do_search()
{
	DIR		*dir;
	struct dirent	*dp;
	char		buf[MAXPATHLEN];
	int		c;
	int		i, j;

	/*
	 * In case repeated numbers were found, assign the repititions as
	 * RAID_DONT_USE
	 */
	for (i = 0; i < ctrl_nums; i++) {
		int first_one = 1;
		for (j = 0; j < ctrl_nums; j++) {
			if (info_ctrl[i][INFO_CTRL] ==
				info_ctrl[j][INFO_CTRL]) {
				if (info_ctrl[j][INFO_STATUS] == RAID_DONT_USE)
					continue;
				if (first_one) {
					first_one = 0;
				} else {
					info_ctrl[j][INFO_STATUS] =
						RAID_DONT_USE;
				}
			}
		}
	}

	if ((dir = opendir("/dev/cfg")) == NULL) {
		(void) fprintf(stderr,
			gettext("Cannot open /dev/cfg: %s\n"), strerror(errno));
		return;
	}
	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;
		if (sscanf(dp->d_name, "c%d", &c) != 1)
			continue;
		(void) snprintf(buf, sizeof (buf), "/dev/cfg/%s", dp->d_name);
		add_raid_to_raidlist(buf, c);
	}
	(void) closedir(dir);
}

/*
 * do_info() will do the following:
 * - create a list of disks' devctls
 * - try to talk to each of the devctls found
 * - if raid configuration is found, display it.
 */
static void
do_info()
{
	int i;
	(void) chdir(DEVDIR);

	do_search();

	if (raids == NULL) {
		if (info_ctrl != NULL) {
			print_no_raids();
			for (i = 0; i < ctrl_nums; i++)
				free(info_ctrl[i]);
			free(info_ctrl);
		} else {
			(void) printf(gettext("No RAID volumes found\n"));
		}
		return;
	}

	print_header();
	print_disklist();
	print_no_raids();
	free_disklist();
	if (info_ctrl) {
		for (i = 0; i < ctrl_nums; i++)
			free(info_ctrl[i]);
		free(info_ctrl);
	}
}

static int
disk_there(int c, int t)
{
	char	disk[100];
	int	fd;

	(void) snprintf(disk, sizeof (disk), "c%dt%dd0s2", c, t);

	fd = open(disk, O_RDWR | O_NDELAY);
	if (fd == -1) {
		return (-1);
	}

	(void) close(fd);
	return (0);
}

static int
get_controller(char *dev)
{
	raidlist_t	*curr;
	int		c;
	do_search();
	curr = raids;
	while (curr != NULL) {
		if (strcmp(curr->devctl, dev) == 0) {
			c = curr->controller;
			break;
		}
		curr = curr->next;
	}

	free_disklist();
	return (c);
}

static int
disk_mounted(char *d)
{
	struct mnttab	mt;
	FILE		*f = fopen("/etc/mnttab", "r");

	while (getmntent(f, &mt) != EOF)
		if (strstr(mt.mnt_special, d) != NULL)
			return (1);
	return (0);
}

static int
disk_big_enough(char **d, diskaddr_t *cap, int *errcond)
{
	struct dk_minfo minfo;
	char		disk[N_DISKS][MAXPATHLEN];
	diskaddr_t	disk_lbsize[N_DISKS];
	diskaddr_t	disk_capacity[N_DISKS];
	int		i, fd;

	for (i = 0; i < N_DISKS; i++) {
		(void) snprintf(disk[i], sizeof (disk[i]), DEVDIR"/%ss2", d[i]);
		fd = open(disk[i],  O_RDWR | O_NDELAY);
		if (fd == -1) {
			return (FAILURE);
		}

		if (ioctl(fd, DKIOCGMEDIAINFO, &minfo) == -1) {
			(void) close(fd);
			return (FAILURE);
		}

		disk_lbsize[i] = minfo.dki_lbsize;
		disk_capacity[i] = minfo.dki_capacity;
		(void) close(fd);
	}

	/* lbsize must be the same on both disks */
	if (disk_lbsize[0] != disk_lbsize[1]) {
		*errcond = 2;
		return (INVALID_ARG);
	}

	/* secondary size is not greater than or equal to primary size */
	if (disk_capacity[0] > disk_capacity[1]) {
		*errcond = 1;
		return (INVALID_ARG);
	}

	/* Secondary disk is big enough */
	*cap = disk_capacity[0];
	return (SUCCESS);
}

static int
do_config_change_state(cfga_cmd_t cmd, int d, int c)
{
	cfga_err_t	cfga_err;
	char		*ap_id;
	int		rv = SUCCESS;
	int		count = 0;

	ap_id = (char *)malloc(100);
	if (ap_id == NULL)
		return (FAILURE);

	(void) snprintf(ap_id, 100, "c%d::dsk/c%dt%dd0", c, c, d);

	/*
	 * If the config_change_state() funcation fails, we want to
	 * retry.  If the retry fails, then we return failure to fail.
	 *
	 * If we fail:
	 *
	 *	If we were called from create, then we fail the raid
	 *	creation.
	 *
	 *	If we were called from delete, then the disk will not
	 *	be re-configured by raidctl.
	 */
	do {
		cfga_err = config_change_state(cmd, 1, &ap_id, NULL,
			NULL, NULL, NULL, 0);
		count++;
	} while (cfga_err != CFGA_OK && count < 2);

	if (cfga_err != CFGA_OK)
		rv = FAILURE;

	free(ap_id);
	return (rv);
}

static int
do_create(char **d)
{
	raid_config_t	config;
	char		disk[N_DISKS][MAXPATHLEN] = {0};
	char		channel1[MAXPATHLEN];
	char		channel2[MAXPATHLEN];
	diskaddr_t	capacity;
	int		fd, fd2, size, errcond, disk_here = 1;
	int		c[N_DISKS];
	int		t[N_DISKS];
	char		*tmp;
	int		i;

	(void) chdir(DEVDIR);

	for (i = 0; i < N_DISKS; i++) {
		if ((sscanf(d[i], "c%dt%dd0", &c[i], &t[i])) != 2 ||
		    t[i] < 0) {
			(void) fprintf(stderr,
				gettext("Invalid disk format.\n"));
			return (INVALID_ARG);
		}
		(void) snprintf(disk[i], sizeof (disk[i]), DEVDIR"/%ss2", d[i]);
	}

	/* Must be on same controller */
	if (c[0] != c[1]) {
		(void) fprintf(stderr,
			gettext("Disks must be on the same controller.\n"));
		return (INVALID_ARG);
	}

	/* primary disk target must be lower than secondary disk target */
	if (t[0] > t[1]) {
		(void) fprintf(stderr, gettext("Primary target ID "
				"must be less than secondary target ID.\n"));
		return (INVALID_ARG);
	}

	/* disks must not be the same */
	if (t[0] == t[1]) {
		(void) fprintf(stderr, gettext("Disks must be different.\n"));
		return (INVALID_ARG);
	}

	/* disks must be present */
	if (disk_there(c[0], t[0])) {
		(void) printf(gettext("Disk 'c%dt%dd0' is not present.\n"),
			c[0], t[0]);
		disk_here = 0;
	}
	if (disk_there(c[1], t[1])) {
		(void) printf(gettext("Disk 'c%dt%dd0' is not present.\n"),
			c[0], t[1]);
		disk_here = 0;
	}

	if (!disk_here) {
		(void) printf(gettext("Cannot create RAID volume.\n"));
		return (INVALID_ARG);
	}

	/* secondary disk's size must be greater or equal to primary disk's */
	switch (disk_big_enough(d, &capacity, &errcond)) {
	case FAILURE:
		return (FAILURE);
	case INVALID_ARG:
		switch (errcond) {
		case 1:
		(void) fprintf(stderr, gettext("Cannot create RAID volume when "
			"primary disk is larger than secondary disk.\n"));
		break;
		case 2:
		(void) fprintf(stderr, gettext("Cannot create RAID volume when "
			"disk block sizes differ.\n"));
		}
		return (INVALID_ARG);
	}

	/* secondary disk must not be mounted */
	if (disk_mounted(d[1])) {
		(void) fprintf(stderr, gettext("Cannot create RAID volume when "
				"secondary disk \"%s\" is mounted.\n"), d[1]);
		return (INVALID_ARG);
	}

	/* Only one RAID can exist per controller */
	if (get_devctl(disk[0], channel1))
		return (FAILURE);

	fd = open(channel1, O_RDONLY);
	if (fd == -1) {
		perror(channel1);
		return (FAILURE);
	}

	if (ioctl(fd, RAID_GETCONFIG, &config) < 0) {
		raidctl_error("RAID_GETCONFIG");
		goto fail1;
	}

	if (config.ndisks != 0) {
		(void) printf(gettext("RAID Volume already exists on this "
			"controller 'c%dt%dd0'\n"), c[0], config.targetid);
		goto fail1;
	}

	/*
	 * Make sure there isn't a raid created on this controller's
	 * other channel
	 */
	(void) strlcpy(channel2, channel1, sizeof (channel2));
	tmp = strrchr(channel2, ':');
	tmp[0] = 0;
	size = strlen(channel2);

	/*
	 * Format the channel string for the other channel so we can
	 * see if a raid exists on it.  In this case if we are being asked
	 * to create a raid on channel 2 (indicated by the 1,1 at the end
	 * of the string) we want to check channel 1) otherwise we will
	 * check channel 2.
	 */
	if (channel2[size - 2] == ',') {
		channel2[size - 1] = 0;
		channel2[size - 2] = 0;
		(void) snprintf(channel2, sizeof (channel2), "%s:devctl",
			channel2);
	} else {
		(void) snprintf(channel2, sizeof (channel2), "%s,1:devctl",
			channel2);
	}

	fd2 = open(channel2, O_RDONLY);
	if (fd2 == -1) {
		if (errno == ENOENT)
			goto no_secondary_channel;
		perror(channel2);
		goto fail1;
	}

	if (ioctl(fd2, RAID_GETCONFIG, &config) < 0) {
		goto fail2;
	}

	if (config.ndisks != 0) {
		int	cx;
		cx = get_controller(channel2);
		(void) printf(gettext("RAID Volume already exists on this "
			"controller 'c%dt%dd0'\n"), cx, config.targetid);
		goto fail2;
	}

no_secondary_channel:

	/* No other RAID volumes exist, so we may continue */
	config.raid_capacity = capacity;
	config.raid_level = 1;	/* RAID 1: Mirror */
	config.targetid = t[0];	/* Assume identity of first disk */
	config.disk[0] = t[0];	/* Primary Disk */
	config.disk[1] = t[1];	/* Secondary Disk */

	/* Make secondary disk inaccessible to the system */
	if (do_config_change_state(CFGA_CMD_UNCONFIGURE,
		config.disk[1], c[0])) {
		perror("config_change_state");
		goto fail2;
	}

	if (ioctl(fd, RAID_CREATE, &config)) {
		(void) do_config_change_state(CFGA_CMD_CONFIGURE,
			config.disk[1], c[0]);
		raidctl_error("RAID_CREATE");
		goto fail2;
	}

	(void) printf(gettext("Volume 'c%dt%dd0' created\n"), c[0], t[0]);
	(void) close(fd);
	(void) close(fd2);
	return (SUCCESS);

fail2:
	(void) close(fd2);
fail1:
	(void) close(fd);
	return (FAILURE);
}

static int
do_delete(char *d)
{
	raid_config_t	config;
	char		disk1[MAXPATHLEN];
	char		buf[MAXPATHLEN];
	int		fd;
	int		target;
	int		ctrl;
	uint8_t		t;

	(void) chdir(DEVDIR);

	if ((sscanf(d, "c%dt%dd0", &ctrl, &target)) != 2) {
		(void) fprintf(stderr, gettext("Invalid disk format.\n"));
		return (INVALID_ARG);
	}
	t = (uint8_t)target;

	(void) snprintf(disk1, sizeof (disk1), DEVDIR"/%ss2", d);

	if (get_devctl(disk1, buf) != 0) {
		return (FAILURE);
	}

	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		perror(buf);
		return (FAILURE);
	}

	if (ioctl(fd, RAID_GETCONFIG, &config)) {
		raidctl_error("RAID_GETCONFIG");
		goto fail;
	}

	if (config.ndisks == 0) {
		(void) fprintf(stderr, gettext("No RAID Volume exists on "
			"controller '%d'\n"), ctrl);
		goto fail;
	}

	if (config.targetid != t) {
		(void) fprintf(stderr,
			gettext("RAID volume 'c%dt%dd0' does not exist\n"),
			ctrl, t);
		goto fail;
	}

	if (ioctl(fd, RAID_DELETE, &t)) {
		perror("RAID_DELETE");
		goto fail;
	}

	/*
	 * Make secondary disk accessible to the system.
	 * Ignore return value from do_config_change_state.
	 */
	(void) do_config_change_state(CFGA_CMD_CONFIGURE, config.disk[1], ctrl);

	(void) fprintf(stderr, gettext("Volume 'c%dt%dd0' deleted.\n"),
		ctrl, target);
	(void) close(fd);
	return (SUCCESS);

fail:
	(void) close(fd);
	return (FAILURE);
}

static int
getfcodever(uint8_t *rombuf, uint32_t nbytes, char **fcodeversion)
{
	int x, y, size;
	int found_1 = 0, found_2 = 0;
	int image_length = 0;
	int no_of_images = 0;
	uint8_t *rombuf_1 = NULL;
	uint16_t image_units = 0;

	/*
	 * Single Image - Open firmware image
	 */
	if (rombuf[gw(&rombuf[PCIR_OFF]) + PCIR_CODETYPE] == 1) {
		rombuf_1 = rombuf + gw(rombuf + PCIR_OFF) + PCI_PDS_INDICATOR;
		no_of_images = 1;
		goto process_image;
	}

	/*
	 * Combined Image - First Image - x86/PC-AT Bios image
	 */
	if (rombuf[gw(&rombuf[PCIR_OFF]) + PCIR_CODETYPE] != 0) {
		(void) fprintf(stderr, gettext("This is neither open image"
			    " nor Bios/Fcode combined image\n"));
		return (1);
	}

	/*
	 * Seek to 2nd Image
	 */
	rombuf_1 = rombuf + gw(rombuf + PCI_ROM_PCI_DATA_STRUCT_PTR);
	image_units = gw(rombuf_1 + PCI_PDS_IMAGE_LENGTH);
	image_length = image_units * PCI_IMAGE_UNIT_SIZE;
	rombuf_1 += image_length;

	/*
	 * Combined Image - Second Image - Open Firmware image
	 */
	if (rombuf_1[PCI_PDS_CODE_TYPE] != 1) {
		(void) fprintf(stderr, gettext("This is neither open image"
			    " nor Bios/Fcode combined image\n"));
		return (1);
	}
	rombuf_1 += PCI_PDS_INDICATOR;
	no_of_images = 2;

process_image:
	/*
	 * This should be the last image
	 */
	if (*rombuf_1 != LAST_IMAGE) {
		(void) fprintf(stderr, gettext("This is not a valid "
		    "Bios/Fcode image file\n"));
		return (1);
	}

	/*
	 * Scan through the bois/fcode file to get the fcode version
	 * 0x12 and 0x7 indicate the start of the fcode version string
	 */
	for (x = 0; x < (nbytes - 8); x++) {
		if ((rombuf[x] == FCODE_VERS_KEY1) &&
		    (rombuf[x+1] == FCODE_VERS_KEY2) &&
		    (rombuf[x+2] == 'v') && (rombuf[x+3] == 'e') &&
		    (rombuf[x+4] == 'r') && (rombuf[x+5] == 's') &&
		    (rombuf[x+6] == 'i') && (rombuf[x+7] == 'o') &&
		    (rombuf[x+8] == 'n')) {
			found_1 = 1;
			break;
		}
	}

	/*
	 * Store the version string if we have found the beginning of it
	 */
	if (found_1) {
		while (x > 0) {
			if (rombuf[--x] == FCODE_VERS_KEY1) {
				if (rombuf[x-1] != FCODE_VERS_KEY1) {
					x++;
				}
				break;
			}
		}
		if (x > 0) {
			*fcodeversion = (char *)malloc(rombuf[x] + 1);
			for (y = 0; y < rombuf[x]; y++) {
				(*fcodeversion)[y] = rombuf[x+y+1];
			}
			(*fcodeversion)[y] = '\0';
		} else {
			found_1 = 0;
		}
	}

	/*
	 * Scan through the bois/fcode file to get the Bios version
	 * "@(#)" string indicates the start of the Bios version string
	 * Append this version string, after already existing fcode version.
	 */
	if (no_of_images == 2) {
		for (x = 0; x < (nbytes - 4); x++) {
			if ((rombuf[x] == '@') && (rombuf[x+1] == '(') &&
			    (rombuf[x+2] == '#') && (rombuf[x+3] == ')')) {
				found_2 = 1;
				break;
			}
		}

		if (found_2) {
			x += 4;
			(*fcodeversion)[y] = '\n';
			size = y + strlen((char *)(rombuf + x)) +
			    strlen(BIOS_STR) + 2;
			*fcodeversion = (char *)realloc((*fcodeversion), size);
			y++;
			(*fcodeversion)[y] = '\0';
			(void) strlcat(*fcodeversion, BIOS_STR, size);
			(void) strlcat(*fcodeversion, (char *)(rombuf + x),
			    size);
		}
	}

	return ((found_1 || found_2) ? 0 : 1);
}

static void
getfwver(uint8_t *rombuf, char *fwversion)
{
	(void) snprintf(fwversion, 8, "%d.%.2d.%.2d.%.2d",
		rombuf[FW_ROM_OFFSET_VERSION + 3],
		rombuf[FW_ROM_OFFSET_VERSION + 2],
		rombuf[FW_ROM_OFFSET_VERSION + 1],
		rombuf[FW_ROM_OFFSET_VERSION + 0]);
}

static int
checkfile(uint8_t *rombuf, uint32_t nbytes, uint32_t chksum, int *imagetype)
{
	char *imageversion = NULL;
	char *fwversion;

	fwversion = (char *)malloc(8);

	if (gw(&rombuf[0]) == PCIROM_SIG) {
		/* imageversion is malloc(2)'ed in getfcodever() */
		if (getfcodever(rombuf, nbytes, &imageversion) == 0) {
			*imagetype = FCODE_IMAGE;
		} else {
			*imagetype = UNKNOWN_IMAGE;
		}
		if (*imagetype != UNKNOWN_IMAGE) {
			(void) printf(gettext("Image file contains:\n%s\n"),
			    imageversion);
			free(imageversion);
		} else {
			if (imageversion != NULL) {
				free(imageversion);
			}
			return (-1);
		}
	} else if (gw(&rombuf[3]) == FW_ROM_ID) {
			if (chksum != 0) {
				(void) fprintf(stderr,
					gettext("The ROM checksum appears bad "
					"(%d)\n"), chksum);
				return (-1);
			}
			getfwver(rombuf, fwversion);

			if ((gw(&rombuf[FW_ROM_OFFSET_CHIP_TYPE]) &
				MPI_FW_HEADER_PID_PROD_MASK) ==
				MPI_FW_HEADER_PID_PROD_IM_SCSI) {
				(void) printf(gettext("ROM image contains "
					"MPT firmware version %s "
					"(w/Integrated Mirroring)\n"),
						fwversion);
			} else {
				(void) printf(gettext("ROM image contains "
					"MPT firmware ""version %s\n"),
						fwversion);
			}
			free(fwversion);
	} else {

#ifdef	DEBUG
	(void) fprintf(stderr, "Not valid FCODE image %x\n", gw(&rombuf[0]));
#else
	(void) fprintf(stderr, gettext("Not valid FCODE image\n"));
#endif
		return (-1);
	}
	return (0);
}

static int
updateflash(uint8_t *rombuf, uint32_t nbytes, char *devctl)
{
	int fd = 0;
	update_flash_t flashdata;

	fd = open(devctl, O_RDONLY);
	if (fd == -1) {
		perror(devctl);
		return (-1);
	}
	(void) memset(&flashdata, 0, sizeof (flashdata));
	flashdata.ptrbuffer = (caddr_t)rombuf;
	flashdata.size = nbytes;
	if ((rombuf[0] == 0x55) && (rombuf[1] == 0xaa)) {
		flashdata.type = FW_TYPE_FCODE;
	} else {
		flashdata.type = FW_TYPE_UCODE;
	}

	if (ioctl(fd, RAID_UPDATEFW, &flashdata)) {
		raidctl_error("RAID_UPDATEFW");
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);
	return (0);
}

static int
readfile(char *filespec, uint8_t **rombuf, uint32_t *nbytes, uint32_t *chksum)
{
	struct stat	statbuf;
	uint32_t	count;
	uint32_t	checksum = 0;
	int		fd, i;
	uint8_t		*filebuf;


	if ((fd = open((const char *)filespec, O_RDONLY | O_NDELAY)) == -1) {
		perror(filespec);
		return (-1);
	}

	if (fstat(fd, &statbuf) != 0) {
		perror("fstat");
		(void) fprintf(stderr,
			gettext("Error getting stats on file\n"));
		(void) close(fd);
		return (-1);
	}

#ifdef	DEBUG
	(void) printf("Filesize = %ld\n", statbuf.st_size);
#endif

	filebuf = (uint8_t *)realloc(*rombuf, statbuf.st_size + *nbytes);

	count = read(fd, filebuf + *nbytes, statbuf.st_size);
	(void) close(fd);
	if (count != statbuf.st_size) {
		perror("size check");
		(void) fprintf(stderr, gettext("File is corrupt\n"));
		return (-1);
	}

	for (i = 0; i < *nbytes; i++)
		checksum += filebuf[i] << (8 * (i & 3));

	*rombuf = filebuf;
	*nbytes = *nbytes + count;
	*chksum = checksum;

	return (0);
}

static int
yes(int c)
{
	int	i, b;
	char    ans[SCHAR_MAX + 1];

	for (i = 0; ; i++) {
		b = getchar();
		if (b == '\n' || b == '\0' || b == EOF) {
			ans[i] = 0;
			break;
		}
		if (i < SCHAR_MAX)
			ans[i] = b;
	}
	if (i >= SCHAR_MAX) {
		i = SCHAR_MAX;
		ans[SCHAR_MAX] = 0;
	}
	if ((i != 0) && ((strncmp(yeschr, ans, i)) == 0)) {
		return (1);
	} else {
		(void) fprintf(stderr, gettext("User response is \"%s\", "
		    "Controller %d not flashed.\n\n"), ans, c);
		return (0);
	}
}

static int
do_flash(int c, char *fpath, int force)
{
	char		devctl[MAXPATHLEN] = {0};
	char		buf[MAXPATHLEN] = {0};
	int		rv = 0;
	int		imagetype;
	uint32_t	nbytes = 0;
	uint32_t	chksum;
	uint8_t		*rombuf = NULL;
	char		cwd[MAXPATHLEN];

	/*
	 * Read fw file
	 */
	rv = readfile(fpath, &rombuf, &nbytes, &chksum);
	if (rv != 0) {
		return (FAILURE);
	}

	(void) getcwd(cwd, sizeof (cwd));

	(void) chdir(DEVDIR);

	/* Get link from "/dev/cfg" */
	(void) snprintf(buf, sizeof (buf), "/dev/cfg/c%d", c);
	if (get_link_path(buf, devctl) != 0) {
		(void) fprintf(stderr,
			gettext("Invalid controller '%d'\n"), c);
		return (INVALID_ARG);
	}

	/* Check File */
	rv = checkfile(rombuf, nbytes, chksum, &imagetype);
	if (rv != 0) {
		return (FAILURE);
	}

	/* Confirm */
	if (!force) {
		(void) fprintf(stderr, gettext("Update flash image on "
			"controller %d (%s/%s)? "), c, yeschr, nochr);
		if (!yes(c)) {
			return (SUCCESS);
		}
	}

	/* Do Flash */
	if (updateflash(rombuf, nbytes, devctl)) {
		(void) fprintf(stderr, gettext("Flash not updated on "
		    "Controller %d.\n\n"), c);
		return (INVALID_ARG);
	}
	(void) printf(gettext("Flash updated successfully.\n\n"));
	return (SUCCESS);
}

static int
fully_numeric(char *str)
{
	int	size = strlen(str);
	int	i;

	for (i = 0; i < size; i++) {
		if (i == 0 && str[i] == '-' && size != 1)
			continue;
		if (!isdigit(str[i]))
			return (0);
	}
	return (1);
}

/*
 * Useful parsing macros
 */
#define	must_be(s, c)		if (*s++ != c) return (0)
#define	skip_digits(s)		while (isdigit(*s)) s++

/*
 * Return true if a name is in the internal canonical form
 */
static int
canonical_name(char *name)
{
	must_be(name, 'c');
	skip_digits(name);
	if (*name == 't') {
		name++;
		skip_digits(name);
	}
	must_be(name, 'd');
	skip_digits(name);
	return (*name == 0);
}

int
main(int argc, char **argv)
{
	int	rv = SUCCESS;
	int	i, c;
	int	findex = DO_HW_RAID_INFO;
	int	controller;
	char	*disks[N_DISKS];
	char	*darg;
	char	*farg;
	char	*progname;

	int	l_flag = 0;
	int	c_flag = 0;
	int	d_flag = 0;
	int	f_flag = 0;
	int	F_flag = 0;
	int	no_flags = 1;
	char	*current_dir;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (geteuid() != 0) {
		(void) fprintf(stderr, gettext("Must be root.\n"));
		exit(1);
	}

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	raids = NULL;

	(void) strncpy(yeschr, nl_langinfo(YESSTR), SCHAR_MAX + 1);
	(void) strncpy(nochr, nl_langinfo(NOSTR), SCHAR_MAX + 1);

	while ((c = getopt(argc, argv, "clfd:F:")) != EOF) {
		switch (c) {
		case 'c':
			if (f_flag || argc != 4) {
				usage(progname);
			}

			findex = DO_HW_RAID_CREATE;
			c_flag = 1;
			no_flags = 0;
			break;
		case 'd':
			darg = optarg;
			d_flag = 1;
			findex = DO_HW_RAID_DELETE;
			no_flags = 0;
			break;
		case 'l':
			findex = DO_HW_RAID_INFO;
			l_flag = 1;
			no_flags = 0;
			break;
		case 'F':
			findex = DO_HW_RAID_FLASH;
			farg = optarg;
			F_flag = 1;
			no_flags = 0;
			break;
		case 'f':
			f_flag = 1;
			no_flags = 0;
			break;
		case '?': default:
			usage(progname);
		}
	}

	if (no_flags && argc > 1)
		usage(progname);

	/* compatibility rules */
	if (c_flag && d_flag)
		usage(progname);
	if (l_flag && (d_flag || c_flag || f_flag || F_flag))
		usage(progname);
	if (F_flag && (d_flag || c_flag || l_flag))
		usage(progname);

	switch (findex) {
	case DO_HW_RAID_INFO:
		if (l_flag) {
			/*
			 * "raidctl"	makes argc == 1
			 * "-l"		makes argc == 2
			 */
			ctrl_nums = argc - 2;
			if (ctrl_nums != 0) {
				info_ctrl = (int **)
					malloc(ctrl_nums * sizeof (int));
				if (info_ctrl == NULL)
					return (FAILURE);
			}
			for (i = 0; i < ctrl_nums; i++) {
				char *tmp = argv[i + 2];

				info_ctrl[i] = (int *)malloc(2 * sizeof (int));
				if (info_ctrl[i] == NULL) {
					free(info_ctrl);
					return (FAILURE);
				}
				if (fully_numeric(tmp)) {
					(void) sscanf(tmp, "%d",
						&info_ctrl[i][INFO_CTRL]);
					info_ctrl[i][INFO_STATUS] =
						RAID_INVALID_CTRL;
				} else {
				(void) fprintf(stderr,
					gettext("Invalid controller '%s'\n"),
					tmp);
					info_ctrl[i][INFO_STATUS] =
						RAID_DONT_USE;
				}
			}
		} else if (argc > 1) {
			usage(progname);
		}

		do_info();
		break;
	case DO_HW_RAID_CREATE:
		for (i = 0; i < N_DISKS; i++) {
			disks[i] = argv[argc - 2 + i];
			if (!canonical_name(disks[i]))
				usage(progname);
		}
		rv = do_create(disks);
		break;
	case DO_HW_RAID_DELETE:
		if (!canonical_name(darg))
			usage(progname);

		rv = do_delete(darg);
		break;
	case DO_HW_RAID_FLASH:
		/*
		 * "raidctl"	makes argc == 1
		 * "-F"		makes argc == 2
		 * "filename"	makes argc == 3
		 * "-f"		makes argc == 4 if added.
		 */
		ctrl_nums = argc - f_flag - 3;
		if (ctrl_nums == 0)
			usage(progname);

		current_dir = getcwd(NULL, MAXPATHLEN);

		for (i = 0; i < ctrl_nums; i++) {
			char *tmp = argv[i + 3 + f_flag];
			(void) chdir(current_dir);
			if (fully_numeric(tmp)) {
				(void) sscanf(tmp, "%d", &controller);
				rv = do_flash(controller, farg, f_flag);
				if (rv == FAILURE)
					break;
			} else {
				(void) fprintf(stderr,
					gettext("Invalid controller '%s'\n"),
					tmp);
			}
		}
		free(current_dir);
		break;
	default:
		usage(progname);
	}
	return (rv);
}
