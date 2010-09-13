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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<unistd.h>
#include	<devmgmt.h>
#include	<devtab.h>
#include	<dirent.h>
#include	<libgen.h>
#include	<sys/stat.h>
#include	<sys/vtoc.h>
#include	<sys/vfstab.h>

/*
 * Update device.tab and dgroup.tab to reflect current configuration.
 * Designed so it can be run either once at installation time or after
 * every reboot.  The alias naming scheme used is non-intuitive but
 * is consistent with existing conventions and documentation and with
 * the device numbering scheme used by the disks command.
 * Code borrowed liberally from prtconf, disks and prtvtoc commands.
 */

/*
 * make this long enough to start out with.
 * there are place we write into putdevcmd
 * where we are not testing for overrun.
 */
#define	ORIGLEN	1024

struct dpart {
	char		alias[20];
	char		*cdevice;
	char		*bdevice;
	diskaddr_t	capacity;
};

static int		vfsnum;
static char		*putdevcmd;
static char		cmd[80];
static int		lastlen = ORIGLEN;
#ifdef att3b2
static struct mainedt	*edtp;
#endif
static struct vfstab	*vfstab;

static void checkandresize(int);

static char *
memstr(const char *str)
{
	char	*mem;

	if ((mem = (char *)malloc((uint_t)strlen(str) + 1)) == NULL) {
		(void) fprintf(stderr,
		    "%s: can't update device tables:Out of memory\n", cmd);
		exit(1);
	}
	return (strcpy(mem, str));
}



/*
 * Add device table entry for the floppy drive.
 */
static void
fdisk(const int diskno, const char *disknm)
{
	if (snprintf(putdevcmd, lastlen, "/usr/bin/putdev -a diskette%d "
	    "cdevice=/dev/r%s bdevice=/dev/%s desc=\"Floppy Drive\" "
	    "mountpt=/mnt volume=diskette "
	    "type=diskette removable=true capacity=2880 "
	    "fmtcmd=\"/usr/bin/fdformat -f -v /dev/r%s\" "
	    "erasecmd=\"/usr/sbin/fdformat -f -v /dev/r%s\" "
	    "removecmd=\"/usr/bin/eject\" copy=true "
	    "mkfscmd=\"/usr/sbin/mkfs -F ufs /dev/r%s 2880 18 "
	    "2 4096 512 80 2 5 3072 t\"",
	    diskno, disknm, disknm, disknm, disknm, disknm) >= lastlen) {
		(void) fprintf(stderr,
		    "%s: Command too long: %s\n", cmd, putdevcmd);
		exit(1);
	}
	(void) system(putdevcmd);
}

static void
do_fdisks(void)
{
	DIR *dp;
	struct dirent *dirp;
	int drive = 1;

	if ((dp = opendir("/dev")) == NULL) {
		(void) fprintf(stderr, "%s: can't open /dev\n", cmd);
		return;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (gmatch(dirp->d_name, "diskette*")) {
			fdisk(drive++, dirp->d_name);
		}
	}

	(void) closedir(dp);
}

/*
 * hdisk() gets information about the specified hard drive from the vtoc
 * and vfstab and adds the disk and partition entries to device.tab. If
 * we can't access the raw disk we simply assume it isn't properly configured
 * and we add no entries to device.tab.
 */
static void
hdisk(const int drive, const char *drivepfx)
{
	char		*cdskpath;
	char		*bdskpath;
	char		*mountpoint;
	int		i, j, dpartcnt, fd;
	struct extvtoc	vtoc;
	static struct dpart    *dparttab;

	if ((cdskpath = (char *)malloc(strlen(drivepfx) + 13)) == NULL) {
		(void) fprintf(stderr, "%s: Memory request failed\n", cmd);
		exit(1);
	}

	(void) snprintf(cdskpath, strlen(drivepfx) + 13, "/dev/rdsk/%ss2",
	    drivepfx);
	if ((fd = open(cdskpath, O_RDONLY)) == -1) {
		free(cdskpath);
		return;
	}


	/*
	 * Read volume table of contents.
	 */
	if (read_extvtoc(fd, &vtoc) < 0) {
		(void) close(fd);
		free(cdskpath);
		return;
	}

	(void) close(fd);

	/*
	 * Begin building the putdev command string that will be
	 * used to make the entry for this disk.
	 */

	if ((bdskpath = (char *)malloc(strlen(drivepfx) + 13)) == NULL) {
		(void) fprintf(stderr, "%s: Memory request failed\n", cmd);
		exit(1);
	}

	(void) snprintf(bdskpath, strlen(drivepfx) + 13, "/dev/dsk/%ss2",
	    drivepfx);
	if (snprintf(putdevcmd, lastlen, "/usr/bin/putdev -a disk%d "
	    "cdevice=%s bdevice=%s "
	    "desc=\"Disk Drive\" type=disk "
	    "part=true removable=false capacity=%llu dpartlist=",
	    drive, cdskpath, bdskpath, vtoc.v_part[2].p_size) >= lastlen) {
		(void) fprintf(stderr,
		    "%s: Command too long: %s\n", cmd, putdevcmd);
		exit(1);
	}

	free(cdskpath);
	free(bdskpath);

	/*
	 * Build a table of disk partitions we are interested in and finish
	 * the putdev command string for the disk by adding the dpartlist.
	 */

	if ((dparttab =
	    (struct dpart *)malloc((int)vtoc.v_nparts *
	    sizeof (struct dpart))) == NULL) {
		(void) fprintf(stderr,
		    "%s: can't disk partitions table: Out of memory\n", cmd);
		exit(1);
	}

	dpartcnt = 0;
	for (i = 0; i < (int)vtoc.v_nparts; ++i) {
		if (vtoc.v_part[i].p_size == 0 || vtoc.v_part[i].p_flag != 0)
			continue;
		(void) sprintf(dparttab[dpartcnt].alias, "dpart%d%02d", drive,
		    i);

		if ((dparttab[dpartcnt].cdevice =
		    (char *)malloc(strlen(drivepfx) + 14)) == NULL) {
			(void) fprintf(stderr, "%s: Out of memory\n", cmd);
			exit(1);
		}

		(void) snprintf(dparttab[dpartcnt].cdevice,
		    strlen(drivepfx) + 14, "/dev/rdsk/%ss%x", drivepfx, i);
		if ((dparttab[dpartcnt].bdevice =
		    (char *)malloc(strlen(drivepfx) + 14)) == NULL) {
			(void) fprintf(stderr, "%s: Out of memory\n", cmd);
			exit(1);
		}
		(void) snprintf(dparttab[dpartcnt].bdevice,
		    strlen(drivepfx) + 14, "/dev/dsk/%ss%x", drivepfx, i);
		dparttab[dpartcnt].capacity = vtoc.v_part[i].p_size;

		if (dpartcnt != 0)
			(void) strcat(putdevcmd, ",");
		(void) strcat(putdevcmd, dparttab[dpartcnt].alias);
		dpartcnt++;
	}

	(void) system(putdevcmd);

	/*
	 * We assemble the rest of the information about the partitions by
	 * looking in the vfstab.
	 */
	for (i = 0; i < dpartcnt; i++) {
		for (j = 0; j < vfsnum; j++) {
			if (vfstab[j].vfs_special != NULL &&
			    strcmp(dparttab[i].bdevice,
			    vfstab[j].vfs_special) == 0)
				break;
		}
		if (j < vfsnum) {
			/*
			 * Partition found in vfstab.
			 */
			if (vfstab[j].vfs_mountp == NULL ||
			    strcmp(vfstab[j].vfs_mountp, "-") == 0)
				mountpoint = "/mnt";
			else
				mountpoint = vfstab[j].vfs_mountp;
			if (snprintf(putdevcmd, lastlen, "/usr/bin/putdev "
			    "-a %s cdevice=%s bdevice=%s "
			    "desc=\"Disk Partition\" type=dpart "
			    "removable=false capacity=%llu dparttype=fs "
			    "fstype=%s mountpt=%s", dparttab[i].alias,
			    dparttab[i].cdevice, dparttab[i].bdevice,
			    dparttab[i].capacity, vfstab[j].vfs_fstype,
			    mountpoint) >= lastlen) {
					(void) fprintf(stderr,
					    "%s: Command too long: %s\n",
					    cmd, putdevcmd);
					exit(1);
				}
				(void) system(putdevcmd);
		}
		free(dparttab[i].cdevice);
		free(dparttab[i].bdevice);
	}
	free(dparttab);
}

static void
do_hdisks(void)
{
	DIR *dp;
	struct dirent *dirp;
	int drive = 1;	char disknm[MAXNAMLEN+1];

	if ((dp = opendir("/dev/rdsk")) == NULL) {
		(void) fprintf(stderr, "%s: can't open /dev/rdsk\n", cmd);
		return;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (gmatch(dirp->d_name, "c[0-9]*s2")) {
			(void) strcpy(disknm, dirp->d_name);
			/*
			 * now know off the 's2'
			 */
			disknm[strlen(disknm)-2] = '\0';
			/*
			 * And do it!
			 */
			hdisk(drive++, disknm);
		}
	}

	(void) closedir(dp);
}


/*
 * Add device table entry for the cartridge tape drive.
 */
static void
tape(const int driveno, const char *drivenm)
{
	if (snprintf(putdevcmd, lastlen, "/usr/bin/putdev -a ctape%d "
	    "cdevice=/dev/rmt/%s "
	    "desc=\"Tape Drive\" volume=\"tape\" "
	    "type=ctape removable=true capacity=45539 bufsize=15872 "
	    "erasecmd=\"/usr/bin/mt -f /dev/rmt/%s erase\" "
	    "removecmd=\"/usr/bin/mt -f /dev/rmt/%s offline\"",
	    driveno, drivenm, drivenm, drivenm) >= lastlen) {
		(void) fprintf(stderr,
		    "%s: Command too long: %s\n", cmd, putdevcmd);
		exit(1);
	}
	(void) system(putdevcmd);
}

static void
do_tapes(void)
{
	DIR *dp;
	struct dirent *dirp;

	if ((dp = opendir("/dev/rmt")) == NULL) {
		(void) fprintf(stderr, "%s: can't open /dev/rmt\n", cmd);
		return;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (gmatch(dirp->d_name, "[0-9]") ||
		    gmatch(dirp->d_name, "[1-9][0-9]")) {
			tape(atoi(dirp->d_name), dirp->d_name);
		}
	}

	(void) closedir(dp);
}

static void
initialize(void)
{
	FILE		*fp;
	int		i;
	struct vfstab	vfsent;
	char		*criteria[5];
	char		**olddevlist;

	/*
	 * Build a copy of vfstab in memory for later use.
	 */
	if ((fp = fopen("/etc/vfstab", "r")) == NULL) {
		(void) fprintf(stderr,
		    "%s: can't update device tables:Can't open /etc/vfstab\n",
		    cmd);
		exit(1);
	}

	/*
	 * Go through the vfstab file once to get the number of entries so
	 * we can allocate the right amount of contiguous memory.
	 */
	vfsnum = 0;
	while (getvfsent(fp, &vfsent) == 0)
		vfsnum++;
	rewind(fp);

	if ((vfstab = (struct vfstab *)malloc(vfsnum * sizeof (struct vfstab)))
	    == NULL) {
		(void) fprintf(stderr,
		    "%s: can't update device tables:Out of memory\n", cmd);
		exit(1);
	}

	/*
	 * Go through the vfstab file one more time to populate our copy in
	 * memory.  We only populate the fields we'll need.
	 */
	i = 0;
	while (getvfsent(fp, &vfsent) == 0 && i < vfsnum) {
		if (vfsent.vfs_special == NULL)
			vfstab[i].vfs_special = NULL;
		else
			vfstab[i].vfs_special = memstr(vfsent.vfs_special);
		if (vfsent.vfs_mountp == NULL)
			vfstab[i].vfs_mountp = NULL;
		else
			vfstab[i].vfs_mountp = memstr(vfsent.vfs_mountp);
		if (vfsent.vfs_fstype == NULL)
			vfstab[i].vfs_fstype = NULL;
		else
			vfstab[i].vfs_fstype = memstr(vfsent.vfs_fstype);
		i++;
	}
	(void) fclose(fp);

	/*
	 * Now remove all current entries of type disk, dpart, ctape
	 * and diskette from the device and device group tables.
	 * Any changes made manually since the last time this command
	 * was run will be lost.  Note that after this we are committed
	 * to try our best to rebuild the tables (i.e. the command
	 * should try not to fail completely after this point).
	 */
	criteria[0] = "type=disk";
	criteria[1] = "type=dpart";
	criteria[2] = "type=ctape";
	criteria[3] = "type=diskette";
	criteria[4] = (char *)NULL;
	olddevlist = getdev((char **)NULL, criteria, 0);
	_enddevtab();	/* getdev() should do this but doesn't */

	putdevcmd = malloc(ORIGLEN);

	if (putdevcmd == NULL) {
		perror("malloc");
		exit(-1);
	}

	(void) memset(putdevcmd, 0, ORIGLEN);

	for (i = 0; olddevlist[i] != (char *)NULL; i++) {
		if (snprintf(putdevcmd, lastlen,
		    "/usr/bin/putdev -d %s", olddevlist[i]) >= lastlen) {
			(void) fprintf(stderr,
			    "%s: Command too long: %s\n", cmd, putdevcmd);
			exit(1);
		}
		(void) system(putdevcmd);
	}

	(void) sprintf(putdevcmd, "/usr/bin/putdgrp -d disk 2>/dev/null");
	(void) system(putdevcmd);
	(void) sprintf(putdevcmd, "/usr/bin/putdgrp -d dpart 2>/dev/null");
	(void) system(putdevcmd);
	(void) sprintf(putdevcmd, "/usr/bin/putdgrp -d ctape 2>/dev/null");
	(void) system(putdevcmd);
	(void) sprintf(putdevcmd, "/usr/bin/putdgrp -d diskette 2>/dev/null");
	(void) system(putdevcmd);
}


/*
 * Update the dgroup.tab file with information from the updated device.tab.
 */
static void
mkdgroups(void)
{
	int	i;
	char	*criteria[2];
	char	**devlist;

	criteria[1] = (char *)NULL;

	criteria[0] = "type=disk";

	devlist = getdev((char **)NULL, criteria, DTAB_ANDCRITERIA);

	(void) sprintf(putdevcmd, "/usr/bin/putdgrp disk");
	for (i = 0; devlist[i] != (char *)NULL; i++) {
		checkandresize((strlen(putdevcmd) + strlen(devlist[i]) + 2));
		(void) strcat(putdevcmd, " ");
		(void) strcat(putdevcmd, devlist[i]);
	}
	if (i != 0)
		(void) system(putdevcmd);

	criteria[0] = "type=dpart";

	devlist = getdev((char **)NULL, criteria, DTAB_ANDCRITERIA);

	(void) sprintf(putdevcmd, "/usr/bin/putdgrp dpart");
	for (i = 0; devlist[i] != (char *)NULL; i++) {
		checkandresize((strlen(putdevcmd) + strlen(devlist[i]) + 2));
		(void) strcat(putdevcmd, " ");
		(void) strcat(putdevcmd, devlist[i]);
	}
	if (i != 0)
		(void) system(putdevcmd);

	criteria[0] = "type=ctape";

	devlist = getdev((char **)NULL, criteria, DTAB_ANDCRITERIA);

	(void) sprintf(putdevcmd, "/usr/bin/putdgrp ctape");
	for (i = 0; devlist[i] != (char *)NULL; i++) {
		checkandresize((strlen(putdevcmd) + strlen(devlist[i]) + 2));
		(void) strcat(putdevcmd, " ");
		(void) strcat(putdevcmd, devlist[i]);
	}
	if (i != 0)
		(void) system(putdevcmd);

	criteria[0] = "type=diskette";

	devlist = getdev((char **)NULL, criteria, DTAB_ANDCRITERIA);

	(void) sprintf(putdevcmd, "/usr/bin/putdgrp diskette");
	for (i = 0; devlist[i] != (char *)NULL; i++) {
		checkandresize((strlen(putdevcmd) + strlen(devlist[i]) + 2));
		(void) strcat(putdevcmd, " ");
		(void) strcat(putdevcmd, devlist[i]);
	}
	if (i != 0)
		(void) system(putdevcmd);
}

static void
checkandresize(int size)
{
	if (size >= lastlen) {
		putdevcmd = realloc(putdevcmd, lastlen * 2);
		lastlen = lastlen * 2;
	}
}

/*ARGSUSED*/
int
main(int argc, char **argv)
{
	(void) strncpy(cmd, argv[0], 80);

	initialize();

	/*
	 * AT&T code looked at the 3B2 EDT here.  Since we have a known-good
	 * /dev directory ( presuming 'disks' has already been run), we simply
	 * look in the /dev subdirectories.
	 */
	do_hdisks();

	do_fdisks();

	do_tapes();

	/*
	 * Update the dgroup.tab file.
	 */
	mkdgroups();

	return (0);

}
