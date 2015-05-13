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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/dumpadm.h>
#include <sys/utsname.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <libdiskmgt.h>
#include <libzfs.h>
#include <uuid/uuid.h>

#include "dconf.h"
#include "minfree.h"
#include "utils.h"
#include "swap.h"

typedef struct dc_token {
	const char *tok_name;
	int (*tok_parse)(dumpconf_t *, char *);
	int (*tok_print)(const dumpconf_t *, FILE *);
} dc_token_t;


static int print_device(const dumpconf_t *, FILE *);
static int print_savdir(const dumpconf_t *, FILE *);
static int print_content(const dumpconf_t *, FILE *);
static int print_enable(const dumpconf_t *, FILE *);
static int print_csave(const dumpconf_t *, FILE *);

static const dc_token_t tokens[] = {
	{ "DUMPADM_DEVICE", dconf_str2device, print_device },
	{ "DUMPADM_SAVDIR", dconf_str2savdir, print_savdir },
	{ "DUMPADM_CONTENT", dconf_str2content, print_content },
	{ "DUMPADM_ENABLE", dconf_str2enable, print_enable },
	{ "DUMPADM_CSAVE", dconf_str2csave, print_csave },
	{ NULL, NULL, NULL }
};

static const char DC_STR_ON[] = "on";		/* On string */
static const char DC_STR_OFF[] = "off";		/* Off string */
static const char DC_STR_YES[] = "yes";		/* Enable on string */
static const char DC_STR_NO[] = "no";		/* Enable off string */
static const char DC_STR_SWAP[] = "swap";	/* Default dump device */
static const char DC_STR_NONE[] = "none";

/* The pages included in the dump */
static const char DC_STR_KERNEL[] = "kernel";	/* Kernel only */
static const char DC_STR_CURPROC[] = "curproc";	/* Kernel + current process */
static const char DC_STR_ALL[] = "all";		/* All pages */

/*
 * Permissions and ownership for the configuration file:
 */
#define	DC_OWNER	0				/* Uid 0 (root) */
#define	DC_GROUP	1				/* Gid 1 (other) */
#define	DC_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* Mode 0644 */

static void
dconf_init(dumpconf_t *dcp, int dcmode)
{
	struct utsname ut;

	/*
	 * Default device for dumps is 'swap' (appropriate swap device),
	 * and default savecore directory is /var/crash/`uname -n`,
	 * which is compatible with pre-dumpadm behavior.
	 */
	(void) strcpy(dcp->dc_device, DC_STR_SWAP);
	(void) strcpy(dcp->dc_savdir, "/var/crash");

	if (uname(&ut) != -1) {
		(void) strcat(dcp->dc_savdir, "/");
		(void) strcat(dcp->dc_savdir, ut.nodename);
	}

	/*
	 * Default is contents kernel, savecore enabled on reboot,
	 * savecore saves compressed core files.
	 */
	dcp->dc_cflags = DUMP_KERNEL;
	dcp->dc_enable = DC_ON;
	dcp->dc_csave = DC_COMPRESSED;

	dcp->dc_mode = dcmode;
	dcp->dc_conf_fp = NULL;
	dcp->dc_conf_fd = -1;
	dcp->dc_dump_fd = -1;
	dcp->dc_readonly = B_FALSE;
}

int
dconf_open(dumpconf_t *dcp, const char *dpath, const char *fpath, int dcmode)
{
	char buf[BUFSIZ];
	int line;
	const char *fpmode = "r+";

	dconf_init(dcp, dcmode);

	if ((dcp->dc_dump_fd = open(dpath, O_RDWR)) == -1) {
		warn(gettext("failed to open %s"), dpath);
		return (-1);
	}

	if ((dcp->dc_conf_fd = open(fpath, O_RDWR | O_CREAT, DC_PERM)) == -1) {
		/*
		 * Attempt to open the file read-only.
		 */
		if ((dcp->dc_conf_fd = open(fpath, O_RDONLY)) == -1) {
			warn(gettext("failed to open %s"), fpath);
			return (-1);
		}

		dcp->dc_readonly = B_TRUE;
		fpmode = "r";
	}

	if ((dcp->dc_conf_fp = fdopen(dcp->dc_conf_fd, fpmode)) == NULL) {
		warn(gettext("failed to open stream for %s"), fpath);
		return (-1);
	}

	/*
	 * If we're in override mode, the current kernel settings override the
	 * default settings and anything invalid in the configuration file.
	 */
	if (dcmode == DC_OVERRIDE)
		(void) dconf_getdev(dcp);

	for (line = 1; fgets(buf, BUFSIZ, dcp->dc_conf_fp) != NULL; line++) {

		char name[BUFSIZ], value[BUFSIZ];
		const dc_token_t *tokp;
		int len;

		if (buf[0] == '#' || buf[0] == '\n')
			continue;

		/*
		 * Look for "name=value", with optional whitespace on either
		 * side, terminated by a newline, and consuming the whole line.
		 */
		/* LINTED - unbounded string specifier */
		if (sscanf(buf, " %[^=]=%s \n%n", name, value, &len) == 2 &&
		    name[0] != '\0' && value[0] != '\0' && len == strlen(buf)) {
			/*
			 * Locate a matching token in the tokens[] table,
			 * and invoke its parsing function.
			 */
			for (tokp = tokens; tokp->tok_name != NULL; tokp++) {
				if (strcmp(name, tokp->tok_name) == 0) {
					if (tokp->tok_parse(dcp, value) == -1) {
						warn(gettext("\"%s\", line %d: "
						    "warning: invalid %s\n"),
						    fpath, line, name);
					}
					break;
				}
			}

			/*
			 * If we hit the end of the tokens[] table,
			 * no matching token was found.
			 */
			if (tokp->tok_name == NULL) {
				warn(gettext("\"%s\", line %d: warning: "
				    "invalid token: %s\n"), fpath, line, name);
			}

		} else {
			warn(gettext("\"%s\", line %d: syntax error\n"),
			    fpath, line);
		}
	}

	/*
	 * If we're not in override mode, the current kernel settings
	 * override the settings read from the configuration file.
	 */
	if (dcmode == DC_CURRENT)
		return (dconf_getdev(dcp));

	return (0);
}

int
dconf_getdev(dumpconf_t *dcp)
{
	int status = 0;

	if ((dcp->dc_cflags = ioctl(dcp->dc_dump_fd, DIOCGETCONF, 0)) == -1) {
		warn(gettext("failed to get kernel dump settings"));
		status = -1;
	}

	if (ioctl(dcp->dc_dump_fd, DIOCGETDEV, dcp->dc_device) == -1) {
		if (errno != ENODEV) {
			warn(gettext("failed to get dump device"));
			status = -1;
		} else
			dcp->dc_device[0] = '\0';
	}

	return (status);
}

int
dconf_close(dumpconf_t *dcp)
{
	if (fclose(dcp->dc_conf_fp) == 0) {
		(void) close(dcp->dc_dump_fd);
		return (0);
	}
	return (-1);
}

int
dconf_write(dumpconf_t *dcp)
{
	const dc_token_t *tokp;

	if (fseeko(dcp->dc_conf_fp, (off_t)0, SEEK_SET) == -1) {
		warn(gettext("failed to seek config file"));
		return (-1);
	}

	if (ftruncate(dcp->dc_conf_fd, (off_t)0) == -1) {
		warn(gettext("failed to truncate config file"));
		return (-1);
	}

	(void) fputs("#\n# dumpadm.conf\n#\n"
	    "# Configuration parameters for system crash dump.\n"
	    "# Do NOT edit this file by hand -- use dumpadm(1m) instead.\n"
	    "#\n", dcp->dc_conf_fp);

	for (tokp = tokens; tokp->tok_name != NULL; tokp++) {
		if (fprintf(dcp->dc_conf_fp, "%s=", tokp->tok_name) == -1 ||
		    tokp->tok_print(dcp, dcp->dc_conf_fp) == -1) {
			warn(gettext("failed to write token"));
			return (-1);
		}
	}

	if (fflush(dcp->dc_conf_fp) != 0)
		warn(gettext("warning: failed to flush config file"));

	if (fsync(dcp->dc_conf_fd) == -1)
		warn(gettext("warning: failed to sync config file to disk"));

	if (fchmod(dcp->dc_conf_fd, DC_PERM) == -1)
		warn(gettext("warning: failed to reset mode on config file"));

	if (fchown(dcp->dc_conf_fd, DC_OWNER, DC_GROUP) == -1)
		warn(gettext("warning: failed to reset owner on config file"));

	return (0);
}

static int
open_stat64(const char *path, struct stat64 *stp)
{
	int fd = open64(path, O_RDONLY);

	if (fd >= 0) {
		int status = fstat64(fd, stp);
		(void) close(fd);
		return (status);
	}

	return (-1);
}

static int
dconf_swap_compare(const swapent_t *s1, const swapent_t *s2)
{
	struct stat64 st1, st2;

	int prefer_s1 = -1;	/* Return value to move s1 left (s1 < s2) */
	int prefer_s2 = 1;	/* Return value to move s2 left (s1 > s2) */

	/*
	 * First try: open and fstat each swap entry.  If either system
	 * call fails, arbitrarily prefer the other entry.
	 */
	if (open_stat64(s1->ste_path, &st1) == -1)
		return (prefer_s2);

	if (open_stat64(s2->ste_path, &st2) == -1)
		return (prefer_s1);

	/*
	 * Second try: if both entries are block devices, or if
	 * neither is a block device, prefer the larger.
	 */
	if (S_ISBLK(st1.st_mode) == S_ISBLK(st2.st_mode)) {
		if (st2.st_size > st1.st_size)
			return (prefer_s2);
		return (prefer_s1);
	}

	/*
	 * Third try: prefer the entry that is a block device.
	 */
	if (S_ISBLK(st2.st_mode))
		return (prefer_s2);
	return (prefer_s1);
}

static int
dconf_dev_ioctl(dumpconf_t *dcp, int cmd)
{
	if (ioctl(dcp->dc_dump_fd, cmd, dcp->dc_device) == 0)
		return (0);

	switch (errno) {
	case ENOTSUP:
		warn(gettext("dumps not supported on %s\n"), dcp->dc_device);
		break;
	case EBUSY:
		warn(gettext("device %s is already in use\n"), dcp->dc_device);
		break;
	case EBADR:
		/* ZFS pool is too fragmented to support a dump device */
		warn(gettext("device %s is too fragmented to be used as "
		    "a dump device\n"), dcp->dc_device);
		break;
	default:
		/*
		 * NOTE: The stmsboot(1M) command's boot-up script parses this
		 * error to get the dump device name. If you change the format
		 * of this message, make sure that stmsboot(1M) is in sync.
		 */
		warn(gettext("cannot use %s as dump device"), dcp->dc_device);
	}
	return (-1);
}

int
dconf_update(dumpconf_t *dcp, int checkinuse)
{
	int		oconf;
	int		error;
	char		*msg;

	error = 0;

	if (checkinuse && (dm_inuse(dcp->dc_device, &msg, DM_WHO_DUMP,
	    &error) || error)) {
		if (error != 0) {
			warn(gettext("failed to determine if %s is"
			    " in use"), dcp->dc_device);
		} else {
			warn(msg);
			free(msg);
			return (-1);
		}
	}

	/*
	 * Save the existing dump configuration in case something goes wrong.
	 */
	if ((oconf = ioctl(dcp->dc_dump_fd, DIOCGETCONF, 0)) == -1) {
		warn(gettext("failed to get kernel dump configuration"));
		return (-1);
	}

	oconf &= DUMP_CONTENT;
	dcp->dc_cflags &= DUMP_CONTENT;

	if (ioctl(dcp->dc_dump_fd, DIOCSETCONF, dcp->dc_cflags) == -1) {
		warn(gettext("failed to update kernel dump configuration"));
		return (-1);
	}

	if (strcmp(dcp->dc_device, DC_STR_SWAP) == 0) {
		swaptbl_t *swt;
		int i;

		if ((swt = swap_list()) == NULL)
			goto err;

		if (swt->swt_n == 0) {
			warn(gettext("no swap devices are available\n"));
			free(swt);
			goto err;
		}

		qsort(&swt->swt_ent[0], swt->swt_n, sizeof (swapent_t),
		    (int (*)(const void *, const void *))dconf_swap_compare);

		/*
		 * Iterate through the prioritized list of swap entries,
		 * trying to configure one as the dump device.
		 */
		for (i = 0; i < swt->swt_n; i++) {
			if (ioctl(dcp->dc_dump_fd, DIOCSETDEV,
			    swt->swt_ent[i].ste_path) == 0) {
				(void) strcpy(dcp->dc_device,
				    swt->swt_ent[i].ste_path);
				break;
			}
		}

		if (i == swt->swt_n) {
			warn(gettext("no swap devices could be configured "
			    "as the dump device\n"));
			free(swt);
			goto err;
		}
		free(swt);

	} else if (strcmp(dcp->dc_device, DC_STR_NONE) == 0) {
		if (ioctl(dcp->dc_dump_fd, DIOCRMDEV, NULL) == -1) {
			warn(gettext("failed to remove dump device"));
			return (-1);
		}
	} else if (dcp->dc_device[0] != '\0') {
		/*
		 * If we're not in forcible update mode, then fail the change
		 * if the selected device cannot be used as the dump device,
		 * or if it is not big enough to hold the dump.
		 */
		if (dcp->dc_mode == DC_CURRENT) {
			struct stat64 st;
			uint64_t d;

			if (dconf_dev_ioctl(dcp, DIOCTRYDEV) == -1)
				goto err;

			if (open_stat64(dcp->dc_device, &st) == -1) {
				warn(gettext("failed to access %s"),
				    dcp->dc_device);
				goto err;
			}

			if ((error = zvol_check_dump_config(
			    dcp->dc_device)) > 0)
				goto err;
			if (ioctl(dcp->dc_dump_fd, DIOCGETDUMPSIZE, &d) == -1) {
				warn(gettext("failed to get kernel dump size"));
				goto err;
			}

			if (st.st_size < d) {
				warn(gettext("dump device %s is too small to "
				    "hold a system dump\ndump size %llu "
				    "bytes, device size %lld bytes\n"),
				    dcp->dc_device, d, st.st_size);
				goto err;
			}
		}

		if (dconf_dev_ioctl(dcp, DIOCSETDEV) == -1)
			goto err;
	}

	/*
	 * Now that we've updated the dump device, we need to issue another
	 * ioctl to re-read the config flags to determine whether we
	 * obtained DUMP_EXCL access on our dump device.
	 */
	if ((dcp->dc_cflags = ioctl(dcp->dc_dump_fd, DIOCGETCONF, 0)) == -1) {
		warn(gettext("failed to re-read kernel dump configuration"));
		return (-1);
	}

	return (0);

err:
	(void) ioctl(dcp->dc_dump_fd, DIOCSETCONF, oconf);
	return (-1);
}

int
dconf_write_uuid(dumpconf_t *dcp)
{
	char uuidstr[36 + 1];
	uuid_t uu;
	int err;

	uuid_generate(uu);
	uuid_unparse(uu, uuidstr);

	err = ioctl(dcp->dc_dump_fd, DIOCSETUUID, uuidstr);

	if (err)
		warn(gettext("kernel image uuid write failed"));

	return (err == 0);
}

int
dconf_get_dumpsize(dumpconf_t *dcp)
{
	char buf[32];
	uint64_t d;

	if (ioctl(dcp->dc_dump_fd, DIOCGETDUMPSIZE, &d) == -1) {
		warn(gettext("failed to get kernel dump size"));
		return (-1);
	}

	zfs_nicenum(d, buf, sizeof (buf));

	(void) printf(gettext("Estimated dump size: %s\n"), buf);
	return (0);
}

void
dconf_print(dumpconf_t *dcp, FILE *fp)
{
	u_longlong_t min;
	char *content;

	if (dcp->dc_cflags & DUMP_ALL)
		content = gettext("all");
	else if (dcp->dc_cflags & DUMP_CURPROC)
		content = gettext("kernel and current process");
	else
		content = gettext("kernel");

	(void) fprintf(fp, gettext("      Dump content: %s pages\n"), content);

	if (dcp->dc_device[0] != '\0') {
		(void) fprintf(fp, gettext("       Dump device: %s (%s)\n"),
		    dcp->dc_device, (dcp->dc_cflags & DUMP_EXCL) ?
		    gettext("dedicated") : gettext("swap"));
	} else {
		(void) fprintf(fp, gettext("       Dump device: none "
		    "(dumps disabled)\n"));
	}

	(void) fprintf(fp, gettext("Savecore directory: %s"), dcp->dc_savdir);

	if (minfree_read(dcp->dc_savdir, &min) == 0) {
		if (min < 1024 || (min % 1024) != 0)
			(void) fprintf(fp, gettext(" (minfree = %lluKB)"), min);
		else
			(void) fprintf(fp, gettext(" (minfree = %lluMB)"),
			    min / 1024);
	}

	(void) fprintf(fp, gettext("\n"));

	(void) fprintf(fp, gettext("  Savecore enabled: %s\n"),
	    (dcp->dc_enable == DC_OFF) ? gettext("no") : gettext("yes"));
	(void) fprintf(fp, gettext("   Save compressed: %s\n"),
	    (dcp->dc_csave == DC_UNCOMPRESSED) ? gettext("off") :
	    gettext("on"));
}

int
dconf_str2device(dumpconf_t *dcp, char *buf)
{
	if (strcasecmp(buf, DC_STR_SWAP) == 0) {
		(void) strcpy(dcp->dc_device, DC_STR_SWAP);
		return (0);
	}

	if (strcasecmp(buf, DC_STR_NONE) == 0) {
		(void) strcpy(dcp->dc_device, DC_STR_NONE);
		return (0);
	}

	if (valid_abspath(buf)) {
		(void) strcpy(dcp->dc_device, buf);
		return (0);
	}

	return (-1);
}

int
dconf_str2savdir(dumpconf_t *dcp, char *buf)
{
	if (valid_abspath(buf)) {
		(void) strcpy(dcp->dc_savdir, buf);
		return (0);
	}

	return (-1);
}

int
dconf_str2content(dumpconf_t *dcp, char *buf)
{
	if (strcasecmp(buf, DC_STR_KERNEL) == 0) {
		dcp->dc_cflags = (dcp->dc_cflags & ~DUMP_CONTENT) | DUMP_KERNEL;
		return (0);
	}

	if (strcasecmp(buf, DC_STR_CURPROC) == 0) {
		dcp->dc_cflags = (dcp->dc_cflags & ~DUMP_CONTENT) |
		    DUMP_CURPROC;
		return (0);
	}

	if (strcasecmp(buf, DC_STR_ALL) == 0) {
		dcp->dc_cflags = (dcp->dc_cflags & ~DUMP_CONTENT) | DUMP_ALL;
		return (0);
	}

	warn(gettext("invalid dump content type -- %s\n"), buf);
	return (-1);
}

int
dconf_str2enable(dumpconf_t *dcp, char *buf)
{
	if (strcasecmp(buf, DC_STR_YES) == 0) {
		dcp->dc_enable = DC_ON;
		return (0);
	}

	if (strcasecmp(buf, DC_STR_NO) == 0) {
		dcp->dc_enable = DC_OFF;
		return (0);
	}

	warn(gettext("invalid enable value -- %s\n"), buf);
	return (-1);
}

int
dconf_str2csave(dumpconf_t *dcp, char *buf)
{
	if (strcasecmp(buf, DC_STR_ON) == 0) {
		dcp->dc_csave = DC_COMPRESSED;
		return (0);
	}

	if (strcasecmp(buf, DC_STR_OFF) == 0) {
		dcp->dc_csave = DC_UNCOMPRESSED;
		return (0);
	}

	warn(gettext("invalid save compressed value -- %s\n"), buf);
	return (-1);
}

static int
print_content(const dumpconf_t *dcp, FILE *fp)
{
	const char *content;

	if (dcp->dc_cflags & DUMP_ALL)
		content = DC_STR_ALL;
	else if (dcp->dc_cflags & DUMP_CURPROC)
		content = DC_STR_CURPROC;
	else
		content = DC_STR_KERNEL;

	return (fprintf(fp, "%s\n", content));
}

static int
print_device(const dumpconf_t *dcp, FILE *fp)
{
	return (fprintf(fp, "%s\n", (dcp->dc_device[0] != '\0') ?
	    dcp->dc_device : DC_STR_SWAP));
}

static int
print_enable(const dumpconf_t *dcp, FILE *fp)
{
	return (fprintf(fp, "%s\n", (dcp->dc_enable == DC_OFF) ?
	    DC_STR_NO : DC_STR_YES));
}

static int
print_csave(const dumpconf_t *dcp, FILE *fp)
{
	return (fprintf(fp, "%s\n", (dcp->dc_csave == DC_COMPRESSED) ?
	    DC_STR_ON : DC_STR_OFF));
}

static int
print_savdir(const dumpconf_t *dcp, FILE *fp)
{
	return (fprintf(fp, "%s\n", dcp->dc_savdir));
}
