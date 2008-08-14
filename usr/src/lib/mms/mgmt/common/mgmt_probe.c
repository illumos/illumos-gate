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

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <dirent.h>
#include <sys/mtio.h>
#include <ctype.h>
#include <fcntl.h>
#include <libnvpair.h>

#include "mms_mgmt.h"
#include "mgmt_sym.h"

#define	TPDIR	"/dev/rmt"

int
mgmt_find_local_drives(nvlist_t **drv_list)
{
	int			st = 0;
	int			i;
	struct	uscsi_cmd	us;
	uchar_t			cdb[] = {0x12, 0x01, 0x80, 0x00, 64, 0x00};
						/* cdb to read serial number */
	uchar_t			cdbinq[] = { 0x12, 0x00, 0x00, 0x00, 64, 0 };
						/* cdb to read inquiry data */
	int			fd = -1;
	char			senbuf[64];
	char			buf[68];	/* 64 + 4 */
	char			ser[65];	/* 64 + nul */
	DIR			*dir;
	dirent_t		*ent;
	ssize_t			len;
	char			*name;
	char			path[MAXPATHLEN];
	struct	mtdrivetype	dt;
	struct	mtdrivetype_request dtreq = { sizeof (dt), &dt };
	char			vid[9];
	char			pid[17];
	char			*bufp;
	nvlist_t		*drv = NULL;
	char			*unavail = "device unavailable";

	if (!drv_list) {
		return (MMS_MGMT_NOARG);
	}

	if ((dir = opendir(TPDIR)) == NULL) {
		st = errno;
		return (st);
	}

	st = nvlist_alloc(drv_list, NV_UNIQUE_NAME, 0);
	if (st != 0) {
		return (st);
	}

	while (ent = readdir(dir)) {
		if (fd != -1) {
			(void) close(fd);
			fd = -1;
		}

		if (drv != NULL) {
			(void) nvlist_add_nvlist(*drv_list, path, drv);
			drv = NULL;
		}

		/*
		 * Use the device with only norewind
		 */
		len = strlen(ent->d_name);
		name = ent->d_name;
		if (name[len - 1] != 'n' || !isdigit(name[len - 2])) {
			continue;
		}

		(void) snprintf(path, sizeof (path), "%s/%s", TPDIR, name);

		/* list all drives, accessible or not */
		st = nvlist_alloc(&drv, NV_UNIQUE_NAME, 0);
		if (st != 0) {
			break;
		}
		(void) nvlist_add_string(drv, O_DEVPATH, path);

		fd = open(path, O_NDELAY | O_RDWR);
		if (fd < 0) {
			if (errno == EBUSY) {
				(void) nvlist_add_string(drv, O_TYPE,
				    "device busy");
			} else {
				(void) nvlist_add_string(drv, O_TYPE, unavail);
			}
			continue;
		}

		/*
		 * Read the serial number
		 */
		(void) memset(&us, 0, sizeof (us));
		us.uscsi_flags |= (USCSI_RQENABLE | USCSI_READ);
		us.uscsi_cdb = (char *)cdb;
		us.uscsi_cdblen = sizeof (cdb);
		us.uscsi_bufaddr = buf;
		us.uscsi_buflen = sizeof (buf);
		us.uscsi_rqlen = sizeof (senbuf);
		us.uscsi_rqbuf = senbuf;

		(void) memset(us.uscsi_rqbuf, 0, us.uscsi_rqlen);

		if (ioctl(fd, USCSICMD, &us)) {
			if (errno != EIO) {
				(void) nvlist_add_string(drv, O_TYPE, unavail);
				continue;
			}
		}

		if ((us.uscsi_status != STATUS_GOOD) ||
		    (us.uscsi_resid == us.uscsi_buflen)) {
			/* No data transfered */
			(void) nvlist_add_string(drv, O_TYPE, unavail);
			continue;
		}

		(void) memset(ser, 0, sizeof (ser));
		len = buf[3];
		bufp = &(buf[4]);

		for (i = 0; (i < (sizeof (ser) - 1)) && (i < len);
		    i++, bufp++) {
			if ((*bufp == '\0') || (*bufp == ' ')) {
				break;
			}

			ser[i] = *bufp;
		}

		/*
		 * Read vid and pid using inquiry. The MTIOCGETDRIVETYPE
		 * ioctl does not give you the full 16 bytes of product id.
		 */
		(void) memset(&us, 0, sizeof (us));
		us.uscsi_flags |= (USCSI_RQENABLE | USCSI_READ);
		us.uscsi_cdb = (char *)cdbinq;
		us.uscsi_cdblen = sizeof (cdbinq);
		us.uscsi_bufaddr = buf;
		us.uscsi_buflen = sizeof (buf);
		us.uscsi_rqlen = sizeof (senbuf);
		us.uscsi_rqbuf = senbuf;

		(void) memset(us.uscsi_rqbuf, 0, us.uscsi_rqlen);

		if (ioctl(fd, USCSICMD, &us)) {
			(void) nvlist_add_string(drv, O_TYPE, unavail);
			continue;
		}

		if ((us.uscsi_status != STATUS_GOOD) ||
		    (us.uscsi_resid == us.uscsi_buflen)) {
			/* No data transfered */
			(void) nvlist_add_string(drv, O_TYPE, unavail);
			continue;
		}

		(void) memset(vid, 0, sizeof (vid));
		bufp = &(buf[8]);

		for (i = 0; i < (sizeof (vid) - 1); i++, bufp++) {
			if ((*bufp == '\0') || (*bufp == ' ')) {
				break;
			}

			vid[i] = *bufp;
		}

		(void) memset(pid, 0, sizeof (pid));
		bufp = &(buf[16]);

		for (i = 0; i < (sizeof (pid) - 1); i++, bufp++) {
			if ((*bufp == '\0') || (*bufp == ' ')) {
				break;
			}

			pid[i] = *bufp;
		}

		/*
		 * Get the drive type
		 */
		if (ioctl(fd, MTIOCGETDRIVETYPE, &dtreq) == 0) {
			(void) nvlist_add_string(drv, O_SERIALNO, ser);
			(void) nvlist_add_string(drv, O_TYPE, pid);
			(void) nvlist_add_string(drv, "vendorid", vid);
			(void) nvlist_add_string(drv, "fullname", dt.name);
		}

		(void) close(fd);
		fd = -1;
	}
	(void) closedir(dir);

	/* make sure the last drive made it to the list */
	if (drv != NULL) {
		(void) nvlist_add_nvlist(*drv_list, path, drv);
	}

	return (st);
}
