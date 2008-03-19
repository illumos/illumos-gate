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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>
#include <limits.h>
#include <dbus/dbus.h>
#include <hal/libhal.h>

#include "transport.h"
#include "mmc.h"
#include "device.h"
#include "util.h"
#include "msgs.h"
#include "misc_scsi.h"
#include "toshiba.h"
#include "main.h"

/*
 * Old sun drives have a vendor specific mode page for setting/getting speed.
 * Also they use a different method for extracting audio.
 * We have the device inquiry strings at this time. This is used to enable
 * us to use older sun drives to extract audio.
 */
static int
is_old_sun_drive(cd_device *dev)
{
	/*
	 * If we have a SONY CDU 561, CDU 8012, or TOSHIBA model with XMa we
	 * need to handle these drives a bit differently.
	 */
	if (strncmp("SONY", (const char *)&dev->d_inq[8], 4) == 0) {
		if (strncmp("CDU 561", (const char *)&dev->d_inq[16], 7) == 0)
			return (1);
		if (strncmp("CDU-8012", (const char *)&dev->d_inq[16], 8) == 0)
			return (1);
	}

	if ((strncmp("TOSHIBA", (const char *)&dev->d_inq[8], 7) == 0) &&
	    (strncmp("XM", (const char *)&dev->d_inq[16], 2) == 0)) {

		char product_id[17];

		/* Changing speed is not allowed for 32X TOSHIBA drives */
		if (strncmp("SUN32XCD", (const char *)&dev->d_inq[24], 8) == 0)
			dev->d_cap |= DEV_CAP_SETTING_SPEED_NOT_ALLOWED;
		(void) strncpy(product_id, (const char *)&dev->d_inq[16], 16);
		product_id[16] = 0;
		if (strstr(product_id, "SUN") != NULL)
			return (1);
	}
	return (0);
}

/*
 * returns a cd_device handle for a node returned by lookup_device()
 * also takes the user supplied name and stores it inside the node
 */
cd_device *
get_device(char *user_supplied, char *node)
{
	cd_device *dev;
	int fd;
	uchar_t *cap;
	char devnode[PATH_MAX];
	int size;
	struct dk_minfo mediainfo;
	int use_cd_speed = 0;

	/*
	 * we need to resolve any link paths to avoid fake files
	 * such as /dev/rdsk/../../export/file.
	 */

	TRACE(traceall_msg("get_device(%s, %s)\n", user_supplied ?
	    user_supplied : "<nil>", node ? node : "<nil>"));

	size = resolvepath(node, devnode, PATH_MAX);
	if ((size <= 0) || (size >= (PATH_MAX - 1)))
		return (NULL);

	/* resolvepath may not return a null terminated string */
	devnode[size] = '\0';


	/* the device node must be in /devices/ or /vol/dev/rdsk */

	if ((strncmp(devnode, "/devices/", 9) != 0) &&
	    (strncmp(devnode, "/vol/dev/rdsk", 13) != 0))
		return (NULL);
	/*
	 * Since we are currently running with the user euid it is
	 * safe to try to open the file without checking access.
	 */

	fd = open(devnode, O_RDONLY|O_NDELAY);

	if (fd < 0) {
		TRACE(traceall_msg("Cannot open %s: %s\n", node,
		    strerror(errno)));
		return (NULL);
	}

	dev = (cd_device *)my_zalloc(sizeof (cd_device));

	dev->d_node = (char *)my_zalloc(strlen(devnode) + 1);
	(void) strcpy(dev->d_node, devnode);

	dev->d_fd = fd;

	dev->d_inq = (uchar_t *)my_zalloc(INQUIRY_DATA_LENGTH);

	if (!inquiry(fd, dev->d_inq)) {
		TRACE(traceall_msg("Inquiry failed on device %s\n", node));
		if (debug) {
			(void) printf("USCSI ioctl failed %d\n",
			    uscsi_error);
		}
		free(dev->d_inq);
		free(dev->d_node);
		(void) close(dev->d_fd);
		free(dev);
		return (NULL);
	}

	if (debug) {
		cap = (uchar_t *)my_zalloc(18);
		(void) printf("Checking device type\n");
		if (get_mode_page(fd, 0x2A, 0, 8, cap)) {
			if (cap[2] & 0x10)
				(void) printf("DVD-R read support\n");
			if (cap[3] & 0x10)
				(void) printf("DVD-R write support\n");
			if (cap[5] & 0x4)
				(void) printf("R-W supported\n");
			if (cap[2] & 0x20)
				(void) printf("DVD-RAM read supported\n");
			if (cap[3] & 0x20)
				(void) printf("DVD-RAM write supported\n");
		} else {
			(void) printf("Could not read mode page 2A! \n");
		}
		free(cap);
	}

	/* Detect if it's a Lite-ON drive with a streaming CD problem */
	if ((strncmp("LITE-ON", (const char *)&dev->d_inq[8], 7) == 0) &&
	    (strncmp("LTR-48", (const char *)&dev->d_inq[16], 6) == 0)) {
		use_cd_speed = 1;
	}

	/*
	 * a workaround for the firmware problem in LITE-ON COMBO drives.
	 * streaming for these drives sets it only to max speed regardless
	 * of requested speed. cd_speed_ctrl allow speeds less than max
	 * to be set but not max thus the code below. (x48 is max speed
	 * for these drives).
	 */
	if ((strncmp("LITE-ON", (const char *)&dev->d_inq[8], 7) == 0) &&
	    (strncmp("COMBO SOHC-4836VS",
	    (const char *)&dev->d_inq[16], 17) == 0))
		if (requested_speed < 48)
			use_cd_speed = 1;

	cap = (uchar_t *)my_zalloc(8);
	if (is_old_sun_drive(dev)) {
		dev->d_read_audio = toshiba_read_audio;
		dev->d_speed_ctrl = toshiba_speed_ctrl;
	} else {
		/*
		 * If the CD Read Feature is supported, READ CD will work
		 * and will return jitter free audio data. Otherwise, look
		 * at Page Code 2A for this information.
		 */
		if (ftr_supported(fd, MMC_FTR_CD_READ) == 1) {
			dev->d_read_audio = read_audio_through_read_cd;
			dev->d_cap |= DEV_CAP_ACCURATE_CDDA;
		} else if (get_mode_page(fd, 0x2A, 0, 8, cap)) {
			if (cap[5] & 1) {
				dev->d_read_audio = read_audio_through_read_cd;
				if (cap[5] & 2)
					dev->d_cap |= DEV_CAP_ACCURATE_CDDA;
			}
		}
		/*
		 * If the Real Time Streaming Feature is supported then
		 * Real-time streaming commands can be used for speed control
		 * (except when we want to use cd_speed_ctrl explicitly which
		 * is specified by setting use_cd_speed to 1).
		 * Otherwise try SET CD SPEED.
		 */
		if ((ftr_supported(fd, MMC_FTR_RT_STREAM) == 1) &&
		    !use_cd_speed) {
			dev->d_speed_ctrl = rt_streaming_ctrl;
			if (debug)
				(void) printf("using rt speed ctrl\n");
		} else {
			dev->d_speed_ctrl = cd_speed_ctrl;
			if (debug)
				(void) printf("using cd speed ctrl\n");
		}
	}
	if (dev->d_read_audio != NULL)
		dev->d_cap |= DEV_CAP_EXTRACT_CDDA;

	dev->d_blksize = 0;

	/*
	 * Find the block size of the device so we can translate
	 * the reads/writes to the device blocksize.
	 */

	if (ioctl(fd, DKIOCGMEDIAINFO, &mediainfo) < 0) {
		/*
		 * If DKIOCGMEDIAINFO fails we'll try to get
		 * the blocksize from the device itself.
		 */
		if (debug)
			(void) printf("DKIOCGMEDIAINFO failed\n");
		if (read_capacity(fd, cap))
			dev->d_blksize = read_scsi32(cap + 4);
	} else {

		dev->d_blksize = mediainfo.dki_lbsize;
	}

	if (debug) {
		uint_t bsize;

		(void) printf("blocksize = %d\n", dev->d_blksize);
		(void) printf("read_format_capacity = %d \n",
		    read_format_capacity(fd, &bsize));
	}

	/*
	 * Some devices will return invalid blocksizes. ie. Toshiba
	 * drives will return 2352 when an audio CD is inserted.
	 * Older Sun drives will use 512 byte block sizes. All newer
	 * drives should have 2k blocksizes.
	 */
	if (((dev->d_blksize != 512) && (dev->d_blksize != 2048))) {
			if (is_old_sun_drive(dev)) {
				dev->d_blksize = 512;
			} else {
				dev->d_blksize = 2048;
			}
		if (debug)
			(void) printf(" switching to %d\n", dev->d_blksize);
	}

	free(cap);
	if (user_supplied) {
		dev->d_name = (char *)my_zalloc(strlen(user_supplied) + 1);
		(void) strcpy(dev->d_name, user_supplied);
	}
	TRACE(traceall_msg("Got device %s\n", node));
	return (dev);
}

void
fini_device(cd_device *dev)
{
	free(dev->d_inq);
	free(dev->d_node);
	(void) close(dev->d_fd);
	if (dev->d_name)
		free(dev->d_name);
	free(dev);
}

/*
 * Given a /dev path resolve that path to a symbolic
 * name such as cdrom0 if hald is running. If hald is
 * not running, or does not have a symbolic name for the
 * the specified /dev path return NULL.
 */
static char *
hald_symname(char *path)
{
	LibHalContext *ctx = NULL;
	DBusError error;

	char **udi, *p = NULL;
	int ndevs = 0, i;

	/* Make sure hald is running */
	if (vol_running == 0)
		return (p);

	dbus_error_init(&error);

	if ((ctx = attach_to_hald()) == NULL)
		return (p);

	if ((udi = libhal_manager_find_device_string_match(ctx,
	    HAL_RDSK_PROP, path, &ndevs, &error)) == NULL)
		goto done;

	/* Look for the node that contains the valid (non-null) symdev */
	for (i = 0; i < ndevs; i++) {
		if ((p = libhal_device_get_property_string(ctx, udi[i],
		    HAL_SYMDEV_PROP, NULL)) != NULL)
			break;
		else
			libhal_free_string(p);
	}

done:
	if (udi != NULL)
		libhal_free_string_array(udi);
	if (dbus_error_is_set(&error))
		dbus_error_free(&error);
	detach_from_hald(ctx, HAL_INITIALIZED);
	return (p);
}

/*
 * Given a name resolve that name to a raw device in the case
 * that it is a symbolic name or just return what is given if
 * we are given a /dev path or hald is not running.
 */
static char *
hald_findname(char *symname)
{
	LibHalContext *ctx = NULL;
	DBusError error;

	char **udi, *path = NULL;
	int ndevs = 0, i;

	/* We already have a raw path just return that */
	if (symname[0] == '/')
		return (symname);

	/* Get the raw device from the hal record */
	if (vol_running != 0) {
		dbus_error_init(&error);

		if ((ctx = attach_to_hald()) == NULL)
			return (path);

		if ((udi = libhal_manager_find_device_string_match(ctx,
		    HAL_SYMDEV_PROP, symname, &ndevs,
		    &error)) == NULL)
			goto done;

		/*
		 * Loop over the returned UDIs to access the raw
		 * device path.
		 */
		for (i = 0; i < ndevs; i++) {
			if ((path = libhal_device_get_property_string(ctx,
			    udi[i], HAL_RDSK_PROP, NULL)) != NULL)
				break;
			else
				libhal_free_string(path);
		}

done:
		if (udi != NULL)
			libhal_free_string_array(udi);
		if (dbus_error_is_set(&error))
			dbus_error_free(&error);
		detach_from_hald(ctx, HAL_INITIALIZED);
		return (path);
	} else {
		return (NULL);
	}
}

static int
vol_name_to_dev_node(char *vname, char *found)
{
	struct stat statbuf;
	char *p1;
	int i;

	if (vname == NULL)
		return (0);

	p1 = hald_findname(vname);

	if (p1 == NULL)
		return (0);
	if (stat(p1, &statbuf) < 0) {
		libhal_free_string(p1);
		return (0);
	}
	if (S_ISDIR(statbuf.st_mode)) {
		for (i = 0; i < 16; i++) {
			(void) snprintf(found, PATH_MAX, "%s/s%d", p1, i);
			if (access(found, F_OK) >= 0)
				break;
		}
		if (i == 16) {
			libhal_free_string(p1);
			return (0);
		}
	} else {
		(void) strlcpy(found, p1, PATH_MAX);
	}
	libhal_free_string(p1);
	return (1);
}

/*
 * Builds an open()able device path from a user supplied node which can be
 * of the * form of /dev/[r]dsk/cxtxdx[sx] or cxtxdx[sx] or volmgt-name like
 * cdrom[n]
 * returns the path found in 'found' and returns 1. Otherwise returns 0.
 */
int
lookup_device(char *supplied, char *found)
{
	struct stat statbuf;
	int fd;
	char tmpstr[PATH_MAX];

	/* If everything is fine and proper, no need to analyze */
	if ((stat(supplied, &statbuf) == 0) && S_ISCHR(statbuf.st_mode) &&
	    ((fd = open(supplied, O_RDONLY|O_NDELAY)) >= 0)) {
		(void) close(fd);
		(void) strlcpy(found, supplied, PATH_MAX);
		return (1);
	}

	/*
	 * Hal only allows access to a device when the user is
	 * on the console, therefore if hal is running and we can't
	 * open the /dev/rdsk or /dev/removable-media/rdsk device
	 * file we will return 0 marking this device as not avaiable.
	 */
	if (fd < 0 && ((strncmp(supplied, "/dev/rdsk/", 10) == 0) ||
	    (strncmp(supplied, "/dev/removable-media/rdsk/", 26) == 0)))
		return (0);

	if ((strncmp(supplied, "/dev/dsk/", 9) == 0) ||
	    (strncmp(supplied, "/dev/removable-media/dsk/", 25) == 0)) {
		(void) snprintf(tmpstr, PATH_MAX, "/dev/rdsk/%s",
		    (char *)strrchr(supplied, '/'));

		if ((fd = open(tmpstr, O_RDONLY|O_NDELAY)) >= 0) {
			(void) close(fd);
			(void) strlcpy(found, supplied, PATH_MAX);
			return (1);
		}

		/* This device can't be opened mark it as unavailable. */
		return (0);
	}
	if ((strncmp(supplied, "cdrom", 5) != 0) &&
	    (strlen(supplied) < 32)) {
		(void) snprintf(tmpstr, sizeof (tmpstr), "/dev/rdsk/%s",
		    supplied);
		if (access(tmpstr, F_OK) < 0) {
			(void) strcat(tmpstr, "s2");
		}
		if ((fd = open(tmpstr, O_RDONLY|O_NDELAY)) >= 0) {
			(void) close(fd);
			(void) strlcpy(found, tmpstr, PATH_MAX);
			return (1);
		}

		/* This device can't be opened mark it as unavailable. */
		return (0);
	}
	return (vol_name_to_dev_node(supplied, found));
}

/*
 * Opens the device node name passed and returns 1 (true) if the
 * device is a CD.
 */

static int
is_cd(char *node)
{
	int fd;
	struct dk_cinfo cinfo;
	int ret = 1;

	fd = open(node, O_RDONLY|O_NDELAY);
	if (fd < 0) {
		ret = 0;
	} else if (ioctl(fd, DKIOCINFO, &cinfo) < 0) {
		ret = 0;
	} else if (cinfo.dki_ctype != DKC_CDROM) {
		ret = 0;
	}

	if (fd >= 0) {
		(void) close(fd);
	}
	return (ret);
}

static void
print_header(void)
{
	/* l10n_NOTE : Column spacing should be kept same */
	(void) printf(gettext("    Node	           Connected Device"));
	/* l10n_NOTE : Column spacing should be kept same */
	(void) printf(gettext("	           Device type\n"));
	(void) printf(
	    "----------------------+--------------------------------");
	(void) printf("+-----------------\n");
}

/*
 * returns the number of writers or CD/DVD-roms found and the path of
 * the first device found depending on the mode argument.
 * possible mode values are:
 * SCAN_ALL_CDS 	Scan all CD/DVD devices. Return first CD-RW found.
 * SCAN_WRITERS		Scan all CD-RW devices. Return first one found.
 * SCAN_LISTDEVS	List all devices found.
 */
int
scan_for_cd_device(int mode, cd_device **found)
{
	DIR *dir;
	struct dirent *dirent;
	char sdev[PATH_MAX], dev[PATH_MAX];
	cd_device *t_dev;
	int writers_found = 0;
	int header_printed = 0;
	int is_writer;
	int total_devices_found;

	TRACE(traceall_msg("scan_for_cd_devices (mode=%d) called\n", mode));

	if (mode) {
		(void) printf(gettext("Looking for CD devices...\n"));
	}

	dir = opendir("/dev/rdsk");
	if (dir == NULL)
		return (0);

	writers_found = 0;
	total_devices_found = 0;
	while ((dirent = readdir(dir)) != NULL) {
		if (dirent->d_name[0] == '.')
			continue;
		(void) snprintf(sdev, PATH_MAX, "/dev/rdsk/%s",
		    dirent->d_name);
		if (strcmp("s2", (char *)strrchr(sdev, 's')) != 0)
			continue;
		if (!lookup_device(sdev, dev))
			continue;
		if (!is_cd(dev))
			continue;
		if ((t_dev = get_device(NULL, dev)) == NULL) {
			continue;
		}
		total_devices_found++;

		is_writer = !(check_device(t_dev, CHECK_DEVICE_NOT_WRITABLE));

		if (is_writer) {
			writers_found++;

			if ((writers_found == 1) && (mode != SCAN_LISTDEVS)) {
				*found = t_dev;
			}

		} else if ((mode == SCAN_ALL_CDS) && (writers_found == 0) &&
		    (total_devices_found == 1) && found) {

			/* We found a CD-ROM or DVD-ROM */
			*found = t_dev;
		}

		if (mode == SCAN_LISTDEVS) {
			char *sn;

			sn = hald_symname(sdev);
			if (!header_printed) {
				print_header();
				header_printed = 1;
			}
			/* show vendor, model, firmware rev and device type */
			(void) printf(" %-21.21s| %.8s %.16s %.4s | %s%s\n",
			    sn ? sn : sdev, &t_dev->d_inq[8],
			    &t_dev->d_inq[16], &t_dev->d_inq[32],
			    gettext("CD Reader"),
			    is_writer ? gettext("/Writer") : "");
			if (sn)
				free(sn);
		}
		if ((found != NULL) && ((*found) != t_dev))
			fini_device(t_dev);
	}

	(void) closedir(dir);

	if ((mode & SCAN_WRITERS) || writers_found)
		return (writers_found);
	else
		return (total_devices_found);
}

/*
 * Check device for various conditions/capabilities
 * If EXIT_IF_CHECK_FAILED set in cond then it will also exit after
 * printing a message.
 */
int
check_device(cd_device *dev, int cond)
{
	uchar_t *disc_info, disc_status = 0, erasable = 0;
	uchar_t page_code[4];
	char *errmsg = NULL;

	if ((errmsg == NULL) && (cond & CHECK_TYPE_NOT_CDROM) &&
	    ((dev->d_inq[0] & 0x1f) != 5)) {
		errmsg =
		    gettext("Specified device does not appear to be a CDROM");
	}

	if ((errmsg == NULL) && (cond & CHECK_DEVICE_NOT_READY) &&
	    !test_unit_ready(dev->d_fd)) {
		errmsg = gettext("Device not ready");
	}

	/* Look at the capabilities page for this information */
	if ((errmsg == NULL) && (cond & CHECK_DEVICE_NOT_WRITABLE)) {
		if (!get_mode_page(dev->d_fd, 0x2a, 0, 4, page_code) ||
		    ((page_code[3] & 1) == 0)) {
			errmsg = gettext("Target device is not a CD writer");
		}
	}

	if ((errmsg == NULL) && (cond & CHECK_NO_MEDIA)) {
		if (!test_unit_ready(dev->d_fd) && (uscsi_status == 2) &&
		    ((RQBUFLEN - rqresid) >= 14) &&
		    ((SENSE_KEY(rqbuf) & 0x0f) == 2) && (ASC(rqbuf) == 0x3A) &&
		    ((ASCQ(rqbuf) == 0) || (ASCQ(rqbuf) == 1) ||
		    (ASCQ(rqbuf) == 2))) {
			/* medium not present */
			errmsg = gettext("No media in device");
		}
	}



	/* Issue READ DISC INFORMATION mmc command */
	if ((errmsg == NULL) && ((cond & CHECK_MEDIA_IS_NOT_BLANK) ||
	    (cond & CHECK_MEDIA_IS_NOT_WRITABLE) ||
	    (cond & CHECK_MEDIA_IS_NOT_ERASABLE))) {

		disc_info = (uchar_t *)my_zalloc(DISC_INFO_BLOCK_SIZE);
		if (!read_disc_info(dev->d_fd, disc_info)) {
			errmsg = gettext("Cannot obtain disc information");
		} else {
			disc_status = disc_info[2] & 0x03;
			erasable = disc_info[2] & 0x10;
		}
		free(disc_info);
		if (errmsg == NULL) {
			if (!erasable && (cond & CHECK_MEDIA_IS_NOT_ERASABLE))
				errmsg = gettext(
				    "Media in the device is not erasable");
			else if ((disc_status != 0) &&
			    (cond & CHECK_MEDIA_IS_NOT_BLANK))
				errmsg = gettext(
				    "Media in the device is not blank");
			else if ((disc_status == 2) &&
			    (cond & CHECK_MEDIA_IS_NOT_WRITABLE) &&
			    ((device_type != DVD_PLUS_W) &&
			    (device_type != DVD_PLUS)))
				errmsg = gettext(
				    "Media in the device is not writable");
		}
	}

	if (errmsg) {
		if (cond & EXIT_IF_CHECK_FAILED) {
			err_msg("%s.\n", errmsg);
			exit(1);
		}
		return (1);
	}
	return (0);
}

/*
 * Generic routine for writing whatever the next track is and taking
 * care of the progress bar. Mode tells the track type (audio or data).
 * Data from track is taken from the byte stream h
 */
void
write_next_track(int mode, bstreamhandle h)
{
	struct track_info *ti;
	struct trackio_error *te;
	off_t size;

	ti = (struct track_info *)my_zalloc(sizeof (*ti));
	if ((build_track_info(target, -1, ti) == 0) ||
	    ((ti->ti_flags & TI_NWA_VALID) == 0)) {
		if ((device_type == DVD_PLUS) || (device_type ==
		    DVD_PLUS_W)) {
			ti->ti_flags |= TI_NWA_VALID;
		} else {
			err_msg(gettext(
			    "Cannot get writable address for the media.\n"));
			exit(1);
		}
	}
	if (ti->ti_nwa != ti->ti_start_address) {
		err_msg(gettext(
		    "Media state is not suitable for this write mode.\n"));
		exit(1);
	}
	if (mode == TRACK_MODE_DATA) {
		if (!(ti->ti_track_mode & 4)) {
			/* Write track depends upon this bit */
			ti->ti_track_mode |= TRACK_MODE_DATA;
		}
	}
	size = 0;
	h->bstr_size(h, &size);
	h->bstr_rewind(h);
	te = (struct trackio_error *)my_zalloc(sizeof (*te));

	print_n_flush(gettext("Writing track %d..."), (int)ti->ti_track_no);
	init_progress();
	if (!write_track(target, ti, h, progress, size, te)) {
		if (te->err_type == TRACKIO_ERR_USER_ABORT) {
			(void) str_print(gettext("Aborted.\n"), progress_pos);
		} else {
			if (device_type != DVD_PLUS_W) {
			/* l10n_NOTE : 'failed' as in Writing Track...failed  */
				(void) str_print(gettext("failed.\n"),
				    progress_pos);
			}
		}
	}
	/* l10n_NOTE : 'done' as in "Writing track 1...done"  */
	(void) str_print(gettext("done.\n"), progress_pos);
	free(ti);
	free(te);
}

void
list(void)
{
	if (scan_for_cd_device(SCAN_LISTDEVS, NULL) == 0) {
		if (vol_running) {
			err_msg(gettext(
			    "No CD writers found, no media in the drive "
			    "or not on the console.\n"));
		} else {
			if (cur_uid != 0) {
				err_msg(gettext(
				    "Volume manager is not running.\n"));
				err_msg(gettext(
"Please start volume manager or run cdrw as root to access all devices.\n"));
			} else {
				err_msg(gettext("No CD writers found.\n"));
			}
		}
	}
	exit(0);
}

void
get_media_type(int fd)
{
	uchar_t *cap = (uchar_t *)my_zalloc(MMC_FTR_HDR_LEN);

	if (get_configuration(fd, MMC_FTR_PRFL_LIST,
	    MMC_FTR_HDR_LEN, cap)) {
		if (debug)
			(void) print_profile_list(fd);
		switch (read_scsi16(&cap[6])) {
			case 0x8: /* CD-ROM */
				if (debug)
					(void) printf("CD-ROM found\n");
				/*
				 * To avoid regression issues, treat as
				 * A cdrw, we will check the writable
				 * mode page to see if the media is
				 * actually writable.
				 */
				device_type = CD_RW;
				break;

			case 0x9: /* CD-R */
				if (debug)
					(void) printf("CD-R found\n");
				device_type = CD_RW;
				break;

			case 0x10: /* DVD-ROM */
				/*
				 * Have seen drives return DVD+RW media
				 * DVD-ROM, so try treating it as a DVD+RW
				 * profile. checking for writable media
				 * is done through mode page 5.
				 */
				if (debug)
					(void) printf("DVD-ROM found\n");
				device_type = DVD_PLUS_W;
				break;

			case 0xA: /* CD-RW */
				if (debug)
					(void) printf("CD-RW found\n");
				device_type = CD_RW;
				break;

			case 0x11: /* DVD-R */
				if (debug)
					(void) printf("DVD-R found\n");
				device_type = DVD_MINUS;
				break;

			case 0x12: /* DVD-RAM */
				if (debug)
					(void) printf("DVD-RAM found\n");
				/* treat as CD-RW, may be a legacy drive */
				device_type = CD_RW;
				break;

			case 0x13: /* DVD-RW restricted overwrite */
			case 0x14: /* DVD-RW sequential */
				if (debug)
					(void) printf("DVD-RW found\n");
				device_type = DVD_MINUS;
				break;

			case 0x1A: /* DVD+RW */
				if (debug)
					(void) printf("DVD+RW found\n");

				device_type = DVD_PLUS_W;
				break;
			case 0x1B: /* DVD+R */
				if (debug)
					(void) printf("DVD+R found\n");
				device_type = DVD_PLUS;
				break;

			default:
				if (debug)
					(void) printf(
					    "unknown drive found\n type = 0x%x",
					    cap[7]);
				/*
				 * Treat as CD_RW to avoid regression, may
				 * be a legacy drive.
				 */
				device_type = CD_RW;
		}
	}
	free(cap);
}

/* Translate a transfer rate (eg, KB/s) into a Speed (eg, "2X") */
uint_t
cdrw_bandwidth_to_x(uint_t rate)
{
	switch (device_type) {
	case DVD_PLUS_W:
	case DVD_MINUS:
	case DVD_PLUS:
		return (DVD_RATE_TO_X(rate));

	default:
	case CD_RW:
		return (CD_RATE_TO_X(rate));
	}
}

/* Translate a Speed (eg, "2X") into a transfer rate (eg, KB/s) */
uint_t
cdrw_x_to_bandwidth(uint_t x)
{
	switch (device_type) {
	case DVD_PLUS_W:
	case DVD_MINUS:
	case DVD_PLUS:
		return (DVD_X_TO_RATE(x));

	default:
	case CD_RW:
		return (CD_X_TO_RATE(x));
	}
}
