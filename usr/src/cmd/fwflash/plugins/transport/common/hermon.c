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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The reference for the functions in this file is the
 *
 *	Mellanox HCA Flash Programming Application Note
 * (Mellanox document number 2205AN) rev 1.45, 2007.
 * Chapter 4 in particular.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>

#include <sys/byteorder.h>

#include <libintl.h> /* for gettext(3c) */

#include <fwflash/fwflash.h>
#include "../../hdrs/hermon_ib.h"

char *devprefix = "/devices";
char drivername[] = "hermon\0";
char *devsuffix = ":devctl";

extern di_node_t rootnode;
extern int errno;
extern struct fw_plugin *self;
extern struct vrfyplugin *verifier;
extern int fwflash_debug;

/* required functions for this plugin */
int fw_readfw(struct devicelist *device, char *filename);
int fw_writefw(struct devicelist *device);
int fw_identify(int start);
int fw_devinfo();


/* helper functions */
static int cnx_identify(struct devicelist *thisdev);
static int cnx_get_guids(ib_cnx_encap_ident_t *handle);
static int cnx_close(struct devicelist *flashdev);
static int cnx_check_for_magic_pattern(ib_cnx_encap_ident_t *hdl, uint32_t adr);
static uint32_t cnx_get_log2_chunk_size_f_hdl(ib_cnx_encap_ident_t *handle,
    int type);
static uint32_t cnx_get_log2_chunk_size(uint32_t chunk_size_word);
static uint32_t cnx_cont2phys(uint32_t log2_chunk_sz, uint32_t cont_addr,
    int type);
static uint32_t cnx_get_image_size_f_hdl(ib_cnx_encap_ident_t *hdl, int type);
static void cnx_local_set_guid_crc_img(uint32_t offset, uint32_t guid_crc_size,
    uint32_t guid_crc_offset);
static int cnx_read_image(ib_cnx_encap_ident_t *handle);
static int cnx_write_file(ib_cnx_encap_ident_t *handle, const char *filename);
static int cnx_verify_image(ib_cnx_encap_ident_t *handle, int type);
static int cnx_read_guids(ib_cnx_encap_ident_t *handle, int type);
static int cnx_set_guids(ib_cnx_encap_ident_t *handle, void *arg);
static int cnx_write_image(ib_cnx_encap_ident_t *handle, int type);
static int cnx_read_ioctl(ib_cnx_encap_ident_t *hdl,
    hermon_flash_ioctl_t *info);
static int cnx_write_ioctl(ib_cnx_encap_ident_t *hdl,
    hermon_flash_ioctl_t *info);
static int cnx_erase_sector_ioctl(ib_cnx_encap_ident_t *hdl,
    hermon_flash_ioctl_t *info);
static int cnx_find_magic_n_chnk_sz(ib_cnx_encap_ident_t *handle, int type);
static int cnx_get_image_info(ib_cnx_encap_ident_t *handle);


int
fw_readfw(struct devicelist *flashdev, char *filename)
{
	ib_cnx_encap_ident_t	*manuf;
	int 			rv = FWFLASH_SUCCESS;

	logmsg(MSG_INFO, "hermon: fw_readfw: filename %s\n", filename);

	manuf = (ib_cnx_encap_ident_t *)flashdev->ident->encap_ident;
	if (CNX_I_CHECK_HANDLE(manuf)) {
		logmsg(MSG_ERROR, gettext("hermon: Invalid Handle for "
		    "device %s! \n"), flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	logmsg(MSG_INFO, "hermon: fw_identify should have read the image. "
	    "state 0x%x\n", manuf->state);

	rv = cnx_read_image(manuf);
	if (rv != FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR, gettext("hermon: Failed to read any valid "
		    "image on device (%s)\n"), flashdev->access_devname);
		logmsg(MSG_ERROR, gettext("Aborting read.\n"));
	} else {
		rv = cnx_write_file(manuf, filename);
	}

	cnx_close(flashdev);
	return (rv);
}


/*
 * If we're invoking fw_writefw, then flashdev is a valid,
 * flashable device as determined by fw_identify().
 *
 * If verifier is null, then we haven't been called following a firmware
 * image verification load operation.
 */
int
fw_writefw(struct devicelist *flashdev)
{
	ib_cnx_encap_ident_t	*manuf;
	int			i, j, k;

	logmsg(MSG_INFO, "hermon: fw_writefw\n");

	manuf = (ib_cnx_encap_ident_t *)flashdev->ident->encap_ident;

	if (CNX_I_CHECK_HANDLE(manuf)) {
		logmsg(MSG_ERROR, gettext("hermon: Invalid Handle for "
		    "device %s! \n"), flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	/*
	 * Try the primary first, then the secondary.
	 * If we get here, then the verifier has _already_ checked that
	 * the part number in the firmware image matches that in the HCA,
	 * so we only need this check if there's no hardware info available
	 * already after running through fw_identify().
	 */
	if (manuf->pn_len == 0) {
		int resp;

		(void) fprintf(stderr, gettext("Unable to completely verify "
		    "that this firmware image (%s) is compatible with your "
		    "HCA %s"), verifier->imgfile, flashdev->access_devname);
		(void) fprintf(stderr, gettext("Do you really want to "
		    "continue? (Y/N): "));
		(void) fflush(stdin);
		resp = getchar();
		if (resp != 'Y' && resp != 'y') {
			(void) fprintf(stderr, gettext("Not proceeding with "
			    "flash operation of %s on %s"),
			    verifier->imgfile, flashdev->access_devname);
			return (FWFLASH_FAILURE);
		}
	}

	logmsg(MSG_INFO, "hermon: fw_writefw: Using Existing GUIDs.\n");
	manuf->state |=
	    FWFLASH_IB_STATE_GUIDN |
	    FWFLASH_IB_STATE_GUID1 |
	    FWFLASH_IB_STATE_GUID2 |
	    FWFLASH_IB_STATE_GUIDS;
	if (cnx_set_guids(manuf, manuf->ibguids) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: Failed to set GUIDs"));
	}

	/*
	 * Update both Primary and Secondary images
	 *
	 * For Failsafe firmware image update, if the current image (i.e.
	 * containing a magic pattern) on the Flash is stored on the Primary
	 * location, burn the new image to the Secondary location first,
	 * or vice versa.
	 */

	/* Note Current Image location. */
	j = manuf->state &
	    (FWFLASH_IB_STATE_IMAGE_PRI | FWFLASH_IB_STATE_IMAGE_SEC);

	/*
	 * If we find that current image location is not found, no worries
	 * we shall default to PRIMARY, and proceed with burning anyway.
	 */
	if (j == 0)
		j = FWFLASH_IB_STATE_IMAGE_PRI;

	for (i = FWFLASH_FLASH_IMAGES; i > 0; i--) {
		char *type;

		if (i == 2) {
			if (j == 2)
				k = 1;	/* Burn PRI First */
			else
				k = 2;	/* Burn SEC First */
		} else {
			if (k == 2)
				k = 1;	/* Burn PRI next */
			else
				k = 2;	/* Burn SEC next */
		}
		type = ((k == 1) ? "Primary" : "Secondary");

		logmsg(MSG_INFO, "hermon: fw_write: UPDATING %s image\n", type);

		if (cnx_write_image(manuf, k) != FWFLASH_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("Failed to update %s image on device %s"),
			    type, flashdev->access_devname);
			goto out;
		}

		logmsg(MSG_INFO, "hermon: fw_write: Verify %s image..\n", type);
		if (cnx_verify_image(manuf, k) != FWFLASH_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("Failed to verify %s image for device %s"),
			    type, flashdev->access_devname);
			goto out;
		}
	}
out:
	/* final update marker to the user */
	(void) printf(" +\n");
	return (cnx_close(flashdev));
}


/*
 * The fw_identify() function walks the device tree trying to find
 * devices which this plugin can work with.
 *
 * The parameter "start" gives us the starting index number
 * to give the device when we add it to the fw_devices list.
 *
 * firstdev is allocated by us and we add space as necessary
 */
int
fw_identify(int start)
{
	int		rv = FWFLASH_FAILURE;
	di_node_t	thisnode;
	struct devicelist *newdev;
	char		*devpath;
	int		idx = start;
	int		devlength = 0;

	logmsg(MSG_INFO, "hermon: fw_identify\n");
	thisnode = di_drv_first_node(drivername, rootnode);

	if (thisnode == DI_NODE_NIL) {
		logmsg(MSG_INFO, gettext("No %s nodes in this system\n"),
		    drivername);
		return (rv);
	}

	/* we've found one, at least */
	for (; thisnode != DI_NODE_NIL; thisnode = di_drv_next_node(thisnode)) {

		devpath = di_devfs_path(thisnode);

		if ((newdev = calloc(1, sizeof (struct devicelist))) == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: Unable to allocate "
			    "space for device entry\n"));
			di_devfs_path_free(devpath);
			return (FWFLASH_FAILURE);
		}

		/* calloc enough for /devices + devpath + ":devctl" + '\0' */
		devlength = strlen(devpath) + strlen(devprefix) +
		    strlen(devsuffix) + 2;

		if ((newdev->access_devname = calloc(1, devlength)) == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: Unable to allocate "
			    "space for a devfs name\n"));
			(void) free(newdev);
			di_devfs_path_free(devpath);
			return (FWFLASH_FAILURE);
		}
		snprintf(newdev->access_devname, devlength,
		    "%s%s%s", devprefix, devpath, devsuffix);

		if ((newdev->ident = calloc(1, sizeof (struct vpr))) == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: Unable to allocate "
			    "space for a device identification record\n"));
			(void) free(newdev->access_devname);
			(void) free(newdev);
			di_devfs_path_free(devpath);
			return (FWFLASH_FAILURE);
		}

		/* CHECK VARIOUS IB THINGS HERE */
		rv = cnx_identify(newdev);
		if (rv == FWFLASH_FAILURE) {
			(void) free(newdev->ident);
			(void) free(newdev->access_devname);
			(void) free(newdev);
			di_devfs_path_free(devpath);
			continue;
		}

		if ((newdev->drvname = calloc(1, strlen(drivername) + 1))
		    == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: Unable to allocate"
			    " space for a driver name\n"));
			(void) free(newdev->ident);
			(void) free(newdev->access_devname);
			(void) free(newdev);
			di_devfs_path_free(devpath);
			return (FWFLASH_FAILURE);
		}

		(void) strlcpy(newdev->drvname, drivername,
		    strlen(drivername) + 1);

		/* this next bit is backwards compatibility - "IB\0" */
		if ((newdev->classname = calloc(1, 3)) == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: Unable to allocate "
			    "space for a class name\n"));
			(void) free(newdev->drvname);
			(void) free(newdev->ident);
			(void) free(newdev->access_devname);
			(void) free(newdev);
			di_devfs_path_free(devpath);
			return (FWFLASH_FAILURE);
		}
		(void) strlcpy(newdev->classname, "IB", 3);

		newdev->index = idx;
		++idx;
		newdev->plugin = self;

		di_devfs_path_free(devpath);

		TAILQ_INSERT_TAIL(fw_devices, newdev, nextdev);
	}

	if (fwflash_debug != 0) {
		struct devicelist *tempdev;

		TAILQ_FOREACH(tempdev, fw_devices, nextdev) {
			logmsg(MSG_INFO, "fw_identify: hermon:\n");
			logmsg(MSG_INFO, "\ttempdev @ 0x%lx\n"
			    "\t\taccess_devname: %s\n"
			    "\t\tdrvname: %s\tclassname: %s\n"
			    "\t\tident->vid:   %s\n"
			    "\t\tident->pid:   %s\n"
			    "\t\tident->revid: %s\n"
			    "\t\tindex: %d\n"
			    "\t\tguid0: %s\n"
			    "\t\tguid1: %s\n"
			    "\t\tguid2: %s\n"
			    "\t\tguid3: %s\n"
			    "\t\tplugin @ 0x%lx\n\n",
			    &tempdev,
			    tempdev->access_devname,
			    tempdev->drvname, newdev->classname,
			    tempdev->ident->vid,
			    tempdev->ident->pid,
			    tempdev->ident->revid,
			    tempdev->index,
			    (tempdev->addresses[0] ? tempdev->addresses[0] :
			    "(not supported)"),
			    (tempdev->addresses[1] ? tempdev->addresses[1] :
			    "(not supported)"),
			    (tempdev->addresses[2] ? tempdev->addresses[2] :
			    "(not supported)"),
			    (tempdev->addresses[3] ? tempdev->addresses[3] :
			    "(not supported)"),
			    tempdev->plugin);
		}
	}

	return (FWFLASH_SUCCESS);
}


int
fw_devinfo(struct devicelist *thisdev)
{
	ib_cnx_encap_ident_t	*encap;

	logmsg(MSG_INFO, "hermon: fw_devinfo\n");

	encap = (ib_cnx_encap_ident_t *)thisdev->ident->encap_ident;
	if (CNX_I_CHECK_HANDLE(encap)) {
		logmsg(MSG_ERROR, gettext("hermon: fw_devinfo: Invalid handle "
		    "for device %s! \n"), thisdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	/* Try the primary first, then the secondary */
	fprintf(stdout, gettext("Device[%d] %s\n"),
	    thisdev->index, thisdev->access_devname);
	fprintf(stdout, gettext("Class [%s]\n"), thisdev->classname);

	fprintf(stdout, "\t");

	/* Mellanox HCA Flash app note, p40, #4.2.3 table 9 */
	fprintf(stdout, gettext("GUID: System Image - %s\n"),
	    thisdev->addresses[3]);
	fprintf(stdout, gettext("\t\tNode Image - %s\n"),
	    thisdev->addresses[0]);
	fprintf(stdout, gettext("\t\tPort 1\t   - %s\n"),
	    thisdev->addresses[1]);
	fprintf(stdout, gettext("\t\tPort 2\t   - %s\n"),
	    thisdev->addresses[2]);

	fprintf(stdout, gettext("\tFirmware revision  : %s\n"),
	    thisdev->ident->revid);

	if (encap->pn_len != 0) {
		if (strlen(encap->info.mlx_id))
			fprintf(stdout, gettext("\tProduct\t\t   : "
			    "%s %X (%s)\n"), encap->info.mlx_pn,
			    encap->hwrev, encap->info.mlx_id);
		else
			fprintf(stdout, gettext("\tProduct\t\t   : %s %X\n"),
			    encap->info.mlx_pn, encap->hwrev);

		if (strlen(encap->info.mlx_psid))
			fprintf(stdout, gettext("\tPSID\t\t   : %s\n"),
			    encap->info.mlx_psid);
		else if (strlen(thisdev->ident->pid))
			fprintf(stdout, gettext("\t%s\n"), thisdev->ident->pid);
	} else {
		fprintf(stdout, gettext("\t%s\n"), thisdev->ident->pid);
	}
	fprintf(stdout, "\n\n");

	return (cnx_close(thisdev));
}


/*
 * Helper functions lurk beneath this point
 */


/*
 * Notes:
 * 1. flash read is done in 32 bit quantities, and the driver returns
 *    data in host byteorder form.
 * 2. flash write is done in 8 bit quantities by the driver.
 * 3. data in the flash should be in network byteorder.
 * 4. data in image files is in network byteorder form.
 * 5. data in image structures in memory is kept in network byteorder.
 * 6. the functions in this file deal with data in host byteorder form.
 */

static int
cnx_read_image(ib_cnx_encap_ident_t *handle)
{
	hermon_flash_ioctl_t	ioctl_info;
	uint32_t		phys_addr;
	int			ret, i;
	int			image_size;
	int			type;

	type = handle->state &
	    (FWFLASH_IB_STATE_IMAGE_PRI | FWFLASH_IB_STATE_IMAGE_SEC);
	logmsg(MSG_INFO, "cnx_read_image: type %lx\n", type);

	if (type == 0) {
		logmsg(MSG_ERROR, gettext("cnx_read_image: Must read in "
		    "image first\n"));
		return (FWFLASH_FAILURE);
	}

	image_size = handle->fw_sz;
	if (image_size <= 0) {
		logmsg(MSG_ERROR, gettext("cnx_read_image: Invalid image size "
		    "0x%x for %s image\n"),
		    image_size, (type == 0x1 ? "Primary" : "Secondary"));
		return (FWFLASH_FAILURE);
	}

	logmsg(MSG_INFO, "hermon: fw_size: 0x%x\n", image_size);

	handle->fw = (uint32_t *)calloc(1, image_size);
	if (handle->fw == NULL) {
		logmsg(MSG_ERROR, gettext("cnx_read_image: Unable to allocate "
		    "memory for fw_img : (%s)\n"), strerror(errno));
		return (FWFLASH_FAILURE);
	}

	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;
	for (i = 0; i < image_size; i += 4) {
		phys_addr = cnx_cont2phys(handle->log2_chunk_sz, i, type);
		ioctl_info.af_addr = phys_addr;

		ret = cnx_read_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			logmsg(MSG_ERROR, gettext("cnx_read_image: Failed to "
			    "read sector %d\n"), i);
			free(handle->fw);
			return (FWFLASH_FAILURE);
		}
		handle->fw[i / 4] = htonl(ioctl_info.af_quadlet);
	}

	for (i = 0; i < image_size; i += 4) {
		logmsg(MSG_INFO, "cnx_read_image: addr[0x%x] = 0x%08x\n", i,
		    ntohl(handle->fw[i / 4]));
	}

	return (FWFLASH_SUCCESS);
}

static int
cnx_write_file(ib_cnx_encap_ident_t *handle, const char *filename)
{
	FILE		*fp;
	int 		fd;
	mode_t		mode = S_IRUSR | S_IWUSR;
	int		len;

	logmsg(MSG_INFO, "cnx_write_file\n");

	errno = 0;
	if ((fd = open(filename, O_RDWR|O_CREAT|O_DSYNC, mode)) < 0) {
		logmsg(MSG_ERROR, gettext("hermon: Unable to open specified "
		    "file (%s) for writing: %s\n"), filename, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	errno = 0;
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		(void) fprintf(stderr, gettext("hermon: Unknown filename %s : "
		    "%s\n"), filename, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	len = ntohl(handle->fw[CNX_IMG_SIZE_OFFSET / 4]);
	logmsg(MSG_INFO, "cnx_write_file: Writing to file. Length 0x%x\n", len);

	if (fwrite(&handle->fw[0], len, 1, fp) == 0) {
		(void) fprintf(stderr, gettext("hermon: fwrite failed"));
		perror("fwrite");
		(void) fclose(fp);
		return (FWFLASH_FAILURE);
	}
	(void) fclose(fp);
	return (FWFLASH_SUCCESS);
}

static int
cnx_verify_image(ib_cnx_encap_ident_t *handle, int type)
{
	uint32_t	new_start_addr;

	logmsg(MSG_INFO, "hermon: cnx_verify_image\n");

	new_start_addr = cnx_cont2phys(handle->log2_chunk_sz, 0, type);

	return (cnx_check_for_magic_pattern(handle, new_start_addr));
}

static int
cnx_set_guids(ib_cnx_encap_ident_t *handle, void *arg)
{
	uint32_t	addr;
	uint32_t	*guids;

	logmsg(MSG_INFO, "hermon: cnx_set_guids\n");

	guids = (uint32_t *)arg;
	addr = ntohl(verifier->fwimage[CNX_NGUIDPTR_OFFSET / 4]) / 4;
	logmsg(MSG_INFO, "cnx_set_guids: guid_start_addr: 0x%x\n", addr * 4);

	/*
	 * guids are supplied by callers as 64 bit values in host byteorder.
	 * Storage is in network byteorder.
	 */
#ifdef _BIG_ENDIAN
	if (handle->state & FWFLASH_IB_STATE_GUIDN) {
		verifier->fwimage[addr] = guids[0];
		verifier->fwimage[addr + 1] = guids[1];
	}

	if (handle->state & FWFLASH_IB_STATE_GUID1) {
		verifier->fwimage[addr + 2] = guids[2];
		verifier->fwimage[addr + 3] = guids[3];
	}

	if (handle->state & FWFLASH_IB_STATE_GUID2) {
		verifier->fwimage[addr + 4] = guids[4];
		verifier->fwimage[addr + 5] = guids[5];
	}

	if (handle->state & FWFLASH_IB_STATE_GUIDS) {
		verifier->fwimage[addr + 6] = guids[6];
		verifier->fwimage[addr + 7] = guids[7];
	}
#else
	if (handle->state & FWFLASH_IB_STATE_GUIDN) {
		verifier->fwimage[addr] = htonl(guids[1]);
		verifier->fwimage[addr + 1] = htonl(guids[0]);
	}

	if (handle->state & FWFLASH_IB_STATE_GUID1) {
		verifier->fwimage[addr + 2] = htonl(guids[3]);
		verifier->fwimage[addr + 3] = htonl(guids[2]);
	}

	if (handle->state & FWFLASH_IB_STATE_GUID2) {
		verifier->fwimage[addr + 4] = htonl(guids[5]);
		verifier->fwimage[addr + 5] = htonl(guids[4]);
	}

	if (handle->state & FWFLASH_IB_STATE_GUIDS) {
		verifier->fwimage[addr + 6] = htonl(guids[7]);
		verifier->fwimage[addr + 7] = htonl(guids[6]);
	}
#endif

	cnx_local_set_guid_crc_img((addr * 4) - 0x10, CNX_GUID_CRC16_SIZE,
	    CNX_GUID_CRC16_OFFSET);

	return (FWFLASH_SUCCESS);
}

/*
 * Notes: Burn the image
 *
 * 1. Erase the entire sector where the new image is to be burned.
 * 2. Burn the image WITHOUT the magic pattern. This marks the new image
 *    as invalid during the burn process. If the current image (i.e
 *    containing a magic pattern) on the Flash is stored on the even
 *    chunks (PRIMARY), burn the new image to the odd chunks (SECONDARY),
 *    or vice versa.
 * 3. Burn the magic pattern at the beginning of the new image on the Flash.
 *    This will validate the new image.
 * 4. Set the BootAddress register to its new location.
 */
static int
cnx_write_image(ib_cnx_encap_ident_t *handle, int type)
{
	hermon_flash_ioctl_t	ioctl_info;
	int			sector_size;
	int			size;
	int			i;
	uint32_t		new_start_addr;
	uint32_t		log2_chunk_sz;
	uint8_t			*fw;

	logmsg(MSG_INFO, "hermon: cnx_write_image\n");

	if (type == 0) {
		logmsg(MSG_ERROR, gettext("cnx_write_image: Must inform us "
		    " where to write.\n"));
		return (FWFLASH_FAILURE);
	}

	log2_chunk_sz = cnx_get_log2_chunk_size(
	    ntohl(verifier->fwimage[CNX_CHUNK_SIZE_OFFSET / 4]));

	sector_size = handle->sector_sz;
	new_start_addr = ((type - 1) << handle->log2_chunk_sz);

	/* Read Image Size */
	size = ntohl(verifier->fwimage[CNX_IMG_SIZE_OFFSET / 4]);
	logmsg(MSG_INFO, "cnx_write_image: fw image size: 0x%x\n", size);

	/* Sectors must be erased before they can be written to. */
	ioctl_info.af_type = HERMON_FLASH_ERASE_SECTOR;
	for (i = 0; i < size; i += sector_size) {
		ioctl_info.af_sector_num =
		    cnx_cont2phys(log2_chunk_sz, i, type) / sector_size;
		if (cnx_erase_sector_ioctl(handle, &ioctl_info) != 0) {
			logmsg(MSG_ERROR, gettext("cnx_write_image: Failed to "
			    "erase sector 0x%x\n"), ioctl_info.af_sector_num);
			return (FWFLASH_FAILURE);
		}
	}

	fw = (uint8_t *)verifier->fwimage;
	ioctl_info.af_type = HERMON_FLASH_WRITE_BYTE;

	/* Write the new image without the magic pattern */
	for (i = 16; i < size; i++) {
		ioctl_info.af_byte = fw[i];
		ioctl_info.af_addr = cnx_cont2phys(log2_chunk_sz, i, type);
		if (cnx_write_ioctl(handle, &ioctl_info) != 0) {
			logmsg(MSG_ERROR, gettext("cnx_write_image: Failed to "
			    "write byte 0x%x\n"), ioctl_info.af_byte);
			return (FWFLASH_FAILURE);
		}

		if (i && !(i % handle->sector_sz)) {
			(void) printf(" .");
			(void) fflush((void *)NULL);
		}
	}

	/* Validate the new image -- Write the magic pattern. */
	for (i = 0; i < 16; i++) {
		ioctl_info.af_byte = fw[i];
		ioctl_info.af_addr = cnx_cont2phys(log2_chunk_sz, i, type);
		if (cnx_write_ioctl(handle, &ioctl_info) != 0) {
			logmsg(MSG_ERROR, gettext("cnx_write_image: Failed to "
			    "write magic pattern byte 0x%x\n"),
			    ioctl_info.af_byte);
			return (FWFLASH_FAILURE);
		}
	}

	/* Write new image start address to CR space */
	errno = 0;
	ioctl_info.af_addr = new_start_addr;
	if (ioctl(handle->fd, HERMON_IOCTL_WRITE_BOOT_ADDR, &ioctl_info) != 0) {
		logmsg(MSG_WARN, gettext("cnx_write_image: Failed to "
		    "update boot address register: %s\n"), strerror(errno));
	}

	return (FWFLASH_SUCCESS);
}


/*
 * cnx_identify performs the following actions:
 *
 *	allocates and assigns thisdev->vpr
 *
 *	allocates space for the 4 GUIDs which each IB device must have
 *	queries the hermon driver for this device's GUIDs
 *
 *	determines the hardware vendor, so that thisdev->vpr->vid
 *	can be set correctly
 */
static int
cnx_identify(struct devicelist *thisdev)
{
	int				fd, ret, i;
	hermon_flash_init_ioctl_t	init_ioctl;
	ib_cnx_encap_ident_t		*manuf;
	cfi_t				cfi;
	int				hw_psid_found = 0;

	logmsg(MSG_INFO, "hermon: cnx_identify\n");
	/* open the device */
	/* hook thisdev->ident->encap_ident to ib_cnx_encap_ident_t */
	/* check that all the bits are sane */
	/* return success, if warranted */

	errno = 0;
	if ((fd = open(thisdev->access_devname, O_RDONLY)) < 0) {
		logmsg(MSG_ERROR, gettext("hermon: Unable to open a %s-"
		    "attached device node: %s: %s\n"), drivername,
		    thisdev->access_devname, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	if ((manuf = calloc(1, sizeof (ib_cnx_encap_ident_t))) == NULL) {
		logmsg(MSG_ERROR, gettext("hermon: Unable to allocate space "
		    "for a %s-attached handle structure\n"), drivername);
		close(fd);
		return (FWFLASH_FAILURE);
	}
	manuf->magic = FWFLASH_IB_MAGIC_NUMBER;
	manuf->state = FWFLASH_IB_STATE_NONE;
	manuf->fd = fd;
	manuf->log2_chunk_sz = 0;

	thisdev->ident->encap_ident = manuf;

	/*
	 * Inform driver that this command supports the Intel Extended
	 * CFI command set.
	 */
	cfi.cfi_char[0x10] = 'M';
	cfi.cfi_char[0x11] = 'X';
	cfi.cfi_char[0x12] = '2';
	init_ioctl.af_cfi_info[0x4] = ntohl(cfi.cfi_int[0x4]);

	errno = 0;
	ret = ioctl(fd, HERMON_IOCTL_FLASH_INIT, &init_ioctl);
	if (ret < 0) {
		logmsg(MSG_ERROR, gettext("hermon: HERMON_IOCTL_FLASH_INIT "
		    "failed: %s\n"), strerror(errno));
		close(fd);
		free(manuf);
		return (FWFLASH_FAILURE);
	}

	manuf->hwrev = init_ioctl.af_hwrev;
	logmsg(MSG_INFO, "hermon: init_ioctl: hwrev: %x, fwver: %d.%d.%04d, "
	    "PN# Len %d\n", init_ioctl.af_hwrev, init_ioctl.af_fwrev.afi_maj,
	    init_ioctl.af_fwrev.afi_min, init_ioctl.af_fwrev.afi_sub,
	    init_ioctl.af_pn_len);

	/*
	 * Determine whether the attached driver supports the Intel or
	 * AMD Extended CFI command sets. If it doesn't support either,
	 * then we're hosed, so error out.
	 */
	for (i = 0; i < HERMON_FLASH_CFI_SIZE_QUADLET; i++) {
		cfi.cfi_int[i] = ntohl(init_ioctl.af_cfi_info[i]);
	}
	manuf->cmd_set = cfi.cfi_char[0x13];

	if (cfi.cfi_char[0x10] == 'Q' &&
	    cfi.cfi_char[0x11] == 'R' &&
	    cfi.cfi_char[0x12] == 'Y') {
		/* make sure the cmd set is SPI */
		if (manuf->cmd_set != HERMON_FLASH_SPI_CMDSET) {
			logmsg(MSG_ERROR, gettext("hermon: Unsupported flash "
			    "device command set\n"));
			goto identify_end;
		}
		/* set some defaults */
		manuf->sector_sz = HERMON_FLASH_SECTOR_SZ_DEFAULT;
		manuf->device_sz = HERMON_FLASH_DEVICE_SZ_DEFAULT;
	} else if (manuf->cmd_set == HERMON_FLASH_SPI_CMDSET) {
		manuf->sector_sz = HERMON_FLASH_SPI_SECTOR_SIZE;
		manuf->device_sz = HERMON_FLASH_SPI_DEVICE_SIZE;
	} else {
		if (manuf->cmd_set != HERMON_FLASH_AMD_CMDSET &&
		    manuf->cmd_set != HERMON_FLASH_INTEL_CMDSET) {
			logmsg(MSG_ERROR, gettext("hermon: Unknown flash "
			    "device command set %lx\n"), manuf->cmd_set);
			goto identify_end;
		}
		/* read from the CFI data */
		manuf->sector_sz = ((cfi.cfi_char[0x30] << 8) |
		    cfi.cfi_char[0x2F]) << 8;
		manuf->device_sz = 0x1 << cfi.cfi_char[0x27];
	}

	logmsg(MSG_INFO, "hermon: sector_sz: 0x%08x device_sz: 0x%08x\n",
	    manuf->sector_sz, manuf->device_sz);

	/* set firmware revision */
	manuf->hwfw_img_info.fw_rev.major = init_ioctl.af_fwrev.afi_maj;
	manuf->hwfw_img_info.fw_rev.minor = init_ioctl.af_fwrev.afi_min;
	manuf->hwfw_img_info.fw_rev.subminor = init_ioctl.af_fwrev.afi_sub;

	if (((thisdev->ident->vid = calloc(1, MLX_VPR_VIDLEN + 1)) == NULL) ||
	    ((thisdev->ident->revid = calloc(1, MLX_VPR_REVLEN + 1)) == NULL)) {
		logmsg(MSG_ERROR, gettext("hermon: Unable to allocate space "
		    "for a VPR record.\n"));
		goto identify_end;
	}
	(void) strlcpy(thisdev->ident->vid, "MELLANOX", MLX_VPR_VIDLEN);

	/*
	 * We actually want the hwrev field from the ioctl above.
	 * Until we find out otherwise, add it onto the end of the
	 * firmware version details.
	 */
	snprintf(thisdev->ident->revid, MLX_VPR_REVLEN, "%d.%d.%03d",
	    manuf->hwfw_img_info.fw_rev.major,
	    manuf->hwfw_img_info.fw_rev.minor,
	    manuf->hwfw_img_info.fw_rev.subminor);

	if ((ret = cnx_get_guids(manuf)) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: No GUIDs found for "
		    "device %s!\n"), thisdev->access_devname);
	}

	/* set hw part number, psid, and name in handle */
	/* now walk the magic decoder ring table */
	manuf->info.mlx_pn = NULL;
	manuf->info.mlx_psid = NULL;
	manuf->info.mlx_id = NULL;

	if (cnx_get_image_info(manuf) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: Failed to read Image Info "
		    "for PSID\n"));
		hw_psid_found = 0;
	} else {
		hw_psid_found = 1;
	}

	if (init_ioctl.af_pn_len != 0) {
		/* part number length */
		for (i = 0; i < init_ioctl.af_pn_len; i++) {
			if (init_ioctl.af_hwpn[i] == ' ') {
				manuf->pn_len = i;
				break;
			}
		}
		if (i == init_ioctl.af_pn_len) {
			manuf->pn_len = init_ioctl.af_pn_len;
		}
	} else {
		logmsg(MSG_INFO, "hermon: Failed to get Part# from hermon "
		    "driver \n");
		manuf->pn_len = 0;
	}

	if (manuf->pn_len != 0) {
		errno = 0;
		manuf->info.mlx_pn = calloc(1, manuf->pn_len);
		if (manuf->info.mlx_pn == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: no space available "
			    "for the HCA PN record (%s)\n"), strerror(errno));
			goto identify_end;
		}
		(void) memcpy(manuf->info.mlx_pn, init_ioctl.af_hwpn,
		    manuf->pn_len);
		manuf->info.mlx_pn[manuf->pn_len] = 0;

		logmsg(MSG_INFO, "hermon: HCA PN (%s) PN-Len %d\n",
		    manuf->info.mlx_pn, manuf->pn_len);

		errno = 0;
		manuf->info.mlx_psid = calloc(1, MLX_PSID_SZ);
		if (manuf->info.mlx_psid == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: PSID calloc "
			    "failed :%s\n"), strerror(errno));
			goto identify_end;
		}

		errno = 0;
		if ((manuf->info.mlx_id = calloc(1, MLX_STR_ID_SZ)) == NULL) {
			logmsg(MSG_ERROR, gettext("hermon: "
			    "ID calloc failed (%s)\n"),
			    strerror(errno));
			goto identify_end;
		}

		/* Find part number, set the rest */
		for (i = 0; i < MLX_MAX_ID; i++) {
			if (strncmp((const char *)init_ioctl.af_hwpn,
			    mlx_mdr[i].mlx_pn, manuf->pn_len) == 0) {

				if (hw_psid_found) {
					logmsg(MSG_INFO, "HW-PSID: %s "
					    "MLX_MDR[%d]: %s\n",
					    manuf->hwfw_img_info.psid, i,
					    mlx_mdr[i].mlx_psid);
					if (strncmp((const char *)
					    manuf->hwfw_img_info.psid,
					    mlx_mdr[i].mlx_psid,
					    MLX_PSID_SZ) != 0)
						continue;
				}
				/* Set PSID */
				(void) memcpy(manuf->info.mlx_psid,
				    mlx_mdr[i].mlx_psid, MLX_PSID_SZ);
				manuf->info.mlx_psid[MLX_PSID_SZ - 1] = 0;

				logmsg(MSG_INFO, "hermon: HCA PSID (%s)\n",
				    manuf->info.mlx_psid);

				(void) strlcpy(manuf->info.mlx_id,
				    mlx_mdr[i].mlx_id,
				    strlen(mlx_mdr[i].mlx_id) + 1);

				logmsg(MSG_INFO, "hermon: HCA Name (%s)\n",
				    manuf->info.mlx_id);

				break;
			}
		}
	}

	if ((manuf->pn_len == 0) || (i == MLX_MAX_ID)) {
		logmsg(MSG_INFO, "hermon: No hardware part number "
		    "information available for this HCA\n");

		i = strlen("No hardware information available for this device");

		thisdev->ident->pid = calloc(1, i + 2);
		sprintf(thisdev->ident->pid, "No additional hardware info "
		    "available for this device");
	} else {
		errno = 0;
		if ((thisdev->ident->pid = calloc(1,
		    strlen(manuf->info.mlx_psid) + 1)) != NULL) {
			(void) strlcpy(thisdev->ident->pid,
			    manuf->info.mlx_psid,
			    strlen(manuf->info.mlx_psid) + 1);
		} else {
			logmsg(MSG_ERROR,
			    gettext("hermon: Unable to allocate space for a "
			    "hardware identifier: %s\n"), strerror(errno));
			goto identify_end;
		}
	}

	for (i = 0; i < 4; i++) {
		errno = 0;
		if ((thisdev->addresses[i] = calloc(1,
		    (2 * sizeof (uint64_t)) + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("hermon: Unable to allocate space for a "
			    "human-readable HCA guid: %s\n"), strerror(errno));
			goto identify_end;
		}
		(void) sprintf(thisdev->addresses[i], "%016llx",
		    manuf->ibguids[i]);
	}

	/*
	 * We do NOT close the fd here, since we can close it
	 * at the end of the fw_readfw() or fw_writefw() functions
	 * instead and not get the poor dear confused about whether
	 * it's been inited already.
	 */

	return (FWFLASH_SUCCESS);

	/* cleanup */
identify_end:
	cnx_close(thisdev);
	return (FWFLASH_FAILURE);
}

static int
cnx_get_guids(ib_cnx_encap_ident_t *handle)
{
	int	i, rv;

	logmsg(MSG_INFO, "cnx_get_guids\n");

	/* make sure we've got our fallback position organised */
	for (i = 0; i < 4; i++) {
		handle->ibguids[i] = 0x00000000;
	}

	rv = cnx_find_magic_n_chnk_sz(handle, FWFLASH_IB_STATE_IMAGE_PRI);
	if (rv != FWFLASH_SUCCESS) {
		logmsg(MSG_INFO, "hermon: Failed to get Primary magic number. "
		    "Trying Secondary... \n");
		rv = cnx_find_magic_n_chnk_sz(handle,
		    FWFLASH_IB_STATE_IMAGE_SEC);
		if (rv != FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR, gettext("hermon: Failed to get "
			    "Secondary magic number.\n"));
			logmsg(MSG_ERROR,
			    gettext("Warning: HCA Firmware corrupt.\n"));
			return (FWFLASH_FAILURE);
		}
		rv = cnx_read_guids(handle, FWFLASH_IB_STATE_IMAGE_SEC);
		if (rv != FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR, gettext("hermon: Failed to read "
			    "secondary guids.\n"));
			return (FWFLASH_FAILURE);
		}
	} else {
		rv = cnx_read_guids(handle, FWFLASH_IB_STATE_IMAGE_PRI);
		if (rv != FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR, gettext("hermon: Failed to read "
			    "primary guids.\n"));
			return (FWFLASH_FAILURE);
		}
	}
	for (i = 0; i < 4; i++) {
		logmsg(MSG_INFO, "hermon: ibguids[%d] 0x%016llx\n", i,
		    handle->ibguids[i]);
	}
	for (i = 0; i < 2; i++) {
		logmsg(MSG_INFO, "hermon: ib_portmac[%d] 0x%016llx\n", i,
		    handle->ib_mac[i]);
	}

	return (FWFLASH_SUCCESS);
}

static int
cnx_close(struct devicelist *flashdev)
{
	ib_cnx_encap_ident_t	*handle;

	logmsg(MSG_INFO, "cnx_close\n");

	handle = (ib_cnx_encap_ident_t *)flashdev->ident->encap_ident;

	if (CNX_I_CHECK_HANDLE(handle)) {
		logmsg(MSG_ERROR, gettext("hermon: Invalid Handle to close "
		    "device %s! \n"), flashdev->access_devname);
		return (FWFLASH_FAILURE);
	}

	if (handle->fd > 0) {
		errno = 0;
		(void) ioctl(handle->fd, HERMON_IOCTL_FLASH_FINI);
		if (close(handle->fd) != 0) {
			logmsg(MSG_ERROR, gettext("hermon: Unable to properly "
			    "close device %s! (%s)\n"),
			    flashdev->access_devname, strerror(errno));
			return (FWFLASH_FAILURE);
		}
	}

	if (handle != NULL) {
		if (handle->info.mlx_id != NULL)
			free(handle->info.mlx_id);

		if (handle->info.mlx_psid != NULL)
			free(handle->info.mlx_psid);

		if (handle->fw != NULL)
			free(handle->fw);
		free(handle);
	}

	if (flashdev->ident->vid != NULL)
		free(flashdev->ident->vid);

	if (flashdev->ident->revid != NULL)
		free(flashdev->ident->revid);

	return (FWFLASH_SUCCESS);
}


/*
 * Driver read/write ioctl calls.
 */
static int
cnx_read_ioctl(ib_cnx_encap_ident_t *hdl, hermon_flash_ioctl_t *info)
{
	int	ret;

#ifdef CNX_DEBUG
	logmsg(MSG_INFO, "cnx_read_ioctl: fd %d af_type 0x%x af_addr 0x%x "
	    "af_sector_num(0x%x)\n", hdl->fd, info->af_type,
	    info->af_addr, info->af_sector_num);
#endif

	errno = 0;
	ret = ioctl(hdl->fd, HERMON_IOCTL_FLASH_READ, info);
	if (ret != 0) {
		logmsg(MSG_ERROR, gettext("HERMON_IOCTL_FLASH_READ failed "
		    "(%s)\n"), strerror(errno));
	}
	return (ret);
}

static int
cnx_write_ioctl(ib_cnx_encap_ident_t *hdl, hermon_flash_ioctl_t *info)
{
	int	ret;

#ifdef CNX_DEBUG
	logmsg(MSG_INFO, "cnx_write_ioctl: fd(%d) af_type(0x%x) "
	    "af_addr(0x%x) af_sector_num(0x%x) af_byte(0x%x)\n",
	    hdl->fd, info->af_type, info->af_addr, info->af_sector_num,
	    info->af_byte);
#endif
	errno = 0;
	ret = ioctl(hdl->fd, HERMON_IOCTL_FLASH_WRITE, info);
	if (ret != 0) {
		logmsg(MSG_ERROR, gettext("HERMON_IOCTL_FLASH_WRITE "
		    "failed (%s)\n"), strerror(errno));
	}
	return (ret);
}

static int
cnx_erase_sector_ioctl(ib_cnx_encap_ident_t *hdl, hermon_flash_ioctl_t *info)
{
	int	ret;

#ifdef CNX_DEBUG
	logmsg(MSG_INFO, "cnx_erase_sector_ioctl: fd(%d) af_type(0x%x) "
	    "af_sector_num(0x%x)\n", hdl->fd, info->af_type,
	    info->af_sector_num);
#endif
	errno = 0;
	ret = ioctl(hdl->fd, HERMON_IOCTL_FLASH_ERASE, info);
	if (ret != 0) {
		logmsg(MSG_ERROR, gettext("HERMON_IOCTL_FLASH_ERASE "
		    "failed (%s)\n"), strerror(errno));
	}
	return (ret);
}

/*
 * cnx_crc16 - computes 16 bit crc of supplied buffer.
 *   image should be in network byteorder
 *   result is returned in host byteorder form
 */
uint16_t
cnx_crc16(uint8_t *image, uint32_t size, int is_image)
{
	const uint16_t	poly = 0x100b;
	uint32_t	crc = 0xFFFF;
	uint32_t	word;
	uint32_t	i, j;

	logmsg(MSG_INFO, "hermon: cnx_crc16\n");

	for (i = 0; i < size / 4; i++) {
		word = (image[4 * i] << 24) |
		    (image[4 * i + 1] << 16) |
		    (image[4 * i + 2] << 8) |
		    (image[4 * i + 3]);

		if (is_image == CNX_HW_IMG)
			word = MLXSWAPBITS32(word);

		for (j = 0; j < 32; j++) {
			if (crc & 0x8000) {
				crc = (((crc << 1) |
				    (word >> 31)) ^ poly) & 0xFFFF;
			} else {
				crc = ((crc << 1) | (word >> 31)) & 0xFFFF;
			}
			word = (word << 1) & 0xFFFFFFFF;
		}
	}

	for (i = 0; i < 16; i++) {
		if (crc & 0x8000) {
			crc = ((crc << 1) ^ poly) & 0xFFFF;
		} else {
			crc = (crc << 1) & 0xFFFF;
		}
	}

	crc = crc ^ 0xFFFF;
	return (crc & 0xFFFF);
}

static void
cnx_local_set_guid_crc_img(uint32_t offset, uint32_t guid_crc_size,
    uint32_t guid_crc_offset)
{
	uint16_t	crc;
	uint8_t		*fw_p = (uint8_t *)&verifier->fwimage[0];

	crc = htons(cnx_crc16((uint8_t *)&verifier->fwimage[offset / 4],
	    guid_crc_size, CNX_FILE_IMG));

	logmsg(MSG_INFO, "cnx_local_set_guid_crc_img: new guid_sect crc: %x\n",
	    ntohs(crc));
	(void) memcpy(&fw_p[offset + guid_crc_offset], &crc, 2);
}

/*
 * Address translation functions for ConnectX
 * Variable definitions:
 * - log2_chunk_size: log2 of a Flash chunk size
 * - cont_addr: a contiguous image address to be translated
 * - is_image_in_odd_chunk: When this bit is 1, it indicates the new image is
 * stored in odd chunks of the Flash.
 */
static uint32_t
cnx_cont2phys(uint32_t log2_chunk_size, uint32_t cont_addr, int type)
{
	uint32_t	result;
	int		is_image_in_odd_chunks;

	is_image_in_odd_chunks = type - 1;

	if (log2_chunk_size) {
		result = cont_addr & (0xffffffff >> (32 - log2_chunk_size)) |
		    (is_image_in_odd_chunks << log2_chunk_size) |
		    (cont_addr << 1) & (0xffffffff << (log2_chunk_size + 1));
	} else {
		result = cont_addr;
	}

	return (result);
}

static int
cnx_read_guids(ib_cnx_encap_ident_t *handle, int type)
{
#ifdef _LITTLE_ENDIAN
	uint32_t		*ptr, tmp;
#endif
	hermon_flash_ioctl_t	ioctl_info;
	uint32_t		*guids;
	uint32_t		*ibmac;
	int			ret, i;
	uint32_t		nguidptr_addr;
	union {
		uint8_t		bytes[4];
		uint32_t	dword;
	} crc16_u;
	uint32_t		*guid_structure;
	uint16_t		crc;

	logmsg(MSG_INFO, "cnx_read_guids\n");

	errno = 0;
	guid_structure = (uint32_t *)calloc(1,
	    CNX_GUID_CRC16_SIZE / 4 * sizeof (uint32_t));
	if (guid_structure == NULL) {
		logmsg(MSG_WARN, gettext("hermon: Can't calloc guid_structure "
		    ": (%s)\n"), strerror(errno));
		return (FWFLASH_FAILURE);
	}

	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;
	ioctl_info.af_addr = cnx_cont2phys(handle->log2_chunk_sz,
	    CNX_NGUIDPTR_OFFSET, type);

	ret = cnx_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		logmsg(MSG_WARN, gettext("hermon: Failed to read GUID Pointer "
		    "Address\n"));
		goto out;
	}

	guids = (uint32_t *)&handle->ibguids[0];
	ibmac = (uint32_t *)&handle->ib_mac[0];
	nguidptr_addr = cnx_cont2phys(handle->log2_chunk_sz,
	    ioctl_info.af_quadlet, type);

	logmsg(MSG_INFO, "NGUIDPTR: 0x%08x \n", nguidptr_addr);
	/* Read in the entire guid section in order to calculate the CRC */
	ioctl_info.af_addr = nguidptr_addr - 0x10;
	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	for (i = 0; i < CNX_GUID_CRC16_SIZE / 4; i++) {
		ret = cnx_read_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			logmsg(MSG_INFO, "Failed to read guid_structure "
			    "(0x%x)\n", i);
			goto out;
		}

		if (i >= 4 && i < 12) {
			guids[i - 4] = ioctl_info.af_quadlet;
		}
		if (i >= 12 && i < 16) {
			ibmac[i - 12] = ioctl_info.af_quadlet;
		}

		guid_structure[i] = ioctl_info.af_quadlet;
		ioctl_info.af_addr += 4;
	}

	for (i = 0; i < CNX_GUID_CRC16_SIZE / 4; i++) {
		logmsg(MSG_INFO, "guid_structure[%x] = 0x%08x\n", i,
		    guid_structure[i]);
	}

	/*
	 * Check the CRC--make sure it computes.
	 */

	/* 0x12 subtracted: 0x2 for alignment, 0x10 to reach structure start */
	ioctl_info.af_addr = nguidptr_addr + CNX_GUID_CRC16_OFFSET - 0x12;
	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	ret = cnx_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		logmsg(MSG_WARN, gettext("hermon: Failed to read guid crc "
		    "at 0x%x\n"), ioctl_info.af_addr);
		goto out;
	}

	crc16_u.dword = ioctl_info.af_quadlet;
	crc = cnx_crc16((uint8_t *)guid_structure, CNX_GUID_CRC16_SIZE,
	    CNX_HW_IMG);

	if (crc != crc16_u.dword) {
		logmsg(MSG_WARN, gettext("hermon: calculated crc16: 0x%x "
		    "differs from GUID section 0x%x\n"), crc, crc16_u.dword);
	} else {
		logmsg(MSG_INFO, "hermon: calculated crc16: 0x%x MATCHES with "
		    "GUID section 0x%x\n", crc, crc16_u.dword);
	}

#ifdef _LITTLE_ENDIAN
	/*
	 * guids are read as pairs of 32 bit host byteorder values and treated
	 * by callers as 64 bit values. So swap each pair of 32 bit values
	 * to make them correct
	 */
	ptr = (uint32_t *)guids;
	for (ret = 0; ret < 8; ret += 2) {
		tmp = ptr[ret];
		ptr[ret] = ptr[ret+1];
		ptr[ret+1] = tmp;
	}
	ptr = (uint32_t *)&handle->ib_mac[0];
	for (ret = 0; ret < 4; ret += 2) {
		tmp = ptr[ret];
		ptr[ret] = ptr[ret+1];
		ptr[ret+1] = tmp;
	}
#endif
	ret = FWFLASH_SUCCESS;

out:
	free(guid_structure);
	return (ret);
}

static int
cnx_find_magic_n_chnk_sz(ib_cnx_encap_ident_t *handle, int type)
{
	int	i, found = 0;
	uint32_t addr;
	uint32_t boot_addresses[] =
	    {0, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000};

	logmsg(MSG_INFO, "cnx_find_magic_n_chnk_sz\n");

	switch (type) {
	case FWFLASH_IB_STATE_IMAGE_PRI:
		addr = 0;
		if (cnx_check_for_magic_pattern(handle, addr) !=
		    FWFLASH_SUCCESS) {
			goto err;
		}
		break;

	case FWFLASH_IB_STATE_IMAGE_SEC:
		for (i = 1; i < 6; i++) {
			addr = boot_addresses[i];
			if (cnx_check_for_magic_pattern(handle, addr) ==
			    FWFLASH_SUCCESS) {
				found = 1;
				break;
			}
		}
		if (!found) {
			goto err;
		}
		break;

	default:
		logmsg(MSG_INFO, "cnx_find_magic_pattern: unknown type\n");
		goto err;
	}

	logmsg(MSG_INFO, "magic_pattern found at addr %x\n", addr);
	handle->img2_start_addr = addr;

	handle->log2_chunk_sz = cnx_get_log2_chunk_size_f_hdl(handle, type);
	if (handle->log2_chunk_sz == 0) {
		logmsg(MSG_INFO, "no chunk size found for type %x. "
		    "Assuming non-failsafe burn\n", type);
	}

	handle->fw_sz = cnx_get_image_size_f_hdl(handle, type);
	if (handle->fw_sz == 0) {
		logmsg(MSG_INFO, "no fw size found for type %x. \n", type);
	}
	handle->state |= type;

	return (FWFLASH_SUCCESS);
err:
	logmsg(MSG_INFO, "no magic_pattern found for type %x\n", type);
	return (FWFLASH_FAILURE);
}

static int
cnx_check_for_magic_pattern(ib_cnx_encap_ident_t *handle, uint32_t addr)
{
	int 			i;
	hermon_flash_ioctl_t	ioctl_info;
	int 			magic_pattern_buf[4];

	logmsg(MSG_INFO, "cnx_check_for_magic_pattern\n");

	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	for (i = 0; i < 4; i++) {
		ioctl_info.af_addr = addr + (i * sizeof (uint32_t));
		if (cnx_read_ioctl(handle, &ioctl_info) != 0) {
			logmsg(MSG_INFO, "\nFailed to read magic pattern\n");
			return (FWFLASH_FAILURE);
		}

		magic_pattern_buf[i] = ioctl_info.af_quadlet;
	}

	return (cnx_is_magic_pattern_present(magic_pattern_buf, CNX_HW_IMG));

}

int
cnx_is_magic_pattern_present(int *data, int is_image)
{
	int	i;
	int	dword;

	logmsg(MSG_INFO, "cnx_is_magic_pattern_present\n");

	for (i = 0; i < 4; i++) {
		if (is_image == CNX_FILE_IMG)
			dword = MLXSWAPBITS32(data[i]);
		else
			dword = data[i];
		logmsg(MSG_INFO, "local_quadlet: %08x, magic pattern: %08x\n",
		    dword, cnx_magic_pattern[i]);
		if (dword != cnx_magic_pattern[i]) {
			return (FWFLASH_FAILURE);
		}
	}

	return (FWFLASH_SUCCESS);
}

static uint32_t
cnx_get_log2_chunk_size_f_hdl(ib_cnx_encap_ident_t *handle, int type)
{
	hermon_flash_ioctl_t	ioctl_info;
	int			ret;

	logmsg(MSG_INFO, "cnx_get_log2_chunk_size_f_hdl\n");

	/* If chunk size is already set, just return it. */
	if (handle->log2_chunk_sz) {
		return (handle->log2_chunk_sz);
	}

	switch (type) {
	case FWFLASH_IB_STATE_IMAGE_PRI:
		ioctl_info.af_addr = CNX_CHUNK_SIZE_OFFSET;
		break;
	case FWFLASH_IB_STATE_IMAGE_SEC:
		ioctl_info.af_addr =
		    handle->img2_start_addr + CNX_CHUNK_SIZE_OFFSET;
		break;
	default:
		logmsg(MSG_INFO,
		    "cnx_get_log2_chunk_size_f_hdl: unknown type\n");
		return (0);
	}

	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	ret = cnx_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		logmsg(MSG_INFO, "\nFailed to read chunk size\n");
		return (0);
	}

	return (cnx_get_log2_chunk_size(ioctl_info.af_quadlet));
}


static uint32_t
cnx_get_log2_chunk_size(uint32_t chunk_size_word)
{
	uint8_t		checksum;
	uint32_t	log2_chunk_size;

	logmsg(MSG_INFO, "cnx_get_log2_chunk_size: chunk_size_word:"
	    " 0x%x\n", chunk_size_word);

	checksum =
	    (chunk_size_word & 0xff) +
	    ((chunk_size_word >> 8) & 0xff) +
	    ((chunk_size_word >> 16) & 0xff) +
	    ((chunk_size_word >> 24) & 0xff);

	if (checksum != 0) {
		logmsg(MSG_INFO, "Corrupted chunk size checksum\n");
		return (0);
	}

	if (chunk_size_word & 0x8) {
		log2_chunk_size = (chunk_size_word & 0x7) + 16;
		logmsg(MSG_INFO, "log2 chunk size: 0x%x\n", log2_chunk_size);
		return (log2_chunk_size);
	} else {
		return (0);
	}
}

static uint32_t
cnx_get_image_size_f_hdl(ib_cnx_encap_ident_t *handle, int type)
{
	hermon_flash_ioctl_t	ioctl_info;
	int			ret;

	logmsg(MSG_INFO, "cnx_get_image_size_f_hdl\n");

	ioctl_info.af_addr = cnx_cont2phys(handle->log2_chunk_sz,
	    CNX_IMG_SIZE_OFFSET, type);
	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	ret = cnx_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		logmsg(MSG_INFO, "Failed to read image size\n");
		return (0);
	}

	logmsg(MSG_INFO, "Image Size: 0x%x\n", ioctl_info.af_quadlet);

	return (ioctl_info.af_quadlet);
}

static int
cnx_get_image_info(ib_cnx_encap_ident_t *handle)
{
	uint32_t	ii_ptr_addr;
	uint32_t	ii_size;
	int		*buf;
	int		i, type;
	hermon_flash_ioctl_t	ioctl_info;

	logmsg(MSG_INFO, "cnx_get_image_info: state %x\n", handle->state);

	type = handle->state &
	    (FWFLASH_IB_STATE_IMAGE_PRI | FWFLASH_IB_STATE_IMAGE_SEC);

	/* Get the image info pointer */
	ioctl_info.af_addr = cnx_cont2phys(handle->log2_chunk_sz,
	    CNX_IMG_INF_PTR_OFFSET, type);
	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	if (cnx_read_ioctl(handle, &ioctl_info) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: Failed to read image info "
		    "Address\n"));
		return (FWFLASH_FAILURE);
	}
	ii_ptr_addr = ioctl_info.af_quadlet & 0xffffff;

	/* Get the image info size, a negative offset from the image info ptr */
	ioctl_info.af_addr = cnx_cont2phys(handle->log2_chunk_sz,
	    ii_ptr_addr + CNX_IMG_INF_SZ_OFFSET, type);
	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	if (cnx_read_ioctl(handle, &ioctl_info) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: Failed to read image info "
		    "size\n"));
		return (FWFLASH_FAILURE);
	}
	logmsg(MSG_INFO, "hermon: ImageInfo Sz: 0x%x\n", ioctl_info.af_quadlet);

	ii_size = ioctl_info.af_quadlet;
	/* size is in dwords--convert it to bytes */
	ii_size *= 4;

	logmsg(MSG_INFO, "hermon: ii_ptr_addr: 0x%x ii_size: 0x%x\n",
	    ii_ptr_addr, ii_size);

	buf = (int *)calloc(1, ii_size);

	ioctl_info.af_addr = cnx_cont2phys(handle->log2_chunk_sz,
	    ii_ptr_addr, type);
	ioctl_info.af_type = HERMON_FLASH_READ_QUADLET;

	for (i = 0; i < ii_size/4; i++) {
		if (cnx_read_ioctl(handle, &ioctl_info) != FWFLASH_SUCCESS) {
			logmsg(MSG_WARN, gettext("hermon: Failed to read "
			    "image info (0x%x)\n"), i);
			free(buf);
			return (FWFLASH_FAILURE);
		}

		buf[i] = ioctl_info.af_quadlet;
		ioctl_info.af_addr += 4;
	}

	/* Parse the image info section */
	if (cnx_parse_img_info(buf, ii_size, &handle->hwfw_img_info,
	    CNX_HW_IMG) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: Failed to parse Image Info "
		    "section\n"));
		free(buf);
		return (FWFLASH_FAILURE);
	}

	free(buf);
	return (FWFLASH_SUCCESS);
}

int
cnx_parse_img_info(int *buf, uint32_t byte_size, cnx_img_info_t *img_info,
    int is_image)
{
	uint32_t 	*p;
	uint32_t 	offs = 0;
	uint32_t 	tag_num = 0;
	int 		end_found = 0;
	uint32_t 	tag_size, tag_id;
	uint32_t 	tmp;
	const char 	*str;
	int		i;

	p = (uint32_t *)buf;

	logmsg(MSG_INFO, "hermon: cnx_parse_img_info\n");

	while (!end_found && (offs < byte_size)) {
		if (is_image == CNX_FILE_IMG) {
			tag_size = ntohl(*p) & 0xffffff;
			tag_id = ntohl(*p) >> 24;
			tmp = ntohl(*(p + 1));
		} else {
			tag_size = ((*p) & 0xffffff);
			tag_id = ((*p) >> 24);
			tmp = (*(p + 1));
		}

		logmsg(MSG_INFO, "tag_id: %d tag_size: %d\n", tag_id, tag_size);

		if ((offs + tag_size) > byte_size) {
			logmsg(MSG_WARN, gettext("hermon: Image Info section "
			    "corrupted: Tag# %d - tag_id %d, size %d exceeds "
			    "info section size (%d bytes)"), tag_num, tag_id,
			    tag_size, byte_size);
			return (FWFLASH_FAILURE);
		}

		switch (tag_id) {
		case CNX_FW_VER:
			if (tag_size != CNX_FW_VER_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_FW_VER_SZ);
			}
			tmp = (tmp & CNX_MASK_FW_VER_MAJ) >> 16;
			img_info->fw_rev.major = tmp;
			if (is_image == CNX_FILE_IMG)
				tmp = ntohl(*(p + 2));
			else
				tmp = (*(p + 2));
			img_info->fw_rev.minor =
			    (tmp & CNX_MASK_FW_VER_MIN)>> 16;
			img_info->fw_rev.subminor =
			    tmp & CNX_MASK_FW_VER_SUBMIN;

			logmsg(MSG_INFO, "FW_VER: %d.%d.%03d\n",
			    img_info->fw_rev.major, img_info->fw_rev.minor,
			    img_info->fw_rev.subminor);
			break;

		case CNX_FW_BUILD_TIME:
			if (tag_size != CNX_FW_BUILD_TIME_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_FW_BUILD_TIME_SZ);
			}
			img_info->fw_buildtime.hour =
			    (tmp & CNX_MASK_FW_BUILD_HOUR) >> 16;
			img_info->fw_buildtime.minute =
			    (tmp & CNX_MASK_FW_BUILD_MIN) >> 8;
			img_info->fw_buildtime.second =
			    (tmp & CNX_MASK_FW_BUILD_SEC);

			if (is_image == CNX_FILE_IMG)
				tmp = ntohl(*(p + 2));
			else
				tmp = (*(p + 2));

			img_info->fw_buildtime.year =
			    (tmp & CNX_MASK_FW_BUILD_YEAR) >> 16;
			img_info->fw_buildtime.month =
			    (tmp & CNX_MASK_FW_BUILD_MON) >> 8;
			img_info->fw_buildtime.day =
			    (tmp & CNX_MASK_FW_BUILD_DAY);

			logmsg(MSG_INFO, "Build TIME: %d:%d:%d %d:%d:%d\n",
			    img_info->fw_buildtime.year,
			    img_info->fw_buildtime.month,
			    img_info->fw_buildtime.day,
			    img_info->fw_buildtime.hour,
			    img_info->fw_buildtime.minute,
			    img_info->fw_buildtime.second);
			break;

		case CNX_DEV_TYPE:
			if (tag_size != CNX_DEV_TYPE_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_DEV_TYPE_SZ);
			}
			img_info->dev_id = tmp & CNX_MASK_DEV_TYPE_ID;
			logmsg(MSG_INFO, "DEV_TYPE: %d\n", img_info->dev_id);
			break;

		case CNX_VSD_VENDOR_ID:
			if (tag_size != CNX_VSD_VENDOR_ID_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_VSD_VENDOR_ID_SZ);
			}
			img_info->vsd_vendor_id = tmp & CNX_MASK_VSD_VENDORID;
			logmsg(MSG_INFO, "VSD Vendor ID: 0x%lX\n",
			    img_info->vsd_vendor_id);
			break;

		case CNX_PSID:
			if (tag_size != CNX_PSID_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_PSID_SZ);
			}
			str = (const char *)p;
			str += 4;

			for (i = 0; i < CNX_PSID_SZ; i++)
				img_info->psid[i] = str[i];

#ifdef _LITTLE_ENDIAN
			if (is_image == CNX_HW_IMG) {
				for (i = 0; i < CNX_PSID_SZ; i += 4) {
					img_info->psid[i+3] = str[i];
					img_info->psid[i+2] = str[i+1];
					img_info->psid[i+1] = str[i+2];
					img_info->psid[i] = str[i+3];
				}
			}
#endif

			logmsg(MSG_INFO, "PSID: %s\n", img_info->psid);
			break;

		case CNX_VSD:
			if (tag_size != CNX_VSD_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_VSD_SZ);
			}
			str = (const char *)p;
			str += 4;

			for (i = 0; i < CNX_VSD_SZ; i++)
				img_info->vsd[i] = str[i];

#ifdef _LITTLE_ENDIAN
			if (is_image == CNX_HW_IMG) {
				for (i = 0; i < CNX_VSD_SZ; i += 4) {
					img_info->vsd[i+3] = str[i];
					img_info->vsd[i+2] = str[i+1];
					img_info->vsd[i+1] = str[i+2];
					img_info->vsd[i] = str[i+3];
				}
			}
#endif
			logmsg(MSG_INFO, "VSD: %s\n", img_info->vsd);
			break;

		case CNX_END_TAG:
			if (tag_size != CNX_END_TAG_SZ) {
				logmsg(MSG_INFO, "ERROR: tag_id: %d tag_size: "
				    "%d expected sz %d\n", tag_id, tag_size,
				    CNX_END_TAG_SZ);
			}
			end_found = 1;
			break;

		default:
			if (tag_id > CNX_END_TAG) {
				logmsg(MSG_WARN, gettext("Invalid img_info "
				    "tag ID %d of size %d\n"), tag_id,
				    tag_size);
			}
			break;
		}

		p += (tag_size / 4) + 1;
		offs += tag_size + 4;
		tag_num++;
	}

	if (offs != byte_size) {
		logmsg(MSG_WARN, gettext("hermon: Corrupt Image Info section "
		    "in firmware image\n"));
		if (end_found) {
			logmsg(MSG_WARN, gettext("Info section corrupted: "
			    "Section data size is %x bytes, but end tag found "
			    "after %x bytes.\n"), byte_size, offs);
		} else {
			logmsg(MSG_WARN, gettext("Info section corrupted: "
			    "Section data size is %x bytes, but end tag not "
			    "found at section end.\n"), byte_size);
		}
		return (FWFLASH_FAILURE);
	}

	return (FWFLASH_SUCCESS);
}
