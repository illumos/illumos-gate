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
 * IB (InfiniBand) specific functions.
 */

/*
 * The reference for the functions in this file is the
 *
 *	Mellanox HCA Flash Programming Application Note
 * (Mellanox document number 2205AN)
 * rev 1.44, 2007. Chapter 4 in particular.
 *
 * NOTE: this Mellanox document is labelled Confidential
 * so DO NOT move this file out of usr/closed without
 * explicit approval from Sun Legal.
 */

/*
 * IMPORTANT NOTE:
 * 1. flash read is done in 32 bit quantities, and the driver returns
 *    data in host byteorder form.
 * 2. flash write is done in 8 bit quantities by the driver.
 * 3. data in the flash should be in network byteorder (bigendian).
 * 4. data in image files is in network byteorder form.
 * 5. data in image structures in memory is kept in network byteorder.
 * 6. the functions in this file deal with data in host byteorder form.
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
#include "../../hdrs/MELLANOX.h"
#include "../../hdrs/tavor_ib.h"



char *devprefix = "/devices";
char drivername[] = "tavor\0";
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

static int tavor_identify(struct devicelist *thisdev);
static int tavor_get_guids(struct ib_encap_ident *handle);
static int tavor_close(struct devicelist *flashdev);
static void tavor_cisco_extensions(mlx_xps_t *hcaxps, mlx_xps_t *diskxps);
static uint16_t crc16(uint8_t *image, uint32_t size);
static int tavor_write_sector(int fd, int sectnum, int32_t *data);
static int tavor_zero_sig_crc(int fd, uint32_t start);
static int tavor_write_xps_fia(int fd, uint32_t offset, uint32_t start);
static int tavor_write_xps_crc_sig(int fd, uint32_t offset, uint16_t newcrc);
static int tavor_blast_image(int fd, int prisec, uint32_t hcafia,
    uint32_t sectsz, struct mlx_xps *newxps);
static int tavor_readback(int infd, int whichsect, int sectsz);



int
fw_readfw(struct devicelist *flashdev, char *filename)
{

	int 				rv = FWFLASH_SUCCESS;
	int 				fd;
	mode_t				mode = S_IRUSR | S_IWUSR;
	uint8_t				pchunks;
	uint8_t				*raw_pfi;
	uint8_t				*raw_sfi;
	uint32_t			j, offset;
	uint32_t			pfia, sfia, psz, ssz;
	tavor_flash_ioctl_t		tfi_data;
	struct ib_encap_ident		*manuf;
	struct mlx_xps			*lpps;
	struct mlx_xps			*lsps;
#if defined(_LITTLE_ENDIAN)
	uint32_t			*ptr;
#endif

	errno = 0;
	if ((fd = open(filename, O_RDWR|O_CREAT|O_DSYNC, mode)) < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to open specified file "
		    "(%s) for writing: %s\n"), filename, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	manuf =
	    (struct ib_encap_ident *)(uintptr_t)flashdev->ident->encap_ident;
	lpps = (struct mlx_xps *)(uintptr_t)manuf->pps;
	lsps = (struct mlx_xps *)(uintptr_t)manuf->sps;

	/*
	 * Now that we've got an open, init'd fd, we can read the
	 * xFI from the device itself. We've already got the IS
	 * and xPS stored in manuf.
	 */

	/* stash some values for later */
	pfia = MLXSWAPBITS32(lpps->fia);
	sfia = MLXSWAPBITS32(lsps->fia);
	psz = MLXSWAPBITS32(lpps->fis);
	ssz = MLXSWAPBITS32(lsps->fis);

	/* Invariant Sector comes first */
	if ((j = write(fd, manuf->inv, manuf->sector_sz)) !=
	    manuf->sector_sz) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to write HCA Invariant Sector "
		    "(%d of %d bytes)\n"),
		    j, manuf->sector_sz);
		(void) tavor_close(flashdev);
		return (FWFLASH_FAILURE);
	} else {
		fprintf(stdout, gettext("Writing ."));
	}

	/* followed by Primary Pointer Sector */
	if ((j = write(fd, manuf->pps, manuf->sector_sz)) !=
	    manuf->sector_sz) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to write HCA Primary Pointer "
		    "Sector (%d of %d bytes)\n)"),
		    j, manuf->sector_sz);
		(void) tavor_close(flashdev);
		return (FWFLASH_FAILURE);
	} else {
		fprintf(stdout, " .");
	}

	/* followed by Secondary Pointer Sector */
	if ((j = write(fd, manuf->sps, manuf->sector_sz)) !=
	    manuf->sector_sz) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to write HCA Secondary Pointer "
		    "Sector (%d of %d bytes)\n"),
		    j, manuf->sector_sz);
		(void) tavor_close(flashdev);
		return (FWFLASH_FAILURE);
	} else {
		fprintf(stdout, " .");
	}

	/* Now for the xFI sectors */
	pchunks = psz / manuf->sector_sz;

	if ((psz % manuf->sector_sz) != 0)
		pchunks++;

	/* Get the PFI, then the SFI */
	if ((raw_pfi = calloc(1, pchunks * manuf->sector_sz)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for "
		    "device's Primary Firmware Image\n"));
		return (FWFLASH_FAILURE);
	}
	bzero(&tfi_data, sizeof (tavor_flash_ioctl_t));
	tfi_data.tf_type = TAVOR_FLASH_READ_SECTOR;
	j = pfia / manuf->sector_sz;

	for (offset = 0; offset < psz; offset += manuf->sector_sz) {
		tfi_data.tf_sector_num = j;
		tfi_data.tf_sector = (caddr_t)&raw_pfi[offset];
		rv = ioctl(manuf->fd, TAVOR_IOCTL_FLASH_READ, &tfi_data);
		if (rv < 0) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to read sector %d of "
			    "HCA Primary Firmware Image\n"), j);
			free(raw_pfi);
			(void) tavor_close(flashdev);
			return (FWFLASH_FAILURE);
		}
		++j;
	}

	/*
	 * It appears that the tavor driver is returning a signed
	 * -1 (0xffff) in unassigned quadlets if we read a sector
	 * that isn't full, so for backwards compatibility with
	 * earlier fwflash versions, we need to zero out what
	 * remains in the sector.
	 */
	bzero(&raw_pfi[psz], (pchunks * manuf->sector_sz) - psz);

#if defined(_LITTLE_ENDIAN)
	ptr = (uint32_t *)(uintptr_t)raw_pfi;
	for (j = 0; j < (pchunks * manuf->sector_sz / 4); j++) {
		ptr[j] = htonl(ptr[j]);
		if (j > psz)
			break;
	}
#endif

	if ((j = write(fd, raw_pfi, pchunks * manuf->sector_sz))
	    != pchunks * manuf->sector_sz) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to write HCA Primary Firmware "
		    "Image data (%d of %d bytes)\n"),
		    j, pchunks * manuf->sector_sz);
		free(raw_pfi);
		(void) tavor_close(flashdev);
		return (FWFLASH_FAILURE);
	} else {
		fprintf(stdout, " .");
	}

	pchunks = ssz / manuf->sector_sz;

	if ((ssz % manuf->sector_sz) != 0)
		pchunks++;

	/*
	 * We allocate wholenum sectors, but only write out what we
	 * really need (ssz bytes)
	 */
	if ((raw_sfi = calloc(1, pchunks * manuf->sector_sz)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for "
		    "device's Secondary Firmware Image\n"));
		free(raw_pfi);
		return (FWFLASH_FAILURE);
	}
	bzero(&tfi_data, sizeof (tavor_flash_ioctl_t));
	tfi_data.tf_type = TAVOR_FLASH_READ_SECTOR;

	/* get our starting sector number */
	j = sfia / manuf->sector_sz;

	for (offset = 0; offset < ssz; offset += manuf->sector_sz) {
		tfi_data.tf_sector_num = j;
		tfi_data.tf_sector = (caddr_t)&raw_sfi[offset];
		if ((rv = ioctl(manuf->fd, TAVOR_IOCTL_FLASH_READ,
		    &tfi_data)) < 0) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to read sector %d of "
			    "HCA Secondary Firmware Image\n"), j);
			(void) tavor_close(flashdev);
			free(raw_pfi);
			free(raw_sfi);
			return (FWFLASH_FAILURE);
		}
		++j;
	}

	/*
	 * It appears that the tavor driver is returning a signed
	 * -1 (0xffff) in unassigned quadlets if we read a sector
	 * that isn't full, so for backwards compatibility with
	 * earlier fwflash versions, we need to zero out what
	 * remains in the sector.
	 */
	bzero(&raw_sfi[ssz], (pchunks * manuf->sector_sz) - ssz);

#if defined(_LITTLE_ENDIAN)
	ptr = (uint32_t *)(uintptr_t)raw_sfi;
	for (j = 0; j < ssz / 4; j++) {
		ptr[j] = htonl(ptr[j]);
	}
#endif

	/* only write out ssz bytes */
	if ((j = write(fd, raw_sfi, ssz)) != ssz) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to write HCA Secondary Firmware "
		    "Image data (%d of %d bytes)\n"),
		    j, ssz);
		(void) tavor_close(flashdev);
		free(raw_pfi);
		free(raw_sfi);
		return (FWFLASH_FAILURE);
	} else {
		fprintf(stdout, " .\n");
	}

	fprintf(stdout,
	    gettext("Done.\n"));

	free(raw_pfi);
	free(raw_sfi);
	/*
	 * this should succeed, but we don't just blindly ignore
	 * the return code cos that would be obnoxious.
	 */
	return (tavor_close(flashdev));
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

	int			rv;
	uint32_t 		j, sectsz, hpfia, hsfia;
	uint32_t		ipfia, isfia, ipfis, isfis;
	struct ib_encap_ident	*manuf;
	struct mlx_is		*iinv;
	struct mlx_xps		*ipps, *lpps;
	struct mlx_xps		*isps, *lsps;
	struct mlx_xfi		*ipfi, *isfi;

	/*
	 * linv, lpps/lsps are from the HCA whereas
	 * iinv/ipps/isps are in the on-disk firmware image that
	 * we've read in to the verifier->fwimage field, and are
	 * about to do some hand-waving with.
	 */

	/*
	 * From the Mellanox HCA Flash programming app note,
	 * start of ch4, page36:
	 * ===========================================================
	 * Failsafe firmware programming ensures that an HCA device
	 * can boot up in a functional mode even if the burn process
	 * was interrupted (because of a power failure, reboot, user
	 * interrupt, etc.). This can be implemented by burning the
	 * new image to a vacant region on the Flash, and erasing the
	 * old image only after the new image is successfully burnt.
	 * This method ensures that there is at least one valid firmware
	 * image on the Flash at all times. Thus, in case a firmware
	 * image programming process is aborted for any reason, the HCA
	 * will still be able to boot up properly using the valid image
	 * on the Flash.
	 * ...
	 *
	 * 4.1 Notes on Image Programming of HCA Flashes
	 * Following are some general notes regarding the Flash memory
	 * in the context of Mellanox HCA devices:
	 * > The Flash memory is divided into sectors, and each sector
	 *   must be erased prior to its programming.
	 * > The image to be burnt is byte packed and should be programmed
	 *   into the Flash byte by byte, preserving the byte order, starting
	 *   at offset zero. No amendments are needed for endianess.
	 * > It is recommended to program the Flash while the device is idle.
	 * ===========================================================
	 *
	 * The comment about endianness is particularly important for us
	 * since we operate on both big- and litte-endian hosts - it means
	 * we have to do some byte-swapping gymnastics
	 */

	/*
	 * From the Mellanox HCA Flash programming app note,
	 * section 4.2.5 on page 41/42:
	 * ===========================================================
	 * 4.2.5 Failsafe Programming Example
	 * This section provides an example of a programming utility
	 * that performs a Failsafe firmware image update. The flow
	 * ensures that there is at least one valid firmware image on
	 * the Flash at all times. Thus, in case a firmware image pro-
	 * gramming process is aborted for any reason, the HCA will
	 * still be able to boot up properly using the valid image on
	 * the Flash. Any other flow that ensures the above is also
	 * considered a Failsafe firmware update.
	 *
	 * Update Flow:
	 * * Check the validity of the PPS and SPS:
	 * > If both PSs are valid, arbitrarily invalidate one of them
	 * > If both PSs are invalid, the image on flash is corrupted
	 *   and cannot be updated in a Failsafe way. The user must
	 *   burn a full image in a non-failsafe way.
	 *
	 * > If only the PPS is valid:
	 *   i.Burn the secondary image (erase each sector first)
	 *  ii.Burn the SPS with the correct image address (FIA field)
	 * iii.Invalidate the PPS
	 *
	 * > If only the SPS is valid:
	 *   i.Burn the primary image (erase each sector first)
	 *  ii.Burn the PPS with the correct image address (FIA field)
	 * iii.Invalidate the SPS
	 * ===========================================================
	 */

	/*
	 * Other required tasks called from this function:
	 *
	 * * check for CISCO boot extensions in the current xPS, and
	 *   if found, set them in the new xPS
	 *
	 * * update the xPS CRC field
	 *
	 * _then_ you can setup the outbound transfer to the HCA flash.
	 */

	/*
	 * VERY IMPORTANT NOTE:
	 * The above text from the app note programming guide v1.44 does
	 * NOT match reality. If you try to do exactly what the above
	 * text specifies then you'll wind up with a warm, brick-like
	 * HCA that if you're really lucky has booted up in maintenance
	 * mode for you to re-flash.
	 *
	 * What you need to do is follow the example of the previous
	 * (v1.2 etc) version from the ON gate - which is what happens
	 * in this file. Basically - don't erase prior to writing a new
	 * sector, and _read back_ each sector after writing it. Especially
	 * the pointer sectors. Otherwise you'll get a warm brick.
	 */

	manuf =
	    (struct ib_encap_ident *)(uintptr_t)flashdev->ident->encap_ident;
	lpps = (struct mlx_xps *)(uintptr_t)manuf->pps;
	lsps = (struct mlx_xps *)(uintptr_t)manuf->sps;
	iinv = (struct mlx_is *)&verifier->fwimage[0];
	sectsz = 1 << MLXSWAPBITS16(iinv->log2sectsz + iinv->log2sectszp);
	ipps = (struct mlx_xps *)&verifier->fwimage[sectsz/4];
	isps = (struct mlx_xps *)&verifier->fwimage[sectsz/2];

	/*
	 * If we get here, then the verifier has _already_ checked that
	 * the part number in the firmware image matches that in the HCA,
	 * so we only need this check if there's no hardware info available
	 * already after running through fw_identify().
	 */
	if (manuf->pn_len == 0) {
		int resp;

		(void) printf("\nUnable to completely verify that this "
		    "firmware image\n\t(%s)\nis compatible with your "
		    "HCA\n\t%s\n",
		    verifier->imgfile, flashdev->access_devname);
		(void) printf("\n\tDo you really want to continue? (Y/N): ");

		(void) fflush(stdin);
		resp = getchar();
		if (resp != 'Y' && resp != 'y') {
			(void) printf("\nNot proceeding with flash "
			    "operation of %s on %s\n",
			    verifier->imgfile, flashdev->access_devname);
			return (FWFLASH_FAILURE);
		}
	}

	/* stash these for later */
	hpfia = MLXSWAPBITS32(lpps->fia);
	hsfia = MLXSWAPBITS32(lsps->fia);

	/* where does the on-disk image think everything is at? */
	ipfia = MLXSWAPBITS32(ipps->fia);
	isfia = MLXSWAPBITS32(isps->fia);
	ipfis = MLXSWAPBITS32(ipps->fis);
	isfis = MLXSWAPBITS32(isps->fis);

	logmsg(MSG_INFO, "tavor: hpfia 0x%0x hsfia 0x%0x "
	    "ipfia 0x%0x isfia 0x%0x ipfis 0x%0x isfis 0x%0x\n",
	    hpfia, hsfia, ipfia, isfia, ipfis, isfis);

	if ((ipfis + isfis) > manuf->device_sz) {
		/*
		 * This is bad - don't flash an image which is larger
		 * than the size of the HCA's flash
		 */
		logmsg(MSG_ERROR,
		    gettext("tavor: on-disk firmware image size (0x%lx bytes) "
		    "exceeds HCA's flash memory size (0x%lx bytes)!\n"),
		    ipfis + isfis, manuf->device_sz);
		logmsg(MSG_ERROR,
		    gettext("tavor: not flashing this image (%s)\n"),
		    verifier->imgfile);
		return (FWFLASH_FAILURE);
	}

	/*
	 * The Mellanox HCA Flash app programming note does _not_
	 * specify that you have to insert the HCA's guid section
	 * into the flash image before burning it.
	 *
	 * HOWEVER it was determined during testing that this is
	 * actually required (otherwise your HCA's GUIDs revert to
	 * the manufacturer's defaults, ugh!), so we'll do it too.
	 */

	ipfi = (struct mlx_xfi *)&verifier->fwimage[ipfia/4];
	isfi = (struct mlx_xfi *)&verifier->fwimage[isfia/4];

	/*
	 * Here we check against our stored, properly-bitwise-munged copy
	 * of the HCA's GUIDS. If they're not set to default AND the OUI
	 * is MLX_OUI, then they're ok so we copy the HCA's version into
	 * our in-memory copy and blat it. If the GUIDs don't match this
	 * condition, then we use the default GUIDs which are in the on-disk
	 * firmware image instead.
	 */
	if (((manuf->ibguids[0] != MLX_DEFAULT_NODE_GUID) &&
	    (manuf->ibguids[1] != MLX_DEFAULT_P1_GUID) &&
	    (manuf->ibguids[2] != MLX_DEFAULT_P2_GUID) &&
	    (manuf->ibguids[3] != MLX_DEFAULT_SYSIMG_GUID)) &&
	    ((((manuf->ibguids[0] & HIGHBITS64) >> OUISHIFT) == MLX_OUI) ||
	    (((manuf->ibguids[1] & HIGHBITS64) >> OUISHIFT) == MLX_OUI) ||
	    (((manuf->ibguids[2] & HIGHBITS64) >> OUISHIFT) == MLX_OUI) ||
	    (((manuf->ibguids[3] & HIGHBITS64) >> OUISHIFT) == MLX_OUI))) {
		/* The GUIDs are ok, blat them into the in-memory image */
		j = ((ipfia + MLXSWAPBITS32(ipfi->nguidptr)) / 4) - 4;
		bcopy(manuf->pri_guid_section, &verifier->fwimage[j],
		    sizeof (struct mlx_guid_sect));
		j = ((isfia + MLXSWAPBITS32(isfi->nguidptr)) / 4) - 4;
		bcopy(manuf->sec_guid_section, &verifier->fwimage[j],
		    sizeof (struct mlx_guid_sect));
	} else {
		/*
		 * The GUIDs are hosed, we'll have to use
		 * the vendor defaults in the image instead
		 */
		logmsg(MSG_ERROR,
		    gettext("tavor: HCA's GUID section is set to defaults or "
		    " is invalid, using firmware image manufacturer's "
		    "default GUID section instead\n"));
	}

	/* Just in case somebody is booting from this card... */
	tavor_cisco_extensions(lpps, ipps);
	tavor_cisco_extensions(lsps, isps);

	/* first we write the secondary image and SPS, then the primary */
	rv = tavor_blast_image(manuf->fd, 2, hsfia, manuf->sector_sz, isps);
	if (rv != FWFLASH_SUCCESS) {
		logmsg(MSG_INFO,
		    "tavor: failed to update #2 firmware image\n");
		(void) tavor_close(flashdev);
		return (FWFLASH_FAILURE);
	}

	rv = tavor_blast_image(manuf->fd, 1, hpfia, manuf->sector_sz, ipps);
	if (rv != FWFLASH_SUCCESS) {
		logmsg(MSG_INFO,
		    "tavor: failed to update #1 firmware image\n");
		(void) tavor_close(flashdev);
		return (FWFLASH_FAILURE);
	}

	/* final update marker to the user */
	(void) printf(" +\n");
	return (tavor_close(flashdev));
}


/*
 * The fw_identify() function walks the device
 * tree trying to find devices which this plugin
 * can work with.
 *
 * The parameter "start" gives us the starting index number
 * to give the device when we add it to the fw_devices list.
 *
 * firstdev is allocated by us and we add space as necessary
 *
 */
int
fw_identify(int start)
{
	int rv = FWFLASH_FAILURE;
	di_node_t thisnode;
	struct devicelist *newdev;
	char *devpath;
	int idx = start;
	int devlength = 0;

	thisnode = di_drv_first_node(drivername, rootnode);

	if (thisnode == DI_NODE_NIL) {
		logmsg(MSG_INFO, gettext("No %s nodes in this system\n"),
		    drivername);
		return (rv);
	}

	/* we've found one, at least */
	for (; thisnode != DI_NODE_NIL; thisnode = di_drv_next_node(thisnode)) {

		devpath = di_devfs_path(thisnode);

		if ((newdev = calloc(1, sizeof (struct devicelist)))
		    == NULL) {
			logmsg(MSG_ERROR,
			    gettext("tavor identification function: unable "
			    "to allocate space for device entry\n"));
			di_devfs_path_free(devpath);
			return (rv);
		}

		/* calloc enough for /devices + devpath + ":devctl" + '\0' */
		devlength = strlen(devpath) + strlen(devprefix) +
		    strlen(devsuffix) + 2;

		if ((newdev->access_devname = calloc(1, devlength)) == NULL) {
			logmsg(MSG_ERROR, gettext("Unable to calloc space "
			    "for a devfs name\n"));
			di_devfs_path_free(devpath);
			(void) free(newdev);
			return (FWFLASH_FAILURE);
		}
		snprintf(newdev->access_devname, devlength,
		    "%s%s%s", devprefix, devpath, devsuffix);

		/* CHECK VARIOUS IB THINGS HERE */

		if ((newdev->ident = calloc(1, sizeof (struct vpr))) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to allocate space for a "
			    "device identification record\n"));
			(void) free(newdev->access_devname);
			(void) free(newdev);
			di_devfs_path_free(devpath);
			return (FWFLASH_FAILURE);
		}

		rv = tavor_identify(newdev);
		if (rv == FWFLASH_FAILURE) {
			(void) free(newdev->ident);
			(void) free(newdev->access_devname);
			(void) free(newdev);
			di_devfs_path_free(devpath);
			continue;
		}

		if ((newdev->drvname = calloc(1, strlen(drivername) + 1))
		    == NULL) {
			logmsg(MSG_ERROR, gettext("Unable to allocate space "
			    "for a driver name\n"));
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
			logmsg(MSG_ERROR, gettext("Unable to allocate space "
			    "for a class name\n"));
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
			logmsg(MSG_INFO, "fw_identify:\n");
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

	struct ib_encap_ident	*encap;


	encap = (struct ib_encap_ident *)thisdev->ident->encap_ident;

	fprintf(stdout, gettext("Device[%d] %s\n  Class [%s]\n"),
	    thisdev->index, thisdev->access_devname, thisdev->classname);

	fprintf(stdout, "\t");

	/* Mellanox HCA Flash app note, p40, #4.2.3 table 9 */
	fprintf(stdout,
	    gettext("GUID: System Image - %s\n"),
	    thisdev->addresses[3]);
	fprintf(stdout,
	    gettext("\t\tNode Image - %s\n"),
	    thisdev->addresses[0]);
	fprintf(stdout,
	    gettext("\t\tPort 1\t   - %s\n"),
	    thisdev->addresses[1]);
	fprintf(stdout,
	    gettext("\t\tPort 2\t   - %s\n"),
	    thisdev->addresses[2]);

	if (encap->pn_len != 0) {
		fprintf(stdout,
		    gettext("\tFirmware revision : %s\n"
		    "\tProduct\t\t: %s %X\n"
		    "\tPSID\t\t: %s\n"),
		    thisdev->ident->revid,
		    encap->info.mlx_pn,
		    encap->hwrev,
		    encap->info.mlx_psid);
	} else {
		fprintf(stdout,
		    gettext("\tFirmware revision : %s\n"
		    "\tNo hardware information available for this "
		    "device\n"), thisdev->ident->revid);
	}
	fprintf(stdout, "\n\n");

	return (tavor_close(thisdev));
}


/*
 * Helper functions lurk beneath this point
 */


/*
 * tavor_identify performs the following actions:
 *
 *	allocates and assigns thisdev->vpr
 *
 *	allocates space for the 4 GUIDs which each IB device must have
 *	queries the tavor driver for this device's GUIDs
 *
 *	determines the hardware vendor, so that thisdev->vpr->vid
 *	can be set correctly
 */
static int
tavor_identify(struct devicelist *thisdev)
{
	int rv = FWFLASH_SUCCESS;
	int fd, ret, i;

	tavor_flash_init_ioctl_t	init_ioctl;
	tavor_flash_ioctl_t		info;
	struct ib_encap_ident		*manuf;
	cfi_t				cfi;
	char temppsid[17];
	char rawpsid[16];

#if defined(_LITTLE_ENDIAN)
	uint32_t			*ptr;
#endif

	/* open the device */
	/* hook thisdev->ident->encap_ident to ib_encap_ident */
	/* check that all the bits are sane */
	/* return success, if warranted */

	errno = 0;
	if ((fd = open(thisdev->access_devname, O_RDONLY)) < 0) {
		logmsg(MSG_INFO,
		    gettext("tavor: Unable to open a %s-attached "
		    "device node: %s: %s\n"), drivername,
		    thisdev->access_devname, strerror(errno));
		return (FWFLASH_FAILURE);
	}

	if ((manuf = calloc(1, sizeof (ib_encap_ident_t))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to calloc space for a "
		    "%s-attached handle structure\n"),
		    drivername);
		return (FWFLASH_FAILURE);
	}
	manuf->magic = FWFLASH_IB_MAGIC_NUMBER;
	manuf->state = FWFLASH_IB_STATE_NONE;
	manuf->fd = fd;

	thisdev->ident->encap_ident = manuf;

	bzero(&init_ioctl, sizeof (tavor_flash_init_ioctl_t));
	bzero(&cfi, sizeof (cfi_t));
	/*
	 * Inform driver that this command supports the Intel Extended
	 * CFI command set.
	 */
	cfi.cfi_char[0x10] = 'M';
	cfi.cfi_char[0x11] = 'X';
	cfi.cfi_char[0x12] = '2';
	init_ioctl.tf_cfi_info[0x4] = MLXSWAPBITS32(cfi.cfi_int[0x4]);

	errno = 0;
	ret = ioctl(fd, TAVOR_IOCTL_FLASH_INIT, &init_ioctl);
	if (ret < 0) {
		logmsg(MSG_ERROR,
		    gettext("ib: TAVOR_IOCTL_FLASH_INIT failed: %s\n"),
		    strerror(errno));
		free(manuf);
		close(fd);
		return (FWFLASH_FAILURE);
	}

	manuf->hwrev = init_ioctl.tf_hwrev;

	logmsg(MSG_INFO, "tavor_identify: init_ioctl: hwrev: %X, "
	    "fwver: %d.%d.%04d\n", init_ioctl.tf_hwrev,
	    init_ioctl.tf_fwrev.tfi_maj, init_ioctl.tf_fwrev.tfi_min,
	    init_ioctl.tf_fwrev.tfi_sub);

	/*
	 * Determine whether the attached driver supports the Intel or
	 * AMD Extended CFI command sets. If it doesn't support either,
	 * then we're hosed, so error out.
	 */
	for (i = 0; i < TAVOR_FLASH_CFI_SIZE_QUADLET; i++) {
		cfi.cfi_int[i] = MLXSWAPBITS32(init_ioctl.tf_cfi_info[i]);
	}
	manuf->cmd_set = cfi.cfi_char[0x13];

	if (cfi.cfi_char[0x10] == 'Q' &&
	    cfi.cfi_char[0x11] == 'R' &&
	    cfi.cfi_char[0x12] == 'Y') {
		/* make sure the cmd set is AMD */
		if (manuf->cmd_set != TAVOR_FLASH_AMD_CMDSET) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unsupported flash device "
			    "command set\n"));
			free(manuf);
			close(fd);
			return (FWFLASH_FAILURE);
		}
		/* set some defaults */
		manuf->sector_sz = TAVOR_FLASH_SECTOR_SZ_DEFAULT;
		manuf->device_sz = TAVOR_FLASH_DEVICE_SZ_DEFAULT;
		logmsg(MSG_INFO, "tavor_identify: CMDSET is AMD, SectorSz "
		    "are default \n");
	} else {
		if (manuf->cmd_set != TAVOR_FLASH_AMD_CMDSET &&
		    manuf->cmd_set != TAVOR_FLASH_INTEL_CMDSET) {
			logmsg(MSG_ERROR,
			    gettext("ib: Unknown flash device command set\n"));
			free(manuf);
			close(fd);
			return (FWFLASH_FAILURE);
		}
		/* read from the CFI data */
		manuf->sector_sz = ((cfi.cfi_char[0x30] << 8) |
		    cfi.cfi_char[0x2F]) << 8;
		manuf->device_sz = 0x1 << cfi.cfi_char[0x27];
		logmsg(MSG_INFO, "tavor_identify: SectorSz is from CFI Data\n");
	}

	logmsg(MSG_INFO, "tavor_identify: sector_sz: 0x%08x dev_sz: 0x%08x\n",
	    manuf->sector_sz, manuf->device_sz);

	manuf->state |= FWFLASH_IB_STATE_MMAP;

	/* set firmware revision */
	manuf->fw_rev.major = init_ioctl.tf_fwrev.tfi_maj;
	manuf->fw_rev.minor = init_ioctl.tf_fwrev.tfi_min;
	manuf->fw_rev.subminor = init_ioctl.tf_fwrev.tfi_sub;

	logmsg(MSG_INFO, "tavor_identify: pn_len %d hwpn %s \n",
	    init_ioctl.tf_pn_len,
	    (init_ioctl.tf_pn_len != 0) ? init_ioctl.tf_hwpn : "(null)");

	if (((thisdev->ident->vid = calloc(1, MLX_VPR_VIDLEN + 1)) == NULL) ||
	    ((thisdev->ident->revid = calloc(1, MLX_VPR_REVLEN + 1)) == NULL)) {

		logmsg(MSG_ERROR,
		    gettext("ib: Unable to allocate space for a VPR "
		    "record.\n"));
		free(thisdev->ident);
		free(manuf->info.mlx_pn);
		free(manuf->info.mlx_psid);
		free(manuf->info.mlx_id);
		free(manuf);
		close(fd);
		return (FWFLASH_FAILURE);
	}
	(void) strlcpy(thisdev->ident->vid, "MELLANOX", MLX_VPR_VIDLEN);
	/*
	 * We actually want the hwrev field from the ioctl above.
	 * Until we find out otherwise, add it onto the end of the
	 * firmware version details.
	 */

	snprintf(thisdev->ident->revid, MLX_VPR_REVLEN, "%d.%d.%03d",
	    manuf->fw_rev.major, manuf->fw_rev.minor,
	    manuf->fw_rev.subminor);

	bzero(manuf->ibguids, sizeof (manuf->ibguids));

	/*
	 * For convenience we read in the Invariant Sector as
	 * well as both the Primary and Secondary Pointer Sectors
	 */

	if ((manuf->inv = calloc(1, manuf->sector_sz)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for storing "
		    "the HCA's Invariant Sector\n"));
		return (FWFLASH_FAILURE);
	}
	bzero(&info, sizeof (tavor_flash_ioctl_t));

	info.tf_type = TAVOR_FLASH_READ_SECTOR;
	info.tf_sector = (caddr_t)manuf->inv;
	info.tf_sector_num = 0;

	errno = 0;

	if ((rv = ioctl(manuf->fd, TAVOR_IOCTL_FLASH_READ, &info))
	    < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to read HCA Invariant Sector\n"));
		return (FWFLASH_FAILURE);
	}

#if defined(_LITTLE_ENDIAN)
	ptr = (uint32_t *)(uintptr_t)manuf->inv;
	for (i = 0; i < (manuf->sector_sz / 4); i++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	if ((manuf->pps = calloc(1, manuf->sector_sz)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for storing "
		    "the HCA's Primary Pointer Sector\n"));
		return (FWFLASH_FAILURE);
	}
	bzero(&info, sizeof (tavor_flash_ioctl_t));

	info.tf_type = TAVOR_FLASH_READ_SECTOR;
	info.tf_sector = (caddr_t)manuf->pps;
	info.tf_sector_num = 1;

	errno = 0;

	if ((rv = ioctl(manuf->fd, TAVOR_IOCTL_FLASH_READ, &info))
	    < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to read HCA Primary "
		    "Pointer Sector\n"));
		return (FWFLASH_FAILURE);
	}

#if defined(_LITTLE_ENDIAN)
	ptr = (uint32_t *)(uintptr_t)manuf->pps;
	for (i = 0; i < (manuf->sector_sz / 4); i++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	if ((manuf->sps = calloc(1, manuf->sector_sz)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for storing "
		    "the HCA's Secondary Pointer Sector\n"));
		return (FWFLASH_FAILURE);
	}
	bzero(&info, sizeof (tavor_flash_ioctl_t));

	info.tf_type = TAVOR_FLASH_READ_SECTOR;
	info.tf_sector = (caddr_t)manuf->sps;
	info.tf_sector_num = 2;

	errno = 0;

	if ((rv = ioctl(manuf->fd, TAVOR_IOCTL_FLASH_READ, &info))
	    < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to read HCA Secondary "
		    "Pointer Sector\n"));
		return (FWFLASH_FAILURE);
	}

#if defined(_LITTLE_ENDIAN)
	ptr = (uint32_t *)(uintptr_t)manuf->sps;
	for (i = 0; i < (manuf->sector_sz / 4); i++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	if ((ret = tavor_get_guids(manuf)) != FWFLASH_SUCCESS) {
		logmsg(MSG_INFO,
		    gettext("ib: No guids found for device %s!\n"),
		    thisdev->access_devname);
	}

	/* set hw part number, psid, and name in handle */
	bzero(temppsid, 17);
	bcopy(manuf->pps+FLASH_PS_PSID_OFFSET, &rawpsid, 16);

	for (i = 0; i < 16; i += 4) {
		temppsid[i]   = rawpsid[i+3];
		temppsid[i+1] = rawpsid[i+2];
		temppsid[i+2] = rawpsid[i+1];
		temppsid[i+3] = rawpsid[i];
	}
	logmsg(MSG_INFO,
	    "tavor: have raw '%s', want munged '%s'\n",
	    rawpsid, temppsid);

	/* now walk the magic decoder ring table */
	manuf->info.mlx_pn = NULL;
	manuf->info.mlx_psid = NULL;
	manuf->info.mlx_id = NULL;
	manuf->pn_len = 0;

	for (i = 0; i < MLX_MAX_ID; i++) {
		if ((strncmp(temppsid, mlx_mdr[i].mlx_psid,
		    MLX_PSID_SZ)) == 0) {
			/* matched */
			if ((manuf->info.mlx_pn = calloc(1,
			    strlen(mlx_mdr[i].mlx_pn) + 1)) == NULL) {
				logmsg(MSG_INFO,
				    "tavor: no space available for the "
				    "HCA PSID record (1)\n");
			} else {
				(void) strlcpy(manuf->info.mlx_pn,
				    mlx_mdr[i].mlx_pn,
				    strlen(mlx_mdr[i].mlx_pn) + 1);
				manuf->pn_len = strlen(mlx_mdr[i].mlx_pn);
			}

			if ((manuf->info.mlx_psid = calloc(1,
			    strlen(mlx_mdr[i].mlx_psid) + 1)) == NULL) {
				logmsg(MSG_INFO,
				    "tavor: no space available for the "
				    "HCA PSID record (2)\n");
			} else {
				(void) strlcpy(manuf->info.mlx_psid,
				    mlx_mdr[i].mlx_psid,
				    strlen(mlx_mdr[i].mlx_psid) + 1);
			}
			if ((manuf->info.mlx_id = calloc(1,
			    strlen(mlx_mdr[i].mlx_id) + 1)) == NULL) {
				logmsg(MSG_INFO,
				    "tavor: no space available for the "
				    "HCA PSID record (3)\n");
			} else {
				(void) strlcpy(manuf->info.mlx_id,
				    mlx_mdr[i].mlx_id,
				    strlen(mlx_mdr[i].mlx_id) + 1);
			}
		}
	}
	if ((manuf->pn_len == 0) || (i == MLX_MAX_ID)) {
		logmsg(MSG_INFO,
		    "tavor: No hardware part number information available "
		    "for this HCA\n");
		/* Until we deliver the arbel driver, it's all Mellanox */
		i = strlen("No hardware information available for this device");

		thisdev->ident->pid = calloc(1, i + 2);
		sprintf(thisdev->ident->pid, "No hardware information "
		    "available for this device");
	} else {
		if ((thisdev->ident->pid = calloc(1,
		    strlen(manuf->info.mlx_psid) + 1)) != NULL) {
			(void) strlcpy(thisdev->ident->pid,
			    manuf->info.mlx_psid,
			    strlen(manuf->info.mlx_psid) + 1);
		} else {
			logmsg(MSG_ERROR,
			    gettext("ib: Unable to allocate space for a "
			    "hardware identifier\n"));
			free(thisdev->ident);
			free(manuf->info.mlx_pn);
			free(manuf->info.mlx_psid);
			free(manuf->info.mlx_id);
			free(manuf);
			close(fd);
			return (FWFLASH_FAILURE);
		}
	}

	for (i = 0; i < 4; i++) {
		if ((thisdev->addresses[i] = calloc(1,
		    (2 * sizeof (uint64_t)) + 1)) == NULL) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to allocate space for a "
			    "human-readable HCA guid\n"));
			return (FWFLASH_FAILURE);
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

	return (rv);
}

/*ARGSUSED*/
static int
tavor_get_guids(struct ib_encap_ident *handle)
{
	int 			rv, j;
	uint32_t		i = 0x00;
	tavor_flash_ioctl_t	info;
	struct mlx_guid_sect	*p, *s;

#if defined(_LITTLE_ENDIAN)
	uint32_t		*ptr, tmp;
#endif

	/*
	 * The reference for this function is the
	 *	Mellanox HCA Flash Programming Application Note
	 * rev 1.44, 2007. Chapter 4 in particular.
	 *
	 * NOTE: this Mellanox document is labelled Confidential
	 * so DO NOT move this file out of usr/closed without
	 * explicit approval from Sun Legal.
	 */

	/*
	 * We need to check for both the Primary and Secondary
	 * Image GUIDs. handle->pps and handle->sps should be
	 * non-NULL by the time we're called, since we depend
	 * on them being stashed in handle. Saves on an ioctl().
	 */

	/* make sure we've got our fallback position organised */
	for (i = 0; i < 4; i++) {
		handle->ibguids[i] = 0x00000000;
	}

	/* convenience .... */

	if ((p = calloc(1, sizeof (mlx_guid_sect_t))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for "
		    "HCA guid record (1)\n"));
		return (FWFLASH_FAILURE);
	}
	if ((s = calloc(1, sizeof (mlx_guid_sect_t))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to allocate space for "
		    "HCA guid record (2)\n"));
		free(p);
		return (FWFLASH_FAILURE);
	}

	bcopy(&handle->pps[0], &i, 4);
	handle->pfi_guid_addr = MLXSWAPBITS32(i) + FLASH_GUID_PTR;
	bcopy(&handle->sps[0], &i, 4);
	handle->sfi_guid_addr = MLXSWAPBITS32(i) + FLASH_GUID_PTR;

	bzero(&info, sizeof (tavor_flash_ioctl_t));
	info.tf_type = TAVOR_FLASH_READ_QUADLET;
	info.tf_addr = handle->pfi_guid_addr;

	errno = 0;

	rv = ioctl(handle->fd, TAVOR_IOCTL_FLASH_READ, &info);
	if (rv < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to read Primary Image "
		    "guid offset\n"));
		free(p);
		free(s);
		return (FWFLASH_FAILURE);
	}

	/*
	 * This is because we want the whole of the section
	 * including the 16 reserved bytes at the front so
	 * that if we recalculate the CRC we've got the correct
	 * data to do it with
	 */
	info.tf_addr = handle->pfi_guid_addr + info.tf_quadlet
	    - FLASH_GUID_PTR - 16;

	bzero(handle->pri_guid_section, sizeof (mlx_guid_sect_t));

	for (j = 0; j < 13; j++) {
		errno = 0;
		if ((rv = ioctl(handle->fd, TAVOR_IOCTL_FLASH_READ,
		    &info)) < 0) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to read Primary Image "
			    "guid chunk %d\n"), j);
		}
		handle->pri_guid_section[j] = info.tf_quadlet;
		info.tf_addr += 4;
	}
	bcopy(&handle->pri_guid_section, p, sizeof (struct mlx_guid_sect));

	/* now grab the secondary guid set */
	bzero(&info, sizeof (tavor_flash_ioctl_t));
	info.tf_type = TAVOR_FLASH_READ_QUADLET;
	info.tf_addr = handle->sfi_guid_addr;

	errno = 0;

	if ((rv = ioctl(handle->fd, TAVOR_IOCTL_FLASH_READ,
	    &info)) < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to read Secondary Image "
		    "guid offset (%s)\n"), strerror(errno));
		free(p);
		free(s);
		return (FWFLASH_FAILURE);
	}

	info.tf_addr = handle->sfi_guid_addr + info.tf_quadlet
	    - FLASH_GUID_PTR - 16;

	bzero(handle->sec_guid_section, sizeof (mlx_guid_sect_t));

	for (j = 0; j < 13; j++) {
		errno = 0;
		if ((rv = ioctl(handle->fd, TAVOR_IOCTL_FLASH_READ,
		    &info)) < 0) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to read Secondary Image "
			    "guid chunk %d (%s)\n"), j, strerror(errno));
			return (FWFLASH_FAILURE);
		}
		handle->sec_guid_section[j] = info.tf_quadlet;
		info.tf_addr += 4;
	}

	bcopy(&handle->sec_guid_section, s, sizeof (struct mlx_guid_sect));

#if defined(_LITTLE_ENDIAN)

	/*
	 * We don't actually care about p or s later on if we
	 * write to the HCA - we've already stored the binary
	 * form in handle->pri_guid_section and handle->sec_guid_section.
	 * What we're doing here is creating human-readable forms.
	 */

	ptr = (uint32_t *)(uintptr_t)p;
	for (j = 0; j < 14; j += 2) {
		tmp = ptr[j];
		ptr[j] = ptr[j+1];
		ptr[j+1] = tmp;
	}

	ptr = (uint32_t *)(uintptr_t)s;
	for (j = 0; j < 14; j += 2) {
		tmp = ptr[j];
		ptr[j] = ptr[j+1];
		ptr[j+1] = tmp;
	}
#endif

	/*
	 * We don't check and munge the GUIDs to the manufacturer's
	 * defaults, because if the GUIDs are actually set incorrectly
	 * at identify time, we really need to know that.
	 *
	 * If the GUIDs are bogus, then we'll fix that in fw_writefw()
	 * by blatting the manufacturer's defaults from the firmware
	 * image file instead.
	 */
	if ((p->nodeguid == s->nodeguid) &&
	    (p->port1guid == s->port1guid) &&
	    (p->port2guid == s->port2guid) &&
	    (p->sysimguid == s->sysimguid)) {
		logmsg(MSG_INFO,
		    "tavor: primary and secondary guids are the same\n");
		handle->ibguids[0] = p->nodeguid;
		handle->ibguids[1] = p->port1guid;
		handle->ibguids[2] = p->port2guid;
		handle->ibguids[3] = p->sysimguid;
	} else {
		/*
		 * We're going to assume that the guids which are numerically
		 * larger than the others are correct and copy them to
		 * handle->ibguids.
		 *
		 * For those in the know wrt InfiniBand, if this assumption
		 * is incorrect, _please_ bug this and fix it, adding a
		 * comment or two to indicate why
		 */
		logmsg(MSG_INFO,
		    "tavor: primary and secondary guids don't all match\n");

		if (s->nodeguid > p->nodeguid) {
			handle->ibguids[0] = s->nodeguid;
			handle->ibguids[1] = s->port1guid;
			handle->ibguids[2] = s->port2guid;
			handle->ibguids[3] = s->sysimguid;
			bzero(p, sizeof (struct mlx_guid_sect));
		} else {
			handle->ibguids[0] = p->nodeguid;
			handle->ibguids[1] = p->port1guid;
			handle->ibguids[2] = p->port2guid;
			handle->ibguids[3] = p->sysimguid;
			bzero(s, sizeof (struct mlx_guid_sect));
		}
	}

	free(p);
	free(s);

	if (fwflash_debug) {
		for (i = 0; i < 4; i++) {
			logmsg(MSG_INFO, "ibguids[%d] %0llx\n", i,
			    handle->ibguids[i]);
		}
	}

	return (FWFLASH_SUCCESS);
}


int
tavor_close(struct devicelist *flashdev)
{

	struct ib_encap_ident *handle;

	handle = (struct ib_encap_ident *)flashdev->ident->encap_ident;
	if (handle->fd > 0) {
		(void) ioctl(handle->fd, TAVOR_IOCTL_FLASH_FINI);
		errno = 0;
		if (close(handle->fd) != 0) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to properly close "
			    "device %s! (%s)\n"),
			    flashdev->access_devname,
			    strerror(errno));
			return (FWFLASH_FAILURE);
		}
		return (FWFLASH_SUCCESS);
	} else
		return (FWFLASH_FAILURE);
}


/*
 * We would not need this if it were not for Cisco's image using the
 * VSD to store boot options and flags for their PXE boot extension,
 * but not setting the proper default values for the extension in
 * their image.  As it turns out, some of the data for the extension
 * is stored in the VSD in the firmware file, and the rest is set by
 * their firmware utility.  That's not very nice for us, since it could
 * change at any time without our knowledge.  Well, for the time being,
 * we can use this to examine and fix up anything in the VSD that we might
 * need to handle, for any vendor specific settings.
 */
static void
tavor_cisco_extensions(mlx_xps_t *hcaxps, mlx_xps_t *diskxps)
{
	uint16_t sig1, sig2;
	uint32_t i;


	bcopy(hcaxps->vsdpsid, &i, 4);
	sig1 = htonl(i);
	bcopy(&hcaxps->vsdpsid[223], &i, 4);
	sig2 = htonl(i);


	if (sig1 == FLASH_VSD_CISCO_SIGNATURE &&
	    sig2 == FLASH_VSD_CISCO_SIGNATURE) {
		logmsg(MSG_INFO,
		    "tavor: CISCO signature found in HCA's VSD, copying to "
		    "new image's VSD\n");

		i = htonl(FLASH_VSD_CISCO_SIGNATURE);
		bcopy(&i, diskxps->vsdpsid, 2);

		/*
		 * Set the boot_version field to '2'. This value is
		 * located in the 2nd byte of the last uint32_t.
		 * Per the previous version of fwflash, we just or
		 * the bit in and get on with it.
		 */

		i = (diskxps->vsdpsid[222] | FLASH_VSD_CISCO_BOOT_VERSION);
		bcopy(&i, &diskxps->vsdpsid[222], 2);
		/*
		 * Now set some defaults for the SRP boot extension,
		 * currently the only extension we support. These flags
		 * are located in the second uint32_t of the VSD.
		 */

		logmsg(MSG_INFO, "tavor: CISCO boot flags currently set "
		    "to 0x%08x\n",
		    diskxps->vsdpsid[1]);

		diskxps->vsdpsid[1] =
		    htonl(diskxps->vsdpsid[1] |
		    FLASH_VSD_CISCO_FLAG_AUTOUPGRADE |
		    FLASH_VSD_CISCO_BOOT_OPTIONS |
		    FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_PORT_1 |
		    FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_PORT_2 |
		    FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_SCAN |
		    FLASH_VSD_CISCO_FLAG_BOOT_TYPE_WELL_KNOWN |
		    FLASH_VSD_CISCO_FLAG_BOOT_TRY_FOREVER);

		logmsg(MSG_INFO, "tavor: CISCO boot flags now set "
		    "to 0x%08x\n",
		    diskxps->vsdpsid[1]);
	} else
		logmsg(MSG_INFO,
		    "tavor: CISCO signature not found in HCA's VSD\n");
}


static int
tavor_write_sector(int fd, int sectnum, int32_t *data)
{
	int rv, i;
	tavor_flash_ioctl_t	cmd;


	bzero(&cmd, sizeof (tavor_flash_ioctl_t));

	cmd.tf_type = TAVOR_FLASH_WRITE_SECTOR;
	cmd.tf_sector_num = sectnum;
	cmd.tf_sector = (caddr_t)data;

	errno = 0;

	logmsg(MSG_INFO,
	    "tavor: tavor_write_sector(fd %d, sectnum 0x%x, data 0x%lx)\n",
	    fd, sectnum, data);
	logmsg(MSG_INFO,
	    "tavor:\n"
	    "\tcmd.tf_type       %d\n"
	    "\tcmd.tf_sector     0x%lx\n"
	    "\tcmd.tf_sector_num %d\n",
	    cmd.tf_type, data, cmd.tf_sector_num);

	/*
	 * If we're debugging, dump the first 64 uint32_t that we've
	 * been passed
	 */
	if (fwflash_debug > 0) {
		i = 0;
		while (i < 64) {
			logmsg(MSG_INFO,
			    "%02x: %08x %08x %08x %08x\n",
			    i, data[i], data[i+1],
			    data[i+2], data[i+3]);
			i += 4;
		}
	}

	rv = ioctl(fd, TAVOR_IOCTL_FLASH_WRITE, &cmd);
	if (rv < 0) {
		logmsg(MSG_ERROR,
		    gettext("tavor: WRITE SECTOR failed for sector "
		    "%d: %s\n"),
		    sectnum, strerror(errno));
		return (FWFLASH_FAILURE);
	} else
		return (FWFLASH_SUCCESS);
}

/*
 * Write zeros to the on-HCA signature and CRC16 fields of sector.
 *
 * NOTE we do _not_ divide start by 4 because we're talking to the
 * HCA, and not finding an offset into verifier->fwimage.
 */

static int
tavor_zero_sig_crc(int fd, uint32_t start)
{
	int 			i, rv;
	tavor_flash_ioctl_t 	cmd;

	/* signature first, then CRC16 */
	bzero(&cmd, sizeof (tavor_flash_ioctl_t));
	cmd.tf_type = TAVOR_FLASH_WRITE_BYTE;
	cmd.tf_byte = 0x00;

	logmsg(MSG_INFO,
	    "tavor: tavor_zero_sig_crc(fd %d, start 0x%04x)\n",
	    fd, start);

	for (i = 0; i < 4; i++) {
		cmd.tf_addr = start + FLASH_PS_SIGNATURE_OFFSET + i;

		logmsg(MSG_INFO,
		    "tavor: invalidating xPS sig (offset from IS 0x%04x) "
		    "byte %d\n",
		    cmd.tf_addr, i);
		errno = 0;

		rv = ioctl(fd, TAVOR_IOCTL_FLASH_WRITE, &cmd);
		if (rv < 0) {
			logmsg(MSG_INFO,
			    gettext("tavor: Unable to write 0x00 to "
			    "offset 0x%04x from IS (sig byte %d): %s\n"),
			    cmd.tf_addr, i, strerror(errno));
			return (FWFLASH_FAILURE);
		}
	}

	cmd.tf_byte = 0x00;
	for (i = 0; i < 2; i++) {
		cmd.tf_addr = start + FLASH_PS_CRC16_OFFSET + i;

		logmsg(MSG_INFO,
		    "tavor: invalidating xPS CRC16 (offset from IS 0x%04x) "
		    "byte %d\n",
		    cmd.tf_addr, i);
		errno = 0;

		rv = ioctl(fd, TAVOR_IOCTL_FLASH_WRITE, &cmd);
		if (rv < 0) {
			logmsg(MSG_INFO,
			    gettext("tavor: Unable to write 0x00 to "
			    "offset 0x%04x from IS (CRC16 byte %d): %s\n"),
			    cmd.tf_addr, i, strerror(errno));
			return (FWFLASH_FAILURE);
		}
	}
	return (FWFLASH_SUCCESS);
}


/*
 * Write a new FIA for the given xPS. The _caller_ handles
 * any required byte-swapping for us.
 *
 * NOTE we do _not_ divide start by 4 because we're talking to the
 * HCA, and not finding an offset into verifier->fwimage.
 */
static int
tavor_write_xps_fia(int fd, uint32_t offset, uint32_t start)
{
	int 			i, rv;
	uint8_t			*addrbytep;
	tavor_flash_ioctl_t 	cmd;

	logmsg(MSG_INFO,
	    "tavor: tavor_write_xps_fia(fd %d, offset 0x%04x, "
	    "start 0x%04x)\n",
	    fd, offset, start);

	addrbytep = (uint8_t *)&start;

	bzero(&cmd, sizeof (tavor_flash_ioctl_t));
	cmd.tf_type = TAVOR_FLASH_WRITE_BYTE;
	for (i = 0; i < 4; i++) {
		cmd.tf_byte = addrbytep[i];
		cmd.tf_addr = offset + FLASH_PS_FI_ADDR_OFFSET + i;
		logmsg(MSG_INFO,
		    "tavor: writing xPS' new FIA, byte %d (0x%0x) at "
		    "offset from IS 0x%04x\n",
		    i, cmd.tf_byte, cmd.tf_addr);
		errno = 0;

		rv = ioctl(fd, TAVOR_IOCTL_FLASH_WRITE, &cmd);
		if (rv < 0) {
			logmsg(MSG_INFO,
			    gettext("tavor: Unable to write byte %d "
			    "of xPS new FIA (0x%0x, offset from IS "
			    "0x%04x): %s\n"),
			    i, cmd.tf_byte, cmd.tf_addr, strerror(errno));
			return (FWFLASH_FAILURE);
		}
	}
	return (FWFLASH_SUCCESS);
}


/*
 * Write the new CRC16 and Signature to the given xPS. The caller
 * has already byte-swapped newcrc if that's necessary.
 *
 * NOTE we do _not_ divide start by 4 because we're talking to the
 * HCA, and not finding an offset into verifier->fwimage.
 */
static int
tavor_write_xps_crc_sig(int fd, uint32_t offset, uint16_t newcrc)
{
	int 			i, rv;
	uint8_t			*bytep;
	uint32_t		tempsig;
	tavor_flash_ioctl_t 	cmd;

	logmsg(MSG_INFO,
	    "tavor: tavor_write_xps_crc_sig(fd %d, offset 0x%04x, "
	    "newcrc 0x%04x)\n",
	    fd, offset, newcrc);

	bytep = (uint8_t *)&newcrc;

	bzero(&cmd, sizeof (tavor_flash_ioctl_t));
	cmd.tf_type = TAVOR_FLASH_WRITE_BYTE;
	for (i = 0; i < 2; i++) {
		cmd.tf_byte = bytep[i];
		cmd.tf_addr = offset + FLASH_PS_CRC16_OFFSET + i;
		logmsg(MSG_INFO,
		    "tavor: writing new XPS CRC16, byte %d (0x%0x) at "
		    "offset from IS 0x%04x\n",
		    i, bytep[i], cmd.tf_addr);
		errno = 0;

		rv = ioctl(fd, TAVOR_IOCTL_FLASH_WRITE, &cmd);
		if (rv < 0) {
			logmsg(MSG_INFO,
			    gettext("tavor: Unable to write byte %d "
			    "(0x%0x) of xPS' new CRC16 to offset "
			    "from IS 0x%04x: %s\n"),
			    i, bytep[i], cmd.tf_addr, strerror(errno));
			return (FWFLASH_FAILURE);
		}
	}

	tempsig = htonl(FLASH_PS_SIGNATURE);
	bytep = (uint8_t *)&tempsig;

	for (i = 0; i < 4; i++) {
		cmd.tf_byte = bytep[i];
		cmd.tf_addr = offset + FLASH_PS_SIGNATURE_OFFSET + i;
		logmsg(MSG_INFO,
		    "tavor: writing new xPS Signature, byte %d (0x%0x) at "
		    "offset from IS 0x%04x\n",
		    i, bytep[i], cmd.tf_addr);
		errno = 0;

		rv = ioctl(fd, TAVOR_IOCTL_FLASH_WRITE, &cmd);
		if (rv < 0) {
			logmsg(MSG_INFO,
			    gettext("tavor: Unable to write byte %d (0x%0x) "
			    "of xPS' signature at offset from IS 0x%04x: %s\n"),
			    i, bytep[i], cmd.tf_addr, strerror(errno));
			return (FWFLASH_FAILURE);
		}
	}
	return (FWFLASH_SUCCESS);
}



/*
 * This function contains "Begin/End documentation departure point"
 * because the reality of what actually _works_ is quite, quite
 * different to what is written in the Mellanox HCA Flash Application
 * Programming Guide.
 */
static int
tavor_blast_image(int fd, int prisec, uint32_t hcafia, uint32_t sectsz,
    struct mlx_xps *newxps)
{
	uint32_t i, j, rv;
	uint32_t startsectimg, startsecthca, numsect;

	if ((prisec != 1) && (prisec != 2)) {
		logmsg(MSG_ERROR,
		    gettext("tavor: invalid image number requested (%d)\n"),
		    prisec);
		return (FWFLASH_FAILURE);
	}

	/* Begin documentation departure point  */

	/* zero the HCA's PPS signature and CRC */
	if (tavor_zero_sig_crc(fd, (prisec * sectsz))
	    != FWFLASH_SUCCESS) {
		logmsg(MSG_INFO,
		    "tavor: Unable zero HCA's %s signature "
		    "and CRC16 fields\n",
		    ((prisec == 1) ? "PPS" : "SPS"));
		return (FWFLASH_FAILURE);
	}

	logmsg(MSG_INFO, "tavor: zeroing HCA's %s sig and crc\n",
	    (prisec == 1) ? "pps" : "sps");

	/* End documentation departure point  */

	/* make sure we don't inadvertently overwrite bits */

	startsectimg = MLXSWAPBITS32(newxps->fia) / sectsz;
	startsecthca = hcafia / sectsz;

	numsect = (MLXSWAPBITS32(newxps->fis) / sectsz) +
	    ((MLXSWAPBITS32(newxps->fis) % sectsz) ? 1 : 0);

	logmsg(MSG_INFO, "tavor: %s imgsize 0x%0x  startsecthca %d, "
	    "startsectimg %d, num sectors %d\n",
	    (prisec == 1) ? "PFI" : "SFI", MLXSWAPBITS32(newxps->fis),
	    startsecthca, startsectimg, numsect);

	for (i = 0; i < numsect; i++) {

		j = (MLXSWAPBITS32(newxps->fia) + (i * sectsz)) / 4;

		logmsg(MSG_INFO, "tavor: image offset 0x%0x\n", j);
		logmsg(MSG_INFO, "tavor: writing HCA sector %d\n",
		    i + startsecthca);

		if (tavor_write_sector(fd, i + startsecthca,
		    &verifier->fwimage[j])
		    != FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to write "
			    "sector %d to HCA\n"),
			    i + startsecthca);
			return (FWFLASH_FAILURE);
		}
		(void) printf(" .");

		rv = tavor_readback(fd, i + startsecthca, sectsz);
		if (rv != FWFLASH_SUCCESS) {
			logmsg(MSG_ERROR,
			    gettext("tavor: Unable to read sector %d "
			    "back from HCA\n"), i + startsecthca);
			return (FWFLASH_FAILURE);
		}
		(void) printf(" | ");
	}

	/* Begin documentation departure point  */

	/* invalidate the xps signature and fia fields */
	newxps->signature = 0xffffffff;
	newxps->crc16 = 0xffff;
	/* we put the fia back to imgfia later */
	newxps->fia = 0xffffffff;
	/* End documentation departure point  */

	/* success so far, now burn the new xPS */
	if (tavor_write_sector(fd, prisec, (int *)newxps)
	    != FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to write new %s "
		    "pointer sector to HCA\n"),
		    (prisec == 1) ? "primary" : "secondary");
		return (FWFLASH_FAILURE);
	}
	(void) printf(" .");

	/* Begin documentation departure point  */

	/* write new fia to the HCA's pps */
	logmsg(MSG_INFO, "tavor: writing new fia (0x%0x) to HCA\n",
	    MLXSWAPBITS32(newxps->fia));

	if (tavor_write_xps_fia(fd, (prisec * sectsz),
	    MLXSWAPBITS32(hcafia)) != FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to update HCA's %s "
		    "pointer sector FIA record\n"),
		    (prisec == 1) ? "primary" : "secondary");
		return (FWFLASH_FAILURE);
	}

	/* don't forget the byte-swapping */
	newxps->fia = MLXSWAPBITS32(hcafia);
	newxps->signature =
	    (uint32_t)MLXSWAPBITS32(FLASH_PS_SIGNATURE);
	newxps->crc16 =
	    MLXSWAPBITS16(crc16((uint8_t *)newxps, FLASH_PS_CRC16_SIZE));

	logmsg(MSG_INFO, "tavor: writing new fia 0x%0x, "
	    "sig 0x%0x and new crc16 0x%0x\n",
	    newxps->fia, MLXSWAPBITS32(newxps->signature),
	    newxps->crc16);

	if (tavor_write_xps_crc_sig(fd, (prisec * sectsz),
	    newxps->crc16) != FWFLASH_SUCCESS) {
		/*
		 * Now we're REALLY hosed. If the card comes up at all,
		 * expect it to be in "Maintenance Mode".
		 */
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to update HCA's %s CRC "
		    "and Firmware Image signature fields\n"),
		    (prisec == 1) ? "PPS" : "SPS");
		return (FWFLASH_FAILURE);
	}

	rv = tavor_readback(fd, prisec, sectsz);
	if (rv != FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR,
		    gettext("tavor: Unable to read %s pointer sector "
		    "from HCA\n"),
		    (prisec == 1) ? "Primary" : "Secondary");
		return (FWFLASH_FAILURE);
	}
	(void) printf(" |");
	/* End documentation departure point  */
	return (FWFLASH_SUCCESS);
}


static int
tavor_readback(int infd, int whichsect, int sectsz)
{
	uint32_t *data;
	tavor_flash_ioctl_t	cmd;
	int rv;

	bzero(&cmd, sizeof (tavor_flash_ioctl_t));
	data = calloc(1, sectsz); /* assumption! */

	cmd.tf_type = TAVOR_FLASH_READ_SECTOR;
	cmd.tf_sector_num = whichsect;
	cmd.tf_sector = (caddr_t)data;
	rv = ioctl(infd, TAVOR_IOCTL_FLASH_READ, &cmd);
	if (rv < 0) {
		logmsg(MSG_INFO,
		    "tavor: UNABLE TO READ BACK SECTOR %d from HCA\n",
		    whichsect);
		return (FWFLASH_FAILURE);
	}
	free(data);
	return (FWFLASH_SUCCESS);
}


/*
 * crc16 - computes 16 bit crc of supplied buffer.
 *   image should be in network byteorder
 *   result is returned in host byteorder form
 */
static uint16_t
crc16(uint8_t *image, uint32_t size)
{
	const uint16_t	poly = 0x100b;
	uint32_t	crc = 0xFFFF;
	uint32_t	word;
	uint32_t	i, j;

	for (i = 0; i < size / 4; i++) {
		word = (image[4 * i] << 24) |
		    (image[4 * i + 1] << 16) |
		    (image[4 * i + 2] << 8) |
		    (image[4 * i + 3]);

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
