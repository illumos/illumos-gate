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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * p_generic.c :
 *      This file contains the functions for pcmcia memory card plug-in
 * 	for libsm.so.g
 */

#include <stdio.h>
#include <unistd.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/dkio.h>
#include <string.h>
#include "../../../library/common/l_defines.h"
#include "../../../library/inc/rmedia.h"

/*
 * These defines are from the PCMCIA memory driver driver
 *      header files (pcramio.h/pcramvar.h) and they are in
 *      the Platform Specific (PS) train.
 */
#ifndef PCRAM_PROBESIZE
#define	PCRAMIOC	('P' << 8)
#define	PCRAM_PROBESIZE (PCRAMIOC|22)   /* Probe memory card size */
#endif

/* FORMAT PATTERNS */
#define		PATTERN_1	0x55;
#define		PATTERN_2	0xaa;
#define		PATTERN_3	0xff;
#define		PATTERN_4	0x00;

#define	PERROR(string)	my_perror(gettext(string))

static void
my_perror(char *err_string)
{

	int error_no;
	if (errno == 0)
		return;

	error_no = errno;
	(void) fprintf(stderr, gettext(err_string));
	(void) fprintf(stderr, gettext(" : "));
	errno = error_no;
	perror("");
}

int32_t
_m_version_no(void)
{
	return (SM_PCMEM_VERSION_1);
}

int32_t
_m_device_type(ushort_t ctype, ushort_t mtype)
{
	if (ctype == DKC_PCMCIA_MEM) {
		if (mtype == 0)
			return (0);
	}
	return (-1);
}


int32_t
_m_get_media_info(rmedia_handle_t *handle, void *ip)
{
	smmedium_prop_t *mp = (smmedium_prop_t *)ip;
	struct dk_geom dkg;
	enum dkio_state		state = DKIO_NONE;

	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
				LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}

	if (ioctl(handle->sm_fd, DKIOCSTATE, &state) < 0) {
		PERROR("DKIOCSTATE failed");
		return (-1);
	}

	if (state != DKIO_INSERTED) {
		DPRINTF("No media.\n");
		mp->sm_media_type = SM_NOT_PRESENT;
		mp->sm_version = SMMEDIA_PROP_V_1;
		return (0);

	}
	/*  Get card cyl/head/secptrack info  */
	if (ioctl(handle->sm_fd, DKIOCGGEOM, &dkg) < 0) {
		/*
		 * Card doesn't have a CIS. So, ask driver to probe
		 * card size info
		 */
		if (ioctl(handle->sm_fd, PCRAM_PROBESIZE, &dkg) < 0) {
			int save_errno;
			save_errno = errno;
			(void) fprintf(stderr, gettext("Unable to get card \
						size information"));
			errno = save_errno;
			if (!errno)
				errno = EIO;
			return (-1);
		}
	}

	mp->sm_media_type = SM_PCMCIA_MEM;
	mp->sm_blocksize = DEV_BSIZE; /* PCMCIA memory default sector size */
	mp->sm_pcyl = dkg.dkg_pcyl;
	mp->sm_nhead = dkg.dkg_nhead;
	mp->sm_nsect = dkg.dkg_nsect;
	mp->sm_capacity = mp->sm_pcyl * mp->sm_nhead * mp->sm_nsect;
	return (0);
}



/* ARGSUSED0 */

int32_t
_m_get_device_info(rmedia_handle_t *handle, void *ip)
{
	smdevice_info_t *mp = (smdevice_info_t *)ip;
	char *vendor_name, *product_name, *fw_version;

	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
				LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	vendor_name = (char *)malloc(1);
	if (vendor_name == NULL) {
	if (!errno)
		errno = ENOMEM;
		return (-1);
	}
	product_name = (char *)malloc(1);
	if (product_name == NULL) {
		free(vendor_name);
		if (!errno)
			errno = ENOMEM;
		return (-1);
	}

	fw_version = (char *)malloc(1);
	if (fw_version == NULL) {
		free(vendor_name);
		free(product_name);
			if (!errno)
		errno = ENOMEM;
		return (-1);
	}

	vendor_name[0] = 0;
	product_name[0] = 0;
	fw_version[0] = 0;
	mp->sm_interface_type = IF_PCMCIA;
	mp->sm_vendor_name = vendor_name;
	mp->sm_product_name = product_name;
	mp->sm_firmware_version = fw_version;
	return (0);
}

int32_t
_m_free_device_info(rmedia_handle_t *handle, void *ip)
{
	struct smdevice_info *dev_info = ip;

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		errno = EINVAL;
		return (-1);
	}

	free(dev_info->sm_vendor_name);
	free(dev_info->sm_product_name);
	free(dev_info->sm_firmware_version);
	return (0);
}


/* ARGSUSED1 */

int32_t
_m_media_format(rmedia_handle_t *handle, void *ip)
{
	int32_t	sec_size;	/* sector size */
	int32_t	i, j;
	char    wrpat;
	char    wrbuf[512];
	char    rdbuf[512];
	enum dkio_state		state = DKIO_NONE;
	int32_t	card_size;	/* PCMCIA memory card size */
	struct dk_geom dkg;

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
				LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (ioctl(handle->sm_fd, DKIOCSTATE, &state) < 0) {
		PERROR("DKIOCSTATE failed");
		return (-1);
	}

	if (state != DKIO_INSERTED) {
			(void) fprintf(stderr,
				gettext("No media.\n"));
		return (-1);
	}


	/*  Get card cyl/head/secptrack info  */
	if (ioctl(handle->sm_fd, DKIOCGGEOM, &dkg) < 0) {
		/*
		 * Card doesn't have a CIS. So, ask driver to probe
		 * card size info
		 */
		if (ioctl(handle->sm_fd, PCRAM_PROBESIZE, &dkg) < 0) {
			PERROR("Unable to get card size information");
			return (-1);
		}
	}

	/* PCMCIA memory default sector size */
	sec_size = DEV_BSIZE;

	card_size = dkg.dkg_ncyl * dkg.dkg_nhead *
		dkg.dkg_nsect * sec_size;

	/*
	 * First try to format only 512 bytes with four different
	 * patterns.
	 */
	for (i = 0; i < 4; ++i) {
		switch (i) {

		case 0:
			wrpat = (uchar_t)PATTERN_1;
			break;
		case 1:
			wrpat = (uchar_t)PATTERN_2;
			break;
		case 2:
			wrpat = (uchar_t)PATTERN_3;
			break;
		case 3:
			wrpat = PATTERN_4;
			break;
		}

		if (llseek(handle->sm_fd, (off_t)0, 0) != 0) {
			if (!errno)
				errno = EIO;
			PERROR("seek to blk 0 failed");
			return (-1);
		}

		(void) memset(wrbuf, wrpat, 512);

		if (write(handle->sm_fd, &wrbuf[0], 512) != 512) {
			if (!errno)
				errno = EIO;
			PERROR("Format Write failed");
			return (-1);
		}

		if (llseek(handle->sm_fd, (off_t)0, 0) != 0) {
			if (!errno)
				errno = EIO;
			PERROR("seek to blk 0 failed");
			return (-1);
		}

		if (read(handle->sm_fd, &rdbuf[0], 512) != 512) {
			if (!errno)
				errno = EIO;
			PERROR("Format Read failed");
			return (-1);
		}

		if (memcmp(wrbuf, rdbuf, 512) != 0) {
			(void) fprintf(stderr,
				gettext("Format Compare Error"));
			return (-1);
		}
	}
	/*
	 * Then format the whole memory card with patterns
	 * 0xff and 0x00 to erase the card.
	 */
	for (i = 0; i < 2; ++i) {

		if (i == 0) {
			wrpat = (uchar_t)PATTERN_3;
		} else {
			wrpat = PATTERN_4;
		}

		if (llseek(handle->sm_fd, (off_t)0, 0) != 0) {
			if (!errno)
				errno = EIO;
			PERROR("seek to blk 0 failed");
			return (-1);
		}

		(void) memset(wrbuf, wrpat, 512);

		for (j = 0; j < (card_size/512); ++j) {
			if (write(handle->sm_fd, &wrbuf[0], 512) != 512) {
				if (!errno)
					errno = EIO;
				PERROR("Format Write failed");
				return (-1);
			}
		}
		/*
		 * do a verify
		 */

		if (llseek(handle->sm_fd, (off_t)0, 0) != 0) {
			if (!errno)
				errno = EIO;
			PERROR("seek to blk 0 failed");
			return (-1);
		}

		for (j = 0; j < (card_size/512); ++j) {
			if (read(handle->sm_fd, &rdbuf[0], 512) != 512) {
				if (!errno)
					errno = EIO;
				PERROR("Format Read failed");
				return (-1);
			}
			if (memcmp(wrbuf, rdbuf, 512) != 0) {
				(void) fprintf(stderr,
					gettext("Format Compare Error"));
				return (-1);
			}
		}
	}

	return (0);
}

int32_t
_m_media_format_track(rmedia_handle_t *handle, void *ip)
{
	struct format_track *ft = (struct format_track *)ip;
	int32_t	sec_size;	/* sector size */
	int32_t	i, j;
	char    wrpat;
	char    wrbuf[512];
	char    rdbuf[512];
	enum dkio_state		state = DKIO_NONE;
	int32_t	fmt_start; 	/* The offset where format starts */
	struct dk_geom dkg;

	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
				LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Using DKIOCSTATE ioctl()
	 * to replace FDGETCHANGE ioctl()
	 * start out with state=DKIO_NONE
	 */
	if (ioctl(handle->sm_fd, DKIOCSTATE, &state) < 0) {
		PERROR("DKIOCSTATE failed");
		return (-1);
	}

	if (state != DKIO_INSERTED) {
		(void) fprintf(stderr,
			gettext("No media\n"));
		return (-1);
	}


	/*  Get card cyl/head/secptrack info  */
	if (ioctl(handle->sm_fd, DKIOCGGEOM, &dkg) < 0) {
		/*
		 * Card doesn't have a CIS. So, ask driver to probe
		 * card size info
		 */
		if (ioctl(handle->sm_fd, PCRAM_PROBESIZE, &dkg) < 0) {
			PERROR("Unable to get card size information");
			return (-1);
		}
	}

	/* PCMCIA memory default sector size */
	sec_size = DEV_BSIZE;

	fmt_start = ft->track_no * dkg.dkg_nhead * dkg.dkg_nsect * sec_size;

	/*
	 * If first track is being formatted, first try to format
	 * only 512 bytes with four different patterns.
	 */
	if (ft->track_no == 0) {
		for (i = 0; i < 4; ++i) {
			switch (i) {

			case 0:
				wrpat = (uchar_t)PATTERN_1;
				break;
			case 1:
				wrpat = (uchar_t)PATTERN_2;
				break;
			case 2:
				wrpat = (uchar_t)PATTERN_3;
				break;
			case 3:
				wrpat = PATTERN_4;
				break;
			}

			if (llseek(handle->sm_fd, (off_t)0, 0) != 0) {
				if (!errno)
					errno = EIO;
				PERROR("seek to blk 0 failed");
				return (-1);
			}

			(void) memset(wrbuf, wrpat, 512);

			if (write(handle->sm_fd, &wrbuf[0], 512) != 512) {
				if (!errno)
					errno = EIO;
				PERROR("Format Write failed");
				return (-1);
			}

			if (llseek(handle->sm_fd, (off_t)0, 0) != 0) {
				if (!errno)
					errno = EIO;
				PERROR("seek to blk 0 failed");
				return (-1);
			}

			if (read(handle->sm_fd, &rdbuf[0], 512) != 512) {
				if (!errno)
					errno = EIO;
				PERROR("Format Read failed");
				return (-1);
			}

			if (memcmp(wrbuf, rdbuf, 512) != 0) {
				(void) fprintf(stderr,
					gettext("Format Compare Error"));
				return (-1);
			}
		}
	}

	/*
	 * Then format the whole memory card with patterns
	 * 0xff and 0x00 to erase the card.
	 */
	for (i = 0; i < 2; ++i) {

		if (i == 0) {
			wrpat = (uchar_t)PATTERN_3;
		} else {
			wrpat = PATTERN_4;
		}

		if (llseek(handle->sm_fd, (off_t)fmt_start, 0) != fmt_start) {
			if (!errno)
				errno = EIO;
			PERROR("seek to blk 0 failed");
			return (-1);
		}

		(void) memset(wrbuf, wrpat, 512);

		for (j = fmt_start/512; j < (fmt_start/512 + dkg.dkg_nsect);
								j++) {
			if (write(handle->sm_fd, &wrbuf[0], 512) != 512) {
				if (!errno)
					errno = EIO;
				PERROR("Format Write failed");
				return (-1);
			}
		}
		/*
		 * do a verify
		 */

		if (llseek(handle->sm_fd, (off_t)fmt_start, 0) != fmt_start) {
			if (!errno)
				errno = EIO;
			PERROR("seek to blk 0 failed");
			return (-1);
		}

		for (j = fmt_start/512; j < (fmt_start/512 + dkg.dkg_nsect);
								++j) {
			if (read(handle->sm_fd, &rdbuf[0], 512) != 512) {
				if (!errno)
					errno = EIO;
				PERROR("Format Read failed");
				return (-1);
			}
			if (memcmp(wrbuf, rdbuf, 512) != 0) {
				(void) fprintf(stderr,
					gettext("Format Compare Error"));
				return (-1);
			}
		}
	}

	return (0);
}
