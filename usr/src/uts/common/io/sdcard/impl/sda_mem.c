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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 */

/*
 * Memory target support for SDcard.
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/conf.h>
#include <sys/blkdev.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdcard/sda.h>
#include <sys/sdcard/sda_impl.h>

static int sda_mem_errno(sda_err_t);
static int sda_mem_rw(sda_slot_t *, bd_xfer_t *, uint8_t, uint16_t);
static void sda_mem_done(sda_cmd_t *);
static void sda_mem_getstring(uint32_t *, char *, int, int);

/*
 * To minimize complexity and reduce layering, we implement almost the
 * entire memory card driver (sdcard) here.  The memory card still
 * needs to be a separate driver though, due to the requirement to
 * have both SCSI HBA bus ops and SD bus ops.
 */

/*
 * Everything beyond this is private.
 */

int
sda_mem_errno(sda_err_t errno)
{
	/* the hot path */
	if (errno == SDA_EOK) {
		return (0);
	}

	switch (errno) {
	case SDA_ENOMEM:
		return (ENOMEM);
	case SDA_ETIME:
		return (ETIMEDOUT);
	case SDA_EWPROTECT:
		return (EROFS);
	case SDA_ESUSPENDED:
	case SDA_ENODEV:
		return (ENODEV);
	case SDA_EFAULT:
	case SDA_ECRC7:
	case SDA_EPROTO:
	case SDA_ERESET:
	case SDA_EIO:
	case SDA_ERESID:
	default:
		return (EIO);
	}
}

void
sda_mem_done(sda_cmd_t *cmdp)
{
	bd_xfer_t	*xfer = sda_cmd_data(cmdp);
	int		errno = sda_cmd_errno(cmdp);

	bd_xfer_done(xfer, sda_mem_errno(errno));
	sda_cmd_free(cmdp);
}

int
sda_mem_rw(sda_slot_t *slot, bd_xfer_t *xfer, uint8_t cmd, uint16_t flags)
{
	sda_cmd_t	*cmdp;
	uint64_t	nblks;
	uint64_t	blkno;
	uint16_t	rblen;

	blkno = xfer->x_blkno;
	nblks = xfer->x_nblks;

	ASSERT(nblks != 0);

	if ((blkno + nblks) > slot->s_nblks) {
		return (EINVAL);
	}

	cmdp = sda_cmd_alloc(slot, cmd, blkno << slot->s_bshift,
	    R1, xfer, KM_NOSLEEP);
	if (cmdp == NULL) {
		return (ENOMEM);
	}

	if (slot->s_hostp->h_dma != NULL) {
		cmdp->sc_dmah = xfer->x_dmah;
		cmdp->sc_ndmac = xfer->x_ndmac;
		cmdp->sc_dmac = xfer->x_dmac;
		cmdp->sc_kvaddr = 0;
	} else {
		cmdp->sc_ndmac = 0;
		cmdp->sc_kvaddr = xfer->x_kaddr;
	}

	rblen = slot->s_blksz;

	/* other fields are set by sda_cmd_alloc */
	cmdp->sc_blksz = rblen;
	cmdp->sc_nblks = (uint16_t)nblks;
	cmdp->sc_flags = flags;

	sda_cmd_submit(slot, cmdp, sda_mem_done);
	return (0);
}

int
sda_mem_bd_read(void *arg, bd_xfer_t *xfer)
{
	sda_slot_t	*slot = arg;
	uint8_t		cmd;
	uint16_t	flags;

	if (xfer->x_flags & BD_XFER_POLL) {
		return (EIO);
	}
	if (xfer->x_nblks > 1) {
		cmd = CMD_READ_MULTI;
		flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_READ |
		    SDA_CMDF_AUTO_CMD12;
	} else {
		cmd = CMD_READ_SINGLE;
		flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_READ;
	}

	return (sda_mem_rw(slot, xfer, cmd, flags));
}

int
sda_mem_bd_write(void *arg, bd_xfer_t *xfer)
{
	sda_slot_t	*slot = arg;
	uint8_t		cmd;
	uint16_t	flags;

	if (xfer->x_flags & BD_XFER_POLL) {
		return (EIO);
	}
	if ((slot->s_flags & SLOTF_WRITABLE) == 0) {
		return (EROFS);
	}
	if (xfer->x_nblks > 1) {
		cmd = CMD_WRITE_MULTI;
		flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_WRITE |
		    SDA_CMDF_AUTO_CMD12;
	} else {
		cmd = CMD_WRITE_SINGLE;
		flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_WRITE;
	}

	return (sda_mem_rw(slot, xfer, cmd, flags));
}

void
sda_mem_bd_driveinfo(void *arg, bd_drive_t *drive)
{
	sda_slot_t	*slot = arg;

	drive->d_qsize = 4;	/* we queue up internally, 4 is enough */
	drive->d_maxxfer = 65536;
	drive->d_removable = B_TRUE;
	drive->d_hotpluggable = B_FALSE;
	drive->d_target = slot->s_slot_num;
}

int
sda_mem_bd_mediainfo(void *arg, bd_media_t *media)
{
	sda_slot_t	*slot = arg;

	sda_slot_enter(slot);
	if (!slot->s_ready) {
		sda_slot_exit(slot);
		return (ENXIO);
	}
	media->m_nblks = slot->s_nblks;
	media->m_blksize = slot->s_blksz;
	media->m_readonly = slot->s_flags & SLOTF_WRITABLE ? B_FALSE : B_TRUE;
	media->m_solidstate = B_TRUE;
	sda_slot_exit(slot);
	return (0);
}

uint32_t
sda_mem_getbits(uint32_t *resp, int hibit, int len)
{
	uint32_t	val = 0;
	uint32_t	bit;

	for (bit = hibit; len--; bit--) {
		val <<= 1;
		val |= ((resp[bit / 32]) >> (bit % 32)) & 1;
	}
	return (val);
}

void
sda_mem_getstring(uint32_t *resp, char *s, int hibit, int len)
{
	while (len--) {
		*s++ = sda_mem_getbits(resp, hibit, 8);
		hibit -= 8;
	}
	*s = 0;
}

uint32_t
sda_mem_maxclk(sda_slot_t *slot)
{
	static const uint32_t	mult[16] = {
		0, 10, 12, 13, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80
	};

	static const uint32_t	units[8] = {
		10000, 100000, 1000000, 10000000, 0, 0, 0, 0,
	};
	uint8_t			ts;

	ts = sda_mem_getbits(slot->s_rcsd, 103, 8);

	return ((units[ts & 0x7]) * (mult[(ts >> 3) & 0xf]));
}

int
sda_mem_parse_cid_csd(sda_slot_t *slot)
{
	uint32_t	*rcid;
	uint32_t	*rcsd;
	int		csdver;
	uint16_t	rblen;
	uint16_t	bshift;
	uint32_t	cmult;
	uint32_t	csize;

	rcid = slot->s_rcid;
	rcsd = slot->s_rcsd;

	csdver = sda_mem_getbits(rcsd, 127, 2);

	if (slot->s_flags & SLOTF_SDMEM) {
		switch (csdver) {
		case 0:
			csize = sda_mem_getbits(rcsd, 73, 12);
			rblen = (1 << sda_mem_getbits(rcsd, 83, 4));
			cmult = (4 << sda_mem_getbits(rcsd, 49, 3));
			bshift = 9;
			break;
		case 1:
			rblen = 512;
			csize = sda_mem_getbits(rcsd, 69, 22);
			cmult = 1024;
			bshift = 0;
			break;
		default:
			sda_slot_err(slot, "Unknown SD CSD version (%d)",
			    csdver);
			return (DDI_FAILURE);
		}

		slot->s_mfg = sda_mem_getbits(rcid, 127, 8);
		sda_mem_getstring(rcid, slot->s_oem, 119, 2);
		sda_mem_getstring(rcid, slot->s_prod, 103, 5);
		slot->s_majver = sda_mem_getbits(rcid, 63, 4);
		slot->s_minver = sda_mem_getbits(rcid, 59, 4);
		slot->s_serial =  sda_mem_getbits(rcid, 55, 32);
		slot->s_year = sda_mem_getbits(rcid, 19, 8) + 2000;
		slot->s_month = sda_mem_getbits(rcid, 11, 4);

	} else if (slot->s_flags & SLOTF_MMC) {
		if ((csdver < 1) || (csdver > 2)) {
			sda_slot_err(slot, "Unknown MMC CSD version (%d)",
			    csdver);
			return (DDI_FAILURE);
		}

		switch (sda_mem_getbits(rcsd, 125, 4)) {
		case 0:	/* MMC 1.0 - 1.2 */
		case 1:	/* MMC 1.4 */
			slot->s_mfg = sda_mem_getbits(rcid, 127, 24);
			slot->s_oem[0] = 0;
			sda_mem_getstring(rcid, slot->s_prod, 103, 7);
			slot->s_majver = sda_mem_getbits(rcid, 47, 4);
			slot->s_minver = sda_mem_getbits(rcid, 43, 4);
			slot->s_serial =  sda_mem_getbits(rcid, 39, 24);
			break;

		case 2:	/* MMC 2.0 - 2.2 */
		case 3:	/* MMC 3.1 - 3.3 */
		case 4:	/* MMC 4.x */
			slot->s_mfg = sda_mem_getbits(rcid, 127, 8);
			sda_mem_getstring(rcid, slot->s_oem, 119, 2);
			sda_mem_getstring(rcid, slot->s_prod, 103, 6);
			slot->s_majver = sda_mem_getbits(rcid, 55, 4);
			slot->s_minver = sda_mem_getbits(rcid, 51, 4);
			slot->s_serial =  sda_mem_getbits(rcid, 47, 32);
			break;

		default:
			/* this error isn't fatal to us */
			sda_slot_err(slot, "Unknown MMCA version (%d)",
			    sda_mem_getbits(rcsd, 125, 4));
			break;
		}

		slot->s_year = sda_mem_getbits(rcid, 11, 4) + 1997;
		slot->s_month = sda_mem_getbits(rcid, 15, 4);

		csize = sda_mem_getbits(rcsd, 73, 12);
		rblen = (1 << sda_mem_getbits(rcsd, 83, 4));
		cmult = (4 << sda_mem_getbits(rcsd, 49, 3));
		bshift = 9;

	} else {

		sda_slot_err(slot, "Card type unknown");
		return (DDI_FAILURE);
	}

	/*
	 * These fields are common to all known MMC/SDcard memory cards.
	 *
	 * The spec requires that block size 512 be supported.
	 * The media may have a different native size, but 512
	 * byte blocks will always work.  This is true for SDcard,
	 * and apparently for MMC as well.
	 */
	rblen = max(rblen, 512);	/* paranoia */
	slot->s_nblks = (csize + 1) * cmult * (rblen / 512);
	slot->s_bshift = bshift;
	slot->s_blksz = 512;

	slot->s_r2w = (1 << sda_mem_getbits(rcsd, 28, 3));
	slot->s_ccc = sda_mem_getbits(rcsd, 95, 12);
	slot->s_perm_wp = sda_mem_getbits(rcsd, 13, 1);
	slot->s_temp_wp = sda_mem_getbits(rcsd, 12, 1);
	slot->s_dsr = sda_mem_getbits(rcsd, 76, 1);

	if (((slot->s_ccc & (1 << 4)) == 0) ||
	    (slot->s_perm_wp != 0) || (slot->s_temp_wp != 0)) {
		slot->s_flags &= ~SLOTF_WRITABLE;
	}

	return (DDI_SUCCESS);
}
