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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MISC_SCSI_H
#define	_MISC_SCSI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "device.h"

struct track_info {
	uint32_t ti_flags;		/* flags, see below */
	int ti_track_no;		/* Track number */
	int ti_session_no;		/* session no. 0 if cannot find that */
	uchar_t ti_track_mode;		/* track ctrl nibble, see READ TOC */
	uchar_t ti_data_mode;		/* Mode 0,1,2 or FF */
	uint32_t ti_start_address;	/* Start LBA */
	uint32_t ti_track_size;		/* Size in blocks */
	uint32_t ti_packet_size;	/* If a packet written track */
	uint32_t ti_free_blocks;	/* For an incomplete track */
	uint32_t ti_lra;		/* LBA of Last written user datablock */
	uint32_t ti_nwa;		/* Next writable address */
};

/*
 * track_info_flags
 */
#define	TI_FIXED_PACKET		1
#define	TI_PACKET_MODE		2
#define	TI_BLANK_TRACK		4
#define	TI_RESERVED_TRACK	8
#define	TI_COPY			0x10
#define	TI_DAMAGED_TRACK	0x20
#define	TI_NWA_VALID		0x100
#define	TI_LRA_VALID		0x200
#define	TI_SESSION_NO_VALID	0x1000
#define	TI_FREE_BLOCKS_VALID	0x2000

/*
 * Track mode nibble
 */
#define	TRACK_MODE_DATA		0x06
#define	TRACK_MODE_AUDIO	0x02

/* 74 minutes, each second is 75 blocks */
#define	MAX_CD_BLKS		(74*60*75)
#define	MAX_DVD_BLKS		2295100

/*
 * Macros to translate between a bandwidth ("RATE") and a Speed ("X")
 * for CDs.  Eg, "1X == 176,400 bytes/second".
 *
 * Some devices just multiply speed by 176. But more accurate ones
 * multiply speed by 176.4.
 */
#define	CD_RATE_TO_X(r) ((r) % 176 ? ((uint_t)(((double)(r)*10)/1764 + 0.5)) :\
		(r) / 176)
#define	CD_X_TO_RATE(s)	((((s)*1764)+5)/10)

/*
 * Macros to translate between a bandwidth ("RATE") and a Speed ("X")
 * for DVDs. Eg, "1X == 1,385,000 bytes/second".
 */
#define	DVD_RATE_TO_X(r)	(((ulong_t)(r)*1000)/1385000)
#define	DVD_X_TO_RATE(s)	(((s)*1385000)/1000)


#define	FINALIZE_TIMEOUT		(6 * 12)	/* Six minutes */

uint32_t read_scsi32(void *addr);
uint16_t read_scsi16(void *addr);
void load_scsi32(void *addr, uint32_t val);
void load_scsi16(void *addr, uint16_t val);

int get_mode_page(int fd, int page_no, int pc, int buf_len, uchar_t *buffer);
int set_mode_page(int fd, uchar_t *buffer);
int build_track_info(cd_device *dev, int trackno, struct track_info *t_info);
uchar_t get_data_mode(int fd, uint32_t lba);
int prepare_for_write(cd_device *dev, int track_mode, int test_write,
    int keep_disc_open);
int finalize(cd_device *dev);
uint32_t get_last_possible_lba(cd_device *dev);
int read_audio_through_read_cd(cd_device *dev, uint_t start_lba, uint_t nblks,
    uchar_t *buf);
int eject_media(cd_device *dev);
int cd_speed_ctrl(cd_device *dev, int cmd, int speed);
int rt_streaming_ctrl(cd_device *dev, int cmd, int speed);

void tao_init(int mode);
void tao_fini(void);
void write_init(int mode);
void write_fini(void);

#ifdef	__cplusplus
}
#endif

#endif /* _MISC_SCSI_H */
