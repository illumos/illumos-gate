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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DADA_IMPL_IDENTIFY_H
#define	_SYS_DADA_IMPL_IDENTIFY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Implementation identify data.
 */
struct	dcd_identify {
	ushort_t dcd_config;	/*	0  general configuration bits */
	ushort_t dcd_fixcyls;	/*	1  # of fixed cylinders  */
	ushort_t dcd_remcyls;	/*   2  # of removable cylinders */
	ushort_t dcd_heads;	/*   3  # of heads */
	ushort_t dcd_trksiz;	/*   4  # of unformatted bytes/track  */
	ushort_t dcd_secsiz;	/*   5  # of unformatted bytes/sector */
	ushort_t dcd_sectors;	/*   6  # of sectors/track */
	ushort_t dcd_resv1[3];	/*   7  "Vendor Unique" */
	char	 dcd_drvser[20];	/*  10  Serial number */
	ushort_t dcd_buftype;	/*  20  Buffer type */
	ushort_t dcd_bufsz;	/*  21  Buffer size in 512 byte incr */
	ushort_t dcd_ecc;	/*  22  # of ecc bytes avail on rd/wr */
	char	 dcd_fw[8];	/*  23  Firmware revision */
	char	 dcd_model[40];	/*  27  Model # */
	ushort_t dcd_mult1;	/*  47  Multiple command flags */
	ushort_t dcd_dwcap;	/*  48  Doubleword capabilities */
	ushort_t dcd_cap;	/*  49  Capabilities */
	ushort_t dcd_resv2;	/*  50  Reserved */
	ushort_t dcd_piomode;	/*  51  PIO timing mode */
	ushort_t dcd_dmamode;	/*  52  DMA timing mode */
	ushort_t dcd_validinfo;	/*  53  bit0: wds 54-58, bit1: 64-70 */
	ushort_t dcd_curcyls;	/*  54	# of current cylinders */
	ushort_t dcd_curheads;	/*  55  # of current heads */
	ushort_t dcd_cursectrk;	/*  56  # of current sectors/track */
	ushort_t dcd_cursccp[2];	/*  57  current sectors capacity */
	ushort_t dcd_mult2;	/*  59  multiple sectors info */
	ushort_t dcd_addrsec[2];	/*  60  LBA only: no of addr secs */
	ushort_t dcd_sworddma;	/*  62  single word dma modes */
	ushort_t dcd_dworddma;	/*  63  double word dma modes */
	ushort_t dcd_advpiomode;	/*  64  advanced PIO modes supported */
	ushort_t dcd_minmwdma;	/*  65  min multi-word dma cycle info    */
	ushort_t dcd_recmwdma;	/*  66  rec multi-word dma cycle info    */
	ushort_t dcd_minpio;	/*  67  min PIO cycle info */
	ushort_t dcd_minpioflow;	/*  68  min PIO cycle info w/flow ctl */
	ushort_t dcd_padding1[11];	/* 69 pad to 79 */
	ushort_t dcd_majvers;	/*  80  ATA major version supported */
	ushort_t dcd_padding2[4];	/* 81 pad to 84 */
	ushort_t dcd_features85;	/*  85  feature enabled bits */
	ushort_t dcd_padding3[2];	/* 86 pad to 87 */
	ushort_t dcd_ultra_dma;	/*  88	Ultra dma capability */
	ushort_t dcd_padding4[37];	/* 89 pad to 125 */
	ushort_t dcd_lastlun;	/* 126 last logical unit number */
	ushort_t dcd_padding5[129];	/* pad to 255 */
};


/*
 * Indentify data size definition
 */

#define	SUN_IDENTSIZE	(sizeof (struct dcd_identify))

/*
 * The following are the bit for dcd_config field
 */
#define	ATAPI_DEVICE  		(1 << 15)
#define	ATANON_REMOVABLE	(1 << 6)

/*
 * The following are the bit defined  word 64
 */
#define	PIO_MODE4_MASK		0x02
#define	PIO_MODE3_MASK		0x01

/*
 * The following are bits for dcd_majvers, word 80
 */
#define	IDENTIFY_80_ATAPI_4	0x0010

/*
 * The following are the bits for dcd_features85, word 85
 */
#define	IDENTIFY_85_WCE		(1 << 5)

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DADA_IMPL_IDENTIFY_H */
