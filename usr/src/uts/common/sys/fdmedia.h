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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FDMEDIA_H
#define	_SYS_FDMEDIA_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Default names for label
 */
static char deflabel_35[] = {
	"3.5\" floppy cyl %d alt 0 hd %d sec %d"
};
static char deflabel_525[] = {
	"5.25\" floppy cyl %d alt 0 hd %d sec %d"
};

/*
 * default characteristics
 */
static struct fdattr fdtypes[] = {
	{	/* [0] = struct fdattr fdattr_5H */
		360,		/* rotational speed */
		1,		/* interleave factor */
		0x1B,		/* gap 3 length */
		0x54		/* format gap 3 length */
	},
	{	/* [1] = struct fdattr fdattr_5Q */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x1B,		/* gap 3 length */
		0x54		/* format gap 3 length */
	},
	{	/* [2] = struct fdattr fdattr_5D9 */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x2A,		/* gap 3 length */
		0x50		/* format gap 3 length */
	},
	{	/* [3] = struct fdattr fdattr_5D8 */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x2A,		/* gap 3 length */
		0x50		/* format gap 3 length */
	},
	{	/* [4] = struct fdattr fdattr_5D4 */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x80,		/* gap 3 length */
		0xF0		/* format gap 3 length */
	},
	{	/* [5] = struct fdattr fdattr_5D16 */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x20,		/* gap 3 length */
		0x32		/* format gap 3 length */
	},
	{	/* [6] = struct fdattr fdattr_3E */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x1B,		/* gap 3 length */
		0x53		/* format gap 3 length */
	},
	{	/* [7] = struct fdattr fdattr_3H */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x1B,		/* gap 3 length */
		0x6C		/* format gap 3 length */
	},
	{	/* [8] = struct fdattr fdattr_3I */
		300,		/* rotational speed */
		1,		/* interleave factor */
		4,		/* gap 3 length */
		12		/* format gap 3 length */
	},
	{	/* [9] = struct fdattr fdattr_3M */
		360,		/* rotational speed */
		1,		/* interleave factor */
		0x35,		/* gap 3 length */
		0x74		/* format gap 3 length */
	},
	{	/* [10] = struct fdattr fdattr_3D */
		300,		/* rotational speed */
		1,		/* interleave factor */
		0x1B,		/* gap 3 length */
		0x50		/* format gap 3 length */
	}
};

static int nfdtypes = sizeof (fdtypes) / sizeof (fdtypes[0]);


static struct fd_char dfc_80x36 = {
		3,		/* medium */
		1000,		/* transfer rate */
		80,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		36,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_80x21 = {
		3,		/* medium */
		500,		/* transfer rate */
		80,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		21,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_80x18 = {
		3,		/* medium */
		500,		/* transfer rate */
		80,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		18,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_80x15 = {
		5,		/* medium */
		500,		/* transfer rate */
		80,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		15,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_80x9 = {
		3,		/* medium */
		250,		/* transfer rate */
		80,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		9,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_77x8 = {
		3,		/* medium */
		500,		/* transfer rate */
		77,		/* number of cylinders */
		2,		/* number of heads */
		1024,		/* sector size */
		8,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_40x16 = {
		5,		/* medium */
		250,		/* transfer rate */
		40,		/* number of cylinders */
		2,		/* number of heads */
		256,		/* sector size */
		16,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_40x9 = {
		5,		/* medium */
		250,		/* transfer rate */
		40,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		9,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_40x8 = {
		5,		/* medium */
		250,		/* transfer rate */
		40,		/* number of cylinders */
		2,		/* number of heads */
		512,		/* sector size */
		8,		/* sectors per track */
		1,		/* # steps per data track */
};
static struct fd_char dfc_40x4 = {
		5,		/* medium */
		250,		/* transfer rate */
		40,		/* number of cylinders */
		2,		/* number of heads */
		1024,		/* sector size */
		4,		/* sectors per track */
		1,		/* # steps per data track */
};

static struct fd_char *defchar[] = {
		&dfc_80x15,	/* FMT_5H */
		&dfc_80x9,	/* FMT_5Q */
		&dfc_40x9,	/* FMT_5D9 */
		&dfc_40x8,	/* FMT_5D8 */
		&dfc_40x4,	/* FMT_5D4 */
		&dfc_40x16,	/* FMT_5D16 */
		&dfc_80x36,	/* FMT_3E */
		&dfc_80x18,	/* FMT_3H */
		&dfc_80x21,	/* FMT_3I */
		&dfc_77x8,	/* FMT_3M */
		&dfc_80x9	/* FMT_3D */
};


static struct fd_drive dfd_350ED = {
		0,	/* ejectable,  does the drive support eject? */
		4,	/* maxsearch, size of per-unit search table */
		0,	/* cyl to start write precompensation */
		80,	/* cyl to start reducing write current */
		1,	/* step width pulse in 1 us units */
		30,	/* step rate in 100 us units */
		150,	/* head settle delay, in 100 us units */
		150,	/* head load delay, in 100 us units */
		2560,	/* head unload delay, in 100 us units */
		3,	/* motor on delay, in 100 ms units */
		20,	/* motor off delay, in 100 ms units */
		65,	/* precomp level, bit shift, in nano-secs */
		0,	/* pins, defines meaning of pin 1, 2, 4, and 34 */
		0,	/* flags, TRUE READY, Starting Sector #, & Motor On */
};
static struct fd_drive dfd_350HD = {
		0,	/* ejectable,  does the drive support eject? */
		4,	/* maxsearch, size of per-unit search table */
		0,	/* cyl to start write prcompensation */
		80,	/* cyl to start reducing write current */
		1,	/* step width pulse in 1 us units */
		30,	/* step rate in 100 us units */
		150,	/* head settle delay, in 100 us units */
		150,	/* head load delay, in 100 us units */
		2560,	/* head unload delay, in 100 us units */
		3,	/* motor on delay, in 100 ms units */
		20,	/* motor off delay, in 100 ms units */
		125,	/* precomp level, bit shift, in nano-secs */
		0,	/* pins, defines meaning of pin 1, 2, 4, and 34 */
		0,	/* flags, TRUE READY, Starting Sector #, & Motor On */
};
static struct fd_drive dfd_525HD = {
		0,	/* ejectable,  does the drive support eject? */
		6,	/* maxsearch, size of per-unit search table */
		43,	/* cyl to start write prcompensation */
		80,	/* cyl to start reducing write current */
		1,	/* step width pulse in 1 us units */
		30,	/* step rate in 100 us units */
		150,	/* head settle delay, in 100 us units */
		150,	/* head load delay, in 100 us units */
		2560,	/* head unload delay, in 100 us units */
		5,	/* motor on delay, in 100 ms units */
		20,	/* motor off delay, in 100 ms units */
		175,	/* precomp level, bit shift, in nano-secs */
		0,	/* pins, defines meaning of pin 1, 2, 4, and 34 */
		0,	/* flags, TRUE READY, Starting Sector #, & Motor On */
};
static struct fd_drive dfd_525DD = {
		0,	/* ejectable,  does the drive support eject? */
		4,	/* maxsearch, size of per-unit search table */
		22,	/* cyl to start write prcompensation */
		40,	/* cyl to start reducing write current */
		1,	/* step width pulse in 1 us units */
		60,	/* step rate in 100 us units */
		150,	/* head settle delay, in 100 us units */
		150,	/* head load delay, in 100 us units */
		2560,	/* head unload delay, in 100 us units */
		5,	/* motor on delay, in 100 ms units */
		20,	/* motor off delay, in 100 ms units */
		250,	/* precomp level, bit shift, in nano-secs */
		0,	/* pins, defines meaning of pin 1, 2, 4, and 34 */
		0,	/* flags, TRUE READY, Starting Sector #, & Motor On */
};

/*
 * Default partition maps
 */
static struct partition dpt_80x36[NDKMAP] = {
		{ 0, 0, 0,	79*2*36 },	/* part 0 - all but last cyl */
		{ 0, 0, 79*2*36, 1*2*36 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	80*2*36 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_80x21[NDKMAP] = {
		{ 0, 0, 0,	79*2*21 },	/* part 0 - all but last cyl */
		{ 0, 0, 79*2*21, 1*2*21 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	80*2*21 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_80x18[NDKMAP] = {
		{ 0, 0, 0,	79*2*18 },	/* part 0 - all but last cyl */
		{ 0, 0, 79*2*18, 1*2*18 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	80*2*18 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_80x15[NDKMAP] = {
		{ 0, 0, 0,	79*2*15 },	/* part 0 - all but last cyl */
		{ 0, 0, 79*2*15, 1*2*15 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	80*2*15 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_80x9[NDKMAP] = {
		{ 0, 0, 0,	79*2*9 },	/* part 0 - all but last cyl */
		{ 0, 0, 79*2*9,	 1*2*9 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	80*2*9 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_77x8[NDKMAP] = {
		/* double number of blocks since sector size is 1024 */
		{ 0, 0, 0,	 76*2*8*2 },	/* part 0 - all but last cyl */
		{ 0, 0, 76*2*8*2, 1*2*8*2 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	 77*2*8*2 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_40x16[NDKMAP] = {
		/* halve number of blocks since sector size is 256 */
		{ 0, 0, 0,	 39*2*16/2 },	/* part 0 - all but last cyl */
		{ 0, 0, 39*2*16/2, 1*2*16/2 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	 40*2*16/2 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_40x9[NDKMAP] = {
		{ 0, 0, 0,	39*2*9 },	/* part 0 - all but last cyl */
		{ 0, 0, 39*2*9,  1*2*9 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	40*2*9 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_40x8[NDKMAP] = {
		/* double number of blocks since sector size is 1024 */
		{ 0, 0, 0,	 39*2*8*2 },	/* part 0 - all but last cyl */
		{ 0, 0, 39*2*8*2, 1*2*8*2 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	 40*2*8*2 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};
static struct partition dpt_40x4[NDKMAP] = {
		{ 0, 0, 0,	39*2*4 },	/* part 0 - all but last cyl */
		{ 0, 0, 39*2*4,  1*2*4 },	/* part 1 - just the last cyl */
		{ 0, 0, 0,	40*2*4 },	/* part 2 - "the whole thing" */
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 },
		{ 0, 0, 0, 0 }, { 0, 0, 0, 0 }, { 0, 0, 0, 0 }
};

static struct partition *fdparts[] = {
		dpt_80x15,	/* FMT_5H */
		dpt_80x9,	/* FMT_5Q */
		dpt_40x9,	/* FMT_5D9 */
		dpt_40x8,	/* FMT_5D8 */
		dpt_40x4,	/* FMT_5D4 */
		dpt_40x16,	/* FMT_5D16 */
		dpt_80x36,	/* FMT_3E */
		dpt_80x18,	/* FMT_3H */
		dpt_80x21,	/* FMT_3I */
		dpt_77x8,	/* FMT_3M */
		dpt_80x9	/* FMT_3D */
};

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FDMEDIA_H */
