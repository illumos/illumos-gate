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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * libparted - a library for manipulating disk partitions
 *
 * This module recognizes the Solaris x86 VTOC so that the
 * partition can be identified as "solaris".
 *
 * Mark Logan <mark.logan@sun.com>
 */

#include <config.h>

#include <parted/parted.h>
#include <parted/endian.h>
#include <parted/debug.h>

#if ENABLE_NLS
#include <libintl.h>
#define	_(String)	dgettext(PACKAGE, String)
#else
#define	_(String)	(String)
#endif /* ENABLE_NLS */

#include <unistd.h>
#include <string.h>

#define	BLOCK_SIZES	((int[2]) {512, 0})

#define	VTOC_SANE	0x600DDEEE
#define	LEN_DKL_VVOL	8
#define	V_NUMPAR	16		/* # of logical partitions */
#define	LEN_DKL_ASCII	128		/* length of dkl_asciilabel */

#define	LEN_DKL_PAD	\
	(512 - \
	((5 * sizeof (uint32_t)) + \
	LEN_DKL_VVOL + \
	(2 * sizeof (uint16_t)) + \
	(10 * sizeof (uint32_t)) + \
	(V_NUMPAR * sizeof (struct partition)) + \
	(V_NUMPAR * sizeof (uint32_t)) + \
	LEN_DKL_ASCII + \
	(2 * (sizeof (uint16_t)))))

#define	DKL_MAGIC	0xDABE		/* magic number */

struct partition {
	unsigned short p_tag;		/* ID tag of partition */
	unsigned short p_flag;		/* permission flags */
	long p_start;			/* start sector no of partition */
	long p_size;			/* # of blocks in partition */
};

struct vtoc {
	unsigned long	v_bootinfo[3];	/* info for mboot (unsupported) */
	unsigned long	v_sanity;	/* to verify vtoc sanity */
	unsigned long	v_version;	/* layout version */
	char 		v_volume[LEN_DKL_VVOL]; /* volume name */
	unsigned short	v_sectorsz;	/* sector size in bytes */
	unsigned short	v_nparts;	/* number of partitions */
	unsigned long	v_reserved[10]; /* free space */
	struct partition v_part[V_NUMPAR]; /* partition headers */
	int32_t	timestamp[V_NUMPAR];	/* partition timestamp (unsupported) */
	char		 v_asciilabel[LEN_DKL_ASCII];	/* for compatibility */
	char		dkl_pad[LEN_DKL_PAD];	/* unused part of 512 bytes */
	uint16_t	dkl_magic;	/* identifies this label format */
	uint16_t	dkl_cksum;	/* xor checksum of sector */
};

static PedGeometry*
solaris_x86_probe(PedGeometry* geom)
{
	int8_t buf[512 * 3];
	struct vtoc *pvtoc;
	uint16_t *dkl_magic;

	if (geom->length < 5)
		return (0);
	if (!ped_geometry_read(geom, buf, 1, 1))
		return (0);

	pvtoc = (struct vtoc *)buf;

	if (pvtoc->v_sanity == VTOC_SANE && pvtoc->dkl_magic == DKL_MAGIC) {
		PedSector block_size = pvtoc->v_sectorsz / 512;
		/*
		 * Use the size of the backup slice:
		 */
		PedSector block_count = pvtoc->v_part[2].p_size;
		return ped_geometry_new(geom->dev, geom->start,
		    block_size * block_count);
	}

	return (NULL);
}

#ifndef DISCOVER_ONLY
static int
solaris_x86_clobber(PedGeometry* geom)
{
	char	buf[512*3];

	if (!ped_geometry_read(geom, buf, 1, 1))
		return (0);

	memset(buf, 0, sizeof (struct vtoc));

	return (ped_geometry_write(geom, buf, 1, 1));
}
#endif /* !DISCOVER_ONLY */

static PedFileSystemOps solaris_x86_ops = {
	.probe = solaris_x86_probe,
#ifndef DISCOVER_ONLY
	.clobber = solaris_x86_clobber,
#else
	.clobber = NULL,
#endif
	.open = NULL,
	.create = NULL,
	.close = NULL,
	.check = NULL,
	.copy =	 NULL,
	.resize = NULL,
	.get_create_constraint = NULL,
	.get_resize_constraint = NULL,
	.get_copy_constraint = NULL
};

static PedFileSystemType solaris_x86_type = {
	.next =	NULL,
	.ops =	&solaris_x86_ops,
	.name =	"solaris",
	.block_sizes = BLOCK_SIZES
};

void
ped_file_system_solaris_x86_init()
{
	ped_file_system_type_register(&solaris_x86_type);
}

void
ped_file_system_solaris_x86_done()
{
	ped_file_system_type_unregister(&solaris_x86_type);
}
