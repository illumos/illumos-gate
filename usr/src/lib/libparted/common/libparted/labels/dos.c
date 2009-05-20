/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 1999, 2000, 2001, 2004, 2005, 2007
    Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#include <sys/time.h>
#include <stdbool.h>
#include <parted/parted.h>
#include <parted/debug.h>
#include <parted/endian.h>

#if ENABLE_NLS
#  include <libintl.h>
#  define _(String) dgettext (PACKAGE, String)
#else
#  define _(String) (String)
#endif /* ENABLE_NLS */

/* this MBR boot code is loaded into 0000:7c00 by the BIOS.  See mbr.s for
 * the source, and how to build it
 */

static const unsigned char MBR_BOOT_CODE[] = {
	0xfa, 0xb8, 0x00, 0x10, 0x8e, 0xd0, 0xbc, 0x00,
	0xb0, 0xb8, 0x00, 0x00, 0x8e, 0xd8, 0x8e, 0xc0,
	0xfb, 0xbe, 0x00, 0x7c, 0xbf, 0x00, 0x06, 0xb9,
	0x00, 0x02, 0xf3, 0xa4, 0xea, 0x21, 0x06, 0x00,
	0x00, 0xbe, 0xbe, 0x07, 0x38, 0x04, 0x75, 0x0b,
	0x83, 0xc6, 0x10, 0x81, 0xfe, 0xfe, 0x07, 0x75,
	0xf3, 0xeb, 0x16, 0xb4, 0x02, 0xb0, 0x01, 0xbb,
	0x00, 0x7c, 0xb2, 0x80, 0x8a, 0x74, 0x01, 0x8b,
	0x4c, 0x02, 0xcd, 0x13, 0xea, 0x00, 0x7c, 0x00,
	0x00, 0xeb, 0xfe
};

#define MSDOS_MAGIC		0xAA55
#define PARTITION_MAGIC_MAGIC	0xf6f6

#define PARTITION_EMPTY		0x00
#define PARTITION_FAT12		0x01
#define PARTITION_FAT16_SM	0x04
#define PARTITION_DOS_EXT	0x05
#define PARTITION_FAT16		0x06
#define PARTITION_NTFS		0x07
#define PARTITION_HPFS		0x07
#define PARTITION_FAT32		0x0b
#define PARTITION_FAT32_LBA	0x0c
#define PARTITION_FAT16_LBA	0x0e
#define PARTITION_EXT_LBA	0x0f

#define PART_FLAG_HIDDEN	0x10	/* Valid for FAT/NTFS only */
#define PARTITION_FAT12_H	(PARTITION_FAT12	| PART_FLAG_HIDDEN)
#define PARTITION_FAT16_SM_H	(PARTITION_FAT16_SM	| PART_FLAG_HIDDEN)
#define PARTITION_DOS_EXT_H	(PARTITION_DOS_EXT	| PART_FLAG_HIDDEN)
#define PARTITION_FAT16_H	(PARTITION_FAT16	| PART_FLAG_HIDDEN)
#define PARTITION_NTFS_H	(PARTITION_NTFS		| PART_FLAG_HIDDEN)
#define PARTITION_FAT32_H	(PARTITION_FAT32	| PART_FLAG_HIDDEN)
#define PARTITION_FAT32_LBA_H	(PARTITION_FAT32_LBA	| PART_FLAG_HIDDEN)
#define PARTITION_FAT16_LBA_H	(PARTITION_FAT16_LBA	| PART_FLAG_HIDDEN)

#define PARTITION_COMPAQ_DIAG	0x12
#define PARTITION_LDM		0x42
#define PARTITION_LINUX_SWAP	0x82
#define PARTITION_LINUX		0x83
#define PARTITION_LINUX_EXT	0x85
#define PARTITION_LINUX_LVM	0x8e
#define PARTITION_SUN_UFS	0xbf
#define PARTITION_DELL_DIAG	0xde
#define PARTITION_GPT		0xee
#define PARTITION_PALO		0xf0
#define PARTITION_PREP		0x41
#define PARTITION_LINUX_RAID	0xfd
#define PARTITION_LINUX_LVM_OLD 0xfe

/* This constant contains the maximum cylinder number that can be represented
 * in (C,H,S) notation.  Higher cylinder numbers are reserved for
 * "too big" indicators (in which case only LBA addressing can be used).
 * 	Some partition tables in the wild indicate this number is 1021.
 * (i.e. 1022 is sometimes used to indicate "use LBA").
 */
#define MAX_CHS_CYLINDER	1021

typedef struct _DosRawPartition		DosRawPartition;
typedef struct _DosRawTable		DosRawTable;

#ifdef __sun
#define __attribute__(X)	/*nothing*/
#endif /* __sun */

/* note: lots of bit-bashing here, thus, you shouldn't look inside it.
 * Use chs_to_sector() and sector_to_chs() instead.
 */
#ifdef __sun
#pragma pack(1)
#endif
typedef struct {
	uint8_t		head;
	uint8_t		sector;
	uint8_t		cylinder;
} __attribute__((packed)) RawCHS;

/* ripped from Linux source */
struct _DosRawPartition {
        uint8_t		boot_ind;	/* 00:  0x80 - active */
	RawCHS		chs_start;	/* 01: */
	uint8_t		type;		/* 04: partition type */
	RawCHS		chs_end;	/* 05: */
	uint32_t	start;		/* 08: starting sector counting from 0 */
	uint32_t	length;		/* 0c: nr of sectors in partition */
} __attribute__((packed));

struct _DosRawTable {
	char			boot_code [440];
	uint32_t                mbr_signature;	/* really a unique ID */
	uint16_t                Unknown;
	DosRawPartition		partitions [4];
	uint16_t		magic;
} __attribute__((packed));
#ifdef __sun
#pragma pack()
#endif


/* OrigState is information we want to preserve about the partition for
 * dealing with CHS issues
 */
typedef struct {
	PedGeometry	geom;
	DosRawPartition	raw_part;
	PedSector	lba_offset;	/* needed for computing start/end for
					 * logical partitions */
} OrigState;

typedef struct {
	unsigned char	system;
	int		boot;
	int		hidden;
	int		raid;
	int		lvm;
	int		lba;
	int		palo;
	int		prep;
	OrigState*	orig;			/* used for CHS stuff */
} DosPartitionData;

static PedDiskType msdos_disk_type;

/* FIXME: factor out this function: copied from aix.c, with changes to
   the description, and an added sector number argument.
   Read sector, SECTOR_NUM (which has length DEV->sector_size) into malloc'd
   storage.  If the read fails, free the memory and return zero without
   modifying *BUF.  Otherwise, set *BUF to the new buffer and return 1.  */
static int
read_sector (const PedDevice *dev, PedSector sector_num, char **buf)
{
	char *b = ped_malloc (dev->sector_size);
	PED_ASSERT (b != NULL, return 0);
	if (!ped_device_read (dev, b, sector_num, 1)) {
		ped_free (b);
		return 0;
	}
	*buf = b;
	return 1;
}

static int
msdos_probe (const PedDevice *dev)
{
	PedDiskType*	disk_type;
	DosRawTable*	part_table;
	int		i;

	PED_ASSERT (dev != NULL, return 0);

        if (dev->sector_size < sizeof *part_table)
                return 0;

	char *label;
	if (!read_sector (dev, 0, &label))
		return 0;

	part_table = (DosRawTable *) label;

	/* check magic */
	if (PED_LE16_TO_CPU (part_table->magic) != MSDOS_MAGIC)
		goto probe_fail;

	/* if this is a FAT fs, fail here.  Note that the Smart Boot Manager
	 * Loader (SBML) signature indicates a partition table, not a file
	 * system.
	 */
	if ((!strncmp (part_table->boot_code + 0x36, "FAT", 3)
	    && strncmp (part_table->boot_code + 0x40, "SBML", 4) != 0)
	    || !strncmp (part_table->boot_code + 0x52, "FAT", 3))
		goto probe_fail;

	/* If this is a GPT disk, fail here */
	for (i = 0; i < 4; i++) {
		if (part_table->partitions[i].type == PARTITION_GPT)
			goto probe_fail;
	}

	/* If this is an AIX Physical Volume, fail here.  IBMA in EBCDIC */
	if (part_table->boot_code[0] == (char) 0xc9 &&
	    part_table->boot_code[1] == (char) 0xc2 &&
	    part_table->boot_code[2] == (char) 0xd4 &&
	    part_table->boot_code[3] == (char) 0xc1)
		goto probe_fail;

#ifdef ENABLE_PC98
	/* HACK: it's impossible to tell PC98 and msdos disk labels apart.
	 * Someone made the signatures the same (very clever).  Since
	 * PC98 has some idiosyncracies with it's boot-loader, it's detection
	 * is more reliable */
	disk_type = ped_disk_type_get ("pc98");
	if (disk_type && disk_type->ops->probe (dev))
		goto probe_fail;
#endif /* ENABLE_PC98 */

	free (label);
	return 1;

 probe_fail:
	free (label);
	return 0;
}

static PedDisk*
msdos_alloc (const PedDevice* dev)
{
	PedDisk* disk;
	PED_ASSERT (dev != NULL, return NULL);

	disk = _ped_disk_alloc ((PedDevice*)dev, &msdos_disk_type);
	if (disk)
		disk->disk_specific = NULL;
	return disk;
}

static PedDisk*
msdos_duplicate (const PedDisk* disk)
{
	PedDisk*	new_disk;
       
	new_disk = ped_disk_new_fresh (disk->dev, &msdos_disk_type);
	if (!new_disk)
		return NULL;
	new_disk->disk_specific = NULL;
	return new_disk;
}

static void
msdos_free (PedDisk* disk)
{
	PED_ASSERT (disk != NULL, return);

	_ped_disk_free (disk);
}

#ifndef DISCOVER_ONLY
static int
msdos_clobber (PedDevice* dev)
{
	DosRawTable		table;

	PED_ASSERT (dev != NULL, return 0);
	PED_ASSERT (msdos_probe (dev), return 0);

	if (!ped_device_read (dev, &table, 0, 1))
		return 0;
	table.magic = 0;
	return ped_device_write (dev, (void*) &table, 0, 1);
}
#endif /* !DISCOVER_ONLY */

static int
chs_get_cylinder (const RawCHS* chs)
{
	return chs->cylinder + ((chs->sector >> 6) << 8);
}

static int
chs_get_head (const RawCHS* chs)
{
	return chs->head;
}

/* counts from 0 */
static int
chs_get_sector (const RawCHS* chs)
{
	return (chs->sector & 0x3f) - 1;
}

static PedSector
chs_to_sector (const PedDevice* dev, const PedCHSGeometry *bios_geom,
	       const RawCHS* chs)
{
	PedSector	c;		/* not measured in sectors, but need */
	PedSector	h;		/* lots of bits */
	PedSector	s;

	PED_ASSERT (bios_geom != NULL, return 0);
	PED_ASSERT (chs != NULL, return 0);

	c = chs_get_cylinder (chs);
	h = chs_get_head (chs);
	s = chs_get_sector (chs);

	if (c > MAX_CHS_CYLINDER)		/* MAGIC: C/H/S is irrelevant */
		return 0;
	if (s < 0)
		return 0;
	return ((c * bios_geom->heads + h) * bios_geom->sectors + s)
		* (dev->sector_size / 512);
}

static void
sector_to_chs (const PedDevice* dev, const PedCHSGeometry* bios_geom,
	       PedSector sector, RawCHS* chs)
{
	PedSector	real_c, real_h, real_s;

	PED_ASSERT (dev != NULL, return);
	PED_ASSERT (chs != NULL, return);
	
	if (!bios_geom)
		bios_geom = &dev->bios_geom;

	sector /= (dev->sector_size / 512);

	real_c = sector / (bios_geom->heads * bios_geom->sectors);
	real_h = (sector / bios_geom->sectors) % bios_geom->heads;
	real_s = sector % bios_geom->sectors;

	if (real_c > MAX_CHS_CYLINDER) {
		real_c = 1023;
		real_h = bios_geom->heads - 1;
		real_s = bios_geom->sectors - 1;
	}

	chs->cylinder = real_c % 0x100;
	chs->head = real_h;
	chs->sector = real_s + 1 + (real_c >> 8 << 6);
}

static PedSector
legacy_start (const PedDisk* disk, const PedCHSGeometry* bios_geom,
	      const DosRawPartition* raw_part)
{
	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (raw_part != NULL, return 0);

	return chs_to_sector (disk->dev, bios_geom, &raw_part->chs_start);
}

static PedSector
legacy_end (const PedDisk* disk, const PedCHSGeometry* bios_geom,
	    const DosRawPartition* raw_part)
{
	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (raw_part != NULL, return 0);

	return chs_to_sector (disk->dev, bios_geom, &raw_part->chs_end);
}

static PedSector
linear_start (const PedDisk* disk, const DosRawPartition* raw_part,
	      PedSector offset)
{
	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (raw_part != NULL, return 0);

	return offset
	       + PED_LE32_TO_CPU (raw_part->start)
	       	 	* (disk->dev->sector_size / 512);
}

static PedSector
linear_end (const PedDisk* disk, const DosRawPartition* raw_part,
	    PedSector offset)
{
	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (raw_part != NULL, return 0);

	return linear_start (disk, raw_part, offset)
	       + (PED_LE32_TO_CPU (raw_part->length) - 1)
	       	 	* (disk->dev->sector_size / 512);
}

#ifndef DISCOVER_ONLY
static int
partition_check_bios_geometry (PedPartition* part, PedCHSGeometry* bios_geom)
{
	PedSector		leg_start, leg_end;
	DosPartitionData*	dos_data;
	PedDisk*		disk;

	PED_ASSERT (part != NULL, return 0);
	PED_ASSERT (part->disk != NULL, return 0);
	PED_ASSERT (part->disk_specific != NULL, return 0);
	dos_data = part->disk_specific;

	if (!dos_data->orig)
		return 1;

	disk = part->disk;
	leg_start = legacy_start (disk, bios_geom, &dos_data->orig->raw_part);
	leg_end = legacy_end (disk, bios_geom, &dos_data->orig->raw_part);

	if (leg_start && leg_start != dos_data->orig->geom.start)
		return 0;
	if (leg_end && leg_end != dos_data->orig->geom.end)
		return 0;
	return 1;
}

static int
disk_check_bios_geometry (const PedDisk* disk, PedCHSGeometry* bios_geom)
{
	PedPartition* part = NULL;

	PED_ASSERT (disk != NULL, return 0);

	while ((part = ped_disk_next_partition (disk, part))) {
		if (ped_partition_is_active (part)) {
			if (!partition_check_bios_geometry (part, bios_geom))
				return 0;
		}
	}

	return 1;
}

static int
probe_filesystem_for_geom (const PedPartition* part, PedCHSGeometry* bios_geom)
{
	const char* ms_types[] = {"ntfs", "fat16", "fat32", NULL};
	int i;
	int found;
	unsigned char* buf;
	int sectors;
	int heads;
	int res = 0;

	PED_ASSERT (bios_geom        != NULL, return 0);
        PED_ASSERT (part             != NULL, return 0);
        PED_ASSERT (part->disk       != NULL, return 0);
        PED_ASSERT (part->disk->dev  != NULL, return 0);
        PED_ASSERT (part->disk->dev->sector_size % PED_SECTOR_SIZE_DEFAULT == 0,
                    return 0);

        buf = ped_malloc (part->disk->dev->sector_size);
        
	if (!buf)
		return 0;

	if (!part->fs_type)
		goto end;

	found = 0;
	for (i = 0; ms_types[i]; i++) {
		if (!strcmp(ms_types[i], part->fs_type->name))
			found = 1;
	}
	if (!found)
		goto end;

	if (!ped_geometry_read(&part->geom, buf, 0, 1))
		goto end;

	/* shared by the start of all Microsoft file systems */
	sectors = buf[0x18] + (buf[0x19] << 8);
	heads = buf[0x1a] + (buf[0x1b] << 8);

	if (sectors < 1 || sectors > 63)
		goto end;
	if (heads > 255 || heads < 1)
		goto end;

	bios_geom->sectors = sectors;
	bios_geom->heads = heads;
	bios_geom->cylinders = part->disk->dev->length / (sectors * heads);
	res = 1;
end:
	ped_free(buf);
	return res;
}

/* This function attempts to infer the BIOS CHS geometry of the hard disk
 * from the CHS + LBA information contained in the partition table from
 * a single partition's entry.
 *
 * This involves some maths.  Let (c,h,s,a) be the starting cylinder,
 * starting head, starting sector and LBA start address of the partition.
 * Likewise, (C,H,S,A) the end addresses.  Using both of these pieces
 * of information, we want to deduce cyl_sectors and head_sectors which
 * are the sizes of a single cylinder and a single head, respectively.
 *
 * The relationships are:
 * c*cyl_sectors + h * head_sectors + s = a
 * C*cyl_sectors + H * head_sectors + S = A
 *
 * We can rewrite this in matrix form:
 *
 * [ c h ] [ cyl_sectors  ]  =  [ s - a ]  =  [ a_ ]
 * [ C H ] [ head_sectors ]     [ S - A ]     [ A_ ].
 * 
 * (s - a is abbreviated to a_to simplify the notation.)
 *
 * This can be abbreviated into augmented matrix form:
 *
 * [ c h | a_ ]
 * [ C H | A_ ].
 * 
 * Solving these equations requires following the row reduction algorithm.  We
 * need to be careful about a few things though:
 * 	- the equations might be linearly dependent, in which case there
 * 	are many solutions.
 * 	- the equations might be inconsistent, in which case there
 * 	are no solutions.  (Inconsistent partition table entry!)
 * 	- there might be zeros, so we need to be careful about applying
 * 	the algorithm.  We know, however, that C > 0.
 */
static int
probe_partition_for_geom (const PedPartition* part, PedCHSGeometry* bios_geom)
{
	DosPartitionData* dos_data;
	RawCHS* start_chs;
	RawCHS* end_chs;
	PedSector c, h, s, a, a_;	/* start */
	PedSector C, H, S, A, A_;	/* end */
	PedSector dont_overflow, denum;
	PedSector cyl_size, head_size;
	PedSector cylinders, heads, sectors;

	PED_ASSERT (part != NULL, return 0);
	PED_ASSERT (part->disk_specific != NULL, return 0);
	PED_ASSERT (bios_geom != NULL, return 0);

	dos_data = part->disk_specific;

	if (!dos_data->orig)
		return 0;

	start_chs = &dos_data->orig->raw_part.chs_start;
	c = chs_get_cylinder (start_chs);
	h = chs_get_head (start_chs);
	s = chs_get_sector (start_chs);
	a = dos_data->orig->geom.start;
	a_ = a - s;

	end_chs = &dos_data->orig->raw_part.chs_end;
	C = chs_get_cylinder (end_chs);
	H = chs_get_head (end_chs);
	S = chs_get_sector (end_chs);
	A = dos_data->orig->geom.end;
	A_ = A - S;

	if (h < 0 || H < 0 || h > 254 || H > 254)
		return 0;
	if (c > C)
		return 0;

	/* If no geometry is feasible, then don't even bother.
	 * Useful for eliminating assertions for broken partition
	 * tables generated by Norton Ghost et al.
	 */
	if (A > (C+1) * 255 * 63)
		return 0;

	/* Not enough information.  In theory, we can do better.  Should we? */
	if (C > MAX_CHS_CYLINDER)
		return 0;
	if (C == 0)
		return 0;

	/* Calculate the maximum number that can be multiplied by
	 * any head count without overflowing a PedSector
	 * 2^8 = 256, 8 bits + 1(sign bit) = 9
	 */
	dont_overflow = 1;
	dont_overflow <<= (8*sizeof(dont_overflow)) - 9;
	dont_overflow--;

	if (a_ > dont_overflow || A_ > dont_overflow)
		return 0;

	/* The matrix is solved by :
	 *
	 * [ c h | a_]			R1
	 * [ C H | A_]			R2
	 *
	 * (cH - Ch) cyl_size = a_H - A_h		H R1 - h R2
	 * => (if cH - Ch != 0) cyl_size = (a_H - A_h) / (cH - Ch)
	 *
	 * (Hc - hC) head_size = A_c - a_C		c R2 - C R1
	 * => (if cH - Ch != 0) head_size = (A_c - a_C) / (cH - Ch)
	 *
	 *   But this calculation of head_size would need
	 *   not overflowing A_c or a_C
	 *   So substitution is use instead, to minimize dimension
	 *   of temporary results :
	 *
	 * If h != 0 : head_size = ( a_ - c cyl_size ) / h
	 * If H != 0 : head_size = ( A_ - C cyl_size ) / H
	 *
	 */
	denum = c * H - C * h;
	if (denum == 0)
		return 0;

	cyl_size = (a_*H - A_*h) / denum;
	/* Check for non integer result */
	if (cyl_size * denum != a_*H - A_*h)
		return 0;

	PED_ASSERT (cyl_size > 0, return 0);
 	PED_ASSERT (cyl_size <= 255 * 63, return 0);

	if (h > 0)
		head_size = ( a_ - c * cyl_size ) / h;
	else if (H > 0)
		head_size = ( A_ - C * cyl_size ) / H;
	else { 
		/* should not happen because denum != 0 */
		head_size = 0;
		PED_ASSERT (0, return 0);
	}

	PED_ASSERT (head_size > 0, return 0);
	PED_ASSERT (head_size <= 63, return 0);

	cylinders = part->disk->dev->length / cyl_size;
	heads = cyl_size / head_size;
	sectors = head_size;

	PED_ASSERT (heads > 0, return 0);
	PED_ASSERT (heads < 256, return 0);

	PED_ASSERT (sectors > 0, return 0);
	PED_ASSERT (sectors <= 63, return 0);

	/* Some broken OEM partitioning program(s) seem to have an out-by-one
	 * error on the end of partitions.  We should offer to fix the
	 * partition table...
	 */
	if (((C + 1) * heads + H) * sectors + S == A)
		C++;

	PED_ASSERT ((c * heads + h) * sectors + s == a, return 0);
	PED_ASSERT ((C * heads + H) * sectors + S == A, return 0);

	bios_geom->cylinders = cylinders;
	bios_geom->heads = heads;
	bios_geom->sectors = sectors;

	return 1;
}

static void
partition_probe_bios_geometry (const PedPartition* part,
                               PedCHSGeometry* bios_geom)
{
	PED_ASSERT (part != NULL, return);
	PED_ASSERT (part->disk != NULL, return);
	PED_ASSERT (bios_geom != NULL, return);

	if (ped_partition_is_active (part)) {
		if (probe_partition_for_geom (part, bios_geom))
			return;
		if (part->type & PED_PARTITION_EXTENDED) {
			if (probe_filesystem_for_geom (part, bios_geom))
				return;
		}
	}
	if (part->type & PED_PARTITION_LOGICAL) {
		PedPartition* ext_part;
		ext_part = ped_disk_extended_partition (part->disk);
		PED_ASSERT (ext_part != NULL, return);
		partition_probe_bios_geometry (ext_part, bios_geom);
	} else {
		*bios_geom = part->disk->dev->bios_geom;
	}
}

static void
disk_probe_bios_geometry (const PedDisk* disk, PedCHSGeometry* bios_geom)
{
	PedPartition*	part;

	/* first look at the boot partition */
	part = NULL;
	while ((part = ped_disk_next_partition (disk, part))) {
		if (!ped_partition_is_active (part))
			continue;
		if (ped_partition_get_flag (part, PED_PARTITION_BOOT)) {
			if (probe_filesystem_for_geom (part, bios_geom))
				return;
			if (probe_partition_for_geom (part, bios_geom))
				return;
		}
	}

	/* that didn't work... try all partition table entries */
	part = NULL;
	while ((part = ped_disk_next_partition (disk, part))) {
		if (ped_partition_is_active (part)) {
			if (probe_partition_for_geom (part, bios_geom))
				return;
		}
	}

	/* that didn't work... look at all file systems */
	part = NULL;
	while ((part = ped_disk_next_partition (disk, part))) {
		if (ped_partition_is_active (part)) {
			if (probe_filesystem_for_geom (part, bios_geom))
				return;
		}
	}
}
#endif /* !DISCOVER_ONLY */

static int
raw_part_is_extended (const DosRawPartition* raw_part)
{
	PED_ASSERT (raw_part != NULL, return 0);

	switch (raw_part->type) {
	case PARTITION_DOS_EXT:
	case PARTITION_EXT_LBA:
	case PARTITION_LINUX_EXT:
		return 1;

	default:
		return 0;
	}

	return 0;
}

static int
raw_part_is_hidden (const DosRawPartition* raw_part)
{
	PED_ASSERT (raw_part != NULL, return 0);

	switch (raw_part->type) {
	case PARTITION_FAT12_H:
	case PARTITION_FAT16_SM_H:
	case PARTITION_FAT16_H:
	case PARTITION_FAT32_H:
	case PARTITION_NTFS_H:
	case PARTITION_FAT32_LBA_H:
	case PARTITION_FAT16_LBA_H:
		return 1;

	default:
		return 0;
	}

	return 0;
}

static int
raw_part_is_lba (const DosRawPartition* raw_part)
{
	PED_ASSERT (raw_part != NULL, return 0);

	switch (raw_part->type) {
	case PARTITION_FAT32_LBA:
	case PARTITION_FAT16_LBA:
	case PARTITION_EXT_LBA:
	case PARTITION_FAT32_LBA_H:
	case PARTITION_FAT16_LBA_H:
		return 1;

	default:
		return 0;
	}

	return 0;
}

static PedPartition*
raw_part_parse (const PedDisk* disk, const DosRawPartition* raw_part,
	        PedSector lba_offset, PedPartitionType type)
{
	PedPartition* part;
	DosPartitionData* dos_data;

	PED_ASSERT (disk != NULL, return NULL);
	PED_ASSERT (raw_part != NULL, return NULL);

	part = ped_partition_new (
		disk, type, NULL,
		linear_start (disk, raw_part, lba_offset),
		linear_end (disk, raw_part, lba_offset));
	if (!part)
		return NULL;
	dos_data = part->disk_specific;
	dos_data->system = raw_part->type;
	dos_data->boot = raw_part->boot_ind != 0;
	dos_data->hidden = raw_part_is_hidden (raw_part);
	dos_data->raid = raw_part->type == PARTITION_LINUX_RAID;
	dos_data->lvm = raw_part->type == PARTITION_LINUX_LVM_OLD
			|| raw_part->type == PARTITION_LINUX_LVM;
	dos_data->lba = raw_part_is_lba (raw_part);
	dos_data->palo = raw_part->type == PARTITION_PALO;
	dos_data->prep = raw_part->type == PARTITION_PREP;
	dos_data->orig = ped_malloc (sizeof (OrigState));
	if (!dos_data->orig) {
		ped_partition_destroy (part);
		return NULL;
	}
	dos_data->orig->geom = part->geom;
	dos_data->orig->raw_part = *raw_part;
	dos_data->orig->lba_offset = lba_offset;
	return part;
}

static int
read_table (PedDisk* disk, PedSector sector, int is_extended_table)
{
	int			i;
	DosRawTable*		table;
	DosRawPartition*	raw_part;
	PedPartition*		part;
	PedPartitionType	type;
	PedSector		lba_offset;
	PedConstraint*		constraint_exact;

	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (disk->dev != NULL, return 0);

	char *label = NULL;
	if (!read_sector (disk->dev, sector, &label))
		goto error;

        table = (DosRawTable *) label;

	/* weird: empty extended partitions are filled with 0xf6 by PM */
	if (is_extended_table
	    && PED_LE16_TO_CPU (table->magic) == PARTITION_MAGIC_MAGIC)
		goto read_ok;

#ifndef DISCOVER_ONLY
	if (PED_LE16_TO_CPU (table->magic) != MSDOS_MAGIC) {
		if (ped_exception_throw (
			PED_EXCEPTION_ERROR, PED_EXCEPTION_IGNORE_CANCEL,
			_("Invalid partition table on %s "
			  "-- wrong signature %x."),
			disk->dev->path,
			PED_LE16_TO_CPU (table->magic))
				!= PED_EXCEPTION_IGNORE)
			goto error;
		goto read_ok;
	}
#endif

	/* parse the partitions from this table */
	for (i = 0; i < 4; i++) {
		raw_part = &table->partitions [i];
		if (raw_part->type == PARTITION_EMPTY || !raw_part->length)
			continue;

		/* process nested extended partitions after normal logical
		 * partitions, to make sure we get the order right.
		 */
		if (is_extended_table && raw_part_is_extended (raw_part))
			continue;	

		lba_offset = is_extended_table ? sector : 0;

		if (linear_start (disk, raw_part, lba_offset) == sector) {
			if (ped_exception_throw (
				PED_EXCEPTION_ERROR,
				PED_EXCEPTION_IGNORE_CANCEL,
				_("Invalid partition table - recursive "
				"partition on %s."),
				disk->dev->path)
					!= PED_EXCEPTION_IGNORE)
				goto error;
			continue;	/* avoid infinite recursion */
		}

		if (is_extended_table)
			type = PED_PARTITION_LOGICAL;
		else if (raw_part_is_extended (raw_part))
			type = PED_PARTITION_EXTENDED;
		else
			type = PED_PARTITION_NORMAL;

		part = raw_part_parse (disk, raw_part, lba_offset, type);
		if (!part)
			goto error;
		if (!is_extended_table)
			part->num = i + 1;
		if (type != PED_PARTITION_EXTENDED)
			part->fs_type = ped_file_system_probe (&part->geom);

		constraint_exact = ped_constraint_exact (&part->geom);
		if (!ped_disk_add_partition (disk, part, constraint_exact))
			goto error;
		ped_constraint_destroy (constraint_exact);

		/* non-nested extended partition */
		if (part->type == PED_PARTITION_EXTENDED) {
			if (!read_table (disk, part->geom.start, 1))
				goto error;
		}
	}

	if (is_extended_table) {
		/* process the nested extended partitions */
		for (i = 0; i < 4; i++) {
			PedSector part_start;

			raw_part = &table->partitions [i];
			if (!raw_part_is_extended (raw_part))
				continue;

			lba_offset = ped_disk_extended_partition
					(disk)->geom.start;
			part_start = linear_start (disk, raw_part, lba_offset);
			if (part_start == sector) {
				/* recursive table - already threw an
				 * exception above.
				 */
				continue;
			}
			if (!read_table (disk, part_start, 1))
				goto error;
		}
	}

read_ok:
	free (label);
	return 1;

error:
	free (label);
	ped_disk_delete_all (disk);
	return 0;
}

static int
msdos_read (PedDisk* disk)
{
	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (disk->dev != NULL, return 0);

	ped_disk_delete_all (disk);
	if (!read_table (disk, 0, 0))
		return 0;

#ifndef DISCOVER_ONLY
	/* try to figure out the correct BIOS CHS values */
	if (!disk_check_bios_geometry (disk, &disk->dev->bios_geom)) {
		PedCHSGeometry bios_geom = disk->dev->bios_geom;
		disk_probe_bios_geometry (disk, &bios_geom);

		/* if the geometry was wrong, then we should reread, to
		 * make sure the metadata is allocated in the right places.
		 */
		if (disk->dev->bios_geom.cylinders != bios_geom.cylinders
		    || disk->dev->bios_geom.heads != bios_geom.heads
		    || disk->dev->bios_geom.sectors != bios_geom.sectors) {
			disk->dev->bios_geom = bios_geom;
			return msdos_read (disk);
		}
	}
#endif

	return 1;
}

#ifndef DISCOVER_ONLY
static int
fill_raw_part (DosRawPartition* raw_part,
               const PedPartition* part, PedSector offset)
{
	DosPartitionData*	dos_data;
	PedCHSGeometry		bios_geom;

	PED_ASSERT (raw_part != NULL, return 0);
	PED_ASSERT (part != NULL, return 0);

	partition_probe_bios_geometry (part, &bios_geom);

	dos_data = part->disk_specific;

	raw_part->boot_ind = 0x80 * dos_data->boot;
	raw_part->type = dos_data->system;
	raw_part->start = PED_CPU_TO_LE32 ((part->geom.start - offset)
				/ (part->disk->dev->sector_size / 512));
	raw_part->length = PED_CPU_TO_LE32 (part->geom.length
				/ (part->disk->dev->sector_size / 512));

	sector_to_chs (part->disk->dev, &bios_geom, part->geom.start,
		       &raw_part->chs_start);
	sector_to_chs (part->disk->dev, &bios_geom, part->geom.end,
		       &raw_part->chs_end);

	if (dos_data->orig) {
		DosRawPartition* orig_raw_part = &dos_data->orig->raw_part;
		if (dos_data->orig->geom.start == part->geom.start)
			raw_part->chs_start = orig_raw_part->chs_start;
		if (dos_data->orig->geom.end == part->geom.end)
			raw_part->chs_end = orig_raw_part->chs_end;
	}

	return 1;
}

static int
fill_ext_raw_part_geom (DosRawPartition* raw_part,
                        const PedCHSGeometry* bios_geom,
			const PedGeometry* geom, PedSector offset)
{
	PED_ASSERT (raw_part != NULL, return 0);
	PED_ASSERT (geom != NULL, return 0);
	PED_ASSERT (geom->dev != NULL, return 0);

	raw_part->boot_ind = 0;
	raw_part->type = PARTITION_DOS_EXT;
	raw_part->start = PED_CPU_TO_LE32 ((geom->start - offset)
				/ (geom->dev->sector_size / 512));
	raw_part->length = PED_CPU_TO_LE32 (geom->length
				/ (geom->dev->sector_size / 512));

	sector_to_chs (geom->dev, bios_geom, geom->start, &raw_part->chs_start);
	sector_to_chs (geom->dev, bios_geom, geom->start + geom->length - 1,
		       &raw_part->chs_end);

	return 1;
}

static int
write_ext_table (const PedDisk* disk,
                 PedSector sector, const PedPartition* logical)
{
	DosRawTable		table;
	PedPartition*		part;
	PedSector		lba_offset;

	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (ped_disk_extended_partition (disk) != NULL, return 0);
	PED_ASSERT (logical != NULL, return 0);

	lba_offset = ped_disk_extended_partition (disk)->geom.start;

	memset (&table, 0, sizeof (DosRawTable));
	table.magic = PED_CPU_TO_LE16 (MSDOS_MAGIC);

	if (!fill_raw_part (&table.partitions[0], logical, sector))
		return 0;

	part = ped_disk_get_partition (disk, logical->num + 1);
	if (part) {
		PedGeometry*		geom;
		PedCHSGeometry		bios_geom;

		geom = ped_geometry_new (disk->dev, part->prev->geom.start,
				part->geom.end - part->prev->geom.start + 1);
		if (!geom)
			return 0;
		partition_probe_bios_geometry (part, &bios_geom);
		fill_ext_raw_part_geom (&table.partitions[1], &bios_geom,
				        geom, lba_offset);
		ped_geometry_destroy (geom);

		if (!write_ext_table (disk, part->prev->geom.start, part))
			return 0;
	}

	return ped_device_write (disk->dev, (void*) &table, sector, 1);
}

static int
write_empty_table (const PedDisk* disk, PedSector sector)
{
	DosRawTable		table;

	PED_ASSERT (disk != NULL, return 0);

	memset (&table, 0, sizeof (DosRawTable));
	table.magic = PED_CPU_TO_LE16 (MSDOS_MAGIC);

	return ped_device_write (disk->dev, (void*) &table, sector, 1);
}

/* Find the first logical partition, and write the partition table for it.
 */
static int
write_extended_partitions (const PedDisk* disk)
{
	PedPartition*		ext_part;
	PedPartition*		part;
	PedCHSGeometry		bios_geom;

	PED_ASSERT (disk != NULL, return 0);

	ext_part = ped_disk_extended_partition (disk);
	partition_probe_bios_geometry (ext_part, &bios_geom);
	part = ped_disk_get_partition (disk, 5);
	if (part)
		return write_ext_table (disk, ext_part->geom.start, part);
	else
		return write_empty_table (disk, ext_part->geom.start);
}

static inline uint32_t generate_random_id (void)
{
	struct timeval tv;
	int rc;
	rc = gettimeofday(&tv, NULL);
	if (rc == -1)
		return 0;
	return (uint32_t)(tv.tv_usec & 0xFFFFFFFFUL);
}

static int
msdos_write (const PedDisk* disk)
{
	DosRawTable		table;
	PedPartition*		part;
	int			i;

	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (disk->dev != NULL, return 0);

	ped_device_read (disk->dev, &table, 0, 1);

	if (!table.boot_code[0]) {
		memset (table.boot_code, 0, 512);
		memcpy (table.boot_code, MBR_BOOT_CODE, sizeof (MBR_BOOT_CODE));
	}

	/* If there is no unique identifier, generate a random one */
	if (!table.mbr_signature)
		table.mbr_signature = generate_random_id();

	memset (table.partitions, 0, sizeof (DosRawPartition) * 4);
	table.magic = PED_CPU_TO_LE16 (MSDOS_MAGIC);

	for (i=1; i<=4; i++) {
		part = ped_disk_get_partition (disk, i);
		if (!part)
			continue;

		if (!fill_raw_part (&table.partitions [i - 1], part, 0))
			return 0;

		if (part->type == PED_PARTITION_EXTENDED) {
			if (!write_extended_partitions (disk))
				return 0;
		}
	}

	if (!ped_device_write (disk->dev, (void*) &table, 0, 1))
		return 0;
	return ped_device_sync (disk->dev);
}
#endif /* !DISCOVER_ONLY */

static PedPartition*
msdos_partition_new (const PedDisk* disk, PedPartitionType part_type,
		     const PedFileSystemType* fs_type,
		     PedSector start, PedSector end)
{
	PedPartition*		part;
	DosPartitionData*	dos_data;

	part = _ped_partition_alloc (disk, part_type, fs_type, start, end);
	if (!part)
		goto error;

	if (ped_partition_is_active (part)) {
		part->disk_specific
		       	= dos_data = ped_malloc (sizeof (DosPartitionData));
		if (!dos_data)
			goto error_free_part;
		dos_data->orig = NULL;
		dos_data->system = PARTITION_LINUX;
		dos_data->hidden = 0;
		dos_data->boot = 0;
		dos_data->raid = 0;
		dos_data->lvm = 0;
		dos_data->lba = 0;
		dos_data->palo = 0;
		dos_data->prep = 0;
	} else {
		part->disk_specific = NULL;
	}
	return part;

	ped_free (dos_data);
error_free_part:
	ped_free (part);
error:
	return 0;
}

static PedPartition*
msdos_partition_duplicate (const PedPartition* part)
{
	PedPartition*		new_part;
	DosPartitionData*	new_dos_data;
	DosPartitionData*	old_dos_data;

	new_part = ped_partition_new (part->disk, part->type, part->fs_type,
				      part->geom.start, part->geom.end);
	if (!new_part)
		return NULL;
	new_part->num = part->num;

	old_dos_data = (DosPartitionData*) part->disk_specific;
	new_dos_data = (DosPartitionData*) new_part->disk_specific;
	new_dos_data->system = old_dos_data->system;
	new_dos_data->boot = old_dos_data->boot;
	new_dos_data->hidden = old_dos_data->hidden;
	new_dos_data->raid = old_dos_data->raid;
	new_dos_data->lvm = old_dos_data->lvm;
	new_dos_data->lba = old_dos_data->lba;
	new_dos_data->palo = old_dos_data->palo;
	new_dos_data->prep = old_dos_data->prep;

	if (old_dos_data->orig) {
		new_dos_data->orig = ped_malloc (sizeof (OrigState));
		if (!new_dos_data->orig) {
			ped_partition_destroy (new_part);
			return NULL;
		}
		new_dos_data->orig->geom = old_dos_data->orig->geom;
		new_dos_data->orig->raw_part = old_dos_data->orig->raw_part;
		new_dos_data->orig->lba_offset = old_dos_data->orig->lba_offset;
	}
	return new_part;
}

static void
msdos_partition_destroy (PedPartition* part)
{
	PED_ASSERT (part != NULL, return);

	if (ped_partition_is_active (part)) {
		DosPartitionData* dos_data;
		dos_data = (DosPartitionData*) part->disk_specific;
		if (dos_data->orig)
			ped_free (dos_data->orig);
		ped_free (part->disk_specific);
	}
	ped_free (part);
}

static int
msdos_partition_set_system (PedPartition* part,
			    const PedFileSystemType* fs_type)
{
	DosPartitionData* dos_data = part->disk_specific;

	part->fs_type = fs_type;

	if (dos_data->hidden
		    && fs_type
		    && strncmp (fs_type->name, "fat", 3) != 0
		    && strcmp (fs_type->name, "ntfs") != 0)
		dos_data->hidden = 0;

	if (part->type & PED_PARTITION_EXTENDED) {
		dos_data->raid = 0;
		dos_data->lvm = 0;
		dos_data->palo = 0;
		dos_data->prep = 0;
		if (dos_data->lba)
			dos_data->system = PARTITION_EXT_LBA;
		else
			dos_data->system = PARTITION_DOS_EXT;
		return 1;
	}

	if (dos_data->lvm) {
		dos_data->system = PARTITION_LINUX_LVM;
		return 1;
	}
	if (dos_data->raid) {
		dos_data->system = PARTITION_LINUX_RAID;
		return 1;
	}
	if (dos_data->palo) {
		dos_data->system = PARTITION_PALO;
		return 1;
	}
	if (dos_data->prep) {
		dos_data->system = PARTITION_PREP;
		return 1;
	}

	if (!fs_type)
		dos_data->system = PARTITION_LINUX;
	else if (!strcmp (fs_type->name, "fat16")) {
		dos_data->system = dos_data->lba
				   ? PARTITION_FAT16_LBA : PARTITION_FAT16;
		dos_data->system |= dos_data->hidden ? PART_FLAG_HIDDEN : 0;
	} else if (!strcmp (fs_type->name, "fat32")) {
		dos_data->system = dos_data->lba
				   ? PARTITION_FAT32_LBA : PARTITION_FAT32;
		dos_data->system |= dos_data->hidden ? PART_FLAG_HIDDEN : 0;
	} else if (!strcmp (fs_type->name, "ntfs")
		   || !strcmp (fs_type->name, "hpfs")) {
		dos_data->system = PARTITION_NTFS;
		dos_data->system |= dos_data->hidden ? PART_FLAG_HIDDEN : 0;
	} else if (!strcmp (fs_type->name, "sun-ufs"))
		dos_data->system = PARTITION_SUN_UFS;
	else if (!strcmp (fs_type->name, "solaris"))
		dos_data->system = PARTITION_SUN_UFS;
	else if (!strcmp (fs_type->name, "linux-swap"))
		dos_data->system = PARTITION_LINUX_SWAP;
	else
		dos_data->system = PARTITION_LINUX;

	return 1;
}

static int
msdos_partition_set_flag (PedPartition* part,
                          PedPartitionFlag flag, int state)
{
	PedDisk*			disk;
	PedPartition*			walk;
	DosPartitionData*		dos_data;

	PED_ASSERT (part != NULL, return 0);
	PED_ASSERT (part->disk_specific != NULL, return 0);
	PED_ASSERT (part->disk != NULL, return 0);

	dos_data = part->disk_specific;
	disk = part->disk;

	switch (flag) {
	case PED_PARTITION_HIDDEN:
		if (part->type == PED_PARTITION_EXTENDED) {
			ped_exception_throw (
				PED_EXCEPTION_ERROR,
				PED_EXCEPTION_CANCEL,
				_("Extended partitions cannot be hidden on "
				  "msdos disk labels."));
			return 0;
		}
		dos_data->hidden = state;
		return ped_partition_set_system (part, part->fs_type);

	case PED_PARTITION_BOOT:
		dos_data->boot = state;
		if (!state)
			return 1;

		walk = ped_disk_next_partition (disk, NULL);
		for (; walk; walk = ped_disk_next_partition (disk, walk)) {
			if (walk == part || !ped_partition_is_active (walk))
				continue;
			msdos_partition_set_flag (walk, PED_PARTITION_BOOT, 0);
		}
		return 1;

	case PED_PARTITION_RAID:
		if (state) {
			dos_data->hidden = 0;
			dos_data->lvm = 0;
			dos_data->palo = 0;
			dos_data->prep = 0;
		}
		dos_data->raid = state;
		return ped_partition_set_system (part, part->fs_type);

	case PED_PARTITION_LVM:
		if (state) {
			dos_data->hidden = 0;
			dos_data->raid = 0;
			dos_data->palo = 0;
			dos_data->prep = 0;
		}
		dos_data->lvm = state;
		return ped_partition_set_system (part, part->fs_type);

	case PED_PARTITION_LBA:
		dos_data->lba = state;
		return ped_partition_set_system (part, part->fs_type);

	case PED_PARTITION_PALO:
		if (state) {
			dos_data->hidden = 0;
			dos_data->raid = 0;
			dos_data->lvm = 0;
		}
		dos_data->palo = state;
		return ped_partition_set_system (part, part->fs_type);

	case PED_PARTITION_PREP:
		if (state) {
			dos_data->hidden = 0;
			dos_data->raid = 0;
			dos_data->lvm = 0;
		}
		dos_data->prep = state;
		return ped_partition_set_system (part, part->fs_type);

	default:
		return 0;
	}
}

static int
msdos_partition_get_flag (const PedPartition* part, PedPartitionFlag flag)
{
	DosPartitionData*	dos_data;

	PED_ASSERT (part != NULL, return 0);
	PED_ASSERT (part->disk_specific != NULL, return 0);

	dos_data = part->disk_specific;
	switch (flag) {
	case PED_PARTITION_HIDDEN:
		return dos_data->hidden;

	case PED_PARTITION_BOOT:
		return dos_data->boot;

	case PED_PARTITION_RAID:
		return dos_data->raid;

	case PED_PARTITION_LVM:
		return dos_data->lvm;

	case PED_PARTITION_LBA:
		return dos_data->lba;

	case PED_PARTITION_PALO:
		return dos_data->palo;

	case PED_PARTITION_PREP:
		return dos_data->prep;

	default:
		return 0;
	}
}

static int
msdos_partition_is_flag_available (const PedPartition* part,
				   PedPartitionFlag flag)
{
	switch (flag) {
	case PED_PARTITION_HIDDEN:
	case PED_PARTITION_BOOT:
	case PED_PARTITION_RAID:
	case PED_PARTITION_LVM:
	case PED_PARTITION_LBA:
	case PED_PARTITION_PALO:
	case PED_PARTITION_PREP:
		return 1;

	default:
		return 0;
	}
}

static PedGeometry*
_try_constraint (const PedPartition* part, const PedConstraint* external,
		 PedConstraint* internal)
{
	PedConstraint*		intersection;
	PedGeometry*		solution;

	intersection = ped_constraint_intersect (external, internal);
	ped_constraint_destroy (internal);
	if (!intersection)
		return NULL;

	solution = ped_constraint_solve_nearest (intersection, &part->geom);
	ped_constraint_destroy (intersection);
	return solution;
}

static PedGeometry*
_best_solution (const PedPartition* part, const PedCHSGeometry* bios_geom,
		PedGeometry* a, PedGeometry* b)
{
	PedSector	cyl_size = bios_geom->heads * bios_geom->sectors;
	int		a_cylinder;
	int		b_cylinder;

	if (!a)
		return b;
	if (!b)
		return a;

	a_cylinder = a->start / cyl_size;
	b_cylinder = b->start / cyl_size;

	if (a_cylinder == b_cylinder) {
		if ( (a->start / bios_geom->sectors) % bios_geom->heads
			  < (b->start / bios_geom->sectors) % bios_geom->heads)
	       		goto choose_a;
		else
			goto choose_b;
	} else {
		PedSector	a_delta;
		PedSector	b_delta;

		a_delta = abs (part->geom.start - a->start);
		b_delta = abs (part->geom.start - b->start);

		if (a_delta < b_delta)
			goto choose_a;
		else
			goto choose_b;
	}

	return NULL;	/* never get here! */

choose_a:
	ped_geometry_destroy (b);
	return a;

choose_b:
	ped_geometry_destroy (a);
	return b;
}

/* This constraint is for "normal" primary partitions, that start at the
 * beginning of a cylinder, and end at the end of a cylinder.
 * 	Note: you can't start a partition at the beginning of the 1st
 * cylinder, because that's where the partition table is!  There are different
 * rules for that - see the _primary_start_constraint.
 */
static PedConstraint*
_primary_constraint (const PedDisk* disk, const PedCHSGeometry* bios_geom,
		     PedGeometry* min_geom)
{
	PedDevice*	dev = disk->dev;
	PedSector	cylinder_size = bios_geom->sectors * bios_geom->heads;
	PedAlignment	start_align;
	PedAlignment	end_align;
	PedGeometry	start_geom;
	PedGeometry	end_geom;

	if (!ped_alignment_init (&start_align, 0, cylinder_size))
		return NULL;
	if (!ped_alignment_init (&end_align, -1, cylinder_size))
		return NULL;

	if (min_geom) {
		if (min_geom->start < cylinder_size)
			return NULL;
		if (!ped_geometry_init (&start_geom, dev, cylinder_size,
			       		min_geom->start + 1 - cylinder_size))
			return NULL;
		if (!ped_geometry_init (&end_geom, dev, min_geom->end,
			       		dev->length - min_geom->end))
			return NULL;
	} else {
		if (!ped_geometry_init (&start_geom, dev, cylinder_size,
			       		dev->length - cylinder_size))
			return NULL;
		if (!ped_geometry_init (&end_geom, dev, 0, dev->length))
			return NULL;
	}

	return ped_constraint_new (&start_align, &end_align, &start_geom,
				   &end_geom, 1, dev->length);
}

/* This constraint is for partitions starting on the first cylinder.  They
 * must start on the 2nd head of the 1st cylinder.
 *
 * NOTE: We don't always start on the 2nd head of the 1st cylinder.  Windows
 * Vista aligns starting partitions at sector 2048 (0x800) by default.  See:
 * http://support.microsoft.com/kb/923332
 */
static PedConstraint*
_primary_start_constraint (const PedDisk* disk,
                           const PedPartition *part,
                           const PedCHSGeometry* bios_geom,
                           const PedGeometry* min_geom)
{
	PedDevice*	dev = disk->dev;
	PedSector	cylinder_size = bios_geom->sectors * bios_geom->heads;
	PedAlignment	start_align;
	PedAlignment	end_align;
	PedGeometry	start_geom;
	PedGeometry	end_geom;
	PedSector start_pos;

	if (part->geom.start == 2048)
		/* check for known Windows Vista (NTFS >= 3.1) alignments */
		/* sector 0x800 == 2048                                   */
		start_pos = 2048;
	else
		/* all other primary partitions on a DOS label align to   */
		/* the 2nd head of the first cylinder (0x3F == 63)        */
		start_pos = bios_geom->sectors;

	if (!ped_alignment_init (&start_align, start_pos, 0))
		return NULL;
	if (!ped_alignment_init (&end_align, -1, cylinder_size))
		return NULL;
	if (min_geom) {
		if (!ped_geometry_init (&start_geom, dev, start_pos, 1))
			return NULL;
		if (!ped_geometry_init (&end_geom, dev, min_geom->end,
			       		dev->length - min_geom->end))
			return NULL;
	} else {
		if (!ped_geometry_init (&start_geom, dev, start_pos,
			dev->length - start_pos))
			return NULL;
		if (!ped_geometry_init (&end_geom, dev, 0, dev->length))
			return NULL;
	}

	return ped_constraint_new (&start_align, &end_align, &start_geom,
				   &end_geom, 1, dev->length);
}

/* constraints for logical partitions:
 * 	- start_offset is the offset in the start alignment.  "normally",
 * this is bios_geom->sectors.  exceptions: MINOR > 5 at the beginning of the
 * extended partition, or MINOR == 5 in the middle of the extended partition
 * 	- is_start_part == 1 if the constraint is for the first cylinder of
 * the extended partition, or == 0 if the constraint is for the second cylinder
 * onwards of the extended partition.
 */
static PedConstraint*
_logical_constraint (const PedDisk* disk, const PedCHSGeometry* bios_geom,
		     PedSector start_offset, int is_start_part)
{
	PedPartition*	ext_part = ped_disk_extended_partition (disk);
	PedDevice*	dev = disk->dev;
	PedSector	cylinder_size = bios_geom->sectors * bios_geom->heads;
	PedAlignment	start_align;
	PedAlignment	end_align;
	PedGeometry	max_geom;

	PED_ASSERT (ext_part != NULL, return NULL);

	if (!ped_alignment_init (&start_align, start_offset, cylinder_size))
		return NULL;
	if (!ped_alignment_init (&end_align, -1, cylinder_size))
		return NULL;
	if (is_start_part) {
		if (!ped_geometry_init (&max_geom, dev,
					ext_part->geom.start,
					ext_part->geom.length))
			return NULL;
	} else {
		PedSector	min_start;
		PedSector	max_length;

		min_start = ped_round_up_to (ext_part->geom.start + 1,
					     cylinder_size);
		max_length = ext_part->geom.end - min_start + 1;
		if (min_start >= ext_part->geom.end)
			return NULL;

		if (!ped_geometry_init (&max_geom, dev, min_start, max_length))
			return NULL;
	}

	return ped_constraint_new (&start_align, &end_align, &max_geom,
		       		   &max_geom, 1, dev->length);
}

/* returns the minimum geometry for the extended partition, given that the
 * extended partition must contain:
 *   * all logical partitions
 *   * all partition tables for all logical partitions (except the first)
 *   * the extended partition table
 */
static PedGeometry*
_get_min_extended_part_geom (const PedPartition* ext_part,
			     const PedCHSGeometry* bios_geom)
{
	PedDisk*		disk = ext_part->disk;
	PedSector		head_size = bios_geom ? bios_geom->sectors : 1;
	PedPartition*		walk;
	PedGeometry*		min_geom;

	walk = ped_disk_get_partition (disk, 5);
	if (!walk)
		return NULL;

	min_geom = ped_geometry_duplicate (&walk->geom);
	if (!min_geom)
		return NULL;
	ped_geometry_set_start (min_geom, walk->geom.start - 1 * head_size);

	for (walk = ext_part->part_list; walk; walk = walk->next) {
		if (!ped_partition_is_active (walk) || walk->num == 5)
			continue;
		if (walk->geom.start < min_geom->start)
			ped_geometry_set_start (min_geom,
					walk->geom.start - 2 * head_size);
		if (walk->geom.end > min_geom->end)
			ped_geometry_set_end (min_geom, walk->geom.end);
	}

	return min_geom;
}

static int
_align_primary (PedPartition* part, const PedCHSGeometry* bios_geom,
		const PedConstraint* constraint)
{
	PedDisk*	disk = part->disk;
	PedGeometry*	min_geom = NULL;
	PedGeometry*	solution = NULL;

	if (part->type == PED_PARTITION_EXTENDED)
		min_geom = _get_min_extended_part_geom (part, bios_geom);

	solution = _best_solution (part, bios_geom, solution,
			_try_constraint (part, constraint,
					 _primary_start_constraint (disk, part,
						 bios_geom, min_geom)));

	solution = _best_solution (part, bios_geom, solution,
			_try_constraint (part, constraint,
				_primary_constraint (disk, bios_geom,
				min_geom)));

	if (min_geom)
		ped_geometry_destroy (min_geom);

	if (solution) {
		ped_geometry_set (&part->geom, solution->start,
				  solution->length);
		ped_geometry_destroy (solution);
		return 1;
	}

	return 0;
}

static int
_logical_min_start_head (const PedPartition* part,
                         const PedCHSGeometry* bios_geom,
			 const PedPartition* ext_part,
                         int is_start_ext_part)
{
	PedSector	cylinder_size = bios_geom->sectors * bios_geom->heads;
	PedSector	base_head;

	if (is_start_ext_part)
		base_head = 1 + (ext_part->geom.start % cylinder_size)
					/ bios_geom->sectors;
	else
		base_head = 0;

	if (part->num == 5)
		return base_head + 0;
	else
		return base_head + 1;
}

/* Shamelessly copied and adapted from _partition_get_overlap_constraint
 * (in disk.c)
 * This should get ride of the infamous Assertion (metadata_length > 0) failed
 * bug for extended msdos disklabels generated by Parted.
 * 1) There always is a partition table at the start of ext_part, so we leave
 *    a one sector gap there.
 * 2)*The partition table of part5 is always at the beginning of the ext_part
 *    so there is no need to leave a one sector gap before part5.
 *   *There always is a partition table at the beginning of each partition != 5.
 * We don't need to worry to much about consistency with 
 * _partition_get_overlap_constraint because missing it means we are in edge
 * cases anyway, and we don't lose anything by just refusing to do the job in
 * those cases.
 */
static PedConstraint*
_log_meta_overlap_constraint (PedPartition* part, const PedGeometry* geom)
{
	PedGeometry	safe_space;
	PedSector	min_start;
	PedSector	max_end;
	PedPartition*	ext_part = ped_disk_extended_partition (part->disk);
	PedPartition*	walk;
	int		not_5 = (part->num != 5);

	PED_ASSERT (ext_part != NULL, return NULL);

	walk = ext_part->part_list;

	/*                                 1)  2)     */
	min_start = ext_part->geom.start + 1 + not_5;
	max_end = ext_part->geom.end;

	while (walk != NULL             /*      2)                         2) */
		&& (   walk->geom.start - (walk->num != 5) < geom->start - not_5
		    || walk->geom.start - (walk->num != 5) <= min_start )) {
		if (walk != part && ped_partition_is_active (walk))
			min_start = walk->geom.end + 1 + not_5; /* 2) */
		walk = walk->next;
	}

	while (walk && (walk == part || !ped_partition_is_active (walk)))
		walk = walk->next;

	if (walk)
		max_end = walk->geom.start - 1 - (walk->num != 5); /* 2) */

	if (min_start >= max_end)
		return NULL;

	ped_geometry_init (&safe_space, part->disk->dev,
			   min_start, max_end - min_start + 1);
	return ped_constraint_new_from_max (&safe_space);
}

static int
_align_logical (PedPartition* part, const PedCHSGeometry* bios_geom,
		const PedConstraint* constraint)
{
	PedDisk*	disk = part->disk;
	PedPartition*	ext_part = ped_disk_extended_partition (disk);
	PedSector	cyl_size = bios_geom->sectors * bios_geom->heads;
	PedSector	start_base;
	int		head;
	PedGeometry*	solution = NULL;
	PedConstraint   *intersect, *log_meta_overlap;

	PED_ASSERT (ext_part != NULL, return 0);

	log_meta_overlap = _log_meta_overlap_constraint(part, &part->geom);
	intersect = ped_constraint_intersect (constraint, log_meta_overlap);
	ped_constraint_destroy (log_meta_overlap);
	if (!intersect)
		return 0;

	start_base = ped_round_down_to (part->geom.start, cyl_size);

	for (head = _logical_min_start_head (part, bios_geom, ext_part, 0);
	     head < PED_MIN (5, bios_geom->heads); head++) {
		PedConstraint*	disk_constraint;
		PedSector	start = start_base + head * bios_geom->sectors;

		if (head >= _logical_min_start_head (part, bios_geom,
						     ext_part, 1))
			disk_constraint =
				_logical_constraint (disk, bios_geom, start, 1);
		else
			disk_constraint =
				_logical_constraint (disk, bios_geom, start, 0);

		solution = _best_solution (part, bios_geom, solution,
				_try_constraint (part, intersect,
						 disk_constraint));
	}

	ped_constraint_destroy (intersect);

	if (solution) {
		ped_geometry_set (&part->geom, solution->start,
				  solution->length);
		ped_geometry_destroy (solution);
		return 1;
	}

	return 0;
}

static int
_align (PedPartition* part, const PedCHSGeometry* bios_geom,
	const PedConstraint* constraint)
{
	if (part->type == PED_PARTITION_LOGICAL)
		return _align_logical (part, bios_geom, constraint);
	else
		return _align_primary (part, bios_geom, constraint);
}

static PedConstraint*
_no_geom_constraint (const PedDisk* disk, PedSector start, PedSector end)
{
	PedGeometry	 max;

	ped_geometry_init (&max, disk->dev, start, end - start + 1);
	return ped_constraint_new_from_max (&max);
}

static PedConstraint*
_no_geom_extended_constraint (const PedPartition* part)
{
	PedDevice*	dev = part->disk->dev;
	PedGeometry*	min = _get_min_extended_part_geom (part, NULL);
	PedGeometry	start_range;
	PedGeometry	end_range;
	PedConstraint*	constraint;

	if (min) {
		ped_geometry_init (&start_range, dev, 1, min->start);
		ped_geometry_init (&end_range, dev, min->end,
				   dev->length - min->end);
		ped_geometry_destroy (min);
	} else {
		ped_geometry_init (&start_range, dev, 1, dev->length - 1);
		ped_geometry_init (&end_range, dev, 1, dev->length - 1);
	}
	constraint = ped_constraint_new (ped_alignment_any, ped_alignment_any,
			&start_range, &end_range, 1, dev->length);
	return constraint;
}

static int
_align_primary_no_geom (PedPartition* part, const PedConstraint* constraint)
{
	PedDisk*	disk = part->disk;
	PedGeometry*	solution;

	if (part->type == PED_PARTITION_EXTENDED) {
		solution = _try_constraint (part, constraint,
				_no_geom_extended_constraint (part));
	} else {
		solution = _try_constraint (part, constraint,
				_no_geom_constraint (disk, 1,
						     disk->dev->length - 1));
	}

	if (solution) {
		ped_geometry_set (&part->geom, solution->start,
				  solution->length);
		ped_geometry_destroy (solution);
		return 1;
	}
	return 0;
}

static int
_align_logical_no_geom (PedPartition* part, const PedConstraint* constraint)
{
	PedGeometry*	solution;

	solution = _try_constraint (part, constraint,
			_log_meta_overlap_constraint (part, &part->geom));

	if (solution) {
		ped_geometry_set (&part->geom, solution->start,
				  solution->length);
		ped_geometry_destroy (solution);
		return 1;
	}
	return 0;
}

static int
_align_no_geom (PedPartition* part, const PedConstraint* constraint)
{
	if (part->type == PED_PARTITION_LOGICAL)
		return _align_logical_no_geom (part, constraint);
	else
		return _align_primary_no_geom (part, constraint);
}

static int
msdos_partition_align (PedPartition* part, const PedConstraint* constraint)
{
	PedCHSGeometry	bios_geom;
	DosPartitionData* dos_data;

 	PED_ASSERT (part != NULL, return 0);
	PED_ASSERT (part->disk_specific != NULL, return 0);

	dos_data = part->disk_specific;
	if (dos_data->system == PARTITION_LDM && dos_data->orig) {
		PedGeometry *orig_geom = &dos_data->orig->geom;

		if (ped_geometry_test_equal (&part->geom, orig_geom)
		    && ped_constraint_is_solution (constraint, &part->geom))
			return 1;

		ped_geometry_set (&part->geom, orig_geom->start,
				  orig_geom->length);
		ped_exception_throw (
			PED_EXCEPTION_ERROR,
			PED_EXCEPTION_CANCEL,
			_("Parted can't resize partitions managed by "
			  "Windows Dynamic Disk."));
		return 0;
	}

	partition_probe_bios_geometry (part, &bios_geom);

	if (_align (part, &bios_geom, constraint))
		return 1;
	if (_align_no_geom (part, constraint))
		return 1;
 
#ifndef DISCOVER_ONLY
	ped_exception_throw (
		PED_EXCEPTION_ERROR,
		PED_EXCEPTION_CANCEL,
		_("Unable to satisfy all constraints on the partition."));
#endif
	return 0;
}

static int
add_metadata_part (PedDisk* disk, PedPartitionType type, PedSector start,
		   PedSector end)
{
	PedPartition*		new_part;

	PED_ASSERT (disk != NULL, return 0);

	new_part = ped_partition_new (disk, type | PED_PARTITION_METADATA, NULL,
				      start, end);
	if (!new_part)
		goto error;
	if (!ped_disk_add_partition (disk, new_part, NULL))
		goto error_destroy_new_part;

	return 1;

error_destroy_new_part:
	ped_partition_destroy (new_part);
error:
	return 0;
}

/* There are a few objectives here:
 * 	- avoid having lots of "free space" partitions lying around, to confuse
 * the front end.
 * 	- ensure that there's enough room to put in the extended partition
 * tables, etc.
 */
static int
add_logical_part_metadata (PedDisk* disk, const PedPartition* log_part)
{
	PedPartition*	ext_part = ped_disk_extended_partition (disk);
	PedPartition*	prev = log_part->prev;
	PedCHSGeometry	bios_geom;
	PedSector	cyl_size;
	PedSector	metadata_start;
	PedSector	metadata_end;
	PedSector	metadata_length;

	partition_probe_bios_geometry (ext_part, &bios_geom);
	cyl_size = bios_geom.sectors * bios_geom.heads;

	/* if there's metadata shortly before the partition (on the same
	 * cylinder), then make this new metadata partition touch the end of
	 * the other.  No point having 63 bytes (or whatever) of free space
	 * partition - just confuses front-ends, etc.
	 * 	Otherwise, start the metadata at the start of the cylinder
	 */

	metadata_end = log_part->geom.start - 1;
	metadata_start = ped_round_down_to (metadata_end, cyl_size);
	if (prev)
		metadata_start = PED_MAX (metadata_start, prev->geom.end + 1);
	else
		metadata_start = PED_MAX (metadata_start,
					  ext_part->geom.start + 1);
	metadata_length = metadata_end - metadata_start + 1;

	/* partition 5 doesn't need to have any metadata */
	if (log_part->num == 5 && metadata_length < bios_geom.sectors)
		return 1;

	PED_ASSERT (metadata_length > 0, return 0);

	return add_metadata_part (disk, PED_PARTITION_LOGICAL,
				  metadata_start, metadata_end);
}

static PedPartition*
get_last_part (const PedDisk* disk)
{
	PedPartition* first_part = disk->part_list;
	PedPartition* walk;

	if (!first_part)
		return NULL;
	for (walk = first_part; walk->next; walk = walk->next);
	return walk;
}

/* Adds metadata placeholder partitions to cover the partition table (and
 * "free" space after it that often has bootloader stuff), and the last
 * incomplete cylinder at the end of the disk.
 * 	Parted has to be mindful of the uncertainty of dev->bios_geom.
 * It therefore makes sure this metadata doesn't overlap with partitions.
 */
static int
add_startend_metadata (PedDisk* disk)
{
	PedDevice* dev = disk->dev;
	PedSector cyl_size = dev->bios_geom.sectors * dev->bios_geom.heads;
	PedPartition* first_part = disk->part_list;
	PedPartition* last_part = get_last_part (disk);
	PedSector start, end;

	if (!first_part)
		return 1;

	start = 0;
	end = PED_MIN (dev->bios_geom.sectors - 1, first_part->geom.start - 1);
	if (!add_metadata_part (disk, PED_PARTITION_NORMAL, start, end))
		return 0;

	start = PED_MAX (last_part->geom.end + 1,
			 ped_round_down_to (dev->length, cyl_size));
	end = dev->length - 1;
	if (start < end) {
		if (!add_metadata_part (disk, PED_PARTITION_NORMAL, start, end))
			return 0;
	}

	return 1;
}

static int
msdos_alloc_metadata (PedDisk* disk)
{
	PedPartition*		ext_part;

	PED_ASSERT (disk != NULL, return 0);
	PED_ASSERT (disk->dev != NULL, return 0);

	if (!add_startend_metadata (disk))
		return 0;

	ext_part = ped_disk_extended_partition (disk);
	if (ext_part) {
		int		i;
		PedSector	start, end;
		PedCHSGeometry	bios_geom;
		
		for (i=5; 1; i++) {
			PedPartition* log_part;
			log_part = ped_disk_get_partition (disk, i);
			if (!log_part)
				break;
			if (!add_logical_part_metadata (disk, log_part))
				return 0;
		}

		partition_probe_bios_geometry (ext_part, &bios_geom);
		start = ext_part->geom.start;
		end = start + bios_geom.sectors - 1;
		if (ext_part->part_list)
			end = PED_MIN (end,
				       ext_part->part_list->geom.start - 1);
		if (!add_metadata_part (disk, PED_PARTITION_LOGICAL,
					start, end))
			return 0;
	}

	return 1;
}

static int
next_primary (const PedDisk* disk)
{
	int	i;
	for (i=1; i<=4; i++) {
		if (!ped_disk_get_partition (disk, i))
			return i;
	}
	return 0;
}

static int
next_logical (const PedDisk* disk)
{
	int	i;
	for (i=5; 1; i++) {
		if (!ped_disk_get_partition (disk, i))
			return i;
	}
}

static int
msdos_partition_enumerate (PedPartition* part)
{
	PED_ASSERT (part != NULL, return 0);
	PED_ASSERT (part->disk != NULL, return 0);

	/* don't re-number a primary partition */
	if (part->num != -1 && part->num <= 4)
		return 1;

	part->num = -1;

	if (part->type & PED_PARTITION_LOGICAL)
		part->num = next_logical (part->disk);
	else
		part->num = next_primary (part->disk);

	return 1;
}

static int
msdos_get_max_primary_partition_count (const PedDisk* disk)
{
	return 4;
}

static PedDiskOps msdos_disk_ops = {
	.probe =		msdos_probe,
#ifndef DISCOVER_ONLY
	.clobber =		msdos_clobber,
#else
	.clobber =		NULL,
#endif
	.alloc =		msdos_alloc,
	.duplicate =		msdos_duplicate,
	.free =			msdos_free,
	.read =			msdos_read,
#ifndef DISCOVER_ONLY
	.write =		msdos_write,
#else
	.write =		NULL,
#endif

	.partition_new =	msdos_partition_new,
	.partition_duplicate =	msdos_partition_duplicate,
	.partition_destroy =	msdos_partition_destroy,
	.partition_set_system =	msdos_partition_set_system,
	.partition_set_flag =	msdos_partition_set_flag,
	.partition_get_flag =	msdos_partition_get_flag,
	.partition_is_flag_available =	msdos_partition_is_flag_available,
	.partition_set_name =	NULL,
	.partition_get_name =	NULL,
	.partition_align =	msdos_partition_align,
	.partition_enumerate =	msdos_partition_enumerate,

	.alloc_metadata =	msdos_alloc_metadata,
	.get_max_primary_partition_count =
				msdos_get_max_primary_partition_count
};

static PedDiskType msdos_disk_type = {
	.next =			NULL,
	.name =			"msdos",
	.ops =			&msdos_disk_ops,
	.features =		PED_DISK_TYPE_EXTENDED
};

void
ped_disk_msdos_init ()
{
	PED_ASSERT (sizeof (DosRawPartition) == 16, return);
	PED_ASSERT (sizeof (DosRawTable) == 512, return);

	ped_disk_type_register (&msdos_disk_type);
}

void
ped_disk_msdos_done ()
{
	ped_disk_type_unregister (&msdos_disk_type);
}
