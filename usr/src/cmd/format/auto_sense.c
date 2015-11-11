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
 * Copyright (c) 2011 Gary Mills
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * This file contains functions to implement automatic configuration
 * of scsi disks.
 */
#include "global.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

#include "misc.h"
#include "param.h"
#include "ctlr_scsi.h"
#include "auto_sense.h"
#include "partition.h"
#include "label.h"
#include "startup.h"
#include "analyze.h"
#include "io.h"
#include "hardware_structs.h"
#include "menu_fdisk.h"


#define	DISK_NAME_MAX		256

extern	int			nctypes;
extern	struct	ctlr_type	ctlr_types[];


/*
 * Marker for free hog partition
 */
#define	HOG		(-1)



/*
 * Default partition tables
 *
 *	Disk capacity		root	swap	usr
 *	-------------		----	----	---
 *	0mb to 64mb		0	0	remainder
 *	64mb to 180mb		16mb	16mb	remainder
 *	180mb to 280mb		16mb	32mb	remainder
 *	280mb to 380mb		24mb	32mb	remainder
 *	380mb to 600mb		32mb	32mb	remainder
 *	600mb to 1gb		32mb	64mb	remainder
 *	1gb to 2gb		64mb	128mb	remainder
 *	2gb on up		128mb	128mb	remainder
 */
struct part_table {
	int	partitions[NDKMAP];
};

static struct part_table part_table_64mb = {
	{ 0,	0,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_180mb = {
	{ 16,	16,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_280mb = {
	{ 16,	32,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_380mb = {
	{ 24,	32,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_600mb = {
	{ 32,	32,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_1gb = {
	{ 32,	64,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_2gb = {
	{ 64,	128,	0,	0,	0,	0,	HOG,	0}
};

static struct part_table part_table_infinity = {
	{ 128,	128,	0,	0,	0,	0,	HOG,	0}
};


static struct default_partitions {
	diskaddr_t		min_capacity;
	diskaddr_t		max_capacity;
	struct part_table	*part_table;
} default_partitions[] = {
	{ 0,	64,		&part_table_64mb },	/* 0 to 64 mb */
	{ 64,	180,		&part_table_180mb },	/* 64 to 180 mb */
	{ 180,	280,		&part_table_280mb },	/* 180 to 280 mb */
	{ 280,	380,		&part_table_380mb },	/* 280 to 380 mb */
	{ 380,	600,		&part_table_600mb },	/* 380 to 600 mb */
	{ 600,	1024,		&part_table_1gb },	/* 600 to 1 gb */
	{ 1024,	2048,		&part_table_2gb },	/* 1 to 2 gb */
	{ 2048,	INFINITY,	&part_table_infinity },	/* 2 gb on up */
};

#define	DEFAULT_PARTITION_TABLE_SIZE	\
	(sizeof (default_partitions) / sizeof (struct default_partitions))

/*
 * msgs for check()
 */
#define	FORMAT_MSG	"Auto configuration via format.dat"
#define	GENERIC_MSG	"Auto configuration via generic SCSI-2"

/*
 * Disks on symbios(Hardwire raid controller) return a fixed number
 * of heads(64)/cylinders(64) and adjust the cylinders depending
 * capacity of the configured lun.
 * In such a case we get number of physical cylinders < 3 which
 * is the minimum required by solaris(2 reserved + 1 data cylinders).
 * Hence try to adjust the cylinders by reducing the "nsect/nhead".
 *
 */
/*
 * assuming a minimum of 32 block cylinders.
 */
#define	MINIMUM_NO_HEADS	2
#define	MINIMUM_NO_SECTORS	16

#define	MINIMUM_NO_CYLINDERS	128

#if defined(_SUNOS_VTOC_8)

/* These are 16-bit fields */
#define	MAXIMUM_NO_HEADS	65535
#define	MAXIMUM_NO_SECTORS	65535
#define	MAXIMUM_NO_CYLINDERS	65535

#endif	/* defined(_SUNOS_VTOC_8) */

/*
 * minimum number of cylinders required by Solaris.
 */
#define	SUN_MIN_CYL		3



/*
 * ANSI prototypes for local static functions
 */
static struct disk_type	*generic_disk_sense(
				int		fd,
				int		can_prompt,
				struct dk_label	*label,
				struct scsi_inquiry *inquiry,
				struct scsi_capacity_16 *capacity,
				char		*disk_name);
static int		use_existing_disk_type(
				int		fd,
				int		can_prompt,
				struct dk_label	*label,
				struct scsi_inquiry *inquiry,
				struct disk_type *disk_type,
				struct scsi_capacity_16 *capacity);
int			build_default_partition(struct dk_label *label,
				int ctrl_type);
static struct disk_type	*find_scsi_disk_type(
				char		*disk_name,
				struct dk_label	*label);
static struct disk_type	*find_scsi_disk_by_name(
				char		*disk_name);
static struct ctlr_type	*find_scsi_ctlr_type(void);
static struct ctlr_info	*find_scsi_ctlr_info(
				struct dk_cinfo	*dkinfo);
static struct disk_type	*new_scsi_disk_type(
				int		fd,
				char		*disk_name,
				struct dk_label	*label);
static struct disk_info	*find_scsi_disk_info(
				struct dk_cinfo	*dkinfo);

static struct disk_type *new_direct_disk_type(int fd, char *disk_name,
    struct dk_label *label);

static struct disk_info *find_direct_disk_info(struct dk_cinfo *dkinfo);
static int efi_ioctl(int fd, int cmd, dk_efi_t *dk_ioc);
static int auto_label_init(struct dk_label *label);
static struct ctlr_type *find_direct_ctlr_type(void);
static struct ctlr_info *find_direct_ctlr_info(struct dk_cinfo	*dkinfo);
static  struct disk_info *find_direct_disk_info(struct dk_cinfo *dkinfo);
static struct ctlr_type *find_vbd_ctlr_type(void);
static struct ctlr_info *find_vbd_ctlr_info(struct dk_cinfo *dkinfo);
static struct disk_info *find_vbd_disk_info(struct dk_cinfo *dkinfo);

static char		*get_sun_disk_name(
				char		*disk_name,
				struct scsi_inquiry *inquiry);
static char		*strcopy(
				char	*dst,
				char	*src,
				int	n);
static	int		adjust_disk_geometry(diskaddr_t capacity, uint_t *cyl,
				uint_t *nsect, uint_t *nhead);
static void 		compute_chs_values(diskaddr_t total_capacity,
				diskaddr_t usable_capacity, uint_t *pcylp,
				uint_t *nheadp, uint_t *nsectp);
#if defined(_SUNOS_VTOC_8)
static diskaddr_t square_box(
			diskaddr_t capacity,
			uint_t *dim1, uint_t lim1,
			uint_t *dim2, uint_t lim2,
			uint_t *dim3, uint_t lim3);
#endif	/* defined(_SUNOS_VTOC_8) */


/*
 * We need to get information necessary to construct a *new* efi
 * label type
 */
struct disk_type *
auto_efi_sense(int fd, struct efi_info *label)
{

	struct dk_gpt	*vtoc;
	int		i;

	struct disk_type *disk, *dp;
	struct disk_info *disk_info;
	struct ctlr_info *ctlr;
	struct dk_cinfo dkinfo;
	struct partition_info *part;

	if (ioctl(fd, DKIOCINFO, &dkinfo) == -1) {
		if (option_msg && diag_msg) {
			err_print("DKIOCINFO failed\n");
		}
		return (NULL);
	}
	if ((cur_ctype != NULL) && (cur_ctype->ctype_ctype == DKC_DIRECT)) {
		ctlr = find_direct_ctlr_info(&dkinfo);
		disk_info = find_direct_disk_info(&dkinfo);
	} else if ((cur_ctype != NULL) && (cur_ctype->ctype_ctype == DKC_VBD)) {
		ctlr = find_vbd_ctlr_info(&dkinfo);
		disk_info = find_vbd_disk_info(&dkinfo);
	} else {
		ctlr = find_scsi_ctlr_info(&dkinfo);
		disk_info = find_scsi_disk_info(&dkinfo);
	}

	/*
	 * get vendor, product, revision and capacity info.
	 */
	if (get_disk_info(fd, label, disk_info) == -1) {
		return ((struct disk_type *)NULL);
	}
	/*
	 * Now build the default partition table
	 */
	if (efi_alloc_and_init(fd, EFI_NUMPAR, &vtoc) != 0) {
		err_print("efi_alloc_and_init failed. \n");
		return ((struct disk_type *)NULL);
	}

	label->e_parts = vtoc;

	/*
	 * Create a whole hog EFI partition table:
	 * S0 takes the whole disk except the primary EFI label,
	 * backup EFI label, and the reserved partition.
	 */
	vtoc->efi_parts[0].p_tag = V_USR;
	vtoc->efi_parts[0].p_start = vtoc->efi_first_u_lba;
	vtoc->efi_parts[0].p_size = vtoc->efi_last_u_lba - vtoc->efi_first_u_lba
	    - EFI_MIN_RESV_SIZE + 1;

	/*
	 * S1-S6 are unassigned slices.
	 */
	for (i = 1; i < vtoc->efi_nparts - 2; i ++) {
		vtoc->efi_parts[i].p_tag = V_UNASSIGNED;
		vtoc->efi_parts[i].p_start = 0;
		vtoc->efi_parts[i].p_size = 0;
	}

	/*
	 * The reserved slice
	 */
	vtoc->efi_parts[vtoc->efi_nparts - 1].p_tag = V_RESERVED;
	vtoc->efi_parts[vtoc->efi_nparts - 1].p_start =
	    vtoc->efi_last_u_lba - EFI_MIN_RESV_SIZE + 1;
	vtoc->efi_parts[vtoc->efi_nparts - 1].p_size = EFI_MIN_RESV_SIZE;

	/*
	 * Now stick all of it into the disk_type struct
	 */

	disk = (struct disk_type *)zalloc(sizeof (struct disk_type));
	assert(disk_info->disk_ctlr == ctlr);
	dp = ctlr->ctlr_ctype->ctype_dlist;
	if (dp == NULL) {
		ctlr->ctlr_ctype->ctype_dlist = dp;
	} else {
		while (dp->dtype_next != NULL) {
			dp = dp->dtype_next;
		}
		dp->dtype_next = disk;
	}
	disk->dtype_next = NULL;

	disk->vendor = strdup(label->vendor);
	disk->product = strdup(label->product);
	disk->revision = strdup(label->revision);

	if (disk->vendor == NULL ||
	    disk->product == NULL ||
	    disk->revision == NULL) {
		free(disk->vendor);
		free(disk->product);
		free(disk->revision);
		free(disk);
		return (NULL);
	}

	disk->capacity = label->capacity;

	part = (struct partition_info *)
	    zalloc(sizeof (struct partition_info));
	disk->dtype_plist = part;

	part->pinfo_name = alloc_string("default");
	part->pinfo_next = NULL;
	part->etoc = vtoc;

	bzero(disk_info->v_volume, LEN_DKL_VVOL);
	disk_info->disk_parts = part;
	return (disk);
}

static int
efi_ioctl(int fd, int cmd, dk_efi_t *dk_ioc)
{
	void *data = dk_ioc->dki_data;
	int error;

	dk_ioc->dki_data_64 = (uint64_t)(uintptr_t)data;
	error = ioctl(fd, cmd, (void *)dk_ioc);
	dk_ioc->dki_data = data;

	return (error);
}

static struct ctlr_type *
find_direct_ctlr_type()
{
	struct	mctlr_list	*mlp;

	mlp = controlp;

	while (mlp != NULL) {
		if (mlp->ctlr_type->ctype_ctype == DKC_DIRECT) {
			return (mlp->ctlr_type);
		}
		mlp = mlp->next;
	}

	impossible("no DIRECT controller type");

	return ((struct ctlr_type *)NULL);
}

static struct ctlr_type *
find_vbd_ctlr_type()
{
	struct	mctlr_list	*mlp;

	mlp = controlp;

	while (mlp != NULL) {
		if (mlp->ctlr_type->ctype_ctype == DKC_VBD) {
			return (mlp->ctlr_type);
		}
		mlp = mlp->next;
	}

	impossible("no VBD controller type");

	return ((struct ctlr_type *)NULL);
}

static struct ctlr_info *
find_direct_ctlr_info(
	struct dk_cinfo		*dkinfo)
{
	struct ctlr_info	*ctlr;

	if (dkinfo->dki_ctype != DKC_DIRECT)
		return (NULL);

	for (ctlr = ctlr_list; ctlr != NULL; ctlr = ctlr->ctlr_next) {
		if (ctlr->ctlr_addr == dkinfo->dki_addr &&
		    ctlr->ctlr_space == dkinfo->dki_space &&
		    ctlr->ctlr_ctype->ctype_ctype == DKC_DIRECT) {
			return (ctlr);
		}
	}

	impossible("no DIRECT controller info");
	/*NOTREACHED*/
}

static struct ctlr_info *
find_vbd_ctlr_info(
	struct dk_cinfo		*dkinfo)
{
	struct ctlr_info	*ctlr;

	if (dkinfo->dki_ctype != DKC_VBD)
		return (NULL);

	for (ctlr = ctlr_list; ctlr != NULL; ctlr = ctlr->ctlr_next) {
		if (ctlr->ctlr_addr == dkinfo->dki_addr &&
		    ctlr->ctlr_space == dkinfo->dki_space &&
		    ctlr->ctlr_ctype->ctype_ctype == DKC_VBD) {
			return (ctlr);
		}
	}

	impossible("no VBD controller info");
	/*NOTREACHED*/
}

static  struct disk_info *
find_direct_disk_info(
	struct dk_cinfo		*dkinfo)
{
	struct disk_info	*disk;
	struct dk_cinfo		*dp;

	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		assert(dkinfo->dki_ctype == DKC_DIRECT);
		dp = &disk->disk_dkinfo;
		if (dp->dki_ctype == dkinfo->dki_ctype &&
		    dp->dki_cnum == dkinfo->dki_cnum &&
		    dp->dki_unit == dkinfo->dki_unit &&
		    strcmp(dp->dki_dname, dkinfo->dki_dname) == 0) {
			return (disk);
		}
	}

	impossible("No DIRECT disk info instance\n");
	/*NOTREACHED*/
}

static  struct disk_info *
find_vbd_disk_info(
	struct dk_cinfo		*dkinfo)
{
	struct disk_info	*disk;
	struct dk_cinfo		*dp;

	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		assert(dkinfo->dki_ctype == DKC_VBD);
		dp = &disk->disk_dkinfo;
		if (dp->dki_ctype == dkinfo->dki_ctype &&
		    dp->dki_cnum == dkinfo->dki_cnum &&
		    dp->dki_unit == dkinfo->dki_unit &&
		    strcmp(dp->dki_dname, dkinfo->dki_dname) == 0) {
			return (disk);
		}
	}

	impossible("No VBD disk info instance\n");
	/*NOTREACHED*/
}

/*
 * To convert EFI to SMI labels, we need to get label geometry.
 * Unfortunately at this time there is no good way to do so.
 * DKIOCGGEOM will fail if disk is EFI labeled. So we hack around
 * it and clear EFI label, do a DKIOCGGEOM and put the EFI label
 * back on disk.
 * This routine gets the label geometry and initializes the label
 * It uses cur_file as opened device.
 * returns 0 if succeeds or -1 if failed.
 */
static int
auto_label_init(struct dk_label *label)
{
	dk_efi_t	dk_ioc;
	dk_efi_t	dk_ioc_back;
	efi_gpt_t	*data = NULL;
	efi_gpt_t	*databack = NULL;
	struct dk_geom	disk_geom;
	struct dk_minfo	disk_info;
	efi_gpt_t 	*backsigp;
	int		fd = cur_file;
	int		rval = -1;
	int		efisize = EFI_LABEL_SIZE * 2;
	int		success = 0;
	uint64_t	sig;
	uint64_t	backsig;

	if ((data = calloc(efisize, 1)) == NULL) {
		err_print("auto_label_init: calloc failed\n");
		goto auto_label_init_out;
	}

	dk_ioc.dki_data = data;
	dk_ioc.dki_lba = 1;
	dk_ioc.dki_length = efisize;

	if (efi_ioctl(fd, DKIOCGETEFI, &dk_ioc) != 0) {
		err_print("auto_label_init: GETEFI failed\n");
		goto auto_label_init_out;
	}

	if ((databack = calloc(efisize, 1)) == NULL) {
		err_print("auto_label_init calloc2 failed");
		goto auto_label_init_out;
	}

	/* get the LBA size and capacity */
	if (ioctl(fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info) == -1) {
		err_print("auto_label_init: dkiocgmediainfo failed\n");
		goto auto_label_init_out;
	}

	if (disk_info.dki_lbsize == 0) {
		if (option_msg && diag_msg) {
			err_print("auto_lbal_init: assuming 512 byte"
			    "block size");
		}
		disk_info.dki_lbsize = DEV_BSIZE;
	}

	dk_ioc_back.dki_data = databack;

	/*
	 * back up efi label goes to capacity - 1, we are reading an extra block
	 * before the back up label.
	 */
	dk_ioc_back.dki_lba = disk_info.dki_capacity - 1 - 1;
	dk_ioc_back.dki_length = efisize;

	if (efi_ioctl(fd, DKIOCGETEFI, &dk_ioc_back) != 0) {
		err_print("auto_label_init: GETEFI backup failed\n");
		goto auto_label_init_out;
	}

	sig = dk_ioc.dki_data->efi_gpt_Signature;
	dk_ioc.dki_data->efi_gpt_Signature = 0x0;

	enter_critical();

	if (efi_ioctl(fd, DKIOCSETEFI, &dk_ioc) == -1) {
		err_print("auto_label_init: SETEFI failed\n");
		exit_critical();
		goto auto_label_init_out;
	}

	backsigp = (efi_gpt_t *)((uintptr_t)dk_ioc_back.dki_data + cur_blksz);

	backsig = backsigp->efi_gpt_Signature;

	backsigp->efi_gpt_Signature = 0;

	if (efi_ioctl(fd, DKIOCSETEFI, &dk_ioc_back) == -1) {
		err_print("auto_label_init: SETEFI backup failed\n");
	}

	if (ioctl(cur_file, DKIOCGGEOM, &disk_geom) != 0)
		err_print("auto_label_init: GGEOM failed\n");
	else
		success = 1;

	dk_ioc.dki_data->efi_gpt_Signature = sig;
	backsigp->efi_gpt_Signature = backsig;

	if (efi_ioctl(cur_file, DKIOCSETEFI, &dk_ioc_back) == -1) {
		err_print("auto_label_init: SETEFI revert backup failed\n");
		success = 0;
	}

	if (efi_ioctl(cur_file, DKIOCSETEFI, &dk_ioc) == -1) {
		err_print("auto_label_init: SETEFI revert failed\n");
		success = 0;
	}

	exit_critical();

	if (success == 0)
		goto auto_label_init_out;

	ncyl = disk_geom.dkg_ncyl;
	acyl = disk_geom.dkg_acyl;
	nhead =  disk_geom.dkg_nhead;
	nsect = disk_geom.dkg_nsect;
	pcyl = ncyl + acyl;

	label->dkl_pcyl = pcyl;
	label->dkl_ncyl = ncyl;
	label->dkl_acyl = acyl;
	label->dkl_nhead = nhead;
	label->dkl_nsect = nsect;
	label->dkl_apc = 0;
	label->dkl_intrlv = 1;
	label->dkl_rpm = disk_geom.dkg_rpm;

	label->dkl_magic = DKL_MAGIC;

	(void) snprintf(label->dkl_asciilabel, sizeof (label->dkl_asciilabel),
	    "%s cyl %u alt %u hd %u sec %u",
	    "DEFAULT", ncyl, acyl, nhead, nsect);

	rval = 0;
#if defined(_FIRMWARE_NEEDS_FDISK)
	(void) auto_solaris_part(label);
	ncyl = label->dkl_ncyl;

#endif	/* defined(_FIRMWARE_NEEDS_FDISK) */

	if (!build_default_partition(label, DKC_DIRECT)) {
		rval = -1;
	}

	(void) checksum(label, CK_MAKESUM);


auto_label_init_out:
	if (data)
		free(data);
	if (databack)
		free(databack);

	return (rval);
}

static struct disk_type *
new_direct_disk_type(
	int		fd,
	char		*disk_name,
	struct dk_label	*label)
{
	struct disk_type	*dp;
	struct disk_type	*disk;
	struct ctlr_info	*ctlr;
	struct dk_cinfo		dkinfo;
	struct partition_info	*part = NULL;
	struct partition_info	*pt;
	struct disk_info	*disk_info;
	int			i;

	/*
	 * Get the disk controller info for this disk
	 */
	if (ioctl(fd, DKIOCINFO, &dkinfo) == -1) {
		if (option_msg && diag_msg) {
			err_print("DKIOCINFO failed\n");
		}
		return (NULL);
	}

	/*
	 * Find the ctlr_info for this disk.
	 */
	ctlr = find_direct_ctlr_info(&dkinfo);

	/*
	 * Allocate a new disk type for the direct controller.
	 */
	disk = (struct disk_type *)zalloc(sizeof (struct disk_type));

	/*
	 * Find the disk_info instance for this disk.
	 */
	disk_info = find_direct_disk_info(&dkinfo);

	/*
	 * The controller and the disk should match.
	 */
	assert(disk_info->disk_ctlr == ctlr);

	/*
	 * Link the disk into the list of disks
	 */
	dp = ctlr->ctlr_ctype->ctype_dlist;
	if (dp == NULL) {
		ctlr->ctlr_ctype->ctype_dlist = dp;
	} else {
		while (dp->dtype_next != NULL) {
			dp = dp->dtype_next;
		}
		dp->dtype_next = disk;
	}
	disk->dtype_next = NULL;

	/*
	 * Allocate and initialize the disk name.
	 */
	disk->dtype_asciilabel = alloc_string(disk_name);

	/*
	 * Initialize disk geometry info
	 */
	disk->dtype_pcyl = label->dkl_pcyl;
	disk->dtype_ncyl = label->dkl_ncyl;
	disk->dtype_acyl = label->dkl_acyl;
	disk->dtype_nhead = label->dkl_nhead;
	disk->dtype_nsect = label->dkl_nsect;
	disk->dtype_rpm = label->dkl_rpm;

	part = (struct partition_info *)
	    zalloc(sizeof (struct partition_info));
	pt = disk->dtype_plist;
	if (pt == NULL) {
		disk->dtype_plist = part;
	} else {
		while (pt->pinfo_next != NULL) {
			pt = pt->pinfo_next;
		}
		pt->pinfo_next = part;
	}

	part->pinfo_next = NULL;

	/*
	 * Set up the partition name
	 */
	part->pinfo_name = alloc_string("default");

	/*
	 * Fill in the partition info from the label
	 */
	for (i = 0; i < NDKMAP; i++) {

#if defined(_SUNOS_VTOC_8)
		part->pinfo_map[i] = label->dkl_map[i];

#elif defined(_SUNOS_VTOC_16)
		part->pinfo_map[i].dkl_cylno =
		    label->dkl_vtoc.v_part[i].p_start /
		    ((blkaddr_t)(disk->dtype_nhead *
		    disk->dtype_nsect - apc));
		part->pinfo_map[i].dkl_nblk =
		    label->dkl_vtoc.v_part[i].p_size;
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */
	}

	/*
	 * Use the VTOC if valid, or install a default
	 */
	if (label->dkl_vtoc.v_version == V_VERSION) {
		(void) memcpy(disk_info->v_volume, label->dkl_vtoc.v_volume,
		    LEN_DKL_VVOL);
		part->vtoc = label->dkl_vtoc;
	} else {
		(void) memset(disk_info->v_volume, 0, LEN_DKL_VVOL);
		set_vtoc_defaults(part);
	}

	/*
	 * Link the disk to the partition map
	 */
	disk_info->disk_parts = part;

	return (disk);
}

/*
 * Get a disk type that has label info. This is used to convert
 * EFI label to SMI label
 */
struct disk_type *
auto_direct_get_geom_label(int fd, struct dk_label *label)
{
	struct disk_type		*disk_type;

	if (auto_label_init(label) != 0) {
		err_print("auto_direct_get_geom_label: failed to get label"
		    "geometry");
		return (NULL);
	} else {
		disk_type = new_direct_disk_type(fd, "DEFAULT", label);
		return (disk_type);
	}
}

/*
 * Auto-sense a scsi disk configuration, ie get the information
 * necessary to construct a label.  We have two different
 * ways to auto-sense a scsi disk:
 *	- format.dat override, via inquiry name
 *	- generic scsi, via standard mode sense and inquiry
 * Depending on how and when we are called, and/or
 * change geometry and reformat.
 */
struct disk_type *
auto_sense(
	int		fd,
	int		can_prompt,
	struct dk_label	*label)
{
	struct scsi_inquiry		inquiry;
	struct scsi_capacity_16		capacity;
	struct disk_type		*disk_type;
	char				disk_name[DISK_NAME_MAX];
	int				force_format_dat = 0;
	int				force_generic = 0;
	u_ioparam_t			ioparam;
	int				deflt;
	char				*buf;

	/*
	 * First, if expert mode, find out if the user
	 * wants to override any of the standard methods.
	 */
	if (can_prompt && expert_mode) {
		deflt = 1;
		ioparam.io_charlist = confirm_list;
		if (input(FIO_MSTR, FORMAT_MSG, '?', &ioparam,
		    &deflt, DATA_INPUT) == 0) {
			force_format_dat = 1;
		} else if (input(FIO_MSTR, GENERIC_MSG, '?', &ioparam,
		    &deflt, DATA_INPUT) == 0) {
			force_generic = 1;
		}
	}

	/*
	 * Get the Inquiry data.  If this fails, there's
	 * no hope for this disk, so give up.
	 */
	if (uscsi_inquiry(fd, (char *)&inquiry, sizeof (inquiry))) {
		return ((struct disk_type *)NULL);
	}
	if (option_msg && diag_msg) {
		err_print("Product id: ");
		print_buf(inquiry.inq_pid, sizeof (inquiry.inq_pid));
		err_print("\n");
	}

	/*
	 * Get the Read Capacity
	 */
	if (uscsi_read_capacity(fd, &capacity)) {
		return ((struct disk_type *)NULL);
	}

	/*
	 * If the reported capacity is set to zero, then the disk
	 * is not usable. If the reported capacity is set to all
	 * 0xf's, then this disk is too large.  These could only
	 * happen with a device that supports LBAs larger than 64
	 * bits which are not defined by any current T10 standards
	 * or by error responding from target.
	 */
	if ((capacity.sc_capacity == 0) ||
	    (capacity.sc_capacity == UINT_MAX64)) {
		if (option_msg && diag_msg) {
			err_print("Invalid capacity\n");
		}
		return ((struct disk_type *)NULL);
	}
	if (option_msg && diag_msg) {
		err_print("blocks:  %llu (0x%llx)\n",
		    capacity.sc_capacity, capacity.sc_capacity);
		err_print("blksize: %u\n", capacity.sc_lbasize);
	}

	/*
	 * Extract the disk name for the format.dat override
	 */
	(void) get_sun_disk_name(disk_name, &inquiry);
	if (option_msg && diag_msg) {
		err_print("disk name:  `%s`\n", disk_name);
	}

	buf = zalloc(cur_blksz);
	if (scsi_rdwr(DIR_READ, fd, (diskaddr_t)0, 1, (caddr_t)buf,
	    F_SILENT, NULL)) {
		free(buf);
		return ((struct disk_type *)NULL);
	}
	free(buf);

	/*
	 * Figure out which method we use for auto sense.
	 * If a particular method fails, we fall back to
	 * the next possibility.
	 */

	if (force_generic) {
		return (generic_disk_sense(fd, can_prompt, label,
		    &inquiry, &capacity, disk_name));
	}

	/*
	 * Try for an existing format.dat first
	 */
	if ((disk_type = find_scsi_disk_by_name(disk_name)) != NULL) {
		if (use_existing_disk_type(fd, can_prompt, label,
		    &inquiry, disk_type, &capacity)) {
			return (disk_type);
		}
		if (force_format_dat) {
			return (NULL);
		}
	}

	/*
	 * Otherwise, try using generic SCSI-2 sense and inquiry.
	 */

	return (generic_disk_sense(fd, can_prompt, label,
	    &inquiry, &capacity, disk_name));
}



/*ARGSUSED*/
static struct disk_type *
generic_disk_sense(
	int			fd,
	int			can_prompt,
	struct dk_label		*label,
	struct scsi_inquiry	*inquiry,
	struct scsi_capacity_16	*capacity,
	char			*disk_name)
{
	struct disk_type		*disk;
	int				setdefault = 0;
	uint_t				pcyl = 0;
	uint_t				ncyl = 0;
	uint_t				acyl = 0;
	uint_t				nhead = 0;
	uint_t				nsect = 0;
	int				rpm = 0;
	diskaddr_t			nblocks = 0;
	diskaddr_t			tblocks = 0;
	union {
		struct mode_format	page3;
		uchar_t			buf3[MAX_MODE_SENSE_SIZE];
	} u_page3;
	union {
		struct mode_geometry	page4;
		uchar_t			buf4[MAX_MODE_SENSE_SIZE];
	} u_page4;
	struct mode_format		*page3 = &u_page3.page3;
	struct mode_geometry		*page4 = &u_page4.page4;
	struct scsi_ms_header		header;

	/*
	 * If the name of this disk appears to be "SUN", use it,
	 * otherwise construct a name out of the generic
	 * Inquiry info.  If it turns out that we already
	 * have a SUN disk type of this name that differs
	 * in geometry, we will revert to the generic name
	 * anyway.
	 */
	if (memcmp(disk_name, "SUN", strlen("SUN")) != 0) {
		(void) get_generic_disk_name(disk_name, inquiry);
	}

	/*
	 * Get the number of blocks from Read Capacity data. Note that
	 * the logical block address range from 0 to capacity->sc_capacity.
	 * Limit the size to 2 TB (UINT32_MAX) to use with SMI labels.
	 */
	tblocks = (capacity->sc_capacity + 1);
	if (tblocks > UINT32_MAX)
		nblocks = UINT32_MAX;
	else
		nblocks = tblocks;

	/*
	 * Get current Page 3 - Format Parameters page
	 */
	if (uscsi_mode_sense(fd, DAD_MODE_FORMAT, MODE_SENSE_PC_CURRENT,
	    (caddr_t)&u_page3, MAX_MODE_SENSE_SIZE, &header)) {
		setdefault = 1;
	}

	/*
	 * Get current Page 4 - Drive Geometry page
	 */
	if (uscsi_mode_sense(fd, DAD_MODE_GEOMETRY, MODE_SENSE_PC_CURRENT,
	    (caddr_t)&u_page4, MAX_MODE_SENSE_SIZE, &header)) {
		setdefault = 1;
	}

	if (setdefault != 1) {
		/* The inquiry of mode page 3 & page 4 are successful */
		/*
		 * Correct for byte order if necessary
		 */
		page4->rpm = BE_16(page4->rpm);
		page4->step_rate = BE_16(page4->step_rate);
		page3->tracks_per_zone = BE_16(page3->tracks_per_zone);
		page3->alt_sect_zone = BE_16(page3->alt_sect_zone);
		page3->alt_tracks_zone = BE_16(page3->alt_tracks_zone);
		page3->alt_tracks_vol = BE_16(page3->alt_tracks_vol);
		page3->sect_track = BE_16(page3->sect_track);
		page3->data_bytes_sect = BE_16(page3->data_bytes_sect);
		page3->interleave = BE_16(page3->interleave);
		page3->track_skew = BE_16(page3->track_skew);
		page3->cylinder_skew = BE_16(page3->cylinder_skew);


		/*
		 * Construct a new label out of the sense data,
		 * Inquiry and Capacity.
		 *
		 * If the disk capacity is > 1TB then simply compute
		 * the CHS values based on the total disk capacity and
		 * not use the values from mode-sense data.
		 */
		if (tblocks > INT32_MAX) {
			compute_chs_values(tblocks, nblocks, &pcyl, &nhead,
			    &nsect);
		} else {
			pcyl = (page4->cyl_ub << 16) + (page4->cyl_mb << 8) +
			    page4->cyl_lb;
			nhead = page4->heads;
			nsect = page3->sect_track;
		}

		rpm = page4->rpm;

		/*
		 * If the number of physical cylinders reported is less
		 * the SUN_MIN_CYL(3) then try to adjust the geometry so that
		 * we have atleast SUN_MIN_CYL cylinders.
		 */
		if (pcyl < SUN_MIN_CYL) {
			if (nhead == 0 || nsect == 0) {
				setdefault = 1;
			} else if (adjust_disk_geometry(
			    (diskaddr_t)(capacity->sc_capacity + 1),
			    &pcyl, &nhead, &nsect)) {
				setdefault = 1;
			}
		}
	}

	/*
	 * Mode sense page 3 and page 4 are obsolete in SCSI-3. For
	 * newly developed large sector size disk, we will not rely on
	 * those two pages but compute geometry directly.
	 */
	if ((setdefault == 1) || (capacity->sc_lbasize != DEV_BSIZE)) {
		/*
		 * If the number of cylinders or the number of heads reported
		 * is zero, we think the inquiry of page 3 and page 4 failed.
		 * We will set the geometry infomation by ourselves.
		 */
		compute_chs_values(tblocks, nblocks, &pcyl, &nhead, &nsect);
	}

	/*
	 * The sd driver reserves 2 cylinders the backup disk label and
	 * the deviceid.  Set the number of data cylinders to pcyl-acyl.
	 */
	acyl = DK_ACYL;
	ncyl = pcyl - acyl;

	if (option_msg && diag_msg) {
		err_print("Geometry:\n");
		err_print("    pcyl:    %u\n", pcyl);
		err_print("    ncyl:    %u\n", ncyl);
		err_print("    heads:   %u\n", nhead);
		err_print("    nsects:  %u\n", nsect);
		err_print("    acyl:    %u\n", acyl);

#if defined(_SUNOS_VTOC_16)
		err_print("    bcyl:    %u\n", bcyl);
#endif			/* defined(_SUNOS_VTOC_16) */

		err_print("    rpm:     %d\n", rpm);
		err_print("    nblocks:     %llu\n", nblocks);
	}

	/*
	 * Some drives do not support page4 or report 0 for page4->rpm,
	 * adjust it to AVG_RPM, 3600.
	 */
	if (rpm < MIN_RPM || rpm > MAX_RPM) {
		if (option_msg && diag_msg)
			err_print("The current rpm value %d is invalid,"
			    " adjusting it to %d\n", rpm, AVG_RPM);
		rpm = AVG_RPM;
	}

	/*
	 * Some drives report 0 for nsect (page 3, byte 10 and 11) if they
	 * have variable number of sectors per track. So adjust nsect.
	 * Also the value is defined as vendor specific, hence check if
	 * it is in a tolerable range. The values (32 and 4 below) are
	 * chosen so that this change below does not generate a different
	 * geometry for currently supported sun disks.
	 */
	if ((nsect == 0) ||
	    ((diskaddr_t)pcyl * nhead * nsect) < (nblocks - nblocks/32) ||
	    ((diskaddr_t)pcyl * nhead * nsect) > (nblocks + nblocks/4)) {
		if (nblocks > (pcyl * nhead)) {
			err_print("Mode sense page(3) reports nsect value"
			    " as %d, adjusting it to %llu\n",
			    nsect, nblocks / (pcyl * nhead));
			nsect = nblocks / (pcyl * nhead);
		} else {
			/* convert capacity to nsect * nhead * pcyl */
			err_print("\nWARNING: Disk geometry is based on "
			    "capacity data.\n\n");
			compute_chs_values(tblocks, nblocks, &pcyl, &nhead,
			    &nsect);
			ncyl = pcyl - acyl;
			if (option_msg && diag_msg) {
				err_print("Geometry:(after adjustment)\n");
				err_print("    pcyl:    %u\n", pcyl);
				err_print("    ncyl:    %u\n", ncyl);
				err_print("    heads:   %u\n", nhead);
				err_print("    nsects:  %u\n", nsect);
				err_print("    acyl:    %u\n", acyl);

#if defined(_SUNOS_VTOC_16)
				err_print("    bcyl:    %u\n", bcyl);
#endif

				err_print("    rpm:     %d\n", rpm);
				err_print("    nblocks:     %llu\n", nblocks);
			}
		}
	}

	/*
	 * Some drives report their physical geometry such that
	 * it is greater than the actual capacity.  Adjust the
	 * geometry to allow for this, so we don't run off
	 * the end of the disk.
	 */
	if (((diskaddr_t)pcyl * nhead * nsect) > nblocks) {
		uint_t	p = pcyl;
		if (option_msg && diag_msg) {
			err_print("Computed capacity (%llu) exceeds actual "
			    "disk capacity (%llu)\n",
			    (diskaddr_t)pcyl * nhead * nsect, nblocks);
		}
		do {
			pcyl--;
		} while (((diskaddr_t)pcyl * nhead * nsect) > nblocks);

		if (can_prompt && expert_mode && !option_f) {
			/*
			 * Try to adjust nsect instead of pcyl to see if we
			 * can optimize. For compatability reasons do this
			 * only in expert mode (refer to bug 1144812).
			 */
			uint_t	n = nsect;
			do {
				n--;
			} while (((diskaddr_t)p * nhead * n) > nblocks);
			if (((diskaddr_t)p * nhead * n) >
			    ((diskaddr_t)pcyl * nhead * nsect)) {
				u_ioparam_t	ioparam;
				int		deflt = 1;
				/*
				 * Ask the user for a choice here.
				 */
				ioparam.io_bounds.lower = 1;
				ioparam.io_bounds.upper = 2;
				err_print("1. Capacity = %llu, with pcyl = %u "
				    "nhead = %u nsect = %u\n",
				    ((diskaddr_t)pcyl * nhead * nsect),
				    pcyl, nhead, nsect);
				err_print("2. Capacity = %llu, with pcyl = %u "
				    "nhead = %u nsect = %u\n",
				    ((diskaddr_t)p * nhead * n),
				    p, nhead, n);
				if (input(FIO_INT, "Select one of the above "
				    "choices ", ':', &ioparam,
				    &deflt, DATA_INPUT) == 2) {
					pcyl = p;
					nsect = n;
				}
			}
		}
	}

#if defined(_SUNOS_VTOC_8)
	/*
	 * Finally, we need to make sure we don't overflow any of the
	 * fields in our disk label.  To do this we need to `square
	 * the box' so to speak.  We will lose bits here.
	 */

	if ((pcyl > MAXIMUM_NO_CYLINDERS &&
	    ((nsect > MAXIMUM_NO_SECTORS) ||
	    (nhead > MAXIMUM_NO_HEADS))) ||
	    ((nsect > MAXIMUM_NO_SECTORS) &&
	    (nhead > MAXIMUM_NO_HEADS))) {
		err_print("This disk is too big to label. "
		    " You will lose some blocks.\n");
	}
	if ((pcyl > MAXIMUM_NO_CYLINDERS) ||
	    (nsect > MAXIMUM_NO_SECTORS) ||
	    (nhead > MAXIMUM_NO_HEADS)) {
		u_ioparam_t	ioparam;
		int		order;
		char		msg[256];

		order = ((pcyl > nhead)<<2) |
		    ((pcyl > nsect)<<1) |
		    (nhead > nsect);
		switch (order) {
		case 0x7: /* pcyl > nhead > nsect */
			nblocks =
			    square_box(nblocks,
			    &pcyl, MAXIMUM_NO_CYLINDERS,
			    &nhead, MAXIMUM_NO_HEADS,
			    &nsect, MAXIMUM_NO_SECTORS);
			break;
		case 0x6: /* pcyl > nsect > nhead */
			nblocks =
			    square_box(nblocks,
			    &pcyl, MAXIMUM_NO_CYLINDERS,
			    &nsect, MAXIMUM_NO_SECTORS,
			    &nhead, MAXIMUM_NO_HEADS);
			break;
		case 0x4: /* nsect > pcyl > nhead */
			nblocks =
			    square_box(nblocks,
			    &nsect, MAXIMUM_NO_SECTORS,
			    &pcyl, MAXIMUM_NO_CYLINDERS,
			    &nhead, MAXIMUM_NO_HEADS);
			break;
		case 0x0: /* nsect > nhead > pcyl */
			nblocks =
			    square_box(nblocks,
			    &nsect, MAXIMUM_NO_SECTORS,
			    &nhead, MAXIMUM_NO_HEADS,
			    &pcyl, MAXIMUM_NO_CYLINDERS);
			break;
		case 0x3: /* nhead > pcyl > nsect */
			nblocks =
			    square_box(nblocks,
			    &nhead, MAXIMUM_NO_HEADS,
			    &pcyl, MAXIMUM_NO_CYLINDERS,
			    &nsect, MAXIMUM_NO_SECTORS);
			break;
		case 0x1: /* nhead > nsect > pcyl */
			nblocks =
			    square_box(nblocks,
			    &nhead, MAXIMUM_NO_HEADS,
			    &nsect, MAXIMUM_NO_SECTORS,
			    &pcyl, MAXIMUM_NO_CYLINDERS);
			break;
		default:
			/* How did we get here? */
			impossible("label overflow adjustment");

			/* Do something useful */
			nblocks =
			    square_box(nblocks,
			    &nhead, MAXIMUM_NO_HEADS,
			    &nsect, MAXIMUM_NO_SECTORS,
			    &pcyl, MAXIMUM_NO_CYLINDERS);
			break;
		}
		if (option_msg && diag_msg &&
		    (capacity->sc_capacity + 1 != nblocks)) {
			err_print("After adjusting geometry you lost"
			    " %llu of %llu blocks.\n",
			    (capacity->sc_capacity + 1 - nblocks),
			    capacity->sc_capacity + 1);
		}
		while (can_prompt && expert_mode && !option_f) {
			int				deflt = 1;

			/*
			 * Allow user to modify this by hand if desired.
			 */
			(void) sprintf(msg,
			    "\nGeometry: %u heads, %u sectors %u cylinders"
			    " result in %llu out of %llu blocks.\n"
			    "Do you want to modify the device geometry",
			    nhead, nsect, pcyl,
			    nblocks, capacity->sc_capacity + 1);

			ioparam.io_charlist = confirm_list;
			if (input(FIO_MSTR, msg, '?', &ioparam,
			    &deflt, DATA_INPUT) != 0)
				break;

			ioparam.io_bounds.lower = MINIMUM_NO_HEADS;
			ioparam.io_bounds.upper = MAXIMUM_NO_HEADS;
			nhead = input(FIO_INT, "Number of heads", ':',
			    &ioparam, (int *)&nhead, DATA_INPUT);
			ioparam.io_bounds.lower = MINIMUM_NO_SECTORS;
			ioparam.io_bounds.upper = MAXIMUM_NO_SECTORS;
			nsect = input(FIO_INT,
			    "Number of sectors per track",
			    ':', &ioparam, (int *)&nsect, DATA_INPUT);
			ioparam.io_bounds.lower = SUN_MIN_CYL;
			ioparam.io_bounds.upper = MAXIMUM_NO_CYLINDERS;
			pcyl = input(FIO_INT, "Number of cylinders",
			    ':', &ioparam, (int *)&pcyl, DATA_INPUT);
			nblocks = (diskaddr_t)nhead * nsect * pcyl;
			if (nblocks > capacity->sc_capacity + 1) {
				err_print("Warning: %llu blocks exceeds "
				    "disk capacity of %llu blocks\n",
				    nblocks,
				    capacity->sc_capacity + 1);
			}
		}
	}
#endif		/* defined(_SUNOS_VTOC_8) */

	ncyl = pcyl - acyl;

	if (option_msg && diag_msg) {
		err_print("\nGeometry after adjusting for capacity:\n");
		err_print("    pcyl:    %u\n", pcyl);
		err_print("    ncyl:    %u\n", ncyl);
		err_print("    heads:   %u\n", nhead);
		err_print("    nsects:  %u\n", nsect);
		err_print("    acyl:    %u\n", acyl);
		err_print("    rpm:     %d\n", rpm);
	}

	(void) memset((char *)label, 0, sizeof (struct dk_label));

	label->dkl_magic = DKL_MAGIC;

	(void) snprintf(label->dkl_asciilabel, sizeof (label->dkl_asciilabel),
	    "%s cyl %u alt %u hd %u sec %u",
	    disk_name, ncyl, acyl, nhead, nsect);

	label->dkl_pcyl = pcyl;
	label->dkl_ncyl = ncyl;
	label->dkl_acyl = acyl;
	label->dkl_nhead = nhead;
	label->dkl_nsect = nsect;
	label->dkl_apc = 0;
	label->dkl_intrlv = 1;
	label->dkl_rpm = rpm;

#if defined(_FIRMWARE_NEEDS_FDISK)
	if (auto_solaris_part(label) == -1)
		goto err;
	ncyl = label->dkl_ncyl;
#endif		/* defined(_FIRMWARE_NEEDS_FDISK) */


	if (!build_default_partition(label, DKC_SCSI_CCS)) {
		goto err;
	}

	(void) checksum(label, CK_MAKESUM);

	/*
	 * Find an existing disk type defined for this disk.
	 * For this to work, both the name and geometry must
	 * match.  If there is no such type, but there already
	 * is a disk defined with that name, but with a different
	 * geometry, construct a new generic disk name out of
	 * the inquiry information.  Whatever name we're
	 * finally using, if there's no such disk type defined,
	 * build a new disk definition.
	 */
	if ((disk = find_scsi_disk_type(disk_name, label)) == NULL) {
		if (find_scsi_disk_by_name(disk_name) != NULL) {
			char	old_name[DISK_NAME_MAX];
			(void) strcpy(old_name, disk_name);
			(void) get_generic_disk_name(disk_name,
			    inquiry);
			if (option_msg && diag_msg) {
				err_print(
"Changing disk type name from '%s' to '%s'\n", old_name, disk_name);
			}
			(void) snprintf(label->dkl_asciilabel,
			    sizeof (label->dkl_asciilabel),
			    "%s cyl %u alt %u hd %u sec %u",
			    disk_name, ncyl, acyl, nhead, nsect);
			(void) checksum(label, CK_MAKESUM);
			disk = find_scsi_disk_type(disk_name, label);
		}
		if (disk == NULL) {
			disk = new_scsi_disk_type(fd, disk_name, label);
			if (disk == NULL)
				goto err;
		}
	}

	return (disk);

err:
	if (option_msg && diag_msg) {
		err_print(
		"Configuration via generic SCSI-2 information failed\n");
	}
	return (NULL);
}


/*ARGSUSED*/
static int
use_existing_disk_type(
	int			fd,
	int			can_prompt,
	struct dk_label		*label,
	struct scsi_inquiry	*inquiry,
	struct disk_type	*disk_type,
	struct scsi_capacity_16	*capacity)
{
	int			pcyl;
	int			acyl;
	int			nhead;
	int			nsect;
	int			rpm;

	/*
	 * Construct a new label out of the format.dat
	 */
	pcyl = disk_type->dtype_pcyl;
	acyl = disk_type->dtype_acyl;
	ncyl = disk_type->dtype_ncyl;
	nhead = disk_type->dtype_nhead;
	nsect = disk_type->dtype_nsect;
	rpm = disk_type->dtype_rpm;

	if (option_msg && diag_msg) {
		err_print("Format.dat geometry:\n");
		err_print("    pcyl:    %u\n", pcyl);
		err_print("    heads:   %u\n", nhead);
		err_print("    nsects:  %u\n", nsect);
		err_print("    acyl:    %u\n", acyl);
		err_print("    rpm:     %d\n", rpm);
	}

	(void) memset((char *)label, 0, sizeof (struct dk_label));

	label->dkl_magic = DKL_MAGIC;

	(void) snprintf(label->dkl_asciilabel, sizeof (label->dkl_asciilabel),
	    "%s cyl %u alt %u hd %u sec %u",
	    disk_type->dtype_asciilabel,
	    ncyl, acyl, nhead, nsect);

	label->dkl_pcyl = pcyl;
	label->dkl_ncyl = ncyl;
	label->dkl_acyl = acyl;
	label->dkl_nhead = nhead;
	label->dkl_nsect = nsect;
	label->dkl_apc = 0;
	label->dkl_intrlv = 1;
	label->dkl_rpm = rpm;

	if (!build_default_partition(label, DKC_SCSI_CCS)) {
		goto err;
	}

	(void) checksum(label, CK_MAKESUM);
	return (1);

err:
	if (option_msg && diag_msg) {
		err_print(
		    "Configuration via format.dat geometry failed\n");
	}
	return (0);
}

int
build_default_partition(
	struct dk_label			*label,
	int				ctrl_type)
{
	int				i;
	int				ncyls[NDKMAP];
	diskaddr_t			nblks;
	int				cyl;
	struct dk_vtoc			*vtoc;
	struct part_table		*pt;
	struct default_partitions	*dpt;
	diskaddr_t			capacity;
	int				freecyls;
	int				blks_per_cyl;
	int				ncyl;

#ifdef lint
	ctrl_type = ctrl_type;
#endif

	/*
	 * Install a default vtoc
	 */
	vtoc = &label->dkl_vtoc;
	vtoc->v_version = V_VERSION;
	vtoc->v_nparts = NDKMAP;
	vtoc->v_sanity = VTOC_SANE;

	for (i = 0; i < NDKMAP; i++) {
		vtoc->v_part[i].p_tag = default_vtoc_map[i].p_tag;
		vtoc->v_part[i].p_flag = default_vtoc_map[i].p_flag;
	}

	/*
	 * Find a partition that matches this disk.  Capacity
	 * is in integral number of megabytes.
	 */
	capacity = ((diskaddr_t)(label->dkl_ncyl) * label->dkl_nhead *
	    label->dkl_nsect) / (diskaddr_t)((1024 * 1024) / cur_blksz);
	dpt = default_partitions;
	for (i = 0; i < DEFAULT_PARTITION_TABLE_SIZE; i++, dpt++) {
		if (capacity >= dpt->min_capacity &&
		    capacity < dpt->max_capacity) {
			break;
		}
	}
	if (i == DEFAULT_PARTITION_TABLE_SIZE) {
		if (option_msg && diag_msg) {
			err_print("No matching default partition (%llu)\n",
			    capacity);
		}
		return (0);
	}
	pt = dpt->part_table;

	/*
	 * Go through default partition table, finding fixed
	 * sized entries.
	 */
	freecyls = label->dkl_ncyl;
	blks_per_cyl = label->dkl_nhead * label->dkl_nsect;
	for (i = 0; i < NDKMAP; i++) {
		if (pt->partitions[i] == HOG || pt->partitions[i] == 0) {
			ncyls[i] = 0;
		} else {
			/*
			 * Calculate number of cylinders necessary
			 * for specified size, rounding up to
			 * the next greatest integral number of
			 * cylinders.  Always give what they
			 * asked or more, never less.
			 */
			nblks = pt->partitions[i] * ((1024*1024)/cur_blksz);
			nblks += (blks_per_cyl - 1);
			ncyls[i] = nblks / blks_per_cyl;
			freecyls -= ncyls[i];
		}
	}

	if (freecyls < 0) {
		if (option_msg && diag_msg) {
			for (i = 0; i < NDKMAP; i++) {
				if (ncyls[i] == 0)
					continue;
				err_print("Partition %d: %u cyls\n",
				    i, ncyls[i]);
			}
			err_print("Free cylinders exhausted (%d)\n",
			    freecyls);
		}
		return (0);
	}
#if defined(i386)
	/*
	 * Set the default boot partition to 1 cylinder
	 */
	ncyls[8] = 1;
	freecyls -= 1;

	/*
	 * If current disk type is not a SCSI disk,
	 * set the default alternates partition to 2 cylinders
	 */
	if (ctrl_type != DKC_SCSI_CCS) {
		ncyls[9] = 2;
		freecyls -= 2;
	}
#endif			/* defined(i386) */

	/*
	 * Set the free hog partition to whatever space remains.
	 * It's an error to have more than one HOG partition,
	 * but we don't verify that here.
	 */
	for (i = 0; i < NDKMAP; i++) {
		if (pt->partitions[i] == HOG) {
			assert(ncyls[i] == 0);
			ncyls[i] = freecyls;
			break;
		}
	}

	/*
	 * Error checking
	 */
	ncyl = 0;
	for (i = 0; i < NDKMAP; i++) {
		ncyl += ncyls[i];
	}
	assert(ncyl == (label->dkl_ncyl));

	/*
	 * Finally, install the partition in the label.
	 */
	cyl = 0;

#if defined(_SUNOS_VTOC_16)
	for (i = NDKMAP/2; i < NDKMAP; i++) {
		if (i == 2 || ncyls[i] == 0)
			continue;
		label->dkl_vtoc.v_part[i].p_start = cyl * blks_per_cyl;
		label->dkl_vtoc.v_part[i].p_size = ncyls[i] * blks_per_cyl;
		cyl += ncyls[i];
	}
	for (i = 0; i < NDKMAP/2; i++) {

#elif defined(_SUNOS_VTOC_8)
	for (i = 0; i < NDKMAP; i++) {

#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_16) */

		if (i == 2 || ncyls[i] == 0) {
#if defined(_SUNOS_VTOC_8)
			if (i != 2) {
				label->dkl_map[i].dkl_cylno = 0;
				label->dkl_map[i].dkl_nblk = 0;
			}
#endif
			continue;
		}
#if defined(_SUNOS_VTOC_8)
		label->dkl_map[i].dkl_cylno = cyl;
		label->dkl_map[i].dkl_nblk = ncyls[i] * blks_per_cyl;
#elif defined(_SUNOS_VTOC_16)
		label->dkl_vtoc.v_part[i].p_start = cyl * blks_per_cyl;
		label->dkl_vtoc.v_part[i].p_size = ncyls[i] * blks_per_cyl;

#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

		cyl += ncyls[i];
	}

	/*
	 * Set the whole disk partition
	 */
#if defined(_SUNOS_VTOC_8)
	label->dkl_map[2].dkl_cylno = 0;
	label->dkl_map[2].dkl_nblk =
	    label->dkl_ncyl * label->dkl_nhead * label->dkl_nsect;

#elif defined(_SUNOS_VTOC_16)
	label->dkl_vtoc.v_part[2].p_start = 0;
	label->dkl_vtoc.v_part[2].p_size =
	    (label->dkl_ncyl + label->dkl_acyl) * label->dkl_nhead *
	    label->dkl_nsect;
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */


	if (option_msg && diag_msg) {
		float	scaled;
		err_print("\n");
		for (i = 0; i < NDKMAP; i++) {
#if defined(_SUNOS_VTOC_8)
			if (label->dkl_map[i].dkl_nblk == 0)

#elif defined(_SUNOS_VTOC_16)
			if (label->dkl_vtoc.v_part[i].p_size == 0)

#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

				continue;
			err_print("Partition %d:   ", i);
#if defined(_SUNOS_VTOC_8)
			scaled = bn2mb(label->dkl_map[i].dkl_nblk);

#elif defined(_SUNOS_VTOC_16)

			scaled = bn2mb(label->dkl_vtoc.v_part[i].p_size);
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

			if (scaled > 1024.0) {
				err_print("%6.2fGB  ", scaled/1024.0);
			} else {
				err_print("%6.2fMB  ", scaled);
			}
#if defined(_SUNOS_VTOC_8)
			err_print(" %6d cylinders\n",
			    label->dkl_map[i].dkl_nblk/blks_per_cyl);
#elif defined(_SUNOS_VTOC_16)
			err_print(" %6d cylinders\n",
			    label->dkl_vtoc.v_part[i].p_size/blks_per_cyl);
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

		}
		err_print("\n");
	}

	return (1);
}



/*
 * Find an existing scsi disk definition by this name,
 * if possible.
 */
static struct disk_type *
find_scsi_disk_type(
	char			*disk_name,
	struct dk_label		*label)
{
	struct ctlr_type	*ctlr;
	struct disk_type	*dp;

	ctlr = find_scsi_ctlr_type();
	for (dp = ctlr->ctype_dlist; dp != NULL; dp = dp->dtype_next) {
		if (dp->dtype_asciilabel) {
			if ((strcmp(dp->dtype_asciilabel, disk_name) == 0) &&
			    dp->dtype_pcyl == label->dkl_pcyl &&
			    dp->dtype_ncyl == label->dkl_ncyl &&
			    dp->dtype_acyl == label->dkl_acyl &&
			    dp->dtype_nhead == label->dkl_nhead &&
			    dp->dtype_nsect == label->dkl_nsect) {
				return (dp);
			}
		}
	}

	return ((struct disk_type *)NULL);
}


/*
 * Find an existing scsi disk definition by this name,
 * if possible.
 */
static struct disk_type *
find_scsi_disk_by_name(
	char			*disk_name)
{
	struct ctlr_type	*ctlr;
	struct disk_type	*dp;

	ctlr = find_scsi_ctlr_type();
	for (dp = ctlr->ctype_dlist; dp != NULL; dp = dp->dtype_next) {
		if (dp->dtype_asciilabel) {
			if ((strcmp(dp->dtype_asciilabel, disk_name) == 0)) {
				return (dp);
			}
		}
	}

	return ((struct disk_type *)NULL);
}


/*
 * Return a pointer to the ctlr_type structure for SCSI
 * disks.  This list is built into the program, so there's
 * no chance of not being able to find it, unless someone
 * totally mangles the code.
 */
static struct ctlr_type *
find_scsi_ctlr_type()
{
	struct	mctlr_list	*mlp;

	mlp = controlp;

	while (mlp != NULL) {
		if (mlp->ctlr_type->ctype_ctype == DKC_SCSI_CCS) {
			return (mlp->ctlr_type);
		}
		mlp = mlp->next;
	}

	impossible("no SCSI controller type");

	return ((struct ctlr_type *)NULL);
}



/*
 * Return a pointer to the scsi ctlr_info structure.  This
 * structure is allocated the first time format sees a
 * disk on this controller, so it must be present.
 */
static struct ctlr_info *
find_scsi_ctlr_info(
	struct dk_cinfo		*dkinfo)
{
	struct ctlr_info	*ctlr;

	if (dkinfo->dki_ctype != DKC_SCSI_CCS) {
		return (NULL);
	}

	for (ctlr = ctlr_list; ctlr != NULL; ctlr = ctlr->ctlr_next) {
		if (ctlr->ctlr_addr == dkinfo->dki_addr &&
		    ctlr->ctlr_space == dkinfo->dki_space &&
		    ctlr->ctlr_ctype->ctype_ctype == DKC_SCSI_CCS) {
			return (ctlr);
		}
	}

	impossible("no SCSI controller info");

	return ((struct ctlr_info *)NULL);
}



static struct disk_type *
new_scsi_disk_type(
	int		fd,
	char		*disk_name,
	struct dk_label	*label)
{
	struct disk_type	*dp;
	struct disk_type	*disk;
	struct ctlr_info	*ctlr;
	struct dk_cinfo		dkinfo;
	struct partition_info	*part;
	struct partition_info	*pt;
	struct disk_info	*disk_info;
	int			i;

	/*
	 * Get the disk controller info for this disk
	 */
	if (ioctl(fd, DKIOCINFO, &dkinfo) == -1) {
		if (option_msg && diag_msg) {
			err_print("DKIOCINFO failed\n");
		}
		return (NULL);
	}

	/*
	 * Find the ctlr_info for this disk.
	 */
	ctlr = find_scsi_ctlr_info(&dkinfo);

	/*
	 * Allocate a new disk type for the SCSI controller.
	 */
	disk = (struct disk_type *)zalloc(sizeof (struct disk_type));

	/*
	 * Find the disk_info instance for this disk.
	 */
	disk_info = find_scsi_disk_info(&dkinfo);

	/*
	 * The controller and the disk should match.
	 */
	assert(disk_info->disk_ctlr == ctlr);

	/*
	 * Link the disk into the list of disks
	 */
	dp = ctlr->ctlr_ctype->ctype_dlist;
	if (dp == NULL) {
		ctlr->ctlr_ctype->ctype_dlist = disk;
	} else {
		while (dp->dtype_next != NULL) {
			dp = dp->dtype_next;
		}
		dp->dtype_next = disk;
	}
	disk->dtype_next = NULL;

	/*
	 * Allocate and initialize the disk name.
	 */
	disk->dtype_asciilabel = alloc_string(disk_name);

	/*
	 * Initialize disk geometry info
	 */
	disk->dtype_pcyl = label->dkl_pcyl;
	disk->dtype_ncyl = label->dkl_ncyl;
	disk->dtype_acyl = label->dkl_acyl;
	disk->dtype_nhead = label->dkl_nhead;
	disk->dtype_nsect = label->dkl_nsect;
	disk->dtype_rpm = label->dkl_rpm;

	/*
	 * Attempt to match the partition map in the label
	 * with a know partition for this disk type.
	 */
	for (part = disk->dtype_plist; part; part = part->pinfo_next) {
		if (parts_match(label, part)) {
			break;
		}
	}

	/*
	 * If no match was made, we need to create a partition
	 * map for this disk.
	 */
	if (part == NULL) {
		part = (struct partition_info *)
		    zalloc(sizeof (struct partition_info));
		pt = disk->dtype_plist;
		if (pt == NULL) {
			disk->dtype_plist = part;
		} else {
			while (pt->pinfo_next != NULL) {
				pt = pt->pinfo_next;
			}
			pt->pinfo_next = part;
		}
		part->pinfo_next = NULL;

		/*
		 * Set up the partition name
		 */
		part->pinfo_name = alloc_string("default");

		/*
		 * Fill in the partition info from the label
		 */
		for (i = 0; i < NDKMAP; i++) {

#if defined(_SUNOS_VTOC_8)
			part->pinfo_map[i] = label->dkl_map[i];

#elif defined(_SUNOS_VTOC_16)
			part->pinfo_map[i].dkl_cylno =
			    label->dkl_vtoc.v_part[i].p_start /
			    ((blkaddr32_t)(disk->dtype_nhead *
			    disk->dtype_nsect - apc));
			part->pinfo_map[i].dkl_nblk =
			    label->dkl_vtoc.v_part[i].p_size;
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

		}
	}


	/*
	 * Use the VTOC if valid, or install a default
	 */
	if (label->dkl_vtoc.v_version == V_VERSION) {
		(void) memcpy(disk_info->v_volume, label->dkl_vtoc.v_volume,
		    LEN_DKL_VVOL);
		part->vtoc = label->dkl_vtoc;
	} else {
		(void) memset(disk_info->v_volume, 0, LEN_DKL_VVOL);
		set_vtoc_defaults(part);
	}

	/*
	 * Link the disk to the partition map
	 */
	disk_info->disk_parts = part;

	return (disk);
}


/*
 * Delete a disk type from disk type list.
 */
int
delete_disk_type(
		struct disk_type *disk_type)
{
	struct ctlr_type	*ctlr;
	struct disk_type	*dp, *disk;

	if (cur_ctype->ctype_ctype == DKC_DIRECT)
		ctlr = find_direct_ctlr_type();
	else if (cur_ctype->ctype_ctype == DKC_VBD)
		ctlr = find_vbd_ctlr_type();
	else
		ctlr = find_scsi_ctlr_type();
	if (ctlr == NULL || ctlr->ctype_dlist == NULL) {
		return (-1);
	}

	disk = ctlr->ctype_dlist;
	if (disk == disk_type) {
		ctlr->ctype_dlist = disk->dtype_next;
		if (cur_label == L_TYPE_EFI)
			free(disk->dtype_plist->etoc);
		free(disk->dtype_plist);
		free(disk->vendor);
		free(disk->product);
		free(disk->revision);
		free(disk);
		return (0);
	} else {
		for (dp = disk->dtype_next; dp != NULL;
		    disk = disk->dtype_next, dp = dp->dtype_next) {
			if (dp == disk_type) {
				disk->dtype_next = dp->dtype_next;
				if (cur_label == L_TYPE_EFI)
					free(dp->dtype_plist->etoc);
				free(dp->dtype_plist);
				free(dp->vendor);
				free(dp->product);
				free(dp->revision);
				free(dp);
				return (0);
			}
		}
		return (-1);
	}
}


static struct disk_info *
find_scsi_disk_info(
	struct dk_cinfo		*dkinfo)
{
	struct disk_info	*disk;
	struct dk_cinfo		*dp;

	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		assert(dkinfo->dki_ctype == DKC_SCSI_CCS);
		dp = &disk->disk_dkinfo;
		if (dp->dki_ctype == dkinfo->dki_ctype &&
		    dp->dki_cnum == dkinfo->dki_cnum &&
		    dp->dki_unit == dkinfo->dki_unit &&
		    strcmp(dp->dki_dname, dkinfo->dki_dname) == 0) {
			return (disk);
		}
	}

	impossible("No SCSI disk info instance\n");

	return ((struct disk_info *)NULL);
}


static char *
get_sun_disk_name(
	char			*disk_name,
	struct scsi_inquiry	*inquiry)
{
	/*
	 * Extract the sun name of the disk
	 */
	(void) memset(disk_name, 0, DISK_NAME_MAX);
	(void) memcpy(disk_name, (char *)&inquiry->inq_pid[9], 7);

	return (disk_name);
}


char *
get_generic_disk_name(
	char			*disk_name,
	struct scsi_inquiry	*inquiry)
{
	char	*p;

	(void) memset(disk_name, 0, DISK_NAME_MAX);
	p = strcopy(disk_name, inquiry->inq_vid,
	    sizeof (inquiry->inq_vid));
	*p++ = '-';
	p = strcopy(p, inquiry->inq_pid, sizeof (inquiry->inq_pid));
	*p++ = '-';
	p = strcopy(p, inquiry->inq_revision,
	    sizeof (inquiry->inq_revision));

	return (disk_name);
}

/*
 * Copy a string of characters from src to dst, for at
 * most n bytes.  Strip all leading and trailing spaces,
 * and stop if there are any non-printable characters.
 * Return ptr to the next character to be filled.
 */
static char *
strcopy(
	char	*dst,
	char	*src,
	int	n)
{
	int	i;

	while (*src == ' ' && n > 0) {
		src++;
		n--;
	}

	for (i = 0; n-- > 0 && isascii(*src) && isprint(*src); src++) {
		if (*src == ' ') {
			i++;
		} else {
			while (i-- > 0)
				*dst++ = ' ';
			*dst++ = *src;
		}
	}

	*dst = 0;
	return (dst);
}

/*
 * adjust disk geometry.
 * This is used when disk reports a disk geometry page having
 * no of physical cylinders is < 3 which is the minimum required
 * by Solaris (2 for storing labels and at least one as a data
 * cylinder )
 */
int
adjust_disk_geometry(diskaddr_t capacity, uint_t *cyl, uint_t *nhead,
	uint_t *nsect)
{
	uint_t	lcyl = *cyl;
	uint_t	lnhead = *nhead;
	uint_t	lnsect = *nsect;

	assert(lcyl < SUN_MIN_CYL);

	/*
	 * reduce nsect by 2 for each iteration  and re-calculate
	 * the number of cylinders.
	 */
	while (lnsect > MINIMUM_NO_SECTORS &&
	    lcyl < MINIMUM_NO_CYLINDERS) {
		/*
		 * make sure that we do not go below MINIMUM_NO_SECTORS.
		 */
		lnsect = max(MINIMUM_NO_SECTORS, lnsect / 2);
		lcyl   = (capacity) / (lnhead * lnsect);
	}
	/*
	 * If the geometry still does not satisfy
	 * MINIMUM_NO_CYLINDERS then try to reduce the
	 * no of heads.
	 */
	while (lnhead > MINIMUM_NO_HEADS &&
	    lcyl < MINIMUM_NO_CYLINDERS) {
		lnhead = max(MINIMUM_NO_HEADS, lnhead / 2);
		lcyl =  (capacity) / (lnhead * lnsect);
	}
	/*
	 * now we should have atleast SUN_MIN_CYL cylinders.
	 * If we still do not get SUN_MIN_CYL with MINIMUM_NO_HEADS
	 * and MINIMUM_NO_HEADS then return error.
	 */
	if (lcyl < SUN_MIN_CYL)
		return (1);
	else {
		*cyl = lcyl;
		*nhead = lnhead;
		*nsect = lnsect;
		return (0);
	}
}

#if defined(_SUNOS_VTOC_8)
/*
 * Reduce the size of one dimention below a specified
 * limit with a minimum loss of volume.  Dimenstions are
 * assumed to be passed in form the largest value (the one
 * that needs to be reduced) to the smallest value.  The
 * values will be twiddled until they are all less than or
 * equal to their limit.  Returns the number in the new geometry.
 */
static diskaddr_t
square_box(
		diskaddr_t capacity,
		uint_t *dim1, uint_t lim1,
		uint_t *dim2, uint_t lim2,
		uint_t *dim3, uint_t lim3)
{
	uint_t	i;

	/*
	 * Although the routine should work with any ordering of
	 * parameters, it's most efficient if they are passed in
	 * in decreasing magnitude.
	 */
	assert(*dim1 >= *dim2);
	assert(*dim2 >= *dim3);

	/*
	 * This is done in a very arbitrary manner.  We could try to
	 * find better values but I can't come up with a method that
	 * would run in a reasonable amount of time.  That could take
	 * approximately 65535 * 65535 iterations of a dozen flops each
	 * or well over 4G flops.
	 *
	 * First:
	 *
	 * Let's see how far we can go with bitshifts w/o losing
	 * any blocks.
	 */

	for (i = 0; (((*dim1)>>i)&1) == 0 && ((*dim1)>>i) > lim1; i++)
		;
	if (i) {
		*dim1 = ((*dim1)>>i);
		*dim3 = ((*dim3)<<i);
	}

	if (((*dim1) > lim1) || ((*dim2) > lim2) || ((*dim3) > lim3)) {
		double 	d[4];

		/*
		 * Second:
		 *
		 * Set the highest value at its limit then calculate errors,
		 * adjusting the 2nd highest value (we get better resolution
		 * that way).
		 */
		d[1] = lim1;
		d[3] = *dim3;
		d[2] = (double)capacity/(d[1]*d[3]);

		/*
		 * If we overflowed the middle term, set it to its limit and
		 * chose a new low term.
		 */
		if (d[2] > lim2) {
			d[2] = lim2;
			d[3] = (double)capacity/(d[1]*d[2]);
		}
		/*
		 * Convert to integers.
		 */
		*dim1 = (int)d[1];
		*dim2 = (int)d[2];
		*dim3 = (int)d[3];
	}
	/*
	 * Fixup any other possible problems.
	 * If this happens, we need a new disklabel format.
	 */
	if (*dim1 > lim1) *dim1 = lim1;
	if (*dim2 > lim2) *dim2 = lim2;
	if (*dim3 > lim3) *dim3 = lim3;
	return (*dim1 * *dim2 * *dim3);
}
#endif /* defined(_SUNOS_VTOC_8) */

/*
 * Calculate CHS values based on the capacity data.
 *
 * NOTE: This function is same as cmlb_convert_geomerty() function in
 * cmlb kernel module.
 */
static void
compute_chs_values(diskaddr_t total_capacity, diskaddr_t usable_capacity,
	uint_t *pcylp, uint_t *nheadp, uint_t *nsectp)
{

	/* Unlabeled SCSI floppy device */
	if (total_capacity < 160) {
		/* Less than 80K */
		*nheadp = 1;
		*pcylp = total_capacity;
		*nsectp = 1;
		return;
	} else if (total_capacity <= 0x1000) {
		*nheadp = 2;
		*pcylp = 80;
		*nsectp = total_capacity / (80 * 2);
		return;
	}

	/*
	 * For all devices we calculate cylinders using the heads and sectors
	 * we assign based on capacity of the device.  The algorithm is
	 * designed to be compatible with the way other operating systems
	 * lay out fdisk tables for X86 and to insure that the cylinders never
	 * exceed 65535 to prevent problems with X86 ioctls that report
	 * geometry.
	 * For some smaller disk sizes we report geometry that matches those
	 * used by X86 BIOS usage. For larger disks, we use SPT that are
	 * multiples of 63, since other OSes that are not limited to 16-bits
	 * for cylinders stop at 63 SPT we make do by using multiples of 63 SPT.
	 *
	 * The following table (in order) illustrates some end result
	 * calculations:
	 *
	 * Maximum number of blocks 		nhead	nsect
	 *
	 * 2097152 (1GB)			64	32
	 * 16777216 (8GB)			128	32
	 * 1052819775 (502.02GB)		255  	63
	 * 2105639550 (0.98TB)			255	126
	 * 3158459325 (1.47TB)			255  	189
	 * 4211279100 (1.96TB)			255  	252
	 * 5264098875 (2.45TB)			255  	315
	 * ...
	 */

	if (total_capacity <= 0x200000) {
		*nheadp = 64;
		*nsectp = 32;
	} else if (total_capacity <= 0x01000000) {
		*nheadp = 128;
		*nsectp = 32;
	} else {
		*nheadp = 255;

		/* make nsect be smallest multiple of 63 */
		*nsectp = ((total_capacity +
		    (UINT16_MAX * 255 * 63) - 1) /
		    (UINT16_MAX * 255 * 63)) * 63;

		if (*nsectp == 0)
			*nsectp = (UINT16_MAX / 63) * 63;
	}

	if (usable_capacity < total_capacity)
		*pcylp = usable_capacity / ((*nheadp) * (*nsectp));
	else
		*pcylp = total_capacity / ((*nheadp) * (*nsectp));
}
