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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * This file contains the code relating to label manipulation.
 */

#include <string.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/isa_defs.h>
#include <sys/efi_partition.h>
#include <sys/vtoc.h>
#include <sys/uuid.h>
#include <errno.h>
#include <devid.h>
#include <libdevinfo.h>
#include "global.h"
#include "label.h"
#include "misc.h"
#include "main.h"
#include "partition.h"
#include "ctlr_scsi.h"
#include "checkdev.h"

#if defined(_FIRMWARE_NEEDS_FDISK)
#include <sys/dktp/fdisk.h>
#include "menu_fdisk.h"
#endif		/* defined(_FIRMWARE_NEEDS_FDISK) */

#ifndef	WD_NODE
#define	WD_NODE		7
#endif

#ifdef	__STDC__
/*
 * Prototypes for ANSI C compilers
 */
static int	do_geometry_sanity_check(void);
static int	vtoc_to_label(struct dk_label *label, struct extvtoc *vtoc,
		struct dk_geom *geom, struct dk_cinfo *cinfo);
extern int	read_extvtoc(int, struct extvtoc *);
extern int	write_extvtoc(int, struct extvtoc *);
static int	vtoc64_to_label(struct efi_info *, struct dk_gpt *);

#else	/* __STDC__ */

/*
 * Prototypes for non-ANSI C compilers
 */
static int	do_geometry_sanity_check();
static int	vtoc_to_label();
extern int	read_extvtoc();
extern int	write_extvtoc();
static int	vtoc64_to_label();

#endif	/* __STDC__ */

#ifdef	DEBUG
static void dump_label(struct dk_label *label);
#endif

/*
 * This routine checks the given label to see if it is valid.
 */
int
checklabel(label)
	register struct dk_label *label;
{

	/*
	 * Check the magic number.
	 */
	if (label->dkl_magic != DKL_MAGIC)
		return (0);
	/*
	 * Check the checksum.
	 */
	if (checksum(label, CK_CHECKSUM) != 0)
		return (0);
	return (1);
}

/*
 * This routine checks or calculates the label checksum, depending on
 * the mode it is called in.
 */
int
checksum(label, mode)
	struct	dk_label *label;
	int	mode;
{
	register short *sp, sum = 0;
	register short count = (sizeof (struct dk_label)) / (sizeof (short));

	/*
	 * If we are generating a checksum, don't include the checksum
	 * in the rolling xor.
	 */
	if (mode == CK_MAKESUM)
		count -= 1;
	sp = (short *)label;
	/*
	 * Take the xor of all the half-words in the label.
	 */
	while (count--) {
		sum ^= *sp++;
	}
	/*
	 * If we are checking the checksum, the total will be zero for
	 * a correct checksum, so we can just return the sum.
	 */
	if (mode == CK_CHECKSUM)
		return (sum);
	/*
	 * If we are generating the checksum, fill it in.
	 */
	else {
		label->dkl_cksum = sum;
		return (0);
	}
}

/*
 * This routine is used to extract the id string from the string stored
 * in a disk label.  The problem is that the string in the label has
 * the physical characteristics of the drive appended to it.  The approach
 * is to find the beginning of the physical attributes portion of the string
 * and truncate it there.
 */
int
trim_id(id)
	char	*id;
{
	register char *c;

	/*
	 * Start at the end of the string.  When we match the word ' cyl',
	 * we are at the beginning of the attributes.
	 */
	for (c = id + strlen(id); c >= id; c--) {
		if (strncmp(c, " cyl", strlen(" cyl")) == 0) {
			/*
			 * Remove any white space.
			 */
			for (; (((*(c - 1) == ' ') || (*(c - 1) == '\t')) &&
				(c >= id)); c--);
			break;
		}
	}
	/*
	 * If we ran off the beginning of the string, something is wrong.
	 */
	if (c < id)
		return (-1);
	/*
	 * Truncate the string.
	 */
	*c = '\0';
	return (0);
}

/*
 * This routine is used by write_label() to do a quick sanity check on the
 * supplied geometry. This is not a thorough check.
 *
 * The SCSI READ_CAPACITY command is used here to get the capacity of the
 * disk. But, the available area to store data on a disk is usually less
 * than this. So, if the specified geometry evaluates to a value which falls
 * in this margin, then such illegal geometries can slip through the cracks.
 */
static int
do_geometry_sanity_check()
{
	struct scsi_capacity_16	 capacity;

	if (uscsi_read_capacity(cur_file, &capacity)) {
		err_print("Warning: Unable to get capacity."
		    " Cannot check geometry\n");
		return (0);	/* Just ignore this problem */
	}

	if (capacity.sc_capacity < ncyl * nhead * nsect) {
		err_print("\nWarning: Current geometry overshoots "
		    "actual geometry of disk\n\n");
		if (check("Continue labelling disk") != 0)
			return (-1);
		return (0);	/* Just ignore this problem */
	}

	return (0);
}

/*
 * create a clear EFI partition table when format is used
 * to convert an SMI label to an EFI label
 */
int
SMI_vtoc_to_EFI(int fd, struct dk_gpt **new_vtoc)
{
	int i;
	struct dk_gpt	*efi;

	if (efi_alloc_and_init(fd, EFI_NUMPAR, new_vtoc) != 0) {
		err_print("SMI vtoc to EFI failed\n");
		return (-1);
	}
	efi = *new_vtoc;

	/*
	 * create a clear EFI partition table:
	 * s0 takes the whole disk except the primary EFI lable,
	 * backup EFI labels, and the reserved partition.
	 * s1-s6 are unassigned slices.
	 */
	efi->efi_parts[0].p_tag = V_USR;
	efi->efi_parts[0].p_start = efi->efi_first_u_lba;
	efi->efi_parts[0].p_size = efi->efi_last_u_lba - efi->efi_first_u_lba
	    - EFI_MIN_RESV_SIZE + 1;

	/*
	 * s1-s6 are unassigned slices
	 */
	for (i = 1; i < efi->efi_nparts - 2; i++) {
		efi->efi_parts[i].p_tag = V_UNASSIGNED;
		efi->efi_parts[i].p_start = 0;
		efi->efi_parts[i].p_size = 0;
	}

	/*
	 * the reserved slice
	 */
	efi->efi_parts[efi->efi_nparts - 1].p_tag = V_RESERVED;
	efi->efi_parts[efi->efi_nparts - 1].p_start =
	    efi->efi_last_u_lba - EFI_MIN_RESV_SIZE + 1;
	efi->efi_parts[efi->efi_nparts - 1].p_size = EFI_MIN_RESV_SIZE;

	return (0);
}

/*
 * This routine constructs and writes a label on the disk.  It writes both
 * the primary and backup labels.  It assumes that there is a current
 * partition map already defined.  It also notifies the SunOS kernel of
 * the label and partition information it has written on the disk.
 */
int
write_label()
{
	int	error = 0, head, sec;
	struct dk_label label;
	struct extvtoc	vtoc;
	struct dk_geom	geom;
	struct dk_gpt	*vtoc64;
	int		nbackups;
	char		*new_label;

#if defined(_SUNOS_VTOC_8)
	int i;
#endif		/* defined(_SUNOS_VTOC_8) */

	/*
	 * Check to see if any partitions used for svm, vxvm or live upgrade
	 * are on the disk. If so, refuse to label the disk, but only
	 * if we are trying to shrink a partition in use.
	 */
	if (checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 1)) {
		err_print("Cannot label disk when "
		    "partitions are in use as described.\n");
		return (-1);
	}

	/*
	 * If EFI label, then write it out to disk
	 */
	if (cur_label == L_TYPE_EFI) {
		enter_critical();
		vtoc64 = cur_parts->etoc;
		err_check(vtoc64);
		if (efi_write(cur_file, vtoc64) != 0) {
			err_print("Warning: error writing EFI.\n");
			error = -1;
			}

		cur_disk->disk_flags |= DSK_LABEL;
		exit_critical();
		return (error);
	}

	/*
	 * Fill in a label structure with the geometry information.
	 */
	(void) memset((char *)&label, 0, sizeof (struct dk_label));
	new_label = zalloc(cur_blksz);

	label.dkl_pcyl = pcyl;
	label.dkl_ncyl = ncyl;
	label.dkl_acyl = acyl;

#if defined(_SUNOS_VTOC_16)
	label.dkl_bcyl = bcyl;
#endif			/* defined(_SUNOC_VTOC_16) */

	label.dkl_nhead = nhead;
	label.dkl_nsect = nsect;
	label.dkl_apc = apc;
	label.dkl_intrlv = 1;
	label.dkl_rpm = cur_dtype->dtype_rpm;

#if defined(_SUNOS_VTOC_8)
	/*
	 * Also fill in the current partition information.
	 */
	for (i = 0; i < NDKMAP; i++) {
		label.dkl_map[i] = cur_parts->pinfo_map[i];
	}
#endif			/* defined(_SUNOS_VTOC_8) */

	label.dkl_magic = DKL_MAGIC;

	/*
	 * Fill in the vtoc information
	 */
	label.dkl_vtoc = cur_parts->vtoc;

	/*
	 * Use the current label
	 */
	bcopy(cur_disk->v_volume, label.dkl_vtoc.v_volume, LEN_DKL_VVOL);

	/*
	 * Put asciilabel in; on x86 it's in the vtoc, not the label.
	 */
	(void) snprintf(label.dkl_asciilabel, sizeof (label.dkl_asciilabel),
	    "%s cyl %d alt %d hd %d sec %d",
	    cur_dtype->dtype_asciilabel, ncyl, acyl, nhead, nsect);

#if defined(_SUNOS_VTOC_16)
	/*
	 * Also add in v_sectorsz, as the driver will.
	 */
	label.dkl_vtoc.v_sectorsz = cur_blksz;
#endif			/* defined(_SUNOS_VTOC_16) */

	/*
	 * Generate the correct checksum.
	 */
	(void) checksum(&label, CK_MAKESUM);
	/*
	 * Convert the label into a vtoc
	 */
	if (label_to_vtoc(&vtoc, &label) == -1) {
		free(new_label);
		return (-1);
	}
	/*
	 * Fill in the geometry info.  This is critical that
	 * we do this before writing the vtoc.
	 */
	bzero((caddr_t)&geom, sizeof (struct dk_geom));
	geom.dkg_ncyl = ncyl;
	geom.dkg_acyl = acyl;

#if defined(_SUNOS_VTOC_16)
	geom.dkg_bcyl = bcyl;
#endif			/* defined(_SUNOS_VTOC_16) */

	geom.dkg_nhead = nhead;
	geom.dkg_nsect = nsect;
	geom.dkg_intrlv = 1;
	geom.dkg_apc = apc;
	geom.dkg_rpm = cur_dtype->dtype_rpm;
	geom.dkg_pcyl = pcyl;

	/*
	 * Make a quick check to see that the geometry is being
	 * written now is not way off from the actual capacity
	 * of the disk. This is only an appoximate check and
	 * is only for SCSI disks.
	 */
	if (SCSI && do_geometry_sanity_check() != 0) {
		free(new_label);
		return (-1);
	}

	/*
	 * Lock out interrupts so we do things in sync.
	 */
	enter_critical();
	/*
	 * Do the ioctl to tell the kernel the geometry.
	 */
	if (ioctl(cur_file, DKIOCSGEOM, &geom) == -1) {
		err_print("Warning: error setting drive geometry.\n");
		error = -1;
	}
	/*
	 * Write the vtoc.  At the time of this writing, our
	 * drivers convert the vtoc back to a label, and
	 * then write both the primary and backup labels.
	 * This is not a requirement, however, as we
	 * always use an ioctl to read the vtoc from the
	 * driver, so it can do as it likes.
	 */
	if (write_extvtoc(cur_file, &vtoc) != 0) {
		err_print("Warning: error writing VTOC.\n");
		error = -1;
	}

	/*
	 * Calculate where the backup labels went.  They are always on
	 * the last alternate cylinder, but some older drives put them
	 * on head 2 instead of the last head.  They are always on the
	 * first 5 odd sectors of the appropriate track.
	 */
	if (cur_ctype->ctype_flags & CF_BLABEL)
		head  = 2;
	else
		head = nhead - 1;
	/*
	 * Read and verify the backup labels.
	 */
	nbackups = 0;
	for (sec = 1; ((sec < BAD_LISTCNT * 2 + 1) && (sec < nsect));
	    sec += 2) {
		if ((*cur_ops->op_rdwr)(DIR_READ, cur_file, (diskaddr_t)
		    ((chs2bn(ncyl + acyl - 1, head, sec))
		    + solaris_offset), 1, new_label, F_NORMAL, NULL)) {
			err_print("Warning: error reading"
			    "backup label.\n");
			error = -1;
		} else {
			if (bcmp((char *)&label, new_label,
			    sizeof (struct dk_label)) == 0) {
				nbackups++;
			}
		}
	}
	if (nbackups != BAD_LISTCNT) {
		err_print("Warning: %s\n", nbackups == 0 ?
		    "no backup labels" : "some backup labels incorrect");
	}
	/*
	 * Mark the current disk as labelled and notify the kernel of what
	 * has happened.
	 */
	cur_disk->disk_flags |= DSK_LABEL;

	exit_critical();
	free(new_label);
	return (error);
}


/*
 * Read the label from the disk.
 * Do this via the read_extvtoc() library routine, then convert it to a label.
 * We also need a DKIOCGGEOM ioctl to get the disk's geometry.
 */
int
read_label(int fd, struct dk_label *label)
{
	struct extvtoc	vtoc;
	struct dk_geom	geom;
	struct dk_cinfo	dkinfo;

	if (read_extvtoc(fd, &vtoc) < 0		||
	    ioctl(fd, DKIOCGGEOM, &geom) == -1	||
	    ioctl(fd, DKIOCINFO, &dkinfo) == -1) {
		return (-1);
	}

	return (vtoc_to_label(label, &vtoc, &geom, &dkinfo));
}

int
get_disk_inquiry_prop(char *devpath, char **vid, char **pid, char **rid)
{
	char *v, *p, *r;
	di_node_t node;
	int ret = -1;

	node = di_init(devpath, DINFOCPYALL);

	if (node == DI_NODE_NIL)
		goto out;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-vendor-id", &v) != 1)
		goto out;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-product-id", &p) != 1)
		goto out;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "inquiry-revision-id", &r) != 1)
		goto out;

	*vid = strdup(v);
	*pid = strdup(p);
	*rid = strdup(r);

	if (*vid == NULL || *pid == NULL || *rid == NULL) {
		free(*vid);
		free(*pid);
		free(*rid);
		goto out;
	}

	ret = 0;

out:
	di_fini(node);
	return (ret);
}

int
get_disk_inquiry_uscsi(int fd, char **vid, char **pid, char **rid)
{
	struct scsi_inquiry inquiry;

	if (uscsi_inquiry(fd, (char *)&inquiry, sizeof (inquiry)))
		return (-1);

	*vid = strndup(inquiry.inq_vid, 8);
	*pid = strndup(inquiry.inq_pid, 16);
	*rid = strndup(inquiry.inq_revision, 4);

	if (*vid == NULL || *pid == NULL || *rid == NULL) {
		free(*vid);
		free(*pid);
		free(*rid);
		return (-1);
	}

	return (0);
}

int
get_disk_capacity(int fd, uint64_t *capacity)
{
	struct dk_minfo	minf;
	struct scsi_capacity_16	cap16;

	if (ioctl(fd, DKIOCGMEDIAINFO, &minf) == 0) {
		*capacity = minf.dki_capacity * minf.dki_lbsize / cur_blksz;
		return (0);
	}

	if (uscsi_read_capacity(fd, &cap16) == 0) {
		*capacity = cap16.sc_capacity;

		/* Since we are counting from zero, add 1 to capacity */
		(*capacity)++;

		return (0);
	}

	err_print("Fetch Capacity failed\n");
	return (-1);
}

int
get_disk_inquiry_devid(int fd, char **vid, char **pid, char **rid)
{
	ddi_devid_t	devid;
	char		*s;
	char		*v, *p;
	struct dk_cinfo	dkinfo;

	if (devid_get(fd, &devid)) {
		if (option_msg && diag_msg)
			err_print("devid_get failed\n");
		return (-1);
	}

	s = (char *)devid;

	if (ioctl(fd, DKIOCINFO, &dkinfo) == -1) {
		if (option_msg && diag_msg)
			err_print("DKIOCINFO failed\n");
		return (-1);
	}

	if (dkinfo.dki_ctype != DKC_DIRECT)
		return (-1);

	v = s+12;
	if (!(p = strchr(v, '=')))
		return (-1);
	p += 1;

	*vid = strdup(v);
	*pid = strdup(p);
	*rid = strdup("0001");
	devid_free(devid);

	if (*vid == NULL || *pid == NULL || *rid == NULL) {
		free(*vid);
		free(*pid);
		free(*rid);
		return (-1);
	}

	return (0);
}

/*
 * Issue uscsi_inquiry and read_capacity commands to
 * retrieve the disk's Vendor, Product, Revision and
 * Capacity information.
 */
int
get_disk_info(int fd, struct efi_info *label, struct disk_info *disk_info)
{
	(void) get_disk_capacity(fd, &label->capacity);

	if (get_disk_inquiry_prop(disk_info->devfs_name,
	    &label->vendor, &label->product, &label->revision) != 0) {
		if (get_disk_inquiry_devid(fd, &label->vendor, &label->product,
		    &label->revision) != 0) {
			if (get_disk_inquiry_uscsi(fd, &label->vendor,
			    &label->product, &label->revision) != 0) {
				label->vendor = strdup("Unknown");
				label->product = strdup("Unknown");
				label->revision = strdup("0001");
				if (label->vendor == NULL ||
				    label->product == NULL ||
				    label->revision == NULL) {
					free(label->vendor);
					free(label->product);
					free(label->revision);
					return (-1);
				}
			}
		}
	}

	return (0);
}

int
read_efi_label(int fd, struct efi_info *label, struct disk_info *disk_info)
{
	struct dk_gpt	*vtoc64;

	/* This could fail if there is no label already */
	if (efi_alloc_and_read(fd, &vtoc64) < 0) {
		return (-1);
	}
	if (vtoc64_to_label(label, vtoc64) != 0) {
		err_print("vtoc64_to_label failed\n");
		return (-1);
	}
	efi_free(vtoc64);
	if (get_disk_info(fd, label, disk_info) != 0) {
		return (-1);
	}
	return (0);
}


/*
 * We've read a 64-bit label which has no geometry information.  Use
 * some heuristics to fake up a geometry that would match the disk in
 * order to make the rest of format(1M) happy.
 */
static int
vtoc64_to_label(struct efi_info *label, struct dk_gpt *vtoc)
{
	int		i, nparts = 0;
	struct dk_gpt	*lmap;

	(void) memset((char *)label, 0, sizeof (struct efi_info));

	/* XXX do a sanity check here for nparts */
	nparts = vtoc->efi_nparts;
	lmap = (struct dk_gpt *) calloc(1, (sizeof (struct dk_part) *
	    nparts) + sizeof (struct dk_gpt));
	if (lmap == NULL) {
		err_print("vtoc64_to_label: unable to allocate lmap\n");
		fullabort();
	}
	label->e_parts = lmap;

	/*
	 * Copy necessary portions
	 * XXX Maybe we can use memcpy() ??
	 */
	lmap->efi_version = vtoc->efi_version;
	lmap->efi_nparts = vtoc->efi_nparts;
	lmap->efi_part_size = vtoc->efi_part_size;
	lmap->efi_lbasize = vtoc->efi_lbasize;
	lmap->efi_last_lba = vtoc->efi_last_lba;
	lmap->efi_first_u_lba = vtoc->efi_first_u_lba;
	lmap->efi_last_u_lba = vtoc->efi_last_u_lba;
	lmap->efi_altern_lba = vtoc->efi_altern_lba;
	lmap->efi_flags = vtoc->efi_flags;
	(void) memcpy((uchar_t *)&lmap->efi_disk_uguid,
	    (uchar_t *)&vtoc->efi_disk_uguid, sizeof (struct uuid));

	for (i = 0; i < nparts; i++) {
		lmap->efi_parts[i].p_tag = vtoc->efi_parts[i].p_tag;
		lmap->efi_parts[i].p_flag = vtoc->efi_parts[i].p_flag;
		lmap->efi_parts[i].p_start = vtoc->efi_parts[i].p_start;
		lmap->efi_parts[i].p_size = vtoc->efi_parts[i].p_size;
		(void) memcpy((uchar_t *)&lmap->efi_parts[i].p_uguid,
		    (uchar_t *)&vtoc->efi_parts[i].p_uguid,
		    sizeof (struct uuid));
		if (vtoc->efi_parts[i].p_tag == V_RESERVED) {
			bcopy(vtoc->efi_parts[i].p_name,
			    lmap->efi_parts[i].p_name, LEN_DKL_VVOL);
		}
	}
	return (0);
}

/*
 * Convert vtoc/geom to label.
 */
static int
vtoc_to_label(struct dk_label *label, struct extvtoc *vtoc,
    struct dk_geom *geom, struct dk_cinfo *cinfo)
{
#if defined(_SUNOS_VTOC_8)
	struct dk_map32		*lmap;
#elif defined(_SUNOS_VTOC_16)
	struct dkl_partition	*lmap;
#else
#error No VTOC format defined.
#endif			/* defined(_SUNOS_VTOC_8) */

	struct extpartition	*vpart;
	ulong_t			nblks;
	int			i;

	(void) memset((char *)label, 0, sizeof (struct dk_label));

	/*
	 * Sanity-check the vtoc
	 */
	if (vtoc->v_sanity != VTOC_SANE ||
	    vtoc->v_nparts != V_NUMPAR) {
		return (-1);
	}

	/*
	 * Sanity check of geometry
	 */
	if (geom->dkg_ncyl == 0 || geom->dkg_nhead == 0 ||
	    geom->dkg_nsect == 0) {
		return (-1);
	}

	label->dkl_magic = DKL_MAGIC;

	/*
	 * Copy necessary portions of the geometry information
	 */
	label->dkl_rpm = geom->dkg_rpm;
	label->dkl_pcyl = geom->dkg_pcyl;
	label->dkl_apc = geom->dkg_apc;
	label->dkl_intrlv = geom->dkg_intrlv;
	label->dkl_ncyl = geom->dkg_ncyl;
	label->dkl_acyl = geom->dkg_acyl;

#if defined(_SUNOS_VTOC_16)
	label->dkl_bcyl = geom->dkg_bcyl;
#endif			/* defined(_SUNOS_VTOC_16) */

	label->dkl_nhead = geom->dkg_nhead;
	label->dkl_nsect = geom->dkg_nsect;

#if defined(_SUNOS_VTOC_8)
	label->dkl_obs1 = geom->dkg_obs1;
	label->dkl_obs2 = geom->dkg_obs2;
	label->dkl_obs3 = geom->dkg_obs3;
#endif			/* defined(_SUNOS_VTOC_8) */

	label->dkl_write_reinstruct = geom->dkg_write_reinstruct;
	label->dkl_read_reinstruct = geom->dkg_read_reinstruct;

	/*
	 * Copy vtoc structure fields into the disk label dk_vtoc
	 */
	label->dkl_vtoc.v_sanity = vtoc->v_sanity;
	label->dkl_vtoc.v_nparts = vtoc->v_nparts;
	label->dkl_vtoc.v_version = vtoc->v_version;

	(void) memcpy(label->dkl_vtoc.v_volume, vtoc->v_volume,
	    LEN_DKL_VVOL);
	for (i = 0; i < V_NUMPAR; i++) {
		label->dkl_vtoc.v_part[i].p_tag = vtoc->v_part[i].p_tag;
		label->dkl_vtoc.v_part[i].p_flag = vtoc->v_part[i].p_flag;
		label->dkl_vtoc.v_timestamp[i] = vtoc->timestamp[i];
	}

	for (i = 0; i < 10; i++)
		label->dkl_vtoc.v_reserved[i] = vtoc->v_reserved[i];

	label->dkl_vtoc.v_bootinfo[0] = vtoc->v_bootinfo[0];
	label->dkl_vtoc.v_bootinfo[1] = vtoc->v_bootinfo[1];
	label->dkl_vtoc.v_bootinfo[2] = vtoc->v_bootinfo[2];

	(void) memcpy(label->dkl_asciilabel, vtoc->v_asciilabel,
	    LEN_DKL_ASCII);

	/*
	 * Note the conversion from starting sector number
	 * to starting cylinder number.
	 * Return error if division results in a remainder.
	 *
	 * Note: don't check, if probing virtual disk in Xen
	 * for that virtual disk will use fabricated # of headers
	 * and sectors per track which may cause the capacity
	 * not multiple of # of blocks per cylinder
	 */
#if defined(_SUNOS_VTOC_8)
	lmap = label->dkl_map;

#elif defined(_SUNOS_VTOC_16)
	lmap = label->dkl_vtoc.v_part;
#else
#error No VTOC format defined.
#endif			/* defined(_SUNOS_VTOC_8) */

	vpart = vtoc->v_part;

	nblks = label->dkl_nsect * label->dkl_nhead;

	for (i = 0; i < NDKMAP; i++, lmap++, vpart++) {
		if (cinfo->dki_ctype != DKC_VBD) {
			if ((vpart->p_start % nblks) != 0 ||
			    (vpart->p_size % nblks) != 0) {
				return (-1);
			}
		}
#if defined(_SUNOS_VTOC_8)
		lmap->dkl_cylno = (blkaddr32_t)(vpart->p_start / nblks);
		lmap->dkl_nblk = (blkaddr32_t)vpart->p_size;

#elif defined(_SUNOS_VTOC_16)
		lmap->p_start = (blkaddr32_t)vpart->p_start;
		lmap->p_size = (blkaddr32_t)vpart->p_size;
#else
#error No VTOC format defined.
#endif			/* defined(_SUNOS_VTOC_8) */
	}

	/*
	 * Finally, make a checksum
	 */
	(void) checksum(label, CK_MAKESUM);

#ifdef DEBUG
	if (option_msg && diag_msg)
		dump_label(label);
#endif
	return (0);
}



/*
 * Extract a vtoc structure out of a valid label
 */
int
label_to_vtoc(struct extvtoc *vtoc, struct dk_label *label)
{
#if defined(_SUNOS_VTOC_8)
	struct dk_map2		*lpart;
	struct dk_map32		*lmap;
	ulong_t			nblks;

#elif defined(_SUNOS_VTOC_16)
	struct dkl_partition	*lpart;
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

	struct extpartition	*vpart;
	int			i;

	(void) memset((char *)vtoc, 0, sizeof (struct extvtoc));

	switch (label->dkl_vtoc.v_version) {
	case 0:
		/*
		 * No valid vtoc information in the label.
		 * Construct default p_flags and p_tags.
		 */
		vpart = vtoc->v_part;
		for (i = 0; i < V_NUMPAR; i++, vpart++) {
			vpart->p_tag = default_vtoc_map[i].p_tag;
			vpart->p_flag = default_vtoc_map[i].p_flag;
		}
		break;

	case V_VERSION:
		vpart = vtoc->v_part;
		lpart = label->dkl_vtoc.v_part;
		for (i = 0; i < V_NUMPAR; i++, vpart++, lpart++) {
			vpart->p_tag = lpart->p_tag;
			vpart->p_flag = lpart->p_flag;

#if defined(_SUNOS_VTOC_16)
			vpart->p_start = (diskaddr_t)lpart->p_start;
			vpart->p_size = (diskaddr_t)lpart->p_size;
#endif	/* defined(_SUNOS_VTOC_16) */
			vtoc->timestamp[i] = label->dkl_vtoc.v_timestamp[i];
		}
		(void) memcpy(vtoc->v_volume, label->dkl_vtoc.v_volume,
		    LEN_DKL_VVOL);

		for (i = 0; i < 10; i++)
			vtoc->v_reserved[i] = label->dkl_vtoc.v_reserved[i];

		vtoc->v_bootinfo[0] = label->dkl_vtoc.v_bootinfo[0];
		vtoc->v_bootinfo[1] = label->dkl_vtoc.v_bootinfo[1];
		vtoc->v_bootinfo[2] = label->dkl_vtoc.v_bootinfo[2];
		break;

	default:
		return (-1);
	}

	/*
	 * XXX - this looks wrong to me....
	 * why are these values hardwired, rather than returned from
	 * the real disk label?
	 */
	vtoc->v_sanity = VTOC_SANE;
	vtoc->v_version = V_VERSION;
	vtoc->v_sectorsz = cur_blksz;
	vtoc->v_nparts = V_NUMPAR;

	(void) memcpy(vtoc->v_asciilabel, label->dkl_asciilabel,
	    LEN_DKL_ASCII);

#if defined(_SUNOS_VTOC_8)
	/*
	 * Convert partitioning information.
	 * Note the conversion from starting cylinder number
	 * to starting sector number.
	 */
	lmap = label->dkl_map;
	vpart = vtoc->v_part;
	nblks = label->dkl_nsect * label->dkl_nhead;
	for (i = 0; i < V_NUMPAR; i++, vpart++, lmap++) {
		vpart->p_start = (diskaddr_t)(lmap->dkl_cylno * nblks);
		vpart->p_size = (diskaddr_t)lmap->dkl_nblk;
	}
#endif			/* defined(_SUNOS_VTOC_8) */

	return (0);
}

/*
 * Input: File descriptor
 * Output: 1 if disk has an EFI label, 0 otherwise.
 */

int
is_efi_type(int fd)
{
	struct extvtoc vtoc;

	if (read_extvtoc(fd, &vtoc) == VT_ENOTSUP) {
		/* assume the disk has EFI label */
		return (1);
	}
	return (0);
}

/* make sure the user specified something reasonable */
void
err_check(struct dk_gpt *vtoc)
{
	int			resv_part = -1;
	int			i, j;
	diskaddr_t		istart, jstart, isize, jsize, endsect;
	int			overlap = 0;

	/*
	 * make sure no partitions overlap
	 */
	for (i = 0; i < vtoc->efi_nparts; i++) {
		/* It can't be unassigned and have an actual size */
		if ((vtoc->efi_parts[i].p_tag == V_UNASSIGNED) &&
		    (vtoc->efi_parts[i].p_size != 0)) {
			(void) fprintf(stderr,
"partition %d is \"unassigned\" but has a size of %llu\n", i,
			    vtoc->efi_parts[i].p_size);
		}
		if (vtoc->efi_parts[i].p_tag == V_UNASSIGNED) {
			continue;
		}
		if (vtoc->efi_parts[i].p_tag == V_RESERVED) {
			if (resv_part != -1) {
				(void) fprintf(stderr,
"found duplicate reserved partition at %d\n", i);
			}
			resv_part = i;
			if (vtoc->efi_parts[i].p_size != EFI_MIN_RESV_SIZE)
				(void) fprintf(stderr,
"Warning: reserved partition size must be %d sectors\n",
				    EFI_MIN_RESV_SIZE);
		}
		if ((vtoc->efi_parts[i].p_start < vtoc->efi_first_u_lba) ||
		    (vtoc->efi_parts[i].p_start > vtoc->efi_last_u_lba)) {
			(void) fprintf(stderr,
			    "Partition %d starts at %llu\n",
			    i,
			    vtoc->efi_parts[i].p_start);
			(void) fprintf(stderr,
			    "It must be between %llu and %llu.\n",
			    vtoc->efi_first_u_lba,
			    vtoc->efi_last_u_lba);
		}
		if ((vtoc->efi_parts[i].p_start +
		    vtoc->efi_parts[i].p_size <
		    vtoc->efi_first_u_lba) ||
		    (vtoc->efi_parts[i].p_start +
		    vtoc->efi_parts[i].p_size >
		    vtoc->efi_last_u_lba + 1)) {
			(void) fprintf(stderr,
			    "Partition %d ends at %llu\n",
			    i,
			    vtoc->efi_parts[i].p_start +
			    vtoc->efi_parts[i].p_size);
			(void) fprintf(stderr,
			    "It must be between %llu and %llu.\n",
			    vtoc->efi_first_u_lba,
			    vtoc->efi_last_u_lba);
		}

		for (j = 0; j < vtoc->efi_nparts; j++) {
			isize = vtoc->efi_parts[i].p_size;
			jsize = vtoc->efi_parts[j].p_size;
			istart = vtoc->efi_parts[i].p_start;
			jstart = vtoc->efi_parts[j].p_start;
			if ((i != j) && (isize != 0) && (jsize != 0)) {
				endsect = jstart + jsize -1;
				if ((jstart <= istart) &&
				    (istart <= endsect)) {
					if (!overlap) {
					(void) fprintf(stderr,
"label error: EFI Labels do not support overlapping partitions\n");
					}
					(void) fprintf(stderr,
"Partition %d overlaps partition %d.\n", i, j);
					overlap = 1;
				}
			}
		}
	}
	/* make sure there is a reserved partition */
	if (resv_part == -1) {
		(void) fprintf(stderr,
		    "no reserved partition found\n");
	}
}

#ifdef	DEBUG
static void
dump_label(label)
	struct dk_label	*label;
{
	int		i;

	fmt_print("%s\n", label->dkl_asciilabel);

	fmt_print("version:  %d\n", label->dkl_vtoc.v_version);
	fmt_print("volume:   ");
	for (i = 0; i < LEN_DKL_VVOL; i++) {
		if (label->dkl_vtoc.v_volume[i] == 0)
			break;
		fmt_print("%c", label->dkl_vtoc.v_volume[i]);
	}
	fmt_print("\n");
	fmt_print("v_nparts: %d\n", label->dkl_vtoc.v_nparts);
	fmt_print("v_sanity: %lx\n", label->dkl_vtoc.v_sanity);

#if defined(_SUNOS_VTOC_8)
	fmt_print("rpm:      %d\n", label->dkl_rpm);
	fmt_print("pcyl:     %d\n", label->dkl_pcyl);
	fmt_print("apc:      %d\n", label->dkl_apc);
	fmt_print("obs1:     %d\n", label->dkl_obs1);
	fmt_print("obs2:     %d\n", label->dkl_obs2);
	fmt_print("intrlv:   %d\n", label->dkl_intrlv);
	fmt_print("ncyl:     %d\n", label->dkl_ncyl);
	fmt_print("acyl:     %d\n", label->dkl_acyl);
	fmt_print("nhead:    %d\n", label->dkl_nhead);
	fmt_print("nsect:    %d\n", label->dkl_nsect);
	fmt_print("obs3:     %d\n", label->dkl_obs3);
	fmt_print("obs4:     %d\n", label->dkl_obs4);

#elif defined(_SUNOS_VTOC_16)
	fmt_print("rpm:      %d\n", label->dkl_rpm);
	fmt_print("pcyl:     %d\n", label->dkl_pcyl);
	fmt_print("apc:      %d\n", label->dkl_apc);
	fmt_print("intrlv:   %d\n", label->dkl_intrlv);
	fmt_print("ncyl:     %d\n", label->dkl_ncyl);
	fmt_print("acyl:     %d\n", label->dkl_acyl);
	fmt_print("nhead:    %d\n", label->dkl_nhead);
	fmt_print("nsect:    %d\n", label->dkl_nsect);
	fmt_print("bcyl:     %d\n", label->dkl_bcyl);
	fmt_print("skew:     %d\n", label->dkl_skew);
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */
	fmt_print("magic:    %0x\n", label->dkl_magic);
	fmt_print("cksum:    %0x\n", label->dkl_cksum);

	for (i = 0; i < NDKMAP; i++) {

#if defined(_SUNOS_VTOC_8)
		fmt_print("%c:        cyl=%d, blocks=%d", i+'a',
			label->dkl_map[i].dkl_cylno,
			label->dkl_map[i].dkl_nblk);

#elif defined(_SUNOS_VTOC_16)
		fmt_print("%c:        start=%u, blocks=%u", i+'a',
		    label->dkl_vtoc.v_part[i].p_start,
		    label->dkl_vtoc.v_part[i].p_size);
#else
#error No VTOC format defined.
#endif				/* defined(_SUNOS_VTOC_8) */

		fmt_print(",  tag=%d,  flag=%d",
			label->dkl_vtoc.v_part[i].p_tag,
			label->dkl_vtoc.v_part[i].p_flag);
		fmt_print("\n");
	}

	fmt_print("read_reinstruct:  %d\n", label->dkl_read_reinstruct);
	fmt_print("write_reinstruct: %d\n", label->dkl_write_reinstruct);

	fmt_print("bootinfo: ");
	for (i = 0; i < 3; i++) {
		fmt_print("0x%x ", label->dkl_vtoc.v_bootinfo[i]);
	}
	fmt_print("\n");

	fmt_print("reserved: ");
	for (i = 0; i < 10; i++) {
		if ((i % 4) == 3)
			fmt_print("\n");
		fmt_print("0x%x ", label->dkl_vtoc.v_reserved[i]);
	}
	fmt_print("\n");

	fmt_print("timestamp:\n");
	for (i = 0; i < NDKMAP; i++) {
		if ((i % 4) == 3)
			fmt_print("\n");
		fmt_print("0x%x ", label->dkl_vtoc.v_timestamp[i]);
	}
	fmt_print("\n");

	fmt_print("pad:\n");
	dump("", label->dkl_pad, LEN_DKL_PAD, HEX_ONLY);

	fmt_print("\n\n");
}
#endif	/* DEBUG */
