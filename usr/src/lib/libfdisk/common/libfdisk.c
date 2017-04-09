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
 * Copyright 2017 The MathWorks, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/efi_partition.h>
#include <sys/byteorder.h>

#include <sys/vtoc.h>
#include <sys/tty.h>
#include <sys/dktp/fdisk.h>
#include <sys/dkio.h>
#include <sys/mnttab.h>
#include "libfdisk.h"

#define	DEFAULT_PATH_PREFIX	"/dev/rdsk/"

static void fdisk_free_ld_nodes(ext_part_t *epp);
static void fdisk_ext_place_in_sorted_list(ext_part_t *epp,
    logical_drive_t *newld);
static void fdisk_ext_remove_from_sorted_list(ext_part_t *epp,
    logical_drive_t *delld);
static int fdisk_ext_overlapping_parts(ext_part_t *epp, uint32_t begsec,
    uint32_t endsec);
static int fdisk_read_extpart(ext_part_t *epp);
static void fdisk_set_CHS_values(ext_part_t *epp, struct ipart *part);
static int fdisk_init_master_part_table(ext_part_t *epp);
static struct ipart *fdisk_alloc_part_table();
static int fdisk_read_master_part_table(ext_part_t *epp);

static int
fdisk_init_disk_geom(ext_part_t *epp)
{
	struct dk_geom disk_geom;
	struct dk_minfo disk_info;
	int no_virtgeom_ioctl = 0, no_physgeom_ioctl = 0;

	/* Get disk's HBA (virtual) geometry */
	errno = 0;
	if (ioctl(epp->dev_fd, DKIOCG_VIRTGEOM, &disk_geom)) {
		if (errno == ENOTTY) {
			no_virtgeom_ioctl = 1;
		} else if (errno == EINVAL) {
			/*
			 * This means that the ioctl exists, but
			 * is invalid for this disk, meaning the
			 * disk doesn't have an HBA geometry
			 * (like, say, it's larger than 8GB).
			 */
			epp->disk_geom.virt_cyl = epp->disk_geom.virt_heads =
			    epp->disk_geom.virt_sec = 0;
		} else {
			return (FDISK_ENOVGEOM);
		}
	} else {
		/* save virtual geometry values obtained by ioctl */
		epp->disk_geom.virt_cyl = disk_geom.dkg_ncyl;
		epp->disk_geom.virt_heads = disk_geom.dkg_nhead;
		epp->disk_geom.virt_sec = disk_geom.dkg_nsect;
	}

	errno = 0;
	if (ioctl(epp->dev_fd, DKIOCG_PHYGEOM, &disk_geom)) {
		if (errno == ENOTTY) {
			no_physgeom_ioctl = 1;
		} else {
			return (FDISK_ENOPGEOM);
		}
	}
	/*
	 * Call DKIOCGGEOM if the ioctls for physical and virtual
	 * geometry fail. Get both from this generic call.
	 */
	if (no_virtgeom_ioctl && no_physgeom_ioctl) {
		errno = 0;
		if (ioctl(epp->dev_fd, DKIOCGGEOM, &disk_geom)) {
			return (FDISK_ENOLGEOM);
		}
	}

	epp->disk_geom.phys_cyl = disk_geom.dkg_ncyl;
	epp->disk_geom.phys_heads = disk_geom.dkg_nhead;
	epp->disk_geom.phys_sec = disk_geom.dkg_nsect;
	epp->disk_geom.alt_cyl = disk_geom.dkg_acyl;

	/*
	 * If DKIOCGMEDIAINFO ioctl succeeds, set the dki_lbsize as the
	 * size of the sector, else default to 512
	 */
	if (ioctl(epp->dev_fd, DKIOCGMEDIAINFO, (caddr_t)&disk_info) < 0) {
		/* ioctl failed, falling back to default value of 512 bytes */
		epp->disk_geom.sectsize = 512;
	} else {
		epp->disk_geom.sectsize = ((disk_info.dki_lbsize) ?
		    disk_info.dki_lbsize : 512);
	}

	/*
	 * if hba geometry was not set by DKIOC_VIRTGEOM
	 * or we got an invalid hba geometry
	 * then set hba geometry based on max values
	 */
	if (no_virtgeom_ioctl || disk_geom.dkg_ncyl == 0 ||
	    disk_geom.dkg_nhead == 0 || disk_geom.dkg_nsect == 0 ||
	    disk_geom.dkg_ncyl > MAX_CYL || disk_geom.dkg_nhead > MAX_HEAD ||
	    disk_geom.dkg_nsect > MAX_SECT) {
		epp->disk_geom.virt_sec	= MAX_SECT;
		epp->disk_geom.virt_heads	= MAX_HEAD + 1;
		epp->disk_geom.virt_cyl	= (epp->disk_geom.phys_cyl *
		    epp->disk_geom.phys_heads * epp->disk_geom.phys_sec) /
		    (epp->disk_geom.virt_sec * epp->disk_geom.virt_heads);
	}
	return (FDISK_SUCCESS);
}

/*
 * Initialise important members of the ext_part_t structure and
 * other data structures vital to functionality of libfdisk
 */
int
libfdisk_init(ext_part_t **epp, char *devstr, struct ipart *parttab, int opflag)
{
	ext_part_t *temp;
	struct stat sbuf;
	int rval = FDISK_SUCCESS;
	int found_bad_magic = 0;

	if ((temp = calloc(1, sizeof (ext_part_t))) == NULL) {
		*epp = NULL;
		return (ENOMEM);
	}

	(void) strncpy(temp->device_name, devstr,
	    sizeof (temp->device_name));

	/* Try to stat the node as provided */
	if (stat(temp->device_name, &sbuf) != 0) {

		/* Prefix /dev/rdsk/ and stat again */
		(void) snprintf(temp->device_name, sizeof (temp->device_name),
		    "%s%s", DEFAULT_PATH_PREFIX, devstr);

		if (stat(temp->device_name, &sbuf) != 0) {

			/*
			 * In case of an EFI labeled disk, the device name
			 * could be cN[tN]dN. There is no pN. So we add "p0"
			 * at the end if we do not find it and stat again.
			 */
			if (strrchr(temp->device_name, 'p') == NULL) {
				(void) strcat(temp->device_name, "p0");
			}

			if (stat(temp->device_name, &sbuf) != 0) {

				/* Failed all options, give up */
				rval = EINVAL;
				goto fail;
			}
		}
	}

	/* Make sure the device is a raw device */
	if ((sbuf.st_mode & S_IFMT) != S_IFCHR) {
		rval = EINVAL;
		goto fail;
	}

	temp->ld_head = NULL;
	temp->sorted_ld_head = NULL;

	if ((temp->dev_fd = open(temp->device_name, O_RDWR, 0666)) < 0) {
		rval = EINVAL;
		goto fail;
	}

	if ((temp->mtable = parttab) == NULL) {
		if ((rval = fdisk_init_master_part_table(temp)) !=
		    FDISK_SUCCESS) {
			/*
			 * When we have no fdisk magic 0xAA55 on the disk,
			 * we return FDISK_EBADMAGIC after successfully
			 * obtaining the disk geometry.
			 */
			if (rval != FDISK_EBADMAGIC)
				goto fail;
			else
				found_bad_magic = 1;
		}
	}

	temp->op_flag = opflag;

	if ((rval = fdisk_init_disk_geom(temp)) != FDISK_SUCCESS) {
		goto fail;
	}

	*epp = temp;

	if (found_bad_magic != 0) {
		return (FDISK_EBADMAGIC);
	}

	if (opflag & FDISK_READ_DISK) {
		rval = fdisk_read_extpart(*epp);
	}
	return (rval);

fail:
	*epp = NULL;
	free(temp);
	return (rval);
}

int
libfdisk_reset(ext_part_t *epp)
{
	int rval = FDISK_SUCCESS;

	fdisk_free_ld_nodes(epp);
	epp->first_ebr_is_null = 1;
	epp->corrupt_logical_drives = 0;
	epp->logical_drive_count = 0;
	epp->invalid_bb_sig[0] = 0;
	if (epp->op_flag & FDISK_READ_DISK) {
		rval = fdisk_read_extpart(epp);
	}
	return (rval);
}

void
libfdisk_fini(ext_part_t **epp)
{
	if (*epp == NULL)
		return;

	fdisk_free_ld_nodes(*epp);
	(void) close((*epp)->dev_fd);
	free(*epp);
	*epp = NULL;
}

int
fdisk_is_linux_swap(ext_part_t *epp, uint32_t part_start, uint64_t *lsm_offset)
{
	int		i;
	int		rval = -1;
	off_t		seek_offset;
	uint32_t	linux_pg_size;
	char		*buf, *linux_swap_magic;
	int		sec_sz = fdisk_get_disk_geom(epp, PHYSGEOM, SSIZE);
	off_t		label_offset;

	/*
	 * Known linux kernel page sizes
	 * The linux swap magic is found as the last 10 bytes of a disk chunk
	 * at the beginning of the linux swap partition whose size is that of
	 * kernel page size.
	 */
	uint32_t	linux_pg_size_arr[] = {4096, };

	if ((buf = calloc(1, sec_sz)) == NULL) {
		return (ENOMEM);
	}

	/*
	 * Check if there is a sane Solaris VTOC
	 * If there is a valid vtoc, no need to lookup
	 * for the linux swap signature.
	 */
	label_offset = (part_start + DK_LABEL_LOC) * sec_sz;
	if (lseek(epp->dev_fd, label_offset, SEEK_SET) < 0) {
		rval = EIO;
		goto done;
	}

	if ((rval = read(epp->dev_fd, buf, sec_sz)) < sec_sz) {
		rval = EIO;
		goto done;
	}


	if ((((struct dk_label *)buf)->dkl_magic == DKL_MAGIC) &&
	    (((struct dk_label *)buf)->dkl_vtoc.v_sanity == VTOC_SANE)) {
		rval = -1;
		goto done;
	}

	/* No valid vtoc, so check for linux swap signature */
	linux_swap_magic = buf + sec_sz - LINUX_SWAP_MAGIC_LENGTH;

	for (i = 0; i < sizeof (linux_pg_size_arr)/sizeof (uint32_t); i++) {
		linux_pg_size = linux_pg_size_arr[i];
		seek_offset = linux_pg_size/sec_sz - 1;
		seek_offset += part_start;
		seek_offset *= sec_sz;

		if (lseek(epp->dev_fd, seek_offset, SEEK_SET) < 0) {
			rval = EIO;
			break;
		}

		if ((rval = read(epp->dev_fd, buf, sec_sz)) < sec_sz) {
			rval = EIO;
			break;
		}

		if ((strncmp(linux_swap_magic, "SWAP-SPACE",
		    LINUX_SWAP_MAGIC_LENGTH) == 0) ||
		    (strncmp(linux_swap_magic, "SWAPSPACE2",
		    LINUX_SWAP_MAGIC_LENGTH) == 0)) {
			/* Found a linux swap */
			rval = 0;
			if (lsm_offset != NULL)
				*lsm_offset = (uint64_t)seek_offset;
			break;
		}
	}

done:
	free(buf);
	return (rval);
}

int
fdisk_get_solaris_part(ext_part_t *epp, int *pnum, uint32_t *begsec,
    uint32_t *numsec)
{
	logical_drive_t *temp = fdisk_get_ld_head(epp);
	uint32_t part_start;
	int pno;
	int rval = -1;

	for (pno = 5; temp != NULL; temp = temp->next, pno++) {
		if (fdisk_is_solaris_part(LE_8(temp->parts[0].systid))) {
			part_start = temp->abs_secnum + temp->logdrive_offset;
			if ((temp->parts[0].systid == SUNIXOS) &&
			    (fdisk_is_linux_swap(epp, part_start,
			    NULL) == 0)) {
				continue;
			}
			*pnum = pno;
			*begsec = part_start;
			*numsec = temp->numsect;
			rval = FDISK_SUCCESS;
		}
	}
	return (rval);
}

int
fdisk_get_part_info(ext_part_t *epp, int pnum, uchar_t *sysid, uint32_t *begsec,
    uint32_t *numsec)
{
	logical_drive_t *temp = fdisk_get_ld_head(epp);
	int pno;

	if ((pnum < 5) || (pnum >= MAX_EXT_PARTS + 5)) {
		return (EINVAL);
	}

	for (pno = 5; (pno < pnum) && (temp != NULL); temp = temp->next, pno++)
		;

	if (temp == NULL) {
		return (EINVAL);
	}

	*sysid = LE_8(temp->parts[0].systid);
	*begsec = temp->abs_secnum + temp->logdrive_offset;
	*numsec = temp->numsect;
	return (FDISK_SUCCESS);
}

/*
 * Allocate a node of type logical_drive_t and return the pointer to it
 */
static logical_drive_t *
fdisk_alloc_ld_node()
{
	logical_drive_t *temp;

	if ((temp = calloc(1, sizeof (logical_drive_t))) == NULL) {
		return (NULL);
	}
	temp->next = NULL;
	return (temp);
}

/*
 * Free all the logical_drive_t's allocated during the run
 */
static void
fdisk_free_ld_nodes(ext_part_t *epp)
{
	logical_drive_t *temp;

	for (temp = epp->ld_head; temp != NULL; ) {
		temp = epp->ld_head -> next;
		free(epp->ld_head);
		epp->ld_head = temp;
	}
	epp->ld_head = NULL;
	epp->sorted_ld_head = NULL;
}

/*
 * Find the first free sector within the extended partition
 */
int
fdisk_ext_find_first_free_sec(ext_part_t *epp, uint32_t *first_free_sec)
{
	logical_drive_t *temp;
	uint32_t last_free_sec;

	*first_free_sec = epp->ext_beg_sec;

	if (epp->ld_head == NULL) {
		return (FDISK_SUCCESS);
	}

	/*
	 * When the first logical drive is out of order, we need to adjust
	 * first_free_sec accordingly. In this case, the first extended
	 * partition sector is not free even though the actual logical drive
	 * does not occupy space from the beginning of the extended partition.
	 * The next free sector would be the second sector of the extended
	 * partition.
	 */
	if (epp->ld_head->abs_secnum > epp->ext_beg_sec +
	    MAX_LOGDRIVE_OFFSET) {
		(*first_free_sec)++;
	}

	while (*first_free_sec <= epp->ext_end_sec) {
		for (temp = epp->sorted_ld_head; temp != NULL; temp =
		    temp->sorted_next) {
			if (temp->abs_secnum == *first_free_sec) {
				*first_free_sec = temp->abs_secnum +
				    temp->logdrive_offset + temp->numsect;
			}
		}

		last_free_sec = fdisk_ext_find_last_free_sec(epp,
		    *first_free_sec);

		if ((last_free_sec - *first_free_sec) < MAX_LOGDRIVE_OFFSET) {
			/*
			 * Minimum size of a partition assumed to be atleast one
			 * sector.
			 */
			*first_free_sec = last_free_sec + 1;
			continue;
		}

		break;
	}

	if (*first_free_sec > epp->ext_end_sec) {
		return (FDISK_EOOBOUND);
	}

	return (FDISK_SUCCESS);
}

/*
 * Find the last free sector within the extended partition given, a beginning
 * sector (so that the range - "begsec to last_free_sec" is contiguous)
 */
uint32_t
fdisk_ext_find_last_free_sec(ext_part_t *epp, uint32_t begsec)
{
	logical_drive_t *temp;
	uint32_t last_free_sec;

	last_free_sec = epp->ext_end_sec;
	for (temp = epp->sorted_ld_head; temp != NULL;
	    temp = temp->sorted_next) {
		if (temp->abs_secnum > begsec) {
			last_free_sec = temp->abs_secnum - 1;
			break;
		}
	}
	return (last_free_sec);
}

/*
 * Place the given ext_part_t structure in a sorted list, sorted in the
 * ascending order of their beginning sectors.
 */
static void
fdisk_ext_place_in_sorted_list(ext_part_t *epp, logical_drive_t *newld)
{
	logical_drive_t *pre, *cur;

	if (newld->abs_secnum < epp->sorted_ld_head->abs_secnum) {
		newld->sorted_next = epp->sorted_ld_head;
		epp->sorted_ld_head = newld;
		return;
	}
	pre = cur = epp->sorted_ld_head;

	for (; cur != NULL; pre = cur, cur = cur->sorted_next) {
		if (newld->abs_secnum < cur->abs_secnum) {
			break;
		}
	}

	newld->sorted_next = cur;
	pre->sorted_next = newld;
}

static void
fdisk_ext_remove_from_sorted_list(ext_part_t *epp, logical_drive_t *delld)
{
	logical_drive_t *pre, *cur;

	if (delld == epp->sorted_ld_head) {
		epp->sorted_ld_head = delld->sorted_next;
		return;
	}

	pre = cur = epp->sorted_ld_head;

	for (; cur != NULL; pre = cur, cur = cur->sorted_next) {
		if (cur->abs_secnum == delld->abs_secnum) {
			/* Found */
			break;
		}
	}

	pre->sorted_next = cur->sorted_next;
}

static int
fdisk_ext_overlapping_parts(ext_part_t *epp, uint32_t begsec, uint32_t endsec)
{
	logical_drive_t *temp;
	uint32_t firstsec, lastsec, last_free_sec;

	for (temp = epp->ld_head; temp != NULL; temp = temp->next) {
		firstsec = temp->abs_secnum;
		lastsec = firstsec + temp->logdrive_offset + temp->numsect - 1;
		if ((begsec >= firstsec) &&
		    (begsec <= lastsec)) {
			return (1);
		}
	}

	/*
	 * Find the maximum possible end sector value
	 * given a beginning sector value
	 */
	last_free_sec = fdisk_ext_find_last_free_sec(epp, begsec);

	if (endsec > last_free_sec) {
		return (1);
	}
	return (0);
}

/*
 * Check if the logical drive boundaries are sane
 */
int
fdisk_validate_logical_drive(ext_part_t *epp, uint32_t begsec,
    uint32_t offset, uint32_t numsec)
{
	uint32_t endsec;

	endsec = begsec + offset + numsec - 1;
	if (begsec < epp->ext_beg_sec ||
	    begsec > epp->ext_end_sec ||
	    endsec < epp->ext_beg_sec ||
	    endsec > epp->ext_end_sec ||
	    endsec < begsec ||
	    fdisk_ext_overlapping_parts(epp, begsec, endsec)) {
		return (1);
	}

	return (0);
}

/*
 * Procedure to walk through the extended partitions and build a Singly
 * Linked List out of the data.
 */
static int
fdisk_read_extpart(ext_part_t *epp)
{
	struct ipart *fdp, *ext_fdp;
	int i = 0, j = 0, ext_part_found = 0, lpart = 5;
	off_t secnum, offset;
	logical_drive_t *temp, *ep_ptr;
	unsigned char *ext_buf;
	int sectsize = epp->disk_geom.sectsize;

	if ((ext_buf = (uchar_t *)malloc(sectsize)) == NULL) {
		return (ENOMEM);
	}
	fdp = epp->mtable;

	for (i = 0; (i < FD_NUMPART) && (!ext_part_found); i++, fdp++) {
		if (fdisk_is_dos_extended(LE_8(fdp->systid))) {
			ext_part_found = 1;
			secnum = LE_32(fdp->relsect);
			offset = secnum * sectsize;
			epp->ext_beg_sec = secnum;
			epp->ext_end_sec = secnum + LE_32(fdp->numsect) - 1;
			epp->ext_beg_cyl =
			    FDISK_SECT_TO_CYL(epp, epp->ext_beg_sec);
			epp->ext_end_cyl =
			    FDISK_SECT_TO_CYL(epp, epp->ext_end_sec);

			/*LINTED*/
			while (B_TRUE) {
				if (lseek(epp->dev_fd, offset, SEEK_SET) < 0) {
					return (EIO);
				}
				if (read(epp->dev_fd, ext_buf, sectsize) <
				    sectsize) {
					return (EIO);
				}
				/*LINTED*/
				ext_fdp = (struct ipart *)
				    (&ext_buf[FDISK_PART_TABLE_START]);
				if ((LE_32(ext_fdp->relsect) == 0) &&
				    (epp->logical_drive_count == 0)) {
					/* No logical drives defined */
					epp->first_ebr_is_null = 0;
					return (FDISK_ENOLOGDRIVE);
				}

				temp = fdisk_alloc_ld_node();
				temp->abs_secnum = secnum;
				temp->logdrive_offset =
				    LE_32(ext_fdp->relsect);
				temp ->numsect = LE_32(ext_fdp->numsect);
				if (epp->ld_head == NULL) {
					/* adding first logical drive */
					if (temp->logdrive_offset >
					    MAX_LOGDRIVE_OFFSET) {
						/* out of order */
						temp->abs_secnum +=
						    temp->logdrive_offset;
						temp->logdrive_offset = 0;
					}
				}
				temp->begcyl =
				    FDISK_SECT_TO_CYL(epp, temp->abs_secnum);
				temp->endcyl = FDISK_SECT_TO_CYL(epp,
				    temp->abs_secnum +
				    temp->logdrive_offset +
				    temp->numsect - 1);

				/*
				 * Check for sanity of logical drives
				 */
				if (fdisk_validate_logical_drive(epp,
				    temp->abs_secnum, temp->logdrive_offset,
				    temp->numsect)) {
					epp->corrupt_logical_drives = 1;
					free(temp);
					return (FDISK_EBADLOGDRIVE);
				}

				temp->parts[0] = *ext_fdp;
				ext_fdp++;
				temp->parts[1] = *ext_fdp;

				if (epp->ld_head == NULL) {
					epp->ld_head = temp;
					epp->sorted_ld_head = temp;
					ep_ptr = temp;
					epp->logical_drive_count = 1;
				} else {
					ep_ptr->next = temp;
					ep_ptr = temp;
					fdisk_ext_place_in_sorted_list(epp,
					    temp);
					epp->logical_drive_count++;
				}

				/*LINTED*/
				if (LE_16((*(uint16_t *)&ext_buf[510])) !=
				    MBB_MAGIC) {
					epp->invalid_bb_sig[j++] = lpart;
					temp->modified = FDISK_MINOR_WRITE;
				}

				if (LE_32(ext_fdp->relsect) == 0)
					break;
				else {
					secnum = LE_32(fdp->relsect) +
					    LE_32(ext_fdp->relsect);
					offset = secnum * sectsize;
				}
				lpart++;
			}
		}
	}
	return (FDISK_SUCCESS);
}

static int
fdisk_init_master_part_table(ext_part_t *epp)
{
	int rval;
	if ((epp->mtable = fdisk_alloc_part_table()) == NULL) {
		return (ENOMEM);
	}
	rval = fdisk_read_master_part_table(epp);
	if (rval) {
		return (rval);
	}
	return (FDISK_SUCCESS);
}

static struct ipart *
fdisk_alloc_part_table()
{
	int size = sizeof (struct ipart);
	struct ipart *table;

	if ((table = calloc(4, size)) == NULL) {
		return (NULL);
	}

	return (table);
}

/*
 * Reads the master fdisk partition table from the device assuming that it has
 * a valid table.
 * MBR is supposed to be of 512 bytes no matter what the device block size is.
 */
static int
fdisk_read_master_part_table(ext_part_t *epp)
{
	struct dk_minfo_ext dkmp_ext;
	struct dk_minfo dkmp;
	uchar_t *buf;
	int sectsize;
	int size = sizeof (struct ipart);
	int cpcnt = FD_NUMPART * size;

	if (lseek(epp->dev_fd, 0, SEEK_SET) < 0) {
		return (EIO);
	}
	if (ioctl(epp->dev_fd, DKIOCGMEDIAINFOEXT, &dkmp_ext) < 0) {
		if (ioctl(epp->dev_fd, DKIOCGMEDIAINFO, &dkmp) < 0) {
			return (EIO);
		}
		sectsize = dkmp.dki_lbsize;
	} else {
		sectsize = dkmp_ext.dki_lbsize;
	}
	if (sectsize < 512) {
		return (EIO);
	}
	buf = calloc(sectsize, sizeof (uchar_t));
	if (buf == NULL) {
		return (ENOMEM);
	}
	if (read(epp->dev_fd, buf, sectsize) < sectsize) {
		free(buf);
		return (EIO);
	}

	/*LINTED*/
	if (LE_16((*(uint16_t *)&buf[510])) != MBB_MAGIC) {
		bzero(epp->mtable, cpcnt);
		free(buf);
		return (FDISK_EBADMAGIC);
	}

	bcopy(&buf[FDISK_PART_TABLE_START], epp->mtable, cpcnt);
	free(buf);

	return (FDISK_SUCCESS);
}

int
fdisk_ext_part_exists(ext_part_t *epp)
{
	int i;
	struct ipart *part_table = epp->mtable;

	if (part_table == NULL) {
		/* No extended partition found */
		return (0);
	}

	for (i = 0; i < FD_NUMPART; i++) {
		if (fdisk_is_dos_extended(LE_8(part_table[i].systid))) {
			break;
		}
	}

	if (i == FD_NUMPART) {
		/* No extended partition found */
		return (0);
	}
	return (1);
}

int
fdisk_ext_validate_part_start(ext_part_t *epp, uint32_t begcyl,
    uint32_t *begsec)
{
	logical_drive_t *temp;
	uint32_t first_free_sec;
	uint32_t first_free_cyl;
	int rval;

	rval = fdisk_ext_find_first_free_sec(epp, &first_free_sec);
	if (rval != FDISK_SUCCESS) {
		return (rval);
	}

	first_free_cyl = FDISK_SECT_TO_CYL(epp, first_free_sec);
	if (begcyl == first_free_cyl) {
		*begsec = first_free_sec;
		return (FDISK_SUCCESS);
	}

	/* Check if the cylinder number is beyond the extended partition */
	if ((begcyl < epp->ext_beg_cyl) || (begcyl > epp->ext_end_cyl)) {
		return (FDISK_EOOBOUND);
	}

	for (temp = epp->ld_head; temp != NULL; temp = temp->next) {
		if ((begcyl >= temp->begcyl) &&
		    (begcyl <= temp->endcyl)) {
			return (FDISK_EOVERLAP);
		}
	}
	*begsec = FDISK_CYL_TO_SECT(epp, begcyl);

	return (FDISK_SUCCESS);
}

void
fdisk_change_logical_drive_id(ext_part_t *epp, int pno, uchar_t partid)
{
	logical_drive_t *temp;
	int i;

	i = FD_NUMPART + 1;
	for (temp = epp->ld_head; i < pno; temp = temp->next, i++)
		;

	temp->parts[0].systid = LE_8(partid);
	temp->modified = FDISK_MAJOR_WRITE;
}

/*
 * A couple of special scenarios :
 * 1. Since the first logical drive's EBR is always at the beginning of the
 * extended partition, any specification that starts the first logical drive
 * out of order will need to address the following issue :
 * If the beginning of the drive is not coinciding with the beginning of the
 * extended partition  and :
 * a) The start is within MAX_LOGDRIVE_OFFSET, the offset changes from the
 *	default of 63 to less than 63.
 *	logdrive_offset is updated to keep track of the space between
 *	the beginning of the logical drive and extended partition. abs_secnum
 *	points to the beginning of the extended partition.
 * b) The start is greater than MAX_LOGDRIVE_OFFSET, the offset changes from
 *	the default of 63 to greater than 63.
 *	logdrive_offset is set to 0. abs_secnum points to the beginning of the
 *	logical drive, which is at an offset from the extended partition.
 */
void
fdisk_add_logical_drive(ext_part_t *epp, uint32_t begsec, uint32_t endsec,
    uchar_t partid)
{
	logical_drive_t *temp, *pre, *cur;
	struct ipart *part;

	temp = fdisk_alloc_ld_node();
	temp->abs_secnum = begsec;
	temp->logdrive_offset = MAX_LOGDRIVE_OFFSET;
	temp->numsect = endsec - begsec + 1 - MAX_LOGDRIVE_OFFSET;
	temp->begcyl = FDISK_SECT_TO_CYL(epp, begsec);
	temp->endcyl = FDISK_SECT_TO_CYL(epp, endsec);
	temp->modified = FDISK_MAJOR_WRITE;

	part 		= &temp->parts[0];
	part->bootid	= 0;
	part->systid	= LE_8(partid);
	part->relsect	= MAX_LOGDRIVE_OFFSET;
	part->numsect	= LE_32(temp->numsect);

	fdisk_set_CHS_values(epp, part);

	if (epp->ld_head == NULL) {
		epp->corrupt_logical_drives = 0;
		if (begsec != epp->ext_beg_sec) {
			part->relsect = LE_32(begsec - epp->ext_beg_sec);
			temp->numsect = endsec - begsec + 1;
			part->numsect = LE_32(temp->numsect);
			if (LE_32(part->relsect) > MAX_LOGDRIVE_OFFSET) {
				temp->logdrive_offset = 0;
			} else {
				temp->abs_secnum = epp->ext_beg_sec;
				temp->logdrive_offset = LE_32(part->relsect);
			}
		}
		epp->first_ebr_is_null = 0;
		epp->ld_head = temp;
		epp->sorted_ld_head = temp;
		epp->logical_drive_count = 1;
		return;
	}

	if (temp->abs_secnum == epp->ext_beg_sec) {
		part->relsect = LE_32(LE_32(part->relsect) - 1);
		temp->logdrive_offset--;
		temp->abs_secnum++;
	}

	for (pre = cur = epp->ld_head; cur != NULL; pre = cur, cur = cur->next)
		;

	part = &pre->parts[1];
	part->bootid	= 0;
	part->systid	= LE_8(EXTDOS);
	part->relsect	= LE_32(temp->abs_secnum - epp->ext_beg_sec);
	part->numsect	= LE_32(temp->numsect + temp->logdrive_offset);

	fdisk_set_CHS_values(epp, part);

	pre->next = temp;
	pre->modified = FDISK_MAJOR_WRITE;
	epp->logical_drive_count++;
	fdisk_ext_place_in_sorted_list(epp, temp);
}

/*
 * There are 2 cases that need to be handled.
 * 1. Deleting the first extended partition :
 *	The peculiarity of this case is that the offset of the first extended
 *	partition is always indicated by the entry in the master boot record.
 *	(MBR). This never changes, unless the extended partition itself is
 *	deleted. Hence, the location of the first EBR is fixed.
 *	It is only the logical drive which is deleted. This first EBR now gives
 *	information of the next logical drive and the info about the subsequent
 *	extended partition. Hence the "relsect" of the first EBR is modified to
 *	point to the next logical drive.
 *
 * 2. Deleting an intermediate extended partition.
 *	This is quite normal and follows the semantics of a normal linked list
 *	delete operation. The node being deleted has the information about the
 *	logical drive that it houses and the location and the size of the next
 *	extended partition. This informationis transferred to the node previous
 *	to the node being deleted.
 *
 */

void
fdisk_delete_logical_drive(ext_part_t *epp, int pno)
{
	logical_drive_t *pre, *cur;
	int i;

	i = FD_NUMPART + 1;
	pre = cur = epp->ld_head;
	for (; i < pno; i++) {
		pre = cur;
		cur = cur->next;
	}

	if (cur == epp->ld_head) {
		/* Deleting the first logical drive */
		if (cur->next == NULL) {
			/* Deleting the only logical drive left */
			free(cur);
			epp->ld_head = NULL;
			epp->sorted_ld_head = NULL;
			epp->logical_drive_count = 0;
			epp->first_ebr_is_null = 1;
		} else {
			pre = epp->ld_head;
			cur = pre->next;
			cur->parts[0].relsect =
			    LE_32(LE_32(cur->parts[0].relsect) +
			    LE_32(pre->parts[1].relsect));
			/* Corner case when partitions are out of order */
			if ((pre->abs_secnum != epp->ext_beg_sec) &&
			    (cur->abs_secnum == epp->ext_beg_sec + 1)) {
				cur->logdrive_offset++;
				cur->abs_secnum = epp->ext_beg_sec;
			} else {
				cur->abs_secnum = LE_32(cur->parts[0].relsect) +
				    epp->ext_beg_sec;
				cur->logdrive_offset = 0;
			}
			fdisk_ext_remove_from_sorted_list(epp, pre);
			epp->ld_head = cur;
			epp->ld_head->modified = FDISK_MAJOR_WRITE;
			epp->logical_drive_count--;
			free(pre);
		}
	} else {
		pre->parts[1] = cur->parts[1];
		pre->next = cur->next;
		fdisk_ext_remove_from_sorted_list(epp, cur);
		pre->modified = FDISK_MAJOR_WRITE;
		free(cur);
		epp->logical_drive_count--;
	}
}

static void
fdisk_set_CHS_values(ext_part_t *epp, struct ipart *part)
{
	uint32_t	lba, cy, hd, sc;
	uint32_t	sectors = epp->disk_geom.virt_sec;
	uint32_t	heads = epp->disk_geom.virt_heads;

	lba = LE_32(part->relsect) + epp->ext_beg_sec;
	if (lba >= heads * sectors * MAX_CYL) {
		/*
		 * the lba address cannot be expressed in CHS value
		 * so store the maximum CHS field values in the CHS fields.
		 */
		cy = MAX_CYL + 1;
		hd = MAX_HEAD;
		sc = MAX_SECT;
	} else {
		cy = lba / sectors / heads;
		hd = lba / sectors % heads;
		sc = lba % sectors + 1;
	}

	part->begcyl = cy & 0xff;
	part->beghead = (uchar_t)hd;
	part->begsect = (uchar_t)(((cy >> 2) & 0xc0) | sc);

	/*
	 * This code is identical to the code above
	 * except that it works on ending CHS values
	 */
	lba += LE_32(part->numsect - 1);
	if (lba >= heads * sectors * MAX_CYL) {
		cy = MAX_CYL + 1;
		hd = MAX_HEAD;
		sc = MAX_SECT;
	} else {
		cy = lba / sectors / heads;
		hd = lba / sectors % heads;
		sc = lba % sectors + 1;
	}
	part->endcyl = cy & 0xff;
	part->endhead = (uchar_t)hd;
	part->endsect = (uchar_t)(((cy >> 2) & 0xc0) | sc);
}

static int
read_modify_write_ebr(ext_part_t *epp, unsigned char *ebr_buf,
    struct ipart *ebr_tab, uint32_t sec_offset)
{
	off_t seek_offset;
	int sectsize = epp->disk_geom.sectsize;

	seek_offset = (off_t)sec_offset * sectsize;

	if (lseek(epp->dev_fd, seek_offset, SEEK_SET) < 0) {
		return (EIO);
	}
	if (read(epp->dev_fd, ebr_buf, sectsize) < sectsize) {
		return (EIO);
	}

	bzero(&ebr_buf[FDISK_PART_TABLE_START], 4 * sizeof (struct ipart));
	if (ebr_tab != NULL) {
		bcopy(ebr_tab, &ebr_buf[FDISK_PART_TABLE_START],
		    2 * sizeof (struct ipart));
	}
	ebr_buf[510] = 0x55;
	ebr_buf[511] = 0xAA;
	if (lseek(epp->dev_fd, seek_offset, SEEK_SET) < 0) {
		return (EIO);
	}
	if (write(epp->dev_fd, ebr_buf, sectsize) < sectsize) {
		return (EIO);
	}
	return (0);
}

/*
 * XXX - ZFS mounts not detected. Needs to come in as a feature.
 * Currently only /etc/mnttab entries are being checked
 */
int
fdisk_mounted_logical_drives(ext_part_t *epp)
{
	char *part_str, *canonp;
	char compare_pdev_str[PATH_MAX];
	char compare_sdev_str[PATH_MAX];
	FILE *fp;
	struct mnttab mt;
	int part;
	int look_for_mounted_slices = 0;
	uint32_t begsec, numsec;

	/*
	 * Do not check for mounted logical drives for
	 * devices other than /dev/rdsk/
	 */
	if (strstr(epp->device_name, DEFAULT_PATH_PREFIX) == NULL) {
		return (0);
	}

	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		return (ENOENT);
	}

	canonp = epp->device_name + strlen(DEFAULT_PATH_PREFIX);
	(void) snprintf(compare_pdev_str, PATH_MAX, "%s%s", "/dev/dsk/",
	    canonp);
	part_str = strrchr(compare_pdev_str, 'p');
	*(part_str + 1) = '\0';
	(void) strcpy(compare_sdev_str, compare_pdev_str);
	part_str = strrchr(compare_sdev_str, 'p');
	*part_str = 's';

	if (fdisk_get_solaris_part(epp, &part, &begsec, &numsec) ==
	    FDISK_SUCCESS) {
		if (part > FD_NUMPART) {
			/*
			 * Solaris partition is on a logical drive. Look for
			 * mounted slices.
			 */
			look_for_mounted_slices = 1;
		}
	}

	while (getmntent(fp, &mt) == 0) {
		if (strstr(mt.mnt_special, compare_pdev_str) == NULL) {
			if (strstr(mt.mnt_special, compare_sdev_str) == NULL) {
				continue;
			} else {
				if (look_for_mounted_slices) {
					return (FDISK_EMOUNTED);
				}
			}
		}

		/*
		 * Get the partition number that is mounted, which would be
		 * found just beyond the last 'p' in the device string.
		 * For example, in /dev/dsk/c0t0d0p12, partition number 12
		 * is just beyond the last 'p'.
		 */
		part_str = strrchr(mt.mnt_special, 'p');
		if (part_str != NULL) {
			part_str++;
			part = atoi(part_str);
			/* Extended partition numbers start from 5 */
			if (part >= 5) {
				return (FDISK_EMOUNTED);
			}
		}
	}
	return (0);
}

int
fdisk_commit_ext_part(ext_part_t *epp)
{
	logical_drive_t *temp;
	int wflag = 0;		/* write flag */
	int rval;
	int sectsize = epp->disk_geom.sectsize;
	unsigned char *ebr_buf;
	int ld_count;
	uint32_t abs_secnum;
	int check_mounts = 0;

	if ((ebr_buf = (unsigned char *)malloc(sectsize)) == NULL) {
		return (ENOMEM);
	}

	if (epp->first_ebr_is_null) {
		/*
		 * Indicator that the extended partition as a whole was
		 * modifies (either created or deleted. Must check for mounts
		 * and must commit
		 */
		check_mounts = 1;
	}

	/*
	 * Pass1 through the logical drives to make sure that commit of minor
	 * written block dont get held up due to mounts.
	 */
	for (temp = epp->ld_head; temp != NULL; temp = temp->next) {
		if (temp == epp->ld_head) {
			abs_secnum = epp->ext_beg_sec;
		} else {
			abs_secnum = temp->abs_secnum;
		}
		if (temp->modified == FDISK_MINOR_WRITE) {
			rval = read_modify_write_ebr(epp, ebr_buf,
			    temp->parts, abs_secnum);
			if (rval) {
				goto error;
			}
			temp->modified = 0;
		} else if (temp->modified == FDISK_MAJOR_WRITE) {
			check_mounts = 1;
		}
	}

	if (!check_mounts) {
		goto skip_check_mounts;
	}

	if ((rval = fdisk_mounted_logical_drives(epp)) != 0) {
		/* One/more extended partitions are mounted */
		if (ebr_buf) {
			free(ebr_buf);
		}
		return (rval);
	}

skip_check_mounts:

	if (epp->first_ebr_is_null) {
		rval = read_modify_write_ebr(epp, ebr_buf, NULL,
		    epp->ext_beg_sec);
		if (rval) {
			goto error;
		}
		wflag = 1;
		ld_count = 0;
	} else {
		if (epp->logical_drive_count == 0) {
			/*
			 * Can hit this case when there is just an extended
			 * partition with no logical drives, and the user
			 * committed without making any changes
			 * We dont have anything to commit. Return success
			 */
			if (ebr_buf) {
				free(ebr_buf);
			}
			return (FDISK_SUCCESS);
		}

		/*
		 * Make sure that the first EBR is written with the first
		 * logical drive's data, which might not be the first in disk
		 * order.
		 */
		for (temp = epp->ld_head, ld_count = 0; temp != NULL;
		    temp = temp->next, ld_count++) {
			if (ld_count == 0) {
				abs_secnum = epp->ext_beg_sec;
			} else {
				abs_secnum = temp->abs_secnum;
			}
			if (temp->modified) {
				rval = read_modify_write_ebr(epp, ebr_buf,
				    temp->parts, abs_secnum);
				if (rval) {
					if (ld_count) {
						/*
						 * There was atleast one
						 * write to the disk before
						 * this failure. Make sure that
						 * the kernel is notified.
						 * Issue the ioctl.
						 */
						break;
					}
					goto error;
				}
				if ((!wflag) && (temp->modified ==
				    FDISK_MAJOR_WRITE)) {
					wflag = 1;
				}
			}
		}

		if (wflag == 0) {
			/* No changes made */
			rval = FDISK_SUCCESS;
			goto error;
		}
	}

	/* Issue ioctl to the driver to update extended partition info */
	rval = ioctl(epp->dev_fd, DKIOCSETEXTPART);

	/*
	 * Certain devices ex:lofi do not support DKIOCSETEXTPART.
	 * Extended partitions are still created on these devices.
	 */
	if (errno == ENOTTY)
		rval = FDISK_SUCCESS;

error:
	if (ebr_buf) {
		free(ebr_buf);
	}
	return (rval);
}

int
fdisk_init_ext_part(ext_part_t *epp, uint32_t rsect, uint32_t nsect)
{
	epp->first_ebr_is_null = 1;
	epp->corrupt_logical_drives = 0;
	epp->logical_drive_count = 0;
	epp->ext_beg_sec = rsect;
	epp->ext_end_sec = rsect + nsect - 1;
	epp->ext_beg_cyl = FDISK_SECT_TO_CYL(epp, epp->ext_beg_sec);
	epp->ext_end_cyl = FDISK_SECT_TO_CYL(epp, epp->ext_end_sec);
	epp->invalid_bb_sig[0] = 0;
	return (0);
}

int
fdisk_delete_ext_part(ext_part_t *epp)
{
	epp->first_ebr_is_null = 1;
	/* Clear the logical drive information */
	fdisk_free_ld_nodes(epp);
	epp->logical_drive_count = 0;
	epp->corrupt_logical_drives = 0;
	epp->invalid_bb_sig[0] = 0;
	return (0);
}

int
fdisk_get_disk_geom(ext_part_t *epp, int type, int what)
{
	switch (type) {
		case PHYSGEOM:
			switch (what) {
				case NCYL:
					return ((int)epp->disk_geom.phys_cyl);
				case NHEADS:
					return ((int)epp->disk_geom.phys_heads);
				case NSECTPT:
					return ((int)epp->disk_geom.phys_sec);
				case SSIZE:
					return ((int)epp->disk_geom.sectsize);
				case ACYL:
					return ((int)epp->disk_geom.alt_cyl);
				default:
					return (EINVAL);
			}
		case VIRTGEOM:
			switch (what) {
				case NCYL:
					return ((int)epp->disk_geom.virt_cyl);
				case NHEADS:
					return ((int)epp->disk_geom.virt_heads);
				case NSECTPT:
					return ((int)epp->disk_geom.virt_sec);
				case SSIZE:
					return ((int)epp->disk_geom.sectsize);
				case ACYL:
					return ((int)epp->disk_geom.alt_cyl);
				default:
					return (EINVAL);
			}
		default:
			return (EINVAL);
	}
}

int
fdisk_invalid_bb_sig(ext_part_t *epp, uchar_t **bbsig_arr)
{
	*bbsig_arr = &(epp->invalid_bb_sig[0]);
	return (epp->invalid_bb_sig[0]);
}
