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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	USAGE	gettext("Usage: %s [-fm] stage1 stage2 raw-device\n")

#define	DRY_RUN	gettext("dry run--nothing will be written to disk\n")

#define	NOSOLPAR	\
	gettext("Solaris partition not found. Aborting operation.\n")

#define	NOBOOTPAR	\
	gettext("Solaris x86 boot partition not found. Aborting operation.\n")

#define	SOLPAR_INACTIVE	gettext("Solaris fdisk partition is inactive.\n")

#define	BOOTPAR_NOTFOUND	\
    gettext("Solaris boot partition not found on %s\n")

#define	NOT_RAW_DEVICE	gettext("device %s is not a char special device\n")

#define	NOT_ROOT_SLICE	gettext("raw device must be a root slice (not s2)\n")

#define	CONVERT_FAIL	gettext("cannot convert %s to a block device.\n")

#define	MOUNT_FAIL	gettext("cannot mount %s\n")

#define	MOUNT_FAIL_PCFS	gettext("floppy: cannot mount pcfs\n")

#define	MBOOT_PROMPT	\
	gettext("Updating master boot sector destroys existing boot " \
	"managers (if any).\ncontinue (y/n)? ")

#define	MBOOT_NOT_UPDATED	gettext("master boot sector not updated\n")

#define	OPEN_FAIL	gettext("cannot open/stat device %s\n")

#define	OPEN_FAIL_FILE	gettext("cannot open %s\n")

#define	OPEN_FAIL_PCFS	gettext("cannot open /boot/grub/stage2 on pcfs\n")

#define	PART_FAIL	\
	gettext("cannot get the partition information of the disk\n")

#define	BAD_PART	\
	gettext("Partition %d of the disk has an incorrect offset\n")

#define	READ_FAIL_STAGE1	gettext("cannot read stage1 file %s\n")

#define	READ_FAIL_STAGE2	gettext("cannot read stage2 file %s\n")

#define	READ_FAIL_BPB	gettext("cannot read bios parameter block\n")

#define	READ_FAIL_MBR	gettext("cannot read MBR on %s\n")

#define	WRITE_FAIL_BOOTSEC	gettext("cannot write master boot sector\n")

#define	WRITE_FAIL_PBOOT	gettext("cannot write partition boot sector\n")

#define	WRITE_FAIL_STAGE2	gettext("failed to write stage2\n")

#define	WRITE_FAIL_STAGE2_BLOCKS	\
    gettext("stage2 read/write error: read %d bytes, wrote %d bytes\n")

#define	WRITE_MBOOT	gettext("stage1 written to master boot sector\n")

#define	WRITE_PBOOT	\
    gettext("stage1 written to partition %d sector 0 (abs %d)\n")

#define	WRITE_BOOTSEC_FLOPPY	\
    gettext("stage1 written to floppy boot sector\n")

#define	WRITE_STAGE2_PCFS	gettext("stage2 written to pcfs\n")

#define	WRITE_STAGE2_DISK	gettext("stage2 written to partition %d," \
	" %d sectors starting at %d (abs %d)\n")

#define	PCFS_FRAGMENTED	\
    gettext("cannot install stage2 on pcfs, too many fragments.\n")

#define	OUT_OF_MEMORY	gettext("diskread: out of memory\n")

#define	NO_VIRT_GEOM	gettext("Could not get virtual geometry\n")

#define	NO_PHYS_GEOM	gettext("Could not get physical geometry\n")

#define	NO_LABEL_GEOM	gettext("Could not get label geometry\n")

#define	LIBFDISK_INIT_FAIL	gettext("Failed to initialize libfdisk.\n")



#ifdef	__cplusplus
}
#endif

#endif /* _MESSAGE_H */
