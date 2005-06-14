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

#ifndef	_SYS_BIOSDISK_H
#define	_SYS_BIOSDISK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union device_path {
	struct {			/* ATA or ATAPI or SATA */
		unsigned char 	chan;	/* 0 or 1 */
		unsigned char 	lun;	/* for ATAPI only */
	} ata;
	struct {
		unsigned short	target;
		uint32_t	lun_lo;
		uint32_t	lun_hi;
	} scsi;
	struct {
		uint64_t	usb_serial_id;
	} usb;
	struct {
		uint64_t	eui;
	} s1394;
	struct {
		uint64_t	wwid;
		uint64_t	lun;
	} fibre;
	struct {
		uint64_t	id_tag;
	} i2o;

	struct {
		uint32_t	raid_array_num;
	} raid;
	unsigned char pad[16];		/* total length */
} device_path_t;


typedef union interface_path {
		struct {
			unsigned short 	baseport;
		} isa;
		struct {		/* PCI or PCIX */
			unsigned char bus;
			unsigned char device;
			unsigned char function;
			unsigned char channel;
		} pci;
		char 	pad[8];
} interface_path_t;

/*
 * Structure for Int 13 function 48 (EDD 3.0)
 *
 * from T13/1484D Revision 2
 */

#pragma pack(1)
typedef struct int13_fn48_result {
	unsigned short		buflen;
	unsigned short		flags;
	uint32_t		ncyl;
	uint32_t		nhead;
	uint32_t		spt;
	uint32_t 		nsect_lo;
	uint32_t		nsect_hi;
	unsigned short		bps;
	uint32_t		dpte;
	unsigned short		magic;		/* BEDD if Path info there */
	unsigned char		pathinfo_len;
	unsigned char		res1;
	unsigned short		res2;
	char			bustype[4];	/* offset 36 */
	char			interface_type[8];
	interface_path_t	interfacepath;
	device_path_t		devicepath;
	unsigned char		res3;
	unsigned char		checksum;	/* offset 73 */
} fn48_t;
#pragma pack()

typedef struct biosdev_data {
	uchar_t			first_block_valid;
	uchar_t			first_block[512];
	uchar_t			edd_valid;
	fn48_t			fn48_dev_params;
} biosdev_data_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BIOSDISK_H */
