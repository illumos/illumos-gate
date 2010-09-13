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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_PC_LABEL_H
#define	_SYS_FS_PC_LABEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/isa_defs.h>

/*
 * PC master boot block & partition table defines.
 */

#define	PCB_BPSEC	11	/* (short) bytes per sector */
#define	PCB_SPC		13	/* (byte) sectors per cluster */
#define	PCB_RESSEC	14	/* (short) reserved sectors */
#define	PCB_NFAT	16	/* (byte) number of fats */
#define	PCB_NROOTENT	17	/* (short) number of root dir entries */
#define	PCB_NSEC	19	/* (short) number of sectors on disk */
#define	PCB_MEDIA	21	/* (byte) media descriptor */
#define	PCB_SPF		22	/* (short) sectors per fat */
#define	PCB_SPT		24	/* (short) sectors per track */
#define	PCB_NHEAD	26	/* (short) number of heads */
#define	PCB_HIDSEC	28	/* (short) number of hidden sectors */

#define	PCFS_PART	0x1be	/* partition table offs in blk 0 of unit */
#define	PCFS_NUMPART	4	/* Number of partitions in blk 0 of unit */

/*
 *  Offsets into the boot sector where the string 'FAT' is expected.
 *  First value is where the string is on 12 and 16 bit FATs,
 *  the second value is where it is on 32 bit FATs.
 */
#define	PCFS_TYPESTRING_OFFSET16	0x36
#define	PCFS_TYPESTRING_OFFSET32	0x52

#define	PCFS_BPB	0xb	/* offset of the BPB in the boot block	*/
#define	PCFS_SIGN	0x1fe   /* offset of the DOS signature		*/
#define	DOS_SYSFAT12    1	/* DOS FAT 12 system indicator		*/
#define	DOS_SYSFAT16	4	/* DOS FAT 16 system indicator		*/
#define	DOS_SYSHUGE	6	/* DOS FAT 16 system indicator > 32MB	*/
#define	DOS_FAT32	0xB	/* FAT32 system indicator */
#define	DOS_FAT32_LBA	0xC	/* FAT32 system indicator (LBA) */
#define	DOS_FAT16P_LBA	0xE	/* FAT16 system indicator (Primary/LBA ) */
#define	DOS_FAT16_LBA	0xF	/* FAT16 system indicator (Extended/LBA) */
#define	DOS_F12MAXS	20740	/* Max sector for 12 Bit FAT (DOS>=3.2)	*/
#define	DOS_F12MAXC	4086	/* Max cluster for 12 Bit FAT (DOS>=3.2) */

#define	DOS_ID1		0xe9	/* JMP intrasegment			*/
#define	DOS_ID2a	0xeb    /* JMP short				*/
#define	DOS_ID2b	0x90
#define	DOS_SIGN	0xaa55	/* DOS signature in boot and partition	*/

#define	PC_FATBLOCK	1	/* starting block number of fat */
/*
 * Media descriptor byte.
 * Found in the boot block and in the first byte of the FAT.
 * Second and third byte in the FAT must be 0xFF.
 * Note that all technical sources indicate that this means of
 * identification is extremely unreliable.
 */
#define	MD_FIXED	0xF8	/* fixed disk				*/
#define	SS8SPT		0xFE	/* single sided 8 sectors per track	*/
#define	DS8SPT		0xFF	/* double sided 8 sectors per track	*/
#define	SS9SPT		0xFC	/* single sided 9 sectors per track	*/
#define	DS9SPT		0xFD	/* double sided 9 sectors per track	*/
#define	DS18SPT		0xF0	/* double sided 18 sectors per track	*/
#define	DS9_15SPT	0xF9	/* double sided 9/15 sectors per track	*/

#define	PC_SECSIZE	512	/* pc filesystem sector size */

/*
 * conversions to/from little endian format
 */
#if defined(_LITTLE_ENDIAN)
/* e.g. i386 machines */
#define	ltohs(S)	(*((ushort_t *)(&(S))))
#define	ltohi(I)	(*((uint_t *)(&(I))))
#define	htols(S)	(*((ushort_t *)(&(S))))
#define	htoli(I)	(*((uint_t *)(&(I))))

#else
/* e.g. SPARC machines */
#define	getbyte(A, N)	(((unsigned char *)(&(A)))[N])
#define	ltohs(S)	((getbyte(S, 1) << 8) | getbyte(S, 0))
#define	ltohi(I)	((getbyte(I, 3) << 24) | (getbyte(I, 2) << 16) | \
			    (getbyte(I, 1) << 8) | getbyte(I, 0))
#define	htols(S)	((getbyte(S, 1) << 8) | getbyte(S, 0))
#define	htoli(I)	((getbyte(I, 3) << 24) | (getbyte(I, 2) << 16) | \
			    (getbyte(I, 1) << 8) | getbyte(I, 0))
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_PC_LABEL_H */
