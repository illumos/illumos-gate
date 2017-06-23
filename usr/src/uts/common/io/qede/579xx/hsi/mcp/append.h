/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

/****************************************************************************
 * Name:        append.h
 *
 * Description:
 *      This is a utility to append firmware and other images into a
 *      single file. The primary use of this is to combine two phases
 *      of the bootcode into a single file. It appends some header
 *      information (used for parsing the file) and the input image to
 *      the output file. (If the output file does not yet exist, it'll
 *      create one.)
 *      This header file defines the image header information.
 * 
 * Bundle image layout:
 *      ========================================================
 *      = Bundle Header <bundle_header>
 *      =                             <magic     > - 0xbdbdbdbd
 *	=                             <version   > - Currently 1
 *      =                             <num_images> - Of the bundle
 *      =                             <total_size> - Of the bundle
 *      ========================================================
 *      = Img1 Hdr      <image_header>
 *      =                             <magic     > - 0x669955aa
 *      =                             <version   > - Currently 2
 *      =                             <type      > 
 *      =                             <image_info>
 *      =                             <start_addr>
 *      =                             <run_addr  >
 *      =                             <byte_cnt  >
 *      ========================================================
 *      =     Img1 data 
 *      ========================================================
 *      ========================================================
 *      =     ImgN Hdr     <image_header>
 *      ========================================================
 *      =     ImgN data   
 *      ========================================================
 *
 ****************************************************************************/

#ifndef APPEND_H
#define APPEND_H

#define SIGNATURE_MAX_DER_SIZE 128
#define SIGNATURE_MIN_DER_SIZE 64

struct image_header {
#pragma pack(push, 1)
	u32 magic;
#define FILE_MAGIC                       0x669955aa
	u32 version;
#define FORMAT_VERSION_1                 0x1
#define FORMAT_VERSION_2	         0x2
#define FORMAT_VERSION_3		 0x3
#define LATEST_FORMAT_VERSION            FORMAT_VERSION_3
	u32 type;
	u32 image_info;
	/* MAX_MEM base value is 8K, means if MAX_MEM value is 0,
	 * the size is 8K. */
#define IMAGE_INFO_MAX_MEM_BASE                  8
	/* Runtime mem size required in k, Encoded with value +
	 * IMAGE_INFO_MAX_MEM_BASE */
#define IMAGE_INFO_MAX_MEM_MASK         0x0000001f

	/* bit 23:16 reserved for bit define that device it can support.
	 * These are bit fields. */
#define IMAGE_INFO_CHIP_MASK            0x00ff0000
#define IMAGE_INFO_CHIP_57940		0x00200000
#define IMAGE_INFO_CHIP_579XX		0x00400000
#define IMAGE_INFO_CHIP_579XX_B0_ONLY	0x00500000 /* For PCIE2 */

	u32 start_addr;
	u32 run_addr;
	u32 byte_cnt;
	u32 image[1];        /* Unbounded */
#pragma pack(pop)
};

#define IMG_HDR_LEN (sizeof(struct image_header))

struct bundle_header {
	u32 magic;
#define BUNDLE_MAGIC 0xbdbdbdbd
	u32 version;
#define BUNDLE_IMAGE_VER 1
	u32 num_images;
	u32 total_size;
};

#endif				/*APPEND_H */
