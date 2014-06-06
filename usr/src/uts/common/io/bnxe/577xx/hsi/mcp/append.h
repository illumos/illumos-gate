/****************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *
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
 * $Date: 2014/01/02 $       $Revision: #44 $
 *
 ****************************************************************************/

#ifndef APPEND_H
#define APPEND_H

#include "bcmtype.h"

#pragma pack(push, 1)

typedef struct _image_header_t
{
    u32_t magic;
        #define FILE_MAGIC                       0x669955aa

    u32_t version;
        #define FORMAT_VERSION_1                 0x1
        #define FORMAT_VERSION_2                 0x2
        #define LATEST_FORMAT_VERSION            FORMAT_VERSION_2

    u32_t type;
        #define IMAGE_HDR_TYPE_BC1                       0x31636200   /* -bc1  */
        #define IMAGE_HDR_TYPE_BC2                       0x32636200   /* -bc2  */
        #define IMAGE_HDR_TYPE_NCSI_CMN                  0x6d63636e   /* -nccm */
        #define IMAGE_HDR_TYPE_NCSI_LIB_XI               0x786c636e   /* -nclx */
        #define IMAGE_HDR_TYPE_NCSI_LIB_EV               0x656c636e   /* -ncle */
        #define IMAGE_HDR_TYPE_MODULES_PN                0x706d7500   /* -m_pn */
        #define IMAGE_HDR_TYPE_IPMI                      0x696d7069   /* -ipmi */
        #define IMAGE_HDR_TYPE_MBA                       0x61626d00   /* -mba  */
        #define IMAGE_HDR_TYPE_L2T                       0x74326c00   /* -l2t  */
        #define IMAGE_HDR_TYPE_L2C                       0x63326c00   /* -l2c  */
        #define IMAGE_HDR_TYPE_L2X                       0x78326c00   /* -l2x  */
        #define IMAGE_HDR_TYPE_L2U                       0x75326c00   /* -l2u  */
        #define IMAGE_HDR_TYPE_ISCSI_BOOT                0x62690000   /* -ib   */
        #define IMAGE_HDR_TYPE_ISCSI_BOOT_CFG            0x63626900   /* -ibc  */
        #define IMAGE_HDR_TYPE_ISCSI_BOOT_CPRG           0x65706269   /* -ibpe */
        #define IMAGE_HDR_TYPE_ISCSI_BOOT_IPV6           0x36626900   /* -ib6  */
        #define IMAGE_HDR_TYPE_ISCSI_BOOT_CFG_V2         0x36636269   /* -ibcv2 */
        #define IMAGE_HDR_TYPE_ISCSI_BOOT_IPV4N6         0x6e346269   /* -ib4n6 */
        #define IMAGE_HDR_TYPE_FCOE_BOOT                 0x62656600   /* -feb */
        #define IMAGE_HDR_TYPE_FCOE_BOOT_CFG             0x63626566   /* -febc */
        #define IMAGE_HDR_TYPE_FCOE_BOOT_CPRG            0x70626566   /* -febp */
        #define IMAGE_HDR_TYPE_FCOE_BOOT_CPRG_LGCY       0x6c706266   /* -febpl */
        #define IMAGE_HDR_TYPE_FCOE_BOOT_CPRG_EVRST      0x65706266   /* -febpe */
        #define IMAGE_HDR_TYPE_BOOT_CFG_SHADOW           0x6363caca   /* -bootsh */
        #define IMAGE_HDR_TYPE_NIC_PARTITION_CFG         0x7063696e   /* -nicp */
        #define IMAGE_HDR_TYPE_VPD_TABLE                 0x44505600   /* -vpd */
        #define IMAGE_HDR_TYPE_E3_WC                     0x63773365   /* -e3wc */
        #define IMAGE_HDR_TYPE_E3_PCIE                   0x65703365   /* -e3pe */
        #define IMAGE_HDR_TYPE_NIV_CFG                   0x6e69760a   /* -niv */
        #define IMAGE_HDR_TYPE_NIV_PROFILES_CFG          0x6e6976bb   /* -nivprofiles */
        #define IMAGE_HDR_TYPE_CFG_EXTENDED_SHARED       0x73686172   /* -cfg_extended_shared */
        #define IMAGE_HDR_TYPE_SWIM1                     0x73776949   /* -swi1 */
        #define IMAGE_HDR_TYPE_SWIM2                     0x73776950   /* -swi2 */
        #define IMAGE_HDR_TYPE_SWIM3                     0x73776951   /* -swi3 */
        #define IMAGE_HDR_TYPE_SWIM4                     0x73776952   /* -swi4 */
        #define IMAGE_HDR_TYPE_SWIM5                     0x73776953   /* -swi5 */
        #define IMAGE_HDR_TYPE_SWIM6                     0x73776954   /* -swi6 */
        #define IMAGE_HDR_TYPE_SWIM7                     0x73776955   /* -swi7 */
        #define IMAGE_HDR_TYPE_SWIM8                     0x73776956   /* -swi8 */
        #define IMAGE_HDR_TYPE_SWIM1_B                   0x73776957   /* -swi1b */
        #define IMAGE_HDR_TYPE_SWIM2_B                   0x73776958   /* -swi2b */
        #define IMAGE_HDR_TYPE_SWIM3_B                   0x73776959   /* -swi3b */
        #define IMAGE_HDR_TYPE_SWIM4_B                   0x73776960   /* -swi4b */
        #define IMAGE_HDR_TYPE_SWIM5_B                   0x73776961   /* -swi5b */
        #define IMAGE_HDR_TYPE_SWIM6_B                   0x73776962   /* -swi6b */
        #define IMAGE_HDR_TYPE_SWIM7_B                   0x73776963   /* -swi7b */
        #define IMAGE_HDR_TYPE_SWIM8_B                   0x73776964   /* -swi8b */
        #define IMAGE_HDR_TYPE_MFW1                      0x3177666d   /* -mfw1 */
        #define IMAGE_HDR_TYPE_MFW2                      0x3277666d   /* -mfw2 */
        #define IMAGE_HDR_TYPE_MFW2_A                    0x3377666d   /* -mfw2_a */
        #define IMAGE_HDR_TYPE_OCNVM                     0x766e636f   /* -ocnv */
        #define IMAGE_HDR_TYPE_E3_WCV2                   0x32766377   /* -wcv2 */
        #define IMAGE_HDR_TYPE_E3_PCIEV2                 0x32766570   /* -pev2 */
        #define IMAGE_HDR_TYPE_CCM                       0x6d636300   /* -ccm */
        #define IMAGE_HDR_TYPE_HW_SET                    0x706d7501   /* -hw_set */
        #define IMAGE_HDR_TYPE_USR_BLK                   0x60627275   /* -usrblk */
        #define IMAGE_HDR_TYPE_ISCSI_PERS                0x70657273   /* -ipers */
        #define IMAGE_HDR_TYPE_BDN                       0x6e646200   /* -bdn */


    u32_t image_info;
        /* not defined bits */
        #define IMAGE_INFO_REVERSED_MASK         0xff00ffff

        /* bit 23:16 define which devices it can support
         * These are bit fields */
        #define IMAGE_INFO_CHIP_MASK             0x00ff0000
        #define IMAGE_INFO_CHIP_5706             0x00010000
        #define IMAGE_INFO_CHIP_5708             0x00020000
        #define IMAGE_INFO_CHIP_5709             0x00040000
        #define IMAGE_INFO_CHIP_57710            0x00080000
        #define IMAGE_INFO_CHIP_57711            0x00100000
        #define IMAGE_INFO_CHIP_57712            0x00200000
        #define IMAGE_INFO_CHIP_57840            0x00400000

    u32_t byte_cnt;
} image_header_t;

#pragma pack(pop)

#endif /*APPEND_H*/
