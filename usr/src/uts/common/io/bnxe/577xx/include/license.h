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
 * Name:        license.h
 *
 * Description: Definition of license key.
 *
 * Created:     07/21/2004 skeung
 *
 ****************************************************************************/

#ifndef _LICENSE_H
#define _LICENSE_H

#include "bcmtype.h"

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
    #error "Missing either LITTLE_ENDIAN or BIG_ENDIAN definition."
#endif


#define HASH_VALUE_SIZE                          12
/*
 * license_key_b definition
 */

typedef struct _license_key_b
{
    u8_t digest[HASH_VALUE_SIZE];
        /* KEY_VALID_PATTERN is used when no actual digest is needed */
        #define KEY_VALID_PATTERN_BYTE           0x5a
        #define KEY_VALID_PATTERN_DWORD          0x5a5a5a5a

    u8_t key_type;
        #define KEY_TYPE_ENUM_BCM5706            0x0
        #define KEY_TYPE_ENUM_BCM5710            0x2 /* Special modification for Everest */
    u8_t version;
        #define VERSION_CURRENT                  0x0
    u8_t dword_length;                           /* Not including the digest */
    u8_t oem_id;
        #define OEM_ID_BRCM                      0
        #define OEM_ID_HPQ                       0x3c

    u16_t capability;
        #define CAP_RESERVED                     0x0001 /* Xinan/Teton Only */
        #define CAP_USER_RDMA                    0x0002 /* Xinan/Teton Only */
        #define CAP_TOE                          0x0004 /* Xinan/Teton Only */
        #define CAP_ISCSI_INIT                   0x0008 /* Xinan/Teton Only */
        #define CAP_ISCSI_TRGT                   0x0010 /* Xinan/Teton Only */
        #define CAP_ISER_INIT                    0x0020 /* Xinan/Teton Only */
        #define CAP_ISER_TRGT                    0x0040 /* Xinan/Teton Only */
        #define CAP_ISCSI_BOOT                   0x0080 /* Xinan/Teton Only, not used */
        #define CAP_ISCSI_FULL_ACCL              0x0100 /* Xinan/Teton Only, not used */
        #define CAP_ISCSI_HDR_DGST               0x0200 /* Xinan/Teton Only, not used */
        #define CAP_ISCSI_BODY_DGST              0x0400 /* Xinan/Teton Only, not used */
        #define CAP_SERDES_2_5G                  0x0800 /* Xinan/Teton Only */
        #define CAP_EVRST_RSVD                   0x0800 /* Everest Only */
        #define CAP_FCOE_INIT                    0x1000 /* E2 and onward Only */
        #define CAP_FCOE_TRGT                    0x2000 /* E2 and onward Only */
    u16_t max_toe_conn;
        #define CONN_UNLIMITED                   0xffff

    u16_t reserved;
    u16_t max_um_rdma_conn;

    u16_t max_iscsi_init_conn;
    u16_t max_iscsi_trgt_conn;

    u16_t max_iser_init_conn;
    u16_t max_iser_trgt_conn;

    u16_t max_fcoe_init_conn;
    u16_t max_fcoe_trgt_conn;

    u32_t reserved_a[2];

    u32_t sn;

    u16_t reserved_b;
    u16_t expiration;
        #define EXPIRATION_NEVER                 0xffff

} license_key_b_t;

/*
 * license_key_l definition
 */

typedef struct _license_key_l
{
    u8_t digest[HASH_VALUE_SIZE];
        /* KEY_VALID_PATTERN is used when no actual digest is needed */
        #define KEY_VALID_PATTERN_BYTE           0x5a
        #define KEY_VALID_PATTERN_DWORD          0x5a5a5a5a

    u8_t oem_id;
        #define OEM_ID_BRCM                      0
        #define OEM_ID_HPQ                       0x3c
    u8_t dword_length;                           /* Not including the digest */
    u8_t version;
        #define VERSION_CURRENT                  0x0
    u8_t key_type;
        #define KEY_TYPE_ENUM_BCM5706            0x0
        #define KEY_TYPE_ENUM_BCM5710            0x2 /* Special modification for Everest */

    u16_t max_toe_conn;
        #define CONN_UNLIMITED                   0xffff
    u16_t capability;
        #define CAP_RESERVED                     0x0001 /* Xinan/Teton Only */
        #define CAP_USER_RDMA                    0x0002 /* Xinan/Teton Only */
        #define CAP_TOE                          0x0004 /* Xinan/Teton Only */
        #define CAP_ISCSI_INIT                   0x0008 /* Xinan/Teton Only */
        #define CAP_ISCSI_TRGT                   0x0010 /* Xinan/Teton Only */
        #define CAP_ISER_INIT                    0x0020 /* Xinan/Teton Only */
        #define CAP_ISER_TRGT                    0x0040 /* Xinan/Teton Only */
        #define CAP_ISCSI_BOOT                   0x0080 /* Xinan/Teton Only, not used */
        #define CAP_ISCSI_FULL_ACCL              0x0100 /* Xinan/Teton Only, not used */
        #define CAP_ISCSI_HDR_DGST               0x0200 /* Xinan/Teton Only, not used */
        #define CAP_ISCSI_BODY_DGST              0x0400 /* Xinan/Teton Only, not used */
        #define CAP_SERDES_2_5G                  0x0800 /* Xinan/Teton Only */
        #define CAP_EVRST_RSVD                   0x0800 /* Everest Only */
        #define CAP_FCOE_INIT                    0x1000 /* E2 and onward Only */
        #define CAP_FCOE_TRGT                    0x2000 /* E2 and onward Only */

    u16_t max_um_rdma_conn;
    u16_t reserved;

    u16_t max_iscsi_trgt_conn;
    u16_t max_iscsi_init_conn;

    u16_t max_iser_trgt_conn;
    u16_t max_iser_init_conn;

    u16_t max_fcoe_trgt_conn;
    u16_t max_fcoe_init_conn;

    u32_t reserved_a[2];

    u32_t sn;

    u16_t expiration;
        #define EXPIRATION_NEVER                 0xffff
    u16_t reserved_b;

} license_key_l_t;


#define FW_ENCODE_32BIT_PATTERN                  0x1e1e1e1e
#define FW_ENCODE_16BIT_PATTERN                  0x1e1e
#define FW_ENCODE_8BIT_PATTERN                   0x1e


#if defined(BIG_ENDIAN)
    typedef license_key_b_t license_key_t;
#elif defined(LITTLE_ENDIAN)
    typedef license_key_l_t license_key_t;
#endif

#endif /* _LICENSE_H */
