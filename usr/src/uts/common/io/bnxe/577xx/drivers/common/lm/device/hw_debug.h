/*******************************************************************************
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
 * Module Description:
 *  This file defines the IDLE_CHK macros
 *
 * History:
 *    11/02/08 Miri Shitrit    Inception.
 ******************************************************************************/

#ifndef _LM_DEBUG_H
#define _LM_DEBUG_H

// bits must be corralted to the values in idle_chk.csv
#define IDLE_CHK_CHIP_MASK_57710     0x01
#define IDLE_CHK_CHIP_MASK_57711     0x02
#define IDLE_CHK_CHIP_MASK_57731     0x04
// Added for E3
#define IDLE_CHK_CHIP_MASK_57773     0x08
#define IDLE_CHK_CHIP_MASK_57773_B0  0x10

enum {
    IDLE_CHK_ERROR = 1,
    IDLE_CHK_ERROR_NO_TRAFFIC, // indicates an error if test is not under traffic
    IDLE_CHK_WARNING
} idle_chk_error_level;

#if _MSC_VER
#if defined(_VBD_)
#include <ntddk.h>
#include <ntstrsafe.h>
#define snprintf RtlStringCchPrintfA
#define SNPRINTF_VAR(_str) sizeof(_str),
#else
#include "vc_os_emul.h"
#define SNPRINTF_VAR(_str) sizeof(_str), //needed due to change of sprintf_s to fix warnings
#endif // !NTDDI_VERSION


#else // !_MSC_VER
#define SNPRINTF_VAR(_str) sizeof(_str),
#endif // _MSC_VER

#define CONDITION_CHK(condition, severity, fail_msg) \
        total++; \
        var_severity = severity; \
        if (condition) { \
            switch (var_severity) { \
                case IDLE_CHK_ERROR: \
                    DbgMessage(pdev, FATAL, "idle_chk. Error   (level %d): %s\n", severity, fail_msg); \
                    errors++; \
                    break; \
                case IDLE_CHK_ERROR_NO_TRAFFIC: \
                    DbgMessage(pdev, FATAL, "idle_chk. Error if no traffic (level %d):   %s\n", severity, fail_msg); \
                    errors++; \
                    break; \
                case IDLE_CHK_WARNING: \
                    DbgMessage(pdev, WARN, "idle_chk. Warning (level %d): %s\n", severity, fail_msg); \
                    warnings++; \
                    break; \
            }\
        }


#define IDLE_CHK_CHIP_MASK_CHK(chip_mask) \
        b_test_chip=0; \
        var_chip_mask = 0; \
        val = REG_RD(pdev, MISC_REG_CHIP_NUM); \
        chip_rev = REG_RD(pdev, MISC_REG_CHIP_REV); \
        chip_metal = REG_RD(pdev,  MISC_REG_CHIP_METAL); \
        if (val == 5710) { \
            var_chip_mask = IDLE_CHK_CHIP_MASK_57710; \
        } else if (val == 5711 || val == 5712) { \
            var_chip_mask = IDLE_CHK_CHIP_MASK_57711; \
        } else if ((val == 5713) || (val == 5714) || (val == 5730) || (val == 5731))  { \
            var_chip_mask =  IDLE_CHK_CHIP_MASK_57731; \
        } else if (((chip_rev == 0xC) || (chip_rev == 0xD) || (chip_rev == 1)) && ((val == 5773) || (val == 5774) || (val == 5770))) { \
            var_chip_mask =  IDLE_CHK_CHIP_MASK_57773_B0; \
        } else if ((val == 5773) || (val == 5774) || (val == 5770)) { \
            var_chip_mask =  IDLE_CHK_CHIP_MASK_57773; \
        } \
        if (var_chip_mask & chip_mask) { \
            b_test_chip = 1;\
        }

/* read one reg and check the condition */
#define IDLE_CHK_1(chip_mask, offset, condition, severity, fail_msg) \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            val = REG_RD(pdev, offset); \
            snprintf (prnt_str, SNPRINTF_VAR(prnt_str) "%s. Value is 0x%x\n", fail_msg, val); \
            val1 = 0; \
            val2 = 0; \
            CONDITION_CHK(condition, severity, prnt_str); \
        }

/* loop to read one reg and check the condition */
#define IDLE_CHK_2(chip_mask, offset, loop, inc, condition, severity, fail_msg) \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            for (i = 0; i < (loop); i++) { \
                val = REG_RD(pdev, offset + i*(inc)); \
                snprintf (prnt_str, SNPRINTF_VAR(prnt_str) "%s. Value is 0x%x\n", fail_msg, val); \
                val1 = 0; \
                val2 = 0; \
                CONDITION_CHK(condition, severity, prnt_str); \
            } \
        }

/* read two regs and check the condition */
#define IDLE_CHK_3(chip_mask, offset1, offset2, condition, severity, fail_msg) \
         IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
         if (b_test_chip) { \
            val1 = REG_RD(pdev, offset1); \
            val2 = REG_RD(pdev, offset2); \
            snprintf (prnt_str, SNPRINTF_VAR(prnt_str) "%s. Values are 0x%x 0x%x\n", fail_msg, val1, val2); \
            val = 0; \
            CONDITION_CHK(condition, severity, prnt_str); \
         }

/* read one reg and check according to CID_CAM */
#define IDLE_CHK_4(chip_mask, offset1, offset2, loop, inc, condition, severity, fail_msg) \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            for (i = 0; i < (loop); i++) { \
                val1 = REG_RD(pdev, (offset1 + i*inc)); \
                val2 = REG_RD(pdev, (offset2 + i*(inc))); \
                val2 = val2 >> 1; \
                snprintf (prnt_str, SNPRINTF_VAR(prnt_str)  "%s LCID %d CID_CAM 0x%x. Value is 0x%x\n", fail_msg, i, val2, val1);\
                val = 0; \
                CONDITION_CHK(condition, severity, prnt_str); \
            } \
        }


/* read one reg and check according to another reg */
#define IDLE_CHK_5(chip_mask, offset, offset1, offset2, condition, severity, fail_msg) \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            val = REG_RD(pdev, offset);\
            if (!val) \
                IDLE_CHK_3(chip_mask, offset1, offset2, condition, severity, fail_msg); \
        }

/* read wide-bus reg and check sub-fields */
#define IDLE_CHK_6(chip_mask, offset, loop, inc, severity) \
     { \
        u32 rd_ptr, wr_ptr, rd_bank, wr_bank; \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            for (i = 0; i < (loop); i++) { \
                val1 = REG_RD(pdev, offset + i*(inc)); \
                val2 = REG_RD(pdev, offset + i*(inc) + 4); \
                rd_ptr = ((val1 & 0x3FFFFFC0) >> 6); \
                wr_ptr = ((((val1 & 0xC0000000) >> 30) & 0x3) | ((val2 & 0x3FFFFF) << 2)); \
                snprintf (prnt_str, SNPRINTF_VAR(prnt_str) "QM: PTRTBL entry %d- rd_ptr is not equal to wr_ptr. Values are 0x%x 0x%x\n", i, rd_ptr, wr_ptr);\
                val = 0; \
                CONDITION_CHK((rd_ptr != wr_ptr), severity, prnt_str);\
                rd_bank = ((val1 & 0x30) >> 4); \
                wr_bank = (val1 & 0x03); \
                snprintf (prnt_str, SNPRINTF_VAR(prnt_str) "QM: PTRTBL entry %d- rd_bank is not equal to wr_bank. Values are 0x%x 0x%x\n", i, rd_bank, wr_bank); \
                val = 0; \
                CONDITION_CHK((rd_bank != wr_bank), severity, prnt_str); \
            } \
        } \
      }


/* loop to read wide-bus reg and check according to another reg */
#define IDLE_CHK_7(chip_mask, offset, offset1, offset2, loop, inc, condition, severity, fail_msg) \
    { \
        u32_t chip_num; \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            for (i = 0; i < (loop); i++) { \
                val = REG_RD(pdev, offset2 + i*4); \
                if ((val & 0x1) == 1) { \
                    chip_num = REG_RD(pdev , MISC_REG_CHIP_NUM); \
                    if ((chip_num == 0x1662) || (chip_num == 0x1663) || (chip_num == 0x1651) || (chip_num == 0x1652)) { \
                        val1 = REG_RD(pdev, offset1 + i*(inc)); \
                        val1 = REG_RD(pdev, offset1 + i*(inc) + 4); \
                        val1 = REG_RD(pdev, offset1 + i*(inc) + 8); \
                        REG_RD(pdev, offset1 + i*(inc) + 12); \
                        val1 = (val1 & 0x1E000000) >> 25; \
                    } else { \
                        val1 = REG_RD(pdev, offset1 + i*(inc)); \
                        val1 = REG_RD(pdev, offset1 + i*(inc) + 4); \
                        val1 = REG_RD(pdev, offset1 + i*(inc) + 8); \
                        REG_RD(pdev, offset1 + i*(inc) + 12); \
                        val1 = (val1 & 0x00000078) >> 3; \
                    } \
                    val2 = REG_RD(pdev, offset + i*4); \
                    snprintf (prnt_str, SNPRINTF_VAR(prnt_str) "%s - LCID %d CID_CAM 0x%x. Value is 0x%x\n", fail_msg, i, val2, val1); \
                    CONDITION_CHK(condition, severity, prnt_str); \
                } \
            } \
        } \
    }

/* check PXP VQ occupancy according to condition */
#define IDLE_CHK_8(chip_mask, offset, condition, severity, fail_msg) \
        IDLE_CHK_CHIP_MASK_CHK(chip_mask); \
        if (b_test_chip) { \
            val = REG_RD(pdev, offset); \
            if (condition) { \
                snprintf (prnt_str, SNPRINTF_VAR(prnt_str)  "%s. Value is 0x%x\n%s\n", fail_msg, val,_vq_hoq(pdev,#offset)); \
                val = 0; \
                val1 = 0; \
                val2 = 0; \
                CONDITION_CHK(1, severity, prnt_str); \
            } \
        }

#endif// _LM_DEBUG_H

