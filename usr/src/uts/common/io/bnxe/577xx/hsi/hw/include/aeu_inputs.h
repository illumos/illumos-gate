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
 * Name:        aeu_inputs.h
 *
 * Description: This file contains the AEU inputs bits definitions which
 *              should be used to configure the MISC_REGISTERS_AEU_ENABLE
 *              registers.
 *              The file was based upon the AEU specification.
 *
 * Created:     10/19/2006 eilong
 *
 * $Date: 2014/01/02 $       $Revision: #18 $
 ****************************************************************************/
#ifndef AEU_INPUTS_H
#define AEU_INPUTS_H


// AEU INPUT REGISTER 1
#define AEU_INPUTS_ATTN_BITS_NIG_ATTENTION_FOR_FUNCTION0      (0x1<<0)// Type: Event,     Required Destination: MCP/Driver0
#define AEU_INPUTS_ATTN_BITS_NIG_ATTENTION_FOR_FUNCTION1      (0x1<<1)// Type: Event,     Required Destination: MCP/Driver1
#define AEU_INPUTS_ATTN_BITS_GPIO0_FUNCTION_0                 (0x1<<2)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO1_FUNCTION_0                 (0x1<<3)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO2_FUNCTION_0                 (0x1<<4)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO3_FUNCTION_0                 (0x1<<5)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO0_FUNCTION_1                 (0x1<<6)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO1_FUNCTION_1                 (0x1<<7)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO2_FUNCTION_1                 (0x1<<8)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GPIO3_FUNCTION_1                 (0x1<<9)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_VPD_EVENT_FUNCTION0              (0x1<<10)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_VPD_EVENT_FUNCTION1              (0x1<<11)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_EXPANSION_ROM_EVENT0             (0x1<<12)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_EXPANSION_ROM_EVENT1             (0x1<<13)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SPIO4                            (0x1<<14)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_SPIO5                            (0x1<<15)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MSI_X_INDICATION_FOR_FUNCTION_0  (0x1<<16)// Type: Event,     Required Destination: MCP/Driver0
#define AEU_INPUTS_ATTN_BITS_MSI_X_INDICATION_FOR_FUNCTION_1  (0x1<<17)// Type: Event,     Required Destination: MCP/Driver1
#define AEU_INPUTS_ATTN_BITS_BRB_PARITY_ERROR                 (0x1<<18)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_BRB_HW_INTERRUPT                 (0x1<<19)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PARSER_PARITY_ERROR              (0x1<<20)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PARSER_HW_INTERRUPT              (0x1<<21)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_SEARCHER_PARITY_ERROR            (0x1<<22)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_SEARCHER_HW_INTERRUPT            (0x1<<23)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TSDM_PARITY_ERROR                (0x1<<24)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TSDM_HW_INTERRUPT                (0x1<<25)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TCM_PARITY_ERROR                 (0x1<<26)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TCM_HW_INTERRUPT                 (0x1<<27)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TSEMI_PARITY_ERROR               (0x1<<28)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TSEMI_HW_INTERRUPT               (0x1<<29)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PBCLIENT_PARITY_ERROR            (0x1<<30)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PBCLIENT_HW_INTERRUPT            (0x1UL<<31)// Type: Attention, Required Destination: MCP/Driver0/Driver1



#define HW_INTERRUT_ASSERT_SET_0 \
( AEU_INPUTS_ATTN_BITS_TSDM_HW_INTERRUPT  |\
  AEU_INPUTS_ATTN_BITS_TCM_HW_INTERRUPT   |\
  AEU_INPUTS_ATTN_BITS_TSEMI_HW_INTERRUPT |\
  AEU_INPUTS_ATTN_BITS_BRB_HW_INTERRUPT   |\
  AEU_INPUTS_ATTN_BITS_PBCLIENT_HW_INTERRUPT)


#define HW_PRTY_ASSERT_SET_0 \
( AEU_INPUTS_ATTN_BITS_BRB_PARITY_ERROR      |\
  AEU_INPUTS_ATTN_BITS_PARSER_PARITY_ERROR   |\
  AEU_INPUTS_ATTN_BITS_TSDM_PARITY_ERROR     |\
  AEU_INPUTS_ATTN_BITS_SEARCHER_PARITY_ERROR |\
  AEU_INPUTS_ATTN_BITS_TSEMI_PARITY_ERROR |\
  AEU_INPUTS_ATTN_BITS_TCM_PARITY_ERROR |\
  AEU_INPUTS_ATTN_BITS_PBCLIENT_PARITY_ERROR)


// AEU INPUT REGISTER 2
#define AEU_INPUTS_ATTN_BITS_PBF_PARITY_ERROR                 (0x1<<0)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PBF_HW_INTERRUPT                 (0x1<<1)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_QM_PARITY_ERROR                  (0x1<<2)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_QM_HW_INTERRUPT                  (0x1<<3)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TIMERS_PARITY_ERROR              (0x1<<4)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_TIMERS_HW_INTERRUPT              (0x1<<5)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_XSDM_PARITY_ERROR                (0x1<<6)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_XSDM_HW_INTERRUPT                (0x1<<7)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_XCM_PARITY_ERROR                 (0x1<<8)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_XCM_HW_INTERRUPT                 (0x1<<9)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_XSEMI_PARITY_ERROR               (0x1<<10)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_XSEMI_HW_INTERRUPT               (0x1<<11)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_DOORBELLQ_PARITY_ERROR           (0x1<<12)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_DOORBELLQ_HW_INTERRUPT           (0x1<<13)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_NIG_PARITY_ERROR                 (0x1<<14)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_NIG_HW_INTERRUPT                 (0x1<<15)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_VAUX_PCI_CORE_PARITY_ERROR       (0x1<<16)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_VAUX_PCI_CORE_HW_INTERRUPT       (0x1<<17)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_DEBUG_PARITY_ERROR               (0x1<<18)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_DEBUG_HW_INTERRUPT               (0x1<<19)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_USDM_PARITY_ERROR                (0x1<<20)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_USDM_HW_INTERRUPT                (0x1<<21)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_UCM_PARITY_ERROR                 (0x1<<22)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_UCM_HW_INTERRUPT                 (0x1<<23)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_USEMI_PARITY_ERROR               (0x1<<24)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_USEMI_HW_INTERRUPT               (0x1<<25)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_UPB_PARITY_ERROR                 (0x1<<26)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_UPB_HW_INTERRUPT                 (0x1<<27)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CSDM_PARITY_ERROR                (0x1<<28)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CSDM_HW_INTERRUPT                (0x1<<29)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CCM_PARITY_ERROR                 (0x1<<30)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CCM_HW_INTERRUPT                 (0x1<<31)// Type: Attention, Required Destination: MCP/Driver0/Driver1

#define HW_INTERRUT_ASSERT_SET_1 \
( AEU_INPUTS_ATTN_BITS_QM_HW_INTERRUPT       |\
  AEU_INPUTS_ATTN_BITS_TIMERS_HW_INTERRUPT   |\
  AEU_INPUTS_ATTN_BITS_XSDM_HW_INTERRUPT     |\
  AEU_INPUTS_ATTN_BITS_XCM_HW_INTERRUPT      |\
  AEU_INPUTS_ATTN_BITS_XSEMI_HW_INTERRUPT    |\
  AEU_INPUTS_ATTN_BITS_USDM_HW_INTERRUPT     |\
  AEU_INPUTS_ATTN_BITS_UCM_HW_INTERRUPT      |\
  AEU_INPUTS_ATTN_BITS_USEMI_HW_INTERRUPT    |\
  AEU_INPUTS_ATTN_BITS_UPB_HW_INTERRUPT      |\
  AEU_INPUTS_ATTN_BITS_CSDM_HW_INTERRUPT     |\
  AEU_INPUTS_ATTN_BITS_CCM_HW_INTERRUPT)

#define HW_PRTY_ASSERT_SET_1 \
( AEU_INPUTS_ATTN_BITS_PBF_PARITY_ERROR           |\
  AEU_INPUTS_ATTN_BITS_QM_PARITY_ERROR            |\
  AEU_INPUTS_ATTN_BITS_TIMERS_PARITY_ERROR        |\
  AEU_INPUTS_ATTN_BITS_XSDM_PARITY_ERROR          |\
  AEU_INPUTS_ATTN_BITS_XCM_PARITY_ERROR           |\
  AEU_INPUTS_ATTN_BITS_XSEMI_PARITY_ERROR         |\
  AEU_INPUTS_ATTN_BITS_DOORBELLQ_PARITY_ERROR     |\
  AEU_INPUTS_ATTN_BITS_NIG_PARITY_ERROR           |\
  AEU_INPUTS_ATTN_BITS_VAUX_PCI_CORE_PARITY_ERROR |\
  AEU_INPUTS_ATTN_BITS_DEBUG_PARITY_ERROR         |\
  AEU_INPUTS_ATTN_BITS_USDM_PARITY_ERROR          |\
  AEU_INPUTS_ATTN_BITS_UCM_PARITY_ERROR           |\
  AEU_INPUTS_ATTN_BITS_USEMI_PARITY_ERROR         |\
  AEU_INPUTS_ATTN_BITS_UPB_PARITY_ERROR           |\
  AEU_INPUTS_ATTN_BITS_CSDM_PARITY_ERROR          |\
  AEU_INPUTS_ATTN_BITS_CCM_PARITY_ERROR)


// AEU INPUT REGISTER 3
#define AEU_INPUTS_ATTN_BITS_CSEMI_PARITY_ERROR               (0x1<<0)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CSEMI_HW_INTERRUPT               (0x1<<1)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PXP_PARITY_ERROR                 (0x1<<2)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PXP_HW_INTERRUPT                 (0x1<<3)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PXPPCICLOCKCLIENT_PARITY_ERROR   (0x1<<4)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PXPPCICLOCKCLIENT_HW_INTERRUPT   (0x1<<5)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CFC_PARITY_ERROR                 (0x1<<6)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CFC_HW_INTERRUPT                 (0x1<<7)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CDU_PARITY_ERROR                 (0x1<<8)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_CDU_HW_INTERRUPT                 (0x1<<9)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_DMAE_PARITY_ERROR                (0x1<<10)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_DMAE_HW_INTERRUPT                (0x1<<11)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_IGU_PARITY_ERROR                 (0x1<<12)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_IGU_HW_INT_AND_MSI_X_CONF_CHANGE (0x1<<13)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MISC_PARITY_ERROR                (0x1<<14)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MISC_HW_INTERRUPT                (0x1<<15)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PXP_PXP_MISC_MPS_ATTN            (0x1<<16)// Type: Attention, Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_FLASH_INTERFACE_FLASH_EVENT      (0x1<<17)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SMB_INTERFACE_SMB_EVENT          (0x1<<18)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_MCP_MAPPED_REGISTERS_MCP_ATTN0   (0x1<<19)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_MCP_MAPPED_REGISTERS_MCP_ATTN1   (0x1<<20)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_1_FUNC0           (0x1<<21)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_2_FUNC0           (0x1<<22)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_3_FUNC0           (0x1<<23)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_4_FUNC0           (0x1<<24)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_MISC_PERST                       (0x1<<25)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_1_FUNC1           (0x1<<26)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_2_FUNC1           (0x1<<27)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_3_FUNC1           (0x1<<28)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_SW_TIMERS_ATTN_4_FUNC1           (0x1<<29)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN0         (0x1<<30)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN1         (0x1<<31)// Type: Attention, Required Destination: MCP/Driver0/Driver1



#define HW_INTERRUT_ASSERT_SET_2 \
( AEU_INPUTS_ATTN_BITS_CSEMI_HW_INTERRUPT               |\
  AEU_INPUTS_ATTN_BITS_PXP_HW_INTERRUPT                 |\
  AEU_INPUTS_ATTN_BITS_CFC_HW_INTERRUPT                 |\
  AEU_INPUTS_ATTN_BITS_CDU_HW_INTERRUPT                 |\
  AEU_INPUTS_ATTN_BITS_DMAE_HW_INTERRUPT                |\
  AEU_INPUTS_ATTN_BITS_PXPPCICLOCKCLIENT_HW_INTERRUPT   |\
  AEU_INPUTS_ATTN_BITS_MISC_HW_INTERRUPT)

/*AEU_INPUTS_ATTN_BITS_DMAE_PARITY_ERROR |\*/

#define HW_PRTY_ASSERT_SET_2 \
( AEU_INPUTS_ATTN_BITS_CSEMI_PARITY_ERROR             |\
  AEU_INPUTS_ATTN_BITS_PXP_PARITY_ERROR               |\
  AEU_INPUTS_ATTN_BITS_PXPPCICLOCKCLIENT_PARITY_ERROR |\
  AEU_INPUTS_ATTN_BITS_CFC_PARITY_ERROR               |\
  AEU_INPUTS_ATTN_BITS_CDU_PARITY_ERROR               |\
  AEU_INPUTS_ATTN_BITS_DMAE_PARITY_ERROR              |\
  AEU_INPUTS_ATTN_BITS_IGU_PARITY_ERROR               |\
  AEU_INPUTS_ATTN_BITS_MISC_PARITY_ERROR)


#define HW_PRTY_ASSERT_SET_3 \
( AEU_INPUTS_ATTN_BITS_MCP_LATCHED_ROM_PARITY         | \
  AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_RX_PARITY      | \
  AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_TX_PARITY      | \
  AEU_INPUTS_ATTN_BITS_MCP_LATCHED_SCPAD_PARITY)


// AEU INPUT REGISTER 4
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN2         (0x1<<0)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN3         (0x1<<1)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN4         (0x1<<2)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN5         (0x1<<3)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN6         (0x1<<4)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN7         (0x1<<5)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN8         (0x1<<6)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN9         (0x1<<7)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN10        (0x1<<8)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN11        (0x1<<9)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN12        (0x1<<10)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN13        (0x1<<11)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN14        (0x1<<12)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN15        (0x1<<13)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN16        (0x1<<14)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN17        (0x1<<15)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN18        (0x1<<16)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN19        (0x1<<17)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN20        (0x1<<18)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN21        (0x1<<19)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_INIT_BLOCK_MAIN_POWER_INTERRUPT  (0x1<<20)// Type: Event,     Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_RBCR_LATCHED_ATTN                (0x1<<21)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_RBCT_LATCHED_ATTN                (0x1<<22)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_RBCN_LATCHED_ATTN                (0x1<<23)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_RBCU_LATCHED_ATTN                (0x1<<24)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_RBCP_LATCHED_ATTN                (0x1<<25)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_LATCHED_TIMEOUT_ATTENTION    (0x1<<26)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_GRC_LATCHED_RESERVED_ACCESS_ATTN (0x1<<27)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MCP_LATCHED_ROM_PARITY           (0x1<<28)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_RX_PARITY        (0x1<<29)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MCP_LATCHED_UMP_TX_PARITY        (0x1<<30)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_MCP_LATCHED_SCPAD_PARITY         (0x1UL<<31)// Type: Attention, Required Destination: MCP/Driver0/Driver1

// AEU INPUT REGISTER 5
#define AEU_INPUTS_ATTN_BITS_PGLUE_CFG_SPACE_ATTN             (0x1<<0)// Type: Attention, Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_PGLUE_FLR_ATTN                   (0x1<<1)// Type: Attention, Required Destination: MCP
#define AEU_INPUTS_ATTN_BITS_PGLUE_HW_INTERRUPT               (0x1<<2)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_PGLUE_PARITY_ERROR               (0x1<<3)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_ATC_HW_INTERRUPT                 (0x1<<4)// Type: Attention, Required Destination: MCP/Driver0/Driver1
#define AEU_INPUTS_ATTN_BITS_ATC_PARITY_ERROR                 (0x1<<5)// Type: Attention, Required Destination: MCP/Driver0/Driver1

#define HW_INTERRUT_ASSERT_SET_4 \
( AEU_INPUTS_ATTN_BITS_PGLUE_HW_INTERRUPT |\
  AEU_INPUTS_ATTN_BITS_ATC_HW_INTERRUPT)

#define HW_PRTY_ASSERT_SET_4 \
( AEU_INPUTS_ATTN_BITS_PGLUE_PARITY_ERROR |\
  AEU_INPUTS_ATTN_BITS_ATC_PARITY_ERROR)

#endif //AEU_INPUTS_H
