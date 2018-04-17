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
 *
 * Name:        nvm_fcoe_cfg.h
 *
 * Description: NVM config file for FCoE configurations
 *
 * Created:     04/11/2016
 *
 * Version:     0.3
 *
 ****************************************************************************/

#ifndef NVM_FCOE_CFG_H
#define NVM_FCOE_CFG_H

#define NUM_OF_FCOE_TARGET_PER_PF 8
#define NUM_OF_FCOE_PF_SUPPORTED  4   // One PF per Port

union nvm_fc_world_wide_address
{
  u8  byte[8];
  u32 value[2];
};

union nvm_fc_lun
{
  u8  byte[8];
  u32 value[2];
};



struct nvm_fcoe_generic
{
  u32 ctrl_flags;                                                             /* 0x0 */
  #define NVM_FCOE_CFG_GEN_WORLD_LOGIN                  0x00000001
  #define NVM_FCOE_CFG_GEN_SELECTIVE_LOGIN              0x00000002
  #define NVM_FCOE_CFG_GEN_FIP_VLAN_DISCOVERY           0x00000004

  u32 retry_count;                                                                /* 0x4 */
  #define NVM_FCOE_CFG_GEN_FABRIC_LOGIN_RETRY_MASK        0x000000FF
  #define NVM_FCOE_CFG_GEN_FABRIC_LOGIN_RETRY_OFFSET      0
  #define NVM_FCOE_CFG_GEN_TARGET_LOGIN_RETRY_MASK        0x0000FF00
  #define NVM_FCOE_CFG_GEN_TARGET_LOGIN_RETRY_OFFSET      8

  u32 rsvd[30];                                                               /* 0x8 */
};

struct nvm_fcoe_initiator
{
  u32 fip_vlan;                                                               /* 0x0 */
  #define NVM_FCOE_CFG_INITIATOR_FIP_DEFAULT_VLAN_MASK        0x00000FFF
  #define NVM_FCOE_CFG_INITIATOR_FIP_DEFAULT_VLAN_OFFSET      0

  union nvm_fc_world_wide_address node_name;                                 /* 0x4 */
  union nvm_fc_world_wide_address port_name;                                 /* 0xC */
  
  u32 rsvd[27];                                                               /* 0x14 */
};

struct nvm_fcoe_target
{
  u32 ctrl_flags;                                                             /* 0x0 */
  #define NVM_FCOE_CFG_TARGET_ENABLED   0x00000001

  union nvm_fc_world_wide_address port_name;                                 /* 0x4 */
  union nvm_fc_lun lun;                                                      /* 0xC */  

  u32 rsvd[27];                                                               /* 0x14 */
};

struct nvm_fcoe_block
{
  u32 id;                                                                     /* 0x0 */
  #define NVM_FCOE_CFG_BLK_MAPPED_PF_ID_MASK         0x0000000F  
  #define NVM_FCOE_CFG_BLK_MAPPED_PF_ID_OFFSET       0
  #define NVM_FCOE_CFG_BLK_CTRL_FLAG_MASK            0x00000FF0
  #define NVM_FCOE_CFG_BLK_CTRL_FLAG_OFFSET          4
  #define NVM_FCOE_CFG_BLK_CTRL_FLAG_IS_NOT_EMPTY    (1 << 0)
  #define NVM_FCOE_CFG_BLK_CTRL_FLAG_PF_MAPPED       (1 << 1)

  u32 rsvd_1[8];                                                              /* 0x4 */

  struct nvm_fcoe_generic     generic;                                        /* 0x24 */
  struct nvm_fcoe_initiator   initiator;                                      /* 0xA4 */
  struct nvm_fcoe_target      target[NUM_OF_FCOE_TARGET_PER_PF];              /* 0x124 */  
 
  u32 rsvd[183];                                                              /* 0x524 */  
  /* total size - 0x800 - 2048 bytes - 2K blocks */
};

struct nvm_fcoe_cfg
{
  u32 id;                                                                     /* 0x0 */
  #define NVM_FCOE_CFG_BLK_VERSION_MINOR_MASK     0x000000FF  
  #define NVM_FCOE_CFG_BLK_VERSION_MAJOR_MASK     0x0000FF00  
  #define NVM_FCOE_CFG_BLK_SIGNATURE_MASK         0xFFFF0000
  #define NVM_FCOE_CFG_BLK_SIGNATURE              0x46430000    // FC - FCoE Config

  #define NVM_FCOE_CFG_BLK_VERSION_MAJOR          0
  #define NVM_FCOE_CFG_BLK_VERSION_MINOR          6
  #define NVM_FCOE_CFG_BLK_VERSION                (NVM_FCOE_CFG_BLK_VERSION_MAJOR << 8) | NVM_FCOE_CFG_BLK_VERSION_MINOR; 

  struct nvm_fcoe_block    block[NUM_OF_FCOE_PF_SUPPORTED];                   /* 0x4 */

};

#endif

