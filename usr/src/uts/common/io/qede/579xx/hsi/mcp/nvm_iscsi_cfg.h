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
 * Name:        nvm_iscsi_cfg.h
 *
 * Description: NVM config file for iSCSI configurations
 *
 * Created:     04/11/2016 
 *
 * Version:     0.2
 *
 ****************************************************************************/

#ifndef NVM_ISCSI_CFG_H
#define NVM_ISCSI_CFG_H

#define NUM_OF_ISCSI_TARGET_PER_PF    4   // Defined as per the ISCSI IBFT constraint
#define NUM_OF_ISCSI_PF_SUPPORTED     4   // One PF per Port - assuming 4 port card

#define NVM_ISCSI_CFG_DHCP_NAME_MAX_LEN  256

union nvm_iscsi_dhcp_vendor_id
{
  u32 value[NVM_ISCSI_CFG_DHCP_NAME_MAX_LEN/4];
  u8  byte[NVM_ISCSI_CFG_DHCP_NAME_MAX_LEN];
};

#define NVM_ISCSI_IPV4_ADDR_BYTE_LEN 4
union nvm_iscsi_ipv4_addr
{
  u32 addr;
  u8  byte[NVM_ISCSI_IPV4_ADDR_BYTE_LEN];
};

#define NVM_ISCSI_IPV6_ADDR_BYTE_LEN 16
union nvm_iscsi_ipv6_addr
{
  u32 addr[4];
  u8  byte[NVM_ISCSI_IPV6_ADDR_BYTE_LEN];
};

struct nvm_iscsi_initiator_ipv4
{
  union nvm_iscsi_ipv4_addr addr;                                             /* 0x0 */
  union nvm_iscsi_ipv4_addr subnet_mask;                                      /* 0x4 */  
  union nvm_iscsi_ipv4_addr gateway;                                          /* 0x8 */
  union nvm_iscsi_ipv4_addr primary_dns;                                      /* 0xC */
  union nvm_iscsi_ipv4_addr secondary_dns;                                    /* 0x10 */
  union nvm_iscsi_ipv4_addr dhcp_addr;                                        /* 0x14 */  

  union nvm_iscsi_ipv4_addr isns_server;                                      /* 0x18 */
  union nvm_iscsi_ipv4_addr slp_server;                                       /* 0x1C */
  union nvm_iscsi_ipv4_addr primay_radius_server;                             /* 0x20 */
  union nvm_iscsi_ipv4_addr secondary_radius_server;                          /* 0x24 */    

  union nvm_iscsi_ipv4_addr rsvd[4];                                          /* 0x28 */
};

struct nvm_iscsi_initiator_ipv6
{  
  union nvm_iscsi_ipv6_addr addr;                                             /* 0x0 */
  union nvm_iscsi_ipv6_addr subnet_mask;                                      /* 0x10 */
  union nvm_iscsi_ipv6_addr gateway;                                          /* 0x20 */
  union nvm_iscsi_ipv6_addr primary_dns;                                      /* 0x30 */
  union nvm_iscsi_ipv6_addr secondary_dns;                                    /* 0x40 */
  union nvm_iscsi_ipv6_addr dhcp_addr;                                        /* 0x50 */

  union nvm_iscsi_ipv6_addr isns_server;                                      /* 0x60 */
  union nvm_iscsi_ipv6_addr slp_server;                                       /* 0x70 */
  union nvm_iscsi_ipv6_addr primay_radius_server;                             /* 0x80 */
  union nvm_iscsi_ipv6_addr secondary_radius_server;                          /* 0x90 */
         
  union nvm_iscsi_ipv6_addr rsvd[3];                                          /* 0xA0 */
  
  u32   config;                                                               /* 0xD0 */          
  #define NVM_ISCSI_CFG_INITIATOR_IPV6_SUBNET_MASK_PREFIX_MASK      0x000000FF
  #define NVM_ISCSI_CFG_INITIATOR_IPV6_SUBNET_MASK_PREFIX_OFFSET    0  

  u32   rsvd_1[3];                                                            /* 0xD4 */
};


#define NVM_ISCSI_CFG_ISCSI_NAME_MAX_LEN  223
#define NVM_ISCSI_CFG_ISCSI_NAME_MAX_PLUS_RESERVED   256 // NVM_ISCSI_CFG_ISCSI_NAME_MAX_LEN + RESERVED for backward compatibility

union nvm_iscsi_name
{
  u32 value[NVM_ISCSI_CFG_ISCSI_NAME_MAX_PLUS_RESERVED/4];
  u8  byte[NVM_ISCSI_CFG_ISCSI_NAME_MAX_PLUS_RESERVED];
};

#define NVM_ISCSI_CFG_CHAP_NAME_MAX_LEN   256

union nvm_iscsi_chap_name
{
  u32 value[NVM_ISCSI_CFG_CHAP_NAME_MAX_LEN/4];
  u8  byte[NVM_ISCSI_CFG_CHAP_NAME_MAX_LEN];
};

#define NVM_ISCSI_CFG_CHAP_PWD_MAX_LEN  				16
// md5 need per RFC1996 is 16 octets
union nvm_iscsi_chap_password
{
  u32 value[NVM_ISCSI_CFG_CHAP_PWD_MAX_LEN/4];
  u8 byte[NVM_ISCSI_CFG_CHAP_PWD_MAX_LEN];
};

union nvm_iscsi_lun
{
  u8  byte[8];
  u32 value[2];                                                               
};


struct nvm_iscsi_generic
{
  u32 ctrl_flags;                                                             /* 0x0 */
  #define NVM_ISCSI_CFG_GEN_CHAP_ENABLED                 (1 << 0)
  #define NVM_ISCSI_CFG_GEN_DHCP_TCPIP_CONFIG_ENABLED    (1 << 1)
  #define NVM_ISCSI_CFG_GEN_DHCP_ISCSI_CONFIG_ENABLED    (1 << 2)
  #define NVM_ISCSI_CFG_GEN_IPV6_ENABLED                 (1 << 3)    
  #define NVM_ISCSI_CFG_GEN_IPV4_FALLBACK_ENABLED        (1 << 4)             // currently not supported
  #define NVM_ISCSI_CFG_GEN_ISNS_WORLD_LOGIN             (1 << 5)
  #define NVM_ISCSI_CFG_GEN_ISNS_SELECTIVE_LOGIN         (1 << 6)
  #define NVM_ISCSI_CFG_GEN_ADDR_REDIRECT_ENABLED        (1 << 7)
  #define NVM_ISCSI_CFG_GEN_CHAP_MUTUAL_ENABLED          (1 << 8)

  u32 timeout;                                                                /* 0x4 */
  #define NVM_ISCSI_CFG_GEN_DHCP_REQUEST_TIMEOUT_MASK       0x0000FFFF
  #define NVM_ISCSI_CFG_GEN_DHCP_REQUEST_TIMEOUT_OFFSET     0
  #define NVM_ISCSI_CFG_GEN_PORT_LOGIN_TIMEOUT_MASK         0xFFFF0000
  #define NVM_ISCSI_CFG_GEN_PORT_LOGIN_TIMEOUT_OFFSET       16

  union nvm_iscsi_dhcp_vendor_id  dhcp_vendor_id;                            /* 0x8  */
  u32 rsvd[62];                                                              /* 0x108 */
};

struct nvm_iscsi_initiator
{
  struct nvm_iscsi_initiator_ipv4 ipv4;                                       /* 0x0 */
  struct nvm_iscsi_initiator_ipv6 ipv6;                                       /* 0x38 */

  union nvm_iscsi_name           initiator_name;                              /* 0x118 */ 
  union nvm_iscsi_chap_name      chap_name;                                   /* 0x218 */
  union nvm_iscsi_chap_password  chap_password;                               /* 0x318 */

  u32 generic_cont0;                                                          /* 0x328 */
  #define NVM_ISCSI_CFG_INITIATOR_VLAN_MASK                  0x0000FFFF
  #define NVM_ISCSI_CFG_INITIATOR_VLAN_OFFSET                0  
  #define NVM_ISCSI_CFG_INITIATOR_RESERVED                   0x00030000

  u32 ctrl_flags;
  #define NVM_ISCSI_CFG_INITIATOR_IP_VERSION_PRIORITY_V6     (1 << 0)        
  #define NVM_ISCSI_CFG_INITIATOR_VLAN_ENABLED               (1 << 1)        
  
  u32 ip_ver;
  #define NVM_ISCSI_CFG_INITIATOR_IP_MASK			                0x00000007
  #define NVM_ISCSI_CFG_INITIATOR_IP_OFFSET			              0
  #define NVM_ISCSI_CFG_INITIATOR_IPV4			                  1
  #define NVM_ISCSI_CFG_INITIATOR_IPV6			                  2 
  #define NVM_ISCSI_CFG_INITIATOR_IPV4_IPV6			              4

  u32 rsvd[115];                                                              /* 0x32C */
};


struct nvm_iscsi_target
{
  u32 ctrl_flags;                                                             /* 0x0 */
  #define NVM_ISCSI_CFG_TARGET_ENABLED            (1 << 0)                      
  #define NVM_ISCSI_CFG_BOOT_TIME_LOGIN_STATUS    (1 << 1)                      

  u32 generic_cont0;                                                          /* 0x4 */
  #define NVM_ISCSI_CFG_TARGET_TCP_PORT_MASK      0x0000FFFF
  #define NVM_ISCSI_CFG_TARGET_TCP_PORT_OFFSET    0
 
  u32 ip_ver; 
  #define NVM_ISCSI_CFG_TARGET_IP_MASK			      0x00000007
  #define NVM_ISCSI_CFG_TARGET_IP_OFFSET			    0
  #define NVM_ISCSI_CFG_TARGET_IPV4			 	        NVM_ISCSI_CFG_INITIATOR_IPV4
  #define NVM_ISCSI_CFG_TARGET_IPV6				        NVM_ISCSI_CFG_INITIATOR_IPV6 
  #define NVM_ISCSI_CFG_TARGET_IPV4_IPV6			    NVM_ISCSI_CFG_INITIATOR_IPV4_IPV6   // currently not supported

  u32 rsvd_1[7];                                                              /* 0x24 */ 
  union nvm_iscsi_ipv4_addr ipv4_addr;                                       /* 0x28 */
  union nvm_iscsi_ipv6_addr ipv6_addr;                                       /* 0x2C */
  union nvm_iscsi_lun lun;                                                   /* 0x3C */

  union nvm_iscsi_name           target_name;                                /* 0x44 */
  union nvm_iscsi_chap_name      chap_name;                                  /* 0x144 */                                 
  union nvm_iscsi_chap_password  chap_password;                              /* 0x244 */  

  u32 rsvd_2[107];                                                           /* 0x254 */ 
};

struct nvm_iscsi_block
{
  u32 id;                                                                     /* 0x0 */
  #define NVM_ISCSI_CFG_BLK_MAPPED_PF_ID_MASK         0x0000000F  
  #define NVM_ISCSI_CFG_BLK_MAPPED_PF_ID_OFFSET       0
  #define NVM_ISCSI_CFG_BLK_CTRL_FLAG_MASK            0x00000FF0
  #define NVM_ISCSI_CFG_BLK_CTRL_FLAG_OFFSET          4
  #define NVM_ISCSI_CFG_BLK_CTRL_FLAG_IS_NOT_EMPTY            (1 << 0)
  #define NVM_ISCSI_CFG_BLK_CTRL_FLAG_PF_MAPPED               (1 << 1)

  u32 rsvd_1[5];                                                              /* 0x4 */

  struct nvm_iscsi_generic     generic;                                       /* 0x18 */
  struct nvm_iscsi_initiator   initiator;                                     /* 0x218 */
  struct nvm_iscsi_target      target[NUM_OF_ISCSI_TARGET_PER_PF];            /* 0x718 */

  u32 rsvd_2[58];                                                             /* 0x1718 */   
  /* total size - 0x1800 - 6K block */
};

struct nvm_iscsi_cfg
{
  u32 id;                                                                      /* 0x0 */
  #define NVM_ISCSI_CFG_BLK_VERSION_MINOR_MASK     0x000000FF  
  #define NVM_ISCSI_CFG_BLK_VERSION_MAJOR_MASK     0x0000FF00  
  #define NVM_ISCSI_CFG_BLK_SIGNATURE_MASK         0xFFFF0000
  #define NVM_ISCSI_CFG_BLK_SIGNATURE              0x49430000    // IC - Iscsi Config

  #define NVM_ISCSI_CFG_BLK_VERSION_MAJOR          0
  #define NVM_ISCSI_CFG_BLK_VERSION_MINOR          11
  #define NVM_ISCSI_CFG_BLK_VERSION                (NVM_ISCSI_CFG_BLK_VERSION_MAJOR << 8) | NVM_ISCSI_CFG_BLK_VERSION_MINOR; 

  struct nvm_iscsi_block    block[NUM_OF_ISCSI_PF_SUPPORTED];               /* 0x4 */
};

#endif


