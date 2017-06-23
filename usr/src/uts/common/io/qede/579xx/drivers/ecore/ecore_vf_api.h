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

#ifndef __ECORE_VF_API_H__
#define __ECORE_VF_API_H__

#include "ecore_sp_api.h"
#include "ecore_mcp_api.h"

#ifdef CONFIG_ECORE_SRIOV
/**
 * @brief Read the VF bulletin and act on it if needed
 *
 * @param p_hwfn
 * @param p_change - ecore fills 1 iff bulletin board has changed, 0 otherwise.
 *
 * @return enum _ecore_status
 */
enum _ecore_status_t ecore_vf_read_bulletin(struct ecore_hwfn *p_hwfn,
					    u8 *p_change);

/**
 * @brief Get link paramters for VF from ecore
 *
 * @param p_hwfn
 * @param params - the link params structure to be filled for the VF
 */
void ecore_vf_get_link_params(struct ecore_hwfn *p_hwfn,
			      struct ecore_mcp_link_params *params);

/**
 * @brief Get link state for VF from ecore
 *
 * @param p_hwfn
 * @param link - the link state structure to be filled for the VF
 */
void ecore_vf_get_link_state(struct ecore_hwfn *p_hwfn,
			     struct ecore_mcp_link_state *link);

/**
 * @brief Get link capabilities for VF from ecore
 *
 * @param p_hwfn
 * @param p_link_caps - the link capabilities structure to be filled for the VF
 */
void ecore_vf_get_link_caps(struct ecore_hwfn *p_hwfn,
			    struct ecore_mcp_link_capabilities *p_link_caps);

/**
 * @brief Get number of Rx queues allocated for VF by ecore
 *
 *  @param p_hwfn
 *  @param num_rxqs - allocated RX queues
 */
void ecore_vf_get_num_rxqs(struct ecore_hwfn *p_hwfn,
			   u8 *num_rxqs);

/**
 * @brief Get number of Rx queues allocated for VF by ecore
 *
 *  @param p_hwfn
 *  @param num_txqs - allocated RX queues
 */
void ecore_vf_get_num_txqs(struct ecore_hwfn *p_hwfn,
			   u8 *num_txqs);

/**
 * @brief Get port mac address for VF
 *
 * @param p_hwfn
 * @param port_mac - destination location for port mac
 */
void ecore_vf_get_port_mac(struct ecore_hwfn *p_hwfn,
			   u8 *port_mac);

/**
 * @brief Get number of VLAN filters allocated for VF by ecore
 *
 *  @param p_hwfn
 *  @param num_rxqs - allocated VLAN filters
 */
void ecore_vf_get_num_vlan_filters(struct ecore_hwfn *p_hwfn,
				   u8 *num_vlan_filters);

/**
 * @brief Get number of MAC filters allocated for VF by ecore
 *
 *  @param p_hwfn
 *  @param num_rxqs - allocated MAC filters
 */
void ecore_vf_get_num_mac_filters(struct ecore_hwfn *p_hwfn,
				  u8 *num_mac_filters);

/**
 * @brief Check if VF can set a MAC address
 *
 * @param p_hwfn
 * @param mac
 *
 * @return bool
 */
bool ecore_vf_check_mac(struct ecore_hwfn *p_hwfn, u8 *mac);

#ifndef LINUX_REMOVE
/**
 * @brief Copy forced MAC address from bulletin board
 *
 * @param hwfn
 * @param dst_mac
 * @param p_is_forced - out param which indicate in case mac
 *      	        exist if it forced or not.
 *  
 * @return bool       - return true if mac exist and false if
 *                      not.
 */
bool ecore_vf_bulletin_get_forced_mac(struct ecore_hwfn *hwfn, u8 *dst_mac,
				      u8 *p_is_forced);

/**
 * @brief Check if force vlan is set and copy the forced vlan
 *        from bulletin board
 *
 * @param hwfn
 * @param dst_pvid
 * @return bool
 */
bool ecore_vf_bulletin_get_forced_vlan(struct ecore_hwfn *hwfn, u16 *dst_pvid);

/**
 * @brief Check if VF is based on PF whose driver is pre-fp-hsi version;
 *        This affects the fastpath implementation of the driver.
 *
 * @param p_hwfn
 *
 * @return bool - true iff PF is pre-fp-hsi version.
 */
bool ecore_vf_get_pre_fp_hsi(struct ecore_hwfn *p_hwfn);

#endif

/**
 * @brief Set firmware version information in dev_info from VFs acquire response tlv
 *
 * @param p_hwfn
 * @param fw_major
 * @param fw_minor
 * @param fw_rev
 * @param fw_eng
 */
void ecore_vf_get_fw_version(struct ecore_hwfn *p_hwfn,
			     u16 *fw_major,
			     u16 *fw_minor,
			     u16 *fw_rev,
			     u16 *fw_eng);
void ecore_vf_bulletin_get_udp_ports(struct ecore_hwfn *p_hwfn,
				     u16 *p_vxlan_port, u16 *p_geneve_port);
#else
static OSAL_INLINE enum _ecore_status_t ecore_vf_read_bulletin(struct ecore_hwfn *p_hwfn, u8 *p_change) {return ECORE_INVAL;}
static OSAL_INLINE void ecore_vf_get_link_params(struct ecore_hwfn *p_hwfn, struct ecore_mcp_link_params *params) {}
static OSAL_INLINE void ecore_vf_get_link_state(struct ecore_hwfn *p_hwfn, struct ecore_mcp_link_state *link) {}
static OSAL_INLINE void ecore_vf_get_link_caps(struct ecore_hwfn *p_hwfn, struct ecore_mcp_link_capabilities *p_link_caps) {}
static OSAL_INLINE void ecore_vf_get_num_rxqs(struct ecore_hwfn *p_hwfn, u8 *num_rxqs) {}
static OSAL_INLINE void ecore_vf_get_num_txqs(struct ecore_hwfn *p_hwfn, u8 *num_txqs) {}
static OSAL_INLINE void ecore_vf_get_port_mac(struct ecore_hwfn *p_hwfn, u8 *port_mac) {}
static OSAL_INLINE void ecore_vf_get_num_vlan_filters(struct ecore_hwfn *p_hwfn, u8 *num_vlan_filters) {}
static OSAL_INLINE void ecore_vf_get_num_mac_filters(struct ecore_hwfn *p_hwfn, u8 *num_mac_filters) {}
static OSAL_INLINE bool ecore_vf_check_mac(struct ecore_hwfn *p_hwfn, u8 *mac) {return false;}
#ifndef LINUX_REMOVE
static OSAL_INLINE bool ecore_vf_bulletin_get_forced_mac(struct ecore_hwfn *hwfn, u8 *dst_mac, u8 *p_is_forced) {return false;}
static OSAL_INLINE bool ecore_vf_get_pre_fp_hsi(struct ecore_hwfn *p_hwfn) {return false; }
#endif
static OSAL_INLINE void ecore_vf_get_fw_version(struct ecore_hwfn *p_hwfn, u16 *fw_major, u16 *fw_minor, u16 *fw_rev, u16 *fw_eng) {}
static OSAL_INLINE void ecore_vf_bulletin_get_udp_ports(struct ecore_hwfn *p_hwfn, u16 *p_vxlan_port, u16 *p_geneve_port) { return; }
#endif
#endif
