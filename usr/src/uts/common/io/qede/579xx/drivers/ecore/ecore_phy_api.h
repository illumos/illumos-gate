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

#ifndef __ECORE_PHY_API_H__
#define __ECORE_PHY_API_H__

/**
 * @brief Phy core write
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param addr - nvm offset
 *  @param p_phy_result_buf - result buffer
 *  @param data_hi - low 32 bit of data to write
 *  @param data_lo - high 32 bit of data to write
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_core_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			  u32 port, u32 addr, u32 data_lo, u32 data_hi,
			  char *p_phy_result_buf);

/**
 * @brief Phy core read
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param addr - nvm offset
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_core_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u32 port, u32 addr, char *p_phy_result_buf);

/**
 * @brief Phy raw write
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param lane
 *  @param addr - nvm offset
 *  @param p_phy_result_buf - result buffer
 *  @param data_hi - low 32 bit of data to write
 *  @param data_lo - high 32 bit of data to write
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_raw_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u32 port, u32 lane, u32 addr, u32 data_lo,
			 u32 data_hi, char *p_phy_result_buf);

/**
 * @brief Phy raw read
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param lane
 *  @param addr - nvm offset
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_raw_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u32 port, u32 lane, u32 addr, char *p_phy_result_buf);

/**
 * @brief Phy mac status
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_mac_stat(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u32 port, char *p_phy_result_buf);

/**
 * @brief Phy info 
 *  
 *  @param p_hwfn
 *  @param p_ptt
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_info(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
		    char *p_phy_result_buf);

/**
 * @brief Sfp write
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param addr - I2C address
 *  @param offset - EEPROM offset
 *  @param size - number of bytes to write
 *  @param val - byte array to write (1, 2 or 4 bytes)
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u32 port, u32 addr, u32 offset, u32 size,
			u32 val, char *p_phy_result_buf);

/**
 * @brief Sfp read
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param addr - I2C address
 *  @param offset - EEPROM offset
 *  @param size - number of bytes to read
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
		       u32 port, u32 addr, u32 offset, u32 size,
		       char *p_phy_result_buf);

/**
 * @brief Sfp decode
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_decode(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u32 port, char *p_phy_result_buf);

/**
 * @brief Sfp get inserted
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_get_inserted(struct ecore_hwfn *p_hwfn,
			       struct ecore_ptt *p_ptt,
			       u32 port, char *p_phy_result_buf);

/**
 * @brief Sfp get txdisable
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_get_txdisable(struct ecore_hwfn *p_hwfn,
				struct ecore_ptt *p_ptt,
				u32 port, char *p_phy_result_buf);

/**
 * @brief Sfp set txdisable
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param txdisable - tx disable value to set
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_set_txdisable(struct ecore_hwfn *p_hwfn,
				struct ecore_ptt *p_ptt,
				u32 port, u8 txdisable,
				char *p_phy_result_buf);

/**
 * @brief Sfp get txreset
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_get_txreset(struct ecore_hwfn *p_hwfn,
			      struct ecore_ptt *p_ptt,
			      u32 port, char *p_phy_result_buf);

/**
 * @brief Sfp get rxlos
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_get_rxlos(struct ecore_hwfn *p_hwfn,
			    struct ecore_ptt *p_ptt,
			    u32 port, char *p_phy_result_buf);

/**
 * @brief Sfp get eeprom
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_sfp_get_eeprom(struct ecore_hwfn *p_hwfn,
			     struct ecore_ptt *p_ptt,
			     u32 port, char *p_phy_result_buf);

/**
 * @brief Gpio write
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param gpio - gpio number
 *  @param gpio_val - value to write to gpio
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_gpio_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			 u16 gpio, u16 gpio_val, char *p_phy_result_buf);

/**
 * @brief Gpio read
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param gpio - gpio number
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_gpio_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			u16 gpio, char *p_phy_result_buf);

/**
 * @brief Gpio get information
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param gpio - gpio number
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_gpio_info(struct ecore_hwfn *p_hwfn,
			struct ecore_ptt *p_ptt,
			u16 gpio, char *p_phy_result_buf);

/**
 * @brief Ext-Phy Read operation
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port - port number
 *  @param devad - device address
 *  @param reg - register
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_extphy_read(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			  u16 port, u16 devad, u16 reg, char *p_phy_result_buf);

/**
 * @brief Ext-Phy Write operation
 *
 *  @param p_hwfn
 *  @param p_ptt
 *  @param port - port number
 *  @param devad - device address
 *  @param reg - register
 *  @param val - value to be written
 *  @param p_phy_result_buf - result buffer
 *
 * @return enum _ecore_status_t - ECORE_SUCCESS - operation was successful.
 */
int ecore_phy_extphy_write(struct ecore_hwfn *p_hwfn, struct ecore_ptt *p_ptt,
			   u16 port, u16 devad, u16 reg, u16 val,
			   char *p_phy_result_buf);

#endif
