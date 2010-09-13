/*
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
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NPI_ESPC_H
#define	_NPI_ESPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_espc_hw.h>

#define	EPC_WAIT_RW_COMP(handle, val_p, comp_bit) {\
	uint32_t cnt = MAX_PIO_RETRIES;\
	do {\
		NXGE_DELAY(EPC_RW_WAIT);\
		NXGE_REG_RD64(handle, ESPC_REG_ADDR(ESPC_PIO_STATUS_REG),\
				val_p); cnt--;\
	} while (((val & comp_bit) == 0) && (cnt > 0));\
}

/* ESPC specific errors */

#define	ESPC_EEPROM_ADDR_INVALID	0x51
#define	ESPC_STR_LEN_INVALID		0x91

/* ESPC error return macros */

#define	NPI_ESPC_EEPROM_ADDR_INVALID	((ESPC_BLK_ID << 8) |\
					ESPC_EEPROM_ADDR_INVALID)
#define	NPI_ESPC_EEPROM_WRITE_FAILED	((ESPC_BLK_ID << 8) | WRITE_FAILED)
#define	NPI_ESPC_EEPROM_READ_FAILED	((ESPC_BLK_ID << 8) | READ_FAILED)
#define	NPI_ESPC_OPCODE_INVALID		((ESPC_BLK_ID << 8) | OPCODE_INVALID)
#define	NPI_ESPC_STR_LEN_INVALID	((ESPC_BLK_ID << 8) |\
					ESPC_STR_LEN_INVALID)
#define	NPI_ESPC_PORT_INVALID		((ESPC_BLK_ID << 8) | PORT_INVALID)

/* EEPROM size, Fcode and VPD definitions */

/*
 * VPD information.
 */
#define	NXGE_VPD_MOD_LEN	32
#define	NXGE_VPD_BD_MOD_LEN	16
#define	NXGE_VPD_PHY_LEN	5
#define	NXGE_VPD_VER_LEN	60
typedef struct _npi_vpd_info_t {
	uint8_t		mac_addr[ETHERADDRL];
	uint8_t		num_macs;
	char		model[NXGE_VPD_MOD_LEN];
	char		bd_model[NXGE_VPD_BD_MOD_LEN];
	char		phy_type[NXGE_VPD_PHY_LEN];
	char		ver[NXGE_VPD_VER_LEN];
	boolean_t	ver_valid;
	boolean_t	present;
} npi_vpd_info_t, *p_npi_vpd_info_t;

#define	NXGE_FCODE_ID_STR	"FCode "
#define	NXGE_FCODE_VER_STR_LEN	5
#define	NXGE_VPD_VALID_VER_W	3
#define	NXGE_VPD_VALID_VER_F	4
#define	EXPANSION_ROM_SIZE	65536
#define	FD_MODEL		0x01
#define	FD_BD_MODEL		0x02
#define	FD_MAC_ADDR		0x04
#define	FD_NUM_MACS		0x08
#define	FD_PHY_TYPE		0x10
#define	FD_FW_VERSION		0x20
#define	FD_ALL			0x3f

npi_status_t npi_espc_pio_enable(npi_handle_t);
npi_status_t npi_espc_pio_disable(npi_handle_t);
npi_status_t npi_espc_eeprom_entry(npi_handle_t, io_op_t,
				uint32_t, uint8_t *);
npi_status_t npi_espc_mac_addr_get(npi_handle_t, uint8_t *);
npi_status_t npi_espc_num_ports_get(npi_handle_t, uint8_t *);
	npi_status_t npi_espc_num_macs_get(npi_handle_t, uint8_t *);
npi_status_t npi_espc_model_str_get(npi_handle_t, char *);
npi_status_t npi_espc_bd_model_str_get(npi_handle_t, char *);
npi_status_t npi_espc_phy_type_get(npi_handle_t, uint8_t *);
npi_status_t npi_espc_port_phy_type_get(npi_handle_t, uint8_t *,
				uint8_t);
npi_status_t npi_espc_max_frame_get(npi_handle_t, uint16_t *);
npi_status_t npi_espc_version_get(npi_handle_t, uint16_t *);
	npi_status_t npi_espc_img_sz_get(npi_handle_t, uint16_t *);
npi_status_t npi_espc_chksum_get(npi_handle_t, uint8_t *);
npi_status_t npi_espc_intr_num_get(npi_handle_t, uint8_t *);
uint32_t npi_espc_reg_get(npi_handle_t, int);
void npi_espc_dump(npi_handle_t);
npi_status_t npi_espc_vpd_info_get(npi_handle_t, p_npi_vpd_info_t, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_ESPC_H */
