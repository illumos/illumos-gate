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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi_espc.h>
#include <nxge_espc.h>

npi_status_t
npi_espc_pio_enable(npi_handle_t handle)
{
	NXGE_REG_WR64(handle, ESPC_REG_ADDR(ESPC_PIO_EN_REG), 0x1);
	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_pio_disable(npi_handle_t handle)
{
	NXGE_REG_WR64(handle, ESPC_PIO_EN_REG, 0);
	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_eeprom_entry(npi_handle_t handle, io_op_t op, uint32_t addr,
			uint8_t *data)
{
	uint64_t val = 0;

	if ((addr & ~EPC_EEPROM_ADDR_BITS) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			" npi_espc_eerprom_entry"
			" Invalid input addr <0x%x>\n",
			addr));
		return (NPI_FAILURE | NPI_ESPC_EEPROM_ADDR_INVALID);
	}

	switch (op) {
	case OP_SET:
		val = EPC_WRITE_INITIATE | (addr << EPC_EEPROM_ADDR_SHIFT) |
			*data;
		NXGE_REG_WR64(handle, ESPC_REG_ADDR(ESPC_PIO_STATUS_REG), val);
		EPC_WAIT_RW_COMP(handle, &val, EPC_WRITE_COMPLETE);
		if ((val & EPC_WRITE_COMPLETE) == 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				" npi_espc_eeprom_entry"
				" HW Error: EEPROM_WR <0x%x>\n",
				val));
			return (NPI_FAILURE | NPI_ESPC_EEPROM_WRITE_FAILED);
		}
		break;
	case OP_GET:
		val = EPC_READ_INITIATE | (addr << EPC_EEPROM_ADDR_SHIFT);
		NXGE_REG_WR64(handle, ESPC_REG_ADDR(ESPC_PIO_STATUS_REG), val);
		EPC_WAIT_RW_COMP(handle, &val, EPC_READ_COMPLETE);
		if ((val & EPC_READ_COMPLETE) == 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				" npi_espc_eeprom_entry"
				" HW Error: EEPROM_RD <0x%x>",
				val));
			return (NPI_FAILURE | NPI_ESPC_EEPROM_READ_FAILED);
		}
		NXGE_REG_RD64(handle, ESPC_REG_ADDR(ESPC_PIO_STATUS_REG), &val);
		*data = val & EPC_EEPROM_DATA_MASK;
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " npi_espc_eeprom_entry"
				    " Invalid Input addr <0x%x>\n", addr));
		return (NPI_FAILURE | NPI_ESPC_OPCODE_INVALID);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_mac_addr_get(npi_handle_t handle, uint8_t *data)
{
	mac_addr_0_t mac0;
	mac_addr_1_t mac1;

	NXGE_REG_RD64(handle, ESPC_MAC_ADDR_0, &mac0.value);
	data[0] = mac0.bits.w0.byte0;
	data[1] = mac0.bits.w0.byte1;
	data[2] = mac0.bits.w0.byte2;
	data[3] = mac0.bits.w0.byte3;

	NXGE_REG_RD64(handle, ESPC_MAC_ADDR_1, &mac1.value);
	data[4] = mac1.bits.w0.byte4;
	data[5] = mac1.bits.w0.byte5;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_num_ports_get(npi_handle_t handle, uint8_t *data)
{
	uint64_t val = 0;

	NXGE_REG_RD64(handle, ESPC_NUM_PORTS_MACS, &val);
	val &= NUM_PORTS_MASK;
	*data = (uint8_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_num_macs_get(npi_handle_t handle, uint8_t *data)
{
	uint64_t val = 0;

	NXGE_REG_RD64(handle, ESPC_NUM_PORTS_MACS, &val);
	val &= NUM_MAC_ADDRS_MASK;
	val = (val >> NUM_MAC_ADDRS_SHIFT);
	*data = (uint8_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_model_str_get(npi_handle_t handle, char *data)
{
	uint64_t val = 0;
	uint16_t str_len;
	int i, j;

	NXGE_REG_RD64(handle, ESPC_MOD_STR_LEN, &val);
	val &= MOD_STR_LEN_MASK;
	str_len = (uint8_t)val;

	if (str_len > MAX_MOD_STR_LEN) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				" npi_espc_model_str_get"
				" Model string length %d exceeds max %d\n",
				str_len, MAX_MOD_STR_LEN));
		return (NPI_FAILURE | NPI_ESPC_STR_LEN_INVALID);
	}

	/*
	 * Might have to reverse the order depending on how the string
	 * is written.
	 */
	for (i = 0, j = 0; i < str_len; j++) {
		NXGE_REG_RD64(handle, ESPC_MOD_STR(j), &val);
		data[i++] = ((char *)&val)[3];
		data[i++] = ((char *)&val)[2];
		data[i++] = ((char *)&val)[1];
		data[i++] = ((char *)&val)[0];
	}

	data[str_len] = '\0';

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_bd_model_str_get(npi_handle_t handle, char *data)
{
	uint64_t val = 0;
	uint16_t str_len;
	int i, j;

	NXGE_REG_RD64(handle, ESPC_BD_MOD_STR_LEN, &val);
	val &= BD_MOD_STR_LEN_MASK;
	str_len = (uint8_t)val;

	if (str_len > MAX_BD_MOD_STR_LEN) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				" npi_espc_model_str_get"
				" Board Model string length %d "
				"exceeds max %d\n",
				str_len, MAX_BD_MOD_STR_LEN));
		return (NPI_FAILURE | NPI_ESPC_STR_LEN_INVALID);
	}

	/*
	 * Might have to reverse the order depending on how the string
	 * is written.
	 */
	for (i = 0, j = 0; i < str_len; j++) {
		NXGE_REG_RD64(handle, ESPC_BD_MOD_STR(j), &val);
		data[i++] = ((char *)&val)[3];
		data[i++] = ((char *)&val)[2];
		data[i++] = ((char *)&val)[1];
		data[i++] = ((char *)&val)[0];
	}

	data[str_len] = '\0';

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_phy_type_get(npi_handle_t handle, uint8_t *data)
{
	phy_type_t	phy;

	NXGE_REG_RD64(handle, ESPC_PHY_TYPE, &phy.value);
	data[0] = phy.bits.w0.pt0_phy_type;
	data[1] = phy.bits.w0.pt1_phy_type;
	data[2] = phy.bits.w0.pt2_phy_type;
	data[3] = phy.bits.w0.pt3_phy_type;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_port_phy_type_get(npi_handle_t handle, uint8_t *data, uint8_t portn)
{
	phy_type_t	phy;

	ASSERT(IS_PORT_NUM_VALID(portn));

	NXGE_REG_RD64(handle, ESPC_PHY_TYPE, &phy.value);
	switch (portn) {
	case 0:
		*data = phy.bits.w0.pt0_phy_type;
		break;
	case 1:
		*data = phy.bits.w0.pt1_phy_type;
		break;
	case 2:
		*data = phy.bits.w0.pt2_phy_type;
		break;
	case 3:
		*data = phy.bits.w0.pt3_phy_type;
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				" npi_espc_port_phy_type_get"
				" Invalid Input: portn <%d>",
				portn));
		return (NPI_FAILURE | NPI_ESPC_PORT_INVALID);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_max_frame_get(npi_handle_t handle, uint16_t *data)
{
	uint64_t val = 0;

	NXGE_REG_RD64(handle, ESPC_MAX_FM_SZ, &val);
	val &= MAX_FM_SZ_MASK;
	*data = (uint8_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_version_get(npi_handle_t handle, uint16_t *data)
{
	uint64_t val = 0;

	NXGE_REG_RD64(handle, ESPC_VER_IMGSZ, &val);
	val &= VER_NUM_MASK;
	*data = (uint8_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_img_sz_get(npi_handle_t handle, uint16_t *data)
{
	uint64_t val = 0;

	NXGE_REG_RD64(handle, ESPC_VER_IMGSZ, &val);
	val &= IMG_SZ_MASK;
	val = val >> IMG_SZ_SHIFT;
	*data = (uint8_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_chksum_get(npi_handle_t handle, uint8_t *data)
{
	uint64_t val = 0;

	NXGE_REG_RD64(handle, ESPC_CHKSUM, &val);
	val &= CHKSUM_MASK;
	*data = (uint8_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_espc_intr_num_get(npi_handle_t handle, uint8_t *data)
{
	intr_num_t	intr;

	NXGE_REG_RD64(handle, ESPC_INTR_NUM, &intr.value);
	data[0] = intr.bits.w0.pt0_intr_num;
	data[1] = intr.bits.w0.pt1_intr_num;
	data[2] = intr.bits.w0.pt2_intr_num;
	data[3] = intr.bits.w0.pt3_intr_num;

	return (NPI_SUCCESS);
}

void
npi_espc_dump(npi_handle_t handle)
{
	int i;
	uint64_t val = 0;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
				    "Dumping SEEPROM registers directly:\n\n"));

	for (i = 0; i < 23; i++) {
		NXGE_REG_RD64(handle, ESPC_NCR_REGN(i), &val);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
					    "reg[%d]      0x%llx\n",
					    i, val & 0xffffffff));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "\n\n"));
}

uint32_t
npi_espc_reg_get(npi_handle_t handle, int reg_idx)
{
	uint64_t val = 0;
	uint32_t reg_val = 0;

	NXGE_REG_RD64(handle, ESPC_NCR_REGN(reg_idx), &val);
	reg_val = val & 0xffffffff;

	return (reg_val);
}
