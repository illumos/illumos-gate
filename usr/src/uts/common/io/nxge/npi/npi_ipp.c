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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi_ipp.h>

uint64_t ipp_fzc_offset[] = {
		IPP_CONFIG_REG,
		IPP_DISCARD_PKT_CNT_REG,
		IPP_BAD_CKSUM_ERR_CNT_REG,
		IPP_ECC_ERR_COUNTER_REG,
		IPP_INT_STATUS_REG,
		IPP_INT_MASK_REG,
		IPP_PFIFO_RD_DATA0_REG,
		IPP_PFIFO_RD_DATA1_REG,
		IPP_PFIFO_RD_DATA2_REG,
		IPP_PFIFO_RD_DATA3_REG,
		IPP_PFIFO_RD_DATA4_REG,
		IPP_PFIFO_WR_DATA0_REG,
		IPP_PFIFO_WR_DATA1_REG,
		IPP_PFIFO_WR_DATA2_REG,
		IPP_PFIFO_WR_DATA3_REG,
		IPP_PFIFO_WR_DATA4_REG,
		IPP_PFIFO_RD_PTR_REG,
		IPP_PFIFO_WR_PTR_REG,
		IPP_DFIFO_RD_DATA0_REG,
		IPP_DFIFO_RD_DATA1_REG,
		IPP_DFIFO_RD_DATA2_REG,
		IPP_DFIFO_RD_DATA3_REG,
		IPP_DFIFO_RD_DATA4_REG,
		IPP_DFIFO_WR_DATA0_REG,
		IPP_DFIFO_WR_DATA1_REG,
		IPP_DFIFO_WR_DATA2_REG,
		IPP_DFIFO_WR_DATA3_REG,
		IPP_DFIFO_WR_DATA4_REG,
		IPP_DFIFO_RD_PTR_REG,
		IPP_DFIFO_WR_PTR_REG,
		IPP_STATE_MACHINE_REG,
		IPP_CKSUM_STATUS_REG,
		IPP_FFLP_CKSUM_INFO_REG,
		IPP_DEBUG_SELECT_REG,
		IPP_DFIFO_ECC_SYNDROME_REG,
		IPP_DFIFO_EOPM_RD_PTR_REG,
		IPP_ECC_CTRL_REG
};

const char *ipp_fzc_name[] = {
		"IPP_CONFIG_REG",
		"IPP_DISCARD_PKT_CNT_REG",
		"IPP_BAD_CKSUM_ERR_CNT_REG",
		"IPP_ECC_ERR_COUNTER_REG",
		"IPP_INT_STATUS_REG",
		"IPP_INT_MASK_REG",
		"IPP_PFIFO_RD_DATA0_REG",
		"IPP_PFIFO_RD_DATA1_REG",
		"IPP_PFIFO_RD_DATA2_REG",
		"IPP_PFIFO_RD_DATA3_REG",
		"IPP_PFIFO_RD_DATA4_REG",
		"IPP_PFIFO_WR_DATA0_REG",
		"IPP_PFIFO_WR_DATA1_REG",
		"IPP_PFIFO_WR_DATA2_REG",
		"IPP_PFIFO_WR_DATA3_REG",
		"IPP_PFIFO_WR_DATA4_REG",
		"IPP_PFIFO_RD_PTR_REG",
		"IPP_PFIFO_WR_PTR_REG",
		"IPP_DFIFO_RD_DATA0_REG",
		"IPP_DFIFO_RD_DATA1_REG",
		"IPP_DFIFO_RD_DATA2_REG",
		"IPP_DFIFO_RD_DATA3_REG",
		"IPP_DFIFO_RD_DATA4_REG",
		"IPP_DFIFO_WR_DATA0_REG",
		"IPP_DFIFO_WR_DATA1_REG",
		"IPP_DFIFO_WR_DATA2_REG",
		"IPP_DFIFO_WR_DATA3_REG",
		"IPP_DFIFO_WR_DATA4_REG",
		"IPP_DFIFO_RD_PTR_REG",
		"IPP_DFIFO_WR_PTR_REG",
		"IPP_STATE_MACHINE_REG",
		"IPP_CKSUM_STATUS_REG",
		"IPP_FFLP_CKSUM_INFO_REG",
		"IPP_DEBUG_SELECT_REG",
		"IPP_DFIFO_ECC_SYNDROME_REG",
		"IPP_DFIFO_EOPM_RD_PTR_REG",
		"IPP_ECC_CTRL_REG",
};

npi_status_t
npi_ipp_dump_regs(npi_handle_t handle, uint8_t port)
{
	uint64_t		value, offset;
	int 			num_regs, i;

	ASSERT(IS_PORT_NUM_VALID(port));

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nIPP PORT Register Dump for port %d\n", port));

	num_regs = sizeof (ipp_fzc_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		offset = IPP_REG_ADDR(port, ipp_fzc_offset[i]);
#if defined(__i386)
		NXGE_REG_RD64(handle, (uint32_t)offset, &value);
#else
		NXGE_REG_RD64(handle, offset, &value);
#endif
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    offset, ipp_fzc_name[i], value));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n IPP FZC Register Dump for port %d done\n", port));

	return (NPI_SUCCESS);
}

void
npi_ipp_read_regs(npi_handle_t handle, uint8_t port)
{
	uint64_t		value, offset;
	int 			num_regs, i;

	ASSERT(IS_PORT_NUM_VALID(port));

	NPI_DEBUG_MSG((handle.function, NPI_IPP_CTL,
	    "\nIPP PORT Register read (to clear) for port %d\n", port));

	num_regs = sizeof (ipp_fzc_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		offset = IPP_REG_ADDR(port, ipp_fzc_offset[i]);
#if defined(__i386)
		NXGE_REG_RD64(handle, (uint32_t)offset, &value);
#else
		NXGE_REG_RD64(handle, offset, &value);
#endif
	}

}

/*
 * IPP Reset Routine
 */
npi_status_t
npi_ipp_reset(npi_handle_t handle, uint8_t portn)
{
	uint64_t val = 0;
	uint32_t cnt = MAX_PIO_RETRIES;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);
	val |= IPP_SOFT_RESET;
	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);

	do {
		NXGE_DELAY(IPP_RESET_WAIT);
		IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);
		cnt--;
	} while (((val & IPP_SOFT_RESET) != 0) && (cnt > 0));

	if (cnt == 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_reset"
		    " HW Error: IPP_RESET  <0x%x>", val));
		return (NPI_FAILURE | NPI_IPP_RESET_FAILED(portn));
	}

	return (NPI_SUCCESS);
}


/*
 * IPP Configuration Routine
 */
npi_status_t
npi_ipp_config(npi_handle_t handle, config_op_t op, uint8_t portn,
		ipp_config_t config)
{
	uint64_t val = 0;

	ASSERT(IS_PORT_NUM_VALID(portn));

	switch (op) {

	case ENABLE:
	case DISABLE:
		if ((config == 0) || ((config & ~CFG_IPP_ALL) != 0)) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_ipp_config",
			    " Invalid Input config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_IPP_CONFIG_INVALID(portn));
		}

		IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);

		if (op == ENABLE)
			val |= config;
		else
			val &= ~config;
		break;

	case INIT:
		if ((config & ~CFG_IPP_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_ipp_config"
			    " Invalid Input config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_IPP_CONFIG_INVALID(portn));
		}
		IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);


		val &= (IPP_IP_MAX_PKT_BYTES_MASK);
		val |= config;
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_config"
		    " Invalid Input op <0x%x>", op));
		return (NPI_FAILURE | NPI_IPP_OPCODE_INVALID(portn));
	}

	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_set_max_pktsize(npi_handle_t handle, uint8_t portn, uint32_t bytes)
{
	uint64_t val = 0;

	ASSERT(IS_PORT_NUM_VALID(portn));

	if (bytes > IPP_IP_MAX_PKT_BYTES_MASK) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_set_max_pktsize"
		    " Invalid Input Max bytes <0x%x>",
		    bytes));
		return (NPI_FAILURE | NPI_IPP_MAX_PKT_BYTES_INVALID(portn));
	}

	IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);
	val &= ~(IPP_IP_MAX_PKT_BYTES_MASK << IPP_IP_MAX_PKT_BYTES_SHIFT);

	val |= (bytes << IPP_IP_MAX_PKT_BYTES_SHIFT);
	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);

	return (NPI_SUCCESS);
}

/*
 * IPP Interrupt Configuration Routine
 */
npi_status_t
npi_ipp_iconfig(npi_handle_t handle, config_op_t op, uint8_t portn,
		ipp_iconfig_t iconfig)
{
	uint64_t val = 0;

	ASSERT(IS_PORT_NUM_VALID(portn));

	switch (op) {
	case ENABLE:
	case DISABLE:

		if ((iconfig == 0) || ((iconfig & ~ICFG_IPP_ALL) != 0)) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_ipp_iconfig"
			    " Invalid Input iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_IPP_CONFIG_INVALID(portn));
		}

		IPP_REG_RD(handle, portn, IPP_INT_MASK_REG, &val);
		if (op == ENABLE)
			val &= ~iconfig;
		else
			val |= iconfig;
		IPP_REG_WR(handle, portn, IPP_INT_MASK_REG, val);

		break;
	case INIT:

		if ((iconfig & ~ICFG_IPP_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_ipp_iconfig"
			    " Invalid Input iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_IPP_CONFIG_INVALID(portn));
		}
		IPP_REG_WR(handle, portn, IPP_INT_MASK_REG, ~iconfig);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_iconfig"
		    " Invalid Input iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_IPP_OPCODE_INVALID(portn));
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_status(npi_handle_t handle, uint8_t portn, ipp_status_t *status)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_INT_STATUS_REG, &val);

	status->value = val;
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_pfifo_rd_ptr(npi_handle_t handle, uint8_t portn, uint16_t *rd_ptr)
{
	uint64_t value;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_PFIFO_RD_PTR_REG, &value);
	*rd_ptr = value & 0xfff;
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_pfifo_wr_ptr(npi_handle_t handle, uint8_t portn, uint16_t *wr_ptr)
{
	uint64_t value;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_PFIFO_WR_PTR_REG, &value);
	*wr_ptr = value & 0xfff;
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_dfifo_rd_ptr(npi_handle_t handle, uint8_t portn, uint16_t *rd_ptr)
{
	uint64_t value;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_DFIFO_RD_PTR_REG, &value);
	*rd_ptr = (uint16_t)(value & ((portn < 2) ? IPP_XMAC_DFIFO_PTR_MASK :
	    IPP_BMAC_DFIFO_PTR_MASK));
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_dfifo_wr_ptr(npi_handle_t handle, uint8_t portn, uint16_t *wr_ptr)
{
	uint64_t value;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_DFIFO_WR_PTR_REG, &value);
	*wr_ptr = (uint16_t)(value & ((portn < 2) ? IPP_XMAC_DFIFO_PTR_MASK :
	    IPP_BMAC_DFIFO_PTR_MASK));
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_write_pfifo(npi_handle_t handle, uint8_t portn, uint8_t addr,
		uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3, uint32_t d4)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	if (addr >= 64) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_write_pfifo"
		    " Invalid PFIFO address <0x%x>", addr));
		return (NPI_FAILURE | NPI_IPP_FIFO_ADDR_INVALID(portn));
	}

	IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);
	val |= IPP_PRE_FIFO_PIO_WR_EN;
	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);

	IPP_REG_WR(handle, portn, IPP_PFIFO_WR_PTR_REG, addr);
	IPP_REG_WR(handle, portn, IPP_PFIFO_WR_DATA0_REG, d0);
	IPP_REG_WR(handle, portn, IPP_PFIFO_WR_DATA1_REG, d1);
	IPP_REG_WR(handle, portn, IPP_PFIFO_WR_DATA2_REG, d2);
	IPP_REG_WR(handle, portn, IPP_PFIFO_WR_DATA3_REG, d3);
	IPP_REG_WR(handle, portn, IPP_PFIFO_WR_DATA4_REG, d4);

	val &= ~IPP_PRE_FIFO_PIO_WR_EN;
	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_read_pfifo(npi_handle_t handle, uint8_t portn, uint8_t addr,
		uint32_t *d0, uint32_t *d1, uint32_t *d2, uint32_t *d3,
		uint32_t *d4)
{
	ASSERT(IS_PORT_NUM_VALID(portn));

	if (addr >= 64) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_read_pfifo"
		    " Invalid PFIFO address <0x%x>", addr));
		return (NPI_FAILURE | NPI_IPP_FIFO_ADDR_INVALID(portn));
	}

	IPP_REG_WR(handle, portn, IPP_PFIFO_RD_PTR_REG, addr);
	IPP_REG_RD(handle, portn, IPP_PFIFO_RD_DATA0_REG, d0);
	IPP_REG_RD(handle, portn, IPP_PFIFO_RD_DATA1_REG, d1);
	IPP_REG_RD(handle, portn, IPP_PFIFO_RD_DATA2_REG, d2);
	IPP_REG_RD(handle, portn, IPP_PFIFO_RD_DATA3_REG, d3);
	IPP_REG_RD(handle, portn, IPP_PFIFO_RD_DATA4_REG, d4);

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_write_dfifo(npi_handle_t handle, uint8_t portn, uint16_t addr,
		uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3, uint32_t d4)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	if (addr >= 2048) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_write_dfifo"
		    " Invalid DFIFO address <0x%x>", addr));
		return (NPI_FAILURE | NPI_IPP_FIFO_ADDR_INVALID(portn));
	}

	IPP_REG_RD(handle, portn, IPP_CONFIG_REG, &val);
	val |= IPP_DFIFO_PIO_WR_EN;
	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);

	IPP_REG_WR(handle, portn, IPP_DFIFO_WR_PTR_REG, addr);
	IPP_REG_WR(handle, portn, IPP_DFIFO_WR_DATA0_REG, d0);
	IPP_REG_WR(handle, portn, IPP_DFIFO_WR_DATA1_REG, d1);
	IPP_REG_WR(handle, portn, IPP_DFIFO_WR_DATA2_REG, d2);
	IPP_REG_WR(handle, portn, IPP_DFIFO_WR_DATA3_REG, d3);
	IPP_REG_WR(handle, portn, IPP_DFIFO_WR_DATA4_REG, d4);

	val &= ~IPP_DFIFO_PIO_WR_EN;
	IPP_REG_WR(handle, portn, IPP_CONFIG_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_read_dfifo(npi_handle_t handle, uint8_t portn, uint16_t addr,
		uint32_t *d0, uint32_t *d1, uint32_t *d2, uint32_t *d3,
		uint32_t *d4)
{
	ASSERT(IS_PORT_NUM_VALID(portn));

	if (addr >= 2048) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ipp_read_dfifo"
		    " Invalid DFIFO address <0x%x>", addr));
		return (NPI_FAILURE | NPI_IPP_FIFO_ADDR_INVALID(portn));
	}

	IPP_REG_WR(handle, portn, IPP_DFIFO_RD_PTR_REG, addr);
	IPP_REG_RD(handle, portn, IPP_DFIFO_RD_DATA0_REG, d0);
	IPP_REG_RD(handle, portn, IPP_DFIFO_RD_DATA1_REG, d1);
	IPP_REG_RD(handle, portn, IPP_DFIFO_RD_DATA2_REG, d2);
	IPP_REG_RD(handle, portn, IPP_DFIFO_RD_DATA3_REG, d3);
	IPP_REG_RD(handle, portn, IPP_DFIFO_RD_DATA4_REG, d4);

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_ecc_syndrome(npi_handle_t handle, uint8_t portn, uint16_t *syndrome)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_DFIFO_ECC_SYNDROME_REG, &val);

	*syndrome = (uint16_t)val;
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_dfifo_eopm_rdptr(npi_handle_t handle, uint8_t portn,
							uint16_t *rdptr)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_DFIFO_EOPM_RD_PTR_REG, &val);

	*rdptr = (uint16_t)val;
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_state_mach(npi_handle_t handle, uint8_t portn, uint32_t *sm)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_STATE_MACHINE_REG, &val);

	*sm = (uint32_t)val;
	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_ecc_err_count(npi_handle_t handle, uint8_t portn, uint8_t *err_cnt)
{
	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_ECC_ERR_COUNTER_REG, err_cnt);

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_pkt_dis_count(npi_handle_t handle, uint8_t portn, uint16_t *dis_cnt)
{
	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_DISCARD_PKT_CNT_REG, dis_cnt);

	return (NPI_SUCCESS);
}

npi_status_t
npi_ipp_get_cs_err_count(npi_handle_t handle, uint8_t portn, uint16_t *err_cnt)
{
	ASSERT(IS_PORT_NUM_VALID(portn));

	IPP_REG_RD(handle, portn, IPP_BAD_CKSUM_ERR_CNT_REG, err_cnt);

	return (NPI_SUCCESS);
}
