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

#include <npi_zcp.h>

static int zcp_mem_read(npi_handle_t, uint16_t, uint8_t,
	uint16_t, zcp_ram_unit_t *);
static int zcp_mem_write(npi_handle_t, uint16_t, uint8_t,
	uint32_t, uint16_t, zcp_ram_unit_t *);

npi_status_t
npi_zcp_config(npi_handle_t handle, config_op_t op, zcp_config_t config)
{
	uint64_t val = 0;

	switch (op) {
	case ENABLE:
	case DISABLE:
		if ((config == 0) || (config & ~CFG_ZCP_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_config"
			    " Invalid Input: config <0x%x>",
			    config));
			return (NPI_FAILURE | NPI_ZCP_CONFIG_INVALID);
		}

		NXGE_REG_RD64(handle, ZCP_CONFIG_REG, &val);
		if (op == ENABLE) {
			if (config & CFG_ZCP)
				val |= ZC_ENABLE;
			if (config & CFG_ZCP_ECC_CHK)
				val &= ~ECC_CHK_DIS;
			if (config & CFG_ZCP_PAR_CHK)
				val &= ~PAR_CHK_DIS;
			if (config & CFG_ZCP_BUF_RESP)
				val &= ~DIS_BUFF_RN;
			if (config & CFG_ZCP_BUF_REQ)
				val &= ~DIS_BUFF_RQ_IF;
		} else {
			if (config & CFG_ZCP)
				val &= ~ZC_ENABLE;
			if (config & CFG_ZCP_ECC_CHK)
				val |= ECC_CHK_DIS;
			if (config & CFG_ZCP_PAR_CHK)
				val |= PAR_CHK_DIS;
			if (config & CFG_ZCP_BUF_RESP)
				val |= DIS_BUFF_RN;
			if (config & CFG_ZCP_BUF_REQ)
				val |= DIS_BUFF_RQ_IF;
		}
		NXGE_REG_WR64(handle, ZCP_CONFIG_REG, val);

		break;
	case INIT:
		NXGE_REG_RD64(handle, ZCP_CONFIG_REG, &val);
		val &= ((ZCP_DEBUG_SEL_MASK) | (RDMA_TH_MASK));
		if (config & CFG_ZCP)
			val |= ZC_ENABLE;
		else
			val &= ~ZC_ENABLE;
		if (config & CFG_ZCP_ECC_CHK)
			val &= ~ECC_CHK_DIS;
		else
			val |= ECC_CHK_DIS;
		if (config & CFG_ZCP_PAR_CHK)
			val &= ~PAR_CHK_DIS;
		else
			val |= PAR_CHK_DIS;
		if (config & CFG_ZCP_BUF_RESP)
			val &= ~DIS_BUFF_RN;
		else
			val |= DIS_BUFF_RN;
		if (config & CFG_ZCP_BUF_REQ)
			val &= DIS_BUFF_RQ_IF;
		else
			val |= DIS_BUFF_RQ_IF;
		NXGE_REG_WR64(handle, ZCP_CONFIG_REG, val);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_config"
		    " Invalid Input: config <0x%x>",
		    config));
		return (NPI_FAILURE | NPI_ZCP_OPCODE_INVALID);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_iconfig(npi_handle_t handle, config_op_t op, zcp_iconfig_t iconfig)
{
	uint64_t val = 0;

	switch (op) {
	case ENABLE:
	case DISABLE:
		if ((iconfig == 0) || (iconfig & ~ICFG_ZCP_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_ZCP_CONFIG_INVALID);
		}

		NXGE_REG_RD64(handle, ZCP_INT_MASK_REG, &val);
		if (op == ENABLE)
			val |= iconfig;
		else
			val &= ~iconfig;
		NXGE_REG_WR64(handle, ZCP_INT_MASK_REG, val);

		break;

	case INIT:
		if ((iconfig & ~ICFG_ZCP_ALL) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_iconfig"
			    " Invalid Input: iconfig <0x%x>",
			    iconfig));
			return (NPI_FAILURE | NPI_ZCP_CONFIG_INVALID);
		}
		val = (uint64_t)iconfig;
		NXGE_REG_WR64(handle, ZCP_INT_MASK_REG, val);

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_iconfig"
		    " Invalid Input: iconfig <0x%x>",
		    iconfig));
		return (NPI_FAILURE | NPI_ZCP_OPCODE_INVALID);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_get_istatus(npi_handle_t handle, zcp_iconfig_t *istatus)
{
	uint64_t val;

	NXGE_REG_RD64(handle, ZCP_INT_STAT_REG, &val);
	*istatus = (uint32_t)val;

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_clear_istatus(npi_handle_t handle)
{
	uint64_t val;

	val = (uint64_t)0xffff;
	NXGE_REG_WR64(handle, ZCP_INT_STAT_REG, val);
	return (NPI_SUCCESS);
}


npi_status_t
npi_zcp_set_dma_thresh(npi_handle_t handle, uint16_t dma_thres)
{
	uint64_t val = 0;

	if ((dma_thres & ~RDMA_TH_BITS) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_set_dma_thresh"
		    " Invalid Input: dma_thres <0x%x>",
		    dma_thres));
		return (NPI_FAILURE | NPI_ZCP_DMA_THRES_INVALID);
	}

	NXGE_REG_RD64(handle, ZCP_CONFIG_REG, &val);

	val &= ~RDMA_TH_MASK;
	val |= (dma_thres << RDMA_TH_SHIFT);

	NXGE_REG_WR64(handle, ZCP_CONFIG_REG, val);

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_set_bam_region(npi_handle_t handle, zcp_buf_region_t region,
			zcp_bam_region_reg_t *region_attr)
{

	ASSERT(IS_VALID_BAM_REGION(region));
	if (!IS_VALID_BAM_REGION(region)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_set_bam_region"
		    " Invalid Input: region <0x%x>",
		    region));
		return (NPI_FAILURE | ZCP_BAM_REGION_INVALID);
	}

	switch (region) {
	case BAM_4BUF:
		NXGE_REG_WR64(handle, ZCP_BAM4_RE_CTL_REG, region_attr->value);
		break;
	case BAM_8BUF:
		NXGE_REG_WR64(handle, ZCP_BAM8_RE_CTL_REG, region_attr->value);
		break;
	case BAM_16BUF:
		NXGE_REG_WR64(handle, ZCP_BAM16_RE_CTL_REG, region_attr->value);
		break;
	case BAM_32BUF:
		NXGE_REG_WR64(handle, ZCP_BAM32_RE_CTL_REG, region_attr->value);
		break;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_set_dst_region(npi_handle_t handle, zcp_buf_region_t region,
				uint16_t row_idx)
{
	uint64_t val = 0;

	ASSERT(IS_VALID_BAM_REGION(region));
	if (!IS_VALID_BAM_REGION(region)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_set_dst_region"
		    " Invalid Input: region <0x%x>",
		    region));
		return (NPI_FAILURE | NPI_ZCP_BAM_REGION_INVALID);
	}

	if ((row_idx & ~0x3FF) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_set_dst_region"
		    " Invalid Input: row_idx", row_idx));
		return (NPI_FAILURE | NPI_ZCP_ROW_INDEX_INVALID);
	}

	val = (uint64_t)row_idx;

	switch (region) {
	case BAM_4BUF:
		NXGE_REG_WR64(handle, ZCP_DST4_RE_CTL_REG, val);
		break;
	case BAM_8BUF:
		NXGE_REG_WR64(handle, ZCP_DST8_RE_CTL_REG, val);
		break;
	case BAM_16BUF:
		NXGE_REG_WR64(handle, ZCP_DST16_RE_CTL_REG, val);
		break;
	case BAM_32BUF:
		NXGE_REG_WR64(handle, ZCP_DST32_RE_CTL_REG, val);
		break;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_tt_static_entry(npi_handle_t handle, io_op_t op, uint16_t flow_id,
			tte_sflow_attr_mask_t mask, tte_sflow_attr_t *sflow)
{
	uint32_t		byte_en = 0;
	tte_sflow_attr_t	val;

	if ((op != OP_SET) && (op != OP_GET)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_static_entry"
		    " Invalid Input: op <0x%x>",
		    op));
		return (NPI_FAILURE | NPI_ZCP_OPCODE_INVALID);
	}

	if ((mask & TTE_SFLOW_ATTR_ALL) == 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_static_entry"
		    " Invalid Input: mask <0x%x>",
		    mask));
		return (NPI_FAILURE | NPI_ZCP_SFLOW_ATTR_INVALID);
	}

	if ((flow_id & ~0x0FFF) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_static_entry"
		    " Invalid Input: flow_id<0x%x>",
		    flow_id));
		return (NPI_FAILURE | NPI_ZCP_FLOW_ID_INVALID);
	}

	if (zcp_mem_read(handle, flow_id, ZCP_RAM_SEL_TT_STATIC, NULL,
	    (zcp_ram_unit_t *)&val) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_static_entry"
		    " HW Error: ZCP_RAM_ACC <0x%x>",
		    NULL));
		return (NPI_FAILURE | NPI_ZCP_MEM_READ_FAILED);
	}

	if (op == OP_SET) {
		if (mask & TTE_RDC_TBL_OFF) {
			val.qw0.bits.ldw.rdc_tbl_offset =
			    sflow->qw0.bits.ldw.rdc_tbl_offset;
			byte_en |= TTE_RDC_TBL_SFLOW_BITS_EN;
		}
		if (mask & TTE_BUF_SIZE) {
			val.qw0.bits.ldw.buf_size =
			    sflow->qw0.bits.ldw.buf_size;
			byte_en |= TTE_BUF_SIZE_BITS_EN;
		}
		if (mask & TTE_NUM_BUF) {
			val.qw0.bits.ldw.num_buf = sflow->qw0.bits.ldw.num_buf;
			byte_en |= TTE_NUM_BUF_BITS_EN;
		}
		if (mask & TTE_ULP_END) {
			val.qw0.bits.ldw.ulp_end = sflow->qw0.bits.ldw.ulp_end;
			byte_en |=  TTE_ULP_END_BITS_EN;
		}
		if (mask & TTE_ULP_END) {
			val.qw1.bits.ldw.ulp_end = sflow->qw1.bits.ldw.ulp_end;
			byte_en |= TTE_ULP_END_BITS_EN;
		}
		if (mask & TTE_ULP_END_EN) {
			val.qw1.bits.ldw.ulp_end_en =
			    sflow->qw1.bits.ldw.ulp_end_en;
			byte_en |= TTE_ULP_END_EN_BITS_EN;
		}
		if (mask & TTE_UNMAP_ALL_EN) {
			val.qw1.bits.ldw.unmap_all_en =
			    sflow->qw1.bits.ldw.unmap_all_en;
			byte_en |= TTE_UNMAP_ALL_EN;
		}
		if (mask & TTE_TMODE) {
			val.qw1.bits.ldw.tmode = sflow->qw1.bits.ldw.tmode;
			byte_en |= TTE_TMODE_BITS_EN;
		}
		if (mask & TTE_SKIP) {
			val.qw1.bits.ldw.skip = sflow->qw1.bits.ldw.skip;
			byte_en |= TTE_SKIP_BITS_EN;
		}
		if (mask & TTE_HBM_RING_BASE_ADDR) {
			val.qw1.bits.ldw.ring_base =
			    sflow->qw1.bits.ldw.ring_base;
			byte_en |= TTE_RING_BASE_ADDR_BITS_EN;
		}
		if (mask & TTE_HBM_RING_BASE_ADDR) {
			val.qw2.bits.ldw.ring_base =
			    sflow->qw2.bits.ldw.ring_base;
			byte_en |= TTE_RING_BASE_ADDR_BITS_EN;
		}
		if (mask & TTE_HBM_RING_SIZE) {
			val.qw2.bits.ldw.ring_size =
			    sflow->qw2.bits.ldw.ring_size;
			byte_en |= TTE_RING_SIZE_BITS_EN;
		}
		if (mask & TTE_HBM_BUSY) {
			val.qw2.bits.ldw.busy = sflow->qw2.bits.ldw.busy;
			byte_en |= TTE_BUSY_BITS_EN;
		}
		if (mask & TTE_HBM_TOQ) {
			val.qw3.bits.ldw.toq = sflow->qw3.bits.ldw.toq;
			byte_en |= TTE_TOQ_BITS_EN;
		}

		if (zcp_mem_write(handle, flow_id, ZCP_RAM_SEL_TT_STATIC,
		    byte_en, NULL,
		    (zcp_ram_unit_t *)&val) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_tt_static_entry"
			    " HW Error: ZCP_RAM_ACC <0x%x>",
			    NULL));
			return (NPI_FAILURE | NPI_ZCP_MEM_WRITE_FAILED);
		}
	} else {
		sflow->qw0.value = val.qw0.value;
		sflow->qw1.value = val.qw1.value;
		sflow->qw2.value = val.qw2.value;
		sflow->qw3.value = val.qw3.value;
		sflow->qw4.value = val.qw4.value;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_tt_dynamic_entry(npi_handle_t handle, io_op_t op, uint16_t flow_id,
			tte_dflow_attr_mask_t mask, tte_dflow_attr_t *dflow)
{
	uint32_t		byte_en = 0;
	tte_dflow_attr_t	val;

	if ((op != OP_SET) && (op != OP_GET)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_dynamic_entry"
		    " Invalid Input: op <0x%x>", op));
		return (NPI_FAILURE | NPI_ZCP_OPCODE_INVALID);
	}

	if ((mask & TTE_DFLOW_ATTR_ALL) == 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_dynamic_entry"
		    " Invalid Input: mask <0x%x>",
		    mask));
		return (NPI_FAILURE | NPI_ZCP_DFLOW_ATTR_INVALID);
	}

	if ((flow_id & ~0x0FFF) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_dynamic_entry"
		    " Invalid Input: flow_id <0x%x>",
		    flow_id));
		return (NPI_FAILURE | NPI_ZCP_FLOW_ID_INVALID);
	}

	if (zcp_mem_read(handle, flow_id, ZCP_RAM_SEL_TT_DYNAMIC, NULL,
	    (zcp_ram_unit_t *)&val) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_dynamic_entry"
		    " HW Error: ZCP_RAM_ACC <0x%x>",
		    NULL));
		return (NPI_FAILURE | NPI_ZCP_MEM_READ_FAILED);
	}

	if (op == OP_SET) {

		/* Get data read */
		if (mask & TTE_MAPPED_IN) {
			val.qw0.bits.ldw.mapped_in =
			    dflow->qw0.bits.ldw.mapped_in;
			byte_en |= TTE_MAPPED_IN_BITS_EN;
		}
		if (mask & TTE_ANCHOR_SEQ) {
			val.qw1.bits.ldw.anchor_seq =
			    dflow->qw1.bits.ldw.anchor_seq;
			byte_en |= TTE_ANCHOR_SEQ_BITS_EN;
		}
		if (mask & TTE_ANCHOR_OFFSET) {
			val.qw2.bits.ldw.anchor_offset =
			    dflow->qw2.bits.ldw.anchor_offset;
			byte_en |= TTE_ANCHOR_OFFSET_BITS_EN;
		}
		if (mask & TTE_ANCHOR_BUFFER) {
			val.qw2.bits.ldw.anchor_buf =
			    dflow->qw2.bits.ldw.anchor_buf;
			byte_en |= TTE_ANCHOR_BUFFER_BITS_EN;
		}
		if (mask & TTE_ANCHOR_BUF_FLAG) {
			val.qw2.bits.ldw.anchor_buf_flag =
			    dflow->qw2.bits.ldw.anchor_buf_flag;
			byte_en |= TTE_ANCHOR_BUF_FLAG_BITS_EN;
		}
		if (mask & TTE_UNMAP_ON_LEFT) {
			val.qw2.bits.ldw.unmap_on_left =
			    dflow->qw2.bits.ldw.unmap_on_left;
			byte_en |= TTE_UNMAP_ON_LEFT_BITS_EN;
		}
		if (mask & TTE_ULP_END_REACHED) {
			val.qw2.bits.ldw.ulp_end_reached =
			    dflow->qw2.bits.ldw.ulp_end_reached;
			byte_en |= TTE_ULP_END_REACHED_BITS_EN;
		}
		if (mask & TTE_ERR_STAT) {
			val.qw3.bits.ldw.err_stat =
			    dflow->qw3.bits.ldw.err_stat;
			byte_en |= TTE_ERR_STAT_BITS_EN;
		}
		if (mask & TTE_HBM_WR_PTR) {
			val.qw3.bits.ldw.wr_ptr = dflow->qw3.bits.ldw.wr_ptr;
			byte_en |= TTE_WR_PTR_BITS_EN;
		}
		if (mask & TTE_HBM_HOQ) {
			val.qw3.bits.ldw.hoq = dflow->qw3.bits.ldw.hoq;
			byte_en |= TTE_HOQ_BITS_EN;
		}
		if (mask & TTE_HBM_PREFETCH_ON) {
			val.qw3.bits.ldw.prefetch_on =
			    dflow->qw3.bits.ldw.prefetch_on;
			byte_en |= TTE_PREFETCH_ON_BITS_EN;
		}

		if (zcp_mem_write(handle, flow_id, ZCP_RAM_SEL_TT_DYNAMIC,
		    byte_en, NULL,
		    (zcp_ram_unit_t *)&val) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_tt_dynamic_entry"
			    " HW Error: ZCP_RAM_ACC <0x%x>",
			    NULL));
			return (NPI_FAILURE | NPI_ZCP_MEM_WRITE_FAILED);
		}
	} else {
		dflow->qw0.value = val.qw0.value;
		dflow->qw1.value = val.qw1.value;
		dflow->qw2.value = val.qw2.value;
		dflow->qw3.value = val.qw3.value;
		dflow->qw4.value = val.qw4.value;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_tt_bam_entry(npi_handle_t handle, io_op_t op, uint16_t flow_id,
			uint8_t bankn, uint8_t word_en, zcp_ram_unit_t *data)
{
	zcp_ram_unit_t val;

	if ((op != OP_SET) && (op != OP_GET)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_bam_entry"
		    " Invalid Input: op <0x%x>", op));
		return (NPI_FAILURE | NPI_ZCP_OPCODE_INVALID);
	}

	if ((flow_id & ~0x0FFF) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_dynamic_entry"
		    " Invalid Input: flow_id <0x%x>",
		    flow_id));
		return (NPI_FAILURE | NPI_ZCP_FLOW_ID_INVALID);
	}

	if (bankn >= MAX_BAM_BANKS) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_bam_entry"
		    " Invalid Input: bankn <0x%x>",
		    bankn));
		return (NPI_FAILURE | NPI_ZCP_BAM_BANK_INVALID);
	}

	if ((word_en & ~0xF) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_bam_entry"
		    " Invalid Input: word_en <0x%x>",
		    word_en));
		return (NPI_FAILURE | NPI_ZCP_BAM_WORD_EN_INVALID);
	}

	if (zcp_mem_read(handle, flow_id, ZCP_RAM_SEL_BAM0 + bankn, NULL,
	    (zcp_ram_unit_t *)&val) != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_bam_entry"
		    " HW Error: ZCP_RAM_ACC <0x%x>",
		    NULL));
		return (NPI_FAILURE | NPI_ZCP_MEM_READ_FAILED);
	}

	if (op == OP_SET) {
		if (zcp_mem_write(handle, flow_id, ZCP_RAM_SEL_BAM0 + bankn,
		    word_en, NULL,
		    (zcp_ram_unit_t *)&val) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_tt_bam_entry"
			    " HW Error: ZCP_RAM_ACC <0x%x>",
			    NULL));
			return (NPI_FAILURE | NPI_ZCP_MEM_WRITE_FAILED);
		}
	} else {
		data->w0 = val.w0;
		data->w1 = val.w1;
		data->w2 = val.w2;
		data->w3 = val.w3;
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_tt_cfifo_entry(npi_handle_t handle, io_op_t op, uint8_t portn,
			uint16_t entryn, zcp_ram_unit_t *data)
{
	if ((op != OP_SET) && (op != OP_GET)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_cfifo_entry"
		    " Invalid Input: op <0x%x>", op));
		return (NPI_FAILURE | NPI_ZCP_OPCODE_INVALID);
	}

	if (portn > 3) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_cfifo_entry"
		    " Invalid Input: portn <%d>", portn));
		return (NPI_FAILURE | NPI_ZCP_PORT_INVALID(portn));
	}

	if (op == OP_SET) {
		if (zcp_mem_write(handle, NULL, ZCP_RAM_SEL_CFIFO0 + portn,
		    0x1ffff, entryn, data) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_tt_cfifo_entry"
			    " HW Error: ZCP_RAM_ACC <0x%x>",
			    NULL));
			return (NPI_FAILURE | NPI_ZCP_MEM_WRITE_FAILED);
		}
	} else {
		if (zcp_mem_read(handle, NULL, ZCP_RAM_SEL_CFIFO0 + portn,
		    entryn, data) != 0) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_zcp_tt_cfifo_entry"
			    " HW Error: ZCP_RAM_ACC  <0x%x>",
			    NULL));
			return (NPI_FAILURE | NPI_ZCP_MEM_READ_FAILED);
		}
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_rest_cfifo_port(npi_handle_t handle, uint8_t port)
{
	uint64_t offset = ZCP_RESET_CFIFO_REG;
	zcp_reset_cfifo_t cfifo_reg;
	NXGE_REG_RD64(handle, offset, &cfifo_reg.value);
	cfifo_reg.value &= ZCP_RESET_CFIFO_MASK;

	switch (port) {
		case 0:
			cfifo_reg.bits.ldw.reset_cfifo0 = 1;
			NXGE_REG_WR64(handle, offset, cfifo_reg.value);
			cfifo_reg.bits.ldw.reset_cfifo0 = 0;

			break;
		case 1:
			cfifo_reg.bits.ldw.reset_cfifo1 = 1;
			NXGE_REG_WR64(handle, offset, cfifo_reg.value);
			cfifo_reg.bits.ldw.reset_cfifo1 = 0;
			break;
		case 2:
			cfifo_reg.bits.ldw.reset_cfifo2 = 1;
			NXGE_REG_WR64(handle, offset, cfifo_reg.value);
			cfifo_reg.bits.ldw.reset_cfifo2 = 0;
			break;
		case 3:
			cfifo_reg.bits.ldw.reset_cfifo3 = 1;
			NXGE_REG_WR64(handle, offset, cfifo_reg.value);
			cfifo_reg.bits.ldw.reset_cfifo3 = 0;
			break;
		default:
			break;
	}

	NXGE_DELAY(ZCP_CFIFIO_RESET_WAIT);
	NXGE_REG_WR64(handle, offset, cfifo_reg.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_zcp_rest_cfifo_all(npi_handle_t handle)
{
	uint64_t offset = ZCP_RESET_CFIFO_REG;
	zcp_reset_cfifo_t cfifo_reg;

	cfifo_reg.value = ZCP_RESET_CFIFO_MASK;
	NXGE_REG_WR64(handle, offset, cfifo_reg.value);
	cfifo_reg.value = 0;
	NXGE_DELAY(ZCP_CFIFIO_RESET_WAIT);
	NXGE_REG_WR64(handle, offset, cfifo_reg.value);
	return (NPI_SUCCESS);
}

static int
zcp_mem_read(npi_handle_t handle, uint16_t flow_id, uint8_t ram_sel,
		uint16_t cfifo_entryn, zcp_ram_unit_t *val)
{
	zcp_ram_access_t ram_ctl;

	ram_ctl.value = 0;
	ram_ctl.bits.ldw.ram_sel = ram_sel;
	ram_ctl.bits.ldw.zcfid = flow_id;
	ram_ctl.bits.ldw.rdwr = ZCP_RAM_RD;
	ram_ctl.bits.ldw.cfifo = cfifo_entryn;

	/* Wait for RAM ready to be read */
	ZCP_WAIT_RAM_READY(handle, ram_ctl.value);
	if (ram_ctl.bits.ldw.busy != 0) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_zcp_tt_static_entry"
		    " HW Error: ZCP_RAM_ACC <0x%x>",
		    ram_ctl.value));
		return (-1);
	}

	/* Read from RAM */
	NXGE_REG_WR64(handle, ZCP_RAM_ACC_REG, ram_ctl.value);

	/* Wait for RAM read done */
	ZCP_WAIT_RAM_READY(handle, ram_ctl.value);
	if (ram_ctl.bits.ldw.busy != 0)
		return (-1);

	/* Get data */
	NXGE_REG_RD64(handle, ZCP_RAM_DATA0_REG, &val->w0);
	NXGE_REG_RD64(handle, ZCP_RAM_DATA1_REG, &val->w1);
	NXGE_REG_RD64(handle, ZCP_RAM_DATA2_REG, &val->w2);
	NXGE_REG_RD64(handle, ZCP_RAM_DATA3_REG, &val->w3);
	NXGE_REG_RD64(handle, ZCP_RAM_DATA4_REG, &val->w4);

	return (0);
}

static int
zcp_mem_write(npi_handle_t handle, uint16_t flow_id, uint8_t ram_sel,
		uint32_t byte_en, uint16_t cfifo_entryn, zcp_ram_unit_t *val)
{
	zcp_ram_access_t	ram_ctl;
	zcp_ram_benable_t	ram_en;

	ram_ctl.value = 0;
	ram_ctl.bits.ldw.ram_sel = ram_sel;
	ram_ctl.bits.ldw.zcfid = flow_id;
	ram_ctl.bits.ldw.rdwr = ZCP_RAM_WR;
	ram_en.bits.ldw.be = byte_en;
	ram_ctl.bits.ldw.cfifo = cfifo_entryn;

	/* Setup data */
	NXGE_REG_WR64(handle, ZCP_RAM_DATA0_REG, val->w0);
	NXGE_REG_WR64(handle, ZCP_RAM_DATA1_REG, val->w1);
	NXGE_REG_WR64(handle, ZCP_RAM_DATA2_REG, val->w2);
	NXGE_REG_WR64(handle, ZCP_RAM_DATA3_REG, val->w3);
	NXGE_REG_WR64(handle, ZCP_RAM_DATA4_REG, val->w4);

	/* Set byte mask */
	NXGE_REG_WR64(handle, ZCP_RAM_BE_REG, ram_en.value);

	/* Write to RAM */
	NXGE_REG_WR64(handle, ZCP_RAM_ACC_REG, ram_ctl.value);

	/* Wait for RAM write complete */
	ZCP_WAIT_RAM_READY(handle, ram_ctl.value);
	if (ram_ctl.bits.ldw.busy != 0)
		return (-1);

	return (0);
}
