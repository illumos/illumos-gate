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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

#include <qlge.h>

static uint32_t ql_dump_buf_8(uint8_t *, uint32_t, uint32_t);
static uint32_t ql_dump_buf_16(uint16_t *, uint32_t, uint32_t);
static uint32_t ql_dump_buf_32(uint32_t *, uint32_t, uint32_t);
static uint32_t ql_dump_buf_64(uint64_t *, uint32_t, uint32_t);
static int ql_binary_core_dump(qlge_t *, uint32_t, uint32_t *);

static char ISP_8100_REGION[] = {
	"nic: nic_boot, nic_param, nic_vpd \n"
	"mpi: mpi_fw, mpi_config, edc_fw\n"
	"fc: fc_boot, fc_fw, fc_nvram, fc_vpd"};
static char ISP_8100_AVAILABLE_DUMPS[] = {"core,register,all"};

/*
 * Get byte from I/O port
 */
uint8_t
ql_get8(qlge_t *qlge, uint32_t index)
{
	uint8_t ret;

	ret = (uint8_t)ddi_get8(qlge->dev_handle,
	    (uint8_t *)(((caddr_t)qlge->iobase) + index));
	return (ret);
}

/*
 * Get word from I/O port
 */
uint16_t
ql_get16(qlge_t *qlge, uint32_t index)
{
	uint16_t ret;

	ret = (uint16_t)ddi_get16(qlge->dev_handle,
	    (uint16_t *)(void *)(((caddr_t)qlge->iobase) + index));
	return (ret);
}

/*
 * Get double word from I/O port
 */
uint32_t
ql_get32(qlge_t *qlge, uint32_t index)
{
	uint32_t ret;

	ret = ddi_get32(qlge->dev_handle,
	    (uint32_t *)(void *)(((caddr_t)qlge->iobase) + index));
	return (ret);
}

/*
 * Send byte to I/O port
 */
void
ql_put8(qlge_t *qlge, uint32_t index, uint8_t data)
{
	ddi_put8(qlge->dev_handle,
	    (uint8_t *)(((caddr_t)qlge->iobase) + index), data);
}

/*
 * Send word to I/O port
 */
void
ql_put16(qlge_t *qlge, uint32_t index, uint16_t data)
{
	ddi_put16(qlge->dev_handle,
	    (uint16_t *)(void *)(((caddr_t)qlge->iobase) + index), data);
}

/*
 * Send double word to I/O port
 */
void
ql_put32(qlge_t *qlge, uint32_t index, uint32_t data)
{
	ddi_put32(qlge->dev_handle,
	    (uint32_t *)(void *)(((caddr_t)qlge->iobase) + index), data);
}

/*
 * Read from a register
 */
uint32_t
ql_read_reg(qlge_t *qlge, uint32_t reg)
{
	uint32_t data = ql_get32(qlge, reg);

	return (data);
}

/*
 * Write 32 bit data to a register
 */
void
ql_write_reg(qlge_t *qlge, uint32_t reg, uint32_t data)
{
	ql_put32(qlge, reg, data);
}

/*
 * Set semaphore register bit to lock access to a shared register
 */
int
ql_sem_lock(qlge_t *qlge, uint32_t sem_mask, uint32_t sem_bits)
{
	uint32_t value;

	ql_put32(qlge, REG_SEMAPHORE, (sem_mask | sem_bits));
	value = ql_get32(qlge, REG_SEMAPHORE);
	return ((value & (sem_mask >> 16)) == sem_bits);
}
/*
 * Wait up to "delay" seconds until the register "reg"'s
 * "wait_bit" is set
 * Default wait time is 5 seconds if "delay" time was not set.
 */
int
ql_wait_reg_bit(qlge_t *qlge, uint32_t reg, uint32_t wait_bit, int set,
    uint32_t delay)
{
	uint32_t reg_status;
	uint32_t timer = 5; /* 5 second */
	int rtn_val = DDI_SUCCESS;
	uint32_t delay_ticks;

	if (delay != 0)
		timer = delay;

	delay_ticks = timer * 100;
	/*
	 * wait for Configuration register test bit to be set,
	 * if not, then it is still busy.
	 */
	do {
		reg_status = ql_read_reg(qlge, reg);
		/* wait for bit set or reset? */
		if (set == BIT_SET) {
			if (reg_status & wait_bit)
				break;
			else
				qlge_delay(QL_ONE_SEC_DELAY / 100);
		} else {
			if (reg_status & wait_bit)
				qlge_delay(QL_ONE_SEC_DELAY / 100);
			else
				break;
		}
	} while (--delay_ticks);

	if (delay_ticks == 0) {
		rtn_val = DDI_FAILURE;
		cmn_err(CE_WARN, "qlge(%d)wait reg %x, bit %x time out",
		    qlge->instance, reg, wait_bit);
		if (qlge->fm_enable) {
			ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
			atomic_or_32(&qlge->flags, ADAPTER_ERROR);
		}
	}
	return (rtn_val);
}

/*
 * Dump the value of control registers
 */
void
ql_dump_all_contrl_regs(qlge_t *qlge)
{
	int i;
	uint32_t data;

	for (i = 0; i < 0xff; i = i+4) {
		data = ql_read_reg(qlge, i);
		ql_printf("\tregister# 0x%x value: 0x%x\n", i, data);
	}
}

/*
 * Prints string plus buffer.
 */
void
ql_dump_buf(char *string, uint8_t *buffer, uint8_t wd_size,
    uint32_t count)
{
	uint32_t offset = 0;

	if (strcmp(string, "") != 0)
		ql_printf(string);

	if ((buffer == NULL) || (count == 0))
		return;

	switch (wd_size) {
	case 8:
		while (count) {
			count = ql_dump_buf_8(buffer, count, offset);
			offset += 8;
			buffer += 8;
		}
		break;

	case 16:
		while (count) {
			count = ql_dump_buf_16((uint16_t *)(void *)buffer,
			    count, offset);
			offset += 16;
			buffer += 16;
		}
		break;
	case 32:
		while (count) {
			count = ql_dump_buf_32((uint32_t *)(void *)buffer,
			    count, offset);
			offset += 16;
			buffer += 16;
		}
		break;
	case 64:
		while (count) {
			count = ql_dump_buf_64((uint64_t *)(void *)buffer,
			    count, offset);
			offset += 16;
			buffer += 16;
		}
		break;
	default:
		break;
	}
}

/*
 * Print as 8bit bytes
 */
static uint32_t
ql_dump_buf_8(uint8_t *bp, uint32_t count, uint32_t offset)
{
	switch (count) {
	case 1:
		ql_printf("0x%016x : %02x\n",
		    offset,
		    *bp);
		break;

	case 2:
		ql_printf("0x%016x : %02x %02x\n",
		    offset,
		    *bp, *(bp+1));
		break;

	case 3:
		ql_printf("0x%016x : %02x %02x %02x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2));
		break;

	case 4:
		ql_printf("0x%016x : %02x %02x %02x %02x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3));
		break;

	case 5:
		ql_printf("0x%016x : %02x %02x %02x %02x %02x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4));
		break;

	case 6:
		ql_printf("0x%016x : %02x %02x %02x %02x %02x %02x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4), *(bp+5));
		break;

	case 7:
		ql_printf("0x%016x : %02x %02x %02x %02x %02x %02x %02x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4), *(bp+5), *(bp+6));
		break;

	default:
		ql_printf("0x%016x : %02x %02x %02x %02x %02x %02x %02x %02x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4), *(bp+5), *(bp+6),
		    *(bp+7));
		break;

	}

	if (count < 8) {
		count = 0;
	} else {
		count -= 8;
	}

	return (count);
}

/*
 * Print as 16bit
 */
static uint32_t
ql_dump_buf_16(uint16_t *bp, uint32_t count, uint32_t offset)
{

	switch (count) {
	case 1:
		ql_printf("0x%016x : %04x\n",
		    offset,
		    *bp);
		break;

	case 2:
		ql_printf("0x%016x : %04x %04x\n",
		    offset,
		    *bp, *(bp+1));
		break;

	case 3:
		ql_printf("0x%016x : %04x %04x %04x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2));
		break;

	case 4:
		ql_printf("0x%016x : %04x %04x %04x %04x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3));
		break;

	case 5:
		ql_printf("0x%016x : %04x %04x %04x %04x %04x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4));
		break;

	case 6:
		ql_printf("0x%016x : %04x %04x %04x %04x %04x %04x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4), *(bp+5));
		break;

	case 7:
		ql_printf("0x%016x : %04x %04x %04x %04x %04x %04x %04x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4), *(bp+5), *(bp+6));
		break;

	default:
		ql_printf("0x%016x : %04x %04x %04x %04x %04x %04x %04x %04x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3), *(bp+4), *(bp+5), *(bp+6),
		    *(bp+7));
		break;
	}

	if (count < 8) {
		count = 0;
	} else {
		count -= 8;
	}

	return (count);
}

/*
 * Print as 32bit
 */
static uint32_t
ql_dump_buf_32(uint32_t *bp, uint32_t count, uint32_t offset)
{

	switch (count) {
	case 1:
		ql_printf("0x%016x : %08x\n",
		    offset,
		    *bp);
		break;

	case 2:
		ql_printf("0x%016x : %08x %08x\n",
		    offset,
		    *bp, *(bp+1));
		break;

	case 3:
		ql_printf("0x%016x : %08x %08x %08x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2));
		break;

	default:
		ql_printf("0x%016x : %08x %08x %08x %08x\n",
		    offset,
		    *bp, *(bp+1), *(bp+2), *(bp+3));
		break;
	}

	if (count < 4) {
		count = 0;
	} else {
		count -= 4;
	}

	return (count);
}

/*
 * Print as 64bit
 */
static uint32_t
ql_dump_buf_64(uint64_t *bp, uint32_t count, uint32_t offset)
{

	switch (count) {
	case 1:
		ql_printf("0x%016x : %016x\n",
		    offset,
		    *bp);
		break;

	default:
		ql_printf("0x%016x : %016x %016x\n",
		    offset,
		    *bp, *(bp+1));
		break;

	}

	if (count < 2) {
		count = 0;
	} else {
		count -= 2;
	}

	return (count);
}

/*
 * Print CQICB control block information
 */
/* ARGSUSED */
void
ql_dump_cqicb(qlge_t *qlge, struct cqicb_t *cqicb)
{
	_NOTE(ARGUNUSED(qlge));
	ASSERT(qlge != NULL);
	ASSERT(cqicb != NULL);
	ql_printf("ql_dump_cqicb:entered\n");

	ql_printf("\t msix_vect   = 0x%x\n",
	    cqicb->msix_vect);
	ql_printf("\t reserved1  = 0x%x\n",
	    cqicb->reserved1);
	ql_printf("\t reserved2  = 0x%x\n",
	    cqicb->reserved2);
	ql_printf("\t flags  = 0x%x\n",
	    cqicb->flags);
	ql_printf("\t len  = 0x%x\n",
	    le16_to_cpu(cqicb->len));
	ql_printf("\t rid = 0x%x\n",
	    le16_to_cpu(cqicb->rid));
	ql_printf("\t cq_base_addr_lo = 0x%x\n",
	    le32_to_cpu(cqicb->cq_base_addr_lo));
	ql_printf("\t cq_base_addr_hi = 0x%x\n",
	    le32_to_cpu(cqicb->cq_base_addr_hi));
	ql_printf("\t prod_idx_addr_lo = %x\n",
	    le32_to_cpu(cqicb->prod_idx_addr_lo));
	ql_printf("\t prod_idx_addr_hi = %x\n",
	    le32_to_cpu(cqicb->prod_idx_addr_hi));
	ql_printf("\t pkt_delay = %d\n",
	    le16_to_cpu(cqicb->pkt_delay));
	ql_printf("\t irq_delay = 0x%x\n",
	    le16_to_cpu(cqicb->irq_delay));
	ql_printf("\t lbq_addr_lo = 0x%x\n",
	    le32_to_cpu(cqicb->lbq_addr_lo));
	ql_printf("\t lbq_addr_hi = 0x%x\n",
	    le32_to_cpu(cqicb->lbq_addr_hi));
	ql_printf("\t lbq_buf_size = 0x%x\n",
	    le16_to_cpu(cqicb->lbq_buf_size));
	ql_printf("\t lbq_len = 0x%x\n",
	    le16_to_cpu(cqicb->lbq_len));
	ql_printf("\t sbq_addr_lo = 0x%x\n",
	    le32_to_cpu(cqicb->sbq_addr_lo));
	ql_printf("\t sbq_addr_hi = 0x%x\n",
	    le32_to_cpu(cqicb->sbq_addr_hi));
	ql_printf("\t sbq_buf_size = 0x%x\n",
	    le16_to_cpu(cqicb->sbq_buf_size));
	ql_printf("\t sbq_len = 0x%x\n",
	    le16_to_cpu(cqicb->sbq_len));

	ql_printf("ql_dump_cqicb:exiting\n");
}

/*
 * Print WQICB control block information
 */
/* ARGSUSED */
void
ql_dump_wqicb(qlge_t *qlge, struct wqicb_t *wqicb)
{
	_NOTE(ARGUNUSED(qlge));
	ASSERT(qlge != NULL);
	ASSERT(wqicb != NULL);

	ql_printf("ql_dump_wqicb:entered\n");

	ql_printf("\t len = %x\n",
	    le16_to_cpu(wqicb->len));
	ql_printf("\t flags = %x\n",
	    le16_to_cpu(wqicb->flags));
	ql_printf("\t cq_id_rss = %x\n",
	    le16_to_cpu(wqicb->cq_id_rss));
	ql_printf("\t rid = 0x%x\n",
	    le16_to_cpu(wqicb->rid));
	ql_printf("\t wq_addr_lo = 0x%x\n",
	    le32_to_cpu(wqicb->wq_addr_lo));
	ql_printf("\t wq_addr_hi = 0x%x\n",
	    le32_to_cpu(wqicb->wq_addr_hi));
	ql_printf("\t cnsmr_idx_addr_lo = %x\n",
	    le32_to_cpu(wqicb->cnsmr_idx_addr_lo));
	ql_printf("\t cnsmr_idx_addr_hi = %x\n",
	    le32_to_cpu(wqicb->cnsmr_idx_addr_hi));

	ql_printf("ql_dump_wqicb:exit\n");
}

/*
 * Print request descriptor information
 */
void
ql_dump_req_pkt(qlge_t *qlge, struct ob_mac_iocb_req *pkt, void *oal,
    int number)
{
	int i = 0;
	struct oal_entry *oal_entry;

	ql_printf("ql_dump_req_pkt(%d):enter\n", qlge->instance);

	ql_printf("\t opcode = 0x%x\n",
	    pkt->opcode);
	ql_printf("\t flag0  = 0x%x\n",
	    pkt->flag0);
	ql_printf("\t flag1  = 0x%x\n",
	    pkt->flag1);
	ql_printf("\t flag2  = 0x%x\n",
	    pkt->flag2);
	ql_printf("\t frame_len  = 0x%x\n",
	    le16_to_cpu(pkt->frame_len));
	ql_printf("\t transaction_id_low = 0x%x\n",
	    le16_to_cpu(pkt->tid));
	ql_printf("\t txq_idx = 0x%x\n",
	    le16_to_cpu(pkt->txq_idx));
	ql_printf("\t protocol_hdr_len = 0x%x\n",
	    le16_to_cpu(pkt->protocol_hdr_len));
	ql_printf("\t hdr_off = %d\n",
	    le16_to_cpu(pkt->hdr_off));
	ql_printf("\t vlan_tci = %d\n",
	    le16_to_cpu(pkt->vlan_tci));
	ql_printf("\t mss = %d\n",
	    le16_to_cpu(pkt->mss));

	/* if OAL is needed */
	if (number > TX_DESC_PER_IOCB) {
		for (i = 0; i < TX_DESC_PER_IOCB; i++) {
			ql_printf("\t buf_addr%d_low = 0x%x\n",
			    i, pkt->oal_entry[i].buf_addr_low);
			ql_printf("\t buf_addr%d_high = 0x%x\n",
			    i, pkt->oal_entry[i].buf_addr_high);
			ql_printf("\t buf%d_len = 0x%x\n",
			    i, pkt->oal_entry[i].buf_len);
		}
		oal_entry = (struct oal_entry *)oal;
		ql_printf("\t additional %d tx descriptors in OAL\n",
		    (number - TX_DESC_PER_IOCB + 1));
		for (i = 0; i < (number-TX_DESC_PER_IOCB + 1); i++) {
			ql_printf("\t buf_addr%d_low = 0x%x\n",
			    i, oal_entry[i].buf_addr_low);
			ql_printf("\t buf_addr%d_high = 0x%x\n",
			    i, oal_entry[i].buf_addr_high);
			ql_printf("\t buf%d_len = 0x%x\n",
			    i, oal_entry[i].buf_len);
		}
	} else {
		for (i = 0; i < number; i++) {
			ql_printf("\t buf_addr%d_low = 0x%x\n",
			    i, pkt->oal_entry[i].buf_addr_low);
			ql_printf("\t buf_addr%d_high = 0x%x\n",
			    i, pkt->oal_entry[i].buf_addr_high);
			ql_printf("\t buf%d_len = 0x%x\n",
			    i, pkt->oal_entry[i].buf_len);
		}
	}
	ql_printf("ql_dump_req_pkt:exiting\n");
}

/*
 * Print PCI configuration
 */
void
ql_dump_pci_config(qlge_t *qlge)
{
	qlge->pci_cfg.vendor_id = (uint16_t)
	    pci_config_get16(qlge->pci_handle, PCI_CONF_VENID);

	qlge->pci_cfg.device_id = (uint16_t)
	    pci_config_get16(qlge->pci_handle, PCI_CONF_DEVID);

	qlge->pci_cfg.command = (uint16_t)
	    pci_config_get16(qlge->pci_handle, PCI_CONF_COMM);

	qlge->pci_cfg.status = (uint16_t)
	    pci_config_get16(qlge->pci_handle, PCI_CONF_STAT);

	qlge->pci_cfg.revision = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_REVID);

	qlge->pci_cfg.prog_class = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_PROGCLASS);

	qlge->pci_cfg.sub_class = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_SUBCLASS);

	qlge->pci_cfg.base_class = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_BASCLASS);

	qlge->pci_cfg.cache_line_size = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_CACHE_LINESZ);

	qlge->pci_cfg.latency_timer = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_LATENCY_TIMER);

	qlge->pci_cfg.header_type = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_HEADER);

	qlge->pci_cfg.io_base_address =
	    pci_config_get32(qlge->pci_handle, PCI_CONF_BASE0);

	qlge->pci_cfg.pci_cntl_reg_set_mem_base_address_lower =
	    pci_config_get32(qlge->pci_handle, PCI_CONF_BASE1);

	qlge->pci_cfg.pci_cntl_reg_set_mem_base_address_upper =
	    pci_config_get32(qlge->pci_handle, PCI_CONF_BASE2);

	qlge->pci_cfg.pci_doorbell_mem_base_address_lower =
	    pci_config_get32(qlge->pci_handle, PCI_CONF_BASE3);

	qlge->pci_cfg.pci_doorbell_mem_base_address_upper =
	    pci_config_get32(qlge->pci_handle, PCI_CONF_BASE4);

	qlge->pci_cfg.sub_vendor_id = (uint16_t)
	    pci_config_get16(qlge->pci_handle, PCI_CONF_SUBVENID);

	qlge->pci_cfg.sub_device_id = (uint16_t)
	    pci_config_get16(qlge->pci_handle, PCI_CONF_SUBSYSID);

	qlge->pci_cfg.expansion_rom =
	    pci_config_get32(qlge->pci_handle, PCI_CONF_ROM);

	qlge->pci_cfg.intr_line = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_ILINE);

	qlge->pci_cfg.intr_pin = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_IPIN);

	qlge->pci_cfg.min_grant = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_MIN_G);

	qlge->pci_cfg.max_latency = (uint8_t)
	    pci_config_get8(qlge->pci_handle, PCI_CONF_MAX_L);

	qlge->pci_cfg.pcie_device_control = (uint16_t)
	    pci_config_get16(qlge->pci_handle, 0x54);

	qlge->pci_cfg.link_status = (uint16_t)
	    pci_config_get16(qlge->pci_handle, 0x5e);

	qlge->pci_cfg.msi_msg_control = (uint16_t)
	    pci_config_get16(qlge->pci_handle, 0x8a);

	qlge->pci_cfg.msi_x_msg_control = (uint16_t)
	    pci_config_get16(qlge->pci_handle, 0xa2);

	if (qlge->ql_dbgprnt & DBG_GLD) {
		ql_printf("ql_dump_pci_config(%d): enter\n",
		    qlge->instance);
		ql_printf("\tvendorid =0x%x.\n",
		    qlge->pci_cfg.vendor_id);
		ql_printf("\tdeviceid =0x%x.\n",
		    qlge->pci_cfg.device_id);
		ql_printf("\tcommand =0x%x.\n",
		    qlge->pci_cfg.command);
		ql_printf("\tstatus =0x%x.\n",
		    qlge->pci_cfg.status);
		ql_printf("\trevision id =0x%x.\n",
		    qlge->pci_cfg.revision);
		ql_printf("\tprogram class =0x%x.\n",
		    qlge->pci_cfg.prog_class);
		ql_printf("\tsubclass code =0x%x.\n",
		    qlge->pci_cfg.sub_class);
		ql_printf("\tbase class code =0x%x.\n",
		    qlge->pci_cfg.base_class);
		ql_printf("\tcache line size =0x%x.\n",
		    qlge->pci_cfg.cache_line_size);
		ql_printf("\tlatency timer =0x%x.\n",
		    qlge->pci_cfg.latency_timer);
		ql_printf("\theader =0x%x.\n",
		    qlge->pci_cfg.header_type);
		ql_printf("\tI/O Base Register Address0 =0x%x.\n",
		    qlge->pci_cfg.io_base_address);
		ql_printf("\tpci_cntl_reg_set_mem_base_address_lower =0x%x.\n",
		    qlge->pci_cfg.pci_cntl_reg_set_mem_base_address_lower);
		ql_printf("\tpci_cntl_reg_set_mem_base_address_upper =0x%x.\n",
		    qlge->pci_cfg.pci_cntl_reg_set_mem_base_address_upper);
		ql_printf("\tpci_doorbell_mem_base_address_lower =0x%x.\n",
		    qlge->pci_cfg.pci_doorbell_mem_base_address_lower);
		ql_printf("\tpci_doorbell_mem_base_address_upper =0x%x.\n",
		    qlge->pci_cfg.pci_doorbell_mem_base_address_upper);
		ql_printf("\tSubsystem Vendor Id =0x%x.\n",
		    qlge->pci_cfg.sub_vendor_id);
		ql_printf("\tSubsystem Id =0x%x.\n",
		    qlge->pci_cfg.sub_device_id);
		ql_printf("\tExpansion ROM Base Register =0x%x.\n",
		    qlge->pci_cfg.expansion_rom);
		ql_printf("\tInterrupt Line =0x%x.\n",
		    qlge->pci_cfg.intr_line);
		ql_printf("\tInterrupt Pin =0x%x.\n",
		    qlge->pci_cfg.intr_pin);
		ql_printf("\tMin Grant =0x%x.\n",
		    qlge->pci_cfg.min_grant);
		ql_printf("\tMax Grant =0x%x.\n",
		    qlge->pci_cfg.max_latency);
		ql_printf("\tdevice_control =0x%x.\n",
		    qlge->pci_cfg.pcie_device_control);
		ql_printf("\tlink_status =0x%x.\n",
		    qlge->pci_cfg.link_status);
		ql_printf("\tmsi_msg_control =0x%x.\n",
		    qlge->pci_cfg.msi_msg_control);
		ql_printf("\tmsi_x_msg_control =0x%x.\n",
		    qlge->pci_cfg.msi_x_msg_control);

		ql_printf("ql_dump_pci_config(%d): exit\n", qlge->instance);
	}
}

/*
 * Print a formated string
 */
void
ql_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vcmn_err(CE_CONT, fmt, ap);
	va_end(ap);

}

/*
 * Read all control registers value and save in a string
 */
static uint32_t
read_ctrl_reg_set(qlge_t *qlge, caddr_t bufp)
{
	int i, j;
	uint32_t data;
	caddr_t bp = bufp;
	uint32_t cnt;

	/* read Reg 0 -0xC4 */
	for (i = 0, j = 0; i <= 0xfc; i += 4) {
		data = ql_read_reg(qlge, i);
		(void) sprintf(bp, "Register[%x] = 0x%x\n", i, data);
		bp += strlen(bp);
		if (i == REG_INTERRUPT_ENABLE) {
			/* Read */
			data = INTR_EN_TYPE_READ;
			ql_write_reg(qlge, i, (data | (data << 16)));
			data = ql_read_reg(qlge, i);
			if (data & INTR_EN_EN) {
				(void) sprintf(bp, "Intr0 enabled: 0x%x\n",
				    data);
				bp += strlen(bp);
			} else {
				(void) sprintf(bp, "Intr0 disabled: 0x%x\n",
				    data);
				bp += strlen(bp);
			}
		}
		j++;
	}
	*bp = '\0';
	bp++;
	cnt = (uint32_t)((uintptr_t)bp - (uintptr_t)bufp);
	QL_PRINT(DBG_GLD, ("%s(%d) %x bytes to export\n",
	    __func__, qlge->instance, cnt));
	return (cnt);
}

/*
 * Get address and size of image tables in flash memory
 */
static int
ql_get_flash_table_region_info(qlge_t *qlge, uint32_t region, uint32_t *addr,
    uint32_t *size)
{
	int rval = DDI_SUCCESS;

	switch (region) {
	case FLT_REGION_FDT:
		*addr = ISP_8100_FDT_ADDR;
		*size = ISP_8100_FDT_SIZE;
		break;
	case FLT_REGION_FLT:
		*addr = ISP_8100_FLT_ADDR;
		*size = ISP_8100_FLT_SIZE;
		break;
	case FLT_REGION_NIC_BOOT_CODE:
		*addr = ISP_8100_NIC_BOOT_CODE_ADDR;
		*size = ISP_8100_NIC_BOOT_CODE_SIZE;
		break;
	case FLT_REGION_MPI_FW_USE:
		*addr = ISP_8100_MPI_FW_USE_ADDR;
		*size = ISP_8100_MPI_FW_USE_SIZE;
		break;
	case FLT_REGION_MPI_RISC_FW:
		*addr = ISP_8100_MPI_RISC_FW_ADDR;
		*size = ISP_8100_MPI_RISC_FW_SIZE;
		break;
	case FLT_REGION_VPD0:
		*addr = ISP_8100_VPD0_ADDR;
		*size = ISP_8100_VPD0_SIZE;
		break;
	case FLT_REGION_NIC_PARAM0:
		*addr = ISP_8100_NIC_PARAM0_ADDR;
		*size = ISP_8100_NIC_PARAM0_SIZE;
		break;
	case FLT_REGION_VPD1:
		*addr = ISP_8100_VPD1_ADDR;
		*size = ISP_8100_VPD1_SIZE;
		break;
	case FLT_REGION_NIC_PARAM1:
		*addr = ISP_8100_NIC_PARAM1_ADDR;
		*size = ISP_8100_NIC_PARAM1_SIZE;
		break;
	case FLT_REGION_MPI_CFG:
		*addr = ISP_8100_MPI_CFG_ADDR;
		*size = ISP_8100_MPI_CFG_SIZE;
		break;
	case FLT_REGION_EDC_PHY_FW:
		*addr = ISP_8100_EDC_PHY_FW_ADDR;
		*size = ISP_8100_EDC_PHY_FW_SIZE;
		break;
	case FLT_REGION_FC_BOOT_CODE:
		*addr = ISP_8100_FC_BOOT_CODE_ADDR;
		*size = ISP_8100_FC_BOOT_CODE_SIZE;
		break;
	case FLT_REGION_FC_FW:
		*addr = ISP_8100_FC_FW_ADDR;
		*size = ISP_8100_FC_FW_SIZE;
		break;
	default:
		cmn_err(CE_WARN, "%s(%d): Unknown region code %x!",
		    __func__, qlge->instance, region);
		rval = DDI_FAILURE;
	}
	return (rval);
}

/*
 * Get PCI bus information
 */
static int
ql_get_pci_bus_info(qlge_t *qlge, uint32_t *pci_bus_info_ptr)
{
	dev_info_t *dip;
	int *options;
	unsigned int noptions;
	int rval = DDI_FAILURE;

	dip = qlge->dip;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0,
	    "assigned-addresses", &options, &noptions) == DDI_PROP_SUCCESS) {
		QL_PRINT(DBG_GLD, ("%s(%d) %d options\n",
		    __func__, qlge->instance, noptions));

		if (noptions != 0) {
			*pci_bus_info_ptr = options[0];
			rval = DDI_SUCCESS;
		}

		ddi_prop_free(options);
	}
	return (rval);
}

/*
 * Build the first packet header in case that 1k+ data transfer is required
 */
void
build_init_pkt_header(qlge_t *qlge, ioctl_header_info_t *pheader, uint32_t size)
{
	qlge->ioctl_total_length = size;
	QL_PRINT(DBG_GLD, ("%d bytes used in kernel buffer\n",
	    qlge->ioctl_total_length));
	qlge->expected_trans_times =
	    (uint16_t)(qlge->ioctl_total_length / IOCTL_MAX_DATA_LEN);
	if ((qlge->ioctl_total_length % IOCTL_MAX_DATA_LEN) != 0)
		qlge->expected_trans_times++;
	QL_PRINT(DBG_GLD, ("expected transer times %d \n",
	    qlge->expected_trans_times));
	qlge->ioctl_transferred_bytes = 0;
	/*
	 * tell user total bytes prepare to receive in the
	 * following transactions
	 */
	pheader->version = 0;
	pheader->total_length = qlge->ioctl_total_length;
	pheader->payload_length = 0;
	pheader->expected_trans_times = qlge->expected_trans_times;
}

/*
 * Do ioctl on hardware
 */
/* ARGSUSED */
enum ioc_reply
ql_chip_ioctl(qlge_t *qlge, queue_t *q, mblk_t *mp)
{
	mblk_t *dmp;
	int cmd, i, rval;
	struct ql_device_reg *reg;
	struct ql_pci_reg *pci_reg;
	struct ql_flash_io_info *flash_io_info_ptr;
	pci_cfg_t *pci_cfg;
	uint32_t *pvalue;
	struct qlnic_prop_info *prop_ptr;
	ql_adapter_info_t *adapter_info_ptr;
	uint16_t payload_len;
	uint32_t remaining_bytes;
	ioctl_header_info_t *pheader;
	caddr_t bp, bdesc;
	uint32_t len;
	uint32_t addr, size, region;
	struct iocblk *iocp = (struct iocblk *)(void *)mp->b_rptr;
	uint16_t iltds_image_entry_regions[] = {
			FLT_REGION_NIC_BOOT_CODE, FLT_REGION_MPI_RISC_FW,
			FLT_REGION_EDC_PHY_FW, FLT_REGION_FC_BOOT_CODE,
			FLT_REGION_FC_FW};
	ql_iltds_description_header_t *iltds_ptr;
	ql_iltds_header_t *ql_iltds_header_ptr;
	uint32_t offset;
	uint16_t requested_dump;

	/*
	 * There should be a M_DATA mblk following
	 * the initial M_IOCTL mblk
	 */
	if ((dmp = mp->b_cont) == NULL) {
		cmn_err(CE_WARN, "%s(%d) b_count NULL",
		    __func__, qlge->instance);
		return (IOC_INVAL);
	}

	cmd = iocp->ioc_cmd;

	reg = (struct ql_device_reg *)(void *)dmp->b_rptr;
	pci_reg = (struct ql_pci_reg *)(void *)dmp->b_rptr;
	pvalue = (uint32_t *)(void *)dmp->b_rptr;
	flash_io_info_ptr = (struct ql_flash_io_info *)(void *)dmp->b_rptr;
	adapter_info_ptr = (ql_adapter_info_t *)(void *)dmp->b_rptr;

	switch (cmd) {
		case QLA_GET_DBGLEAVEL:
			if (iocp->ioc_count != sizeof (*pvalue)) {
				return (IOC_INVAL);
			}
			*pvalue = qlge->ql_dbgprnt;
			break;

		case QLA_SET_DBGLEAVEL:
			if (iocp->ioc_count != sizeof (*pvalue)) {
				return (IOC_INVAL);
			}
			qlge->ql_dbgprnt = *pvalue;
			break;

		case QLA_WRITE_REG:
			if (iocp->ioc_count != sizeof (*reg)) {
				return (IOC_INVAL);
			}
			ql_write_reg(qlge, reg->addr, reg->value);
			break;

		case QLA_READ_PCI_REG:
			if (iocp->ioc_count != sizeof (*pci_reg)) {
				return (IOC_INVAL);
			}
			/* protect against bad addr values */
			if (pci_reg->addr > 0xff)
				return (IOC_INVAL);
			pci_reg->value =
			    (uint16_t)pci_config_get16(qlge->pci_handle,
			    pci_reg->addr);
			break;

		case QLA_WRITE_PCI_REG:
			if (iocp->ioc_count != sizeof (*pci_reg)) {
				return (IOC_INVAL);
			}
			/* protect against bad addr values */
			if (pci_reg->addr > 0xff)
				return (IOC_INVAL);
			pci_config_put16(qlge->pci_handle, pci_reg->addr,
			    pci_reg->value);
			break;

		case QLA_PCI_STATUS:
			len = (uint32_t)iocp->ioc_count;
			if (len != sizeof (pci_cfg_t)) {
				cmn_err(CE_WARN, "QLA_PCI_STATUS size error, "
				    "driver size 0x%x not 0x%x ",
				    (int)MBLKL(dmp),
				    (int)sizeof (pci_cfg_t));
				return (IOC_INVAL);
			}
			pci_cfg = (pci_cfg_t *)(void *)dmp->b_rptr;
			/* get PCI configuration */
			bcopy((const void *)(&qlge->pci_cfg),
			    (void *)pci_cfg, len);
			break;

		case QLA_GET_PROP:
			len = (uint32_t)iocp->ioc_count;
			if (len != sizeof (struct qlnic_prop_info)) {
				cmn_err(CE_WARN, "QLA_GET_PROP size error, "
				    "driver size 0x%x not 0x%x ",
				    (int)MBLKL(dmp),
				    (int)sizeof (pci_cfg_t));
				return (IOC_INVAL);
			}
			prop_ptr =
			    (struct qlnic_prop_info *)(void *)dmp->b_rptr;
			/* get various properties */
			mutex_enter(&qlge->mbx_mutex);
			(void) ql_get_firmware_version(qlge,
			    &prop_ptr->mpi_version);
			(void) ql_get_fw_state(qlge, &prop_ptr->fw_state);
			(void) qlge_get_link_status(qlge,
			    &prop_ptr->link_status);
			mutex_exit(&qlge->mbx_mutex);
			break;

		case QLA_LIST_ADAPTER_INFO:
			/* count must be exactly same */
			if (iocp->ioc_count != sizeof (ql_adapter_info_t)) {
				return (IOC_INVAL);
			}
			if (ql_get_pci_bus_info(qlge,
			    &(adapter_info_ptr->pci_binding)) != DDI_SUCCESS) {
				return (IOC_INVAL);
			}
			adapter_info_ptr->vendor_id =
			    qlge->pci_cfg.vendor_id;
			adapter_info_ptr->sub_vendor_id =
			    qlge->pci_cfg.sub_vendor_id;
			adapter_info_ptr->device_id =
			    qlge->pci_cfg.device_id;
			adapter_info_ptr->sub_device_id =
			    qlge->pci_cfg.sub_device_id;

			bcopy(qlge->unicst_addr[0].addr.ether_addr_octet,
			    &(adapter_info_ptr->cur_addr), ETHERADDRL);
			break;

		case QLA_SHOW_REGION:
			len = (uint32_t)iocp->ioc_count;
			bdesc = (caddr_t)dmp->b_rptr;
			if (CFG_IST(qlge, CFG_CHIP_8100))
				(void) sprintf(bdesc, "ISP 8100 available "
				    "regions %s", ISP_8100_REGION);
			break;

		case QLA_CONTINUE_COPY_OUT:
			if (qlge->ioctl_buf_ptr == NULL)
				return (IOC_INVAL);
			len = (uint32_t)iocp->ioc_count;
			bp = qlge->ioctl_buf_ptr;
			bp += qlge->ioctl_transferred_bytes;
			remaining_bytes =
			    qlge->ioctl_total_length -
			    qlge->ioctl_transferred_bytes;
			/* how many data bytes sent this time */
			payload_len =
			    (uint16_t)min(IOCTL_MAX_DATA_LEN, remaining_bytes);
			/* create packet header */
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			pheader->version = 0;
			pheader->total_length = qlge->ioctl_total_length;
			pheader->expected_trans_times =
			    qlge->expected_trans_times;
			pheader->payload_length = payload_len;
			/* create packet payload */
			bdesc = (caddr_t)dmp->b_rptr;
			bdesc += IOCTL_HEADER_LEN;
			bcopy(bp, bdesc, pheader->payload_length);
			qlge->ioctl_transferred_bytes +=
			    pheader->payload_length;
			QL_PRINT(DBG_GLD, ("QLA_CONTINUE_COPY_OUT, %d bytes"
			    " exported \n", payload_len));
			if (qlge->ioctl_transferred_bytes >=
			    qlge->ioctl_total_length) {
				QL_PRINT(DBG_GLD, ("all data out,clean up \n"));
				kmem_free(qlge->ioctl_buf_ptr,
				    qlge->ioctl_buf_lenth);
				qlge->ioctl_buf_ptr = NULL;
				qlge->ioctl_buf_lenth = 0;
			}
			iocp->ioc_count = len;
			break;

		case QLA_CONTINUE_COPY_IN:
			if (qlge->ioctl_buf_ptr == NULL)
				return (IOC_INVAL);
			len = (uint32_t)iocp->ioc_count;
			bdesc = qlge->ioctl_buf_ptr;
			bdesc += qlge->ioctl_transferred_bytes;
			remaining_bytes = qlge->ioctl_total_length -
			    qlge->ioctl_transferred_bytes;
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			payload_len = pheader->payload_length;
			/* create packet header */
			pheader->version = 0;
			pheader->total_length = qlge->ioctl_total_length;
			pheader->expected_trans_times =
			    qlge->expected_trans_times;
			/* get packet payload */
			bp = (caddr_t)dmp->b_rptr;
			bp += IOCTL_HEADER_LEN;
			bcopy(bp, bdesc, pheader->payload_length);
			qlge->ioctl_transferred_bytes +=
			    pheader->payload_length;
			QL_PRINT(DBG_GLD, ("QLA_CONTINUE_COPY_IN, %d bytes "
			    "received \n", payload_len));
			if (qlge->ioctl_transferred_bytes >=
			    qlge->ioctl_total_length) {
				region = pheader->option[0];
				(void) ql_get_flash_table_region_info(qlge,
				    region, &addr, &size);
				QL_PRINT(DBG_GLD, ("write data to region 0x%x,"
				    " addr 0x%x, max size %d bytes\n",
				    region, addr, size));
				(void) qlge_load_flash(qlge,
				    (uint8_t *)qlge->ioctl_buf_ptr,
				    qlge->ioctl_transferred_bytes /* size */,
				    addr);
				QL_PRINT(DBG_GLD, ("all %d data written, do "
				    "clean up \n",
				    qlge->ioctl_transferred_bytes));
				kmem_free(qlge->ioctl_buf_ptr,
				    qlge->ioctl_buf_lenth);
				qlge->ioctl_buf_ptr = NULL;
				qlge->ioctl_buf_lenth = 0;
			}
			iocp->ioc_count = len;
			break;

		case QLA_READ_CONTRL_REGISTERS:
			if (qlge->ioctl_buf_ptr == NULL) {
				qlge->ioctl_buf_lenth =
				    IOCTL_MAX_BUF_SIZE; /* 512k */
				qlge->ioctl_buf_ptr =
				    kmem_zalloc(qlge->ioctl_buf_lenth,
				    KM_SLEEP);
				if (qlge->ioctl_buf_ptr == NULL) {
					cmn_err(CE_WARN, "%s(%d): Unable to "
					    "allocate ioctl buffer",
					    __func__, qlge->instance);
					return (IOC_INVAL);
				}
			}
			len = read_ctrl_reg_set(qlge, qlge->ioctl_buf_ptr);
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			/* build initial ioctl packet header */
			build_init_pkt_header(qlge, pheader, len);
			iocp->ioc_count = sizeof (*pheader);
			break;

		case QLA_SUPPORTED_DUMP_TYPES: /* show available regions */
			len = (uint32_t)iocp->ioc_count;
			bdesc = (caddr_t)dmp->b_rptr;
			if (CFG_IST(qlge, CFG_CHIP_8100))
				(void) sprintf(bdesc, "ISP 8100 supported dump"
				    " types: %s", ISP_8100_AVAILABLE_DUMPS);
			break;

		case QLA_GET_BINARY_CORE_DUMP:
			len = (uint32_t)iocp->ioc_count;
			requested_dump = *((uint16_t *)(void *)dmp->b_rptr);
			rval = ql_binary_core_dump(qlge, requested_dump, &len);
			if (rval == DDI_SUCCESS) {
				pheader =
				    (ioctl_header_info_t *)(void *)dmp->b_rptr;
				/* build initial ioctl packet header */
				build_init_pkt_header(qlge, pheader, len);
				iocp->ioc_count = sizeof (*pheader);
			} else {
				cmn_err(CE_WARN, "ql_binary_core_dump error");
				return (IOC_INVAL);
			}
			break;

		case QLA_TRIGGER_SYS_ERROR_EVENT:
			(void) ql_trigger_system_error_event(qlge);
			break;

		case QLA_READ_VPD:
			if (qlge->ioctl_buf_ptr == NULL) {
				qlge->ioctl_buf_lenth =
				    IOCTL_MAX_BUF_SIZE; /* 512k */
				qlge->ioctl_buf_ptr =
				    kmem_zalloc(qlge->ioctl_buf_lenth,
				    KM_SLEEP);
				if (qlge->ioctl_buf_ptr == NULL) {
					cmn_err(CE_WARN, "%s(%d): Unable to "
					    "allocate ioctl buffer",
					    __func__, qlge->instance);
					return (IOC_INVAL);
				}
			}
			len = (uint32_t)iocp->ioc_count;
			QL_PRINT(DBG_GLD, (" 0x%x user buffer available \n",
			    len));
			(void) ql_flash_vpd(qlge,
			    (uint8_t *)qlge->ioctl_buf_ptr);
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			/* build initial ioctl packet header */
			build_init_pkt_header(qlge, pheader,
			    ISP_8100_VPD0_SIZE);
			iocp->ioc_count = sizeof (*pheader);
			break;

		case QLA_MANUAL_READ_FLASH:
			if (qlge->ioctl_buf_ptr == NULL) {
				qlge->ioctl_buf_lenth =
				    IOCTL_MAX_BUF_SIZE; /* 512k */
				qlge->ioctl_buf_ptr =
				    kmem_zalloc(qlge->ioctl_buf_lenth,
				    KM_SLEEP);
				if (qlge->ioctl_buf_ptr == NULL) {
					cmn_err(CE_WARN, "%s(%d): Unable to "
					    "allocate ioctl buffer",
					    __func__, qlge->instance);
					return (IOC_INVAL);
				}
			}
			len = (uint32_t)iocp->ioc_count;
			rval = qlge_dump_fcode(qlge,
			    (uint8_t *)qlge->ioctl_buf_ptr,
			    flash_io_info_ptr->size,
			    flash_io_info_ptr->addr);
			if (rval != DDI_SUCCESS) {
				return (IOC_INVAL);
			}
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			/* build initial ioctl packet header */
			build_init_pkt_header(qlge, pheader,
			    flash_io_info_ptr->size);
			iocp->ioc_count = sizeof (*pheader);
			break;

		case QLA_READ_FLASH:
			if (qlge->ioctl_buf_ptr == NULL) {
				qlge->ioctl_buf_lenth = IOCTL_MAX_BUF_SIZE;
				qlge->ioctl_buf_ptr =
				    kmem_zalloc(qlge->ioctl_buf_lenth,
				    KM_SLEEP);
				if (qlge->ioctl_buf_ptr == NULL) {
					cmn_err(CE_WARN, "%s(%d): Unable to"
					    "allocate ioctl buffer",
					    __func__, qlge->instance);
					return (IOC_INVAL);
				}
			}
			len = (uint32_t)iocp->ioc_count;
			region = *pvalue;
			if (ql_get_flash_table_region_info(qlge, region, &addr,
			    &size) != DDI_SUCCESS)
				return (IOC_INVAL);
			rval = qlge_dump_fcode(qlge,
			    (uint8_t *)qlge->ioctl_buf_ptr,
			    size, addr);
			if (rval != DDI_SUCCESS) {
				return (IOC_INVAL);
			}
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			/* build initial ioctl packet header */
			build_init_pkt_header(qlge, pheader, size);
			iocp->ioc_count = sizeof (*pheader);
			break;

		case QLA_WRITE_FLASH:
			len = (uint32_t)iocp->ioc_count;
			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			region = pheader->option[0];
			qlge->ioctl_buf_lenth = pheader->total_length;
			qlge->ioctl_total_length = pheader->total_length;
			qlge->expected_trans_times =
			    pheader->expected_trans_times;
			qlge->ioctl_transferred_bytes = 0;
			if (qlge->ioctl_buf_ptr == NULL) {
				qlge->ioctl_buf_ptr =
				    kmem_zalloc(qlge->ioctl_buf_lenth,
				    KM_SLEEP);
				if (qlge->ioctl_buf_ptr == NULL) {
					cmn_err(CE_WARN, "%s(%d): Unable to "
					    "allocate ioctl buffer",
					    __func__, qlge->instance);
					return (IOC_INVAL);
				}
			}
			QL_PRINT(DBG_GLD, ("QLA_WRITE_FLASH write to region "
			    "%x, total buffer size 0x%x bytes\n",
			    region, qlge->ioctl_buf_lenth));
			iocp->ioc_count = sizeof (*pheader);
			break;

		case QLA_READ_FW_IMAGE:
			if (qlge->ioctl_buf_ptr != NULL) {
				kmem_free(qlge->ioctl_buf_ptr,
				    qlge->ioctl_buf_lenth);
			}
			qlge->ioctl_buf_lenth = IOCTL_MAX_BUF_SIZE * 4;
			qlge->ioctl_buf_ptr = kmem_zalloc(qlge->ioctl_buf_lenth,
			    KM_SLEEP);
			if (qlge->ioctl_buf_ptr == NULL) {
				cmn_err(CE_WARN, "%s(%d): Unable to "
				    "allocate ioctl buffer",
				    __func__, qlge->instance);
				return (IOC_INVAL);
			}
			len = (uint32_t)iocp->ioc_count;
			iltds_ptr = (ql_iltds_description_header_t *)
			    (void *)qlge->ioctl_buf_ptr;
			iltds_ptr->iltds_table_header.signature =
			    FLASH_ILTDS_SIGNATURE;
			iltds_ptr->iltds_table_header.table_version = 1;
			iltds_ptr->iltds_table_header.length =
			    ILTDS_DESCRIPTION_HEADERS_LEN;
			iltds_ptr->iltds_table_header.number_entries =
			    IMAGE_TABLE_IMAGE_DEFAULT_ENTRIES +
			    1 /* timestamp */;
			iltds_ptr->iltds_table_header.reserved = 0;
			iltds_ptr->iltds_table_header.version = 1;
			/* where is the flash data saved */
			bdesc = qlge->ioctl_buf_ptr +
			    ILTDS_DESCRIPTION_HEADERS_LEN;
			offset = iltds_ptr->iltds_table_header.length;
			for (i = 0; i < IMAGE_TABLE_IMAGE_DEFAULT_ENTRIES;
			    i++) {
				region = iltds_image_entry_regions[i];
				if (ql_get_flash_table_region_info(qlge,
				    region, &addr, &size) != DDI_SUCCESS)
					return (IOC_INVAL);
				QL_PRINT(DBG_GLD, ("region %x addr 0x%x, 0x%x "
				    "bytes\n", region, addr, size));
				/* Dump one image entry */
				rval = qlge_dump_fcode(qlge, (uint8_t *)bdesc,
				    size, addr);
				if (rval != DDI_SUCCESS) {
					return (IOC_INVAL);
				}
				bdesc += size;
				iltds_ptr->img_entry[i].region_type =
				    (uint16_t)region;
				iltds_ptr->img_entry[i].region_version_len = 0;
				iltds_ptr->img_entry[i].region_version[0] = 0;
				iltds_ptr->img_entry[i].region_version[1] = 0;
				iltds_ptr->img_entry[i].region_version[2] = 0;
				iltds_ptr->img_entry[i].offset_lo = LSW(offset);
				iltds_ptr->img_entry[i].offset_hi = MSW(offset);
				iltds_ptr->img_entry[i].size_lo = LSW(size);
				iltds_ptr->img_entry[i].size_hi = MSW(size);
				iltds_ptr->img_entry[i].swap_mode = 0;
				iltds_ptr->img_entry[i].card_type = 0;
				QL_PRINT(DBG_GLD, ("image offset %x size %x "
				    "bytes\n", offset, size));
				QL_PRINT(DBG_GLD, ("offset %x lsw %x msw %x"
				    " \n", offset, LSW(offset), MSW(offset)));
				offset += size;
			}
			/* Last entry */
			iltds_ptr->time_stamp.region_type =
			    FLT_REGION_TIME_STAMP;
			iltds_ptr->time_stamp.region_version_len = 0;
			iltds_ptr->time_stamp.region_version[0] = 0;
			iltds_ptr->time_stamp.region_version[1] = 0;
			iltds_ptr->time_stamp.region_version[2] = 0;
			iltds_ptr->time_stamp.year = 0x09;
			iltds_ptr->time_stamp.month = 0x01;
			iltds_ptr->time_stamp.day = 0x20;
			iltds_ptr->time_stamp.hour = 0x14;
			iltds_ptr->time_stamp.min = 0x20;
			iltds_ptr->time_stamp.sec = 0x50;

			pheader = (ioctl_header_info_t *)(void *)dmp->b_rptr;
			/* build initial ioctl packet header */
			build_init_pkt_header(qlge, pheader, offset);
			iocp->ioc_count = sizeof (*pheader);
			break;

		case QLA_WRITE_FW_IMAGE_HEADERS:
			len = (uint32_t)iocp->ioc_count;
			if (len == 0)
				return (IOC_INVAL);
			ql_iltds_header_ptr =
			    (ql_iltds_header_t *)(void *)dmp->b_rptr;
			if (len != ql_iltds_header_ptr->length) {
				cmn_err(CE_WARN, "QLA_WRITE_FW_IMAGE_HEADERS "
				    "data length error!"
				    " %x bytes expected, %x received",
				    ql_iltds_header_ptr->length, len);
				return (IOC_INVAL);
			}
			QL_PRINT(DBG_GLD, ("Fw Image header len 0x%x bytes, "
			    "0x%x entries\n",
			    len, ql_iltds_header_ptr->number_entries));
			ql_dump_buf("all copy in data:\n",
			    (uint8_t *)dmp->b_rptr, 8, len);
			mp->b_cont = NULL;
			break;

		case QLA_SOFT_RESET:
			iocp->ioc_count = 0;
			ql_wake_asic_reset_soft_intr(qlge);
			QL_PRINT(DBG_GLD, ("QLA_SOFT_RESET started \n"));
			break;

		default:
			return (IOC_INVAL);
	}

	return (IOC_REPLY);
}

/*
 * Loopback ioctl code
 */
static lb_property_t loopmodes[] = {
	{ normal,	"normal",	QLGE_LOOP_NONE			},
	{ internal,	"parallel",	QLGE_LOOP_INTERNAL_PARALLEL	},
	{ internal,	"serial",	QLGE_LOOP_INTERNAL_SERIAL	},
	{ external,	"phy",		QLGE_LOOP_EXTERNAL_PHY		}
};

/*
 * Set Loopback mode
 */
static enum ioc_reply
qlge_set_loop_mode(qlge_t *qlge, uint32_t mode)
{
	/*
	 * If the mode is same as current mode ...
	 */
	if (mode == qlge->loop_back_mode)
		return (IOC_ACK);

	/*
	 * Validate the requested mode
	 */
	switch (mode) {
	default:
		return (IOC_INVAL);

	case QLGE_LOOP_NONE:
	case QLGE_LOOP_INTERNAL_PARALLEL:
	case QLGE_LOOP_INTERNAL_SERIAL:
	case QLGE_LOOP_EXTERNAL_PHY:
		break;
	}

	/*
	 * All OK; reprogram for the new mode ...
	 */
	qlge->loop_back_mode = mode;
	mutex_enter(&qlge->mbx_mutex);
	(void) ql_set_loop_back_mode(qlge);
	mutex_exit(&qlge->mbx_mutex);
	/* if loopback mode test is done */
	if (mode == QLGE_LOOP_NONE) {
		mutex_enter(&qlge->hw_mutex);
		(void) ql_route_initialize(qlge);
		mutex_exit(&qlge->hw_mutex);
	}

	return (IOC_REPLY);
}
/*
 * Loopback ioctl
 */
/* ARGSUSED */
enum ioc_reply
ql_loop_ioctl(qlge_t *qlge, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	uint32_t *lbmp;
	int cmd;

	_NOTE(ARGUNUSED(wq))
	/*
	 * Validate format of ioctl
	 */
	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		QL_PRINT(DBG_GLD, ("%s(%d) invalid cmd 0x%x\n",
		    __func__, qlge->instance, cmd));
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		if (iocp->ioc_count != sizeof (lb_info_sz_t))
			return (IOC_INVAL);
		lbsp = (void *)mp->b_cont->b_rptr;
		*lbsp = sizeof (loopmodes);
		return (IOC_REPLY);

	case LB_GET_INFO:
		if (iocp->ioc_count != sizeof (loopmodes))
			return (IOC_INVAL);
		lbpp = (void *)mp->b_cont->b_rptr;
		bcopy(loopmodes, lbpp, sizeof (loopmodes));
		return (IOC_REPLY);

	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (void *)mp->b_cont->b_rptr;
		*lbmp = qlge->loop_back_mode;
		return (IOC_REPLY);

	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (void *)mp->b_cont->b_rptr;
		return (qlge_set_loop_mode(qlge, *lbmp));
	}
}

/*
 * Dumps binary data from firmware.
 */
static int
ql_8xxx_binary_core_dump_with_header(qlge_t *qlge, caddr_t buf,
    uint32_t *len_ptr)
{
	caddr_t bp = buf;
	int rval = DDI_SUCCESS;
	ql_dump_image_header_t *ql_dump_image_header_ptr =
	    (ql_dump_image_header_t *)(void *)bp;

	ql_dump_image_header_ptr->signature = DUMP_IMAGE_HEADER_SIGNATURE;
	ql_dump_image_header_ptr->version = 1;
	ql_dump_image_header_ptr->header_length = 16;
	ql_dump_image_header_ptr->data_type = DUMP_TYPE_CORE_DUMP;
	/* point to real dump data area */
	bp += sizeof (ql_dump_image_header_t);
	bcopy(&qlge->ql_mpi_coredump, bp, sizeof (ql_mpi_coredump_t));
	ql_dump_image_header_ptr->data_length = sizeof (ql_mpi_coredump_t);
	/* total length: header + data image */
	ql_dump_image_header_ptr->checksum = (uint16_t)
	    (ql_dump_image_header_ptr->signature
	    +ql_dump_image_header_ptr->version
	    +ql_dump_image_header_ptr->header_length
	    +ql_dump_image_header_ptr->data_type
	    +ql_dump_image_header_ptr->data_length);

	*len_ptr = ql_dump_image_header_ptr->header_length +
	    ql_dump_image_header_ptr->data_length;
	QL_PRINT(DBG_GLD, ("%s done,core dump lenth %d bytes\n",
	    __func__, *len_ptr));
	return (rval);
}

/*
 * Dump registers value in binary format
 */
static int
ql_8xxx_binary_register_dump_with_header(qlge_t *qlge, caddr_t buf,
    uint32_t *len_ptr)
{
	caddr_t bp = buf;
	int i;
	uint32_t *data_ptr;
	int rval = DDI_SUCCESS;

	ql_dump_image_header_t *ql_dump_image_header_ptr =
	    (ql_dump_image_header_t *)(void *)bp;
	ql_dump_image_header_ptr->signature =
	    DUMP_IMAGE_HEADER_SIGNATURE;
	ql_dump_image_header_ptr->version = 1;
	ql_dump_image_header_ptr->header_length = 16;
	ql_dump_image_header_ptr->data_type = DUMP_TYPE_REGISTER_DUMP;
	/* point to real dump data area */
	bp += sizeof (ql_dump_image_header_t);
	data_ptr = (uint32_t *)(void *)bp;

	for (i = 0; i <= 0xfc; i += 4) {
		*data_ptr = ql_read_reg(qlge, i);
		data_ptr++;
	}
	ql_dump_image_header_ptr->data_length = 0x100; /* 0 ~ 0xFF */
	/* total length: header + data image */
	ql_dump_image_header_ptr->checksum = (uint16_t)
	    (ql_dump_image_header_ptr->signature
	    +ql_dump_image_header_ptr->version
	    +ql_dump_image_header_ptr->header_length
	    +ql_dump_image_header_ptr->data_type
	    +ql_dump_image_header_ptr->data_length);

	*len_ptr = ql_dump_image_header_ptr->header_length +
	    ql_dump_image_header_ptr->data_length;

	QL_PRINT(DBG_GLD, ("%s done, dump lenth %x bytes\n", __func__,
	    *len_ptr));

	return (rval);
}

/*
 * Core dump in binary format
 */
static int
ql_binary_core_dump(qlge_t *qlge, uint32_t requested_dumps, uint32_t *len_ptr)
{
	int rval = DDI_FAILURE;
	uint32_t length, size = 0;
	uint64_t timestamp;
	caddr_t bp;
	ql_dump_header_t *ql_dump_header_ptr;
	ql_dump_footer_t *ql_dump_footer_ptr;

	if (qlge->ioctl_buf_ptr == NULL) {
		qlge->ioctl_buf_lenth = IOCTL_MAX_BUF_SIZE; /* 512k */
		qlge->ioctl_buf_ptr =
		    kmem_zalloc(qlge->ioctl_buf_lenth, KM_SLEEP);
		if (qlge->ioctl_buf_ptr == NULL) {
			cmn_err(CE_WARN,
			    "%s(%d): Unable to allocate ioctl buffer",
			    __func__, qlge->instance);
			goto out;
		}
	}

	/* description info header */
	ql_dump_header_ptr = (ql_dump_header_t *)(void *)qlge->ioctl_buf_ptr;
	/* add QTSB signature */
	ql_dump_header_ptr->signature = DUMP_DESCRIPTION_HEADER_SIGNATURE;
	ql_dump_header_ptr->version = 1;
	ql_dump_header_ptr->length = 16;
	ql_dump_header_ptr->reserved = 0;
	/* get dump creation timestamp */
	timestamp = ddi_get_time();
	timestamp *= 1000000;
	ql_dump_header_ptr->time_stamp_lo = LSW(timestamp);
	ql_dump_header_ptr->time_stamp_hi = MSW(timestamp);
	/* point to first image header area */
	length = sizeof (ql_dump_header_t);
	bp = (caddr_t)qlge->ioctl_buf_ptr + length;

	if (CFG_IST(qlge, CFG_CHIP_8100)) {
		/* if dumping all */
		if ((requested_dumps & DUMP_REQUEST_ALL) != 0) {
			ql_dump_header_ptr->num_dumps = 2;
			(void) ql_8xxx_binary_core_dump_with_header(qlge,
			    bp, &size);
			length += size;
			bp = (caddr_t)qlge->ioctl_buf_ptr + length;
			(void) ql_8xxx_binary_register_dump_with_header(qlge,
			    bp, &size);
			length += size;
			bp = (caddr_t)qlge->ioctl_buf_ptr + length;
		} else if ((requested_dumps & DUMP_REQUEST_CORE) != 0) {
			ql_dump_header_ptr->num_dumps = 1;
			(void) ql_8xxx_binary_core_dump_with_header(qlge,
			    bp, &size);
			length += size;
			bp = (caddr_t)qlge->ioctl_buf_ptr + length;
		} else if ((requested_dumps & DUMP_REQUEST_REGISTER) != 0) {
			ql_dump_header_ptr->num_dumps = 1;
			(void) ql_8xxx_binary_register_dump_with_header(qlge,
			    bp, &size);
			length += size;
			bp = (caddr_t)qlge->ioctl_buf_ptr + length;
		} else {
			cmn_err(CE_WARN, "%s(%d): not supported dump type %d",
			    __func__, qlge->instance, requested_dumps);
			goto out;
		}
	}

	ql_dump_footer_ptr = (ql_dump_footer_t *)(void *)bp;
	ql_dump_footer_ptr->signature = DUMP_DESCRIPTION_FOOTER_SIGNATURE;
	ql_dump_footer_ptr->version = 1;
	ql_dump_footer_ptr->length = 16;
	ql_dump_footer_ptr->reserved = 0;
	timestamp = ddi_get_time();
	timestamp *= 1000000;
	ql_dump_footer_ptr->time_stamp_lo = LSW(timestamp);
	ql_dump_footer_ptr->time_stamp_hi = MSW(timestamp);
	length += ql_dump_footer_ptr->length;
	rval = DDI_SUCCESS;
	*len_ptr = length;
	QL_PRINT(DBG_MBX, ("%s(%d): exiting,total %x bytes\n",
	    __func__, qlge->instance, length));
out:
	return (rval);
}

/*
 * build core dump segment header
 */
static void
ql_build_coredump_seg_header(mpi_coredump_segment_header_t *seg_hdr,
    uint32_t seg_number, uint32_t seg_size, uint8_t *desc)
{
	(void) memset(seg_hdr, 0, sizeof (mpi_coredump_segment_header_t));
	seg_hdr->cookie = MPI_COREDUMP_COOKIE;
	seg_hdr->seg_number = seg_number;
	seg_hdr->seg_size = seg_size;
	(void) memcpy(seg_hdr->description, desc,
	    (sizeof (seg_hdr->description))-1);
}

/*
 * Unpause MPI risc
 */
static int
ql_unpause_mpi_risc(qlge_t *qlge)
{
	uint32_t tmp;

	/* Un-pause the RISC */
	tmp = ql_read_reg(qlge, REG_HOST_CMD_STATUS);
	if ((tmp & CSR_RP) == 0)
		return (DDI_FAILURE);

	ql_write_reg(qlge, REG_HOST_CMD_STATUS, CSR_CMD_CLR_PAUSE);
	return (DDI_SUCCESS);
}

/*
 * Pause MPI risc
 */
static int
ql_pause_mpi_risc(qlge_t *qlge)
{
	uint32_t tmp;
	int count = 10;

	/* Pause the RISC */
	ql_write_reg(qlge, REG_HOST_CMD_STATUS, CSR_CMD_SET_PAUSE);
	do {
		tmp = ql_read_reg(qlge, REG_HOST_CMD_STATUS);
		if ((tmp & CSR_RP) != 0)
			break;
		qlge_delay(10);
		count--;
	} while (count);
	return ((count == 0) ? DDI_FAILURE : DDI_SUCCESS);
}

/*
 * Get Interrupt Status registers value
 */
static void
ql_get_intr_states(qlge_t *qlge, uint32_t *buf)
{
	int i;

	for (i = 0; i < MAX_RX_RINGS; i++, buf++) {
		/* read the interrupt enable register for each rx ring */
		ql_write_reg(qlge, REG_INTERRUPT_ENABLE, 0x037f0300 + i);
		*buf = ql_read_reg(qlge, REG_INTERRUPT_ENABLE);
	}
}

/*
 * Read serdes register
 */
static int
ql_read_serdes_reg(qlge_t *qlge, uint32_t reg, uint32_t *data)
{
	int rtn_val = DDI_FAILURE;

	/* wait for reg to come ready */
	if (ql_wait_reg_bit(qlge, REG_XG_SERDES_ADDR,
	    XG_SERDES_ADDR_RDY, BIT_SET, 0) != DDI_SUCCESS)
		goto exit;
	/* set up for reg read */
	ql_write_reg(qlge, REG_XG_SERDES_ADDR, reg | PROC_ADDR_R);
	/* wait for reg to come ready */
	if (ql_wait_reg_bit(qlge, REG_XG_SERDES_ADDR,
	    XG_SERDES_ADDR_RDY, BIT_SET, 0) != DDI_SUCCESS)
		goto exit;
	/* get the data */
	*data = ql_read_reg(qlge, REG_XG_SERDES_DATA);
	rtn_val = DDI_SUCCESS;
exit:
	return (rtn_val);
}

/*
 * Read XGMAC register
 */
static int
ql_get_xgmac_regs(qlge_t *qlge, uint32_t *buf)
{
	int status;
	int i;

	for (i = 0; i < XGMAC_REGISTER_END; i += 4, buf ++) {
		switch (i) {
		case  PAUSE_SRC_LO		:
		case  PAUSE_SRC_HI		:
		case  GLOBAL_CFG		:
		case  TX_CFG			:
		case  RX_CFG			:
		case  FLOW_CTL			:
		case  PAUSE_OPCODE		:
		case  PAUSE_TIMER		:
		case  PAUSE_FRM_DEST_LO		:
		case  PAUSE_FRM_DEST_HI		:
		case  MAC_TX_PARAMS		:
		case  MAC_RX_PARAMS		:
		case  MAC_SYS_INT		:
		case  MAC_SYS_INT_MASK		:
		case  MAC_MGMT_INT		:
		case  MAC_MGMT_IN_MASK		:
		case  EXT_ARB_MODE		:
		case  TX_PKTS		:
		case  TX_PKTS_LO		:
		case  TX_BYTES			:
		case  TX_BYTES_LO		:
		case  TX_MCAST_PKTS		:
		case  TX_MCAST_PKTS_LO		:
		case  TX_BCAST_PKTS		:
		case  TX_BCAST_PKTS_LO		:
		case  TX_UCAST_PKTS		:
		case  TX_UCAST_PKTS_LO		:
		case  TX_CTL_PKTS		:
		case  TX_CTL_PKTS_LO		:
		case  TX_PAUSE_PKTS		:
		case  TX_PAUSE_PKTS_LO		:
		case  TX_64_PKT			:
		case  TX_64_PKT_LO		:
		case  TX_65_TO_127_PKT		:
		case  TX_65_TO_127_PKT_LO	:
		case  TX_128_TO_255_PKT		:
		case  TX_128_TO_255_PKT_LO	:
		case  TX_256_511_PKT		:
		case  TX_256_511_PKT_LO		:
		case  TX_512_TO_1023_PKT	:
		case  TX_512_TO_1023_PKT_LO	:
		case  TX_1024_TO_1518_PKT	:
		case  TX_1024_TO_1518_PKT_LO	:
		case  TX_1519_TO_MAX_PKT	:
		case  TX_1519_TO_MAX_PKT_LO	:
		case  TX_UNDERSIZE_PKT		:
		case  TX_UNDERSIZE_PKT_LO	:
		case  TX_OVERSIZE_PKT		:
		case  TX_OVERSIZE_PKT_LO	:
		case  RX_HALF_FULL_DET		:
		case  TX_HALF_FULL_DET_LO	:
		case  RX_OVERFLOW_DET		:
		case  TX_OVERFLOW_DET_LO	:
		case  RX_HALF_FULL_MASK		:
		case  TX_HALF_FULL_MASK_LO	:
		case  RX_OVERFLOW_MASK		:
		case  TX_OVERFLOW_MASK_LO	:
		case  STAT_CNT_CTL		:
		case  AUX_RX_HALF_FULL_DET	:
		case  AUX_TX_HALF_FULL_DET	:
		case  AUX_RX_OVERFLOW_DET	:
		case  AUX_TX_OVERFLOW_DET	:
		case  AUX_RX_HALF_FULL_MASK	:
		case  AUX_TX_HALF_FULL_MASK	:
		case  AUX_RX_OVERFLOW_MASK	:
		case  AUX_TX_OVERFLOW_MASK	:
		case  RX_BYTES			:
		case  RX_BYTES_LO		:
		case  RX_BYTES_OK		:
		case  RX_BYTES_OK_LO		:
		case  RX_PKTS			:
		case  RX_PKTS_LO		:
		case  RX_PKTS_OK		:
		case  RX_PKTS_OK_LO		:
		case  RX_BCAST_PKTS		:
		case  RX_BCAST_PKTS_LO		:
		case  RX_MCAST_PKTS		:
		case  RX_MCAST_PKTS_LO		:
		case  RX_UCAST_PKTS		:
		case  RX_UCAST_PKTS_LO		:
		case  RX_UNDERSIZE_PKTS		:
		case  RX_UNDERSIZE_PKTS_LO	:
		case  RX_OVERSIZE_PKTS		:
		case  RX_OVERSIZE_PKTS_LO	:
		case  RX_JABBER_PKTS		:
		case  RX_JABBER_PKTS_LO		:
		case  RX_UNDERSIZE_FCERR_PKTS	:
		case  RX_UNDERSIZE_FCERR_PKTS_LO :
		case  RX_DROP_EVENTS		:
		case  RX_DROP_EVENTS_LO		:
		case  RX_FCERR_PKTS		:
		case  RX_FCERR_PKTS_LO		:
		case  RX_ALIGN_ERR		:
		case  RX_ALIGN_ERR_LO		:
		case  RX_SYMBOL_ERR		:
		case  RX_SYMBOL_ERR_LO		:
		case  RX_MAC_ERR		:
		case  RX_MAC_ERR_LO		:
		case  RX_CTL_PKTS		:
		case  RX_CTL_PKTS_LO		:
		case  RX_PAUSE_PKTS		:
		case  RX_PAUSE_PKTS_LO		:
		case  RX_64_PKTS		:
		case  RX_64_PKTS_LO		:
		case  RX_65_TO_127_PKTS		:
		case  RX_65_TO_127_PKTS_LO	:
		case  RX_128_255_PKTS		:
		case  RX_128_255_PKTS_LO	:
		case  RX_256_511_PKTS		:
		case  RX_256_511_PKTS_LO	:
		case  RX_512_TO_1023_PKTS	:
		case  RX_512_TO_1023_PKTS_LO	:
		case  RX_1024_TO_1518_PKTS	:
		case  RX_1024_TO_1518_PKTS_LO	:
		case  RX_1519_TO_MAX_PKTS	:
		case  RX_1519_TO_MAX_PKTS_LO	:
		case  RX_LEN_ERR_PKTS		:
		case  RX_LEN_ERR_PKTS_LO	:
		case  MDIO_TX_DATA		:
		case  MDIO_RX_DATA		:
		case  MDIO_CMD			:
		case  MDIO_PHY_ADDR		:
		case  MDIO_PORT			:
		case  MDIO_STATUS		:
		case  TX_CBFC_PAUSE_FRAMES0	:
		case  TX_CBFC_PAUSE_FRAMES0_LO	:
		case  TX_CBFC_PAUSE_FRAMES1	:
		case  TX_CBFC_PAUSE_FRAMES1_LO	:
		case  TX_CBFC_PAUSE_FRAMES2	:
		case  TX_CBFC_PAUSE_FRAMES2_LO	:
		case  TX_CBFC_PAUSE_FRAMES3	:
		case  TX_CBFC_PAUSE_FRAMES3_LO	:
		case  TX_CBFC_PAUSE_FRAMES4	:
		case  TX_CBFC_PAUSE_FRAMES4_LO	:
		case  TX_CBFC_PAUSE_FRAMES5	:
		case  TX_CBFC_PAUSE_FRAMES5_LO	:
		case  TX_CBFC_PAUSE_FRAMES6	:
		case  TX_CBFC_PAUSE_FRAMES6_LO	:
		case  TX_CBFC_PAUSE_FRAMES7	:
		case  TX_CBFC_PAUSE_FRAMES7_LO	:
		case  TX_FCOE_PKTS		:
		case  TX_FCOE_PKTS_LO		:
		case  TX_MGMT_PKTS		:
		case  TX_MGMT_PKTS_LO		:
		case  RX_CBFC_PAUSE_FRAMES0	:
		case  RX_CBFC_PAUSE_FRAMES0_LO	:
		case  RX_CBFC_PAUSE_FRAMES1	:
		case  RX_CBFC_PAUSE_FRAMES1_LO	:
		case  RX_CBFC_PAUSE_FRAMES2	:
		case  RX_CBFC_PAUSE_FRAMES2_LO	:
		case  RX_CBFC_PAUSE_FRAMES3	:
		case  RX_CBFC_PAUSE_FRAMES3_LO	:
		case  RX_CBFC_PAUSE_FRAMES4	:
		case  RX_CBFC_PAUSE_FRAMES4_LO	:
		case  RX_CBFC_PAUSE_FRAMES5	:
		case  RX_CBFC_PAUSE_FRAMES5_LO	:
		case  RX_CBFC_PAUSE_FRAMES6	:
		case  RX_CBFC_PAUSE_FRAMES6_LO	:
		case  RX_CBFC_PAUSE_FRAMES7	:
		case  RX_CBFC_PAUSE_FRAMES7_LO	:
		case  RX_FCOE_PKTS		:
		case  RX_FCOE_PKTS_LO		:
		case  RX_MGMT_PKTS		:
		case  RX_MGMT_PKTS_LO		:
		case  RX_NIC_FIFO_DROP		:
		case  RX_NIC_FIFO_DROP_LO	:
		case  RX_FCOE_FIFO_DROP		:
		case  RX_FCOE_FIFO_DROP_LO	:
		case  RX_MGMT_FIFO_DROP		:
		case  RX_MGMT_FIFO_DROP_LO	:
		case  RX_PKTS_PRIORITY0		:
		case  RX_PKTS_PRIORITY0_LO	:
		case  RX_PKTS_PRIORITY1		:
		case  RX_PKTS_PRIORITY1_LO	:
		case  RX_PKTS_PRIORITY2		:
		case  RX_PKTS_PRIORITY2_LO	:
		case  RX_PKTS_PRIORITY3		:
		case  RX_PKTS_PRIORITY3_LO	:
		case  RX_PKTS_PRIORITY4		:
		case  RX_PKTS_PRIORITY4_LO	:
		case  RX_PKTS_PRIORITY5		:
		case  RX_PKTS_PRIORITY5_LO	:
		case  RX_PKTS_PRIORITY6		:
		case  RX_PKTS_PRIORITY6_LO	:
		case  RX_PKTS_PRIORITY7		:
		case  RX_PKTS_PRIORITY7_LO	:
		case  RX_OCTETS_PRIORITY0	:
		case  RX_OCTETS_PRIORITY0_LO	:
		case  RX_OCTETS_PRIORITY1	:
		case  RX_OCTETS_PRIORITY1_LO	:
		case  RX_OCTETS_PRIORITY2	:
		case  RX_OCTETS_PRIORITY2_LO	:
		case  RX_OCTETS_PRIORITY3	:
		case  RX_OCTETS_PRIORITY3_LO	:
		case  RX_OCTETS_PRIORITY4	:
		case  RX_OCTETS_PRIORITY4_LO	:
		case  RX_OCTETS_PRIORITY5	:
		case  RX_OCTETS_PRIORITY5_LO	:
		case  RX_OCTETS_PRIORITY6	:
		case  RX_OCTETS_PRIORITY6_LO	:
		case  RX_OCTETS_PRIORITY7	:
		case  RX_OCTETS_PRIORITY7_LO	:
		case  TX_PKTS_PRIORITY0		:
		case  TX_PKTS_PRIORITY0_LO	:
		case  TX_PKTS_PRIORITY1		:
		case  TX_PKTS_PRIORITY1_LO	:
		case  TX_PKTS_PRIORITY2		:
		case  TX_PKTS_PRIORITY2_LO	:
		case  TX_PKTS_PRIORITY3		:
		case  TX_PKTS_PRIORITY3_LO	:
		case  TX_PKTS_PRIORITY4		:
		case  TX_PKTS_PRIORITY4_LO	:
		case  TX_PKTS_PRIORITY5		:
		case  TX_PKTS_PRIORITY5_LO	:
		case  TX_PKTS_PRIORITY6		:
		case  TX_PKTS_PRIORITY6_LO	:
		case  TX_PKTS_PRIORITY7		:
		case  TX_PKTS_PRIORITY7_LO	:
		case  TX_OCTETS_PRIORITY0	:
		case  TX_OCTETS_PRIORITY0_LO	:
		case  TX_OCTETS_PRIORITY1	:
		case  TX_OCTETS_PRIORITY1_LO	:
		case  TX_OCTETS_PRIORITY2	:
		case  TX_OCTETS_PRIORITY2_LO	:
		case  TX_OCTETS_PRIORITY3	:
		case  TX_OCTETS_PRIORITY3_LO	:
		case  TX_OCTETS_PRIORITY4	:
		case  TX_OCTETS_PRIORITY4_LO	:
		case  TX_OCTETS_PRIORITY5	:
		case  TX_OCTETS_PRIORITY5_LO	:
		case  TX_OCTETS_PRIORITY6	:
		case  TX_OCTETS_PRIORITY6_LO	:
		case  TX_OCTETS_PRIORITY7	:
		case  TX_OCTETS_PRIORITY7_LO	:
		case  RX_DISCARD_PRIORITY0	:
		case  RX_DISCARD_PRIORITY0_LO	:
		case  RX_DISCARD_PRIORITY1	:
		case  RX_DISCARD_PRIORITY1_LO	:
		case  RX_DISCARD_PRIORITY2	:
		case  RX_DISCARD_PRIORITY2_LO	:
		case  RX_DISCARD_PRIORITY3	:
		case  RX_DISCARD_PRIORITY3_LO	:
		case  RX_DISCARD_PRIORITY4	:
		case  RX_DISCARD_PRIORITY4_LO	:
		case  RX_DISCARD_PRIORITY5	:
		case  RX_DISCARD_PRIORITY5_LO	:
		case  RX_DISCARD_PRIORITY6	:
		case  RX_DISCARD_PRIORITY6_LO	:
		case  RX_DISCARD_PRIORITY7	:
		case  RX_DISCARD_PRIORITY7_LO	:
			status = ql_read_xgmac_reg(qlge, i, buf);
			if (status != DDI_SUCCESS)
				goto err;
			break;

		default:
			break;
		}
	}
err:
	return (status);
}

/*
 * Read MPI related registers
 */
static int
ql_get_mpi_regs(qlge_t *qlge, uint32_t *buf, uint32_t offset, uint32_t count)
{
	int i, rtn_val = DDI_FAILURE;

	for (i = 0; i < count; i++, buf++) {
		if (ql_read_processor_data(qlge, offset + i, buf)
		    != DDI_SUCCESS) {
			goto out;
		}
	}
	rtn_val = DDI_SUCCESS;
out:
	return (rtn_val);
}

/*
 * Read processor "shadow" register "addr" value and save
 * in "data".Assume all the locks&semaphore have been acquired
 */
static int
ql_get_mpi_shadow_regs(qlge_t *qlge, uint32_t *buf)
{
	uint32_t i;
	int rtn_val = DDI_FAILURE;

#define	RISC_124	0x0003007c
#define	RISC_127	0x0003007f
#define	SHADOW_OFFSET	0xb0000000

	for (i = 0; i < MPI_CORE_SH_REGS_CNT; i++, buf++) {
		if (ql_write_processor_data(qlge, RISC_124,
		    (SHADOW_OFFSET | i << 20)) != DDI_SUCCESS)
			goto end;
		if (ql_read_processor_data(qlge, RISC_127, buf) != DDI_SUCCESS)
			goto end;
	}
	rtn_val = DDI_SUCCESS;

end:
	return (rtn_val);
}

#define	SYS_CLOCK		0x00
#define	PCI_CLOCK		0x80
#define	FC_CLOCK		0x140
#define	XGM_CLOCK		0x180
#define	ADDRESS_REGISTER_ENABLE	0x00010000
#define	UP			0x00008000
#define	MAX_MUX			0x40
#define	MAX_MODULES		0x1F

static uint32_t *
ql_get_probe(qlge_t *qlge, uint32_t clock, uint8_t *valid, uint32_t *buf)
{
	uint32_t module, mux_sel, probe, lo_val, hi_val;

	for (module = 0; module < MAX_MODULES; module ++) {
		if (valid[module]) {
			for (mux_sel = 0; mux_sel < MAX_MUX; mux_sel++) {
				probe = clock | ADDRESS_REGISTER_ENABLE |
				    mux_sel |(module << 9);

				ql_write_reg(qlge, REG_PRB_MX_ADDR, probe);
				lo_val = ql_read_reg(qlge, REG_PRB_MX_DATA);
				if (mux_sel == 0) {
					*buf = probe;
					buf ++;
				}
				probe |= UP;
				ql_write_reg(qlge, REG_PRB_MX_ADDR, probe);
				hi_val = ql_read_reg(qlge, REG_PRB_MX_DATA);
				*buf = lo_val;
				buf++;
				*buf = hi_val;
				buf++;
			}
		}
	}
	return (buf);
}

static int
ql_get_probe_dump(qlge_t *qlge, uint32_t *buf)
{
	uint8_t sys_clock_valid_modules[0x20] = {
		1,	/* 0x00 */
		1,	/* 0x01 */
		1,	/* 0x02 */
		0,	/* 0x03 */
		1,	/* 0x04 */
		1,	/* 0x05 */
		1,	/* 0x06 */
		1,	/* 0x07 */
		1,	/* 0x08 */
		1,	/* 0x09 */
		1,	/* 0x0A */
		1,	/* 0x0B */
		1,	/* 0x0C */
		1,	/* 0x0D */
		1,	/* 0x0E */
		0,	/* 0x0F */
		1,	/* 0x10 */
		1,	/* 0x11 */
		1,	/* 0x12 */
		1,	/* 0x13 */
		0,	/* 0x14 */
		0,	/* 0x15 */
		0,	/* 0x16 */
		0,	/* 0x17 */
		0,	/* 0x18 */
		0,	/* 0x19 */
		0,	/* 0x1A */
		0,	/* 0x1B */
		0,	/* 0x1C */
		0,	/* 0x1D */
		0,	/* 0x1E */
		0	/* 0x1F */
	};

	unsigned char pci_clock_valid_modules[0x20] = {
		1,	/* 0x00 */
		0,	/* 0x01 */
		0,	/* 0x02 */
		0,	/* 0x03 */
		0,	/* 0x04 */
		0,	/* 0x05 */
		1,	/* 0x06 */
		1,	/* 0x07 */
		0,	/* 0x08 */
		0,	/* 0x09 */
		0,	/* 0x0A */
		0,	/* 0x0B */
		0,	/* 0x0C */
		0,	/* 0x0D */
		1,	/* 0x0E */
		0,	/* 0x0F */
		0,	/* 0x10 */
		0,	/* 0x11 */
		0,	/* 0x12 */
		0,	/* 0x13 */
		0,	/* 0x14 */
		0,	/* 0x15 */
		0,	/* 0x16 */
		0,	/* 0x17 */
		0,	/* 0x18 */
		0,	/* 0x19 */
		0,	/* 0x1A */
		0,	/* 0x1B */
		0,	/* 0x1C */
		0,	/* 0x1D */
		0,	/* 0x1E */
		0	/* 0x1F */
	};

	unsigned char xgm_clock_valid_modules[0x20] = {
		1,	/* 0x00 */
		0,	/* 0x01 */
		0,	/* 0x02 */
		1,	/* 0x03 */
		0,	/* 0x04 */
		0,	/* 0x05 */
		0,	/* 0x06 */
		0,	/* 0x07 */
		1,	/* 0x08 */
		1,	/* 0x09 */
		0,	/* 0x0A */
		0,	/* 0x0B */
		1,	/* 0x0C */
		1,	/* 0x0D */
		1,	/* 0x0E */
		0,	/* 0x0F */
		1,	/* 0x10 */
		1,	/* 0x11 */
		0,	/* 0x12 */
		0,	/* 0x13 */
		0,	/* 0x14 */
		0,	/* 0x15 */
		0,	/* 0x16 */
		0,	/* 0x17 */
		0,	/* 0x18 */
		0,	/* 0x19 */
		0,	/* 0x1A */
		0,	/* 0x1B */
		0,	/* 0x1C */
		0,	/* 0x1D */
		0,	/* 0x1E */
		0	/* 0x1F */
	};

	unsigned char fc_clock_valid_modules[0x20] = {
		1,	/* 0x00 */
		0,	/* 0x01 */
		0,	/* 0x02 */
		0,	/* 0x03 */
		0,	/* 0x04 */
		0,	/* 0x05 */
		0,	/* 0x06 */
		0,	/* 0x07 */
		0,	/* 0x08 */
		0,	/* 0x09 */
		0,	/* 0x0A */
		0,	/* 0x0B */
		1,	/* 0x0C */
		1,	/* 0x0D */
		0,	/* 0x0E */
		0,	/* 0x0F */
		0,	/* 0x10 */
		0,	/* 0x11 */
		0,	/* 0x12 */
		0,	/* 0x13 */
		0,	/* 0x14 */
		0,	/* 0x15 */
		0,	/* 0x16 */
		0,	/* 0x17 */
		0,	/* 0x18 */
		0,	/* 0x19 */
		0,	/* 0x1A */
		0,	/* 0x1B */
		0,	/* 0x1C */
		0,	/* 0x1D */
		0,	/* 0x1E */
		0	/* 0x1F */
	};

	/*
	 * First we have to enable the probe mux
	 */
	(void) ql_write_processor_data(qlge, 0x100e, 0x18a20000);

	buf = ql_get_probe(qlge, SYS_CLOCK, sys_clock_valid_modules, buf);

	buf = ql_get_probe(qlge, PCI_CLOCK, pci_clock_valid_modules, buf);

	buf = ql_get_probe(qlge, XGM_CLOCK, xgm_clock_valid_modules, buf);

	buf = ql_get_probe(qlge, FC_CLOCK, fc_clock_valid_modules, buf);

	return (0);

}

/*
 * Dump rounting index registers
 */
void
ql_get_routing_index_registers(qlge_t *qlge, uint32_t *buf)
{
	uint32_t type, index, index_max;
	uint32_t result_index;
	uint32_t result_data;
	uint32_t val;

	for (type = 0; type < 4; type ++) {
		if (type < 2) {
			index_max = 8;
		} else {
			index_max = 16;
		}
		for (index = 0; index < index_max; index ++) {
			val = 0x04000000 | (type << 16) | (index << 8);
			ql_write_reg(qlge, REG_ROUTING_INDEX, val);
			result_index = 0;
			while ((result_index & 0x40000000) == 0) {
				result_index =
				    ql_read_reg(qlge, REG_ROUTING_INDEX);
			}
			result_data = ql_read_reg(qlge, REG_ROUTING_DATA);
			*buf = type;
			buf ++;
			*buf = index;
			buf ++;
			*buf = result_index;
			buf ++;
			*buf = result_data;
			buf ++;
		}
	}
}

/*
 * Dump mac protocol registers
 */
void
ql_get_mac_protocol_registers(qlge_t *qlge, uint32_t *buf)
{
#define	RS_AND_ADR	0x06000000
#define	RS_ONLY		0x04000000
#define	NUM_TYPES	10
	uint32_t result_index, result_data;
	uint32_t type;
	uint32_t index;
	uint32_t offset;
	uint32_t val;
	uint32_t initial_val;
	uint32_t max_index;
	uint32_t max_offset;

	for (type = 0; type < NUM_TYPES; type ++) {
		switch (type) {

		case 0: /* CAM */
			initial_val = RS_AND_ADR;
			max_index = 512;
			max_offset = 3;
			break;

		case 1: /* Multicast MAC Address */
			initial_val = RS_ONLY;
			max_index = 32;
			max_offset = 2;
			break;

		case 2: /* VLAN filter mask */
		case 3: /* MC filter mask */
			initial_val = RS_ONLY;
			max_index = 4096;
			max_offset = 1;
			break;

		case 4: /* FC MAC addresses */
			initial_val = RS_ONLY;
			max_index = 4;
			max_offset = 2;
			break;

		case 5: /* Mgmt MAC addresses */
			initial_val = RS_ONLY;
			max_index = 8;
			max_offset = 2;
			break;

		case 6: /* Mgmt VLAN addresses */
			initial_val = RS_ONLY;
			max_index = 16;
			max_offset = 1;
			break;

		case 7: /* Mgmt IPv4 address */
			initial_val = RS_ONLY;
			max_index = 4;
			max_offset = 1;
			break;

		case 8: /* Mgmt IPv6 address */
			initial_val = RS_ONLY;
			max_index = 4;
			max_offset = 4;
			break;

		case 9: /* Mgmt TCP/UDP Dest port */
			initial_val = RS_ONLY;
			max_index = 4;
			max_offset = 1;
			break;

		default:
			cmn_err(CE_WARN, "Bad type!!! 0x%08x", type);
			max_index = 0;
			max_offset = 0;
			break;
		}
		for (index = 0; index < max_index; index ++) {
			for (offset = 0; offset < max_offset; offset ++) {
				val = initial_val | (type << 16) | (index << 4)
				    | (offset);
				ql_write_reg(qlge,
				    REG_MAC_PROTOCOL_ADDRESS_INDEX, val);
				result_index = 0;
				while ((result_index & 0x40000000) == 0) {
					result_index = ql_read_reg(qlge,
					    REG_MAC_PROTOCOL_ADDRESS_INDEX);
				}
				result_data =
				    ql_read_reg(qlge, REG_MAC_PROTOCOL_DATA);
				*buf = result_index;
				buf ++;
				*buf = result_data;
				buf ++;
			}
		}
	}
}

/*
 * Dump serdes registers
 */
static int
ql_get_serdes_regs(qlge_t *qlge, struct ql_mpi_coredump *mpi_coredump)
{
	uint32_t i, j;
	int status;

	for (i = 0, j = 0; i <= 0x000000034; i += 4) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xaui_an[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x800, j = 0; i <= 0x880; i += 4) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xaui_hss_pcs[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x1000, j = 0; i <= 0x1034; i += 4) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xfi_an[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x1050, j = 0; i <= 0x107c; i += 4) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xfi_train[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x1800, j = 0; i <= 0x1838; i += 4) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xfi_hss_pcs[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x1c00, j = 0; i <= 0x1c1f; i++) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xfi_hss_tx[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x1c40, j = 0; i <= 0x1c5f; i++) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xfi_hss_rx[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

	for (i = 0x1e00, j = 0; i <= 0x1e1f; i++) {
		status = ql_read_serdes_reg(qlge, i,
		    &mpi_coredump->serdes_xfi_hss_pll[j++]);
		if (status != DDI_SUCCESS) {
			goto err;
		}
	}

err:
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Serdes register 0x%x access error", i);
	}

	return (status);
}

/*
 * Dump ets registers
 */
static int
ql_get_ets_regs(qlge_t *qlge, uint32_t *buf)
{
	int i;

	/*
	 * First read out the NIC ETS
	 */
	for (i = 0; i < 8; i++, buf++) {
		ql_write_reg(qlge, REG_NIC_ENHANCED_TX_SCHEDULE,
		    i << 29 | 0x08000000);
		/* wait for reg to come ready */
		/* get the data */
		*buf = ql_read_reg(qlge, REG_NIC_ENHANCED_TX_SCHEDULE);
	}
	/*
	 * Now read out the CNA ETS
	 */
	for (i = 0; i < 2; i ++, buf ++) {
		ql_write_reg(qlge, REG_CNA_ENHANCED_TX_SCHEDULE,
		    i << 29 | 0x08000000);
		/* wait for reg to come ready */
		*buf = ql_read_reg(qlge, REG_CNA_ENHANCED_TX_SCHEDULE);
	}

	return (0);
}

/*
 * Core dump in binary format
 */
int
ql_8xxx_binary_core_dump(qlge_t *qlge, ql_mpi_coredump_t *mpi_coredump)
{
	int		rtn_val = DDI_FAILURE;
	uint64_t	timestamp, phy_addr;
	uint32_t	addr;
	int		i;

	if (ql_sem_spinlock(qlge, QL_PROCESSOR_SEM_MASK) != DDI_SUCCESS) {
		return (rtn_val);
	}

	/* pause the risc */
	if (ql_pause_mpi_risc(qlge) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) Wait for RISC paused timeout.",
		    __func__, qlge->instance);
		goto out;
	}

	/* 0:make core dump header */
	bzero(&(mpi_coredump->mpi_global_header),
	    sizeof (mpi_coredump_global_header_t));
	mpi_coredump->mpi_global_header.cookie = MPI_COREDUMP_COOKIE;
	(void) strcpy(mpi_coredump->mpi_global_header.id_string,
	    "MPI Coredump");
	timestamp = ddi_get_time();
	timestamp *= 1000000;
	mpi_coredump->mpi_global_header.time_lo = LSW(timestamp);
	mpi_coredump->mpi_global_header.time_hi = MSW(timestamp);
	mpi_coredump->mpi_global_header.total_image_size =
	    (uint32_t)(sizeof (ql_mpi_coredump_t));
	mpi_coredump->mpi_global_header.global_header_size =
	    sizeof (mpi_coredump_global_header_t);
	(void) strcpy(mpi_coredump->mpi_global_header.driver_info,
	    "driver version is "VERSIONSTR);

	/* 1:MPI Core Registers */
	ql_build_coredump_seg_header(&mpi_coredump->core_regs_seg_hdr,
	    CORE_SEG_NUM, sizeof (mpi_coredump->core_regs_seg_hdr) +
	    sizeof (mpi_coredump->mpi_core_regs) +
	    sizeof (mpi_coredump->mpi_core_sh_regs),
	    (uint8_t *)"Core Registers");

	/* first, read 127 core registers */
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->mpi_core_regs[0],
	    MPI_CORE_REGS_ADDR, MPI_CORE_REGS_CNT);
	/* read the next 16 shadow registers */
	(void) ql_get_mpi_shadow_regs(qlge,
	    &mpi_coredump->mpi_core_sh_regs[0]);

	/* 2:MPI Test Logic Registers */
	ql_build_coredump_seg_header(&mpi_coredump->test_logic_regs_seg_hdr,
	    TEST_LOGIC_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->test_logic_regs),
	    (uint8_t *)"Test Logic Regs");

	(void) ql_get_mpi_regs(qlge, &mpi_coredump->test_logic_regs[0],
	    TEST_REGS_ADDR, TEST_REGS_CNT);

	/* 3:RMII Registers */
	ql_build_coredump_seg_header(&mpi_coredump->rmii_regs_seg_hdr,
	    RMII_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->rmii_regs),
	    (uint8_t *)"RMII Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->rmii_regs[0],
	    RMII_REGS_ADDR, RMII_REGS_CNT);

	/* 4:FCMAC1 Registers */
	ql_build_coredump_seg_header(&mpi_coredump->fcmac1_regs_seg_hdr,
	    FCMAC1_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->fcmac1_regs),
	    (uint8_t *)"FCMAC1 Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->fcmac1_regs[0],
	    FCMAC1_REGS_ADDR, FCMAC_REGS_CNT);

	/* 5:FCMAC2 Registers */
	ql_build_coredump_seg_header(&mpi_coredump->fcmac2_regs_seg_hdr,
	    FCMAC2_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->fcmac2_regs),
	    (uint8_t *)"FCMAC2 Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->fcmac2_regs[0],
	    FCMAC2_REGS_ADDR, FCMAC_REGS_CNT);

	/* 6:FC1 Mailbox Registers */
	ql_build_coredump_seg_header(&mpi_coredump->fc1_mbx_regs_seg_hdr,
	    FC1_MBOX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->fc1_mbx_regs),
	    (uint8_t *)"FC1 MBox Regs");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->fc1_mbx_regs[0],
	    FC1_MBX_REGS_ADDR, FC_MBX_REGS_CNT);

	/* 7:IDE Registers */
	ql_build_coredump_seg_header(&mpi_coredump->ide_regs_seg_hdr,
	    IDE_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->ide_regs),
	    (uint8_t *)"IDE Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->ide_regs[0],
	    IDE_REGS_ADDR, IDE_REGS_CNT);

	/* 8:Host1 Mailbox Registers */
	ql_build_coredump_seg_header(&mpi_coredump->nic1_mbx_regs_seg_hdr,
	    NIC1_MBOX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->nic1_mbx_regs),
	    (uint8_t *)"NIC1 MBox Regs");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->nic1_mbx_regs[0],
	    NIC1_MBX_REGS_ADDR, NIC_MBX_REGS_CNT);

	/* 9:SMBus Registers */
	ql_build_coredump_seg_header(&mpi_coredump->smbus_regs_seg_hdr,
	    SMBUS_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->smbus_regs),
	    (uint8_t *)"SMBus Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->smbus_regs[0],
	    SMBUS_REGS_ADDR, SMBUS_REGS_CNT);

	/* 10:FC2 Mailbox Registers */
	ql_build_coredump_seg_header(&mpi_coredump->fc2_mbx_regs_seg_hdr,
	    FC2_MBOX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->fc2_mbx_regs),
	    (uint8_t *)"FC2 MBox Regs");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->fc2_mbx_regs[0],
	    FC2_MBX_REGS_ADDR, FC_MBX_REGS_CNT);

	/* 11:Host2 Mailbox Registers */
	ql_build_coredump_seg_header(&mpi_coredump->nic2_mbx_regs_seg_hdr,
	    NIC2_MBOX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->nic2_mbx_regs),
	    (uint8_t *)"NIC2 MBox Regs");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->nic2_mbx_regs[0],
	    NIC2_MBX_REGS_ADDR, NIC_MBX_REGS_CNT);

	/* 12:i2C Registers */
	ql_build_coredump_seg_header(&mpi_coredump->i2c_regs_seg_hdr,
	    I2C_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->i2c_regs),
	    (uint8_t *)"I2C Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->i2c_regs[0],
	    I2C_REGS_ADDR, I2C_REGS_CNT);

	/* 13:MEMC Registers */
	ql_build_coredump_seg_header(&mpi_coredump->memc_regs_seg_hdr,
	    MEMC_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->memc_regs),
	    (uint8_t *)"MEMC Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->memc_regs[0],
	    MEMC_REGS_ADDR, MEMC_REGS_CNT);

	/* 14:PBus Registers */
	ql_build_coredump_seg_header(&mpi_coredump->pbus_regs_seg_hdr,
	    PBUS_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->pbus_regs),
	    (uint8_t *)"PBUS Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->pbus_regs[0],
	    PBUS_REGS_ADDR, PBUS_REGS_CNT);

	/* 15:MDE Registers */
	ql_build_coredump_seg_header(&mpi_coredump->mde_regs_seg_hdr,
	    MDE_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->mde_regs),
	    (uint8_t *)"MDE Registers");
	(void) ql_get_mpi_regs(qlge, &mpi_coredump->mde_regs[0],
	    MDE_REGS_ADDR, MDE_REGS_CNT);

	ql_build_coredump_seg_header(&mpi_coredump->xaui_an_hdr,
	    XAUI_AN_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xaui_an),
	    (uint8_t *)"XAUI AN Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xaui_hss_pcs_hdr,
	    XAUI_HSS_PCS_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xaui_hss_pcs),
	    (uint8_t *)"XAUI HSS PCS Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xfi_an_hdr,
	    XFI_AN_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xfi_an),
	    (uint8_t *)"XFI AN Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xfi_train_hdr,
	    XFI_TRAIN_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xfi_train),
	    (uint8_t *)"XFI TRAIN Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xfi_hss_pcs_hdr,
	    XFI_HSS_PCS_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xfi_hss_pcs),
	    (uint8_t *)"XFI HSS PCS Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xfi_hss_tx_hdr,
	    XFI_HSS_TX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xfi_hss_tx),
	    (uint8_t *)"XFI HSS TX Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xfi_hss_rx_hdr,
	    XFI_HSS_RX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xfi_hss_rx),
	    (uint8_t *)"XFI HSS RX Registers");

	ql_build_coredump_seg_header(&mpi_coredump->xfi_hss_pll_hdr,
	    XFI_HSS_PLL_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->serdes_xfi_hss_pll),
	    (uint8_t *)"XFI HSS PLL Registers");

	(void) ql_get_serdes_regs(qlge, mpi_coredump);

	/* 16:NIC Ctrl Registers Port1 */
	ql_build_coredump_seg_header(&mpi_coredump->nic_regs_seg_hdr,
	    NIC1_CONTROL_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->nic_regs),
	    (uint8_t *)"NIC Registers");
	i = 0;
	for (addr = 0; addr <= 0xFC; i++) {
		mpi_coredump->nic_regs[i] = ql_read_reg(qlge, addr);
		addr += 4;
	}

	ql_build_coredump_seg_header(&mpi_coredump->intr_states_seg_hdr,
	    INTR_STATES_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->intr_states),
	    (uint8_t *)"INTR States");
	ql_get_intr_states(qlge, &mpi_coredump->intr_states[0]);

	ql_build_coredump_seg_header(&mpi_coredump->xgmac_seg_hdr,
	    NIC1_XGMAC_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->xgmac),
	    (uint8_t *)"NIC XGMac Registers");
	(void) ql_get_xgmac_regs(qlge, &mpi_coredump->xgmac[0]);

	ql_build_coredump_seg_header(&mpi_coredump->probe_dump_seg_hdr,
	    PROBE_DUMP_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->probe_dump),
	    (uint8_t *)"Probe Dump");
	(void) ql_get_probe_dump(qlge, &mpi_coredump->probe_dump[0]);

	ql_build_coredump_seg_header(&mpi_coredump->routing_reg_seg_hdr,
	    ROUTING_INDEX_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->routing_regs),
	    (uint8_t *)"Routing Regs");

	ql_get_routing_index_registers(qlge, &mpi_coredump->routing_regs[0]);

	ql_build_coredump_seg_header(&mpi_coredump->mac_prot_reg_seg_hdr,
	    MAC_PROTOCOL_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->mac_prot_regs),
	    (uint8_t *)"MAC Prot Regs");

	ql_get_mac_protocol_registers(qlge, &mpi_coredump->mac_prot_regs[0]);

	ql_build_coredump_seg_header(&mpi_coredump->ets_seg_hdr,
	    ETS_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->ets),
	    (uint8_t *)"ETS Registers");

	(void) ql_get_ets_regs(qlge, &mpi_coredump->ets[0]);

	/* clear the pause */
	if (ql_unpause_mpi_risc(qlge) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "Failed RISC unpause.");
		goto out;
	}

	/* Reset the MPI Processor */
	if (ql_reset_mpi_risc(qlge) != DDI_SUCCESS) {
		goto out;
	}

	/* 22:WCS MPI Ram ?? */
	ql_build_coredump_seg_header(&mpi_coredump->code_ram_seg_hdr,
	    WCS_RAM_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->code_ram),
	    (uint8_t *)"WCS RAM");
	phy_addr = qlge->ioctl_buf_dma_attr.dma_addr;
	if (ql_read_risc_ram(qlge, CODE_RAM_ADDR, phy_addr, CODE_RAM_CNT)
	    == DDI_SUCCESS) {
		(void) ddi_dma_sync(qlge->ioctl_buf_dma_attr.dma_handle, 0,
		    sizeof (mpi_coredump->code_ram), DDI_DMA_SYNC_FORKERNEL);
		bcopy(qlge->ioctl_buf_dma_attr.vaddr,
		    mpi_coredump->code_ram,
		    sizeof (mpi_coredump->code_ram));
	} else {
		mutex_exit(&qlge->mbx_mutex);
		goto out;
	}

	/* 23:MEMC Ram ?? */
	ql_build_coredump_seg_header(&mpi_coredump->memc_ram_seg_hdr,
	    MEMC_RAM_SEG_NUM,
	    sizeof (mpi_coredump_segment_header_t) +
	    sizeof (mpi_coredump->memc_ram),
	    (uint8_t *)"MEMC RAM");
	phy_addr = qlge->ioctl_buf_dma_attr.dma_addr;
	if (ql_read_risc_ram(qlge, MEMC_RAM_ADDR, phy_addr, MEMC_RAM_CNT)
	    == DDI_SUCCESS) {
		(void) ddi_dma_sync(qlge->ioctl_buf_dma_attr.dma_handle, 0,
		    sizeof (mpi_coredump->memc_ram), DDI_DMA_SYNC_FORKERNEL);
		bcopy(qlge->ioctl_buf_dma_attr.vaddr, mpi_coredump->memc_ram,
		    sizeof (mpi_coredump->memc_ram));
	} else {
		mutex_exit(&qlge->mbx_mutex);
		goto out;
	}
	/*
	 * 24. Restart MPI
	 */
	if (ql_write_processor_data(qlge, 0x1010, 1) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "MPI restart failure.");
	}

	rtn_val = DDI_SUCCESS;
out:
	ql_sem_unlock(qlge, QL_PROCESSOR_SEM_MASK);
	return (rtn_val);
}
