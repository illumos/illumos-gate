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
/*
 * Local Function Prototypes.
 */
static int ql_read_flash(qlge_t *, uint32_t, uint32_t *);
static int ql_write_flash(qlge_t *, uint32_t, uint32_t);
static int ql_protect_flash(qlge_t *);
static int ql_unprotect_flash(qlge_t *);

/*
 * ql_flash_id
 * The flash memory chip exports 3 ID bytes in the order of manufacturer, id,
 * capability
 */
int
ql_flash_id(qlge_t *qlge)
{
	int rval;
	uint32_t fdata = 0;

	/*
	 * Send Restore command (0xAB) to release Flash from
	 * possible deep power down state
	 */
	rval = ql_read_flash(qlge, FLASH_CONF_ADDR | 0x300 | FLASH_RES_CMD,
	    &fdata);
	QL_PRINT(DBG_FLASH, ("%s(%d) flash electronic signature is %x \n",
	    __func__, qlge->instance, fdata));
	fdata = 0;

	/* 0x9F */
	rval = ql_read_flash(qlge, FLASH_CONF_ADDR | 0x0400 | FLASH_RDID_CMD,
	    &fdata);

	if ((rval != DDI_SUCCESS) || (fdata == 0)) {
		cmn_err(CE_WARN, "%s(%d) read_flash failed 0x%x.",
		    __func__, qlge->instance, fdata);
	} else {
		qlge->flash_info.flash_manuf = LSB(LSW(fdata));
		qlge->flash_info.flash_id = MSB(LSW(fdata));
		qlge->flash_info.flash_cap = LSB(MSW(fdata));
		QL_PRINT(DBG_FLASH, ("%s(%d) flash manufacturer 0x%x,"
		    " flash id 0x%x, flash cap 0x%x\n",
		    __func__, qlge->instance,
		    qlge->flash_info.flash_manuf, qlge->flash_info.flash_id,
		    qlge->flash_info.flash_cap));
	}
	return (rval);
}

/*
 * qlge_dump_fcode
 * Dumps fcode from flash.
 */
int
qlge_dump_fcode(qlge_t *qlge, uint8_t *dp, uint32_t size, uint32_t startpos)
{
	uint32_t cnt, data, addr;
	int rval = DDI_SUCCESS;

	QL_PRINT(DBG_FLASH, ("%s(%d) entered to read address %x, %x bytes\n",
	    __func__, qlge->instance, startpos, size));

	/* make sure startpos+size doesn't exceed flash */
	if (size + startpos > qlge->fdesc.flash_size) {
		cmn_err(CE_WARN, "%s(%d) exceeded flash range, sz=%xh, stp=%xh,"
		    " flsz=%xh", __func__, qlge->instance,
		    size, startpos, qlge->fdesc.flash_size);
		return (DDI_FAILURE);
	}

	/* check start addr is 32 bit or 4 byte aligned for M25Pxx */
	if ((startpos & 0x3) != 0) {
		cmn_err(CE_WARN, "%s(%d) incorrect buffer size alignment",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	/* adjust flash start addr for 32 bit words */
	addr = startpos / 4;

	/* Read fcode data from flash. */
	cnt = startpos;
	size += startpos;
	while (cnt < size) {
		/* Allow other system activity. */
		if (cnt % 0x1000 == 0) {
			drv_usecwait(1);
		}
		rval = ql_read_flash(qlge, addr++, &data);
		if (rval != DDI_SUCCESS) {
			break;
		}
		*dp++ = LSB(LSW(data));
		*dp++ = MSB(LSW(data));
		*dp++ = LSB(MSW(data));
		*dp++ = MSB(MSW(data));
		cnt += 4;
	}

	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed, rval = %xh", rval);
	}
	return (rval);
}

int
ql_erase_and_write_to_flash(qlge_t *qlge, uint8_t *dp, uint32_t size,
    uint32_t faddr)
{
	int rval = DDI_FAILURE;
	uint32_t cnt, rest_addr, fdata;

	QL_PRINT(DBG_FLASH, ("%s(%d) entered to write addr %x, %d bytes\n",
	    __func__, qlge->instance, faddr, size));

	/* start address must be 32 bit word aligned */
	if ((faddr & 0x3) != 0) {
		cmn_err(CE_WARN, "%s(%d) incorrect buffer size alignment",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	/* setup mask of address range within a sector */
	rest_addr = (qlge->fdesc.block_size - 1) >> 2;

	faddr = faddr >> 2;	/* flash gets 32 bit words */

	/*
	 * Write data to flash.
	 */
	cnt = 0;
	size = (size + 3) >> 2;	/* Round up & convert to dwords */
	while (cnt < size) {
		/* Beginning of a sector? do a sector erase */
		if ((faddr & rest_addr) == 0) {
			fdata = (faddr & ~rest_addr) << 2;
			fdata = (fdata & 0xff00) |
			    (fdata << 16 & 0xff0000) |
			    (fdata >> 16 & 0xff);
			/* 64k bytes sector erase */
			rval = ql_write_flash(qlge, /* 0xd8 */
			    FLASH_CONF_ADDR | 0x0300 | qlge->fdesc.erase_cmd,
			    fdata);

			if (rval != DDI_SUCCESS) {
				cmn_err(CE_WARN, "Unable to flash sector: "
				    "address=%xh", faddr);
				goto out;
			}
		}
		/* Write data */
		fdata = *dp++;
		fdata |= *dp++ << 8;
		fdata |= *dp++ << 16;
		fdata |= *dp++ << 24;

		rval = ql_write_flash(qlge, faddr, fdata);
		if (rval != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Unable to program flash "
			    "address=%xh data=%xh", faddr,
			    *dp);
			goto out;
		}
		cnt++;
		faddr++;

		/* Allow other system activity. */
		if (cnt % 0x1000 == 0) {
			qlge_delay(10000);
		}
	}
	rval = DDI_SUCCESS;
out:
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d failed=%xh",
		    __func__, qlge->instance, rval);
	}
	return (rval);
}

void
get_sector_number(qlge_t *qlge, uint32_t faddr, uint32_t *psector)
{
	*psector = faddr / qlge->fdesc.block_size; /* 0x10000 */
}

/*
 * qlge_load_flash
 * Write "size" bytes from memory "dp" to flash address "faddr".
 * faddr = 32bit word flash address.
 */
int
qlge_load_flash(qlge_t *qlge, uint8_t *dp, uint32_t len, uint32_t faddr)
{
	int rval = DDI_FAILURE;
	uint32_t start_block, end_block;
	uint32_t start_byte, end_byte;
	uint32_t num;
	uint32_t sector_size, addr_src, addr_desc;
	uint8_t *temp;
	caddr_t bp, bdesc;

	QL_PRINT(DBG_FLASH, ("%s(%d) entered to write addr %x, %d bytes\n",
	    __func__, qlge->instance, faddr, len));

	sector_size = qlge->fdesc.block_size;

	if (faddr > qlge->fdesc.flash_size) {
		cmn_err(CE_WARN, "%s(%d): invalid flash write address %x",
		    __func__, qlge->instance, faddr);
		return (DDI_FAILURE);
	}
	/* Get semaphore to access Flash Address and Flash Data Registers */
	if (ql_sem_spinlock(qlge, QL_FLASH_SEM_MASK) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	temp = kmem_zalloc(sector_size, KM_SLEEP);
	if (temp == NULL) {
		cmn_err(CE_WARN, "%s(%d): Unable to allocate buffer",
		    __func__, qlge->instance);
		ql_sem_unlock(qlge, QL_FLASH_SEM_MASK);
		return (DDI_FAILURE);
	}

	(void) ql_unprotect_flash(qlge);

	get_sector_number(qlge, faddr, &start_block);
	get_sector_number(qlge, faddr + len - 1, &end_block);

	QL_PRINT(DBG_FLASH, ("%s(%d) start_block %x, end_block %x\n",
	    __func__, qlge->instance, start_block, end_block));

	for (num = start_block; num <= end_block; num++) {
		QL_PRINT(DBG_FLASH,
		    ("%s(%d) sector_size 0x%x, sector read addr %x\n",
		    __func__, qlge->instance, sector_size, num * sector_size));
		/* read one whole sector flash data to buffer */
		rval = qlge_dump_fcode(qlge, (uint8_t *)temp, sector_size,
		    num * sector_size);

		start_byte = num * sector_size;
		end_byte = start_byte + sector_size -1;
		if (start_byte < faddr)
			start_byte = faddr;
		if (end_byte > (faddr + len))
			end_byte = (faddr + len - 1);

		addr_src = start_byte - faddr;
		addr_desc = start_byte - num * sector_size;
		bp = (caddr_t)dp + addr_src;
		bdesc = (caddr_t)temp + addr_desc;
		bcopy(bp, bdesc, (end_byte - start_byte + 1));

		/* write the whole sector data to flash */
		if (ql_erase_and_write_to_flash(qlge, temp, sector_size,
		    num * sector_size) != DDI_SUCCESS)
			goto out;
	}
	rval = DDI_SUCCESS;
out:
	(void) ql_protect_flash(qlge);
	kmem_free(temp, sector_size);

	ql_sem_unlock(qlge, QL_FLASH_SEM_MASK);

	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d failed=%xh",
		    __func__, qlge->instance, rval);
	}

	return (rval);
}


/*
 * ql_check_pci
 * checks the passed buffer for a valid pci signature and
 * expected (and in range) pci length values.
 * On successful pci check, nextpos adjusted to next pci header.
 */
static int
ql_check_pci(qlge_t *qlge, uint8_t *buf, uint32_t *nextpos)
{
	pci_header_t *pcih;
	pci_data_t *pcid;
	uint32_t doff;
	uint8_t *pciinfo;
	uint32_t image_size = 0;
	int rval = CONTINUE_SEARCH;

	QL_PRINT(DBG_FLASH, ("%s(%d) check image at 0x%x\n",
	    __func__, qlge->instance, *nextpos));

	if (buf != NULL) {
		pciinfo = buf;
	} else {
		cmn_err(CE_WARN, "%s(%d) failed, null buf ptr passed",
		    __func__, qlge->instance);
		return (STOP_SEARCH);
	}

	/* get the pci header image length */
	pcih = (pci_header_t *)pciinfo;

	doff = pcih->dataoffset[1];
	doff <<= 8;
	doff |= pcih->dataoffset[0];

	/* some header section sanity check */
	if (pcih->signature[0] != PCI_HEADER0 /* '55' */ ||
	    pcih->signature[1] != PCI_HEADER1 /* 'AA' */ || doff > 50) {
		cmn_err(CE_WARN, "%s(%d) image format error: s0=%xh, s1=%xh,"
		    "off=%xh\n", __func__, qlge->instance,
		    pcih->signature[0], pcih->signature[1], doff);
		return (STOP_SEARCH);
	}

	pcid = (pci_data_t *)(pciinfo + doff);

	/* a slight sanity data section check */
	if (pcid->signature[0] != 'P' || pcid->signature[1] != 'C' ||
	    pcid->signature[2] != 'I' || pcid->signature[3] != 'R') {
		cmn_err(CE_WARN, "%s(%d) failed, data sig mismatch!",
		    __func__, qlge->instance);
		return (STOP_SEARCH);
	}
	image_size =
	    (pcid->imagelength[0] | (pcid->imagelength[1] << 8))*
	    PCI_SECTOR_SIZE /* 512 */;

	switch (pcid->codetype) {
	case PCI_CODE_X86PC:
		QL_PRINT(DBG_FLASH, ("%s(%d) boot image is FTYPE_BIOS \n",
		    __func__, qlge->instance));
		break;
	case PCI_CODE_FCODE:
		QL_PRINT(DBG_FLASH, ("%s(%d) boot image is FTYPE_FCODE \n",
		    __func__, qlge->instance));
		break;
	case PCI_CODE_EFI:
		QL_PRINT(DBG_FLASH, ("%s(%d) boot image is FTYPE_EFI \n",
		    __func__, qlge->instance));
		break;
	case PCI_CODE_HPPA:
		QL_PRINT(DBG_FLASH, ("%s(%d) boot image is PCI_CODE_HPPA \n",
		    __func__, qlge->instance));
		break;
	default:
		QL_PRINT(DBG_FLASH, ("%s(%d) boot image is FTYPE_UNKNOWN \n",
		    __func__, qlge->instance));
		break;
	}

	QL_PRINT(DBG_FLASH, ("%s(%d) image size %x at %x\n",
	    __func__, qlge->instance, image_size, *nextpos));

	if (pcid->indicator == PCI_IND_LAST_IMAGE) {
		QL_PRINT(DBG_FLASH, ("%s(%d) last boot image found \n",
		    __func__, qlge->instance));
		rval = LAST_IMAGE_FOUND;
	} else {
		rval = CONTINUE_SEARCH;
	}
	/* Get the next flash image address */
	*nextpos += image_size;

	return (rval);
}

/*
 * ql_find_flash_layout_table_data_structure
 * Find Flash Layout Table Data Structure (FLTDS) that
 * is located at the end of last boot image.
 * Assume FLTDS is located with first 2M bytes.
 * Note:
 * Driver must be in stalled state prior to entering or
 * add code to this function prior to calling ql_setup_flash()
 */
int
ql_find_flash_layout_table_data_structure_addr(qlge_t *qlge)
{
	int rval = DDI_FAILURE;
	int result = CONTINUE_SEARCH;
	uint32_t freadpos = 0;
	uint8_t buf[FBUFSIZE];

	if (qlge->flash_fltds_addr != 0) {
		QL_PRINT(DBG_FLASH, ("%s(%d) done already\n",
		    __func__, qlge->instance));
		return (DDI_SUCCESS);
	}
	/*
	 * Temporarily set the fdesc.flash_size to
	 * 1M flash size to avoid failing of ql_dump_focde.
	 */
	qlge->fdesc.flash_size = FLASH_FIRMWARE_IMAGE_ADDR;

	while (result == CONTINUE_SEARCH) {

		if ((rval = qlge_dump_fcode(qlge, buf, FBUFSIZE, freadpos))
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d) qlge_dump_fcode failed"
			    " pos=%xh rval=%xh",
			    __func__, qlge->instance, freadpos, rval);
			break;
		}
		/*
		 * checkout the pci boot image format
		 * and get next read address
		 */
		result = ql_check_pci(qlge, buf, &freadpos);
		/*
		 * find last image? If so, then the freadpos
		 * is the address of FLTDS
		 */
		if (result == LAST_IMAGE_FOUND) {
			QL_PRINT(DBG_FLASH,
			    ("%s(%d) flash layout table data structure "
			    "(FLTDS) address is at %x \n", __func__,
			    qlge->instance, freadpos));
			qlge->flash_fltds_addr = freadpos;
			rval = DDI_SUCCESS;
			break;
		} else if (result == STOP_SEARCH) {
			cmn_err(CE_WARN, "%s(%d) flash header incorrect,"
			    "stop searching",
			    __func__, qlge->instance);
			break;
		}
	}
	return (rval);
}

/*
 * ql_flash_fltds
 * Get flash layout table data structure table.
 */
static int
ql_flash_fltds(qlge_t *qlge)
{
	uint32_t cnt;
	uint16_t chksum, *bp, data;
	int rval;

	rval = qlge_dump_fcode(qlge, (uint8_t *)&qlge->fltds,
	    sizeof (ql_fltds_t), qlge->flash_fltds_addr);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d)read error",
		    __func__, qlge->instance);
		bzero(&qlge->fltds, sizeof (ql_fltds_t));
		return (rval);
	}

	QL_DUMP(DBG_FLASH, "flash layout table data structure:\n",
	    &qlge->fltds, 8, sizeof (ql_fltds_t));

	chksum = 0;
	data = 0;
	bp = (uint16_t *)&qlge->fltds;
	for (cnt = 0; cnt < (sizeof (ql_fltds_t)) / 2; cnt++) {
		data = *bp;
		LITTLE_ENDIAN_16(&data);
		chksum += data;
		bp++;
	}

	LITTLE_ENDIAN_32(&qlge->fltds.signature);
	LITTLE_ENDIAN_16(&qlge->fltds.flt_addr_lo);
	LITTLE_ENDIAN_16(&qlge->fltds.flt_addr_hi);
	LITTLE_ENDIAN_16(&qlge->fltds.checksum);

	QL_PRINT(DBG_FLASH, ("%s(%d) signature %xh\n",
	    __func__, qlge->instance, qlge->fltds.signature));
	QL_PRINT(DBG_FLASH, ("%s(%d) flt_addr_lo %xh\n",
	    __func__, qlge->instance, qlge->fltds.flt_addr_lo));
	QL_PRINT(DBG_FLASH, ("%s(%d) flt_addr_hi %xh\n",
	    __func__, qlge->instance, qlge->fltds.flt_addr_hi));
	QL_PRINT(DBG_FLASH, ("%s(%d) version %xh\n",
	    __func__, qlge->instance, qlge->fltds.version));
	QL_PRINT(DBG_FLASH, ("%s(%d) checksum %xh\n",
	    __func__, qlge->instance, qlge->fltds.checksum));
	/* QFLT */
	if (chksum != 0 || qlge->fltds.signature != FLASH_FLTDS_SIGNATURE) {
		cmn_err(CE_WARN, "%s(%d) invalid flash layout table data"
		    " structure", __func__, qlge->instance);
		bzero(&qlge->fltds, sizeof (ql_fltds_t));
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * ql_flash_flt
 * Get flash layout table.
 */
int
ql_flash_flt(qlge_t *qlge)
{
	uint32_t addr, cnt;
	int rval = DDI_FAILURE;
	ql_flt_entry_t *entry;
	uint8_t region;

	addr = qlge->fltds.flt_addr_hi;
	addr <<= 16;
	addr |= qlge->fltds.flt_addr_lo;

	/* first read flt header to know how long the table is */
	rval = qlge_dump_fcode(qlge, (uint8_t *)&qlge->flt.header,
	    sizeof (ql_flt_header_t), addr);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) read flt header at %x error",
		    __func__, qlge->instance, addr);
		bzero(&qlge->flt, sizeof (ql_flt_header_t));
		return (rval);
	}

	LITTLE_ENDIAN_16(&qlge->flt.header.version);
	LITTLE_ENDIAN_16(&qlge->flt.header.length);
	LITTLE_ENDIAN_16(&qlge->flt.header.checksum);
	LITTLE_ENDIAN_16(&qlge->flt.header.reserved);

	if ((qlge->flt.header.version != 1) &&
	    (qlge->flt.header.version != 0)) {
		cmn_err(CE_WARN, "%s(%d) flt header version %x unsupported",
		    __func__, qlge->instance, qlge->flt.header.version);
		bzero(&qlge->flt, sizeof (ql_flt_header_t));
		return (DDI_FAILURE);
	}
	/* 2.allocate memory to save all flt table entries */
	if ((qlge->flt.ql_flt_entry_ptr = (ql_flt_entry_t *)
	    (kmem_zalloc(qlge->flt.header.length, KM_SLEEP))) == NULL) {
		cmn_err(CE_WARN, "%s(%d) flt table alloc failed",
		    __func__, qlge->instance);
		goto err;
	}
	/* how many tables? */
	qlge->flt.num_entries = (uint16_t)(qlge->flt.header.length /
	    sizeof (ql_flt_entry_t));

	/* 3. read the rest of flt table */
	addr += (uint32_t)sizeof (ql_flt_header_t);
	QL_PRINT(DBG_FLASH, ("%s(%d) flt has %x entries \n",
	    __func__, qlge->instance, qlge->flt.num_entries));
	rval = qlge_dump_fcode(qlge,
	    (uint8_t *)qlge->flt.ql_flt_entry_ptr, qlge->flt.header.length,
	    addr);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "read flt table entry error");
		goto err;
	}

	entry = (ql_flt_entry_t *)qlge->flt.ql_flt_entry_ptr;
	for (cnt = 0; cnt < qlge->flt.num_entries; cnt++) {
		LITTLE_ENDIAN_32(&entry->size);
		LITTLE_ENDIAN_32(&entry->begin_addr);
		LITTLE_ENDIAN_32(&entry->end_addr);
		entry++;
	}
	/* TO Do :4. Checksum verification */

	/* 5.search index of Flash Descriptor Table in the Flash Layout Table */
	entry = (ql_flt_entry_t *)qlge->flt.ql_flt_entry_ptr;
	qlge->flash_fdt_addr = 0;
	for (cnt = 0; cnt < qlge->flt.num_entries; cnt++) {
		if (entry->region == FLT_REGION_FDT) {
			qlge->flash_flt_fdt_index = cnt;
			qlge->flash_fdt_addr = entry->begin_addr;
			qlge->flash_fdt_size = entry->size;
			QL_PRINT(DBG_FLASH, ("%s(%d) flash_flt_fdt_index is"
			    " %x, addr %x,size %x \n", __func__,
			    qlge->instance,
			    cnt, entry->begin_addr, entry->size));
			break;
		}
		entry++;
	}

	if (qlge->flash_fdt_addr == 0) {
		cmn_err(CE_WARN, "%s(%d) flash descriptor table not found",
		    __func__, qlge->instance);
		goto err;
	}
	/* 6.search index of Nic Config. Table in the Flash Layout Table */
	entry = (ql_flt_entry_t *)qlge->flt.ql_flt_entry_ptr;
	if (qlge->func_number == qlge->fn0_net)
		region = FLT_REGION_NIC_PARAM0;
	else
		region = FLT_REGION_NIC_PARAM1;
	qlge->flash_nic_config_table_addr = 0;
	for (cnt = 0; cnt < qlge->flt.num_entries; cnt++) {
		if (entry->region == region) {
			qlge->flash_flt_nic_config_table_index = cnt;
			qlge->flash_nic_config_table_addr = entry->begin_addr;
			qlge->flash_nic_config_table_size = entry->size;
			QL_PRINT(DBG_FLASH, ("%s(%d) "
			    "flash_flt_nic_config_table_index "
			    "is %x, address %x, size %x \n",
			    __func__, qlge->instance,
			    cnt, entry->begin_addr, entry->size));
			break;
		}
		entry++;
	}
	if (qlge->flash_nic_config_table_addr == 0) {
		cmn_err(CE_WARN, "%s(%d) NIC Configuration Table not found",
		    __func__, qlge->instance);
		goto err;
	}

	return (DDI_SUCCESS);
err:
	bzero(&qlge->flt, sizeof (ql_flt_header_t));
	if (qlge->flt.ql_flt_entry_ptr != NULL) {
		bzero(&qlge->flt.ql_flt_entry_ptr, qlge->flt.header.length);
		kmem_free(qlge->flt.ql_flt_entry_ptr, qlge->flt.header.length);
		qlge->flt.ql_flt_entry_ptr = NULL;
	}
	cmn_err(CE_WARN, "%s(%d) read FLT failed", __func__, qlge->instance);
	return (DDI_FAILURE);
}

/*
 * ql_flash_desc
 * Get flash descriptor table.
 */
static int
ql_flash_desc(qlge_t *qlge)
{
	uint8_t w8;
	uint32_t cnt, addr;
	uint16_t chksum, *bp, data;
	int rval;

	addr = qlge->flash_fdt_addr;

	rval = qlge_dump_fcode(qlge, (uint8_t *)&qlge->fdesc,
	    sizeof (flash_desc_t), addr);
	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) read Flash Descriptor Table error",
		    __func__, qlge->instance);
		bzero(&qlge->fdesc, sizeof (flash_desc_t));
		return (rval);
	}

	chksum = 0;
	data = 0;
	bp = (uint16_t *)&qlge->fdesc;
	for (cnt = 0; cnt < (sizeof (flash_desc_t)) / 2; cnt++) {
		data = *bp;
		LITTLE_ENDIAN_16(&data);
		chksum += data;
		bp++;
	}
	/* endian adjustment */
	LITTLE_ENDIAN_32(&qlge->fdesc.flash_valid);
	LITTLE_ENDIAN_16(&qlge->fdesc.flash_version);
	LITTLE_ENDIAN_16(&qlge->fdesc.flash_len);
	LITTLE_ENDIAN_16(&qlge->fdesc.flash_checksum);
	LITTLE_ENDIAN_16(&qlge->fdesc.flash_unused);
	LITTLE_ENDIAN_16(&qlge->fdesc.flash_manuf);
	LITTLE_ENDIAN_16(&qlge->fdesc.flash_id);
	LITTLE_ENDIAN_32(&qlge->fdesc.block_size);
	LITTLE_ENDIAN_32(&qlge->fdesc.alt_block_size);
	LITTLE_ENDIAN_32(&qlge->fdesc.flash_size);
	LITTLE_ENDIAN_32(&qlge->fdesc.write_enable_data);
	LITTLE_ENDIAN_32(&qlge->fdesc.read_timeout);

	/* flash size in desc table is in 1024 bytes */
	QL_PRINT(DBG_FLASH, ("flash_valid=%xh\n", qlge->fdesc.flash_valid));
	QL_PRINT(DBG_FLASH, ("flash_version=%xh\n", qlge->fdesc.flash_version));
	QL_PRINT(DBG_FLASH, ("flash_len=%xh\n", qlge->fdesc.flash_len));
	QL_PRINT(DBG_FLASH, ("flash_checksum=%xh\n",
	    qlge->fdesc.flash_checksum));

	w8 = qlge->fdesc.flash_model[15];
	qlge->fdesc.flash_model[15] = 0;
	QL_PRINT(DBG_FLASH, ("flash_model=%s\n", qlge->fdesc.flash_model));
	qlge->fdesc.flash_model[15] = w8;
	QL_PRINT(DBG_FLASH, ("flash_size=%xK bytes\n", qlge->fdesc.flash_size));
	qlge->fdesc.flash_size = qlge->fdesc.flash_size * 0x400;
	qlge->flash_info.flash_size = qlge->fdesc.flash_size;

	if (chksum != 0 || qlge->fdesc.flash_valid != FLASH_DESC_VAILD ||
	    qlge->fdesc.flash_version != FLASH_DESC_VERSION) {
		cmn_err(CE_WARN, "invalid descriptor table");
		bzero(&qlge->fdesc, sizeof (flash_desc_t));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * ql_flash_nic_config
 * Get flash NIC Configuration table.
 */
static int
ql_flash_nic_config(qlge_t *qlge)
{
	uint32_t cnt, addr;
	uint16_t chksum, *bp, data;
	int rval;

	addr = qlge->flash_nic_config_table_addr;

	rval = qlge_dump_fcode(qlge, (uint8_t *)&qlge->nic_config,
	    sizeof (ql_nic_config_t), addr);

	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "fail to read nic_cfg image %xh", rval);
		bzero(&qlge->nic_config, sizeof (ql_nic_config_t));
		return (rval);
	}

	chksum = 0;
	data = 0;
	bp = (uint16_t *)&qlge->nic_config;
	for (cnt = 0; cnt < (sizeof (ql_nic_config_t)) / 2; cnt++) {
		data = *bp;
		LITTLE_ENDIAN_16(&data);
		chksum += data;
		bp++;
	}

	LITTLE_ENDIAN_32(&qlge->nic_config.signature);
	LITTLE_ENDIAN_16(&qlge->nic_config.version);
	LITTLE_ENDIAN_16(&qlge->nic_config.size);
	LITTLE_ENDIAN_16(&qlge->nic_config.checksum);
	LITTLE_ENDIAN_16(&qlge->nic_config.total_data_size);
	LITTLE_ENDIAN_16(&qlge->nic_config.num_of_entries);
	LITTLE_ENDIAN_16(&qlge->nic_config.vlan_id);
	LITTLE_ENDIAN_16(&qlge->nic_config.last_entry);
	LITTLE_ENDIAN_16(&qlge->nic_config.subsys_vendor_id);
	LITTLE_ENDIAN_16(&qlge->nic_config.subsys_device_id);

	QL_PRINT(DBG_FLASH, ("(%d): signature=%xh\n",
	    qlge->instance, qlge->nic_config.signature));
	QL_PRINT(DBG_FLASH, ("(%d): size=%xh\n",
	    qlge->instance, qlge->nic_config.size));
	QL_PRINT(DBG_FLASH, ("(%d): checksum=%xh\n",
	    qlge->instance, qlge->nic_config.checksum));
	QL_PRINT(DBG_FLASH, ("(%d): version=%xh\n",
	    qlge->instance, qlge->nic_config.version));
	QL_PRINT(DBG_FLASH, ("(%d): total_data_size=%xh\n",
	    qlge->instance, qlge->nic_config.total_data_size));
	QL_PRINT(DBG_FLASH, ("(%d): num_of_entries=%xh\n",
	    qlge->instance, qlge->nic_config.num_of_entries));
	QL_PRINT(DBG_FLASH, ("(%d): data_type=%xh\n",
	    qlge->instance, qlge->nic_config.factory_data_type));
	QL_PRINT(DBG_FLASH, ("(%d): data_type_size=%xh\n",
	    qlge->instance, qlge->nic_config.factory_data_type_size));
	QL_PRINT(DBG_FLASH,
	    ("(%d): factory mac=%02x %02x %02x %02x %02x %02x h\n",
	    qlge->instance,
	    qlge->nic_config.factory_MAC[0],
	    qlge->nic_config.factory_MAC[1],
	    qlge->nic_config.factory_MAC[2],
	    qlge->nic_config.factory_MAC[3],
	    qlge->nic_config.factory_MAC[4],
	    qlge->nic_config.factory_MAC[5]));

	QL_PRINT(DBG_FLASH, ("(%d): data_type=%xh\n",
	    qlge->instance, qlge->nic_config.clp_data_type));
	QL_PRINT(DBG_FLASH, ("(%d): data_type_size=%xh\n",
	    qlge->instance, qlge->nic_config.clp_data_type_size));
	QL_PRINT(DBG_FLASH, ("(%d): clp mac=%x %x %x %x %x %x h\n",
	    qlge->instance,
	    qlge->nic_config.clp_MAC[0],
	    qlge->nic_config.clp_MAC[1],
	    qlge->nic_config.clp_MAC[2],
	    qlge->nic_config.clp_MAC[3],
	    qlge->nic_config.clp_MAC[4],
	    qlge->nic_config.clp_MAC[5]));

	QL_PRINT(DBG_FLASH, ("(%d): data_type=%xh\n",
	    qlge->instance, qlge->nic_config.clp_vlan_data_type));
	QL_PRINT(DBG_FLASH, ("(%d): data_type_size=%xh\n",
	    qlge->instance, qlge->nic_config.clp_vlan_data_type_size));
	QL_PRINT(DBG_FLASH, ("(%d): vlan_id=%xh\n",
	    qlge->instance, qlge->nic_config.vlan_id));

	QL_PRINT(DBG_FLASH, ("(%d): data_type=%xh\n",
	    qlge->instance, qlge->nic_config.last_data_type));
	QL_PRINT(DBG_FLASH, ("(%d): data_type_size=%xh\n",
	    qlge->instance, qlge->nic_config.last_data_type_size));
	QL_PRINT(DBG_FLASH, ("(%d): last_entry=%xh\n",
	    qlge->instance, qlge->nic_config.last_entry));

	QL_PRINT(DBG_FLASH, ("(%d): subsys_vendor_id=%xh\n",
	    qlge->instance, qlge->nic_config.subsys_vendor_id));
	QL_PRINT(DBG_FLASH, ("(%d): subsys_device_id=%xh\n",
	    qlge->instance, qlge->nic_config.subsys_device_id));

	if (chksum != 0 || qlge->nic_config.signature !=
	    FLASH_NIC_CONFIG_SIGNATURE || qlge->nic_config.version != 1) {
		cmn_err(CE_WARN,
		    "invalid flash nic configuration table: chksum %x, "
		    "signature %x, version %x",
		    chksum, qlge->nic_config.signature,
		    qlge->nic_config.version);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
ql_flash_vpd(qlge_t *qlge, uint8_t *buf)
{
	uint32_t cnt;
	uint16_t chksum, *bp, data;
	int rval;
	uint32_t vpd_size;

	if (buf == NULL) {
		cmn_err(CE_WARN, "%s(%d) buffer is not available.",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	if (!qlge->flash_vpd_addr) {
		if (qlge->func_number == qlge->fn0_net)
			qlge->flash_vpd_addr = ISP_8100_VPD0_ADDR;
		else
			qlge->flash_vpd_addr = ISP_8100_VPD1_ADDR;
		vpd_size = ISP_8100_VPD0_SIZE;
	}
	rval = qlge_dump_fcode(qlge, buf, vpd_size, qlge->flash_vpd_addr);

	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d)read error",
		    __func__, qlge->instance);
		bzero(buf, vpd_size);
		return (rval);
	}

	QL_DUMP(DBG_FLASH, "flash vpd table raw data:\n", buf, 8, vpd_size);

	chksum = 0;
	data = 0;
	bp = (uint16_t *)(void *)buf;
	for (cnt = 0; cnt < (vpd_size/2); cnt++) {
		data = *bp;
		LITTLE_ENDIAN_16(&data);
		chksum += data;
		bp++;
	}
	if (chksum != 0) {
		cmn_err(CE_WARN, "%s(%d) invalid flash vpd table",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

int
ql_get_flash_params(qlge_t *qlge)
{
	int rval = DDI_SUCCESS;

	/* Get semaphore to access Flash Address and Flash Data Registers */
	if (ql_sem_spinlock(qlge, QL_FLASH_SEM_MASK)) {
		rval = DDI_FAILURE;
		goto out;
	}
	/* do test read of flash ID */
	rval = ql_flash_id(qlge);
	if (rval != DDI_SUCCESS)
		goto out;

	/*
	 * Temporarily set the fdesc.flash_size to
	 * 4M flash size to avoid failing of ql_dump_focde.
	 */
	qlge->fdesc.flash_size = 4096 * 1024; /* ie. 4M bytes */

	/* Default flash descriptor table. */
	qlge->fdesc.write_statusreg_cmd = 1;
	qlge->fdesc.write_enable_bits = 0;
	qlge->fdesc.unprotect_sector_cmd = 0;
	qlge->fdesc.protect_sector_cmd = 0;
	qlge->fdesc.write_disable_bits = 0x9c;
	qlge->fdesc.block_size = 0x10000;
	qlge->fdesc.erase_cmd = 0xd8;

	/* ! todo : should read from fltds! */
	/* !ql_get_flash_params(qlge); */
	qlge->fltds.flt_addr_hi = 0x36;
	qlge->fltds.flt_addr_lo = 0x1000;
	/* read all other tables from Flash memory */
	if (ql_flash_flt(qlge) != DDI_SUCCESS) {
		if (CFG_IST(qlge, CFG_CHIP_8100)) {
			qlge->flash_fdt_addr = ISP_8100_FDT_ADDR; /* 0x360000 */
			if (qlge->func_number == qlge->fn0_net)
				/* 0x140200 */
				qlge->flash_nic_config_table_addr =
				    ISP_8100_NIC_PARAM0_ADDR;
			else
				/* 0x140600 */
				qlge->flash_nic_config_table_addr =
				    ISP_8100_NIC_PARAM1_ADDR;
		}
	}
	(void) ql_flash_desc(qlge);
	(void) ql_flash_nic_config(qlge);

out:
	ql_sem_unlock(qlge, QL_FLASH_SEM_MASK);

	return (rval);
}

/*
 * ql_setup_flash
 * Gets the manufacturer and id number of the flash chip,
 * and sets up the size parameter.
 */
int
ql_setup_flash(qlge_t *qlge)
{
	int rval = DDI_SUCCESS;

	if (qlge->flash_fltds_addr != 0) {
		return (rval);
	}
	if (ql_sem_spinlock(qlge, QL_FLASH_SEM_MASK)) {
		rval = DDI_FAILURE;
		goto out;
	}
	/* try reading flash ID */
	rval = ql_flash_id(qlge);
	if (rval != DDI_SUCCESS)
		goto out;

	/* Default flash descriptor table. */
	qlge->fdesc.write_statusreg_cmd = 1;
	qlge->fdesc.write_enable_bits = 0;
	qlge->fdesc.unprotect_sector_cmd = 0;
	qlge->fdesc.protect_sector_cmd = 0;
	qlge->fdesc.write_disable_bits = 0x9c;
	qlge->fdesc.block_size = 0x10000;
	qlge->fdesc.erase_cmd = 0xd8;
	/* 1 Get the location of Flash Layout Table Data Structure (FLTDS) */
	if (ql_find_flash_layout_table_data_structure_addr(qlge)
	    == DDI_SUCCESS) {
		/* 2,read fltds */
		if (ql_flash_fltds(qlge) == DDI_SUCCESS) {
			/*
			 * 3,search for flash descriptor table (FDT)
			 * and Nic Configuration Table indices
			 */
			if ((qlge->flash_fdt_addr == 0) ||
			    (qlge->flash_nic_config_table_addr == 0)) {
				rval = ql_flash_flt(qlge);
				if (rval == DDI_SUCCESS) {
					(void) ql_flash_desc(qlge);
					(void) ql_flash_nic_config(qlge);
				} else {
					rval = DDI_FAILURE;
					goto out;
				}
			}
		} else {
			rval = DDI_FAILURE;
			goto out;
		}
	} else {
		rval = DDI_FAILURE;
		goto out;
	}
out:
	ql_sem_unlock(qlge, QL_FLASH_SEM_MASK);

	return (rval);

}

/*
 * ql_change_endian
 * Change endianess of byte array.
 */
void
ql_change_endian(uint8_t buf[], size_t size)
{
	uint8_t byte;
	size_t cnt1;
	size_t cnt;

	cnt1 = size - 1;
	for (cnt = 0; cnt < size / 2; cnt++) {
		byte = buf[cnt1];
		buf[cnt1] = buf[cnt];
		buf[cnt] = byte;
		cnt1--;
	}
}

static int
ql_wait_flash_reg_ready(qlge_t *qlge, uint32_t wait_bit)
{
	uint32_t reg_status;
	int rtn_val = DDI_SUCCESS;
	uint32_t delay = 300000;

	do {
		reg_status = ql_read_reg(qlge, REG_FLASH_ADDRESS);
		if (reg_status & FLASH_ERR_FLAG) {
			cmn_err(CE_WARN,
			    "%s(%d) flash address register error bit set!",
			    __func__, qlge->instance);
			rtn_val = DDI_FAILURE;
			break;
		}
		if (reg_status & wait_bit) {
			break;
		}
		drv_usecwait(10);
	} while (--delay);

	if (delay == 0) {
		cmn_err(CE_WARN,
		    "%s(%d) timeout error!", __func__, qlge->instance);
		if (qlge->fm_enable) {
			ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
			atomic_or_32(&qlge->flags, ADAPTER_ERROR);
			ddi_fm_service_impact(qlge->dip, DDI_SERVICE_LOST);
		}
		rtn_val = DDI_FAILURE;
	}
	return (rtn_val);
}

/*
 * ql_read_flash
 * Reads a 32bit word from FLASH.
 */
static int
ql_read_flash(qlge_t *qlge, uint32_t faddr, uint32_t *bp)
{
	int rval = DDI_SUCCESS;

	ql_write_reg(qlge, REG_FLASH_ADDRESS, faddr | FLASH_R_FLAG);

	/* Wait for READ cycle to complete. */
	rval = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG);

	if (rval == DDI_SUCCESS) {
		*bp = ql_read_reg(qlge, REG_FLASH_DATA);
	}
	return (rval);
}

static int
ql_read_flash_status(qlge_t *qlge, uint8_t *value)
{
	int rtn_val = DDI_SUCCESS;
	uint32_t data, cmd = FLASH_CONF_ADDR | FLASH_R_FLAG;

	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    != DDI_SUCCESS) {
		return (rtn_val);
	}
	cmd |= FLASH_RDSR_CMD /* 0x05 */;
	ql_write_reg(qlge, REG_FLASH_ADDRESS, cmd);
	if ((rtn_val = ql_wait_flash_reg_ready(qlge,
	    FLASH_RDY_FLAG | FLASH_R_FLAG)) != DDI_SUCCESS) {
		return (rtn_val);
	}
	data = ql_read_reg(qlge, REG_FLASH_DATA);
	*value = (uint8_t)(data & 0xff);
	return (rtn_val);
}

static int
ql_flash_write_enable(qlge_t *qlge)
{
	uint8_t reg_status;
	int rtn_val = DDI_SUCCESS;
	uint32_t cmd = FLASH_CONF_ADDR;
	uint32_t delay = 300000;

	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) timeout!", __func__, qlge->instance);
		rtn_val = DDI_FAILURE;
		return (rtn_val);
	}
	cmd |= qlge->fdesc.write_enable_cmd;
	ql_write_reg(qlge, REG_FLASH_ADDRESS, cmd);
	/* wait for WEL bit set */
	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    == DDI_SUCCESS) {
		do {
			(void) ql_read_flash_status(qlge, &reg_status);
			if (reg_status & BIT_1)
				break;
			drv_usecwait(10);
		} while (--delay);
	}
	if (delay == 0) {
		cmn_err(CE_WARN,
		    "%s(%d) timeout error! flash status reg: %x",
		    __func__, qlge->instance, reg_status);
		rtn_val = DDI_FAILURE;
	}
	return (rtn_val);
}

static int
ql_flash_erase_sector(qlge_t *qlge, uint32_t sectorAddr)
{
	int rtn_val = DDI_SUCCESS;
	uint32_t data, cmd = FLASH_CONF_ADDR;
	uint32_t delay = 300000;
	uint8_t flash_status;

	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    != DDI_SUCCESS) {
		return (rtn_val);
	}

	cmd |= (0x0300 | qlge->fdesc.erase_cmd);
	data = ((sectorAddr & 0xff) << 16) | (sectorAddr & 0xff00) |
	    ((sectorAddr & 0xff0000) >> 16);

	ql_write_reg(qlge, REG_FLASH_DATA, data);
	ql_write_reg(qlge, REG_FLASH_ADDRESS, cmd);

	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    == DDI_SUCCESS) {
		/* wait Write In Progress (WIP) bit to reset */
		do {
			(void) ql_read_flash_status(qlge, &flash_status);
			if ((flash_status & BIT_0 /* WIP */) == 0)
				break;
			drv_usecwait(10);
		} while (--delay);
	} else {
		return (rtn_val);
	}

	if (delay == 0) {
		cmn_err(CE_WARN,
		    "%s(%d) timeout error! flash status reg: %x",
		    __func__, qlge->instance, flash_status);
		rtn_val = DDI_FAILURE;
	}
	return (rtn_val);
}

/*
 * ql_write_flash
 * Writes a 32bit word to FLASH.
 */
static int
ql_write_flash(qlge_t *qlge, uint32_t addr, uint32_t data)
{
	int rval = DDI_SUCCESS;
	uint32_t delay = 300000;
	uint8_t flash_status;

	ql_write_reg(qlge, REG_FLASH_DATA, data);
	(void) ql_read_reg(qlge, REG_FLASH_DATA);
	ql_write_reg(qlge, REG_FLASH_ADDRESS, addr);

	if ((rval = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    == DDI_SUCCESS) {
		if ((addr & FLASH_ADDR_MASK) == FLASH_CONF_ADDR) {
			/* wait Write In Progress (WIP) bit to reset */
			do {
				(void) ql_read_flash_status(qlge,
				    &flash_status);
				if ((flash_status & BIT_0 /* WIP */) == 0)
					break;
				drv_usecwait(10);
			} while (--delay);
		}
	} else {
		return (rval);
	}

	if (delay == 0) {
		cmn_err(CE_WARN,
		    "%s(%d) timeout error! flash status reg: %x",
		    __func__, qlge->instance, flash_status);
		rval = DDI_FAILURE;
	}

	return (rval);
}

/*
 * ql_unprotect_flash
 * Enable writes
 */
static int
ql_unprotect_flash(qlge_t *qlge)
{
	int fdata, rtn_val;

	if ((rtn_val = ql_flash_write_enable(qlge)) != DDI_SUCCESS) {
		return (rtn_val);
	}

	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    != DDI_SUCCESS) {
		return (rtn_val);
	}

	/*
	 * Remove block write protection (SST and ST) and
	 * Sector/Block Protection Register Lock (SST, ST, ATMEL).
	 * Unprotect sectors.
	 */
	(void) ql_write_flash(qlge,
	    FLASH_CONF_ADDR | 0x100 | qlge->fdesc.write_statusreg_cmd,
	    qlge->fdesc.write_enable_bits);

	if (qlge->fdesc.unprotect_sector_cmd != 0) {
		for (fdata = 0; fdata < 0x10; fdata++) {
			(void) ql_write_flash(qlge, FLASH_CONF_ADDR |
			    0x300 | qlge->fdesc.unprotect_sector_cmd, fdata);
		}

		(void) ql_write_flash(qlge, FLASH_CONF_ADDR | 0x300 |
		    qlge->fdesc.unprotect_sector_cmd, 0x00400f);
		(void) ql_write_flash(qlge, FLASH_CONF_ADDR | 0x300 |
		    qlge->fdesc.unprotect_sector_cmd, 0x00600f);
		(void) ql_write_flash(qlge, FLASH_CONF_ADDR | 0x300 |
		    qlge->fdesc.unprotect_sector_cmd, 0x00800f);
	}
	rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG);
	return (rtn_val);
}

/*
 * ql_protect_flash
 * Disable writes
 */
static int
ql_protect_flash(qlge_t *qlge)
{
	int fdata, rtn_val;

	if ((rtn_val = ql_flash_write_enable(qlge)) != DDI_SUCCESS) {
		return (rtn_val);
	}

	if ((rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG))
	    != DDI_SUCCESS) {
		return (rtn_val);
	}
	/*
	 * Protect sectors.
	 * Set block write protection (SST and ST) and
	 * Sector/Block Protection Register Lock (SST, ST, ATMEL).
	 */

	if (qlge->fdesc.protect_sector_cmd != 0) {
		for (fdata = 0; fdata < 0x10; fdata++) {
			(void) ql_write_flash(qlge, FLASH_CONF_ADDR |
			    0x330 | qlge->fdesc.protect_sector_cmd, fdata);
		}
		(void) ql_write_flash(qlge, FLASH_CONF_ADDR | 0x330 |
		    qlge->fdesc.protect_sector_cmd, 0x00400f);
		(void) ql_write_flash(qlge, FLASH_CONF_ADDR | 0x330 |
		    qlge->fdesc.protect_sector_cmd, 0x00600f);
		(void) ql_write_flash(qlge, FLASH_CONF_ADDR | 0x330 |
		    qlge->fdesc.protect_sector_cmd, 0x00800f);

		(void) ql_write_flash(qlge,
		    FLASH_CONF_ADDR | 0x101, 0x80);
	} else {
		(void) ql_write_flash(qlge,
		    FLASH_CONF_ADDR | 0x100 | qlge->fdesc.write_statusreg_cmd,
		    qlge->fdesc.write_disable_bits /* 0x9c */);
	}

	rtn_val = ql_wait_flash_reg_ready(qlge, FLASH_RDY_FLAG);
	return (rtn_val);
}

/*
 * ql_write_flash_test
 * test write to a flash sector that is not being used
 */
void
ql_write_flash_test(qlge_t *qlge, uint32_t test_addr)
{
	uint32_t old_data, data;
	uint32_t addr = 0;

	addr = (test_addr / 4);
	(void) ql_read_flash(qlge, addr, &old_data);
	QL_PRINT(DBG_FLASH, ("read addr %x old value %x\n", test_addr,
	    old_data));

	/* enable writing to flash */
	(void) ql_unprotect_flash(qlge);

	/* erase the sector */
	(void) ql_flash_erase_sector(qlge, test_addr);
	(void) ql_read_flash(qlge, addr, &data);
	QL_PRINT(DBG_FLASH, ("after sector erase, addr %x value %x\n",
	    test_addr, data));

	/* write new value to it and read back to confirm */
	data = 0x33445566;
	(void) ql_write_flash(qlge, addr, data);
	QL_PRINT(DBG_FLASH, ("new value written to addr %x value %x\n",
	    test_addr, data));
	(void) ql_read_flash(qlge, addr, &data);
	if (data != 0x33445566) {
		cmn_err(CE_WARN, "flash write test failed, get data %x"
		    " after writing", data);
	}

	/* write old value to it and read back to restore */
	(void) ql_flash_erase_sector(qlge, test_addr);
	(void) ql_write_flash(qlge, addr, old_data);
	(void) ql_read_flash(qlge, addr, &data);
	QL_PRINT(DBG_FLASH, ("write back old value addr %x value %x\n",
	    test_addr, data));

	/* test done, protect the flash to forbid any more flash writting */
	(void) ql_protect_flash(qlge);

}


void
ql_write_flash_test2(qlge_t *qlge, uint32_t test_addr)
{
	uint32_t data, old_data;

	(void) qlge_dump_fcode(qlge, (uint8_t *)&old_data, sizeof (old_data),
	    test_addr);
	QL_PRINT(DBG_FLASH, ("read addr %x old value %x\n",
	    test_addr, old_data));

	data = 0x12345678;

	QL_PRINT(DBG_FLASH, ("write new test value %x\n", data));
	(void) qlge_load_flash(qlge, (uint8_t *)&data, sizeof (data),
	    test_addr);
	(void) qlge_dump_fcode(qlge, (uint8_t *)&data, sizeof (data),
	    test_addr);
	if (data != 0x12345678) {
		cmn_err(CE_WARN,
		    "flash write test failed, get data %x after writing",
		    data);
	}
	/* write old value to it and read back to restore */
	(void) qlge_load_flash(qlge, (uint8_t *)&old_data, sizeof (old_data),
	    test_addr);
	(void) qlge_dump_fcode(qlge, (uint8_t *)&data, sizeof (data),
	    test_addr);
	QL_PRINT(DBG_FLASH, ("write back old value addr %x value %x verified\n",
	    test_addr, data));
}

/*
 * ql_sem_flash_lock
 * Flash memory is a shared resource amoung various PCI Functions, so,
 * anyone wants to access flash memory, it needs to lock it first.
 */
int
ql_sem_flash_lock(qlge_t *qlge)
{
	int rval = DDI_SUCCESS;

	/* Get semaphore to access Flash Address and Flash Data Registers */
	if (ql_sem_spinlock(qlge, QL_FLASH_SEM_MASK)) {
		rval = DDI_FAILURE;
	}
	return (rval);
}

void
ql_sem_flash_unlock(qlge_t *qlge)
{
	ql_sem_unlock(qlge, QL_FLASH_SEM_MASK);
}
