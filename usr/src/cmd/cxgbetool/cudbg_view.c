/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2019 by Chelsio Communications, Inc.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "t4_regs.h"
#include "t4_chip_type.h"
#include "cudbg_view.h"
#include "osdep.h"
#include "t4fw_interface.h"

#include "cudbg_view_entity.h"
#include "cudbg_entity.h"
#include "cudbg.h"
#include "cudbg_lib_common.h"
#include "fastlz.h"

extern struct reg_info t6_sge_regs[];
extern struct reg_info t6_pcie_regs[];
extern struct reg_info t6_dbg_regs[];
extern struct reg_info t6_ma_regs[];
extern struct reg_info t6_cim_regs[];
extern struct reg_info t6_tp_regs[];
extern struct reg_info t6_ulp_tx_regs[];
extern struct reg_info t6_pm_rx_regs[];
extern struct reg_info t6_pm_tx_regs[];
extern struct reg_info t6_mps_regs[];
extern struct reg_info t6_cpl_switch_regs[];
extern struct reg_info t6_smb_regs[];
extern struct reg_info t6_i2cm_regs[];
extern struct reg_info t6_mi_regs[];
extern struct reg_info t6_uart_regs[];
extern struct reg_info t6_pmu_regs[];
extern struct reg_info t6_ulp_rx_regs[];
extern struct reg_info t6_sf_regs[];
extern struct reg_info t6_pl_regs[];
extern struct reg_info t6_le_regs[];
extern struct reg_info t6_ncsi_regs[];
extern struct reg_info t6_mac_regs[];
extern struct reg_info t6_mc_0_regs[];
extern struct reg_info t6_edc_t60_regs[];
extern struct reg_info t6_edc_t61_regs[];
extern struct reg_info t6_hma_t6_regs[];

extern struct reg_info t5_sge_regs[];
extern struct reg_info t5_pcie_regs[];
extern struct reg_info t5_dbg_regs[];
extern struct reg_info t5_ma_regs[];
extern struct reg_info t5_cim_regs[];
extern struct reg_info t5_tp_regs[];
extern struct reg_info t5_ulp_tx_regs[];
extern struct reg_info t5_pm_rx_regs[];
extern struct reg_info t5_pm_tx_regs[];
extern struct reg_info t5_mps_regs[];
extern struct reg_info t5_cpl_switch_regs[];
extern struct reg_info t5_smb_regs[];
extern struct reg_info t5_i2cm_regs[];
extern struct reg_info t5_mi_regs[];
extern struct reg_info t5_uart_regs[];
extern struct reg_info t5_pmu_regs[];
extern struct reg_info t5_ulp_rx_regs[];
extern struct reg_info t5_sf_regs[];
extern struct reg_info t5_pl_regs[];
extern struct reg_info t5_le_regs[];
extern struct reg_info t5_ncsi_regs[];
extern struct reg_info t5_mac_regs[];
extern struct reg_info t5_mc_0_regs[];
extern struct reg_info t5_mc_1_regs[];
extern struct reg_info t5_edc_t50_regs[];
extern struct reg_info t5_edc_t51_regs[];
extern struct reg_info t5_hma_t5_regs[];

#include "reg_defs_t5.c"
#include "reg_defs_t6.c"

#include <time.h>
#include <stdarg.h>

int is_t5(enum chip_type chip)
{
	return (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T5);
}

int is_t6(enum chip_type chip)
{
	return (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6);
}

enum {                                 /* adapter flags */                      
	FULL_INIT_DONE     = (1 << 0),                                          
	USING_MSI          = (1 << 1),                                          
	USING_MSIX         = (1 << 2),                                          
	QUEUES_BOUND       = (1 << 3),                                          
	FW_OK              = (1 << 4),                                          
	RSS_TNLALLLOOKUP   = (1 << 5),                                          
	USING_SOFT_PARAMS  = (1 << 6),                                          
	MASTER_PF          = (1 << 7),                                          
	BYPASS_DROP        = (1 << 8),                                          
	FW_OFLD_CONN       = (1 << 9),                                          
};

static struct ver_cs {
	int major;
	int minor;
	int changeset;
} ver_to_cs[] = {
	{1, 9, 12852},
	{1, 10, 13182},
	{1, 11, 13257},
	{1, 12, 13495},
	{1, 13, 13905},
	{1, 14, 13969},
};

static bool flash_info_banner = true;

#include "cudbg_view_compat.c"

int
cudbg_sge_ctxt_check_valid(u32 *buf, int type)
{                                                                               
	int index, bit, bit_pos = 0;                                            

	switch (type) {                                                         
		case CTXT_EGRESS:                                                       
			bit_pos = 176;                                                  
			break;                                                          
		case CTXT_INGRESS:                                                      
			bit_pos = 141;                                                  
			break;                                                          
		case CTXT_FLM:                                                          
			bit_pos = 89;                                                   
			break;                                                          
	}                                                                       
	index = bit_pos / 32;                                                   
	bit =  bit_pos % 32;                                                    
	return buf[index] & (1U << bit);                                        
}

int
cudbg_view_decompress_buff(char *pbuf,
			   struct cudbg_entity_hdr *entity_hdr,
			   struct cudbg_buffer *c_buff,
			   struct cudbg_buffer *dc_buff)
{
	int rc = 0;

	c_buff->data = pbuf + entity_hdr->start_offset;
	/* Remove padding bytes, if any */
	if (entity_hdr->num_pad)
		c_buff->size = entity_hdr->size - entity_hdr->num_pad;
	else
		c_buff->size = entity_hdr->size;
	c_buff->offset = 0;
	memset(dc_buff, 0, sizeof(struct cudbg_buffer));

	rc = validate_buffer(c_buff);
	if (rc)
		return rc;

	rc = decompress_buffer_wrapper(c_buff, dc_buff);
	if (rc) {
		free(dc_buff->data);
		return rc;
	}
	return rc;
}

int
get_entity_rev(struct cudbg_ver_hdr *ver_hdr)
{
	if (ver_hdr->signature == CUDBG_ENTITY_SIGNATURE)
		return ver_hdr->revision;
	return 0;
}

/* Find Mercurial sw repo changeset number
 * where major or minor number set to given number
 * */
int
cudbg_find_changeset(int major, int minor)
{
	int i;

	for (i = 0; i < sizeof(ver_to_cs)/sizeof(struct ver_cs); i++) {
		if (ver_to_cs[i].major == major &&
		    ver_to_cs[i].minor == minor)
			return ver_to_cs[i].changeset;
	}

	return -1;
}

/* Format a value in a unit that differs from the
 * value's native unit by the
 * given factor.
 */
static void
unit_conv(char *buf, size_t len, unsigned int val,
	  unsigned int factor)
{
	unsigned int rem = val % factor;

	if (rem == 0)
		(void) snprintf(buf, len, "%u", val / factor);
	else {
		while (rem % 10 == 0)
			rem /= 10;
		(void) snprintf(buf, len, "%u.%u", val / factor, rem);
	}
}

int
validate_next_rec_offset(void *pinbuf, u32 inbuf_size, u32
			 next_rec_offset)
{
	struct cudbg_hdr *cudbg_hdr;

	if (inbuf_size <= next_rec_offset)
		return 0;

	cudbg_hdr = (struct cudbg_hdr *)((char *)pinbuf + next_rec_offset);
	if ((cudbg_hdr->signature != CUDBG_SIGNATURE) &&
	    (cudbg_hdr->signature != CUDBG_LEGACY_SIGNATURE))
		return 0; /* no next rec */

	return next_rec_offset;
}

int
view_ext_entity(char *pinbuf, struct cudbg_entity_hdr *ent_hdr,
		struct cudbg_buffer *cudbg_poutbuf,
		enum chip_type chip)
{
	struct cudbg_entity_hdr *entity_hdr = NULL;
	u32 size, total_size = 0;
	u32 next_ext_offset = 0;
	u32 entity_type;
	int rc = 0;

	entity_hdr = (struct cudbg_entity_hdr *)
		     (pinbuf + ent_hdr->start_offset);
	/* Remove padding bytes, if any */
	size = ent_hdr->num_pad ? ent_hdr->size - ent_hdr->num_pad :
				  ent_hdr->size;
	while ((entity_hdr->flag & CUDBG_EXT_DATA_VALID)
		&& (total_size < size)) {
		entity_type = entity_hdr->entity_type;
		if (entity_hdr->sys_warn)
			printf("Entity warning: Type %s , %d\n",
			       entity_list[entity_type].name,
			       entity_hdr->sys_warn);

		if (entity_hdr->hdr_flags) {
			printf("Entity error: Type %s, %s\n",
			       entity_list[entity_type].name,
			       err_msg[-entity_hdr->hdr_flags]);
			if (entity_hdr->sys_err)
				printf("System error  %d\n",
				       entity_hdr->sys_err);

			next_ext_offset = entity_hdr->next_ext_offset;
			entity_hdr = (struct cudbg_entity_hdr *)
				     (pinbuf + ent_hdr->start_offset +
				      next_ext_offset);
			continue;
		}
		if (entity_hdr->size > 0) {
			total_size += entity_hdr->size +
					sizeof(struct cudbg_entity_hdr);

			rc = view_entity[entity_type - 1]
				(pinbuf + ent_hdr->start_offset,
				 entity_hdr,
				 cudbg_poutbuf,
				 chip);
			if (rc < 0)
				goto out;
		}
		next_ext_offset = entity_hdr->next_ext_offset;
		entity_hdr = (struct cudbg_entity_hdr *)
			     (pinbuf + ent_hdr->start_offset + next_ext_offset);
	}

	if (total_size != size)
		printf("Entity warning: Extended entity size mismatch\n");

out:
	return rc;
}

static void
cudbg_print_cudbg_header(struct cudbg_hdr *hdr)
{
	printf("\n/***************Header Information***************/\n");
	printf("Library Version: %u.%u\n", hdr->major_ver, hdr->minor_ver);
	printf("Compressed with: ");
	printf("Chip Version: ");
	switch (CHELSIO_CHIP_VERSION(hdr->chip_ver)) {
	case CHELSIO_T4:
		printf("T4 rev: %u\n", CHELSIO_CHIP_RELEASE(hdr->chip_ver));
		break;
	case CHELSIO_T5:
		printf("T5 rev: %u\n", CHELSIO_CHIP_RELEASE(hdr->chip_ver));
		break;
	case CHELSIO_T6:
		printf("T6 rev: %u\n", CHELSIO_CHIP_RELEASE(hdr->chip_ver));
		break;
	default:
		printf("%u (unknown)\n", hdr->chip_ver);
		break;
	}
	printf("/************************************************/\n\n");
}

void
cudbg_print_flash_header(void *pinbuf)
{
	struct cudbg_flash_hdr *fl_hdr = (struct cudbg_flash_hdr *)pinbuf;

	if (fl_hdr->signature == CUDBG_FL_SIGNATURE && flash_info_banner) {
		printf("\n/***************Flash Header information***************/\n");
		printf("Flash signature: %c%c%c%c\n",
		       (fl_hdr->signature  >> 24) & 0xFF,
		       (fl_hdr->signature  >> 16) & 0xFF,
		       (fl_hdr->signature  >> 8) & 0xFF,
		       fl_hdr->signature & 0xFF);

		printf("Flash payload timestamp (GMT): %s",
		       asctime(gmtime((time_t *)&fl_hdr->timestamp)));
		printf("Flash payload size: %u bytes\n", fl_hdr->data_len);
		printf("/******************************************************/\n");
		flash_info_banner = false;
	}
}

int
cudbg_view(void *handle, void *pinbuf, u32 inbuf_size,
	   void *poutbuf, s64 *poutbuf_size)
{

	struct cudbg_buffer cudbg_poutbuf = {0};
	struct cudbg_entity_hdr *entity_hdr;
	u32 info, offset, max_entities, i;
	struct cudbg_hdr *tmp_hdr;
	u32 next_rec_offset = 0;
	int index, bit, all;
	int rc = 0, cs;
	u8 *dbg_bitmap;
	int count = 0;

	dbg_bitmap = ((struct cudbg_private *)handle)->dbg_init.dbg_bitmap;
	info = ((struct cudbg_private *)handle)->dbg_init.info;

	if (inbuf_size < (sizeof(struct cudbg_entity_hdr) +
			  sizeof(struct cudbg_hdr))) {
		printf("\n\tInvalid cudbg dump file\n");
		return CUDBG_STATUS_NO_SIGNATURE;
	}

	tmp_hdr  = (struct cudbg_hdr *)pinbuf;
	if ((tmp_hdr->signature != CUDBG_SIGNATURE) &&
	    (tmp_hdr->signature != CUDBG_LEGACY_SIGNATURE)) {
		printf("\n\tInvalid cudbg dump file\n");
		return CUDBG_STATUS_NO_SIGNATURE;
	}

	if ((tmp_hdr->major_ver != CUDBG_MAJOR_VERSION) ||
	    (tmp_hdr->minor_ver != CUDBG_MINOR_VERSION)) {
		printf("\n\tMeta data version mismatch\n");
		printf("\tMeta data version expected %d.%d\n",
		       CUDBG_MAJOR_VERSION, CUDBG_MINOR_VERSION);
		printf("\tMeta data version in dump %d.%d\n",
		       tmp_hdr->major_ver, tmp_hdr->minor_ver);

		cs = cudbg_find_changeset(tmp_hdr->major_ver,
					  tmp_hdr->minor_ver);
		if (cs != -1) {
			printf("\n\tPlease use changeset %d in sw Mercurial "\
			       "repo to build cudbg_app with version %d.%d\n",
			       cs, tmp_hdr->major_ver, tmp_hdr->minor_ver);

			printf("\n\tOr\n\n\tUse precompiled cudbg_app binary for RHEL 5.x from "\
			       "vnc52:/home/surendra/vnc52/"\
			       "cudbg_app/cudbg_app_<version>\"\n\n");


		}
		return CUDBG_METADATA_VERSION_MISMATCH;
	}

	if (info)
		cudbg_print_cudbg_header(tmp_hdr);

	next_rec_offset += tmp_hdr->data_len;
	offset = tmp_hdr->hdr_len;
	all = dbg_bitmap[0] & (1 << CUDBG_ALL);
	max_entities = min(tmp_hdr->max_entities, CUDBG_MAX_ENTITY);

	for (i = 1; i < max_entities; i++) {
		index = i / 8;
		bit = i % 8;

		if (all || (dbg_bitmap[index] & (1 << bit))) {
			entity_hdr =
				(struct cudbg_entity_hdr *)((char *)pinbuf + offset);

			if (entity_hdr->sys_warn)
				printf("Entity warning: Type %s , %d\n",
				       entity_list[i].name,
				       entity_hdr->sys_warn);

			if (entity_hdr->hdr_flags) {
				offset += sizeof(struct cudbg_entity_hdr);
				printf("Entity error: Type %s, %s\n",
				       entity_list[i].name,
				       err_msg[-entity_hdr->hdr_flags]);
				if (entity_hdr->sys_err)
					printf("System error  %d\n",
					       entity_hdr->sys_err);

				if (poutbuf)
					*poutbuf_size = 0;

				continue;
			}
			memset(&cudbg_poutbuf, 0, sizeof(cudbg_poutbuf));
			if (entity_hdr->size > 0) {
				if (poutbuf) {
					cudbg_poutbuf.data = poutbuf;
					/* poutbuf_size value should not be
 					 * more than 32 bit value
 					 */
					assert(!((*poutbuf_size) >> 32));
					cudbg_poutbuf.size = (u32)*poutbuf_size;
					cudbg_poutbuf.offset = 0;
				}

				if (info)
					printf("%-20s compressed size %u\n",
					       entity_list[i].name,
					       entity_hdr->size);
				else {
					if (entity_hdr->entity_type !=
					    CUDBG_EXT_ENTITY)
						printf("%s() dbg entity : %s\n",
						       __func__,
						       entity_list[i].name);

					rc = view_entity[i - 1]
						((char *)pinbuf,
						 entity_hdr,
						 &cudbg_poutbuf,
						 tmp_hdr->chip_ver);

					count++;
				}
			} else if (!all && i !=
				   CUDBG_EXT_ENTITY) {
				printf("%s() dbg entity : %s\n",
				       __func__, entity_list[i].name);
				printf("\t%s not available\n",
				       entity_list[i].name);
			}
			if (rc < 0)
				goto out;
		}
		offset += sizeof(struct cudbg_entity_hdr);
	}

	/* if max_entities in dump is less than current CUDBG_MAX_ENTITY
	 * it means entities after tmp_hdr->max_entities does not exist
	 * in that dump
	 */
	if (tmp_hdr->max_entities < CUDBG_MAX_ENTITY) {
		for (i = tmp_hdr->max_entities; i < CUDBG_MAX_ENTITY; i++) {
			index = i / 8;
			bit = i % 8;

			if (all || (dbg_bitmap[index] & (1 << bit))) {
				printf("%s() dbg entity : %s\n",
				       __func__, entity_list[i].name);
				printf("\t%s does not Exist\n",
				       entity_list[i].name);
			}
		}
	}
	if (poutbuf) {
		if (!count)
			*poutbuf_size = 0;
		else
			*poutbuf_size = cudbg_poutbuf.size;
	}

	return validate_next_rec_offset(pinbuf, inbuf_size, next_rec_offset);

out:
	if (poutbuf)
		*poutbuf_size = cudbg_poutbuf.size;
	return rc;
}

int
view_cim_q(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	   struct cudbg_buffer *cudbg_poutbuf,
	   enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	u32 i, *pdata = NULL;
	int rc;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	pdata = (u32 *)dc_buff.data;
	for (i = 0; i < dc_buff.offset / 4; i += 4)
		printf("%#06x: %08x %08x %08x "\
			     "%08x\n", i * 4,
			     pdata[i + 0], pdata[i + 1],
			     pdata[i + 2], pdata[i + 3]);

	return rc;
}

static int
view_cim_la_t6(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff, dc_buff;
	u32 i, *p, cfg, dc_size;
	int rc;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	dc_size = dc_buff.offset;
	p = (u32 *)((char *)dc_buff.data + sizeof(cfg));
	cfg = *((u32 *)dc_buff.data);
	dc_size -= sizeof(cfg);

	if (cfg & F_UPDBGLACAPTPCONLY) {
		printf("Status   Inst    Data      "\
			     "PC\r\n");

		for (i = 0; i < dc_size; i += 40, p += 10) {
			printf("  %02x   %08x %08x %08x\n",
				p[3] & 0xff, p[2], p[1], p[0]);

			printf("  %02x   %02x%06x %02x%06x %02x%06x\n",
				(p[6] >> 8) & 0xff, p[6] & 0xff, p[5] >> 8,
				     p[5] & 0xff, p[4] >> 8, p[4] & 0xff,
				     p[3] >> 8);

			printf("  %02x   %04x%04x %04x%04x %04x%04x\n",
				(p[9] >> 16) & 0xff, p[9] & 0xffff,
				p[8] >> 16, p[8] & 0xffff, p[7] >> 16,
				p[7] & 0xffff, p[6] >> 16);
		}
		goto err1;
	}

	printf("Status   Inst    Data      PC     "\
		     "LS0Stat  LS0Addr  LS0Data  LS1Stat  LS1Addr  LS1Data\n");

	for (i = 0; i < dc_size; i += 40, p += 10) {
		printf("  %02x   %04x%04x %04x%04x "\
			     "%04x%04x %08x %08x %08x %08x %08x %08x\n",
			     (p[9] >> 16) & 0xff,       /* Status */
			     p[9] & 0xffff, p[8] >> 16, /* Inst */
			     p[8] & 0xffff, p[7] >> 16, /* Data */
			     p[7] & 0xffff, p[6] >> 16, /* PC */
			     p[2], p[1], p[0],          /* LS0 Stat, Addr
							   and Data */
			     p[5], p[4], p[3]);         /* LS1 Stat, Addr
							   and Data */
	}

err1:
	return rc;
}

static int
view_cim_la_t5(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff, dc_buff;
	u32 i, *p, cfg, dc_size;
	int rc;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	dc_size = dc_buff.offset;
	p = (u32 *)((char *)dc_buff.data + sizeof(cfg));
	cfg = *((u32 *)dc_buff.data);
	dc_size -= sizeof(cfg);

	if (cfg & F_UPDBGLACAPTPCONLY) {
		/* as per cim_la_show_3in1() (in
		 * sw\dev\linux\drv\cxgb4_main.c)*/
		printf("Status   Data      PC\r\n");

		for (i = 0; i < dc_size; i += 32, p += 8) {
			printf("  %02X   %08X %08X\r\n",
				(p[5] & 0xFF), p[6], p[7]);

			printf(
				     "  %02X   %02X%06X %02X%06X\n",
				     ((p[3] >> 8) & 0xFF), (p[3] & 0xFF),
				     (p[4] >> 8), (p[4] & 0xFF), (p[5] >> 8));

			printf(
				     "  %02X   %X%07X %X%07X\r\n",
				     ((p[0] >> 4) & 0xFF), (p[0] & 0xF),
				     (p[1] >> 4), (p[1] & 0xF), (p[2] >> 4));
		}
		goto err1;
	}

	printf("Status   Data      PC     LS0Stat  "\
		     "LS0Addr             LS0Data\n");

	for (i = 0; i < dc_size; i += 32, p += 8) {
		printf("%02x   %x%07x %x%07x %08x "\
			     "%08x %08x%08x%08x%08x\n",
			     ((p[0] >> 4) & 0xFF), (p[0] & 0xF), (p[1] >> 4),
			     (p[1] & 0xF), (p[2] >> 4), (p[2] & 0xF), p[3],
			     p[4], p[5], p[6], p[7]);
	}
err1:
	return rc;
}

int
view_cim_la(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	    struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	int rc = -1;

	if (is_t5(chip))
		rc = view_cim_la_t5(pbuf, entity_hdr, cudbg_poutbuf);
	else if (is_t6(chip))
		rc = view_cim_la_t6(pbuf, entity_hdr, cudbg_poutbuf);

	return rc;
}

int
view_cim_ma_la(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	int rc, i, j;
	u32 *p;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	p = (u32 *)dc_buff.data;
	for (i = 0; i <= CIM_MALA_SIZE; i++, p += 4) {
		if (i < CIM_MALA_SIZE) {
			printf(
				     "%02x%08x%08x%08x%08x\n",
				     p[4], p[3], p[2], p[1], p[0]);
		} else {
			printf("\nCnt ID Tag UE   "\
				     "   Data       RDY VLD\n");
			for (j = 0; j < CIM_MALA_SIZE ; j++, p += 3) {
				printf(
					     "%3u %2u  %x  %u %08x%08x  %u   "\
					     "%u\n",
					     (p[2] >> 10) & 0xff,
					     (p[2] >> 7) & 7, (p[2] >> 3) & 0xf,
					     (p[2] >> 2) & 1,
					     (p[1] >> 2) | ((p[2] & 3) << 30),
					     (p[0] >> 2) | ((p[1] & 3) << 30),
					     (p[0] >> 1) & 1, p[0] & 1);
			}
		}
	}

	return rc;
}

int
view_cim_qcfg(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	static const char * const pQname[] = {
		"TP0", "TP1", "ULP", "SGE0", "SGE1", "NC-SI",
		"ULP0", "ULP1", "ULP2", "ULP3", "SGE", "NC-SI"
	};
	struct cudbg_buffer c_buff, dc_buff;
	struct struct_cim_qcfg *q_cfg_data;
	u32 *p, *wr;
	int rc, i;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	q_cfg_data = (struct struct_cim_qcfg *) (dc_buff.data);
	p = q_cfg_data->stat;
	wr = q_cfg_data->obq_wr;

	printf("  Queue Base Size Thres  RdPtr "\
		     "WrPtr  SOP  EOP Avail\n");
	for (i = 0; i < CIM_NUM_IBQ; i++, p += 4) {
		printf("%5s %5x %5u %4u %6x  %4x "\
			     "%4u %4u %5u\n",
			     pQname[i],
			     q_cfg_data->base[i], q_cfg_data->size[i],
			     q_cfg_data->thres[i], G_IBQRDADDR(p[0]),
			     G_IBQWRADDR(p[1]), G_QUESOPCNT(p[3]),
			     G_QUEEOPCNT(p[3]), G_QUEREMFLITS(p[2]) * 16);
	}

	for (; i < CIM_NUM_IBQ + CIM_NUM_OBQ; i++, p += 4, wr += 2) {
		printf("%5s %5x %5u %11x  %4x %4u "\
			     "%4u %5u\n",
			     pQname[i],
			     q_cfg_data->base[i], q_cfg_data->size[i],
			     G_QUERDADDR(p[0]) & 0x3fff,
			     wr[0] - q_cfg_data->base[i], G_QUESOPCNT(p[3]),
			     G_QUEEOPCNT(p[3]), G_QUEREMFLITS(p[2]) * 16);
	}

	return rc;
}

int
decompress_buffer_wrapper(struct cudbg_buffer *pc_buff,
			  struct cudbg_buffer *pdc_buff)
{
	int rc = 0;
	pdc_buff->data =  malloc(2 * CUDBG_CHUNK_SIZE);
	if (pdc_buff->data == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto err;
	}
	pdc_buff->size = 2 * CUDBG_CHUNK_SIZE;

	rc = decompress_buffer(pc_buff, pdc_buff);
	if (rc == CUDBG_STATUS_SMALL_BUFF) {
		free(pdc_buff->data);
		pdc_buff->data =  malloc(pdc_buff->size);

		if (pdc_buff->data == NULL) {
			printf("malloc failed for size %u\n", pdc_buff->size);
			rc = CUDBG_STATUS_NOSPACE;
			goto err;
		}
		rc = decompress_buffer(pc_buff, pdc_buff);
	}
err:
	return rc;
}

int
copy_bin_data(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      const char *fname, struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;

	if (cudbg_poutbuf->data == NULL)
		return 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	if (dc_buff.size > cudbg_poutbuf->size) {
		rc = CUDBG_STATUS_OUTBUFF_OVERFLOW;
		cudbg_poutbuf->size = dc_buff.size;
		goto err1;
	}

	memcpy(cudbg_poutbuf->data, dc_buff.data, dc_buff.size);
	cudbg_poutbuf->size = dc_buff.size;

err1:
	return rc;
}

int
view_edc0_data(char *pbuf, struct cudbg_entity_hdr *ent_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	return copy_bin_data(pbuf, ent_hdr, "_cudbg_edc0.bin", cudbg_poutbuf);
}

int
view_edc1_data(char *pbuf, struct cudbg_entity_hdr *ent_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	return copy_bin_data(pbuf, ent_hdr, "_cudbg_edc1.bin", cudbg_poutbuf);
}

int
view_mc0_data(char *pbuf, struct cudbg_entity_hdr *ent_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	return copy_bin_data(pbuf, ent_hdr, "_cudbg_mc0.bin", cudbg_poutbuf);
}

int
view_mc1_data(char *pbuf, struct cudbg_entity_hdr *ent_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	return copy_bin_data(pbuf, ent_hdr, "_cudbg_mc1.bin", cudbg_poutbuf);
}

int
view_hma_data(char *pbuf, struct cudbg_entity_hdr *ent_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	return copy_bin_data(pbuf, ent_hdr, "_cudbg_hma.bin", cudbg_poutbuf);
}

int
view_sw_state(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	u8 os_type, *caller_string;
	struct sw_state *swstate;
	char *os, *fwstate;
	u32 fw_state;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	swstate = (struct sw_state *) dc_buff.data;
	fw_state = swstate->fw_state;
	caller_string = swstate->caller_string;
	os_type = swstate->os_type;

	printf("\n");
	if (fw_state & F_PCIE_FW_ERR && G_PCIE_FW_EVAL(fw_state) ==
	    PCIE_FW_EVAL_CRASH)
		fwstate = "Crashed";
	else
		fwstate = "Alive";

	switch (os_type) {
	case CUDBG_OS_TYPE_WINDOWS:
		os = "Windows";
		break;
	case CUDBG_OS_TYPE_LINUX:
		os = "Linux";
		break;
	case CUDBG_OS_TYPE_ESX:
		os = "ESX";
		break;
	case CUDBG_OS_TYPE_UNKNOWN:
	default:
		os = "Unknown";
	}

	printf("\tFW STATE  : %s\n", fwstate);
	printf("\tOS        : %s\n", os);
	printf("\tCALLER    : %s\n", caller_string);
	printf("\n");

	return rc;
}

int
view_cpl_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_tp_cpl_stats *tp_cpl_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	struct tp_cpl_stats stats;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tp_cpl_stats_buff = (struct struct_tp_cpl_stats *) dc_buff.data;
	stats = tp_cpl_stats_buff->stats;
	if (tp_cpl_stats_buff->nchan == NCHAN) {
		printf("                 channel 0"\
			     "  channel 1  channel 2  channel 3\n");
		printf("CPL requests:   %10u %10u "\
			     "%10u %10u\n",
			     stats.req[0], stats.req[1], stats.req[2],
			     stats.req[3]);
		printf("CPL responses:  %10u %10u "\
			     "%10u %10u\n",
			     stats.rsp[0], stats.rsp[1], stats.rsp[2],
			     stats.rsp[3]);
	} else {
		printf("                 channel 0"\
			     "  channel 1\n");
		printf("CPL requests:   %10u %10u\n",
			     stats.req[0], stats.req[1]);
		printf("CPL responses:  %10u %10u\n",
			     stats.rsp[0], stats.rsp[1]);
	}

	return rc;
}

int
view_ddp_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct tp_usm_stats *tp_usm_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tp_usm_stats_buff = (struct tp_usm_stats *) dc_buff.data;
	printf("Frames: %u\n",
		     tp_usm_stats_buff->frames);
	printf("Octets: %llu\n",
		     (unsigned long long)tp_usm_stats_buff->octets);
	printf("Drops:  %u\n",
		     tp_usm_stats_buff->drops);

	return rc;
}

int
view_macstats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_mac_stats_rev1 *macstats_buff1;
	struct struct_mac_stats *mac_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	struct port_stats *stats;
	u32 port_count, i;
	int rc = 0, rev;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	rev = get_entity_rev((struct cudbg_ver_hdr *)dc_buff.data);
	if (rev) {
		macstats_buff1 = (struct struct_mac_stats_rev1 *)(dc_buff.data);
		port_count = macstats_buff1->port_count;
		stats = macstats_buff1->stats;

	} else {
		mac_stats_buff = (struct struct_mac_stats *)(dc_buff.data);
		port_count = mac_stats_buff->port_count;
		stats = mac_stats_buff->stats;
	}

	for (i = 0; i < port_count; i++) {
		printf("\nMac %d Stats:\n", i);
		printf("tx_octets              "\
			     "%64llu\n", stats[i].tx_octets);
		printf("tx_frames              "\
			     "%64llu\n", stats[i].tx_frames);
		printf("tx_bcast_frames        "\
			     "%64llu\n", stats[i].tx_bcast_frames);
		printf("tx_mcast_frames        "\
			     "%64llu\n", stats[i].tx_mcast_frames);
		printf("tx_ucast_frames        "\
			     "%64llu\n", stats[i].tx_ucast_frames);
		printf("tx_error_frames        "\
			     "%64llu\n", stats[i].tx_error_frames);
		printf("tx_frames_64           "\
			     "%64llu\n", stats[i].tx_frames_64);
		printf("tx_frames_65_127       "\
			     "%64llu\n", stats[i].tx_frames_65_127);
		printf("tx_frames_128_255      "\
			     "%64llu\n", stats[i].tx_frames_128_255);
		printf("tx_frames_256_511      "\
			     "%64llu\n", stats[i].tx_frames_256_511);
		printf("tx_frames_512_1023     "\
			     "%64llu\n", stats[i].tx_frames_512_1023);
		printf("tx_frames_1024_1518    "\
			     "%64llu\n", stats[i].tx_frames_1024_1518);
		printf("tx_frames_1519_max     "\
			     "%64llu\n", stats[i].tx_frames_1519_max);
		printf("tx_drop                "\
			     "%64llu\n", stats[i].tx_drop);
		printf("tx_pause               "\
			     "%64llu\n", stats[i].tx_pause);
		printf("tx_ppp0                "\
			     "%64llu\n", stats[i].tx_ppp0);
		printf("tx_ppp1                "\
			     "%64llu\n", stats[i].tx_ppp1);
		printf("tx_ppp2                "\
			     "%64llu\n", stats[i].tx_ppp2);
		printf("tx_ppp3                "\
			     "%64llu\n", stats[i].tx_ppp3);
		printf("tx_ppp4                "\
			     "%64llu\n", stats[i].tx_ppp4);
		printf("tx_ppp5                "\
			     "%64llu\n", stats[i].tx_ppp5);
		printf("tx_ppp6                "\
			     "%64llu\n", stats[i].tx_ppp6);
		printf("tx_ppp7                "\
			     "%64llu\n", stats[i].tx_ppp7);
		printf("rx_octets              "\
			     "%64llu\n", stats[i].rx_octets);
		printf("rx_frames              "\
			     "%64llu\n", stats[i].rx_frames);
		printf("rx_bcast_frames        "\
			     "%64llu\n", stats[i].rx_bcast_frames);
		printf("rx_mcast_frames        "\
			     "%64llu\n", stats[i].rx_mcast_frames);
		printf("rx_ucast_frames        "\
			     "%64llu\n", stats[i].rx_ucast_frames);
		printf("rx_too_long            "\
			     "%64llu\n", stats[i].rx_too_long);
		printf("rx_jabber              "\
			     "%64llu\n", stats[i].rx_jabber);
		printf("rx_fcs_err             "\
			     "%64llu\n", stats[i].rx_fcs_err);
		printf("rx_len_err             "\
			     "%64llu\n", stats[i].rx_len_err);
		printf("rx_symbol_err          "\
			     "%64llu\n", stats[i].rx_symbol_err);
		printf("rx_runt                "\
			     "%64llu\n", stats[i].rx_runt);
		printf("rx_frames_64           "\
			     "%64llu\n", stats[i].rx_frames_64);
		printf("rx_frames_65_127       "\
			     "%64llu\n", stats[i].rx_frames_65_127);
		printf("rx_frames_128_255      "\
			     "%64llu\n", stats[i].rx_frames_128_255);
		printf("rx_frames_256_511      "\
			     "%64llu\n", stats[i].rx_frames_256_511);
		printf("rx_frames_512_1023     "\
			     "%64llu\n", stats[i].rx_frames_512_1023);
		printf("rx_frames_1024_1518    "\
			     "%64llu\n", stats[i].rx_frames_1024_1518);
		printf("rx_frames_1519_max     "\
			     "%64llu\n", stats[i].rx_frames_1519_max);
		printf("rx_pause               "\
			     "%64llu\n", stats[i].rx_pause);
		printf("rx_ppp0                "\
			     "%64llu\n", stats[i].rx_ppp0);
		printf("rx_ppp1                "\
			     "%64llu\n", stats[i].rx_ppp1);
		printf("rx_ppp2                "\
			     "%64llu\n", stats[i].rx_ppp2);
		printf("rx_ppp3                "\
			     "%64llu\n", stats[i].rx_ppp3);
		printf("rx_ppp4                "\
			     "%64llu\n", stats[i].rx_ppp4);
		printf("rx_ppp5                "\
			     "%64llu\n", stats[i].rx_ppp5);
		printf("rx_ppp6                "\
			     "%64llu\n", stats[i].rx_ppp6);
		printf("rx_ppp7                "\
			     "%64llu\n", stats[i].rx_ppp7);
		printf("rx_ovflow0             "\
			     "%64llu\n", stats[i].rx_ovflow0);
		printf("rx_ovflow1             "\
			     "%64llu\n", stats[i].rx_ovflow1);
		printf("rx_ovflow2             "\
			     "%64llu\n", stats[i].rx_ovflow2);
		printf("rx_ovflow3             "\
			     "%64llu\n", stats[i].rx_ovflow3);
		printf("rx_trunc0              "\
			     "%64llu\n", stats[i].rx_trunc0);
		printf("rx_trunc1              "\
			     "%64llu\n", stats[i].rx_trunc1);
		printf("rx_trunc2              "\
			     "%64llu\n", stats[i].rx_trunc2);
		printf("rx_trunc3              "\
			     "%64llu\n", stats[i].rx_trunc3);
	}

	return rc;
}

int
view_ulptx_la(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_ulptx_la *ulptx_la_buff;
	struct cudbg_buffer c_buff, dc_buff;
	void *data;
	int i, rc = 0, rev;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	data = dc_buff.data + sizeof(struct cudbg_ver_hdr);
	rev = get_entity_rev((struct cudbg_ver_hdr *)dc_buff.data);
	switch (rev) {
		case 0:
			/* for rev 0 there is no version hdr so 
 			 * passing dc_buff.data */
			rc = view_ulptx_la_rev0(dc_buff.data, cudbg_poutbuf);
			goto err1;
		case CUDBG_ULPTX_LA_REV:
			/* for rev 1, print first rev 0 and then remaining of rev 1 */
			rc = view_ulptx_la_rev0(data, cudbg_poutbuf);
			if (rc < 0)
				goto err1;
			ulptx_la_buff = (struct struct_ulptx_la *)data;
			break;
		default:
			printf("Unsupported revision %u. Only supports <= %u\n",
			       rev, CUDBG_ULPTX_LA_REV);
			goto err1;
	}

	printf("\n=======================DUMPING ULP_TX_ASIC_DEBUG=======================\n\n");

	for (i = 0; i < CUDBG_NUM_ULPTX_ASIC_READ; i++) {
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     A_ULP_TX_ASIC_DEBUG_CTRL, i,
			     "A_ULP_TX_ASIC_DEBUG_CTRL",
			     ulptx_la_buff->rdptr_asic[i],
			     ulptx_la_buff->rdptr_asic[i]);
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     A_ULP_TX_ASIC_DEBUG_0,
			     i, "A_ULP_TX_ASIC_DEBUG_0",
			     ulptx_la_buff->rddata_asic[i][0],
			     ulptx_la_buff->rddata_asic[i][0]);
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     A_ULP_TX_ASIC_DEBUG_1,
			     i, "A_ULP_TX_ASIC_DEBUG_1",
			     ulptx_la_buff->rddata_asic[i][1],
			     ulptx_la_buff->rddata_asic[i][1]);
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     A_ULP_TX_ASIC_DEBUG_2,
			     i, "A_ULP_TX_ASIC_DEBUG_2",
			     ulptx_la_buff->rddata_asic[i][2],
			     ulptx_la_buff->rddata_asic[i][2]);
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     A_ULP_TX_ASIC_DEBUG_3,
			     i, "A_ULP_TX_ASIC_DEBUG_3",
			     ulptx_la_buff->rddata_asic[i][3],
			     ulptx_la_buff->rddata_asic[i][3]);
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     A_ULP_TX_ASIC_DEBUG_4,
			     i, "A_ULP_TX_ASIC_DEBUG_4",
			     ulptx_la_buff->rddata_asic[i][4],
			     ulptx_la_buff->rddata_asic[i][4]);
		printf("[0x%x][%#2x] %-24s %#-16x [%u]\n",
			     PM_RX_BASE_ADDR,
			     i, "PM_RX_BASE_ADDR",
			     ulptx_la_buff->rddata_asic[i][5],
			     ulptx_la_buff->rddata_asic[i][5]);
		printf("\n");
	}

err1:
	return rc;

}

int
view_ulprx_la(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_ulprx_la *ulprx_la_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;
	u32 i, *p;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	ulprx_la_buff = (struct struct_ulprx_la *) dc_buff.data;
	p = ulprx_la_buff->data;

	printf(
		     "      Pcmd        Type   Message                Data\n");
	for (i = 0; i <  ulprx_la_buff->size; i++, p += 8)
		printf(
			     "%08x%08x  %4x  %08x  %08x%08x%08x%08x\n",
			     p[1], p[0], p[2], p[3], p[7], p[6], p[5], p[4]);

	return rc;
}

int
view_wc_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_wc_stats *wc_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	wc_stats_buff = (struct struct_wc_stats *) dc_buff.data;

	printf("WriteCoalSuccess: %u\n",
		     wc_stats_buff->wr_cl_success);
	printf("WriteCoalFail:    %u\n",
		     wc_stats_buff->wr_cl_fail);

	return rc;
}

static int
field_desc_show(u64 v, const struct field_desc *p,
		struct cudbg_buffer *cudbg_poutbuf)
{
	int line_size = 0;
	char buf[32];
	int rc = 0;

	while (p->name) {
		u64 mask = (1ULL << p->width) - 1;
		int len = snprintf(buf, sizeof(buf), "%s: %llu", p->name,
				   ((unsigned long long)v >> p->start) & mask);

		if (line_size + len >= 79) {
			line_size = 8;
			printf("\n        ");
		}
		printf("%s ", buf);
		line_size += len + 1;
		p++;
	}
	printf("\n");

	return rc;
}

static int
tp_la_show(void *v, int idx, struct cudbg_buffer *cudbg_poutbuf)
{
	const u64 *p = v;
	int rc;

	rc = field_desc_show(*p, tp_la0, cudbg_poutbuf);
	return rc;
}

static int
tp_la_show2(void *v, int idx, struct cudbg_buffer *cudbg_poutbuf)
{
	const u64 *p = v;
	int rc;

	if (idx)
		printf("'\n");
	rc = field_desc_show(p[0], tp_la0, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		rc = field_desc_show(p[1], tp_la0, cudbg_poutbuf);

err1:
	return rc;
}

static int
tp_la_show3(void *v, int idx, struct cudbg_buffer *cudbg_poutbuf)
{
	const u64 *p = v;
	int rc;

	if (idx)
		printf("\n");
	rc = field_desc_show(p[0], tp_la0, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	if (idx < (TPLA_SIZE / 2 - 1) || p[1] != ~0ULL)
		rc = field_desc_show(p[1], (p[0] & BIT(17)) ? tp_la2 : tp_la1,
				     cudbg_poutbuf);

err1:
	return rc;
}

int
view_tp_la(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	   struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	static int (*la_show) (void *v, int idx,
			       struct cudbg_buffer *cudbg_poutbuf);
	struct cudbg_buffer c_buff, dc_buff;
	struct struct_tp_la *tp_la_buff;
	int i, rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tp_la_buff = (struct struct_tp_la *) dc_buff.data;
	switch (tp_la_buff->mode) {
	case 2:
		la_show = tp_la_show2;
		break;
	case 3:
		la_show = tp_la_show3;
		break;
	default:
		la_show = tp_la_show;
	}

	for (i = 0; i < TPLA_SIZE/2; i++) {
		rc = la_show((u64 *)tp_la_buff->data + i*2, i, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
	}

err1:
	return rc;
}

static unsigned long
do_div(unsigned long *number, u32 divisor)
{
	unsigned long remainder = *number % divisor;

	(*number) /= divisor;
	return remainder;
}

static int
string_get_size(unsigned long size,
		const enum string_size_units units, char *buf,
		int len)
{
	const char *units_10[] = {
		"B", "kB", "MB", "GB", "TB", "PB",
		"EB", "ZB", "YB", NULL
	};
	const char *units_2[] = {
		"B", "KiB", "MiB", "GiB", "TiB", "PiB",
		"EiB", "ZiB", "YiB", NULL
	};
	const char **units_str[2];/* = {units_10, units_2};*/
	const u32 divisor[] = {1000, 1024};
	unsigned long remainder = 0;
	unsigned long sf_cap = 0;
	char tmp[8] = {0};
	int i, j;

	tmp[0] = '\0';
	i = 0;

	units_str[STRING_UNITS_10] = units_10;
	units_str[STRING_UNITS_2] = units_2;

	if (size >= divisor[units]) {
		while (size >= divisor[units] && units_str[units][i]) {
			remainder = do_div(&size, divisor[units]);
			i++;
		}

		sf_cap = size;

		for (j = 0; sf_cap*10 < 1000; j++)
			sf_cap *= 10;

		if (j) {
			remainder *= 1000;
			do_div(&remainder, divisor[units]);

			(void)snprintf(tmp, sizeof(tmp), ".%03lu",
						   (unsigned long)remainder);
			tmp[j + 1] = '\0';
		}
	}

	(void)snprintf(buf, len, "%lu%s %s", (unsigned long)size, tmp,
		 units_str[units][i]);

	return 0;
}

static int
mem_region_show(const char *name, u32 from, u32 to,
		struct cudbg_buffer *cudbg_poutbuf)
{
	char buf[40] = {0};
	int rc = 0;

	string_get_size((u64)to - from + 1, STRING_UNITS_2,
			buf, sizeof(buf));
	printf("%-14s %#x-%#x [%s]\n", name, from,
		     to, buf);

	return rc;
} /* mem_region_show */

int
view_meminfo(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	     struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_meminfo *meminfo_buff;
	struct cudbg_buffer c_buff, dc_buff;
	u32 i, lo, idx;
	int rc = 0, rev;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	rev = get_entity_rev((struct cudbg_ver_hdr *)dc_buff.data);
	switch (rev) {
		case 0:
			meminfo_buff = (struct struct_meminfo *)dc_buff.data;
			break;
		case CUDBG_MEMINFO_REV:
			meminfo_buff = (struct struct_meminfo *)
				       (dc_buff.data +
				        sizeof(struct cudbg_ver_hdr));
			break;
		default:
			printf("Unsupported revision %u. Only supports <= %u\n",
				rev, CUDBG_MEMINFO_REV);
			goto err1;
	}

	for (lo = 0; lo < meminfo_buff->avail_c; lo++) {
		idx = meminfo_buff->avail[lo].idx;
		rc = mem_region_show(memory[idx], meminfo_buff->avail[lo].base,
				     meminfo_buff->avail[lo].limit - 1,
				     cudbg_poutbuf);
		if (rc < 0)
			goto err1;
	}

	for (i = 0; i < meminfo_buff->mem_c; i++) {
		if (meminfo_buff->mem[i].idx >= ARRAY_SIZE(region))
			continue;                        /* skip holes */
		if (!(meminfo_buff->mem[i].limit))
			meminfo_buff->mem[i].limit =
				i < meminfo_buff->mem_c - 1 ?
				meminfo_buff->mem[i + 1].base - 1 : ~0;

		idx = meminfo_buff->mem[i].idx;
		rc = mem_region_show(region[idx], meminfo_buff->mem[i].base,
				     meminfo_buff->mem[i].limit, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
	}

	rc = mem_region_show("uP RAM:", meminfo_buff->up_ram_lo,
			     meminfo_buff->up_ram_hi, cudbg_poutbuf);
	if (rc < 0)
		goto err1;
	rc = mem_region_show("uP Extmem2:", meminfo_buff->up_extmem2_lo,
			     meminfo_buff->up_extmem2_hi, cudbg_poutbuf);
	if (rc < 0)
		goto err1;

	if (rev == 0) {
		struct struct_meminfo_rev0 *meminfo_buff_rev0 =
			(struct struct_meminfo_rev0 *)meminfo_buff;

		printf("\n%u Rx pages of size %uKiB for %u channels\n",
			     meminfo_buff_rev0->rx_pages_data[0],
			     meminfo_buff_rev0->rx_pages_data[1],
			     meminfo_buff_rev0->rx_pages_data[2]);
		printf("%u Tx pages of size %u%ciB for %u channels\n\n",
			     meminfo_buff_rev0->tx_pages_data[0],
			     meminfo_buff_rev0->tx_pages_data[1],
			     meminfo_buff_rev0->tx_pages_data[2],
			     meminfo_buff_rev0->tx_pages_data[3]);
	} else if (rev == CUDBG_MEMINFO_REV) {
		printf("\n%u Rx pages (%u free) of size %uKiB for %u channels\n",
			     meminfo_buff->rx_pages_data[0],
			     meminfo_buff->free_rx_cnt,
			     meminfo_buff->rx_pages_data[1],
			     meminfo_buff->rx_pages_data[2]);
		printf("%u Tx pages (%u free) of size %u%ciB for %u channels\n",
			     meminfo_buff->tx_pages_data[0],
			     meminfo_buff->free_tx_cnt,
			     meminfo_buff->tx_pages_data[1],
			     meminfo_buff->tx_pages_data[2],
			     meminfo_buff->tx_pages_data[3]);
		printf("%u p-structs (%u free)\n\n",
			     meminfo_buff->p_structs,
			     meminfo_buff->pstructs_free_cnt);
	}

	for (i = 0; i < 4; i++) {
		printf("Port %d using %u pages out "\
			     "of %u allocated\n",
			     i, meminfo_buff->port_used[i],
			     meminfo_buff->port_alloc[i]);
	}

	for (i = 0; i < NCHAN; i++) {
		printf("Loopback %d using %u pages "\
			     "out of %u allocated\n",
			     i, meminfo_buff->loopback_used[i],
			     meminfo_buff->loopback_alloc[i]);
	}

err1:
	return rc;
}

int
view_lb_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_lb_stats *lb_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	struct lb_port_stats *tmp_stats;
	int i, j, rc = 0;
	u64 *p0, *p1;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	lb_stats_buff = (struct struct_lb_stats *) dc_buff.data;
	tmp_stats  = lb_stats_buff->s;
	for (i = 0; i < lb_stats_buff->nchan; i += 2, tmp_stats += 2) {
		p0 = &(tmp_stats[0].octets);
		p1 = &(tmp_stats[1].octets);
		printf("%s                       "\
			     "Loopback %u           Loopback %u\n",
			     i == 0 ? "" : "\n", i, i + 1);

		for (j = 0; j < ARRAY_SIZE(lb_stat_name); j++)
			printf("%-17s %20llu "\
				     "%20llu\n", lb_stat_name[j],
				     (unsigned long long)*p0++,
				     (unsigned long long)*p1++);
	}

	return rc;
}

int
view_rdma_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct tp_rdma_stats *rdma_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	rdma_stats_buff = (struct tp_rdma_stats *) dc_buff.data;
	printf("NoRQEModDefferals: %u\n",
		     rdma_stats_buff->rqe_dfr_mod);
	printf("NoRQEPktDefferals: %u\n",
		     rdma_stats_buff->rqe_dfr_pkt);

	return rc;
}

int
view_clk_info(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_clk_info *clk_info_buff;
	struct cudbg_buffer c_buff, dc_buff;
	char tmp[32] = { 0 };
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	clk_info_buff = (struct struct_clk_info *) dc_buff.data;

	unit_conv(tmp, 32, clk_info_buff->cclk_ps, 1000);
	printf("Core clock period: %s ns\n", tmp);

	unit_conv(tmp, 32, clk_info_buff->cclk_ps << clk_info_buff->tre,
		  1000000);
	printf("TP timer tick: %s us\n", tmp);

	unit_conv(tmp, 32,
		  clk_info_buff->cclk_ps << G_TIMESTAMPRESOLUTION(clk_info_buff->res),
		  1000000);
	printf("TCP timestamp tick: %s us\n", tmp);

	unit_conv(tmp, 32, clk_info_buff->cclk_ps << clk_info_buff->dack_re,
		  1000000);
	printf("DACK tick: %s us\n", tmp);

	printf("DACK timer: %u us\n",
		     clk_info_buff->dack_timer);
	printf("Retransmit min: %llu us\n",
		     clk_info_buff->retransmit_min);
	printf("Retransmit max: %llu us\n",
		     clk_info_buff->retransmit_max);
	printf("Persist timer min: %llu us\n",
		     clk_info_buff->persist_timer_min);
	printf("Persist timer max: %llu us\n",
		     clk_info_buff->persist_timer_max);
	printf("Keepalive idle timer: %llu us\n",
		     clk_info_buff->keepalive_idle_timer);
	printf("Keepalive interval: %llu us\n",
		     clk_info_buff->keepalive_interval);
	printf("Initial SRTT: %llu us\n",
		     clk_info_buff->initial_srtt);
	printf("FINWAIT2 timer: %llu us\n",
		     clk_info_buff->finwait2_timer);

	return rc;
}

int
view_cim_pif_la(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct cim_pif_la *cim_pif_la_buff;
	int i, rc = 0;
	u32 *p;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	cim_pif_la_buff = (struct cim_pif_la *) dc_buff.data;
	p = (u32 *)cim_pif_la_buff->data;

	printf("Cntl ID DataBE   Addr            "\
		     "     Data\n");
	for (i = 0; i < cim_pif_la_buff->size; i++, p = p + 6)
		printf(" %02x  %02x  %04x  %08x "\
			     "%08x%08x%08x%08x\n",
			     (p[5] >> 22) & 0xff, (p[5] >> 16) & 0x3f,
			     p[5] & 0xffff, p[4], p[3], p[2], p[1], p[0]);

	p = (u32 *) cim_pif_la_buff->data +  6 * CIM_PIFLA_SIZE;

	printf("\nCntl ID               Data\n");
	for (i = 0; i < cim_pif_la_buff->size; i++, p = p + 6)
		printf(" %02x  %02x "\
			     "%08x%08x%08x%08x\n",
			     (p[4] >> 6) & 0xff, p[4] & 0x3f, p[3], p[2], p[1],
			     p[0]);

	return rc;
}

int
view_fcoe_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_tp_fcoe_stats *tp_fcoe_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	struct tp_fcoe_stats stats[4];
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tp_fcoe_stats_buff = (struct struct_tp_fcoe_stats *) dc_buff.data;
	memcpy(stats, tp_fcoe_stats_buff->stats, sizeof(stats));

	if (tp_fcoe_stats_buff->nchan == NCHAN) {
		printf("                   channel "\
			     "0        channel 1        channel 2        "\
			     "channel 3\n");
		printf("octetsDDP:  %16llu %16llu "\
			     "%16llu %16llu\n",
			     stats[0].octets_ddp, stats[1].octets_ddp,
			     stats[2].octets_ddp, stats[3].octets_ddp);
		printf("framesDDP:  %16u %16u %16u "\
			     "%16u\n",
			     stats[0].frames_ddp, stats[1].frames_ddp,
			     stats[2].frames_ddp, stats[3].frames_ddp);
		printf("framesDrop: %16u %16u %16u "\
			     "%16u\n",
			     stats[0].frames_drop, stats[1].frames_drop,
			     stats[2].frames_drop, stats[3].frames_drop);
	} else {
		printf("                   channel "\
			     "0        channel 1\n");
		printf("octetsDDP:  %16llu "\
			     "%16llu\n",
			     stats[0].octets_ddp, stats[1].octets_ddp);
		printf("framesDDP:  %16u %16u\n",
			     stats[0].frames_ddp, stats[1].frames_ddp);
		printf("framesDrop: %16u %16u\n",
			     stats[0].frames_drop, stats[1].frames_drop);
	}

	return rc;
}

int
view_tp_err_stats_show(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		       struct cudbg_buffer *cudbg_poutbuf,
		       enum chip_type chip)
{
	struct struct_tp_err_stats *tp_err_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	struct tp_err_stats stats;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tp_err_stats_buff = (struct struct_tp_err_stats *) dc_buff.data;
	stats = tp_err_stats_buff->stats;
	if (tp_err_stats_buff->nchan == NCHAN) {
		printf("                 channel 0"\
			     "  channel 1  channel 2  channel 3\n");
		printf("macInErrs:      %10u %10u "\
			     "%10u %10u\n",
			     stats.mac_in_errs[0], stats.mac_in_errs[1],
			     stats.mac_in_errs[2], stats.mac_in_errs[3]);
		printf("hdrInErrs:      %10u %10u "\
			     "%10u %10u\n",
			     stats.hdr_in_errs[0], stats.hdr_in_errs[1],
			     stats.hdr_in_errs[2], stats.hdr_in_errs[3]);
		printf("tcpInErrs:      %10u %10u "\
			     "%10u %10u\n",
			     stats.tcp_in_errs[0], stats.tcp_in_errs[1],
			     stats.tcp_in_errs[2], stats.tcp_in_errs[3]);
		printf("tcp6InErrs:     %10u %10u "\
			     "%10u %10u\n",
			     stats.tcp6_in_errs[0], stats.tcp6_in_errs[1],
			     stats.tcp6_in_errs[2], stats.tcp6_in_errs[3]);
		printf("tnlCongDrops:   %10u %10u "\
			     "%10u %10u\n",
			     stats.tnl_cong_drops[0], stats.tnl_cong_drops[1],
			     stats.tnl_cong_drops[2], stats.tnl_cong_drops[3]);
		printf("tnlTxDrops:     %10u %10u "\
			     "%10u %10u\n",
			     stats.tnl_tx_drops[0], stats.tnl_tx_drops[1],
			     stats.tnl_tx_drops[2], stats.tnl_tx_drops[3]);
		printf("ofldVlanDrops:  %10u %10u "\
			     "%10u %10u\n",
			     stats.ofld_vlan_drops[0], stats.ofld_vlan_drops[1],
			     stats.ofld_vlan_drops[2],
			     stats.ofld_vlan_drops[3]);
		printf("ofldChanDrops:  %10u %10u "\
			     "%10u %10u\n\n",
			     stats.ofld_chan_drops[0], stats.ofld_chan_drops[1],
			     stats.ofld_chan_drops[2],
			     stats.ofld_chan_drops[3]);
	} else {
		printf("                 channel 0"\
			     "  channel 1\n");
		printf("macInErrs:      %10u %10u\n",
			     stats.mac_in_errs[0], stats.mac_in_errs[1]);
		printf("hdrInErrs:      %10u %10u\n",
			     stats.hdr_in_errs[0], stats.hdr_in_errs[1]);
		printf("tcpInErrs:      %10u %10u\n",
			     stats.tcp_in_errs[0], stats.tcp_in_errs[1]);
		printf("tcp6InErrs:     %10u %10u\n",
			     stats.tcp6_in_errs[0], stats.tcp6_in_errs[1]);
		printf("tnlCongDrops:   %10u %10u\n",
			     stats.tnl_cong_drops[0], stats.tnl_cong_drops[1]);
		printf("tnlTxDrops:     %10u %10u\n",
			     stats.tnl_tx_drops[0], stats.tnl_tx_drops[1]);
		printf("ofldVlanDrops:  %10u %10u\n",
			     stats.ofld_vlan_drops[0],
			     stats.ofld_vlan_drops[1]);
		printf("ofldChanDrops:  %10u %10u"\
			     "\n\n", stats.ofld_chan_drops[0],
			     stats.ofld_chan_drops[1]);
	}

	printf("ofldNoNeigh:    %u\nofldCongDefer: "\
		     " %u\n", stats.ofld_no_neigh, stats.ofld_cong_defer);

	return rc;
}

int
view_tcp_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_tcp_stats *tcp_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tcp_stats_buff = (struct struct_tcp_stats *) dc_buff.data;
	printf("                                IP"\
		     "                 IPv6\n");
	printf("OutRsts:      %20u %20u\n",
		     tcp_stats_buff->v4.tcp_out_rsts,
		     tcp_stats_buff->v6.tcp_out_rsts);
	printf("InSegs:       %20llu %20llu\n",
		     (unsigned long long)(tcp_stats_buff->v4.tcp_in_segs),
		     (unsigned long long)(tcp_stats_buff->v6.tcp_in_segs));
	printf("OutSegs:      %20llu %20llu\n",
		     (unsigned long long)(tcp_stats_buff->v4.tcp_out_segs),
		     (unsigned long long)(tcp_stats_buff->v6.tcp_out_segs));
	printf("RetransSegs:  %20llu %20llu\n",
		     (unsigned long long)(tcp_stats_buff->v4.tcp_retrans_segs),
		     (unsigned long long)(tcp_stats_buff->v6.tcp_retrans_segs));

	return rc;
}

int
view_hw_sched(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct struct_hw_sched *hw_sched_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int i, rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	hw_sched_buff = (struct struct_hw_sched *)dc_buff.data;

	printf("Scheduler  Mode   Channel  Rate "\
		     "(Kbps)   Class IPG (0.1 ns)   Flow IPG (us)\n");
	for (i = 0; i < NTX_SCHED; ++i, hw_sched_buff->map >>= 2) {
		printf("    %u      %-5s     %u"\
			     "     ", i,
			     (hw_sched_buff->mode & (1 << i)) ?
			     "flow" : "class",
			     hw_sched_buff->map & 3);
		if (hw_sched_buff->kbps[i]) {
			printf("%9u     ",
				     hw_sched_buff->kbps[i]);
		} else {
			printf(" disabled     ");
		}

		if (hw_sched_buff->ipg[i]) {
			printf("%13u        ",
				     hw_sched_buff->ipg[i]);
		} else {
			printf("     disabled    "\
				     "    ");
		}

		if (hw_sched_buff->pace_tab[i]) {
			printf("%10u\n",
				     hw_sched_buff->pace_tab[i]);
		} else {
			printf("  disabled\n");
		}
	}

	return rc;
}

int
view_pm_stats(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	static const char * const tx_pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Bypass + mem:"
	};
	static const char * const rx_pm_stats[] = {
		"Read:", "Write bypass:", "Write mem:", "Flush:"
	};
	struct struct_pm_stats *pm_stats_buff;
	struct cudbg_buffer c_buff, dc_buff;
	int i, rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	pm_stats_buff = (struct struct_pm_stats *)dc_buff.data;

	printf("%13s %10s  %20s\n", " ", "Tx pcmds",
		     "Tx bytes");
	for (i = 0; i < PM_NSTATS - 1; i++)
		printf("%-13s %10u  %20llu\n",
			     tx_pm_stats[i], pm_stats_buff->tx_cnt[i],
			     pm_stats_buff->tx_cyc[i]);

	printf("%13s %10s  %20s\n", " ", "Rx pcmds",
		     "Rx bytes");
	for (i = 0; i < PM_NSTATS - 1; i++)
		printf("%-13s %10u  %20llu\n",
			     rx_pm_stats[i], pm_stats_buff->rx_cnt[i],
			     pm_stats_buff->rx_cyc[i]);

	if (CHELSIO_CHIP_VERSION(chip) > CHELSIO_T5) {
		/* In T5 the granularity of the total wait is too fine.
		 * It is not useful as it reaches the max value too fast.
		 * Hence display this Input FIFO wait for T6 onwards.
		 */
		printf("%13s %10s  %20s\n",
			   " ", "Total wait", "Total Occupancy");
		printf("Tx FIFO wait  "
			     "%10u  %20llu\n", pm_stats_buff->tx_cnt[i],
			     pm_stats_buff->tx_cyc[i]);
		printf("Rx FIFO wait  %10u  "
			     "%20llu\n", pm_stats_buff->rx_cnt[i],
			     pm_stats_buff->rx_cyc[i]);

		/* Skip index 6 as there is nothing useful here */
		i += 2;

		/* At index 7, a new stat for read latency (count, total wait)
		 * is added.
		 */
		printf("%13s %10s  %20s\n",
			     " ", "Reads", "Total wait");
		printf("Tx latency    "
			     "%10u  %20llu\n", pm_stats_buff->tx_cnt[i],
			     pm_stats_buff->tx_cyc[i]);
		printf("Rx latency    "
			     "%10u  %20llu\n", pm_stats_buff->rx_cnt[i],
			     pm_stats_buff->rx_cyc[i]);
	}

	return rc;
}

int
view_path_mtu(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;
	u16 *mtus;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	mtus = (u16 *)dc_buff.data;
	printf("%u %u %u %u %u %u %u %u %u %u %u %u"\
		     " %u %u %u %u\n",
		     mtus[0], mtus[1], mtus[2], mtus[3], mtus[4], mtus[5],
		     mtus[6], mtus[7], mtus[8], mtus[9], mtus[10], mtus[11],
		     mtus[12], mtus[13], mtus[14], mtus[15]);

	return rc;
}

int
view_rss_config(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	static const char * const keymode[] = {
		"global",
		"global and per-VF scramble",
		"per-PF and per-VF scramble",
		"per-VF and per-VF scramble",
	};
	struct cudbg_buffer c_buff, dc_buff;
	struct rss_config *struct_rss_conf;
	u32 rssconf;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	struct_rss_conf = (struct rss_config *)dc_buff.data;
	rssconf = struct_rss_conf->tp_rssconf;
	printf("TP_RSS_CONFIG: %#x\n", rssconf);
	printf("  Tnl4TupEnIpv6: %3s\n",
		     yesno(rssconf & F_TNL4TUPENIPV6));
	printf("  Tnl2TupEnIpv6: %3s\n",
		     yesno(rssconf & F_TNL2TUPENIPV6));
	printf("  Tnl4TupEnIpv4: %3s\n",
		     yesno(rssconf & F_TNL4TUPENIPV4));
	printf("  Tnl2TupEnIpv4: %3s\n",
		     yesno(rssconf & F_TNL2TUPENIPV4));
	printf("  TnlTcpSel:     %3s\n",
		     yesno(rssconf & F_TNLTCPSEL));
	printf("  TnlIp6Sel:     %3s\n",
		     yesno(rssconf & F_TNLIP6SEL));
	printf("  TnlVrtSel:     %3s\n",
		     yesno(rssconf & F_TNLVRTSEL));
	printf("  TnlMapEn:      %3s\n",
		     yesno(rssconf & F_TNLMAPEN));
	printf("  OfdHashSave:   %3s\n",
		     yesno(rssconf & F_OFDHASHSAVE));
	printf("  OfdVrtSel:     %3s\n",
		     yesno(rssconf & F_OFDVRTSEL));
	printf("  OfdMapEn:      %3s\n",
		     yesno(rssconf & F_OFDMAPEN));
	printf("  OfdLkpEn:      %3s\n",
		     yesno(rssconf & F_OFDLKPEN));
	printf("  Syn4TupEnIpv6: %3s\n",
		     yesno(rssconf & F_SYN4TUPENIPV6));
	printf("  Syn2TupEnIpv6: %3s\n",
		     yesno(rssconf & F_SYN2TUPENIPV6));
	printf("  Syn4TupEnIpv4: %3s\n",
		     yesno(rssconf & F_SYN4TUPENIPV4));
	printf("  Syn2TupEnIpv4: %3s\n",
		     yesno(rssconf & F_SYN2TUPENIPV4));
	printf("  Syn4TupEnIpv6: %3s\n",
		     yesno(rssconf & F_SYN4TUPENIPV6));
	printf("  SynIp6Sel:     %3s\n",
		     yesno(rssconf & F_SYNIP6SEL));
	printf("  SynVrt6Sel:    %3s\n",
		     yesno(rssconf & F_SYNVRTSEL));
	printf("  SynMapEn:      %3s\n",
		     yesno(rssconf & F_SYNMAPEN));
	printf("  SynLkpEn:      %3s\n",
		     yesno(rssconf & F_SYNLKPEN));
	printf("  ChnEn:         %3s\n",
		     yesno(rssconf & F_CHANNELENABLE));
	printf("  PrtEn:         %3s\n",
		     yesno(rssconf & F_PORTENABLE));
	printf("  TnlAllLkp:     %3s\n",
		     yesno(rssconf & F_TNLALLLOOKUP));
	printf("  VrtEn:         %3s\n",
		     yesno(rssconf & F_VIRTENABLE));
	printf("  CngEn:         %3s\n",
		     yesno(rssconf & F_CONGESTIONENABLE));
	printf("  HashToeplitz:  %3s\n",
		     yesno(rssconf & F_HASHTOEPLITZ));
	printf("  Udp4En:        %3s\n",
		     yesno(rssconf & F_UDPENABLE));
	printf("  Disable:       %3s\n",
		     yesno(rssconf & F_DISABLE));

	rssconf = struct_rss_conf->tp_rssconf_tnl;
	printf("TP_RSS_CONFIG_TNL: %#x\n",
		     rssconf);
	printf("  MaskSize:      %3d\n",
		     G_MASKSIZE(rssconf));
	printf("  MaskFilter:    %3d\n",
		     G_MASKFILTER(rssconf));
	if (CHELSIO_CHIP_VERSION(struct_rss_conf->chip) > CHELSIO_T5) {
		printf("  HashAll:     %3s\n",
			     yesno(rssconf & F_HASHALL));
		printf("  HashEth:     %3s\n",
			     yesno(rssconf & F_HASHETH));
	}
	printf("  UseWireCh:     %3s\n",
		     yesno(rssconf & F_USEWIRECH));

	rssconf = struct_rss_conf->tp_rssconf_ofd;
	printf("TP_RSS_CONFIG_OFD: %#x\n",
		     rssconf);
	printf("  MaskSize:      %3d\n",
		     G_MASKSIZE(rssconf));
	printf("  RRCplMapEn:    %3s\n",
		     yesno(rssconf & F_RRCPLMAPEN));
	printf("  RRCplQueWidth: %3d\n",
		     G_RRCPLQUEWIDTH(rssconf));

	rssconf = struct_rss_conf->tp_rssconf_syn;
	printf("TP_RSS_CONFIG_SYN: %#x\n",
		     rssconf);
	printf("  MaskSize:      %3d\n",
		     G_MASKSIZE(rssconf));
	printf("  UseWireCh:     %3s\n",
		     yesno(rssconf & F_USEWIRECH));

	rssconf = struct_rss_conf->tp_rssconf_vrt;
	printf("TP_RSS_CONFIG_VRT: %#x\n",
		     rssconf);
	if (CHELSIO_CHIP_VERSION(struct_rss_conf->chip) > CHELSIO_T5) {
		printf("  KeyWrAddrX:     %3d\n",
			     G_KEYWRADDRX(rssconf));
		printf("  KeyExtend:      %3s\n",
			     yesno(rssconf & F_KEYEXTEND));
	}
	printf("  VfRdRg:        %3s\n",
		     yesno(rssconf & F_VFRDRG));
	printf("  VfRdEn:        %3s\n",
		     yesno(rssconf & F_VFRDEN));
	printf("  VfPerrEn:      %3s\n",
		     yesno(rssconf & F_VFPERREN));
	printf("  KeyPerrEn:     %3s\n",
		     yesno(rssconf & F_KEYPERREN));
	printf("  DisVfVlan:     %3s\n",
		     yesno(rssconf & F_DISABLEVLAN));
	printf("  EnUpSwt:       %3s\n",
		     yesno(rssconf & F_ENABLEUP0));
	printf("  HashDelay:     %3d\n",
		     G_HASHDELAY(rssconf));
	if (CHELSIO_CHIP_VERSION(struct_rss_conf->chip) <= CHELSIO_T5) {
		printf("  VfWrAddr:      %3d\n",
			     G_VFWRADDR(rssconf));
	} else {
		printf("  VfWrAddr:      %3d\n",
			     G_T6_VFWRADDR(rssconf));
	}
	printf("  KeyMode:       %s\n",
		     keymode[G_KEYMODE(rssconf)]);
	printf("  VfWrEn:        %3s\n",
		     yesno(rssconf & F_VFWREN));
	printf("  KeyWrEn:       %3s\n",
		     yesno(rssconf & F_KEYWREN));
	printf("  KeyWrAddr:     %3d\n",
		     G_KEYWRADDR(rssconf));

	rssconf = struct_rss_conf->tp_rssconf_cng;
	printf("TP_RSS_CONFIG_CNG: %#x\n",
		     rssconf);
	printf("  ChnCount3:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT3));
	printf("  ChnCount2:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT2));
	printf("  ChnCount1:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT1));
	printf("  ChnCount0:     %3s\n",
		     yesno(rssconf & F_CHNCOUNT0));
	printf("  ChnUndFlow3:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW3));
	printf("  ChnUndFlow2:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW2));
	printf("  ChnUndFlow1:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW1));
	printf("  ChnUndFlow0:   %3s\n",
		     yesno(rssconf & F_CHNUNDFLOW0));
	printf("  RstChn3:       %3s\n",
		     yesno(rssconf & F_RSTCHN3));
	printf("  RstChn2:       %3s\n",
		     yesno(rssconf & F_RSTCHN2));
	printf("  RstChn1:       %3s\n",
		     yesno(rssconf & F_RSTCHN1));
	printf("  RstChn0:       %3s\n",
		     yesno(rssconf & F_RSTCHN0));
	printf("  UpdVld:        %3s\n",
		     yesno(rssconf & F_UPDVLD));
	printf("  Xoff:          %3s\n",
		     yesno(rssconf & F_XOFF));
	printf("  UpdChn3:       %3s\n",
		     yesno(rssconf & F_UPDCHN3));
	printf("  UpdChn2:       %3s\n",
		     yesno(rssconf & F_UPDCHN2));
	printf("  UpdChn1:       %3s\n",
		     yesno(rssconf & F_UPDCHN1));
	printf("  UpdChn0:       %3s\n",
		     yesno(rssconf & F_UPDCHN0));
	printf("  Queue:         %3d\n",
		     G_QUEUE(rssconf));

	return rc;
}

int
view_rss_key(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	     struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;
	u32 *key;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	key = (u32 *)dc_buff.data;
	printf(
		     "%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x\n",
		     key[9], key[8], key[7], key[6], key[5], key[4],
		     key[3], key[2], key[1], key[0]);

	return rc;
}

int
view_rss_vf_config(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		   struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct rss_vf_conf *vfconf;
	int i, rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	vfconf = (struct rss_vf_conf *) dc_buff.data;
	printf("     RSS                     Hash "\
		     "Tuple Enable\n");
	printf("     Enable   IVF  Dis  Enb  IPv6 "\
		     "     IPv4      UDP    Def  Secret Key\n");
	printf(" VF  Chn Prt  Map  VLAN  uP  Four "\
		     "Two  Four Two  Four   Que  Idx       Hash\n");
	for (i = 0; i < dc_buff.offset/sizeof(*vfconf); i += 1) {
		printf("%3d  %3s %3s  %3d   %3s %3s"\
			     "   %3s %3s   %3s %3s   %3s  %4d  %3d %#10x\n",
			     i, yesno(vfconf->rss_vf_vfh & F_VFCHNEN),
			     yesno(vfconf->rss_vf_vfh & F_VFPRTEN),
			     G_VFLKPIDX(vfconf->rss_vf_vfh),
			     yesno(vfconf->rss_vf_vfh & F_VFVLNEX),
			     yesno(vfconf->rss_vf_vfh & F_VFUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP4FOURTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP6TWOTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP4FOURTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_VFIP4TWOTUPEN),
			     yesno(vfconf->rss_vf_vfh & F_ENABLEUDPHASH),
			     G_DEFAULTQUEUE(vfconf->rss_vf_vfh),
			     G_KEYINDEX(vfconf->rss_vf_vfh),
			     vfconf->rss_vf_vfl);

		vfconf++;
	}

	return rc;
}

int
view_rss_pf_config(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		   struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct rss_pf_conf *pfconf;
	int i, rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	pfconf = (struct rss_pf_conf *) dc_buff.data;
	printf("PF Map Index Size = %d\n\n",
		     G_LKPIDXSIZE(pfconf->rss_pf_map));
	printf("     RSS              PF   VF    "\
		     "Hash Tuple Enable         Default\n");
	printf("     Enable       IPF Mask Mask  "\
		     "IPv6      IPv4      UDP   Queue\n");
	printf(" PF  Map Chn Prt  Map Size Size  "\
		     "Four Two  Four Two  Four  Ch1  Ch0\n");

#define G_PFnLKPIDX(map, n) \
	(((map) >> S_PF1LKPIDX*(n)) & M_PF0LKPIDX)
#define G_PFnMSKSIZE(mask, n) \
	(((mask) >> S_PF1MSKSIZE*(n)) & M_PF1MSKSIZE)

	for (i = 0; i < dc_buff.offset/sizeof(*pfconf); i += 1) {
		printf("%3d  %3s %3s %3s  %3d  %3d"\
			     "  %3d   %3s %3s   %3s %3s   %3s  %3d  %3d\n",
			     i, yesno(pfconf->rss_pf_config & F_MAPENABLE),
			     yesno(pfconf->rss_pf_config & F_CHNENABLE),
			     yesno(pfconf->rss_pf_config & F_PRTENABLE),
			     G_PFnLKPIDX(pfconf->rss_pf_map, i),
			     G_PFnMSKSIZE(pfconf->rss_pf_mask, i),
			     G_IVFWIDTH(pfconf->rss_pf_config),
			     yesno(pfconf->rss_pf_config & F_IP6FOURTUPEN),
			     yesno(pfconf->rss_pf_config & F_IP6TWOTUPEN),
			     yesno(pfconf->rss_pf_config & F_IP4FOURTUPEN),
			     yesno(pfconf->rss_pf_config & F_IP4TWOTUPEN),
			     yesno(pfconf->rss_pf_config & F_UDPFOURTUPEN),
			     G_CH1DEFAULTQUEUE(pfconf->rss_pf_config),
			     G_CH0DEFAULTQUEUE(pfconf->rss_pf_config));

		pfconf++;
	}
#undef G_PFnLKPIDX
#undef G_PFnMSKSIZE

	return rc;
}

int
view_rss(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	u16 *pdata = NULL;
	int rc = 0;
	u32 i;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	pdata = (u16 *) dc_buff.data;
	for (i = 0; i < dc_buff.offset / 2; i += 8) {
		printf("%4d:  %4u  %4u  %4u  %4u  "\
			     "%4u  %4u  %4u  %4u\n",
			     i, pdata[i + 0], pdata[i + 1], pdata[i + 2],
			     pdata[i + 3], pdata[i + 4], pdata[i + 5],
			     pdata[i + 6], pdata[i + 7]);
	}

	return rc;
}

int
view_fw_devlog(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	       struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct fw_devlog_e *e, *devlog;
	unsigned long index;
	u32 num_entries = 0;
	u32 first_entry = 0;
	int rc = 0;
	u32 itr;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	translate_fw_devlog(dc_buff.data, dc_buff.offset,
			&num_entries, &first_entry);

	devlog = (struct fw_devlog_e *)(dc_buff.data);
	printf("%10s  %15s  %8s  %8s  %s\n",
		     "Seq#", "Tstamp", "Level", "Facility", "Message");

	index = first_entry;
	for (itr = 0; itr < num_entries; itr++) {
		if (index >= num_entries)
			index = 0;

		e = &devlog[index++];
		if (e->timestamp == 0)
			break;
		printf("%10d  %15llu  %8s  %8s  ",
			     e->seqno, e->timestamp,
			     (e->level < ARRAY_SIZE(devlog_level_strings)
			      ? devlog_level_strings[e->level] : "UNKNOWN"),
			     (e->facility < ARRAY_SIZE(devlog_facility_strings)
			      ? devlog_facility_strings[e->facility]
			      : "UNKNOWN"));
		printf((const char *)e->fmt,
			     e->params[0], e->params[1], e->params[2],
			     e->params[3], e->params[4], e->params[5],
			     e->params[6], e->params[7]);
	}

	return rc;
}

void
translate_fw_devlog(void *pbuf, u32 io_size,
		    u32 *num_entries, u32 *first_entry)
{
	struct fw_devlog_e *e = NULL;
	u64 ftstamp;
	u32 index;

	*num_entries = (io_size / sizeof(struct fw_devlog_e));
	*first_entry = 0;
	e = (struct fw_devlog_e *)pbuf;
	for (ftstamp = ~0ULL, index = 0; index < *num_entries; index++) {
		int i;

		if (e->timestamp == 0)
			continue;

		e->timestamp = ntohll(e->timestamp);
		e->seqno = ntohl(e->seqno);
		for (i = 0; i < 8; i++)
			e->params[i] = ntohl(e->params[i]);

		if (e->timestamp < ftstamp) {
			ftstamp = e->timestamp;
			*first_entry = index;
		}

		e++;
	}
}

/* Regdump function */
static uint32_t
xtract(uint32_t val, int shift, int len)
{
	return (val >> shift) & ((1L << len) - 1);
}

static int
dump_block_regs(const struct reg_info *reg_array, const u32 *regs,
		struct cudbg_buffer *cudbg_poutbuf)
{
	uint32_t reg_val = 0; /* silence compiler warning*/
	int rc = 0;

	for (; reg_array->name; ++reg_array) {
		if (!reg_array->len) {
			reg_val = regs[reg_array->addr / 4];
			printf("[%#7x] %-47s %#-10x"\
				     " %u\n", reg_array->addr, reg_array->name,
				     reg_val, reg_val);
		} else {
			uint32_t v = xtract(reg_val, reg_array->addr,
					    reg_array->len);

			printf("    %*u:%u %-47s "\
				     "%#-10x %u\n",
				     reg_array->addr < 10 ? 3 : 2,
				     reg_array->addr + reg_array->len - 1,
				     reg_array->addr, reg_array->name, v, v);
		}
	}

	return 1;

	return rc;
}

static int
dump_regs_table(const u32 *regs, const struct mod_regs *modtab,
		int nmodules, const char *modnames,
		struct cudbg_buffer *cudbg_poutbuf)
{
	int match = 0;
	int rc = 0;

	for (; nmodules; nmodules--, modtab++) {
		rc = dump_block_regs(modtab->ri,
				     regs + modtab->offset, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		match += rc;
	}

err1:
	return rc;
}

#define T6_MODREGS(name) { #name, t6_##name##_regs }
static int
dump_regs_t6(const u32 *regs, struct cudbg_buffer *cudbg_poutbuf)
{
	static struct mod_regs t6_mod[] = {
		T6_MODREGS(sge),
		{ "pci", t6_pcie_regs },
		T6_MODREGS(dbg),
		{ "mc0", t6_mc_0_regs },
		T6_MODREGS(ma),
		{ "edc0", t6_edc_t60_regs },
		{ "edc1", t6_edc_t61_regs },
		T6_MODREGS(cim),
		T6_MODREGS(tp),
		{ "ulprx", t6_ulp_rx_regs },
		{ "ulptx", t6_ulp_tx_regs },
		{ "pmrx", t6_pm_rx_regs },
		{ "pmtx", t6_pm_tx_regs },
		T6_MODREGS(mps),
		{ "cplsw", t6_cpl_switch_regs },
		T6_MODREGS(smb),
		{ "i2c", t6_i2cm_regs },
		T6_MODREGS(mi),
		T6_MODREGS(uart),
		T6_MODREGS(pmu),
		T6_MODREGS(sf),
		T6_MODREGS(pl),
		T6_MODREGS(le),
		T6_MODREGS(ncsi),
		T6_MODREGS(mac),
		{ "hma", t6_hma_t6_regs }
	};

	return dump_regs_table(regs, t6_mod,
			ARRAY_SIZE(t6_mod),
			"sge, pci, dbg, mc0, ma, edc0, edc1, cim, "\
			"tp, ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "\
			"i2c, mi, uart, pmu, sf, pl, le, ncsi, "\
			"mac, hma", cudbg_poutbuf);
}
#undef T6_MODREGS

#define T5_MODREGS(name) { #name, t5_##name##_regs }

static int
dump_regs_t5(const u32 *regs, struct cudbg_buffer *cudbg_poutbuf)
{
	static struct mod_regs t5_mod[] = {
		T5_MODREGS(sge),
		{ "pci", t5_pcie_regs },
		T5_MODREGS(dbg),
		{ "mc0", t5_mc_0_regs },
		{ "mc1", t5_mc_1_regs },
		T5_MODREGS(ma),
		{ "edc0", t5_edc_t50_regs },
		{ "edc1", t5_edc_t51_regs },
		T5_MODREGS(cim),
		T5_MODREGS(tp),
		{ "ulprx", t5_ulp_rx_regs },
		{ "ulptx", t5_ulp_tx_regs },
		{ "pmrx", t5_pm_rx_regs },
		{ "pmtx", t5_pm_tx_regs },
		T5_MODREGS(mps),
		{ "cplsw", t5_cpl_switch_regs },
		T5_MODREGS(smb),
		{ "i2c", t5_i2cm_regs },
		T5_MODREGS(mi),
		T5_MODREGS(uart),
		T5_MODREGS(pmu),
		T5_MODREGS(sf),
		T5_MODREGS(pl),
		T5_MODREGS(le),
		T5_MODREGS(ncsi),
		T5_MODREGS(mac),
		{ "hma", t5_hma_t5_regs }
	};

	return dump_regs_table(regs, t5_mod,
			ARRAY_SIZE(t5_mod),
			"sge, pci, dbg, mc0, mc1, ma, edc0, edc1, cim, "\
			"tp, ulprx, ulptx, pmrx, pmtx, mps, cplsw, smb, "\
			"i2c, mi, uart, pmu, sf, pl, le, ncsi, "\
			"mac, hma", cudbg_poutbuf);
}
#undef T5_MODREGS

int
view_reg_dump(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;
	u32 *regs;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	regs = (u32 *) ((unsigned int *)dc_buff.data);
	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		rc =  dump_regs_t5((u32 *)regs, cudbg_poutbuf);
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		rc = dump_regs_t6((u32 *)regs, cudbg_poutbuf);
	return rc;
}

static int
t6_view_wtp(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	    struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct wtp_data *wtp = NULL;
	int rc = 0;
	int i = 0;
	/****Rx****/
	u32 pcie_core_dmaw_sop = 0;
	u32 sge_pcie_sop = 0;
	u32 csw_sge_sop = 0;
	u32 tp_csw_sop = 0;
	u32 tpcside_csw_sop = 0;
	u32 ulprx_tpcside_sop = 0;
	u32 pmrx_ulprx_sop = 0;
	u32 mps_tpeside_sop = 0;
	u32 mps_tp_sop = 0;
	u32 xgm_mps_sop = 0;
	u32 rx_xgm_xgm_sop = 0;
	u32 wire_xgm_sop = 0;
	u32 rx_wire_macok_sop = 0;

	u32 pcie_core_dmaw_eop = 0;
	u32 sge_pcie_eop = 0;
	u32 csw_sge_eop = 0;
	u32 tp_csw_eop = 0;
	u32 tpcside_csw_eop = 0;
	u32 ulprx_tpcside_eop = 0;
	u32 pmrx_ulprx_eop = 0;
	u32 mps_tpeside_eop = 0;
	u32 mps_tp_eop = 0;
	u32 xgm_mps_eop = 0;
	u32 rx_xgm_xgm_eop = 0;
	u32 wire_xgm_eop = 0;
	u32 rx_wire_macok_eop = 0;

	/****Tx****/
	u32 core_pcie_dma_rsp_sop = 0;
	u32 pcie_sge_dma_rsp_sop = 0;
	u32 sge_debug_index6_sop = 0;
	u32 sge_utx_sop = 0;
	u32 utx_tp_sop = 0;
	u32 sge_work_req_sop = 0;
	u32 utx_tpcside_sop = 0;
	u32 tpcside_rxarb_sop = 0;
	u32 tpeside_mps_sop = 0;
	u32 tp_mps_sop = 0;
	u32 mps_xgm_sop = 0;
	u32 tx_xgm_xgm_sop = 0;
	u32 xgm_wire_sop = 0;
	u32 tx_macok_wire_sop = 0;

	u32 core_pcie_dma_rsp_eop = 0;
	u32 pcie_sge_dma_rsp_eop = 0;
	u32 sge_debug_index6_eop = 0;
	u32 sge_utx_eop = 0;
	u32 utx_tp_eop = 0;
	u32 utx_tpcside_eop = 0;
	u32 tpcside_rxarb_eop = 0;
	u32 tpeside_mps_eop = 0;
	u32 tp_mps_eop = 0;
	u32 mps_xgm_eop = 0;
	u32 tx_xgm_xgm_eop = 0;
	u32 xgm_wire_eop = 0;
	u32 tx_macok_wire_eop = 0;

	u32 pcie_core_cmd_req_sop = 0;
	u32 sge_pcie_cmd_req_sop = 0;
	u32 core_pcie_cmd_rsp_sop = 0;
	u32 pcie_sge_cmd_rsp_sop = 0;
	u32 sge_cim_sop = 0;
	u32 pcie_core_dma_req_sop = 0;
	u32 sge_pcie_dma_req_sop = 0;
	u32 utx_sge_dma_req_sop = 0;

	u32 sge_pcie_cmd_req_eop = 0;
	u32 pcie_core_cmd_req_eop = 0;
	u32 core_pcie_cmd_rsp_eop = 0;
	u32 pcie_sge_cmd_rsp_eop = 0;
	u32 sge_cim_eop = 0;
	u32 pcie_core_dma_req_eop = 0;
	u32 sge_pcie_dma_req_eop = 0;
	u32 utx_sge_dma_req_eop = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	wtp = (struct wtp_data *) dc_buff.data;
	/*Add up the sop/eop of all channels.*/
	for (i = 0; i < 8; i++) {
		if (i < 2) {
			/*Rx Path*/
			csw_sge_sop           +=
				(wtp->sge_debug_data_high_indx1.sop[i]);
			tp_csw_sop            +=
				(wtp->sge_debug_data_high_indx9.sop[i]);

			csw_sge_eop           += (wtp->csw_sge.eop[i]);
			tp_csw_eop            += (wtp->tp_csw.eop[i]);
			rx_wire_macok_sop     +=
				wtp->mac_porrx_etherstatspkts.sop[i];
			rx_wire_macok_eop     +=
				wtp->mac_porrx_etherstatspkts.eop[i];

			/*Tx Path*/
			sge_pcie_cmd_req_sop  += wtp->sge_pcie_cmd_req.sop[i];
			pcie_sge_cmd_rsp_sop  += wtp->pcie_sge_cmd_rsp.sop[i];
			sge_cim_sop           += wtp->sge_cim.sop[i];
			tpcside_csw_sop       += (wtp->utx_tpcside_tx.sop[i]);
			sge_work_req_sop      += wtp->sge_work_req_pkt.sop[i];
			tx_macok_wire_sop     +=
				wtp->mac_portx_etherstatspkts.sop[i];
			tx_macok_wire_eop     +=
				wtp->mac_portx_etherstatspkts.eop[i];

			sge_pcie_cmd_req_eop  += wtp->sge_pcie_cmd_req.eop[i];
			pcie_sge_cmd_rsp_eop  += wtp->pcie_sge_cmd_rsp.eop[i];
			sge_cim_eop           += wtp->sge_cim.eop[i];

		}

		if (i < 3) {
			pcie_core_cmd_req_sop += wtp->pcie_cmd_stat2.sop[i];
			core_pcie_cmd_rsp_sop += wtp->pcie_cmd_stat3.sop[i];

			core_pcie_cmd_rsp_eop += wtp->pcie_cmd_stat3.eop[i];
			pcie_core_cmd_req_eop += wtp->pcie_cmd_stat2.eop[i];
		}

		if (i < 4) {
			/*Rx Path*/
			pcie_core_dmaw_sop    +=
				(wtp->pcie_dma1_stat2.sop[i]);
			sge_pcie_sop          +=
				(wtp->sge_debug_data_high_indx7.sop[i]);
			ulprx_tpcside_sop     += (wtp->ulprx_tpcside.sop[i]);
			pmrx_ulprx_sop        += (wtp->pmrx_ulprx.sop[i]);
			mps_tpeside_sop       +=
				(wtp->tp_dbg_eside_pktx.sop[i]);
			rx_xgm_xgm_sop        +=
				(wtp->mac_porrx_pkt_count.sop[i]);
			wire_xgm_sop          +=
				(wtp->mac_porrx_aframestra_ok.sop[i]);

			pcie_core_dmaw_eop    +=
				(wtp->pcie_dma1_stat2.eop[i]);
			sge_pcie_eop          += (wtp->sge_pcie.eop[i]);
			tpcside_csw_eop       += (wtp->tpcside_csw.eop[i]);
			ulprx_tpcside_eop     += (wtp->ulprx_tpcside.eop[i]);
			pmrx_ulprx_eop        += (wtp->pmrx_ulprx.eop[i]);
			mps_tpeside_eop       += (wtp->mps_tpeside.eop[i]);
			rx_xgm_xgm_eop        +=
				(wtp->mac_porrx_pkt_count.eop[i]);
			wire_xgm_eop          +=
				(wtp->mac_porrx_aframestra_ok.eop[i]);

			/*special case type 3:*/
			mps_tp_sop            += (wtp->mps_tp.sop[i]);
			mps_tp_eop            += (wtp->mps_tp.eop[i]);

			/*Tx Path*/
			core_pcie_dma_rsp_sop +=
				wtp->pcie_t5_dma_stat3.sop[i];
			pcie_sge_dma_rsp_sop  += wtp->pcie_sge_dma_rsp.sop[i];
			sge_debug_index6_sop  +=
				wtp->sge_debug_data_high_index_6.sop[i];
			sge_utx_sop           += wtp->ulp_se_cnt_chx.sop[i];
			utx_tp_sop            += wtp->utx_tp.sop[i];
			utx_tpcside_sop       += wtp->utx_tpcside.sop[i];
			tpcside_rxarb_sop     += wtp->tpcside_rxarb.sop[i];
			tpeside_mps_sop       += wtp->tpeside_mps.sop[i];
			tx_xgm_xgm_sop        +=
				wtp->mac_portx_pkt_count.sop[i];
			xgm_wire_sop          +=
				wtp->mac_portx_aframestra_ok.sop[i];

			core_pcie_dma_rsp_eop +=
				wtp->pcie_t5_dma_stat3.eop[i];
			pcie_sge_dma_rsp_eop  += wtp->pcie_sge_dma_rsp.eop[i];
			sge_debug_index6_eop  +=
				wtp->sge_debug_data_high_index_6.eop[i];
			sge_utx_eop           += wtp->sge_utx.eop[i];
			utx_tp_eop            += wtp->utx_tp.eop[i];
			utx_tpcside_eop       += wtp->utx_tpcside.eop[i];
			tpcside_rxarb_eop     += wtp->tpcside_rxarb.eop[i];
			tpeside_mps_eop       += wtp->tpeside_mps.eop[i];
			tx_xgm_xgm_eop        +=
				wtp->mac_portx_pkt_count.eop[i];
			xgm_wire_eop          +=
				wtp->mac_portx_aframestra_ok.eop[i];

			/*special case type 3:*/
			tp_mps_sop            += wtp->tp_mps.sop[i];
			mps_xgm_sop           += wtp->mps_xgm.sop[i];

			tp_mps_eop            += wtp->tp_mps.eop[i];
			mps_xgm_eop           += wtp->mps_xgm.eop[i];

			pcie_core_dma_req_sop +=
				wtp->pcie_dma1_stat2_core.sop[i];
			sge_pcie_dma_req_sop  +=
				wtp->sge_debug_data_high_indx5.sop[i];
			utx_sge_dma_req_sop   += wtp->utx_sge_dma_req.sop[i];

			pcie_core_dma_req_eop +=
				wtp->pcie_dma1_stat2_core.eop[i];
			sge_pcie_dma_req_eop  +=
				wtp->sge_debug_data_high_indx5.eop[i];
			utx_sge_dma_req_eop   += wtp->utx_sge_dma_req.eop[i];
		}

		if (i < 5) {
			xgm_mps_sop               += (wtp->xgm_mps.sop[i]);
			xgm_mps_eop               += (wtp->xgm_mps.eop[i]);
		}
	}
	printf("ifaces = nic0 nic1\n");
	printf("*************************EGGRESS (TX) PATH **********************************\n");
	printf("MOD :  core---->PCIE---->SGE<-|    #Ring Doorbell\n");
	printf("SOP        ?      ???         |\n");
	printf("EOP        ?      ???         |\n");
	printf("MOD |<-core<----PCIE<----SGE<-|    #Request Work Request\n");
	printf("SOP_CH0  %02X       %02x\n",
		     wtp->pcie_cmd_stat2.sop[0], wtp->sge_pcie_cmd_req.sop[0]);
	printf("SOP |    %02X       %02X\n",
		     pcie_core_cmd_req_sop, sge_pcie_cmd_req_sop);
	printf("EOP |    %2X       %2X\n",
		     pcie_core_cmd_req_eop, sge_pcie_cmd_req_eop);
	printf("MOD |->core---->PCIE---->SGE------>CIM/uP->| uP<-CIM<-CSW #->Work req. <-Pkts\n");
	printf("SOP_CH0  %02X       %02X      %02X"\
		     "               |      %2X\n",
		     wtp->pcie_cmd_stat3.sop[0], wtp->pcie_sge_cmd_rsp.sop[1],
		     wtp->sge_cim.sop[0], wtp->sge_work_req_pkt.sop[0]);

	printf("SOP_CH1                   %02X"\
		     "               |\n", wtp->pcie_sge_cmd_rsp.sop[1]);
	printf("SOP      %02X       %02X      %2X"\
		     "               |      %2X\n", core_pcie_cmd_rsp_sop,
		     pcie_sge_cmd_rsp_sop, sge_cim_sop, sge_work_req_sop);
	printf("EOP      %2X       %2X      %2X"\
		     "               |\n", core_pcie_cmd_rsp_eop,
		     pcie_sge_cmd_rsp_eop, sge_cim_eop);
	printf("MOD |<-core<----PCIE<----SGE<------UTX<--------|#data dma requests\n");
	printf("SOP_CH0  %02X\n",
		     wtp->pcie_dma1_stat2_core.sop[0]);
	printf("SOP_CH1  %02X\n",
		     wtp->pcie_dma1_stat2_core.sop[1]);
	printf("SOP |    %2X\n",
		     pcie_core_dma_req_sop);
	printf("EOP |    %2X\n",
		     pcie_core_dma_req_eop);

	printf("MOD |->core-->PCIE-->SGE-->UTX---->TPC------->TPE---->MPS--->MAC--->MACOK->wire\n");
	printf("SOP_CH0        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X  %02X      %02X   "\
		     " %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[0], wtp->ulp_se_cnt_chx.sop[0],
		     wtp->utx_tpcside.sop[0], wtp->tpcside_rxarb.sop[0],
		     wtp->tpeside_mps.sop[0], wtp->tp_mps.sop[0],
		     wtp->mps_xgm.sop[0], wtp->mac_portx_pkt_count.sop[0],
		     wtp->mac_portx_aframestra_ok.sop[0],
		     wtp->mac_portx_etherstatspkts.sop[0]);

	printf("EOP_CH0        %02X         %2X  "\
		     "    %2X       %2X    %2X   %02X  %02X  %02X      %02X"\
		     "    %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[0], wtp->ulp_se_cnt_chx.eop[0],
		     wtp->utx_tpcside.eop[0], wtp->tpcside_rxarb.eop[0],
		     wtp->tpeside_mps.eop[0], wtp->tp_mps.eop[0],
		     wtp->mps_xgm.eop[0], wtp->mac_portx_pkt_count.eop[0],
		     wtp->mac_portx_aframestra_ok.eop[0],
		     wtp->mac_portx_etherstatspkts.eop[0]);
	printf("SOP_CH1        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X  %02X      %02X  "\
		     "%02X\n",
		     wtp->pcie_t5_dma_stat3.sop[1], wtp->ulp_se_cnt_chx.sop[1],
		     wtp->utx_tpcside.sop[1], wtp->tpcside_rxarb.sop[1],
		     wtp->tpeside_mps.sop[1], wtp->tp_mps.sop[1],
		     wtp->mps_xgm.sop[1], wtp->mac_portx_pkt_count.sop[1],
		     wtp->mac_portx_aframestra_ok.sop[1],
		     wtp->mac_portx_etherstatspkts.sop[1]);

	printf("EOP_CH1        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X  %02X      %02X"\
		     "    %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[1], wtp->ulp_se_cnt_chx.eop[1],
		     wtp->utx_tpcside.eop[1], wtp->tpcside_rxarb.eop[1],
		     wtp->tpeside_mps.eop[1], wtp->tp_mps.eop[1],
		     wtp->mps_xgm.eop[1], wtp->mac_portx_pkt_count.eop[1],
		     wtp->mac_portx_aframestra_ok.eop[1],
		     wtp->mac_portx_etherstatspkts.eop[1]);
	printf("SOP_CH2        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[2], wtp->ulp_se_cnt_chx.sop[2],
		     wtp->utx_tpcside.sop[2], wtp->tpcside_rxarb.sop[2],
		     wtp->tpeside_mps.sop[2], wtp->tp_mps.sop[2],
		     wtp->mps_xgm.sop[2]);

	printf("EOP_CH2        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[2], wtp->ulp_se_cnt_chx.eop[2],
		     wtp->utx_tpcside.eop[2], wtp->tpcside_rxarb.eop[2],
		     wtp->tpeside_mps.eop[2], wtp->tp_mps.eop[2],
		     wtp->mps_xgm.eop[2]);
	printf("SOP_CH3        %02X         %2X  "\
		     "    %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[3], wtp->ulp_se_cnt_chx.sop[3],
		     wtp->utx_tpcside.sop[3], wtp->tpcside_rxarb.sop[3],
		     wtp->tpeside_mps.sop[3], wtp->tp_mps.sop[3],
		     wtp->mps_xgm.sop[3]);

	printf("EOP_CH3        %02X         %2X   "\
		     "   %2X       %2X    %2X   %02X  %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[3], wtp->ulp_se_cnt_chx.eop[3],
		     wtp->utx_tpcside.eop[3], wtp->tpcside_rxarb.eop[3],
		     wtp->tpeside_mps.eop[3], wtp->tp_mps.eop[3],
		     wtp->mps_xgm.eop[3]);
	printf("SOP            %2X         %2X    "\
		     "  %2X       %2X    %2X   %2X  %2X  %2X      %2X    %2X\n",
		     core_pcie_dma_rsp_sop, sge_utx_sop, utx_tp_sop,
		     tpcside_rxarb_sop, tpeside_mps_sop, tp_mps_sop,
		     mps_xgm_sop, tx_xgm_xgm_sop, xgm_wire_sop,
		     tx_macok_wire_sop);
	printf("EOP            %2X         %2X   "\
			"   %2X       %2X    %2X   %2X  %2X  %2X      %2X  "\
			"  %2X\n",
			core_pcie_dma_rsp_eop, sge_utx_eop, utx_tp_eop,
			tpcside_rxarb_eop, tpeside_mps_eop, tp_mps_eop,
			mps_xgm_eop, tx_xgm_xgm_eop, xgm_wire_eop,
			tx_macok_wire_eop);
	printf("*************************INGRESS (RX) PATH **********************************\n");

	printf("MOD   core<-PCIE<---SGE<--CSW<-----TPC<-URX<-LE-TPE<-----MPS<--MAC<-MACOK<--wire\n");

	printf("SOP_CH0      %2X  %2X    %2X    %2X"\
		     "   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X     "\
		     " %02X    %02X\n",
		     wtp->pcie_dma1_stat2.sop[0],
		     wtp->sge_debug_data_high_indx7.sop[0],
		     wtp->sge_debug_data_high_indx1.sop[0],
		     wtp->sge_debug_data_high_indx9.sop[0],
		     wtp->utx_tpcside_tx.sop[0], wtp->ulprx_tpcside.sop[0],
		     wtp->pmrx_ulprx.sop[0], wtp->le_db_rsp_cnt.sop,
		     wtp->tp_dbg_eside_pktx.sop[0], wtp->mps_tp.sop[0],
		     wtp->xgm_mps.sop[0], wtp->mac_porrx_pkt_count.sop[0],
		     wtp->mac_porrx_aframestra_ok.sop[0],
		     wtp->mac_porrx_etherstatspkts.sop[0]);

	printf("EOP_CH0      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X   "\
		     "   %02X    %02X\n",
		     wtp->pcie_dma1_stat2.eop[0],
		     wtp->sge_debug_data_high_indx7.eop[0],
		     wtp->sge_debug_data_high_indx1.eop[0],
		     wtp->sge_debug_data_high_indx9.eop[0],
		     wtp->utx_tpcside_tx.eop[0], wtp->ulprx_tpcside.eop[0],
		     wtp->pmrx_ulprx.eop[0], wtp->le_db_rsp_cnt.eop,
		     wtp->tp_dbg_eside_pktx.eop[0], wtp->mps_tp.eop[0],
		     wtp->xgm_mps.eop[0], wtp->mac_porrx_pkt_count.eop[0],
		     wtp->mac_porrx_aframestra_ok.eop[0],
		     wtp->mac_porrx_etherstatspkts.eop[0]);
	printf("SOP_CH1      %2X  %2X    %2X   "\
		     " %2X   %2X  %2X  %2X     %2X    %2X   %02X  %02X  "\
		     "    %02X    %02X\n",
		     wtp->pcie_dma1_stat2.sop[1],
		     wtp->sge_debug_data_high_indx7.sop[1],
		     wtp->sge_debug_data_high_indx1.sop[1],
		     wtp->sge_debug_data_high_indx9.sop[1],
		     wtp->utx_tpcside_tx.sop[1], wtp->ulprx_tpcside.sop[1],
		     wtp->pmrx_ulprx.sop[1], wtp->tp_dbg_eside_pktx.sop[1],
		     wtp->mps_tp.sop[1], wtp->xgm_mps.sop[1],
		     wtp->mac_porrx_pkt_count.sop[1],
		     wtp->mac_porrx_aframestra_ok.sop[1],
		     wtp->mac_porrx_etherstatspkts.sop[1]);

	printf("EOP_CH1      %2X  %2X    %2X    %2X"\
		     "   %2X  %2X  %2X     %2X    %2X   %02X  %02X      "\
		     "%02X    %02X\n",
		     wtp->pcie_dma1_stat2.eop[1],
		     wtp->sge_debug_data_high_indx7.eop[1],
		     wtp->sge_debug_data_high_indx1.eop[1],
		     wtp->sge_debug_data_high_indx9.eop[1],
		     wtp->utx_tpcside_tx.eop[1], wtp->ulprx_tpcside.eop[1],
		     wtp->pmrx_ulprx.eop[1], wtp->tp_dbg_eside_pktx.eop[1],
		     wtp->mps_tp.eop[1], wtp->xgm_mps.eop[1],
		     wtp->mac_porrx_pkt_count.eop[1],
		     wtp->mac_porrx_aframestra_ok.eop[1],
		     wtp->mac_porrx_etherstatspkts.eop[1]);
	printf("SOP_CH2                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.sop[2], wtp->xgm_mps.sop[2]);

	printf("EOP_CH2                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.eop[2], wtp->xgm_mps.eop[2]);
	printf("SOP_CH3                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.sop[3],
		     wtp->xgm_mps.sop[3]);

	printf("EOP_CH3                           "\
		     "               %2X         %02X\n",
		     wtp->tp_dbg_eside_pktx.eop[3], wtp->xgm_mps.eop[3]);
	printf("SOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[4]);
	printf("EOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[4]);
	printf("SOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[5]);
	printf("EOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[5]);
	printf("SOP_CH6\n");
	printf("EOP_CH6\n");
	printf("SOP_CH7\n");
	printf("EOP_CH7\n");

	printf("SOP          %2X  %2X    %2X    %2X"\
		     "   %2X  %2X   %2X    %2X    %2X   %2X  %2X      %2X "\
		     "  %2X\n",
		     pcie_core_dmaw_sop, sge_pcie_sop, csw_sge_sop,
		     tp_csw_sop, tpcside_csw_sop, ulprx_tpcside_sop,
		     pmrx_ulprx_sop, mps_tpeside_sop,
		     mps_tp_sop, xgm_mps_sop, rx_xgm_xgm_sop,
		     wire_xgm_sop, rx_wire_macok_sop);
	printf("EOP          %2X  %2X    %2X    "\
		     "%2X   %2X  %2X   %2X    %2X    %2X   %2X  %2X     "\
		     " %2X   %2X\n",
		     pcie_core_dmaw_eop, sge_pcie_eop, csw_sge_eop,
		     tp_csw_eop, tpcside_csw_eop, ulprx_tpcside_eop,
		     pmrx_ulprx_eop, mps_tpeside_eop, mps_tp_eop,
		     xgm_mps_eop, rx_xgm_xgm_eop, wire_xgm_eop,
		     rx_wire_macok_eop);
	printf("DROP: ???      ???      ???       "\
		     "%2X(mib)  %2X(err) %2X(oflow) %X(cls)\n",
		     (wtp->mps_tp.drops & 0xFF), (wtp->xgm_mps.err & 0xFF),
		     (wtp->xgm_mps.drop & 0xFF),
		     (wtp->xgm_mps.cls_drop & 0xFF));
	printf("INTS:  ");
	for (i = 0; i < 2; i++) {
		printf("%2X<- %2X    ",
			     (wtp->pcie_core_dmai.sop[i] & 0xF),
			     (wtp->sge_pcie_ints.sop[i] & 0xF));
	}
	printf("(PCIE<-SGE, channels 0 to 1)\n");

	return rc;
}

static int
t5_view_wtp(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	    struct cudbg_buffer *cudbg_poutbuf)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct wtp_data *wtp = NULL;
	int rc = 0;
	int i = 0;
	/****Rx****/
	u32 pcie_core_dmaw_sop = 0;
	u32 sge_pcie_sop = 0;
	u32 csw_sge_sop = 0;
	u32 tp_csw_sop = 0;
	u32 tpcside_csw_sop = 0;
	u32 ulprx_tpcside_sop = 0;
	u32 pmrx_ulprx_sop = 0;
	u32 mps_tpeside_sop = 0;
	u32 mps_tp_sop = 0;
	u32 xgm_mps_sop = 0;
	u32 rx_xgm_xgm_sop = 0;
	u32 wire_xgm_sop = 0;

	u32 pcie_core_dmaw_eop = 0;
	u32 sge_pcie_eop = 0;
	u32 csw_sge_eop = 0;
	u32 tp_csw_eop = 0;
	u32 tpcside_csw_eop = 0;
	u32 ulprx_tpcside_eop = 0;
	u32 pmrx_ulprx_eop = 0;
	u32 mps_tpeside_eop = 0;
	u32 mps_tp_eop = 0;
	u32 xgm_mps_eop = 0;
	u32 rx_xgm_xgm_eop = 0;
	u32 wire_xgm_eop = 0;

	/****Tx****/
	u32 core_pcie_dma_rsp_sop = 0;
	u32 pcie_sge_dma_rsp_sop = 0;
	u32 sge_debug_index6_sop = 0;
	u32 sge_utx_sop = 0;
	u32 utx_tp_sop = 0;
	u32 sge_work_req_sop = 0;
	u32 utx_tpcside_sop = 0;
	u32 tpcside_rxarb_sop = 0;
	u32 tpeside_mps_sop = 0;
	u32 tp_mps_sop = 0;
	u32 mps_xgm_sop = 0;
	u32 tx_xgm_xgm_sop = 0;
	u32 xgm_wire_sop = 0;

	u32 core_pcie_dma_rsp_eop = 0;
	u32 pcie_sge_dma_rsp_eop = 0;
	u32 sge_debug_index6_eop = 0;
	u32 sge_utx_eop = 0;
	u32 utx_tp_eop = 0;
	u32 utx_tpcside_eop = 0;
	u32 tpcside_rxarb_eop = 0;
	u32 tpeside_mps_eop = 0;
	u32 tp_mps_eop = 0;
	u32 mps_xgm_eop = 0;
	u32 tx_xgm_xgm_eop = 0;
	u32 xgm_wire_eop = 0;

	u32 pcie_core_cmd_req_sop = 0;
	u32 sge_pcie_cmd_req_sop = 0;
	u32 core_pcie_cmd_rsp_sop = 0;
	u32 pcie_sge_cmd_rsp_sop = 0;
	u32 sge_cim_sop = 0;
	u32 pcie_core_dma_req_sop = 0;
	u32 sge_pcie_dma_req_sop = 0;
	u32 utx_sge_dma_req_sop = 0;

	u32 sge_pcie_cmd_req_eop = 0;
	u32 pcie_core_cmd_req_eop = 0;
	u32 core_pcie_cmd_rsp_eop = 0;
	u32 pcie_sge_cmd_rsp_eop = 0;
	u32 sge_cim_eop = 0;
	u32 pcie_core_dma_req_eop = 0;
	u32 sge_pcie_dma_req_eop = 0;
	u32 utx_sge_dma_req_eop = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	wtp = (struct wtp_data *) dc_buff.data;
	/*Add up the sop/eop of all channels.*/
	for (i = 0; i < 8; i++) {
		if (i < 2) {
			/*Rx Path*/
			csw_sge_sop           +=
				(wtp->sge_debug_data_high_indx1.sop[i]);
			tp_csw_sop            +=
				(wtp->sge_debug_data_high_indx9.sop[i]);

			csw_sge_eop           += (wtp->csw_sge.eop[i]);
			tp_csw_eop            += (wtp->tp_csw.eop[i]);

			/*Tx Path*/
			sge_pcie_cmd_req_sop  += wtp->sge_pcie_cmd_req.sop[i];
			pcie_sge_cmd_rsp_sop  += wtp->pcie_sge_cmd_rsp.sop[i];
			sge_cim_sop           += wtp->sge_cim.sop[i];
			tpcside_csw_sop       += (wtp->utx_tpcside_tx.sop[i]);
			sge_work_req_sop      += wtp->sge_work_req_pkt.sop[i];

			sge_pcie_cmd_req_eop  += wtp->sge_pcie_cmd_req.eop[i];
			pcie_sge_cmd_rsp_eop  += wtp->pcie_sge_cmd_rsp.eop[i];
			sge_cim_eop           += wtp->sge_cim.eop[i];

		}

		if (i < 3) {
			pcie_core_cmd_req_sop += wtp->pcie_cmd_stat2.sop[i];
			core_pcie_cmd_rsp_sop += wtp->pcie_cmd_stat3.sop[i];

			core_pcie_cmd_rsp_eop += wtp->pcie_cmd_stat3.eop[i];
			pcie_core_cmd_req_eop += wtp->pcie_cmd_stat2.eop[i];
		}

		if (i < 4) {
			/*Rx Path*/
			pcie_core_dmaw_sop    +=
				(wtp->pcie_dma1_stat2.sop[i]);
			sge_pcie_sop          +=
				(wtp->sge_debug_data_high_indx7.sop[i]);
			ulprx_tpcside_sop     += (wtp->ulprx_tpcside.sop[i]);
			pmrx_ulprx_sop        += (wtp->pmrx_ulprx.sop[i]);
			mps_tpeside_sop       +=
				(wtp->tp_dbg_eside_pktx.sop[i]);
			rx_xgm_xgm_sop        +=
				(wtp->mac_porrx_pkt_count.sop[i]);
			wire_xgm_sop          +=
				(wtp->mac_porrx_aframestra_ok.sop[i]);

			pcie_core_dmaw_eop    +=
				(wtp->pcie_dma1_stat2.eop[i]);
			sge_pcie_eop          += (wtp->sge_pcie.eop[i]);
			tpcside_csw_eop       += (wtp->tpcside_csw.eop[i]);
			ulprx_tpcside_eop     += (wtp->ulprx_tpcside.eop[i]);
			pmrx_ulprx_eop        += (wtp->pmrx_ulprx.eop[i]);
			mps_tpeside_eop       += (wtp->mps_tpeside.eop[i]);
			rx_xgm_xgm_eop        +=
				(wtp->mac_porrx_pkt_count.eop[i]);
			wire_xgm_eop          += (wtp->xgm_mps.eop[i]);

			/*special case type 3:*/
			mps_tp_sop            += (wtp->mps_tp.sop[i]);
			mps_tp_eop            += (wtp->mps_tp.eop[i]);

			/*Tx Path*/
			core_pcie_dma_rsp_sop +=
				wtp->pcie_t5_dma_stat3.sop[i];
			pcie_sge_dma_rsp_sop  += wtp->pcie_sge_dma_rsp.sop[i];
			sge_debug_index6_sop  +=
				wtp->sge_debug_data_high_index_6.sop[i];
			sge_utx_sop           += wtp->ulp_se_cnt_chx.sop[i];
			utx_tp_sop            += wtp->utx_tp.sop[i];
			utx_tpcside_sop       += wtp->utx_tpcside.sop[i];
			tpcside_rxarb_sop     += wtp->tpcside_rxarb.sop[i];
			tpeside_mps_sop       += wtp->tpeside_mps.sop[i];
			tx_xgm_xgm_sop        +=
				wtp->mac_portx_pkt_count.sop[i];
			xgm_wire_sop          +=
				wtp->mac_portx_aframestra_ok.sop[i];

			core_pcie_dma_rsp_eop +=
				wtp->pcie_t5_dma_stat3.eop[i];
			pcie_sge_dma_rsp_eop  += wtp->pcie_sge_dma_rsp.eop[i];
			sge_debug_index6_eop  +=
				wtp->sge_debug_data_high_index_6.eop[i];
			sge_utx_eop           += wtp->sge_utx.eop[i];
			utx_tp_eop            += wtp->utx_tp.eop[i];
			utx_tpcside_eop       += wtp->utx_tpcside.eop[i];
			tpcside_rxarb_eop     += wtp->tpcside_rxarb.eop[i];
			tpeside_mps_eop       += wtp->tpeside_mps.eop[i];
			tx_xgm_xgm_eop        +=
				wtp->mac_portx_pkt_count.eop[i];
			xgm_wire_eop          +=
				wtp->mac_portx_aframestra_ok.eop[i];

			/*special case type 3:*/
			tp_mps_sop            += wtp->tp_mps.sop[i];
			mps_xgm_sop           += wtp->mps_xgm.sop[i];

			tp_mps_eop            += wtp->tp_mps.eop[i];
			mps_xgm_eop           += wtp->mps_xgm.eop[i];

			pcie_core_dma_req_sop +=
				wtp->pcie_dma1_stat2_core.sop[i];
			sge_pcie_dma_req_sop  +=
				wtp->sge_debug_data_high_indx5.sop[i];
			utx_sge_dma_req_sop   += wtp->utx_sge_dma_req.sop[i];

			pcie_core_dma_req_eop +=
				wtp->pcie_dma1_stat2_core.eop[i];
			sge_pcie_dma_req_eop  +=
				wtp->sge_debug_data_high_indx5.eop[i];
			utx_sge_dma_req_eop   += wtp->utx_sge_dma_req.eop[i];
		}

		xgm_mps_sop               += (wtp->xgm_mps.sop[i]);
		xgm_mps_eop               += (wtp->xgm_mps.eop[i]);
	}
	printf("ifaces = nic0 nic1\n");
	printf("*************************EGGRESS (TX) PATH **********************************\n");
	printf("MOD :  core---->PCIE---->SGE<-|    #Ring Doorbell\n");
	printf("SOP        ?      ???         |\n");
	printf("EOP        ?      ???         |\n");
	printf("MOD |<-core<----PCIE<----SGE<-|    #Request Work Request\n");
	printf("SOP_CH0  %02X       %02x\n",
			     wtp->pcie_cmd_stat2.sop[0],
			     wtp->sge_pcie_cmd_req.sop[0]);
	printf("SOP_CH1  %02X       %02X\n",
		     wtp->pcie_cmd_stat2.sop[1], wtp->sge_pcie_cmd_req.sop[1]);
	printf("SOP_CH2  %02X\n",
		     wtp->pcie_cmd_stat2.sop[2]);
	printf("SOP |    %02X       %02X\n",
		     pcie_core_cmd_req_sop, sge_pcie_cmd_req_sop);
	printf("EOP |   %2X       %2X\n",
		     pcie_core_cmd_req_eop, sge_pcie_cmd_req_eop);
	printf("MOD |->core---->PCIE---->SGE------>CIM/uP->| uP<-CIM<-CSW #->Work req. <-Pkts\n");
	printf("SOP_CH0  %02X       %02X      %02X"\
		     "               |      %2X\n",
		     wtp->pcie_cmd_stat3.sop[0], wtp->pcie_sge_cmd_rsp.sop[0],
		     wtp->sge_cim.sop[0], wtp->sge_work_req_pkt.sop[0]);
	printf("SOP_CH1  %02X       %02X      %02X"\
		     "               |      %2X\n",
		     wtp->pcie_cmd_stat3.sop[1], wtp->pcie_sge_cmd_rsp.sop[1],
		     wtp->sge_cim.sop[1], wtp->sge_work_req_pkt.sop[1]);
	printf("SOP_CH2  %02X                     "\
		     "           |\n", wtp->pcie_cmd_stat3.sop[2]);
	printf("SOP      %02X       %02X      %2X "\
		     "              |      %2X\n",
		     core_pcie_cmd_rsp_sop, pcie_sge_cmd_rsp_sop,
		     sge_cim_sop, sge_work_req_sop);
	printf("EOP      %2X       %2X      %2X   "\
		     "            |\n",
		     core_pcie_cmd_rsp_eop,
		     pcie_sge_cmd_rsp_eop, sge_cim_eop);
	printf("MOD |<-core<----PCIE<----SGE<------UTX<--------|#data dma requests\n");
	printf("SOP_CH0  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[0],
		     wtp->sge_debug_data_high_indx5.sop[0],
		     wtp->utx_sge_dma_req.sop[0]);
	printf("SOP_CH1  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[1],
		     wtp->sge_debug_data_high_indx5.sop[1],
		     wtp->utx_sge_dma_req.sop[1]);
	printf("SOP_CH2  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[2],
		     wtp->sge_debug_data_high_indx5.sop[2],
		     wtp->utx_sge_dma_req.sop[2]);
	printf("SOP_CH3  %02X       %02X      "\
		     "%02X\n", wtp->pcie_dma1_stat2_core.sop[3],
		     wtp->sge_debug_data_high_indx5.sop[3],
		     wtp->utx_sge_dma_req.sop[3]);
	printf("SOP |    %2X       %2X      %2X\n",
		     pcie_core_dma_req_sop/*eop in perl??*/,
		     sge_pcie_dma_req_sop, utx_sge_dma_req_sop);
	printf("EOP |    %2X       %2X      %2X\n",
		     pcie_core_dma_req_eop,
		     sge_pcie_dma_req_eop, utx_sge_dma_req_eop);
	printf("MOD |->core-->PCIE-->SGE-->UTX---->TPC------->TPE---->MPS--->MAC--->wire\n");
	printf("SOP_CH0        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[0],
		     wtp->sge_debug_data_high_index_6.sop[0],
		     wtp->sge_debug_data_high_index_3.sop[0],
		     wtp->ulp_se_cnt_chx.sop[0], wtp->utx_tpcside.sop[0],
		     wtp->tpcside_rxarb.sop[0], wtp->tpeside_mps.sop[0],
		     wtp->tp_mps.sop[0], wtp->mps_xgm.sop[0],
		     wtp->mac_portx_pkt_count.sop[0],
		     wtp->mac_portx_aframestra_ok.sop[0]);

	printf("EOP_CH0        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[0],
		     wtp->sge_debug_data_high_index_6.eop[0],
		     wtp->sge_debug_data_high_index_3.eop[0],
		     wtp->ulp_se_cnt_chx.eop[0], wtp->utx_tpcside.eop[0],
		     wtp->tpcside_rxarb.eop[0], wtp->tpeside_mps.eop[0],
		     wtp->tp_mps.eop[0], wtp->mps_xgm.eop[0],
		     wtp->mac_portx_pkt_count.eop[0],
		     wtp->mac_portx_aframestra_ok.eop[0]);
	printf("SOP_CH1        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[1],
		     wtp->sge_debug_data_high_index_6.sop[1],
		     wtp->sge_debug_data_high_index_3.sop[1],
		     wtp->ulp_se_cnt_chx.sop[1], wtp->utx_tpcside.sop[1],
		     wtp->tpcside_rxarb.sop[1], wtp->tpeside_mps.sop[1],
		     wtp->tp_mps.sop[1], wtp->mps_xgm.sop[1],
		     wtp->mac_portx_pkt_count.sop[1],
		     wtp->mac_portx_aframestra_ok.sop[1]);

	printf("EOP_CH1        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[1],
		     wtp->sge_debug_data_high_index_6.eop[1],
		     wtp->sge_debug_data_high_index_3.eop[1],
		     wtp->ulp_se_cnt_chx.eop[1], wtp->utx_tpcside.eop[1],
		     wtp->tpcside_rxarb.eop[1], wtp->tpeside_mps.eop[1],
		     wtp->tp_mps.eop[1], wtp->mps_xgm.eop[1],
		     wtp->mac_portx_pkt_count.eop[1],
		     wtp->mac_portx_aframestra_ok.eop[1]);
	printf("SOP_CH2        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[2],
		     wtp->sge_debug_data_high_index_6.sop[2],
		     wtp->sge_debug_data_high_index_3.sop[2],
		     wtp->ulp_se_cnt_chx.sop[2], wtp->utx_tpcside.sop[2],
		     wtp->tpcside_rxarb.sop[2], wtp->tpeside_mps.sop[2],
		     wtp->tp_mps.sop[2], wtp->mps_xgm.sop[2],
		     wtp->mac_portx_pkt_count.sop[2],
		     wtp->mac_portx_aframestra_ok.sop[2]);

	printf("EOP_CH2        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[2],
		     wtp->sge_debug_data_high_index_6.eop[2],
		     wtp->sge_debug_data_high_index_3.eop[2],
		     wtp->ulp_se_cnt_chx.eop[2], wtp->utx_tpcside.eop[2],
		     wtp->tpcside_rxarb.eop[2], wtp->tpeside_mps.eop[2],
		     wtp->tp_mps.eop[2], wtp->mps_xgm.eop[2],
		     wtp->mac_portx_pkt_count.eop[2],
		     wtp->mac_portx_aframestra_ok.eop[2]);
	printf("SOP_CH3        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.sop[3],
		     wtp->sge_debug_data_high_index_6.sop[3],
		     wtp->sge_debug_data_high_index_3.sop[3],
		     wtp->ulp_se_cnt_chx.sop[3], wtp->utx_tpcside.sop[3],
		     wtp->tpcside_rxarb.sop[3], wtp->tpeside_mps.sop[3],
		     wtp->tp_mps.sop[3], wtp->mps_xgm.sop[3],
		     wtp->mac_portx_pkt_count.sop[3],
		     wtp->mac_portx_aframestra_ok.sop[3]);

	printf("EOP_CH3        %02X %2X   %2X  %2X"\
		     "    %2X       %2X    %2X   %02X  %02X   %02X      %02X\n",
		     wtp->pcie_t5_dma_stat3.eop[3],
		     wtp->sge_debug_data_high_index_6.eop[3],
		     wtp->sge_debug_data_high_index_3.eop[3],
		     wtp->ulp_se_cnt_chx.eop[3], wtp->utx_tpcside.eop[3],
		     wtp->tpcside_rxarb.eop[3], wtp->tpeside_mps.eop[3],
		     wtp->tp_mps.eop[3], wtp->mps_xgm.eop[3],
		     wtp->mac_portx_pkt_count.eop[3],
		     wtp->mac_portx_aframestra_ok.eop[3]);
	printf("SOP            %2X %2X   %2X  %2X "\
		     "   %2X       %2X    %2X   %2X  %2X   %2X      %2X\n",
		     core_pcie_dma_rsp_sop, sge_debug_index6_sop,
		     pcie_sge_dma_rsp_sop, sge_utx_sop, utx_tp_sop,
		     tpcside_rxarb_sop, tpeside_mps_sop, tp_mps_sop,
		     mps_xgm_sop, tx_xgm_xgm_sop, xgm_wire_sop);
	printf("EOP            %2X %2X   %2X  %2X "\
		     "   %2X       %2X    %2X   %2X  %2X   %2X      %2X\n",
		     core_pcie_dma_rsp_eop, sge_debug_index6_eop,
		     pcie_sge_dma_rsp_eop, sge_utx_eop, utx_tp_eop,
		     tpcside_rxarb_eop, tpeside_mps_eop, tp_mps_eop,
		     mps_xgm_eop, tx_xgm_xgm_eop, xgm_wire_eop);
	printf("*************************INGRESS (RX) PATH **********************************\n");

	printf("MOD   core<-PCIE<---SGE<--CSW<-----TPC<-URX<-LE-TPE<-----MPS<--MAC<---wire\n");

	printf("SOP_CH0      %2X  %2X    %2X    %2X"\
		     "   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X      "\
		     "%02X\n",
		     wtp->pcie_dma1_stat2.sop[0],
		     wtp->sge_debug_data_high_indx7.sop[0],
		     wtp->sge_debug_data_high_indx1.sop[0],
		     wtp->sge_debug_data_high_indx9.sop[0],
		     wtp->utx_tpcside_tx.sop[0], wtp->ulprx_tpcside.sop[0],
		     wtp->pmrx_ulprx.sop[0], wtp->le_db_rsp_cnt.sop,
		     wtp->tp_dbg_eside_pktx.sop[0], wtp->mps_tp.sop[0],
		     wtp->xgm_mps.sop[0], wtp->mac_porrx_pkt_count.sop[0],
		     wtp->mac_porrx_aframestra_ok.sop[0]);

	printf("EOP_CH0      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X %2X  %2X    %2X   %02X  %02X  "\
		     "    %02X\n",
		     wtp->pcie_dma1_stat2.eop[0],
		     wtp->sge_debug_data_high_indx7.eop[0],
		     wtp->sge_debug_data_high_indx1.eop[0],
		     wtp->sge_debug_data_high_indx9.eop[0],
		     wtp->utx_tpcside_tx.eop[0], wtp->ulprx_tpcside.eop[0],
		     wtp->pmrx_ulprx.eop[0], wtp->le_db_rsp_cnt.eop,
		     wtp->tp_dbg_eside_pktx.eop[0], wtp->mps_tp.eop[0],
		     wtp->xgm_mps.eop[0], wtp->mac_porrx_pkt_count.eop[0],
		     wtp->mac_porrx_aframestra_ok.eop[0]);
	printf("SOP_CH1      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X     %2X    %2X   %02X  %02X   "\
		     "   %02X\n",
		     wtp->pcie_dma1_stat2.sop[1],
		     wtp->sge_debug_data_high_indx7.sop[1],
		     wtp->sge_debug_data_high_indx1.sop[1],
		     wtp->sge_debug_data_high_indx9.sop[1],
		     wtp->utx_tpcside_tx.sop[1], wtp->ulprx_tpcside.sop[1],
		     wtp->pmrx_ulprx.sop[1], wtp->tp_dbg_eside_pktx.sop[1],
		     wtp->mps_tp.sop[1], wtp->xgm_mps.sop[1],
		     wtp->mac_porrx_pkt_count.sop[1],
		     wtp->mac_porrx_aframestra_ok.sop[1]);

	printf("EOP_CH1      %2X  %2X    %2X    "\
		     "%2X   %2X  %2X  %2X     %2X    %2X   %02X  %02X   "\
		     "   %02X\n",
		     wtp->pcie_dma1_stat2.eop[1],
		     wtp->sge_debug_data_high_indx7.eop[1],
		     wtp->sge_debug_data_high_indx1.eop[1],
		     wtp->sge_debug_data_high_indx9.eop[1],
		     wtp->utx_tpcside_tx.eop[1], wtp->ulprx_tpcside.eop[1],
		     wtp->pmrx_ulprx.eop[1], wtp->tp_dbg_eside_pktx.eop[1],
		     wtp->mps_tp.eop[1], wtp->xgm_mps.eop[1],
		     wtp->mac_porrx_pkt_count.eop[1],
		     wtp->mac_porrx_aframestra_ok.eop[1]);
	printf("SOP_CH2      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.sop[2],
		     wtp->sge_debug_data_high_indx7.sop[2],
		     wtp->tp_dbg_eside_pktx.sop[2], wtp->mps_tp.sop[2],
		     wtp->xgm_mps.sop[2], wtp->mac_porrx_pkt_count.sop[2],
		     wtp->mac_porrx_aframestra_ok.sop[2]);

	printf("EOP_CH2      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.eop[2],
		     wtp->sge_debug_data_high_indx7.eop[2],
		     wtp->tp_dbg_eside_pktx.eop[2], wtp->mps_tp.eop[2],
		     wtp->xgm_mps.eop[2], wtp->mac_porrx_pkt_count.eop[2],
		     wtp->mac_porrx_aframestra_ok.eop[2]);
	printf("SOP_CH3      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.sop[3],
		     wtp->sge_debug_data_high_indx7.sop[3],
		     wtp->tp_dbg_eside_pktx.sop[3], wtp->mps_tp.sop[3],
		     wtp->xgm_mps.sop[3], wtp->mac_porrx_pkt_count.sop[3],
		     wtp->mac_porrx_aframestra_ok.sop[3]);

	printf("EOP_CH3      %2X  %2X             "\
		     "                 %2X    %2X   %02X  %02X      %02X\n",
		     wtp->pcie_dma1_stat2.eop[3],
		     wtp->sge_debug_data_high_indx7.eop[3],
		     wtp->tp_dbg_eside_pktx.eop[3], wtp->mps_tp.eop[3],
		     wtp->xgm_mps.eop[3], wtp->mac_porrx_pkt_count.eop[3],
		     wtp->mac_porrx_aframestra_ok.eop[3]);
	printf("SOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[4]);
	printf("EOP_CH4                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[4]);
	printf("SOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[5]);
	printf("EOP_CH5                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[5]);
	printf("SOP_CH6                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[6]);
	printf("EOP_CH6                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[6]);
	printf("SOP_CH7                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.sop[7]);
	printf("EOP_CH7                           "\
		     "                          %02X\n",
		     wtp->xgm_mps.eop[7]);

	printf("SOP          %2X  %2X    %2X    "\
		     "%2X   %2X  %2X   %2X    %2X    %2X   %2X  %2X     %2X\n",
		     pcie_core_dmaw_sop, sge_pcie_sop, csw_sge_sop,
		     tp_csw_sop, tpcside_csw_sop, ulprx_tpcside_sop,
		     pmrx_ulprx_sop, mps_tpeside_sop, mps_tp_sop,
		     xgm_mps_sop, rx_xgm_xgm_sop, wire_xgm_sop);
	printf("EOP          %2X  %2X    %2X    "\
		     "%2X   %2X  %2X   %2X    %2X    %2X   %2X  %2X     %2X\n",
		     pcie_core_dmaw_eop, sge_pcie_eop,
		     csw_sge_eop, tp_csw_eop,
		     tpcside_csw_eop, ulprx_tpcside_eop,
		     pmrx_ulprx_eop, mps_tpeside_eop,
		     mps_tp_eop, xgm_mps_eop, rx_xgm_xgm_eop,
		     wire_xgm_eop);
	printf("DROP: ???      ???      ???       "\
		     "%2X(mib)  %2X(err) %2X(oflow) %X(cls)\n",
		     (wtp->mps_tp.drops & 0xFF),
		     (wtp->xgm_mps.err & 0xFF),
		     (wtp->xgm_mps.drop & 0xFF),
		     (wtp->xgm_mps.cls_drop & 0xFF));
	printf("INTS:  ");
	for (i = 0; i < 4; i++) {
		printf("%2X<- %2X    ",
			     (wtp->pcie_core_dmai.sop[i] & 0xF),
			     (wtp->sge_pcie_ints.sop[i] & 0xF));
	}
	printf("(PCIE<-SGE, channels 0 to 3)\n");

	return rc;
}

int
view_wtp(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	int rc = -1;

	if (is_t5(chip))
		rc = t5_view_wtp(pbuf, entity_hdr, cudbg_poutbuf);
	else if (is_t6(chip))
		rc = t6_view_wtp(pbuf, entity_hdr, cudbg_poutbuf);

	return rc;
}

/*
 *  * Small utility function to return the strings "yes" or "no" if the
 *  supplied
 *   * argument is non-zero.
 *    */
static const char *
yesno(int x)
{
	static const char *yes = "yes";
	static const char *no = "no";

	return x ? yes : no;
}

static int
dump_indirect_regs(const struct cudbg_reg_info *reg_array,
		   u32 indirect_addr, const u32 *regs,
		   struct cudbg_buffer *cudbg_poutbuf)
{
	uint32_t reg_val = 0; /* silence compiler warning*/
	int i, rc;

	for (i = 0 ; reg_array->name; ++reg_array) {
		if (!reg_array->len) {
			reg_val = regs[i];
			i++;
			printf("[0x%05x:0x%05x] "\
				     "%-47s %#-14x %u\n",
				     indirect_addr, reg_array->addr,
				     reg_array->name, reg_val, reg_val);
		} else {
			uint32_t v = xtract(reg_val, reg_array->addr,
					reg_array->len);
			printf("    %*u:%u %-55s "\
				     "%#-14x %u\n",
				     reg_array->addr < 10 ? 3 : 2,
				     reg_array->addr + reg_array->len - 1,
				     reg_array->addr, reg_array->name, v, v);
		}
	}

	return 1;

	return rc;
}

int
view_cctrl(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	   struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	u16 (*incr)[NCCTRL_WIN];
	int rc = 0;
	u32 i = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	incr = (void *)dc_buff.data;
	for (i = 0; i < NCCTRL_WIN; i++) {
		printf("%2d: %4u %4u %4u %4u %4u "\
			     "%4u %4u %4u\n", i,
			     incr[0][i], incr[1][i], incr[2][i], incr[3][i],
			     incr[4][i], incr[5][i], incr[6][i], incr[7][i]);
		printf("%8u %4u %4u %4u %4u %4u %4u"\
			     " %4u\n", incr[8][i], incr[9][i], incr[10][i],
			     incr[11][i], incr[12][i], incr[13][i],
			     incr[14][i], incr[15][i]);
	}

	return rc;
}

int
view_up_cim_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		     struct cudbg_buffer *cudbg_poutbuf,
		     enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct ireg_buf *up_cim_indr;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	indirect_addr = A_CIM_HOST_ACC_CTRL;
	up_cim_indr = (struct ireg_buf *)dc_buff.data;
	if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T5)
		n = sizeof(t5_up_cim_reg_array) / (5 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_up_cim_reg_array) / (5 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = up_cim_indr->outbuf;

		if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T5)
			rc = dump_indirect_regs(t5_up_cim_reg_ptr[i],
						indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			rc = dump_indirect_regs(t6_up_cim_reg_ptr[i],
						indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);

		if (rc < 0)
			goto err1;
		up_cim_indr++;

		/* Prohibit accessing data beyond entity size. This helps
		 * new app and old dump compatibily scenario
		 */
		if ((char *)up_cim_indr >= (dc_buff.data + dc_buff.size))
			break;
	}

err1:
	return rc;
}

static int
print_pbt_addr_entry(struct cudbg_buffer *cudbg_poutbuf, u32 val)
{
	char *fmts = "\n    [%2u:%2u]  %-10s  ";
	u32 vld, alloc, pending, address;
	int rc = 0;

	vld = (val >> 28) & 1;
	printf(fmts, 28, 28, "vld");
	printf("%d", vld);

	alloc = (val >> 27) & 1;
	printf(fmts, 27, 27, "alloc");
	printf("%d", alloc);

	pending = (val >> 26) & 1;
	printf(fmts, 26, 26, "pending");
	printf("%d", pending);

	address = val & 0x1FFFFFF;
	printf(fmts, 25, 0, "address<<6");
	printf("0x%08x", address<<6);
	printf("\n");


	return rc;
}

int
view_mbox_log(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_mbox_log *mboxlog = NULL;
	struct cudbg_buffer c_buff, dc_buff;
	u16 mbox_cmds;
	int rc, i, k;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	mbox_cmds = (u16)dc_buff.size / sizeof(struct cudbg_mbox_log);
	mboxlog = (struct cudbg_mbox_log *)dc_buff.data;
	printf(
		     "%10s  %15s  %5s  %5s  %s\n", "Seq", "Tstamp", "Atime",
		     "Etime", "Command/Reply");

	for (i = 0; i < mbox_cmds && mboxlog->entry.timestamp; i++) {
		printf("%10u  %15llu  %5d  %5d",
			     mboxlog->entry.seqno, mboxlog->entry.timestamp,
			     mboxlog->entry.access, mboxlog->entry.execute);

		for (k = 0; k < MBOX_LEN / 8; k++)
			printf("  %08x %08x",
				     mboxlog->hi[k], mboxlog->lo[k]);

		printf("\n");
		mboxlog++;
	}

	return rc;
}

int
view_pbt_tables(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct cudbg_pbt_tables *pbt;
	int rc = 0;
	int i = 0;
	u32 addr;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	pbt = (struct cudbg_pbt_tables *)dc_buff.data;
	/* PBT dynamic entries */
	addr = CUDBG_CHAC_PBT_ADDR;
	for (i = 0; i < CUDBG_PBT_DYNAMIC_ENTRIES; i++) {
		printf("Dynamic ");
		printf("Addr Table [0x%03x]: 0x%08x",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_ADDR),
			     pbt->pbt_dynamic[i]);
		rc = print_pbt_addr_entry(cudbg_poutbuf, pbt->pbt_dynamic[i]);
		if (rc < 0)
			goto err1;
	}

	/* PBT static entries */
	addr = CUDBG_CHAC_PBT_ADDR + (1 << 6);
	for (i = 0; i < CUDBG_PBT_STATIC_ENTRIES; i++) {
		printf("Static ");
		printf("Addr Table [0x%03x]: 0x%08x",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_ADDR),
			     pbt->pbt_static[i]);
		rc = print_pbt_addr_entry(cudbg_poutbuf, pbt->pbt_static[i]);
		if (rc < 0)
			goto err1;
	}

	/* PBT lrf entries */
	addr = CUDBG_CHAC_PBT_LRF;
	for (i = 0; i < CUDBG_LRF_ENTRIES; i++) {
		printf(
			     "LRF Table [0x%03x]: 0x%08x\n",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_LRF),
			     pbt->lrf_table[i]);
	}

	/* PBT data entries */
	addr = CUDBG_CHAC_PBT_DATA;
	for (i = 0; i < CUDBG_PBT_DATA_ENTRIES; i++) {
		printf(
			     "DATA Table [0x%03x]: 0x%08x\n",
			     (addr + (i * 4) - CUDBG_CHAC_PBT_DATA),
			     pbt->pbt_data[i]);
	}

err1:
	return rc;
}

int
view_ma_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct ireg_buf *ma_indr;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	indirect_addr = A_MA_LOCAL_DEBUG_CFG;
	ma_indr = (struct ireg_buf *)dc_buff.data;
	n = sizeof(t6_ma_ireg_array) / (4 * sizeof(u32));
	n += sizeof(t6_ma_ireg_array2) / (4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ma_indr->outbuf;

		rc = dump_indirect_regs(t6_ma_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ma_indr++;
	}

err1:
	return rc;
}

int
view_hma_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		  struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct ireg_buf *hma_indr;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	indirect_addr = A_HMA_LOCAL_DEBUG_CFG;
	hma_indr = (struct ireg_buf *)dc_buff.data;
	n = sizeof(t6_hma_ireg_array) / (4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = hma_indr->outbuf;

		rc = dump_indirect_regs(t6_hma_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		hma_indr++;
	}

err1:
	return rc;
}

int
view_pm_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct ireg_buf *ch_pm;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	ch_pm = (struct ireg_buf *)dc_buff.data;

	if (!cudbg_poutbuf->data)
		printf("\n\nPM_RX\n\n");

	indirect_addr = PM_RX_INDIRECT;
	n = sizeof(t5_pm_rx_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pm->outbuf;

		rc = dump_indirect_regs(t5_pm_rx_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;

		ch_pm++;
	}

	if (!cudbg_poutbuf->data)
		printf("\n\nPM_TX\n\n");

	indirect_addr = PM_TX_INDIRECT;
	n = sizeof(t5_pm_tx_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pm->outbuf;

		rc = dump_indirect_regs(t5_pm_tx_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ch_pm++;
	}

err1:
	return rc;
}

int
view_tx_rate(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	     struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct tx_rate *tx_rate;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tx_rate = (struct tx_rate *)dc_buff.data;
	printf("\n\n\t\tTX_RATE\n\n");
	if (tx_rate->nchan == NCHAN) {
		printf("              channel 0   channel 1   channel 2   channel 3\n");
		printf("NIC B/s:     %10llu  %10llu"\
			     "  %10llu  %10llu\n",
			     (unsigned long long)tx_rate->nrate[0],
			     (unsigned long long)tx_rate->nrate[1],
			     (unsigned long long)tx_rate->nrate[2],
			     (unsigned long long)tx_rate->nrate[3]);
		printf("Offload B/s: %10llu  %10llu"\
			     "  %10llu  %10llu\n",
			     (unsigned long long)tx_rate->orate[0],
			     (unsigned long long)tx_rate->orate[1],
			     (unsigned long long)tx_rate->orate[2],
			     (unsigned long long)tx_rate->orate[3]);
	} else {
		printf("              channel 0   "\
			     "channel 1\n");
		printf("NIC B/s:     %10llu  "\
			     "%10llu\n",
			     (unsigned long long)tx_rate->nrate[0],
			     (unsigned long long)tx_rate->nrate[1]);
		printf("Offload B/s: %10llu  "\
			     "%10llu\n",
			     (unsigned long long)tx_rate->orate[0],
			     (unsigned long long)tx_rate->orate[1]);
	}

	return rc;
}

int
view_tid(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct tid_info_region_rev1 *tid1;
	struct tid_info_region *tid;
	u32 tid_start = 0;
	int rc = 0, rev;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	rev = get_entity_rev((struct cudbg_ver_hdr *)dc_buff.data);
	if (rev) {
		tid1 = (struct tid_info_region_rev1 *)(dc_buff.data);
		tid_start = tid1->tid_start;
		tid = &(tid1->tid);
	} else
		tid = (struct tid_info_region *)dc_buff.data;

	printf("\n\n\tTID INFO\n\n");
	if (tid->le_db_conf & F_HASHEN) {
		if (tid->sb) {
			printf("TID range: "\
				     "%u..%u/%u..%u\n", tid_start, tid->sb - 1,
				     tid->hash_base, tid->ntids - 1);
		} else if (tid->flags & FW_OFLD_CONN) {
			printf("TID range: "\
				     "%u..%u/%u..%u\n", tid->aftid_base,
				     tid->aftid_end, tid->hash_base,
				     tid->ntids - 1);

		} else {
			printf("TID range: "\
				     "%u..%u\n", tid->hash_base,
				     tid->ntids - 1);
		}
	} else if (tid->ntids) {
		printf("TID range: %u..%u\n",
			     tid_start, tid->ntids - 1);
	}

	if (tid->nstids)
		printf("STID range: %u..%u\n",
			     tid->stid_base, tid->stid_base + tid->nstids - 1);

#if 0    /*For T4 cards*/
	if (tid->nsftids)
		printf("SFTID range: %u..%u\n",
			     tid->sftid_base,
			     tid->sftid_base + tid->nsftids - 2);
#endif

	if (tid->nuotids)
		printf("UOTID range: %u..%u\n",
			     tid->uotid_base,
			     tid->uotid_base + tid->nuotids - 1);

	if (tid->nhpftids && is_t6(chip))
		printf("HPFTID range: %u..%u\n",
			     tid->hpftid_base,
			     tid->hpftid_base + tid->nhpftids - 1);
	if (tid->ntids)
		printf("HW TID usage: %u IP users, "\
			     "%u IPv6 users\n",
			     tid->IP_users, tid->IPv6_users);

	return rc;
}

static int
show_cntxt(struct cudbg_ch_cntxt *context,
	   struct cudbg_cntxt_field *field,
	   struct cudbg_buffer *cudbg_poutbuf)
{
	char str[8];
	int rc = 0;

	if (context->cntxt_type == CTXT_EGRESS)
		strcpy(str, "egress");
	if (context->cntxt_type == CTXT_INGRESS)
		strcpy(str, "ingress");
	if (context->cntxt_type == CTXT_FLM)
		strcpy(str, "fl");
	if (context->cntxt_type == CTXT_CNM)
		strcpy(str, "cong");
	printf("\n\nContext type: %-47s\nQueue ID: "\
			"%-10d\n", str, context->cntxt_id);

	while (field->name) {
		unsigned long long data;

		u32 index = field->start_bit / 32;
		u32 bits = field->start_bit % 32;
		u32 width = field->end_bit - field->start_bit + 1;
		u32 mask = (1ULL << width) - 1;

		data = (unsigned long long)((context->data[index] >> bits) |
		       ((u64)context->data[index + 1] << (32 - bits)));
		if (bits)
			data |= ((u64)context->data[index + 2] << (64 - bits));
		data &= mask;

		if (field->islog2)
			data = (unsigned long long)1 << data;

		printf("%-47s %#-10llx\n",
			     field->name, data << field->shift);
		field++;
	}

	return rc;
}

int
view_mps_tcam(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct cudbg_mps_tcam *tcam;
	int rc = 0;
	int n, i;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	n = dc_buff.size / sizeof(struct cudbg_mps_tcam);
	tcam = (struct cudbg_mps_tcam *)dc_buff.data;
	if (is_t6(chip)) {
		printf("Idx  Ethernet address     "\
			     "Mask       VNI   Mask   IVLAN Vld DIP_Hit   "\
			     "Lookup  Port Vld Ports PF  VF                  "\
			     "         Replication                           "\
			     "         P0 P1 P2 P3  ML\n");
	} else if (is_t5(chip)) {
		if (tcam->rplc_size > CUDBG_MAX_RPLC_SIZE) {
			printf("Idx  Ethernet "\
				     "address     Mask     Vld Ports PF  VF  "\
				     "                         Replication   "\
				     "                                 P0 P1 "\
				     "P2 P3  ML\n");
		} else {
			printf("Idx  Ethernet "\
				     "address     Mask     Vld Ports PF  VF  "\
				     "            Replication               P0"\
				     " P1 P2 P3  ML\n");
		}
	}

	for (i = 0; i < n; i++, tcam++) {
		/* Print only valid MPS TCAM entries */
		if (i && !tcam->idx)
			continue;

		if (is_t6(chip)) {
			/* Inner header lookup */
			if (tcam->lookup_type && (tcam->lookup_type !=
						  M_DATALKPTYPE)) {
				printf("%3u "\
					     "%02x:%02x:%02x:%02x:%02x:%02x "\
					     "%012llx %06x %06x    -    -   "\
					     "%3c      %3c  %4x   %3c   "\
					     "%#x%4u%4d",
					     tcam->idx, tcam->addr[0],
					     tcam->addr[1], tcam->addr[2],
					     tcam->addr[3], tcam->addr[4],
					     tcam->addr[5],
					     (unsigned long long)tcam->mask,
					     tcam->vniy, (tcam->vnix | tcam->vniy),
					     tcam->dip_hit ? 'Y' : 'N',
					     tcam->lookup_type ? 'I' : 'O',
					     tcam->port_num,
					     (tcam->cls_lo & F_T6_SRAM_VLD)
					     ? 'Y' : 'N',
					     G_PORTMAP(tcam->cls_hi),
					     G_T6_PF(tcam->cls_lo),
					     (tcam->cls_lo & F_T6_VF_VALID)
					     ?
					     G_T6_VF(tcam->cls_lo) : -1);
			} else {
				printf("%3u "\
					     "%02x:%02x:%02x:%02x:%02x:%02x"\
					     " %012llx    -       -   ",
					     tcam->idx, tcam->addr[0],
					     tcam->addr[1], tcam->addr[2],
					     tcam->addr[3], tcam->addr[4],
					     tcam->addr[5],
					     (unsigned long long)tcam->mask);

				if (tcam->vlan_vld) {
					printf(
						     "%4u  Y     ",
						     tcam->ivlan);
				} else {
					printf(
						     "  -    N     ");
				}

				printf(
					     "-      %3c  %4x   %3c   "\
					     "%#x%4u%4d",
					     tcam->lookup_type ? 'I' : 'O',
					     tcam->port_num,
					     (tcam->cls_lo & F_T6_SRAM_VLD)
					     ? 'Y' : 'N',
					     G_PORTMAP(tcam->cls_hi),
					     G_T6_PF(tcam->cls_lo),
					     (tcam->cls_lo & F_T6_VF_VALID)
					     ?
					     G_T6_VF(tcam->cls_lo) : -1);
			}
		} else if (is_t5(chip)) {
			printf("%3u "\
				     "%02x:%02x:%02x:%02x:%02x:%02x %012llx%3c"\
				     "   %#x%4u%4d",
				     tcam->idx, tcam->addr[0], tcam->addr[1],
				     tcam->addr[2], tcam->addr[3],
				     tcam->addr[4], tcam->addr[5],
				     (unsigned long long)tcam->mask,
				     (tcam->cls_lo & F_SRAM_VLD) ? 'Y' : 'N',
				     G_PORTMAP(tcam->cls_hi),
				     G_PF(tcam->cls_lo),
				     (tcam->cls_lo & F_VF_VALID) ?
				     G_VF(tcam->cls_lo) : -1);
		}

		if (tcam->repli) {
			if (tcam->rplc_size > CUDBG_MAX_RPLC_SIZE) {
				printf(" %08x %08x "\
					     "%08x %08x %08x %08x %08x %08x",
					     tcam->rplc[7], tcam->rplc[6],
					     tcam->rplc[5], tcam->rplc[4],
					     tcam->rplc[3], tcam->rplc[2],
					     tcam->rplc[1], tcam->rplc[0]);
			} else {
				printf(" %08x %08x "\
					     "%08x %08x", tcam->rplc[3],
					     tcam->rplc[2], tcam->rplc[1],
					     tcam->rplc[0]);
			}
		} else {
			if (tcam->rplc_size > CUDBG_MAX_RPLC_SIZE)
				printf("%72c", ' ');
			else
				printf("%36c", ' ');
		}
		if (is_t6(chip)) {
			printf( "%4u%3u%3u%3u %#x\n",
				     G_T6_SRAM_PRIO0(tcam->cls_lo),
				     G_T6_SRAM_PRIO1(tcam->cls_lo),
				     G_T6_SRAM_PRIO2(tcam->cls_lo),
				     G_T6_SRAM_PRIO3(tcam->cls_lo),
				     (tcam->cls_lo >> S_T6_MULTILISTEN0) & 0xf);
		} else if (is_t5(chip)) {
			printf("%4u%3u%3u%3u %#x\n",
				     G_SRAM_PRIO0(tcam->cls_lo),
				     G_SRAM_PRIO1(tcam->cls_lo),
				     G_SRAM_PRIO2(tcam->cls_lo),
				     G_SRAM_PRIO3(tcam->cls_lo),
				     (tcam->cls_lo >> S_MULTILISTEN0) & 0xf);
		}
	}

	return rc;
}

int
view_dump_context(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		  struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct cudbg_ch_cntxt *context;
	int rc = 0;
	int n, i;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	n = dc_buff.size / sizeof(struct cudbg_ch_cntxt);
	context = (struct cudbg_ch_cntxt *)dc_buff.data;
	for (i = 0; i < n; i++, context++) {
		/* Only print valid contexts */
		if (context->cntxt_type != CTXT_CNM) {
			rc = cudbg_sge_ctxt_check_valid(context->data,
							context->cntxt_type);
			if (!rc)
				continue;
		}

		if (context->cntxt_type == CTXT_EGRESS) {
			if (is_t5(chip))
				rc = show_cntxt(context, t5_egress_cntxt,
						cudbg_poutbuf);
			else if (is_t6(chip))
				rc = show_cntxt(context, t6_egress_cntxt,
						cudbg_poutbuf);
		} else if (context->cntxt_type == CTXT_INGRESS) {
			if (is_t5(chip))
				rc = show_cntxt(context, t5_ingress_cntxt,
						cudbg_poutbuf);
			else if (is_t6(chip))
				rc = show_cntxt(context, t6_ingress_cntxt,
						cudbg_poutbuf);
		} else if (context->cntxt_type == CTXT_CNM)
			rc = show_cntxt(context, t5_cnm_cntxt, cudbg_poutbuf);
		else if (context->cntxt_type == CTXT_FLM) {
			if (is_t5(chip))
				rc = show_cntxt(context, t5_flm_cntxt,
						cudbg_poutbuf);
			else if (is_t6(chip))
				rc = show_cntxt(context, t6_flm_cntxt,
						cudbg_poutbuf);
		}

		if (rc < 0)
			goto err1;
	}

err1:
	return rc;
}

int
view_le_tcam(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	     struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	char *le_region[] = {
		"active", "server", "filter", "clip", "routing"
	};
	struct cudbg_tid_data *tid_data = NULL;
	struct cudbg_tcam *tcam_region = NULL;
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0, j;
	u32 i;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	tcam_region = (struct cudbg_tcam *)dc_buff.data;
	tid_data = (struct cudbg_tid_data *)(tcam_region + 1);
	printf("\n\nRouting table index: 0x%X\n",
		     tcam_region->routing_start);
	printf("Lip comp table index: 0x%X\n",
		     tcam_region->clip_start);
	printf("Filter table index: 0x%X\n",
		     tcam_region->filter_start);
	printf("Server index: 0x%X\n\n",
		     tcam_region->server_start);

	printf("tid start: %d\n\n", 0);
	printf("tid end: %d\n\n",
		     tcam_region->max_tid);

	for (i = 0; i < tcam_region->max_tid; i++) {
		printf(
			     "======================================================================================\n");
		printf("This is a LE_DB_DATA_READ "\
			     "command: on TID %d at index %d\n", i, i * 4);
		if (i < tcam_region->server_start / 4) {
			printf("Region: %s\n\n",
				     le_region[0]);
		} else if ((i >= tcam_region->server_start / 4) &&
			   (i < tcam_region->filter_start / 4)) {
			printf("Region: %s\n\n",
				     le_region[1]);
		} else if ((i >= tcam_region->filter_start / 4) &&
			   (i < tcam_region->clip_start / 4)) {
			printf("Region: %s\n\n",
				     le_region[2]);
		} else if ((i >= tcam_region->clip_start / 4) &&
			   (i < tcam_region->routing_start / 4)) {
			printf("Region: %s\n\n",
				     le_region[3]);
		} else if (i >= tcam_region->routing_start / 4) {
			printf("Region: %s\n\n",
				     le_region[4]);
		}

		printf("READ:\n");
		printf("DBGICMDMODE: %s\n",
			     (tid_data->dbig_conf & 1) ? "LE" : "TCAM");
		printf("READING TID: 0x%X\n",
			     tid_data->tid);
		printf("Write: "\
			     "LE_DB_DBGI_REQ_TCAM_CMD: 0x%X\n",
			     tid_data->dbig_cmd);
		printf("Write: LE_DB_DBGI_CONFIG "\
			     "0x%X\n", tid_data->dbig_conf);
		printf("Polling: LE_DB_DBGI_CONFIG:"\
			     " busy bit\n");
		printf("Read: "\
			     "LE_DB_DBGI_RSP_STATUS: 0x%X [%d]\n",
			     tid_data->dbig_rsp_stat & 1,
			     tid_data->dbig_rsp_stat & 1);
		printf("Read: "\
			     "LE_DB_DBGI_RSP_DATA:\n");
		printf("Response data for TID "\
			     "0x%X:\n", i);

		for (j = 0; j < CUDBG_NUM_REQ_REGS; j++) {
			printf("\t0x%X: 0x%08X\n",
				     A_LE_DB_DBGI_RSP_DATA + (j << 2),
				     tid_data->data[j]);
		}

		printf("DATA READ: ");
		for (j = CUDBG_NUM_REQ_REGS - 1; j >= 0; j--) {
			printf("%08X",
				     tid_data->data[j]);
		}
		printf("\n\n");

		tid_data++;
	}

	return rc;
}

int
view_pcie_config(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	u32 *pcie_config;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	if (!cudbg_poutbuf->data)
		printf("\n\t\t\tPCIE CONFIG\n\n");

	pcie_config = (u32 *)dc_buff.data;
	rc = dump_indirect_regs(t5_pcie_config_ptr[0], 0,
				(const u32 *)pcie_config, cudbg_poutbuf);

	return rc;
}

int
view_pcie_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		   struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct ireg_buf *ch_pcie;
	u32 indirect_addr;
	int rc = 0;
	int i = 0;
	int n;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	if (!cudbg_poutbuf->data)
		printf("\n\nPCIE_PDBG\n\n");

	indirect_addr = PCIE_PDEBUG_INDIRECT;
	ch_pcie = (struct ireg_buf *)dc_buff.data;
	n = sizeof(t5_pcie_pdbg_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pcie->outbuf;

		rc = dump_indirect_regs(t5_pcie_pdbg_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ch_pcie++;
	}

	if (!cudbg_poutbuf->data)
		printf("\n\nPCIE_CDBG\n\n");

	indirect_addr = PCIE_CDEBUG_INDIRECT;
	n = sizeof(t5_pcie_cdbg_array)/(4 * sizeof(u32));
	for (i = 0; i < n; i++) {
		u32 *buff = ch_pcie->outbuf;

		rc = dump_indirect_regs(t5_pcie_cdbg_ptr[i], indirect_addr,
					(const u32 *) buff, cudbg_poutbuf);
		if (rc < 0)
			goto err1;
		ch_pcie++;
	}

err1:
	return rc;
}

int
view_tp_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		 struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	int j = 0, k, l, len, n = 0;
	struct ireg_buf *ch_tp_pio;
	u32 indirect_addr;
	u32 *pkey = NULL;
	int rc = 0;
	int i = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	ch_tp_pio = (struct ireg_buf *)dc_buff.data;
	l = 0;

	indirect_addr = TP_PIO;
	if (!cudbg_poutbuf->data)
		printf("\n\nTP_PIO\n\n");

	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		n = sizeof(t5_tp_pio_array)/(4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_tp_pio_array)/(4 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = ch_tp_pio->outbuf;

		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			rc = dump_indirect_regs(t5_tp_pio_ptr[i], indirect_addr,
						(const u32 *) buff,
						cudbg_poutbuf);
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			rc = dump_indirect_regs(t6_tp_pio_ptr[i], indirect_addr,
						(const u32 *) buff,
						cudbg_poutbuf);

		if (rc < 0)
			goto err1;

		ch_tp_pio++;
	}

	indirect_addr = TP_TM_PIO_ADDR;
	if (!cudbg_poutbuf->data)
		printf("\n\nTP_TM_PIO\n\n");

	l = 0;
	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		n = sizeof(t5_tp_tm_pio_array)/(4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_tp_tm_pio_array)/(4 * sizeof(u32));

	for (i = 0; i < n; i++) {
		u32 *buff = ch_tp_pio->outbuf;

		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			rc = dump_indirect_regs(t5_tp_tm_regs, indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			rc = dump_indirect_regs(t6_tp_tm_regs, indirect_addr,
						(const u32 *)buff,
						cudbg_poutbuf);

		if (rc < 0)
			goto err1;

		ch_tp_pio++;
	}
	indirect_addr = TP_MIB_INDEX;
	if (!cudbg_poutbuf->data)
		printf("\n\nTP_MIB_INDEX\n\n");

	l = 0;
	if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
		n = sizeof(t5_tp_mib_index_array)/(4 * sizeof(u32));
	else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
		n = sizeof(t6_tp_mib_index_array)/(4 * sizeof(u32));
	for (i = 0; i < n ; i++) {
		u32 *buff = ch_tp_pio->outbuf;

		pkey = (u32 *) buff;
		if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5)
			j = l + t5_tp_mib_index_array[i][3];
		else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6)
			j = l + t6_tp_mib_index_array[i][3];

		len = 0;
		for (k = l; k < j; k++) {
			if (CHELSIO_CHIP_VERSION(chip) <= CHELSIO_T5) {
				printf("[0x%x:%2s]"\
					     " %-47s %#-10x %u\n",
					     indirect_addr,
					     t5_tp_mib_index_reg_array[k].addr,
					     t5_tp_mib_index_reg_array[k].name,
					     pkey[len], pkey[len]);
			} else if (CHELSIO_CHIP_VERSION(chip) == CHELSIO_T6) {
				printf("[0x%x:%2s]"\
					     " %-47s %#-10x %u\n",
					     indirect_addr,
					     t6_tp_mib_index_reg_array[k].addr,
					     t6_tp_mib_index_reg_array[k].name,
					     pkey[len], pkey[len]);
			}
			len++;
		}
		l = k;
		ch_tp_pio++;
	}

err1:
	return rc;
}

int
find_index_in_t6_sge_regs(u32 addr)
{
	u32 i = 0;

	while (t6_sge_regs[i].name) {
		if (t6_sge_regs[i].addr == addr)
			return i;
		i++;
	}

	return -1;
}

void
print_t6_sge_reg_value(u32 reg_addr, u32 reg_data, u32 data_value,
		       int idx_map, struct cudbg_buffer *cudbg_poutbuf)
{
	struct reg_info *reg_array = &t6_sge_regs[idx_map];
	u32 value;

	printf("[0x%x:0x%x] %-47s %#-10x %u\n",
		     reg_addr, reg_data, reg_array->name, data_value,
		     data_value);

	reg_array++;
	while (reg_array->len) {
		value = xtract(data_value, reg_array->addr, reg_array->len);

		printf("        %-3u:%3u %-47s "\
			     "%#-10x %u\n",
			     reg_array->addr + reg_array->len - 1,
			     reg_array->addr, reg_array->name, value, value);

		reg_array++;
	}


	return;
}

void
print_sge_qbase(struct sge_qbase_reg_field *sge_qbase, u32 pf_vf_count,
		int isPF, struct cudbg_buffer *cudbg_poutbuf)
{
	u32 *data_value;
	u32 f;
	int idx_map0, idx_map1, idx_map2, idx_map3;

	idx_map0 = find_index_in_t6_sge_regs(sge_qbase->reg_data[0]);
	idx_map1 = find_index_in_t6_sge_regs(sge_qbase->reg_data[1]);
	idx_map2 = find_index_in_t6_sge_regs(sge_qbase->reg_data[2]);
	idx_map3 = find_index_in_t6_sge_regs(sge_qbase->reg_data[3]);

	if (idx_map0 < 0 || idx_map1 < 0 || idx_map2 < 0 || idx_map3 < 0) {
		printf("Error: one of these addr is "\
			     "wrong: 0x%x 0x%x 0x%x 0x%x\n", sge_qbase->reg_data[0],
			     sge_qbase->reg_data[1], sge_qbase->reg_data[2],
			     sge_qbase->reg_data[3]);
		return;
	}

	for (f = 0; f < pf_vf_count; f++) {
		if (isPF)
			data_value = (u32 *)sge_qbase->pf_data_value[f];
		else
			data_value = (u32 *)sge_qbase->vf_data_value[f];
		printf("\nSGE_QBASE_INDEX for %s %d\n",
			     isPF ? "pf" : "vf", f);
		print_t6_sge_reg_value(sge_qbase->reg_addr, sge_qbase->reg_data[0],
				       data_value[0], idx_map0, cudbg_poutbuf);

		print_t6_sge_reg_value(sge_qbase->reg_addr, sge_qbase->reg_data[1],
				       data_value[1], idx_map1, cudbg_poutbuf);

		print_t6_sge_reg_value(sge_qbase->reg_addr, sge_qbase->reg_data[2],
				       data_value[2], idx_map2, cudbg_poutbuf);

		print_t6_sge_reg_value(sge_qbase->reg_addr, sge_qbase->reg_data[3],
				       data_value[3], idx_map3, cudbg_poutbuf);
	}

	return;
}

int
view_sge_indirect(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
		  struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct sge_qbase_reg_field *sge_qbase;
	u32 indirect_addr;
	u32 *pkey = NULL;
	int j, k, len;
	int rc = 0;
	int i = 0;
	int l = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	pkey = (u32 *) (dc_buff.data + sizeof(struct ireg_field));
	indirect_addr = SGE_DEBUG_DATA_INDIRECT;
	for (i = 0; i < 2; i++) {
		printf("\n");
		j = l + t5_sge_dbg_index_array[i][3];
		len = 0;
		for (k = l; k < j; k++) {
			if (i == 0) {
				printf("[0x%x:0x%x]"\
					     "  %-47s %#-10x %u\n",
					     indirect_addr,
					     sge_debug_data_high[k].addr,
					     sge_debug_data_high[k].name,
					     pkey[len], pkey[len]);
			} else {
				printf("[0x%x:0x%x]"\
					     " %-47s %#-10x %u\n",
					     indirect_addr,
					     sge_debug_data_low[k].addr,
					     sge_debug_data_low[k].name,
					     pkey[len], pkey[len]);
			}
			len++;
		}
		pkey = (u32 *)((char *)pkey + sizeof(struct ireg_buf));
	}

	if (is_t6(chip)) {
		dc_buff.offset = 2 * sizeof(struct ireg_buf);

		if (dc_buff.size <= dc_buff.offset)
			goto err1;

		sge_qbase = (struct sge_qbase_reg_field *)(dc_buff.data +
							   dc_buff.offset);
		print_sge_qbase(sge_qbase, 8, 1, cudbg_poutbuf);
		print_sge_qbase(sge_qbase, sge_qbase->vfcount, 0,
				cudbg_poutbuf);
	}
	
err1:
	return rc;
}

static int
view_full_t6(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	     struct cudbg_buffer *cudbg_poutbuf)
{
	u32 pcie_c0rd_full, pcie_c0wr_full, pcie_c0rsp_full;
	u32 pcie_c1rd_full, pcie_c1wr_full, pcie_c1rsp_full;
	u32 rx_fifo_cng, rx_pcmd_cng, rx_hdr_cng;
	u32 tx, rx, cs, es, pcie, pcie1, sge;
	struct cudbg_buffer c_buff, dc_buff;
	u32 sge_req_full = 0, sge_rx_full;
	u32 cng0, cng1;
	int rc = 0;
	u32 *sp;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	sp = (u32 *)dc_buff.data;

	/* Collect Registers:
	 * TP_DBG_SCHED_TX (0x7e40 + 0x6a),
	 * TP_DBG_SCHED_RX (0x7e40 + 0x6b),
	 * TP_DBG_CSIDE_INT (0x7e40 + 0x23f),
	 * TP_DBG_ESIDE_INT (0x7e40 + 0x148),
	 * PCIE_CDEBUG_INDEX[AppData0] (0x5a10 + 2),
	 * PCIE_CDEBUG_INDEX[AppData1] (0x5a10 + 3),
	 * SGE_DEBUG_DATA_HIGH_INDEX_10 (0x12a8)
	 **/
	tx = *sp;
	rx = *(sp + 1);
	cs = *(sp + 2);
	es = *(sp + 3);
	pcie = *(sp + 4);
	pcie1 = *(sp + 5);
	sge = *(sp + 6);

	pcie_c0wr_full = pcie & 1;
	pcie_c0rd_full = (pcie >> 2) & 1;
	pcie_c0rsp_full = (pcie >> 4) & 1;

	pcie_c1wr_full = pcie1 & 1;
	pcie_c1rd_full = (pcie1 >> 2) & 1;
	pcie_c1rsp_full = (pcie1 >> 4) & 1;

	/* sge debug_PD_RdRspAFull_d for each channel */
	sge_rx_full = (sge >> 30) & 0x3;

	rx_fifo_cng = (rx >> 20) & 0xf;
	rx_pcmd_cng = (rx >> 14) & 0x3;
	rx_hdr_cng = (rx >> 8) & 0xf;
	cng0 = (rx_fifo_cng & 1) | (rx_pcmd_cng & 1) | (rx_hdr_cng & 1);
	cng1 = ((rx_fifo_cng & 2) >> 1) | ((rx_pcmd_cng & 2) >> 1) |
		((rx_hdr_cng & 2) >> 1);

	printf("\n");
	/* TP resource reservation */
	printf("Tx0 ==%1u=>  T  <=%1u= Rx0\n",
		     ((tx >> 28) & 1), ((rx >> 28) & 1));
	printf("Tx1 ==%1u=>  P  <=%1u= Rx1\n",
		     ((tx >> 29) & 1), ((rx >> 29) & 1));
	printf("\n");

	/* TX path */
	/* pcie bits 19:16 are D_RspAFull for each channel */
	/* Tx is blocked when Responses from system cannot flow toward TP. */
	printf("Tx0 P =%1u=> S ? U =>%1u=>  T\n",
		     pcie_c0rsp_full, ((cs >> 24) & 1));
	printf("Tx1 C =%1u=> G ? T =>%1u=>  P\n",
		     pcie_c1rsp_full, ((cs >> 25) & 1));

	/* RX path */
	/* Rx is blocked when sge and/or pcie cannot send requests to system.
	 * */
	printf("       Rd Wr\n");
	printf("RX0 P <=%1u=%1u=%1u S <=%1u= C "\
		     "<=%1u= T <=T <=%1u=  T <=%1u= M\n",
		     ((pcie_c0rd_full >> 0) & 1), ((pcie_c0wr_full >> 0) & 1),
		     ((sge_req_full >> 0) & 1), ((sge_rx_full >> 0) & 1),
		     cng0, ((cs >> 20) & 1), ((es >> 16) & 1));
#ifndef __CHECKER__
	printf("RX1 C <=%1u=%1u=%1u G <=%1u= X "\
		     "<=%1u= C <=P <=%1u=  E <=%1u= P\n",
		     ((pcie_c1rd_full >> 1) & 1), ((pcie_c1wr_full >> 1) & 1),
		     ((sge_req_full >> 1) & 1), ((sge_rx_full >> 1) & 1),
		     cng1, ((cs >> 21) & 1), ((es >> 17) & 1));
#endif
	printf("\n");


	return rc;
}

static int
view_full_t5(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	     struct cudbg_buffer *cudbg_poutbuf)
{
	u32 sge_rsp_full, sge_req_full, sge_rx_full;
	u32 rx_fifo_cng, rx_pcmd_cng, rx_hdr_cng;
	struct cudbg_buffer c_buff, dc_buff;
	u32 pcie_rd_full, pcie_wr_full;
	u32 tx, rx, cs, es, pcie, sge;
	u32 cng0, cng1;
	int rc = 0;
	u32 *sp;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	sp = (u32 *)dc_buff.data;

	/* Collect Registers:
	 * TP_DBG_SCHED_TX (0x7e40 + 0x6a),
	 * TP_DBG_SCHED_RX (0x7e40 + 0x6b),
	 * TP_DBG_CSIDE_INT (0x7e40 + 0x23f),
	 * TP_DBG_ESIDE_INT (0x7e40 + 0x148),
	 * PCIE_CDEBUG_INDEX[AppData0] (0x5a10 + 2),
	 * SGE_DEBUG_DATA_HIGH_INDEX_10 (0x12a8)
	 **/
	tx = *sp;
	rx = *(sp + 1);
	cs = *(sp + 2);
	es = *(sp + 3);
	pcie = *(sp + 4);
	sge = *(sp + 5);

	pcie_rd_full = (pcie >> 8) & 0xf;
	pcie_wr_full = pcie & 0xf;

	/* OR together D_RdReqAFull and D_WrReqAFull for pcie */

	/* sge debug_PD_RdRspAFull_d for each channel */
	sge_rsp_full = ((sge >> 26) & 0xf);
	/* OR together sge debug_PD_RdReqAFull_d and debug PD_WrReqAFull_d */
	sge_req_full = ((sge >> 22) & 0xf) | ((sge >> 18) & 0xf);
	sge_rx_full = (sge >> 30) & 0x3;

	rx_fifo_cng = (rx >> 20) & 0xf;
	rx_pcmd_cng = (rx >> 14) & 0x3;
	rx_hdr_cng = (rx >> 8) & 0xf;
	cng0 = (rx_fifo_cng & 1) | (rx_pcmd_cng & 1) | (rx_hdr_cng & 1);
	cng1 = ((rx_fifo_cng & 2) >> 1) | ((rx_pcmd_cng & 2) >> 1) |
		((rx_hdr_cng & 2) >> 1);

	printf("\n");
	/* TP resource reservation */
	printf("Tx0 ==%1u=\\     /=%1u= Rx0\n",
		     ((tx >> 28) & 1), ((rx >> 28) & 1));
	printf("Tx1 ==%1u= | T | =%1u= Rx1\n",
		     ((tx >> 29) & 1), ((rx >> 29) & 1));
	printf("Tx2 ==%1u= | P | =%1u= Rx2\n",
		     ((tx >> 30) & 1), ((rx >> 30) & 1));
	printf("Tx3 ==%1u=/     \\=%1u= Rx3\n",
		     ((tx >> 31) & 1), ((rx >> 31) & 1));
	printf("\n");

	/* TX path */
	/* pcie bits 19:16 are D_RspAFull for each channel */
	/* Tx is blocked when Responses from system cannot flow toward TP. */
	printf("Tx0 P =%1u=%1u=\\ S ? U ==%1u=\\\n",
		     ((pcie >> 16) & 1), (sge_rsp_full & 1), ((cs >> 24) & 1));
	printf("Tx1 C =%1u=%1u= |G ? T ==%1u= | T\n",
		     ((pcie >> 17) & 1), ((sge_rsp_full >> 1) & 1),
		     ((cs >> 25) & 1));
	printf("Tx2 I =%1u=%1u= |E ? X ==%1u= | P\n",
		     ((pcie >> 18) & 1), ((sge_rsp_full >> 2) & 1),
		     ((cs >> 26) & 1));
	printf("Tx3 E =%1u=%1u=/   ?   ==%1u=/\n",
		     ((pcie >> 19) & 1), ((sge_rsp_full >> 3) & 1),
		     ((cs >> 27) & 1));
	printf("\n");

	/* RX path */
	/* Rx is blocked when sge and/or pcie cannot send requests to system.
	 * */
	printf("       Rd Wr\n");
	printf("RX0 P /=%1u=%1u=%1u S <=%1u= C "\
		     "<=%1u= T <=T <=%1u=  T /=%1u= M\n",
		     ((pcie_rd_full >> 0) & 1), ((pcie_wr_full >> 0) & 1),
		     ((sge_req_full >> 0) & 1), ((sge_rx_full >> 0) & 1),
		     cng0, ((cs >> 20) & 1), ((es >> 16) & 1));
	printf("RX1 C| =%1u=%1u=%1u G <=%1u= X "\
		     "<=%1u= C <=P <=%1u=  E| =%1u= P\n",
		     ((pcie_rd_full >> 1) & 1), ((pcie_wr_full >> 1) & 1),
		     ((sge_req_full >> 1) & 1), ((sge_rx_full >> 1) & 1),
		     cng1, ((cs >> 21) & 1), ((es >> 17) & 1));
	printf("RX2 I| =%1u=%1u=%1u E             "\
		     "             | =%1u= S\n",
		     ((pcie_rd_full >> 2) & 1), ((pcie_wr_full >> 2) & 1),
		     ((sge_req_full >> 2) & 1), ((es >> 18) & 1));
	printf("RX3 E \\=%1u=%1u=%1u               "\
		     "              \\=%1u=\n",
		     ((pcie_rd_full >> 3) & 1), ((pcie_wr_full >> 3) & 1),
		     ((sge_req_full >> 3) & 1), ((es >> 19) & 1));
	printf("\n");

	return rc;
}

int
view_full(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	  struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	int rc = -1;

	if (is_t5(chip))
		rc = view_full_t5(pbuf, entity_hdr, cudbg_poutbuf);
	else if (is_t6(chip))
		rc = view_full_t6(pbuf, entity_hdr, cudbg_poutbuf);

	return rc;
}

int
view_vpd_data(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	      struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	struct struct_vpd_data *vpd_data;
	int rc = 0;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	vpd_data = (struct struct_vpd_data *) dc_buff.data;
	printf("MN %s\n", vpd_data->mn);
	printf("SN %s\n", vpd_data->sn);
	printf("BN %s\n", vpd_data->bn);
	printf("NA %s\n", vpd_data->na);
	printf("SCFG Version 0x%x\n",
		     vpd_data->scfg_vers);
	printf("VPD Version  0x%x\n",
		     vpd_data->vpd_vers);

	printf("Firmware Version: %d.%d.%d.%d\n",
		    vpd_data->fw_major, vpd_data->fw_minor, vpd_data->fw_micro,
		    vpd_data->fw_build);

	return rc;
}

int
view_upload(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	    struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_buffer c_buff, dc_buff;
	int rc = 0;
	u32 *value;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	value = (u32 *) dc_buff.data;
	if (*value == 0xffffffff) {
		printf("uP load: <not available>\n");
		goto err1;
	}

	printf("uP load: %d, %d, %d\n",
		     (*value >>  0) & 0xff,
		     (*value >>  8) & 0xff,
		     (*value >> 16) & 0xff);

err1:
	return rc;
}

static const char *
cudbg_qdesc_qtype_to_str(enum cudbg_qdesc_qtype qtype)
{
	switch (qtype) {
	case CUDBG_QTYPE_NIC_TXQ:
		return "ETHERNET-TXQ";
	case CUDBG_QTYPE_NIC_RXQ:
		return "ETHERNET-RXQ";
	case CUDBG_QTYPE_NIC_FLQ:
		return "ETHERNET-FL";
	case CUDBG_QTYPE_CTRLQ:
		return "ETHERNET-CTRLQ";
	case CUDBG_QTYPE_FWEVTQ:
		return "FIRMWARE-EVENT-QUEUE";
	case CUDBG_QTYPE_INTRQ:
		return "NON-DATA-INTERRUPT-QUEUE";
	case CUDBG_QTYPE_PTP_TXQ:
		return "PTP-TXQ";
	case CUDBG_QTYPE_OFLD_TXQ:
		return "OFFLOAD-TXQ";
	case CUDBG_QTYPE_RDMA_RXQ:
		return "RDMA-RXQ";
	case CUDBG_QTYPE_RDMA_FLQ:
		return "RDMA-FL";
	case CUDBG_QTYPE_RDMA_CIQ:
		return "RDMA-CIQ";
	case CUDBG_QTYPE_ISCSI_RXQ:
		return "iSCSI-RXQ";
	case CUDBG_QTYPE_ISCSI_FLQ:
		return "iSCSI-FL";
	case CUDBG_QTYPE_ISCSIT_RXQ:
		return "iSCSIT-RXQ";
	case CUDBG_QTYPE_ISCSIT_FLQ:
		return "iSCSIT-FL";
	case CUDBG_QTYPE_CRYPTO_TXQ:
		return "CRYPTO-TXQ";
	case CUDBG_QTYPE_CRYPTO_RXQ:
		return "CRYPTO-RXQ";
	case CUDBG_QTYPE_CRYPTO_FLQ:
		return "CRYPTO-FL";
	case CUDBG_QTYPE_TLS_RXQ:
		return "TLS-RXQ";
	case CUDBG_QTYPE_TLS_FLQ:
		return "TLS-FL";
	case CUDBG_QTYPE_UNKNOWN:
	case CUDBG_QTYPE_MAX:
		return "UNKNOWN";
	}

	return "UNKNOWN";
}

static struct cudbg_qdesc_entry *
cudbg_next_qdesc(struct cudbg_qdesc_entry *e)
{
	return (struct cudbg_qdesc_entry *)
	       ((u8 *)e + sizeof(*e) + e->data_size);
}

int
view_qdesc(char *pbuf, struct cudbg_entity_hdr *entity_hdr,
	   struct cudbg_buffer *cudbg_poutbuf, enum chip_type chip)
{
	struct cudbg_qdesc_entry *qdesc_entry;
	struct cudbg_qdesc_info *qdesc_info;
	struct cudbg_buffer c_buff, dc_buff;
	u8 zero_memory_128[128] = { 0 };
	struct cudbg_ver_hdr *ver_hdr;
	u32 i, j, k, l, max_desc;
	u32 star_count = 0;
	int rc = 0;
	u8 *p;

	rc = cudbg_view_decompress_buff(pbuf, entity_hdr, &c_buff, &dc_buff);
	if (rc)
		return rc;

	ver_hdr = (struct cudbg_ver_hdr *)dc_buff.data;
	qdesc_info = (struct cudbg_qdesc_info *)
		     (dc_buff.data + sizeof(*ver_hdr));

	if (!qdesc_info->num_queues) {
		printf("No queues found\n");
		goto err1;
	}

	qdesc_entry = (struct cudbg_qdesc_entry *)
		      ((u8 *)qdesc_info + ver_hdr->size);

	for (i = 0; i < qdesc_info->num_queues; i++) {
		star_count = 0;
		printf(
			     "\n\nQueue - %s, context-id: %u, desc-size: %u, desc-num: %u\n",
			     cudbg_qdesc_qtype_to_str(qdesc_entry->qtype),
			     qdesc_entry->qid,
			     qdesc_entry->desc_size,
			     qdesc_entry->num_desc);
		p = (u8 *)qdesc_entry + qdesc_info->qdesc_entry_size;

		for (j = 0; j < qdesc_entry->num_desc; j++) {
			k = 0;
			/* Below logic skips printing descriptors filled with
			 * all zeros and replaces it with star
			 */
			if (!memcmp(p, zero_memory_128, qdesc_entry->desc_size)) {
				star_count++;
				if (star_count >= 2 &&
				    j != (qdesc_entry->num_desc - 1)) {
					/* Skip all consecutive descriptors
					 * filled with zeros until the last
					 * descriptor.
					 */
					p += qdesc_entry->desc_size;

					if (star_count == 2) {
						/* Print * for the second
						 * consecutive descriptor
						 * filled with zeros.
						 */
						printf("\n%-8s\n", "*");
					}
					continue;
				}
			} else {
				/* Descriptor doesn't contain all zeros, so
				 * restart skip logic.
				 */
				star_count = 0;
			}

			printf("\n%-8d:", j);
			while (k < qdesc_entry->desc_size) {
				max_desc = min(qdesc_entry->desc_size - k,
					       sizeof(u32));
				if (k && !(k % 32))
					printf("\n%-9s", " ");
				if (!(k % 4))
					printf(" ");
				for (l = 0; l < max_desc; l++, k++, p++)
					printf("%02x", *p);
			}
		}
		qdesc_entry = cudbg_next_qdesc(qdesc_entry);
	}

err1:
	return rc;
}
