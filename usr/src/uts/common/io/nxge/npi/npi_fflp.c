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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <npi_fflp.h>
#include <nxge_common.h>

/* macros to compute calss configuration register offset */

#define	  GET_TCAM_CLASS_OFFSET(cls) \
	(FFLP_TCAM_CLS_BASE_OFFSET + (cls - 2) * 8)
#define	  GET_TCAM_KEY_OFFSET(cls) \
	(FFLP_TCAM_KEY_BASE_OFFSET + (cls - 4) * 8)
#define	  GET_FLOW_KEY_OFFSET(cls) \
	(FFLP_FLOW_KEY_BASE_OFFSET + (cls - 4) * 8)

#define	  HASHTBL_PART_REG_STEP 8192
#define	  HASHTBL_PART_REG_VIR_OFFSET 0x2100
#define	  HASHTBL_PART_REG_VIR_STEP 0x4000
#define	  GET_HASHTBL_PART_OFFSET_NVIR(partid, reg)	\
	((partid  * HASHTBL_PART_REG_STEP) + reg)

#define	  GET_HASHTBL_PART_OFFSET(handle, partid, reg)	\
	    (handle.is_vraddr ?					\
	    (((partid & 0x1) * HASHTBL_PART_REG_VIR_STEP) +	\
	    (reg & 0x8) + (HASHTBL_PART_REG_VIR_OFFSET)) :	\
	    (partid * HASHTBL_PART_REG_STEP) + reg)

#define	 FFLP_PART_OFFSET(partid, reg) ((partid  * 8) + reg)
#define	 FFLP_VLAN_OFFSET(vid, reg) ((vid  * 8) + reg)

#define	 TCAM_COMPLETION_TRY_COUNT 10
#define	 BIT_ENABLE	0x1
#define	 BIT_DISABLE	0x0

#define	 FCRAM_PARTITION_VALID(partid) \
	((partid < NXGE_MAX_RDC_GRPS))
#define	FFLP_VLAN_VALID(vid) \
	((vid > 0) && (vid < NXGE_MAX_VLANS))
#define	FFLP_PORT_VALID(port) \
	((port < MAX_PORTS_PER_NXGE))
#define	FFLP_RDC_TABLE_VALID(table) \
	((table < NXGE_MAX_RDC_GRPS))
#define	TCAM_L3_USR_CLASS_VALID(class) \
	((class >= TCAM_CLASS_IP_USER_4) && (class <= TCAM_CLASS_IP_USER_7))
#define	TCAM_L2_USR_CLASS_VALID(class) \
	((class == TCAM_CLASS_ETYPE_1) || (class == TCAM_CLASS_ETYPE_2))
#define	TCAM_L3_CLASS_VALID(class) \
	((class >= TCAM_CLASS_IP_USER_4) && (class <= TCAM_CLASS_SCTP_IPV6))
#define	TCAM_L3_CLASS_VALID_RFNL(class) \
	((TCAM_L3_CLASS_VALID(class)) || class == TCAM_CLASS_IPV6_FRAG)
#define	TCAM_CLASS_VALID(class) \
	((class >= TCAM_CLASS_ETYPE_1) && (class <= TCAM_CLASS_RARP))


uint64_t fflp_fzc_offset[] = {
	FFLP_ENET_VLAN_TBL_REG, FFLP_L2_CLS_ENET1_REG, FFLP_L2_CLS_ENET2_REG,
	FFLP_TCAM_KEY_IP_USR4_REG, FFLP_TCAM_KEY_IP_USR5_REG,
	FFLP_TCAM_KEY_IP_USR6_REG, FFLP_TCAM_KEY_IP_USR7_REG,
	FFLP_TCAM_KEY_IP4_TCP_REG, FFLP_TCAM_KEY_IP4_UDP_REG,
	FFLP_TCAM_KEY_IP4_AH_ESP_REG, FFLP_TCAM_KEY_IP4_SCTP_REG,
	FFLP_TCAM_KEY_IP6_TCP_REG, FFLP_TCAM_KEY_IP6_UDP_REG,
	FFLP_TCAM_KEY_IP6_AH_ESP_REG, FFLP_TCAM_KEY_IP6_SCTP_REG,
	FFLP_TCAM_KEY_0_REG, FFLP_TCAM_KEY_1_REG, FFLP_TCAM_KEY_2_REG,
	FFLP_TCAM_KEY_3_REG, FFLP_TCAM_MASK_0_REG, FFLP_TCAM_MASK_1_REG,
	FFLP_TCAM_MASK_2_REG, FFLP_TCAM_MASK_3_REG, FFLP_TCAM_CTL_REG,
	FFLP_VLAN_PAR_ERR_REG, FFLP_TCAM_ERR_REG, HASH_LKUP_ERR_LOG1_REG,
	HASH_LKUP_ERR_LOG2_REG, FFLP_FCRAM_ERR_TST0_REG,
	FFLP_FCRAM_ERR_TST1_REG, FFLP_FCRAM_ERR_TST2_REG, FFLP_ERR_MSK_REG,
	FFLP_CFG_1_REG, FFLP_DBG_TRAIN_VCT_REG, FFLP_TCP_CFLAG_MSK_REG,
	FFLP_FCRAM_REF_TMR_REG,  FFLP_FLOW_KEY_IP_USR4_REG,
	FFLP_FLOW_KEY_IP_USR5_REG, FFLP_FLOW_KEY_IP_USR6_REG,
	FFLP_FLOW_KEY_IP_USR7_REG, FFLP_FLOW_KEY_IP4_TCP_REG,
	FFLP_FLOW_KEY_IP4_UDP_REG, FFLP_FLOW_KEY_IP4_AH_ESP_REG,
	FFLP_FLOW_KEY_IP4_SCTP_REG, FFLP_FLOW_KEY_IP6_TCP_REG,
	FFLP_FLOW_KEY_IP6_UDP_REG, FFLP_FLOW_KEY_IP6_AH_ESP_REG,
	FFLP_FLOW_KEY_IP6_SCTP_REG, FFLP_H1POLY_REG, FFLP_H2POLY_REG,
	FFLP_FLW_PRT_SEL_REG
};

const char *fflp_fzc_name[] = {
	"FFLP_ENET_VLAN_TBL_REG", "FFLP_L2_CLS_ENET1_REG",
	"FFLP_L2_CLS_ENET2_REG", "FFLP_TCAM_KEY_IP_USR4_REG",
	"FFLP_TCAM_KEY_IP_USR5_REG", "FFLP_TCAM_KEY_IP_USR6_REG",
	"FFLP_TCAM_KEY_IP_USR7_REG", "FFLP_TCAM_KEY_IP4_TCP_REG",
	"FFLP_TCAM_KEY_IP4_UDP_REG", "FFLP_TCAM_KEY_IP4_AH_ESP_REG",
	"FFLP_TCAM_KEY_IP4_SCTP_REG", "FFLP_TCAM_KEY_IP6_TCP_REG",
	"FFLP_TCAM_KEY_IP6_UDP_REG", "FFLP_TCAM_KEY_IP6_AH_ESP_REG",
	"FFLP_TCAM_KEY_IP6_SCTP_REG", "FFLP_TCAM_KEY_0_REG",
	"FFLP_TCAM_KEY_1_REG", "FFLP_TCAM_KEY_2_REG", "FFLP_TCAM_KEY_3_REG",
	"FFLP_TCAM_MASK_0_REG", "FFLP_TCAM_MASK_1_REG", "FFLP_TCAM_MASK_2_REG",
	"FFLP_TCAM_MASK_3_REG", "FFLP_TCAM_CTL_REG", "FFLP_VLAN_PAR_ERR_REG",
	"FFLP_TCAM_ERR_REG", "HASH_LKUP_ERR_LOG1_REG",
	"HASH_LKUP_ERR_LOG2_REG", "FFLP_FCRAM_ERR_TST0_REG",
	"FFLP_FCRAM_ERR_TST1_REG", "FFLP_FCRAM_ERR_TST2_REG",
	"FFLP_ERR_MSK_REG", "FFLP_CFG_1_REG", "FFLP_DBG_TRAIN_VCT_REG",
	"FFLP_TCP_CFLAG_MSK_REG", "FFLP_FCRAM_REF_TMR_REG",
	"FFLP_FLOW_KEY_IP_USR4_REG", "FFLP_FLOW_KEY_IP_USR5_REG",
	"FFLP_FLOW_KEY_IP_USR6_REG", "FFLP_FLOW_KEY_IP_USR7_REG",
	"FFLP_FLOW_KEY_IP4_TCP_REG", "FFLP_FLOW_KEY_IP4_UDP_REG",
	"FFLP_FLOW_KEY_IP4_AH_ESP_REG", "FFLP_FLOW_KEY_IP4_SCTP_REG",
	"FFLP_FLOW_KEY_IP6_TCP_REG", "FFLP_FLOW_KEY_IP6_UDP_REG",
	"FFLP_FLOW_KEY_IP6_AH_ESP_REG",
	"FFLP_FLOW_KEY_IP6_SCTP_REG", "FFLP_H1POLY_REG", "FFLP_H2POLY_REG",
	"FFLP_FLW_PRT_SEL_REG"
};

uint64_t fflp_reg_offset[] = {
	FFLP_HASH_TBL_ADDR_REG, FFLP_HASH_TBL_DATA_REG,
	FFLP_HASH_TBL_DATA_LOG_REG
};

const char *fflp_reg_name[] = {
	"FFLP_HASH_TBL_ADDR_REG", "FFLP_HASH_TBL_DATA_REG",
	"FFLP_HASH_TBL_DATA_LOG_REG"
};




npi_status_t
npi_fflp_dump_regs(npi_handle_t handle)
{

	uint64_t value;
	int num_regs, i;

	num_regs = sizeof (fflp_fzc_offset) / sizeof (uint64_t);
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nFFLP_FZC Register Dump \n"));
	for (i = 0; i < num_regs; i++) {
		REG_PIO_READ64(handle, fflp_fzc_offset[i], &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    " %8llx %s\t %8llx \n",
		    fflp_fzc_offset[i], fflp_fzc_name[i], value));

	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nFFLP Register Dump\n"));
	num_regs = sizeof (fflp_reg_offset) / sizeof (uint64_t);

	for (i = 0; i < num_regs; i++) {
		REG_PIO_READ64(handle, fflp_reg_offset[i], &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    " %8llx %s\t %8llx \n",
		    fflp_reg_offset[i], fflp_reg_name[i], value));

	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n FFLP Register Dump done\n"));

	return (NPI_SUCCESS);
}

void
npi_fflp_vlan_tbl_dump(npi_handle_t handle)
{
	uint64_t offset;
	vlan_id_t vlan_id;
	uint64_t value;
	vlan_id_t start = 0, stop = NXGE_MAX_VLANS;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nVlan Table Dump \n"));

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "VID\t Offset\t Value\n"));

	for (vlan_id = start; vlan_id < stop; vlan_id++) {
		offset = FFLP_VLAN_OFFSET(vlan_id, FFLP_ENET_VLAN_TBL_REG);
		REG_PIO_READ64(handle, offset, &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "%x\t %llx\t %llx\n", vlan_id, offset, value));
	}

}

static uint64_t
npi_fflp_tcam_check_completion(npi_handle_t handle, tcam_op_t op_type);

/*
 * npi_fflp_tcam_check_completion()
 * Returns TCAM completion status.
 *
 * Input:
 *           op_type :        Read, Write, Compare
 *           handle  :        OS specific handle
 *
 * Output:
 *        For Read and write operations:
 *        0   Successful
 *        -1  Fail/timeout
 *
 *       For Compare operations (debug only )
 *        TCAM_REG_CTL read value    on success
 *                     value contains match location
 *        NPI_TCAM_COMP_NO_MATCH          no match
 *
 */
static uint64_t
npi_fflp_tcam_check_completion(npi_handle_t handle, tcam_op_t op_type)
{

	uint32_t try_counter, tcam_delay = 10;
	tcam_ctl_t tctl;

	try_counter = TCAM_COMPLETION_TRY_COUNT;

	switch (op_type) {
	case TCAM_RWC_STAT:

		READ_TCAM_REG_CTL(handle, &tctl.value);
		while ((try_counter) &&
		    (tctl.bits.ldw.stat != TCAM_CTL_RWC_RWC_STAT)) {
			try_counter--;
			NXGE_DELAY(tcam_delay);
			READ_TCAM_REG_CTL(handle, &tctl.value);
		}

		if (!try_counter) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " TCAM RWC_STAT operation"
			    " failed to complete \n"));
			return (NPI_FFLP_TCAM_HW_ERROR);
		}

		tctl.value = 0;
		break;

	case TCAM_RWC_MATCH:
		READ_TCAM_REG_CTL(handle, &tctl.value);

		while ((try_counter) &&
		    (tctl.bits.ldw.match != TCAM_CTL_RWC_RWC_MATCH)) {
			try_counter--;
			NXGE_DELAY(tcam_delay);
			READ_TCAM_REG_CTL(handle, &tctl.value);
		}

		if (!try_counter) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " TCAM Match operation"
			    "failed to find match \n"));
			tctl.value = NPI_TCAM_COMP_NO_MATCH;
		}


		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		" Invalid TCAM completion Request \n"));
		return (NPI_FFLP_ERROR |
		    NPI_TCAM_ERROR | OPCODE_INVALID);
	}

	return (tctl.value);
}

/*
 * npi_fflp_tcam_entry_invalidate()
 *
 * invalidates entry at tcam location
 *
 * Input
 * handle  :        OS specific handle
 * location	:	TCAM location
 *
 * Return
 *   NPI_SUCCESS
 *   NPI_FFLP_TCAM_HW_ERROR
 *
 */
npi_status_t
npi_fflp_tcam_entry_invalidate(npi_handle_t handle, tcam_location_t location)
{

	tcam_ctl_t tctl, tctl_stat;

/*
 * Need to write zero to class field.
 * Class field is bits [195:191].
 * This corresponds to TCAM key 0 register
 *
 */


	WRITE_TCAM_REG_MASK0(handle, 0xffULL);
	WRITE_TCAM_REG_KEY0(handle, 0x0ULL);
	tctl.value = 0;
	tctl.bits.ldw.location = location;
	tctl.bits.ldw.rwc = TCAM_CTL_RWC_TCAM_WR;

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tctl_stat.value = npi_fflp_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tctl_stat.value & NPI_FAILURE)
		return (NPI_FFLP_TCAM_HW_ERROR);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_tcam_entry_match()
 *
 * lookup a tcam entry in the TCAM
 *
 * Input
 * handle  :        OS specific handle
 * tcam_ptr   :     TCAM entry ptr
 *
 * Return
 *
 *	 NPI_FAILURE | NPI_XX_ERROR:	     Operational Error (HW etc ...)
 *	 NPI_TCAM_NO_MATCH:		     no match
 *	 0 - TCAM_SIZE:			     matching entry location (if match)
 */
int
npi_fflp_tcam_entry_match(npi_handle_t handle,  tcam_entry_t *tcam_ptr)
{

	uint64_t tcam_stat = 0;
	tcam_ctl_t tctl, tctl_stat;

	WRITE_TCAM_REG_MASK0(handle, tcam_ptr->mask0);
	WRITE_TCAM_REG_MASK1(handle, tcam_ptr->mask1);
	WRITE_TCAM_REG_MASK2(handle, tcam_ptr->mask2);
	WRITE_TCAM_REG_MASK3(handle, tcam_ptr->mask3);

	WRITE_TCAM_REG_KEY0(handle, tcam_ptr->key0);
	WRITE_TCAM_REG_KEY1(handle, tcam_ptr->key1);
	WRITE_TCAM_REG_KEY2(handle, tcam_ptr->key2);
	WRITE_TCAM_REG_KEY3(handle, tcam_ptr->key3);

	tctl.value = 0;
	tctl.bits.ldw.rwc = TCAM_CTL_RWC_TCAM_CMP;

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tcam_stat = npi_fflp_tcam_check_completion(handle, TCAM_RWC_STAT);
	if (tcam_stat & NPI_FAILURE) {
		return ((uint32_t)tcam_stat);
	}

	tctl_stat.value = npi_fflp_tcam_check_completion(handle,
	    TCAM_RWC_MATCH);

	if (tctl_stat.bits.ldw.match == TCAM_CTL_RWC_RWC_MATCH) {
		return (uint32_t)(tctl_stat.bits.ldw.location);
	}

	return ((uint32_t)tctl_stat.value);

}

/*
 * npi_fflp_tcam_entry_read ()
 *
 * Reads a tcam entry from the TCAM location, location
 *
 * Input:
 * handle  :        OS specific handle
 * location  :		TCAM location
 * tcam_ptr  :		TCAM entry pointer
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FFLP_TCAM_RD_ERROR
 *
 */
npi_status_t
npi_fflp_tcam_entry_read(npi_handle_t handle,
						    tcam_location_t location,
						    struct tcam_entry *tcam_ptr)
{

	uint64_t tcam_stat;
	tcam_ctl_t tctl;

	tctl.value = 0;
	tctl.bits.ldw.location = location;
	tctl.bits.ldw.rwc = TCAM_CTL_RWC_TCAM_RD;

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tcam_stat = npi_fflp_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & NPI_FAILURE) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "TCAM read failed loc %d \n", location));
		return (NPI_FFLP_TCAM_RD_ERROR);
	}

	READ_TCAM_REG_MASK0(handle, &tcam_ptr->mask0);
	READ_TCAM_REG_MASK1(handle, &tcam_ptr->mask1);
	READ_TCAM_REG_MASK2(handle, &tcam_ptr->mask2);
	READ_TCAM_REG_MASK3(handle, &tcam_ptr->mask3);

	READ_TCAM_REG_KEY0(handle, &tcam_ptr->key0);
	READ_TCAM_REG_KEY1(handle, &tcam_ptr->key1);
	READ_TCAM_REG_KEY2(handle, &tcam_ptr->key2);
	READ_TCAM_REG_KEY3(handle, &tcam_ptr->key3);

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_tcam_entry_write()
 *
 * writes a tcam entry to the TCAM location, location
 *
 * Input:
 * handle  :        OS specific handle
 * location :	TCAM location
 * tcam_ptr :	TCAM entry pointer
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FFLP_TCAM_WR_ERROR
 *
 */
npi_status_t
npi_fflp_tcam_entry_write(npi_handle_t handle,
			    tcam_location_t location,
			    tcam_entry_t *tcam_ptr)
{

	uint64_t tcam_stat;

	tcam_ctl_t tctl;

	WRITE_TCAM_REG_MASK0(handle, tcam_ptr->mask0);
	WRITE_TCAM_REG_MASK1(handle, tcam_ptr->mask1);
	WRITE_TCAM_REG_MASK2(handle, tcam_ptr->mask2);
	WRITE_TCAM_REG_MASK3(handle, tcam_ptr->mask3);

	WRITE_TCAM_REG_KEY0(handle, tcam_ptr->key0);
	WRITE_TCAM_REG_KEY1(handle, tcam_ptr->key1);
	WRITE_TCAM_REG_KEY2(handle, tcam_ptr->key2);
	WRITE_TCAM_REG_KEY3(handle, tcam_ptr->key3);

	NPI_DEBUG_MSG((handle.function, NPI_FFLP_CTL,
	    " tcam write: location %x\n"
	    " key:  %llx %llx %llx %llx \n"
	    " mask: %llx %llx %llx %llx \n",
	    location, tcam_ptr->key0, tcam_ptr->key1,
	    tcam_ptr->key2, tcam_ptr->key3,
	    tcam_ptr->mask0, tcam_ptr->mask1,
	    tcam_ptr->mask2, tcam_ptr->mask3));
	tctl.value = 0;
	tctl.bits.ldw.location = location;
	tctl.bits.ldw.rwc = TCAM_CTL_RWC_TCAM_WR;
	NPI_DEBUG_MSG((handle.function, NPI_FFLP_CTL,
	    " tcam write: ctl value %llx \n", tctl.value));
	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tcam_stat = npi_fflp_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & NPI_FAILURE) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "TCAM Write failed loc %d \n", location));
		return (NPI_FFLP_TCAM_WR_ERROR);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_tcam_asc_ram_entry_write()
 *
 * writes a tcam associatedRAM at the TCAM location, location
 *
 * Input:
 * handle  :        OS specific handle
 * location :	tcam associatedRAM location
 * ram_data :	Value to write
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FFLP_ASC_RAM_WR_ERROR
 *
 */
npi_status_t
npi_fflp_tcam_asc_ram_entry_write(npi_handle_t handle,
				    tcam_location_t location,
				    uint64_t ram_data)
{

	uint64_t tcam_stat = 0;
	tcam_ctl_t tctl;


	WRITE_TCAM_REG_KEY1(handle, ram_data);

	tctl.value = 0;
	tctl.bits.ldw.location = location;
	tctl.bits.ldw.rwc = TCAM_CTL_RWC_RAM_WR;

	NPI_DEBUG_MSG((handle.function, NPI_FFLP_CTL,
	    " tcam ascr write: location %x data %llx ctl value %llx \n",
	    location, ram_data, tctl.value));
	WRITE_TCAM_REG_CTL(handle, tctl.value);
	tcam_stat = npi_fflp_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & NPI_FAILURE) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "TCAM RAM write failed loc %d \n", location));
		return (NPI_FFLP_ASC_RAM_WR_ERROR);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_tcam_asc_ram_entry_read()
 *
 * reads a tcam associatedRAM content at the TCAM location, location
 *
 * Input:
 * handle  :        OS specific handle
 * location :	tcam associatedRAM location
 * ram_data :	ptr to return contents
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FFLP_ASC_RAM_RD_ERROR
 *
 */
npi_status_t
npi_fflp_tcam_asc_ram_entry_read(npi_handle_t handle,
				    tcam_location_t location,
				    uint64_t *ram_data)
{

	uint64_t tcam_stat;
	tcam_ctl_t tctl;


	tctl.value = 0;
	tctl.bits.ldw.location = location;
	tctl.bits.ldw.rwc = TCAM_CTL_RWC_RAM_RD;

	WRITE_TCAM_REG_CTL(handle, tctl.value);

	tcam_stat = npi_fflp_tcam_check_completion(handle, TCAM_RWC_STAT);

	if (tcam_stat & NPI_FAILURE) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "TCAM RAM read failed loc %d \n", location));
		return (NPI_FFLP_ASC_RAM_RD_ERROR);
	}

	READ_TCAM_REG_KEY1(handle, ram_data);

	return (NPI_SUCCESS);
}

/* FFLP FCRAM Related functions */
/* The following are FCRAM datapath functions */

/*
 * npi_fflp_fcram_entry_write ()
 * Populates an FCRAM entry
 * Inputs:
 *         handle:	opaque handle interpreted by the underlying OS
 *	   partid:	Partition ID
 *	   location:	Index to the FCRAM.
 *			 Corresponds to last 20 bits of H1 value
 *	   fcram_ptr:	Pointer to the FCRAM contents to be used for writing
 *	   format:	Entry Format. Determines the size of the write.
 *			      FCRAM_ENTRY_OPTIM:   8 bytes (a 64 bit write)
 *			      FCRAM_ENTRY_EX_IP4:  32 bytes (4 X 64 bit write)
 *			      FCRAM_ENTRY_EX_IP6:  56 bytes (7 X 64 bit write)
 *
 * Outputs:
 *         NPI success/failure status code
 */
npi_status_t
npi_fflp_fcram_entry_write(npi_handle_t handle, part_id_t partid,
			    uint32_t location, fcram_entry_t *fcram_ptr,
			    fcram_entry_format_t format)

{

	int num_subareas = 0;
	uint64_t addr_reg, data_reg;
	int subarea;
	int autoinc;
	hash_tbl_addr_t addr;
	switch (format) {
	case FCRAM_ENTRY_OPTIM:
		if (location % 8) {
		/* need to be 8 byte alligned */

			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " FCRAM_ENTRY_OOPTIM Write:"
				    " unaligned location %llx \n",
				    location));

			return (NPI_FFLP_FCRAM_LOC_INVALID);
	}

	num_subareas = 1;
	autoinc = 0;
	break;

	case FCRAM_ENTRY_EX_IP4:
		if (location % 32) {
/* need to be 32 byte alligned */
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " FCRAM_ENTRY_EX_IP4 Write:"
			    " unaligned location %llx \n",
			    location));
			return (NPI_FFLP_FCRAM_LOC_INVALID);
	}

	num_subareas = 4;
	autoinc = 1;

	break;
	case FCRAM_ENTRY_EX_IP6:
		if (location % 64) {
				/* need to be 64 byte alligned */
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " FCRAM_ENTRY_EX_IP6 Write:"
				    " unaligned location %llx \n",
				    location));
				return (NPI_FFLP_FCRAM_LOC_INVALID);

		}
		num_subareas = 7;
		autoinc = 1;
			break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " fcram_entry_write:"
			    " unknown format param location %llx\n",
			    location));
		return (NPI_FFLP_ERROR | NPI_FCRAM_ERROR | OPCODE_INVALID);
	}

	addr.value = 0;
	addr.bits.ldw.autoinc = autoinc;
	addr.bits.ldw.addr = location;
	addr_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
					    FFLP_HASH_TBL_ADDR_REG);
	data_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
					    FFLP_HASH_TBL_DATA_REG);
/* write to addr reg */
	REG_PIO_WRITE64(handle, addr_reg, addr.value);
/* write data to the data register */

	for (subarea = 0; subarea < num_subareas; subarea++) {
		REG_PIO_WRITE64(handle, data_reg, fcram_ptr->value[subarea]);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_fcram_read_read ()
 * Reads an FCRAM entry
 * Inputs:
 *         handle:	opaque handle interpreted by the underlying OS
 *	   partid:	Partition ID
 *	   location:	Index to the FCRAM.
 *                  Corresponds to last 20 bits of H1 value
 *
 *	   fcram_ptr:	Pointer to the FCRAM contents to be updated
 *	   format:	Entry Format. Determines the size of the read.
 *			      FCRAM_ENTRY_OPTIM:   8 bytes (a 64 bit read)
 *			      FCRAM_ENTRY_EX_IP4:  32 bytes (4 X 64 bit read )
 *			      FCRAM_ENTRY_EX_IP6:  56 bytes (7 X 64 bit read )
 * Return:
 * NPI Success/Failure status code
 *
 */
npi_status_t
npi_fflp_fcram_entry_read(npi_handle_t handle,  part_id_t partid,
			    uint32_t location, fcram_entry_t *fcram_ptr,
			    fcram_entry_format_t format)
{

	int num_subareas = 0;
	uint64_t addr_reg, data_reg;
	int subarea, autoinc;
	hash_tbl_addr_t addr;
	switch (format) {
		case FCRAM_ENTRY_OPTIM:
			if (location % 8) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " FCRAM_ENTRY_OOPTIM Read:"
			    " unaligned location %llx \n",
			    location));
			/* need to be 8 byte alligned */
				return (NPI_FFLP_FCRAM_LOC_INVALID);
			}
			num_subareas = 1;
			autoinc = 0;
			break;
		case FCRAM_ENTRY_EX_IP4:
			if (location % 32) {
					/* need to be 32 byte alligned */
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " FCRAM_ENTRY_EX_IP4 READ:"
			    " unaligned location %llx \n",
			    location));
				return (NPI_FFLP_FCRAM_LOC_INVALID);
			}
			num_subareas = 4;
			autoinc = 1;

			break;
		case FCRAM_ENTRY_EX_IP6:
			if (location % 64) {
					/* need to be 64 byte alligned */
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " FCRAM_ENTRY_EX_IP6 READ:"
			    " unaligned location %llx \n",
			    location));

				return (NPI_FFLP_FCRAM_LOC_INVALID);
	}
			num_subareas = 7;
			autoinc = 1;

			break;
		default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fcram_entry_read:"
		    " unknown format param location %llx\n",
		    location));
		return (NPI_FFLP_SW_PARAM_ERROR);
	}

	addr.value = 0;
	addr.bits.ldw.autoinc = autoinc;
	addr.bits.ldw.addr = location;
	addr_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
	    FFLP_HASH_TBL_ADDR_REG);
	data_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
	    FFLP_HASH_TBL_DATA_REG);
/* write to addr reg */
	REG_PIO_WRITE64(handle, addr_reg, addr.value);
/* read data from the data register */
	for (subarea = 0; subarea < num_subareas; subarea++) {
		REG_PIO_READ64(handle, data_reg, &fcram_ptr->value[subarea]);
	}


	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_entry_invalidate ()
 * Invalidate FCRAM entry at the given location
 * Inputs:
 *	handle:		opaque handle interpreted by the underlying OS
 *	partid:		Partition ID
 *	location:	location of the FCRAM/hash entry.
 *
 * Return:
 * NPI Success/Failure status code
 */
npi_status_t
npi_fflp_fcram_entry_invalidate(npi_handle_t handle, part_id_t partid,
				    uint32_t location)
{

	hash_tbl_addr_t addr;
	uint64_t addr_reg, data_reg;
	hash_hdr_t	   hdr;


	if (location % 8) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " FCRAM_ENTRY_Invalidate:"
		    " unaligned location %llx \n",
		    location));
			/* need to be 8 byte aligned */
		return (NPI_FFLP_FCRAM_LOC_INVALID);
	}

	addr.value = 0;
	addr.bits.ldw.addr = location;
	addr_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
	    FFLP_HASH_TBL_ADDR_REG);
	data_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
	    FFLP_HASH_TBL_DATA_REG);

/* write to addr reg */
	REG_PIO_WRITE64(handle, addr_reg, addr.value);

	REG_PIO_READ64(handle, data_reg, &hdr.value);
	hdr.exact_hdr.valid = 0;
	REG_PIO_WRITE64(handle, data_reg, hdr.value);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_write_subarea ()
 * Writes to FCRAM entry subarea i.e the 8 bytes within the 64 bytes
 * pointed by the  last 20 bits of  H1. Effectively, this accesses
 * specific 8 bytes within the hash table bucket.
 *
 *  H1-->  |-----------------|
 *	   |	subarea 0    |
 *	   |_________________|
 *	   | Subarea 1	     |
 *	   |_________________|
 *	   | .......	     |
 *	   |_________________|
 *	   | Subarea 7       |
 *	   |_________________|
 *
 * Inputs:
 *         handle:	opaque handle interpreted by the underlying OS
 *	   partid:	Partition ID
 *	   location:	location of the subarea. It is derived from:
 *			Bucket = [19:15][14:0]       (20 bits of H1)
 *			location = (Bucket << 3 ) + subarea * 8
 *				 = [22:18][17:3] || subarea * 8
 *	   data:	Data
 *
 * Return:
 * NPI Success/Failure status code
 */
npi_status_t
npi_fflp_fcram_subarea_write(npi_handle_t handle, part_id_t partid,
			    uint32_t location, uint64_t data)
{

	hash_tbl_addr_t addr;
	uint64_t addr_reg, data_reg;


	if (location % 8) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fcram_subarea_write:"
		    " unaligned location %llx \n",
		    location));
			/* need to be 8 byte alligned */
		return (NPI_FFLP_FCRAM_LOC_INVALID);
	}

	addr.value = 0;
	addr.bits.ldw.addr = location;
	addr_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
	    FFLP_HASH_TBL_ADDR_REG);
	data_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
	    FFLP_HASH_TBL_DATA_REG);

/* write to addr reg */
	REG_PIO_WRITE64(handle, addr_reg, addr.value);
	REG_PIO_WRITE64(handle, data_reg, data);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_subarea_read ()
 * Reads an FCRAM entry subarea i.e the 8 bytes within the 64 bytes
 * pointed by  the last 20 bits of  H1. Effectively, this accesses
 * specific 8 bytes within the hash table bucket.
 *
 *  H1-->  |-----------------|
 *	   |	subarea 0    |
 *	   |_________________|
 *	   | Subarea 1	     |
 *	   |_________________|
 *	   | .......	     |
 *	   |_________________|
 *	   | Subarea 7       |
 *	   |_________________|
 *
 * Inputs:
 *         handle:	opaque handle interpreted by the underlying OS
 *	   partid:	Partition ID
 *	   location:	location of the subarea. It is derived from:
 *			Bucket = [19:15][14:0]       (20 bits of H1)
 *			location = (Bucket << 3 ) + subarea * 8
 *				 = [22:18][17:3] || subarea * 8
 *	   data:	ptr do write subarea contents to.
 *
 * Return:
 * NPI Success/Failure status code
 */
npi_status_t
npi_fflp_fcram_subarea_read(npi_handle_t handle, part_id_t partid,
			    uint32_t location, uint64_t *data)

{

	hash_tbl_addr_t addr;
	uint64_t addr_reg, data_reg;

	if (location % 8) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " fcram_subarea_read:"
				    " unaligned location %llx \n",
				    location));
			/* need to be 8 byte alligned */
		return (NPI_FFLP_FCRAM_LOC_INVALID);
	}

	addr.value = 0;
	addr.bits.ldw.addr = location;
	addr_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
						    FFLP_HASH_TBL_ADDR_REG);
	data_reg = GET_HASHTBL_PART_OFFSET(handle, partid,
						    FFLP_HASH_TBL_DATA_REG);

/* write to addr reg */
	REG_PIO_WRITE64(handle, addr_reg, addr.value);
	REG_PIO_READ64(handle, data_reg, data);

	return (NPI_SUCCESS);

}

/*
 * The following are zero function fflp configuration functions.
 */

/*
 * npi_fflp_fcram_config_partition()
 * Partitions and configures the FCRAM
 */
npi_status_t
npi_fflp_cfg_fcram_partition(npi_handle_t handle, part_id_t partid,
				    uint8_t base_mask, uint8_t base_reloc)

{
/*
 * assumes that the base mask and relocation are computed somewhere
 * and kept in the state data structure. Alternativiely, one can pass
 * a partition size and a starting address and this routine can compute
 * the mask and reloc vlaues.
 */

    flow_prt_sel_t sel;
    uint64_t offset;

    ASSERT(FCRAM_PARTITION_VALID(partid));
	if (!FCRAM_PARTITION_VALID(partid)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " npi_fflp_cfg_fcram_partition:"
				    " Invalid Partition %d \n",
				    partid));
		return (NPI_FFLP_FCRAM_PART_INVALID);
	}

    offset = FFLP_PART_OFFSET(partid, FFLP_FLW_PRT_SEL_REG);
    sel.value = 0;
    sel.bits.ldw.mask = base_mask;
    sel.bits.ldw.base = base_reloc;
    sel.bits.ldw.ext = BIT_DISABLE; /* disable */
    REG_PIO_WRITE64(handle, offset, sel.value);
    return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_partition_enable
 * Enable previously configured FCRAM partition
 *
 * Input
 *         handle:	opaque handle interpreted by the underlying OS
 *         partid:	 partition ID, Corresponds to the RDC table
 *
 * Return
 *      0			Successful
 *      Non zero  error code    Enable failed, and reason.
 *
 */
npi_status_t
npi_fflp_cfg_fcram_partition_enable  (npi_handle_t handle, part_id_t partid)

{

    flow_prt_sel_t sel;
    uint64_t offset;

    ASSERT(FCRAM_PARTITION_VALID(partid));
    if (!FCRAM_PARTITION_VALID(partid)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " fcram_partition enable:"
				    " Invalid Partition %d \n",
				    partid));
		return (NPI_FFLP_FCRAM_PART_INVALID);
	}

    offset = FFLP_PART_OFFSET(partid, FFLP_FLW_PRT_SEL_REG);

    REG_PIO_READ64(handle, offset, &sel.value);
    sel.bits.ldw.ext = BIT_ENABLE; /* enable */
    REG_PIO_WRITE64(handle, offset, sel.value);

    return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_partition_disable
 * Disable previously configured FCRAM partition
 *
 * Input
 *         handle:	opaque handle interpreted by the underlying OS
 *         partid:	partition ID, Corresponds to the RDC table
 *
 * Return:
 * NPI Success/Failure status code
 */
npi_status_t
npi_fflp_cfg_fcram_partition_disable(npi_handle_t handle, part_id_t partid)

{

	flow_prt_sel_t sel;
	uint64_t offset;

	ASSERT(FCRAM_PARTITION_VALID(partid));
	if (!FCRAM_PARTITION_VALID(partid)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " fcram_partition disable:"
				    " Invalid Partition %d \n",
				    partid));
		return (NPI_FFLP_FCRAM_PART_INVALID);
	}
	offset = FFLP_PART_OFFSET(partid, FFLP_FLW_PRT_SEL_REG);
	REG_PIO_READ64(handle, offset, &sel.value);
	sel.bits.ldw.ext = BIT_DISABLE; /* disable */
	REG_PIO_WRITE64(handle, offset, sel.value);
	return (NPI_SUCCESS);
}

/*
 *  npi_fflp_cam_errorcheck_disable
 *  Disables FCRAM and TCAM error checking
 */
npi_status_t
npi_fflp_cfg_cam_errorcheck_disable(npi_handle_t handle)

{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);

	fflp_cfg.bits.ldw.errordis = BIT_ENABLE;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	return (NPI_SUCCESS);

}

/*
 *  npi_fflp_cam_errorcheck_enable
 *  Enables FCRAM and TCAM error checking
 */
npi_status_t
npi_fflp_cfg_cam_errorcheck_enable(npi_handle_t handle)

{
	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);

	fflp_cfg.bits.ldw.errordis = BIT_DISABLE;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	return (NPI_SUCCESS);

}

/*
 *  npi_fflp_cam_llcsnap_enable
 *  Enables input parser llcsnap recognition
 */
npi_status_t
npi_fflp_cfg_llcsnap_enable(npi_handle_t handle)

{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);

	fflp_cfg.bits.ldw.llcsnap = BIT_ENABLE;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	return (NPI_SUCCESS);

}

/*
 *  npi_fflp_cam_llcsnap_disable
 *  Disables input parser llcsnap recognition
 */
npi_status_t
npi_fflp_cfg_llcsnap_disable(npi_handle_t handle)

{


	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);

	fflp_cfg.bits.ldw.llcsnap = BIT_DISABLE;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_config_fcram_refresh
 * Set FCRAM min and max refresh time.
 *
 * Input
 *      handle			opaque handle interpreted by the underlying OS
 *	min_time		Minimum Refresh time count
 *	max_time		maximum Refresh Time count
 *	sys_time		System Clock rate
 *
 *	The counters are 16 bit counters. The maximum refresh time is
 *      3.9us/clock cycle. The minimum is 400ns/clock cycle.
 *	Clock cycle is the FCRAM clock cycle?????
 *	If the cycle is FCRAM clock cycle, then sys_time parameter
 *      is not needed as there wont be configuration variation due to
 *      system clock cycle.
 *
 * Return:
 * NPI Success/Failure status code
 */
npi_status_t
npi_fflp_cfg_fcram_refresh_time(npi_handle_t handle, uint32_t min_time,
				    uint32_t max_time, uint32_t sys_time)

{

	uint64_t offset;
	fcram_ref_tmr_t refresh_timer_reg;
	uint16_t max, min;

	offset = FFLP_FCRAM_REF_TMR_REG;
/* need to figure out how to dervive the numbers */
	max = max_time * sys_time;
	min = min_time * sys_time;
/* for now, just set with #def values */

	max = FCRAM_REFRESH_DEFAULT_MAX_TIME;
	min = FCRAM_REFRESH_DEFAULT_MIN_TIME;
	REG_PIO_READ64(handle, offset, &refresh_timer_reg.value);
	refresh_timer_reg.bits.ldw.min = min;
	refresh_timer_reg.bits.ldw.max = max;
	REG_PIO_WRITE64(handle, offset, refresh_timer_reg.value);
	return (NPI_SUCCESS);
}

/*
 *  npi_fflp_hash_lookup_err_report
 *  Reports hash table (fcram) lookup errors
 *
 *  Input
 *      handle			opaque handle interpreted by the underlying OS
 *      err_stat		Pointer to return Error bits
 *
 *
 * Return:
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_fcram_get_lookup_err_log(npi_handle_t handle,
				    hash_lookup_err_log_t *err_stat)

{

	hash_lookup_err_log1_t err_log1;
	hash_lookup_err_log2_t err_log2;
	uint64_t  err_log1_offset, err_log2_offset;
	err_log1.value = 0;
	err_log2.value = 0;

	err_log1_offset = HASH_LKUP_ERR_LOG1_REG;
	err_log2_offset = HASH_LKUP_ERR_LOG2_REG;

	REG_PIO_READ64(handle, err_log1_offset, &err_log1.value);
	REG_PIO_READ64(handle, err_log2_offset, &err_log2.value);

	if (err_log1.value) {
/* nonzero means there are some errors */
		err_stat->lookup_err = BIT_ENABLE;
		err_stat->syndrome = err_log2.bits.ldw.syndrome;
		err_stat->subarea = err_log2.bits.ldw.subarea;
		err_stat->h1 = err_log2.bits.ldw.h1;
		err_stat->multi_bit = err_log1.bits.ldw.mult_bit;
		err_stat->multi_lkup = err_log1.bits.ldw.mult_lk;
		err_stat->ecc_err = err_log1.bits.ldw.ecc_err;
		err_stat->uncor_err = err_log1.bits.ldw.cu;
	} else {
		err_stat->lookup_err = BIT_DISABLE;
	}

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_get_pio_err_log
 * Reports hash table PIO read errors for the given partition.
 * by default, it clears the error bit which was set by the HW.
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *	partid:		partition ID
 *      err_stat	Pointer to return Error bits
 *
 * Return
 *	NPI success/failure status code
 */
npi_status_t
npi_fflp_fcram_get_pio_err_log(npi_handle_t handle, part_id_t partid,
				    hash_pio_err_log_t *err_stat)
{

	hash_tbl_data_log_t err_log;
	uint64_t offset;

	ASSERT(FCRAM_PARTITION_VALID(partid));
	if (!FCRAM_PARTITION_VALID(partid)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fcram_get_pio_err_log:"
		    " Invalid Partition %d \n",
		    partid));
		return (NPI_FFLP_FCRAM_PART_INVALID);
	}

	offset = GET_HASHTBL_PART_OFFSET_NVIR(partid,
	    FFLP_HASH_TBL_DATA_LOG_REG);

	REG_PIO_READ64(handle, offset, &err_log.value);

	if (err_log.bits.ldw.pio_err == BIT_ENABLE) {
/* nonzero means there are some errors */
		err_stat->pio_err = BIT_ENABLE;
		err_stat->syndrome = err_log.bits.ldw.syndrome;
		err_stat->addr = err_log.bits.ldw.fcram_addr;
		err_log.value = 0;
		REG_PIO_WRITE64(handle, offset, err_log.value);
	} else {
		err_stat->pio_err = BIT_DISABLE;
	}

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_clr_pio_err_log
 * Clears FCRAM PIO  error status for the partition.
 * If there are TCAM errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *	partid:		partition ID
 *
 *
 * Return
 *	NPI success/failure status code
 */
npi_status_t
npi_fflp_fcram_clr_pio_err_log(npi_handle_t handle, part_id_t partid)
{
	uint64_t offset;

	hash_tbl_data_log_t err_log;

	ASSERT(FCRAM_PARTITION_VALID(partid));
	if (!FCRAM_PARTITION_VALID(partid)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fcram_clr_pio_err_log:"
		    " Invalid Partition %d \n",
		    partid));

		return (NPI_FFLP_FCRAM_PART_INVALID);
	}

	offset = GET_HASHTBL_PART_OFFSET_NVIR(partid,
	    FFLP_HASH_TBL_DATA_LOG_REG);

	err_log.value = 0;
	REG_PIO_WRITE64(handle, offset, err_log.value);


	return (NPI_SUCCESS);

}

/*
 * npi_fflp_tcam_get_err_log
 * Reports TCAM PIO read and lookup errors.
 * If there are TCAM errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *	err_stat:	 structure to report various TCAM errors.
 *                       will be updated if there are TCAM errors.
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t
npi_fflp_tcam_get_err_log(npi_handle_t handle, tcam_err_log_t *err_stat)
{
	tcam_err_t err_log;
	uint64_t offset;

	offset = FFLP_TCAM_ERR_REG;
	err_log.value = 0;

	REG_PIO_READ64(handle, offset, &err_log.value);

	if (err_log.bits.ldw.err == BIT_ENABLE) {
/* non-zero means err */
		err_stat->tcam_err = BIT_ENABLE;
		if (err_log.bits.ldw.p_ecc) {
			err_stat->parity_err = 0;
			err_stat->ecc_err = 1;
		} else {
			err_stat->parity_err = 1;
			err_stat->ecc_err = 0;

		}
		err_stat->syndrome = err_log.bits.ldw.syndrome;
		err_stat->location = err_log.bits.ldw.addr;


		err_stat->multi_lkup = err_log.bits.ldw.mult;
			/* now clear the error */
		err_log.value = 0;
		REG_PIO_WRITE64(handle, offset, err_log.value);

	} else {
		err_stat->tcam_err = 0;
	}
	return (NPI_SUCCESS);

}

/*
 * npi_fflp_tcam_clr_err_log
 * Clears TCAM PIO read and lookup error status.
 * If there are TCAM errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *         handle:	opaque handle interpreted by the underlying OS
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t
npi_fflp_tcam_clr_err_log(npi_handle_t handle)
{
	tcam_err_t err_log;
	uint64_t offset;

	offset = FFLP_TCAM_ERR_REG;
	err_log.value = 0;
	REG_PIO_WRITE64(handle, offset, err_log.value);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_err_synd_test
 * Tests the FCRAM error detection logic.
 * The error detection logic for the syndrome is tested.
 * tst0->synd (8bits) are set to select the syndrome bits
 * to be XOR'ed
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *	syndrome_bits:	 Syndrome bits to select bits to be xor'ed
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t
npi_fflp_fcram_err_synd_test(npi_handle_t handle, uint8_t syndrome_bits)
{

	uint64_t t0_offset;
	fcram_err_tst0_t tst0;
	t0_offset = FFLP_FCRAM_ERR_TST0_REG;

	tst0.value = 0;
	tst0.bits.ldw.syndrome_mask = syndrome_bits;

	REG_PIO_WRITE64(handle, t0_offset, tst0.value);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_fcram_err_data_test
 * Tests the FCRAM error detection logic.
 * The error detection logic for the datapath is tested.
 * bits [63:0] are set to select the data bits to be xor'ed
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *	data:	 data bits to select bits to be xor'ed
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t
npi_fflp_fcram_err_data_test(npi_handle_t handle, fcram_err_data_t *data)
{

	uint64_t t1_offset, t2_offset;
	fcram_err_tst1_t tst1; /* for data bits [31:0] */
	fcram_err_tst2_t tst2; /* for data bits [63:32] */

	t1_offset = FFLP_FCRAM_ERR_TST1_REG;
	t2_offset = FFLP_FCRAM_ERR_TST2_REG;
	tst1.value = 0;
	tst2.value = 0;
	tst1.bits.ldw.dat = data->bits.ldw.dat;
	tst2.bits.ldw.dat = data->bits.hdw.dat;

	REG_PIO_WRITE64(handle, t1_offset, tst1.value);
	REG_PIO_WRITE64(handle, t2_offset, tst2.value);

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_enet_vlan_table_assoc
 * associates port vlan id to rdc table.
 *
 * Input
 *     handle			opaque handle interpreted by the underlying OS
 *     mac_portn		port number
 *     vlan_id			VLAN ID
 *     rdc_table		RDC Table #
 *     priority			priority
 *
 * Output
 *
 *	NPI success/failure status code
 *
 */
npi_status_t
npi_fflp_cfg_enet_vlan_table_assoc(npi_handle_t handle, uint8_t mac_portn,
				    vlan_id_t vlan_id, uint8_t rdc_table,
				    uint8_t priority)
{

	fflp_enet_vlan_tbl_t cfg;
	uint64_t offset;
	uint8_t vlan_parity[8] = {0, 1, 1, 2, 1, 2, 2, 3};
	uint8_t parity_bit;

	ASSERT(FFLP_VLAN_VALID(vlan_id));
	if (!FFLP_VLAN_VALID(vlan_id)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fflp_cfg_enet_vlan_table:"
		    " Invalid vlan ID %d \n",
		    vlan_id));
		return (NPI_FFLP_VLAN_INVALID);
	}

	ASSERT(FFLP_PORT_VALID(mac_portn));
	if (!FFLP_PORT_VALID(mac_portn)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fflp_cfg_enet_vlan_table:"
		    " Invalid port num %d \n",
		    mac_portn));
		return (NPI_FFLP_PORT_INVALID);
	}

	ASSERT(FFLP_RDC_TABLE_VALID(rdc_table));
	if (!FFLP_RDC_TABLE_VALID(rdc_table)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " fflp_cfg_enet_vlan_table:"
		    " Invalid RDC Table %d \n",
		    rdc_table));
		return (NPI_FFLP_RDC_TABLE_INVALID);
	}

	offset = FFLP_VLAN_OFFSET(vlan_id, FFLP_ENET_VLAN_TBL_REG);
	REG_PIO_READ64(handle, offset, &cfg.value);

	switch (mac_portn) {
		case 0:
			cfg.bits.ldw.vlanrdctbln0 = rdc_table;
			if (priority)
				cfg.bits.ldw.vpr0 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr0 = BIT_DISABLE;
				/* set the parity bits */
			parity_bit = vlan_parity[cfg.bits.ldw.vlanrdctbln0] +
			    vlan_parity[cfg.bits.ldw.vlanrdctbln1] +
			    cfg.bits.ldw.vpr0 + cfg.bits.ldw.vpr1;
			cfg.bits.ldw.parity0 = parity_bit & 0x1;
			break;
		case 1:
			cfg.bits.ldw.vlanrdctbln1 = rdc_table;
			if (priority)
				cfg.bits.ldw.vpr1 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr1 = BIT_DISABLE;
				/* set the parity bits */
			parity_bit = vlan_parity[cfg.bits.ldw.vlanrdctbln0] +
			    vlan_parity[cfg.bits.ldw.vlanrdctbln1] +
			    cfg.bits.ldw.vpr0 + cfg.bits.ldw.vpr1;
				cfg.bits.ldw.parity0 = parity_bit & 0x1;

			break;
		case 2:
			cfg.bits.ldw.vlanrdctbln2 = rdc_table;
			if (priority)
				cfg.bits.ldw.vpr2 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr2 = BIT_DISABLE;
				/* set the parity bits */
			parity_bit = vlan_parity[cfg.bits.ldw.vlanrdctbln2] +
			    vlan_parity[cfg.bits.ldw.vlanrdctbln3] +
			    cfg.bits.ldw.vpr2 + cfg.bits.ldw.vpr3;
			cfg.bits.ldw.parity1 = parity_bit & 0x1;

			break;
		case 3:
			cfg.bits.ldw.vlanrdctbln3 = rdc_table;
			if (priority)
				cfg.bits.ldw.vpr3 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr3 = BIT_DISABLE;
				/* set the parity bits */
			parity_bit = vlan_parity[cfg.bits.ldw.vlanrdctbln2] +
			    vlan_parity[cfg.bits.ldw.vlanrdctbln3] +
			    cfg.bits.ldw.vpr2 + cfg.bits.ldw.vpr3;
			cfg.bits.ldw.parity1 = parity_bit & 0x1;
			break;
		default:
			return (NPI_FFLP_SW_PARAM_ERROR);
	}

	REG_PIO_WRITE64(handle, offset, cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_enet_vlan_table_set_pri
 * sets the  vlan based classification priority in respect to L2DA
 * classification.
 *
 * Input
 *     handle		opaque handle interpreted by the underlying OS
 *     mac_portn	port number
 *     vlan_id		VLAN ID
 *     priority 	priority
 *			1: vlan classification has higher priority
 *			0: l2da classification has higher priority
 *
 * Output
 *
 *	NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_enet_vlan_table_set_pri(npi_handle_t handle, uint8_t mac_portn,
				    vlan_id_t vlan_id, uint8_t priority)
{

	fflp_enet_vlan_tbl_t cfg;
	uint64_t offset;
	uint64_t old_value;

	ASSERT(FFLP_VLAN_VALID(vlan_id));
	if (!FFLP_VLAN_VALID(vlan_id)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " enet_vlan_table set pri:"
		    " Invalid vlan ID %d \n",
		    vlan_id));
		return (NPI_FFLP_VLAN_INVALID);
	}

	ASSERT(FFLP_PORT_VALID(mac_portn));
	if (!FFLP_PORT_VALID(mac_portn)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " enet_vlan_table set pri:"
		    " Invalid port num %d \n",
		    mac_portn));
		return (NPI_FFLP_PORT_INVALID);
	}


	offset = FFLP_ENET_VLAN_TBL_REG + (vlan_id  << 3);
	REG_PIO_READ64(handle, offset, &cfg.value);
	old_value = cfg.value;
	switch (mac_portn) {
		case 0:
			if (priority)
				cfg.bits.ldw.vpr0 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr0 = BIT_DISABLE;
			break;
		case 1:
			if (priority)
				cfg.bits.ldw.vpr1 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr1 = BIT_DISABLE;
			break;
		case 2:
			if (priority)
				cfg.bits.ldw.vpr2 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr2 = BIT_DISABLE;
			break;
		case 3:
			if (priority)
				cfg.bits.ldw.vpr3 = BIT_ENABLE;
			else
				cfg.bits.ldw.vpr3 = BIT_DISABLE;
			break;
		default:
			return (NPI_FFLP_SW_PARAM_ERROR);
	}
	if (old_value != cfg.value) {
		if (mac_portn > 1)
			cfg.bits.ldw.parity1++;
		else
			cfg.bits.ldw.parity0++;

		REG_PIO_WRITE64(handle, offset, cfg.value);
	}
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_vlan_table_clear
 * Clears the vlan RDC table
 *
 * Input
 *     handle		opaque handle interpreted by the underlying OS
 *     vlan_id		VLAN ID
 *
 * Output
 *
 *	NPI success/failure status code
 *
 */
npi_status_t
npi_fflp_cfg_vlan_table_clear(npi_handle_t handle, vlan_id_t vlan_id)
{

	uint64_t offset;
	uint64_t clear = 0ULL;
	vlan_id_t start_vlan = 0;

	if ((vlan_id < start_vlan) || (vlan_id >= NXGE_MAX_VLANS)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " enet_vlan_table clear:"
		    " Invalid vlan ID %d \n",
		    vlan_id));
		return (NPI_FFLP_VLAN_INVALID);
	}


	offset = FFLP_VLAN_OFFSET(vlan_id, FFLP_ENET_VLAN_TBL_REG);

	REG_PIO_WRITE64(handle, offset, clear);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_vlan_tbl_get_err_log
 * Reports VLAN Table  errors.
 * If there are VLAN Table errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *	err_stat:	 structure to report various VLAN table errors.
 *                       will be updated if there are errors.
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t
npi_fflp_vlan_tbl_get_err_log(npi_handle_t handle, vlan_tbl_err_log_t *err_stat)
{
	vlan_par_err_t err_log;
	uint64_t offset;


	offset = FFLP_VLAN_PAR_ERR_REG;
	err_log.value = 0;

	REG_PIO_READ64(handle, offset, &err_log.value);

	if (err_log.bits.ldw.err == BIT_ENABLE) {
/* non-zero means err */
		err_stat->err = BIT_ENABLE;
		err_stat->multi = err_log.bits.ldw.m_err;
		err_stat->addr = err_log.bits.ldw.addr;
		err_stat->data = err_log.bits.ldw.data;
/* now clear the error */
		err_log.value = 0;
		REG_PIO_WRITE64(handle, offset, err_log.value);

	} else {
		err_stat->err = 0;
	}

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_vlan_tbl_clr_err_log
 * Clears VLAN Table PIO  error status.
 * If there are VLAN Table errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *         handle:	opaque handle interpreted by the underlying OS
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t
npi_fflp_vlan_tbl_clr_err_log(npi_handle_t handle)
{
	vlan_par_err_t err_log;
	uint64_t offset;

	offset = FFLP_VLAN_PAR_ERR_REG;
	err_log.value = 0;

	REG_PIO_WRITE64(handle, offset, err_log.value);

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_enet_usr_cls_set()
 * Configures a user configurable ethernet class
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *      class:       Ethernet Class  class
 *		     (TCAM_CLASS_ETYPE or  TCAM_CLASS_ETYPE_2)
 *      enet_type:   16 bit Ethernet Type value, corresponding ethernet bytes
 *                        [13:14] in the frame.
 *
 *  by default, the class will be disabled until explicitly enabled.
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_enet_usr_cls_set(npi_handle_t handle,
			    tcam_class_t class, uint16_t enet_type)
{
	uint64_t offset;
	tcam_class_prg_ether_t cls_cfg;
	cls_cfg.value = 0x0;

/* check if etype is valid */
	ASSERT(TCAM_L2_USR_CLASS_VALID(class));
	if (!TCAM_L2_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_enet_usr_cls_set:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}
	offset = GET_TCAM_CLASS_OFFSET(class);

/*
 * etype check code
 *
 * if (check_fail)
 *  return (NPI_FAILURE | NPI_SW_ERROR);
 */

	cls_cfg.bits.ldw.etype = enet_type;
	cls_cfg.bits.ldw.valid = BIT_DISABLE;
	REG_PIO_WRITE64(handle, offset, cls_cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_enet_usr_cls_enable()
 * Enable previously configured TCAM user configurable Ethernet classes.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      class:       Ethernet Class  class
 *		     (TCAM_CLASS_ETYPE or  TCAM_CLASS_ETYPE_2)
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_enet_usr_cls_enable(npi_handle_t handle, tcam_class_t class)
{
	uint64_t offset;
	tcam_class_prg_ether_t cls_cfg;

	ASSERT(TCAM_L2_USR_CLASS_VALID(class));
	if (!TCAM_L2_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_enet_usr_cls_enable:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);

	REG_PIO_READ64(handle, offset, &cls_cfg.value);
	cls_cfg.bits.ldw.valid = BIT_ENABLE;
	REG_PIO_WRITE64(handle, offset, cls_cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_enet_usr_cls_disable()
 * Disables previously configured TCAM user configurable Ethernet classes.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      class:       Ethernet Class  class
 *		     (TCAM_CLASS_ETYPE or  TCAM_CLASS_ETYPE_2)
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_enet_usr_cls_disable(npi_handle_t handle, tcam_class_t class)
{
	uint64_t offset;
	tcam_class_prg_ether_t cls_cfg;

	ASSERT(TCAM_L2_USR_CLASS_VALID(class));
	if (!TCAM_L2_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_enet_usr_cls_disable:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);

	REG_PIO_READ64(handle, offset, &cls_cfg.value);
	cls_cfg.bits.ldw.valid = BIT_DISABLE;

	REG_PIO_WRITE64(handle, offset, cls_cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_ip_usr_cls_set()
 * Configures the TCAM user configurable IP classes.
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *      class:       IP Class  class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *      tos:         IP TOS bits
 *      tos_mask:    IP TOS bits mask. bits with mask bits set will be used
 *      proto:       IP Proto
 *      ver:         IP Version
 * by default, will the class is disabled until explicitly enabled
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_usr_cls_set(npi_handle_t handle, tcam_class_t class,
			    uint8_t tos, uint8_t tos_mask,
			    uint8_t proto, uint8_t ver)
{
	uint64_t offset;
	tcam_class_prg_ip_t ip_cls_cfg;

	ASSERT(TCAM_L3_USR_CLASS_VALID(class));
	if (!TCAM_L3_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_usr_cls_set:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);

	ip_cls_cfg.bits.ldw.pid = proto;
	ip_cls_cfg.bits.ldw.ipver = ver;
	ip_cls_cfg.bits.ldw.tos = tos;
	ip_cls_cfg.bits.ldw.tosmask = tos_mask;
	ip_cls_cfg.bits.ldw.valid = 0;
	REG_PIO_WRITE64(handle, offset, ip_cls_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_ip_usr_cls_set_iptun()
 * Configures the TCAM user configurable IP classes. This function sets the
 * new fields that were added for IP tunneling support
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *      class:       IP Class  class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *	l4b0_val	value of the first L4 byte to be compared
 *	l4b0_msk	mask to apply to compare byte 0 of L4
 *	l4b23_val	values of L4 bytes 2 and 3 to compare
 *	l4b23_sel	set to 1 to compare L4 bytes 2 and 3.
 * by default, the class is disabled until explicitly enabled
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_usr_cls_set_iptun(npi_handle_t handle, tcam_class_t class,
			    uint8_t l4b0_val, uint8_t l4b0_msk,
			    uint16_t l4b23_val, uint8_t l4b23_sel)
{
	uint64_t offset, val;
	tcam_class_prg_ip_t ip_cls_cfg;

	ASSERT(TCAM_L3_USR_CLASS_VALID(class));
	if (!TCAM_L3_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_usr_cls_set:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);
	REG_PIO_READ64(handle, offset, &ip_cls_cfg.value);

	val = 1;
	ip_cls_cfg.value |= (val << L3_UCLS_L4_MODE_SH);
	val = l4b0_val;
	ip_cls_cfg.value |= (val << L3_UCLS_L4B0_VAL_SH);
	val = l4b0_msk;
	ip_cls_cfg.value |= (val << L3_UCLS_L4B0_MASK_SH);
	val = l4b23_sel;
	ip_cls_cfg.value |= (val << L3_UCLS_L4B23_SEL_SH);
	val = l4b23_val;
	ip_cls_cfg.value |= (val << L3_UCLS_L4B23_VAL_SH);

	ip_cls_cfg.bits.ldw.valid = 0;
	REG_PIO_WRITE64(handle, offset, ip_cls_cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_ip_usr_cls_get_iptun()
 * Retrieves the IP tunneling related settings for the given TCAM user
 * configurable IP classe.
 *
 * Input
 *      handle:		opaque handle interpreted by the underlying OS
 *      class:       IP Class  class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *	l4b0_val	value of the first L4 byte to be compared
 *	l4b0_msk	mask to apply to compare byte 0 of L4
 *	l4b23_val	values of L4 bytes 2 and 3 to compare
 *	l4b23_sel	set to 1 to compare L4 bytes 2 and 3.
 * by default, the class is disabled until explicitly enabled
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_usr_cls_get_iptun(npi_handle_t handle, tcam_class_t class,
			    uint8_t *l4b0_val, uint8_t *l4b0_msk,
			    uint16_t *l4b23_val, uint8_t *l4b23_sel)
{
	uint64_t offset;
	tcam_class_prg_ip_t ip_cls_cfg;

	ASSERT(TCAM_L3_USR_CLASS_VALID(class));
	if (!TCAM_L3_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_usr_cls_set:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);
	REG_PIO_READ64(handle, offset, &ip_cls_cfg.value);

	*l4b0_val = (ip_cls_cfg.value >> L3_UCLS_L4B0_VAL_SH) &
	    L3_UCLS_L4B0_VAL_MSK;
	*l4b0_msk = (ip_cls_cfg.value >> L3_UCLS_L4B0_MASK_SH) &
	    L3_UCLS_L4B0_MASK_MSK;
	*l4b23_sel = (ip_cls_cfg.value >> L3_UCLS_L4B23_SEL_SH) &
	    L3_UCLS_L4B23_SEL_MSK;
	*l4b23_val = (ip_cls_cfg.value >> L3_UCLS_L4B23_VAL_SH) &
	    L3_UCLS_L4B23_VAL_MSK;

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_ip_usr_cls_enable()
 * Enable previously configured TCAM user configurable IP classes.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      class:       IP Class  class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_usr_cls_enable(npi_handle_t handle, tcam_class_t class)
{
	uint64_t offset;
	tcam_class_prg_ip_t ip_cls_cfg;

	ASSERT(TCAM_L3_USR_CLASS_VALID(class));
	if (!TCAM_L3_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_usr_cls_enable:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);
	REG_PIO_READ64(handle, offset, &ip_cls_cfg.value);
	ip_cls_cfg.bits.ldw.valid = 1;

	REG_PIO_WRITE64(handle, offset, ip_cls_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_ip_usr_cls_disable()
 * Disables previously configured TCAM user configurable IP classes.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      class:       IP Class  class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_usr_cls_disable(npi_handle_t handle, tcam_class_t class)
{
	uint64_t offset;
	tcam_class_prg_ip_t ip_cls_cfg;

	ASSERT(TCAM_L3_USR_CLASS_VALID(class));
	if (!TCAM_L3_USR_CLASS_VALID(class)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_usr_cls_disable:"
		    " Invalid class %d \n",
		    class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_TCAM_CLASS_OFFSET(class);

	REG_PIO_READ64(handle, offset, &ip_cls_cfg.value);
	ip_cls_cfg.bits.ldw.valid = 0;

	REG_PIO_WRITE64(handle, offset, ip_cls_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_ip_cls_tcam_key ()
 *
 * Configures the TCAM key generation for the IP classes
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      l3_class:        IP class to configure key generation
 *      cfg:             Configuration bits:
 *                   discard:      Discard all frames of this class
 *                   use_ip_saddr: use ip src address (for ipv6)
 *                   use_ip_daddr: use ip dest address (for ipv6)
 *                   lookup_enable: Enable Lookup
 *
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_cls_tcam_key(npi_handle_t handle,
			    tcam_class_t l3_class, tcam_key_cfg_t *cfg)
{
	uint64_t offset;
	tcam_class_key_ip_t tcam_cls_cfg;

	ASSERT(TCAM_L3_CLASS_VALID(l3_class));
	if (!(TCAM_L3_CLASS_VALID(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_tcam_key:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	if ((cfg->use_ip_daddr) &&
	    (cfg->use_ip_saddr == cfg->use_ip_daddr)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_tcam_key:"
		    " Invalid configuration %x for class %d \n",
		    *cfg, l3_class));
		return (NPI_FFLP_SW_PARAM_ERROR);
	}


	offset = GET_TCAM_KEY_OFFSET(l3_class);
	tcam_cls_cfg.value = 0;

	if (cfg->discard) {
		tcam_cls_cfg.bits.ldw.discard = 1;
	}

	if (cfg->use_ip_saddr) {
		tcam_cls_cfg.bits.ldw.ipaddr = 1;
	}

	if (cfg->use_ip_daddr) {
		tcam_cls_cfg.bits.ldw.ipaddr = 0;
	}

	if (cfg->lookup_enable) {
		tcam_cls_cfg.bits.ldw.tsel = 1;
	}

	REG_PIO_WRITE64(handle, offset, tcam_cls_cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_ip_cls_flow_key ()
 *
 * Configures the flow key generation for the IP classes
 * Flow key is used to generate the H1 hash function value
 * The fields used for the generation are configured using this
 * NPI function.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      l3_class:        IP class to configure flow key generation
 *      cfg:             Configuration bits:
 *                   use_proto:     Use IP proto field
 *                   use_dport:     use l4 destination port
 *                   use_sport:     use l4 source port
 *                   ip_opts_exist: IP Options Present
 *                   use_daddr:     use ip dest address
 *                   use_saddr:     use ip source address
 *                   use_vlan:      use VLAN ID
 *                   use_l2da:      use L2 Dest MAC Address
 *                   use_portnum:   use L2 virtual port number
 *
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_cls_flow_key(npi_handle_t handle, tcam_class_t l3_class,
							    flow_key_cfg_t *cfg)
{
	uint64_t offset;
	flow_class_key_ip_t flow_cfg_reg;

	ASSERT(TCAM_L3_CLASS_VALID(l3_class));
	if (!(TCAM_L3_CLASS_VALID(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_flow_key:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}


	offset = GET_FLOW_KEY_OFFSET(l3_class);
	flow_cfg_reg.value = 0; /* default */

	if (cfg->use_proto) {
		flow_cfg_reg.bits.ldw.proto = 1;
	}

	if (cfg->use_dport) {
		flow_cfg_reg.bits.ldw.l4_1 = 2;
		if (cfg->ip_opts_exist)
			flow_cfg_reg.bits.ldw.l4_1 = 3;
	}

	if (cfg->use_sport) {
		flow_cfg_reg.bits.ldw.l4_0 = 2;
		if (cfg->ip_opts_exist)
			flow_cfg_reg.bits.ldw.l4_0 = 3;
	}

	if (cfg->use_daddr) {
		flow_cfg_reg.bits.ldw.ipda = BIT_ENABLE;
	}

	if (cfg->use_saddr) {
		flow_cfg_reg.bits.ldw.ipsa = BIT_ENABLE;
	}

	if (cfg->use_vlan) {
		flow_cfg_reg.bits.ldw.vlan = BIT_ENABLE;
	}

	if (cfg->use_l2da) {
		flow_cfg_reg.bits.ldw.l2da = BIT_ENABLE;
	}

	if (cfg->use_portnum) {
		flow_cfg_reg.bits.ldw.port = BIT_ENABLE;
	}

	REG_PIO_WRITE64(handle, offset, flow_cfg_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_fflp_cfg_ip_cls_flow_key_get(npi_handle_t handle,
				    tcam_class_t l3_class,
				    flow_key_cfg_t *cfg)
{
	uint64_t offset;
	flow_class_key_ip_t flow_cfg_reg;

	ASSERT(TCAM_L3_CLASS_VALID(l3_class));
	if (!(TCAM_L3_CLASS_VALID(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_flow_key:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	offset = GET_FLOW_KEY_OFFSET(l3_class);

	cfg->use_proto = 0;
	cfg->use_dport = 0;
	cfg->use_sport = 0;
	cfg->ip_opts_exist = 0;
	cfg->use_daddr = 0;
	cfg->use_saddr = 0;
	cfg->use_vlan = 0;
	cfg->use_l2da = 0;
	cfg->use_portnum  = 0;

	REG_PIO_READ64(handle, offset, &flow_cfg_reg.value);

	if (flow_cfg_reg.bits.ldw.proto) {
		cfg->use_proto = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_1 == 2) {
		cfg->use_dport = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_1 == 3) {
		cfg->use_dport = 1;
		cfg->ip_opts_exist = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_0 == 2) {
		cfg->use_sport = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_0 == 3) {
		cfg->use_sport = 1;
		cfg->ip_opts_exist = 1;
	}

	if (flow_cfg_reg.bits.ldw.ipda) {
		cfg->use_daddr = 1;
	}

	if (flow_cfg_reg.bits.ldw.ipsa) {
		cfg->use_saddr = 1;
	}

	if (flow_cfg_reg.bits.ldw.vlan) {
		cfg->use_vlan = 1;
	}

	if (flow_cfg_reg.bits.ldw.l2da) {
		cfg->use_l2da = 1;
	}

	if (flow_cfg_reg.bits.ldw.port) {
		cfg->use_portnum = 1;
	}

	NPI_DEBUG_MSG((handle.function, NPI_FFLP_CTL,
	    " npi_fflp_cfg_ip_cls_flow_get %llx \n",
	    flow_cfg_reg.value));

	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_ip_cls_flow_key_rfnl ()
 *
 * Configures the flow key generation for the IP classes
 * Flow key is used to generate the H1 hash function value
 * The fields used for the generation are configured using this
 * NPI function.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      l3_class:        IP class to configure flow key generation
 *      cfg:             Configuration bits:
 *		     l4_xor_sel:    bit field to select the L4 payload
 *				    bytes for X-OR to get hash key.
 *		     use_l4_md:	    Set to 1 for enabling L4-mode.
 *		     use_sym:	    Set to 1 to use symmetric mode.
 *                   use_proto:     Use IP proto field
 *                   use_dport:     use l4 destination port
 *                   use_sport:     use l4 source port
 *                   ip_opts_exist: IP Options Present
 *                   use_daddr:     use ip dest address
 *                   use_saddr:     use ip source address
 *                   use_vlan:      use VLAN ID
 *                   use_l2da:      use L2 Dest MAC Address
 *                   use_portnum:   use L2 virtual port number
 *
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_ip_cls_flow_key_rfnl(npi_handle_t handle, tcam_class_t l3_class,
		flow_key_cfg_t *cfg)
{
	uint64_t offset;
	flow_class_key_ip_t flow_cfg_reg;

	ASSERT(TCAM_L3_CLASS_VALID_RFNL(l3_class));
	if (!(TCAM_L3_CLASS_VALID_RFNL(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_flow_key_rfnl:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	if (l3_class == TCAM_CLASS_IPV6_FRAG) {
		offset = FFLP_FLOW_KEY_IP6_FRAG_REG;
	} else {
		offset = GET_FLOW_KEY_OFFSET(l3_class);
	}

	flow_cfg_reg.value = 0;

	flow_cfg_reg.bits.ldw.l4_xor = cfg->l4_xor_sel;

	if (cfg->use_l4_md)
		flow_cfg_reg.bits.ldw.l4_mode = 1;

	if (cfg->use_sym)
		flow_cfg_reg.bits.ldw.sym = 1;

	if (cfg->use_proto) {
		flow_cfg_reg.bits.ldw.proto = 1;
	}

	if (cfg->use_dport) {
		flow_cfg_reg.bits.ldw.l4_1 = 2;
		if (cfg->ip_opts_exist)
			flow_cfg_reg.bits.ldw.l4_1 = 3;
	}

	if (cfg->use_sport) {
		flow_cfg_reg.bits.ldw.l4_0 = 2;
		if (cfg->ip_opts_exist)
			flow_cfg_reg.bits.ldw.l4_0 = 3;
	}

	if (cfg->use_daddr) {
		flow_cfg_reg.bits.ldw.ipda = BIT_ENABLE;
	}

	if (cfg->use_saddr) {
		flow_cfg_reg.bits.ldw.ipsa = BIT_ENABLE;
	}

	if (cfg->use_vlan) {
		flow_cfg_reg.bits.ldw.vlan = BIT_ENABLE;
	}

	if (cfg->use_l2da) {
		flow_cfg_reg.bits.ldw.l2da = BIT_ENABLE;
	}

	if (cfg->use_portnum) {
		flow_cfg_reg.bits.ldw.port = BIT_ENABLE;
	}

	REG_PIO_WRITE64(handle, offset, flow_cfg_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_fflp_cfg_sym_ip_cls_flow_key(npi_handle_t handle, tcam_class_t l3_class,
		boolean_t enable)
{
	uint64_t offset;
	flow_class_key_ip_t flow_cfg_reg;

	ASSERT(TCAM_L3_CLASS_VALID_RFNL(l3_class));
	if (!(TCAM_L3_CLASS_VALID_RFNL(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_sym_ip_cls_flow_key:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	if (l3_class == TCAM_CLASS_IPV6_FRAG) {
		offset = FFLP_FLOW_KEY_IP6_FRAG_REG;
	} else {
		offset = GET_FLOW_KEY_OFFSET(l3_class);
	}

	REG_PIO_READ64(handle, offset, &flow_cfg_reg.value);

	if (enable && flow_cfg_reg.bits.ldw.sym == 0) {
		flow_cfg_reg.bits.ldw.sym = 1;
		REG_PIO_WRITE64(handle, offset, flow_cfg_reg.value);
	} else if (!enable && flow_cfg_reg.bits.ldw.sym == 1) {
		flow_cfg_reg.bits.ldw.sym = 0;
		REG_PIO_WRITE64(handle, offset, flow_cfg_reg.value);
	}

	return (NPI_SUCCESS);

}

npi_status_t
npi_fflp_cfg_ip_cls_flow_key_get_rfnl(npi_handle_t handle,
				    tcam_class_t l3_class,
				    flow_key_cfg_t *cfg)
{
	uint64_t offset;
	flow_class_key_ip_t flow_cfg_reg;

	ASSERT(TCAM_L3_CLASS_VALID_RFNL(l3_class));
	if (!(TCAM_L3_CLASS_VALID_RFNL(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_flow_key_get_rfnl:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}

	if (l3_class == TCAM_CLASS_IPV6_FRAG) {
		offset = FFLP_FLOW_KEY_IP6_FRAG_REG;
	} else {
		offset = GET_FLOW_KEY_OFFSET(l3_class);
	}

	cfg->l4_xor_sel = 0;
	cfg->use_l4_md = 0;
	cfg->use_sym = 0;
	cfg->use_proto = 0;
	cfg->use_dport = 0;
	cfg->use_sport = 0;
	cfg->ip_opts_exist = 0;
	cfg->use_daddr = 0;
	cfg->use_saddr = 0;
	cfg->use_vlan = 0;
	cfg->use_l2da = 0;
	cfg->use_portnum  = 0;

	REG_PIO_READ64(handle, offset, &flow_cfg_reg.value);

	cfg->l4_xor_sel = flow_cfg_reg.bits.ldw.l4_xor;

	if (flow_cfg_reg.bits.ldw.l4_mode)
		cfg->use_l4_md = 1;

	if (flow_cfg_reg.bits.ldw.sym)
		cfg->use_sym = 1;

	if (flow_cfg_reg.bits.ldw.proto) {
		cfg->use_proto = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_1 == 2) {
		cfg->use_dport = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_1 == 3) {
		cfg->use_dport = 1;
		cfg->ip_opts_exist = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_0 == 2) {
		cfg->use_sport = 1;
	}

	if (flow_cfg_reg.bits.ldw.l4_0 == 3) {
		cfg->use_sport = 1;
		cfg->ip_opts_exist = 1;
	}

	if (flow_cfg_reg.bits.ldw.ipda) {
		cfg->use_daddr = 1;
	}

	if (flow_cfg_reg.bits.ldw.ipsa) {
		cfg->use_saddr = 1;
	}

	if (flow_cfg_reg.bits.ldw.vlan) {
		cfg->use_vlan = 1;
	}

	if (flow_cfg_reg.bits.ldw.l2da) {
		cfg->use_l2da = 1;
	}

	if (flow_cfg_reg.bits.ldw.port) {
		cfg->use_portnum = 1;
	}

	NPI_DEBUG_MSG((handle.function, NPI_FFLP_CTL,
	    " npi_fflp_cfg_ip_cls_flow_get %llx \n",
	    flow_cfg_reg.value));

	return (NPI_SUCCESS);

}

npi_status_t
npi_fflp_cfg_ip_cls_tcam_key_get(npi_handle_t handle,
			    tcam_class_t l3_class, tcam_key_cfg_t *cfg)
{
	uint64_t offset;
	tcam_class_key_ip_t tcam_cls_cfg;

	ASSERT(TCAM_L3_CLASS_VALID(l3_class));
	if (!(TCAM_L3_CLASS_VALID(l3_class))) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_ip_cls_tcam_key_get:"
		    " Invalid class %d \n",
		    l3_class));
		return (NPI_FFLP_TCAM_CLASS_INVALID);
	}


	offset = GET_TCAM_KEY_OFFSET(l3_class);

	REG_PIO_READ64(handle, offset, &tcam_cls_cfg.value);

	cfg->discard = 0;
	cfg->use_ip_saddr = 0;
	cfg->use_ip_daddr = 1;
	cfg->lookup_enable = 0;

	if (tcam_cls_cfg.bits.ldw.discard)
			cfg->discard = 1;

	if (tcam_cls_cfg.bits.ldw.ipaddr) {
		cfg->use_ip_saddr = 1;
		cfg->use_ip_daddr = 0;
	}

	if (tcam_cls_cfg.bits.ldw.tsel) {
		cfg->lookup_enable = 1;
	}

	NPI_DEBUG_MSG((handle.function, NPI_CTL,
	    " npi_fflp_cfg_ip_cls_tcam_key_get %llx \n",
	    tcam_cls_cfg.value));
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_fcram_access ()
 *
 * Sets the ratio between the FCRAM pio and lookup access
 * Input:
 * handle:	opaque handle interpreted by the underlying OS
 * access_ratio: 0  Lookup has the highest priority
 *		 15 PIO has maximum possible priority
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_fcram_access(npi_handle_t handle, uint8_t access_ratio)
{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	if (access_ratio > 0xf) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_fcram_access:"
		    " Invalid access ratio %d \n",
		    access_ratio));
		return (NPI_FFLP_ERROR | NPI_FFLP_SW_PARAM_ERROR);
	}

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.fflpinitdone = 0;
	fflp_cfg.bits.ldw.fcramratio = access_ratio;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.fflpinitdone = 1;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * npi_fflp_cfg_tcam_access ()
 *
 * Sets the ratio between the TCAM pio and lookup access
 * Input:
 * handle:	opaque handle interpreted by the underlying OS
 * access_ratio: 0  Lookup has the highest priority
 *		 15 PIO has maximum possible priority
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_tcam_access(npi_handle_t handle, uint8_t access_ratio)
{
	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	if (access_ratio > 0xf) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_cfg_tcram_access:"
		    " Invalid access ratio %d \n",
		    access_ratio));
		return (NPI_FFLP_ERROR | NPI_FFLP_SW_PARAM_ERROR);
	}

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.fflpinitdone = 0;
	fflp_cfg.bits.ldw.camratio = access_ratio;

	/* since the cam latency is fixed, we might set it here */
	fflp_cfg.bits.ldw.camlatency = TCAM_DEFAULT_LATENCY;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.fflpinitdone = 1;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_hash_h1poly()
 * Initializes the H1 hash generation logic.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      init_value:       The initial value (seed)
 *
 * Return
 * NPI success/failure status code
 */
npi_status_t
npi_fflp_cfg_hash_h1poly(npi_handle_t handle, uint32_t init_value)
{


	hash_h1poly_t h1_cfg;
	uint64_t offset;
	offset = FFLP_H1POLY_REG;

	h1_cfg.value = 0;
	h1_cfg.bits.ldw.init_value = init_value;

	REG_PIO_WRITE64(handle, offset, h1_cfg.value);
	return (NPI_SUCCESS);
}

/*
 * npi_fflp_cfg_hash_h2poly()
 * Initializes the H2 hash generation logic.
 *
 * Input
 *      handle:	opaque handle interpreted by the underlying OS
 *      init_value:       The initial value (seed)
 *
 * Return
 * NPI_SUCCESS
 *
 */
npi_status_t
npi_fflp_cfg_hash_h2poly(npi_handle_t handle, uint16_t init_value)
{


	hash_h2poly_t h2_cfg;
	uint64_t offset;
	offset = FFLP_H2POLY_REG;

	h2_cfg.value = 0;
	h2_cfg.bits.ldw.init_value = init_value;

	REG_PIO_WRITE64(handle, offset, h2_cfg.value);
	return (NPI_SUCCESS);


}

/*
 *  npi_fflp_cfg_reset
 *  Initializes the FCRAM reset sequence.
 *
 *  Input
 *      handle:		opaque handle interpreted by the underlying OS
 *	strength:		FCRAM Drive strength
 *				   strong, weak or normal
 *				   HW recommended value:
 *	qs:			FCRAM QS mode selection
 *				   qs mode or free running
 *				   HW recommended value is:
 *
 * Return:
 * NPI success/failure status code
 */

npi_status_t
npi_fflp_cfg_fcram_reset(npi_handle_t handle,
	fflp_fcram_output_drive_t strength, fflp_fcram_qs_t qs)
{
	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	/* These bits have to be configured before FCRAM reset is issued */
	fflp_cfg.value = 0;
	fflp_cfg.bits.ldw.pio_fio_rst = 1;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	NXGE_DELAY(5); /* TODO: What is the correct delay? */

	fflp_cfg.bits.ldw.pio_fio_rst = 0;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	fflp_cfg.bits.ldw.fcramqs = qs;
	fflp_cfg.bits.ldw.fcramoutdr = strength;
	fflp_cfg.bits.ldw.fflpinitdone = 1;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_fflp_cfg_init_done(npi_handle_t handle)

{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.fflpinitdone = 1;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_fflp_cfg_init_start(npi_handle_t handle)

{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;

	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.fflpinitdone = 0;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * Enables the TCAM search function.
 *
 */
npi_status_t
npi_fflp_cfg_tcam_enable(npi_handle_t handle)

{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;
	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.tcam_disable = 0;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * Disables the TCAM search function.
 * While the TCAM is in disabled state, all TCAM matches would return NO_MATCH
 *
 */
npi_status_t
npi_fflp_cfg_tcam_disable(npi_handle_t handle)

{

	fflp_cfg_1_t fflp_cfg;
	uint64_t offset;
	offset = FFLP_CFG_1_REG;
	REG_PIO_READ64(handle, offset, &fflp_cfg.value);
	fflp_cfg.bits.ldw.tcam_disable = 1;
	REG_PIO_WRITE64(handle, offset, fflp_cfg.value);
	return (NPI_SUCCESS);

}

/*
 * npi_rxdma_event_mask_config():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts
 *	and status register.
 */
npi_status_t
npi_fflp_event_mask_config(npi_handle_t handle, io_op_t op_mode,
		fflp_event_mask_cfg_t *mask_cfgp)
{
	int		status = NPI_SUCCESS;
	fflp_err_mask_t mask_reg;

	switch (op_mode) {
	case OP_GET:

		REG_PIO_READ64(handle, FFLP_ERR_MSK_REG, &mask_reg.value);
		*mask_cfgp = mask_reg.value & FFLP_ERR_MASK_ALL;
		break;

	case OP_SET:
		mask_reg.value = (~(*mask_cfgp) & FFLP_ERR_MASK_ALL);
		REG_PIO_WRITE64(handle, FFLP_ERR_MSK_REG, mask_reg.value);
		break;

	case OP_UPDATE:
		REG_PIO_READ64(handle, FFLP_ERR_MSK_REG, &mask_reg.value);
		mask_reg.value |=  (~(*mask_cfgp) & FFLP_ERR_MASK_ALL);
		REG_PIO_WRITE64(handle, FFLP_ERR_MSK_REG, mask_reg.value);
		break;

	case OP_CLEAR:
		mask_reg.value = FFLP_ERR_MASK_ALL;
		REG_PIO_WRITE64(handle, FFLP_ERR_MSK_REG, mask_reg.value);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fflp_event_mask_config",
		    " eventmask <0x%x>", op_mode));
		return (NPI_FFLP_ERROR | NPI_FFLP_SW_PARAM_ERROR);
	}

	return (status);
}

/*
 * Read vlan error bits
 */
void
npi_fflp_vlan_error_get(npi_handle_t handle, p_vlan_par_err_t p_err)
{
	REG_PIO_READ64(handle, FFLP_VLAN_PAR_ERR_REG, &p_err->value);
}

/*
 * clear vlan error bits
 */
void
npi_fflp_vlan_error_clear(npi_handle_t handle)
{
	vlan_par_err_t p_err;
	p_err.value  = 0;
	p_err.bits.ldw.m_err = 0;
	p_err.bits.ldw.err = 0;
	REG_PIO_WRITE64(handle, FFLP_ERR_MSK_REG, p_err.value);

}

/*
 * Read TCAM error bits
 */
void
npi_fflp_tcam_error_get(npi_handle_t handle, p_tcam_err_t p_err)
{
	REG_PIO_READ64(handle, FFLP_TCAM_ERR_REG, &p_err->value);
}

/*
 * clear TCAM error bits
 */
void
npi_fflp_tcam_error_clear(npi_handle_t handle)
{
	tcam_err_t p_err;

	p_err.value  = 0;
	p_err.bits.ldw.p_ecc = 0;
	p_err.bits.ldw.mult = 0;
	p_err.bits.ldw.err = 0;
	REG_PIO_WRITE64(handle, FFLP_TCAM_ERR_REG, p_err.value);

}

/*
 * Read FCRAM error bits
 */
void
npi_fflp_fcram_error_get(npi_handle_t handle,
	p_hash_tbl_data_log_t p_err, uint8_t partition)
{
	uint64_t offset;

	offset = FFLP_HASH_TBL_DATA_LOG_REG + partition * 8192;
	REG_PIO_READ64(handle, offset, &p_err->value);
}

/*
 * clear FCRAM error bits
 */
void
npi_fflp_fcram_error_clear(npi_handle_t handle, uint8_t partition)
{
	hash_tbl_data_log_t p_err;
	uint64_t offset;

	p_err.value  = 0;
	p_err.bits.ldw.pio_err = 0;
	offset = FFLP_HASH_TBL_DATA_LOG_REG + partition * 8192;

	REG_PIO_WRITE64(handle, offset,
	    p_err.value);

}

/*
 * Read FCRAM lookup error log1 bits
 */
void
npi_fflp_fcram_error_log1_get(npi_handle_t handle,
			    p_hash_lookup_err_log1_t log1)
{
	REG_PIO_READ64(handle, HASH_LKUP_ERR_LOG1_REG,
	    &log1->value);
}

/*
 * Read FCRAM lookup error log2 bits
 */
void
npi_fflp_fcram_error_log2_get(npi_handle_t handle,
		    p_hash_lookup_err_log2_t log2)
{
	REG_PIO_READ64(handle, HASH_LKUP_ERR_LOG2_REG,
	    &log2->value);
}
