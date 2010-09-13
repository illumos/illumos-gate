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

#ifndef _NPI_FFLP_H
#define	_NPI_FFLP_H

#ifdef	__cplusplus
extern "C" {
#endif


#include <npi.h>
#include <nxge_hw.h>
#include <nxge_fflp_hw.h>
#include <nxge_fflp.h>


typedef uint8_t part_id_t;
typedef uint8_t tcam_location_t;
typedef uint16_t vlan_id_t;

typedef	enum _tcam_op {
	TCAM_RWC_STAT	= 0x1,
	TCAM_RWC_MATCH	= 0x2
} tcam_op_t;


#define	NPI_TCAM_COMP_NO_MATCH	0x8000000000000ULL

/*
 * NPI FFLP ERROR Codes
 */

#define	NPI_FFLP_BLK_CODE	FFLP_BLK_ID << 8
#define	NPI_FFLP_ERROR		(NPI_FAILURE | NPI_FFLP_BLK_CODE)
#define	NPI_TCAM_ERROR		0x10
#define	NPI_FCRAM_ERROR		0x20
#define	NPI_GEN_FFLP		0x30
#define	NPI_FFLP_SW_PARAM_ERROR	0x40
#define	NPI_FFLP_HW_ERROR	0x80


#define	NPI_FFLP_RESET_ERROR	(NPI_FFLP_ERROR | NPI_GEN_FFLP | RESET_FAILED)
#define	NPI_FFLP_RDC_TABLE_INVALID	(NPI_FFLP_ERROR | RDC_TAB_INVALID)
#define	NPI_FFLP_VLAN_INVALID		(NPI_FFLP_ERROR | VLAN_INVALID)
#define	NPI_FFLP_PORT_INVALID		(NPI_FFLP_ERROR | PORT_INVALID)
#define	NPI_FFLP_TCAM_RD_ERROR		\
	(NPI_FFLP_ERROR | NPI_TCAM_ERROR | READ_FAILED)
#define	NPI_FFLP_TCAM_WR_ERROR		\
	(NPI_FFLP_ERROR | NPI_TCAM_ERROR | WRITE_FAILED)
#define	NPI_FFLP_TCAM_LOC_INVALID	\
	(NPI_FFLP_ERROR | NPI_TCAM_ERROR | LOCATION_INVALID)
#define	NPI_FFLP_ASC_RAM_RD_ERROR	\
	(NPI_FFLP_ERROR | NPI_TCAM_ERROR | READ_FAILED)
#define	NPI_FFLP_ASC_RAM_WR_ERROR	\
	(NPI_FFLP_ERROR | NPI_TCAM_ERROR | WRITE_FAILED)
#define	NPI_FFLP_FCRAM_READ_ERROR	\
	(NPI_FFLP_ERROR | NPI_FCRAM_ERROR | READ_FAILED)
#define	NPI_FFLP_FCRAM_WR_ERROR		\
	(NPI_FFLP_ERROR | NPI_FCRAM_ERROR | WRITE_FAILED)
#define	NPI_FFLP_FCRAM_PART_INVALID	\
	(NPI_FFLP_ERROR | NPI_FCRAM_ERROR | RDC_TAB_INVALID)
#define	NPI_FFLP_FCRAM_LOC_INVALID	\
	(NPI_FFLP_ERROR | NPI_FCRAM_ERROR | LOCATION_INVALID)

#define	TCAM_CLASS_INVALID		\
	(NPI_FFLP_SW_PARAM_ERROR | 0xb)
/* have only 0xc, 0xd, 0xe and 0xf left for sw error codes */
#define	NPI_FFLP_TCAM_CLASS_INVALID	\
	(NPI_FFLP_ERROR | NPI_TCAM_ERROR | TCAM_CLASS_INVALID)
#define	NPI_FFLP_TCAM_HW_ERROR		\
	(NPI_FFLP_ERROR | NPI_FFLP_HW_ERROR | NPI_TCAM_ERROR)
#define	NPI_FFLP_FCRAM_HW_ERROR		\
	(NPI_FFLP_ERROR | NPI_FFLP_HW_ERROR | NPI_FCRAM_ERROR)


/*
 * FFLP NPI defined event masks (mapped to the hardware defined masks).
 */
typedef	enum _fflp_event_mask_cfg_e {
	CFG_FFLP_ENT_MSK_VLAN_MASK = FFLP_ERR_VLAN_MASK,
	CFG_FFLP_ENT_MSK_TCAM_MASK = FFLP_ERR_TCAM_MASK,
	CFG_FFLP_ENT_MSK_HASH_TBL_LKUP_MASK = FFLP_ERR_HASH_TBL_LKUP_MASK,
	CFG_FFLP_ENT_MSK_HASH_TBL_DAT_MASK = FFLP_ERR_HASH_TBL_DAT_MASK,

	CFG_FFLP_MASK_ALL	= (FFLP_ERR_VLAN_MASK | FFLP_ERR_TCAM_MASK |
						FFLP_ERR_HASH_TBL_LKUP_MASK |
						FFLP_ERR_HASH_TBL_DAT_MASK)
} fflp_event_mask_cfg_t;


/* FFLP FCRAM Related Functions */
/* The following are FCRAM datapath functions */

/*
 * npi_fflp_fcram_entry_write ()
 * Populates an FCRAM entry
 * Inputs:
 *         handle:	opaque handle interpreted by the underlying OS
 *	   partid:	Partition ID
 *	   location:	Index to the FCRAM.
 *			Corresponds to last 20 bits of H1 value
 *	   fcram_ptr:	Pointer to the FCRAM contents to be used for writing
 *	   format:	Entry Format. Determines the size of the write.
 *			      FCRAM_ENTRY_OPTIM:   8 bytes (a 64 bit write)
 *			      FCRAM_ENTRY_EX_IP4:  32 bytes (4 X 64 bit write)
 *			      FCRAM_ENTRY_EX_IP6:  56 bytes (7 X 64 bit write)
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_fcram_entry_write(npi_handle_t, part_id_t,
			    uint32_t, fcram_entry_t *,
			    fcram_entry_format_t);

/*
 * npi_fflp_fcram_entry_read ()
 * Reads an FCRAM entry
 * Inputs:
 *         handle:	opaque handle interpreted by the underlying OS
 *	   partid:	Partition ID
 *	   location:	Index to the FCRAM.
 *			Corresponds to last 20 bits of H1 value
 *	   fcram_ptr:	Pointer to the FCRAM contents to be updated
 *	   format:	Entry Format. Determines the size of the read.
 *			      FCRAM_ENTRY_OPTIM:   8 bytes (a 64 bit read)
 *			      FCRAM_ENTRY_EX_IP4:  32 bytes (4 X 64 bit read )
 *			      FCRAM_ENTRY_EX_IP6:  56 bytes (7 X 64 bit read )
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 */

npi_status_t npi_fflp_fcram_entry_read(npi_handle_t,  part_id_t,
				    uint32_t, fcram_entry_t *,
				    fcram_entry_format_t);

/*
 * npi_fflp_fcram_entry_invalidate ()
 * Invalidate FCRAM entry at the given location
 * Inputs:
 *	handle:		opaque handle interpreted by the underlying OS
 *	partid:		Partition ID
 *	location:	location of the FCRAM/hash entry.
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t
npi_fflp_fcram_entry_invalidate(npi_handle_t, part_id_t,
				    uint32_t);

/*
 * npi_fflp_fcram_subarea_write ()
 * Writes to FCRAM entry subarea i.e the 8 bytes within the 64 bytes pointed by
 * last 20 bits of  H1. Effectively, this accesses specific 8 bytes within the
 * hash table bucket.
 *
 *    |-----------------| <-- H1
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
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */


npi_status_t npi_fflp_fcram_subarea_write(npi_handle_t, part_id_t,
				    uint32_t, uint64_t);
/*
 * npi_fflp_fcram_subarea_read ()
 * Reads an FCRAM entry subarea i.e the 8 bytes within the 64 bytes pointed by
 * last 20 bits of  H1. Effectively, this accesses specific 8 bytes within the
 * hash table bucket.
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
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_fcram_subarea_read  (npi_handle_t,
			part_id_t, uint32_t, uint64_t *);


/* The following are zero function fflp configuration functions */
/*
 * npi_fflp_fcram_config_partition()
 * Partitions and configures the FCRAM
 *
 * Input
 *     partid			partition ID
 *				Corresponds to the RDC table
 *     part_size		Size of the partition
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */
npi_status_t npi_fflp_cfg_fcram_partition(npi_handle_t, part_id_t,
				uint8_t, uint8_t);

/*
 * npi_fflp_fcram_partition_enable
 * Enable previously configured FCRAM partition
 *
 * Input
 *     partid			partition ID
 *				Corresponds to the RDC table
 *
 * Return
 *      0			Successful
 *      Non zero  error code    Enable failed, and reason.
 *
 */
npi_status_t npi_fflp_cfg_fcram_partition_enable(npi_handle_t,
				part_id_t);

/*
 * npi_fflp_fcram_partition_disable
 * Disable previously configured FCRAM partition
 *
 * Input
 *     partid			partition ID
 *				Corresponds to the RDC table
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_fcram_partition_disable(npi_handle_t,
				part_id_t);


/*
 *  npi_fflp_cfg_fcram_reset
 *  Initializes the FCRAM reset sequence (including FFLP).
 *
 *  Input
 *	strength:		FCRAM Drive strength
 *				   strong, weak or normal
 *				   HW recommended value:
 *	qs:			FCRAM QS mode selection
 *				   qs mode or free running
 *				   HW recommended value is:
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_fcram_reset(npi_handle_t,
				    fflp_fcram_output_drive_t,
				    fflp_fcram_qs_t);



/*
 *  npi_fflp_cfg_tcam_reset
 *  Initializes the FFLP reset sequence
 * Doesn't configure the FCRAM params.
 *
 *  Input
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_tcam_reset(npi_handle_t);

/*
 *  npi_fflp_cfg_tcam_enable
 *  Enables the TCAM function
 *
 *  Input
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_tcam_enable(npi_handle_t);

/*
 *  npi_fflp_cfg_tcam_disable
 *  Enables the TCAM function
 *
 *  Input
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_tcam_disable(npi_handle_t);


/*
 *  npi_fflp_cfg_cam_errorcheck_disable
 *  Disables FCRAM and TCAM error checking
 *
 *  Input
 *
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_cam_errorcheck_disable(npi_handle_t);

/*
 *  npi_fflp_cfg_cam_errorcheck_enable
 *  Enables FCRAM and TCAM error checking
 *
 *  Input
 *
 *
 *  Return
 *      0			Successful
 *      Non zero  error code    Enable failed, and reason.
 *
 */
npi_status_t npi_fflp_cfg_cam_errorcheck_enable(npi_handle_t);


/*
 *  npi_fflp_cfg_llcsnap_enable
 *  Enables input parser llcsnap recognition
 *
 *  Input
 *
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 *
 */
npi_status_t npi_fflp_cfg_llcsnap_enable(npi_handle_t);

/*
 *  npi_fflp_cam_llcsnap_disable
 *  Disables input parser llcsnap recognition
 *
 *  Input
 *
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 *
 */

npi_status_t npi_fflp_cfg_llcsnap_disable(npi_handle_t);

/*
 * npi_fflp_config_fcram_refresh
 * Set FCRAM min and max refresh time.
 *
 * Input
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
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_fcram_refresh_time(npi_handle_t,
		uint32_t, uint32_t, uint32_t);


/*
 * npi_fflp_cfg_fcram_access ()
 *
 * Sets the ratio between the FCRAM pio and lookup access
 * Input:
 * access_ratio: 0  Lookup has the highest priority
 *		 15 PIO has maximum possible priority
 *
 */

npi_status_t npi_fflp_cfg_fcram_access(npi_handle_t,
					uint8_t);


/*
 * npi_fflp_cfg_tcam_access ()
 *
 * Sets the ratio between the TCAM pio and lookup access
 * Input:
 * access_ratio: 0  Lookup has the highest priority
 *		 15 PIO has maximum possible priority
 *
 */

npi_status_t npi_fflp_cfg_tcam_access(npi_handle_t, uint8_t);


/*
 *  npi_fflp_hash_lookup_err_report
 *  Reports hash table (fcram) lookup errors
 *
 *  Input
 *      status			Pointer to return Error bits
 *
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_fcram_get_lookup_err_log(npi_handle_t,
				    hash_lookup_err_log_t *);



/*
 * npi_fflp_fcram_get_pio_err_log
 * Reports hash table PIO read errors.
 *
 * Input
 *	partid:		partition ID
 *      err_stat	pointer to return Error bits
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */
npi_status_t npi_fflp_fcram_get_pio_err_log(npi_handle_t,
				part_id_t, hash_pio_err_log_t *);


/*
 * npi_fflp_fcram_clr_pio_err_log
 * Clears FCRAM PIO  error status for the partition.
 * If there are TCAM errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *	partid:		partition ID
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */

npi_status_t npi_fflp_fcram_clr_pio_err_log(npi_handle_t,
						part_id_t);



/*
 * npi_fflp_fcram_err_data_test
 * Tests the FCRAM error detection logic.
 * The error detection logic for the datapath is tested.
 * bits [63:0] are set to select the data bits to be xored
 *
 * Input
 *	data:	 data bits to select bits to be xored
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t npi_fflp_fcram_err_data_test(npi_handle_t, fcram_err_data_t *);


/*
 * npi_fflp_fcram_err_synd_test
 * Tests the FCRAM error detection logic.
 * The error detection logic for the syndrome is tested.
 * tst0->synd (8bits) are set to select the syndrome bits
 * to be XOR'ed
 *
 * Input
 *	syndrome_bits:	 Syndrome bits to select bits to be xor'ed
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t npi_fflp_fcram_err_synd_test(npi_handle_t, uint8_t);


/*
 * npi_fflp_cfg_vlan_table_clear
 * Clears the vlan RDC table
 *
 * Input
 *     vlan_id		VLAN ID
 *
 * Output
 *
 *	NPI_SUCCESS			Successful
 *
 */

npi_status_t npi_fflp_cfg_vlan_table_clear(npi_handle_t, vlan_id_t);

/*
 * npi_fflp_cfg_enet_vlan_table_assoc
 * associates port vlan id to rdc table and sets the priority
 * in respect to L2DA rdc table.
 *
 * Input
 *     mac_portn		port number
 *     vlan_id			VLAN ID
 *     rdc_table		RDC Table #
 *     priority			priority
 *				1: vlan classification has higher priority
 *				0: l2da classification has higher priority
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_enet_vlan_table_assoc(npi_handle_t,
				    uint8_t, vlan_id_t,
				    uint8_t, uint8_t);


/*
 * npi_fflp_cfg_enet_vlan_table_set_pri
 * sets the  vlan based classification priority in respect to
 * L2DA classification.
 *
 * Input
 *     mac_portn	port number
 *     vlan_id		VLAN ID
 *     priority 	priority
 *			1: vlan classification has higher priority
 *			0: l2da classification has higher priority
 *
 * Return:
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_enet_vlan_table_set_pri(npi_handle_t,
				    uint8_t, vlan_id_t,
				    uint8_t);

/*
 * npi_fflp_cfg_enet_usr_cls_set()
 * Configures a user configurable ethernet class
 *
 * Input
 *      class:       Ethernet Class
 *		     class (TCAM_CLASS_ETYPE or  TCAM_CLASS_ETYPE_2)
 *      enet_type:   16 bit Ethernet Type value, corresponding ethernet bytes
 *                        [13:14] in the frame.
 *
 *  by default, the class will be disabled until explicitly enabled.
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 *
 *
 */

npi_status_t npi_fflp_cfg_enet_usr_cls_set(npi_handle_t,
				    tcam_class_t, uint16_t);

/*
 * npi_fflp_cfg_enet_usr_cls_enable()
 * Enable previously configured TCAM user configurable Ethernet classes.
 *
 * Input
 *      class:       Ethernet Class  class
 *		     (TCAM_CLASS_ETYPE or  TCAM_CLASS_ETYPE_2)
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_enet_usr_cls_enable(npi_handle_t, tcam_class_t);

/*
 * npi_fflp_cfg_enet_usr_cls_disable()
 * Disables previously configured TCAM user configurable Ethernet classes.
 *
 * Input
 *      class:       Ethernet Class
 *		     class = (TCAM_CLASS_ETYPE or  TCAM_CLASS_ETYPE_2)
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */


npi_status_t npi_fflp_cfg_enet_usr_cls_disable(npi_handle_t, tcam_class_t);


/*
 * npi_fflp_cfg_ip_usr_cls_set()
 * Configures the TCAM user configurable IP classes.
 *
 * Input
 *      class:       IP Class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *      tos:         IP TOS bits
 *      tos_mask:    IP TOS bits mask. bits with mask bits set will be used
 *      proto:       IP Proto
 *      ver:         IP Version
 * by default, will the class is disabled until explicitly enabled
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_ip_usr_cls_set(npi_handle_t,
					tcam_class_t,
					uint8_t, uint8_t,
					uint8_t, uint8_t);

npi_status_t npi_fflp_cfg_ip_usr_cls_set_iptun(npi_handle_t,
		tcam_class_t, uint8_t, uint8_t, uint16_t, uint8_t);

npi_status_t npi_fflp_cfg_ip_usr_cls_get_iptun(npi_handle_t,
		tcam_class_t, uint8_t *, uint8_t *, uint16_t *, uint8_t *);

/*
 * npi_fflp_cfg_ip_usr_cls_enable()
 * Enable previously configured TCAM user configurable IP classes.
 *
 * Input
 *      class:       IP Class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_ip_usr_cls_enable(npi_handle_t, tcam_class_t);

/*
 * npi_fflp_cfg_ip_usr_cls_disable()
 * Disables previously configured TCAM user configurable IP classes.
 *
 * Input
 *      class:       IP Class
 *		     (TCAM_CLASS_IP_USER_4 <= class <= TCAM_CLASS_IP_USER_7)
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */


npi_status_t npi_fflp_cfg_ip_usr_cls_disable(npi_handle_t, tcam_class_t);


/*
 * npi_fflp_cfg_ip_cls_tcam_key ()
 *
 * Configures the TCAM key generation for the IP classes
 *
 * Input
 *      l3_class:        IP class to configure key generation
 *      cfg:             Configuration bits:
 *                   discard:      Discard all frames of this class
 *                   use_ip_saddr: use ip src address (for ipv6)
 *                   use_ip_daddr: use ip dest address (for ipv6)
 *                   lookup_enable: Enable Lookup
 *
 *
 * Return
 * NPI_SUCCESS
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */


npi_status_t npi_fflp_cfg_ip_cls_tcam_key(npi_handle_t,
				    tcam_class_t, tcam_key_cfg_t *);

/*
 * npi_fflp_cfg_ip_cls_flow_key ()
 *
 * Configures the flow key generation for the IP classes
 * Flow key is used to generate the H1 hash function value
 * The fields used for the generation are configured using this
 * NPI function.
 *
 * Input
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
 * NPI_SUCCESS
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_ip_cls_flow_key(npi_handle_t,
			    tcam_class_t, flow_key_cfg_t *);

npi_status_t npi_fflp_cfg_ip_cls_flow_key_get(npi_handle_t,
				    tcam_class_t,
				    flow_key_cfg_t *);

npi_status_t npi_fflp_cfg_ip_cls_flow_key_rfnl(npi_handle_t,
		tcam_class_t, flow_key_cfg_t *);

npi_status_t npi_fflp_cfg_sym_ip_cls_flow_key(npi_handle_t, tcam_class_t,
					boolean_t);

npi_status_t npi_fflp_cfg_ip_cls_flow_key_get_rfnl(npi_handle_t,
			tcam_class_t, flow_key_cfg_t *);

npi_status_t npi_fflp_cfg_ip_cls_tcam_key_get(npi_handle_t,
			tcam_class_t, tcam_key_cfg_t *);
/*
 * npi_fflp_cfg_hash_h1poly()
 * Initializes the H1 hash generation logic.
 *
 * Input
 *      init_value:       The initial value (seed)
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_hash_h1poly(npi_handle_t, uint32_t);



/*
 * npi_fflp_cfg_hash_h2poly()
 * Initializes the H2 hash generation logic.
 *
 * Input
 *      init_value:       The initial value (seed)
 *
 * Return
 * NPI_SUCCESS
 * NPI_FAILURE
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_cfg_hash_h2poly(npi_handle_t, uint16_t);


/*
 * Reset the fflp block (actually the FCRAM)
 * Waits until reset is completed
 *
 * input
 * strength	fcram output drive strength: weak, normal or strong
 * qs		qs mode. Normal or free running
 *
 * return value
 *	  NPI_SUCCESS
 *	  NPI_SW_ERR
 *	  NPI_HW_ERR
 */

npi_status_t npi_fflp_fcram_reset(npi_handle_t,
			    fflp_fcram_output_drive_t,
			    fflp_fcram_qs_t);


/* FFLP TCAM Related Functions */


/*
 * npi_fflp_tcam_entry_match()
 *
 * Tests for TCAM match of the tcam entry
 *
 * Input
 * tcam_ptr
 *
 * Return
 *   NPI_SUCCESS
 *   NPI_SW_ERR
 *   NPI_HW_ERR
 *
 */

int npi_fflp_tcam_entry_match(npi_handle_t, tcam_entry_t *);

/*
 * npi_fflp_tcam_entry_write()
 *
 * writes a tcam entry at the TCAM location, location
 *
 * Input
 * location
 * tcam_ptr
 *
 * Return
 *   NPI_SUCCESS
 *   NPI_SW_ERR
 *   NPI_HW_ERR
 *
 */

npi_status_t npi_fflp_tcam_entry_write(npi_handle_t,
				tcam_location_t,
				tcam_entry_t *);

/*
 * npi_fflp_tcam_entry_read ()
 *
 * Reads a tcam entry from the TCAM location, location
 *
 * Input:
 * location
 * tcam_ptr
 *
 * Return:
 * NPI_SUCCESS
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */


npi_status_t npi_fflp_tcam_entry_read(npi_handle_t,
					tcam_location_t,
					tcam_entry_t *);

/*
 * npi_fflp_tcam_entry_invalidate()
 *
 * invalidates entry at tcam location
 *
 * Input
 * location
 *
 * Return
 *   NPI_SUCCESS
 *   NPI_SW_ERR
 *   NPI_HW_ERR
 *
 */

npi_status_t npi_fflp_tcam_entry_invalidate(npi_handle_t,
				    tcam_location_t);


/*
 * npi_fflp_tcam_asc_ram_entry_write()
 *
 * writes a tcam associatedRAM at the TCAM location, location
 *
 * Input:
 * location	tcam associatedRAM location
 * ram_data	Value to write
 *
 * Return:
 * NPI_SUCCESS
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_tcam_asc_ram_entry_write(npi_handle_t,
				    tcam_location_t,
				    uint64_t);


/*
 * npi_fflp_tcam_asc_ram_entry_read()
 *
 * reads a tcam associatedRAM content at the TCAM location, location
 *
 * Input:
 * location	tcam associatedRAM location
 * ram_data	ptr to return contents
 *
 * Return:
 * NPI_SUCCESS
 * NPI_HW_ERR
 * NPI_SW_ERR
 *
 */

npi_status_t npi_fflp_tcam_asc_ram_entry_read(npi_handle_t,
				    tcam_location_t,
				    uint64_t *);

/*
 * npi_fflp_tcam_get_err_log
 * Reports TCAM PIO read and lookup errors.
 * If there are TCAM errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *	err_stat:	 structure to report various TCAM errors.
 *                       will be updated if there are TCAM errors.
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t npi_fflp_tcam_get_err_log(npi_handle_t, tcam_err_log_t *);



/*
 * npi_fflp_tcam_clr_err_log
 * Clears TCAM PIO read and lookup error status.
 * If there are TCAM errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *	err_stat:	 structure to report various TCAM errors.
 *                       will be updated if there are TCAM errors.
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */

npi_status_t npi_fflp_tcam_clr_err_log(npi_handle_t);





/*
 * npi_fflp_vlan_tbl_clr_err_log
 * Clears VLAN Table PIO  error status.
 * If there are VLAN Table errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *	err_stat:	 structure to report various VLAN Table errors.
 *                       will be updated if there are  errors.
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */

npi_status_t npi_fflp_vlan_tbl_clr_err_log(npi_handle_t);


/*
 * npi_fflp_vlan_tbl_get_err_log
 * Reports VLAN Table  errors.
 * If there are VLAN Table errors as indicated by err bit set by HW,
 *  then the SW will clear it by clearing the bit.
 *
 * Input
 *	err_stat:	 structure to report various VLAN table errors.
 *                       will be updated if there are errors.
 *
 *
 * Return
 *	NPI_SUCCESS	Success
 *
 *
 */
npi_status_t npi_fflp_vlan_tbl_get_err_log(npi_handle_t,
				    vlan_tbl_err_log_t *);




/*
 * npi_rxdma_event_mask_config():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	cfgp		- pointer to NPI defined event mask
 *			  enum data type.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *	NPI_FFLP_ERROR | NPI_FFLP_SW_PARAM_ERROR
 *
 */
npi_status_t
npi_fflp_event_mask_config(npi_handle_t, io_op_t,
			    fflp_event_mask_cfg_t *);

npi_status_t npi_fflp_dump_regs(npi_handle_t);


/* Error status read and clear functions */

void	npi_fflp_vlan_error_get(npi_handle_t,
				    p_vlan_par_err_t);
void	npi_fflp_vlan_error_clear(npi_handle_t);
void	npi_fflp_tcam_error_get(npi_handle_t,
				    p_tcam_err_t);
void	npi_fflp_tcam_error_clear(npi_handle_t);

void	npi_fflp_fcram_error_get(npi_handle_t,
				    p_hash_tbl_data_log_t,
				    uint8_t);
void npi_fflp_fcram_error_clear(npi_handle_t, uint8_t);

void npi_fflp_fcram_error_log1_get(npi_handle_t,
				    p_hash_lookup_err_log1_t);

void npi_fflp_fcram_error_log2_get(npi_handle_t,
			    p_hash_lookup_err_log2_t);

void npi_fflp_vlan_tbl_dump(npi_handle_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_FFLP_H */
