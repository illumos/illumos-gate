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

#ifndef __STORAGE_COMMON__
#define __STORAGE_COMMON__ 
/*********************/
/* SCSI CONSTANTS */
/*********************/


#define NUM_OF_CMDQS_CQS (NUM_OF_GLOBAL_QUEUES / 2)
// Each Resource ID is one-one-valued mapped by the driver to a BDQ Resource ID (for instance per port)
#define BDQ_NUM_RESOURCES (4)

// ID 0 : RQ, ID 1 : IMMEDIATE_DATA:
#define BDQ_ID_RQ			 (0)
#define BDQ_ID_IMM_DATA  	 (1)
#define BDQ_NUM_IDS          (2) 

#define SCSI_NUM_SGES_SLOW_SGL_THR	8

#define BDQ_MAX_EXTERNAL_RING_SIZE (1<<15)




/*
 * SCSI buffer descriptor
 */
struct scsi_bd
{
	struct regpair address /* Physical Address of buffer */;
	struct regpair opaque /* Driver Metadata (preferably Virtual Address of buffer) */;
};


/*
 * Scsi Drv BDQ struct
 */
struct scsi_bdq_ram_drv_data
{
	__le16 external_producer /* BDQ External Producer; updated by driver when it loads BDs to External Ring */;
	__le16 reserved0[3];
};


/*
 * SCSI SGE entry
 */
struct scsi_sge
{
	struct regpair sge_addr /* SGE address */;
	__le32 sge_len /* SGE length */;
	__le32 reserved;
};

/*
 * Cached SGEs section
 */
struct scsi_cached_sges
{
	struct scsi_sge sge[4] /* Cached SGEs section */;
};


/*
 * Scsi Drv CMDQ struct
 */
struct scsi_drv_cmdq
{
	__le16 cmdq_cons /* CMDQ consumer - updated by driver when CMDQ is consumed */;
	__le16 reserved0;
	__le32 reserved1;
};


/*
 * Common SCSI init params passed by driver to FW in function init ramrod 
 */
struct scsi_init_func_params
{
	__le16 num_tasks /* Number of tasks in global task list */;
	u8 log_page_size /* log of page size value */;
	u8 debug_mode /* Use iscsi_debug_mode enum */;
	u8 reserved2[12];
};


/*
 * SCSI RQ/CQ/CMDQ firmware function init parameters
 */
struct scsi_init_func_queues
{
	struct regpair glbl_q_params_addr /* Global Qs (CQ/RQ/CMDQ) params host address */;
	__le16 rq_buffer_size /* The buffer size of RQ BDQ */;
	__le16 cq_num_entries /* CQ num entries */;
	__le16 cmdq_num_entries /* CMDQ num entries */;
	u8 bdq_resource_id /* Each function-init Ramrod maps its funciton ID to a BDQ function ID, each BDQ function ID contains per-BDQ-ID BDQs */;
	u8 q_validity;
#define SCSI_INIT_FUNC_QUEUES_RQ_VALID_MASK        0x1
#define SCSI_INIT_FUNC_QUEUES_RQ_VALID_SHIFT       0
#define SCSI_INIT_FUNC_QUEUES_IMM_DATA_VALID_MASK  0x1
#define SCSI_INIT_FUNC_QUEUES_IMM_DATA_VALID_SHIFT 1
#define SCSI_INIT_FUNC_QUEUES_CMD_VALID_MASK       0x1
#define SCSI_INIT_FUNC_QUEUES_CMD_VALID_SHIFT      2
#define SCSI_INIT_FUNC_QUEUES_RESERVED_VALID_MASK  0x1F
#define SCSI_INIT_FUNC_QUEUES_RESERVED_VALID_SHIFT 3
	u8 num_queues /* Number of continuous global queues used */;
	u8 queue_relative_offset /* offset of continuous global queues used */;
	u8 cq_sb_pi /* Protocol Index of CQ in status block (CQ consumer) */;
	u8 cmdq_sb_pi /* Protocol Index of CMDQ in status block (CMDQ consumer) */;
	__le16 cq_cmdq_sb_num_arr[NUM_OF_CMDQS_CQS] /* CQ/CMDQ status block number array */;
	__le16 reserved0 /* reserved */;
	u8 bdq_pbl_num_entries[BDQ_NUM_IDS] /* Per BDQ ID, the PBL page size (number of entries in PBL) */;
	struct regpair bdq_pbl_base_address[BDQ_NUM_IDS] /* Per BDQ ID, the PBL page Base Address */;
	__le16 bdq_xoff_threshold[BDQ_NUM_IDS] /* BDQ XOFF threshold - when number of entries will be below that TH, it will send XOFF */;
	__le16 bdq_xon_threshold[BDQ_NUM_IDS] /* BDQ XON threshold - when number of entries will be above that TH, it will send XON */;
	__le16 cmdq_xoff_threshold /* CMDQ XOFF threshold - when number of entries will be below that TH, it will send XOFF */;
	__le16 cmdq_xon_threshold /* CMDQ XON threshold - when number of entries will be above that TH, it will send XON */;
	__le32 reserved1 /* reserved */;
};


/*
 * Scsi Drv BDQ Data struct (2 BDQ IDs: 0 - RQ, 1 - Immediate Data)
 */
struct scsi_ram_per_bdq_resource_drv_data
{
	struct scsi_bdq_ram_drv_data drv_data_per_bdq_id[BDQ_NUM_IDS] /* External ring data */;
};



/*
 * SCSI SGL types
 */
enum scsi_sgl_mode
{
	SCSI_TX_SLOW_SGL /* Slow-SGL: More than SCSI_NUM_SGES_SLOW_SGL_THR SGEs and there is at least 1 middle SGE than is smaller than a page size. May be only at TX  */,
	SCSI_FAST_SGL /* Fast SGL: Less than SCSI_NUM_SGES_SLOW_SGL_THR SGEs or all middle SGEs are at least a page size */,
	MAX_SCSI_SGL_MODE
};


/*
 * SCSI SGL parameters
 */
struct scsi_sgl_params
{
	struct regpair sgl_addr /* SGL base address */;
	__le32 sgl_total_length /* SGL total legnth (bytes)  */;
	__le32 sge_offset /* Offset in SGE (bytes) */;
	__le16 sgl_num_sges /* Number of SGLs sges */;
	u8 sgl_index /* SGL index */;
	u8 reserved;
};


/*
 * SCSI terminate connection params
 */
struct scsi_terminate_extra_params
{
	__le16 unsolicited_cq_count /* Counts number of CQ placements done due to arrival of unsolicited packets on this connection */;
	__le16 cmdq_count /* Counts number of CMDQ placements on this connection */;
	u8 reserved[4];
};

#endif /* __STORAGE_COMMON__ */
