#ifndef __EVEREST_ISCSI_CONSTANTS_H_
#define __EVEREST_ISCSI_CONSTANTS_H_

/**
* This file defines HSI constants for the iSCSI flows
*/

/* Everest general configuartion */
#define ISCSI_NUM_OF_CQS					(8) /*MAX num of CQs*/
#define ISCSI_NUM_OF_EQS					(ISCSI_NUM_OF_CQS*MAX_NUM_OF_PF) /*per port*/
#define ISCSI_NUM_OF_CONNECTIONS			(128)
#define ISCSI_NUM_OF_CONNECTIONS_BOTH_PORTS	(ISCSI_NUM_OF_CONNECTIONS*MAX_NUM_OF_PF)
#define ISCSI_MAX_NUM_OF_PENDING_R2TS		(4)
#define ISCSI_R2TQE_SIZE					(8)
#define ISCSI_NUM_OF_CQ_TIMERS_PER_FUNC		(ISCSI_NUM_OF_CONNECTIONS*ISCSI_NUM_OF_CQS)
#define ISCSI_NUM_OF_CQ_TIMERS				(ISCSI_NUM_OF_CONNECTIONS*ISCSI_NUM_OF_CQS*MAX_NUM_OF_PF) 
#define ISCSI_RQE_SIZE						(256)
#define ISCSI_CQE_SIZE						(64) /* must be equal to sizeof(iscsi_response_t), which is verified using a static assert */
#define ISCSI_GLOBAL_BUF_SIZE				(64)

/* Slow path commands */
#define ISCSI_RAMROD_CMD_ID_UPDATE_CONN					(ISCSI_KCQE_OPCODE_UPDATE_CONN)
#define ISCSI_RAMROD_CMD_ID_INIT						(ISCSI_KCQE_OPCODE_INIT)
// for internal FW processing
#define ISCSI_CMD_ID_INIT_FW_CLEAN_TASK					(ISCSI_KCQE_OPCODE_FW_CLEAN_TASK)

/* iSCSI states */
#define	ISCSI_STATE_SHIFT			(3)
#define ISCSI_STATES_MASK			(3)
#define ISCSI_INIT_STATE			(0 << ISCSI_STATE_SHIFT)
#define ISCSI_OFFLOAD_STATE			(1 << ISCSI_STATE_SHIFT)
#define ISCSI_ERROR_STATE			(2 << ISCSI_STATE_SHIFT)
#define ISCSI_TERMINATION_STATE		(3 << ISCSI_STATE_SHIFT)

/* number of elements in the EQ that are reserved for slow path completions, catastrophic error
   in case the EQ is (almost) full, and an end of page element */
#define RESERVED_ISCSI_EQ_ELEMENTS (MAX_RAMRODS_PER_PORT + 2)

/* EQE Source types */
#define ISCSI_SOURCE_TYPE_NIC	(0)
#define ISCSI_SOURCE_TYPE_CID	(1)

/* EQE Layer */
#define ISCSI_EVENT_LAYER_ULP				(0)
#define ISCSI_EVENT_LAYER_LLP				(1)

/* EQE Completion Types */
#define ISCSI_EVENT_TYPE_FAST_PATH				(0)
#define ISCSI_EVENT_TYPE_SLOW_PATH				(1)

/* the task context Pbl cache entry Index that marks PBL not cached */
#define ISCSI_PBL_NOT_CACHED (0xff) 
#define ISCSI_PDU_HEADER_NOT_CACHED (0xff)


// OOO constants
#define ISCSI_L2_OOO_RX_BDS_THRSHLD_DEFAULT			(5) // threshold for number of available RX BDs 

#endif //__EVEREST_ISCSI_CONSTANTS_H_
