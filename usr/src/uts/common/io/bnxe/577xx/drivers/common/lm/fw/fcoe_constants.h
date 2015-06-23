#ifndef __FCOE_CONSTANTS_H_
#define __FCOE_CONSTANTS_H_


/**
* This file defines HSI constants for the FCOE flows
*/

/* Slow path commands */
#define FCOE_RAMROD_CMD_ID_INIT_FUNC		(FCOE_KCQE_OPCODE_INIT_FUNC)
#define FCOE_RAMROD_CMD_ID_DESTROY_FUNC		(FCOE_KCQE_OPCODE_DESTROY_FUNC)
#define FCOE_RAMROD_CMD_ID_STAT_FUNC		(FCOE_KCQE_OPCODE_STAT_FUNC)
#define FCOE_RAMROD_CMD_ID_OFFLOAD_CONN		(FCOE_KCQE_OPCODE_OFFLOAD_CONN)
#define FCOE_RAMROD_CMD_ID_ENABLE_CONN		(FCOE_KCQE_OPCODE_ENABLE_CONN)
#define FCOE_RAMROD_CMD_ID_DISABLE_CONN		(FCOE_KCQE_OPCODE_DISABLE_CONN)
/* Known only to FW and VBD */
#define FCOE_RAMROD_CMD_ID_TERMINATE_CONN	(0x81)

/* number of elements in the EQ that are reserved for slow path completions, catastrophic error
in case the EQ is (almost) full, and an end of page element */
#define RESERVED_FCOE_EQ_ELEMENTS (MAX_RAMRODS_PER_PORT + 2)

#define REC_TOV_EXPIRATION 1
#define NO_REC_TOV_EXPIRATION 0

#endif //__FCOE_CONSTANTS_H_
