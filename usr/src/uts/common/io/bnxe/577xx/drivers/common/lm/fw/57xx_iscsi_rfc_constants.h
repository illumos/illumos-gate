#ifndef __57XX_ISCSI_RFC_CONSTANTS_H_
#define __57XX_ISCSI_RFC_CONSTANTS_H_

/**
* This file defines SCSI/iSCSI RFC constants
*/

/* iSCSI request op codes */
#define ISCSI_OPCODE_NOP_OUT        (0 | 0x40)
#define ISCSI_OPCODE_SCSI_CMD       (1)
#define ISCSI_OPCODE_TMF_REQUEST    (2 | 0x40)
#define ISCSI_OPCODE_LOGIN_REQUEST  (3 | 0x40)
#define ISCSI_OPCODE_TEXT_REQUEST   (4 | 0x40)
#define ISCSI_OPCODE_DATA_OUT       (5)
#define ISCSI_OPCODE_LOGOUT_REQUEST (6 | 0x00)

/* iSCSI response/messages op codes */
#define ISCSI_OPCODE_NOP_IN             (0x20)
#define ISCSI_OPCODE_SCSI_RESPONSE      (0x21)
#define ISCSI_OPCODE_TMF_RESPONSE       (0x22)
#define ISCSI_OPCODE_LOGIN_RESPONSE     (0x23)
#define ISCSI_OPCODE_TEXT_RESPONSE      (0x24)
#define ISCSI_OPCODE_DATA_IN            (0x25)
#define ISCSI_OPCODE_LOGOUT_RESPONSE    (0x26)
#define ISCSI_OPCODE_R2T                (0x31)
#define ISCSI_OPCODE_ASYNC_MSG          (0x32)
#define ISCSI_OPCODE_REJECT             (0x3f)

/* iSCSI stages */
#define ISCSI_STAGE_SECURITY_NEGOTIATION            (0)
#define ISCSI_STAGE_LOGIN_OPERATIONAL_NEGOTIATION   (1)
#define ISCSI_STAGE_FULL_FEATURE_PHASE              (3)

/* SCSI command response codes */
#define ISCSI_SCSI_CMD_RESPONSE_CMD_COMPLETED   (0x00)
#define ISCSI_SCSI_CMD_RESPONSE_TARGET_FAILURE  (0x01)

/* SCSI command status codes */
#define ISCSI_SCSI_CMD_STATUS_GOOD              (0x00)
#define ISCSI_SCSI_CMD_STATUS_CHECK_CONDITION   (0x02)
#define ISCSI_SCSI_CMD_STATUS_INTERMIDIATE      (0x10)
#define ISCSI_SCSI_CMD_STATUS_ACA_ACTIVE		(0x30)

/* TMF codes */
#define ISCSI_TMF_ABORT_TASK            (1)
#define ISCSI_TMF_LOGICAL_UNIT_RESET    (5)
#define ISCSI_TMF_FUNCTION_MASK         (0x7F)

/* TMF response codes */
#define ISCSI_TMF_RESPONSE_FUNCTION_COMPLETE                (0x00)
#define ISCSI_TMF_RESPONSE_TASK_DOESNT_EXIST                (0x01)
#define ISCSI_TMF_RESPONSE_LUN_DOESNT_EXIST                 (0x02)
#define ISCSI_TMF_RESPONSE_TASK_STILL_ALLEGIANT	            (0x03)
#define ISCSI_TMF_RESPONSE_FUNCTION_NOT_SUPPORTED           (0x05)
#define ISCSI_TMF_RESPONSE_FUNCTION_AUTHORIZATION_FAILED    (0x06)
#define ISCSI_TMF_RESPONSE_FUNCTION_REJECTED                (0xff)

/* Logout reason codes */
#define ISCSI_LOGOUT_REASON_CLOSE_CONNECTION    (1)

/* Logout response codes */
#define ISCSI_LOGOUT_RESPONSE_CONNECTION_CLOSED (0)
#define ISCSI_LOGOUT_RESPONSE_CID_NOT_FOUND     (1)
#define ISCSI_LOGOUT_RESPONSE_CLEANUP_FAILED    (3)

/* iSCSI parameter defaults */
#define ISCSI_DEFAULT_HEADER_DIGEST         (0)
#define ISCSI_DEFAULT_DATA_DIGEST           (0)
#define ISCSI_DEFAULT_INITIAL_R2T           (1)
#define ISCSI_DEFAULT_IMMEDIATE_DATA        (1)
#define ISCSI_DEFAULT_MAX_PDU_LENGTH        (0x2000)
#define ISCSI_DEFAULT_FIRST_BURST_LENGTH    (0x10000)
#define ISCSI_DEFAULT_MAX_BURST_LENGTH      (0x40000)
#define ISCSI_DEFAULT_MAX_OUTSTANDING_R2T   (1)

/* iSCSI parameter limits */
#define ISCSI_MIN_VAL_MAX_PDU_LENGTH        (0x200)
#define ISCSI_MAX_VAL_MAX_PDU_LENGTH        (0xffffff)
#define ISCSI_MIN_VAL_BURST_LENGTH          (0x200)
#define ISCSI_MAX_VAL_BURST_LENGTH          (0xffffff)
#define ISCSI_MIN_VAL_MAX_OUTSTANDING_R2T   (1)
#define ISCSI_MAX_VAL_MAX_OUTSTANDING_R2T   (0xff) // 0x10000 according to RFC

#endif /*__57XX_ISCSI_RFC_CONSTANTS_H_ */
