#ifndef __57XX_L5CM_CONSTANTS_H_
#define __57XX_L5CM_CONSTANTS_H_

/**
* This file defines HSI constants for the L4 flows
*/


// KWQ (kernel work queue) request op codes
#define L4_KWQE_OPCODE_VALUE_CONNECT1               (50)
#define L4_KWQE_OPCODE_VALUE_CONNECT2               (51)
#define L4_KWQE_OPCODE_VALUE_CONNECT3               (52)
#define L4_KWQE_OPCODE_VALUE_RESET                  (53)
#define L4_KWQE_OPCODE_VALUE_CLOSE                  (54)
#define L4_KWQE_OPCODE_VALUE_UPDATE_SECRET          (60)
#define L4_KWQE_OPCODE_VALUE_INIT_ULP               (61)

#ifndef L4_KWQE_OPCODE_VALUE_OFFLOAD_PG
#define L4_KWQE_OPCODE_VALUE_OFFLOAD_PG             (1)
#endif

// KCQ (kernel completion queue) response op codes
#define L4_KCQE_OPCODE_VALUE_MINIMUM				(53) /*bottom limit to L4 KCQE values*/
#define L4_KCQE_OPCODE_VALUE_CLOSE_COMP             (53)
#define L4_KCQE_OPCODE_VALUE_RESET_COMP             (54)       
#define L4_KCQE_OPCODE_VALUE_FW_TCP_UPDATE          (55)
#define L4_KCQE_OPCODE_VALUE_CONNECT_COMPLETE       (56)
#define L4_KCQE_OPCODE_VALUE_REMOTE_CONNECTION_ABORTED  (57)                
#define L4_KCQE_OPCODE_VALUE_CLOSE_RECEIVED         (58)
#define L4_KCQE_OPCODE_VALUE_INIT_ULP               (61)
#define L4_KCQE_OPCODE_VALUE_TERMINATE_COMP         (62)
#define L4_KCQE_OPCODE_VALUE_MAXIMUM				(62) /*top limit to L4 KCQE values*/

#ifndef L4_KCQE_OPCODE_VALUE_OFFLOAD_PG
#define L4_KCQE_OPCODE_VALUE_OFFLOAD_PG             (1)
#endif

#ifndef L4_KWQE_OPCODE_VALUE_UPDATE_PG
#define L4_KWQE_OPCODE_VALUE_UPDATE_PG              (9)
#endif

#ifndef L4_KWQE_OPCODE_VALUE_UPLOAD_PG
#define L4_KWQE_OPCODE_VALUE_UPLOAD_PG              (14)
#endif



// KCQ (kernel completion queue) completion status
#define L4_KCQE_COMPLETION_STATUS_SUCCESS		    (0)
#define L4_KCQE_COMPLETION_STATUS_TIMEOUT        (0x93)

#define L4_LAYER_CODE (4)

#endif //__57XX_L5CM_CONSTANTS_H_
