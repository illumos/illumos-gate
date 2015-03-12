/*
********************************************************************************
* $Id: //servers/main/nx2/577xx/hsi/microcode/rdma/headers/rdma_constants.h#39 $ 
********************************************************************************
* $Name:  $ 
********************************************************************************
* $Date: 2007/11/13 $ 
********************************************************************************
* $Revision: #39 $ 
********************************************************************************
* $Author: yaronu $ 
********************************************************************************
* $Log: rdma_constants.h,v $
* Revision 1.37  2007/06/13 11:46:43  yanivr
* Add support for RDMA classifier in favor of the Eth
*
* Revision 1.36  2007/05/31 14:38:45  yanivr
* Enhance PCS request/PCS response scheme
*
* Revision 1.35  2007/05/30 13:35:11  yanivr
* Enable L5cm Passive Connection Establishment
*
* Revision 1.34  2007/04/29 14:58:29  yanivr
* Add RDMA_ASYNC_EVENT_PCS_RESPONSE1_SUCCEEDED, RDMA_ASYNC_EVENT_PCS_RESPONSE2_SUCCEEDED, RDMA_ASYNC_EVENT_PCS_RESPONSE3_SUCCEEDED
*
* Revision 1.33  2007/04/29 12:57:26  yanivr
* Add RDMA_RAMROD_CMD_ID_CLOSE_PHY_PORT defines
*
* Revision 1.32  2007/04/18 18:57:45  yanivr
* Add support for L5cm passive side connection establishment
*
* Revision 1.31  2007/02/22 18:19:11  yanivr
* Move common connection establishments ramrods to L5cm
*
* Revision 1.30  2006/09/19 06:14:39  edreayc
* Insert RDMA Error reporting & Invalidation process
*
* Revision 1.29  2006/08/28 06:32:40  yanivr
* Add RDMA_ASYNC_EVENT_UPDATE_ULP_SUCCEEDED event
*
* Revision 1.28  2006/08/27 15:43:24  yaronu
* - removed old include of rdma_eqe struct from rdma_constants
* - removed old includes to rdma event report files
* - added include to rdma event report structs where needed
*
* Revision 1.27  2006/08/27 15:18:26  yuvalk
* Rdma, Error reporting, Rx
*
* Revision 1.26  2006/08/22 15:38:05  yuvalk
* Rdma - Ustorm, Tstorm Error reporting fixes
*
* Revision 1.25  2006/08/21 15:39:12  yuvalk
* Rdma - added completion code defines for completion errors
*
* Revision 1.24  2006/08/20 17:00:35  yuvalk
* Rdma, Ustorm, Tstorm, Error reporting
*
* Revision 1.23  2006/08/17 14:39:25  yanivr
* Resupport ramrod RDMA_RxLlpSlowPath.cpp
*
* Revision 1.22  2006/08/13 08:34:49  yaronu
* Added some event code constants
*
* Revision 1.21  2006/07/30 08:42:04  yaronu
* renamed SEND_MPA SP command ID to LLP_SEND
*
* Revision 1.20  2006/07/12 09:51:14  yaronu
* Added  new slow path command IDs and event codes
*
* Revision 1.19  2006/06/08 06:27:44  yuvalk
* Rdma -
* Tstorm - some minor changes to better suite ASM code writting
* everest.fmt - added Rdma Xstorm slowPath handler
* microcode.vcproj - marked ASM files as excluded from build
*
* Revision 1.18  2006/05/16 16:25:51  yaronu
* - modified rdma slow path handlers for easier translation into ASM
* - add function execution counter in rdma driversim
*
* Revision 1.17  2006/05/15 11:44:21  yuvalk
* Rdma - changed "rh" prefix in all rdma hsi structs to be "rdma"
*
* Revision 1.16  2006/05/11 16:05:06  yaronu
* - extended Tstorm slow path handler
* - added new Ustorm and Cstorm slow path handlers
* - modified output message argument of Cstorm event report handler
*
* Revision 1.15  2006/05/09 09:38:47  yaronu
* updates to event report handlers and driversim after debugging events with terminate messages
*
* Revision 1.14  2006/05/02 08:07:06  ofirh
* HSI changes before microcode and driver entering lab
*
* Revision 1.13  2006/04/27 16:19:16  yaronu
* - updated driversim event handling
* - created event report handler in Ustorm
* - moved MAX_RAMROD_PER_PORT to hsi
*
* Revision 1.12  2006/04/25 07:59:45  yaronu
* added completion event type
*
* Revision 1.11  2006/04/24 13:34:53  yaronu
* event reporting handler updates
*
* Revision 1.10  2006/04/23 10:02:26  ofirh
* tree change - phase 3
*
* Revision 1.9  2006/04/16 13:00:04  yaronu
* added rdma event processing constants
*
* Revision 1.8  2006/04/05 08:25:37  yaronu
* added handler for rdma error reporting
*
* Revision 1.7  2006/03/21 13:53:31  yuvalk
* Rdma -
* uRdmaSend.cpp - Send Received flow implemented and partially tested
* uRdmaWriteReadResp - fixed bug when ddpLen == pbeSize
*
* Revision 1.6  2006/03/09 08:32:08  vitalyo
* Started implementing data integrity mechanism
*
* Revision 1.5  2006/03/06 10:28:57  vitalyo
* Adding functionality to test engine module
* Adding modify to rts implementation
*
* Revision 1.4  2006/02/22 09:27:59  yuvalk
* Rdma-
* RdmaCommon.cpp - StagLoad - first run on code. some bug fixes
* uRdmaWriteReadResp.cpp - some minor changes
*
* Revision 1.3  2006/02/20 09:41:06  yuvalk
* Rdma - first run on uRdmaWriteReadResp.cpp
* bring up of UstormRdmaSurroundingsRuntime.xml
* RamAccessHeader - fixed bug in RAM_ADDR macro
*
* Revision 1.2  2006/02/13 08:47:18  yuvalk
* Rdma -
* uRdmaWriteReadResp.cpp
* - calling loadPbl function, using 6 PBEs
* - change in cache coherency entry structure
*
* Revision 1.1  2006/02/08 10:39:29  shmulikr
* Microcode Hsi include files
* 
********************************************************************************
*/
#ifndef __RDMA_CONSTANTS_H_
#define __RDMA_CONSTANTS_H_

/**
* This file defines HSI constants for the RDMA flows
*/

#include "microcode_constants.h"

/* SQ WQE operations */
#define EVEREST_SQ_WQE_OP_INTERNAL					(1 << 7)
#define EVEREST_SQ_WQE_OP_INLINE					(1 << 6)

#define EVEREST_SQ_WQE_OP_WRITE						(0)
#define EVEREST_SQ_WQE_OP_WRITE_INLINE				(EVEREST_SQ_WQE_OP_WRITE | EVEREST_SQ_WQE_OP_INLINE)
#define EVEREST_SQ_WQE_OP_READ						(1)
#define EVEREST_SQ_WQE_OP_READ_INVAL_LOCAL			(EVEREST_SQ_WQE_OP_READ | EVEREST_SQ_WQE_OP_INTERNAL)
#define EVEREST_SQ_WQE_OP_READ_RESP					(2) /* not a WQE opcode -  reserved for network opcode only */
#define EVEREST_SQ_WQE_OP_SEND						(3)
#define EVEREST_SQ_WQE_OP_SEND_INVAL				(4)
#define EVEREST_SQ_WQE_OP_SEND_SE					(5)
#define EVEREST_SQ_WQE_OP_SEND_SE_INVAL				(6)
#define EVEREST_SQ_WQE_OP_SEND_INLINE				(EVEREST_SQ_WQE_OP_SEND				| EVEREST_SQ_WQE_OP_INLINE)
#define EVEREST_SQ_WQE_OP_SEND_INVAL_INLINE			(EVEREST_SQ_WQE_OP_SEND_INVAL		| EVEREST_SQ_WQE_OP_INLINE)
#define EVEREST_SQ_WQE_OP_SEND_SE_INLINE			(EVEREST_SQ_WQE_OP_SEND_SE			| EVEREST_SQ_WQE_OP_INLINE)
#define EVEREST_SQ_WQE_OP_SEND_SE_INVAL_INLINE		(EVEREST_SQ_WQE_OP_SEND_SE_INVAL	| EVEREST_SQ_WQE_OP_INLINE)
#define EVEREST_SQ_WQE_OP_TERMINATE					(7)

#define EVEREST_SQ_WQE_OP_BIND_MEM_WINDOW			((8)	| EVEREST_SQ_WQE_OP_INTERNAL) 
#define EVEREST_SQ_WQE_OP_FAST_MEM_REGISTER			((9)	| EVEREST_SQ_WQE_OP_INTERNAL)
#define EVEREST_SQ_WQE_OP_INVAL_LOCAL				((10)	| EVEREST_SQ_WQE_OP_INTERNAL)
#define EVEREST_SQ_WQE_INVALID_OPCODE				(0xFF)

/* DDP and RDMAP versions */
#define RDMA_RDMAP_DDP_VERSION_RDMAC	(0)		/* RDMAP and DDP versions must have the same value hence use the same "define" */
#define RDMA_RDMAP_DDP_VERSION_IETF		(1)		/* RDMAP and DDP versions must have the same value hence use the same "define" */

/* MPA Markers */
#define RDMA_MPA_USE_MARKERS_FLAG (0x8000)

/* CQE constants */
#define RDMA_CQE_TYPE_NON_AGGR	(1)
#define RDMA_CQE_STATUS_OK		(0)

/* RQ WQE constants */
#define RDMA_RQ_WQE_SHIFT		(6)
#define RDMA_RQ_WQE_SGL_SIZE_SMALL		(2) /* number of SGES in 64 byte WQE */
#define RDMA_RQ_WQE_SGL_SIZE_BIG		(6) /* number of SGES in 128 byte WQE */

/* Slow path commands */
#define RDMA_RAMROD_CMD_ID_SEND_MPA						(14)
#define RDMA_RAMROD_CMD_ID_UPDATE_ULP					(15)
#define	RDMA_RAMROD_CMD_ID_CLOSE_PHY_PORT				(16)

/* Terminate message constants */
#define RDMA_MAX_TERMINATE_MESSAGE_SIZE (52) // in bytes


#define RDMA_FWD_MODE_L2	(0)
#define RDMA_FWD_MODE_RDMA	(1)
/* Event reporting constants */

// number of elements in the EQ that are reserved for slow path completions, catastrophic error
// in case the EQ is (almost) full, and an end of page element
#define RESERVED_EQ_ELEMENTS (MAX_RAMRODS_PER_PORT + 2)

// Event types
#define RDMA_EVENT_TYPE_ASYNC					(0)
#define RDMA_EVENT_TYPE_ERROR					(1)
#define RDMA_EVENT_TYPE_TERMINATE_MESSAGE		(2)
#define RDMA_EVENT_TYPE_SLOW_PATH_COMPLETION	(3)

// Source types
#define RDMA_SOURCE_TYPE_RNIC	(0)
#define RDMA_SOURCE_TYPE_QP		(1)
#define RDMA_SOURCE_TYPE_CQ		(2)
#define RDMA_SOURCE_TYPE_SRQ	(3)

// Queue types
#define RDMA_QUEUE_TYPE_NONE	(0)
#define RDMA_QUEUE_TYPE_SQ		(1)
#define RDMA_QUEUE_TYPE_RQ		(2)
#define RDMA_QUEUE_TYPE_IRQ		(3)
#define RDMA_QUEUE_TYPE_SRQ		(4)

// Asynchronous event types - from Verbs
#define RDMA_ASYNC_EVENT_LLP_CLOSE_COMPLETE						(0)
#define RDMA_ASYNC_EVENT_TERMINATE_MESSAGE_RECEIVED				(1)
#define RDMA_ASYNC_EVENT_LLP_CONNECTION_RESET					(2)
#define RDMA_ASYNC_EVENT_LLP_CONNECTION_LOST					(3)
#define RDMA_ASYNC_EVENT_LLP_INTEGRITY_INVALID_SEGMENT_SIZE		(4)
#define RDMA_ASYNC_EVENT_LLP_INTEGRITY_INVALID_CRC				(5)
#define RDMA_ASYNC_EVENT_LLP_INTEGRITY_BAD_FPDU					(6)
#define RDMA_ASYNC_EVENT_REMOTE_INVALID_DDP_VERSION				(7)
#define RDMA_ASYNC_EVENT_REMOTE_INVALID_RDMA_VERSION			(8)
#define RDMA_ASYNC_EVENT_REMOTE_UNEXPECTED_OPCODE				(9)
#define RDMA_ASYNC_EVENT_REMOTE_INVALID_DDP_QUEUE_NUMBER		(10)
#define RDMA_ASYNC_EVENT_REMOTE_READ_REQUEST_DISABLED			(11)
#define RDMA_ASYNC_EVENT_REMOTE_WRITE_OR_READ_RESPONSE_DISABLED (12)
#define RDMA_ASYNC_EVENT_REMOTE_INVALID_READ_REQUEST			(13)
#define RDMA_ASYNC_EVENT_REMOTE_NO_L_BIT						(14)
#define RDMA_ASYNC_EVENT_PROTECTION_INVALID_STAG				(15)
#define RDMA_ASYNC_EVENT_PROTECTION_TAGGED_BOUNDS_VIOLATION		(16)
#define RDMA_ASYNC_EVENT_PROTECTION_TAGGED_ACCESS_VIOLATION		(17)
#define RDMA_ASYNC_EVENT_PROTECTION_TAGGED_INVALID_PD			(18)
#define RDMA_ASYNC_EVENT_PROTECTION_WRAP_ERROR					(19)
#define RDMA_ASYNC_EVENT_BAD_CLOSE								(20)
#define RDMA_ASYNC_EVENT_BAD_LLP_CLOSE							(21)
#define RDMA_ASYNC_EVENT_RQ_PROTECTION_INVALID_MSN_RANGE		(22)
#define RDMA_ASYNC_EVENT_RQ_PROTECTION_INVALID_MSN_GAP			(23)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_TOO_MANY_READ_REQUEST	(24)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_INVALID_MSN_GAP			(25)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_INVALID_MSN_RANGE		(26)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_INVALID_STAG			(27)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_TAGGED_BOUNDS_VIOLATION (28)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_TAGGED_ACCESS_VIOLATION (29)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_TAGGED_INVALID_PD		(30)
#define RDMA_ASYNC_EVENT_IRQ_PROTECTION_WRAP_ERROR				(31)
#define RDMA_ASYNC_EVENT_SQ_COMPLETION_CQ_OVERFLOW				(32)
#define RDMA_ASYNC_EVENT_RQ_COMPLETION_CQ_OPERATION_ERROR		(33)
#define RDMA_ASYNC_EVENT_SRQ_ERROR_ON_QP						(34)
#define RDMA_ASYNC_EVENT_LOCAL_QP_CATASTROPHIC_ERROR			(35)
#define RDMA_ASYNC_EVENT_CQ_OVERFLOW							(36)
#define RDMA_ASYNC_EVENT_CQ_OPERATION_ERROR						(37)
#define RDMA_ASYNC_EVENT_SRQ_LIMIT_REACHED						(38)
#define RDMA_ASYNC_EVENT_RQ_LIMIT_REACHED						(39)
#define RDMA_ASYNC_EVENT_SRQ_CATASTROPHIC_ERROR					(40)
#define RDMA_ASYNC_EVENT_RNIC_CATASTROPHIC_ERROR				(41)
#define RDMA_ASYNC_EVENT_COMPLETION								(42)
#define RDMA_ASYNC_EVENT_SLOW_PATH_COMPLETION_SUCCEEDED			(43)
#define RDMA_ASYNC_EVENT_SLOW_PATH_COMPLETION_FAILED			(44)
#define RDMA_ASYNC_EVENT_CONNECTION_LIMIT_REACHED			    (45)
#define RDMA_ASYNC_EVENT_ADD_NEW_CONNECTION_SUCCEEDED			(46)
#define RDMA_ASYNC_EVENT_CONNECT_SUCCEEDED					    (47)
#define RDMA_ASYNC_EVENT_SEND_MPA_SUCCEEDED						(48)
#define RDMA_ASYNC_EVENT_CONNECT_COMPLETE_SUCCEEDED				(49)
#define RDMA_ASYNC_EVENT_CONNECT_COMPLETE_FAILED				(50)
#define RDMA_ASYNC_EVENT_RECEIVED_MPA_SUCCEEDED					(51)
#define RDMA_ASYNC_EVENT_UPDATE_ULP_SUCCEEDED					(52)
#define RDMA_ASYNC_EVENT_PCS_REQUEST1							(53) // SYN RECEIVED
#define RDMA_ASYNC_EVENT_PCS_REQUEST2							(54) // Final-Ack received with MPA request
#define RDMA_ASYNC_EVENT_PCS_REQUEST3							(55) // Final-Ack received with DDP segment
#define RDMA_ASYNC_EVENT_PCS_REQUEST4							(56) // send segment through the forward channel
#define RDMA_ASYNC_EVENT_PCS_RESPONSE1_SUCCEEDED				(57)	
#define	RDMA_ASYNC_EVENT_PCS_RESPONSE2_SUCCEEDED				(58)
#define	RDMA_ASYNC_EVENT_PCS_RESPONSE3_SUCCEEDED				(59)
#define RDMA_ASYNC_EVENT_PCS_RESPONSE4_SUCCEEDED				(60) 
#define RDMA_ASYNC_EVENT_PCS_RESPONSE_FAILED					(61)
#define	RDMA_ASYNC_EVENT_INIT_SEED_SUCCEEDED					(62)
#define	RDMA_ASYNC_EVENT_UPDATE_SEED_SUCCEEDED					(63)
#define RDMA_ASYNC_EVENT_CLOSE_PHY_PORT_SUCCEEDED				(64)
#define RDMA_ASYNC_EVENT_LOCAL_CATASTROPHIC_ERROR				(65)
#define RDMA_COMPLETION_CODE_INVALID_REGION_STAG				(66)  // bind/FR
#define RDMA_COMPLETION_CODE_INVALID_WINDOW_STAG				(67)  // bind//FR
#define RDMA_COMPLETION_CODE_BASE_AND_BOUNDS_VIOLATION			(68)  //Bind
#define RDMA_COMPLETION_CODE_RIGHTS_ACCESS_VIOLATION			(69)  //Bind
#define RDMA_COMPLETION_CODE_STAG_NOT_IN_INVALID_STATE			(70)  // fast-register, bind 
#define RDMA_COMPLETION_MR_NOT_IN_VALID_STATE					(71)  // fast-register, bind 
#define RDMA_COMPLETION_CODE_INVALID_PD_ID						(72)  // fast-register, bind //used


// Asyncronous event types <--> Completion status codes (Everest specific)
#define RDMA_COMPLETION_CODE_QP_CATASTROPHIC_ERROR						(254)
#define RDMA_COMPLETION_CODE_REMOTE_TERMINATION_ERROR					(253)
#define RDMA_COMPLETION_CODE_INVALID_STAG								(252) 
#define RDMA_COMPLETION_CODE_ACCESS_VIOLATION							(251) 
#define RDMA_COMPLETION_CODE_INVALID_PD									(250) 
#define RDMA_COMPLETION_CODE_WRAP_ERROR									(249) 
#define RDMA_COMPLETION_CODE_INVALIDATE_STAG_PD_OR_ACCESS_RIGHTS_ERROR	(248)  
#define RDMA_COMPLETION_CODE_ZERO_ORD									(247)  
#define RDMA_COMPLETION_CODE_QP_NOT_IN_PRIVILEGED_MODE					(246)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_PAGE_SIZE							(245)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_PHYSICAL_BUFFER_SIZE				(244)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_PHYSICAL_BUFFER_LIST_ENTRY			(243)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_FBO								(242)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_FR_LENGTH							(241)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_ACCESS_RIGHTS						(240)  // fast-register
#define RDMA_COMPLETION_CODE_PHYSICAL_BUFFER_LIST_TOO_LONG				(239)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_VA									(238)  // fast-register
#define RDMA_COMPLETION_CODE_INVALID_LENGTH								(237)  
#define RDMA_COMPLETION_CODE_TRYING_TO_BIND_AND_QP_DOESNT_SUPPORT_BIND	(236)	// bind
#define RDMA_COMPLETION_MR_DOESNT_HAVE_BIND_MW_PREEMPTION				(235)  // bind 
#define RDMA_COMPLETION_STAG_KEY_DOESNT_MATCH							(234)  // bind 
#define RDMA_COMPLETION_MR_IS_ZERO_BASED								(233)  //bind

#define RDMA_COMPLETION_CODE_INVALID_WQE								(232)

// Everest specific async events
#define RDMA_ASYNC_EVENT_RQ_EMPTY										(85)


#define RDMA_ASYNC_EVENT_INVALID_EVENT									(0xFF)


// Terminate codes
#define RDMA_TERM_CODE_LLP_CLOSE_COMPLETE						(0)
#define RDMA_TERM_CODE_TERMINATE_MESSAGE_RECEIVED				(0)
#define RDMA_TERM_CODE_LLP_CONNECTION_RESET						(0)
#define RDMA_TERM_CODE_LLP_CONNECTION_LOST						(0)
#define RDMA_TERM_CODE_LLP_INTEGRITY_INVALID_SEGMENT_SIZE		(0x1000)
#define RDMA_TERM_CODE_LLP_INTEGRITY_INVALID_CRC				(0x0202)
#define RDMA_TERM_CODE_LLP_INTEGRITY_BAD_FPDU					(0x0203)
#define RDMA_TERM_CODE_REMOTE_INVALID_DDP_VERSION				(0x1206)
#define RDMA_TERM_CODE_REMOTE_INVALID_RDMA_VERSION				(0x0205)
#define RDMA_TERM_CODE_REMOTE_UNEXPECTED_OPCODE					(0x0206)
#define RDMA_TERM_CODE_REMOTE_INVALID_DDP_QUEUE_NUMBER			(0x1201)
#define RDMA_TERM_CODE_REMOTE_READ_REQUEST_DISABLED				(0x1201)
#define RDMA_TERM_CODE_REMOTE_WRITE_OR_READ_RESPONSE_DISABLED	(0)
#define RDMA_TERM_CODE_REMOTE_INVALID_READ_REQUEST				(0)
#define RDMA_TERM_CODE_REMOTE_NO_L_BIT							(0x0207)
#define RDMA_TERM_CODE_PROTECTION_INVALID_STAG					(0x1100)
#define RDMA_TERM_CODE_PROTECTION_TAGGED_BOUNDS_VIOLATION		(0x1101)
#define RDMA_TERM_CODE_PROTECTION_TAGGED_ACCESS_VIOLATION		(0x1102)
#define RDMA_TERM_CODE_PROTECTION_TAGGED_INVALID_PD				(0x1102)
#define RDMA_TERM_CODE_PROTECTION_WRAP_ERROR					(0x1103)
#define RDMA_TERM_CODE_BAD_CLOSE								(0)
#define RDMA_TERM_CODE_BAD_LLP_CLOSE							(0x0207)
#define RDMA_TERM_CODE_RQ_PROTECTION_INVALID_MSN_RANGE			(0x1202)
#define RDMA_TERM_CODE_RQ_PROTECTION_INVALID_MSN_GAP			(0x1202)
#define RDMA_TERM_CODE_IRQ_PROTECTION_TOO_MANY_READ_REQUEST		(0x1203)
#define RDMA_TERM_CODE_IRQ_PROTECTION_INVALID_MSN_GAP			(0x1203)
#define RDMA_TERM_CODE_IRQ_PROTECTION_INVALID_MSN_RANGE			(0x1203)
#define RDMA_TERM_CODE_IRQ_PROTECTION_INVALID_STAG				(0x0100)
#define RDMA_TERM_CODE_IRQ_PROTECTION_TAGGED_BOUNDS_VIOLATION	(0x0101)
#define RDMA_TERM_CODE_IRQ_PROTECTION_TAGGED_ACCESS_VIOLATION	(0x0102)
#define RDMA_TERM_CODE_IRQ_PROTECTION_TAGGED_INVALID_PD			(0x0103)
#define RDMA_TERM_CODE_IRQ_PROTECTION_WRAP_ERROR				(0x0104)
#define RDMA_TERM_CODE_SQ_COMPLETION_CQ_OVERFLOW				(0x0207)
#define RDMA_TERM_CODE_RQ_COMPLETION_CQ_OPERATION_ERROR			(0x0207)
#define RDMA_TERM_CODE_SRQ_ERROR_ON_QP							(0x0207)
#define RDMA_TERM_CODE_LOCAL_QP_CATASTROPHIC_ERROR				(0x0207)
#define RDMA_TERM_CODE_LOCAL_CATASTROPHIC_ERROR					(0x0)
#define RDMA_TERM_CODE_CQ_OVERFLOW								(0)
#define RDMA_TERM_CODE_CQ_OPERATION_ERROR						(0)
#define RDMA_TERM_CODE_SRQ_LIMIT_REACHED						(0)
#define RDMA_TERM_CODE_RQ_LIMIT_REACHED							(0)
#define RDMA_TERM_CODE_SRQ_CATASTROPHIC_ERROR					(0)
#define RDMA_TERM_CODE_RNIC_CATASTROPHIC_ERROR					(0x0208)
// Terminate codes for RQ completion errors
#define RDMA_TERM_CODE_RQ_WQE_ERROR								0
#define RDMA_TERM_CODE_RQ_INVALIDATE_STAG_INVALID				(0x0100)
#define RDMA_TERM_CODE_RQ_INVALIDATE_STAG_ACCESS_RIGHTS			(0x0102)
#define RDMA_TERM_CODE_RQ_INVALIDATE_STAG_INVALID_PD_ID			(0x0103)
#define RDMA_TERM_CODE_RQ_INVALIDATE_STAG_NOT_BOUND_TO_QP		(0x0103)
#define RDMA_TERM_CODE_RQ_INVALIDATE_MR_STAG_HAD_BOUND_MW		(0x0103)

// Terminate message control fields
// Layer name mask
#define	RDMA_TERM_LAYER_MASK(termErrCode)						(((termErrCode) >> 12) & 0xf)
// Error type mask
#define	RDMA_TERM_ERR_TYPE_MASK(termErrCode)					(((termErrCode) >> 8) & 0xf)
// Error code mask
#define	RDMA_TERM_ERR_CODE_MASK(termErrCode)					((termErrCode) & 0xff)


#endif //__RDMA_CONSTANTS_H_
