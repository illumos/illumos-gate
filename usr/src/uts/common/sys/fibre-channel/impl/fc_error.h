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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FC_ERROR_H
#define	_FC_ERROR_H

#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * If there are a good set of status, reason (may be action, expln)
 * values, an FC_FAILURE function return code should be enough.
 * Otherwise pick and choose your favorite from here. Try consulting
 * the transport programming guide for any help. If that doesn't help,
 * watch the blue sky.
 *
 * Geez, FC_ is already in use in vm/faultcode.h. Hope it won't grow
 * much. The FC_NOMAP is already a defined Value there. So defining
 * FC_NOMAP as FC_NO_MAP here. Remember to keep a tab on faultcode.h
 *
 */
#define	FC_FAILURE		-1	/* general failure */
#define	FC_FAILURE_SILENT	-2	/* general failure but fail silently */
#define	FC_SUCCESS		0x00	/* successful completion */
#define	FC_CAP_ERROR		0x01	/* FCA capability error */
#define	FC_CAP_FOUND		0x02	/* FCA capability unsettable */
#define	FC_CAP_SETTABLE		0x03	/* FCA capability settable */
#define	FC_UNBOUND		0x04	/* unbound stuff */
#define	FC_NOMEM		0x05	/* allocation error */
#define	FC_BADPACKET		0x06	/* invalid packet specified/supplied */
#define	FC_OFFLINE		0x07	/* I/O resource unavailable */
#define	FC_OLDPORT		0x08	/* operation on non-loop port */
#define	FC_NO_MAP		0x09	/* requested map unavailable */
#define	FC_TRANSPORT_ERROR	0x0A	/* unable to transport I/O */
#define	FC_ELS_FREJECT		0x0B	/* ELS rejected by a Fabric */
#define	FC_ELS_PREJECT		0x0C	/* ELS rejected by an N_port */
#define	FC_ELS_BAD		0x0D	/* ELS rejected by FCA/fctl */
#define	FC_ELS_MALFORMED	0x0E	/* poorly formed ELS request */
#define	FC_TOOMANY		0x0F	/* resource request too large */
#define	FC_UB_BADTOKEN		0x10	/* invalid unsolicited buffer token */
#define	FC_UB_ERROR		0x11	/* invalid unsol buf request */
#define	FC_UB_BUSY		0x12	/* buffer already in use */
#define	FC_BADULP		0x15	/* Unknown ulp */
#define	FC_BADTYPE		0x16	/* ULP not registered to */
					/* handle this FC4 type */
#define	FC_UNCLAIMED		0x17	/* request or data not claimed */
#define	FC_ULP_SAMEMODULE	0x18	/* module already in use */
#define	FC_ULP_SAMETYPE		0x19	/* FC4 module already in use */
#define	FC_ABORTED		0x20	/* request aborted */
#define	FC_ABORT_FAILED		0x21	/* abort request failed */
#define	FC_BADEXCHANGE		0x22	/* exchange doesnÕt exist */
#define	FC_BADWWN		0x23	/* WWN not recognized */
#define	FC_BADDEV		0x24	/* device unrecognized */
#define	FC_BADCMD		0x25	/* invalid command issued */
#define	FC_BADOBJECT		0x26	/* invalid object requested */
#define	FC_BADPORT		0x27	/* invalid port specified */
#define	FC_NOTTHISPORT		0x30	/* resource not at this port */
#define	FC_PREJECT		0x31	/* reject at remote N_Port */
#define	FC_FREJECT		0x32	/* reject at remote Fabric */
#define	FC_PBUSY		0x33	/* remote N_Port busy */
#define	FC_FBUSY		0x34	/* remote Fabric busy */
#define	FC_ALREADY		0x35	/* already logged in */
#define	FC_LOGINREQ		0x36	/* login required */
#define	FC_RESETFAIL		0x37	/* reset failed */
#define	FC_INVALID_REQUEST	0x38	/* request is invalid */
#define	FC_OUTOFBOUNDS		0x39	/* port number is out of bounds */
#define	FC_TRAN_BUSY		0x40	/* command transport busy */
#define	FC_STATEC_BUSY		0x41	/* port driver currently busy */
#define	FC_DEVICE_BUSY		0x42	/* transport working on this device */
#define	FC_DEVICE_NOT_TGT	0x43    /* try to send command to non target */
#define	FC_DEVICE_BUSY_NEW_RSCN	0x44	/* transport has a new(er) RSCN */
#define	FC_INVALID_LUN		0x45	/* invalid logical unit number */
#define	FC_NPIV_FDISC_FAILED	0x46	/* FDISC command for the port failed */
#define	FC_NPIV_FDISC_WWN_INUSE	0x47	/* NPIV WWN is already in used */
#define	FC_NPIV_NOT_SUPPORTED	0x48	/* HBA does not support NPIV */
#define	FC_NPIV_WRONG_TOPOLOGY	0x49	/* Topology does not support NPIV */



/*
 * pkt state definitions
 */
#define	FC_PKT_SUCCESS		0x01
#define	FC_PKT_REMOTE_STOP	0x02
#define	FC_PKT_LOCAL_RJT	0x03
#define	FC_PKT_NPORT_RJT	0x04
#define	FC_PKT_FABRIC_RJT	0x05
#define	FC_PKT_LOCAL_BSY	0x06
#define	FC_PKT_TRAN_BSY		0x07
#define	FC_PKT_NPORT_BSY	0x08
#define	FC_PKT_FABRIC_BSY	0x09
#define	FC_PKT_LS_RJT		0x0A
#define	FC_PKT_BA_RJT		0x0B
#define	FC_PKT_TIMEOUT		0x0C
#define	FC_PKT_FS_RJT		0x0D
#define	FC_PKT_TRAN_ERROR	0x0E
#define	FC_PKT_FAILURE		0x0F
#define	FC_PKT_PORT_OFFLINE	0x10
#define	FC_PKT_ELS_IN_PROGRESS	0x11	/* ELS in progress */

/*
 * pkt_reason for REMOTE_STOP
 */
#define	FC_REASON_ABTS		0x00
#define	FC_REASON_ABTX		0x01

/*
 * pkt_reason (except for state = NPORT_RJT, FABRIC_RJT, NPORT_BSY,
 *     FABRIC_BSY, LS_RJT, BA_RJT, FS_RJT)
 *
 * FCA unique error codes can begin after
 * FC_REASON_FCA_UNIQUE. Each FCA defines its
 * own set with values greater >= 0x7F
 */
#define	FC_REASON_HW_ERROR		0x01
#define	FC_REASON_SEQ_TIMEOUT		0x02
#define	FC_REASON_ABORTED		0x03
#define	FC_REASON_ABORT_FAILED		0x04
#define	FC_REASON_NO_CONNECTION		0x05
#define	FC_REASON_XCHG_DROPPED		0x06
#define	FC_REASON_ILLEGAL_FRAME		0x07
#define	FC_REASON_ILLEGAL_LENGTH	0x08
#define	FC_REASON_UNSUPPORTED		0x09
#define	FC_REASON_RX_BUF_TIMEOUT	0x0A
#define	FC_REASON_FCAL_OPN_FAIL		0x0B
#define	FC_REASON_OVERRUN		0x0C
#define	FC_REASON_QFULL			0x0D
#define	FC_REASON_ILLEGAL_REQ		0x0E
#define	FC_REASON_PKT_BUSY		0x0F
#define	FC_REASON_OFFLINE		0x11
#define	FC_REASON_BAD_XID		0x12
#define	FC_REASON_XCHG_BSY		0x13
#define	FC_REASON_NOMEM			0x14
#define	FC_REASON_BAD_SID		0x15
#define	FC_REASON_NO_SEQ_INIT		0x16
#define	FC_REASON_DIAG_BUSY		0x17
#define	FC_REASON_DMA_ERROR		0x18
#define	FC_REASON_CRC_ERROR		0x19
#define	FC_REASON_ABORT_TIMEOUT		0x1A
#define	FC_REASON_UNDERRUN		0x1B
#define	FC_REASON_FCA_UNIQUE		0x7E

/*
 * pkt_reason for FABRIC_RJT and NPORT_RJT
 *
 * +--------------------------------------------+
 * | F_RJT Specific        P_RJT Specific       |
 * +--------------------------------------------+
 * | INVALID_D_ID          INVALID_D_ID         |
 * | INVALID_S_ID          INVALID_S_ID         |
 * | NPORT_NOT_AVAIL_TEMP                       |
 * | NPORT_NOT_AVAIL_PERM                       |
 * | CLASS_NOT_SUPPORTED   CLASS_NOT_SUPPORTED  |
 * | DELIMITER_ERROR       DELIMITER_ERROR      |
 * | TYPE_NOT_SUPPORTED    TYPE_NOT_SUPPORTED   |
 * |                       INVALID_LINK_CONTROL |
 * |                       INVALID_R_CTL        |
 * |                       INVALID_F_CTL        |
 * |                       INVALID_OX_ID        |
 * |                       INVALID_RX_ID        |
 * |                       INVALID_SEQ_ID       |
 * |                       INVALID_DF_CTL       |
 * |                       INVALID_SEQ_CNT      |
 * |                       INVALID_PARAMETER    |
 * |                       EXCHANGE_ERROR       |
 * | PROTOCOL_ERROR        PROTOCOL_ERROR       |
 * | INCORRECT_LENGTH      INCORRECT_LENGTH     |
 * |                       UNEXPECTED_ACK       |
 * | LOGIN_REQUIRED        LOGIN_REQUIRED       |
 * |                       EXCESSIVE_SEQUENCES  |
 * |                       CANT_ESTABLISH_EXCH  |
 * |                       SECURITY_NOT_SUPP    |
 * | NO_FABRIC_PATH                             |
 * | VENDOR_UNIQUE         VENDOR_UNIQUE        |
 * +--------------------------------------------+
 *
 */
#define	FC_REASON_INVALID_D_ID			0x01
#define	FC_REASON_INVALID_S_ID			0x02
#define	FC_REASON_TEMP_UNAVAILABLE		0x03
#define	FC_REASON_PERM_UNAVAILABLE		0x04
#define	FC_REASON_CLASS_NOT_SUPP		0x05
#define	FC_REASON_DELIMTER_USAGE_ERROR		0x06
#define	FC_REASON_TYPE_NOT_SUPP			0x07
#define	FC_REASON_INVALID_LINK_CTRL		0x08
#define	FC_REASON_INVALID_R_CTL			0x09
#define	FC_REASON_INVALID_F_CTL			0x0A
#define	FC_REASON_INVALID_OX_ID			0x0B
#define	FC_REASON_INVALID_RX_ID			0x0C
#define	FC_REASON_INVALID_SEQ_ID		0x0D
#define	FC_REASON_INVALID_DF_CTL		0x0E
#define	FC_REASON_INVALID_SEQ_CNT		0x0F
#define	FC_REASON_INVALID_PARAM			0x10
#define	FC_REASON_EXCH_ERROR			0x11
#define	FC_REASON_PROTOCOL_ERROR		0x12
#define	FC_REASON_INCORRECT_LENGTH		0x13
#define	FC_REASON_UNEXPECTED_ACK		0x14
#define	FC_REASON_UNEXPECTED_LR			0x15
#define	FC_REASON_LOGIN_REQUIRED		0x16
#define	FC_REASON_EXCESSIVE_SEQS		0x17
#define	FC_REASON_EXCH_UNABLE			0x18
#define	FC_REASON_ESH_NOT_SUPP			0x19
#define	FC_REASON_NO_FABRIC_PATH		0x1A
#define	FC_REASON_VENDOR_UNIQUE			0xFF

/*
 * pkt_reason for NPORT_BSY
 */
#define	FC_REASON_PHYSICAL_BUSY			0x01
#define	FC_REASON_N_PORT_RESOURCE_BSY	0x03
#define	FC_REASON_N_PORT_VENDOR_UNIQUE	0xFF

/*
 * pkt_reason for FABRIC_BSY
 */
#define	FC_REASON_FABRIC_BSY			0x01
#define	FC_REASON_N_PORT_BSY			0x03

/*
 * pkt_reason for LS_RJT
 * pkt_reason for BA_RJT
 */
#define	FC_REASON_INVALID_LA_CODE		0x01
#define	FC_REASON_LOGICAL_ERROR			0x03
#define	FC_REASON_LOGICAL_BSY			0x05
#define	FC_REASON_PROTOCOL_ERROR_RJT		0x07
#define	FC_REASON_CMD_UNABLE			0x09
#define	FC_REASON_CMD_UNSUPPORTED		0x0B
#define	FC_REASON_VU_RJT			0xFF

/*
 * pkt_reason for FS_RJT
 */
#define	FC_REASON_FS_INVALID_CMD		0x01
#define	FC_REASON_FS_INVALID_VER		0x02
#define	FC_REASON_FS_LOGICAL_ERR		0x03
#define	FC_REASON_FS_INVALID_IUSIZE		0x04
#define	FC_REASON_FS_LOGICAL_BUSY		0x05
#define	FC_REASON_FS_PROTOCOL_ERR		0x07
#define	FC_REASON_FS_CMD_UNABLE			0x09
#define	FC_REASON_FS_CMD_UNSUPPORTED		0x0B
#define	FC_REASON_FS_VENDOR_UNIQUE		0xFF

/*
 * pkt_action for NPORT_BUSY
 */
#define	FC_ACTION_SEQ_TERM_RETRY		0x01
#define	FC_ACTION_SEQ_ACTIVE_RETRY		0x02

/*
 * pkt_action codes for NPORT_RJT, FABRIC_RJT
 * and TIMEOUT
 */
#define	FC_ACTION_RETRYABLE			0x01
#define	FC_ACTION_NON_RETRYABLE			0x02

/*
 * pkt_action codes for reason FC_REASON_ABORT_TIMEOUT
 */
#define	FC_ACTION_FREE_PACKET			0x01
#define	FC_ACTION_DONT_FREE_PACKET		0x02

/*
 * pkt_expln codes for BA_RJT
 */
#define	FC_EXPLN_NONE				0x00
#define	FC_EXPLN_INVALID_OX_RX_ID		0x03
#define	FC_EXPLN_SEQ_ABORTED			0x05

#ifdef	__cplusplus
}
#endif

#endif	/* _FC_ERROR_H */
