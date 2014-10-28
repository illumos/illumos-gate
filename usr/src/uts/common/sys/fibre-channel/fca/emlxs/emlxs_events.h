/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_EVENTS_H
#define	_EMLXS_EVENTS_H

#ifdef	__cplusplus
extern "C" {
#endif

extern void emlxs_null_func();

#ifdef DEF_EVENT_STRUCT

#define	DEFINE_EVT(_name, _label, _mask, _timeout, _destroy) \
	extern void _destroy(); \
	emlxs_event_t _name = {_mask, _label, _timeout, _destroy};

#else

#define	DEFINE_EVT(_name, _label, _mask, _timeout, _destroy) \
	extern void _destroy(); \
	extern emlxs_event_t _name;

#endif	/* DEF_EVENT_STRUCT */


/* Event Mask Bits */
#define	EVT_LINK		0x00000001	/* FC_REG_LINK_EVENT */
#define	EVT_RSCN		0x00000002	/* FC_REG_RSCN_EVENT */
#define	EVT_CT			0x00000004	/* FC_REG_CT_EVENT   */
#define	EVT_MPULSE		0x00000008	/* FC_REG_MULTIPULSE_EVENT */
#define	EVT_DUMP		0x00000010	/* FC_REG_DUMP_EVENT */
#define	EVT_TEMP		0x00000020	/* FC_REG_TEMP_EVENT */
#define	EVT_VPORTRSCN		0x00000040	/* FC_REG_VPORTRSCN_EVENT */
#define	EVT_ASYNC		0x00000080	/* FC_REG_ASYNC_EVENT */

#ifdef SAN_DIAG_SUPPORT
#define	EVT_SD_ELS		0x00001000	/* FC_REG_SD_ELS_EVENT */
#define	EVT_SD_FABRIC		0x00002000	/* FC_REG_SD_FABRIC_EVENT */
#define	EVT_SD_SCSI		0x00004000	/* FC_REG_SD_SCSI_EVENT */
#define	EVT_SD_BOARD		0x00008000	/* FC_REG_SD_BOARD_EVENT */
#endif /* SAN_DIAG_SUPPORT */

#define	EVT_FCOE		0x80000000	/* FC_REG_FCOE_EVENT */


typedef struct emlxs_event
{
	uint32_t	mask;
	char		label[64];
	uint32_t 	timeout;
	void		(*destroy)();

} emlxs_event_t;


#define	EMLXS_EVENT_PERIOD	5
#define	EVT_TIMEOUT_DEFAULT	60
#define	EVT_TIMEOUT_NEVER	0
#define	EVT_DESTROY_DEFAULT	emlxs_null_func


/* EVENT defines */
DEFINE_EVT(emlxs_link_event, \
	"LINK", \
	EVT_LINK,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_rscn_event, \
	"RSCN", \
	EVT_RSCN,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_vportrscn_event, \
	"VPORT RSCN", \
	EVT_VPORTRSCN,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_ct_event, \
	"CT", \
	EVT_CT,
	EVT_TIMEOUT_DEFAULT,
	emlxs_ct_event_destroy)

DEFINE_EVT(emlxs_dump_event, \
	"DUMP", \
	EVT_DUMP,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_temp_event, \
	"TEMP", \
	EVT_TEMP,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_fcoe_event, \
	"FCOE", \
	EVT_FCOE,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_async_event, \
	"ASYNC", \
	EVT_ASYNC,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

#ifdef SAN_DIAG_SUPPORT
DEFINE_EVT(emlxs_sd_els_event, \
	"SD_ELS", \
	EVT_SD_ELS,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_sd_fabric_event, \
	"SD_FC", \
	EVT_SD_FABRIC,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_sd_scsi_event, \
	"SD_SCSI", \
	EVT_SD_SCSI,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)

DEFINE_EVT(emlxs_sd_board_event, \
	"SD_BOARD", \
	EVT_SD_BOARD,
	EVT_TIMEOUT_DEFAULT,
	EVT_DESTROY_DEFAULT)
#endif /* SAN_DIAG_SUPPORT */

#define	MAX_LOG_INFO_LENGTH	96

typedef struct emlxs_event_entry
{
	struct emlxs_event_entry	*next;
	struct emlxs_event_entry	*prev;

	uint32_t	id;
	uint32_t	timestamp;
	uint32_t	timer;

	emlxs_event_t	*evt;

	void *port;

	void		*bp;			/* Context buffer */
						/* pointer */
	uint32_t	size;			/* Context buffer */
						/* size */
	uint32_t	flag;
#define	EMLXS_DFC_EVENT_DONE	0x00000001
#define	EMLXS_SD_EVENT_DONE	0x00000002

} emlxs_event_entry_t;


typedef struct emlxs_event_queue
{
	kmutex_t		lock;
	kcondvar_t		lock_cv;

	uint32_t		last_id[32]; /* per event */
	uint32_t		next_id;
	uint32_t		count;

	emlxs_event_entry_t	*first;
	emlxs_event_entry_t	*last;

} emlxs_event_queue_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_EVENTS_H */
