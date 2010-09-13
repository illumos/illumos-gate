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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_PORTIF_H
#define	_PORTIF_H

/*
 * Definitions for stmf local ports and port providers.
 */

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct stmf_dbuf_store {
	void			*ds_stmf_private;
	void			*ds_port_private;

	stmf_data_buf_t		*(*ds_alloc_data_buf)(struct scsi_task *task,
	    uint32_t size, uint32_t *pminsize, uint32_t flags);

	void			(*ds_free_data_buf)(
	    struct stmf_dbuf_store *ds, stmf_data_buf_t *dbuf);

	stmf_status_t		(*ds_setup_dbuf)(struct scsi_task *task,
	    stmf_data_buf_t *dbuf, uint32_t flags);

	void			(*ds_teardown_dbuf)(
	    struct stmf_dbuf_store *ds, stmf_data_buf_t *dbuf);
} stmf_dbuf_store_t;

#define	PORTIF_REV_1	0x00010000

typedef struct stmf_local_port {
	void			*lport_stmf_private;
	void			*lport_port_private;

	uint32_t		lport_abort_timeout;

	struct scsi_devid_desc	*lport_id;
	char			*lport_alias;
	struct stmf_port_provider *lport_pp;
	struct stmf_dbuf_store	*lport_ds;
	/* lport ops */
	stmf_status_t		(*lport_xfer_data)(struct scsi_task *task,
		struct stmf_data_buf *dbuf, uint32_t ioflags);
	stmf_status_t		(*lport_send_status)(struct scsi_task *task,
						uint32_t ioflags);
	void			(*lport_task_free)(struct scsi_task *task);
	stmf_status_t		(*lport_abort)(struct stmf_local_port *lport,
		int abort_cmd, void *arg, uint32_t flags);
	void			(*lport_task_poll)(struct scsi_task *task);
	void			(*lport_ctl)(struct stmf_local_port *lport,
						int cmd, void *arg);
	stmf_status_t		(*lport_info)(uint32_t cmd,
		struct stmf_local_port *lport, void *arg, uint8_t *buf,
		uint32_t *bufsizep);
	void			(*lport_event_handler)(
		struct stmf_local_port *lport, int eventid, void *arg,
		uint32_t flags);
} stmf_local_port_t;

typedef struct stmf_remote_port {
	struct scsi_transport_id	*rport_tptid;
	uint16_t			rport_tptid_sz;
} stmf_remote_port_t;

typedef struct stmf_dflt_scsi_tptid {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t			protocol_id : 4,
				resbits : 2,
				format_code : 2;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t			format_code : 2,
				resbits : 2,
				protocol_id : 4;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uint8_t			rsvbyte1;
	uint8_t			ident_len[2];
	char			ident[1];
} stmf_dflt_scsi_tptid_t;
/*
 * abort cmd
 */
#define	STMF_LPORT_ABORT_TASK	0x40

typedef struct stmf_port_provider {
	void			*pp_stmf_private;
	void			*pp_provider_private;

	uint32_t		pp_portif_rev;	/* Currently PORTIF_REV_1 */
	int			pp_instance;
	char			*pp_name;
	void			(*pp_cb)(struct stmf_port_provider *pp,
	    int cmd, void *arg, uint32_t flags);
} stmf_port_provider_t;

#define	STMF_SESSION_ID_NONE		((uint64_t)0)

typedef struct stmf_scsi_session {
	void			*ss_stmf_private;
	void			*ss_port_private;

	struct scsi_devid_desc	*ss_rport_id;
	char			*ss_rport_alias;
	struct stmf_local_port	*ss_lport;
	uint64_t		ss_session_id;
	struct stmf_remote_port	*ss_rport;
} stmf_scsi_session_t;

stmf_status_t stmf_register_port_provider(stmf_port_provider_t *pp);
stmf_status_t stmf_deregister_port_provider(stmf_port_provider_t *pp);
stmf_status_t stmf_register_local_port(stmf_local_port_t *lportp);
stmf_status_t stmf_deregister_local_port(stmf_local_port_t *lport);
stmf_status_t stmf_register_scsi_session(stmf_local_port_t *lport,
				stmf_scsi_session_t *ss);
void stmf_deregister_scsi_session(stmf_local_port_t *lport,
				stmf_scsi_session_t *ss);
void stmf_set_port_standby(stmf_local_port_t *lport, uint16_t rtpid);
void stmf_set_port_alua(stmf_local_port_t *lport);

#ifdef	__cplusplus
}
#endif

#endif /* _PORTIF_H */
