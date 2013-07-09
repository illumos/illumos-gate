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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */
#ifndef	_LPIF_H
#define	_LPIF_H

/*
 * Definitions for stmf LUs and lu providers.
 */

#include <sys/stmf_defines.h>
#include <sys/stmf.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LPIF_REV_1	0x00010000
#define	LPIF_REV_2	0x00020000

typedef struct stmf_lu {
	void			*lu_stmf_private;
	void			*lu_provider_private;

	struct scsi_devid_desc	*lu_id;
	char			*lu_alias;	/* optional */
	struct stmf_lu_provider *lu_lp;
	uint32_t		lu_abort_timeout;	/* In seconds */

	/* SAM Device Server Class */
	stmf_status_t		(*lu_task_alloc)(struct scsi_task *task);
	void			(*lu_new_task)(struct scsi_task *task,
		struct stmf_data_buf *initial_dbuf);
	void			(*lu_dbuf_xfer_done)(struct scsi_task *task,
		struct stmf_data_buf *dbuf);
	/*
	 * If completion confirmation is not requested, status xfer done
	 * is called after the transport has confirmed that status has been
	 * sent. If completion confirmation is requested then the HBA will
	 * request a completion confirmation from the host and upon receiving
	 * the same, this entry point will be called.
	 */
	void			(*lu_send_status_done)(struct scsi_task *task);
	void			(*lu_task_free)(struct scsi_task *task);
	stmf_status_t		(*lu_abort)(struct stmf_lu *lu,
		int abort_cmd, void *arg, uint32_t flags);
	void			(*lu_task_poll)(struct scsi_task *task);
	void			(*lu_ctl)(struct stmf_lu *lu, int cmd,
								void *arg);
	stmf_status_t		(*lu_info)(uint32_t cmd, struct stmf_lu *lu,
		void *arg, uint8_t *buf, uint32_t *bufsizep);
	void			(*lu_event_handler)(struct stmf_lu *lu,
		int eventid, void *arg, uint32_t flags);
	void			*lu_proxy_reg_arg;
	uint32_t		lu_proxy_reg_arg_len;
	void			(*lu_dbuf_free)(struct scsi_task *task,
		struct stmf_data_buf *dbuf);
} stmf_lu_t;

/*
 * Abort cmd
 */
#define	STMF_LU_ABORT_TASK		1
#define	STMF_LU_RESET_STATE		2
#define	STMF_LU_ITL_HANDLE_REMOVED	3

/*
 * Asymmetric access state
 */
#define	STMF_LU_ACTIVE			0
#define	STMF_LU_STANDBY			1

/*
 * proxy register msg types
 */
#define	STMF_MSG_LU_REGISTER		0
#define	STMF_MSG_LU_ACTIVE		1
#define	STMF_MSG_LU_DEREGISTER		2


#define	STMF_PROXY_READ			1
#define	STMF_PROXY_WRITE		2

/*
 * Reasons for itl handle removal. Passed in flags.
 */
#define	STMF_ITL_REASON_MASK		0x0f
#define	STMF_ITL_REASON_UNKNOWN		0x0
#define	STMF_ITL_REASON_DEREG_REQUEST	0x1
#define	STMF_ITL_REASON_USER_REQUEST	0x2
#define	STMF_ITL_REASON_IT_NEXUS_LOSS	0x3

typedef struct stmf_lu_provider {
	void			*lp_stmf_private;
	void			*lp_private;

	uint32_t		lp_lpif_rev;	/* Currently LPIF_REV_2 */
	int			lp_instance;
	char			*lp_name;
	void			(*lp_cb)(struct stmf_lu_provider *lp,
	    int cmd, void *arg, uint32_t flags);
	uint8_t			lp_alua_support;
	stmf_status_t		(*lp_proxy_msg)(uint8_t *luid,
	    void *proxy_reg_arg, uint32_t proxy_reg_arg_len, uint32_t type);
} stmf_lu_provider_t;

stmf_status_t stmf_deregister_lu_provider(stmf_lu_provider_t *lp);
stmf_status_t stmf_register_lu_provider(stmf_lu_provider_t *lp);
stmf_status_t stmf_register_lu(stmf_lu_t *lup);
stmf_status_t stmf_deregister_lu(stmf_lu_t *lup);
stmf_status_t stmf_set_lu_access(stmf_lu_t *lup, uint8_t access_state);
stmf_status_t stmf_proxy_scsi_cmd(scsi_task_t *, stmf_data_buf_t *dbuf);
int stmf_is_standby_port(scsi_task_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _LPIF_H */
