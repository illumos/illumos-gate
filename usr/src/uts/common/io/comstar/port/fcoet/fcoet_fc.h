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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef	_FCOET_FC_H
#define	_FCOET_FC_H

#include <sys/stmf_defines.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

fct_status_t
fcoet_get_link_info(fct_local_port_t *port, fct_link_info_t *li);
fct_status_t fcoet_register_remote_port(fct_local_port_t *port,
    fct_remote_port_t *rp, fct_cmd_t *login);
fct_status_t
fcoet_deregister_remote_port(fct_local_port_t *port, fct_remote_port_t *rp);
fct_status_t fcoet_send_cmd(fct_cmd_t *cmd);
fct_status_t fcoet_send_cmd_response(fct_cmd_t *cmd, uint32_t ioflags);
fct_status_t
fcoet_xfer_scsi_data(fct_cmd_t *cmd, stmf_data_buf_t *dbuf, uint32_t ioflags);
fct_status_t
fcoet_abort_cmd(struct fct_local_port *port, fct_cmd_t *cmd, uint32_t flags);
fct_status_t
fcoet_do_flogi(fct_local_port_t *port, fct_flogi_xchg_t *fx);
void fcoet_send_sol_flogi(fcoet_soft_state_t *ss);
void fcoet_send_sol_abts(fcoet_exchange_t *xch);
void fcoet_ctl(struct fct_local_port *port, int cmd, void *arg);
void fcoet_populate_hba_fru_details(struct fct_local_port *port,
    struct fct_port_attrs *port_attrs);
fct_status_t fcoet_enable_port(fcoet_soft_state_t *ss);
fct_status_t fcoet_disable_port(fcoet_soft_state_t *ss);
fcoet_exchange_t *fcoet_init_sol_exchange(fct_cmd_t *cmd);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _FCOET_FC_H */
