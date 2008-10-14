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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_EXTERN_H
#define	_EMLXS_EXTERN_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <emlxs_hbaapi.h>

extern void *emlxs_soft_state;
extern uint32_t emlxs_instance[MAX_FC_BRDS];
extern uint32_t emlxs_instance_count;
extern char emlxs_revision[32];
extern char emlxs_version[32];
extern char emlxs_name[64];
extern char emlxs_label[64];

extern emlxs_device_t emlxs_device;
extern uint32_t emlxs_instance[MAX_FC_BRDS];
extern uint32_t emlxs_instance_count;

extern ddi_device_acc_attr_t emlxs_data_acc_attr;
extern ddi_device_acc_attr_t emlxs_dev_acc_attr;
extern ddi_dma_lim_t emlxs_dma_lim;
extern uint32_t emlxs_diag_state;
extern emlxs_config_t emlxs_cfg[];
extern ddi_dma_attr_t emlxs_dma_attr;
extern ddi_dma_attr_t emlxs_dma_attr_ro;
extern ddi_dma_attr_t emlxs_dma_attr_fcip_rsp;
extern ddi_dma_attr_t emlxs_dma_attr_1sg;

/* Module emlxs_msg.c External Routine Declarations */
extern void emlxs_msg_printf(emlxs_port_t *port, const uint32_t fileno,
	const uint32_t line, void *bp, uint32_t size, emlxs_msg_t *msg,
	const char *fmt, ...);
extern uint32_t emlxs_msg_log_create(emlxs_hba_t *hba);
extern uint32_t emlxs_msg_log_destroy(emlxs_hba_t *hba);
extern uint32_t emlxs_msg_log_get(emlxs_hba_t *hba, emlxs_log_req_t *req,
	emlxs_log_resp_t *resp);
extern void emlxs_log_dump_event(emlxs_port_t *port, uint8_t *buffer,
	uint32_t size);
extern void emlxs_log_link_event(emlxs_port_t *port);
extern void emlxs_log_ct_event(emlxs_port_t *port, uint8_t *payload,
	uint32_t size, uint32_t rxid);
extern void emlxs_log_rscn_event(emlxs_port_t *port, uint8_t *payload,
	uint32_t size);
extern uint32_t emlxs_get_dfc_event(emlxs_port_t *port,
	emlxs_dfc_event_t *dfc_event, uint32_t sleep);
extern uint32_t emlxs_kill_dfc_event(emlxs_port_t *port,
	emlxs_dfc_event_t *dfc_event);
extern uint32_t emlxs_get_dfc_eventinfo(emlxs_port_t *port,
	HBA_EVENTINFO *eventinfo, uint32_t *eventcount, uint32_t *missed);
extern void emlxs_log_temp_event(emlxs_port_t *port, uint32_t type,
	uint32_t temp);
extern void emlxs_log_fcoe_event(emlxs_port_t *port,
	menlo_init_rsp_t *init_rsp);

/* Module emlxs_solaris.c External Routine Declarations */
extern int32_t emlxs_pkt_abort(opaque_t fca_port_handle, fc_packet_t *pkt,
	int32_t sleep);
extern char *emlxs_state_xlate(uint8_t state);
extern char *emlxs_error_xlate(uint8_t errno);
extern void emlxs_mem_free(emlxs_hba_t *hba, MBUF_INFO *buf_info);
extern uint8_t *emlxs_mem_alloc(emlxs_hba_t *hba, MBUF_INFO *buf_info);
extern int emlxs_mapmem(emlxs_hba_t *hba);
extern void emlxs_unmapmem(emlxs_hba_t *hba);
extern fc_unsol_buf_t *emlxs_ub_find(emlxs_port_t *port, uint32_t token);
extern fc_unsol_buf_t *emlxs_ub_get(emlxs_port_t *port, uint32_t size,
	uint32_t type, uint32_t resv);
extern int32_t emlxs_log_printf(int32_t f, int32_t type, int32_t num,
	int32_t brdno, const char *fmt, ...);
extern void emlxs_set_pkt_state(emlxs_buf_t *sbp, uint32_t iostat,
	uint8_t localstat, uint32_t lock);
extern char *emlxs_elscmd_xlate(uint32_t cmd);
extern char *emlxs_ctcmd_xlate(uint32_t cmd);
extern char *emlxs_rmcmd_xlate(uint32_t cmd);
extern char *emlxs_wwn_xlate(char *buffer, uint8_t *wwn);
extern int32_t emlxs_transport(opaque_t fca_port_handle, fc_packet_t *pkt);
extern int32_t emlxs_pkt_uninit(opaque_t fca_port_handle, fc_packet_t *pkt);
extern int32_t emlxs_pkt_init(opaque_t fca_port_handle, fc_packet_t *pkt,
	int32_t sleep);
extern void emlxs_pkt_complete(emlxs_buf_t *sbp, uint32_t iostat,
	uint8_t localstat, uint32_t doneq);
extern uint32_t emlxs_get_instance(int32_t ddiinst);
extern char *emlxs_mscmd_xlate(uint16_t cmd);
extern int32_t emlxs_reset(opaque_t fca_port_handle, uint32_t cmd);
extern void emlxs_swap_service_params(SERV_PARM *sp);
extern void emlxs_swap_fcp_pkt(emlxs_buf_t *sbp);
extern void emlxs_swap_ct_pkt(emlxs_buf_t *sbp);
extern void emlxs_swap_els_pkt(emlxs_buf_t *sbp);
extern int emlxs_ub_release(opaque_t fca_port_handle, uint32_t count,
	uint64_t tokens[]);
extern void emlxs_swap_els_ub(fc_unsol_buf_t *ubp);
extern void emlxs_unswap_pkt(emlxs_buf_t *sbp);
extern uint32_t emlxs_get_key(emlxs_hba_t *hba, MAILBOX *mb);
extern int emlxs_pm_busy_component(dev_info_t *dip);
extern int emlxs_pm_idle_component(dev_info_t *dip);
extern void emlxs_pm_idle_timer(dev_info_t *dip);
extern void emlxs_shutdown_thread(void *arg);
extern uint32_t emlxs_set_parm(emlxs_hba_t *hba, uint32_t index,
	uint32_t new_value);
extern void emlxs_ub_destroy(emlxs_port_t *port, emlxs_unsol_buf_t *pool);
extern void emlxs_ub_callback(emlxs_port_t *port, fc_unsol_buf_t *ubp);
extern void emlxs_ub_flush(emlxs_port_t *port);
extern uint32_t emlxs_check_parm(emlxs_hba_t *hba, uint32_t index,
	uint32_t new_value);
extern int32_t emlxs_port_manage(opaque_t fca_port_handle, fc_fca_pm_t *pm);
extern void emlxs_port_init(emlxs_port_t *port);
extern void emlxs_get_fcode_version(emlxs_hba_t *hba);

#ifdef MENLO_SUPPORT
extern char *emlxs_menlo_cmd_xlate(uint32_t cmd);
extern char *emlxs_menlo_rsp_xlate(uint32_t rsp);
#endif	/* MENLO_SUPPORT */

/* Module emlxs_pkt.c External Routine Declarations */
extern int32_t emlxs_pkt_send(fc_packet_t *pkt, uint32_t now);
extern void emlxs_pkt_free(fc_packet_t *pkt);
extern void emlxs_pkt_callback(fc_packet_t *pkt);
extern fc_packet_t *emlxs_pkt_alloc(emlxs_port_t *port, uint32_t cmdlen,
	uint32_t rsplen, uint32_t datalen, int32_t sleep);

/* Module emlxs_clock.c External Routine Declarations */
extern void emlxs_timer_start(emlxs_hba_t *hba);
extern void emlxs_timer_stop(emlxs_hba_t *hba);
extern void emlxs_link_timeout(emlxs_hba_t *hba);
extern clock_t emlxs_timeout(emlxs_hba_t *hba, uint32_t timeout);

/* Module emlxs_dhchap.c External Routine Declarations */
#ifdef DHCHAP_SUPPORT
extern int emlxs_dhchap_state_machine(emlxs_port_t *port, RING *ring,
	IOCBQ *iocbq, MATCHMAP *mp, NODELIST *node, int event);

extern void emlxs_dhc_attach(emlxs_hba_t *hba);
extern void emlxs_dhc_detach(emlxs_hba_t *hba);
extern void emlxs_dhc_authrsp_timeout(emlxs_port_t *port, void *node,
	void *null);
extern void emlxs_dhc_reauth_timeout(emlxs_port_t *port, void *newtimeout,
	void *node);
extern void emlxs_dhc_auth_stop(emlxs_port_t *port, emlxs_node_t *node);
extern int emlxs_dhc_auth_start(emlxs_port_t *port, emlxs_node_t *node,
	uint8_t *sbp, uint8_t *ubp);
extern void emlxs_dhc_init_sp(emlxs_port_t *port, uint32_t did, SERV_PARM *sp,
	char *msg);
extern uint32_t emlxs_dhc_verify_login(emlxs_port_t *port, uint32_t sid,
	SERV_PARM *sp);
extern void emlxs_dhc_status(emlxs_port_t *port, emlxs_node_t *ndlp,
	uint32_t reason, uint32_t explaination);
extern void emlxs_dhc_state(emlxs_port_t *port, emlxs_node_t *ndlp,
	uint32_t state, uint32_t reason, uint32_t explaination);
extern uint32_t emlxs_dhc_init_auth(emlxs_hba_t *hba, uint8_t *lwwpn,
	uint8_t *rwwpn);
extern uint32_t emlxs_dhc_get_auth_cfg(emlxs_hba_t *hba,
	dfc_fcsp_config_t *fcsp_cfg);
extern uint32_t emlxs_dhc_get_auth_key(emlxs_hba_t *hba,
	dfc_auth_password_t *dfc_auth_pwd);
extern uint32_t emlxs_dhc_add_auth_cfg(emlxs_hba_t *hba,
	dfc_fcsp_config_t *fcsp_cfg, dfc_password_t *dfc_pwd);
extern uint32_t emlxs_dhc_delete_auth_cfg(emlxs_hba_t *hba,
	dfc_fcsp_config_t *fcsp_cfg, dfc_password_t *dfc_pwd);
extern uint32_t emlxs_dhc_set_auth_key(emlxs_hba_t *hba,
	dfc_auth_password_t *dfc_pwd);
extern uint32_t emlxs_dhc_get_auth_status(emlxs_hba_t *hba,
	dfc_auth_status_t *fcsp_status);
extern uint32_t emlxs_dhc_get_auth_cfg_table(emlxs_hba_t *hba,
	dfc_fcsp_config_t *fcsp_cfg);
extern uint32_t emlxs_dhc_get_auth_key_table(emlxs_hba_t *hba,
	dfc_auth_password_t *auth_pwd);
#endif	/* DHCHAP_SUPPORT */

/* Module emlxs_node.c External Routine Declarations */
extern void emlxs_node_open(emlxs_port_t *port, NODELIST *ndlp,
	uint32_t ringno);
extern void emlxs_node_close(emlxs_port_t *port, NODELIST *ndlp,
	uint32_t ringno, uint32_t tics);
extern NODELIST *emlxs_node_find_did(emlxs_port_t *port, uint32_t did);
extern NODELIST *emlxs_node_find_rpi(emlxs_port_t *port, uint32_t rpi);
extern void emlxs_node_destroy_all(emlxs_port_t *port);
extern NODELIST *emlxs_node_find_mac(emlxs_port_t *port, uint8_t *mac);
extern void emlxs_node_add(emlxs_port_t *port, NODELIST *ndlp);
extern void emlxs_node_rm(emlxs_port_t *port, NODELIST *ndlp);
extern NODELIST *emlxs_node_find_wwpn(emlxs_port_t *port, uint8_t *wwpn);
extern NODELIST *emlxs_node_find_index(emlxs_port_t *port, uint32_t index,
	uint32_t nports_only);
extern uint32_t emlxs_nport_count(emlxs_port_t *port);

/* Module emlxs_els.c External Routine Declarations */
extern int32_t emlxs_els_handle_event(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);
extern int32_t emlxs_els_handle_unsol_req(emlxs_port_t *port, RING *rp,
	IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
extern uint32_t emlxs_generate_rscn(emlxs_port_t *port, uint32_t d_id);
extern int32_t emlxs_ct_handle_event(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);
extern int32_t emlxs_ct_handle_unsol_req(emlxs_port_t *port, RING *rp,
	IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
extern int32_t emlxs_els_reply(emlxs_port_t *port, IOCBQ *iocbq,
	uint32_t type, uint32_t type2, uint32_t reason, uint32_t explain);
extern void emlxs_send_logo(emlxs_port_t *port, uint32_t d_id);
extern void emlxs_reset_link_thread(void *arg);
extern uint32_t emlxs_process_unsol_flogi(emlxs_port_t *port, IOCBQ *iocbq,
	MATCHMAP *mp, uint32_t size, char *buffer);
extern uint32_t emlxs_process_unsol_plogi(emlxs_port_t *port, IOCBQ *iocbq,
	MATCHMAP *mp, uint32_t size, char *buffer);
extern uint32_t emlxs_ub_send_login_acc(emlxs_port_t *port, fc_unsol_buf_t *bp);

#ifdef MENLO_SUPPORT
extern int emlxs_menlo_handle_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
#endif	/* MENLO_SUPPORT */

/* Module emlxs_ip.c External Routine Declarations */
extern int32_t emlxs_ip_handle_event(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);
extern int emlxs_ip_handle_rcv_seq_list(emlxs_hba_t *hba, RING *rp,
	IOCBQ *saveq);
extern int emlxs_ip_handle_unsol_req(emlxs_port_t *port, RING *rp,
	IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
extern int emlxs_create_xri(emlxs_port_t *port, RING *rp, NODELIST *ndlp);
extern int emlxs_handle_create_xri(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);
extern int emlxs_handle_xri_aborted(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);

/* Module emlxs_mbox.c External Routine Declarations */
extern void emlxs_mb_config_msi(emlxs_hba_t *hba, MAILBOX *mb,
	uint32_t *intr_map, uint32_t intr_count);
extern void emlxs_mb_config_msix(emlxs_hba_t *hba, MAILBOX *mb,
	uint32_t *intr_map, uint32_t intr_count);
extern void emlxs_mb_read_lnk_stat(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_config_link(emlxs_hba_t *hba, MAILBOX *mb);
extern uint32_t emlxs_mb_config_port(emlxs_hba_t *hba, MAILBOX *mb,
	uint32_t sli_mode, uint32_t hbainit);
extern void emlxs_mb_config_ring(emlxs_hba_t *hba, int32_t ring, MAILBOX *mb);
extern void emlxs_mb_init_link(emlxs_hba_t *hba, MAILBOX *mb,
	uint32_t topology, uint32_t linkspeed);
extern void emlxs_mb_down_link(emlxs_hba_t *hba, MAILBOX *mb);
extern uint32_t emlxs_mb_read_la(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_read_nv(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_read_rev(emlxs_hba_t *hba, MAILBOX *mb, uint32_t v3);
extern uint32_t emlxs_mb_read_rpi(emlxs_hba_t *hba, uint32_t rpi,
	MAILBOX *mb, uint32_t flg);
extern uint32_t emlxs_mb_read_xri(emlxs_hba_t *hba, uint32_t xri,
	MAILBOX *mb, uint32_t flg);
extern uint32_t emlxs_mb_read_sparam(emlxs_hba_t *hba, MAILBOX *mb);
extern uint32_t emlxs_mb_reg_did(emlxs_port_t *port, uint32_t did,
	SERV_PARM *param, emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq);
extern void emlxs_disable_tc(emlxs_hba_t *hba, MAILBOX *mb);
extern uint32_t emlxs_mb_run_biu_diag(emlxs_hba_t *hba, MAILBOX *mb,
	uint64_t in, uint64_t out);
extern uint32_t emlxs_handle_mb_event(emlxs_hba_t *hba);
extern uint32_t emlxs_mb_unreg_rpi(emlxs_port_t *port, uint32_t rpi,
	emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq);
extern uint32_t emlxs_mb_unreg_did(emlxs_port_t *port, uint32_t did,
	emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq);
extern void emlxs_mb_dump_vpd(emlxs_hba_t *hba, MAILBOX *mb, uint32_t offset);
extern void emlxs_mb_config_farp(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_read_config(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_put(emlxs_hba_t *hba, MAILBOXQ *mbq);
extern MAILBOXQ *emlxs_mb_get(emlxs_hba_t *hba);
extern uint32_t emlxs_mb_issue_cmd(emlxs_hba_t *hba, MAILBOX *mb,
	int32_t flag, uint32_t timeout);
extern void emlxs_mb_clear_la(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_set_var(emlxs_hba_t *hba, MAILBOX *mb, uint32_t addr,
	uint32_t value);
extern void emlxs_mb_reset_ring(emlxs_hba_t *hba, MAILBOX *mb, uint32_t ringno);
extern char *emlxs_mb_cmd_xlate(uint8_t command);
extern void emlxs_mb_read_status(emlxs_hba_t *hba, MAILBOX *mb);
extern uint32_t emlxs_mb_reg_vpi(emlxs_port_t *port);
extern uint32_t emlxs_mb_unreg_vpi(emlxs_port_t *port);
extern void emlxs_mb_fini(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mbxStatus);
extern void emlxs_mb_heartbeat(emlxs_hba_t *hba, MAILBOX *mb);
extern void emlxs_mb_async_event(emlxs_hba_t *hba, MAILBOX *mb);
extern int32_t emlxs_mb_check_sparm(emlxs_hba_t *hba, SERV_PARM *nsp);

#ifdef SLI3_SUPPORT
extern void emlxs_mb_config_hbq(emlxs_hba_t *hba, MAILBOX *mb, int hbq_id);
#endif	/* SLI3_SUPPORT */

/* Module emlxs_mem.c External Routine Declarations */
extern MATCHMAP *emlxs_mem_get_vaddr(emlxs_hba_t *hba, RING *rp, uint64_t mbp);
extern uint8_t *emlxs_mem_get(emlxs_hba_t *hba, uint32_t seg);
extern uint8_t *emlxs_mem_put(emlxs_hba_t *hba, uint32_t seg, uint8_t *bp);
extern int32_t emlxs_mem_free_buffer(emlxs_hba_t *hba);
extern int32_t emlxs_mem_alloc_buffer(emlxs_hba_t *hba);
extern void emlxs_mem_map_vaddr(emlxs_hba_t *hba, RING *rp, MATCHMAP *mp,
	uint32_t *haddr, uint32_t *laddr);
extern uint8_t *emlxs_mem_buf_alloc(emlxs_hba_t *hba);
extern uint8_t *emlxs_mem_buf_free(emlxs_hba_t *hba, uint8_t *bp);
#ifdef SLI3_SUPPORT
extern void emlxs_update_HBQ_index(emlxs_hba_t *hba, uint32_t hbq_id);
extern uint32_t emlxs_hbq_setup(emlxs_hba_t *hba, uint32_t hbq_id);
#endif	/* SLI3_SUPPORT */

/* Module emlxs_hba.c  External Routine Declarations */
extern uint32_t emlxs_interlock(emlxs_hba_t *hba);
extern uint32_t emlxs_hba_reset(emlxs_hba_t *hba, uint32_t restart,
	uint32_t skip_post);
extern int32_t emlxs_ffinit(emlxs_hba_t *hba);
extern void emlxs_issue_iocb_cmd(emlxs_hba_t *hba, RING *rp, IOCBQ *iocb_cmd);
extern void emlxs_decode_firmware_rev(emlxs_hba_t *hba, emlxs_vpd_t *vp);
extern void emlxs_poll_intr(emlxs_hba_t *hba, uint32_t att_bit);
extern uint32_t emlxs_init_adapter_info(emlxs_hba_t *hba);
extern uint32_t emlxs_strtol(char *str, uint32_t base);
extern uint64_t emlxs_strtoll(char *str, uint32_t base);
extern void emlxs_decode_version(uint32_t version, char *buffer);
extern char *emlxs_ffstate_xlate(uint32_t new_state);
extern char *emlxs_ring_xlate(uint32_t ringno);
extern uint32_t emlxs_reset_ring(emlxs_hba_t *hba, uint32_t ringno);
extern void emlxs_proc_ring(emlxs_hba_t *hba, RING *rp, void *arg2);
extern void emlxs_pcix_mxr_update(emlxs_hba_t *hba, uint32_t verbose);
extern void emlxs_restart_thread(void *arg);
extern void emlxs_handle_ff_error(emlxs_hba_t *hba);

#ifdef MSI_SUPPORT
extern int32_t emlxs_msi_add(emlxs_hba_t *hba);
extern int32_t emlxs_msi_remove(emlxs_hba_t *hba);
extern int32_t emlxs_msi_init(emlxs_hba_t *hba, uint32_t max);
extern int32_t emlxs_msi_uninit(emlxs_hba_t *hba);
#endif	/* MSI_SUPPORT */

extern int32_t emlxs_intx_add(emlxs_hba_t *hba);
extern int32_t emlxs_intx_remove(emlxs_hba_t *hba);
extern int32_t emlxs_intx_init(emlxs_hba_t *hba, uint32_t max);
extern int32_t emlxs_intx_uninit(emlxs_hba_t *hba);


/* Module emlxs_diag.c  External Routine Declarations */
extern uint32_t emlxs_diag_post_run(emlxs_hba_t *hba);
extern uint32_t emlxs_diag_biu_run(emlxs_hba_t *hba, uint32_t pattern);
extern uint32_t emlxs_diag_pattern[256];
extern uint32_t emlxs_diag_echo_run(emlxs_port_t *port, uint32_t did,
	uint32_t pattern);
extern uint32_t emlxs_core_size(emlxs_hba_t *hba);
extern uint32_t emlxs_core_dump(emlxs_hba_t *hba, char *buffer, uint32_t size);

/* Module emlxs_download.c External Routine Declarations */
extern int32_t emlxs_fw_download(emlxs_hba_t *hba, caddr_t buffer,
	uint32_t len, uint32_t offline);
extern uint32_t emlxs_get_max_sram(emlxs_hba_t *hba, uint32_t *MaxRbusSize,
	uint32_t *MaxIbusSize);
extern uint32_t emlxs_get_load_list(emlxs_hba_t *hba, PROG_ID *load_list);
extern uint32_t emlxs_read_wakeup_parms(emlxs_hba_t *hba,
	PWAKE_UP_PARMS WakeUpParms, uint32_t verbose);
extern int32_t emlxs_cfl_download(emlxs_hba_t *hba, uint32_t region,
	caddr_t buffer, uint32_t len);

extern uint32_t emlxs_boot_code_disable(emlxs_hba_t *hba);
extern uint32_t emlxs_boot_code_enable(emlxs_hba_t *hba);
extern uint32_t emlxs_boot_code_state(emlxs_hba_t *hba);

/* Module emlxs_fcp.c External Routine Declarations */
extern int emlxs_power_up(emlxs_hba_t *hba);
extern int emlxs_power_down(emlxs_hba_t *hba);
extern int emlxs_reset_link(emlxs_hba_t *hba, uint32_t linkup);
extern emlxs_buf_t *emlxs_unregister_pkt(RING *rp, uint16_t iotag,
	uint32_t forced);
extern uint16_t emlxs_register_pkt(RING *rp, emlxs_buf_t *sbp);

extern IOCBQ *emlxs_create_abort_xri_cn(emlxs_port_t *port, NODELIST *ndlp,
	uint16_t iotag, RING *rp, uint8_t class, int32_t flag);
extern IOCBQ *emlxs_create_close_xri_cn(emlxs_port_t *port, NODELIST *ndlp,
	uint16_t iotag, RING *rp);
extern IOCBQ *emlxs_create_abort_xri_cx(emlxs_port_t *port, NODELIST *ndlp,
	uint16_t xid, RING *rp, uint8_t class, int32_t flag);
extern IOCBQ *emlxs_create_close_xri_cx(emlxs_port_t *port, NODELIST *ndlp,
	uint16_t xid, RING *rp);

extern emlxs_buf_t *emlxs_chipq_get(RING *rp, uint16_t iotag);
extern void emlxs_chipq_put(RING *rp, emlxs_buf_t *sbp);
extern uint32_t emlxs_chipq_node_flush(emlxs_port_t *port, RING *rp,
	NODELIST *ndlp, emlxs_buf_t *fpkt);
extern uint32_t emlxs_chipq_lun_flush(emlxs_port_t *port, NODELIST *ndlp,
	uint32_t lun, emlxs_buf_t *fpkt);
extern uint32_t emlxs_chipq_node_check(emlxs_port_t *port, RING *ring,
	NODELIST *ndlp);

extern IOCBQ *emlxs_tx_get(RING *rp, uint32_t lock);
extern void emlxs_tx_put(IOCBQ *iocbq, uint32_t lock);
extern uint32_t emlxs_tx_node_check(emlxs_port_t *port, NODELIST *ndlp,
	RING *ring);
extern uint32_t emlxs_tx_node_flush(emlxs_port_t *port, NODELIST *ndlp,
	RING *ring, uint32_t shutdown, emlxs_buf_t *fpkt);
extern uint32_t emlxs_tx_lun_flush(emlxs_port_t *port, NODELIST *ndlp,
	uint32_t lun, emlxs_buf_t *fpkt);
extern uint32_t emlxs_tx_ring_flush(emlxs_hba_t *hba, RING *rp,
	emlxs_buf_t *fpkt);

extern void emlxs_linkdown(emlxs_hba_t *hba);
extern void emlxs_linkup(emlxs_hba_t *hba);
extern void emlxs_port_online(emlxs_port_t *port);
extern int32_t emlxs_port_offline(emlxs_port_t *port, uint32_t scope);
extern void emlxs_ffcleanup(emlxs_hba_t *hba);
extern int32_t emlxs_offline(emlxs_hba_t *hba);
extern int32_t emlxs_online(emlxs_hba_t *hba);
extern void emlxs_pcimem_bcopy(uint32_t *src, uint32_t *dest, uint32_t cnt);
extern int32_t emlxs_post_buffer(emlxs_hba_t *hba, RING *rp, int16_t cnt);
extern void emlxs_swap_bcopy(uint32_t *src, uint32_t *dest, uint32_t cnt);
extern void emlxs_ff_start(emlxs_hba_t *hba);
extern void emlxs_handle_fcp_event(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);

/* Module emlxs_thread.c External Routine Declarations */
extern void emlxs_taskq_destroy(emlxs_taskq_t *taskq);
extern void emlxs_taskq_create(emlxs_hba_t *hba, emlxs_taskq_t *taskq);
extern uint32_t emlxs_taskq_dispatch(emlxs_taskq_t *taskq,
	void (*func) (), void *arg);
extern void emlxs_thread_create(emlxs_hba_t *hba, emlxs_thread_t *ethread);
extern void emlxs_thread_destroy(emlxs_thread_t *ethread);
extern void emlxs_thread_trigger1(emlxs_thread_t *ethread, void (*func) ());
extern void emlxs_thread_trigger2(emlxs_thread_t *ethread,
	void (*func) (), RING *rp);

/* Module emlxs_dfc.c External Routine Declarations */
extern int32_t emlxs_dfc_manage(emlxs_hba_t *hba, void *dfc, int32_t mode);
extern int32_t emlxs_dfc_handle_event(emlxs_hba_t *hba, RING *rp, IOCBQ *temp);
extern int emlxs_dfc_handle_unsol_req(emlxs_port_t *port, RING *rp,
	IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
extern void emlxs_fcoe_attention_thread(void *arg);


#ifdef SFCT_SUPPORT
/* Module emlxs_fct.c External Routine Declarations */
extern void emlxs_fct_link_down(emlxs_port_t *port);
extern void emlxs_fct_link_up(emlxs_port_t *port);
extern void emlxs_fct_init(emlxs_hba_t *hba);
extern void emlxs_fct_detach(emlxs_hba_t *hba);
extern int emlxs_fct_handle_unsol_els(emlxs_port_t *port, RING *rp,
	IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
extern int emlxs_fct_handle_unsol_req(emlxs_port_t *port, RING *rp,
	IOCBQ *iocbq, MATCHMAP *mp, uint32_t size);
extern int emlxs_fct_handle_fcp_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
extern void emlxs_fct_bind_port(emlxs_port_t *port);
extern void emlxs_fct_unbind_port(emlxs_port_t *port);
extern void emlxs_fct_unsol_callback(emlxs_port_t *port, fct_cmd_t *fct_cmd);
extern void emlxs_fct_attach(emlxs_hba_t *hba);
extern int emlxs_fct_port_shutdown(emlxs_port_t *port);
extern int emlxs_fct_port_initialize(emlxs_port_t *port);

#ifdef MODSYM_SUPPORT
extern void emlxs_fct_modclose();
#endif	/* MODSYM_SUPPORT */

#endif	/* SFCT_SUPPORT */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_EXTERN_H */
