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

#ifndef _EMLXS_EXTERN_H
#define	_EMLXS_EXTERN_H

#ifdef	__cplusplus
extern "C" {
#endif

extern void			*emlxs_soft_state;
extern uint32_t			emlxs_instance[MAX_FC_BRDS];
extern uint32_t			emlxs_instance_count;
extern char			emlxs_revision[32];
extern char			emlxs_version[32];
extern char			emlxs_name[64];
extern char			emlxs_label[64];

extern emlxs_device_t		emlxs_device;
extern uint32_t			emlxs_instance[MAX_FC_BRDS];
extern uint32_t			emlxs_instance_count;

extern ddi_device_acc_attr_t	emlxs_data_acc_attr;
extern ddi_device_acc_attr_t	emlxs_dev_acc_attr;
extern ddi_dma_lim_t		emlxs_dma_lim;
extern emlxs_config_t		emlxs_cfg[];
extern ddi_dma_attr_t		emlxs_dma_attr;
extern ddi_dma_attr_t		emlxs_dma_attr_ro;
extern ddi_dma_attr_t		emlxs_dma_attr_fcip_rsp;
extern ddi_dma_attr_t		emlxs_dma_attr_1sg;

/* Module emlxs_msg.c External Routine Declarations */
extern void			emlxs_msg_printf(emlxs_port_t *port,
					const uint32_t fileno,
					const uint32_t line,
					emlxs_msg_t *msg,
					const char *fmt, ...);
extern uint32_t			emlxs_msg_log_create(emlxs_hba_t *hba);
extern void			emlxs_msg_lock_reinit(emlxs_hba_t *hba);
extern void			emlxs_msg_log_destroy(emlxs_hba_t *hba);
extern uint32_t			emlxs_msg_log_get(emlxs_hba_t *hba,
					emlxs_log_req_t *req,
					emlxs_log_resp_t *resp);

/* Module emlxs_event.c External Routine Declarations */
extern uint32_t			emlxs_flush_ct_event(emlxs_port_t *port,
					uint32_t rxid);
extern void			emlxs_timer_check_events(emlxs_hba_t *hba);

extern uint32_t			emlxs_event_queue_create(emlxs_hba_t *hba);

extern void			emlxs_event_queue_destroy(emlxs_hba_t *hba);

extern void			emlxs_event(emlxs_port_t *port,
					emlxs_event_t *evt, void *bp,
					uint32_t size);
extern void			emlxs_log_dump_event(emlxs_port_t *port,
					uint8_t *buffer, uint32_t size);
extern void			emlxs_log_link_event(emlxs_port_t *port);

extern uint32_t			emlxs_log_ct_event(emlxs_port_t *port,
					uint8_t *payload, uint32_t size,
					uint32_t rxid);
extern void			emlxs_log_rscn_event(emlxs_port_t *port,
					uint8_t *payload, uint32_t size);
extern void			emlxs_log_vportrscn_event(emlxs_port_t *port,
					uint8_t *payload, uint32_t size);
extern void			emlxs_get_dfc_event(emlxs_port_t *port,
					emlxs_dfc_event_t *dfc_event,
					uint32_t sleep);
extern uint32_t			emlxs_kill_dfc_event(emlxs_port_t *port,
					emlxs_dfc_event_t *dfc_event);
extern uint32_t			emlxs_get_dfc_eventinfo(emlxs_port_t *port,
					HBA_EVENTINFO *eventinfo,
					uint32_t *eventcount,
					uint32_t *missed);
extern void			emlxs_log_temp_event(emlxs_port_t *port,
					uint32_t type, uint32_t temp);
extern void			emlxs_log_fcoe_event(emlxs_port_t *port,
					menlo_init_rsp_t *init_rsp);
extern void			emlxs_log_async_event(emlxs_port_t *port,
					IOCB *iocb);

#ifdef SAN_DIAG_SUPPORT
extern void			emlxs_get_sd_event(emlxs_port_t *port,
					emlxs_dfc_event_t *dfc_event,
					uint32_t sleep);
extern void			emlxs_log_sd_basic_els_event(emlxs_port_t *port,
					uint32_t subcat, HBA_WWN *portname,
					HBA_WWN *nodename);
extern void			emlxs_log_sd_prlo_event(emlxs_port_t *port,
					HBA_WWN *portname);
extern void			emlxs_log_sd_lsrjt_event(emlxs_port_t *port,
					HBA_WWN *remoteport, uint32_t orig_cmd,
					uint32_t reason, uint32_t reason_expl);
extern void			emlxs_log_sd_fc_bsy_event(emlxs_port_t *port,
					HBA_WWN *remoteport);
extern void			emlxs_log_sd_fc_rdchk_event(emlxs_port_t *port,
					HBA_WWN *remoteport, uint32_t lun,
					uint32_t opcode, uint32_t fcp_param);
extern void			emlxs_log_sd_scsi_event(emlxs_port_t *port,
					uint32_t type, HBA_WWN *remoteport,
					int32_t lun);
extern void			emlxs_log_sd_scsi_check_event(
					emlxs_port_t *port,
					HBA_WWN *remoteport, uint32_t lun,
					uint32_t cmdcode, uint32_t sensekey,
					uint32_t asc, uint32_t ascq);
#endif  /* SAN_DIAG_SUPPORT */

/* Module emlxs_solaris.c External Routine Declarations */

extern void			emlxs_fca_link_up(emlxs_port_t *port);

extern void			emlxs_fca_link_down(emlxs_port_t *port);

extern void 			emlxs_ulp_unsol_cb(emlxs_port_t *port,
					fc_unsol_buf_t *ubp);
extern void			emlxs_ulp_statec_cb(emlxs_port_t *port,
					uint32_t statec);
extern int32_t			emlxs_fca_reset(opaque_t fca_port_handle,
					uint32_t cmd);
extern int32_t			emlxs_fca_pkt_abort(opaque_t fca_port_handle,
					fc_packet_t *pkt, int32_t sleep);
extern char			*emlxs_state_xlate(uint8_t state);
extern char			*emlxs_error_xlate(uint8_t errno);
extern void			emlxs_mem_free(emlxs_hba_t *hba,
					MBUF_INFO *buf_info);
extern uint8_t			*emlxs_mem_alloc(emlxs_hba_t *hba,
					MBUF_INFO *buf_info);
extern int			emlxs_map_bus(emlxs_hba_t *hba);
extern void			emlxs_unmap_bus(emlxs_hba_t *hba);
extern fc_unsol_buf_t		*emlxs_ub_find(emlxs_port_t *port,
					uint32_t token);
extern fc_unsol_buf_t		*emlxs_ub_get(emlxs_port_t *port, uint32_t size,
					uint32_t type, uint32_t resv);
extern int32_t			emlxs_log_printf(int32_t f, int32_t type,
					int32_t num, int32_t brdno,
					const char *fmt, ...);
extern void			emlxs_set_pkt_state(emlxs_buf_t *sbp,
					uint32_t iostat, uint8_t localstat,
					uint32_t lock);
extern char			*emlxs_elscmd_xlate(uint32_t cmd);
extern char			*emlxs_ctcmd_xlate(uint32_t cmd);
extern char			*emlxs_rmcmd_xlate(uint32_t cmd);
extern char			*emlxs_wwn_xlate(char *buffer, size_t len,
					uint8_t *wwn);
extern int32_t			emlxs_wwn_cmp(uint8_t *wwn1, uint8_t *wwn2);
extern int32_t			emlxs_fca_transport(opaque_t fca_port_handle,
					fc_packet_t *pkt);
extern int32_t			emlxs_fca_pkt_uninit(opaque_t fca_port_handle,
					fc_packet_t *pkt);
extern int32_t			emlxs_fca_pkt_init(opaque_t fca_port_handle,
					fc_packet_t *pkt, int32_t sleep);
extern void			emlxs_pkt_complete(emlxs_buf_t *sbp,
					uint32_t iostat, uint8_t localstat,
					uint32_t doneq);

#ifdef SAN_DIAG_SUPPORT
extern void			emlxs_update_sd_bucket(emlxs_buf_t *sbp);
#endif /* SAN_DIAG_SUPPORT */

extern uint32_t			emlxs_get_instance(int32_t ddiinst);
extern char			*emlxs_mscmd_xlate(uint16_t cmd);
extern int32_t			emlxs_reset(emlxs_port_t *port, uint32_t cmd);
extern void			emlxs_swap_service_params(SERV_PARM *sp);
extern void			emlxs_swap_fcp_pkt(emlxs_buf_t *sbp);
extern void			emlxs_swap_ct_pkt(emlxs_buf_t *sbp);
extern void			emlxs_swap_els_pkt(emlxs_buf_t *sbp);
extern int			emlxs_fca_ub_release(opaque_t fca_port_handle,
					uint32_t count, uint64_t tokens[]);
extern void			emlxs_swap_els_ub(fc_unsol_buf_t *ubp);
extern void			emlxs_unswap_pkt(emlxs_buf_t *sbp);
extern uint32_t			emlxs_get_key(emlxs_hba_t *hba, MAILBOXQ *mbq);
extern int			emlxs_pm_busy_component(dev_info_t *dip);
extern int			emlxs_pm_idle_component(dev_info_t *dip);
extern void			emlxs_pm_idle_timer(dev_info_t *dip);
extern void			emlxs_shutdown_thread(emlxs_hba_t *hba,
					void *arg1, void *arg2);
extern uint32_t			emlxs_set_parm(emlxs_hba_t *hba, uint32_t index,
					uint32_t new_value);
extern void			emlxs_ub_destroy(emlxs_port_t *port,
					emlxs_unsol_buf_t *pool);
extern void			emlxs_ub_callback(emlxs_port_t *port,
					fc_unsol_buf_t *ubp);
extern void			emlxs_ub_flush(emlxs_port_t *port);
extern uint32_t			emlxs_check_parm(emlxs_hba_t *hba,
					uint32_t index, uint32_t new_value);
extern int32_t			emlxs_fca_port_manage(opaque_t fca_port_handle,
					fc_fca_pm_t *pm);
extern void			emlxs_port_init(emlxs_port_t *port);
extern void			emlxs_get_fcode_version(emlxs_hba_t *hba);

extern void			emlxs_swap32_buffer(uint8_t *buffer,
					uint32_t size);
extern void			emlxs_swap32_bcopy(uint8_t *src,
					uint8_t *dst, uint32_t size);

extern char 			*emlxs_strtoupper(char *str);

extern void			emlxs_mode_set(emlxs_hba_t *hba);

extern char			*emlxs_mode_xlate(uint32_t mode);

#ifdef MENLO_SUPPORT
extern char			*emlxs_menlo_cmd_xlate(uint32_t cmd);
extern char			*emlxs_menlo_rsp_xlate(uint32_t rsp);
#endif /* MENLO_SUPPORT */

#ifdef FMA_SUPPORT
extern void			emlxs_fm_init(emlxs_hba_t *hba);
extern void			emlxs_fm_fini(emlxs_hba_t *hba);
extern int			emlxs_fm_check_acc_handle(emlxs_hba_t *hba,
					ddi_acc_handle_t handle);
extern int			emlxs_fm_check_dma_handle(emlxs_hba_t *hba,
					ddi_dma_handle_t handle);
extern void			emlxs_fm_ereport(emlxs_hba_t *hba,
					char *detail);
extern void			emlxs_fm_service_impact(emlxs_hba_t *hba,
					int impact);
extern int			emlxs_fm_error_cb(dev_info_t *dip,
					ddi_fm_error_t *err,
					const void *impl_data);
extern void			emlxs_check_dma(emlxs_hba_t *hba,
					emlxs_buf_t *sbp);
#endif	/* FMA_SUPPORT */

/* Module emlxs_pkt.c External Routine Declarations */
extern int32_t			emlxs_pkt_send(fc_packet_t *pkt, uint32_t now);
extern void			emlxs_pkt_free(fc_packet_t *pkt);
extern void			emlxs_pkt_callback(fc_packet_t *pkt);
extern fc_packet_t		*emlxs_pkt_alloc(emlxs_port_t *port,
					uint32_t cmdlen, uint32_t rsplen,
					uint32_t datalen, int32_t sleep);

/* Module emlxs_clock.c External Routine Declarations */
extern void			emlxs_timer_checks(emlxs_hba_t *hba);
extern void			emlxs_timer_start(emlxs_hba_t *hba);
extern void			emlxs_timer_stop(emlxs_hba_t *hba);
extern void			emlxs_link_timeout(emlxs_hba_t *hba);
extern clock_t			emlxs_timeout(emlxs_hba_t *hba,
					uint32_t timeout);
extern void			emlxs_timer_cancel_clean_address(
					emlxs_port_t *port);

/* Module emlxs_dhchap.c External Routine Declarations */
#ifdef DHCHAP_SUPPORT
extern int			emlxs_dhchap_state_machine(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq,
					MATCHMAP *mp, NODELIST *node, int evt);

extern void			emlxs_dhc_attach(emlxs_hba_t *hba);
extern void			emlxs_dhc_detach(emlxs_hba_t *hba);
extern void			emlxs_dhc_authrsp_timeout(emlxs_port_t *port,
					void *node, void *null);
extern void			emlxs_dhc_reauth_timeout(emlxs_port_t *port,
					void *newtimeout, void *node);
extern void			emlxs_dhc_auth_stop(emlxs_port_t *port,
					emlxs_node_t *node);
extern int			emlxs_dhc_auth_start(emlxs_port_t *port,
					emlxs_node_t *node, uint8_t *sbp,
					uint8_t *ubp);
extern void			emlxs_dhc_init_sp(emlxs_port_t *port,
					uint32_t did, SERV_PARM *sp,
					char **msg);
extern uint32_t			emlxs_dhc_verify_login(emlxs_port_t *port,
					uint32_t sid, SERV_PARM *sp);
extern void			emlxs_dhc_status(emlxs_port_t *port,
					emlxs_node_t *ndlp, uint32_t reason,
					uint32_t explaination);
extern void			emlxs_dhc_state(emlxs_port_t *port,
					emlxs_node_t *ndlp, uint32_t state,
					uint32_t reason,
					uint32_t explaination);
extern uint32_t			emlxs_dhc_init_auth(emlxs_hba_t *hba,
					uint8_t *lwwpn, uint8_t *rwwpn);
extern uint32_t			emlxs_dhc_get_auth_cfg(emlxs_hba_t *hba,
					dfc_fcsp_config_t *fcsp_cfg);
extern uint32_t			emlxs_dhc_get_auth_key(emlxs_hba_t *hba,
					dfc_auth_password_t *dfc_auth_pwd);
extern uint32_t			emlxs_dhc_add_auth_cfg(emlxs_hba_t *hba,
					dfc_fcsp_config_t *fcsp_cfg,
					dfc_password_t *dfc_pwd);
extern uint32_t			emlxs_dhc_delete_auth_cfg(emlxs_hba_t *hba,
					dfc_fcsp_config_t *fcsp_cfg,
					dfc_password_t *dfc_pwd);
extern uint32_t			emlxs_dhc_set_auth_key(emlxs_hba_t *hba,
					dfc_auth_password_t *dfc_pwd);
extern uint32_t			emlxs_dhc_get_auth_status(emlxs_hba_t *hba,
					dfc_auth_status_t *fcsp_status);
extern uint32_t			emlxs_dhc_get_auth_cfg_table(emlxs_hba_t *hba,
					dfc_fcsp_config_t *fcsp_cfg);
extern uint32_t			emlxs_dhc_get_auth_key_table(emlxs_hba_t *hba,
					dfc_auth_password_t *auth_pwd);
#endif	/* DHCHAP_SUPPORT */

/* Module emlxs_node.c External Routine Declarations */
extern void 			emlxs_node_throttle_set(emlxs_port_t *port,
					NODELIST *node);
extern NODELIST *		emlxs_node_create(emlxs_port_t *port,
					uint32_t did, uint32_t rpi,
					SERV_PARM *sp);
extern void			emlxs_node_timeout(emlxs_port_t *port,
					NODELIST *ndlp, uint32_t ringno);
extern void			emlxs_node_open(emlxs_port_t *port,
					NODELIST *ndlp, uint32_t ringno);
extern void			emlxs_node_close(emlxs_port_t *port,
					NODELIST *ndlp, uint32_t ringno,
					int32_t timeout);
extern NODELIST			*emlxs_node_find_did(emlxs_port_t *port,
					uint32_t did, uint32_t lock);
extern NODELIST			*emlxs_node_find_rpi(emlxs_port_t *port,
					uint32_t rpi);
extern void			emlxs_node_destroy_all(emlxs_port_t *port);
extern NODELIST			*emlxs_node_find_mac(emlxs_port_t *port,
					uint8_t *mac);
extern void			emlxs_node_rm(emlxs_port_t *port,
					NODELIST *ndlp);
extern NODELIST			*emlxs_node_find_wwpn(emlxs_port_t *port,
					uint8_t *wwpn, uint32_t lock);
extern NODELIST			*emlxs_node_find_index(emlxs_port_t *port,
					uint32_t index, uint32_t nports_only);
extern uint32_t			emlxs_nport_count(emlxs_port_t *port);

/* Module emlxs_els.c External Routine Declarations */
extern int32_t			emlxs_els_handle_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *temp);
extern int32_t			emlxs_els_handle_unsol_req(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq,
					MATCHMAP *mp, uint32_t size);
extern uint32_t			emlxs_generate_rscn(emlxs_port_t *port,
					uint32_t d_id);
extern int32_t			emlxs_ct_handle_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *temp);
extern int32_t			emlxs_ct_handle_unsol_req(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq,
					MATCHMAP *mp, uint32_t size);
extern int32_t			emlxs_els_reply(emlxs_port_t *port,
					IOCBQ *iocbq, uint32_t type,
					uint32_t type2, uint32_t reason,
					uint32_t explain);
extern void			emlxs_send_logo(emlxs_port_t *port,
					uint32_t d_id);
extern void			emlxs_reset_link_thread(emlxs_hba_t *hba,
					void *arg1, void *arg2);
extern uint32_t			emlxs_process_unsol_flogi(emlxs_port_t *port,
					IOCBQ *iocbq, MATCHMAP *mp,
					uint32_t size, char *buffer,
					size_t len);
extern uint32_t			emlxs_process_unsol_plogi(emlxs_port_t *port,
					IOCBQ *iocbq, MATCHMAP *mp,
					uint32_t size, char *buffer,
					size_t len);
extern uint32_t			emlxs_ub_send_login_acc(emlxs_port_t *port,
					fc_unsol_buf_t *ubp);

#ifdef MENLO_SUPPORT
extern int			emlxs_menlo_handle_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *iocbq);
#endif /* MENLO_SUPPORT */

/* Module emlxs_ip.c External Routine Declarations */
extern int32_t			emlxs_ip_handle_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *temp);
extern int			emlxs_ip_handle_rcv_seq_list(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *saveq);
extern int			emlxs_ip_handle_unsol_req(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq, MATCHMAP *mp,
					uint32_t size);
extern int			emlxs_create_xri(emlxs_port_t *port,
					CHANNEL *cp, NODELIST *ndlp);
extern int			emlxs_handle_create_xri(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *temp);
extern int			emlxs_handle_xri_aborted(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *temp);

/* Module emlxs_mbox.c External Routine Declarations */
extern void			emlxs_mb_get_port_name(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_get_extents_info(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint16_t type);
extern void			emlxs_mb_get_extents(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint16_t type);
extern void			emlxs_mb_dealloc_extents(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint16_t type);
extern void			emlxs_mb_alloc_extents(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint16_t type,
					uint16_t count);
extern void			emlxs_mb_get_sli4_params(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern char			*emlxs_mb_xlate_status(uint32_t status);

extern void			emlxs_mb_config_msi(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t *intr_map,
					uint32_t intr_count);
extern void			emlxs_mb_config_msix(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t *intr_map,
					uint32_t intr_count);
extern void			emlxs_mb_read_lnk_stat(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_config_link(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_config_ring(emlxs_hba_t *hba,
					int32_t ring, MAILBOXQ *mbq);
extern void			emlxs_mb_init_link(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t topology,
					uint32_t linkspeed);
extern void			emlxs_mb_down_link(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern uint32_t			emlxs_mb_read_la(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_read_nv(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_read_rev(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t v3);
extern uint32_t			emlxs_mb_read_rpi(emlxs_hba_t *hba,
					uint32_t rpi, MAILBOXQ *mbq,
					uint32_t flg);
extern uint32_t			emlxs_mb_read_xri(emlxs_hba_t *hba,
					uint32_t xri, MAILBOXQ *mbq,
					uint32_t flg);
extern uint32_t			emlxs_mb_read_sparam(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_disable_tc(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern uint32_t			emlxs_mb_run_biu_diag(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint64_t in,
					uint64_t out);
extern void			emlxs_mb_dump_vpd(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t offset);
extern void			emlxs_mb_dump_fcoe(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t offset);
extern void			emlxs_mb_config_farp(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_read_config(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_put(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern MAILBOXQ			*emlxs_mb_get(emlxs_hba_t *hba);
extern void			emlxs_mb_clear_la(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_set_var(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t addr,
					uint32_t value);
extern void			emlxs_mb_reset_ring(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t ringno);
extern char			*emlxs_mb_cmd_xlate(uint8_t command);
extern char			*emlxs_request_feature_xlate(uint32_t mask);
extern void			emlxs_mb_read_status(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern int			emlxs_cmpl_init_vpi(void *arg1, MAILBOXQ *mbq);
extern uint32_t			emlxs_mb_init_vpi(emlxs_port_t *port);
extern int			emlxs_cmpl_reg_vpi(void *arg1, MAILBOXQ *mbq);
extern uint32_t			emlxs_mb_reg_vpi(emlxs_port_t *port,
					emlxs_buf_t *sbp);
extern int			emlxs_cmpl_unreg_vpi(void *arg1, MAILBOXQ *mbq);
extern uint32_t			emlxs_mb_unreg_vpi(emlxs_port_t *port);
extern void			emlxs_mb_fini(emlxs_hba_t *hba,
					MAILBOX *mb, uint32_t mbxStatus);
extern void			emlxs_mb_deferred_cmpl(emlxs_port_t *port,
					uint32_t mbxStatus, emlxs_buf_t *sbp,
					fc_unsol_buf_t *ubp, IOCBQ *iocbq);
extern void			emlxs_mb_flush(emlxs_hba_t *hba);
extern void			emlxs_mb_heartbeat(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_request_features(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t mask);
extern int			emlxs_mb_resume_rpi(emlxs_hba_t *hba,
					emlxs_buf_t *sbp, uint16_t rpi);
extern void			emlxs_mb_noop(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern int			emlxs_mbext_noop(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_resetport(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_eq_create(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t num);
extern void			emlxs_mb_cq_create(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t num);
extern void			emlxs_mb_wq_create(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t num);
extern void			emlxs_mb_rq_create(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t num);
extern void			emlxs_mb_mq_create(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_mq_create_ext(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern int			emlxs_mb_reg_fcfi(emlxs_hba_t *hba,
					MAILBOXQ *mbq, FCFIobj_t *fcfp);
extern int			emlxs_mb_unreg_fcfi(emlxs_hba_t *hba,
					FCFIobj_t *fcfp);
extern int			emlxs_mb_reg_vfi(emlxs_hba_t *hba,
					MAILBOXQ *mb, VFIobj_t *vfip,
					emlxs_port_t *vpip);
extern int			emlxs_mb_unreg_vfi(emlxs_hba_t *hba,
					VFIobj_t *vfip);
extern int			emlxs_mbext_read_fcf_table(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t index);
extern int			emlxs_mbext_add_fcf_table(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t index);
extern void			emlxs_mb_rediscover_fcf_table(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern void			emlxs_mb_async_event(emlxs_hba_t *hba,
					MAILBOXQ *mbq);
extern int32_t			emlxs_mb_check_sparm(emlxs_hba_t *hba,
					SERV_PARM *nsp);
extern void			emlxs_cmpl_mbox(emlxs_hba_t *hba, MAILBOXQ *mq);
extern void			emlxs_mb_dump(emlxs_hba_t *hba, MAILBOXQ *mbq,
					uint32_t offset, uint32_t words);
extern void			emlxs_mb_retry(emlxs_hba_t *hba, MAILBOXQ *mbq);
extern void			emlxs_mb_init(emlxs_hba_t *hba, MAILBOXQ *mbq,
					uint32_t flag, uint32_t tmo);
extern void			emlxs_mb_config_hbq(emlxs_hba_t *hba,
					MAILBOXQ *mbq, int hbq_id);

/* Module emlxs_mem.c External Routine Declarations */
extern void			*emlxs_mem_pool_get(emlxs_hba_t *hba,
					MEMSEG *seg);
extern void 			emlxs_mem_pool_put(emlxs_hba_t *hba,
					MEMSEG *seg, void *bp);
extern uint32_t 		emlxs_mem_pool_create(emlxs_hba_t *hba,
					MEMSEG *seg);
extern void 			emlxs_mem_pool_destroy(emlxs_hba_t *hba,
					MEMSEG *seg);
extern void 			emlxs_mem_pool_clean(emlxs_hba_t *hba,
					MEMSEG *seg);
extern MATCHMAP			*emlxs_mem_get_vaddr(emlxs_hba_t *hba,
					RING *rp, uint64_t mapbp);
extern void			*emlxs_mem_get(emlxs_hba_t *hba,
					uint32_t seg_id);
extern void			emlxs_mem_put(emlxs_hba_t *hba,
					uint32_t seg_id, void *bp);
extern int32_t			emlxs_mem_free_buffer(emlxs_hba_t *hba);
extern int32_t			emlxs_mem_alloc_buffer(emlxs_hba_t *hba);
extern void			emlxs_mem_map_vaddr(emlxs_hba_t *hba,
					RING *rp, MATCHMAP *mp, uint32_t *haddr,
					uint32_t *laddr);
extern MATCHMAP			*emlxs_mem_buf_alloc(emlxs_hba_t *hba,
					uint32_t size);
extern void			emlxs_mem_buf_free(emlxs_hba_t *hba,
					MATCHMAP *mp);
extern uint32_t			emlxs_hbq_alloc(emlxs_hba_t *hba,
					uint32_t hbq_id);

/* Module emlxs_hba.c  External Routine Declarations */
extern char			*emlxs_pci_cap_xlate(uint32_t id);
extern char			*emlxs_pci_ecap_xlate(uint32_t id);

extern void			emlxs_decode_firmware_rev(emlxs_hba_t *hba,
					emlxs_vpd_t *vp);
extern uint32_t			emlxs_init_adapter_info(emlxs_hba_t *hba);
extern uint32_t			emlxs_strtol(char *str, uint32_t base);
extern uint64_t			emlxs_strtoll(char *str, uint32_t base);
extern void			emlxs_decode_version(uint32_t version,
					char *buffer, size_t len);
extern char			*emlxs_ffstate_xlate(uint32_t new_state);
extern char			*emlxs_ring_xlate(uint32_t ringno);
extern void			emlxs_proc_channel(emlxs_hba_t *hba,
					CHANNEL *cp, void *arg2);
extern void			emlxs_pcix_mxr_update(emlxs_hba_t *hba,
					uint32_t verbose);
extern void			emlxs_restart_thread(emlxs_hba_t *hba,
					void *arg1, void *arg2);
extern void			emlxs_fw_show(emlxs_hba_t *hba);
extern void			emlxs_proc_channel_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *iocbq);

#ifdef MODFW_SUPPORT
extern void			emlxs_fw_load(emlxs_hba_t *hba,
					emlxs_firmware_t *fw);
extern void			emlxs_fw_unload(emlxs_hba_t *hba,
					emlxs_firmware_t *fw);
#endif /* MODFW_SUPPORT */

#ifdef MSI_SUPPORT
extern int32_t			emlxs_msi_add(emlxs_hba_t *hba);
extern int32_t			emlxs_msi_remove(emlxs_hba_t *hba);
extern int32_t			emlxs_msi_init(emlxs_hba_t *hba, uint32_t max);
extern int32_t			emlxs_msi_uninit(emlxs_hba_t *hba);
#endif	/* MSI_SUPPORT */

extern int32_t			emlxs_intx_add(emlxs_hba_t *hba);
extern int32_t			emlxs_intx_remove(emlxs_hba_t *hba);
extern int32_t			emlxs_intx_init(emlxs_hba_t *hba, uint32_t max);
extern int32_t			emlxs_intx_uninit(emlxs_hba_t *hba);

extern void			emlxs_parse_prog_types(emlxs_hba_t *hba,
					char *types);
extern int32_t			emlxs_parse_vpd(emlxs_hba_t *hba, uint8_t *vpd,
					uint32_t size);
extern int32_t			emlxs_parse_fcoe(emlxs_hba_t *hba, uint8_t *p,
					uint32_t size);

extern void			emlxs_decode_label(char *label, char *buffer,
					int bige, size_t len);
extern void			emlxs_build_prog_types(emlxs_hba_t *hba,
					emlxs_vpd_t *vpd);
extern void			emlxs_process_link_speed(emlxs_hba_t *hba);

extern uint32_t			emlxs_iotag_flush(emlxs_hba_t *hba);

extern int			emlxs_pci_model_count;
extern emlxs_model_t		emlxs_pci_model[];

extern int			emlxs_fw_count;
extern emlxs_firmware_t		emlxs_fw_table[];


/* Module emlxs_sli3.c  External Routine Declarations */
extern emlxs_sli_api_t		emlxs_sli3_api;

extern int			emlxs_handle_rcv_seq(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *iocbq);
extern void			emlxs_update_HBQ_index(emlxs_hba_t *hba,
					uint32_t hbq_id);
extern void			emlxs_hbq_free_all(emlxs_hba_t *hba,
					uint32_t hbq_id);

/* Module emlxs_sli4.c  External Routine Declarations */

extern uint32_t			emlxs_sli4_vfi_to_index(emlxs_hba_t *hba,
					uint32_t vfi);
extern uint32_t			emlxs_sli4_index_to_vfi(emlxs_hba_t *hba,
					uint32_t index);
extern uint32_t			emlxs_sli4_vpi_to_index(emlxs_hba_t *hba,
					uint32_t vpi);
extern uint32_t			emlxs_sli4_index_to_vpi(emlxs_hba_t *hba,
					uint32_t index);
extern uint32_t			emlxs_sli4_xri_to_index(emlxs_hba_t *hba,
					uint32_t xri);
extern uint32_t			emlxs_sli4_index_to_xri(emlxs_hba_t *hba,
					uint32_t index);
extern uint32_t			emlxs_sli4_rpi_to_index(emlxs_hba_t *hba,
					uint32_t rpi);
extern uint32_t			emlxs_sli4_index_to_rpi(emlxs_hba_t *hba,
					uint32_t index);

extern uint32_t 		emlxs_sli4_unreg_all_nodes(
					emlxs_port_t *port);
extern void			emlxs_sli4_hba_reset_all(emlxs_hba_t *hba,
					uint32_t flag);
extern XRIobj_t 		*emlxs_sli4_reserve_xri(emlxs_port_t *port,
					RPIobj_t *rpip, uint32_t type,
					uint16_t rx_id);
extern emlxs_sli_api_t		emlxs_sli4_api;

extern FCFIobj_t		*emlxs_sli4_assign_fcfi(emlxs_hba_t *hba,
					FCF_RECORD_t *fcfrec,
					uint32_t event_tag);
extern void			emlxs_data_dump(emlxs_port_t *port, char *str,
					uint32_t *data, int cnt, int err);
extern void			emlxs_ue_dump(emlxs_hba_t *hba, char *str);

extern XRIobj_t			*emlxs_sli4_find_xri(emlxs_port_t *port,
					uint16_t xri);
extern VFIobj_t			*emlxs_sli4_alloc_vfi(emlxs_hba_t *hba,
					FCFIobj_t *fp);
extern void			emlxs_sli4_free_vfi(emlxs_hba_t *hba,
					VFIobj_t *xp);
extern void			emlxs_sli4_free_fcfi(emlxs_hba_t *hba,
					FCFIobj_t *xp);
extern void			emlxs_sli4_free_xri(emlxs_port_t *port,
					emlxs_buf_t *sbp, XRIobj_t *xp,
					uint8_t lock);
extern FCFIobj_t		*emlxs_sli4_bind_fcfi(emlxs_hba_t *hba);

extern uint32_t			emlxs_sli4_unreserve_xri(emlxs_port_t *port,
					uint16_t xri, uint32_t lock);
extern XRIobj_t 		*emlxs_sli4_register_xri(emlxs_port_t *port,
					emlxs_buf_t *sbp, uint16_t xri,
					uint32_t did);


/* Module emlxs_diag.c  External Routine Declarations */
extern uint32_t			emlxs_diag_post_run(emlxs_hba_t *hba);
extern uint32_t			emlxs_diag_biu_run(emlxs_hba_t *hba,
					uint32_t pattern);
extern uint32_t			emlxs_diag_pattern[256];
extern uint32_t			emlxs_diag_echo_run(emlxs_port_t *port,
					uint32_t did, uint32_t pattern);

/* Module emlxs_download.c External Routine Declarations */
extern void			emlxs_memset(uint8_t *buffer, uint8_t value,
					uint32_t size);
extern int32_t			emlxs_fw_download(emlxs_hba_t *hba,
					caddr_t buffer, uint32_t len,
					uint32_t offline);
extern uint32_t			emlxs_get_max_sram(emlxs_hba_t *hba,
					uint32_t *MaxRbusSize,
					uint32_t *MaxIbusSize);
extern uint32_t			emlxs_get_load_list(emlxs_hba_t *hba,
					PROG_ID *load_list);
extern uint32_t			emlxs_read_wakeup_parms(emlxs_hba_t *hba,
					PWAKE_UP_PARMS WakeUpParms,
					uint32_t verbose);
extern int32_t			emlxs_cfl_download(emlxs_hba_t *hba,
					uint32_t region, caddr_t buffer,
					uint32_t len);

extern int32_t			emlxs_boot_code_disable(emlxs_hba_t *hba);
extern int32_t			emlxs_boot_code_enable(emlxs_hba_t *hba);
extern int32_t			emlxs_boot_code_state(emlxs_hba_t *hba);

extern int32_t			emlxs_be_read_fw_version(emlxs_hba_t *hba,
					emlxs_firmware_t *fw);

/* Module emlxs_fcp.c External Routine Declarations */
extern int			emlxs_power_up(emlxs_hba_t *hba);
extern int			emlxs_power_down(emlxs_hba_t *hba);
extern int			emlxs_reset_link(emlxs_hba_t *hba,
					uint32_t linkup, uint32_t wait);
extern emlxs_buf_t		*emlxs_unregister_pkt(CHANNEL *cp,
					uint16_t iotag, uint32_t forced);
extern uint16_t			emlxs_register_pkt(CHANNEL *cp,
					emlxs_buf_t *sbp);

extern IOCBQ			*emlxs_create_abort_xri_cn(emlxs_port_t *port,
					NODELIST *ndlp, uint16_t iotag,
					CHANNEL *cp, uint8_t class,
					int32_t flag);
extern IOCBQ			*emlxs_create_close_xri_cn(emlxs_port_t *port,
					NODELIST *ndlp, uint16_t iotag,
					CHANNEL *cp);
extern IOCBQ			*emlxs_create_abort_xri_cx(emlxs_port_t *port,
					NODELIST *ndlp, uint16_t xid,
					CHANNEL *cp, uint8_t class,
					int32_t flag);
extern IOCBQ			*emlxs_create_close_xri_cx(emlxs_port_t *port,
					NODELIST *ndlp, uint16_t xid,
					CHANNEL *cp);
extern void			emlxs_abort_ct_exchange(emlxs_hba_t *hba,
					emlxs_port_t *port, uint32_t rxid);
extern void			emlxs_abort_els_exchange(emlxs_hba_t *hba,
					emlxs_port_t *port, uint32_t rxid);
extern void			emlxs_close_els_exchange(emlxs_hba_t *hba,
					emlxs_port_t *port, uint32_t rxid);
extern void			emlxs_abort_fct_exchange(emlxs_hba_t *hba,
					emlxs_port_t *port, uint32_t rxid);
extern emlxs_buf_t		*emlxs_chipq_get(CHANNEL *cp, uint16_t iotag);
extern void			emlxs_chipq_put(CHANNEL *cp, emlxs_buf_t *sbp);
extern uint32_t			emlxs_chipq_node_flush(emlxs_port_t *port,
					CHANNEL *cp, NODELIST *ndlp,
					emlxs_buf_t *fpkt);
extern uint32_t			emlxs_chipq_lun_flush(emlxs_port_t *port,
					NODELIST *ndlp, uint32_t lun,
					emlxs_buf_t *fpkt);
extern uint32_t			emlxs_chipq_node_check(emlxs_port_t *port,
					CHANNEL *cp, NODELIST *ndlp);

extern IOCBQ			*emlxs_tx_get(CHANNEL *cp, uint32_t lock);
extern void			emlxs_tx_put(IOCBQ *iocbq, uint32_t lock);
extern void			emlxs_tx_move(NODELIST *ndlp, CHANNEL *from,
					CHANNEL *to, uint32_t cmd,
					emlxs_buf_t *fpkt, uint32_t lock);

extern uint32_t			emlxs_tx_node_check(emlxs_port_t *port,
					NODELIST *ndlp, CHANNEL *cp);
extern uint32_t			emlxs_tx_node_flush(emlxs_port_t *port,
					NODELIST *ndlp, CHANNEL *cp,
					uint32_t shutdown, emlxs_buf_t *fpkt);
extern uint32_t			emlxs_tx_lun_flush(emlxs_port_t *port,
					NODELIST *ndlp, uint32_t lun,
					emlxs_buf_t *fpkt);
extern uint32_t			emlxs_tx_channel_flush(emlxs_hba_t *hba,
					CHANNEL *cp, emlxs_buf_t *fpkt);

extern void			emlxs_linkdown(emlxs_hba_t *hba);
extern void			emlxs_linkup(emlxs_hba_t *hba);
extern void			emlxs_port_online(emlxs_port_t *port);
extern int32_t			emlxs_port_offline(emlxs_port_t *port,
					uint32_t scope);
extern void			emlxs_ffcleanup(emlxs_hba_t *hba);
extern int32_t			emlxs_offline(emlxs_hba_t *hba,
					uint32_t reset_requested);
extern int32_t			emlxs_online(emlxs_hba_t *hba);
extern int32_t			emlxs_post_buffer(emlxs_hba_t *hba,
					RING *rp, int16_t cnt);
extern void			emlxs_ff_start(emlxs_hba_t *hba);
extern void			emlxs_handle_fcp_event(emlxs_hba_t *hba,
					CHANNEL *rp, IOCBQ *temp);
extern int			emlxs_fct_handle_abort(emlxs_hba_t *hba,
					CHANNEL *rp, IOCBQ *iocbq);

/* Module emlxs_thread.c External Routine Declarations */
extern void			emlxs_taskq_destroy(emlxs_taskq_t *taskq);
extern void			emlxs_taskq_create(emlxs_hba_t *hba,
					emlxs_taskq_t *taskq);
extern uint32_t			emlxs_taskq_dispatch(emlxs_taskq_t *taskq,
					void (*func) (), void *arg);
extern void			emlxs_thread_create(emlxs_hba_t *hba,
					emlxs_thread_t *ethread);
extern void			emlxs_thread_destroy(emlxs_thread_t *ethread);
extern void			emlxs_thread_trigger1(emlxs_thread_t *ethread,
					void (*func) ());
extern void			emlxs_thread_trigger2(emlxs_thread_t *ethread,
					void (*func) (), CHANNEL *cp);
extern void			emlxs_thread_spawn(emlxs_hba_t *hba,
					void (*func) (), void *arg1,
					void *arg2);
extern void			emlxs_thread_spawn_create(emlxs_hba_t *hba);
extern void			emlxs_thread_spawn_destroy(emlxs_hba_t *hba);

/* Module emlxs_dfc.c External Routine Declarations */
extern int32_t			emlxs_dfc_manage(emlxs_hba_t *hba, void *dfc,
					int32_t mode);
extern int32_t			emlxs_dfc_handle_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *temp);
extern int			emlxs_dfc_handle_unsol_req(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq,
					MATCHMAP *mp, uint32_t size);
extern void			emlxs_fcoe_attention_thread(emlxs_hba_t *hba,
					void *arg1, void *arg2);
extern uint32_t		emlxs_set_hba_mode(emlxs_hba_t *hba, uint32_t mode);
extern uint32_t		emlxs_get_dump_region(emlxs_hba_t *hba, uint32_t region,
			    uint8_t *buffer, uint32_t *psize);
extern int32_t		emlxs_send_menlo_cmd(emlxs_hba_t *hba, uint8_t *cmd_buf,
			    uint32_t cmd_size, uint8_t *rsp_buf,
			    uint32_t *rsp_size);

#ifdef SFCT_SUPPORT
/* Module emlxs_fct.c External Routine Declarations */
extern uint32_t			emlxs_fct_stmf_alloc(emlxs_hba_t *hba,
					MATCHMAP *mp);
extern void			emlxs_fct_stmf_free(emlxs_hba_t *hba,
					MATCHMAP *mp);
extern void			emlxs_fct_link_down(emlxs_port_t *port);
extern void			emlxs_fct_link_up(emlxs_port_t *port);
extern uint32_t			emlxs_fct_init(emlxs_hba_t *hba);
extern void			emlxs_fct_detach(emlxs_hba_t *hba);
extern int			emlxs_fct_handle_unsol_els(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq, MATCHMAP *mp,
					uint32_t size);
extern int			emlxs_fct_handle_unsol_req(emlxs_port_t *port,
					CHANNEL *cp, IOCBQ *iocbq, MATCHMAP *mp,
					uint32_t size);
extern int			emlxs_fct_handle_fcp_event(emlxs_hba_t *hba,
					CHANNEL *cp, IOCBQ *iocbq);
extern void			emlxs_fct_bind_port(emlxs_port_t *port);
extern void			emlxs_fct_unbind_port(emlxs_port_t *port);
extern void			emlxs_fct_unsol_callback(emlxs_port_t *port,
					fct_cmd_t *fct_cmd);
extern void			emlxs_fct_attach(emlxs_hba_t *hba);
extern int			emlxs_fct_port_shutdown(emlxs_port_t *port);
extern int			emlxs_fct_port_initialize(emlxs_port_t *port);

#ifdef MODSYM_SUPPORT
extern int			emlxs_fct_modopen();
extern void			emlxs_fct_modclose();
#endif /* MODSYM_SUPPORT */

#ifdef FCT_IO_TRACE
extern void			emlxs_fct_io_trace(emlxs_port_t *,
					fct_cmd_t *, uint32_t);
#endif /* FCT_IO_TRACE */
#endif /* SFCT_SUPPORT */

#ifdef DUMP_SUPPORT
/* Module emlxs_dump.c External Routine Declarations */
extern uint32_t		emlxs_dump_drv_event(emlxs_hba_t *hba);
extern uint32_t		emlxs_dump_user_event(emlxs_hba_t *hba);
extern uint32_t		emlxs_dump_temp_event(emlxs_hba_t *hba,
				uint32_t tempType, uint32_t temp);
extern void		emlxs_dump_drv_thread(emlxs_hba_t *hba,
				void *arg1, void *arg2);
extern void		emlxs_dump_user_thread(emlxs_hba_t *hba,
				void *arg1, void *arg2);
extern void		emlxs_dump_temp_thread(emlxs_hba_t *hba,
				void *arg1, void *arg2);
extern uint32_t		emlxs_ftell(emlxs_file_t *fp);
extern uint32_t		emlxs_get_dump(emlxs_hba_t *hba, uint8_t *buffer,
			    uint32_t *buflen);
extern void		emlxs_dump_wait(emlxs_hba_t *hba);
extern void		emlxs_dump(emlxs_hba_t *hba, uint32_t type,
			    uint32_t temp_type, uint32_t temp);

extern emlxs_file_t	*emlxs_fopen(emlxs_hba_t *hba, uint32_t file_type);
extern void		emlxs_fflush(emlxs_file_t *fp);
extern uint32_t		emlxs_fclose(emlxs_file_t *fp);
extern uint32_t		emlxs_dump_word_dmpfile(emlxs_file_t *fpDmpFile,
				uint8_t *pBuffer, uint32_t bufferLen,
				int fSwap);
#endif /* DUMP_SUPPORT */


/* Module emlxs_fcf.c External Routine Declarations */
extern void		emlxs_fcf_init(emlxs_hba_t *hba);

extern void		emlxs_fcf_fini(emlxs_hba_t *hba);

extern uint32_t 	emlxs_vpi_port_bind_notify(emlxs_port_t *port);

extern uint32_t 	emlxs_vpi_port_unbind_notify(emlxs_port_t *port,
				uint32_t wait);
extern uint32_t		emlxs_vpi_logo_cmpl_notify(emlxs_port_t *port);

extern uint32_t		emlxs_vpi_logi_notify(emlxs_port_t *port,
				emlxs_buf_t *sbp);
extern uint32_t		emlxs_vpi_logi_failed_notify(emlxs_port_t *port,
				emlxs_buf_t *sbp);
extern uint32_t		emlxs_vpi_rpi_offline_notify(emlxs_port_t *port,
				uint32_t did, uint32_t rpi);
extern uint32_t		emlxs_vpi_rpi_online_notify(emlxs_port_t *port,
				uint32_t did, uint32_t rpi, uint32_t lock);
extern uint32_t		emlxs_fcf_shutdown_notify(emlxs_port_t *port,
				uint32_t wait);
extern uint32_t		emlxs_fcf_linkup_notify(emlxs_port_t *port);

extern uint32_t		emlxs_fcf_linkdown_notify(emlxs_port_t *port);

extern uint32_t		emlxs_fcf_cvl_notify(emlxs_port_t *port, uint32_t vpi);

extern uint32_t		emlxs_fcf_full_notify(emlxs_port_t *port);

extern uint32_t		emlxs_fcf_found_notify(emlxs_port_t *port,
				uint32_t fcf_index);
extern uint32_t		emlxs_fcf_changed_notify(emlxs_port_t *port,
				uint32_t fcf_index);
extern uint32_t		emlxs_fcf_lost_notify(emlxs_port_t *port,
				uint32_t fcf_index);
extern void		emlxs_fcf_timer_notify(emlxs_hba_t *hba);


extern RPIobj_t 	*emlxs_rpi_find(emlxs_port_t *port, uint16_t rpi);

extern RPIobj_t		*emlxs_rpi_reserve_notify(emlxs_port_t *port,
				uint32_t did, XRIobj_t *xrip);
extern RPIobj_t 	*emlxs_rpi_alloc_notify(emlxs_port_t *port,
				uint32_t did);
extern uint32_t		emlxs_rpi_free_notify(emlxs_port_t *port,
				RPIobj_t *rpip);
extern uint32_t		emlxs_rpi_online_notify(emlxs_port_t *port,
				RPIobj_t *rpip, uint32_t did, SERV_PARM *sparam,
				void *arg1, void *arg2, void *arg3);
extern uint32_t		emlxs_rpi_offline_notify(emlxs_port_t *port,
				RPIobj_t *rpip, void *arg1, void *arg2,
				void *arg3);
extern uint32_t		emlxs_rpi_pause_notify(emlxs_port_t *port,
				RPIobj_t *rpip);
extern uint32_t		emlxs_rpi_resume_notify(emlxs_port_t *port,
				RPIobj_t *rpip, emlxs_buf_t *sbp);


#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_EXTERN_H */
