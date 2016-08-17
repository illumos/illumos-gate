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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Fibre Channel SCSI ULP Mapping driver
 */

#include <sys/scsi/scsi.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/devctl.h>
#include <sys/thread.h>
#include <sys/thread.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/sunndi.h>
#include <sys/console.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/ndi_impldefs.h>
#include <sys/byteorder.h>
#include <sys/fs/dv_node.h>
#include <sys/ctype.h>
#include <sys/sunmdi.h>

#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/ulp/fcpvar.h>

/*
 * Discovery Process
 * =================
 *
 *    The discovery process is a major function of FCP.	 In order to help
 * understand that function a flow diagram is given here.  This diagram
 * doesn't claim to cover all the cases and the events that can occur during
 * the discovery process nor the subtleties of the code.  The code paths shown
 * are simplified.  Its purpose is to help the reader (and potentially bug
 * fixer) have an overall view of the logic of the code.  For that reason the
 * diagram covers the simple case of the line coming up cleanly or of a new
 * port attaching to FCP the link being up.  The reader must keep in mind
 * that:
 *
 *	- There are special cases where bringing devices online and offline
 *	  is driven by Ioctl.
 *
 *	- The behavior of the discovery process can be modified through the
 *	  .conf file.
 *
 *	- The line can go down and come back up at any time during the
 *	  discovery process which explains some of the complexity of the code.
 *
 * ............................................................................
 *
 * STEP 1: The line comes up or a new Fibre Channel port attaches to FCP.
 *
 *
 *			+-------------------------+
 *   fp/fctl module --->|    fcp_port_attach	  |
 *			+-------------------------+
 *	   |			     |
 *	   |			     |
 *	   |			     v
 *	   |		+-------------------------+
 *	   |		| fcp_handle_port_attach  |
 *	   |		+-------------------------+
 *	   |				|
 *	   |				|
 *	   +--------------------+	|
 *				|	|
 *				v	v
 *			+-------------------------+
 *			|   fcp_statec_callback	  |
 *			+-------------------------+
 *				    |
 *				    |
 *				    v
 *			+-------------------------+
 *			|    fcp_handle_devices	  |
 *			+-------------------------+
 *				    |
 *				    |
 *				    v
 *			+-------------------------+
 *			|   fcp_handle_mapflags	  |
 *			+-------------------------+
 *				    |
 *				    |
 *				    v
 *			+-------------------------+
 *			|     fcp_send_els	  |
 *			|			  |
 *			| PLOGI or PRLI To all the|
 *			| reachable devices.	  |
 *			+-------------------------+
 *
 *
 * ............................................................................
 *
 * STEP 2: The callback functions of the PLOGI and/or PRLI requests sent during
 *	   STEP 1 are called (it is actually the same function).
 *
 *
 *			+-------------------------+
 *			|    fcp_icmd_callback	  |
 *   fp/fctl module --->|			  |
 *			| callback for PLOGI and  |
 *			| PRLI.			  |
 *			+-------------------------+
 *				     |
 *				     |
 *	    Received PLOGI Accept   /-\	  Received PRLI Accept
 *		       _ _ _ _ _ _ /   \_ _ _ _ _ _
 *		      |		   \   /	   |
 *		      |		    \-/		   |
 *		      |				   |
 *		      v				   v
 *	+-------------------------+	+-------------------------+
 *	|     fcp_send_els	  |	|     fcp_send_scsi	  |
 *	|			  |	|			  |
 *	|	  PRLI		  |	|	REPORT_LUN	  |
 *	+-------------------------+	+-------------------------+
 *
 * ............................................................................
 *
 * STEP 3: The callback functions of the SCSI commands issued by FCP are called
 *	   (It is actually the same function).
 *
 *
 *			    +-------------------------+
 *   fp/fctl module ------->|	 fcp_scsi_callback    |
 *			    +-------------------------+
 *					|
 *					|
 *					|
 *	Receive REPORT_LUN reply       /-\	Receive INQUIRY PAGE83 reply
 *		  _ _ _ _ _ _ _ _ _ _ /	  \_ _ _ _ _ _ _ _ _ _ _ _
 *		 |		      \	  /			  |
 *		 |		       \-/			  |
 *		 |			|			  |
 *		 | Receive INQUIRY reply|			  |
 *		 |			|			  |
 *		 v			v			  v
 * +------------------------+ +----------------------+ +----------------------+
 * |  fcp_handle_reportlun  | |	 fcp_handle_inquiry  | |  fcp_handle_page83   |
 * |(Called for each Target)| | (Called for each LUN)| |(Called for each LUN) |
 * +------------------------+ +----------------------+ +----------------------+
 *		 |			|			  |
 *		 |			|			  |
 *		 |			|			  |
 *		 v			v			  |
 *     +-----------------+	+-----------------+		  |
 *     |  fcp_send_scsi	 |	|  fcp_send_scsi  |		  |
 *     |		 |	|		  |		  |
 *     |     INQUIRY	 |	| INQUIRY PAGE83  |		  |
 *     |  (To each LUN)	 |	+-----------------+		  |
 *     +-----------------+					  |
 *								  |
 *								  v
 *						      +------------------------+
 *						      |	 fcp_call_finish_init  |
 *						      +------------------------+
 *								  |
 *								  v
 *						 +-----------------------------+
 *						 |  fcp_call_finish_init_held  |
 *						 +-----------------------------+
 *								  |
 *								  |
 *			   All LUNs scanned			 /-\
 *			       _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ __ /   \
 *			      |					\   /
 *			      |					 \-/
 *			      v					  |
 *		     +------------------+			  |
 *		     |	fcp_finish_tgt	|			  |
 *		     +------------------+			  |
 *			      |	  Target Not Offline and	  |
 *  Target Not Offline and    |	  not marked and tgt_node_state	  |
 *  marked		     /-\  not FCP_TGT_NODE_ON_DEMAND	  |
 *		_ _ _ _ _ _ /	\_ _ _ _ _ _ _ _		  |
 *	       |	    \	/		|		  |
 *	       |	     \-/		|		  |
 *	       v				v		  |
 * +----------------------------+     +-------------------+	  |
 * |	 fcp_offline_target	|     |	 fcp_create_luns  |	  |
 * |				|     +-------------------+	  |
 * | A structure fcp_tgt_elem	|		|		  |
 * | is created and queued in	|		v		  |
 * | the FCP port list		|     +-------------------+	  |
 * | port_offline_tgts.	 It	|     |	 fcp_pass_to_hp	  |	  |
 * | will be unqueued by the	|     |			  |	  |
 * | watchdog timer.		|     | Called for each	  |	  |
 * +----------------------------+     | LUN. Dispatches	  |	  |
 *		  |		      | fcp_hp_task	  |	  |
 *		  |		      +-------------------+	  |
 *		  |				|		  |
 *		  |				|		  |
 *		  |				|		  |
 *		  |				+---------------->|
 *		  |						  |
 *		  +---------------------------------------------->|
 *								  |
 *								  |
 *		All the targets (devices) have been scanned	 /-\
 *				_ _ _ _	_ _ _ _	_ _ _ _ _ _ _ _ /   \
 *			       |				\   /
 *			       |				 \-/
 *	    +-------------------------------------+		  |
 *	    |		fcp_finish_init		  |		  |
 *	    |					  |		  |
 *	    | Signal broadcasts the condition	  |		  |
 *	    | variable port_config_cv of the FCP  |		  |
 *	    | port.  One potential code sequence  |		  |
 *	    | waiting on the condition variable	  |		  |
 *	    | the code sequence handling	  |		  |
 *	    | BUS_CONFIG_ALL and BUS_CONFIG_DRIVER|		  |
 *	    | The other is in the function	  |		  |
 *	    | fcp_reconfig_wait which is called	  |		  |
 *	    | in the transmit path preventing IOs |		  |
 *	    | from going through till the disco-  |		  |
 *	    | very process is over.		  |		  |
 *	    +-------------------------------------+		  |
 *			       |				  |
 *			       |				  |
 *			       +--------------------------------->|
 *								  |
 *								  v
 *								Return
 *
 * ............................................................................
 *
 * STEP 4: The hot plug task is called (for each fcp_hp_elem).
 *
 *
 *			+-------------------------+
 *			|      fcp_hp_task	  |
 *			+-------------------------+
 *				     |
 *				     |
 *				     v
 *			+-------------------------+
 *			|     fcp_trigger_lun	  |
 *			+-------------------------+
 *				     |
 *				     |
 *				     v
 *		   Bring offline    /-\	 Bring online
 *		  _ _ _ _ _ _ _ _ _/   \_ _ _ _ _ _ _ _ _ _
 *		 |		   \   /		   |
 *		 |		    \-/			   |
 *		 v					   v
 *    +---------------------+			+-----------------------+
 *    |	 fcp_offline_child  |			|      fcp_get_cip	|
 *    +---------------------+			|			|
 *						| Creates a dev_info_t	|
 *						| or a mdi_pathinfo_t	|
 *						| depending on whether	|
 *						| mpxio is on or off.	|
 *						+-----------------------+
 *							   |
 *							   |
 *							   v
 *						+-----------------------+
 *						|  fcp_online_child	|
 *						|			|
 *						| Set device online	|
 *						| using NDI or MDI.	|
 *						+-----------------------+
 *
 * ............................................................................
 *
 * STEP 5: The watchdog timer expires.	The watch dog timer does much more that
 *	   what is described here.  We only show the target offline path.
 *
 *
 *			 +--------------------------+
 *			 |	  fcp_watch	    |
 *			 +--------------------------+
 *				       |
 *				       |
 *				       v
 *			 +--------------------------+
 *			 |  fcp_scan_offline_tgts   |
 *			 +--------------------------+
 *				       |
 *				       |
 *				       v
 *			 +--------------------------+
 *			 |  fcp_offline_target_now  |
 *			 +--------------------------+
 *				       |
 *				       |
 *				       v
 *			 +--------------------------+
 *			 |   fcp_offline_tgt_luns   |
 *			 +--------------------------+
 *				       |
 *				       |
 *				       v
 *			 +--------------------------+
 *			 |     fcp_offline_lun	    |
 *			 +--------------------------+
 *				       |
 *				       |
 *				       v
 *		     +----------------------------------+
 *		     |	     fcp_offline_lun_now	|
 *		     |					|
 *		     | A request (or two if mpxio) is	|
 *		     | sent to the hot plug task using	|
 *		     | a fcp_hp_elem structure.		|
 *		     +----------------------------------+
 */

/*
 * Functions registered with DDI framework
 */
static int fcp_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int fcp_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int fcp_open(dev_t *devp, int flag, int otype, cred_t *credp);
static int fcp_close(dev_t dev, int flag, int otype, cred_t *credp);
static int fcp_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);

/*
 * Functions registered with FC Transport framework
 */
static int fcp_port_attach(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    fc_attach_cmd_t cmd,  uint32_t s_id);
static int fcp_port_detach(opaque_t ulph, fc_ulp_port_info_t *info,
    fc_detach_cmd_t cmd);
static int fcp_port_ioctl(opaque_t ulph, opaque_t port_handle, dev_t dev,
    int cmd, intptr_t data, int mode, cred_t *credp, int *rval,
    uint32_t claimed);
static int fcp_els_callback(opaque_t ulph, opaque_t port_handle,
    fc_unsol_buf_t *buf, uint32_t claimed);
static int fcp_data_callback(opaque_t ulph, opaque_t port_handle,
    fc_unsol_buf_t *buf, uint32_t claimed);
static void fcp_statec_callback(opaque_t ulph, opaque_t port_handle,
    uint32_t port_state, uint32_t port_top, fc_portmap_t *devlist,
    uint32_t  dev_cnt, uint32_t port_sid);

/*
 * Functions registered with SCSA framework
 */
static int fcp_phys_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int fcp_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static void fcp_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int fcp_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int fcp_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int fcp_scsi_reset(struct scsi_address *ap, int level);
static int fcp_scsi_getcap(struct scsi_address *ap, char *cap, int whom);
static int fcp_scsi_setcap(struct scsi_address *ap, char *cap, int value,
    int whom);
static void fcp_pkt_teardown(struct scsi_pkt *pkt);
static int fcp_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg);
static int fcp_scsi_bus_get_eventcookie(dev_info_t *dip, dev_info_t *rdip,
    char *name, ddi_eventcookie_t *event_cookiep);
static int fcp_scsi_bus_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void (*callback)(), void *arg,
    ddi_callback_id_t *cb_id);
static int fcp_scsi_bus_remove_eventcall(dev_info_t *devi,
    ddi_callback_id_t cb_id);
static int fcp_scsi_bus_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void *impldata);
static int fcp_scsi_bus_config(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int fcp_scsi_bus_unconfig(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg);

/*
 * Internal functions
 */
static int fcp_setup_device_data_ioctl(int cmd, struct fcp_ioctl *data,
    int mode, int *rval);

static int fcp_setup_scsi_ioctl(struct fcp_scsi_cmd *u_fscsi,
    int mode, int *rval);
static int fcp_copyin_scsi_cmd(caddr_t base_addr,
    struct fcp_scsi_cmd *fscsi, int mode);
static int fcp_copyout_scsi_cmd(struct fcp_scsi_cmd *fscsi,
    caddr_t base_addr, int mode);
static int fcp_send_scsi_ioctl(struct fcp_scsi_cmd *fscsi);

static struct fcp_tgt *fcp_port_create_tgt(struct fcp_port *pptr,
    la_wwn_t *pwwn, int	*ret_val, int *fc_status, int *fc_pkt_state,
    int *fc_pkt_reason, int *fc_pkt_action);
static int fcp_tgt_send_plogi(struct fcp_tgt *ptgt, int *fc_status,
    int *fc_pkt_state, int *fc_pkt_reason, int *fc_pkt_action);
static int fcp_tgt_send_prli(struct fcp_tgt	*ptgt, int *fc_status,
    int *fc_pkt_state, int *fc_pkt_reason, int *fc_pkt_action);
static void fcp_ipkt_sema_init(struct fcp_ipkt *icmd);
static int fcp_ipkt_sema_wait(struct fcp_ipkt *icmd);
static void fcp_ipkt_sema_callback(struct fc_packet *fpkt);
static void fcp_ipkt_sema_cleanup(struct fcp_ipkt *icmd);

static void fcp_handle_devices(struct fcp_port *pptr,
    fc_portmap_t devlist[], uint32_t dev_cnt, int link_cnt,
    fcp_map_tag_t *map_tag, int cause);
static int fcp_handle_mapflags(struct fcp_port *pptr,
    struct fcp_tgt *ptgt, fc_portmap_t *map_entry, int link_cnt,
    int tgt_cnt, int cause);
static int fcp_handle_reportlun_changed(struct fcp_tgt *ptgt, int cause);
static int fcp_send_els(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    struct fcp_ipkt *icmd, uchar_t opcode, int lcount, int tcount, int cause);
static void fcp_update_state(struct fcp_port *pptr, uint32_t state,
    int cause);
static void fcp_update_tgt_state(struct fcp_tgt *ptgt, int flag,
    uint32_t state);
static struct fcp_port *fcp_get_port(opaque_t port_handle);
static void fcp_unsol_callback(fc_packet_t *fpkt);
static void fcp_unsol_resp_init(fc_packet_t *pkt, fc_unsol_buf_t *buf,
    uchar_t r_ctl, uchar_t type);
static int fcp_unsol_prli(struct fcp_port *pptr, fc_unsol_buf_t *buf);
static struct fcp_ipkt *fcp_icmd_alloc(struct fcp_port *pptr,
    struct fcp_tgt *ptgt, int cmd_len, int resp_len, int data_len,
    int nodma, int lcount, int tcount, int cause, uint32_t rscn_count);
static void fcp_icmd_free(struct fcp_port *pptr, struct fcp_ipkt *icmd);
static int fcp_alloc_dma(struct fcp_port *pptr, struct fcp_ipkt *icmd,
    int nodma, int flags);
static void fcp_free_dma(struct fcp_port *pptr, struct fcp_ipkt *icmd);
static struct fcp_tgt *fcp_lookup_target(struct fcp_port *pptr,
    uchar_t *wwn);
static struct fcp_tgt *fcp_get_target_by_did(struct fcp_port *pptr,
    uint32_t d_id);
static void fcp_icmd_callback(fc_packet_t *fpkt);
static int fcp_send_scsi(struct fcp_lun *plun, uchar_t opcode,
    int len, int lcount, int tcount, int cause, uint32_t rscn_count);
static int fcp_check_reportlun(struct fcp_rsp *rsp, fc_packet_t *fpkt);
static void fcp_scsi_callback(fc_packet_t *fpkt);
static void fcp_retry_scsi_cmd(fc_packet_t *fpkt);
static void fcp_handle_inquiry(fc_packet_t *fpkt, struct fcp_ipkt *icmd);
static void fcp_handle_reportlun(fc_packet_t *fpkt, struct fcp_ipkt *icmd);
static struct fcp_lun *fcp_get_lun(struct fcp_tgt *ptgt,
    uint16_t lun_num);
static int fcp_finish_tgt(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int link_cnt, int tgt_cnt, int cause);
static void fcp_finish_init(struct fcp_port *pptr);
static void fcp_create_luns(struct fcp_tgt *ptgt, int link_cnt,
    int tgt_cnt, int cause);
static int fcp_trigger_lun(struct fcp_lun *plun, child_info_t *cip,
    int old_mpxio, int online, int link_cnt, int tgt_cnt, int flags);
static int fcp_offline_target(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int link_cnt, int tgt_cnt, int nowait, int flags);
static void fcp_offline_target_now(struct fcp_port *pptr,
    struct fcp_tgt *ptgt, int link_cnt, int tgt_cnt, int flags);
static void fcp_offline_tgt_luns(struct fcp_tgt *ptgt, int link_cnt,
    int tgt_cnt, int flags);
static void fcp_offline_lun(struct fcp_lun *plun, int link_cnt, int tgt_cnt,
    int nowait, int flags);
static void fcp_prepare_offline_lun(struct fcp_lun *plun, int link_cnt,
    int tgt_cnt);
static void fcp_offline_lun_now(struct fcp_lun *plun, int link_cnt,
    int tgt_cnt, int flags);
static void fcp_scan_offline_luns(struct fcp_port *pptr);
static void fcp_scan_offline_tgts(struct fcp_port *pptr);
static void fcp_update_offline_flags(struct fcp_lun *plun);
static struct fcp_pkt *fcp_scan_commands(struct fcp_lun *plun);
static void fcp_abort_commands(struct fcp_pkt *head, struct
    fcp_port *pptr);
static void fcp_cmd_callback(fc_packet_t *fpkt);
static void fcp_complete_pkt(fc_packet_t *fpkt);
static int fcp_validate_fcp_response(struct fcp_rsp *rsp,
    struct fcp_port *pptr);
static int fcp_device_changed(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    fc_portmap_t *map_entry, int link_cnt, int tgt_cnt, int cause);
static struct fcp_lun *fcp_alloc_lun(struct fcp_tgt *ptgt);
static void fcp_dealloc_lun(struct fcp_lun *plun);
static struct fcp_tgt *fcp_alloc_tgt(struct fcp_port *pptr,
    fc_portmap_t *map_entry, int link_cnt);
static void fcp_dealloc_tgt(struct fcp_tgt *ptgt);
static void fcp_queue_ipkt(struct fcp_port *pptr, fc_packet_t *fpkt);
static int fcp_transport(opaque_t port_handle, fc_packet_t *fpkt,
    int internal);
static void fcp_log(int level, dev_info_t *dip, const char *fmt, ...);
static int fcp_handle_port_attach(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    uint32_t s_id, int instance);
static int fcp_handle_port_detach(struct fcp_port *pptr, int flag,
    int instance);
static void fcp_cleanup_port(struct fcp_port *pptr, int instance);
static int fcp_kmem_cache_constructor(struct scsi_pkt *, scsi_hba_tran_t *,
    int);
static void fcp_kmem_cache_destructor(struct  scsi_pkt *, scsi_hba_tran_t *);
static int fcp_pkt_setup(struct scsi_pkt *, int (*)(), caddr_t);
static int fcp_alloc_cmd_resp(struct fcp_port *pptr, fc_packet_t *fpkt,
    int flags);
static void fcp_free_cmd_resp(struct fcp_port *pptr, fc_packet_t *fpkt);
static int fcp_reset_target(struct scsi_address *ap, int level);
static int fcp_commoncap(struct scsi_address *ap, char *cap,
    int val, int tgtonly, int doset);
static int fcp_scsi_get_name(struct scsi_device *sd, char *name, int len);
static int fcp_scsi_get_bus_addr(struct scsi_device *sd, char *name, int len);
static int fcp_linkreset(struct fcp_port *pptr, struct scsi_address *ap,
    int sleep);
static int fcp_handle_port_resume(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    uint32_t s_id, fc_attach_cmd_t cmd, int instance);
static void fcp_cp_pinfo(struct fcp_port *pptr, fc_ulp_port_info_t *pinfo);
static void fcp_process_elem(struct fcp_hp_elem *elem, int result);
static child_info_t *fcp_get_cip(struct fcp_lun *plun, child_info_t *cip,
    int lcount, int tcount);
static int fcp_is_dip_present(struct fcp_lun *plun, dev_info_t *cdip);
static int fcp_is_child_present(struct fcp_lun *plun, child_info_t *cip);
static dev_info_t *fcp_create_dip(struct fcp_lun *plun, int link_cnt,
    int tgt_cnt);
static dev_info_t *fcp_find_existing_dip(struct fcp_lun *plun,
    dev_info_t *pdip, caddr_t name);
static int fcp_online_child(struct fcp_lun *plun, child_info_t *cip,
    int lcount, int tcount, int flags, int *circ);
static int fcp_offline_child(struct fcp_lun *plun, child_info_t *cip,
    int lcount, int tcount, int flags, int *circ);
static void fcp_remove_child(struct fcp_lun *plun);
static void fcp_watch(void *arg);
static void fcp_check_reset_delay(struct fcp_port *pptr);
static void fcp_abort_all(struct fcp_port *pptr, struct fcp_tgt *ttgt,
    struct fcp_lun *rlun, int tgt_cnt);
struct fcp_port *fcp_soft_state_unlink(struct fcp_port *pptr);
static struct fcp_lun *fcp_lookup_lun(struct fcp_port *pptr,
    uchar_t *wwn, uint16_t lun);
static void fcp_prepare_pkt(struct fcp_port *pptr, struct fcp_pkt *cmd,
    struct fcp_lun *plun);
static void fcp_post_callback(struct fcp_pkt *cmd);
static int fcp_dopoll(struct fcp_port *pptr, struct fcp_pkt *cmd);
static struct fcp_port *fcp_dip2port(dev_info_t *dip);
struct fcp_lun *fcp_get_lun_from_cip(struct fcp_port *pptr,
    child_info_t *cip);
static int fcp_pass_to_hp_and_wait(struct fcp_port *pptr,
    struct fcp_lun *plun, child_info_t *cip, int what, int link_cnt,
    int tgt_cnt, int flags);
static struct fcp_hp_elem *fcp_pass_to_hp(struct fcp_port *pptr,
    struct fcp_lun *plun, child_info_t *cip, int what, int link_cnt,
    int tgt_cnt, int flags, int wait);
static void fcp_retransport_cmd(struct fcp_port *pptr,
    struct fcp_pkt *cmd);
static void fcp_fail_cmd(struct fcp_pkt *cmd, uchar_t reason,
    uint_t statistics);
static void fcp_queue_pkt(struct fcp_port *pptr, struct fcp_pkt *cmd);
static void fcp_update_targets(struct fcp_port *pptr,
    fc_portmap_t *dev_list, uint32_t count, uint32_t state, int cause);
static int fcp_call_finish_init(struct fcp_port *pptr,
    struct fcp_tgt *ptgt, int lcount, int tcount, int cause);
static int fcp_call_finish_init_held(struct fcp_port *pptr,
    struct fcp_tgt *ptgt, int lcount, int tcount, int cause);
static void fcp_reconfigure_luns(void * tgt_handle);
static void fcp_free_targets(struct fcp_port *pptr);
static void fcp_free_target(struct fcp_tgt *ptgt);
static int fcp_is_retryable(struct fcp_ipkt *icmd);
static int fcp_create_on_demand(struct fcp_port *pptr, uchar_t *pwwn);
static void fcp_ascii_to_wwn(caddr_t string, uchar_t bytes[], unsigned int);
static void fcp_wwn_to_ascii(uchar_t bytes[], char *string);
static void fcp_print_error(fc_packet_t *fpkt);
static int fcp_handle_ipkt_errors(struct fcp_port *pptr,
    struct fcp_tgt *ptgt, struct fcp_ipkt *icmd, int rval, caddr_t op);
static int fcp_outstanding_lun_cmds(struct fcp_tgt *ptgt);
static fc_portmap_t *fcp_construct_map(struct fcp_port *pptr,
    uint32_t *dev_cnt);
static void fcp_offline_all(struct fcp_port *pptr, int lcount, int cause);
static int fcp_get_statec_count(struct fcp_ioctl *data, int mode, int *rval);
static int fcp_copyin_fcp_ioctl_data(struct fcp_ioctl *, int, int *,
    struct fcp_ioctl *, struct fcp_port **);
static char *fcp_get_lun_path(struct fcp_lun *plun);
static int fcp_get_target_mappings(struct fcp_ioctl *data, int mode,
    int *rval);
static int fcp_do_ns_registry(struct fcp_port *pptr, uint32_t s_id);
static void fcp_retry_ns_registry(struct fcp_port *pptr, uint32_t s_id);
static char *fcp_get_lun_path(struct fcp_lun *plun);
static int fcp_get_target_mappings(struct fcp_ioctl *data, int mode,
    int *rval);
static void fcp_reconfig_wait(struct fcp_port *pptr);

/*
 * New functions added for mpxio support
 */
static int fcp_virt_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static mdi_pathinfo_t *fcp_create_pip(struct fcp_lun *plun, int lcount,
    int tcount);
static mdi_pathinfo_t *fcp_find_existing_pip(struct fcp_lun *plun,
    dev_info_t *pdip);
static int fcp_is_pip_present(struct fcp_lun *plun, mdi_pathinfo_t *pip);
static void fcp_handle_page83(fc_packet_t *, struct fcp_ipkt *, int);
static void fcp_update_mpxio_path_verifybusy(struct fcp_port *pptr);
static int fcp_copy_guid_2_lun_block(struct fcp_lun *plun, char *guidp);
static int fcp_update_mpxio_path(struct fcp_lun *plun, child_info_t *cip,
    int what);
static int fcp_is_reconfig_needed(struct fcp_tgt *ptgt,
    fc_packet_t *fpkt);
static int fcp_symmetric_device_probe(struct fcp_lun *plun);

/*
 * New functions added for lun masking support
 */
static void fcp_read_blacklist(dev_info_t *dip,
    struct fcp_black_list_entry **pplun_blacklist);
static void fcp_mask_pwwn_lun(char *curr_pwwn, char *curr_lun,
    struct fcp_black_list_entry **pplun_blacklist);
static void fcp_add_one_mask(char *curr_pwwn, uint32_t lun_id,
    struct fcp_black_list_entry **pplun_blacklist);
static int fcp_should_mask(la_wwn_t *wwn, uint32_t lun_id);
static void fcp_cleanup_blacklist(struct fcp_black_list_entry **lun_blacklist);

/*
 * New functions to support software FCA (like fcoei)
 */
static struct scsi_pkt *fcp_pseudo_init_pkt(
	struct scsi_address *ap, struct scsi_pkt *pkt,
	struct buf *bp, int cmdlen, int statuslen,
	int tgtlen, int flags, int (*callback)(), caddr_t arg);
static void fcp_pseudo_destroy_pkt(
	struct scsi_address *ap, struct scsi_pkt *pkt);
static void fcp_pseudo_sync_pkt(
	struct scsi_address *ap, struct scsi_pkt *pkt);
static int fcp_pseudo_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static void fcp_pseudo_dmafree(
	struct scsi_address *ap, struct scsi_pkt *pkt);

extern struct mod_ops	mod_driverops;
/*
 * This variable is defined in modctl.c and set to '1' after the root driver
 * and fs are loaded.  It serves as an indication that the root filesystem can
 * be used.
 */
extern int		modrootloaded;
/*
 * This table contains strings associated with the SCSI sense key codes.  It
 * is used by FCP to print a clear explanation of the code returned in the
 * sense information by a device.
 */
extern char		*sense_keys[];
/*
 * This device is created by the SCSI pseudo nexus driver (SCSI vHCI).	It is
 * under this device that the paths to a physical device are created when
 * MPxIO is used.
 */
extern dev_info_t	*scsi_vhci_dip;

/*
 * Report lun processing
 */
#define	FCP_LUN_ADDRESSING		0x80
#define	FCP_PD_ADDRESSING		0x00
#define	FCP_VOLUME_ADDRESSING		0x40

#define	FCP_SVE_THROTTLE		0x28 /* Vicom */
#define	MAX_INT_DMA			0x7fffffff
/*
 * Property definitions
 */
#define	NODE_WWN_PROP	(char *)fcp_node_wwn_prop
#define	PORT_WWN_PROP	(char *)fcp_port_wwn_prop
#define	TARGET_PROP	(char *)fcp_target_prop
#define	LUN_PROP	(char *)fcp_lun_prop
#define	SAM_LUN_PROP	(char *)fcp_sam_lun_prop
#define	CONF_WWN_PROP	(char *)fcp_conf_wwn_prop
#define	OBP_BOOT_WWN	(char *)fcp_obp_boot_wwn
#define	MANUAL_CFG_ONLY	(char *)fcp_manual_config_only
#define	INIT_PORT_PROP	(char *)fcp_init_port_prop
#define	TGT_PORT_PROP	(char *)fcp_tgt_port_prop
#define	LUN_BLACKLIST_PROP	(char *)fcp_lun_blacklist_prop
/*
 * Short hand macros.
 */
#define	LUN_PORT	(plun->lun_tgt->tgt_port)
#define	LUN_TGT		(plun->lun_tgt)

/*
 * Driver private macros
 */
#define	FCP_ATOB(x)	(((x) >= '0' && (x) <= '9') ? ((x) - '0') :	\
			((x) >= 'a' && (x) <= 'f') ?			\
			((x) - 'a' + 10) : ((x) - 'A' + 10))

#define	FCP_MAX(a, b)	((a) > (b) ? (a) : (b))

#define	FCP_N_NDI_EVENTS						\
	(sizeof (fcp_ndi_event_defs) / sizeof (ndi_event_definition_t))

#define	FCP_LINK_STATE_CHANGED(p, c)			\
	((p)->port_link_cnt != (c)->ipkt_link_cnt)

#define	FCP_TGT_STATE_CHANGED(t, c)			\
	((t)->tgt_change_cnt != (c)->ipkt_change_cnt)

#define	FCP_STATE_CHANGED(p, t, c)		\
	(FCP_TGT_STATE_CHANGED(t, c))

#define	FCP_MUST_RETRY(fpkt)				\
	((fpkt)->pkt_state == FC_PKT_LOCAL_BSY ||	\
	(fpkt)->pkt_state == FC_PKT_LOCAL_RJT ||	\
	(fpkt)->pkt_state == FC_PKT_TRAN_BSY ||	\
	(fpkt)->pkt_state == FC_PKT_ELS_IN_PROGRESS ||	\
	(fpkt)->pkt_state == FC_PKT_NPORT_BSY ||	\
	(fpkt)->pkt_state == FC_PKT_FABRIC_BSY ||	\
	(fpkt)->pkt_state == FC_PKT_PORT_OFFLINE ||	\
	(fpkt)->pkt_reason == FC_REASON_OFFLINE)

#define	FCP_SENSE_REPORTLUN_CHANGED(es)		\
	((es)->es_key == KEY_UNIT_ATTENTION &&	\
	(es)->es_add_code == 0x3f &&		\
	(es)->es_qual_code == 0x0e)

#define	FCP_SENSE_NO_LUN(es)			\
	((es)->es_key == KEY_ILLEGAL_REQUEST &&	\
	(es)->es_add_code == 0x25 &&		\
	(es)->es_qual_code == 0x0)

#define	FCP_VERSION		"20091208-1.192"
#define	FCP_NAME_VERSION	"SunFC FCP v" FCP_VERSION

#define	FCP_NUM_ELEMENTS(array)			\
	(sizeof (array) / sizeof ((array)[0]))

/*
 * Debugging, Error reporting, and tracing
 */
#define	FCP_LOG_SIZE		1024 * 1024

#define	FCP_LEVEL_1		0x00001		/* attach/detach PM CPR */
#define	FCP_LEVEL_2		0x00002		/* failures/Invalid data */
#define	FCP_LEVEL_3		0x00004		/* state change, discovery */
#define	FCP_LEVEL_4		0x00008		/* ULP messages */
#define	FCP_LEVEL_5		0x00010		/* ELS/SCSI cmds */
#define	FCP_LEVEL_6		0x00020		/* Transport failures */
#define	FCP_LEVEL_7		0x00040
#define	FCP_LEVEL_8		0x00080		/* I/O tracing */
#define	FCP_LEVEL_9		0x00100		/* I/O tracing */



/*
 * Log contents to system messages file
 */
#define	FCP_MSG_LEVEL_1	(FCP_LEVEL_1 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_2	(FCP_LEVEL_2 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_3	(FCP_LEVEL_3 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_4	(FCP_LEVEL_4 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_5	(FCP_LEVEL_5 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_6	(FCP_LEVEL_6 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_7	(FCP_LEVEL_7 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_8	(FCP_LEVEL_8 | FC_TRACE_LOG_MSG)
#define	FCP_MSG_LEVEL_9	(FCP_LEVEL_9 | FC_TRACE_LOG_MSG)


/*
 * Log contents to trace buffer
 */
#define	FCP_BUF_LEVEL_1	(FCP_LEVEL_1 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_2	(FCP_LEVEL_2 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_3	(FCP_LEVEL_3 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_4	(FCP_LEVEL_4 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_5	(FCP_LEVEL_5 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_6	(FCP_LEVEL_6 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_7	(FCP_LEVEL_7 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_8	(FCP_LEVEL_8 | FC_TRACE_LOG_BUF)
#define	FCP_BUF_LEVEL_9	(FCP_LEVEL_9 | FC_TRACE_LOG_BUF)


/*
 * Log contents to both system messages file and trace buffer
 */
#define	FCP_MSG_BUF_LEVEL_1	(FCP_LEVEL_1 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_2	(FCP_LEVEL_2 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_3	(FCP_LEVEL_3 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_4	(FCP_LEVEL_4 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_5	(FCP_LEVEL_5 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_6	(FCP_LEVEL_6 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_7	(FCP_LEVEL_7 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_8	(FCP_LEVEL_8 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#define	FCP_MSG_BUF_LEVEL_9	(FCP_LEVEL_9 | FC_TRACE_LOG_BUF |	\
				FC_TRACE_LOG_MSG)
#ifdef DEBUG
#define	FCP_DTRACE	fc_trace_debug
#else
#define	FCP_DTRACE
#endif

#define	FCP_TRACE	fc_trace_debug

static struct cb_ops fcp_cb_ops = {
	fcp_open,			/* open */
	fcp_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	fcp_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};


static struct dev_ops fcp_ops = {
	DEVO_REV,
	0,
	ddi_getinfo_1to1,
	nulldev,		/* identify */
	nulldev,		/* probe */
	fcp_attach,		/* attach and detach are mandatory */
	fcp_detach,
	nodev,			/* reset */
	&fcp_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
};


char *fcp_version = FCP_NAME_VERSION;

static struct modldrv modldrv = {
	&mod_driverops,
	FCP_NAME_VERSION,
	&fcp_ops
};


static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


static fc_ulp_modinfo_t fcp_modinfo = {
	&fcp_modinfo,			/* ulp_handle */
	FCTL_ULP_MODREV_4,		/* ulp_rev */
	FC4_SCSI_FCP,			/* ulp_type */
	"fcp",				/* ulp_name */
	FCP_STATEC_MASK,		/* ulp_statec_mask */
	fcp_port_attach,		/* ulp_port_attach */
	fcp_port_detach,		/* ulp_port_detach */
	fcp_port_ioctl,			/* ulp_port_ioctl */
	fcp_els_callback,		/* ulp_els_callback */
	fcp_data_callback,		/* ulp_data_callback */
	fcp_statec_callback		/* ulp_statec_callback */
};

#ifdef	DEBUG
#define	FCP_TRACE_DEFAULT	(FC_TRACE_LOG_MASK | FCP_LEVEL_1 |	\
				FCP_LEVEL_2 | FCP_LEVEL_3 |		\
				FCP_LEVEL_4 | FCP_LEVEL_5 |		\
				FCP_LEVEL_6 | FCP_LEVEL_7)
#else
#define	FCP_TRACE_DEFAULT	(FC_TRACE_LOG_MASK | FCP_LEVEL_1 |	\
				FCP_LEVEL_2 | FCP_LEVEL_3 |		\
				FCP_LEVEL_4 | FCP_LEVEL_5 |		\
				FCP_LEVEL_6 | FCP_LEVEL_7)
#endif

/* FCP global variables */
int			fcp_bus_config_debug = 0;
static int		fcp_log_size = FCP_LOG_SIZE;
static int		fcp_trace = FCP_TRACE_DEFAULT;
static fc_trace_logq_t	*fcp_logq = NULL;
static struct fcp_black_list_entry	*fcp_lun_blacklist = NULL;
/*
 * The auto-configuration is set by default.  The only way of disabling it is
 * through the property MANUAL_CFG_ONLY in the fcp.conf file.
 */
static int		fcp_enable_auto_configuration = 1;
static int		fcp_max_bus_config_retries	= 4;
static int		fcp_lun_ready_retry = 300;
/*
 * The value assigned to the following variable has changed several times due
 * to a problem with the data underruns reporting of some firmware(s).	The
 * current value of 50 gives a timeout value of 25 seconds for a max number
 * of 256 LUNs.
 */
static int		fcp_max_target_retries = 50;
/*
 * Watchdog variables
 * ------------------
 *
 * fcp_watchdog_init
 *
 *	Indicates if the watchdog timer is running or not.  This is actually
 *	a counter of the number of Fibre Channel ports that attached.  When
 *	the first port attaches the watchdog is started.  When the last port
 *	detaches the watchdog timer is stopped.
 *
 * fcp_watchdog_time
 *
 *	This is the watchdog clock counter.  It is incremented by
 *	fcp_watchdog_time each time the watchdog timer expires.
 *
 * fcp_watchdog_timeout
 *
 *	Increment value of the variable fcp_watchdog_time as well as the
 *	the timeout value of the watchdog timer.  The unit is 1 second.	 It
 *	is strange that this is not a #define	but a variable since the code
 *	never changes this value.  The reason why it can be said that the
 *	unit is 1 second is because the number of ticks for the watchdog
 *	timer is determined like this:
 *
 *	    fcp_watchdog_tick = fcp_watchdog_timeout *
 *				  drv_usectohz(1000000);
 *
 *	The value 1000000 is hard coded in the code.
 *
 * fcp_watchdog_tick
 *
 *	Watchdog timer value in ticks.
 */
static int		fcp_watchdog_init = 0;
static int		fcp_watchdog_time = 0;
static int		fcp_watchdog_timeout = 1;
static int		fcp_watchdog_tick;

/*
 * fcp_offline_delay is a global variable to enable customisation of
 * the timeout on link offlines or RSCNs. The default value is set
 * to match FCP_OFFLINE_DELAY (20sec), which is 2*RA_TOV_els as
 * specified in FCP4 Chapter 11 (see www.t10.org).
 *
 * The variable fcp_offline_delay is specified in SECONDS.
 *
 * If we made this a static var then the user would not be able to
 * change it. This variable is set in fcp_attach().
 */
unsigned int		fcp_offline_delay = FCP_OFFLINE_DELAY;

static void		*fcp_softstate = NULL; /* for soft state */
static uchar_t		fcp_oflag = FCP_IDLE; /* open flag */
static kmutex_t		fcp_global_mutex;
static kmutex_t		fcp_ioctl_mutex;
static dev_info_t	*fcp_global_dip = NULL;
static timeout_id_t	fcp_watchdog_id;
const char		*fcp_lun_prop = "lun";
const char		*fcp_sam_lun_prop = "sam-lun";
const char		*fcp_target_prop = "target";
/*
 * NOTE: consumers of "node-wwn" property include stmsboot in ON
 * consolidation.
 */
const char		*fcp_node_wwn_prop = "node-wwn";
const char		*fcp_port_wwn_prop = "port-wwn";
const char		*fcp_conf_wwn_prop = "fc-port-wwn";
const char		*fcp_obp_boot_wwn = "fc-boot-dev-portwwn";
const char		*fcp_manual_config_only = "manual_configuration_only";
const char		*fcp_init_port_prop = "initiator-port";
const char		*fcp_tgt_port_prop = "target-port";
const char		*fcp_lun_blacklist_prop = "pwwn-lun-blacklist";

static struct fcp_port	*fcp_port_head = NULL;
static ddi_eventcookie_t	fcp_insert_eid;
static ddi_eventcookie_t	fcp_remove_eid;

static ndi_event_definition_t	fcp_ndi_event_defs[] = {
	{ FCP_EVENT_TAG_INSERT, FCAL_INSERT_EVENT, EPL_KERNEL },
	{ FCP_EVENT_TAG_REMOVE, FCAL_REMOVE_EVENT, EPL_INTERRUPT }
};

/*
 * List of valid commands for the scsi_ioctl call
 */
static uint8_t scsi_ioctl_list[] = {
	SCMD_INQUIRY,
	SCMD_REPORT_LUN,
	SCMD_READ_CAPACITY
};

/*
 * this is used to dummy up a report lun response for cases
 * where the target doesn't support it
 */
static uchar_t fcp_dummy_lun[] = {
	0x00,		/* MSB length (length = no of luns * 8) */
	0x00,
	0x00,
	0x08,		/* LSB length */
	0x00,		/* MSB reserved */
	0x00,
	0x00,
	0x00,		/* LSB reserved */
	FCP_PD_ADDRESSING,
	0x00,		/* LUN is ZERO at the first level */
	0x00,
	0x00,		/* second level is zero */
	0x00,
	0x00,		/* third level is zero */
	0x00,
	0x00		/* fourth level is zero */
};

static uchar_t fcp_alpa_to_switch[] = {
	0x00, 0x7d, 0x7c, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x7a, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x78, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x77, 0x76, 0x00, 0x00, 0x75, 0x00, 0x74,
	0x73, 0x72, 0x00, 0x00, 0x00, 0x71, 0x00, 0x70, 0x6f, 0x6e,
	0x00, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x00, 0x00, 0x67,
	0x66, 0x65, 0x64, 0x63, 0x62, 0x00, 0x00, 0x61, 0x60, 0x00,
	0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x5d,
	0x5c, 0x5b, 0x00, 0x5a, 0x59, 0x58, 0x57, 0x56, 0x55, 0x00,
	0x00, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4f, 0x00, 0x00, 0x4e,
	0x4d, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4b,
	0x00, 0x4a, 0x49, 0x48, 0x00, 0x47, 0x46, 0x45, 0x44, 0x43,
	0x42, 0x00, 0x00, 0x41, 0x40, 0x3f, 0x3e, 0x3d, 0x3c, 0x00,
	0x00, 0x3b, 0x3a, 0x00, 0x39, 0x00, 0x00, 0x00, 0x38, 0x37,
	0x36, 0x00, 0x35, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x33, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x31, 0x30, 0x00, 0x00, 0x2f, 0x00, 0x2e, 0x2d, 0x2c,
	0x00, 0x00, 0x00, 0x2b, 0x00, 0x2a, 0x29, 0x28, 0x00, 0x27,
	0x26, 0x25, 0x24, 0x23, 0x22, 0x00, 0x00, 0x21, 0x20, 0x1f,
	0x1e, 0x1d, 0x1c, 0x00, 0x00, 0x1b, 0x1a, 0x00, 0x19, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x17, 0x16, 0x15,
	0x00, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x00, 0x00, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x00, 0x00, 0x08, 0x07, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x05, 0x04, 0x03, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static caddr_t pid = "SESS01	      ";

#if	!defined(lint)

_NOTE(MUTEX_PROTECTS_DATA(fcp_global_mutex,
    fcp_port::fcp_next fcp_watchdog_id))

_NOTE(DATA_READABLE_WITHOUT_LOCK(fcp_watchdog_time))

_NOTE(SCHEME_PROTECTS_DATA("Unshared",
    fcp_insert_eid
    fcp_remove_eid
    fcp_watchdog_time))

_NOTE(SCHEME_PROTECTS_DATA("Unshared",
    fcp_cb_ops
    fcp_ops
    callb_cpr))

#endif /* lint */

/*
 * This table is used to determine whether or not it's safe to copy in
 * the target node name for a lun.  Since all luns behind the same target
 * have the same wwnn, only tagets that do not support multiple luns are
 * eligible to be enumerated under mpxio if they aren't page83 compliant.
 */

char *fcp_symmetric_disk_table[] = {
	"SEAGATE ST",
	"IBM	 DDYFT",
	"SUNW	 SUNWGS",	/* Daktari enclosure */
	"SUN	 SENA",		/* SES device */
	"SUN	 SESS01"	/* VICOM SVE box */
};

int fcp_symmetric_disk_table_size =
	sizeof (fcp_symmetric_disk_table)/sizeof (char *);

/*
 * This structure is bogus. scsi_hba_attach_setup() requires, as in the kernel
 * will panic if you don't pass this in to the routine, this information.
 * Need to determine what the actual impact to the system is by providing
 * this information if any. Since dma allocation is done in pkt_init it may
 * not have any impact. These values are straight from the Writing Device
 * Driver manual.
 */
static ddi_dma_attr_t pseudo_fca_dma_attr = {
	DMA_ATTR_V0,	/* ddi_dma_attr version */
	0,		/* low address */
	0xffffffff,	/* high address */
	0x00ffffff,	/* counter upper bound */
	1,		/* alignment requirements */
	0x3f,		/* burst sizes */
	1,		/* minimum DMA access */
	0xffffffff,	/* maximum DMA access */
	(1 << 24) - 1,	/* segment boundary restrictions */
	1,		/* scater/gather list length */
	512,		/* device granularity */
	0		/* DMA flags */
};

/*
 * The _init(9e) return value should be that of mod_install(9f). Under
 * some circumstances, a failure may not be related mod_install(9f) and
 * one would then require a return value to indicate the failure. Looking
 * at mod_install(9f), it is expected to return 0 for success and non-zero
 * for failure. mod_install(9f) for device drivers, further goes down the
 * calling chain and ends up in ddi_installdrv(), whose return values are
 * DDI_SUCCESS and DDI_FAILURE - There are also other functions in the
 * calling chain of mod_install(9f) which return values like EINVAL and
 * in some even return -1.
 *
 * To work around the vagaries of the mod_install() calling chain, return
 * either 0 or ENODEV depending on the success or failure of mod_install()
 */
int
_init(void)
{
	int rval;

	/*
	 * Allocate soft state and prepare to do ddi_soft_state_zalloc()
	 * before registering with the transport first.
	 */
	if (ddi_soft_state_init(&fcp_softstate,
	    sizeof (struct fcp_port), FCP_INIT_ITEMS) != 0) {
		return (EINVAL);
	}

	mutex_init(&fcp_global_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&fcp_ioctl_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((rval = fc_ulp_add(&fcp_modinfo)) != FC_SUCCESS) {
		cmn_err(CE_WARN, "fcp: fc_ulp_add failed");
		mutex_destroy(&fcp_global_mutex);
		mutex_destroy(&fcp_ioctl_mutex);
		ddi_soft_state_fini(&fcp_softstate);
		return (ENODEV);
	}

	fcp_logq = fc_trace_alloc_logq(fcp_log_size);

	if ((rval = mod_install(&modlinkage)) != 0) {
		fc_trace_free_logq(fcp_logq);
		(void) fc_ulp_remove(&fcp_modinfo);
		mutex_destroy(&fcp_global_mutex);
		mutex_destroy(&fcp_ioctl_mutex);
		ddi_soft_state_fini(&fcp_softstate);
		rval = ENODEV;
	}

	return (rval);
}


/*
 * the system is done with us as a driver, so clean up
 */
int
_fini(void)
{
	int rval;

	/*
	 * don't start cleaning up until we know that the module remove
	 * has worked  -- if this works, then we know that each instance
	 * has successfully been DDI_DETACHed
	 */
	if ((rval = mod_remove(&modlinkage)) != 0) {
		return (rval);
	}

	(void) fc_ulp_remove(&fcp_modinfo);

	ddi_soft_state_fini(&fcp_softstate);
	mutex_destroy(&fcp_global_mutex);
	mutex_destroy(&fcp_ioctl_mutex);
	fc_trace_free_logq(fcp_logq);

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * attach the module
 */
static int
fcp_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int rval = DDI_SUCCESS;

	FCP_DTRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_8, 0, "fcp module attach: cmd=0x%x", cmd);

	if (cmd == DDI_ATTACH) {
		/* The FCP pseudo device is created here. */
		mutex_enter(&fcp_global_mutex);
		fcp_global_dip = devi;
		mutex_exit(&fcp_global_mutex);

		if (ddi_create_minor_node(fcp_global_dip, "fcp", S_IFCHR,
		    0, DDI_PSEUDO, 0) == DDI_SUCCESS) {
			ddi_report_dev(fcp_global_dip);
		} else {
			cmn_err(CE_WARN, "FCP: Cannot create minor node");
			mutex_enter(&fcp_global_mutex);
			fcp_global_dip = NULL;
			mutex_exit(&fcp_global_mutex);

			rval = DDI_FAILURE;
		}
		/*
		 * We check the fcp_offline_delay property at this
		 * point. This variable is global for the driver,
		 * not specific to an instance.
		 *
		 * We do not recommend setting the value to less
		 * than 10 seconds (RA_TOV_els), or greater than
		 * 60 seconds.
		 */
		fcp_offline_delay = ddi_prop_get_int(DDI_DEV_T_ANY,
		    devi, DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "fcp_offline_delay", FCP_OFFLINE_DELAY);
		if ((fcp_offline_delay < 10) ||
		    (fcp_offline_delay > 60)) {
			cmn_err(CE_WARN, "Setting fcp_offline_delay "
			    "to %d second(s). This is outside the "
			    "recommended range of 10..60 seconds.",
			    fcp_offline_delay);
		}
	}

	return (rval);
}


/*ARGSUSED*/
static int
fcp_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int	res = DDI_SUCCESS;

	FCP_DTRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_8, 0,	 "module detach: cmd=0x%x", cmd);

	if (cmd == DDI_DETACH) {
		/*
		 * Check if there are active ports/threads. If there
		 * are any, we will fail, else we will succeed (there
		 * should not be much to clean up)
		 */
		mutex_enter(&fcp_global_mutex);
		FCP_DTRACE(fcp_logq, "fcp",
		    fcp_trace, FCP_BUF_LEVEL_8, 0,  "port_head=%p",
		    (void *) fcp_port_head);

		if (fcp_port_head == NULL) {
			ddi_remove_minor_node(fcp_global_dip, NULL);
			fcp_global_dip = NULL;
			mutex_exit(&fcp_global_mutex);
		} else {
			mutex_exit(&fcp_global_mutex);
			res = DDI_FAILURE;
		}
	}
	FCP_DTRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_8, 0,	 "module detach returning %d", res);

	return (res);
}


/* ARGSUSED */
static int
fcp_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Allow only root to talk;
	 */
	if (drv_priv(credp)) {
		return (EPERM);
	}

	mutex_enter(&fcp_global_mutex);
	if (fcp_oflag & FCP_EXCL) {
		mutex_exit(&fcp_global_mutex);
		return (EBUSY);
	}

	if (flag & FEXCL) {
		if (fcp_oflag & FCP_OPEN) {
			mutex_exit(&fcp_global_mutex);
			return (EBUSY);
		}
		fcp_oflag |= FCP_EXCL;
	}
	fcp_oflag |= FCP_OPEN;
	mutex_exit(&fcp_global_mutex);

	return (0);
}


/* ARGSUSED */
static int
fcp_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&fcp_global_mutex);
	if (!(fcp_oflag & FCP_OPEN)) {
		mutex_exit(&fcp_global_mutex);
		return (ENODEV);
	}
	fcp_oflag = FCP_IDLE;
	mutex_exit(&fcp_global_mutex);

	return (0);
}


/*
 * fcp_ioctl
 *	Entry point for the FCP ioctls
 *
 * Input:
 *	See ioctl(9E)
 *
 * Output:
 *	See ioctl(9E)
 *
 * Returns:
 *	See ioctl(9E)
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
fcp_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rval)
{
	int			ret = 0;

	mutex_enter(&fcp_global_mutex);
	if (!(fcp_oflag & FCP_OPEN)) {
		mutex_exit(&fcp_global_mutex);
		return (ENXIO);
	}
	mutex_exit(&fcp_global_mutex);

	switch (cmd) {
	case FCP_TGT_INQUIRY:
	case FCP_TGT_CREATE:
	case FCP_TGT_DELETE:
		ret = fcp_setup_device_data_ioctl(cmd,
		    (struct fcp_ioctl *)data, mode, rval);
		break;

	case FCP_TGT_SEND_SCSI:
		mutex_enter(&fcp_ioctl_mutex);
		ret = fcp_setup_scsi_ioctl(
		    (struct fcp_scsi_cmd *)data, mode, rval);
		mutex_exit(&fcp_ioctl_mutex);
		break;

	case FCP_STATE_COUNT:
		ret = fcp_get_statec_count((struct fcp_ioctl *)data,
		    mode, rval);
		break;
	case FCP_GET_TARGET_MAPPINGS:
		ret = fcp_get_target_mappings((struct fcp_ioctl *)data,
		    mode, rval);
		break;
	default:
		fcp_log(CE_WARN, NULL,
		    "!Invalid ioctl opcode = 0x%x", cmd);
		ret	= EINVAL;
	}

	return (ret);
}


/*
 * fcp_setup_device_data_ioctl
 *	Setup handler for the "device data" style of
 *	ioctl for FCP.	See "fcp_util.h" for data structure
 *	definition.
 *
 * Input:
 *	cmd	= FCP ioctl command
 *	data	= ioctl data
 *	mode	= See ioctl(9E)
 *
 * Output:
 *	data	= ioctl data
 *	rval	= return value - see ioctl(9E)
 *
 * Returns:
 *	See ioctl(9E)
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
fcp_setup_device_data_ioctl(int cmd, struct fcp_ioctl *data, int mode,
    int *rval)
{
	struct fcp_port	*pptr;
	struct	device_data	*dev_data;
	uint32_t		link_cnt;
	la_wwn_t		*wwn_ptr = NULL;
	struct fcp_tgt		*ptgt = NULL;
	struct fcp_lun		*plun = NULL;
	int			i, error;
	struct fcp_ioctl	fioctl;

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcp32_ioctl f32_ioctl;

		if (ddi_copyin((void *)data, (void *)&f32_ioctl,
		    sizeof (struct fcp32_ioctl), mode)) {
			return (EFAULT);
		}
		fioctl.fp_minor = f32_ioctl.fp_minor;
		fioctl.listlen = f32_ioctl.listlen;
		fioctl.list = (caddr_t)(long)f32_ioctl.list;
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)data, (void *)&fioctl,
		    sizeof (struct fcp_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}

#else	/* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)data, (void *)&fioctl,
	    sizeof (struct fcp_ioctl), mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	/*
	 * Right now we can assume that the minor number matches with
	 * this instance of fp. If this changes we will need to
	 * revisit this logic.
	 */
	mutex_enter(&fcp_global_mutex);
	pptr = fcp_port_head;
	while (pptr) {
		if (pptr->port_instance == (uint32_t)fioctl.fp_minor) {
			break;
		} else {
			pptr = pptr->port_next;
		}
	}
	mutex_exit(&fcp_global_mutex);
	if (pptr == NULL) {
		return (ENXIO);
	}
	mutex_enter(&pptr->port_mutex);


	if ((dev_data = kmem_zalloc((sizeof (struct device_data)) *
	    fioctl.listlen, KM_NOSLEEP)) == NULL) {
		mutex_exit(&pptr->port_mutex);
		return (ENOMEM);
	}

	if (ddi_copyin(fioctl.list, dev_data,
	    (sizeof (struct device_data)) * fioctl.listlen, mode)) {
		kmem_free(dev_data, sizeof (*dev_data) * fioctl.listlen);
		mutex_exit(&pptr->port_mutex);
		return (EFAULT);
	}
	link_cnt = pptr->port_link_cnt;

	if (cmd == FCP_TGT_INQUIRY) {
		wwn_ptr = (la_wwn_t *)&(dev_data[0].dev_pwwn);
		if (bcmp(wwn_ptr->raw_wwn, pptr->port_pwwn.raw_wwn,
		    sizeof (wwn_ptr->raw_wwn)) == 0) {
			/* This ioctl is requesting INQ info of local HBA */
			mutex_exit(&pptr->port_mutex);
			dev_data[0].dev0_type = DTYPE_UNKNOWN;
			dev_data[0].dev_status = 0;
			if (ddi_copyout(dev_data, fioctl.list,
			    (sizeof (struct device_data)) * fioctl.listlen,
			    mode)) {
				kmem_free(dev_data,
				    sizeof (*dev_data) * fioctl.listlen);
				return (EFAULT);
			}
			kmem_free(dev_data,
			    sizeof (*dev_data) * fioctl.listlen);
#ifdef	_MULTI_DATAMODEL
			switch (ddi_model_convert_from(mode & FMODELS)) {
			case DDI_MODEL_ILP32: {
				struct fcp32_ioctl f32_ioctl;
				f32_ioctl.fp_minor = fioctl.fp_minor;
				f32_ioctl.listlen = fioctl.listlen;
				f32_ioctl.list = (caddr32_t)(long)fioctl.list;
				if (ddi_copyout((void *)&f32_ioctl,
				    (void *)data,
				    sizeof (struct fcp32_ioctl), mode)) {
					return (EFAULT);
				}
				break;
			}
			case DDI_MODEL_NONE:
				if (ddi_copyout((void *)&fioctl, (void *)data,
				    sizeof (struct fcp_ioctl), mode)) {
					return (EFAULT);
				}
				break;
			}
#else	/* _MULTI_DATAMODEL */
			if (ddi_copyout((void *)&fioctl, (void *)data,
			    sizeof (struct fcp_ioctl), mode)) {
				return (EFAULT);
			}
#endif	/* _MULTI_DATAMODEL */
			return (0);
		}
	}

	if (pptr->port_state & (FCP_STATE_INIT | FCP_STATE_OFFLINE)) {
		kmem_free(dev_data, sizeof (*dev_data) * fioctl.listlen);
		mutex_exit(&pptr->port_mutex);
		return (ENXIO);
	}

	for (i = 0; (i < fioctl.listlen) && (link_cnt == pptr->port_link_cnt);
	    i++) {
		wwn_ptr = (la_wwn_t *)&(dev_data[i].dev_pwwn);

		dev_data[i].dev0_type = DTYPE_UNKNOWN;


		dev_data[i].dev_status = ENXIO;

		if ((ptgt = fcp_lookup_target(pptr,
		    (uchar_t *)wwn_ptr)) == NULL) {
			mutex_exit(&pptr->port_mutex);
			if (fc_ulp_get_remote_port(pptr->port_fp_handle,
			    wwn_ptr, &error, 0) == NULL) {
				dev_data[i].dev_status = ENODEV;
				mutex_enter(&pptr->port_mutex);
				continue;
			} else {

				dev_data[i].dev_status = EAGAIN;

				mutex_enter(&pptr->port_mutex);
				continue;
			}
		} else {
			mutex_enter(&ptgt->tgt_mutex);
			if (ptgt->tgt_state & (FCP_TGT_MARK |
			    FCP_TGT_BUSY)) {
				dev_data[i].dev_status = EAGAIN;
				mutex_exit(&ptgt->tgt_mutex);
				continue;
			}

			if (ptgt->tgt_state & FCP_TGT_OFFLINE) {
				if (ptgt->tgt_icap && !ptgt->tgt_tcap) {
					dev_data[i].dev_status = ENOTSUP;
				} else {
					dev_data[i].dev_status = ENXIO;
				}
				mutex_exit(&ptgt->tgt_mutex);
				continue;
			}

			switch (cmd) {
			case FCP_TGT_INQUIRY:
				/*
				 * The reason we give device type of
				 * lun 0 only even though in some
				 * cases(like maxstrat) lun 0 device
				 * type may be 0x3f(invalid) is that
				 * for bridge boxes target will appear
				 * as luns and the first lun could be
				 * a device that utility may not care
				 * about (like a tape device).
				 */
				dev_data[i].dev_lun_cnt = ptgt->tgt_lun_cnt;
				dev_data[i].dev_status = 0;
				mutex_exit(&ptgt->tgt_mutex);

				if ((plun = fcp_get_lun(ptgt, 0)) == NULL) {
					dev_data[i].dev0_type = DTYPE_UNKNOWN;
				} else {
					dev_data[i].dev0_type = plun->lun_type;
				}
				mutex_enter(&ptgt->tgt_mutex);
				break;

			case FCP_TGT_CREATE:
				mutex_exit(&ptgt->tgt_mutex);
				mutex_exit(&pptr->port_mutex);

				/*
				 * serialize state change call backs.
				 * only one call back will be handled
				 * at a time.
				 */
				mutex_enter(&fcp_global_mutex);
				if (fcp_oflag & FCP_BUSY) {
					mutex_exit(&fcp_global_mutex);
					if (dev_data) {
						kmem_free(dev_data,
						    sizeof (*dev_data) *
						    fioctl.listlen);
					}
					return (EBUSY);
				}
				fcp_oflag |= FCP_BUSY;
				mutex_exit(&fcp_global_mutex);

				dev_data[i].dev_status =
				    fcp_create_on_demand(pptr,
				    wwn_ptr->raw_wwn);

				if (dev_data[i].dev_status != 0) {
					char	buf[25];

					for (i = 0; i < FC_WWN_SIZE; i++) {
						(void) sprintf(&buf[i << 1],
						    "%02x",
						    wwn_ptr->raw_wwn[i]);
					}

					fcp_log(CE_WARN, pptr->port_dip,
					    "!Failed to create nodes for"
					    " pwwn=%s; error=%x", buf,
					    dev_data[i].dev_status);
				}

				/* allow state change call backs again */
				mutex_enter(&fcp_global_mutex);
				fcp_oflag &= ~FCP_BUSY;
				mutex_exit(&fcp_global_mutex);

				mutex_enter(&pptr->port_mutex);
				mutex_enter(&ptgt->tgt_mutex);

				break;

			case FCP_TGT_DELETE:
				break;

			default:
				fcp_log(CE_WARN, pptr->port_dip,
				    "!Invalid device data ioctl "
				    "opcode = 0x%x", cmd);
			}
			mutex_exit(&ptgt->tgt_mutex);
		}
	}
	mutex_exit(&pptr->port_mutex);

	if (ddi_copyout(dev_data, fioctl.list,
	    (sizeof (struct device_data)) * fioctl.listlen, mode)) {
		kmem_free(dev_data, sizeof (*dev_data) * fioctl.listlen);
		return (EFAULT);
	}
	kmem_free(dev_data, sizeof (*dev_data) * fioctl.listlen);

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcp32_ioctl f32_ioctl;

		f32_ioctl.fp_minor = fioctl.fp_minor;
		f32_ioctl.listlen = fioctl.listlen;
		f32_ioctl.list = (caddr32_t)(long)fioctl.list;
		if (ddi_copyout((void *)&f32_ioctl, (void *)data,
		    sizeof (struct fcp32_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyout((void *)&fioctl, (void *)data,
		    sizeof (struct fcp_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}
#else	/* _MULTI_DATAMODEL */

	if (ddi_copyout((void *)&fioctl, (void *)data,
	    sizeof (struct fcp_ioctl), mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	return (0);
}

/*
 * Fetch the target mappings (path, etc.) for all LUNs
 * on this port.
 */
/* ARGSUSED */
static int
fcp_get_target_mappings(struct fcp_ioctl *data,
    int mode, int *rval)
{
	struct fcp_port	    *pptr;
	fc_hba_target_mappings_t    *mappings;
	fc_hba_mapping_entry_t	    *map;
	struct fcp_tgt	    *ptgt = NULL;
	struct fcp_lun	    *plun = NULL;
	int			    i, mapIndex, mappingSize;
	int			    listlen;
	struct fcp_ioctl	    fioctl;
	char			    *path;
	fcp_ent_addr_t		    sam_lun_addr;

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcp32_ioctl f32_ioctl;

		if (ddi_copyin((void *)data, (void *)&f32_ioctl,
		    sizeof (struct fcp32_ioctl), mode)) {
			return (EFAULT);
		}
		fioctl.fp_minor = f32_ioctl.fp_minor;
		fioctl.listlen = f32_ioctl.listlen;
		fioctl.list = (caddr_t)(long)f32_ioctl.list;
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)data, (void *)&fioctl,
		    sizeof (struct fcp_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}

#else	/* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)data, (void *)&fioctl,
	    sizeof (struct fcp_ioctl), mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	/*
	 * Right now we can assume that the minor number matches with
	 * this instance of fp. If this changes we will need to
	 * revisit this logic.
	 */
	mutex_enter(&fcp_global_mutex);
	pptr = fcp_port_head;
	while (pptr) {
		if (pptr->port_instance == (uint32_t)fioctl.fp_minor) {
			break;
		} else {
			pptr = pptr->port_next;
		}
	}
	mutex_exit(&fcp_global_mutex);
	if (pptr == NULL) {
		cmn_err(CE_NOTE, "target mappings: unknown instance number: %d",
		    fioctl.fp_minor);
		return (ENXIO);
	}


	/* We use listlen to show the total buffer size */
	mappingSize = fioctl.listlen;

	/* Now calculate how many mapping entries will fit */
	listlen = fioctl.listlen + sizeof (fc_hba_mapping_entry_t)
	    - sizeof (fc_hba_target_mappings_t);
	if (listlen <= 0) {
		cmn_err(CE_NOTE, "target mappings: Insufficient buffer");
		return (ENXIO);
	}
	listlen = listlen / sizeof (fc_hba_mapping_entry_t);

	if ((mappings = kmem_zalloc(mappingSize, KM_SLEEP)) == NULL) {
		return (ENOMEM);
	}
	mappings->version = FC_HBA_TARGET_MAPPINGS_VERSION;

	/* Now get to work */
	mapIndex = 0;

	mutex_enter(&pptr->port_mutex);
	/* Loop through all targets on this port */
	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {

			mutex_enter(&ptgt->tgt_mutex);

			/* Loop through all LUNs on this target */
			for (plun = ptgt->tgt_lun; plun != NULL;
			    plun = plun->lun_next) {
				if (plun->lun_state & FCP_LUN_OFFLINE) {
					continue;
				}

				path = fcp_get_lun_path(plun);
				if (path == NULL) {
					continue;
				}

				if (mapIndex >= listlen) {
					mapIndex ++;
					kmem_free(path, MAXPATHLEN);
					continue;
				}
				map = &mappings->entries[mapIndex++];
				bcopy(path, map->targetDriver,
				    sizeof (map->targetDriver));
				map->d_id = ptgt->tgt_d_id;
				map->busNumber = 0;
				map->targetNumber = ptgt->tgt_d_id;
				map->osLUN = plun->lun_num;

				/*
				 * We had swapped lun when we stored it in
				 * lun_addr. We need to swap it back before
				 * returning it to user land
				 */

				sam_lun_addr.ent_addr_0 =
				    BE_16(plun->lun_addr.ent_addr_0);
				sam_lun_addr.ent_addr_1 =
				    BE_16(plun->lun_addr.ent_addr_1);
				sam_lun_addr.ent_addr_2 =
				    BE_16(plun->lun_addr.ent_addr_2);
				sam_lun_addr.ent_addr_3 =
				    BE_16(plun->lun_addr.ent_addr_3);

				bcopy(&sam_lun_addr, &map->samLUN,
				    FCP_LUN_SIZE);
				bcopy(ptgt->tgt_node_wwn.raw_wwn,
				    map->NodeWWN.raw_wwn, sizeof (la_wwn_t));
				bcopy(ptgt->tgt_port_wwn.raw_wwn,
				    map->PortWWN.raw_wwn, sizeof (la_wwn_t));

				if (plun->lun_guid) {

					/* convert ascii wwn to bytes */
					fcp_ascii_to_wwn(plun->lun_guid,
					    map->guid, sizeof (map->guid));

					if ((sizeof (map->guid)) <
					    plun->lun_guid_size / 2) {
						cmn_err(CE_WARN,
						    "fcp_get_target_mappings:"
						    "guid copy space "
						    "insufficient."
						    "Copy Truncation - "
						    "available %d; need %d",
						    (int)sizeof (map->guid),
						    (int)
						    plun->lun_guid_size / 2);
					}
				}
				kmem_free(path, MAXPATHLEN);
			}
			mutex_exit(&ptgt->tgt_mutex);
		}
	}
	mutex_exit(&pptr->port_mutex);
	mappings->numLuns = mapIndex;

	if (ddi_copyout(mappings, fioctl.list, mappingSize, mode)) {
		kmem_free(mappings, mappingSize);
		return (EFAULT);
	}
	kmem_free(mappings, mappingSize);

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcp32_ioctl f32_ioctl;

		f32_ioctl.fp_minor = fioctl.fp_minor;
		f32_ioctl.listlen = fioctl.listlen;
		f32_ioctl.list = (caddr32_t)(long)fioctl.list;
		if (ddi_copyout((void *)&f32_ioctl, (void *)data,
		    sizeof (struct fcp32_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyout((void *)&fioctl, (void *)data,
		    sizeof (struct fcp_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}
#else	/* _MULTI_DATAMODEL */

	if (ddi_copyout((void *)&fioctl, (void *)data,
	    sizeof (struct fcp_ioctl), mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	return (0);
}

/*
 * fcp_setup_scsi_ioctl
 *	Setup handler for the "scsi passthru" style of
 *	ioctl for FCP.	See "fcp_util.h" for data structure
 *	definition.
 *
 * Input:
 *	u_fscsi	= ioctl data (user address space)
 *	mode	= See ioctl(9E)
 *
 * Output:
 *	u_fscsi	= ioctl data (user address space)
 *	rval	= return value - see ioctl(9E)
 *
 * Returns:
 *	0	= OK
 *	EAGAIN	= See errno.h
 *	EBUSY	= See errno.h
 *	EFAULT	= See errno.h
 *	EINTR	= See errno.h
 *	EINVAL	= See errno.h
 *	EIO	= See errno.h
 *	ENOMEM	= See errno.h
 *	ENXIO	= See errno.h
 *
 * Context:
 *	Kernel context.
 */
/* ARGSUSED */
static int
fcp_setup_scsi_ioctl(struct fcp_scsi_cmd *u_fscsi,
    int mode, int *rval)
{
	int			ret		= 0;
	int			temp_ret;
	caddr_t			k_cdbbufaddr	= NULL;
	caddr_t			k_bufaddr	= NULL;
	caddr_t			k_rqbufaddr	= NULL;
	caddr_t			u_cdbbufaddr;
	caddr_t			u_bufaddr;
	caddr_t			u_rqbufaddr;
	struct fcp_scsi_cmd	k_fscsi;

	/*
	 * Get fcp_scsi_cmd array element from user address space
	 */
	if ((ret = fcp_copyin_scsi_cmd((caddr_t)u_fscsi, &k_fscsi, mode))
	    != 0) {
		return (ret);
	}


	/*
	 * Even though kmem_alloc() checks the validity of the
	 * buffer length, this check is needed when the
	 * kmem_flags set and the zero buffer length is passed.
	 */
	if ((k_fscsi.scsi_cdblen <= 0) ||
	    (k_fscsi.scsi_buflen <= 0) ||
	    (k_fscsi.scsi_rqlen <= 0)) {
		return (EINVAL);
	}

	/*
	 * Allocate data for fcp_scsi_cmd pointer fields
	 */
	if (ret == 0) {
		k_cdbbufaddr = kmem_alloc(k_fscsi.scsi_cdblen, KM_NOSLEEP);
		k_bufaddr    = kmem_alloc(k_fscsi.scsi_buflen, KM_NOSLEEP);
		k_rqbufaddr  = kmem_alloc(k_fscsi.scsi_rqlen,  KM_NOSLEEP);

		if (k_cdbbufaddr == NULL ||
		    k_bufaddr	 == NULL ||
		    k_rqbufaddr	 == NULL) {
			ret = ENOMEM;
		}
	}

	/*
	 * Get fcp_scsi_cmd pointer fields from user
	 * address space
	 */
	if (ret == 0) {
		u_cdbbufaddr = k_fscsi.scsi_cdbbufaddr;
		u_bufaddr    = k_fscsi.scsi_bufaddr;
		u_rqbufaddr  = k_fscsi.scsi_rqbufaddr;

		if (ddi_copyin(u_cdbbufaddr,
		    k_cdbbufaddr,
		    k_fscsi.scsi_cdblen,
		    mode)) {
			ret = EFAULT;
		} else if (ddi_copyin(u_bufaddr,
		    k_bufaddr,
		    k_fscsi.scsi_buflen,
		    mode)) {
			ret = EFAULT;
		} else if (ddi_copyin(u_rqbufaddr,
		    k_rqbufaddr,
		    k_fscsi.scsi_rqlen,
		    mode)) {
			ret = EFAULT;
		}
	}

	/*
	 * Send scsi command (blocking)
	 */
	if (ret == 0) {
		/*
		 * Prior to sending the scsi command, the
		 * fcp_scsi_cmd data structure must contain kernel,
		 * not user, addresses.
		 */
		k_fscsi.scsi_cdbbufaddr	= k_cdbbufaddr;
		k_fscsi.scsi_bufaddr	= k_bufaddr;
		k_fscsi.scsi_rqbufaddr	= k_rqbufaddr;

		ret = fcp_send_scsi_ioctl(&k_fscsi);

		/*
		 * After sending the scsi command, the
		 * fcp_scsi_cmd data structure must contain user,
		 * not kernel, addresses.
		 */
		k_fscsi.scsi_cdbbufaddr	= u_cdbbufaddr;
		k_fscsi.scsi_bufaddr	= u_bufaddr;
		k_fscsi.scsi_rqbufaddr	= u_rqbufaddr;
	}

	/*
	 * Put fcp_scsi_cmd pointer fields to user address space
	 */
	if (ret == 0) {
		if (ddi_copyout(k_cdbbufaddr,
		    u_cdbbufaddr,
		    k_fscsi.scsi_cdblen,
		    mode)) {
			ret = EFAULT;
		} else if (ddi_copyout(k_bufaddr,
		    u_bufaddr,
		    k_fscsi.scsi_buflen,
		    mode)) {
			ret = EFAULT;
		} else if (ddi_copyout(k_rqbufaddr,
		    u_rqbufaddr,
		    k_fscsi.scsi_rqlen,
		    mode)) {
			ret = EFAULT;
		}
	}

	/*
	 * Free data for fcp_scsi_cmd pointer fields
	 */
	if (k_cdbbufaddr != NULL) {
		kmem_free(k_cdbbufaddr, k_fscsi.scsi_cdblen);
	}
	if (k_bufaddr != NULL) {
		kmem_free(k_bufaddr, k_fscsi.scsi_buflen);
	}
	if (k_rqbufaddr != NULL) {
		kmem_free(k_rqbufaddr, k_fscsi.scsi_rqlen);
	}

	/*
	 * Put fcp_scsi_cmd array element to user address space
	 */
	temp_ret = fcp_copyout_scsi_cmd(&k_fscsi, (caddr_t)u_fscsi, mode);
	if (temp_ret != 0) {
		ret = temp_ret;
	}

	/*
	 * Return status
	 */
	return (ret);
}


/*
 * fcp_copyin_scsi_cmd
 *	Copy in fcp_scsi_cmd data structure from user address space.
 *	The data may be in 32 bit or 64 bit modes.
 *
 * Input:
 *	base_addr	= from address (user address space)
 *	mode		= See ioctl(9E) and ddi_copyin(9F)
 *
 * Output:
 *	fscsi		= to address (kernel address space)
 *
 * Returns:
 *	0	= OK
 *	EFAULT	= Error
 *
 * Context:
 *	Kernel context.
 */
static int
fcp_copyin_scsi_cmd(caddr_t base_addr, struct fcp_scsi_cmd *fscsi, int mode)
{
#ifdef	_MULTI_DATAMODEL
	struct fcp32_scsi_cmd	f32scsi;

	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		/*
		 * Copy data from user address space
		 */
		if (ddi_copyin((void *)base_addr,
		    &f32scsi,
		    sizeof (struct fcp32_scsi_cmd),
		    mode)) {
			return (EFAULT);
		}
		/*
		 * Convert from 32 bit to 64 bit
		 */
		FCP32_SCSI_CMD_TO_FCP_SCSI_CMD(&f32scsi, fscsi);
		break;
	case DDI_MODEL_NONE:
		/*
		 * Copy data from user address space
		 */
		if (ddi_copyin((void *)base_addr,
		    fscsi,
		    sizeof (struct fcp_scsi_cmd),
		    mode)) {
			return (EFAULT);
		}
		break;
	}
#else	/* _MULTI_DATAMODEL */
	/*
	 * Copy data from user address space
	 */
	if (ddi_copyin((void *)base_addr,
	    fscsi,
	    sizeof (struct fcp_scsi_cmd),
	    mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	return (0);
}


/*
 * fcp_copyout_scsi_cmd
 *	Copy out fcp_scsi_cmd data structure to user address space.
 *	The data may be in 32 bit or 64 bit modes.
 *
 * Input:
 *	fscsi		= to address (kernel address space)
 *	mode		= See ioctl(9E) and ddi_copyin(9F)
 *
 * Output:
 *	base_addr	= from address (user address space)
 *
 * Returns:
 *	0	= OK
 *	EFAULT	= Error
 *
 * Context:
 *	Kernel context.
 */
static int
fcp_copyout_scsi_cmd(struct fcp_scsi_cmd *fscsi, caddr_t base_addr, int mode)
{
#ifdef	_MULTI_DATAMODEL
	struct fcp32_scsi_cmd	f32scsi;

	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		/*
		 * Convert from 64 bit to 32 bit
		 */
		FCP_SCSI_CMD_TO_FCP32_SCSI_CMD(fscsi, &f32scsi);
		/*
		 * Copy data to user address space
		 */
		if (ddi_copyout(&f32scsi,
		    (void *)base_addr,
		    sizeof (struct fcp32_scsi_cmd),
		    mode)) {
			return (EFAULT);
		}
		break;
	case DDI_MODEL_NONE:
		/*
		 * Copy data to user address space
		 */
		if (ddi_copyout(fscsi,
		    (void *)base_addr,
		    sizeof (struct fcp_scsi_cmd),
		    mode)) {
			return (EFAULT);
		}
		break;
	}
#else	/* _MULTI_DATAMODEL */
	/*
	 * Copy data to user address space
	 */
	if (ddi_copyout(fscsi,
	    (void *)base_addr,
	    sizeof (struct fcp_scsi_cmd),
	    mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	return (0);
}


/*
 * fcp_send_scsi_ioctl
 *	Sends the SCSI command in blocking mode.
 *
 * Input:
 *	fscsi		= SCSI command data structure
 *
 * Output:
 *	fscsi		= SCSI command data structure
 *
 * Returns:
 *	0	= OK
 *	EAGAIN	= See errno.h
 *	EBUSY	= See errno.h
 *	EINTR	= See errno.h
 *	EINVAL	= See errno.h
 *	EIO	= See errno.h
 *	ENOMEM	= See errno.h
 *	ENXIO	= See errno.h
 *
 * Context:
 *	Kernel context.
 */
static int
fcp_send_scsi_ioctl(struct fcp_scsi_cmd *fscsi)
{
	struct fcp_lun	*plun		= NULL;
	struct fcp_port	*pptr		= NULL;
	struct fcp_tgt	*ptgt		= NULL;
	fc_packet_t		*fpkt		= NULL;
	struct fcp_ipkt	*icmd		= NULL;
	int			target_created	= FALSE;
	fc_frame_hdr_t		*hp;
	struct fcp_cmd		fcp_cmd;
	struct fcp_cmd		*fcmd;
	union scsi_cdb		*scsi_cdb;
	la_wwn_t		*wwn_ptr;
	int			nodma;
	struct fcp_rsp		*rsp;
	struct fcp_rsp_info	*rsp_info;
	caddr_t			rsp_sense;
	int			buf_len;
	int			info_len;
	int			sense_len;
	struct scsi_extended_sense	*sense_to = NULL;
	timeout_id_t		tid;
	uint8_t			reconfig_lun = FALSE;
	uint8_t			reconfig_pending = FALSE;
	uint8_t			scsi_cmd;
	int			rsp_len;
	int			cmd_index;
	int			fc_status;
	int			pkt_state;
	int			pkt_action;
	int			pkt_reason;
	int			ret, xport_retval = ~FC_SUCCESS;
	int			lcount;
	int			tcount;
	int			reconfig_status;
	int			port_busy = FALSE;
	uchar_t			*lun_string;

	/*
	 * Check valid SCSI command
	 */
	scsi_cmd = ((uint8_t *)fscsi->scsi_cdbbufaddr)[0];
	ret = EINVAL;
	for (cmd_index = 0;
	    cmd_index < FCP_NUM_ELEMENTS(scsi_ioctl_list) &&
	    ret != 0;
	    cmd_index++) {
		/*
		 * First byte of CDB is the SCSI command
		 */
		if (scsi_ioctl_list[cmd_index] == scsi_cmd) {
			ret = 0;
		}
	}

	/*
	 * Check inputs
	 */
	if (fscsi->scsi_flags != FCP_SCSI_READ) {
		ret = EINVAL;
	} else if (fscsi->scsi_cdblen > FCP_CDB_SIZE) {
		/* no larger than */
		ret = EINVAL;
	}


	/*
	 * Find FC port
	 */
	if (ret == 0) {
		/*
		 * Acquire global mutex
		 */
		mutex_enter(&fcp_global_mutex);

		pptr = fcp_port_head;
		while (pptr) {
			if (pptr->port_instance ==
			    (uint32_t)fscsi->scsi_fc_port_num) {
				break;
			} else {
				pptr = pptr->port_next;
			}
		}

		if (pptr == NULL) {
			ret = ENXIO;
		} else {
			/*
			 * fc_ulp_busy_port can raise power
			 *  so, we must not hold any mutexes involved in PM
			 */
			mutex_exit(&fcp_global_mutex);
			ret = fc_ulp_busy_port(pptr->port_fp_handle);
		}

		if (ret == 0) {

			/* remember port is busy, so we will release later */
			port_busy = TRUE;

			/*
			 * If there is a reconfiguration in progress, wait
			 * for it to complete.
			 */

			fcp_reconfig_wait(pptr);

			/* reacquire mutexes in order */
			mutex_enter(&fcp_global_mutex);
			mutex_enter(&pptr->port_mutex);

			/*
			 * Will port accept DMA?
			 */
			nodma = (pptr->port_fcp_dma == FC_NO_DVMA_SPACE)
			    ? 1 : 0;

			/*
			 * If init or offline, device not known
			 *
			 * If we are discovering (onlining), we can
			 * NOT obviously provide reliable data about
			 * devices until it is complete
			 */
			if (pptr->port_state &	  (FCP_STATE_INIT |
			    FCP_STATE_OFFLINE)) {
				ret = ENXIO;
			} else if (pptr->port_state & FCP_STATE_ONLINING) {
				ret = EBUSY;
			} else {
				/*
				 * Find target from pwwn
				 *
				 * The wwn must be put into a local
				 * variable to ensure alignment.
				 */
				wwn_ptr = (la_wwn_t *)&(fscsi->scsi_fc_pwwn);
				ptgt = fcp_lookup_target(pptr,
				    (uchar_t *)wwn_ptr);

				/*
				 * If target not found,
				 */
				if (ptgt == NULL) {
					/*
					 * Note: Still have global &
					 * port mutexes
					 */
					mutex_exit(&pptr->port_mutex);
					ptgt = fcp_port_create_tgt(pptr,
					    wwn_ptr, &ret, &fc_status,
					    &pkt_state, &pkt_action,
					    &pkt_reason);
					mutex_enter(&pptr->port_mutex);

					fscsi->scsi_fc_status  = fc_status;
					fscsi->scsi_pkt_state  =
					    (uchar_t)pkt_state;
					fscsi->scsi_pkt_reason = pkt_reason;
					fscsi->scsi_pkt_action =
					    (uchar_t)pkt_action;

					if (ptgt != NULL) {
						target_created = TRUE;
					} else if (ret == 0) {
						ret = ENOMEM;
					}
				}

				if (ret == 0) {
					/*
					 * Acquire target
					 */
					mutex_enter(&ptgt->tgt_mutex);

					/*
					 * If target is mark or busy,
					 * then target can not be used
					 */
					if (ptgt->tgt_state &
					    (FCP_TGT_MARK |
					    FCP_TGT_BUSY)) {
						ret = EBUSY;
					} else {
						/*
						 * Mark target as busy
						 */
						ptgt->tgt_state |=
						    FCP_TGT_BUSY;
					}

					/*
					 * Release target
					 */
					lcount = pptr->port_link_cnt;
					tcount = ptgt->tgt_change_cnt;
					mutex_exit(&ptgt->tgt_mutex);
				}
			}

			/*
			 * Release port
			 */
			mutex_exit(&pptr->port_mutex);
		}

		/*
		 * Release global mutex
		 */
		mutex_exit(&fcp_global_mutex);
	}

	if (ret == 0) {
		uint64_t belun = BE_64(fscsi->scsi_lun);

		/*
		 * If it's a target device, find lun from pwwn
		 * The wwn must be put into a local
		 * variable to ensure alignment.
		 */
		mutex_enter(&pptr->port_mutex);
		wwn_ptr = (la_wwn_t *)&(fscsi->scsi_fc_pwwn);
		if (!ptgt->tgt_tcap && ptgt->tgt_icap) {
			/* this is not a target */
			fscsi->scsi_fc_status = FC_DEVICE_NOT_TGT;
			ret = ENXIO;
		} else if ((belun << 16) != 0) {
			/*
			 * Since fcp only support PD and LU addressing method
			 * so far, the last 6 bytes of a valid LUN are expected
			 * to be filled with 00h.
			 */
			fscsi->scsi_fc_status = FC_INVALID_LUN;
			cmn_err(CE_WARN, "fcp: Unsupported LUN addressing"
			    " method 0x%02x with LUN number 0x%016" PRIx64,
			    (uint8_t)(belun >> 62), belun);
			ret = ENXIO;
		} else if ((plun = fcp_lookup_lun(pptr, (uchar_t *)wwn_ptr,
		    (uint16_t)((belun >> 48) & 0x3fff))) == NULL) {
			/*
			 * This is a SCSI target, but no LUN at this
			 * address.
			 *
			 * In the future, we may want to send this to
			 * the target, and let it respond
			 * appropriately
			 */
			ret = ENXIO;
		}
		mutex_exit(&pptr->port_mutex);
	}

	/*
	 * Finished grabbing external resources
	 * Allocate internal packet (icmd)
	 */
	if (ret == 0) {
		/*
		 * Calc rsp len assuming rsp info included
		 */
		rsp_len = sizeof (struct fcp_rsp) +
		    sizeof (struct fcp_rsp_info) + fscsi->scsi_rqlen;

		icmd = fcp_icmd_alloc(pptr, ptgt,
		    sizeof (struct fcp_cmd),
		    rsp_len,
		    fscsi->scsi_buflen,
		    nodma,
		    lcount,			/* ipkt_link_cnt */
		    tcount,			/* ipkt_change_cnt */
		    0,				/* cause */
		    FC_INVALID_RSCN_COUNT);	/* invalidate the count */

		if (icmd == NULL) {
			ret = ENOMEM;
		} else {
			/*
			 * Setup internal packet as sema sync
			 */
			fcp_ipkt_sema_init(icmd);
		}
	}

	if (ret == 0) {
		/*
		 * Init fpkt pointer for use.
		 */

		fpkt = icmd->ipkt_fpkt;

		fpkt->pkt_tran_flags	= FC_TRAN_CLASS3 | FC_TRAN_INTR;
		fpkt->pkt_tran_type	= FC_PKT_FCP_READ; /* only rd for now */
		fpkt->pkt_timeout	= fscsi->scsi_timeout;

		/*
		 * Init fcmd pointer for use by SCSI command
		 */

		if (nodma) {
			fcmd = (struct fcp_cmd *)fpkt->pkt_cmd;
		} else {
			fcmd = &fcp_cmd;
		}
		bzero(fcmd, sizeof (struct fcp_cmd));
		ptgt = plun->lun_tgt;

		lun_string = (uchar_t *)&fscsi->scsi_lun;

		fcmd->fcp_ent_addr.ent_addr_0 =
		    BE_16(*(uint16_t *)&(lun_string[0]));
		fcmd->fcp_ent_addr.ent_addr_1 =
		    BE_16(*(uint16_t *)&(lun_string[2]));
		fcmd->fcp_ent_addr.ent_addr_2 =
		    BE_16(*(uint16_t *)&(lun_string[4]));
		fcmd->fcp_ent_addr.ent_addr_3 =
		    BE_16(*(uint16_t *)&(lun_string[6]));

		/*
		 * Setup internal packet(icmd)
		 */
		icmd->ipkt_lun		= plun;
		icmd->ipkt_restart	= 0;
		icmd->ipkt_retries	= 0;
		icmd->ipkt_opcode	= 0;

		/*
		 * Init the frame HEADER Pointer for use
		 */
		hp = &fpkt->pkt_cmd_fhdr;

		hp->s_id	= pptr->port_id;
		hp->d_id	= ptgt->tgt_d_id;
		hp->r_ctl	= R_CTL_COMMAND;
		hp->type	= FC_TYPE_SCSI_FCP;
		hp->f_ctl	= F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
		hp->rsvd	= 0;
		hp->seq_id	= 0;
		hp->seq_cnt	= 0;
		hp->ox_id	= 0xffff;
		hp->rx_id	= 0xffff;
		hp->ro		= 0;

		fcmd->fcp_cntl.cntl_qtype	= FCP_QTYPE_SIMPLE;
		fcmd->fcp_cntl.cntl_read_data	= 1;	/* only rd for now */
		fcmd->fcp_cntl.cntl_write_data	= 0;
		fcmd->fcp_data_len	= fscsi->scsi_buflen;

		scsi_cdb = (union scsi_cdb *)fcmd->fcp_cdb;
		bcopy((char *)fscsi->scsi_cdbbufaddr, (char *)scsi_cdb,
		    fscsi->scsi_cdblen);

		if (!nodma) {
			FCP_CP_OUT((uint8_t *)fcmd, fpkt->pkt_cmd,
			    fpkt->pkt_cmd_acc, sizeof (struct fcp_cmd));
		}

		/*
		 * Send SCSI command to FC transport
		 */

		if (ret == 0) {
			mutex_enter(&ptgt->tgt_mutex);

			if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {
				mutex_exit(&ptgt->tgt_mutex);
				fscsi->scsi_fc_status = xport_retval =
				    fc_ulp_transport(pptr->port_fp_handle,
				    fpkt);
				if (fscsi->scsi_fc_status != FC_SUCCESS) {
					ret = EIO;
				}
			} else {
				mutex_exit(&ptgt->tgt_mutex);
				ret = EBUSY;
			}
		}
	}

	/*
	 * Wait for completion only if fc_ulp_transport was called and it
	 * returned a success. This is the only time callback will happen.
	 * Otherwise, there is no point in waiting
	 */
	if ((ret == 0) && (xport_retval == FC_SUCCESS)) {
		ret = fcp_ipkt_sema_wait(icmd);
	}

	/*
	 * Copy data to IOCTL data structures
	 */
	rsp = NULL;
	if ((ret == 0) && (xport_retval == FC_SUCCESS)) {
		rsp = (struct fcp_rsp *)fpkt->pkt_resp;

		if (fcp_validate_fcp_response(rsp, pptr) != FC_SUCCESS) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!SCSI command to d_id=0x%x lun=0x%x"
			    " failed, Bad FCP response values:"
			    " rsvd1=%x, rsvd2=%x, sts-rsvd1=%x,"
			    " sts-rsvd2=%x, rsplen=%x, senselen=%x",
			    ptgt->tgt_d_id, plun->lun_num,
			    rsp->reserved_0, rsp->reserved_1,
			    rsp->fcp_u.fcp_status.reserved_0,
			    rsp->fcp_u.fcp_status.reserved_1,
			    rsp->fcp_response_len, rsp->fcp_sense_len);

			ret = EIO;
		}
	}

	if ((ret == 0) && (rsp != NULL)) {
		/*
		 * Calc response lengths
		 */
		sense_len = 0;
		info_len = 0;

		if (rsp->fcp_u.fcp_status.rsp_len_set) {
			info_len = rsp->fcp_response_len;
		}

		rsp_info   = (struct fcp_rsp_info *)
		    ((uint8_t *)rsp + sizeof (struct fcp_rsp));

		/*
		 * Get SCSI status
		 */
		fscsi->scsi_bufstatus = rsp->fcp_u.fcp_status.scsi_status;
		/*
		 * If a lun was just added or removed and the next command
		 * comes through this interface, we need to capture the check
		 * condition so we can discover the new topology.
		 */
		if (fscsi->scsi_bufstatus != STATUS_GOOD &&
		    rsp->fcp_u.fcp_status.sense_len_set) {
			sense_len = rsp->fcp_sense_len;
			rsp_sense  = (caddr_t)((uint8_t *)rsp_info + info_len);
			sense_to = (struct scsi_extended_sense *)rsp_sense;
			if ((FCP_SENSE_REPORTLUN_CHANGED(sense_to)) ||
			    (FCP_SENSE_NO_LUN(sense_to))) {
				reconfig_lun = TRUE;
			}
		}

		if (fscsi->scsi_bufstatus == STATUS_GOOD && (ptgt != NULL) &&
		    (reconfig_lun || (scsi_cdb->scc_cmd == SCMD_REPORT_LUN))) {
			if (reconfig_lun == FALSE) {
				reconfig_status =
				    fcp_is_reconfig_needed(ptgt, fpkt);
			}

			if ((reconfig_lun == TRUE) ||
			    (reconfig_status == TRUE)) {
				mutex_enter(&ptgt->tgt_mutex);
				if (ptgt->tgt_tid == NULL) {
					/*
					 * Either we've been notified the
					 * REPORT_LUN data has changed, or
					 * we've determined on our own that
					 * we're out of date.  Kick off
					 * rediscovery.
					 */
					tid = timeout(fcp_reconfigure_luns,
					    (caddr_t)ptgt, drv_usectohz(1));

					ptgt->tgt_tid = tid;
					ptgt->tgt_state |= FCP_TGT_BUSY;
					ret = EBUSY;
					reconfig_pending = TRUE;
				}
				mutex_exit(&ptgt->tgt_mutex);
			}
		}

		/*
		 * Calc residuals and buffer lengths
		 */

		if (ret == 0) {
			buf_len = fscsi->scsi_buflen;
			fscsi->scsi_bufresid	= 0;
			if (rsp->fcp_u.fcp_status.resid_under) {
				if (rsp->fcp_resid <= fscsi->scsi_buflen) {
					fscsi->scsi_bufresid = rsp->fcp_resid;
				} else {
					cmn_err(CE_WARN, "fcp: bad residue %x "
					    "for txfer len %x", rsp->fcp_resid,
					    fscsi->scsi_buflen);
					fscsi->scsi_bufresid =
					    fscsi->scsi_buflen;
				}
				buf_len -= fscsi->scsi_bufresid;
			}
			if (rsp->fcp_u.fcp_status.resid_over) {
				fscsi->scsi_bufresid = -rsp->fcp_resid;
			}

			fscsi->scsi_rqresid	= fscsi->scsi_rqlen - sense_len;
			if (fscsi->scsi_rqlen < sense_len) {
				sense_len = fscsi->scsi_rqlen;
			}

			fscsi->scsi_fc_rspcode	= 0;
			if (rsp->fcp_u.fcp_status.rsp_len_set) {
				fscsi->scsi_fc_rspcode	= rsp_info->rsp_code;
			}
			fscsi->scsi_pkt_state	= fpkt->pkt_state;
			fscsi->scsi_pkt_action	= fpkt->pkt_action;
			fscsi->scsi_pkt_reason	= fpkt->pkt_reason;

			/*
			 * Copy data and request sense
			 *
			 * Data must be copied by using the FCP_CP_IN macro.
			 * This will ensure the proper byte order since the data
			 * is being copied directly from the memory mapped
			 * device register.
			 *
			 * The response (and request sense) will be in the
			 * correct byte order.	No special copy is necessary.
			 */

			if (buf_len) {
				FCP_CP_IN(fpkt->pkt_data,
				    fscsi->scsi_bufaddr,
				    fpkt->pkt_data_acc,
				    buf_len);
			}
			bcopy((void *)rsp_sense,
			    (void *)fscsi->scsi_rqbufaddr,
			    sense_len);
		}
	}

	/*
	 * Cleanup transport data structures if icmd was alloc-ed
	 * So, cleanup happens in the same thread that icmd was alloc-ed
	 */
	if (icmd != NULL) {
		fcp_ipkt_sema_cleanup(icmd);
	}

	/* restore pm busy/idle status */
	if (port_busy) {
		fc_ulp_idle_port(pptr->port_fp_handle);
	}

	/*
	 * Cleanup target.  if a reconfig is pending, don't clear the BUSY
	 * flag, it'll be cleared when the reconfig is complete.
	 */
	if ((ptgt != NULL) && !reconfig_pending) {
		/*
		 * If target was created,
		 */
		if (target_created) {
			mutex_enter(&ptgt->tgt_mutex);
			ptgt->tgt_state &= ~FCP_TGT_BUSY;
			mutex_exit(&ptgt->tgt_mutex);
		} else {
			/*
			 * De-mark target as busy
			 */
			mutex_enter(&ptgt->tgt_mutex);
			ptgt->tgt_state &= ~FCP_TGT_BUSY;
			mutex_exit(&ptgt->tgt_mutex);
		}
	}
	return (ret);
}


static int
fcp_is_reconfig_needed(struct fcp_tgt *ptgt,
    fc_packet_t	*fpkt)
{
	uchar_t			*lun_string;
	uint16_t		lun_num, i;
	int			num_luns;
	int			actual_luns;
	int			num_masked_luns;
	int			lun_buflen;
	struct fcp_lun	*plun	= NULL;
	struct fcp_reportlun_resp	*report_lun;
	uint8_t			reconfig_needed = FALSE;
	uint8_t			lun_exists = FALSE;
	fcp_port_t			*pptr		 = ptgt->tgt_port;

	report_lun = kmem_zalloc(fpkt->pkt_datalen, KM_SLEEP);

	FCP_CP_IN(fpkt->pkt_data, report_lun, fpkt->pkt_data_acc,
	    fpkt->pkt_datalen);

	/* get number of luns (which is supplied as LUNS * 8) */
	num_luns = BE_32(report_lun->num_lun) >> 3;

	/*
	 * Figure out exactly how many lun strings our response buffer
	 * can hold.
	 */
	lun_buflen = (fpkt->pkt_datalen -
	    2 * sizeof (uint32_t)) / sizeof (longlong_t);

	/*
	 * Is our response buffer full or not? We don't want to
	 * potentially walk beyond the number of luns we have.
	 */
	if (num_luns <= lun_buflen) {
		actual_luns = num_luns;
	} else {
		actual_luns = lun_buflen;
	}

	mutex_enter(&ptgt->tgt_mutex);

	/* Scan each lun to see if we have masked it. */
	num_masked_luns = 0;
	if (fcp_lun_blacklist != NULL) {
		for (i = 0; i < actual_luns; i++) {
			lun_string = (uchar_t *)&(report_lun->lun_string[i]);
			switch (lun_string[0] & 0xC0) {
			case FCP_LUN_ADDRESSING:
			case FCP_PD_ADDRESSING:
			case FCP_VOLUME_ADDRESSING:
				lun_num = ((lun_string[0] & 0x3F) << 8)
				    | lun_string[1];
				if (fcp_should_mask(&ptgt->tgt_port_wwn,
				    lun_num) == TRUE) {
					num_masked_luns++;
				}
				break;
			default:
				break;
			}
		}
	}

	/*
	 * The quick and easy check.  If the number of LUNs reported
	 * doesn't match the number we currently know about, we need
	 * to reconfigure.
	 */
	if (num_luns && num_luns != (ptgt->tgt_lun_cnt + num_masked_luns)) {
		mutex_exit(&ptgt->tgt_mutex);
		kmem_free(report_lun, fpkt->pkt_datalen);
		return (TRUE);
	}

	/*
	 * If the quick and easy check doesn't turn up anything, we walk
	 * the list of luns from the REPORT_LUN response and look for
	 * any luns we don't know about.  If we find one, we know we need
	 * to reconfigure. We will skip LUNs that are masked because of the
	 * blacklist.
	 */
	for (i = 0; i < actual_luns; i++) {
		lun_string = (uchar_t *)&(report_lun->lun_string[i]);
		lun_exists = FALSE;
		switch (lun_string[0] & 0xC0) {
		case FCP_LUN_ADDRESSING:
		case FCP_PD_ADDRESSING:
		case FCP_VOLUME_ADDRESSING:
			lun_num = ((lun_string[0] & 0x3F) << 8) | lun_string[1];

			if ((fcp_lun_blacklist != NULL) && (fcp_should_mask(
			    &ptgt->tgt_port_wwn, lun_num) == TRUE)) {
				lun_exists = TRUE;
				break;
			}

			for (plun = ptgt->tgt_lun; plun;
			    plun = plun->lun_next) {
				if (plun->lun_num == lun_num) {
					lun_exists = TRUE;
					break;
				}
			}
			break;
		default:
			break;
		}

		if (lun_exists == FALSE) {
			reconfig_needed = TRUE;
			break;
		}
	}

	mutex_exit(&ptgt->tgt_mutex);
	kmem_free(report_lun, fpkt->pkt_datalen);

	return (reconfig_needed);
}

/*
 * This function is called by fcp_handle_page83 and uses inquiry response data
 * stored in plun->lun_inq to determine whether or not a device is a member of
 * the table fcp_symmetric_disk_table_size. We return 0 if it is in the table,
 * otherwise 1.
 */
static int
fcp_symmetric_device_probe(struct fcp_lun *plun)
{
	struct scsi_inquiry	*stdinq = &plun->lun_inq;
	char			*devidptr;
	int			i, len;

	for (i = 0; i < fcp_symmetric_disk_table_size; i++) {
		devidptr = fcp_symmetric_disk_table[i];
		len = (int)strlen(devidptr);

		if (bcmp(stdinq->inq_vid, devidptr, len) == 0) {
			return (0);
		}
	}
	return (1);
}


/*
 * This function is called by fcp_ioctl for the FCP_STATE_COUNT ioctl
 * It basically returns the current count of # of state change callbacks
 * i.e the value of tgt_change_cnt.
 *
 * INPUT:
 *   fcp_ioctl.fp_minor -> The minor # of the fp port
 *   fcp_ioctl.listlen	-> 1
 *   fcp_ioctl.list	-> Pointer to a 32 bit integer
 */
/*ARGSUSED2*/
static int
fcp_get_statec_count(struct fcp_ioctl *data, int mode, int *rval)
{
	int			ret;
	uint32_t		link_cnt;
	struct fcp_ioctl	fioctl;
	struct fcp_port	*pptr = NULL;

	if ((ret = fcp_copyin_fcp_ioctl_data(data, mode, rval, &fioctl,
	    &pptr)) != 0) {
		return (ret);
	}

	ASSERT(pptr != NULL);

	if (fioctl.listlen != 1) {
		return (EINVAL);
	}

	mutex_enter(&pptr->port_mutex);
	if (pptr->port_state & FCP_STATE_OFFLINE) {
		mutex_exit(&pptr->port_mutex);
		return (ENXIO);
	}

	/*
	 * FCP_STATE_INIT is set in 2 cases (not sure why it is overloaded):
	 * When the fcp initially attaches to the port and there are nothing
	 * hanging out of the port or if there was a repeat offline state change
	 * callback (refer fcp_statec_callback() FC_STATE_OFFLINE case).
	 * In the latter case, port_tmp_cnt will be non-zero and that is how we
	 * will differentiate the 2 cases.
	 */
	if ((pptr->port_state & FCP_STATE_INIT) && pptr->port_tmp_cnt) {
		mutex_exit(&pptr->port_mutex);
		return (ENXIO);
	}

	link_cnt = pptr->port_link_cnt;
	mutex_exit(&pptr->port_mutex);

	if (ddi_copyout(&link_cnt, fioctl.list, (sizeof (uint32_t)), mode)) {
		return (EFAULT);
	}

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcp32_ioctl f32_ioctl;

		f32_ioctl.fp_minor = fioctl.fp_minor;
		f32_ioctl.listlen = fioctl.listlen;
		f32_ioctl.list = (caddr32_t)(long)fioctl.list;
		if (ddi_copyout((void *)&f32_ioctl, (void *)data,
		    sizeof (struct fcp32_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyout((void *)&fioctl, (void *)data,
		    sizeof (struct fcp_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}
#else	/* _MULTI_DATAMODEL */

	if (ddi_copyout((void *)&fioctl, (void *)data,
	    sizeof (struct fcp_ioctl), mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	return (0);
}

/*
 * This function copies the fcp_ioctl structure passed in from user land
 * into kernel land. Handles 32 bit applications.
 */
/*ARGSUSED*/
static int
fcp_copyin_fcp_ioctl_data(struct fcp_ioctl *data, int mode, int *rval,
    struct fcp_ioctl *fioctl, struct fcp_port **pptr)
{
	struct fcp_port	*t_pptr;

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct fcp32_ioctl f32_ioctl;

		if (ddi_copyin((void *)data, (void *)&f32_ioctl,
		    sizeof (struct fcp32_ioctl), mode)) {
			return (EFAULT);
		}
		fioctl->fp_minor = f32_ioctl.fp_minor;
		fioctl->listlen = f32_ioctl.listlen;
		fioctl->list = (caddr_t)(long)f32_ioctl.list;
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)data, (void *)fioctl,
		    sizeof (struct fcp_ioctl), mode)) {
			return (EFAULT);
		}
		break;
	}

#else	/* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)data, (void *)fioctl,
	    sizeof (struct fcp_ioctl), mode)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	/*
	 * Right now we can assume that the minor number matches with
	 * this instance of fp. If this changes we will need to
	 * revisit this logic.
	 */
	mutex_enter(&fcp_global_mutex);
	t_pptr = fcp_port_head;
	while (t_pptr) {
		if (t_pptr->port_instance == (uint32_t)fioctl->fp_minor) {
			break;
		} else {
			t_pptr = t_pptr->port_next;
		}
	}
	*pptr = t_pptr;
	mutex_exit(&fcp_global_mutex);
	if (t_pptr == NULL) {
		return (ENXIO);
	}

	return (0);
}

/*
 *     Function: fcp_port_create_tgt
 *
 *  Description: As the name suggest this function creates the target context
 *		 specified by the the WWN provided by the caller.  If the
 *		 creation goes well and the target is known by fp/fctl a PLOGI
 *		 followed by a PRLI are issued.
 *
 *     Argument: pptr		fcp port structure
 *		 pwwn		WWN of the target
 *		 ret_val	Address of the return code.  It could be:
 *				EIO, ENOMEM or 0.
 *		 fc_status	PLOGI or PRLI status completion
 *		 fc_pkt_state	PLOGI or PRLI state completion
 *		 fc_pkt_reason	PLOGI or PRLI reason completion
 *		 fc_pkt_action	PLOGI or PRLI action completion
 *
 * Return Value: NULL if it failed
 *		 Target structure address if it succeeds
 */
static struct fcp_tgt *
fcp_port_create_tgt(struct fcp_port *pptr, la_wwn_t *pwwn, int *ret_val,
    int *fc_status, int *fc_pkt_state, int *fc_pkt_reason, int *fc_pkt_action)
{
	struct fcp_tgt	*ptgt = NULL;
	fc_portmap_t		devlist;
	int			lcount;
	int			error;

	*ret_val = 0;

	/*
	 * Check FC port device & get port map
	 */
	if (fc_ulp_get_remote_port(pptr->port_fp_handle, pwwn,
	    &error, 1) == NULL) {
		*ret_val = EIO;
	} else {
		if (fc_ulp_pwwn_to_portmap(pptr->port_fp_handle, pwwn,
		    &devlist) != FC_SUCCESS) {
			*ret_val = EIO;
		}
	}

	/* Set port map flags */
	devlist.map_type = PORT_DEVICE_USER_CREATE;

	/* Allocate target */
	if (*ret_val == 0) {
		lcount = pptr->port_link_cnt;
		ptgt = fcp_alloc_tgt(pptr, &devlist, lcount);
		if (ptgt == NULL) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FC target allocation failed");
			*ret_val = ENOMEM;
		} else {
			/* Setup target */
			mutex_enter(&ptgt->tgt_mutex);

			ptgt->tgt_statec_cause	= FCP_CAUSE_TGT_CHANGE;
			ptgt->tgt_tmp_cnt	= 1;
			ptgt->tgt_d_id		= devlist.map_did.port_id;
			ptgt->tgt_hard_addr	=
			    devlist.map_hard_addr.hard_addr;
			ptgt->tgt_pd_handle	= devlist.map_pd;
			ptgt->tgt_fca_dev	= NULL;

			bcopy(&devlist.map_nwwn, &ptgt->tgt_node_wwn.raw_wwn[0],
			    FC_WWN_SIZE);
			bcopy(&devlist.map_pwwn, &ptgt->tgt_port_wwn.raw_wwn[0],
			    FC_WWN_SIZE);

			mutex_exit(&ptgt->tgt_mutex);
		}
	}

	/* Release global mutex for PLOGI and PRLI */
	mutex_exit(&fcp_global_mutex);

	/* Send PLOGI (If necessary) */
	if (*ret_val == 0) {
		*ret_val = fcp_tgt_send_plogi(ptgt, fc_status,
		    fc_pkt_state, fc_pkt_reason, fc_pkt_action);
	}

	/* Send PRLI (If necessary) */
	if (*ret_val == 0) {
		*ret_val = fcp_tgt_send_prli(ptgt, fc_status,
		    fc_pkt_state, fc_pkt_reason, fc_pkt_action);
	}

	mutex_enter(&fcp_global_mutex);

	return (ptgt);
}

/*
 *     Function: fcp_tgt_send_plogi
 *
 *  Description: This function sends a PLOGI to the target specified by the
 *		 caller and waits till it completes.
 *
 *     Argument: ptgt		Target to send the plogi to.
 *		 fc_status	Status returned by fp/fctl in the PLOGI request.
 *		 fc_pkt_state	State returned by fp/fctl in the PLOGI request.
 *		 fc_pkt_reason	Reason returned by fp/fctl in the PLOGI request.
 *		 fc_pkt_action	Action returned by fp/fctl in the PLOGI request.
 *
 * Return Value: 0
 *		 ENOMEM
 *		 EIO
 *
 *	Context: User context.
 */
static int
fcp_tgt_send_plogi(struct fcp_tgt *ptgt, int *fc_status, int *fc_pkt_state,
    int *fc_pkt_reason, int *fc_pkt_action)
{
	struct fcp_port	*pptr;
	struct fcp_ipkt	*icmd;
	struct fc_packet	*fpkt;
	fc_frame_hdr_t		*hp;
	struct la_els_logi	logi;
	int			tcount;
	int			lcount;
	int			ret, login_retval = ~FC_SUCCESS;

	ret = 0;

	pptr = ptgt->tgt_port;

	lcount = pptr->port_link_cnt;
	tcount = ptgt->tgt_change_cnt;

	/* Alloc internal packet */
	icmd = fcp_icmd_alloc(pptr, ptgt, sizeof (la_els_logi_t),
	    sizeof (la_els_logi_t), 0,
	    pptr->port_state & FCP_STATE_FCA_IS_NODMA,
	    lcount, tcount, 0, FC_INVALID_RSCN_COUNT);

	if (icmd == NULL) {
		ret = ENOMEM;
	} else {
		/*
		 * Setup internal packet as sema sync
		 */
		fcp_ipkt_sema_init(icmd);

		/*
		 * Setup internal packet (icmd)
		 */
		icmd->ipkt_lun		= NULL;
		icmd->ipkt_restart	= 0;
		icmd->ipkt_retries	= 0;
		icmd->ipkt_opcode	= LA_ELS_PLOGI;

		/*
		 * Setup fc_packet
		 */
		fpkt = icmd->ipkt_fpkt;

		fpkt->pkt_tran_flags	= FC_TRAN_CLASS3 | FC_TRAN_INTR;
		fpkt->pkt_tran_type	= FC_PKT_EXCHANGE;
		fpkt->pkt_timeout	= FCP_ELS_TIMEOUT;

		/*
		 * Setup FC frame header
		 */
		hp = &fpkt->pkt_cmd_fhdr;

		hp->s_id	= pptr->port_id;	/* source ID */
		hp->d_id	= ptgt->tgt_d_id;	/* dest ID */
		hp->r_ctl	= R_CTL_ELS_REQ;
		hp->type	= FC_TYPE_EXTENDED_LS;
		hp->f_ctl	= F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
		hp->seq_id	= 0;
		hp->rsvd	= 0;
		hp->df_ctl	= 0;
		hp->seq_cnt	= 0;
		hp->ox_id	= 0xffff;		/* i.e. none */
		hp->rx_id	= 0xffff;		/* i.e. none */
		hp->ro		= 0;

		/*
		 * Setup PLOGI
		 */
		bzero(&logi, sizeof (struct la_els_logi));
		logi.ls_code.ls_code = LA_ELS_PLOGI;

		FCP_CP_OUT((uint8_t *)&logi, fpkt->pkt_cmd,
		    fpkt->pkt_cmd_acc, sizeof (struct la_els_logi));

		/*
		 * Send PLOGI
		 */
		*fc_status = login_retval =
		    fc_ulp_login(pptr->port_fp_handle, &fpkt, 1);
		if (*fc_status != FC_SUCCESS) {
			ret = EIO;
		}
	}

	/*
	 * Wait for completion
	 */
	if ((ret == 0) && (login_retval == FC_SUCCESS)) {
		ret = fcp_ipkt_sema_wait(icmd);

		*fc_pkt_state	= fpkt->pkt_state;
		*fc_pkt_reason	= fpkt->pkt_reason;
		*fc_pkt_action	= fpkt->pkt_action;
	}

	/*
	 * Cleanup transport data structures if icmd was alloc-ed AND if there
	 * is going to be no callback (i.e if fc_ulp_login() failed).
	 * Otherwise, cleanup happens in callback routine.
	 */
	if (icmd != NULL) {
		fcp_ipkt_sema_cleanup(icmd);
	}

	return (ret);
}

/*
 *     Function: fcp_tgt_send_prli
 *
 *  Description: Does nothing as of today.
 *
 *     Argument: ptgt		Target to send the prli to.
 *		 fc_status	Status returned by fp/fctl in the PRLI request.
 *		 fc_pkt_state	State returned by fp/fctl in the PRLI request.
 *		 fc_pkt_reason	Reason returned by fp/fctl in the PRLI request.
 *		 fc_pkt_action	Action returned by fp/fctl in the PRLI request.
 *
 * Return Value: 0
 */
/*ARGSUSED*/
static int
fcp_tgt_send_prli(struct fcp_tgt *ptgt, int *fc_status, int *fc_pkt_state,
    int *fc_pkt_reason, int *fc_pkt_action)
{
	return (0);
}

/*
 *     Function: fcp_ipkt_sema_init
 *
 *  Description: Initializes the semaphore contained in the internal packet.
 *
 *     Argument: icmd	Internal packet the semaphore of which must be
 *			initialized.
 *
 * Return Value: None
 *
 *	Context: User context only.
 */
static void
fcp_ipkt_sema_init(struct fcp_ipkt *icmd)
{
	struct fc_packet	*fpkt;

	fpkt = icmd->ipkt_fpkt;

	/* Create semaphore for sync */
	sema_init(&(icmd->ipkt_sema), 0, NULL, SEMA_DRIVER, NULL);

	/* Setup the completion callback */
	fpkt->pkt_comp = fcp_ipkt_sema_callback;
}

/*
 *     Function: fcp_ipkt_sema_wait
 *
 *  Description: Wait on the semaphore embedded in the internal packet.	 The
 *		 semaphore is released in the callback.
 *
 *     Argument: icmd	Internal packet to wait on for completion.
 *
 * Return Value: 0
 *		 EIO
 *		 EBUSY
 *		 EAGAIN
 *
 *	Context: User context only.
 *
 * This function does a conversion between the field pkt_state of the fc_packet
 * embedded in the internal packet (icmd) and the code it returns.
 */
static int
fcp_ipkt_sema_wait(struct fcp_ipkt *icmd)
{
	struct fc_packet	*fpkt;
	int	ret;

	ret = EIO;
	fpkt = icmd->ipkt_fpkt;

	/*
	 * Wait on semaphore
	 */
	sema_p(&(icmd->ipkt_sema));

	/*
	 * Check the status of the FC packet
	 */
	switch (fpkt->pkt_state) {
	case FC_PKT_SUCCESS:
		ret = 0;
		break;
	case FC_PKT_LOCAL_RJT:
		switch (fpkt->pkt_reason) {
		case FC_REASON_SEQ_TIMEOUT:
		case FC_REASON_RX_BUF_TIMEOUT:
			ret = EAGAIN;
			break;
		case FC_REASON_PKT_BUSY:
			ret = EBUSY;
			break;
		}
		break;
	case FC_PKT_TIMEOUT:
		ret = EAGAIN;
		break;
	case FC_PKT_LOCAL_BSY:
	case FC_PKT_TRAN_BSY:
	case FC_PKT_NPORT_BSY:
	case FC_PKT_FABRIC_BSY:
		ret = EBUSY;
		break;
	case FC_PKT_LS_RJT:
	case FC_PKT_BA_RJT:
		switch (fpkt->pkt_reason) {
		case FC_REASON_LOGICAL_BSY:
			ret = EBUSY;
			break;
		}
		break;
	case FC_PKT_FS_RJT:
		switch (fpkt->pkt_reason) {
		case FC_REASON_FS_LOGICAL_BUSY:
			ret = EBUSY;
			break;
		}
		break;
	}

	return (ret);
}

/*
 *     Function: fcp_ipkt_sema_callback
 *
 *  Description: Registered as the completion callback function for the FC
 *		 transport when the ipkt semaphore is used for sync. This will
 *		 cleanup the used data structures, if necessary and wake up
 *		 the user thread to complete the transaction.
 *
 *     Argument: fpkt	FC packet (points to the icmd)
 *
 * Return Value: None
 *
 *	Context: User context only
 */
static void
fcp_ipkt_sema_callback(struct fc_packet *fpkt)
{
	struct fcp_ipkt	*icmd;

	icmd = (struct fcp_ipkt *)fpkt->pkt_ulp_private;

	/*
	 * Wake up user thread
	 */
	sema_v(&(icmd->ipkt_sema));
}

/*
 *     Function: fcp_ipkt_sema_cleanup
 *
 *  Description: Called to cleanup (if necessary) the data structures used
 *		 when ipkt sema is used for sync.  This function will detect
 *		 whether the caller is the last thread (via counter) and
 *		 cleanup only if necessary.
 *
 *     Argument: icmd	Internal command packet
 *
 * Return Value: None
 *
 *	Context: User context only
 */
static void
fcp_ipkt_sema_cleanup(struct fcp_ipkt *icmd)
{
	struct fcp_tgt	*ptgt;
	struct fcp_port	*pptr;

	ptgt = icmd->ipkt_tgt;
	pptr = icmd->ipkt_port;

	/*
	 * Acquire data structure
	 */
	mutex_enter(&ptgt->tgt_mutex);

	/*
	 * Destroy semaphore
	 */
	sema_destroy(&(icmd->ipkt_sema));

	/*
	 * Cleanup internal packet
	 */
	mutex_exit(&ptgt->tgt_mutex);
	fcp_icmd_free(pptr, icmd);
}

/*
 *     Function: fcp_port_attach
 *
 *  Description: Called by the transport framework to resume, suspend or
 *		 attach a new port.
 *
 *     Argument: ulph		Port handle
 *		 *pinfo		Port information
 *		 cmd		Command
 *		 s_id		Port ID
 *
 * Return Value: FC_FAILURE or FC_SUCCESS
 */
/*ARGSUSED*/
static int
fcp_port_attach(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    fc_attach_cmd_t cmd, uint32_t s_id)
{
	int	instance;
	int	res = FC_FAILURE; /* default result */

	ASSERT(pinfo != NULL);

	instance = ddi_get_instance(pinfo->port_dip);

	switch (cmd) {
	case FC_CMD_ATTACH:
		/*
		 * this port instance attaching for the first time (or after
		 * being detached before)
		 */
		if (fcp_handle_port_attach(ulph, pinfo, s_id,
		    instance) == DDI_SUCCESS) {
			res = FC_SUCCESS;
		} else {
			ASSERT(ddi_get_soft_state(fcp_softstate,
			    instance) == NULL);
		}
		break;

	case FC_CMD_RESUME:
	case FC_CMD_POWER_UP:
		/*
		 * this port instance was attached and the suspended and
		 * will now be resumed
		 */
		if (fcp_handle_port_resume(ulph, pinfo, s_id, cmd,
		    instance) == DDI_SUCCESS) {
			res = FC_SUCCESS;
		}
		break;

	default:
		/* shouldn't happen */
		FCP_TRACE(fcp_logq, "fcp",
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "port_attach: unknown cmdcommand: %d", cmd);
		break;
	}

	/* return result */
	FCP_DTRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_1, 0, "fcp_port_attach returning %d", res);

	return (res);
}


/*
 * detach or suspend this port instance
 *
 * acquires and releases the global mutex
 *
 * acquires and releases the mutex for this port
 *
 * acquires and releases the hotplug mutex for this port
 */
/*ARGSUSED*/
static int
fcp_port_detach(opaque_t ulph, fc_ulp_port_info_t *info,
    fc_detach_cmd_t cmd)
{
	int			flag;
	int			instance;
	struct fcp_port		*pptr;

	instance = ddi_get_instance(info->port_dip);
	pptr = ddi_get_soft_state(fcp_softstate, instance);

	switch (cmd) {
	case FC_CMD_SUSPEND:
		FCP_DTRACE(fcp_logq, "fcp",
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "port suspend called for port %d", instance);
		flag = FCP_STATE_SUSPENDED;
		break;

	case FC_CMD_POWER_DOWN:
		FCP_DTRACE(fcp_logq, "fcp",
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "port power down called for port %d", instance);
		flag = FCP_STATE_POWER_DOWN;
		break;

	case FC_CMD_DETACH:
		FCP_DTRACE(fcp_logq, "fcp",
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "port detach called for port %d", instance);
		flag = FCP_STATE_DETACHING;
		break;

	default:
		/* shouldn't happen */
		return (FC_FAILURE);
	}
	FCP_DTRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_1, 0, "fcp_port_detach returning");

	return (fcp_handle_port_detach(pptr, flag, instance));
}


/*
 * called for ioctls on the transport's devctl interface, and the transport
 * has passed it to us
 *
 * this will only be called for device control ioctls (i.e. hotplugging stuff)
 *
 * return FC_SUCCESS if we decide to claim the ioctl,
 * else return FC_UNCLAIMED
 *
 * *rval is set iff we decide to claim the ioctl
 */
/*ARGSUSED*/
static int
fcp_port_ioctl(opaque_t ulph, opaque_t port_handle, dev_t dev, int cmd,
    intptr_t data, int mode, cred_t *credp, int *rval, uint32_t claimed)
{
	int			retval = FC_UNCLAIMED;	/* return value */
	struct fcp_port		*pptr = NULL;		/* our soft state */
	struct devctl_iocdata	*dcp = NULL;		/* for devctl */
	dev_info_t		*cdip;
	mdi_pathinfo_t		*pip = NULL;
	char			*ndi_nm;		/* NDI name */
	char			*ndi_addr;		/* NDI addr */
	int			is_mpxio, circ;
	int			devi_entered = 0;
	clock_t			end_time;

	ASSERT(rval != NULL);

	FCP_DTRACE(fcp_logq, "fcp",
	    fcp_trace, FCP_BUF_LEVEL_8, 0,
	    "fcp_port_ioctl(cmd=0x%x, claimed=%d)", cmd, claimed);

	/* if already claimed then forget it */
	if (claimed) {
		/*
		 * for now, if this ioctl has already been claimed, then
		 * we just ignore it
		 */
		return (retval);
	}

	/* get our port info */
	if ((pptr = fcp_get_port(port_handle)) == NULL) {
		fcp_log(CE_WARN, NULL,
		    "!fcp:Invalid port handle handle in ioctl");
		*rval = ENXIO;
		return (retval);
	}
	is_mpxio = pptr->port_mpxio;

	switch (cmd) {
	case DEVCTL_BUS_GETSTATE:
	case DEVCTL_BUS_QUIESCE:
	case DEVCTL_BUS_UNQUIESCE:
	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:

	case DEVCTL_BUS_DEV_CREATE:
		if (ndi_dc_allochdl((void *)data, &dcp) != NDI_SUCCESS) {
			return (retval);
		}
		break;

	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_DEVICE_RESET:
		if (ndi_dc_allochdl((void *)data, &dcp) != NDI_SUCCESS) {
			return (retval);
		}

		ASSERT(dcp != NULL);

		/* ensure we have a name and address */
		if (((ndi_nm = ndi_dc_getname(dcp)) == NULL) ||
		    ((ndi_addr = ndi_dc_getaddr(dcp)) == NULL)) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "ioctl: can't get name (%s) or addr (%s)",
			    ndi_nm ? ndi_nm : "<null ptr>",
			    ndi_addr ? ndi_addr : "<null ptr>");
			ndi_dc_freehdl(dcp);
			return (retval);
		}


		/* get our child's DIP */
		ASSERT(pptr != NULL);
		if (is_mpxio) {
			mdi_devi_enter(pptr->port_dip, &circ);
		} else {
			ndi_devi_enter(pptr->port_dip, &circ);
		}
		devi_entered = 1;

		if ((cdip = ndi_devi_find(pptr->port_dip, ndi_nm,
		    ndi_addr)) == NULL) {
			/* Look for virtually enumerated devices. */
			pip = mdi_pi_find(pptr->port_dip, NULL, ndi_addr);
			if (pip == NULL ||
			    ((cdip = mdi_pi_get_client(pip)) == NULL)) {
				*rval = ENXIO;
				goto out;
			}
		}
		break;

	default:
		*rval = ENOTTY;
		return (retval);
	}

	/* this ioctl is ours -- process it */

	retval = FC_SUCCESS;		/* just means we claim the ioctl */

	/* we assume it will be a success; else we'll set error value */
	*rval = 0;


	FCP_DTRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_8, 0,
	    "ioctl: claiming this one");

	/* handle ioctls now */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
		ASSERT(cdip != NULL);
		ASSERT(dcp != NULL);
		if (ndi_dc_return_dev_state(cdip, dcp) != NDI_SUCCESS) {
			*rval = EFAULT;
		}
		break;

	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_DEVICE_OFFLINE: {
		int			flag = 0;
		int			lcount;
		int			tcount;
		struct fcp_pkt	*head = NULL;
		struct fcp_lun	*plun;
		child_info_t		*cip = CIP(cdip);
		int			all = 1;
		struct fcp_lun	*tplun;
		struct fcp_tgt	*ptgt;

		ASSERT(pptr != NULL);
		ASSERT(cdip != NULL);

		mutex_enter(&pptr->port_mutex);
		if (pip != NULL) {
			cip = CIP(pip);
		}
		if ((plun = fcp_get_lun_from_cip(pptr, cip)) == NULL) {
			mutex_exit(&pptr->port_mutex);
			*rval = ENXIO;
			break;
		}

		head = fcp_scan_commands(plun);
		if (head != NULL) {
			fcp_abort_commands(head, LUN_PORT);
		}
		lcount = pptr->port_link_cnt;
		tcount = plun->lun_tgt->tgt_change_cnt;
		mutex_exit(&pptr->port_mutex);

		if (cmd == DEVCTL_DEVICE_REMOVE) {
			flag = NDI_DEVI_REMOVE;
		}

		if (is_mpxio) {
			mdi_devi_exit(pptr->port_dip, circ);
		} else {
			ndi_devi_exit(pptr->port_dip, circ);
		}
		devi_entered = 0;

		*rval = fcp_pass_to_hp_and_wait(pptr, plun, cip,
		    FCP_OFFLINE, lcount, tcount, flag);

		if (*rval != NDI_SUCCESS) {
			*rval = (*rval == NDI_BUSY) ? EBUSY : EIO;
			break;
		}

		fcp_update_offline_flags(plun);

		ptgt = plun->lun_tgt;
		mutex_enter(&ptgt->tgt_mutex);
		for (tplun = ptgt->tgt_lun; tplun != NULL; tplun =
		    tplun->lun_next) {
			mutex_enter(&tplun->lun_mutex);
			if (!(tplun->lun_state & FCP_LUN_OFFLINE)) {
				all = 0;
			}
			mutex_exit(&tplun->lun_mutex);
		}

		if (all) {
			ptgt->tgt_node_state = FCP_TGT_NODE_NONE;
			/*
			 * The user is unconfiguring/offlining the device.
			 * If fabric and the auto configuration is set
			 * then make sure the user is the only one who
			 * can reconfigure the device.
			 */
			if (FC_TOP_EXTERNAL(pptr->port_topology) &&
			    fcp_enable_auto_configuration) {
				ptgt->tgt_manual_config_only = 1;
			}
		}
		mutex_exit(&ptgt->tgt_mutex);
		break;
	}

	case DEVCTL_DEVICE_ONLINE: {
		int			lcount;
		int			tcount;
		struct fcp_lun	*plun;
		child_info_t		*cip = CIP(cdip);

		ASSERT(cdip != NULL);
		ASSERT(pptr != NULL);

		mutex_enter(&pptr->port_mutex);
		if (pip != NULL) {
			cip = CIP(pip);
		}
		if ((plun = fcp_get_lun_from_cip(pptr, cip)) == NULL) {
			mutex_exit(&pptr->port_mutex);
			*rval = ENXIO;
			break;
		}
		lcount = pptr->port_link_cnt;
		tcount = plun->lun_tgt->tgt_change_cnt;
		mutex_exit(&pptr->port_mutex);

		/*
		 * The FCP_LUN_ONLINING flag is used in fcp_scsi_start()
		 * to allow the device attach to occur when the device is
		 * FCP_LUN_OFFLINE (so we don't reject the INQUIRY command
		 * from the scsi_probe()).
		 */
		mutex_enter(&LUN_TGT->tgt_mutex);
		plun->lun_state |= FCP_LUN_ONLINING;
		mutex_exit(&LUN_TGT->tgt_mutex);

		if (is_mpxio) {
			mdi_devi_exit(pptr->port_dip, circ);
		} else {
			ndi_devi_exit(pptr->port_dip, circ);
		}
		devi_entered = 0;

		*rval = fcp_pass_to_hp_and_wait(pptr, plun, cip,
		    FCP_ONLINE, lcount, tcount, 0);

		if (*rval != NDI_SUCCESS) {
			/* Reset the FCP_LUN_ONLINING bit */
			mutex_enter(&LUN_TGT->tgt_mutex);
			plun->lun_state &= ~FCP_LUN_ONLINING;
			mutex_exit(&LUN_TGT->tgt_mutex);
			*rval = EIO;
			break;
		}
		mutex_enter(&LUN_TGT->tgt_mutex);
		plun->lun_state &= ~(FCP_LUN_OFFLINE | FCP_LUN_BUSY |
		    FCP_LUN_ONLINING);
		mutex_exit(&LUN_TGT->tgt_mutex);
		break;
	}

	case DEVCTL_BUS_DEV_CREATE: {
		uchar_t			*bytes = NULL;
		uint_t			nbytes;
		struct fcp_tgt		*ptgt = NULL;
		struct fcp_lun		*plun = NULL;
		dev_info_t		*useless_dip = NULL;

		*rval = ndi_dc_devi_create(dcp, pptr->port_dip,
		    DEVCTL_CONSTRUCT, &useless_dip);
		if (*rval != 0 || useless_dip == NULL) {
			break;
		}

		if ((ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, useless_dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, PORT_WWN_PROP, &bytes,
		    &nbytes) != DDI_PROP_SUCCESS) || nbytes != FC_WWN_SIZE) {
			*rval = EINVAL;
			(void) ndi_devi_free(useless_dip);
			if (bytes != NULL) {
				ddi_prop_free(bytes);
			}
			break;
		}

		*rval = fcp_create_on_demand(pptr, bytes);
		if (*rval == 0) {
			mutex_enter(&pptr->port_mutex);
			ptgt = fcp_lookup_target(pptr, (uchar_t *)bytes);
			if (ptgt) {
				/*
				 * We now have a pointer to the target that
				 * was created. Lets point to the first LUN on
				 * this new target.
				 */
				mutex_enter(&ptgt->tgt_mutex);

				plun = ptgt->tgt_lun;
				/*
				 * There may be stale/offline LUN entries on
				 * this list (this is by design) and so we have
				 * to make sure we point to the first online
				 * LUN
				 */
				while (plun &&
				    plun->lun_state & FCP_LUN_OFFLINE) {
					plun = plun->lun_next;
				}

				mutex_exit(&ptgt->tgt_mutex);
			}
			mutex_exit(&pptr->port_mutex);
		}

		if (*rval == 0 && ptgt && plun) {
			mutex_enter(&plun->lun_mutex);
			/*
			 * Allow up to fcp_lun_ready_retry seconds to
			 * configure all the luns behind the target.
			 *
			 * The intent here is to allow targets with long
			 * reboot/reset-recovery times to become available
			 * while limiting the maximum wait time for an
			 * unresponsive target.
			 */
			end_time = ddi_get_lbolt() +
			    SEC_TO_TICK(fcp_lun_ready_retry);

			while (ddi_get_lbolt() < end_time) {
				retval = FC_SUCCESS;

				/*
				 * The new ndi interfaces for on-demand creation
				 * are inflexible, Do some more work to pass on
				 * a path name of some LUN (design is broken !)
				 */
				if (plun->lun_cip) {
					if (plun->lun_mpxio == 0) {
						cdip = DIP(plun->lun_cip);
					} else {
						cdip = mdi_pi_get_client(
						    PIP(plun->lun_cip));
					}
					if (cdip == NULL) {
						*rval = ENXIO;
						break;
					}

					if (!i_ddi_devi_attached(cdip)) {
						mutex_exit(&plun->lun_mutex);
						delay(drv_usectohz(1000000));
						mutex_enter(&plun->lun_mutex);
					} else {
						/*
						 * This Lun is ready, lets
						 * check the next one.
						 */
						mutex_exit(&plun->lun_mutex);
						plun = plun->lun_next;
						while (plun && (plun->lun_state
						    & FCP_LUN_OFFLINE)) {
							plun = plun->lun_next;
						}
						if (!plun) {
							break;
						}
						mutex_enter(&plun->lun_mutex);
					}
				} else {
					/*
					 * lun_cip field for a valid lun
					 * should never be NULL. Fail the
					 * command.
					 */
					*rval = ENXIO;
					break;
				}
			}
			if (plun) {
				mutex_exit(&plun->lun_mutex);
			} else {
				char devnm[MAXNAMELEN];
				int nmlen;

				nmlen = snprintf(devnm, MAXNAMELEN, "%s@%s",
				    ddi_node_name(cdip),
				    ddi_get_name_addr(cdip));

				if (copyout(&devnm, dcp->cpyout_buf, nmlen) !=
				    0) {
					*rval = EFAULT;
				}
			}
		} else {
			int	i;
			char	buf[25];

			for (i = 0; i < FC_WWN_SIZE; i++) {
				(void) sprintf(&buf[i << 1], "%02x", bytes[i]);
			}

			fcp_log(CE_WARN, pptr->port_dip,
			    "!Failed to create nodes for pwwn=%s; error=%x",
			    buf, *rval);
		}

		(void) ndi_devi_free(useless_dip);
		ddi_prop_free(bytes);
		break;
	}

	case DEVCTL_DEVICE_RESET: {
		struct fcp_lun		*plun;
		child_info_t		*cip = CIP(cdip);

		ASSERT(cdip != NULL);
		ASSERT(pptr != NULL);
		mutex_enter(&pptr->port_mutex);
		if (pip != NULL) {
			cip = CIP(pip);
		}
		if ((plun = fcp_get_lun_from_cip(pptr, cip)) == NULL) {
			mutex_exit(&pptr->port_mutex);
			*rval = ENXIO;
			break;
		}
		mutex_exit(&pptr->port_mutex);

		mutex_enter(&plun->lun_tgt->tgt_mutex);
		if (!(plun->lun_state & FCP_SCSI_LUN_TGT_INIT)) {
			mutex_exit(&plun->lun_tgt->tgt_mutex);

			*rval = ENXIO;
			break;
		}

		if (plun->lun_sd == NULL) {
			mutex_exit(&plun->lun_tgt->tgt_mutex);

			*rval = ENXIO;
			break;
		}
		mutex_exit(&plun->lun_tgt->tgt_mutex);

		/*
		 * set up ap so that fcp_reset can figure out
		 * which target to reset
		 */
		if (fcp_scsi_reset(&plun->lun_sd->sd_address,
		    RESET_TARGET) == FALSE) {
			*rval = EIO;
		}
		break;
	}

	case DEVCTL_BUS_GETSTATE:
		ASSERT(dcp != NULL);
		ASSERT(pptr != NULL);
		ASSERT(pptr->port_dip != NULL);
		if (ndi_dc_return_bus_state(pptr->port_dip, dcp) !=
		    NDI_SUCCESS) {
			*rval = EFAULT;
		}
		break;

	case DEVCTL_BUS_QUIESCE:
	case DEVCTL_BUS_UNQUIESCE:
		*rval = ENOTSUP;
		break;

	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
		ASSERT(pptr != NULL);
		(void) fcp_linkreset(pptr, NULL,  KM_SLEEP);
		break;

	default:
		ASSERT(dcp != NULL);
		*rval = ENOTTY;
		break;
	}

	/* all done -- clean up and return */
out:	if (devi_entered) {
		if (is_mpxio) {
			mdi_devi_exit(pptr->port_dip, circ);
		} else {
			ndi_devi_exit(pptr->port_dip, circ);
		}
	}

	if (dcp != NULL) {
		ndi_dc_freehdl(dcp);
	}

	return (retval);
}


/*ARGSUSED*/
static int
fcp_els_callback(opaque_t ulph, opaque_t port_handle, fc_unsol_buf_t *buf,
    uint32_t claimed)
{
	uchar_t			r_ctl;
	uchar_t			ls_code;
	struct fcp_port	*pptr;

	if ((pptr = fcp_get_port(port_handle)) == NULL || claimed) {
		return (FC_UNCLAIMED);
	}

	mutex_enter(&pptr->port_mutex);
	if (pptr->port_state & (FCP_STATE_DETACHING |
	    FCP_STATE_SUSPENDED | FCP_STATE_POWER_DOWN)) {
		mutex_exit(&pptr->port_mutex);
		return (FC_UNCLAIMED);
	}
	mutex_exit(&pptr->port_mutex);

	r_ctl = buf->ub_frame.r_ctl;

	switch (r_ctl & R_CTL_ROUTING) {
	case R_CTL_EXTENDED_SVC:
		if (r_ctl == R_CTL_ELS_REQ) {
			ls_code = buf->ub_buffer[0];

			switch (ls_code) {
			case LA_ELS_PRLI:
				/*
				 * We really don't care if something fails.
				 * If the PRLI was not sent out, then the
				 * other end will time it out.
				 */
				if (fcp_unsol_prli(pptr, buf) == FC_SUCCESS) {
					return (FC_SUCCESS);
				}
				return (FC_UNCLAIMED);
				/* NOTREACHED */

			default:
				break;
			}
		}
		/* FALLTHROUGH */

	default:
		return (FC_UNCLAIMED);
	}
}


/*ARGSUSED*/
static int
fcp_data_callback(opaque_t ulph, opaque_t port_handle, fc_unsol_buf_t *buf,
    uint32_t claimed)
{
	return (FC_UNCLAIMED);
}

/*
 *     Function: fcp_statec_callback
 *
 *  Description: The purpose of this function is to handle a port state change.
 *		 It is called from fp/fctl and, in a few instances, internally.
 *
 *     Argument: ulph		fp/fctl port handle
 *		 port_handle	fcp_port structure
 *		 port_state	Physical state of the port
 *		 port_top	Topology
 *		 *devlist	Pointer to the first entry of a table
 *				containing the remote ports that can be
 *				reached.
 *		 dev_cnt	Number of entries pointed by devlist.
 *		 port_sid	Port ID of the local port.
 *
 * Return Value: None
 */
/*ARGSUSED*/
static void
fcp_statec_callback(opaque_t ulph, opaque_t port_handle,
    uint32_t port_state, uint32_t port_top, fc_portmap_t *devlist,
    uint32_t dev_cnt, uint32_t port_sid)
{
	uint32_t		link_count;
	int			map_len = 0;
	struct fcp_port	*pptr;
	fcp_map_tag_t		*map_tag = NULL;

	if ((pptr = fcp_get_port(port_handle)) == NULL) {
		fcp_log(CE_WARN, NULL, "!Invalid port handle in callback");
		return;			/* nothing to work with! */
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_2, 0,
	    "fcp_statec_callback: port state/dev_cnt/top ="
	    "%d/%d/%d", FC_PORT_STATE_MASK(port_state),
	    dev_cnt, port_top);

	mutex_enter(&pptr->port_mutex);

	/*
	 * If a thread is in detach, don't do anything.
	 */
	if (pptr->port_state & (FCP_STATE_DETACHING |
	    FCP_STATE_SUSPENDED | FCP_STATE_POWER_DOWN)) {
		mutex_exit(&pptr->port_mutex);
		return;
	}

	/*
	 * First thing we do is set the FCP_STATE_IN_CB_DEVC flag so that if
	 * init_pkt is called, it knows whether or not the target's status
	 * (or pd) might be changing.
	 */

	if (FC_PORT_STATE_MASK(port_state) == FC_STATE_DEVICE_CHANGE) {
		pptr->port_state |= FCP_STATE_IN_CB_DEVC;
	}

	/*
	 * the transport doesn't allocate or probe unless being
	 * asked to by either the applications or ULPs
	 *
	 * in cases where the port is OFFLINE at the time of port
	 * attach callback and the link comes ONLINE later, for
	 * easier automatic node creation (i.e. without you having to
	 * go out and run the utility to perform LOGINs) the
	 * following conditional is helpful
	 */
	pptr->port_phys_state = port_state;

	if (dev_cnt) {
		mutex_exit(&pptr->port_mutex);

		map_len = sizeof (*map_tag) * dev_cnt;
		map_tag = kmem_alloc(map_len, KM_NOSLEEP);
		if (map_tag == NULL) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!fcp%d: failed to allocate for map tags; "
			    " state change will not be processed",
			    pptr->port_instance);

			mutex_enter(&pptr->port_mutex);
			pptr->port_state &= ~FCP_STATE_IN_CB_DEVC;
			mutex_exit(&pptr->port_mutex);

			return;
		}

		mutex_enter(&pptr->port_mutex);
	}

	if (pptr->port_id != port_sid) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "fcp: Port S_ID=0x%x => 0x%x", pptr->port_id,
		    port_sid);
		/*
		 * The local port changed ID. It is the first time a port ID
		 * is assigned or something drastic happened.  We might have
		 * been unplugged and replugged on another loop or fabric port
		 * or somebody grabbed the AL_PA we had or somebody rezoned
		 * the fabric we were plugged into.
		 */
		pptr->port_id = port_sid;
	}

	switch (FC_PORT_STATE_MASK(port_state)) {
	case FC_STATE_OFFLINE:
	case FC_STATE_RESET_REQUESTED:
		/*
		 * link has gone from online to offline -- just update the
		 * state of this port to BUSY and MARKed to go offline
		 */
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "link went offline");
		if ((pptr->port_state & FCP_STATE_OFFLINE) && dev_cnt) {
			/*
			 * We were offline a while ago and this one
			 * seems to indicate that the loop has gone
			 * dead forever.
			 */
			pptr->port_tmp_cnt += dev_cnt;
			pptr->port_state &= ~FCP_STATE_OFFLINE;
			pptr->port_state |= FCP_STATE_INIT;
			link_count = pptr->port_link_cnt;
			fcp_handle_devices(pptr, devlist, dev_cnt,
			    link_count, map_tag, FCP_CAUSE_LINK_DOWN);
		} else {
			pptr->port_link_cnt++;
			ASSERT(!(pptr->port_state & FCP_STATE_SUSPENDED));
			fcp_update_state(pptr, (FCP_LUN_BUSY |
			    FCP_LUN_MARK), FCP_CAUSE_LINK_DOWN);
			if (pptr->port_mpxio) {
				fcp_update_mpxio_path_verifybusy(pptr);
			}
			pptr->port_state |= FCP_STATE_OFFLINE;
			pptr->port_state &=
			    ~(FCP_STATE_ONLINING | FCP_STATE_ONLINE);
			pptr->port_tmp_cnt = 0;
		}
		mutex_exit(&pptr->port_mutex);
		break;

	case FC_STATE_ONLINE:
	case FC_STATE_LIP:
	case FC_STATE_LIP_LBIT_SET:
		/*
		 * link has gone from offline to online
		 */
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "link went online");

		pptr->port_link_cnt++;

		while (pptr->port_ipkt_cnt) {
			mutex_exit(&pptr->port_mutex);
			delay(drv_usectohz(1000000));
			mutex_enter(&pptr->port_mutex);
		}

		pptr->port_topology = port_top;

		/*
		 * The state of the targets and luns accessible through this
		 * port is updated.
		 */
		fcp_update_state(pptr, FCP_LUN_BUSY | FCP_LUN_MARK,
		    FCP_CAUSE_LINK_CHANGE);

		pptr->port_state &= ~(FCP_STATE_INIT | FCP_STATE_OFFLINE);
		pptr->port_state |= FCP_STATE_ONLINING;
		pptr->port_tmp_cnt = dev_cnt;
		link_count = pptr->port_link_cnt;

		pptr->port_deadline = fcp_watchdog_time +
		    FCP_ICMD_DEADLINE;

		if (!dev_cnt) {
			/*
			 * We go directly to the online state if no remote
			 * ports were discovered.
			 */
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "No remote ports discovered");

			pptr->port_state &= ~FCP_STATE_ONLINING;
			pptr->port_state |= FCP_STATE_ONLINE;
		}

		switch (port_top) {
		case FC_TOP_FABRIC:
		case FC_TOP_PUBLIC_LOOP:
		case FC_TOP_PRIVATE_LOOP:
		case FC_TOP_PT_PT:

			if (pptr->port_state & FCP_STATE_NS_REG_FAILED) {
				fcp_retry_ns_registry(pptr, port_sid);
			}

			fcp_handle_devices(pptr, devlist, dev_cnt, link_count,
			    map_tag, FCP_CAUSE_LINK_CHANGE);
			break;

		default:
			/*
			 * We got here because we were provided with an unknown
			 * topology.
			 */
			if (pptr->port_state & FCP_STATE_NS_REG_FAILED) {
				pptr->port_state &= ~FCP_STATE_NS_REG_FAILED;
			}

			pptr->port_tmp_cnt -= dev_cnt;
			fcp_log(CE_WARN, pptr->port_dip,
			    "!unknown/unsupported topology (0x%x)", port_top);
			break;
		}
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "Notify ssd of the reset to reinstate the reservations");

		scsi_hba_reset_notify_callback(&pptr->port_mutex,
		    &pptr->port_reset_notify_listf);

		mutex_exit(&pptr->port_mutex);

		break;

	case FC_STATE_RESET:
		ASSERT(pptr->port_state & FCP_STATE_OFFLINE);
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "RESET state, waiting for Offline/Online state_cb");
		mutex_exit(&pptr->port_mutex);
		break;

	case FC_STATE_DEVICE_CHANGE:
		/*
		 * We come here when an application has requested
		 * Dynamic node creation/deletion in Fabric connectivity.
		 */
		if (pptr->port_state & (FCP_STATE_OFFLINE |
		    FCP_STATE_INIT)) {
			/*
			 * This case can happen when the FCTL is in the
			 * process of giving us on online and the host on
			 * the other side issues a PLOGI/PLOGO. Ideally
			 * the state changes should be serialized unless
			 * they are opposite (online-offline).
			 * The transport will give us a final state change
			 * so we can ignore this for the time being.
			 */
			pptr->port_state &= ~FCP_STATE_IN_CB_DEVC;
			mutex_exit(&pptr->port_mutex);
			break;
		}

		if (pptr->port_state & FCP_STATE_NS_REG_FAILED) {
			fcp_retry_ns_registry(pptr, port_sid);
		}

		/*
		 * Extend the deadline under steady state conditions
		 * to provide more time for the device-change-commands
		 */
		if (!pptr->port_ipkt_cnt) {
			pptr->port_deadline = fcp_watchdog_time +
			    FCP_ICMD_DEADLINE;
		}

		/*
		 * There is another race condition here, where if we were
		 * in ONLINEING state and a devices in the map logs out,
		 * fp will give another state change as DEVICE_CHANGE
		 * and OLD. This will result in that target being offlined.
		 * The pd_handle is freed. If from the first statec callback
		 * we were going to fire a PLOGI/PRLI, the system will
		 * panic in fc_ulp_transport with invalid pd_handle.
		 * The fix is to check for the link_cnt before issuing
		 * any command down.
		 */
		fcp_update_targets(pptr, devlist, dev_cnt,
		    FCP_LUN_BUSY | FCP_LUN_MARK, FCP_CAUSE_TGT_CHANGE);

		link_count = pptr->port_link_cnt;

		fcp_handle_devices(pptr, devlist, dev_cnt,
		    link_count, map_tag, FCP_CAUSE_TGT_CHANGE);

		pptr->port_state &= ~FCP_STATE_IN_CB_DEVC;

		mutex_exit(&pptr->port_mutex);
		break;

	case FC_STATE_TARGET_PORT_RESET:
		if (pptr->port_state & FCP_STATE_NS_REG_FAILED) {
			fcp_retry_ns_registry(pptr, port_sid);
		}

		/* Do nothing else */
		mutex_exit(&pptr->port_mutex);
		break;

	default:
		fcp_log(CE_WARN, pptr->port_dip,
		    "!Invalid state change=0x%x", port_state);
		mutex_exit(&pptr->port_mutex);
		break;
	}

	if (map_tag) {
		kmem_free(map_tag, map_len);
	}
}

/*
 *     Function: fcp_handle_devices
 *
 *  Description: This function updates the devices currently known by
 *		 walking the list provided by the caller.  The list passed
 *		 by the caller is supposed to be the list of reachable
 *		 devices.
 *
 *     Argument: *pptr		Fcp port structure.
 *		 *devlist	Pointer to the first entry of a table
 *				containing the remote ports that can be
 *				reached.
 *		 dev_cnt	Number of entries pointed by devlist.
 *		 link_cnt	Link state count.
 *		 *map_tag	Array of fcp_map_tag_t structures.
 *		 cause		What caused this function to be called.
 *
 * Return Value: None
 *
 *	  Notes: The pptr->port_mutex must be held.
 */
static void
fcp_handle_devices(struct fcp_port *pptr, fc_portmap_t devlist[],
    uint32_t dev_cnt, int link_cnt, fcp_map_tag_t *map_tag, int cause)
{
	int			i;
	int			check_finish_init = 0;
	fc_portmap_t		*map_entry;
	struct fcp_tgt	*ptgt = NULL;

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_3, 0,
	    "fcp_handle_devices: called for %d dev(s)", dev_cnt);

	if (dev_cnt) {
		ASSERT(map_tag != NULL);
	}

	/*
	 * The following code goes through the list of remote ports that are
	 * accessible through this (pptr) local port (The list walked is the
	 * one provided by the caller which is the list of the remote ports
	 * currently reachable).  It checks if any of them was already
	 * known by looking for the corresponding target structure based on
	 * the world wide name.	 If a target is part of the list it is tagged
	 * (ptgt->tgt_aux_state = FCP_TGT_TAGGED).
	 *
	 * Old comment
	 * -----------
	 * Before we drop port mutex; we MUST get the tags updated; This
	 * two step process is somewhat slow, but more reliable.
	 */
	for (i = 0; (i < dev_cnt) && (pptr->port_link_cnt == link_cnt); i++) {
		map_entry = &(devlist[i]);

		/*
		 * get ptr to this map entry in our port's
		 * list (if any)
		 */
		ptgt = fcp_lookup_target(pptr,
		    (uchar_t *)&(map_entry->map_pwwn));

		if (ptgt) {
			map_tag[i] = ptgt->tgt_change_cnt;
			if (cause == FCP_CAUSE_LINK_CHANGE) {
				ptgt->tgt_aux_state = FCP_TGT_TAGGED;
			}
		}
	}

	/*
	 * At this point we know which devices of the new list were already
	 * known (The field tgt_aux_state of the target structure has been
	 * set to FCP_TGT_TAGGED).
	 *
	 * The following code goes through the list of targets currently known
	 * by the local port (the list is actually a hashing table).  If a
	 * target is found and is not tagged, it means the target cannot
	 * be reached anymore through the local port (pptr).  It is offlined.
	 * The offlining only occurs if the cause is FCP_CAUSE_LINK_CHANGE.
	 */
	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			mutex_enter(&ptgt->tgt_mutex);
			if ((ptgt->tgt_aux_state != FCP_TGT_TAGGED) &&
			    (cause == FCP_CAUSE_LINK_CHANGE) &&
			    !(ptgt->tgt_state & FCP_TGT_OFFLINE)) {
				fcp_offline_target_now(pptr, ptgt,
				    link_cnt, ptgt->tgt_change_cnt, 0);
			}
			mutex_exit(&ptgt->tgt_mutex);
		}
	}

	/*
	 * At this point, the devices that were known but cannot be reached
	 * anymore, have most likely been offlined.
	 *
	 * The following section of code seems to go through the list of
	 * remote ports that can now be reached.  For every single one it
	 * checks if it is already known or if it is a new port.
	 */
	for (i = 0; (i < dev_cnt) && (pptr->port_link_cnt == link_cnt); i++) {

		if (check_finish_init) {
			ASSERT(i > 0);
			(void) fcp_call_finish_init_held(pptr, ptgt, link_cnt,
			    map_tag[i - 1], cause);
			check_finish_init = 0;
		}

		/* get a pointer to this map entry */
		map_entry = &(devlist[i]);

		/*
		 * Check for the duplicate map entry flag. If we have marked
		 * this entry as a duplicate we skip it since the correct
		 * (perhaps even same) state change will be encountered
		 * later in the list.
		 */
		if (map_entry->map_flags & PORT_DEVICE_DUPLICATE_MAP_ENTRY) {
			continue;
		}

		/* get ptr to this map entry in our port's list (if any) */
		ptgt = fcp_lookup_target(pptr,
		    (uchar_t *)&(map_entry->map_pwwn));

		if (ptgt) {
			/*
			 * This device was already known.  The field
			 * tgt_aux_state is reset (was probably set to
			 * FCP_TGT_TAGGED previously in this routine).
			 */
			ptgt->tgt_aux_state = 0;
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "handle_devices: map did/state/type/flags = "
			    "0x%x/0x%x/0x%x/0x%x, tgt_d_id=0x%x, "
			    "tgt_state=%d",
			    map_entry->map_did.port_id, map_entry->map_state,
			    map_entry->map_type, map_entry->map_flags,
			    ptgt->tgt_d_id, ptgt->tgt_state);
		}

		if (map_entry->map_type == PORT_DEVICE_OLD ||
		    map_entry->map_type == PORT_DEVICE_NEW ||
		    map_entry->map_type == PORT_DEVICE_REPORTLUN_CHANGED ||
		    map_entry->map_type == PORT_DEVICE_CHANGED) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "map_type=%x, did = %x",
			    map_entry->map_type,
			    map_entry->map_did.port_id);
		}

		switch (map_entry->map_type) {
		case PORT_DEVICE_NOCHANGE:
		case PORT_DEVICE_USER_CREATE:
		case PORT_DEVICE_USER_LOGIN:
		case PORT_DEVICE_NEW:
		case PORT_DEVICE_REPORTLUN_CHANGED:
			FCP_TGT_TRACE(ptgt, map_tag[i], FCP_TGT_TRACE_1);

			if (fcp_handle_mapflags(pptr, ptgt, map_entry,
			    link_cnt, (ptgt) ? map_tag[i] : 0,
			    cause) == TRUE) {

				FCP_TGT_TRACE(ptgt, map_tag[i],
				    FCP_TGT_TRACE_2);
				check_finish_init++;
			}
			break;

		case PORT_DEVICE_OLD:
			if (ptgt != NULL) {
				FCP_TGT_TRACE(ptgt, map_tag[i],
				    FCP_TGT_TRACE_3);

				mutex_enter(&ptgt->tgt_mutex);
				if (!(ptgt->tgt_state & FCP_TGT_OFFLINE)) {
					/*
					 * Must do an in-line wait for I/Os
					 * to get drained
					 */
					mutex_exit(&ptgt->tgt_mutex);
					mutex_exit(&pptr->port_mutex);

					mutex_enter(&ptgt->tgt_mutex);
					while (ptgt->tgt_ipkt_cnt ||
					    fcp_outstanding_lun_cmds(ptgt)
					    == FC_SUCCESS) {
						mutex_exit(&ptgt->tgt_mutex);
						delay(drv_usectohz(1000000));
						mutex_enter(&ptgt->tgt_mutex);
					}
					mutex_exit(&ptgt->tgt_mutex);

					mutex_enter(&pptr->port_mutex);
					mutex_enter(&ptgt->tgt_mutex);

					(void) fcp_offline_target(pptr, ptgt,
					    link_cnt, map_tag[i], 0, 0);
				}
				mutex_exit(&ptgt->tgt_mutex);
			}
			check_finish_init++;
			break;

		case PORT_DEVICE_USER_DELETE:
		case PORT_DEVICE_USER_LOGOUT:
			if (ptgt != NULL) {
				FCP_TGT_TRACE(ptgt, map_tag[i],
				    FCP_TGT_TRACE_4);

				mutex_enter(&ptgt->tgt_mutex);
				if (!(ptgt->tgt_state & FCP_TGT_OFFLINE)) {
					(void) fcp_offline_target(pptr, ptgt,
					    link_cnt, map_tag[i], 1, 0);
				}
				mutex_exit(&ptgt->tgt_mutex);
			}
			check_finish_init++;
			break;

		case PORT_DEVICE_CHANGED:
			if (ptgt != NULL) {
				FCP_TGT_TRACE(ptgt, map_tag[i],
				    FCP_TGT_TRACE_5);

				if (fcp_device_changed(pptr, ptgt,
				    map_entry, link_cnt, map_tag[i],
				    cause) == TRUE) {
					check_finish_init++;
				}
			} else {
				if (fcp_handle_mapflags(pptr, ptgt,
				    map_entry, link_cnt, 0, cause) == TRUE) {
					check_finish_init++;
				}
			}
			break;

		default:
			fcp_log(CE_WARN, pptr->port_dip,
			    "!Invalid map_type=0x%x", map_entry->map_type);
			check_finish_init++;
			break;
		}
	}

	if (check_finish_init && pptr->port_link_cnt == link_cnt) {
		ASSERT(i > 0);
		(void) fcp_call_finish_init_held(pptr, ptgt, link_cnt,
		    map_tag[i-1], cause);
	} else if (dev_cnt == 0 && pptr->port_link_cnt == link_cnt) {
		fcp_offline_all(pptr, link_cnt, cause);
	}
}

static int
fcp_handle_reportlun_changed(struct fcp_tgt *ptgt, int cause)
{
	struct fcp_lun	*plun;
	struct fcp_port *pptr;
	int		 rscn_count;
	int		 lun0_newalloc;
	int		 ret  = TRUE;

	ASSERT(ptgt);
	pptr = ptgt->tgt_port;
	lun0_newalloc = 0;
	if ((plun = fcp_get_lun(ptgt, 0)) == NULL) {
		/*
		 * no LUN struct for LUN 0 yet exists,
		 * so create one
		 */
		plun = fcp_alloc_lun(ptgt);
		if (plun == NULL) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!Failed to allocate lun 0 for"
			    " D_ID=%x", ptgt->tgt_d_id);
			return (ret);
		}
		lun0_newalloc = 1;
	}

	mutex_enter(&ptgt->tgt_mutex);
	/*
	 * consider lun 0 as device not connected if it is
	 * offlined or newly allocated
	 */
	if ((plun->lun_state & FCP_LUN_OFFLINE) || lun0_newalloc) {
		plun->lun_state |= FCP_LUN_DEVICE_NOT_CONNECTED;
	}
	plun->lun_state |= (FCP_LUN_BUSY | FCP_LUN_MARK);
	plun->lun_state &= ~FCP_LUN_OFFLINE;
	ptgt->tgt_lun_cnt = 1;
	ptgt->tgt_report_lun_cnt = 0;
	mutex_exit(&ptgt->tgt_mutex);

	rscn_count = fc_ulp_get_rscn_count(pptr->port_fp_handle);
	if (fcp_send_scsi(plun, SCMD_REPORT_LUN,
	    sizeof (struct fcp_reportlun_resp), pptr->port_link_cnt,
	    ptgt->tgt_change_cnt, cause, rscn_count) != DDI_SUCCESS) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0, "!Failed to send REPORTLUN "
		    "to D_ID=%x", ptgt->tgt_d_id);
	} else {
		ret = FALSE;
	}

	return (ret);
}

/*
 *     Function: fcp_handle_mapflags
 *
 *  Description: This function creates a target structure if the ptgt passed
 *		 is NULL.  It also kicks off the PLOGI if we are not logged
 *		 into the target yet or the PRLI if we are logged into the
 *		 target already.  The rest of the treatment is done in the
 *		 callbacks of the PLOGI or PRLI.
 *
 *     Argument: *pptr		FCP Port structure.
 *		 *ptgt		Target structure.
 *		 *map_entry	Array of fc_portmap_t structures.
 *		 link_cnt	Link state count.
 *		 tgt_cnt	Target state count.
 *		 cause		What caused this function to be called.
 *
 * Return Value: TRUE	Failed
 *		 FALSE	Succeeded
 *
 *	  Notes: pptr->port_mutex must be owned.
 */
static int
fcp_handle_mapflags(struct fcp_port	*pptr, struct fcp_tgt	*ptgt,
    fc_portmap_t *map_entry, int link_cnt, int tgt_cnt, int cause)
{
	int			lcount;
	int			tcount;
	int			ret = TRUE;
	int			alloc;
	struct fcp_ipkt	*icmd;
	struct fcp_lun	*pseq_lun = NULL;
	uchar_t			opcode;
	int			valid_ptgt_was_passed = FALSE;

	ASSERT(mutex_owned(&pptr->port_mutex));

	/*
	 * This case is possible where the FCTL has come up and done discovery
	 * before FCP was loaded and attached. FCTL would have discovered the
	 * devices and later the ULP came online. In this case ULP's would get
	 * PORT_DEVICE_NOCHANGE but target would be NULL.
	 */
	if (ptgt == NULL) {
		/* don't already have a target */
		mutex_exit(&pptr->port_mutex);
		ptgt = fcp_alloc_tgt(pptr, map_entry, link_cnt);
		mutex_enter(&pptr->port_mutex);

		if (ptgt == NULL) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FC target allocation failed");
			return (ret);
		}
		mutex_enter(&ptgt->tgt_mutex);
		ptgt->tgt_statec_cause = cause;
		ptgt->tgt_tmp_cnt = 1;
		mutex_exit(&ptgt->tgt_mutex);
	} else {
		valid_ptgt_was_passed = TRUE;
	}

	/*
	 * Copy in the target parameters
	 */
	mutex_enter(&ptgt->tgt_mutex);
	ptgt->tgt_d_id = map_entry->map_did.port_id;
	ptgt->tgt_hard_addr = map_entry->map_hard_addr.hard_addr;
	ptgt->tgt_pd_handle = map_entry->map_pd;
	ptgt->tgt_fca_dev = NULL;

	/* Copy port and node WWNs */
	bcopy(&map_entry->map_nwwn, &ptgt->tgt_node_wwn.raw_wwn[0],
	    FC_WWN_SIZE);
	bcopy(&map_entry->map_pwwn, &ptgt->tgt_port_wwn.raw_wwn[0],
	    FC_WWN_SIZE);

	if (!(map_entry->map_flags & PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY) &&
	    (map_entry->map_type == PORT_DEVICE_NOCHANGE) &&
	    (map_entry->map_state == PORT_DEVICE_LOGGED_IN) &&
	    valid_ptgt_was_passed) {
		/*
		 * determine if there are any tape LUNs on this target
		 */
		for (pseq_lun = ptgt->tgt_lun;
		    pseq_lun != NULL;
		    pseq_lun = pseq_lun->lun_next) {
			if ((pseq_lun->lun_type == DTYPE_SEQUENTIAL) &&
			    !(pseq_lun->lun_state & FCP_LUN_OFFLINE)) {
				fcp_update_tgt_state(ptgt, FCP_RESET,
				    FCP_LUN_MARK);
				mutex_exit(&ptgt->tgt_mutex);
				return (ret);
			}
		}
	}

	/*
	 * if UA'REPORT_LUN_CHANGED received,
	 * send out REPORT LUN promptly, skip PLOGI/PRLI process
	 */
	if (map_entry->map_type == PORT_DEVICE_REPORTLUN_CHANGED) {
		ptgt->tgt_state &= ~(FCP_TGT_OFFLINE | FCP_TGT_MARK);
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);

		ret = fcp_handle_reportlun_changed(ptgt, cause);

		mutex_enter(&pptr->port_mutex);
		return (ret);
	}

	/*
	 * If ptgt was NULL when this function was entered, then tgt_node_state
	 * was never specifically initialized but zeroed out which means
	 * FCP_TGT_NODE_NONE.
	 */
	switch (ptgt->tgt_node_state) {
	case FCP_TGT_NODE_NONE:
	case FCP_TGT_NODE_ON_DEMAND:
		if (FC_TOP_EXTERNAL(pptr->port_topology) &&
		    !fcp_enable_auto_configuration &&
		    map_entry->map_type != PORT_DEVICE_USER_CREATE) {
			ptgt->tgt_node_state = FCP_TGT_NODE_ON_DEMAND;
		} else if (FC_TOP_EXTERNAL(pptr->port_topology) &&
		    fcp_enable_auto_configuration &&
		    (ptgt->tgt_manual_config_only == 1) &&
		    map_entry->map_type != PORT_DEVICE_USER_CREATE) {
			/*
			 * If auto configuration is set and
			 * the tgt_manual_config_only flag is set then
			 * we only want the user to be able to change
			 * the state through create_on_demand.
			 */
			ptgt->tgt_node_state = FCP_TGT_NODE_ON_DEMAND;
		} else {
			ptgt->tgt_node_state = FCP_TGT_NODE_NONE;
		}
		break;

	case FCP_TGT_NODE_PRESENT:
		break;
	}
	/*
	 * If we are booting from a fabric device, make sure we
	 * mark the node state appropriately for this target to be
	 * enumerated
	 */
	if (FC_TOP_EXTERNAL(pptr->port_topology) && pptr->port_boot_wwn[0]) {
		if (bcmp((caddr_t)pptr->port_boot_wwn,
		    (caddr_t)&ptgt->tgt_port_wwn.raw_wwn[0],
		    sizeof (ptgt->tgt_port_wwn)) == 0) {
			ptgt->tgt_node_state = FCP_TGT_NODE_NONE;
		}
	}
	mutex_exit(&ptgt->tgt_mutex);

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_3, 0,
	    "map_pd=%p, map_type=%x, did = %x, ulp_rscn_count=0x%x",
	    map_entry->map_pd, map_entry->map_type, map_entry->map_did.port_id,
	    map_entry->map_rscn_info.ulp_rscn_count);

	mutex_enter(&ptgt->tgt_mutex);

	/*
	 * Reset target OFFLINE state and mark the target BUSY
	 */
	ptgt->tgt_state &= ~FCP_TGT_OFFLINE;
	ptgt->tgt_state |= (FCP_TGT_BUSY | FCP_TGT_MARK);

	tcount = tgt_cnt ? tgt_cnt : ptgt->tgt_change_cnt;
	lcount = link_cnt;

	mutex_exit(&ptgt->tgt_mutex);
	mutex_exit(&pptr->port_mutex);

	/*
	 * if we are already logged in, then we do a PRLI, else
	 * we do a PLOGI first (to get logged in)
	 *
	 * We will not check if we are the PLOGI initiator
	 */
	opcode = (map_entry->map_state == PORT_DEVICE_LOGGED_IN &&
	    map_entry->map_pd != NULL) ? LA_ELS_PRLI : LA_ELS_PLOGI;

	alloc = FCP_MAX(sizeof (la_els_logi_t), sizeof (la_els_prli_t));

	icmd = fcp_icmd_alloc(pptr, ptgt, alloc, alloc, 0,
	    pptr->port_state & FCP_STATE_FCA_IS_NODMA, lcount, tcount,
	    cause, map_entry->map_rscn_info.ulp_rscn_count);

	if (icmd == NULL) {
		FCP_TGT_TRACE(ptgt, tgt_cnt, FCP_TGT_TRACE_29);
		/*
		 * We've exited port_mutex before calling fcp_icmd_alloc,
		 * we need to make sure we reacquire it before returning.
		 */
		mutex_enter(&pptr->port_mutex);
		return (FALSE);
	}

	/* TRUE is only returned while target is intended skipped */
	ret = FALSE;
	/* discover info about this target */
	if ((fcp_send_els(pptr, ptgt, icmd, opcode,
	    lcount, tcount, cause)) == DDI_SUCCESS) {
		FCP_TGT_TRACE(ptgt, tgt_cnt, FCP_TGT_TRACE_9);
	} else {
		fcp_icmd_free(pptr, icmd);
		ret = TRUE;
	}
	mutex_enter(&pptr->port_mutex);

	return (ret);
}

/*
 *     Function: fcp_send_els
 *
 *  Description: Sends an ELS to the target specified by the caller.  Supports
 *		 PLOGI and PRLI.
 *
 *     Argument: *pptr		Fcp port.
 *		 *ptgt		Target to send the ELS to.
 *		 *icmd		Internal packet
 *		 opcode		ELS opcode
 *		 lcount		Link state change counter
 *		 tcount		Target state change counter
 *		 cause		What caused the call
 *
 * Return Value: DDI_SUCCESS
 *		 Others
 */
static int
fcp_send_els(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    struct fcp_ipkt *icmd, uchar_t opcode, int lcount, int tcount, int cause)
{
	fc_packet_t		*fpkt;
	fc_frame_hdr_t		*hp;
	int			internal = 0;
	int			alloc;
	int			cmd_len;
	int			resp_len;
	int			res = DDI_FAILURE; /* default result */
	int			rval = DDI_FAILURE;

	ASSERT(opcode == LA_ELS_PLOGI || opcode == LA_ELS_PRLI);
	ASSERT(ptgt->tgt_port == pptr);

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "fcp_send_els: d_id=0x%x ELS 0x%x (%s)", ptgt->tgt_d_id, opcode,
	    (opcode == LA_ELS_PLOGI) ? "PLOGI" : "PRLI");

	if (opcode == LA_ELS_PLOGI) {
		cmd_len = sizeof (la_els_logi_t);
		resp_len = sizeof (la_els_logi_t);
	} else {
		ASSERT(opcode == LA_ELS_PRLI);
		cmd_len = sizeof (la_els_prli_t);
		resp_len = sizeof (la_els_prli_t);
	}

	if (icmd == NULL) {
		alloc = FCP_MAX(sizeof (la_els_logi_t),
		    sizeof (la_els_prli_t));
		icmd = fcp_icmd_alloc(pptr, ptgt, alloc, alloc, 0,
		    pptr->port_state & FCP_STATE_FCA_IS_NODMA,
		    lcount, tcount, cause, FC_INVALID_RSCN_COUNT);
		if (icmd == NULL) {
			FCP_TGT_TRACE(ptgt, tcount, FCP_TGT_TRACE_10);
			return (res);
		}
		internal++;
	}
	fpkt = icmd->ipkt_fpkt;

	fpkt->pkt_cmdlen = cmd_len;
	fpkt->pkt_rsplen = resp_len;
	fpkt->pkt_datalen = 0;
	icmd->ipkt_retries = 0;

	/* fill in fpkt info */
	fpkt->pkt_tran_flags = FC_TRAN_CLASS3 | FC_TRAN_INTR;
	fpkt->pkt_tran_type = FC_PKT_EXCHANGE;
	fpkt->pkt_timeout = FCP_ELS_TIMEOUT;

	/* get ptr to frame hdr in fpkt */
	hp = &fpkt->pkt_cmd_fhdr;

	/*
	 * fill in frame hdr
	 */
	hp->r_ctl = R_CTL_ELS_REQ;
	hp->s_id = pptr->port_id;	/* source ID */
	hp->d_id = ptgt->tgt_d_id;	/* dest ID */
	hp->type = FC_TYPE_EXTENDED_LS;
	hp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	hp->seq_id = 0;
	hp->rsvd = 0;
	hp->df_ctl  = 0;
	hp->seq_cnt = 0;
	hp->ox_id = 0xffff;		/* i.e. none */
	hp->rx_id = 0xffff;		/* i.e. none */
	hp->ro = 0;

	/*
	 * at this point we have a filled in cmd pkt
	 *
	 * fill in the respective info, then use the transport to send
	 * the packet
	 *
	 * for a PLOGI call fc_ulp_login(), and
	 * for a PRLI call fc_ulp_issue_els()
	 */
	switch (opcode) {
	case LA_ELS_PLOGI: {
		struct la_els_logi logi;

		bzero(&logi, sizeof (struct la_els_logi));

		hp = &fpkt->pkt_cmd_fhdr;
		hp->r_ctl = R_CTL_ELS_REQ;
		logi.ls_code.ls_code = LA_ELS_PLOGI;
		logi.ls_code.mbz = 0;

		FCP_CP_OUT((uint8_t *)&logi, fpkt->pkt_cmd,
		    fpkt->pkt_cmd_acc, sizeof (struct la_els_logi));

		icmd->ipkt_opcode = LA_ELS_PLOGI;

		mutex_enter(&pptr->port_mutex);
		if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {

			mutex_exit(&pptr->port_mutex);

			rval = fc_ulp_login(pptr->port_fp_handle, &fpkt, 1);
			if (rval == FC_SUCCESS) {
				res = DDI_SUCCESS;
				break;
			}

			FCP_TGT_TRACE(ptgt, tcount, FCP_TGT_TRACE_11);

			res = fcp_handle_ipkt_errors(pptr, ptgt, icmd,
			    rval, "PLOGI");
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_5, 0,
			    "fcp_send_els1: state change occured"
			    " for D_ID=0x%x", ptgt->tgt_d_id);
			mutex_exit(&pptr->port_mutex);
			FCP_TGT_TRACE(ptgt, tcount, FCP_TGT_TRACE_12);
		}
		break;
	}

	case LA_ELS_PRLI: {
		struct la_els_prli	prli;
		struct fcp_prli		*fprli;

		bzero(&prli, sizeof (struct la_els_prli));

		hp = &fpkt->pkt_cmd_fhdr;
		hp->r_ctl = R_CTL_ELS_REQ;

		/* fill in PRLI cmd ELS fields */
		prli.ls_code = LA_ELS_PRLI;
		prli.page_length = 0x10;	/* huh? */
		prli.payload_length = sizeof (struct la_els_prli);

		icmd->ipkt_opcode = LA_ELS_PRLI;

		/* get ptr to PRLI service params */
		fprli = (struct fcp_prli *)prli.service_params;

		/* fill in service params */
		fprli->type = 0x08;
		fprli->resvd1 = 0;
		fprli->orig_process_assoc_valid = 0;
		fprli->resp_process_assoc_valid = 0;
		fprli->establish_image_pair = 1;
		fprli->resvd2 = 0;
		fprli->resvd3 = 0;
		fprli->obsolete_1 = 0;
		fprli->obsolete_2 = 0;
		fprli->data_overlay_allowed = 0;
		fprli->initiator_fn = 1;
		fprli->confirmed_compl_allowed = 1;

		if (fc_ulp_is_name_present("ltct") == FC_SUCCESS) {
			fprli->target_fn = 1;
		} else {
			fprli->target_fn = 0;
		}

		fprli->retry = 1;
		fprli->read_xfer_rdy_disabled = 1;
		fprli->write_xfer_rdy_disabled = 0;

		FCP_CP_OUT((uint8_t *)&prli, fpkt->pkt_cmd,
		    fpkt->pkt_cmd_acc, sizeof (struct la_els_prli));

		/* issue the PRLI request */

		mutex_enter(&pptr->port_mutex);
		if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {

			mutex_exit(&pptr->port_mutex);

			rval = fc_ulp_issue_els(pptr->port_fp_handle, fpkt);
			if (rval == FC_SUCCESS) {
				res = DDI_SUCCESS;
				break;
			}

			FCP_TGT_TRACE(ptgt, tcount, FCP_TGT_TRACE_13);

			res = fcp_handle_ipkt_errors(pptr, ptgt, icmd,
			    rval, "PRLI");
		} else {
			mutex_exit(&pptr->port_mutex);
			FCP_TGT_TRACE(ptgt, tcount, FCP_TGT_TRACE_14);
		}
		break;
	}

	default:
		fcp_log(CE_WARN, NULL, "!invalid ELS opcode=0x%x", opcode);
		break;
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "fcp_send_els: returning %d", res);

	if (res != DDI_SUCCESS) {
		if (internal) {
			fcp_icmd_free(pptr, icmd);
		}
	}

	return (res);
}


/*
 * called internally update the state of all of the tgts and each LUN
 * for this port (i.e. each target  known to be attached to this port)
 * if they are not already offline
 *
 * must be called with the port mutex owned
 *
 * acquires and releases the target mutexes for each target attached
 * to this port
 */
void
fcp_update_state(struct fcp_port *pptr, uint32_t state, int cause)
{
	int i;
	struct fcp_tgt *ptgt;

	ASSERT(mutex_owned(&pptr->port_mutex));

	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			mutex_enter(&ptgt->tgt_mutex);
			fcp_update_tgt_state(ptgt, FCP_SET, state);
			ptgt->tgt_change_cnt++;
			ptgt->tgt_statec_cause = cause;
			ptgt->tgt_tmp_cnt = 1;
			ptgt->tgt_done = 0;
			mutex_exit(&ptgt->tgt_mutex);
		}
	}
}


static void
fcp_offline_all(struct fcp_port *pptr, int lcount, int cause)
{
	int i;
	int ndevs;
	struct fcp_tgt *ptgt;

	ASSERT(mutex_owned(&pptr->port_mutex));

	for (ndevs = 0, i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			ndevs++;
		}
	}

	if (ndevs == 0) {
		return;
	}
	pptr->port_tmp_cnt = ndevs;

	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			(void) fcp_call_finish_init_held(pptr, ptgt,
			    lcount, ptgt->tgt_change_cnt, cause);
		}
	}
}

/*
 *     Function: fcp_update_tgt_state
 *
 *  Description: This function updates the field tgt_state of a target.	 That
 *		 field is a bitmap and which bit can be set or reset
 *		 individually.	The action applied to the target state is also
 *		 applied to all the LUNs belonging to the target (provided the
 *		 LUN is not offline).  A side effect of applying the state
 *		 modification to the target and the LUNs is the field tgt_trace
 *		 of the target and lun_trace of the LUNs is set to zero.
 *
 *
 *     Argument: *ptgt	Target structure.
 *		 flag	Flag indication what action to apply (set/reset).
 *		 state	State bits to update.
 *
 * Return Value: None
 *
 *	Context: Interrupt, Kernel or User context.
 *		 The mutex of the target (ptgt->tgt_mutex) must be owned when
 *		 calling this function.
 */
void
fcp_update_tgt_state(struct fcp_tgt *ptgt, int flag, uint32_t state)
{
	struct fcp_lun *plun;

	ASSERT(mutex_owned(&ptgt->tgt_mutex));

	if (!(ptgt->tgt_state & FCP_TGT_OFFLINE)) {
		/* The target is not offline. */
		if (flag == FCP_SET) {
			ptgt->tgt_state |= state;
			ptgt->tgt_trace = 0;
		} else {
			ptgt->tgt_state &= ~state;
		}

		for (plun = ptgt->tgt_lun; plun != NULL;
		    plun = plun->lun_next) {
			if (!(plun->lun_state & FCP_LUN_OFFLINE)) {
				/* The LUN is not offline. */
				if (flag == FCP_SET) {
					plun->lun_state |= state;
					plun->lun_trace = 0;
				} else {
					plun->lun_state &= ~state;
				}
			}
		}
	}
}

/*
 *     Function: fcp_update_tgt_state
 *
 *  Description: This function updates the field lun_state of a LUN.  That
 *		 field is a bitmap and which bit can be set or reset
 *		 individually.
 *
 *     Argument: *plun	LUN structure.
 *		 flag	Flag indication what action to apply (set/reset).
 *		 state	State bits to update.
 *
 * Return Value: None
 *
 *	Context: Interrupt, Kernel or User context.
 *		 The mutex of the target (ptgt->tgt_mutex) must be owned when
 *		 calling this function.
 */
void
fcp_update_lun_state(struct fcp_lun *plun, int flag, uint32_t state)
{
	struct fcp_tgt	*ptgt = plun->lun_tgt;

	ASSERT(mutex_owned(&ptgt->tgt_mutex));

	if (!(plun->lun_state & FCP_TGT_OFFLINE)) {
		if (flag == FCP_SET) {
			plun->lun_state |= state;
		} else {
			plun->lun_state &= ~state;
		}
	}
}

/*
 *     Function: fcp_get_port
 *
 *  Description: This function returns the fcp_port structure from the opaque
 *		 handle passed by the caller.  That opaque handle is the handle
 *		 used by fp/fctl to identify a particular local port.  That
 *		 handle has been stored in the corresponding fcp_port
 *		 structure.  This function is going to walk the global list of
 *		 fcp_port structures till one has a port_fp_handle that matches
 *		 the handle passed by the caller.  This function enters the
 *		 mutex fcp_global_mutex while walking the global list and then
 *		 releases it.
 *
 *     Argument: port_handle	Opaque handle that fp/fctl uses to identify a
 *				particular port.
 *
 * Return Value: NULL		Not found.
 *		 Not NULL	Pointer to the fcp_port structure.
 *
 *	Context: Interrupt, Kernel or User context.
 */
static struct fcp_port *
fcp_get_port(opaque_t port_handle)
{
	struct fcp_port *pptr;

	ASSERT(port_handle != NULL);

	mutex_enter(&fcp_global_mutex);
	for (pptr = fcp_port_head; pptr != NULL; pptr = pptr->port_next) {
		if (pptr->port_fp_handle == port_handle) {
			break;
		}
	}
	mutex_exit(&fcp_global_mutex);

	return (pptr);
}


static void
fcp_unsol_callback(fc_packet_t *fpkt)
{
	struct fcp_ipkt *icmd = (struct fcp_ipkt *)fpkt->pkt_ulp_private;
	struct fcp_port *pptr = icmd->ipkt_port;

	if (fpkt->pkt_state != FC_PKT_SUCCESS) {
		caddr_t state, reason, action, expln;

		(void) fc_ulp_pkt_error(fpkt, &state, &reason,
		    &action, &expln);

		fcp_log(CE_WARN, pptr->port_dip,
		    "!couldn't post response to unsolicited request: "
		    " state=%s reason=%s rx_id=%x ox_id=%x",
		    state, reason, fpkt->pkt_cmd_fhdr.ox_id,
		    fpkt->pkt_cmd_fhdr.rx_id);
	}
	fcp_icmd_free(pptr, icmd);
}


/*
 * Perform general purpose preparation of a response to an unsolicited request
 */
static void
fcp_unsol_resp_init(fc_packet_t *pkt, fc_unsol_buf_t *buf,
    uchar_t r_ctl, uchar_t type)
{
	pkt->pkt_cmd_fhdr.r_ctl = r_ctl;
	pkt->pkt_cmd_fhdr.d_id = buf->ub_frame.s_id;
	pkt->pkt_cmd_fhdr.s_id = buf->ub_frame.d_id;
	pkt->pkt_cmd_fhdr.type = type;
	pkt->pkt_cmd_fhdr.f_ctl = F_CTL_LAST_SEQ | F_CTL_XCHG_CONTEXT;
	pkt->pkt_cmd_fhdr.seq_id = buf->ub_frame.seq_id;
	pkt->pkt_cmd_fhdr.df_ctl  = buf->ub_frame.df_ctl;
	pkt->pkt_cmd_fhdr.seq_cnt = buf->ub_frame.seq_cnt;
	pkt->pkt_cmd_fhdr.ox_id = buf->ub_frame.ox_id;
	pkt->pkt_cmd_fhdr.rx_id = buf->ub_frame.rx_id;
	pkt->pkt_cmd_fhdr.ro = 0;
	pkt->pkt_cmd_fhdr.rsvd = 0;
	pkt->pkt_comp = fcp_unsol_callback;
	pkt->pkt_pd = NULL;
	pkt->pkt_ub_resp_token = (opaque_t)buf;
}


/*ARGSUSED*/
static int
fcp_unsol_prli(struct fcp_port *pptr, fc_unsol_buf_t *buf)
{
	fc_packet_t		*fpkt;
	struct la_els_prli	prli;
	struct fcp_prli		*fprli;
	struct fcp_ipkt	*icmd;
	struct la_els_prli	*from;
	struct fcp_prli		*orig;
	struct fcp_tgt	*ptgt;
	int			tcount = 0;
	int			lcount;

	from = (struct la_els_prli *)buf->ub_buffer;
	orig = (struct fcp_prli *)from->service_params;
	if ((ptgt = fcp_get_target_by_did(pptr, buf->ub_frame.s_id)) !=
	    NULL) {
		mutex_enter(&ptgt->tgt_mutex);
		tcount = ptgt->tgt_change_cnt;
		mutex_exit(&ptgt->tgt_mutex);
	}

	mutex_enter(&pptr->port_mutex);
	lcount = pptr->port_link_cnt;
	mutex_exit(&pptr->port_mutex);

	if ((icmd = fcp_icmd_alloc(pptr, ptgt, sizeof (la_els_prli_t),
	    sizeof (la_els_prli_t), 0,
	    pptr->port_state & FCP_STATE_FCA_IS_NODMA,
	    lcount, tcount, 0, FC_INVALID_RSCN_COUNT)) == NULL) {
		return (FC_FAILURE);
	}

	fpkt = icmd->ipkt_fpkt;
	fpkt->pkt_tran_flags = FC_TRAN_CLASS3 | FC_TRAN_INTR;
	fpkt->pkt_tran_type = FC_PKT_OUTBOUND;
	fpkt->pkt_timeout = FCP_ELS_TIMEOUT;
	fpkt->pkt_cmdlen = sizeof (la_els_prli_t);
	fpkt->pkt_rsplen = 0;
	fpkt->pkt_datalen = 0;

	icmd->ipkt_opcode = LA_ELS_PRLI;

	bzero(&prli, sizeof (struct la_els_prli));
	fprli = (struct fcp_prli *)prli.service_params;
	prli.ls_code = LA_ELS_ACC;
	prli.page_length = 0x10;
	prli.payload_length = sizeof (struct la_els_prli);

	/* fill in service params */
	fprli->type = 0x08;
	fprli->resvd1 = 0;
	fprli->orig_process_assoc_valid = orig->orig_process_assoc_valid;
	fprli->orig_process_associator = orig->orig_process_associator;
	fprli->resp_process_assoc_valid = 0;
	fprli->establish_image_pair = 1;
	fprli->resvd2 = 0;
	fprli->resvd3 = 0;
	fprli->obsolete_1 = 0;
	fprli->obsolete_2 = 0;
	fprli->data_overlay_allowed = 0;
	fprli->initiator_fn = 1;
	fprli->confirmed_compl_allowed = 1;

	if (fc_ulp_is_name_present("ltct") == FC_SUCCESS) {
		fprli->target_fn = 1;
	} else {
		fprli->target_fn = 0;
	}

	fprli->retry = 1;
	fprli->read_xfer_rdy_disabled = 1;
	fprli->write_xfer_rdy_disabled = 0;

	/* save the unsol prli payload first */
	FCP_CP_OUT((uint8_t *)from, fpkt->pkt_resp,
	    fpkt->pkt_resp_acc, sizeof (struct la_els_prli));

	FCP_CP_OUT((uint8_t *)&prli, fpkt->pkt_cmd,
	    fpkt->pkt_cmd_acc, sizeof (struct la_els_prli));

	fcp_unsol_resp_init(fpkt, buf, R_CTL_ELS_RSP, FC_TYPE_EXTENDED_LS);

	mutex_enter(&pptr->port_mutex);
	if (!FCP_LINK_STATE_CHANGED(pptr, icmd)) {
		int rval;
		mutex_exit(&pptr->port_mutex);

		if ((rval = fc_ulp_issue_els(pptr->port_fp_handle, fpkt)) !=
		    FC_SUCCESS) {
			if ((rval == FC_STATEC_BUSY || rval == FC_OFFLINE) &&
			    ptgt != NULL) {
				fcp_queue_ipkt(pptr, fpkt);
				return (FC_SUCCESS);
			}
			/* Let it timeout */
			fcp_icmd_free(pptr, icmd);
			return (FC_FAILURE);
		}
	} else {
		mutex_exit(&pptr->port_mutex);
		fcp_icmd_free(pptr, icmd);
		return (FC_FAILURE);
	}

	(void) fc_ulp_ubrelease(pptr->port_fp_handle, 1, &buf->ub_token);

	return (FC_SUCCESS);
}

/*
 *     Function: fcp_icmd_alloc
 *
 *  Description: This function allocated a fcp_ipkt structure.	The pkt_comp
 *		 field is initialized to fcp_icmd_callback.  Sometimes it is
 *		 modified by the caller (such as fcp_send_scsi).  The
 *		 structure is also tied to the state of the line and of the
 *		 target at a particular time.  That link is established by
 *		 setting the fields ipkt_link_cnt and ipkt_change_cnt to lcount
 *		 and tcount which came respectively from pptr->link_cnt and
 *		 ptgt->tgt_change_cnt.
 *
 *     Argument: *pptr		Fcp port.
 *		 *ptgt		Target (destination of the command).
 *		 cmd_len	Length of the command.
 *		 resp_len	Length of the expected response.
 *		 data_len	Length of the data.
 *		 nodma		Indicates weither the command and response.
 *				will be transfer through DMA or not.
 *		 lcount		Link state change counter.
 *		 tcount		Target state change counter.
 *		 cause		Reason that lead to this call.
 *
 * Return Value: NULL		Failed.
 *		 Not NULL	Internal packet address.
 */
static struct fcp_ipkt *
fcp_icmd_alloc(struct fcp_port *pptr, struct fcp_tgt *ptgt, int cmd_len,
    int resp_len, int data_len, int nodma, int lcount, int tcount, int cause,
    uint32_t rscn_count)
{
	int			dma_setup = 0;
	fc_packet_t		*fpkt;
	struct fcp_ipkt	*icmd = NULL;

	icmd = kmem_zalloc(sizeof (struct fcp_ipkt) +
	    pptr->port_dmacookie_sz + pptr->port_priv_pkt_len,
	    KM_NOSLEEP);
	if (icmd == NULL) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!internal packet allocation failed");
		return (NULL);
	}

	/*
	 * initialize the allocated packet
	 */
	icmd->ipkt_nodma = nodma;
	icmd->ipkt_next = icmd->ipkt_prev = NULL;
	icmd->ipkt_lun = NULL;

	icmd->ipkt_link_cnt = lcount;
	icmd->ipkt_change_cnt = tcount;
	icmd->ipkt_cause = cause;

	mutex_enter(&pptr->port_mutex);
	icmd->ipkt_port = pptr;
	mutex_exit(&pptr->port_mutex);

	/* keep track of amt of data to be sent in pkt */
	icmd->ipkt_cmdlen = cmd_len;
	icmd->ipkt_resplen = resp_len;
	icmd->ipkt_datalen = data_len;

	/* set up pkt's ptr to the fc_packet_t struct, just after the ipkt */
	icmd->ipkt_fpkt = (fc_packet_t *)(&icmd->ipkt_fc_packet);

	/* set pkt's private ptr to point to cmd pkt */
	icmd->ipkt_fpkt->pkt_ulp_private = (opaque_t)icmd;

	/* set FCA private ptr to memory just beyond */
	icmd->ipkt_fpkt->pkt_fca_private = (opaque_t)
	    ((char *)icmd + sizeof (struct fcp_ipkt) +
	    pptr->port_dmacookie_sz);

	/* get ptr to fpkt substruct and fill it in */
	fpkt = icmd->ipkt_fpkt;
	fpkt->pkt_data_cookie = (ddi_dma_cookie_t *)((caddr_t)icmd +
	    sizeof (struct fcp_ipkt));

	if (ptgt != NULL) {
		icmd->ipkt_tgt = ptgt;
		fpkt->pkt_fca_device = ptgt->tgt_fca_dev;
	}

	fpkt->pkt_comp = fcp_icmd_callback;
	fpkt->pkt_tran_flags = (FC_TRAN_CLASS3 | FC_TRAN_INTR);
	fpkt->pkt_cmdlen = cmd_len;
	fpkt->pkt_rsplen = resp_len;
	fpkt->pkt_datalen = data_len;

	/*
	 * The pkt_ulp_rscn_infop (aka pkt_ulp_rsvd1) field is used to pass the
	 * rscn_count as fcp knows down to the transport. If a valid count was
	 * passed into this function, we allocate memory to actually pass down
	 * this info.
	 *
	 * BTW, if the kmem_zalloc fails, we won't try too hard. This will
	 * basically mean that fcp will not be able to help transport
	 * distinguish if a new RSCN has come after fcp was last informed about
	 * it. In such cases, it might lead to the problem mentioned in CR/bug #
	 * 5068068 where the device might end up going offline in case of RSCN
	 * storms.
	 */
	fpkt->pkt_ulp_rscn_infop = NULL;
	if (rscn_count != FC_INVALID_RSCN_COUNT) {
		fpkt->pkt_ulp_rscn_infop = kmem_zalloc(
		    sizeof (fc_ulp_rscn_info_t), KM_NOSLEEP);
		if (fpkt->pkt_ulp_rscn_infop == NULL) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_6, 0,
			    "Failed to alloc memory to pass rscn info");
		}
	}

	if (fpkt->pkt_ulp_rscn_infop != NULL) {
		fc_ulp_rscn_info_t	*rscnp;

		rscnp = (fc_ulp_rscn_info_t *)fpkt->pkt_ulp_rscn_infop;
		rscnp->ulp_rscn_count = rscn_count;
	}

	if (fcp_alloc_dma(pptr, icmd, nodma, KM_NOSLEEP) != FC_SUCCESS) {
		goto fail;
	}
	dma_setup++;

	/*
	 * Must hold target mutex across setting of pkt_pd and call to
	 * fc_ulp_init_packet to ensure the handle to the target doesn't go
	 * away while we're not looking.
	 */
	if (ptgt != NULL) {
		mutex_enter(&ptgt->tgt_mutex);
		fpkt->pkt_pd = ptgt->tgt_pd_handle;

		/* ask transport to do its initialization on this pkt */
		if (fc_ulp_init_packet(pptr->port_fp_handle, fpkt, KM_NOSLEEP)
		    != FC_SUCCESS) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_6, 0,
			    "fc_ulp_init_packet failed");
			mutex_exit(&ptgt->tgt_mutex);
			goto fail;
		}
		mutex_exit(&ptgt->tgt_mutex);
	} else {
		if (fc_ulp_init_packet(pptr->port_fp_handle, fpkt, KM_NOSLEEP)
		    != FC_SUCCESS) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_6, 0,
			    "fc_ulp_init_packet failed");
			goto fail;
		}
	}

	mutex_enter(&pptr->port_mutex);
	if (pptr->port_state & (FCP_STATE_DETACHING |
	    FCP_STATE_SUSPENDED | FCP_STATE_POWER_DOWN)) {
		int rval;

		mutex_exit(&pptr->port_mutex);

		rval = fc_ulp_uninit_packet(pptr->port_fp_handle, fpkt);
		ASSERT(rval == FC_SUCCESS);

		goto fail;
	}

	if (ptgt != NULL) {
		mutex_enter(&ptgt->tgt_mutex);
		ptgt->tgt_ipkt_cnt++;
		mutex_exit(&ptgt->tgt_mutex);
	}

	pptr->port_ipkt_cnt++;

	mutex_exit(&pptr->port_mutex);

	return (icmd);

fail:
	if (fpkt->pkt_ulp_rscn_infop != NULL) {
		kmem_free(fpkt->pkt_ulp_rscn_infop,
		    sizeof (fc_ulp_rscn_info_t));
		fpkt->pkt_ulp_rscn_infop = NULL;
	}

	if (dma_setup) {
		fcp_free_dma(pptr, icmd);
	}
	kmem_free(icmd, sizeof (struct fcp_ipkt) + pptr->port_priv_pkt_len +
	    (size_t)pptr->port_dmacookie_sz);

	return (NULL);
}

/*
 *     Function: fcp_icmd_free
 *
 *  Description: Frees the internal command passed by the caller.
 *
 *     Argument: *pptr		Fcp port.
 *		 *icmd		Internal packet to free.
 *
 * Return Value: None
 */
static void
fcp_icmd_free(struct fcp_port *pptr, struct fcp_ipkt *icmd)
{
	struct fcp_tgt	*ptgt = icmd->ipkt_tgt;

	/* Let the underlying layers do their cleanup. */
	(void) fc_ulp_uninit_packet(pptr->port_fp_handle,
	    icmd->ipkt_fpkt);

	if (icmd->ipkt_fpkt->pkt_ulp_rscn_infop) {
		kmem_free(icmd->ipkt_fpkt->pkt_ulp_rscn_infop,
		    sizeof (fc_ulp_rscn_info_t));
	}

	fcp_free_dma(pptr, icmd);

	kmem_free(icmd, sizeof (struct fcp_ipkt) + pptr->port_priv_pkt_len +
	    (size_t)pptr->port_dmacookie_sz);

	mutex_enter(&pptr->port_mutex);

	if (ptgt) {
		mutex_enter(&ptgt->tgt_mutex);
		ptgt->tgt_ipkt_cnt--;
		mutex_exit(&ptgt->tgt_mutex);
	}

	pptr->port_ipkt_cnt--;
	mutex_exit(&pptr->port_mutex);
}

/*
 *     Function: fcp_alloc_dma
 *
 *  Description: Allocated the DMA resources required for the internal
 *		 packet.
 *
 *     Argument: *pptr	FCP port.
 *		 *icmd	Internal FCP packet.
 *		 nodma	Indicates if the Cmd and Resp will be DMAed.
 *		 flags	Allocation flags (Sleep or NoSleep).
 *
 * Return Value: FC_SUCCESS
 *		 FC_NOMEM
 */
static int
fcp_alloc_dma(struct fcp_port *pptr, struct fcp_ipkt *icmd,
    int nodma, int flags)
{
	int		rval;
	size_t		real_size;
	uint_t		ccount;
	int		bound = 0;
	int		cmd_resp = 0;
	fc_packet_t	*fpkt;
	ddi_dma_cookie_t	pkt_data_cookie;
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;

	fpkt = &icmd->ipkt_fc_packet;

	ASSERT(fpkt->pkt_cmd_dma == NULL && fpkt->pkt_data_dma == NULL &&
	    fpkt->pkt_resp_dma == NULL);

	icmd->ipkt_nodma = nodma;

	if (nodma) {
		fpkt->pkt_cmd = kmem_zalloc(fpkt->pkt_cmdlen, flags);
		if (fpkt->pkt_cmd == NULL) {
			goto fail;
		}

		fpkt->pkt_resp = kmem_zalloc(fpkt->pkt_rsplen, flags);
		if (fpkt->pkt_resp == NULL) {
			goto fail;
		}
	} else {
		ASSERT(fpkt->pkt_cmdlen && fpkt->pkt_rsplen);

		rval = fcp_alloc_cmd_resp(pptr, fpkt, flags);
		if (rval == FC_FAILURE) {
			ASSERT(fpkt->pkt_cmd_dma == NULL &&
			    fpkt->pkt_resp_dma == NULL);
			goto fail;
		}
		cmd_resp++;
	}

	if ((fpkt->pkt_datalen != 0) &&
	    !(pptr->port_state & FCP_STATE_FCA_IS_NODMA)) {
		/*
		 * set up DMA handle and memory for the data in this packet
		 */
		if (ddi_dma_alloc_handle(pptr->port_dip,
		    &pptr->port_data_dma_attr, DDI_DMA_DONTWAIT,
		    NULL, &fpkt->pkt_data_dma) != DDI_SUCCESS) {
			goto fail;
		}

		if (ddi_dma_mem_alloc(fpkt->pkt_data_dma, fpkt->pkt_datalen,
		    &pptr->port_dma_acc_attr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, NULL, &fpkt->pkt_data,
		    &real_size, &fpkt->pkt_data_acc) != DDI_SUCCESS) {
			goto fail;
		}

		/* was DMA mem size gotten < size asked for/needed ?? */
		if (real_size < fpkt->pkt_datalen) {
			goto fail;
		}

		/* bind DMA address and handle together */
		if (ddi_dma_addr_bind_handle(fpkt->pkt_data_dma,
		    NULL, fpkt->pkt_data, real_size, DDI_DMA_READ |
		    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    &pkt_data_cookie, &ccount) != DDI_DMA_MAPPED) {
			goto fail;
		}
		bound++;

		if (ccount > pptr->port_data_dma_attr.dma_attr_sgllen) {
			goto fail;
		}

		fpkt->pkt_data_cookie_cnt = ccount;

		cp = fpkt->pkt_data_cookie;
		*cp = pkt_data_cookie;
		cp++;

		for (cnt = 1; cnt < ccount; cnt++, cp++) {
			ddi_dma_nextcookie(fpkt->pkt_data_dma,
			    &pkt_data_cookie);
			*cp = pkt_data_cookie;
		}

	} else if (fpkt->pkt_datalen != 0) {
		/*
		 * If it's a pseudo FCA, then it can't support DMA even in
		 * SCSI data phase.
		 */
		fpkt->pkt_data = kmem_alloc(fpkt->pkt_datalen, flags);
		if (fpkt->pkt_data == NULL) {
			goto fail;
		}

	}

	return (FC_SUCCESS);

fail:
	if (bound) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_data_dma);
	}

	if (fpkt->pkt_data_dma) {
		if (fpkt->pkt_data) {
			ddi_dma_mem_free(&fpkt->pkt_data_acc);
		}
		ddi_dma_free_handle(&fpkt->pkt_data_dma);
	} else {
		if (fpkt->pkt_data) {
			kmem_free(fpkt->pkt_data, fpkt->pkt_datalen);
		}
	}

	if (nodma) {
		if (fpkt->pkt_cmd) {
			kmem_free(fpkt->pkt_cmd, fpkt->pkt_cmdlen);
		}
		if (fpkt->pkt_resp) {
			kmem_free(fpkt->pkt_resp, fpkt->pkt_rsplen);
		}
	} else {
		if (cmd_resp) {
			fcp_free_cmd_resp(pptr, fpkt);
		}
	}

	return (FC_NOMEM);
}


static void
fcp_free_dma(struct fcp_port *pptr, struct fcp_ipkt *icmd)
{
	fc_packet_t *fpkt = icmd->ipkt_fpkt;

	if (fpkt->pkt_data_dma) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_data_dma);
		if (fpkt->pkt_data) {
			ddi_dma_mem_free(&fpkt->pkt_data_acc);
		}
		ddi_dma_free_handle(&fpkt->pkt_data_dma);
	} else {
		if (fpkt->pkt_data) {
			kmem_free(fpkt->pkt_data, fpkt->pkt_datalen);
		}
		/*
		 * Need we reset pkt_* to zero???
		 */
	}

	if (icmd->ipkt_nodma) {
		if (fpkt->pkt_cmd) {
			kmem_free(fpkt->pkt_cmd, icmd->ipkt_cmdlen);
		}
		if (fpkt->pkt_resp) {
			kmem_free(fpkt->pkt_resp, icmd->ipkt_resplen);
		}
	} else {
		ASSERT(fpkt->pkt_resp_dma != NULL && fpkt->pkt_cmd_dma != NULL);

		fcp_free_cmd_resp(pptr, fpkt);
	}
}

/*
 *     Function: fcp_lookup_target
 *
 *  Description: Finds a target given a WWN.
 *
 *     Argument: *pptr	FCP port.
 *		 *wwn	World Wide Name of the device to look for.
 *
 * Return Value: NULL		No target found
 *		 Not NULL	Target structure
 *
 *	Context: Interrupt context.
 *		 The mutex pptr->port_mutex must be owned.
 */
/* ARGSUSED */
static struct fcp_tgt *
fcp_lookup_target(struct fcp_port *pptr, uchar_t *wwn)
{
	int			hash;
	struct fcp_tgt	*ptgt;

	ASSERT(mutex_owned(&pptr->port_mutex));

	hash = FCP_HASH(wwn);

	for (ptgt = pptr->port_tgt_hash_table[hash]; ptgt != NULL;
	    ptgt = ptgt->tgt_next) {
		if (!(ptgt->tgt_state & FCP_TGT_ORPHAN) &&
		    bcmp((caddr_t)wwn, (caddr_t)&ptgt->tgt_port_wwn.raw_wwn[0],
		    sizeof (ptgt->tgt_port_wwn)) == 0) {
			break;
		}
	}

	return (ptgt);
}


/*
 * Find target structure given a port identifier
 */
static struct fcp_tgt *
fcp_get_target_by_did(struct fcp_port *pptr, uint32_t d_id)
{
	fc_portid_t		port_id;
	la_wwn_t		pwwn;
	struct fcp_tgt	*ptgt = NULL;

	port_id.priv_lilp_posit = 0;
	port_id.port_id = d_id;
	if (fc_ulp_get_pwwn_by_did(pptr->port_fp_handle, port_id,
	    &pwwn) == FC_SUCCESS) {
		mutex_enter(&pptr->port_mutex);
		ptgt = fcp_lookup_target(pptr, pwwn.raw_wwn);
		mutex_exit(&pptr->port_mutex);
	}

	return (ptgt);
}


/*
 * the packet completion callback routine for info cmd pkts
 *
 * this means fpkt pts to a response to either a PLOGI or a PRLI
 *
 * if there is an error an attempt is made to call a routine to resend
 * the command that failed
 */
static void
fcp_icmd_callback(fc_packet_t *fpkt)
{
	struct fcp_ipkt	*icmd;
	struct fcp_port	*pptr;
	struct fcp_tgt	*ptgt;
	struct la_els_prli	*prli;
	struct la_els_prli	prli_s;
	struct fcp_prli		*fprli;
	struct fcp_lun	*plun;
	int		free_pkt = 1;
	int		rval;
	ls_code_t	resp;
	uchar_t		prli_acc = 0;
	uint32_t	rscn_count = FC_INVALID_RSCN_COUNT;
	int		lun0_newalloc;

	icmd = (struct fcp_ipkt *)fpkt->pkt_ulp_private;

	/* get ptrs to the port and target structs for the cmd */
	pptr = icmd->ipkt_port;
	ptgt = icmd->ipkt_tgt;

	FCP_CP_IN(fpkt->pkt_resp, &resp, fpkt->pkt_resp_acc, sizeof (resp));

	if (icmd->ipkt_opcode == LA_ELS_PRLI) {
		FCP_CP_IN(fpkt->pkt_cmd, &prli_s, fpkt->pkt_cmd_acc,
		    sizeof (prli_s));
		prli_acc = (prli_s.ls_code == LA_ELS_ACC);
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_2, 0,
	    "ELS (%x) callback state=0x%x reason=0x%x for %x",
	    icmd->ipkt_opcode, fpkt->pkt_state, fpkt->pkt_reason,
	    ptgt->tgt_d_id);

	if ((fpkt->pkt_state == FC_PKT_SUCCESS) &&
	    ((resp.ls_code == LA_ELS_ACC) || prli_acc)) {

		mutex_enter(&ptgt->tgt_mutex);
		if (ptgt->tgt_pd_handle == NULL) {
			/*
			 * in a fabric environment the port device handles
			 * get created only after successful LOGIN into the
			 * transport, so the transport makes this port
			 * device (pd) handle available in this packet, so
			 * save it now
			 */
			ASSERT(fpkt->pkt_pd != NULL);
			ptgt->tgt_pd_handle = fpkt->pkt_pd;
		}
		mutex_exit(&ptgt->tgt_mutex);

		/* which ELS cmd is this response for ?? */
		switch (icmd->ipkt_opcode) {
		case LA_ELS_PLOGI:
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_5, 0,
			    "PLOGI to d_id=0x%x succeeded, wwn=%08x%08x",
			    ptgt->tgt_d_id,
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[0]),
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[4]));

			FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
			    FCP_TGT_TRACE_15);

			/* Note that we are not allocating a new icmd */
			if (fcp_send_els(pptr, ptgt, icmd, LA_ELS_PRLI,
			    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
			    icmd->ipkt_cause) != DDI_SUCCESS) {
				FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
				    FCP_TGT_TRACE_16);
				goto fail;
			}
			break;

		case LA_ELS_PRLI:
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_5, 0,
			    "PRLI to d_id=0x%x succeeded", ptgt->tgt_d_id);

			FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
			    FCP_TGT_TRACE_17);

			prli = &prli_s;

			FCP_CP_IN(fpkt->pkt_resp, prli, fpkt->pkt_resp_acc,
			    sizeof (prli_s));

			fprli = (struct fcp_prli *)prli->service_params;

			mutex_enter(&ptgt->tgt_mutex);
			ptgt->tgt_icap = fprli->initiator_fn;
			ptgt->tgt_tcap = fprli->target_fn;
			mutex_exit(&ptgt->tgt_mutex);

			if ((fprli->type != 0x08) || (fprli->target_fn != 1)) {
				/*
				 * this FCP device does not support target mode
				 */
				FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
				    FCP_TGT_TRACE_18);
				goto fail;
			}
			if (fprli->retry == 1) {
				fc_ulp_disable_relogin(pptr->port_fp_handle,
				    &ptgt->tgt_port_wwn);
			}

			/* target is no longer offline */
			mutex_enter(&pptr->port_mutex);
			mutex_enter(&ptgt->tgt_mutex);
			if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {
				ptgt->tgt_state &= ~(FCP_TGT_OFFLINE |
				    FCP_TGT_MARK);
			} else {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "fcp_icmd_callback,1: state change "
				    " occured for D_ID=0x%x", ptgt->tgt_d_id);
				mutex_exit(&ptgt->tgt_mutex);
				mutex_exit(&pptr->port_mutex);
				goto fail;
			}
			mutex_exit(&ptgt->tgt_mutex);
			mutex_exit(&pptr->port_mutex);

			/*
			 * lun 0 should always respond to inquiry, so
			 * get the LUN struct for LUN 0
			 *
			 * Currently we deal with first level of addressing.
			 * If / when we start supporting 0x device types
			 * (DTYPE_ARRAY_CTRL, i.e. array controllers)
			 * this logic will need revisiting.
			 */
			lun0_newalloc = 0;
			if ((plun = fcp_get_lun(ptgt, 0)) == NULL) {
				/*
				 * no LUN struct for LUN 0 yet exists,
				 * so create one
				 */
				plun = fcp_alloc_lun(ptgt);
				if (plun == NULL) {
					fcp_log(CE_WARN, pptr->port_dip,
					    "!Failed to allocate lun 0 for"
					    " D_ID=%x", ptgt->tgt_d_id);
					goto fail;
				}
				lun0_newalloc = 1;
			}

			/* fill in LUN info */
			mutex_enter(&ptgt->tgt_mutex);
			/*
			 * consider lun 0 as device not connected if it is
			 * offlined or newly allocated
			 */
			if ((plun->lun_state & FCP_LUN_OFFLINE) ||
			    lun0_newalloc) {
				plun->lun_state |= FCP_LUN_DEVICE_NOT_CONNECTED;
			}
			plun->lun_state |= (FCP_LUN_BUSY | FCP_LUN_MARK);
			plun->lun_state &= ~FCP_LUN_OFFLINE;
			ptgt->tgt_lun_cnt = 1;
			ptgt->tgt_report_lun_cnt = 0;
			mutex_exit(&ptgt->tgt_mutex);

			/* Retrieve the rscn count (if a valid one exists) */
			if (icmd->ipkt_fpkt->pkt_ulp_rscn_infop != NULL) {
				rscn_count = ((fc_ulp_rscn_info_t *)
				    (icmd->ipkt_fpkt->pkt_ulp_rscn_infop))
				    ->ulp_rscn_count;
			} else {
				rscn_count = FC_INVALID_RSCN_COUNT;
			}

			/* send Report Lun request to target */
			if (fcp_send_scsi(plun, SCMD_REPORT_LUN,
			    sizeof (struct fcp_reportlun_resp),
			    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
			    icmd->ipkt_cause, rscn_count) != DDI_SUCCESS) {
				mutex_enter(&pptr->port_mutex);
				if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {
					fcp_log(CE_WARN, pptr->port_dip,
					    "!Failed to send REPORT LUN to"
					    "  D_ID=%x", ptgt->tgt_d_id);
				} else {
					FCP_TRACE(fcp_logq,
					    pptr->port_instbuf, fcp_trace,
					    FCP_BUF_LEVEL_5, 0,
					    "fcp_icmd_callback,2:state change"
					    " occured for D_ID=0x%x",
					    ptgt->tgt_d_id);
				}
				mutex_exit(&pptr->port_mutex);

				FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
				    FCP_TGT_TRACE_19);

				goto fail;
			} else {
				free_pkt = 0;
				fcp_icmd_free(pptr, icmd);
			}
			break;

		default:
			fcp_log(CE_WARN, pptr->port_dip,
			    "!fcp_icmd_callback Invalid opcode");
			goto fail;
		}

		return;
	}


	/*
	 * Other PLOGI failures are not retried as the
	 * transport does it already
	 */
	if (icmd->ipkt_opcode != LA_ELS_PLOGI) {
		if (fcp_is_retryable(icmd) &&
		    icmd->ipkt_retries++ < FCP_MAX_RETRIES) {

			if (FCP_MUST_RETRY(fpkt)) {
				fcp_queue_ipkt(pptr, fpkt);
				return;
			}

			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "ELS PRLI is retried for d_id=0x%x, state=%x,"
			    " reason= %x", ptgt->tgt_d_id, fpkt->pkt_state,
			    fpkt->pkt_reason);

			/*
			 * Retry by recalling the routine that
			 * originally queued this packet
			 */
			mutex_enter(&pptr->port_mutex);
			if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {
				caddr_t msg;

				mutex_exit(&pptr->port_mutex);

				ASSERT(icmd->ipkt_opcode != LA_ELS_PLOGI);

				if (fpkt->pkt_state == FC_PKT_TIMEOUT) {
					fpkt->pkt_timeout +=
					    FCP_TIMEOUT_DELTA;
				}

				rval = fc_ulp_issue_els(pptr->port_fp_handle,
				    fpkt);
				if (rval == FC_SUCCESS) {
					return;
				}

				if (rval == FC_STATEC_BUSY ||
				    rval == FC_OFFLINE) {
					fcp_queue_ipkt(pptr, fpkt);
					return;
				}
				(void) fc_ulp_error(rval, &msg);

				fcp_log(CE_NOTE, pptr->port_dip,
				    "!ELS 0x%x failed to d_id=0x%x;"
				    " %s", icmd->ipkt_opcode,
				    ptgt->tgt_d_id, msg);
			} else {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "fcp_icmd_callback,3: state change "
				    " occured for D_ID=0x%x", ptgt->tgt_d_id);
				mutex_exit(&pptr->port_mutex);
			}
		}
	} else {
		if (fcp_is_retryable(icmd) &&
		    icmd->ipkt_retries++ < FCP_MAX_RETRIES) {
			if (FCP_MUST_RETRY(fpkt)) {
				fcp_queue_ipkt(pptr, fpkt);
				return;
			}
		}
		mutex_enter(&pptr->port_mutex);
		if (!FCP_TGT_STATE_CHANGED(ptgt, icmd) &&
		    fpkt->pkt_state != FC_PKT_PORT_OFFLINE) {
			mutex_exit(&pptr->port_mutex);
			fcp_print_error(fpkt);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_icmd_callback,4: state change occured"
			    " for D_ID=0x%x", ptgt->tgt_d_id);
			mutex_exit(&pptr->port_mutex);
		}
	}

fail:
	if (free_pkt) {
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
	}
}


/*
 * called internally to send an info cmd using the transport
 *
 * sends either an INQ or a REPORT_LUN
 *
 * when the packet is completed fcp_scsi_callback is called
 */
static int
fcp_send_scsi(struct fcp_lun *plun, uchar_t opcode, int alloc_len,
    int lcount, int tcount, int cause, uint32_t rscn_count)
{
	int			nodma;
	struct fcp_ipkt		*icmd;
	struct fcp_tgt		*ptgt;
	struct fcp_port		*pptr;
	fc_frame_hdr_t		*hp;
	fc_packet_t		*fpkt;
	struct fcp_cmd		fcp_cmd;
	struct fcp_cmd		*fcmd;
	union scsi_cdb		*scsi_cdb;

	ASSERT(plun != NULL);

	ptgt = plun->lun_tgt;
	ASSERT(ptgt != NULL);

	pptr = ptgt->tgt_port;
	ASSERT(pptr != NULL);

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "fcp_send_scsi: d_id=0x%x opcode=0x%x", ptgt->tgt_d_id, opcode);

	nodma = (pptr->port_fcp_dma == FC_NO_DVMA_SPACE) ? 1 : 0;
	icmd = fcp_icmd_alloc(pptr, ptgt, sizeof (struct fcp_cmd),
	    FCP_MAX_RSP_IU_SIZE, alloc_len, nodma, lcount, tcount, cause,
	    rscn_count);

	if (icmd == NULL) {
		return (DDI_FAILURE);
	}

	fpkt = icmd->ipkt_fpkt;
	fpkt->pkt_tran_flags = FC_TRAN_CLASS3 | FC_TRAN_INTR;
	icmd->ipkt_retries = 0;
	icmd->ipkt_opcode = opcode;
	icmd->ipkt_lun = plun;

	if (nodma) {
		fcmd = (struct fcp_cmd *)fpkt->pkt_cmd;
	} else {
		fcmd = &fcp_cmd;
	}
	bzero(fcmd, sizeof (struct fcp_cmd));

	fpkt->pkt_timeout = FCP_SCSI_CMD_TIMEOUT;

	hp = &fpkt->pkt_cmd_fhdr;

	hp->s_id = pptr->port_id;
	hp->d_id = ptgt->tgt_d_id;
	hp->r_ctl = R_CTL_COMMAND;
	hp->type = FC_TYPE_SCSI_FCP;
	hp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	hp->rsvd = 0;
	hp->seq_id = 0;
	hp->seq_cnt = 0;
	hp->ox_id = 0xffff;
	hp->rx_id = 0xffff;
	hp->ro = 0;

	bcopy(&(plun->lun_addr), &(fcmd->fcp_ent_addr), FCP_LUN_SIZE);

	/*
	 * Request SCSI target for expedited processing
	 */

	/*
	 * Set up for untagged queuing because we do not
	 * know if the fibre device supports queuing.
	 */
	fcmd->fcp_cntl.cntl_reserved_0 = 0;
	fcmd->fcp_cntl.cntl_reserved_1 = 0;
	fcmd->fcp_cntl.cntl_reserved_2 = 0;
	fcmd->fcp_cntl.cntl_reserved_3 = 0;
	fcmd->fcp_cntl.cntl_reserved_4 = 0;
	fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_UNTAGGED;
	scsi_cdb = (union scsi_cdb *)fcmd->fcp_cdb;

	switch (opcode) {
	case SCMD_INQUIRY_PAGE83:
		/*
		 * Prepare to get the Inquiry VPD page 83 information
		 */
		fcmd->fcp_cntl.cntl_read_data = 1;
		fcmd->fcp_cntl.cntl_write_data = 0;
		fcmd->fcp_data_len = alloc_len;

		fpkt->pkt_tran_type = FC_PKT_FCP_READ;
		fpkt->pkt_comp = fcp_scsi_callback;

		scsi_cdb->scc_cmd = SCMD_INQUIRY;
		scsi_cdb->g0_addr2 = 0x01;
		scsi_cdb->g0_addr1 = 0x83;
		scsi_cdb->g0_count0 = (uchar_t)alloc_len;
		break;

	case SCMD_INQUIRY:
		fcmd->fcp_cntl.cntl_read_data = 1;
		fcmd->fcp_cntl.cntl_write_data = 0;
		fcmd->fcp_data_len = alloc_len;

		fpkt->pkt_tran_type = FC_PKT_FCP_READ;
		fpkt->pkt_comp = fcp_scsi_callback;

		scsi_cdb->scc_cmd = SCMD_INQUIRY;
		scsi_cdb->g0_count0 = SUN_INQSIZE;
		break;

	case SCMD_REPORT_LUN: {
		fc_portid_t	d_id;
		opaque_t	fca_dev;

		ASSERT(alloc_len >= 16);

		d_id.priv_lilp_posit = 0;
		d_id.port_id = ptgt->tgt_d_id;

		fca_dev = fc_ulp_get_fca_device(pptr->port_fp_handle, d_id);

		mutex_enter(&ptgt->tgt_mutex);
		ptgt->tgt_fca_dev = fca_dev;
		mutex_exit(&ptgt->tgt_mutex);

		fcmd->fcp_cntl.cntl_read_data = 1;
		fcmd->fcp_cntl.cntl_write_data = 0;
		fcmd->fcp_data_len = alloc_len;

		fpkt->pkt_tran_type = FC_PKT_FCP_READ;
		fpkt->pkt_comp = fcp_scsi_callback;

		scsi_cdb->scc_cmd = SCMD_REPORT_LUN;
		scsi_cdb->scc5_count0 = alloc_len & 0xff;
		scsi_cdb->scc5_count1 = (alloc_len >> 8) & 0xff;
		scsi_cdb->scc5_count2 = (alloc_len >> 16) & 0xff;
		scsi_cdb->scc5_count3 = (alloc_len >> 24) & 0xff;
		break;
	}

	default:
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp_send_scsi Invalid opcode");
		break;
	}

	if (!nodma) {
		FCP_CP_OUT((uint8_t *)fcmd, fpkt->pkt_cmd,
		    fpkt->pkt_cmd_acc, sizeof (struct fcp_cmd));
	}

	mutex_enter(&pptr->port_mutex);
	if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {

		mutex_exit(&pptr->port_mutex);
		if (fcp_transport(pptr->port_fp_handle, fpkt, 1) !=
		    FC_SUCCESS) {
			fcp_icmd_free(pptr, icmd);
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	} else {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "fcp_send_scsi,1: state change occured"
		    " for D_ID=0x%x", ptgt->tgt_d_id);
		mutex_exit(&pptr->port_mutex);
		fcp_icmd_free(pptr, icmd);
		return (DDI_FAILURE);
	}
}


/*
 * called by fcp_scsi_callback to check to handle the case where
 * REPORT_LUN returns ILLEGAL REQUEST or a UNIT ATTENTION
 */
static int
fcp_check_reportlun(struct fcp_rsp *rsp, fc_packet_t *fpkt)
{
	uchar_t				rqlen;
	int				rval = DDI_FAILURE;
	struct scsi_extended_sense	sense_info, *sense;
	struct fcp_ipkt		*icmd = (struct fcp_ipkt *)
	    fpkt->pkt_ulp_private;
	struct fcp_tgt		*ptgt = icmd->ipkt_tgt;
	struct fcp_port		*pptr = ptgt->tgt_port;

	ASSERT(icmd->ipkt_opcode == SCMD_REPORT_LUN);

	if (rsp->fcp_u.fcp_status.scsi_status == STATUS_RESERVATION_CONFLICT) {
		/*
		 * SCSI-II Reserve Release support. Some older FC drives return
		 * Reservation conflict for Report Luns command.
		 */
		if (icmd->ipkt_nodma) {
			rsp->fcp_u.fcp_status.rsp_len_set = 0;
			rsp->fcp_u.fcp_status.sense_len_set = 0;
			rsp->fcp_u.fcp_status.scsi_status = STATUS_GOOD;
		} else {
			fcp_rsp_t	new_resp;

			FCP_CP_IN(fpkt->pkt_resp, &new_resp,
			    fpkt->pkt_resp_acc, sizeof (new_resp));

			new_resp.fcp_u.fcp_status.rsp_len_set = 0;
			new_resp.fcp_u.fcp_status.sense_len_set = 0;
			new_resp.fcp_u.fcp_status.scsi_status = STATUS_GOOD;

			FCP_CP_OUT(&new_resp, fpkt->pkt_resp,
			    fpkt->pkt_resp_acc, sizeof (new_resp));
		}

		FCP_CP_OUT(fcp_dummy_lun, fpkt->pkt_data,
		    fpkt->pkt_data_acc, sizeof (fcp_dummy_lun));

		return (DDI_SUCCESS);
	}

	sense = &sense_info;
	if (!rsp->fcp_u.fcp_status.sense_len_set) {
		/* no need to continue if sense length is not set */
		return (rval);
	}

	/* casting 64-bit integer to 8-bit */
	rqlen = (uchar_t)min(rsp->fcp_sense_len,
	    sizeof (struct scsi_extended_sense));

	if (rqlen < 14) {
		/* no need to continue if request length isn't long enough */
		return (rval);
	}

	if (icmd->ipkt_nodma) {
		/*
		 * We can safely use fcp_response_len here since the
		 * only path that calls fcp_check_reportlun,
		 * fcp_scsi_callback, has already called
		 * fcp_validate_fcp_response.
		 */
		sense = (struct scsi_extended_sense *)(fpkt->pkt_resp +
		    sizeof (struct fcp_rsp) + rsp->fcp_response_len);
	} else {
		FCP_CP_IN(fpkt->pkt_resp + sizeof (struct fcp_rsp) +
		    rsp->fcp_response_len, sense, fpkt->pkt_resp_acc,
		    sizeof (struct scsi_extended_sense));
	}

	if (!FCP_SENSE_NO_LUN(sense)) {
		mutex_enter(&ptgt->tgt_mutex);
		/* clear the flag if any */
		ptgt->tgt_state &= ~FCP_TGT_ILLREQ;
		mutex_exit(&ptgt->tgt_mutex);
	}

	if ((sense->es_key == KEY_ILLEGAL_REQUEST) &&
	    (sense->es_add_code == 0x20)) {
		if (icmd->ipkt_nodma) {
			rsp->fcp_u.fcp_status.rsp_len_set = 0;
			rsp->fcp_u.fcp_status.sense_len_set = 0;
			rsp->fcp_u.fcp_status.scsi_status = STATUS_GOOD;
		} else {
			fcp_rsp_t	new_resp;

			FCP_CP_IN(fpkt->pkt_resp, &new_resp,
			    fpkt->pkt_resp_acc, sizeof (new_resp));

			new_resp.fcp_u.fcp_status.rsp_len_set = 0;
			new_resp.fcp_u.fcp_status.sense_len_set = 0;
			new_resp.fcp_u.fcp_status.scsi_status = STATUS_GOOD;

			FCP_CP_OUT(&new_resp, fpkt->pkt_resp,
			    fpkt->pkt_resp_acc, sizeof (new_resp));
		}

		FCP_CP_OUT(fcp_dummy_lun, fpkt->pkt_data,
		    fpkt->pkt_data_acc, sizeof (fcp_dummy_lun));

		return (DDI_SUCCESS);
	}

	/*
	 * This is for the STK library which returns a check condition,
	 * to indicate device is not ready, manual assistance needed.
	 * This is to a report lun command when the door is open.
	 */
	if ((sense->es_key == KEY_NOT_READY) && (sense->es_add_code == 0x04)) {
		if (icmd->ipkt_nodma) {
			rsp->fcp_u.fcp_status.rsp_len_set = 0;
			rsp->fcp_u.fcp_status.sense_len_set = 0;
			rsp->fcp_u.fcp_status.scsi_status = STATUS_GOOD;
		} else {
			fcp_rsp_t	new_resp;

			FCP_CP_IN(fpkt->pkt_resp, &new_resp,
			    fpkt->pkt_resp_acc, sizeof (new_resp));

			new_resp.fcp_u.fcp_status.rsp_len_set = 0;
			new_resp.fcp_u.fcp_status.sense_len_set = 0;
			new_resp.fcp_u.fcp_status.scsi_status = STATUS_GOOD;

			FCP_CP_OUT(&new_resp, fpkt->pkt_resp,
			    fpkt->pkt_resp_acc, sizeof (new_resp));
		}

		FCP_CP_OUT(fcp_dummy_lun, fpkt->pkt_data,
		    fpkt->pkt_data_acc, sizeof (fcp_dummy_lun));

		return (DDI_SUCCESS);
	}

	if ((FCP_SENSE_REPORTLUN_CHANGED(sense)) ||
	    (FCP_SENSE_NO_LUN(sense))) {
		mutex_enter(&ptgt->tgt_mutex);
		if ((FCP_SENSE_NO_LUN(sense)) &&
		    (ptgt->tgt_state & FCP_TGT_ILLREQ)) {
			ptgt->tgt_state &= ~FCP_TGT_ILLREQ;
			mutex_exit(&ptgt->tgt_mutex);
			/*
			 * reconfig was triggred by ILLEGAL REQUEST but
			 * got ILLEGAL REQUEST again
			 */
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "!FCP: Unable to obtain Report Lun data"
			    " target=%x", ptgt->tgt_d_id);
		} else {
			if (ptgt->tgt_tid == NULL) {
				timeout_id_t	tid;
				/*
				 * REPORT LUN data has changed.	 Kick off
				 * rediscovery
				 */
				tid = timeout(fcp_reconfigure_luns,
				    (caddr_t)ptgt, (clock_t)drv_usectohz(1));

				ptgt->tgt_tid = tid;
				ptgt->tgt_state |= FCP_TGT_BUSY;
			}
			if (FCP_SENSE_NO_LUN(sense)) {
				ptgt->tgt_state |= FCP_TGT_ILLREQ;
			}
			mutex_exit(&ptgt->tgt_mutex);
			if (FCP_SENSE_REPORTLUN_CHANGED(sense)) {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_3, 0,
				    "!FCP:Report Lun Has Changed"
				    " target=%x", ptgt->tgt_d_id);
			} else if (FCP_SENSE_NO_LUN(sense)) {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_3, 0,
				    "!FCP:LU Not Supported"
				    " target=%x", ptgt->tgt_d_id);
			}
		}
		rval = DDI_SUCCESS;
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "D_ID=%x, sense=%x, status=%x",
	    fpkt->pkt_cmd_fhdr.d_id, sense->es_key,
	    rsp->fcp_u.fcp_status.scsi_status);

	return (rval);
}

/*
 *     Function: fcp_scsi_callback
 *
 *  Description: This is the callback routine set by fcp_send_scsi() after
 *		 it calls fcp_icmd_alloc().  The SCSI command completed here
 *		 and autogenerated by FCP are:	REPORT_LUN, INQUIRY and
 *		 INQUIRY_PAGE83.
 *
 *     Argument: *fpkt	 FC packet used to convey the command
 *
 * Return Value: None
 */
static void
fcp_scsi_callback(fc_packet_t *fpkt)
{
	struct fcp_ipkt	*icmd = (struct fcp_ipkt *)
	    fpkt->pkt_ulp_private;
	struct fcp_rsp_info	fcp_rsp_err, *bep;
	struct fcp_port	*pptr;
	struct fcp_tgt	*ptgt;
	struct fcp_lun	*plun;
	struct fcp_rsp		response, *rsp;

	ptgt = icmd->ipkt_tgt;
	pptr = ptgt->tgt_port;
	plun = icmd->ipkt_lun;

	if (icmd->ipkt_nodma) {
		rsp = (struct fcp_rsp *)fpkt->pkt_resp;
	} else {
		rsp = &response;
		FCP_CP_IN(fpkt->pkt_resp, rsp, fpkt->pkt_resp_acc,
		    sizeof (struct fcp_rsp));
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_2, 0,
	    "SCSI callback state=0x%x for %x, op_code=0x%x, "
	    "status=%x, lun num=%x",
	    fpkt->pkt_state, ptgt->tgt_d_id, icmd->ipkt_opcode,
	    rsp->fcp_u.fcp_status.scsi_status, plun->lun_num);

	/*
	 * Pre-init LUN GUID with NWWN if it is not a device that
	 * supports multiple luns and we know it's not page83
	 * compliant.  Although using a NWWN is not lun unique,
	 * we will be fine since there is only one lun behind the taget
	 * in this case.
	 */
	if ((plun->lun_guid_size == 0) &&
	    (icmd->ipkt_opcode == SCMD_INQUIRY_PAGE83) &&
	    (fcp_symmetric_device_probe(plun) == 0)) {

		char ascii_wwn[FC_WWN_SIZE*2+1];
		fcp_wwn_to_ascii(&ptgt->tgt_node_wwn.raw_wwn[0], ascii_wwn);
		(void) fcp_copy_guid_2_lun_block(plun, ascii_wwn);
	}

	/*
	 * Some old FC tapes and FC <-> SCSI bridge devices return overrun
	 * when thay have more data than what is asked in CDB. An overrun
	 * is really when FCP_DL is smaller than the data length in CDB.
	 * In the case here we know that REPORT LUN command we formed within
	 * this binary has correct FCP_DL. So this OVERRUN is due to bad device
	 * behavior. In reality this is FC_SUCCESS.
	 */
	if ((fpkt->pkt_state != FC_PKT_SUCCESS) &&
	    (fpkt->pkt_reason == FC_REASON_OVERRUN) &&
	    (icmd->ipkt_opcode == SCMD_REPORT_LUN)) {
		fpkt->pkt_state = FC_PKT_SUCCESS;
	}

	if (fpkt->pkt_state != FC_PKT_SUCCESS) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "icmd failed with state=0x%x for %x", fpkt->pkt_state,
		    ptgt->tgt_d_id);

		if (fpkt->pkt_reason == FC_REASON_CRC_ERROR) {
			/*
			 * Inquiry VPD page command on A5K SES devices would
			 * result in data CRC errors.
			 */
			if (icmd->ipkt_opcode == SCMD_INQUIRY_PAGE83) {
				(void) fcp_handle_page83(fpkt, icmd, 1);
				return;
			}
		}
		if (fpkt->pkt_state == FC_PKT_TIMEOUT ||
		    FCP_MUST_RETRY(fpkt)) {
			fpkt->pkt_timeout += FCP_TIMEOUT_DELTA;
			fcp_retry_scsi_cmd(fpkt);
			return;
		}

		FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
		    FCP_TGT_TRACE_20);

		mutex_enter(&pptr->port_mutex);
		mutex_enter(&ptgt->tgt_mutex);
		if (!FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
			mutex_exit(&ptgt->tgt_mutex);
			mutex_exit(&pptr->port_mutex);
			fcp_print_error(fpkt);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_scsi_callback,1: state change occured"
			    " for D_ID=0x%x", ptgt->tgt_d_id);
			mutex_exit(&ptgt->tgt_mutex);
			mutex_exit(&pptr->port_mutex);
		}
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}

	FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt, FCP_TGT_TRACE_21);

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&ptgt->tgt_mutex);
	if (FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "fcp_scsi_callback,2: state change occured"
		    " for D_ID=0x%x", ptgt->tgt_d_id);
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}
	ASSERT((ptgt->tgt_state & FCP_TGT_MARK) == 0);

	mutex_exit(&ptgt->tgt_mutex);
	mutex_exit(&pptr->port_mutex);

	if (icmd->ipkt_nodma) {
		bep = (struct fcp_rsp_info *)(fpkt->pkt_resp +
		    sizeof (struct fcp_rsp));
	} else {
		bep = &fcp_rsp_err;
		FCP_CP_IN(fpkt->pkt_resp + sizeof (struct fcp_rsp), bep,
		    fpkt->pkt_resp_acc, sizeof (struct fcp_rsp_info));
	}

	if (fcp_validate_fcp_response(rsp, pptr) != FC_SUCCESS) {
		fcp_retry_scsi_cmd(fpkt);
		return;
	}

	if (rsp->fcp_u.fcp_status.rsp_len_set && bep->rsp_code !=
	    FCP_NO_FAILURE) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "rsp_code=0x%x, rsp_len_set=0x%x",
		    bep->rsp_code, rsp->fcp_u.fcp_status.rsp_len_set);
		fcp_retry_scsi_cmd(fpkt);
		return;
	}

	if (rsp->fcp_u.fcp_status.scsi_status == STATUS_QFULL ||
	    rsp->fcp_u.fcp_status.scsi_status == STATUS_BUSY) {
		fcp_queue_ipkt(pptr, fpkt);
		return;
	}

	/*
	 * Devices that do not support INQUIRY_PAGE83, return check condition
	 * with illegal request as per SCSI spec.
	 * Crossbridge is one such device and Daktari's SES node is another.
	 * We want to ideally enumerate these devices as a non-mpxio devices.
	 * SES nodes (Daktari only currently) are an exception to this.
	 */
	if ((icmd->ipkt_opcode == SCMD_INQUIRY_PAGE83) &&
	    (rsp->fcp_u.fcp_status.scsi_status & STATUS_CHECK)) {

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "INQUIRY_PAGE83 for d_id %x (dtype:0x%x) failed with "
		    "check condition. May enumerate as non-mpxio device",
		    ptgt->tgt_d_id, plun->lun_type);

		/*
		 * If we let Daktari's SES be enumerated as a non-mpxio
		 * device, there will be a discrepency in that the other
		 * internal FC disks will get enumerated as mpxio devices.
		 * Applications like luxadm expect this to be consistent.
		 *
		 * So, we put in a hack here to check if this is an SES device
		 * and handle it here.
		 */
		if (plun->lun_type == DTYPE_ESI) {
			/*
			 * Since, pkt_state is actually FC_PKT_SUCCESS
			 * at this stage, we fake a failure here so that
			 * fcp_handle_page83 will create a device path using
			 * the WWN instead of the GUID which is not there anyway
			 */
			fpkt->pkt_state = FC_PKT_LOCAL_RJT;
			(void) fcp_handle_page83(fpkt, icmd, 1);
			return;
		}

		mutex_enter(&ptgt->tgt_mutex);
		plun->lun_state &= ~(FCP_LUN_OFFLINE |
		    FCP_LUN_MARK | FCP_LUN_BUSY);
		mutex_exit(&ptgt->tgt_mutex);

		(void) fcp_call_finish_init(pptr, ptgt,
		    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
		    icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}

	if (rsp->fcp_u.fcp_status.scsi_status != STATUS_GOOD) {
		int rval = DDI_FAILURE;

		/*
		 * handle cases where report lun isn't supported
		 * by faking up our own REPORT_LUN response or
		 * UNIT ATTENTION
		 */
		if (icmd->ipkt_opcode == SCMD_REPORT_LUN) {
			rval = fcp_check_reportlun(rsp, fpkt);

			/*
			 * fcp_check_reportlun might have modified the
			 * FCP response. Copy it in again to get an updated
			 * FCP response
			 */
			if (rval == DDI_SUCCESS && icmd->ipkt_nodma == 0) {
				rsp = &response;

				FCP_CP_IN(fpkt->pkt_resp, rsp,
				    fpkt->pkt_resp_acc,
				    sizeof (struct fcp_rsp));
			}
		}

		if (rsp->fcp_u.fcp_status.scsi_status != STATUS_GOOD) {
			if (rval == DDI_SUCCESS) {
				(void) fcp_call_finish_init(pptr, ptgt,
				    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
				    icmd->ipkt_cause);
				fcp_icmd_free(pptr, icmd);
			} else {
				fcp_retry_scsi_cmd(fpkt);
			}

			return;
		}
	} else {
		if (icmd->ipkt_opcode == SCMD_REPORT_LUN) {
			mutex_enter(&ptgt->tgt_mutex);
			ptgt->tgt_state &= ~FCP_TGT_ILLREQ;
			mutex_exit(&ptgt->tgt_mutex);
		}
	}

	ASSERT(rsp->fcp_u.fcp_status.scsi_status == STATUS_GOOD);
	if (!(pptr->port_state & FCP_STATE_FCA_IS_NODMA)) {
		(void) ddi_dma_sync(fpkt->pkt_data_dma, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
	}

	switch (icmd->ipkt_opcode) {
	case SCMD_INQUIRY:
		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_1);
		fcp_handle_inquiry(fpkt, icmd);
		break;

	case SCMD_REPORT_LUN:
		FCP_TGT_TRACE(ptgt, icmd->ipkt_change_cnt,
		    FCP_TGT_TRACE_22);
		fcp_handle_reportlun(fpkt, icmd);
		break;

	case SCMD_INQUIRY_PAGE83:
		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_2);
		(void) fcp_handle_page83(fpkt, icmd, 0);
		break;

	default:
		fcp_log(CE_WARN, NULL, "!Invalid SCSI opcode");
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		break;
	}
}


static void
fcp_retry_scsi_cmd(fc_packet_t *fpkt)
{
	struct fcp_ipkt	*icmd = (struct fcp_ipkt *)
	    fpkt->pkt_ulp_private;
	struct fcp_tgt	*ptgt = icmd->ipkt_tgt;
	struct fcp_port	*pptr = ptgt->tgt_port;

	if (icmd->ipkt_retries < FCP_MAX_RETRIES &&
	    fcp_is_retryable(icmd)) {
		mutex_enter(&pptr->port_mutex);
		if (!FCP_TGT_STATE_CHANGED(ptgt, icmd)) {
			mutex_exit(&pptr->port_mutex);
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "Retrying %s to %x; state=%x, reason=%x",
			    (icmd->ipkt_opcode == SCMD_REPORT_LUN) ?
			    "Report LUN" : "INQUIRY", ptgt->tgt_d_id,
			    fpkt->pkt_state, fpkt->pkt_reason);

			fcp_queue_ipkt(pptr, fpkt);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "fcp_retry_scsi_cmd,1: state change occured"
			    " for D_ID=0x%x", ptgt->tgt_d_id);
			mutex_exit(&pptr->port_mutex);
			(void) fcp_call_finish_init(pptr, ptgt,
			    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
			    icmd->ipkt_cause);
			fcp_icmd_free(pptr, icmd);
		}
	} else {
		fcp_print_error(fpkt);
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
	}
}

/*
 *     Function: fcp_handle_page83
 *
 *  Description: Treats the response to INQUIRY_PAGE83.
 *
 *     Argument: *fpkt	FC packet used to convey the command.
 *		 *icmd	Original fcp_ipkt structure.
 *		 ignore_page83_data
 *			if it's 1, that means it's a special devices's
 *			page83 response, it should be enumerated under mpxio
 *
 * Return Value: None
 */
static void
fcp_handle_page83(fc_packet_t *fpkt, struct fcp_ipkt *icmd,
    int ignore_page83_data)
{
	struct fcp_port	*pptr;
	struct fcp_lun	*plun;
	struct fcp_tgt	*ptgt;
	uchar_t			dev_id_page[SCMD_MAX_INQUIRY_PAGE83_SIZE];
	int			fail = 0;
	ddi_devid_t		devid;
	char			*guid = NULL;
	int			ret;

	ASSERT(icmd != NULL && fpkt != NULL);

	pptr = icmd->ipkt_port;
	ptgt = icmd->ipkt_tgt;
	plun = icmd->ipkt_lun;

	if (fpkt->pkt_state == FC_PKT_SUCCESS) {
		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_7);

		FCP_CP_IN(fpkt->pkt_data, dev_id_page, fpkt->pkt_data_acc,
		    SCMD_MAX_INQUIRY_PAGE83_SIZE);

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_5, 0,
		    "fcp_handle_page83: port=%d, tgt D_ID=0x%x, "
		    "dtype=0x%x, lun num=%x",
		    pptr->port_instance, ptgt->tgt_d_id,
		    dev_id_page[0], plun->lun_num);

		ret = ddi_devid_scsi_encode(
		    DEVID_SCSI_ENCODE_VERSION_LATEST,
		    NULL,		/* driver name */
		    (unsigned char *) &plun->lun_inq, /* standard inquiry */
		    sizeof (plun->lun_inq), /* size of standard inquiry */
		    NULL,		/* page 80 data */
		    0,		/* page 80 len */
		    dev_id_page,	/* page 83 data */
		    SCMD_MAX_INQUIRY_PAGE83_SIZE, /* page 83 data len */
		    &devid);

		if (ret == DDI_SUCCESS) {

			guid = ddi_devid_to_guid(devid);

			if (guid) {
				/*
				 * Check our current guid.  If it's non null
				 * and it has changed, we need to copy it into
				 * lun_old_guid since we might still need it.
				 */
				if (plun->lun_guid &&
				    strcmp(guid, plun->lun_guid)) {
					unsigned int len;

					/*
					 * If the guid of the LUN changes,
					 * reconfiguration should be triggered
					 * to reflect the changes.
					 * i.e. we should offline the LUN with
					 * the old guid, and online the LUN with
					 * the new guid.
					 */
					plun->lun_state |= FCP_LUN_CHANGED;

					if (plun->lun_old_guid) {
						kmem_free(plun->lun_old_guid,
						    plun->lun_old_guid_size);
					}

					len = plun->lun_guid_size;
					plun->lun_old_guid_size = len;

					plun->lun_old_guid = kmem_zalloc(len,
					    KM_NOSLEEP);

					if (plun->lun_old_guid) {
						/*
						 * The alloc was successful then
						 * let's do the copy.
						 */
						bcopy(plun->lun_guid,
						    plun->lun_old_guid, len);
					} else {
						fail = 1;
						plun->lun_old_guid_size = 0;
					}
				}
				if (!fail) {
					if (fcp_copy_guid_2_lun_block(
					    plun, guid)) {
						fail = 1;
					}
				}
				ddi_devid_free_guid(guid);

			} else {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "fcp_handle_page83: unable to create "
				    "GUID");

				/* couldn't create good guid from devid */
				fail = 1;
			}
			ddi_devid_free(devid);

		} else if (ret == DDI_NOT_WELL_FORMED) {
			/* NULL filled data for page 83 */
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_handle_page83: retry GUID");

			icmd->ipkt_retries = 0;
			fcp_retry_scsi_cmd(fpkt);
			return;
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_handle_page83: bad ddi_devid_scsi_encode %x",
			    ret);
			/*
			 * Since the page83 validation
			 * introduced late, we are being
			 * tolerant to the existing devices
			 * that already found to be working
			 * under mpxio, like A5200's SES device,
			 * its page83 response will not be standard-compliant,
			 * but we still want it to be enumerated under mpxio.
			 */
			if (fcp_symmetric_device_probe(plun) != 0) {
				fail = 1;
			}
		}

	} else {
		/* bad packet state */
		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_8);

		/*
		 * For some special devices (A5K SES and Daktari's SES devices),
		 * they should be enumerated under mpxio
		 * or "luxadm dis" will fail
		 */
		if (ignore_page83_data) {
			fail = 0;
		} else {
			fail = 1;
		}
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "!Devid page cmd failed. "
		    "fpkt_state: %x fpkt_reason: %x",
		    "ignore_page83: %d",
		    fpkt->pkt_state, fpkt->pkt_reason,
		    ignore_page83_data);
	}

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&plun->lun_mutex);
	/*
	 * If lun_cip is not NULL, then we needn't update lun_mpxio to avoid
	 * mismatch between lun_cip and lun_mpxio.
	 */
	if (plun->lun_cip == NULL) {
		/*
		 * If we don't have a guid for this lun it's because we were
		 * unable to glean one from the page 83 response.  Set the
		 * control flag to 0 here to make sure that we don't attempt to
		 * enumerate it under mpxio.
		 */
		if (fail || pptr->port_mpxio == 0) {
			plun->lun_mpxio = 0;
		} else {
			plun->lun_mpxio = 1;
		}
	}
	mutex_exit(&plun->lun_mutex);
	mutex_exit(&pptr->port_mutex);

	mutex_enter(&ptgt->tgt_mutex);
	plun->lun_state &=
	    ~(FCP_LUN_OFFLINE | FCP_LUN_MARK | FCP_LUN_BUSY);
	mutex_exit(&ptgt->tgt_mutex);

	(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
	    icmd->ipkt_change_cnt, icmd->ipkt_cause);

	fcp_icmd_free(pptr, icmd);
}

/*
 *     Function: fcp_handle_inquiry
 *
 *  Description: Called by fcp_scsi_callback to handle the response to an
 *		 INQUIRY request.
 *
 *     Argument: *fpkt	FC packet used to convey the command.
 *		 *icmd	Original fcp_ipkt structure.
 *
 * Return Value: None
 */
static void
fcp_handle_inquiry(fc_packet_t *fpkt, struct fcp_ipkt *icmd)
{
	struct fcp_port	*pptr;
	struct fcp_lun	*plun;
	struct fcp_tgt	*ptgt;
	uchar_t		dtype;
	uchar_t		pqual;
	uint32_t	rscn_count = FC_INVALID_RSCN_COUNT;

	ASSERT(icmd != NULL && fpkt != NULL);

	pptr = icmd->ipkt_port;
	ptgt = icmd->ipkt_tgt;
	plun = icmd->ipkt_lun;

	FCP_CP_IN(fpkt->pkt_data, &plun->lun_inq, fpkt->pkt_data_acc,
	    sizeof (struct scsi_inquiry));

	dtype = plun->lun_inq.inq_dtype & DTYPE_MASK;
	pqual = plun->lun_inq.inq_dtype >> 5;

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "fcp_handle_inquiry: port=%d, tgt D_ID=0x%x, lun=0x%x, "
	    "dtype=0x%x pqual: 0x%x", pptr->port_instance, ptgt->tgt_d_id,
	    plun->lun_num, dtype, pqual);

	if (pqual != 0) {
		/*
		 * Non-zero peripheral qualifier
		 */
		fcp_log(CE_CONT, pptr->port_dip,
		    "!Target 0x%x lun 0x%x: Nonzero peripheral qualifier: "
		    "Device type=0x%x Peripheral qual=0x%x\n",
		    ptgt->tgt_d_id, plun->lun_num, dtype, pqual);

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_5, 0,
		    "!Target 0x%x lun 0x%x: Nonzero peripheral qualifier: "
		    "Device type=0x%x Peripheral qual=0x%x\n",
		    ptgt->tgt_d_id, plun->lun_num, dtype, pqual);

		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_3);

		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}

	/*
	 * If the device is already initialized, check the dtype
	 * for a change. If it has changed then update the flags
	 * so the create_luns will offline the old device and
	 * create the new device. Refer to bug: 4764752
	 */
	if ((plun->lun_state & FCP_LUN_INIT) && dtype != plun->lun_type) {
		plun->lun_state |= FCP_LUN_CHANGED;
	}
	plun->lun_type = plun->lun_inq.inq_dtype;

	/*
	 * This code is setting/initializing the throttling in the FCA
	 * driver.
	 */
	mutex_enter(&pptr->port_mutex);
	if (!pptr->port_notify) {
		if (bcmp(plun->lun_inq.inq_pid, pid, strlen(pid)) == 0) {
			uint32_t cmd = 0;
			cmd = ((cmd & 0xFF | FC_NOTIFY_THROTTLE) |
			    ((cmd & 0xFFFFFF00 >> 8) |
			    FCP_SVE_THROTTLE << 8));
			pptr->port_notify = 1;
			mutex_exit(&pptr->port_mutex);
			(void) fc_ulp_port_notify(pptr->port_fp_handle, cmd);
			mutex_enter(&pptr->port_mutex);
		}
	}

	if (FCP_TGT_STATE_CHANGED(ptgt, icmd)) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "fcp_handle_inquiry,1:state change occured"
		    " for D_ID=0x%x", ptgt->tgt_d_id);
		mutex_exit(&pptr->port_mutex);

		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_5);
		(void) fcp_call_finish_init(pptr, ptgt,
		    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
		    icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}
	ASSERT((ptgt->tgt_state & FCP_TGT_MARK) == 0);
	mutex_exit(&pptr->port_mutex);

	/* Retrieve the rscn count (if a valid one exists) */
	if (icmd->ipkt_fpkt->pkt_ulp_rscn_infop != NULL) {
		rscn_count = ((fc_ulp_rscn_info_t *)
		    (icmd->ipkt_fpkt->pkt_ulp_rscn_infop))->ulp_rscn_count;
	} else {
		rscn_count = FC_INVALID_RSCN_COUNT;
	}

	if (fcp_send_scsi(plun, SCMD_INQUIRY_PAGE83,
	    SCMD_MAX_INQUIRY_PAGE83_SIZE,
	    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
	    icmd->ipkt_cause, rscn_count) != DDI_SUCCESS) {
		fcp_log(CE_WARN, NULL, "!failed to send page 83");
		FCP_LUN_TRACE(plun, FCP_LUN_TRACE_6);
		(void) fcp_call_finish_init(pptr, ptgt,
		    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
		    icmd->ipkt_cause);
	}

	/*
	 * Read Inquiry VPD Page 0x83 to uniquely
	 * identify this logical unit.
	 */
	fcp_icmd_free(pptr, icmd);
}

/*
 *     Function: fcp_handle_reportlun
 *
 *  Description: Called by fcp_scsi_callback to handle the response to a
 *		 REPORT_LUN request.
 *
 *     Argument: *fpkt	FC packet used to convey the command.
 *		 *icmd	Original fcp_ipkt structure.
 *
 * Return Value: None
 */
static void
fcp_handle_reportlun(fc_packet_t *fpkt, struct fcp_ipkt *icmd)
{
	int				i;
	int				nluns_claimed;
	int				nluns_bufmax;
	int				len;
	uint16_t			lun_num;
	uint32_t			rscn_count = FC_INVALID_RSCN_COUNT;
	struct fcp_port			*pptr;
	struct fcp_tgt			*ptgt;
	struct fcp_lun			*plun;
	struct fcp_reportlun_resp	*report_lun;

	pptr = icmd->ipkt_port;
	ptgt = icmd->ipkt_tgt;
	len = fpkt->pkt_datalen;

	if ((len < FCP_LUN_HEADER) ||
	    ((report_lun = kmem_zalloc(len, KM_NOSLEEP)) == NULL)) {
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}

	FCP_CP_IN(fpkt->pkt_data, report_lun, fpkt->pkt_data_acc,
	    fpkt->pkt_datalen);

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "fcp_handle_reportlun: port=%d, tgt D_ID=0x%x",
	    pptr->port_instance, ptgt->tgt_d_id);

	/*
	 * Get the number of luns (which is supplied as LUNS * 8) the
	 * device claims it has.
	 */
	nluns_claimed = BE_32(report_lun->num_lun) >> 3;

	/*
	 * Get the maximum number of luns the buffer submitted can hold.
	 */
	nluns_bufmax = (fpkt->pkt_datalen - FCP_LUN_HEADER) / FCP_LUN_SIZE;

	/*
	 * Due to limitations of certain hardware, we support only 16 bit LUNs
	 */
	if (nluns_claimed > FCP_MAX_LUNS_SUPPORTED) {
		kmem_free(report_lun, len);

		fcp_log(CE_NOTE, pptr->port_dip, "!Can not support"
		    " 0x%x number of LUNs for target=%x", nluns_claimed,
		    ptgt->tgt_d_id);

		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}

	/*
	 * If there are more LUNs than we have allocated memory for,
	 * allocate more space and send down yet another report lun if
	 * the maximum number of attempts hasn't been reached.
	 */
	mutex_enter(&ptgt->tgt_mutex);

	if ((nluns_claimed > nluns_bufmax) &&
	    (ptgt->tgt_report_lun_cnt < FCP_MAX_REPORTLUNS_ATTEMPTS)) {

		struct fcp_lun *plun;

		ptgt->tgt_report_lun_cnt++;
		plun = ptgt->tgt_lun;
		ASSERT(plun != NULL);
		mutex_exit(&ptgt->tgt_mutex);

		kmem_free(report_lun, len);

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_5, 0,
		    "!Dynamically discovered %d LUNs for D_ID=%x",
		    nluns_claimed, ptgt->tgt_d_id);

		/* Retrieve the rscn count (if a valid one exists) */
		if (icmd->ipkt_fpkt->pkt_ulp_rscn_infop != NULL) {
			rscn_count = ((fc_ulp_rscn_info_t *)
			    (icmd->ipkt_fpkt->pkt_ulp_rscn_infop))->
			    ulp_rscn_count;
		} else {
			rscn_count = FC_INVALID_RSCN_COUNT;
		}

		if (fcp_send_scsi(icmd->ipkt_lun, SCMD_REPORT_LUN,
		    FCP_LUN_HEADER + (nluns_claimed * FCP_LUN_SIZE),
		    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
		    icmd->ipkt_cause, rscn_count) != DDI_SUCCESS) {
			(void) fcp_call_finish_init(pptr, ptgt,
			    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
			    icmd->ipkt_cause);
		}

		fcp_icmd_free(pptr, icmd);
		return;
	}

	if (nluns_claimed > nluns_bufmax) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_5, 0,
		    "Target=%x:%x:%x:%x:%x:%x:%x:%x"
		    "	 Number of LUNs lost=%x",
		    ptgt->tgt_port_wwn.raw_wwn[0],
		    ptgt->tgt_port_wwn.raw_wwn[1],
		    ptgt->tgt_port_wwn.raw_wwn[2],
		    ptgt->tgt_port_wwn.raw_wwn[3],
		    ptgt->tgt_port_wwn.raw_wwn[4],
		    ptgt->tgt_port_wwn.raw_wwn[5],
		    ptgt->tgt_port_wwn.raw_wwn[6],
		    ptgt->tgt_port_wwn.raw_wwn[7],
		    nluns_claimed - nluns_bufmax);

		nluns_claimed = nluns_bufmax;
	}
	ptgt->tgt_lun_cnt = nluns_claimed;

	/*
	 * Identify missing LUNs and print warning messages
	 */
	for (plun = ptgt->tgt_lun; plun; plun = plun->lun_next) {
		int offline;
		int exists = 0;

		offline = (plun->lun_state & FCP_LUN_OFFLINE) ? 1 : 0;

		for (i = 0; i < nluns_claimed && exists == 0; i++) {
			uchar_t		*lun_string;

			lun_string = (uchar_t *)&(report_lun->lun_string[i]);

			switch (lun_string[0] & 0xC0) {
			case FCP_LUN_ADDRESSING:
			case FCP_PD_ADDRESSING:
			case FCP_VOLUME_ADDRESSING:
				lun_num = ((lun_string[0] & 0x3F) << 8) |
				    lun_string[1];
				if (plun->lun_num == lun_num) {
					exists++;
					break;
				}
				break;

			default:
				break;
			}
		}

		if (!exists && !offline) {
			mutex_exit(&ptgt->tgt_mutex);

			mutex_enter(&pptr->port_mutex);
			mutex_enter(&ptgt->tgt_mutex);
			if (!FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
				/*
				 * set disappear flag when device was connected
				 */
				if (!(plun->lun_state &
				    FCP_LUN_DEVICE_NOT_CONNECTED)) {
					plun->lun_state |= FCP_LUN_DISAPPEARED;
				}
				mutex_exit(&ptgt->tgt_mutex);
				mutex_exit(&pptr->port_mutex);
				if (!(plun->lun_state &
				    FCP_LUN_DEVICE_NOT_CONNECTED)) {
					fcp_log(CE_NOTE, pptr->port_dip,
					    "!Lun=%x for target=%x disappeared",
					    plun->lun_num, ptgt->tgt_d_id);
				}
				mutex_enter(&ptgt->tgt_mutex);
			} else {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_5, 0,
				    "fcp_handle_reportlun,1: state change"
				    " occured for D_ID=0x%x", ptgt->tgt_d_id);
				mutex_exit(&ptgt->tgt_mutex);
				mutex_exit(&pptr->port_mutex);
				kmem_free(report_lun, len);
				(void) fcp_call_finish_init(pptr, ptgt,
				    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
				    icmd->ipkt_cause);
				fcp_icmd_free(pptr, icmd);
				return;
			}
		} else if (exists) {
			/*
			 * clear FCP_LUN_DEVICE_NOT_CONNECTED when lun 0
			 * actually exists in REPORT_LUN response
			 */
			if (plun->lun_state & FCP_LUN_DEVICE_NOT_CONNECTED) {
				plun->lun_state &=
				    ~FCP_LUN_DEVICE_NOT_CONNECTED;
			}
			if (offline || plun->lun_num == 0) {
				if (plun->lun_state & FCP_LUN_DISAPPEARED)  {
					plun->lun_state &= ~FCP_LUN_DISAPPEARED;
					mutex_exit(&ptgt->tgt_mutex);
					fcp_log(CE_NOTE, pptr->port_dip,
					    "!Lun=%x for target=%x reappeared",
					    plun->lun_num, ptgt->tgt_d_id);
					mutex_enter(&ptgt->tgt_mutex);
				}
			}
		}
	}

	ptgt->tgt_tmp_cnt = nluns_claimed ? nluns_claimed : 1;
	mutex_exit(&ptgt->tgt_mutex);

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "fcp_handle_reportlun: port=%d, tgt D_ID=0x%x, %d LUN(s)",
	    pptr->port_instance, ptgt->tgt_d_id, nluns_claimed);

	/* scan each lun */
	for (i = 0; i < nluns_claimed; i++) {
		uchar_t	*lun_string;

		lun_string = (uchar_t *)&(report_lun->lun_string[i]);

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_5, 0,
		    "handle_reportlun: d_id=%x, LUN ind=%d, LUN=%d,"
		    " addr=0x%x", ptgt->tgt_d_id, i, lun_string[1],
		    lun_string[0]);

		switch (lun_string[0] & 0xC0) {
		case FCP_LUN_ADDRESSING:
		case FCP_PD_ADDRESSING:
		case FCP_VOLUME_ADDRESSING:
			lun_num = ((lun_string[0] & 0x3F) << 8) | lun_string[1];

			/* We will skip masked LUNs because of the blacklist. */
			if (fcp_lun_blacklist != NULL) {
				mutex_enter(&ptgt->tgt_mutex);
				if (fcp_should_mask(&ptgt->tgt_port_wwn,
				    lun_num) == TRUE) {
					ptgt->tgt_lun_cnt--;
					mutex_exit(&ptgt->tgt_mutex);
					break;
				}
				mutex_exit(&ptgt->tgt_mutex);
			}

			/* see if this LUN is already allocated */
			if ((plun = fcp_get_lun(ptgt, lun_num)) == NULL) {
				plun = fcp_alloc_lun(ptgt);
				if (plun == NULL) {
					fcp_log(CE_NOTE, pptr->port_dip,
					    "!Lun allocation failed"
					    " target=%x lun=%x",
					    ptgt->tgt_d_id, lun_num);
					break;
				}
			}

			mutex_enter(&plun->lun_tgt->tgt_mutex);
			/* convert to LUN */
			plun->lun_addr.ent_addr_0 =
			    BE_16(*(uint16_t *)&(lun_string[0]));
			plun->lun_addr.ent_addr_1 =
			    BE_16(*(uint16_t *)&(lun_string[2]));
			plun->lun_addr.ent_addr_2 =
			    BE_16(*(uint16_t *)&(lun_string[4]));
			plun->lun_addr.ent_addr_3 =
			    BE_16(*(uint16_t *)&(lun_string[6]));

			plun->lun_num = lun_num;
			plun->lun_state |= FCP_LUN_BUSY | FCP_LUN_MARK;
			plun->lun_state &= ~FCP_LUN_OFFLINE;
			mutex_exit(&plun->lun_tgt->tgt_mutex);

			/* Retrieve the rscn count (if a valid one exists) */
			if (icmd->ipkt_fpkt->pkt_ulp_rscn_infop != NULL) {
				rscn_count = ((fc_ulp_rscn_info_t *)
				    (icmd->ipkt_fpkt->pkt_ulp_rscn_infop))->
				    ulp_rscn_count;
			} else {
				rscn_count = FC_INVALID_RSCN_COUNT;
			}

			if (fcp_send_scsi(plun, SCMD_INQUIRY, SUN_INQSIZE,
			    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
			    icmd->ipkt_cause, rscn_count) != DDI_SUCCESS) {
				mutex_enter(&pptr->port_mutex);
				mutex_enter(&plun->lun_tgt->tgt_mutex);
				if (!FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
					fcp_log(CE_NOTE, pptr->port_dip,
					    "!failed to send INQUIRY"
					    " target=%x lun=%x",
					    ptgt->tgt_d_id, plun->lun_num);
				} else {
					FCP_TRACE(fcp_logq,
					    pptr->port_instbuf, fcp_trace,
					    FCP_BUF_LEVEL_5, 0,
					    "fcp_handle_reportlun,2: state"
					    " change occured for D_ID=0x%x",
					    ptgt->tgt_d_id);
				}
				mutex_exit(&plun->lun_tgt->tgt_mutex);
				mutex_exit(&pptr->port_mutex);
			} else {
				continue;
			}
			break;

		default:
			fcp_log(CE_WARN, NULL,
			    "!Unsupported LUN Addressing method %x "
			    "in response to REPORT_LUN", lun_string[0]);
			break;
		}

		/*
		 * each time through this loop we should decrement
		 * the tmp_cnt by one -- since we go through this loop
		 * one time for each LUN, the tmp_cnt should never be <=0
		 */
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
	}

	if (i == 0) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!FCP: target=%x reported NO Luns", ptgt->tgt_d_id);
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
	}

	kmem_free(report_lun, len);
	fcp_icmd_free(pptr, icmd);
}


/*
 * called internally to return a LUN given a target and a LUN number
 */
static struct fcp_lun *
fcp_get_lun(struct fcp_tgt *ptgt, uint16_t lun_num)
{
	struct fcp_lun	*plun;

	mutex_enter(&ptgt->tgt_mutex);
	for (plun = ptgt->tgt_lun; plun != NULL; plun = plun->lun_next) {
		if (plun->lun_num == lun_num) {
			mutex_exit(&ptgt->tgt_mutex);
			return (plun);
		}
	}
	mutex_exit(&ptgt->tgt_mutex);

	return (NULL);
}


/*
 * handle finishing one target for fcp_finish_init
 *
 * return true (non-zero) if we want finish_init to continue with the
 * next target
 *
 * called with the port mutex held
 */
/*ARGSUSED*/
static int
fcp_finish_tgt(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int link_cnt, int tgt_cnt, int cause)
{
	int	rval = 1;
	ASSERT(pptr != NULL);
	ASSERT(ptgt != NULL);

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_5, 0,
	    "finish_tgt: D_ID/state = 0x%x/0x%x", ptgt->tgt_d_id,
	    ptgt->tgt_state);

	ASSERT(mutex_owned(&pptr->port_mutex));

	if ((pptr->port_link_cnt != link_cnt) ||
	    (tgt_cnt && ptgt->tgt_change_cnt != tgt_cnt)) {
		/*
		 * oh oh -- another link reset or target change
		 * must have occurred while we are in here
		 */
		FCP_TGT_TRACE(ptgt, tgt_cnt, FCP_TGT_TRACE_23);

		return (0);
	} else {
		FCP_TGT_TRACE(ptgt, tgt_cnt, FCP_TGT_TRACE_24);
	}

	mutex_enter(&ptgt->tgt_mutex);

	if (!(ptgt->tgt_state & FCP_TGT_OFFLINE)) {
		/*
		 * tgt is not offline -- is it marked (i.e. needs
		 * to be offlined) ??
		 */
		if (ptgt->tgt_state & FCP_TGT_MARK) {
			/*
			 * this target not offline *and*
			 * marked
			 */
			ptgt->tgt_state &= ~FCP_TGT_MARK;
			rval = fcp_offline_target(pptr, ptgt, link_cnt,
			    tgt_cnt, 0, 0);
		} else {
			ptgt->tgt_state &= ~FCP_TGT_BUSY;

			/* create the LUNs */
			if (ptgt->tgt_node_state != FCP_TGT_NODE_ON_DEMAND) {
				ptgt->tgt_node_state = FCP_TGT_NODE_PRESENT;
				fcp_create_luns(ptgt, link_cnt, tgt_cnt,
				    cause);
				ptgt->tgt_device_created = 1;
			} else {
				fcp_update_tgt_state(ptgt, FCP_RESET,
				    FCP_LUN_BUSY);
			}
		}
	}

	mutex_exit(&ptgt->tgt_mutex);

	return (rval);
}


/*
 * this routine is called to finish port initialization
 *
 * Each port has a "temp" counter -- when a state change happens (e.g.
 * port online), the temp count is set to the number of devices in the map.
 * Then, as each device gets "discovered", the temp counter is decremented
 * by one.  When this count reaches zero we know that all of the devices
 * in the map have been discovered (or an error has occurred), so we can
 * then finish initialization -- which is done by this routine (well, this
 * and fcp-finish_tgt())
 *
 * acquires and releases the global mutex
 *
 * called with the port mutex owned
 */
static void
fcp_finish_init(struct fcp_port *pptr)
{
#ifdef	DEBUG
	bzero(pptr->port_finish_stack, sizeof (pptr->port_finish_stack));
	pptr->port_finish_depth = getpcstack(pptr->port_finish_stack,
	    FCP_STACK_DEPTH);
#endif /* DEBUG */

	ASSERT(mutex_owned(&pptr->port_mutex));

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_2, 0, "finish_init:"
	    " entering; ipkt count=%d", pptr->port_ipkt_cnt);

	if ((pptr->port_state & FCP_STATE_ONLINING) &&
	    !(pptr->port_state & (FCP_STATE_SUSPENDED |
	    FCP_STATE_DETACHING | FCP_STATE_POWER_DOWN))) {
		pptr->port_state &= ~FCP_STATE_ONLINING;
		pptr->port_state |= FCP_STATE_ONLINE;
	}

	/* Wake up threads waiting on config done */
	cv_broadcast(&pptr->port_config_cv);
}


/*
 * called from fcp_finish_init to create the LUNs for a target
 *
 * called with the port mutex owned
 */
static void
fcp_create_luns(struct fcp_tgt *ptgt, int link_cnt, int tgt_cnt, int cause)
{
	struct fcp_lun	*plun;
	struct fcp_port	*pptr;
	child_info_t		*cip = NULL;

	ASSERT(ptgt != NULL);
	ASSERT(mutex_owned(&ptgt->tgt_mutex));

	pptr = ptgt->tgt_port;

	ASSERT(pptr != NULL);

	/* scan all LUNs for this target */
	for (plun = ptgt->tgt_lun; plun != NULL; plun = plun->lun_next) {
		if (plun->lun_state & FCP_LUN_OFFLINE) {
			continue;
		}

		if (plun->lun_state & FCP_LUN_MARK) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_create_luns: offlining marked LUN!");
			fcp_offline_lun(plun, link_cnt, tgt_cnt, 1, 0);
			continue;
		}

		plun->lun_state &= ~FCP_LUN_BUSY;

		/*
		 * There are conditions in which FCP_LUN_INIT flag is cleared
		 * but we have a valid plun->lun_cip. To cover this case also
		 * CLEAR_BUSY whenever we have a valid lun_cip.
		 */
		if (plun->lun_mpxio && plun->lun_cip &&
		    (!fcp_pass_to_hp(pptr, plun, plun->lun_cip,
		    FCP_MPXIO_PATH_CLEAR_BUSY, link_cnt, tgt_cnt,
		    0, 0))) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_create_luns: enable lun %p failed!",
			    plun);
		}

		if (plun->lun_state & FCP_LUN_INIT &&
		    !(plun->lun_state & FCP_LUN_CHANGED)) {
			continue;
		}

		if (cause == FCP_CAUSE_USER_CREATE) {
			continue;
		}

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_6, 0,
		    "create_luns: passing ONLINE elem to HP thread");

		/*
		 * If lun has changed, prepare for offlining the old path.
		 * Do not offline the old path right now, since it may be
		 * still opened.
		 */
		if (plun->lun_cip && (plun->lun_state & FCP_LUN_CHANGED)) {
			fcp_prepare_offline_lun(plun, link_cnt, tgt_cnt);
		}

		/* pass an ONLINE element to the hotplug thread */
		if (!fcp_pass_to_hp(pptr, plun, cip, FCP_ONLINE,
		    link_cnt, tgt_cnt, NDI_ONLINE_ATTACH, 0)) {

			/*
			 * We can not synchronous attach (i.e pass
			 * NDI_ONLINE_ATTACH) here as we might be
			 * coming from an interrupt or callback
			 * thread.
			 */
			if (!fcp_pass_to_hp(pptr, plun, cip, FCP_ONLINE,
			    link_cnt, tgt_cnt, 0, 0)) {
				fcp_log(CE_CONT, pptr->port_dip,
				    "Can not ONLINE LUN; D_ID=%x, LUN=%x\n",
				    plun->lun_tgt->tgt_d_id, plun->lun_num);
			}
		}
	}
}


/*
 * function to online/offline devices
 */
static int
fcp_trigger_lun(struct fcp_lun *plun, child_info_t *cip, int old_mpxio,
    int online, int lcount, int tcount, int flags)
{
	int			rval = NDI_FAILURE;
	int			circ;
	child_info_t		*ccip;
	struct fcp_port		*pptr = plun->lun_tgt->tgt_port;
	int			is_mpxio = pptr->port_mpxio;
	dev_info_t		*cdip, *pdip;
	char			*devname;

	if ((old_mpxio != 0) && (plun->lun_mpxio != old_mpxio)) {
		/*
		 * When this event gets serviced, lun_cip and lun_mpxio
		 * has changed, so it should be invalidated now.
		 */
		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_2, 0, "fcp_trigger_lun: lun_mpxio changed: "
		    "plun: %p, cip: %p, what:%d", plun, cip, online);
		return (rval);
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_2, 0,
	    "fcp_trigger_lun: plun=%p target=%x lun=%d cip=%p what=%x "
	    "flags=%x mpxio=%x\n",
	    plun, LUN_TGT->tgt_d_id, plun->lun_num, cip, online, flags,
	    plun->lun_mpxio);

	/*
	 * lun_mpxio needs checking here because we can end up in a race
	 * condition where this task has been dispatched while lun_mpxio is
	 * set, but an earlier FCP_ONLINE task for the same LUN tried to
	 * enable MPXIO for the LUN, but was unable to, and hence cleared
	 * the flag. We rely on the serialization of the tasks here. We return
	 * NDI_SUCCESS so any callers continue without reporting spurious
	 * errors, and the still think we're an MPXIO LUN.
	 */

	if (online == FCP_MPXIO_PATH_CLEAR_BUSY ||
	    online == FCP_MPXIO_PATH_SET_BUSY) {
		if (plun->lun_mpxio) {
			rval = fcp_update_mpxio_path(plun, cip, online);
		} else {
			rval = NDI_SUCCESS;
		}
		return (rval);
	}

	/*
	 * Explicit devfs_clean() due to ndi_devi_offline() not
	 * executing devfs_clean() if parent lock is held.
	 */
	ASSERT(!servicing_interrupt());
	if (online == FCP_OFFLINE) {
		if (plun->lun_mpxio == 0) {
			if (plun->lun_cip == cip) {
				cdip = DIP(plun->lun_cip);
			} else {
				cdip = DIP(cip);
			}
		} else if ((plun->lun_cip == cip) && plun->lun_cip) {
			cdip = mdi_pi_get_client(PIP(plun->lun_cip));
		} else if ((plun->lun_cip != cip) && cip) {
			/*
			 * This means a DTYPE/GUID change, we shall get the
			 * dip of the old cip instead of the current lun_cip.
			 */
			cdip = mdi_pi_get_client(PIP(cip));
		}
		if (cdip) {
			if (i_ddi_devi_attached(cdip)) {
				pdip = ddi_get_parent(cdip);
				devname = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
				ndi_devi_enter(pdip, &circ);
				(void) ddi_deviname(cdip, devname);
				/*
				 * Release parent lock before calling
				 * devfs_clean().
				 */
				ndi_devi_exit(pdip, circ);
				(void) devfs_clean(pdip, devname + 1,
				    DV_CLEAN_FORCE);
				kmem_free(devname, MAXNAMELEN + 1);
			}
		}
	}

	if (fc_ulp_busy_port(pptr->port_fp_handle) != 0) {
		return (NDI_FAILURE);
	}

	if (is_mpxio) {
		mdi_devi_enter(pptr->port_dip, &circ);
	} else {
		ndi_devi_enter(pptr->port_dip, &circ);
	}

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&plun->lun_mutex);

	if (online == FCP_ONLINE) {
		ccip = fcp_get_cip(plun, cip, lcount, tcount);
		if (ccip == NULL) {
			goto fail;
		}
	} else {
		if (fcp_is_child_present(plun, cip) != FC_SUCCESS) {
			goto fail;
		}
		ccip = cip;
	}

	if (online == FCP_ONLINE) {
		rval = fcp_online_child(plun, ccip, lcount, tcount, flags,
		    &circ);
		fc_ulp_log_device_event(pptr->port_fp_handle,
		    FC_ULP_DEVICE_ONLINE);
	} else {
		rval = fcp_offline_child(plun, ccip, lcount, tcount, flags,
		    &circ);
		fc_ulp_log_device_event(pptr->port_fp_handle,
		    FC_ULP_DEVICE_OFFLINE);
	}

fail:	mutex_exit(&plun->lun_mutex);
	mutex_exit(&pptr->port_mutex);

	if (is_mpxio) {
		mdi_devi_exit(pptr->port_dip, circ);
	} else {
		ndi_devi_exit(pptr->port_dip, circ);
	}

	fc_ulp_idle_port(pptr->port_fp_handle);

	return (rval);
}


/*
 * take a target offline by taking all of its LUNs offline
 */
/*ARGSUSED*/
static int
fcp_offline_target(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int link_cnt, int tgt_cnt, int nowait, int flags)
{
	struct fcp_tgt_elem	*elem;

	ASSERT(mutex_owned(&pptr->port_mutex));
	ASSERT(mutex_owned(&ptgt->tgt_mutex));

	ASSERT(!(ptgt->tgt_state & FCP_TGT_OFFLINE));

	if (link_cnt != pptr->port_link_cnt || (tgt_cnt && tgt_cnt !=
	    ptgt->tgt_change_cnt)) {
		mutex_exit(&ptgt->tgt_mutex);
		FCP_TGT_TRACE(ptgt, tgt_cnt, FCP_TGT_TRACE_25);
		mutex_enter(&ptgt->tgt_mutex);

		return (0);
	}

	ptgt->tgt_pd_handle = NULL;
	mutex_exit(&ptgt->tgt_mutex);
	FCP_TGT_TRACE(ptgt, tgt_cnt, FCP_TGT_TRACE_26);
	mutex_enter(&ptgt->tgt_mutex);

	tgt_cnt = tgt_cnt ? tgt_cnt : ptgt->tgt_change_cnt;

	if (ptgt->tgt_tcap &&
	    (elem = kmem_zalloc(sizeof (*elem), KM_NOSLEEP)) != NULL) {
		elem->flags = flags;
		elem->time = fcp_watchdog_time;
		if (nowait == 0) {
			elem->time += fcp_offline_delay;
		}
		elem->ptgt = ptgt;
		elem->link_cnt = link_cnt;
		elem->tgt_cnt = tgt_cnt;
		elem->next = pptr->port_offline_tgts;
		pptr->port_offline_tgts = elem;
	} else {
		fcp_offline_target_now(pptr, ptgt, link_cnt, tgt_cnt, flags);
	}

	return (1);
}


static void
fcp_offline_target_now(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int link_cnt, int tgt_cnt, int flags)
{
	ASSERT(mutex_owned(&pptr->port_mutex));
	ASSERT(mutex_owned(&ptgt->tgt_mutex));

	fc_ulp_enable_relogin(pptr->port_fp_handle, &ptgt->tgt_port_wwn);
	ptgt->tgt_state = FCP_TGT_OFFLINE;
	ptgt->tgt_pd_handle = NULL;
	fcp_offline_tgt_luns(ptgt, link_cnt, tgt_cnt, flags);
}


static void
fcp_offline_tgt_luns(struct fcp_tgt *ptgt, int link_cnt, int tgt_cnt,
    int flags)
{
	struct	fcp_lun	*plun;

	ASSERT(mutex_owned(&ptgt->tgt_port->port_mutex));
	ASSERT(mutex_owned(&ptgt->tgt_mutex));

	for (plun = ptgt->tgt_lun; plun != NULL; plun = plun->lun_next) {
		if (!(plun->lun_state & FCP_LUN_OFFLINE)) {
			fcp_offline_lun(plun, link_cnt, tgt_cnt, 1, flags);
		}
	}
}


/*
 * take a LUN offline
 *
 * enters and leaves with the target mutex held, releasing it in the process
 *
 * allocates memory in non-sleep mode
 */
static void
fcp_offline_lun(struct fcp_lun *plun, int link_cnt, int tgt_cnt,
    int nowait, int flags)
{
	struct fcp_port	*pptr = plun->lun_tgt->tgt_port;
	struct fcp_lun_elem	*elem;

	ASSERT(plun != NULL);
	ASSERT(mutex_owned(&LUN_TGT->tgt_mutex));

	if (nowait) {
		fcp_offline_lun_now(plun, link_cnt, tgt_cnt, flags);
		return;
	}

	if ((elem = kmem_zalloc(sizeof (*elem), KM_NOSLEEP)) != NULL) {
		elem->flags = flags;
		elem->time = fcp_watchdog_time;
		if (nowait == 0) {
			elem->time += fcp_offline_delay;
		}
		elem->plun = plun;
		elem->link_cnt = link_cnt;
		elem->tgt_cnt = plun->lun_tgt->tgt_change_cnt;
		elem->next = pptr->port_offline_luns;
		pptr->port_offline_luns = elem;
	} else {
		fcp_offline_lun_now(plun, link_cnt, tgt_cnt, flags);
	}
}


static void
fcp_prepare_offline_lun(struct fcp_lun *plun, int link_cnt, int tgt_cnt)
{
	struct fcp_pkt	*head = NULL;

	ASSERT(mutex_owned(&LUN_TGT->tgt_mutex));

	mutex_exit(&LUN_TGT->tgt_mutex);

	head = fcp_scan_commands(plun);
	if (head != NULL) {
		fcp_abort_commands(head, LUN_PORT);
	}

	mutex_enter(&LUN_TGT->tgt_mutex);

	if (plun->lun_cip && plun->lun_mpxio) {
		/*
		 * Intimate MPxIO lun busy is cleared
		 */
		if (!fcp_pass_to_hp(LUN_PORT, plun, plun->lun_cip,
		    FCP_MPXIO_PATH_CLEAR_BUSY, link_cnt, tgt_cnt,
		    0, 0)) {
			fcp_log(CE_NOTE, LUN_PORT->port_dip,
			    "Can not ENABLE LUN; D_ID=%x, LUN=%x",
			    LUN_TGT->tgt_d_id, plun->lun_num);
		}
		/*
		 * Intimate MPxIO that the lun is now marked for offline
		 */
		mutex_exit(&LUN_TGT->tgt_mutex);
		(void) mdi_pi_disable_path(PIP(plun->lun_cip), DRIVER_DISABLE);
		mutex_enter(&LUN_TGT->tgt_mutex);
	}
}

static void
fcp_offline_lun_now(struct fcp_lun *plun, int link_cnt, int tgt_cnt,
    int flags)
{
	ASSERT(mutex_owned(&LUN_TGT->tgt_mutex));

	mutex_exit(&LUN_TGT->tgt_mutex);
	fcp_update_offline_flags(plun);
	mutex_enter(&LUN_TGT->tgt_mutex);

	fcp_prepare_offline_lun(plun, link_cnt, tgt_cnt);

	FCP_TRACE(fcp_logq, LUN_PORT->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_4, 0,
	    "offline_lun: passing OFFLINE elem to HP thread");

	if (plun->lun_cip) {
		fcp_log(CE_NOTE, LUN_PORT->port_dip,
		    "!offlining lun=%x (trace=%x), target=%x (trace=%x)",
		    plun->lun_num, plun->lun_trace, LUN_TGT->tgt_d_id,
		    LUN_TGT->tgt_trace);

		if (!fcp_pass_to_hp(LUN_PORT, plun, plun->lun_cip, FCP_OFFLINE,
		    link_cnt, tgt_cnt, flags, 0)) {
			fcp_log(CE_CONT, LUN_PORT->port_dip,
			    "Can not OFFLINE LUN; D_ID=%x, LUN=%x\n",
			    LUN_TGT->tgt_d_id, plun->lun_num);
		}
	}
}

static void
fcp_scan_offline_luns(struct fcp_port *pptr)
{
	struct fcp_lun_elem	*elem;
	struct fcp_lun_elem	*prev;
	struct fcp_lun_elem	*next;

	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	prev = NULL;
	elem = pptr->port_offline_luns;
	while (elem) {
		next = elem->next;
		if (elem->time <= fcp_watchdog_time) {
			int			changed = 1;
			struct fcp_tgt	*ptgt = elem->plun->lun_tgt;

			mutex_enter(&ptgt->tgt_mutex);
			if (pptr->port_link_cnt == elem->link_cnt &&
			    ptgt->tgt_change_cnt == elem->tgt_cnt) {
				changed = 0;
			}

			if (!changed &&
			    !(elem->plun->lun_state & FCP_TGT_OFFLINE)) {
				fcp_offline_lun_now(elem->plun,
				    elem->link_cnt, elem->tgt_cnt, elem->flags);
			}
			mutex_exit(&ptgt->tgt_mutex);

			kmem_free(elem, sizeof (*elem));

			if (prev) {
				prev->next = next;
			} else {
				pptr->port_offline_luns = next;
			}
		} else {
			prev = elem;
		}
		elem = next;
	}
}


static void
fcp_scan_offline_tgts(struct fcp_port *pptr)
{
	struct fcp_tgt_elem	*elem;
	struct fcp_tgt_elem	*prev;
	struct fcp_tgt_elem	*next;

	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	prev = NULL;
	elem = pptr->port_offline_tgts;
	while (elem) {
		next = elem->next;
		if (elem->time <= fcp_watchdog_time) {
			int		outdated = 1;
			struct fcp_tgt	*ptgt = elem->ptgt;

			mutex_enter(&ptgt->tgt_mutex);

			if (ptgt->tgt_change_cnt == elem->tgt_cnt) {
				/* No change on tgt since elem was created. */
				outdated = 0;
			} else if (ptgt->tgt_change_cnt == elem->tgt_cnt + 1 &&
			    pptr->port_link_cnt == elem->link_cnt + 1 &&
			    ptgt->tgt_statec_cause == FCP_CAUSE_LINK_DOWN) {
				/*
				 * Exactly one thing happened to the target
				 * inbetween: the local port went offline.
				 * For fp the remote port is already gone so
				 * it will not tell us again to offline the
				 * target. We must offline it now.
				 */
				outdated = 0;
			}

			if (!outdated && !(ptgt->tgt_state &
			    FCP_TGT_OFFLINE)) {
				fcp_offline_target_now(pptr,
				    ptgt, elem->link_cnt, elem->tgt_cnt,
				    elem->flags);
			}

			mutex_exit(&ptgt->tgt_mutex);

			kmem_free(elem, sizeof (*elem));

			if (prev) {
				prev->next = next;
			} else {
				pptr->port_offline_tgts = next;
			}
		} else {
			prev = elem;
		}
		elem = next;
	}
}


static void
fcp_update_offline_flags(struct fcp_lun *plun)
{
	struct fcp_port	*pptr = LUN_PORT;
	ASSERT(plun != NULL);

	mutex_enter(&LUN_TGT->tgt_mutex);
	plun->lun_state |= FCP_LUN_OFFLINE;
	plun->lun_state &= ~(FCP_LUN_INIT | FCP_LUN_BUSY | FCP_LUN_MARK);

	mutex_enter(&plun->lun_mutex);
	if (plun->lun_cip && plun->lun_state & FCP_SCSI_LUN_TGT_INIT) {
		dev_info_t *cdip = NULL;

		mutex_exit(&LUN_TGT->tgt_mutex);

		if (plun->lun_mpxio == 0) {
			cdip = DIP(plun->lun_cip);
		} else if (plun->lun_cip) {
			cdip = mdi_pi_get_client(PIP(plun->lun_cip));
		}

		mutex_exit(&plun->lun_mutex);
		if (cdip) {
			(void) ndi_event_retrieve_cookie(
			    pptr->port_ndi_event_hdl, cdip, FCAL_REMOVE_EVENT,
			    &fcp_remove_eid, NDI_EVENT_NOPASS);
			(void) ndi_event_run_callbacks(
			    pptr->port_ndi_event_hdl, cdip,
			    fcp_remove_eid, NULL);
		}
	} else {
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&LUN_TGT->tgt_mutex);
	}
}


/*
 * Scan all of the command pkts for this port, moving pkts that
 * match our LUN onto our own list (headed by "head")
 */
static struct fcp_pkt *
fcp_scan_commands(struct fcp_lun *plun)
{
	struct fcp_port	*pptr = LUN_PORT;

	struct fcp_pkt	*cmd = NULL;	/* pkt cmd ptr */
	struct fcp_pkt	*ncmd = NULL;	/* next pkt ptr */
	struct fcp_pkt	*pcmd = NULL;	/* the previous command */

	struct fcp_pkt	*head = NULL;	/* head of our list */
	struct fcp_pkt	*tail = NULL;	/* tail of our list */

	int			cmds_found = 0;

	mutex_enter(&pptr->port_pkt_mutex);
	for (cmd = pptr->port_pkt_head; cmd != NULL; cmd = ncmd) {
		struct fcp_lun *tlun =
		    ADDR2LUN(&cmd->cmd_pkt->pkt_address);

		ncmd = cmd->cmd_next;	/* set next command */

		/*
		 * if this pkt is for a different LUN  or the
		 * command is sent down, skip it.
		 */
		if (tlun != plun || cmd->cmd_state == FCP_PKT_ISSUED ||
		    (cmd->cmd_pkt->pkt_flags & FLAG_NOINTR)) {
			pcmd = cmd;
			continue;
		}
		cmds_found++;
		if (pcmd != NULL) {
			ASSERT(pptr->port_pkt_head != cmd);
			pcmd->cmd_next = cmd->cmd_next;
		} else {
			ASSERT(cmd == pptr->port_pkt_head);
			pptr->port_pkt_head = cmd->cmd_next;
		}

		if (cmd == pptr->port_pkt_tail) {
			pptr->port_pkt_tail = pcmd;
			if (pcmd) {
				pcmd->cmd_next = NULL;
			}
		}

		if (head == NULL) {
			head = tail = cmd;
		} else {
			ASSERT(tail != NULL);

			tail->cmd_next = cmd;
			tail = cmd;
		}
		cmd->cmd_next = NULL;
	}
	mutex_exit(&pptr->port_pkt_mutex);

	FCP_DTRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_8, 0,
	    "scan commands: %d cmd(s) found", cmds_found);

	return (head);
}


/*
 * Abort all the commands in the command queue
 */
static void
fcp_abort_commands(struct fcp_pkt *head, struct fcp_port *pptr)
{
	struct fcp_pkt	*cmd = NULL;	/* pkt cmd ptr */
	struct	fcp_pkt	*ncmd = NULL;	/* next pkt ptr */

	ASSERT(mutex_owned(&pptr->port_mutex));

	/* scan through the pkts and invalid them */
	for (cmd = head; cmd != NULL; cmd = ncmd) {
		struct scsi_pkt *pkt = cmd->cmd_pkt;

		ncmd = cmd->cmd_next;
		ASSERT(pkt != NULL);

		/*
		 * The lun is going to be marked offline. Indicate
		 * the target driver not to requeue or retry this command
		 * as the device is going to be offlined pretty soon.
		 */
		pkt->pkt_reason = CMD_DEV_GONE;
		pkt->pkt_statistics = 0;
		pkt->pkt_state = 0;

		/* reset cmd flags/state */
		cmd->cmd_flags &= ~CFLAG_IN_QUEUE;
		cmd->cmd_state = FCP_PKT_IDLE;

		/*
		 * ensure we have a packet completion routine,
		 * then call it.
		 */
		ASSERT(pkt->pkt_comp != NULL);

		mutex_exit(&pptr->port_mutex);
		fcp_post_callback(cmd);
		mutex_enter(&pptr->port_mutex);
	}
}


/*
 * the pkt_comp callback for command packets
 */
static void
fcp_cmd_callback(fc_packet_t *fpkt)
{
	struct fcp_pkt *cmd = (struct fcp_pkt *)fpkt->pkt_ulp_private;
	struct scsi_pkt *pkt = cmd->cmd_pkt;
	struct fcp_port *pptr = ADDR2FCP(&pkt->pkt_address);

	ASSERT(cmd->cmd_state != FCP_PKT_IDLE);

	if (cmd->cmd_state == FCP_PKT_IDLE) {
		cmn_err(CE_PANIC, "Packet already completed %p",
		    (void *)cmd);
	}

	/*
	 * Watch thread should be freeing the packet, ignore the pkt.
	 */
	if (cmd->cmd_state == FCP_PKT_ABORTING) {
		fcp_log(CE_CONT, pptr->port_dip,
		    "!FCP: Pkt completed while aborting\n");
		return;
	}
	cmd->cmd_state = FCP_PKT_IDLE;

	fcp_complete_pkt(fpkt);

#ifdef	DEBUG
	mutex_enter(&pptr->port_pkt_mutex);
	pptr->port_npkts--;
	mutex_exit(&pptr->port_pkt_mutex);
#endif /* DEBUG */

	fcp_post_callback(cmd);
}


static void
fcp_complete_pkt(fc_packet_t *fpkt)
{
	int			error = 0;
	struct fcp_pkt	*cmd = (struct fcp_pkt *)
	    fpkt->pkt_ulp_private;
	struct scsi_pkt		*pkt = cmd->cmd_pkt;
	struct fcp_port		*pptr = ADDR2FCP(&pkt->pkt_address);
	struct fcp_lun	*plun;
	struct fcp_tgt	*ptgt;
	struct fcp_rsp		*rsp;
	struct scsi_address	save;

#ifdef	DEBUG
	save = pkt->pkt_address;
#endif /* DEBUG */

	rsp = (struct fcp_rsp *)cmd->cmd_fcp_rsp;

	if (fpkt->pkt_state == FC_PKT_SUCCESS) {
		if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
			FCP_CP_IN(fpkt->pkt_resp, rsp, fpkt->pkt_resp_acc,
			    sizeof (struct fcp_rsp));
		}

		pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_GOT_STATUS;

		pkt->pkt_resid = 0;

		if (fpkt->pkt_datalen) {
			pkt->pkt_state |= STATE_XFERRED_DATA;
			if (fpkt->pkt_data_resid) {
				error++;
			}
		}

		if ((pkt->pkt_scbp != NULL) && ((*(pkt->pkt_scbp) =
		    rsp->fcp_u.fcp_status.scsi_status) != STATUS_GOOD)) {
			/*
			 * The next two checks make sure that if there
			 * is no sense data or a valid response and
			 * the command came back with check condition,
			 * the command should be retried.
			 */
			if (!rsp->fcp_u.fcp_status.rsp_len_set &&
			    !rsp->fcp_u.fcp_status.sense_len_set) {
				pkt->pkt_state &= ~STATE_XFERRED_DATA;
				pkt->pkt_resid = cmd->cmd_dmacount;
			}
		}

		if ((error | rsp->fcp_u.i_fcp_status | rsp->fcp_resid) == 0) {
			return;
		}

		plun = ADDR2LUN(&pkt->pkt_address);
		ptgt = plun->lun_tgt;
		ASSERT(ptgt != NULL);

		/*
		 * Update the transfer resid, if appropriate
		 */
		if (rsp->fcp_u.fcp_status.resid_over ||
		    rsp->fcp_u.fcp_status.resid_under) {
			pkt->pkt_resid = rsp->fcp_resid;
		}

		/*
		 * First see if we got a FCP protocol error.
		 */
		if (rsp->fcp_u.fcp_status.rsp_len_set) {
			struct fcp_rsp_info	*bep;
			bep = (struct fcp_rsp_info *)(cmd->cmd_fcp_rsp +
			    sizeof (struct fcp_rsp));

			if (fcp_validate_fcp_response(rsp, pptr) !=
			    FC_SUCCESS) {
				pkt->pkt_reason = CMD_CMPLT;
				*(pkt->pkt_scbp) = STATUS_CHECK;

				fcp_log(CE_WARN, pptr->port_dip,
				    "!SCSI command to d_id=0x%x lun=0x%x"
				    " failed, Bad FCP response values:"
				    " rsvd1=%x, rsvd2=%x, sts-rsvd1=%x,"
				    " sts-rsvd2=%x, rsplen=%x, senselen=%x",
				    ptgt->tgt_d_id, plun->lun_num,
				    rsp->reserved_0, rsp->reserved_1,
				    rsp->fcp_u.fcp_status.reserved_0,
				    rsp->fcp_u.fcp_status.reserved_1,
				    rsp->fcp_response_len, rsp->fcp_sense_len);

				return;
			}

			if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
				FCP_CP_IN(fpkt->pkt_resp +
				    sizeof (struct fcp_rsp), bep,
				    fpkt->pkt_resp_acc,
				    sizeof (struct fcp_rsp_info));
			}

			if (bep->rsp_code != FCP_NO_FAILURE) {
				child_info_t	*cip;

				pkt->pkt_reason = CMD_TRAN_ERR;

				mutex_enter(&plun->lun_mutex);
				cip = plun->lun_cip;
				mutex_exit(&plun->lun_mutex);

				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "FCP response error on cmd=%p"
				    " target=0x%x, cip=%p", cmd,
				    ptgt->tgt_d_id, cip);
			}
		}

		/*
		 * See if we got a SCSI error with sense data
		 */
		if (rsp->fcp_u.fcp_status.sense_len_set) {
			uchar_t				rqlen;
			caddr_t				sense_from;
			child_info_t			*cip;
			timeout_id_t			tid;
			struct scsi_arq_status		*arq;
			struct scsi_extended_sense	*sense_to;

			arq = (struct scsi_arq_status *)pkt->pkt_scbp;
			sense_to = &arq->sts_sensedata;

			rqlen = (uchar_t)min(rsp->fcp_sense_len,
			    sizeof (struct scsi_extended_sense));

			sense_from = (caddr_t)fpkt->pkt_resp +
			    sizeof (struct fcp_rsp) + rsp->fcp_response_len;

			if (fcp_validate_fcp_response(rsp, pptr) !=
			    FC_SUCCESS) {
				pkt->pkt_reason = CMD_CMPLT;
				*(pkt->pkt_scbp) = STATUS_CHECK;

				fcp_log(CE_WARN, pptr->port_dip,
				    "!SCSI command to d_id=0x%x lun=0x%x"
				    " failed, Bad FCP response values:"
				    " rsvd1=%x, rsvd2=%x, sts-rsvd1=%x,"
				    " sts-rsvd2=%x, rsplen=%x, senselen=%x",
				    ptgt->tgt_d_id, plun->lun_num,
				    rsp->reserved_0, rsp->reserved_1,
				    rsp->fcp_u.fcp_status.reserved_0,
				    rsp->fcp_u.fcp_status.reserved_1,
				    rsp->fcp_response_len, rsp->fcp_sense_len);

				return;
			}

			/*
			 * copy in sense information
			 */
			if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
				FCP_CP_IN(sense_from, sense_to,
				    fpkt->pkt_resp_acc, rqlen);
			} else {
				bcopy(sense_from, sense_to, rqlen);
			}

			if ((FCP_SENSE_REPORTLUN_CHANGED(sense_to)) ||
			    (FCP_SENSE_NO_LUN(sense_to))) {
				mutex_enter(&ptgt->tgt_mutex);
				if (ptgt->tgt_tid == NULL) {
					/*
					 * Kick off rediscovery
					 */
					tid = timeout(fcp_reconfigure_luns,
					    (caddr_t)ptgt, drv_usectohz(1));

					ptgt->tgt_tid = tid;
					ptgt->tgt_state |= FCP_TGT_BUSY;
				}
				mutex_exit(&ptgt->tgt_mutex);
				if (FCP_SENSE_REPORTLUN_CHANGED(sense_to)) {
					FCP_TRACE(fcp_logq, pptr->port_instbuf,
					    fcp_trace, FCP_BUF_LEVEL_3, 0,
					    "!FCP: Report Lun Has Changed"
					    " target=%x", ptgt->tgt_d_id);
				} else if (FCP_SENSE_NO_LUN(sense_to)) {
					FCP_TRACE(fcp_logq, pptr->port_instbuf,
					    fcp_trace, FCP_BUF_LEVEL_3, 0,
					    "!FCP: LU Not Supported"
					    " target=%x", ptgt->tgt_d_id);
				}
			}
			ASSERT(pkt->pkt_scbp != NULL);

			pkt->pkt_state |= STATE_ARQ_DONE;

			arq->sts_rqpkt_resid = SENSE_LENGTH - rqlen;

			*((uchar_t *)&arq->sts_rqpkt_status) = STATUS_GOOD;
			arq->sts_rqpkt_reason = 0;
			arq->sts_rqpkt_statistics = 0;

			arq->sts_rqpkt_state = STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_GOT_STATUS | STATE_ARQ_DONE |
			    STATE_XFERRED_DATA;

			mutex_enter(&plun->lun_mutex);
			cip = plun->lun_cip;
			mutex_exit(&plun->lun_mutex);

			FCP_DTRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_8, 0,
			    "SCSI Check condition on cmd=%p target=0x%x"
			    " LUN=%p, cmd=%x SCSI status=%x, es key=%x"
			    " ASC=%x ASCQ=%x", cmd, ptgt->tgt_d_id, cip,
			    cmd->cmd_fcp_cmd.fcp_cdb[0],
			    rsp->fcp_u.fcp_status.scsi_status,
			    sense_to->es_key, sense_to->es_add_code,
			    sense_to->es_qual_code);
		}
	} else {
		plun = ADDR2LUN(&pkt->pkt_address);
		ptgt = plun->lun_tgt;
		ASSERT(ptgt != NULL);

		/*
		 * Work harder to translate errors into target driver
		 * understandable ones. Note with despair that the target
		 * drivers don't decode pkt_state and pkt_reason exhaustively
		 * They resort to using the big hammer most often, which
		 * may not get fixed in the life time of this driver.
		 */
		pkt->pkt_state = 0;
		pkt->pkt_statistics = 0;

		switch (fpkt->pkt_state) {
		case FC_PKT_TRAN_ERROR:
			switch (fpkt->pkt_reason) {
			case FC_REASON_OVERRUN:
				pkt->pkt_reason = CMD_CMD_OVR;
				pkt->pkt_statistics |= STAT_ABORTED;
				break;

			case FC_REASON_XCHG_BSY: {
				caddr_t ptr;

				pkt->pkt_reason = CMD_CMPLT;	/* Lie */

				ptr = (caddr_t)pkt->pkt_scbp;
				if (ptr) {
					*ptr = STATUS_BUSY;
				}
				break;
			}

			case FC_REASON_ABORTED:
				pkt->pkt_reason = CMD_TRAN_ERR;
				pkt->pkt_statistics |= STAT_ABORTED;
				break;

			case FC_REASON_ABORT_FAILED:
				pkt->pkt_reason = CMD_ABORT_FAIL;
				break;

			case FC_REASON_NO_SEQ_INIT:
			case FC_REASON_CRC_ERROR:
				pkt->pkt_reason = CMD_TRAN_ERR;
				pkt->pkt_statistics |= STAT_ABORTED;
				break;
			default:
				pkt->pkt_reason = CMD_TRAN_ERR;
				break;
			}
			break;

		case FC_PKT_PORT_OFFLINE: {
			dev_info_t	*cdip = NULL;
			caddr_t		ptr;

			if (fpkt->pkt_reason == FC_REASON_LOGIN_REQUIRED) {
				FCP_DTRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_8, 0,
				    "SCSI cmd; LOGIN REQUIRED from FCA for %x",
				    ptgt->tgt_d_id);
			}

			mutex_enter(&plun->lun_mutex);
			if (plun->lun_mpxio == 0) {
				cdip = DIP(plun->lun_cip);
			} else if (plun->lun_cip) {
				cdip = mdi_pi_get_client(PIP(plun->lun_cip));
			}

			mutex_exit(&plun->lun_mutex);

			if (cdip) {
				(void) ndi_event_retrieve_cookie(
				    pptr->port_ndi_event_hdl, cdip,
				    FCAL_REMOVE_EVENT, &fcp_remove_eid,
				    NDI_EVENT_NOPASS);
				(void) ndi_event_run_callbacks(
				    pptr->port_ndi_event_hdl, cdip,
				    fcp_remove_eid, NULL);
			}

			/*
			 * If the link goes off-line for a lip,
			 * this will cause a error to the ST SG
			 * SGEN drivers. By setting BUSY we will
			 * give the drivers the chance to retry
			 * before it blows of the job. ST will
			 * remember how many times it has retried.
			 */

			if ((plun->lun_type == DTYPE_SEQUENTIAL) ||
			    (plun->lun_type == DTYPE_CHANGER)) {
				pkt->pkt_reason = CMD_CMPLT;	/* Lie */
				ptr = (caddr_t)pkt->pkt_scbp;
				if (ptr) {
					*ptr = STATUS_BUSY;
				}
			} else {
				pkt->pkt_reason = CMD_TRAN_ERR;
				pkt->pkt_statistics |= STAT_BUS_RESET;
			}
			break;
		}

		case FC_PKT_TRAN_BSY:
			/*
			 * Use the ssd Qfull handling here.
			 */
			*pkt->pkt_scbp = STATUS_INTERMEDIATE;
			pkt->pkt_state = STATE_GOT_BUS;
			break;

		case FC_PKT_TIMEOUT:
			pkt->pkt_reason = CMD_TIMEOUT;
			if (fpkt->pkt_reason == FC_REASON_ABORT_FAILED) {
				pkt->pkt_statistics |= STAT_TIMEOUT;
			} else {
				pkt->pkt_statistics |= STAT_ABORTED;
			}
			break;

		case FC_PKT_LOCAL_RJT:
			switch (fpkt->pkt_reason) {
			case FC_REASON_OFFLINE: {
				dev_info_t	*cdip = NULL;

				mutex_enter(&plun->lun_mutex);
				if (plun->lun_mpxio == 0) {
					cdip = DIP(plun->lun_cip);
				} else if (plun->lun_cip) {
					cdip = mdi_pi_get_client(
					    PIP(plun->lun_cip));
				}
				mutex_exit(&plun->lun_mutex);

				if (cdip) {
					(void) ndi_event_retrieve_cookie(
					    pptr->port_ndi_event_hdl, cdip,
					    FCAL_REMOVE_EVENT,
					    &fcp_remove_eid,
					    NDI_EVENT_NOPASS);
					(void) ndi_event_run_callbacks(
					    pptr->port_ndi_event_hdl,
					    cdip, fcp_remove_eid, NULL);
				}

				pkt->pkt_reason = CMD_TRAN_ERR;
				pkt->pkt_statistics |= STAT_BUS_RESET;

				break;
			}

			case FC_REASON_NOMEM:
			case FC_REASON_QFULL: {
				caddr_t ptr;

				pkt->pkt_reason = CMD_CMPLT;	/* Lie */
				ptr = (caddr_t)pkt->pkt_scbp;
				if (ptr) {
					*ptr = STATUS_BUSY;
				}
				break;
			}

			case FC_REASON_DMA_ERROR:
				pkt->pkt_reason = CMD_DMA_DERR;
				pkt->pkt_statistics |= STAT_ABORTED;
				break;

			case FC_REASON_CRC_ERROR:
			case FC_REASON_UNDERRUN: {
				uchar_t		status;
				/*
				 * Work around for Bugid: 4240945.
				 * IB on A5k doesn't set the Underrun bit
				 * in the fcp status, when it is transferring
				 * less than requested amount of data. Work
				 * around the ses problem to keep luxadm
				 * happy till ibfirmware is fixed.
				 */
				if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
					FCP_CP_IN(fpkt->pkt_resp, rsp,
					    fpkt->pkt_resp_acc,
					    sizeof (struct fcp_rsp));
				}
				status = rsp->fcp_u.fcp_status.scsi_status;
				if (((plun->lun_type & DTYPE_MASK) ==
				    DTYPE_ESI) && (status == STATUS_GOOD)) {
					pkt->pkt_reason = CMD_CMPLT;
					*pkt->pkt_scbp = status;
					pkt->pkt_resid = 0;
				} else {
					pkt->pkt_reason = CMD_TRAN_ERR;
					pkt->pkt_statistics |= STAT_ABORTED;
				}
				break;
			}

			case FC_REASON_NO_CONNECTION:
			case FC_REASON_UNSUPPORTED:
			case FC_REASON_ILLEGAL_REQ:
			case FC_REASON_BAD_SID:
			case FC_REASON_DIAG_BUSY:
			case FC_REASON_FCAL_OPN_FAIL:
			case FC_REASON_BAD_XID:
			default:
				pkt->pkt_reason = CMD_TRAN_ERR;
				pkt->pkt_statistics |= STAT_ABORTED;
				break;

			}
			break;

		case FC_PKT_NPORT_RJT:
		case FC_PKT_FABRIC_RJT:
		case FC_PKT_NPORT_BSY:
		case FC_PKT_FABRIC_BSY:
		default:
			FCP_DTRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_8, 0,
			    "FC Status 0x%x, reason 0x%x",
			    fpkt->pkt_state, fpkt->pkt_reason);
			pkt->pkt_reason = CMD_TRAN_ERR;
			pkt->pkt_statistics |= STAT_ABORTED;
			break;
		}

		FCP_DTRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_9, 0,
		    "!FC error on cmd=%p target=0x%x: pkt state=0x%x "
		    " pkt reason=0x%x", cmd, ptgt->tgt_d_id, fpkt->pkt_state,
		    fpkt->pkt_reason);
	}

	ASSERT(save.a_hba_tran == pkt->pkt_address.a_hba_tran);
}


static int
fcp_validate_fcp_response(struct fcp_rsp *rsp, struct fcp_port *pptr)
{
	if (rsp->reserved_0 || rsp->reserved_1 ||
	    rsp->fcp_u.fcp_status.reserved_0 ||
	    rsp->fcp_u.fcp_status.reserved_1) {
		/*
		 * These reserved fields should ideally be zero. FCP-2 does say
		 * that the recipient need not check for reserved fields to be
		 * zero. If they are not zero, we will not make a fuss about it
		 * - just log it (in debug to both trace buffer and messages
		 * file and to trace buffer only in non-debug) and move on.
		 *
		 * Non-zero reserved fields were seen with minnows.
		 *
		 * qlc takes care of some of this but we cannot assume that all
		 * FCAs will do so.
		 */
		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_5, 0,
		    "Got fcp response packet with non-zero reserved fields "
		    "rsp->reserved_0:0x%x, rsp_reserved_1:0x%x, "
		    "status.reserved_0:0x%x, status.reserved_1:0x%x",
		    rsp->reserved_0, rsp->reserved_1,
		    rsp->fcp_u.fcp_status.reserved_0,
		    rsp->fcp_u.fcp_status.reserved_1);
	}

	if (rsp->fcp_u.fcp_status.rsp_len_set && (rsp->fcp_response_len >
	    (FCP_MAX_RSP_IU_SIZE - sizeof (struct fcp_rsp)))) {
		return (FC_FAILURE);
	}

	if (rsp->fcp_u.fcp_status.sense_len_set && rsp->fcp_sense_len >
	    (FCP_MAX_RSP_IU_SIZE - rsp->fcp_response_len -
	    sizeof (struct fcp_rsp))) {
		return (FC_FAILURE);
	}

	return (FC_SUCCESS);
}


/*
 * This is called when there is a change the in device state. The case we're
 * handling here is, if the d_id s does not match, offline this tgt and online
 * a new tgt with the new d_id.	 called from fcp_handle_devices with
 * port_mutex held.
 */
static int
fcp_device_changed(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    fc_portmap_t *map_entry, int link_cnt, int tgt_cnt, int cause)
{
	ASSERT(mutex_owned(&pptr->port_mutex));

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_3, 0,
	    "Starting fcp_device_changed...");

	/*
	 * The two cases where the port_device_changed is called is
	 * either it changes it's d_id or it's hard address.
	 */
	if ((ptgt->tgt_d_id != map_entry->map_did.port_id) ||
	    (FC_TOP_EXTERNAL(pptr->port_topology) &&
	    (ptgt->tgt_hard_addr != map_entry->map_hard_addr.hard_addr))) {

		/* offline this target */
		mutex_enter(&ptgt->tgt_mutex);
		if (!(ptgt->tgt_state & FCP_TGT_OFFLINE)) {
			(void) fcp_offline_target(pptr, ptgt, link_cnt,
			    0, 1, NDI_DEVI_REMOVE);
		}
		mutex_exit(&ptgt->tgt_mutex);

		fcp_log(CE_NOTE, pptr->port_dip,
		    "Change in target properties: Old D_ID=%x New D_ID=%x"
		    " Old HA=%x New HA=%x", ptgt->tgt_d_id,
		    map_entry->map_did.port_id, ptgt->tgt_hard_addr,
		    map_entry->map_hard_addr.hard_addr);
	}

	return (fcp_handle_mapflags(pptr, ptgt, map_entry,
	    link_cnt, tgt_cnt, cause));
}

/*
 *     Function: fcp_alloc_lun
 *
 *  Description: Creates a new lun structure and adds it to the list
 *		 of luns of the target.
 *
 *     Argument: ptgt		Target the lun will belong to.
 *
 * Return Value: NULL		Failed
 *		 Not NULL	Succeeded
 *
 *	Context: Kernel context
 */
static struct fcp_lun *
fcp_alloc_lun(struct fcp_tgt *ptgt)
{
	struct fcp_lun *plun;

	plun = kmem_zalloc(sizeof (struct fcp_lun), KM_NOSLEEP);
	if (plun != NULL) {
		/*
		 * Initialize the mutex before putting in the target list
		 * especially before releasing the target mutex.
		 */
		mutex_init(&plun->lun_mutex, NULL, MUTEX_DRIVER, NULL);
		plun->lun_tgt = ptgt;

		mutex_enter(&ptgt->tgt_mutex);
		plun->lun_next = ptgt->tgt_lun;
		ptgt->tgt_lun = plun;
		plun->lun_old_guid = NULL;
		plun->lun_old_guid_size = 0;
		mutex_exit(&ptgt->tgt_mutex);
	}

	return (plun);
}

/*
 *     Function: fcp_dealloc_lun
 *
 *  Description: Frees the LUN structure passed by the caller.
 *
 *     Argument: plun		LUN structure to free.
 *
 * Return Value: None
 *
 *	Context: Kernel context.
 */
static void
fcp_dealloc_lun(struct fcp_lun *plun)
{
	mutex_enter(&plun->lun_mutex);
	if (plun->lun_cip) {
		fcp_remove_child(plun);
	}
	mutex_exit(&plun->lun_mutex);

	mutex_destroy(&plun->lun_mutex);
	if (plun->lun_guid) {
		kmem_free(plun->lun_guid, plun->lun_guid_size);
	}
	if (plun->lun_old_guid) {
		kmem_free(plun->lun_old_guid, plun->lun_old_guid_size);
	}
	kmem_free(plun, sizeof (*plun));
}

/*
 *     Function: fcp_alloc_tgt
 *
 *  Description: Creates a new target structure and adds it to the port
 *		 hash list.
 *
 *     Argument: pptr		fcp port structure
 *		 *map_entry	entry describing the target to create
 *		 link_cnt	Link state change counter
 *
 * Return Value: NULL		Failed
 *		 Not NULL	Succeeded
 *
 *	Context: Kernel context.
 */
static struct fcp_tgt *
fcp_alloc_tgt(struct fcp_port *pptr, fc_portmap_t *map_entry, int link_cnt)
{
	int			hash;
	uchar_t			*wwn;
	struct fcp_tgt	*ptgt;

	ptgt = kmem_zalloc(sizeof (*ptgt), KM_NOSLEEP);
	if (ptgt != NULL) {
		mutex_enter(&pptr->port_mutex);
		if (link_cnt != pptr->port_link_cnt) {
			/*
			 * oh oh -- another link reset
			 * in progress -- give up
			 */
			mutex_exit(&pptr->port_mutex);
			kmem_free(ptgt, sizeof (*ptgt));
			ptgt = NULL;
		} else {
			/*
			 * initialize the mutex before putting in the port
			 * wwn list, especially before releasing the port
			 * mutex.
			 */
			mutex_init(&ptgt->tgt_mutex, NULL, MUTEX_DRIVER, NULL);

			/* add new target entry to the port's hash list */
			wwn = (uchar_t *)&map_entry->map_pwwn;
			hash = FCP_HASH(wwn);

			ptgt->tgt_next = pptr->port_tgt_hash_table[hash];
			pptr->port_tgt_hash_table[hash] = ptgt;

			/* save cross-ptr */
			ptgt->tgt_port = pptr;

			ptgt->tgt_change_cnt = 1;

			/* initialize the target manual_config_only flag */
			if (fcp_enable_auto_configuration) {
				ptgt->tgt_manual_config_only = 0;
			} else {
				ptgt->tgt_manual_config_only = 1;
			}

			mutex_exit(&pptr->port_mutex);
		}
	}

	return (ptgt);
}

/*
 *     Function: fcp_dealloc_tgt
 *
 *  Description: Frees the target structure passed by the caller.
 *
 *     Argument: ptgt		Target structure to free.
 *
 * Return Value: None
 *
 *	Context: Kernel context.
 */
static void
fcp_dealloc_tgt(struct fcp_tgt *ptgt)
{
	mutex_destroy(&ptgt->tgt_mutex);
	kmem_free(ptgt, sizeof (*ptgt));
}


/*
 * Handle STATUS_QFULL and STATUS_BUSY by performing delayed retry
 *
 *	Device discovery commands will not be retried for-ever as
 *	this will have repercussions on other devices that need to
 *	be submitted to the hotplug thread. After a quick glance
 *	at the SCSI-3 spec, it was found that the spec doesn't
 *	mandate a forever retry, rather recommends a delayed retry.
 *
 *	Since Photon IB is single threaded, STATUS_BUSY is common
 *	in a 4+initiator environment. Make sure the total time
 *	spent on retries (including command timeout) does not
 *	60 seconds
 */
static void
fcp_queue_ipkt(struct fcp_port *pptr, fc_packet_t *fpkt)
{
	struct fcp_ipkt *icmd = (struct fcp_ipkt *)fpkt->pkt_ulp_private;
	struct fcp_tgt *ptgt = icmd->ipkt_tgt;

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&ptgt->tgt_mutex);
	if (FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "fcp_queue_ipkt,1:state change occured"
		    " for D_ID=0x%x", ptgt->tgt_d_id);
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);
		(void) fcp_call_finish_init(pptr, ptgt, icmd->ipkt_link_cnt,
		    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		fcp_icmd_free(pptr, icmd);
		return;
	}
	mutex_exit(&ptgt->tgt_mutex);

	icmd->ipkt_restart = fcp_watchdog_time + icmd->ipkt_retries++;

	if (pptr->port_ipkt_list != NULL) {
		/* add pkt to front of doubly-linked list */
		pptr->port_ipkt_list->ipkt_prev = icmd;
		icmd->ipkt_next = pptr->port_ipkt_list;
		pptr->port_ipkt_list = icmd;
		icmd->ipkt_prev = NULL;
	} else {
		/* this is the first/only pkt on the list */
		pptr->port_ipkt_list = icmd;
		icmd->ipkt_next = NULL;
		icmd->ipkt_prev = NULL;
	}
	mutex_exit(&pptr->port_mutex);
}

/*
 *     Function: fcp_transport
 *
 *  Description: This function submits the Fibre Channel packet to the transort
 *		 layer by calling fc_ulp_transport().  If fc_ulp_transport()
 *		 fails the submission, the treatment depends on the value of
 *		 the variable internal.
 *
 *     Argument: port_handle	fp/fctl port handle.
 *		 *fpkt		Packet to submit to the transport layer.
 *		 internal	Not zero when it's an internal packet.
 *
 * Return Value: FC_TRAN_BUSY
 *		 FC_STATEC_BUSY
 *		 FC_OFFLINE
 *		 FC_LOGINREQ
 *		 FC_DEVICE_BUSY
 *		 FC_SUCCESS
 */
static int
fcp_transport(opaque_t port_handle, fc_packet_t *fpkt, int internal)
{
	int	rval;

	rval = fc_ulp_transport(port_handle, fpkt);
	if (rval == FC_SUCCESS) {
		return (rval);
	}

	/*
	 * LUN isn't marked BUSY or OFFLINE, so we got here to transport
	 * a command, if the underlying modules see that there is a state
	 * change, or if a port is OFFLINE, that means, that state change
	 * hasn't reached FCP yet, so re-queue the command for deferred
	 * submission.
	 */
	if ((rval == FC_STATEC_BUSY) || (rval == FC_OFFLINE) ||
	    (rval == FC_LOGINREQ) || (rval == FC_DEVICE_BUSY) ||
	    (rval == FC_DEVICE_BUSY_NEW_RSCN) || (rval == FC_TRAN_BUSY)) {
		/*
		 * Defer packet re-submission. Life hang is possible on
		 * internal commands if the port driver sends FC_STATEC_BUSY
		 * for ever, but that shouldn't happen in a good environment.
		 * Limiting re-transport for internal commands is probably a
		 * good idea..
		 * A race condition can happen when a port sees barrage of
		 * link transitions offline to online. If the FCTL has
		 * returned FC_STATEC_BUSY or FC_OFFLINE then none of the
		 * internal commands should be queued to do the discovery.
		 * The race condition is when an online comes and FCP starts
		 * its internal discovery and the link goes offline. It is
		 * possible that the statec_callback has not reached FCP
		 * and FCP is carrying on with its internal discovery.
		 * FC_STATEC_BUSY or FC_OFFLINE will be the first indication
		 * that the link has gone offline. At this point FCP should
		 * drop all the internal commands and wait for the
		 * statec_callback. It will be facilitated by incrementing
		 * port_link_cnt.
		 *
		 * For external commands, the (FC)pkt_timeout is decremented
		 * by the QUEUE Delay added by our driver, Care is taken to
		 * ensure that it doesn't become zero (zero means no timeout)
		 * If the time expires right inside driver queue itself,
		 * the watch thread will return it to the original caller
		 * indicating that the command has timed-out.
		 */
		if (internal) {
			char			*op;
			struct fcp_ipkt	*icmd;

			icmd = (struct fcp_ipkt *)fpkt->pkt_ulp_private;
			switch (icmd->ipkt_opcode) {
			case SCMD_REPORT_LUN:
				op = "REPORT LUN";
				break;

			case SCMD_INQUIRY:
				op = "INQUIRY";
				break;

			case SCMD_INQUIRY_PAGE83:
				op = "INQUIRY-83";
				break;

			default:
				op = "Internal SCSI COMMAND";
				break;
			}

			if (fcp_handle_ipkt_errors(icmd->ipkt_port,
			    icmd->ipkt_tgt, icmd, rval, op) == DDI_SUCCESS) {
				rval = FC_SUCCESS;
			}
		} else {
			struct fcp_pkt *cmd;
			struct fcp_port *pptr;

			cmd = (struct fcp_pkt *)fpkt->pkt_ulp_private;
			cmd->cmd_state = FCP_PKT_IDLE;
			pptr = ADDR2FCP(&cmd->cmd_pkt->pkt_address);

			if (cmd->cmd_pkt->pkt_flags & FLAG_NOQUEUE) {
				FCP_DTRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_9, 0,
				    "fcp_transport: xport busy for pkt %p",
				    cmd->cmd_pkt);
				rval = FC_TRAN_BUSY;
			} else {
				fcp_queue_pkt(pptr, cmd);
				rval = FC_SUCCESS;
			}
		}
	}

	return (rval);
}

/*VARARGS3*/
static void
fcp_log(int level, dev_info_t *dip, const char *fmt, ...)
{
	char		buf[256];
	va_list		ap;

	if (dip == NULL) {
		dip = fcp_global_dip;
	}

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	scsi_log(dip, "fcp", level, buf);
}

/*
 * This function retries NS registry of FC4 type.
 * It assumes that fcp_mutex is held.
 * The function does nothing if topology is not fabric
 * So, the topology has to be set before this function can be called
 */
static void
fcp_retry_ns_registry(struct fcp_port *pptr, uint32_t s_id)
{
	int	rval;

	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	if (((pptr->port_state & FCP_STATE_NS_REG_FAILED) == 0) ||
	    ((pptr->port_topology != FC_TOP_FABRIC) &&
	    (pptr->port_topology != FC_TOP_PUBLIC_LOOP))) {
		if (pptr->port_state & FCP_STATE_NS_REG_FAILED) {
			pptr->port_state &= ~FCP_STATE_NS_REG_FAILED;
		}
		return;
	}
	mutex_exit(&pptr->port_mutex);
	rval = fcp_do_ns_registry(pptr, s_id);
	mutex_enter(&pptr->port_mutex);

	if (rval == 0) {
		/* Registry successful. Reset flag */
		pptr->port_state &= ~(FCP_STATE_NS_REG_FAILED);
	}
}

/*
 * This function registers the ULP with the switch by calling transport i/f
 */
static int
fcp_do_ns_registry(struct fcp_port *pptr, uint32_t s_id)
{
	fc_ns_cmd_t		ns_cmd;
	ns_rfc_type_t		rfc;
	uint32_t		types[8];

	/*
	 * Prepare the Name server structure to
	 * register with the transport in case of
	 * Fabric configuration.
	 */
	bzero(&rfc, sizeof (rfc));
	bzero(types, sizeof (types));

	types[FC4_TYPE_WORD_POS(FC_TYPE_SCSI_FCP)] =
	    (1 << FC4_TYPE_BIT_POS(FC_TYPE_SCSI_FCP));

	rfc.rfc_port_id.port_id = s_id;
	bcopy(types, rfc.rfc_types, sizeof (types));

	ns_cmd.ns_flags = 0;
	ns_cmd.ns_cmd = NS_RFT_ID;
	ns_cmd.ns_req_len = sizeof (rfc);
	ns_cmd.ns_req_payload = (caddr_t)&rfc;
	ns_cmd.ns_resp_len = 0;
	ns_cmd.ns_resp_payload = NULL;

	/*
	 * Perform the Name Server Registration for SCSI_FCP FC4 Type.
	 */
	if (fc_ulp_port_ns(pptr->port_fp_handle, NULL, &ns_cmd)) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!ns_registry: failed name server registration");
		return (1);
	}

	return (0);
}

/*
 *     Function: fcp_handle_port_attach
 *
 *  Description: This function is called from fcp_port_attach() to attach a
 *		 new port. This routine does the following:
 *
 *		1) Allocates an fcp_port structure and initializes it.
 *		2) Tries to register the new FC-4 (FCP) capablity with the name
 *		   server.
 *		3) Kicks off the enumeration of the targets/luns visible
 *		   through this new port.  That is done by calling
 *		   fcp_statec_callback() if the port is online.
 *
 *     Argument: ulph		fp/fctl port handle.
 *		 *pinfo		Port information.
 *		 s_id		Port ID.
 *		 instance	Device instance number for the local port
 *				(returned by ddi_get_instance()).
 *
 * Return Value: DDI_SUCCESS
 *		 DDI_FAILURE
 *
 *	Context: User and Kernel context.
 */
/*ARGSUSED*/
int
fcp_handle_port_attach(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    uint32_t s_id, int instance)
{
	int			res = DDI_FAILURE;
	scsi_hba_tran_t		*tran;
	int			mutex_initted = FALSE;
	int			hba_attached = FALSE;
	int			soft_state_linked = FALSE;
	int			event_bind = FALSE;
	struct fcp_port		*pptr;
	fc_portmap_t		*tmp_list = NULL;
	uint32_t		max_cnt, alloc_cnt;
	uchar_t			*boot_wwn = NULL;
	uint_t			nbytes;
	int			manual_cfg;

	/*
	 * this port instance attaching for the first time (or after
	 * being detached before)
	 */
	FCP_TRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_3, 0, "port attach: for port %d", instance);

	if (ddi_soft_state_zalloc(fcp_softstate, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "fcp: Softstate struct alloc failed"
		    "parent dip: %p; instance: %d", (void *)pinfo->port_dip,
		    instance);
		return (res);
	}

	if ((pptr = ddi_get_soft_state(fcp_softstate, instance)) == NULL) {
		/* this shouldn't happen */
		ddi_soft_state_free(fcp_softstate, instance);
		cmn_err(CE_WARN, "fcp: bad soft state");
		return (res);
	}

	(void) sprintf(pptr->port_instbuf, "fcp(%d)", instance);

	/*
	 * Make a copy of ulp_port_info as fctl allocates
	 * a temp struct.
	 */
	(void) fcp_cp_pinfo(pptr, pinfo);

	/*
	 * Check for manual_configuration_only property.
	 * Enable manual configurtion if the property is
	 * set to 1, otherwise disable manual configuration.
	 */
	if ((manual_cfg = ddi_prop_get_int(DDI_DEV_T_ANY, pptr->port_dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    MANUAL_CFG_ONLY,
	    -1)) != -1) {
		if (manual_cfg == 1) {
			char	*pathname;
			pathname = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
			(void) ddi_pathname(pptr->port_dip, pathname);
			cmn_err(CE_NOTE,
			    "%s (%s%d) %s is enabled via %s.conf.",
			    pathname,
			    ddi_driver_name(pptr->port_dip),
			    ddi_get_instance(pptr->port_dip),
			    MANUAL_CFG_ONLY,
			    ddi_driver_name(pptr->port_dip));
			fcp_enable_auto_configuration = 0;
			kmem_free(pathname, MAXPATHLEN);
		}
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(pptr->port_link_cnt));
	pptr->port_link_cnt = 1;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(pptr->port_link_cnt));
	pptr->port_id = s_id;
	pptr->port_instance = instance;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(pptr->port_state));
	pptr->port_state = FCP_STATE_INIT;
	if (pinfo->port_acc_attr == NULL) {
		/*
		 * The corresponding FCA doesn't support DMA at all
		 */
		pptr->port_state |= FCP_STATE_FCA_IS_NODMA;
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(pptr->port_state));

	if (!(pptr->port_state & FCP_STATE_FCA_IS_NODMA)) {
		/*
		 * If FCA supports DMA in SCSI data phase, we need preallocate
		 * dma cookie, so stash the cookie size
		 */
		pptr->port_dmacookie_sz = sizeof (ddi_dma_cookie_t) *
		    pptr->port_data_dma_attr.dma_attr_sgllen;
	}

	/*
	 * The two mutexes of fcp_port are initialized.	 The variable
	 * mutex_initted is incremented to remember that fact.	That variable
	 * is checked when the routine fails and the mutexes have to be
	 * destroyed.
	 */
	mutex_init(&pptr->port_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pptr->port_pkt_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_initted++;

	/*
	 * The SCSI tran structure is allocate and initialized now.
	 */
	if ((tran = scsi_hba_tran_alloc(pptr->port_dip, 0)) == NULL) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp%d: scsi_hba_tran_alloc failed", instance);
		goto fail;
	}

	/* link in the transport structure then fill it in */
	pptr->port_tran = tran;
	tran->tran_hba_private		= pptr;
	tran->tran_tgt_init		= fcp_scsi_tgt_init;
	tran->tran_tgt_probe		= NULL;
	tran->tran_tgt_free		= fcp_scsi_tgt_free;
	tran->tran_start		= fcp_scsi_start;
	tran->tran_reset		= fcp_scsi_reset;
	tran->tran_abort		= fcp_scsi_abort;
	tran->tran_getcap		= fcp_scsi_getcap;
	tran->tran_setcap		= fcp_scsi_setcap;
	tran->tran_init_pkt		= NULL;
	tran->tran_destroy_pkt		= NULL;
	tran->tran_dmafree		= NULL;
	tran->tran_sync_pkt		= NULL;
	tran->tran_reset_notify		= fcp_scsi_reset_notify;
	tran->tran_get_bus_addr		= fcp_scsi_get_bus_addr;
	tran->tran_get_name		= fcp_scsi_get_name;
	tran->tran_clear_aca		= NULL;
	tran->tran_clear_task_set	= NULL;
	tran->tran_terminate_task	= NULL;
	tran->tran_get_eventcookie	= fcp_scsi_bus_get_eventcookie;
	tran->tran_add_eventcall	= fcp_scsi_bus_add_eventcall;
	tran->tran_remove_eventcall	= fcp_scsi_bus_remove_eventcall;
	tran->tran_post_event		= fcp_scsi_bus_post_event;
	tran->tran_quiesce		= NULL;
	tran->tran_unquiesce		= NULL;
	tran->tran_bus_reset		= NULL;
	tran->tran_bus_config		= fcp_scsi_bus_config;
	tran->tran_bus_unconfig		= fcp_scsi_bus_unconfig;
	tran->tran_bus_power		= NULL;
	tran->tran_interconnect_type	= INTERCONNECT_FABRIC;

	tran->tran_pkt_constructor	= fcp_kmem_cache_constructor;
	tran->tran_pkt_destructor	= fcp_kmem_cache_destructor;
	tran->tran_setup_pkt		= fcp_pkt_setup;
	tran->tran_teardown_pkt		= fcp_pkt_teardown;
	tran->tran_hba_len		= pptr->port_priv_pkt_len +
	    sizeof (struct fcp_pkt) + pptr->port_dmacookie_sz;
	if (pptr->port_state & FCP_STATE_FCA_IS_NODMA) {
		/*
		 * If FCA don't support DMA, then we use different vectors to
		 * minimize the effects on DMA code flow path
		 */
		tran->tran_start	   = fcp_pseudo_start;
		tran->tran_init_pkt	   = fcp_pseudo_init_pkt;
		tran->tran_destroy_pkt	   = fcp_pseudo_destroy_pkt;
		tran->tran_sync_pkt	   = fcp_pseudo_sync_pkt;
		tran->tran_dmafree	   = fcp_pseudo_dmafree;
		tran->tran_setup_pkt	   = NULL;
		tran->tran_teardown_pkt	   = NULL;
		tran->tran_pkt_constructor = NULL;
		tran->tran_pkt_destructor  = NULL;
		pptr->port_data_dma_attr   = pseudo_fca_dma_attr;
	}

	/*
	 * Allocate an ndi event handle
	 */
	pptr->port_ndi_event_defs = (ndi_event_definition_t *)
	    kmem_zalloc(sizeof (fcp_ndi_event_defs), KM_SLEEP);

	bcopy(fcp_ndi_event_defs, pptr->port_ndi_event_defs,
	    sizeof (fcp_ndi_event_defs));

	(void) ndi_event_alloc_hdl(pptr->port_dip, NULL,
	    &pptr->port_ndi_event_hdl, NDI_SLEEP);

	pptr->port_ndi_events.ndi_events_version = NDI_EVENTS_REV1;
	pptr->port_ndi_events.ndi_n_events = FCP_N_NDI_EVENTS;
	pptr->port_ndi_events.ndi_event_defs = pptr->port_ndi_event_defs;

	if (DEVI_IS_ATTACHING(pptr->port_dip) &&
	    (ndi_event_bind_set(pptr->port_ndi_event_hdl,
	    &pptr->port_ndi_events, NDI_SLEEP) != NDI_SUCCESS)) {
		goto fail;
	}
	event_bind++;	/* Checked in fail case */

	if (scsi_hba_attach_setup(pptr->port_dip, &pptr->port_data_dma_attr,
	    tran, SCSI_HBA_ADDR_COMPLEX | SCSI_HBA_TRAN_SCB)
	    != DDI_SUCCESS) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp%d: scsi_hba_attach_setup failed", instance);
		goto fail;
	}
	hba_attached++;	/* Checked in fail case */

	pptr->port_mpxio = 0;
	if (mdi_phci_register(MDI_HCI_CLASS_SCSI, pptr->port_dip, 0) ==
	    MDI_SUCCESS) {
		pptr->port_mpxio++;
	}

	/*
	 * The following code is putting the new port structure in the global
	 * list of ports and, if it is the first port to attach, it start the
	 * fcp_watchdog_tick.
	 *
	 * Why put this new port in the global before we are done attaching it?
	 * We are actually making the structure globally known before we are
	 * done attaching it.  The reason for that is: because of the code that
	 * follows.  At this point the resources to handle the port are
	 * allocated.  This function is now going to do the following:
	 *
	 *   1) It is going to try to register with the name server advertizing
	 *	the new FCP capability of the port.
	 *   2) It is going to play the role of the fp/fctl layer by building
	 *	a list of worlwide names reachable through this port and call
	 *	itself on fcp_statec_callback().  That requires the port to
	 *	be part of the global list.
	 */
	mutex_enter(&fcp_global_mutex);
	if (fcp_port_head == NULL) {
		fcp_read_blacklist(pinfo->port_dip, &fcp_lun_blacklist);
	}
	pptr->port_next = fcp_port_head;
	fcp_port_head = pptr;
	soft_state_linked++;

	if (fcp_watchdog_init++ == 0) {
		fcp_watchdog_tick = fcp_watchdog_timeout *
		    drv_usectohz(1000000);
		fcp_watchdog_id = timeout(fcp_watch, NULL,
		    fcp_watchdog_tick);
	}
	mutex_exit(&fcp_global_mutex);

	/*
	 * Here an attempt is made to register with the name server, the new
	 * FCP capability.  That is done using an RTF_ID to the name server.
	 * It is done synchronously.  The function fcp_do_ns_registry()
	 * doesn't return till the name server responded.
	 * On failures, just ignore it for now and it will get retried during
	 * state change callbacks. We'll set a flag to show this failure
	 */
	if (fcp_do_ns_registry(pptr, s_id)) {
		mutex_enter(&pptr->port_mutex);
		pptr->port_state |= FCP_STATE_NS_REG_FAILED;
		mutex_exit(&pptr->port_mutex);
	} else {
		mutex_enter(&pptr->port_mutex);
		pptr->port_state &= ~(FCP_STATE_NS_REG_FAILED);
		mutex_exit(&pptr->port_mutex);
	}

	/*
	 * Lookup for boot WWN property
	 */
	if (modrootloaded != 1) {
		if ((ddi_prop_lookup_byte_array(DDI_DEV_T_ANY,
		    ddi_get_parent(pinfo->port_dip),
		    DDI_PROP_DONTPASS, OBP_BOOT_WWN,
		    &boot_wwn, &nbytes) == DDI_PROP_SUCCESS) &&
		    (nbytes == FC_WWN_SIZE)) {
			bcopy(boot_wwn, pptr->port_boot_wwn, FC_WWN_SIZE);
		}
		if (boot_wwn) {
			ddi_prop_free(boot_wwn);
		}
	}

	/*
	 * Handle various topologies and link states.
	 */
	switch (FC_PORT_STATE_MASK(pptr->port_phys_state)) {
	case FC_STATE_OFFLINE:

		/*
		 * we're attaching a port where the link is offline
		 *
		 * Wait for ONLINE, at which time a state
		 * change will cause a statec_callback
		 *
		 * in the mean time, do not do anything
		 */
		res = DDI_SUCCESS;
		pptr->port_state |= FCP_STATE_OFFLINE;
		break;

	case FC_STATE_ONLINE: {
		if (pptr->port_topology == FC_TOP_UNKNOWN) {
			(void) fcp_linkreset(pptr, NULL, KM_NOSLEEP);
			res = DDI_SUCCESS;
			break;
		}
		/*
		 * discover devices and create nodes (a private
		 * loop or point-to-point)
		 */
		ASSERT(pptr->port_topology != FC_TOP_UNKNOWN);

		/*
		 * At this point we are going to build a list of all the ports
		 * that	can be reached through this local port.	 It looks like
		 * we cannot handle more than FCP_MAX_DEVICES per local port
		 * (128).
		 */
		if ((tmp_list = (fc_portmap_t *)kmem_zalloc(
		    sizeof (fc_portmap_t) * FCP_MAX_DEVICES,
		    KM_NOSLEEP)) == NULL) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!fcp%d: failed to allocate portmap",
			    instance);
			goto fail;
		}

		/*
		 * fc_ulp_getportmap() is going to provide us with the list of
		 * remote ports in the buffer we just allocated.  The way the
		 * list is going to be retrieved depends on the topology.
		 * However, if we are connected to a Fabric, a name server
		 * request may be sent to get the list of FCP capable ports.
		 * It should be noted that is the case the request is
		 * synchronous.	 This means we are stuck here till the name
		 * server replies.  A lot of things can change during that time
		 * and including, may be, being called on
		 * fcp_statec_callback() for different reasons. I'm not sure
		 * the code can handle that.
		 */
		max_cnt = FCP_MAX_DEVICES;
		alloc_cnt = FCP_MAX_DEVICES;
		if ((res = fc_ulp_getportmap(pptr->port_fp_handle,
		    &tmp_list, &max_cnt, FC_ULP_PLOGI_PRESERVE)) !=
		    FC_SUCCESS) {
			caddr_t msg;

			(void) fc_ulp_error(res, &msg);

			/*
			 * this	 just means the transport is
			 * busy perhaps building a portmap so,
			 * for now, succeed this port attach
			 * when the transport has a new map,
			 * it'll send us a state change then
			 */
			fcp_log(CE_WARN, pptr->port_dip,
			    "!failed to get port map : %s", msg);

			res = DDI_SUCCESS;
			break;	/* go return result */
		}
		if (max_cnt > alloc_cnt) {
			alloc_cnt = max_cnt;
		}

		/*
		 * We are now going to call fcp_statec_callback() ourselves.
		 * By issuing this call we are trying to kick off the enumera-
		 * tion process.
		 */
		/*
		 * let the state change callback do the SCSI device
		 * discovery and create the devinfos
		 */
		fcp_statec_callback(ulph, pptr->port_fp_handle,
		    pptr->port_phys_state, pptr->port_topology, tmp_list,
		    max_cnt, pptr->port_id);

		res = DDI_SUCCESS;
		break;
	}

	default:
		/* unknown port state */
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp%d: invalid port state at attach=0x%x",
		    instance, pptr->port_phys_state);

		mutex_enter(&pptr->port_mutex);
		pptr->port_phys_state = FCP_STATE_OFFLINE;
		mutex_exit(&pptr->port_mutex);

		res = DDI_SUCCESS;
		break;
	}

	/* free temp list if used */
	if (tmp_list != NULL) {
		kmem_free(tmp_list, sizeof (fc_portmap_t) * alloc_cnt);
	}

	/* note the attach time */
	pptr->port_attach_time = ddi_get_lbolt64();

	/* all done */
	return (res);

	/* a failure we have to clean up after */
fail:
	fcp_log(CE_WARN, pptr->port_dip, "!failed to attach to port");

	if (soft_state_linked) {
		/* remove this fcp_port from the linked list */
		(void) fcp_soft_state_unlink(pptr);
	}

	/* unbind and free event set */
	if (pptr->port_ndi_event_hdl) {
		if (event_bind) {
			(void) ndi_event_unbind_set(pptr->port_ndi_event_hdl,
			    &pptr->port_ndi_events, NDI_SLEEP);
		}
		(void) ndi_event_free_hdl(pptr->port_ndi_event_hdl);
	}

	if (pptr->port_ndi_event_defs) {
		(void) kmem_free(pptr->port_ndi_event_defs,
		    sizeof (fcp_ndi_event_defs));
	}

	/*
	 * Clean up mpxio stuff
	 */
	if (pptr->port_mpxio) {
		(void) mdi_phci_unregister(pptr->port_dip, 0);
		pptr->port_mpxio--;
	}

	/* undo SCSI HBA setup */
	if (hba_attached) {
		(void) scsi_hba_detach(pptr->port_dip);
	}
	if (pptr->port_tran != NULL) {
		scsi_hba_tran_free(pptr->port_tran);
	}

	mutex_enter(&fcp_global_mutex);

	/*
	 * We check soft_state_linked, because it is incremented right before
	 * we call increment fcp_watchdog_init.	 Therefore, we know if
	 * soft_state_linked is still FALSE, we do not want to decrement
	 * fcp_watchdog_init or possibly call untimeout.
	 */

	if (soft_state_linked) {
		if (--fcp_watchdog_init == 0) {
			timeout_id_t	tid = fcp_watchdog_id;

			mutex_exit(&fcp_global_mutex);
			(void) untimeout(tid);
		} else {
			mutex_exit(&fcp_global_mutex);
		}
	} else {
		mutex_exit(&fcp_global_mutex);
	}

	if (mutex_initted) {
		mutex_destroy(&pptr->port_mutex);
		mutex_destroy(&pptr->port_pkt_mutex);
	}

	if (tmp_list != NULL) {
		kmem_free(tmp_list, sizeof (fc_portmap_t) * alloc_cnt);
	}

	/* this makes pptr invalid */
	ddi_soft_state_free(fcp_softstate, instance);

	return (DDI_FAILURE);
}


static int
fcp_handle_port_detach(struct fcp_port *pptr, int flag, int instance)
{
	int count = 0;

	mutex_enter(&pptr->port_mutex);

	/*
	 * if the port is powered down or suspended, nothing else
	 * to do; just return.
	 */
	if (flag != FCP_STATE_DETACHING) {
		if (pptr->port_state & (FCP_STATE_POWER_DOWN |
		    FCP_STATE_SUSPENDED)) {
			pptr->port_state |= flag;
			mutex_exit(&pptr->port_mutex);
			return (FC_SUCCESS);
		}
	}

	if (pptr->port_state & FCP_STATE_IN_MDI) {
		mutex_exit(&pptr->port_mutex);
		return (FC_FAILURE);
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_2, 0,
	    "fcp_handle_port_detach: port is detaching");

	pptr->port_state |= flag;

	/*
	 * Wait for any ongoing reconfig/ipkt to complete, that
	 * ensures the freeing to targets/luns is safe.
	 * No more ref to this port should happen from statec/ioctl
	 * after that as it was removed from the global port list.
	 */
	while (pptr->port_tmp_cnt || pptr->port_ipkt_cnt ||
	    (pptr->port_state & FCP_STATE_IN_WATCHDOG)) {
		/*
		 * Let's give sufficient time for reconfig/ipkt
		 * to complete.
		 */
		if (count++ >= FCP_ICMD_DEADLINE) {
			break;
		}
		mutex_exit(&pptr->port_mutex);
		delay(drv_usectohz(1000000));
		mutex_enter(&pptr->port_mutex);
	}

	/*
	 * if the driver is still busy then fail to
	 * suspend/power down.
	 */
	if (pptr->port_tmp_cnt || pptr->port_ipkt_cnt ||
	    (pptr->port_state & FCP_STATE_IN_WATCHDOG)) {
		pptr->port_state &= ~flag;
		mutex_exit(&pptr->port_mutex);
		return (FC_FAILURE);
	}

	if (flag == FCP_STATE_DETACHING) {
		pptr = fcp_soft_state_unlink(pptr);
		ASSERT(pptr != NULL);
	}

	pptr->port_link_cnt++;
	pptr->port_state |= FCP_STATE_OFFLINE;
	pptr->port_state &= ~(FCP_STATE_ONLINING | FCP_STATE_ONLINE);

	fcp_update_state(pptr, (FCP_LUN_BUSY | FCP_LUN_MARK),
	    FCP_CAUSE_LINK_DOWN);
	mutex_exit(&pptr->port_mutex);

	/* kill watch dog timer if we're the last */
	mutex_enter(&fcp_global_mutex);
	if (--fcp_watchdog_init == 0) {
		timeout_id_t	tid = fcp_watchdog_id;
		mutex_exit(&fcp_global_mutex);
		(void) untimeout(tid);
	} else {
		mutex_exit(&fcp_global_mutex);
	}

	/* clean up the port structures */
	if (flag == FCP_STATE_DETACHING) {
		fcp_cleanup_port(pptr, instance);
	}

	return (FC_SUCCESS);
}


static void
fcp_cleanup_port(struct fcp_port *pptr, int instance)
{
	ASSERT(pptr != NULL);

	/* unbind and free event set */
	if (pptr->port_ndi_event_hdl) {
		(void) ndi_event_unbind_set(pptr->port_ndi_event_hdl,
		    &pptr->port_ndi_events, NDI_SLEEP);
		(void) ndi_event_free_hdl(pptr->port_ndi_event_hdl);
	}

	if (pptr->port_ndi_event_defs) {
		(void) kmem_free(pptr->port_ndi_event_defs,
		    sizeof (fcp_ndi_event_defs));
	}

	/* free the lun/target structures and devinfos */
	fcp_free_targets(pptr);

	/*
	 * Clean up mpxio stuff
	 */
	if (pptr->port_mpxio) {
		(void) mdi_phci_unregister(pptr->port_dip, 0);
		pptr->port_mpxio--;
	}

	/* clean up SCSA stuff */
	(void) scsi_hba_detach(pptr->port_dip);
	if (pptr->port_tran != NULL) {
		scsi_hba_tran_free(pptr->port_tran);
	}

#ifdef	KSTATS_CODE
	/* clean up kstats */
	if (pptr->fcp_ksp != NULL) {
		kstat_delete(pptr->fcp_ksp);
	}
#endif

	/* clean up soft state mutexes/condition variables */
	mutex_destroy(&pptr->port_mutex);
	mutex_destroy(&pptr->port_pkt_mutex);

	/* all done with soft state */
	ddi_soft_state_free(fcp_softstate, instance);
}

/*
 *     Function: fcp_kmem_cache_constructor
 *
 *  Description: This function allocates and initializes the resources required
 *		 to build a scsi_pkt structure the target driver.  The result
 *		 of the allocation and initialization will be cached in the
 *		 memory cache.	As DMA resources may be allocated here, that
 *		 means DMA resources will be tied up in the cache manager.
 *		 This is a tradeoff that has been made for performance reasons.
 *
 *     Argument: *buf		Memory to preinitialize.
 *		 *arg		FCP port structure (fcp_port).
 *		 kmflags	Value passed to kmem_cache_alloc() and
 *				propagated to the constructor.
 *
 * Return Value: 0	Allocation/Initialization was successful.
 *		 -1	Allocation or Initialization failed.
 *
 *
 * If the returned value is 0, the buffer is initialized like this:
 *
 *		    +================================+
 *	     +----> |	      struct scsi_pkt	     |
 *	     |	    |				     |
 *	     | +--- | pkt_ha_private		     |
 *	     | |    |				     |
 *	     | |    +================================+
 *	     | |
 *	     | |    +================================+
 *	     | +--> |	    struct fcp_pkt	     | <---------+
 *	     |	    |				     |		 |
 *	     +----- | cmd_pkt			     |		 |
 *		    |			  cmd_fp_pkt | ---+	 |
 *	  +-------->| cmd_fcp_rsp[]		     |	  |	 |
 *	  |    +--->| cmd_fcp_cmd[]		     |	  |	 |
 *	  |    |    |--------------------------------|	  |	 |
 *	  |    |    |	      struct fc_packet	     | <--+	 |
 *	  |    |    |				     |		 |
 *	  |    |    |		     pkt_ulp_private | ----------+
 *	  |    |    |		     pkt_fca_private | -----+
 *	  |    |    |		     pkt_data_cookie | ---+ |
 *	  |    |    | pkt_cmdlen		     |	  | |
 *	  |    |(a) | pkt_rsplen		     |	  | |
 *	  |    +----| .......... pkt_cmd ........... | ---|-|---------------+
 *	  |	(b) |		      pkt_cmd_cookie | ---|-|----------+    |
 *	  +---------| .......... pkt_resp .......... | ---|-|------+   |    |
 *		    |		     pkt_resp_cookie | ---|-|--+   |   |    |
 *		    | pkt_cmd_dma		     |	  | |  |   |   |    |
 *		    | pkt_cmd_acc		     |	  | |  |   |   |    |
 *		    +================================+	  | |  |   |   |    |
 *		    |	      dma_cookies	     | <--+ |  |   |   |    |
 *		    |				     |	    |  |   |   |    |
 *		    +================================+	    |  |   |   |    |
 *		    |	      fca_private	     | <----+  |   |   |    |
 *		    |				     |	       |   |   |    |
 *		    +================================+	       |   |   |    |
 *							       |   |   |    |
 *							       |   |   |    |
 *		    +================================+	 (d)   |   |   |    |
 *		    |	     fcp_resp cookies	     | <-------+   |   |    |
 *		    |				     |		   |   |    |
 *		    +================================+		   |   |    |
 *								   |   |    |
 *		    +================================+	 (d)	   |   |    |
 *		    |		fcp_resp	     | <-----------+   |    |
 *		    |	(DMA resources associated)   |		       |    |
 *		    +================================+		       |    |
 *								       |    |
 *								       |    |
 *								       |    |
 *		    +================================+	 (c)	       |    |
 *		    |	     fcp_cmd cookies	     | <---------------+    |
 *		    |				     |			    |
 *		    +================================+			    |
 *									    |
 *		    +================================+	 (c)		    |
 *		    |		 fcp_cmd	     | <--------------------+
 *		    |	(DMA resources associated)   |
 *		    +================================+
 *
 * (a) Only if DMA is NOT used for the FCP_CMD buffer.
 * (b) Only if DMA is NOT used for the FCP_RESP buffer
 * (c) Only if DMA is used for the FCP_CMD buffer.
 * (d) Only if DMA is used for the FCP_RESP buffer
 */
static int
fcp_kmem_cache_constructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran,
    int kmflags)
{
	struct fcp_pkt	*cmd;
	struct fcp_port	*pptr;
	fc_packet_t	*fpkt;

	pptr = (struct fcp_port *)tran->tran_hba_private;
	cmd = (struct fcp_pkt *)pkt->pkt_ha_private;
	bzero(cmd, tran->tran_hba_len);

	cmd->cmd_pkt = pkt;
	pkt->pkt_cdbp = cmd->cmd_fcp_cmd.fcp_cdb;
	fpkt = (fc_packet_t *)&cmd->cmd_fc_packet;
	cmd->cmd_fp_pkt = fpkt;

	cmd->cmd_pkt->pkt_ha_private = (opaque_t)cmd;
	cmd->cmd_fp_pkt->pkt_ulp_private = (opaque_t)cmd;
	cmd->cmd_fp_pkt->pkt_fca_private = (opaque_t)((caddr_t)cmd +
	    sizeof (struct fcp_pkt) + pptr->port_dmacookie_sz);

	fpkt->pkt_data_cookie = (ddi_dma_cookie_t *)((caddr_t)cmd +
	    sizeof (struct fcp_pkt));

	fpkt->pkt_cmdlen = sizeof (struct fcp_cmd);
	fpkt->pkt_rsplen = FCP_MAX_RSP_IU_SIZE;

	if (pptr->port_fcp_dma == FC_NO_DVMA_SPACE) {
		/*
		 * The underlying HBA doesn't want to DMA the fcp_cmd or
		 * fcp_resp.  The transfer of information will be done by
		 * bcopy.
		 * The naming of the flags (that is actually a value) is
		 * unfortunate.	 FC_NO_DVMA_SPACE doesn't mean "NO VIRTUAL
		 * DMA" but instead "NO DMA".
		 */
		fpkt->pkt_resp_acc = fpkt->pkt_cmd_acc = NULL;
		fpkt->pkt_cmd = (caddr_t)&cmd->cmd_fcp_cmd;
		fpkt->pkt_resp = cmd->cmd_fcp_rsp;
	} else {
		/*
		 * The underlying HBA will dma the fcp_cmd buffer and fcp_resp
		 * buffer.  A buffer is allocated for each one the ddi_dma_*
		 * interfaces.
		 */
		if (fcp_alloc_cmd_resp(pptr, fpkt, kmflags) != FC_SUCCESS) {
			return (-1);
		}
	}

	return (0);
}

/*
 *     Function: fcp_kmem_cache_destructor
 *
 *  Description: Called by the destructor of the cache managed by SCSA.
 *		 All the resources pre-allocated in fcp_pkt_constructor
 *		 and the data also pre-initialized in fcp_pkt_constructor
 *		 are freed and uninitialized here.
 *
 *     Argument: *buf		Memory to uninitialize.
 *		 *arg		FCP port structure (fcp_port).
 *
 * Return Value: None
 *
 *	Context: kernel
 */
static void
fcp_kmem_cache_destructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran)
{
	struct fcp_pkt	*cmd;
	struct fcp_port	*pptr;

	pptr = (struct fcp_port *)(tran->tran_hba_private);
	cmd = pkt->pkt_ha_private;

	if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
		/*
		 * If DMA was used to transfer the FCP_CMD and FCP_RESP, the
		 * buffer and DMA resources allocated to do so are released.
		 */
		fcp_free_cmd_resp(pptr, cmd->cmd_fp_pkt);
	}
}

/*
 *     Function: fcp_alloc_cmd_resp
 *
 *  Description: This function allocated an FCP_CMD and FCP_RESP buffer that
 *		 will be DMAed by the HBA.  The buffer is allocated applying
 *		 the DMA requirements for the HBA.  The buffers allocated will
 *		 also be bound.	 DMA resources are allocated in the process.
 *		 They will be released by fcp_free_cmd_resp().
 *
 *     Argument: *pptr	FCP port.
 *		 *fpkt	fc packet for which the cmd and resp packet should be
 *			allocated.
 *		 flags	Allocation flags.
 *
 * Return Value: FC_FAILURE
 *		 FC_SUCCESS
 *
 *	Context: User or Kernel context only if flags == KM_SLEEP.
 *		 Interrupt context if the KM_SLEEP is not specified.
 */
static int
fcp_alloc_cmd_resp(struct fcp_port *pptr, fc_packet_t *fpkt, int flags)
{
	int			rval;
	int			cmd_len;
	int			resp_len;
	ulong_t			real_len;
	int			(*cb) (caddr_t);
	ddi_dma_cookie_t	pkt_cookie;
	ddi_dma_cookie_t	*cp;
	uint32_t		cnt;

	cb = (flags == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	cmd_len = fpkt->pkt_cmdlen;
	resp_len = fpkt->pkt_rsplen;

	ASSERT(fpkt->pkt_cmd_dma == NULL);

	/* Allocation of a DMA handle used in subsequent calls. */
	if (ddi_dma_alloc_handle(pptr->port_dip, &pptr->port_cmd_dma_attr,
	    cb, NULL, &fpkt->pkt_cmd_dma) != DDI_SUCCESS) {
		return (FC_FAILURE);
	}

	/* A buffer is allocated that satisfies the DMA requirements. */
	rval = ddi_dma_mem_alloc(fpkt->pkt_cmd_dma, cmd_len,
	    &pptr->port_dma_acc_attr, DDI_DMA_CONSISTENT, cb, NULL,
	    (caddr_t *)&fpkt->pkt_cmd, &real_len, &fpkt->pkt_cmd_acc);

	if (rval != DDI_SUCCESS) {
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		return (FC_FAILURE);
	}

	if (real_len < cmd_len) {
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		return (FC_FAILURE);
	}

	/* The buffer allocated is DMA bound. */
	rval = ddi_dma_addr_bind_handle(fpkt->pkt_cmd_dma, NULL,
	    fpkt->pkt_cmd, real_len, DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    cb, NULL, &pkt_cookie, &fpkt->pkt_cmd_cookie_cnt);

	if (rval != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		return (FC_FAILURE);
	}

	if (fpkt->pkt_cmd_cookie_cnt >
	    pptr->port_cmd_dma_attr.dma_attr_sgllen) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		return (FC_FAILURE);
	}

	ASSERT(fpkt->pkt_cmd_cookie_cnt != 0);

	/*
	 * The buffer where the scatter/gather list is going to be built is
	 * allocated.
	 */
	cp = fpkt->pkt_cmd_cookie = (ddi_dma_cookie_t *)kmem_alloc(
	    fpkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie),
	    KM_NOSLEEP);

	if (cp == NULL) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		return (FC_FAILURE);
	}

	/*
	 * The scatter/gather list for the buffer we just allocated is built
	 * here.
	 */
	*cp = pkt_cookie;
	cp++;

	for (cnt = 1; cnt < fpkt->pkt_cmd_cookie_cnt; cnt++, cp++) {
		ddi_dma_nextcookie(fpkt->pkt_cmd_dma,
		    &pkt_cookie);
		*cp = pkt_cookie;
	}

	ASSERT(fpkt->pkt_resp_dma == NULL);
	if (ddi_dma_alloc_handle(pptr->port_dip, &pptr->port_resp_dma_attr,
	    cb, NULL, &fpkt->pkt_resp_dma) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		return (FC_FAILURE);
	}

	rval = ddi_dma_mem_alloc(fpkt->pkt_resp_dma, resp_len,
	    &pptr->port_dma_acc_attr, DDI_DMA_CONSISTENT, cb, NULL,
	    (caddr_t *)&fpkt->pkt_resp, &real_len,
	    &fpkt->pkt_resp_acc);

	if (rval != DDI_SUCCESS) {
		ddi_dma_free_handle(&fpkt->pkt_resp_dma);
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		kmem_free(fpkt->pkt_cmd_cookie,
		    fpkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie));
		return (FC_FAILURE);
	}

	if (real_len < resp_len) {
		ddi_dma_mem_free(&fpkt->pkt_resp_acc);
		ddi_dma_free_handle(&fpkt->pkt_resp_dma);
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		kmem_free(fpkt->pkt_cmd_cookie,
		    fpkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie));
		return (FC_FAILURE);
	}

	rval = ddi_dma_addr_bind_handle(fpkt->pkt_resp_dma, NULL,
	    fpkt->pkt_resp, real_len, DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    cb, NULL, &pkt_cookie, &fpkt->pkt_resp_cookie_cnt);

	if (rval != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&fpkt->pkt_resp_acc);
		ddi_dma_free_handle(&fpkt->pkt_resp_dma);
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		kmem_free(fpkt->pkt_cmd_cookie,
		    fpkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie));
		return (FC_FAILURE);
	}

	if (fpkt->pkt_resp_cookie_cnt >
	    pptr->port_resp_dma_attr.dma_attr_sgllen) {
		ddi_dma_mem_free(&fpkt->pkt_resp_acc);
		ddi_dma_free_handle(&fpkt->pkt_resp_dma);
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		kmem_free(fpkt->pkt_cmd_cookie,
		    fpkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie));
		return (FC_FAILURE);
	}

	ASSERT(fpkt->pkt_resp_cookie_cnt != 0);

	cp = fpkt->pkt_resp_cookie = (ddi_dma_cookie_t *)kmem_alloc(
	    fpkt->pkt_resp_cookie_cnt * sizeof (pkt_cookie),
	    KM_NOSLEEP);

	if (cp == NULL) {
		ddi_dma_mem_free(&fpkt->pkt_resp_acc);
		ddi_dma_free_handle(&fpkt->pkt_resp_dma);
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
		kmem_free(fpkt->pkt_cmd_cookie,
		    fpkt->pkt_cmd_cookie_cnt * sizeof (pkt_cookie));
		return (FC_FAILURE);
	}

	*cp = pkt_cookie;
	cp++;

	for (cnt = 1; cnt < fpkt->pkt_resp_cookie_cnt; cnt++, cp++) {
		ddi_dma_nextcookie(fpkt->pkt_resp_dma,
		    &pkt_cookie);
		*cp = pkt_cookie;
	}

	return (FC_SUCCESS);
}

/*
 *     Function: fcp_free_cmd_resp
 *
 *  Description: This function releases the FCP_CMD and FCP_RESP buffer
 *		 allocated by fcp_alloc_cmd_resp() and all the resources
 *		 associated with them.	That includes the DMA resources and the
 *		 buffer allocated for the cookies of each one of them.
 *
 *     Argument: *pptr		FCP port context.
 *		 *fpkt		fc packet containing the cmd and resp packet
 *				to be released.
 *
 * Return Value: None
 *
 *	Context: Interrupt, User and Kernel context.
 */
/* ARGSUSED */
static void
fcp_free_cmd_resp(struct fcp_port *pptr, fc_packet_t *fpkt)
{
	ASSERT(fpkt->pkt_resp_dma != NULL && fpkt->pkt_cmd_dma != NULL);

	if (fpkt->pkt_resp_dma) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_resp_dma);
		ddi_dma_mem_free(&fpkt->pkt_resp_acc);
		ddi_dma_free_handle(&fpkt->pkt_resp_dma);
	}

	if (fpkt->pkt_resp_cookie) {
		kmem_free(fpkt->pkt_resp_cookie,
		    fpkt->pkt_resp_cookie_cnt * sizeof (ddi_dma_cookie_t));
		fpkt->pkt_resp_cookie = NULL;
	}

	if (fpkt->pkt_cmd_dma) {
		(void) ddi_dma_unbind_handle(fpkt->pkt_cmd_dma);
		ddi_dma_mem_free(&fpkt->pkt_cmd_acc);
		ddi_dma_free_handle(&fpkt->pkt_cmd_dma);
	}

	if (fpkt->pkt_cmd_cookie) {
		kmem_free(fpkt->pkt_cmd_cookie,
		    fpkt->pkt_cmd_cookie_cnt * sizeof (ddi_dma_cookie_t));
		fpkt->pkt_cmd_cookie = NULL;
	}
}


/*
 * called by the transport to do our own target initialization
 *
 * can acquire and release the global mutex
 */
/* ARGSUSED */
static int
fcp_phys_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	uchar_t			*bytes;
	uint_t			nbytes;
	uint16_t		lun_num;
	struct fcp_tgt	*ptgt;
	struct fcp_lun	*plun;
	struct fcp_port	*pptr = (struct fcp_port *)
	    hba_tran->tran_hba_private;

	ASSERT(pptr != NULL);

	FCP_DTRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
	    FCP_BUF_LEVEL_8, 0,
	    "fcp_phys_tgt_init: called for %s (instance %d)",
	    ddi_get_name(tgt_dip), ddi_get_instance(tgt_dip));

	/* get our port WWN property */
	bytes = NULL;
	if ((scsi_device_prop_lookup_byte_array(sd, SCSI_DEVICE_PROP_PATH,
	    PORT_WWN_PROP, &bytes, &nbytes) != DDI_PROP_SUCCESS) ||
	    (nbytes != FC_WWN_SIZE)) {
		/* no port WWN property */
		FCP_DTRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_8, 0,
		    "fcp_phys_tgt_init: Returning DDI_NOT_WELL_FORMED"
		    " for %s (instance %d): bytes=%p nbytes=%x",
		    ddi_get_name(tgt_dip), ddi_get_instance(tgt_dip), bytes,
		    nbytes);

		if (bytes != NULL) {
			scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);
		}

		return (DDI_NOT_WELL_FORMED);
	}
	ASSERT(bytes != NULL);

	lun_num = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    LUN_PROP, 0xFFFF);
	if (lun_num == 0xFFFF) {
		FCP_DTRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_8, 0,
		    "fcp_phys_tgt_init: Returning DDI_FAILURE:lun"
		    " for %s (instance %d)", ddi_get_name(tgt_dip),
		    ddi_get_instance(tgt_dip));

		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);
		return (DDI_NOT_WELL_FORMED);
	}

	mutex_enter(&pptr->port_mutex);
	if ((plun = fcp_lookup_lun(pptr, bytes, lun_num)) == NULL) {
		mutex_exit(&pptr->port_mutex);
		FCP_DTRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_8, 0,
		    "fcp_phys_tgt_init: Returning DDI_FAILURE: No Lun"
		    " for %s (instance %d)", ddi_get_name(tgt_dip),
		    ddi_get_instance(tgt_dip));

		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);
		return (DDI_FAILURE);
	}

	ASSERT(bcmp(plun->lun_tgt->tgt_port_wwn.raw_wwn, bytes,
	    FC_WWN_SIZE) == 0);
	ASSERT(plun->lun_num == lun_num);

	scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);

	ptgt = plun->lun_tgt;

	mutex_enter(&ptgt->tgt_mutex);
	plun->lun_tgt_count++;
	scsi_device_hba_private_set(sd, plun);
	plun->lun_state |= FCP_SCSI_LUN_TGT_INIT;
	plun->lun_sd = sd;
	mutex_exit(&ptgt->tgt_mutex);
	mutex_exit(&pptr->port_mutex);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
fcp_virt_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	uchar_t			*bytes;
	uint_t			nbytes;
	uint16_t		lun_num;
	struct fcp_tgt	*ptgt;
	struct fcp_lun	*plun;
	struct fcp_port	*pptr = (struct fcp_port *)
	    hba_tran->tran_hba_private;
	child_info_t		*cip;

	ASSERT(pptr != NULL);

	FCP_DTRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_8, 0,
	    "fcp_virt_tgt_init: called for %s (instance %d) (hba_dip %p),"
	    " (tgt_dip %p)", ddi_get_name(tgt_dip),
	    ddi_get_instance(tgt_dip), hba_dip, tgt_dip);

	cip = (child_info_t *)sd->sd_pathinfo;
	if (cip == NULL) {
		FCP_DTRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "fcp_virt_tgt_init: Returning DDI_NOT_WELL_FORMED"
		    " for %s (instance %d)", ddi_get_name(tgt_dip),
		    ddi_get_instance(tgt_dip));

		return (DDI_NOT_WELL_FORMED);
	}

	/* get our port WWN property */
	bytes = NULL;
	if ((scsi_device_prop_lookup_byte_array(sd, SCSI_DEVICE_PROP_PATH,
	    PORT_WWN_PROP, &bytes, &nbytes) != DDI_PROP_SUCCESS) ||
	    (nbytes != FC_WWN_SIZE)) {
		if (bytes) {
			scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);
		}
		return (DDI_NOT_WELL_FORMED);
	}

	ASSERT(bytes != NULL);

	lun_num = scsi_device_prop_get_int(sd, SCSI_DEVICE_PROP_PATH,
	    LUN_PROP, 0xFFFF);
	if (lun_num == 0xFFFF) {
		FCP_DTRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "fcp_virt_tgt_init: Returning DDI_FAILURE:lun"
		    " for %s (instance %d)", ddi_get_name(tgt_dip),
		    ddi_get_instance(tgt_dip));

		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);
		return (DDI_NOT_WELL_FORMED);
	}

	mutex_enter(&pptr->port_mutex);
	if ((plun = fcp_lookup_lun(pptr, bytes, lun_num)) == NULL) {
		mutex_exit(&pptr->port_mutex);
		FCP_DTRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "fcp_virt_tgt_init: Returning DDI_FAILURE: No Lun"
		    " for %s (instance %d)", ddi_get_name(tgt_dip),
		    ddi_get_instance(tgt_dip));

		scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);
		return (DDI_FAILURE);
	}

	ASSERT(bcmp(plun->lun_tgt->tgt_port_wwn.raw_wwn, bytes,
	    FC_WWN_SIZE) == 0);
	ASSERT(plun->lun_num == lun_num);

	scsi_device_prop_free(sd, SCSI_DEVICE_PROP_PATH, bytes);

	ptgt = plun->lun_tgt;

	mutex_enter(&ptgt->tgt_mutex);
	plun->lun_tgt_count++;
	scsi_device_hba_private_set(sd, plun);
	plun->lun_state |= FCP_SCSI_LUN_TGT_INIT;
	plun->lun_sd = sd;
	mutex_exit(&ptgt->tgt_mutex);
	mutex_exit(&pptr->port_mutex);

	return (DDI_SUCCESS);
}


/*
 * called by the transport to do our own target initialization
 *
 * can acquire and release the global mutex
 */
/* ARGSUSED */
static int
fcp_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	struct fcp_port	*pptr = (struct fcp_port *)
	    hba_tran->tran_hba_private;
	int			rval;

	ASSERT(pptr != NULL);

	/*
	 * Child node is getting initialized.  Look at the mpxio component
	 * type on the child device to see if this device is mpxio managed
	 * or not.
	 */
	if (mdi_component_is_client(tgt_dip, NULL) == MDI_SUCCESS) {
		rval = fcp_virt_tgt_init(hba_dip, tgt_dip, hba_tran, sd);
	} else {
		rval = fcp_phys_tgt_init(hba_dip, tgt_dip, hba_tran, sd);
	}

	return (rval);
}


/* ARGSUSED */
static void
fcp_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	struct fcp_lun	*plun = scsi_device_hba_private_get(sd);
	struct fcp_tgt	*ptgt;

	FCP_DTRACE(fcp_logq, LUN_PORT->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_8, 0,
	    "fcp_scsi_tgt_free: called for tran %s%d, dev %s%d",
	    ddi_get_name(hba_dip), ddi_get_instance(hba_dip),
	    ddi_get_name(tgt_dip), ddi_get_instance(tgt_dip));

	if (plun == NULL) {
		return;
	}
	ptgt = plun->lun_tgt;

	ASSERT(ptgt != NULL);

	mutex_enter(&ptgt->tgt_mutex);
	ASSERT(plun->lun_tgt_count > 0);

	if (--plun->lun_tgt_count == 0) {
		plun->lun_state &= ~FCP_SCSI_LUN_TGT_INIT;
	}
	plun->lun_sd = NULL;
	mutex_exit(&ptgt->tgt_mutex);
}

/*
 *     Function: fcp_scsi_start
 *
 *  Description: This function is called by the target driver to request a
 *		 command to be sent.
 *
 *     Argument: *ap		SCSI address of the device.
 *		 *pkt		SCSI packet containing the cmd to send.
 *
 * Return Value: TRAN_ACCEPT
 *		 TRAN_BUSY
 *		 TRAN_BADPKT
 *		 TRAN_FATAL_ERROR
 */
static int
fcp_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct fcp_port	*pptr = ADDR2FCP(ap);
	struct fcp_lun	*plun = ADDR2LUN(ap);
	struct fcp_pkt	*cmd = PKT2CMD(pkt);
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	int			rval;

	/* ensure command isn't already issued */
	ASSERT(cmd->cmd_state != FCP_PKT_ISSUED);

	FCP_DTRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_9, 0,
	    "fcp_transport Invoked for %x", plun->lun_tgt->tgt_d_id);

	/*
	 * It is strange that we enter the fcp_port mutex and the target
	 * mutex to check the lun state (which has a mutex of its own).
	 */
	mutex_enter(&pptr->port_mutex);
	mutex_enter(&ptgt->tgt_mutex);

	/*
	 * If the device is offline and is not in the process of coming
	 * online, fail the request.
	 */

	if ((plun->lun_state & FCP_LUN_OFFLINE) &&
	    !(plun->lun_state & FCP_LUN_ONLINING)) {
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);

		if (cmd->cmd_fp_pkt->pkt_pd == NULL) {
			pkt->pkt_reason = CMD_DEV_GONE;
		}

		return (TRAN_FATAL_ERROR);
	}
	cmd->cmd_fp_pkt->pkt_timeout = pkt->pkt_time;

	/*
	 * If we are suspended, kernel is trying to dump, so don't
	 * block, fail or defer requests - send them down right away.
	 * NOTE: If we are in panic (i.e. trying to dump), we can't
	 * assume we have been suspended.  There is hardware such as
	 * the v880 that doesn't do PM.	 Thus, the check for
	 * ddi_in_panic.
	 *
	 * If FCP_STATE_IN_CB_DEVC is set, devices are in the process
	 * of changing.	 So, if we can queue the packet, do it.	 Eventually,
	 * either the device will have gone away or changed and we can fail
	 * the request, or we can proceed if the device didn't change.
	 *
	 * If the pd in the target or the packet is NULL it's probably
	 * because the device has gone away, we allow the request to be
	 * put on the internal queue here in case the device comes back within
	 * the offline timeout. fctl will fix up the pd's if the tgt_pd_handle
	 * has gone NULL, while fcp deals cases where pkt_pd is NULL. pkt_pd
	 * could be NULL because the device was disappearing during or since
	 * packet initialization.
	 */

	if (((plun->lun_state & FCP_LUN_BUSY) && (!(pptr->port_state &
	    FCP_STATE_SUSPENDED)) && !ddi_in_panic()) ||
	    (pptr->port_state & (FCP_STATE_ONLINING | FCP_STATE_IN_CB_DEVC)) ||
	    (ptgt->tgt_pd_handle == NULL) ||
	    (cmd->cmd_fp_pkt->pkt_pd == NULL)) {
		/*
		 * If ((LUN is busy AND
		 *	LUN not suspended AND
		 *	The system is not in panic state) OR
		 *	(The port is coming up))
		 *
		 * We check to see if the any of the flags FLAG_NOINTR or
		 * FLAG_NOQUEUE is set.	 If one of them is set the value
		 * returned will be TRAN_BUSY.	If not, the request is queued.
		 */
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);

		/* see if using interrupts is allowed (so queueing'll work) */
		if (pkt->pkt_flags & FLAG_NOINTR) {
			pkt->pkt_resid = 0;
			return (TRAN_BUSY);
		}
		if (pkt->pkt_flags & FLAG_NOQUEUE) {
			FCP_DTRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_9, 0,
			    "fcp_scsi_start: lun busy for pkt %p", pkt);
			return (TRAN_BUSY);
		}
#ifdef	DEBUG
		mutex_enter(&pptr->port_pkt_mutex);
		pptr->port_npkts++;
		mutex_exit(&pptr->port_pkt_mutex);
#endif /* DEBUG */

		/* got queue up the pkt for later */
		fcp_queue_pkt(pptr, cmd);
		return (TRAN_ACCEPT);
	}
	cmd->cmd_state = FCP_PKT_ISSUED;

	mutex_exit(&ptgt->tgt_mutex);
	mutex_exit(&pptr->port_mutex);

	/*
	 * Now that we released the mutexes, what was protected by them can
	 * change.
	 */

	/*
	 * If there is a reconfiguration in progress, wait for it to complete.
	 */
	fcp_reconfig_wait(pptr);

	cmd->cmd_timeout = pkt->pkt_time ? fcp_watchdog_time +
	    pkt->pkt_time : 0;

	/* prepare the packet */

	fcp_prepare_pkt(pptr, cmd, plun);

	if (cmd->cmd_pkt->pkt_time) {
		cmd->cmd_fp_pkt->pkt_timeout = cmd->cmd_pkt->pkt_time;
	} else {
		cmd->cmd_fp_pkt->pkt_timeout = 5 * 60 * 60;
	}

	/*
	 * if interrupts aren't allowed (e.g. at dump time) then we'll
	 * have to do polled I/O
	 */
	if (pkt->pkt_flags & FLAG_NOINTR) {
		cmd->cmd_state &= ~FCP_PKT_ISSUED;
		return (fcp_dopoll(pptr, cmd));
	}

#ifdef	DEBUG
	mutex_enter(&pptr->port_pkt_mutex);
	pptr->port_npkts++;
	mutex_exit(&pptr->port_pkt_mutex);
#endif /* DEBUG */

	rval = fcp_transport(pptr->port_fp_handle, cmd->cmd_fp_pkt, 0);
	if (rval == FC_SUCCESS) {
		FCP_DTRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_9, 0,
		    "fcp_transport success for %x", plun->lun_tgt->tgt_d_id);
		return (TRAN_ACCEPT);
	}

	cmd->cmd_state = FCP_PKT_IDLE;

#ifdef	DEBUG
	mutex_enter(&pptr->port_pkt_mutex);
	pptr->port_npkts--;
	mutex_exit(&pptr->port_pkt_mutex);
#endif /* DEBUG */

	/*
	 * For lack of clearer definitions, choose
	 * between TRAN_BUSY and TRAN_FATAL_ERROR.
	 */

	if (rval == FC_TRAN_BUSY) {
		pkt->pkt_resid = 0;
		rval = TRAN_BUSY;
	} else {
		mutex_enter(&ptgt->tgt_mutex);
		if (plun->lun_state & FCP_LUN_OFFLINE) {
			child_info_t	*cip;

			mutex_enter(&plun->lun_mutex);
			cip = plun->lun_cip;
			mutex_exit(&plun->lun_mutex);

			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_6, 0,
			    "fcp_transport failed 2 for %x: %x; dip=%p",
			    plun->lun_tgt->tgt_d_id, rval, cip);

			rval = TRAN_FATAL_ERROR;
		} else {
			if (pkt->pkt_flags & FLAG_NOQUEUE) {
				FCP_DTRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_9, 0,
				    "fcp_scsi_start: FC_BUSY for pkt %p",
				    pkt);
				rval = TRAN_BUSY;
			} else {
				rval = TRAN_ACCEPT;
				fcp_queue_pkt(pptr, cmd);
			}
		}
		mutex_exit(&ptgt->tgt_mutex);
	}

	return (rval);
}

/*
 * called by the transport to abort a packet
 */
/*ARGSUSED*/
static int
fcp_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	int tgt_cnt;
	struct fcp_port		*pptr = ADDR2FCP(ap);
	struct fcp_lun	*plun = ADDR2LUN(ap);
	struct fcp_tgt	*ptgt = plun->lun_tgt;

	if (pkt == NULL) {
		if (ptgt) {
			mutex_enter(&ptgt->tgt_mutex);
			tgt_cnt = ptgt->tgt_change_cnt;
			mutex_exit(&ptgt->tgt_mutex);
			fcp_abort_all(pptr, ptgt, plun, tgt_cnt);
			return (TRUE);
		}
	}
	return (FALSE);
}


/*
 * Perform reset
 */
int
fcp_scsi_reset(struct scsi_address *ap, int level)
{
	int			rval = 0;
	struct fcp_port		*pptr = ADDR2FCP(ap);
	struct fcp_lun	*plun = ADDR2LUN(ap);
	struct fcp_tgt	*ptgt = plun->lun_tgt;

	if (level == RESET_ALL) {
		if (fcp_linkreset(pptr, ap, KM_NOSLEEP) == FC_SUCCESS) {
			rval = 1;
		}
	} else if (level == RESET_TARGET || level == RESET_LUN) {
		/*
		 * If we are in the middle of discovery, return
		 * SUCCESS as this target will be rediscovered
		 * anyway
		 */
		mutex_enter(&ptgt->tgt_mutex);
		if (ptgt->tgt_state & (FCP_TGT_OFFLINE | FCP_TGT_BUSY)) {
			mutex_exit(&ptgt->tgt_mutex);
			return (1);
		}
		mutex_exit(&ptgt->tgt_mutex);

		if (fcp_reset_target(ap, level) == FC_SUCCESS) {
			rval = 1;
		}
	}
	return (rval);
}


/*
 * called by the framework to get a SCSI capability
 */
static int
fcp_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	return (fcp_commoncap(ap, cap, 0, whom, 0));
}


/*
 * called by the framework to set a SCSI capability
 */
static int
fcp_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	return (fcp_commoncap(ap, cap, value, whom, 1));
}

/*
 *     Function: fcp_pkt_setup
 *
 *  Description: This function sets up the scsi_pkt structure passed by the
 *		 caller. This function assumes fcp_pkt_constructor has been
 *		 called previously for the packet passed by the caller.	 If
 *		 successful this call will have the following results:
 *
 *		   - The resources needed that will be constant through out
 *		     the whole transaction are allocated.
 *		   - The fields that will be constant through out the whole
 *		     transaction are initialized.
 *		   - The scsi packet will be linked to the LUN structure
 *		     addressed by the transaction.
 *
 *     Argument:
 *		 *pkt		Pointer to a scsi_pkt structure.
 *		 callback
 *		 arg
 *
 * Return Value: 0	Success
 *		 !0	Failure
 *
 *	Context: Kernel context or interrupt context
 */
/* ARGSUSED */
static int
fcp_pkt_setup(struct scsi_pkt *pkt,
    int (*callback)(caddr_t arg),
    caddr_t arg)
{
	struct fcp_pkt	*cmd;
	struct fcp_port	*pptr;
	struct fcp_lun	*plun;
	struct fcp_tgt	*ptgt;
	int		kf;
	fc_packet_t	*fpkt;
	fc_frame_hdr_t	*hp;

	pptr = ADDR2FCP(&pkt->pkt_address);
	plun = ADDR2LUN(&pkt->pkt_address);
	ptgt = plun->lun_tgt;

	cmd = (struct fcp_pkt *)pkt->pkt_ha_private;
	fpkt = cmd->cmd_fp_pkt;

	/*
	 * this request is for dma allocation only
	 */
	/*
	 * First step of fcp_scsi_init_pkt: pkt allocation
	 * We determine if the caller is willing to wait for the
	 * resources.
	 */
	kf = (callback == SLEEP_FUNC) ? KM_SLEEP: KM_NOSLEEP;

	/*
	 * Selective zeroing of the pkt.
	 */
	cmd->cmd_back = NULL;
	cmd->cmd_next = NULL;

	/*
	 * Zero out fcp command
	 */
	bzero(&cmd->cmd_fcp_cmd, sizeof (cmd->cmd_fcp_cmd));

	cmd->cmd_state = FCP_PKT_IDLE;

	fpkt = cmd->cmd_fp_pkt;
	fpkt->pkt_data_acc = NULL;

	/*
	 * When port_state is FCP_STATE_OFFLINE, remote_port (tgt_pd_handle)
	 * could be destroyed.	We need fail pkt_setup.
	 */
	if (pptr->port_state & FCP_STATE_OFFLINE) {
		return (-1);
	}

	mutex_enter(&ptgt->tgt_mutex);
	fpkt->pkt_pd = ptgt->tgt_pd_handle;

	if (fc_ulp_init_packet(pptr->port_fp_handle, fpkt, kf)
	    != FC_SUCCESS) {
		mutex_exit(&ptgt->tgt_mutex);
		return (-1);
	}

	mutex_exit(&ptgt->tgt_mutex);

	/* Fill in the Fabric Channel Header */
	hp = &fpkt->pkt_cmd_fhdr;
	hp->r_ctl = R_CTL_COMMAND;
	hp->rsvd = 0;
	hp->type = FC_TYPE_SCSI_FCP;
	hp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	hp->seq_id = 0;
	hp->df_ctl  = 0;
	hp->seq_cnt = 0;
	hp->ox_id = 0xffff;
	hp->rx_id = 0xffff;
	hp->ro = 0;

	/*
	 * A doubly linked list (cmd_forw, cmd_back) is built
	 * out of every allocated packet on a per-lun basis
	 *
	 * The packets are maintained in the list so as to satisfy
	 * scsi_abort() requests. At present (which is unlikely to
	 * change in the future) nobody performs a real scsi_abort
	 * in the SCSI target drivers (as they don't keep the packets
	 * after doing scsi_transport - so they don't know how to
	 * abort a packet other than sending a NULL to abort all
	 * outstanding packets)
	 */
	mutex_enter(&plun->lun_mutex);
	if ((cmd->cmd_forw = plun->lun_pkt_head) != NULL) {
		plun->lun_pkt_head->cmd_back = cmd;
	} else {
		plun->lun_pkt_tail = cmd;
	}
	plun->lun_pkt_head = cmd;
	mutex_exit(&plun->lun_mutex);
	return (0);
}

/*
 *     Function: fcp_pkt_teardown
 *
 *  Description: This function releases a scsi_pkt structure and all the
 *		 resources attached to it.
 *
 *     Argument: *pkt		Pointer to a scsi_pkt structure.
 *
 * Return Value: None
 *
 *	Context: User, Kernel or Interrupt context.
 */
static void
fcp_pkt_teardown(struct scsi_pkt *pkt)
{
	struct fcp_port	*pptr = ADDR2FCP(&pkt->pkt_address);
	struct fcp_lun	*plun = ADDR2LUN(&pkt->pkt_address);
	struct fcp_pkt	*cmd = (struct fcp_pkt *)pkt->pkt_ha_private;

	/*
	 * Remove the packet from the per-lun list
	 */
	mutex_enter(&plun->lun_mutex);
	if (cmd->cmd_back) {
		ASSERT(cmd != plun->lun_pkt_head);
		cmd->cmd_back->cmd_forw = cmd->cmd_forw;
	} else {
		ASSERT(cmd == plun->lun_pkt_head);
		plun->lun_pkt_head = cmd->cmd_forw;
	}

	if (cmd->cmd_forw) {
		cmd->cmd_forw->cmd_back = cmd->cmd_back;
	} else {
		ASSERT(cmd == plun->lun_pkt_tail);
		plun->lun_pkt_tail = cmd->cmd_back;
	}

	mutex_exit(&plun->lun_mutex);

	(void) fc_ulp_uninit_packet(pptr->port_fp_handle, cmd->cmd_fp_pkt);
}

/*
 * Routine for reset notification setup, to register or cancel.
 * This function is called by SCSA
 */
/*ARGSUSED*/
static int
fcp_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	struct fcp_port *pptr = ADDR2FCP(ap);

	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    &pptr->port_mutex, &pptr->port_reset_notify_listf));
}


static int
fcp_scsi_bus_get_eventcookie(dev_info_t *dip, dev_info_t *rdip, char *name,
    ddi_eventcookie_t *event_cookiep)
{
	struct fcp_port *pptr = fcp_dip2port(dip);

	if (pptr == NULL) {
		return (DDI_FAILURE);
	}

	return (ndi_event_retrieve_cookie(pptr->port_ndi_event_hdl, rdip, name,
	    event_cookiep, NDI_EVENT_NOPASS));
}


static int
fcp_scsi_bus_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void (*callback)(), void *arg,
    ddi_callback_id_t *cb_id)
{
	struct fcp_port *pptr = fcp_dip2port(dip);

	if (pptr == NULL) {
		return (DDI_FAILURE);
	}

	return (ndi_event_add_callback(pptr->port_ndi_event_hdl, rdip,
	    eventid, callback, arg, NDI_SLEEP, cb_id));
}


static int
fcp_scsi_bus_remove_eventcall(dev_info_t *dip, ddi_callback_id_t cb_id)
{

	struct fcp_port *pptr = fcp_dip2port(dip);

	if (pptr == NULL) {
		return (DDI_FAILURE);
	}
	return (ndi_event_remove_callback(pptr->port_ndi_event_hdl, cb_id));
}


/*
 * called by the transport to post an event
 */
static int
fcp_scsi_bus_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void *impldata)
{
	struct fcp_port *pptr = fcp_dip2port(dip);

	if (pptr == NULL) {
		return (DDI_FAILURE);
	}

	return (ndi_event_run_callbacks(pptr->port_ndi_event_hdl, rdip,
	    eventid, impldata));
}


/*
 * A target in in many cases in Fibre Channel has a one to one relation
 * with a port identifier (which is also known as D_ID and also as AL_PA
 * in private Loop) On Fibre Channel-to-SCSI bridge boxes a target reset
 * will most likely result in resetting all LUNs (which means a reset will
 * occur on all the SCSI devices connected at the other end of the bridge)
 * That is the latest favorite topic for discussion, for, one can debate as
 * hot as one likes and come up with arguably a best solution to one's
 * satisfaction
 *
 * To stay on track and not digress much, here are the problems stated
 * briefly:
 *
 *	SCSA doesn't define RESET_LUN, It defines RESET_TARGET, but the
 *	target drivers use RESET_TARGET even if their instance is on a
 *	LUN. Doesn't that sound a bit broken ?
 *
 *	FCP SCSI (the current spec) only defines RESET TARGET in the
 *	control fields of an FCP_CMND structure. It should have been
 *	fixed right there, giving flexibility to the initiators to
 *	minimize havoc that could be caused by resetting a target.
 */
static int
fcp_reset_target(struct scsi_address *ap, int level)
{
	int			rval = FC_FAILURE;
	char			lun_id[25];
	struct fcp_port		*pptr = ADDR2FCP(ap);
	struct fcp_lun	*plun = ADDR2LUN(ap);
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	struct scsi_pkt		*pkt;
	struct fcp_pkt	*cmd;
	struct fcp_rsp		*rsp;
	uint32_t		tgt_cnt;
	struct fcp_rsp_info	*rsp_info;
	struct fcp_reset_elem	*p;
	int			bval;

	if ((p = kmem_alloc(sizeof (struct fcp_reset_elem),
	    KM_NOSLEEP)) == NULL) {
		return (rval);
	}

	mutex_enter(&ptgt->tgt_mutex);
	if (level == RESET_TARGET) {
		if (ptgt->tgt_state & (FCP_TGT_OFFLINE | FCP_TGT_BUSY)) {
			mutex_exit(&ptgt->tgt_mutex);
			kmem_free(p, sizeof (struct fcp_reset_elem));
			return (rval);
		}
		fcp_update_tgt_state(ptgt, FCP_SET, FCP_LUN_BUSY);
		(void) strcpy(lun_id, " ");
	} else {
		if (plun->lun_state & (FCP_LUN_OFFLINE | FCP_LUN_BUSY)) {
			mutex_exit(&ptgt->tgt_mutex);
			kmem_free(p, sizeof (struct fcp_reset_elem));
			return (rval);
		}
		fcp_update_lun_state(plun, FCP_SET, FCP_LUN_BUSY);

		(void) sprintf(lun_id, ", LUN=%d", plun->lun_num);
	}
	tgt_cnt = ptgt->tgt_change_cnt;

	mutex_exit(&ptgt->tgt_mutex);

	if ((pkt = scsi_init_pkt(ap, NULL, NULL, 0, 0,
	    0, 0, NULL, 0)) == NULL) {
		kmem_free(p, sizeof (struct fcp_reset_elem));
		mutex_enter(&ptgt->tgt_mutex);
		fcp_update_tgt_state(ptgt, FCP_RESET, FCP_LUN_BUSY);
		mutex_exit(&ptgt->tgt_mutex);
		return (rval);
	}
	pkt->pkt_time = FCP_POLL_TIMEOUT;

	/* fill in cmd part of packet */
	cmd = PKT2CMD(pkt);
	if (level == RESET_TARGET) {
		cmd->cmd_fcp_cmd.fcp_cntl.cntl_reset_tgt = 1;
	} else {
		cmd->cmd_fcp_cmd.fcp_cntl.cntl_reset_lun = 1;
	}
	cmd->cmd_fp_pkt->pkt_comp = NULL;
	cmd->cmd_pkt->pkt_flags |= FLAG_NOINTR;

	/* prepare a packet for transport */
	fcp_prepare_pkt(pptr, cmd, plun);

	if (cmd->cmd_pkt->pkt_time) {
		cmd->cmd_fp_pkt->pkt_timeout = cmd->cmd_pkt->pkt_time;
	} else {
		cmd->cmd_fp_pkt->pkt_timeout = 5 * 60 * 60;
	}

	(void) fc_ulp_busy_port(pptr->port_fp_handle);
	bval = fcp_dopoll(pptr, cmd);
	fc_ulp_idle_port(pptr->port_fp_handle);

	/* submit the packet */
	if (bval == TRAN_ACCEPT) {
		int error = 3;

		rsp = (struct fcp_rsp *)cmd->cmd_fcp_rsp;
		rsp_info = (struct fcp_rsp_info *)(cmd->cmd_fcp_rsp +
		    sizeof (struct fcp_rsp));

		if (rsp->fcp_u.fcp_status.rsp_len_set) {
			if (fcp_validate_fcp_response(rsp, pptr) ==
			    FC_SUCCESS) {
				if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
					FCP_CP_IN(cmd->cmd_fp_pkt->pkt_resp +
					    sizeof (struct fcp_rsp), rsp_info,
					    cmd->cmd_fp_pkt->pkt_resp_acc,
					    sizeof (struct fcp_rsp_info));
				}
				if (rsp_info->rsp_code == FCP_NO_FAILURE) {
					rval = FC_SUCCESS;
					error = 0;
				} else {
					error = 1;
				}
			} else {
				error = 2;
			}
		}

		switch (error) {
		case 0:
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FCP: WWN 0x%08x%08x %s reset successfully",
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[0]),
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[4]), lun_id);
			break;

		case 1:
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FCP: Reset to WWN	 0x%08x%08x %s failed,"
			    " response code=%x",
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[0]),
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[4]), lun_id,
			    rsp_info->rsp_code);
			break;

		case 2:
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FCP: Reset to WWN 0x%08x%08x %s failed,"
			    " Bad FCP response values: rsvd1=%x,"
			    " rsvd2=%x, sts-rsvd1=%x, sts-rsvd2=%x,"
			    " rsplen=%x, senselen=%x",
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[0]),
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[4]), lun_id,
			    rsp->reserved_0, rsp->reserved_1,
			    rsp->fcp_u.fcp_status.reserved_0,
			    rsp->fcp_u.fcp_status.reserved_1,
			    rsp->fcp_response_len, rsp->fcp_sense_len);
			break;

		default:
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FCP: Reset to WWN	 0x%08x%08x %s failed",
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[0]),
			    *((int *)&ptgt->tgt_port_wwn.raw_wwn[4]), lun_id);
			break;
		}
	}
	scsi_destroy_pkt(pkt);

	if (rval == FC_FAILURE) {
		mutex_enter(&ptgt->tgt_mutex);
		if (level == RESET_TARGET) {
			fcp_update_tgt_state(ptgt, FCP_RESET, FCP_LUN_BUSY);
		} else {
			fcp_update_lun_state(plun, FCP_RESET, FCP_LUN_BUSY);
		}
		mutex_exit(&ptgt->tgt_mutex);
		kmem_free(p, sizeof (struct fcp_reset_elem));
		return (rval);
	}

	mutex_enter(&pptr->port_mutex);
	if (level == RESET_TARGET) {
		p->tgt = ptgt;
		p->lun = NULL;
	} else {
		p->tgt = NULL;
		p->lun = plun;
	}
	p->tgt = ptgt;
	p->tgt_cnt = tgt_cnt;
	p->timeout = fcp_watchdog_time + FCP_RESET_DELAY;
	p->next = pptr->port_reset_list;
	pptr->port_reset_list = p;

	FCP_TRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_3, 0,
	    "Notify ssd of the reset to reinstate the reservations");

	scsi_hba_reset_notify_callback(&pptr->port_mutex,
	    &pptr->port_reset_notify_listf);

	mutex_exit(&pptr->port_mutex);

	return (rval);
}


/*
 * called by fcp_getcap and fcp_setcap to get and set (respectively)
 * SCSI capabilities
 */
/* ARGSUSED */
static int
fcp_commoncap(struct scsi_address *ap, char *cap,
    int val, int tgtonly, int doset)
{
	struct fcp_port		*pptr = ADDR2FCP(ap);
	struct fcp_lun	*plun = ADDR2LUN(ap);
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	int			cidx;
	int			rval = FALSE;

	if (cap == (char *)0) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "fcp_commoncap: invalid arg");
		return (rval);
	}

	if ((cidx = scsi_hba_lookup_capstr(cap)) == -1) {
		return (UNDEFINED);
	}

	/*
	 * Process setcap request.
	 */
	if (doset) {
		/*
		 * At present, we can only set binary (0/1) values
		 */
		switch (cidx) {
		case SCSI_CAP_ARQ:
			if (val == 0) {
				rval = FALSE;
			} else {
				rval = TRUE;
			}
			break;

		case SCSI_CAP_LUN_RESET:
			if (val) {
				plun->lun_cap |= FCP_LUN_CAP_RESET;
			} else {
				plun->lun_cap &= ~FCP_LUN_CAP_RESET;
			}
			rval = TRUE;
			break;

		case SCSI_CAP_SECTOR_SIZE:
			rval = TRUE;
			break;
		default:
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_4, 0,
			    "fcp_setcap: unsupported %d", cidx);
			rval = UNDEFINED;
			break;
		}

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_5, 0,
		    "set cap: cap=%s, val/tgtonly/doset/rval = "
		    "0x%x/0x%x/0x%x/%d",
		    cap, val, tgtonly, doset, rval);

	} else {
		/*
		 * Process getcap request.
		 */
		switch (cidx) {
		case SCSI_CAP_DMA_MAX:
			rval = (int)pptr->port_data_dma_attr.dma_attr_maxxfer;

			/*
			 * Need to make an adjustment qlc is uint_t 64
			 * st is int, so we will make the adjustment here
			 * being as nobody wants to touch this.
			 * It still leaves the max single block length
			 * of 2 gig. This should last .
			 */

			if (rval == -1) {
				rval = MAX_INT_DMA;
			}

			break;

		case SCSI_CAP_INITIATOR_ID:
			rval = pptr->port_id;
			break;

		case SCSI_CAP_ARQ:
		case SCSI_CAP_RESET_NOTIFICATION:
		case SCSI_CAP_TAGGED_QING:
			rval = TRUE;
			break;

		case SCSI_CAP_SCSI_VERSION:
			rval = 3;
			break;

		case SCSI_CAP_INTERCONNECT_TYPE:
			if (FC_TOP_EXTERNAL(pptr->port_topology) ||
			    (ptgt->tgt_hard_addr == 0)) {
				rval = INTERCONNECT_FABRIC;
			} else {
				rval = INTERCONNECT_FIBRE;
			}
			break;

		case SCSI_CAP_LUN_RESET:
			rval = ((plun->lun_cap & FCP_LUN_CAP_RESET) != 0) ?
			    TRUE : FALSE;
			break;

		default:
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_4, 0,
			    "fcp_getcap: unsupported %d", cidx);
			rval = UNDEFINED;
			break;
		}

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_8, 0,
		    "get cap: cap=%s, val/tgtonly/doset/rval = "
		    "0x%x/0x%x/0x%x/%d",
		    cap, val, tgtonly, doset, rval);
	}

	return (rval);
}

/*
 * called by the transport to get the port-wwn and lun
 * properties of this device, and to create a "name" based on them
 *
 * these properties don't exist on sun4m
 *
 * return 1 for success else return 0
 */
/* ARGSUSED */
static int
fcp_scsi_get_name(struct scsi_device *sd, char *name, int len)
{
	int			i;
	int			*lun;
	int			numChars;
	uint_t			nlun;
	uint_t			count;
	uint_t			nbytes;
	uchar_t			*bytes;
	uint16_t		lun_num;
	uint32_t		tgt_id;
	char			**conf_wwn;
	char			tbuf[(FC_WWN_SIZE << 1) + 1];
	uchar_t			barray[FC_WWN_SIZE];
	dev_info_t		*tgt_dip;
	struct fcp_tgt	*ptgt;
	struct fcp_port	*pptr;
	struct fcp_lun	*plun;

	ASSERT(sd != NULL);
	ASSERT(name != NULL);

	tgt_dip = sd->sd_dev;
	pptr = ddi_get_soft_state(fcp_softstate,
	    ddi_get_instance(ddi_get_parent(tgt_dip)));
	if (pptr == NULL) {
		return (0);
	}

	ASSERT(tgt_dip != NULL);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sd->sd_dev,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    LUN_PROP, &lun, &nlun) != DDI_SUCCESS) {
		name[0] = '\0';
		return (0);
	}

	if (nlun == 0) {
		ddi_prop_free(lun);
		return (0);
	}

	lun_num = lun[0];
	ddi_prop_free(lun);

	/*
	 * Lookup for .conf WWN property
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, tgt_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, CONF_WWN_PROP,
	    &conf_wwn, &count) == DDI_PROP_SUCCESS) {
		ASSERT(count >= 1);

		fcp_ascii_to_wwn(conf_wwn[0], barray, FC_WWN_SIZE);
		ddi_prop_free(conf_wwn);
		mutex_enter(&pptr->port_mutex);
		if ((plun = fcp_lookup_lun(pptr, barray, lun_num)) == NULL) {
			mutex_exit(&pptr->port_mutex);
			return (0);
		}
		ptgt = plun->lun_tgt;
		mutex_exit(&pptr->port_mutex);

		(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    tgt_dip, PORT_WWN_PROP, barray, FC_WWN_SIZE);

		if (!FC_TOP_EXTERNAL(pptr->port_topology) &&
		    ptgt->tgt_hard_addr != 0) {
			tgt_id = (uint32_t)fcp_alpa_to_switch[
			    ptgt->tgt_hard_addr];
		} else {
			tgt_id = ptgt->tgt_d_id;
		}

		(void) ndi_prop_update_int(DDI_DEV_T_NONE, tgt_dip,
		    TARGET_PROP, tgt_id);
	}

	/* get the our port-wwn property */
	bytes = NULL;
	if ((ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, tgt_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, PORT_WWN_PROP, &bytes,
	    &nbytes) != DDI_PROP_SUCCESS) || nbytes != FC_WWN_SIZE) {
		if (bytes != NULL) {
			ddi_prop_free(bytes);
		}
		return (0);
	}

	for (i = 0; i < FC_WWN_SIZE; i++) {
		(void) sprintf(&tbuf[i << 1], "%02x", *(bytes + i));
	}

	/* Stick in the address of the form "wWWN,LUN" */
	numChars = snprintf(name, len, "w%s,%x", tbuf, lun_num);

	ASSERT(numChars < len);
	if (numChars >= len) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp_scsi_get_name: "
		    "name parameter length too small, it needs to be %d",
		    numChars+1);
	}

	ddi_prop_free(bytes);

	return (1);
}


/*
 * called by the transport to get the SCSI target id value, returning
 * it in "name"
 *
 * this isn't needed/used on sun4m
 *
 * return 1 for success else return 0
 */
/* ARGSUSED */
static int
fcp_scsi_get_bus_addr(struct scsi_device *sd, char *name, int len)
{
	struct fcp_lun	*plun = ADDR2LUN(&sd->sd_address);
	struct fcp_tgt	*ptgt;
	int    numChars;

	if (plun == NULL) {
		return (0);
	}

	if ((ptgt = plun->lun_tgt) == NULL) {
		return (0);
	}

	numChars = snprintf(name, len, "%x", ptgt->tgt_d_id);

	ASSERT(numChars < len);
	if (numChars >= len) {
		fcp_log(CE_WARN, NULL,
		    "!fcp_scsi_get_bus_addr: "
		    "name parameter length too small, it needs to be %d",
		    numChars+1);
	}

	return (1);
}


/*
 * called internally to reset the link where the specified port lives
 */
static int
fcp_linkreset(struct fcp_port *pptr, struct scsi_address *ap, int sleep)
{
	la_wwn_t		wwn;
	struct fcp_lun	*plun;
	struct fcp_tgt	*ptgt;

	/* disable restart of lip if we're suspended */
	mutex_enter(&pptr->port_mutex);

	if (pptr->port_state & (FCP_STATE_SUSPENDED |
	    FCP_STATE_POWER_DOWN)) {
		mutex_exit(&pptr->port_mutex);
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "fcp_linkreset, fcp%d: link reset "
		    "disabled due to DDI_SUSPEND",
		    ddi_get_instance(pptr->port_dip));
		return (FC_FAILURE);
	}

	if (pptr->port_state & (FCP_STATE_OFFLINE | FCP_STATE_ONLINING)) {
		mutex_exit(&pptr->port_mutex);
		return (FC_SUCCESS);
	}

	FCP_DTRACE(fcp_logq, pptr->port_instbuf,
	    fcp_trace, FCP_BUF_LEVEL_8, 0, "Forcing link reset");

	/*
	 * If ap == NULL assume local link reset.
	 */
	if (FC_TOP_EXTERNAL(pptr->port_topology) && (ap != NULL)) {
		plun = ADDR2LUN(ap);
		ptgt = plun->lun_tgt;
		bcopy(&ptgt->tgt_port_wwn.raw_wwn[0], &wwn, sizeof (wwn));
	} else {
		bzero((caddr_t)&wwn, sizeof (wwn));
	}
	mutex_exit(&pptr->port_mutex);

	return (fc_ulp_linkreset(pptr->port_fp_handle, &wwn, sleep));
}


/*
 * called from fcp_port_attach() to resume a port
 * return DDI_* success/failure status
 * acquires and releases the global mutex
 * acquires and releases the port mutex
 */
/*ARGSUSED*/

static int
fcp_handle_port_resume(opaque_t ulph, fc_ulp_port_info_t *pinfo,
    uint32_t s_id, fc_attach_cmd_t cmd, int instance)
{
	int			res = DDI_FAILURE; /* default result */
	struct fcp_port	*pptr;		/* port state ptr */
	uint32_t		alloc_cnt;
	uint32_t		max_cnt;
	fc_portmap_t		*tmp_list = NULL;

	FCP_DTRACE(fcp_logq, "fcp", fcp_trace,
	    FCP_BUF_LEVEL_8, 0, "port resume: for port %d",
	    instance);

	if ((pptr = ddi_get_soft_state(fcp_softstate, instance)) == NULL) {
		cmn_err(CE_WARN, "fcp: bad soft state");
		return (res);
	}

	mutex_enter(&pptr->port_mutex);
	switch (cmd) {
	case FC_CMD_RESUME:
		ASSERT((pptr->port_state & FCP_STATE_POWER_DOWN) == 0);
		pptr->port_state &= ~FCP_STATE_SUSPENDED;
		break;

	case FC_CMD_POWER_UP:
		/*
		 * If the port is DDI_SUSPENded, defer rediscovery
		 * until DDI_RESUME occurs
		 */
		if (pptr->port_state & FCP_STATE_SUSPENDED) {
			pptr->port_state &= ~FCP_STATE_POWER_DOWN;
			mutex_exit(&pptr->port_mutex);
			return (DDI_SUCCESS);
		}
		pptr->port_state &= ~FCP_STATE_POWER_DOWN;
	}
	pptr->port_id = s_id;
	pptr->port_state = FCP_STATE_INIT;
	mutex_exit(&pptr->port_mutex);

	/*
	 * Make a copy of ulp_port_info as fctl allocates
	 * a temp struct.
	 */
	(void) fcp_cp_pinfo(pptr, pinfo);

	mutex_enter(&fcp_global_mutex);
	if (fcp_watchdog_init++ == 0) {
		fcp_watchdog_tick = fcp_watchdog_timeout *
		    drv_usectohz(1000000);
		fcp_watchdog_id = timeout(fcp_watch,
		    NULL, fcp_watchdog_tick);
	}
	mutex_exit(&fcp_global_mutex);

	/*
	 * Handle various topologies and link states.
	 */
	switch (FC_PORT_STATE_MASK(pptr->port_phys_state)) {
	case FC_STATE_OFFLINE:
		/*
		 * Wait for ONLINE, at which time a state
		 * change will cause a statec_callback
		 */
		res = DDI_SUCCESS;
		break;

	case FC_STATE_ONLINE:

		if (pptr->port_topology == FC_TOP_UNKNOWN) {
			(void) fcp_linkreset(pptr, NULL, KM_NOSLEEP);
			res = DDI_SUCCESS;
			break;
		}

		if (FC_TOP_EXTERNAL(pptr->port_topology) &&
		    !fcp_enable_auto_configuration) {
			tmp_list = fcp_construct_map(pptr, &alloc_cnt);
			if (tmp_list == NULL) {
				if (!alloc_cnt) {
					res = DDI_SUCCESS;
				}
				break;
			}
			max_cnt = alloc_cnt;
		} else {
			ASSERT(pptr->port_topology != FC_TOP_UNKNOWN);

			alloc_cnt = FCP_MAX_DEVICES;

			if ((tmp_list = (fc_portmap_t *)kmem_zalloc(
			    (sizeof (fc_portmap_t)) * alloc_cnt,
			    KM_NOSLEEP)) == NULL) {
				fcp_log(CE_WARN, pptr->port_dip,
				    "!fcp%d: failed to allocate portmap",
				    instance);
				break;
			}

			max_cnt = alloc_cnt;
			if ((res = fc_ulp_getportmap(pptr->port_fp_handle,
			    &tmp_list, &max_cnt, FC_ULP_PLOGI_PRESERVE)) !=
			    FC_SUCCESS) {
				caddr_t msg;

				(void) fc_ulp_error(res, &msg);

				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "resume failed getportmap: reason=0x%x",
				    res);

				fcp_log(CE_WARN, pptr->port_dip,
				    "!failed to get port map : %s", msg);
				break;
			}
			if (max_cnt > alloc_cnt) {
				alloc_cnt = max_cnt;
			}
		}

		/*
		 * do the SCSI device discovery and create
		 * the devinfos
		 */
		fcp_statec_callback(ulph, pptr->port_fp_handle,
		    pptr->port_phys_state, pptr->port_topology, tmp_list,
		    max_cnt, pptr->port_id);

		res = DDI_SUCCESS;
		break;

	default:
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp%d: invalid port state at attach=0x%x",
		    instance, pptr->port_phys_state);

		mutex_enter(&pptr->port_mutex);
		pptr->port_phys_state = FCP_STATE_OFFLINE;
		mutex_exit(&pptr->port_mutex);
		res = DDI_SUCCESS;

		break;
	}

	if (tmp_list != NULL) {
		kmem_free(tmp_list, sizeof (fc_portmap_t) * alloc_cnt);
	}

	return (res);
}


static void
fcp_cp_pinfo(struct fcp_port *pptr, fc_ulp_port_info_t *pinfo)
{
	pptr->port_fp_modlinkage = *pinfo->port_linkage;
	pptr->port_dip = pinfo->port_dip;
	pptr->port_fp_handle = pinfo->port_handle;
	if (pinfo->port_acc_attr != NULL) {
		/*
		 * FCA supports DMA
		 */
		pptr->port_data_dma_attr = *pinfo->port_data_dma_attr;
		pptr->port_cmd_dma_attr = *pinfo->port_cmd_dma_attr;
		pptr->port_resp_dma_attr = *pinfo->port_resp_dma_attr;
		pptr->port_dma_acc_attr = *pinfo->port_acc_attr;
	}
	pptr->port_priv_pkt_len = pinfo->port_fca_pkt_size;
	pptr->port_max_exch = pinfo->port_fca_max_exch;
	pptr->port_phys_state = pinfo->port_state;
	pptr->port_topology = pinfo->port_flags;
	pptr->port_reset_action = pinfo->port_reset_action;
	pptr->port_cmds_dma_flags = pinfo->port_dma_behavior;
	pptr->port_fcp_dma = pinfo->port_fcp_dma;
	bcopy(&pinfo->port_nwwn, &pptr->port_nwwn, sizeof (la_wwn_t));
	bcopy(&pinfo->port_pwwn, &pptr->port_pwwn, sizeof (la_wwn_t));

	/* Clear FMA caps to avoid fm-capability ereport */
	if (pptr->port_cmd_dma_attr.dma_attr_flags & DDI_DMA_FLAGERR)
		pptr->port_cmd_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	if (pptr->port_data_dma_attr.dma_attr_flags & DDI_DMA_FLAGERR)
		pptr->port_data_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	if (pptr->port_resp_dma_attr.dma_attr_flags & DDI_DMA_FLAGERR)
		pptr->port_resp_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
}

/*
 * If the elements wait field is set to 1 then
 * another thread is waiting for the operation to complete. Once
 * it is complete, the waiting thread is signaled and the element is
 * freed by the waiting thread. If the elements wait field is set to 0
 * the element is freed.
 */
static void
fcp_process_elem(struct fcp_hp_elem *elem, int result)
{
	ASSERT(elem != NULL);
	mutex_enter(&elem->mutex);
	elem->result = result;
	if (elem->wait) {
		elem->wait = 0;
		cv_signal(&elem->cv);
		mutex_exit(&elem->mutex);
	} else {
		mutex_exit(&elem->mutex);
		cv_destroy(&elem->cv);
		mutex_destroy(&elem->mutex);
		kmem_free(elem, sizeof (struct fcp_hp_elem));
	}
}

/*
 * This function is invoked from the taskq thread to allocate
 * devinfo nodes and to online/offline them.
 */
static void
fcp_hp_task(void *arg)
{
	struct fcp_hp_elem	*elem = (struct fcp_hp_elem *)arg;
	struct fcp_lun	*plun = elem->lun;
	struct fcp_port		*pptr = elem->port;
	int			result;

	ASSERT(elem->what == FCP_ONLINE ||
	    elem->what == FCP_OFFLINE ||
	    elem->what == FCP_MPXIO_PATH_CLEAR_BUSY ||
	    elem->what == FCP_MPXIO_PATH_SET_BUSY);

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&plun->lun_mutex);
	if (((elem->what == FCP_ONLINE || elem->what == FCP_OFFLINE) &&
	    plun->lun_event_count != elem->event_cnt) ||
	    pptr->port_state & (FCP_STATE_SUSPENDED |
	    FCP_STATE_DETACHING | FCP_STATE_POWER_DOWN)) {
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);
		fcp_process_elem(elem, NDI_FAILURE);
		return;
	}
	mutex_exit(&plun->lun_mutex);
	mutex_exit(&pptr->port_mutex);

	result = fcp_trigger_lun(plun, elem->cip, elem->old_lun_mpxio,
	    elem->what, elem->link_cnt, elem->tgt_cnt, elem->flags);
	fcp_process_elem(elem, result);
}


static child_info_t *
fcp_get_cip(struct fcp_lun *plun, child_info_t *cip, int lcount,
    int tcount)
{
	ASSERT(MUTEX_HELD(&plun->lun_mutex));

	if (fcp_is_child_present(plun, cip) == FC_FAILURE) {
		struct fcp_port *pptr = plun->lun_tgt->tgt_port;

		ASSERT(MUTEX_HELD(&pptr->port_mutex));
		/*
		 * Child has not been created yet. Create the child device
		 * based on the per-Lun flags.
		 */
		if (pptr->port_mpxio == 0 || plun->lun_mpxio == 0) {
			plun->lun_cip =
			    CIP(fcp_create_dip(plun, lcount, tcount));
			plun->lun_mpxio = 0;
		} else {
			plun->lun_cip =
			    CIP(fcp_create_pip(plun, lcount, tcount));
			plun->lun_mpxio = 1;
		}
	} else {
		plun->lun_cip = cip;
	}

	return (plun->lun_cip);
}


static int
fcp_is_dip_present(struct fcp_lun *plun, dev_info_t *cdip)
{
	int		rval = FC_FAILURE;
	dev_info_t	*pdip;
	struct dev_info	*dip;
	int		circular;

	ASSERT(MUTEX_HELD(&plun->lun_mutex));

	pdip = plun->lun_tgt->tgt_port->port_dip;

	if (plun->lun_cip == NULL) {
		FCP_TRACE(fcp_logq, LUN_PORT->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "fcp_is_dip_present: plun->lun_cip is NULL: "
		    "plun: %p lun state: %x num: %d target state: %x",
		    plun, plun->lun_state, plun->lun_num,
		    plun->lun_tgt->tgt_port->port_state);
		return (rval);
	}
	ndi_devi_enter(pdip, &circular);
	dip = DEVI(pdip)->devi_child;
	while (dip) {
		if (dip == DEVI(cdip)) {
			rval = FC_SUCCESS;
			break;
		}
		dip = dip->devi_sibling;
	}
	ndi_devi_exit(pdip, circular);
	return (rval);
}

static int
fcp_is_child_present(struct fcp_lun *plun, child_info_t *cip)
{
	int		rval = FC_FAILURE;

	ASSERT(plun != NULL);
	ASSERT(MUTEX_HELD(&plun->lun_mutex));

	if (plun->lun_mpxio == 0) {
		rval = fcp_is_dip_present(plun, DIP(cip));
	} else {
		rval = fcp_is_pip_present(plun, PIP(cip));
	}

	return (rval);
}

/*
 *     Function: fcp_create_dip
 *
 *  Description: Creates a dev_info_t structure for the LUN specified by the
 *		 caller.
 *
 *     Argument: plun		Lun structure
 *		 link_cnt	Link state count.
 *		 tgt_cnt	Target state change count.
 *
 * Return Value: NULL if it failed
 *		 dev_info_t structure address if it succeeded
 *
 *	Context: Kernel context
 */
static dev_info_t *
fcp_create_dip(struct fcp_lun *plun, int link_cnt, int tgt_cnt)
{
	int			failure = 0;
	uint32_t		tgt_id;
	uint64_t		sam_lun;
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	struct fcp_port	*pptr = ptgt->tgt_port;
	dev_info_t		*pdip = pptr->port_dip;
	dev_info_t		*cdip = NULL;
	dev_info_t		*old_dip = DIP(plun->lun_cip);
	char			*nname = NULL;
	char			**compatible = NULL;
	int			ncompatible;
	char			*scsi_binding_set;
	char			t_pwwn[17];

	ASSERT(MUTEX_HELD(&plun->lun_mutex));
	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	/* get the 'scsi-binding-set' property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "scsi-binding-set",
	    &scsi_binding_set) != DDI_PROP_SUCCESS) {
		scsi_binding_set = NULL;
	}

	/* determine the node name and compatible */
	scsi_hba_nodename_compatible_get(&plun->lun_inq, scsi_binding_set,
	    plun->lun_inq.inq_dtype, NULL, &nname, &compatible, &ncompatible);
	if (scsi_binding_set) {
		ddi_prop_free(scsi_binding_set);
	}

	if (nname == NULL) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "%s%d: no driver for "
		    "device @w%02x%02x%02x%02x%02x%02x%02x%02x,%d:"
		    "	 compatible: %s",
		    ddi_driver_name(pdip), ddi_get_instance(pdip),
		    ptgt->tgt_port_wwn.raw_wwn[0],
		    ptgt->tgt_port_wwn.raw_wwn[1],
		    ptgt->tgt_port_wwn.raw_wwn[2],
		    ptgt->tgt_port_wwn.raw_wwn[3],
		    ptgt->tgt_port_wwn.raw_wwn[4],
		    ptgt->tgt_port_wwn.raw_wwn[5],
		    ptgt->tgt_port_wwn.raw_wwn[6],
		    ptgt->tgt_port_wwn.raw_wwn[7], plun->lun_num,
		    *compatible);
#endif	/* DEBUG */
		failure++;
		goto end_of_fcp_create_dip;
	}

	cdip = fcp_find_existing_dip(plun, pdip, nname);

	/*
	 * if the old_dip does not match the cdip, that means there is
	 * some property change. since we'll be using the cdip, we need
	 * to offline the old_dip. If the state contains FCP_LUN_CHANGED
	 * then the dtype for the device has been updated. Offline the
	 * the old device and create a new device with the new device type
	 * Refer to bug: 4764752
	 */
	if (old_dip && (cdip != old_dip ||
	    plun->lun_state & FCP_LUN_CHANGED)) {
		plun->lun_state &= ~(FCP_LUN_INIT);
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);

		mutex_enter(&ptgt->tgt_mutex);
		(void) fcp_pass_to_hp(pptr, plun, CIP(old_dip), FCP_OFFLINE,
		    link_cnt, tgt_cnt, NDI_DEVI_REMOVE, 0);
		mutex_exit(&ptgt->tgt_mutex);

#ifdef DEBUG
		if (cdip != NULL) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "Old dip=%p; New dip=%p don't match", old_dip,
			    cdip);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "Old dip=%p; New dip=NULL don't match", old_dip);
		}
#endif

		mutex_enter(&pptr->port_mutex);
		mutex_enter(&plun->lun_mutex);
	}

	if (cdip == NULL || plun->lun_state & FCP_LUN_CHANGED) {
		plun->lun_state &= ~(FCP_LUN_CHANGED);
		if (ndi_devi_alloc(pptr->port_dip, nname,
		    DEVI_SID_NODEID, &cdip) != NDI_SUCCESS) {
			failure++;
			goto end_of_fcp_create_dip;
		}
	}

	/*
	 * Previously all the properties for the devinfo were destroyed here
	 * with a call to ndi_prop_remove_all(). Since this may cause loss of
	 * the devid property (and other properties established by the target
	 * driver or framework) which the code does not always recreate, this
	 * call was removed.
	 * This opens a theoretical possibility that we may return with a
	 * stale devid on the node if the scsi entity behind the fibre channel
	 * lun has changed.
	 */

	/* decorate the node with compatible */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, cdip,
	    "compatible", compatible, ncompatible) != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}

	if (ndi_prop_update_byte_array(DDI_DEV_T_NONE, cdip, NODE_WWN_PROP,
	    ptgt->tgt_node_wwn.raw_wwn, FC_WWN_SIZE) != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}

	if (ndi_prop_update_byte_array(DDI_DEV_T_NONE, cdip, PORT_WWN_PROP,
	    ptgt->tgt_port_wwn.raw_wwn, FC_WWN_SIZE) != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}

	fcp_wwn_to_ascii(ptgt->tgt_port_wwn.raw_wwn, t_pwwn);
	t_pwwn[16] = '\0';
	if (ndi_prop_update_string(DDI_DEV_T_NONE, cdip, TGT_PORT_PROP, t_pwwn)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}

	/*
	 * If there is no hard address - We might have to deal with
	 * that by using WWN - Having said that it is important to
	 * recognize this problem early so ssd can be informed of
	 * the right interconnect type.
	 */
	if (!FC_TOP_EXTERNAL(pptr->port_topology) && ptgt->tgt_hard_addr != 0) {
		tgt_id = (uint32_t)fcp_alpa_to_switch[ptgt->tgt_hard_addr];
	} else {
		tgt_id = ptgt->tgt_d_id;
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, cdip, TARGET_PROP,
	    tgt_id) != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, cdip, LUN_PROP,
	    (int)plun->lun_num) != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}
	bcopy(&plun->lun_addr, &sam_lun, FCP_LUN_SIZE);
	if (ndi_prop_update_int64(DDI_DEV_T_NONE, cdip, SAM_LUN_PROP,
	    sam_lun) != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_dip;
	}

end_of_fcp_create_dip:
	scsi_hba_nodename_compatible_free(nname, compatible);

	if (cdip != NULL && failure) {
		(void) ndi_prop_remove_all(cdip);
		(void) ndi_devi_free(cdip);
		cdip = NULL;
	}

	return (cdip);
}

/*
 *     Function: fcp_create_pip
 *
 *  Description: Creates a Path Id for the LUN specified by the caller.
 *
 *     Argument: plun		Lun structure
 *		 link_cnt	Link state count.
 *		 tgt_cnt	Target state count.
 *
 * Return Value: NULL if it failed
 *		 mdi_pathinfo_t structure address if it succeeded
 *
 *	Context: Kernel context
 */
static mdi_pathinfo_t *
fcp_create_pip(struct fcp_lun *plun, int lcount, int tcount)
{
	int			i;
	char			buf[MAXNAMELEN];
	char			uaddr[MAXNAMELEN];
	int			failure = 0;
	uint32_t		tgt_id;
	uint64_t		sam_lun;
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	struct fcp_port	*pptr = ptgt->tgt_port;
	dev_info_t		*pdip = pptr->port_dip;
	mdi_pathinfo_t		*pip = NULL;
	mdi_pathinfo_t		*old_pip = PIP(plun->lun_cip);
	char			*nname = NULL;
	char			**compatible = NULL;
	int			ncompatible;
	char			*scsi_binding_set;
	char			t_pwwn[17];

	ASSERT(MUTEX_HELD(&plun->lun_mutex));
	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	scsi_binding_set = "vhci";

	/* determine the node name and compatible */
	scsi_hba_nodename_compatible_get(&plun->lun_inq, scsi_binding_set,
	    plun->lun_inq.inq_dtype, NULL, &nname, &compatible, &ncompatible);

	if (nname == NULL) {
#ifdef	DEBUG
		cmn_err(CE_WARN, "fcp_create_dip: %s%d: no driver for "
		    "device @w%02x%02x%02x%02x%02x%02x%02x%02x,%d:"
		    "	 compatible: %s",
		    ddi_driver_name(pdip), ddi_get_instance(pdip),
		    ptgt->tgt_port_wwn.raw_wwn[0],
		    ptgt->tgt_port_wwn.raw_wwn[1],
		    ptgt->tgt_port_wwn.raw_wwn[2],
		    ptgt->tgt_port_wwn.raw_wwn[3],
		    ptgt->tgt_port_wwn.raw_wwn[4],
		    ptgt->tgt_port_wwn.raw_wwn[5],
		    ptgt->tgt_port_wwn.raw_wwn[6],
		    ptgt->tgt_port_wwn.raw_wwn[7], plun->lun_num,
		    *compatible);
#endif	/* DEBUG */
		failure++;
		goto end_of_fcp_create_pip;
	}

	pip = fcp_find_existing_pip(plun, pdip);

	/*
	 * if the old_dip does not match the cdip, that means there is
	 * some property change. since we'll be using the cdip, we need
	 * to offline the old_dip. If the state contains FCP_LUN_CHANGED
	 * then the dtype for the device has been updated. Offline the
	 * the old device and create a new device with the new device type
	 * Refer to bug: 4764752
	 */
	if (old_pip && (pip != old_pip ||
	    plun->lun_state & FCP_LUN_CHANGED)) {
		plun->lun_state &= ~(FCP_LUN_INIT);
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);

		mutex_enter(&ptgt->tgt_mutex);
		(void) fcp_pass_to_hp(pptr, plun, CIP(old_pip),
		    FCP_OFFLINE, lcount, tcount,
		    NDI_DEVI_REMOVE, 0);
		mutex_exit(&ptgt->tgt_mutex);

		if (pip != NULL) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "Old pip=%p; New pip=%p don't match",
			    old_pip, pip);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "Old pip=%p; New pip=NULL don't match",
			    old_pip);
		}

		mutex_enter(&pptr->port_mutex);
		mutex_enter(&plun->lun_mutex);
	}

	/*
	 * Since FC_WWN_SIZE is 8 bytes and its not like the
	 * lun_guid_size which is dependent on the target, I don't
	 * believe the same trancation happens here UNLESS the standards
	 * change the FC_WWN_SIZE value to something larger than
	 * MAXNAMELEN(currently 255 bytes).
	 */

	for (i = 0; i < FC_WWN_SIZE; i++) {
		(void) sprintf(&buf[i << 1], "%02x",
		    ptgt->tgt_port_wwn.raw_wwn[i]);
	}

	(void) snprintf(uaddr, MAXNAMELEN, "w%s,%x",
	    buf, plun->lun_num);

	if (pip == NULL || plun->lun_state & FCP_LUN_CHANGED) {
		/*
		 * Release the locks before calling into
		 * mdi_pi_alloc_compatible() since this can result in a
		 * callback into fcp which can result in a deadlock
		 * (see bug # 4870272).
		 *
		 * Basically, what we are trying to avoid is the scenario where
		 * one thread does ndi_devi_enter() and tries to grab
		 * fcp_mutex and another does it the other way round.
		 *
		 * But before we do that, make sure that nobody releases the
		 * port in the meantime. We can do this by setting a flag.
		 */
		plun->lun_state &= ~(FCP_LUN_CHANGED);
		pptr->port_state |= FCP_STATE_IN_MDI;
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);
		if (mdi_pi_alloc_compatible(pdip, nname, plun->lun_guid,
		    uaddr, compatible, ncompatible, 0, &pip) != MDI_SUCCESS) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!path alloc failed:0x%x", plun);
			mutex_enter(&pptr->port_mutex);
			mutex_enter(&plun->lun_mutex);
			pptr->port_state &= ~FCP_STATE_IN_MDI;
			failure++;
			goto end_of_fcp_create_pip;
		}
		mutex_enter(&pptr->port_mutex);
		mutex_enter(&plun->lun_mutex);
		pptr->port_state &= ~FCP_STATE_IN_MDI;
	} else {
		(void) mdi_prop_remove(pip, NULL);
	}

	mdi_pi_set_phci_private(pip, (caddr_t)plun);

	if (mdi_prop_update_byte_array(pip, NODE_WWN_PROP,
	    ptgt->tgt_node_wwn.raw_wwn, FC_WWN_SIZE)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_pip;
	}

	if (mdi_prop_update_byte_array(pip, PORT_WWN_PROP,
	    ptgt->tgt_port_wwn.raw_wwn, FC_WWN_SIZE)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_pip;
	}

	fcp_wwn_to_ascii(ptgt->tgt_port_wwn.raw_wwn, t_pwwn);
	t_pwwn[16] = '\0';
	if (mdi_prop_update_string(pip, TGT_PORT_PROP, t_pwwn)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_pip;
	}

	/*
	 * If there is no hard address - We might have to deal with
	 * that by using WWN - Having said that it is important to
	 * recognize this problem early so ssd can be informed of
	 * the right interconnect type.
	 */
	if (!FC_TOP_EXTERNAL(pptr->port_topology) &&
	    ptgt->tgt_hard_addr != 0) {
		tgt_id = (uint32_t)
		    fcp_alpa_to_switch[ptgt->tgt_hard_addr];
	} else {
		tgt_id = ptgt->tgt_d_id;
	}

	if (mdi_prop_update_int(pip, TARGET_PROP, tgt_id)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_pip;
	}

	if (mdi_prop_update_int(pip, LUN_PROP, (int)plun->lun_num)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_pip;
	}
	bcopy(&plun->lun_addr, &sam_lun, FCP_LUN_SIZE);
	if (mdi_prop_update_int64(pip, SAM_LUN_PROP, sam_lun)
	    != DDI_PROP_SUCCESS) {
		failure++;
		goto end_of_fcp_create_pip;
	}

end_of_fcp_create_pip:
	scsi_hba_nodename_compatible_free(nname, compatible);

	if (pip != NULL && failure) {
		(void) mdi_prop_remove(pip, NULL);
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);
		(void) mdi_pi_free(pip, 0);
		mutex_enter(&pptr->port_mutex);
		mutex_enter(&plun->lun_mutex);
		pip = NULL;
	}

	return (pip);
}

static dev_info_t *
fcp_find_existing_dip(struct fcp_lun *plun, dev_info_t *pdip, caddr_t name)
{
	uint_t			nbytes;
	uchar_t			*bytes;
	uint_t			nwords;
	uint32_t		tgt_id;
	int			*words;
	dev_info_t		*cdip;
	dev_info_t		*ndip;
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	struct fcp_port	*pptr = ptgt->tgt_port;
	int			circular;

	ndi_devi_enter(pdip, &circular);

	ndip = (dev_info_t *)DEVI(pdip)->devi_child;
	while ((cdip = ndip) != NULL) {
		ndip = (dev_info_t *)DEVI(cdip)->devi_sibling;

		if (strcmp(DEVI(cdip)->devi_node_name, name)) {
			continue;
		}

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, NODE_WWN_PROP, &bytes,
		    &nbytes) != DDI_PROP_SUCCESS) {
			continue;
		}

		if (nbytes != FC_WWN_SIZE || bytes == NULL) {
			if (bytes != NULL) {
				ddi_prop_free(bytes);
			}
			continue;
		}
		ASSERT(bytes != NULL);

		if (bcmp(bytes, ptgt->tgt_node_wwn.raw_wwn, nbytes) != 0) {
			ddi_prop_free(bytes);
			continue;
		}

		ddi_prop_free(bytes);

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, PORT_WWN_PROP, &bytes,
		    &nbytes) != DDI_PROP_SUCCESS) {
			continue;
		}

		if (nbytes != FC_WWN_SIZE || bytes == NULL) {
			if (bytes != NULL) {
				ddi_prop_free(bytes);
			}
			continue;
		}
		ASSERT(bytes != NULL);

		if (bcmp(bytes, ptgt->tgt_port_wwn.raw_wwn, nbytes) != 0) {
			ddi_prop_free(bytes);
			continue;
		}

		ddi_prop_free(bytes);

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, TARGET_PROP, &words,
		    &nwords) != DDI_PROP_SUCCESS) {
			continue;
		}

		if (nwords != 1 || words == NULL) {
			if (words != NULL) {
				ddi_prop_free(words);
			}
			continue;
		}
		ASSERT(words != NULL);

		/*
		 * If there is no hard address - We might have to deal with
		 * that by using WWN - Having said that it is important to
		 * recognize this problem early so ssd can be informed of
		 * the right interconnect type.
		 */
		if (!FC_TOP_EXTERNAL(pptr->port_topology) &&
		    ptgt->tgt_hard_addr != 0) {
			tgt_id =
			    (uint32_t)fcp_alpa_to_switch[ptgt->tgt_hard_addr];
		} else {
			tgt_id = ptgt->tgt_d_id;
		}

		if (tgt_id != (uint32_t)*words) {
			ddi_prop_free(words);
			continue;
		}
		ddi_prop_free(words);

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, LUN_PROP, &words,
		    &nwords) != DDI_PROP_SUCCESS) {
			continue;
		}

		if (nwords != 1 || words == NULL) {
			if (words != NULL) {
				ddi_prop_free(words);
			}
			continue;
		}
		ASSERT(words != NULL);

		if (plun->lun_num == (uint16_t)*words) {
			ddi_prop_free(words);
			break;
		}
		ddi_prop_free(words);
	}
	ndi_devi_exit(pdip, circular);

	return (cdip);
}


static int
fcp_is_pip_present(struct fcp_lun *plun, mdi_pathinfo_t *pip)
{
	dev_info_t	*pdip;
	char		buf[MAXNAMELEN];
	char		uaddr[MAXNAMELEN];
	int		rval = FC_FAILURE;

	ASSERT(MUTEX_HELD(&plun->lun_mutex));

	pdip = plun->lun_tgt->tgt_port->port_dip;

	/*
	 * Check if pip (and not plun->lun_cip) is NULL. plun->lun_cip can be
	 * non-NULL even when the LUN is not there as in the case when a LUN is
	 * configured and then deleted on the device end (for T3/T4 case). In
	 * such cases, pip will be NULL.
	 *
	 * If the device generates an RSCN, it will end up getting offlined when
	 * it disappeared and a new LUN will get created when it is rediscovered
	 * on the device. If we check for lun_cip here, the LUN will not end
	 * up getting onlined since this function will end up returning a
	 * FC_SUCCESS.
	 *
	 * The behavior is different on other devices. For instance, on a HDS,
	 * there was no RSCN generated by the device but the next I/O generated
	 * a check condition and rediscovery got triggered that way. So, in
	 * such cases, this path will not be exercised
	 */
	if (pip == NULL) {
		FCP_TRACE(fcp_logq, LUN_PORT->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_4, 0,
		    "fcp_is_pip_present: plun->lun_cip is NULL: "
		    "plun: %p lun state: %x num: %d target state: %x",
		    plun, plun->lun_state, plun->lun_num,
		    plun->lun_tgt->tgt_port->port_state);
		return (rval);
	}

	fcp_wwn_to_ascii(plun->lun_tgt->tgt_port_wwn.raw_wwn, buf);

	(void) snprintf(uaddr, MAXNAMELEN, "w%s,%x", buf, plun->lun_num);

	if (plun->lun_old_guid) {
		if (mdi_pi_find(pdip, plun->lun_old_guid, uaddr) == pip) {
			rval = FC_SUCCESS;
		}
	} else {
		if (mdi_pi_find(pdip, plun->lun_guid, uaddr) == pip) {
			rval = FC_SUCCESS;
		}
	}
	return (rval);
}

static mdi_pathinfo_t *
fcp_find_existing_pip(struct fcp_lun *plun, dev_info_t *pdip)
{
	char			buf[MAXNAMELEN];
	char			uaddr[MAXNAMELEN];
	mdi_pathinfo_t		*pip;
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	struct fcp_port	*pptr = ptgt->tgt_port;

	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	fcp_wwn_to_ascii(ptgt->tgt_port_wwn.raw_wwn, buf);
	(void) snprintf(uaddr, MAXNAMELEN, "w%s,%x", buf, plun->lun_num);

	pip = mdi_pi_find(pdip, plun->lun_guid, uaddr);

	return (pip);
}


static int
fcp_online_child(struct fcp_lun *plun, child_info_t *cip, int lcount,
    int tcount, int flags, int *circ)
{
	int			rval;
	struct fcp_port		*pptr = plun->lun_tgt->tgt_port;
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	dev_info_t		*cdip = NULL;

	ASSERT(MUTEX_HELD(&pptr->port_mutex));
	ASSERT(MUTEX_HELD(&plun->lun_mutex));

	if (plun->lun_cip == NULL) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "fcp_online_child: plun->lun_cip is NULL: "
		    "plun: %p state: %x num: %d target state: %x",
		    plun, plun->lun_state, plun->lun_num,
		    plun->lun_tgt->tgt_port->port_state);
		return (NDI_FAILURE);
	}
again:
	if (plun->lun_mpxio == 0) {
		cdip = DIP(cip);
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "!Invoking ndi_devi_online for %s: target=%x lun=%x",
		    ddi_get_name(cdip), ptgt->tgt_d_id, plun->lun_num);

		/*
		 * We could check for FCP_LUN_INIT here but chances
		 * of getting here when it's already in FCP_LUN_INIT
		 * is rare and a duplicate ndi_devi_online wouldn't
		 * hurt either (as the node would already have been
		 * in CF2)
		 */
		if (!i_ddi_devi_attached(ddi_get_parent(cdip))) {
			rval = ndi_devi_bind_driver(cdip, flags);
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "!Invoking ndi_devi_bind_driver: rval=%d", rval);
		} else {
			rval = ndi_devi_online(cdip, flags);
		}

		/*
		 * We log the message into trace buffer if the device
		 * is "ses" and into syslog for any other device
		 * type. This is to prevent the ndi_devi_online failure
		 * message that appears for V880/A5K ses devices.
		 */
		if (rval == NDI_SUCCESS) {
			mutex_enter(&ptgt->tgt_mutex);
			plun->lun_state |= FCP_LUN_INIT;
			mutex_exit(&ptgt->tgt_mutex);
		} else if (strncmp(ddi_node_name(cdip), "ses", 3) != 0) {
			fcp_log(CE_NOTE, pptr->port_dip,
			    "!ndi_devi_online:"
			    " failed for %s: target=%x lun=%x %x",
			    ddi_get_name(cdip), ptgt->tgt_d_id,
			    plun->lun_num, rval);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    " !ndi_devi_online:"
			    " failed for %s: target=%x lun=%x %x",
			    ddi_get_name(cdip), ptgt->tgt_d_id,
			    plun->lun_num, rval);
		}
	} else {
		cdip = mdi_pi_get_client(PIP(cip));
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);

		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "!Invoking mdi_pi_online for %s: target=%x lun=%x",
		    ddi_get_name(cdip), ptgt->tgt_d_id, plun->lun_num);

		/*
		 * Hold path and exit phci to avoid deadlock with power
		 * management code during mdi_pi_online.
		 */
		mdi_hold_path(PIP(cip));
		mdi_devi_exit_phci(pptr->port_dip, *circ);

		rval = mdi_pi_online(PIP(cip), flags);

		mdi_devi_enter_phci(pptr->port_dip, circ);
		mdi_rele_path(PIP(cip));

		if (rval == MDI_SUCCESS) {
			mutex_enter(&ptgt->tgt_mutex);
			plun->lun_state |= FCP_LUN_INIT;
			mutex_exit(&ptgt->tgt_mutex);

			/*
			 * Clear MPxIO path permanent disable in case
			 * fcp hotplug dropped the offline event.
			 */
			(void) mdi_pi_enable_path(PIP(cip), DRIVER_DISABLE);

		} else if (rval == MDI_NOT_SUPPORTED) {
			child_info_t	*old_cip = cip;

			/*
			 * MPxIO does not support this device yet.
			 * Enumerate in legacy mode.
			 */
			mutex_enter(&pptr->port_mutex);
			mutex_enter(&plun->lun_mutex);
			plun->lun_mpxio = 0;
			plun->lun_cip = NULL;
			cdip = fcp_create_dip(plun, lcount, tcount);
			plun->lun_cip = cip = CIP(cdip);
			if (cip == NULL) {
				fcp_log(CE_WARN, pptr->port_dip,
				    "!fcp_online_child: "
				    "Create devinfo failed for LU=%p", plun);
				mutex_exit(&plun->lun_mutex);

				mutex_enter(&ptgt->tgt_mutex);
				plun->lun_state |= FCP_LUN_OFFLINE;
				mutex_exit(&ptgt->tgt_mutex);

				mutex_exit(&pptr->port_mutex);

				/*
				 * free the mdi_pathinfo node
				 */
				(void) mdi_pi_free(PIP(old_cip), 0);
			} else {
				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_3, 0,
				    "fcp_online_child: creating devinfo "
				    "node 0x%p for plun 0x%p",
				    cip, plun);
				mutex_exit(&plun->lun_mutex);
				mutex_exit(&pptr->port_mutex);
				/*
				 * free the mdi_pathinfo node
				 */
				(void) mdi_pi_free(PIP(old_cip), 0);
				mutex_enter(&pptr->port_mutex);
				mutex_enter(&plun->lun_mutex);
				goto again;
			}
		} else {
			if (cdip) {
				fcp_log(CE_NOTE, pptr->port_dip,
				    "!fcp_online_child: mdi_pi_online:"
				    " failed for %s: target=%x lun=%x %x",
				    ddi_get_name(cdip), ptgt->tgt_d_id,
				    plun->lun_num, rval);
			}
		}
		rval = (rval == MDI_SUCCESS) ? NDI_SUCCESS : NDI_FAILURE;
	}

	if (rval == NDI_SUCCESS) {
		if (cdip) {
			(void) ndi_event_retrieve_cookie(
			    pptr->port_ndi_event_hdl, cdip, FCAL_INSERT_EVENT,
			    &fcp_insert_eid, NDI_EVENT_NOPASS);
			(void) ndi_event_run_callbacks(pptr->port_ndi_event_hdl,
			    cdip, fcp_insert_eid, NULL);
		}
	}
	mutex_enter(&pptr->port_mutex);
	mutex_enter(&plun->lun_mutex);
	return (rval);
}

/* ARGSUSED */
static int
fcp_offline_child(struct fcp_lun *plun, child_info_t *cip, int lcount,
    int tcount, int flags, int *circ)
{
	int		rval;
	int		lun_mpxio;
	struct fcp_port	*pptr = plun->lun_tgt->tgt_port;
	struct fcp_tgt	*ptgt = plun->lun_tgt;
	dev_info_t	*cdip;

	ASSERT(MUTEX_HELD(&plun->lun_mutex));
	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	if (plun->lun_cip == NULL) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0,
		    "fcp_offline_child: plun->lun_cip is NULL: "
		    "plun: %p lun state: %x num: %d target state: %x",
		    plun, plun->lun_state, plun->lun_num,
		    plun->lun_tgt->tgt_port->port_state);
		return (NDI_FAILURE);
	}

	/*
	 * We will use this value twice. Make a copy to be sure we use
	 * the same value in both places.
	 */
	lun_mpxio = plun->lun_mpxio;

	if (lun_mpxio == 0) {
		cdip = DIP(cip);
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);
		rval = ndi_devi_offline(DIP(cip), flags);
		if (rval != NDI_SUCCESS) {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "fcp_offline_child: ndi_devi_offline failed "
			    "rval=%x cip=%p", rval, cip);
		}
	} else {
		cdip = mdi_pi_get_client(PIP(cip));
		mutex_exit(&plun->lun_mutex);
		mutex_exit(&pptr->port_mutex);

		/*
		 * Exit phci to avoid deadlock with power management code
		 * during mdi_pi_offline
		 */
		mdi_hold_path(PIP(cip));
		mdi_devi_exit_phci(pptr->port_dip, *circ);

		rval = mdi_pi_offline(PIP(cip), flags);

		mdi_devi_enter_phci(pptr->port_dip, circ);
		mdi_rele_path(PIP(cip));

		rval = (rval == MDI_SUCCESS) ? NDI_SUCCESS : NDI_FAILURE;
	}

	mutex_enter(&ptgt->tgt_mutex);
	plun->lun_state &= ~FCP_LUN_INIT;
	mutex_exit(&ptgt->tgt_mutex);

	if (rval == NDI_SUCCESS) {
		cdip = NULL;
		if (flags & NDI_DEVI_REMOVE) {
			mutex_enter(&plun->lun_mutex);
			/*
			 * If the guid of the LUN changes, lun_cip will not
			 * equal to cip, and after offlining the LUN with the
			 * old guid, we should keep lun_cip since it's the cip
			 * of the LUN with the new guid.
			 * Otherwise remove our reference to child node.
			 *
			 * This must be done before the child node is freed,
			 * otherwise other threads could see a stale lun_cip
			 * pointer.
			 */
			if (plun->lun_cip == cip) {
				plun->lun_cip = NULL;
			}
			if (plun->lun_old_guid) {
				kmem_free(plun->lun_old_guid,
				    plun->lun_old_guid_size);
				plun->lun_old_guid = NULL;
				plun->lun_old_guid_size = 0;
			}
			mutex_exit(&plun->lun_mutex);
		}
	}

	if (lun_mpxio != 0) {
		if (rval == NDI_SUCCESS) {
			/*
			 * Clear MPxIO path permanent disable as the path is
			 * already offlined.
			 */
			(void) mdi_pi_enable_path(PIP(cip), DRIVER_DISABLE);

			if (flags & NDI_DEVI_REMOVE) {
				(void) mdi_pi_free(PIP(cip), 0);
			}
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "fcp_offline_child: mdi_pi_offline failed "
			    "rval=%x cip=%p", rval, cip);
		}
	}

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&plun->lun_mutex);

	if (cdip) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_3, 0, "!%s failed for %s:"
		    " target=%x lun=%x", "ndi_offline",
		    ddi_get_name(cdip), ptgt->tgt_d_id, plun->lun_num);
	}

	return (rval);
}

static void
fcp_remove_child(struct fcp_lun *plun)
{
	child_info_t *cip;
	int circ;

	ASSERT(MUTEX_HELD(&plun->lun_mutex));

	if (fcp_is_child_present(plun, plun->lun_cip) == FC_SUCCESS) {
		if (plun->lun_mpxio == 0) {
			(void) ndi_prop_remove_all(DIP(plun->lun_cip));
			(void) ndi_devi_free(DIP(plun->lun_cip));
			plun->lun_cip = NULL;
		} else {
			/*
			 * Clear reference to the child node in the lun.
			 * This must be done before freeing it with mdi_pi_free
			 * and with lun_mutex held so that other threads always
			 * see either valid lun_cip or NULL when holding
			 * lun_mutex. We keep a copy in cip.
			 */
			cip = plun->lun_cip;
			plun->lun_cip = NULL;

			mutex_exit(&plun->lun_mutex);
			mutex_exit(&plun->lun_tgt->tgt_mutex);
			mutex_exit(&plun->lun_tgt->tgt_port->port_mutex);

			mdi_devi_enter(
			    plun->lun_tgt->tgt_port->port_dip, &circ);

			/*
			 * Exit phci to avoid deadlock with power management
			 * code during mdi_pi_offline
			 */
			mdi_hold_path(PIP(cip));
			mdi_devi_exit_phci(
			    plun->lun_tgt->tgt_port->port_dip, circ);
			(void) mdi_pi_offline(PIP(cip),
			    NDI_DEVI_REMOVE);
			mdi_devi_enter_phci(
			    plun->lun_tgt->tgt_port->port_dip, &circ);
			mdi_rele_path(PIP(cip));

			mdi_devi_exit(
			    plun->lun_tgt->tgt_port->port_dip, circ);

			FCP_TRACE(fcp_logq,
			    plun->lun_tgt->tgt_port->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_3, 0,
			    "lun=%p pip freed %p", plun, cip);

			(void) mdi_prop_remove(PIP(cip), NULL);
			(void) mdi_pi_free(PIP(cip), 0);

			mutex_enter(&plun->lun_tgt->tgt_port->port_mutex);
			mutex_enter(&plun->lun_tgt->tgt_mutex);
			mutex_enter(&plun->lun_mutex);
		}
	} else {
		plun->lun_cip = NULL;
	}
}

/*
 * called when a timeout occurs
 *
 * can be scheduled during an attach or resume (if not already running)
 *
 * one timeout is set up for all ports
 *
 * acquires and releases the global mutex
 */
/*ARGSUSED*/
static void
fcp_watch(void *arg)
{
	struct fcp_port	*pptr;
	struct fcp_ipkt	*icmd;
	struct fcp_ipkt	*nicmd;
	struct fcp_pkt	*cmd;
	struct fcp_pkt	*ncmd;
	struct fcp_pkt	*tail;
	struct fcp_pkt	*pcmd;
	struct fcp_pkt	*save_head;
	struct fcp_port	*save_port;

	/* increment global watchdog time */
	fcp_watchdog_time += fcp_watchdog_timeout;

	mutex_enter(&fcp_global_mutex);

	/* scan each port in our list */
	for (pptr = fcp_port_head; pptr != NULL; pptr = pptr->port_next) {
		save_port = fcp_port_head;
		pptr->port_state |= FCP_STATE_IN_WATCHDOG;
		mutex_exit(&fcp_global_mutex);

		mutex_enter(&pptr->port_mutex);
		if (pptr->port_ipkt_list == NULL &&
		    (pptr->port_state & (FCP_STATE_SUSPENDED |
		    FCP_STATE_DETACHING | FCP_STATE_POWER_DOWN))) {
			pptr->port_state &= ~FCP_STATE_IN_WATCHDOG;
			mutex_exit(&pptr->port_mutex);
			mutex_enter(&fcp_global_mutex);
			goto end_of_watchdog;
		}

		/*
		 * We check if a list of targets need to be offlined.
		 */
		if (pptr->port_offline_tgts) {
			fcp_scan_offline_tgts(pptr);
		}

		/*
		 * We check if a list of luns need to be offlined.
		 */
		if (pptr->port_offline_luns) {
			fcp_scan_offline_luns(pptr);
		}

		/*
		 * We check if a list of targets or luns need to be reset.
		 */
		if (pptr->port_reset_list) {
			fcp_check_reset_delay(pptr);
		}

		mutex_exit(&pptr->port_mutex);

		/*
		 * This is where the pending commands (pkt) are checked for
		 * timeout.
		 */
		mutex_enter(&pptr->port_pkt_mutex);
		tail = pptr->port_pkt_tail;

		for (pcmd = NULL, cmd = pptr->port_pkt_head;
		    cmd != NULL; cmd = ncmd) {
			ncmd = cmd->cmd_next;
			/*
			 * If a command is in this queue the bit CFLAG_IN_QUEUE
			 * must be set.
			 */
			ASSERT(cmd->cmd_flags & CFLAG_IN_QUEUE);
			/*
			 * FCP_INVALID_TIMEOUT will be set for those
			 * command that need to be failed. Mostly those
			 * cmds that could not be queued down for the
			 * "timeout" value. cmd->cmd_timeout is used
			 * to try and requeue the command regularly.
			 */
			if (cmd->cmd_timeout >= fcp_watchdog_time) {
				/*
				 * This command hasn't timed out yet.  Let's
				 * go to the next one.
				 */
				pcmd = cmd;
				goto end_of_loop;
			}

			if (cmd == pptr->port_pkt_head) {
				ASSERT(pcmd == NULL);
				pptr->port_pkt_head = cmd->cmd_next;
			} else {
				ASSERT(pcmd != NULL);
				pcmd->cmd_next = cmd->cmd_next;
			}

			if (cmd == pptr->port_pkt_tail) {
				ASSERT(cmd->cmd_next == NULL);
				pptr->port_pkt_tail = pcmd;
				if (pcmd) {
					pcmd->cmd_next = NULL;
				}
			}
			cmd->cmd_next = NULL;

			/*
			 * save the current head before dropping the
			 * mutex - If the head doesn't remain the
			 * same after re acquiring the mutex, just
			 * bail out and revisit on next tick.
			 *
			 * PS: The tail pointer can change as the commands
			 * get requeued after failure to retransport
			 */
			save_head = pptr->port_pkt_head;
			mutex_exit(&pptr->port_pkt_mutex);

			if (cmd->cmd_fp_pkt->pkt_timeout ==
			    FCP_INVALID_TIMEOUT) {
				struct scsi_pkt		*pkt = cmd->cmd_pkt;
				struct fcp_lun	*plun;
				struct fcp_tgt	*ptgt;

				plun = ADDR2LUN(&pkt->pkt_address);
				ptgt = plun->lun_tgt;

				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "SCSI cmd 0x%x to D_ID=%x timed out",
				    pkt->pkt_cdbp[0], ptgt->tgt_d_id);

				cmd->cmd_state == FCP_PKT_ABORTING ?
				    fcp_fail_cmd(cmd, CMD_RESET,
				    STAT_DEV_RESET) : fcp_fail_cmd(cmd,
				    CMD_TIMEOUT, STAT_ABORTED);
			} else {
				fcp_retransport_cmd(pptr, cmd);
			}
			mutex_enter(&pptr->port_pkt_mutex);
			if (save_head && save_head != pptr->port_pkt_head) {
				/*
				 * Looks like linked list got changed (mostly
				 * happens when an an OFFLINE LUN code starts
				 * returning overflow queue commands in
				 * parallel. So bail out and revisit during
				 * next tick
				 */
				break;
			}
		end_of_loop:
			/*
			 * Scan only upto the previously known tail pointer
			 * to avoid excessive processing - lots of new packets
			 * could have been added to the tail or the old ones
			 * re-queued.
			 */
			if (cmd == tail) {
				break;
			}
		}
		mutex_exit(&pptr->port_pkt_mutex);

		mutex_enter(&pptr->port_mutex);
		for (icmd = pptr->port_ipkt_list; icmd != NULL; icmd = nicmd) {
			struct fcp_tgt *ptgt = icmd->ipkt_tgt;

			nicmd = icmd->ipkt_next;
			if ((icmd->ipkt_restart != 0) &&
			    (icmd->ipkt_restart >= fcp_watchdog_time)) {
				/* packet has not timed out */
				continue;
			}

			/* time for packet re-transport */
			if (icmd == pptr->port_ipkt_list) {
				pptr->port_ipkt_list = icmd->ipkt_next;
				if (pptr->port_ipkt_list) {
					pptr->port_ipkt_list->ipkt_prev =
					    NULL;
				}
			} else {
				icmd->ipkt_prev->ipkt_next = icmd->ipkt_next;
				if (icmd->ipkt_next) {
					icmd->ipkt_next->ipkt_prev =
					    icmd->ipkt_prev;
				}
			}
			icmd->ipkt_next = NULL;
			icmd->ipkt_prev = NULL;
			mutex_exit(&pptr->port_mutex);

			if (fcp_is_retryable(icmd)) {
				fc_ulp_rscn_info_t *rscnp =
				    (fc_ulp_rscn_info_t *)icmd->ipkt_fpkt->
				    pkt_ulp_rscn_infop;

				FCP_TRACE(fcp_logq, pptr->port_instbuf,
				    fcp_trace, FCP_BUF_LEVEL_2, 0,
				    "%x to D_ID=%x Retrying..",
				    icmd->ipkt_opcode,
				    icmd->ipkt_fpkt->pkt_cmd_fhdr.d_id);

				/*
				 * Update the RSCN count in the packet
				 * before resending.
				 */

				if (rscnp != NULL) {
					rscnp->ulp_rscn_count =
					    fc_ulp_get_rscn_count(pptr->
					    port_fp_handle);
				}

				mutex_enter(&pptr->port_mutex);
				mutex_enter(&ptgt->tgt_mutex);
				if (!FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
					mutex_exit(&ptgt->tgt_mutex);
					mutex_exit(&pptr->port_mutex);
					switch (icmd->ipkt_opcode) {
						int rval;
					case LA_ELS_PLOGI:
						if ((rval = fc_ulp_login(
						    pptr->port_fp_handle,
						    &icmd->ipkt_fpkt, 1)) ==
						    FC_SUCCESS) {
							mutex_enter(
							    &pptr->port_mutex);
							continue;
						}
						if (fcp_handle_ipkt_errors(
						    pptr, ptgt, icmd, rval,
						    "PLOGI") == DDI_SUCCESS) {
							mutex_enter(
							    &pptr->port_mutex);
							continue;
						}
						break;

					case LA_ELS_PRLI:
						if ((rval = fc_ulp_issue_els(
						    pptr->port_fp_handle,
						    icmd->ipkt_fpkt)) ==
						    FC_SUCCESS) {
							mutex_enter(
							    &pptr->port_mutex);
							continue;
						}
						if (fcp_handle_ipkt_errors(
						    pptr, ptgt, icmd, rval,
						    "PRLI") == DDI_SUCCESS) {
							mutex_enter(
							    &pptr->port_mutex);
							continue;
						}
						break;

					default:
						if ((rval = fcp_transport(
						    pptr->port_fp_handle,
						    icmd->ipkt_fpkt, 1)) ==
						    FC_SUCCESS) {
							mutex_enter(
							    &pptr->port_mutex);
							continue;
						}
						if (fcp_handle_ipkt_errors(
						    pptr, ptgt, icmd, rval,
						    "PRLI") == DDI_SUCCESS) {
							mutex_enter(
							    &pptr->port_mutex);
							continue;
						}
						break;
					}
				} else {
					mutex_exit(&ptgt->tgt_mutex);
					mutex_exit(&pptr->port_mutex);
				}
			} else {
				fcp_print_error(icmd->ipkt_fpkt);
			}

			(void) fcp_call_finish_init(pptr, ptgt,
			    icmd->ipkt_link_cnt, icmd->ipkt_change_cnt,
			    icmd->ipkt_cause);
			fcp_icmd_free(pptr, icmd);
			mutex_enter(&pptr->port_mutex);
		}

		pptr->port_state &= ~FCP_STATE_IN_WATCHDOG;
		mutex_exit(&pptr->port_mutex);
		mutex_enter(&fcp_global_mutex);

	end_of_watchdog:
		/*
		 * Bail out early before getting into trouble
		 */
		if (save_port != fcp_port_head) {
			break;
		}
	}

	if (fcp_watchdog_init > 0) {
		/* reschedule timeout to go again */
		fcp_watchdog_id =
		    timeout(fcp_watch, NULL, fcp_watchdog_tick);
	}
	mutex_exit(&fcp_global_mutex);
}


static void
fcp_check_reset_delay(struct fcp_port *pptr)
{
	uint32_t		tgt_cnt;
	int			level;
	struct fcp_tgt	*ptgt;
	struct fcp_lun	*plun;
	struct fcp_reset_elem *cur = NULL;
	struct fcp_reset_elem *next = NULL;
	struct fcp_reset_elem *prev = NULL;

	ASSERT(mutex_owned(&pptr->port_mutex));

	next = pptr->port_reset_list;
	while ((cur = next) != NULL) {
		next = cur->next;

		if (cur->timeout < fcp_watchdog_time) {
			prev = cur;
			continue;
		}

		ptgt = cur->tgt;
		plun = cur->lun;
		tgt_cnt = cur->tgt_cnt;

		if (ptgt) {
			level = RESET_TARGET;
		} else {
			ASSERT(plun != NULL);
			level = RESET_LUN;
			ptgt = plun->lun_tgt;
		}
		if (prev) {
			prev->next = next;
		} else {
			/*
			 * Because we drop port mutex while doing aborts for
			 * packets, we can't rely on reset_list pointing to
			 * our head
			 */
			if (cur == pptr->port_reset_list) {
				pptr->port_reset_list = next;
			} else {
				struct fcp_reset_elem *which;

				which = pptr->port_reset_list;
				while (which && which->next != cur) {
					which = which->next;
				}
				ASSERT(which != NULL);

				which->next = next;
				prev = which;
			}
		}

		kmem_free(cur, sizeof (*cur));

		if (tgt_cnt == ptgt->tgt_change_cnt) {
			mutex_enter(&ptgt->tgt_mutex);
			if (level == RESET_TARGET) {
				fcp_update_tgt_state(ptgt,
				    FCP_RESET, FCP_LUN_BUSY);
			} else {
				fcp_update_lun_state(plun,
				    FCP_RESET, FCP_LUN_BUSY);
			}
			mutex_exit(&ptgt->tgt_mutex);

			mutex_exit(&pptr->port_mutex);
			fcp_abort_all(pptr, ptgt, plun, tgt_cnt);
			mutex_enter(&pptr->port_mutex);
		}
	}
}


static void
fcp_abort_all(struct fcp_port *pptr, struct fcp_tgt *ttgt,
    struct fcp_lun *rlun, int tgt_cnt)
{
	int			rval;
	struct fcp_lun	*tlun, *nlun;
	struct fcp_pkt	*pcmd = NULL, *ncmd = NULL,
	    *cmd = NULL, *head = NULL,
	    *tail = NULL;

	mutex_enter(&pptr->port_pkt_mutex);
	for (cmd = pptr->port_pkt_head; cmd != NULL; cmd = ncmd) {
		struct fcp_lun *plun = ADDR2LUN(&cmd->cmd_pkt->pkt_address);
		struct fcp_tgt *ptgt = plun->lun_tgt;

		ncmd = cmd->cmd_next;

		if (ptgt != ttgt && plun != rlun) {
			pcmd = cmd;
			continue;
		}

		if (pcmd != NULL) {
			ASSERT(pptr->port_pkt_head != cmd);
			pcmd->cmd_next = ncmd;
		} else {
			ASSERT(cmd == pptr->port_pkt_head);
			pptr->port_pkt_head = ncmd;
		}
		if (pptr->port_pkt_tail == cmd) {
			ASSERT(cmd->cmd_next == NULL);
			pptr->port_pkt_tail = pcmd;
			if (pcmd != NULL) {
				pcmd->cmd_next = NULL;
			}
		}

		if (head == NULL) {
			head = tail = cmd;
		} else {
			ASSERT(tail != NULL);
			tail->cmd_next = cmd;
			tail = cmd;
		}
		cmd->cmd_next = NULL;
	}
	mutex_exit(&pptr->port_pkt_mutex);

	for (cmd = head; cmd != NULL; cmd = ncmd) {
		struct scsi_pkt *pkt = cmd->cmd_pkt;

		ncmd = cmd->cmd_next;
		ASSERT(pkt != NULL);

		mutex_enter(&pptr->port_mutex);
		if (ttgt->tgt_change_cnt == tgt_cnt) {
			mutex_exit(&pptr->port_mutex);
			cmd->cmd_flags &= ~CFLAG_IN_QUEUE;
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_DEV_RESET;
			cmd->cmd_state = FCP_PKT_IDLE;
			fcp_post_callback(cmd);
		} else {
			mutex_exit(&pptr->port_mutex);
		}
	}

	/*
	 * If the FCA will return all the commands in its queue then our
	 * work is easy, just return.
	 */

	if (pptr->port_reset_action == FC_RESET_RETURN_ALL) {
		return;
	}

	/*
	 * For RESET_LUN get hold of target pointer
	 */
	if (ttgt == NULL) {
		ASSERT(rlun != NULL);

		ttgt = rlun->lun_tgt;

		ASSERT(ttgt != NULL);
	}

	/*
	 * There are some severe race conditions here.
	 * While we are trying to abort the pkt, it might be completing
	 * so mark it aborted and if the abort does not succeed then
	 * handle it in the watch thread.
	 */
	mutex_enter(&ttgt->tgt_mutex);
	nlun = ttgt->tgt_lun;
	mutex_exit(&ttgt->tgt_mutex);
	while ((tlun = nlun) != NULL) {
		int restart = 0;
		if (rlun && rlun != tlun) {
			mutex_enter(&ttgt->tgt_mutex);
			nlun = tlun->lun_next;
			mutex_exit(&ttgt->tgt_mutex);
			continue;
		}
		mutex_enter(&tlun->lun_mutex);
		cmd = tlun->lun_pkt_head;
		while (cmd != NULL) {
			if (cmd->cmd_state == FCP_PKT_ISSUED) {
				struct scsi_pkt *pkt;

				restart = 1;
				cmd->cmd_state = FCP_PKT_ABORTING;
				mutex_exit(&tlun->lun_mutex);
				rval = fc_ulp_abort(pptr->port_fp_handle,
				    cmd->cmd_fp_pkt, KM_SLEEP);
				if (rval == FC_SUCCESS) {
					pkt = cmd->cmd_pkt;
					pkt->pkt_reason = CMD_RESET;
					pkt->pkt_statistics |= STAT_DEV_RESET;
					cmd->cmd_state = FCP_PKT_IDLE;
					fcp_post_callback(cmd);
				} else {
					caddr_t msg;

					(void) fc_ulp_error(rval, &msg);

					/*
					 * This part is tricky. The abort
					 * failed and now the command could
					 * be completing.  The cmd_state ==
					 * FCP_PKT_ABORTING should save
					 * us in fcp_cmd_callback. If we
					 * are already aborting ignore the
					 * command in fcp_cmd_callback.
					 * Here we leave this packet for 20
					 * sec to be aborted in the
					 * fcp_watch thread.
					 */
					fcp_log(CE_WARN, pptr->port_dip,
					    "!Abort failed after reset %s",
					    msg);

					cmd->cmd_timeout =
					    fcp_watchdog_time +
					    cmd->cmd_pkt->pkt_time +
					    FCP_FAILED_DELAY;

					cmd->cmd_fp_pkt->pkt_timeout =
					    FCP_INVALID_TIMEOUT;
					/*
					 * This is a hack, cmd is put in the
					 * overflow queue so that it can be
					 * timed out finally
					 */
					cmd->cmd_flags |= CFLAG_IN_QUEUE;

					mutex_enter(&pptr->port_pkt_mutex);
					if (pptr->port_pkt_head) {
						ASSERT(pptr->port_pkt_tail
						    != NULL);
						pptr->port_pkt_tail->cmd_next
						    = cmd;
						pptr->port_pkt_tail = cmd;
					} else {
						ASSERT(pptr->port_pkt_tail
						    == NULL);
						pptr->port_pkt_head =
						    pptr->port_pkt_tail
						    = cmd;
					}
					cmd->cmd_next = NULL;
					mutex_exit(&pptr->port_pkt_mutex);
				}
				mutex_enter(&tlun->lun_mutex);
				cmd = tlun->lun_pkt_head;
			} else {
				cmd = cmd->cmd_forw;
			}
		}
		mutex_exit(&tlun->lun_mutex);

		mutex_enter(&ttgt->tgt_mutex);
		restart == 1 ? (nlun = ttgt->tgt_lun) : (nlun = tlun->lun_next);
		mutex_exit(&ttgt->tgt_mutex);

		mutex_enter(&pptr->port_mutex);
		if (tgt_cnt != ttgt->tgt_change_cnt) {
			mutex_exit(&pptr->port_mutex);
			return;
		} else {
			mutex_exit(&pptr->port_mutex);
		}
	}
}


/*
 * unlink the soft state, returning the soft state found (if any)
 *
 * acquires and releases the global mutex
 */
struct fcp_port *
fcp_soft_state_unlink(struct fcp_port *pptr)
{
	struct fcp_port	*hptr;		/* ptr index */
	struct fcp_port	*tptr;		/* prev hptr */

	mutex_enter(&fcp_global_mutex);
	for (hptr = fcp_port_head, tptr = NULL;
	    hptr != NULL;
	    tptr = hptr, hptr = hptr->port_next) {
		if (hptr == pptr) {
			/* we found a match -- remove this item */
			if (tptr == NULL) {
				/* we're at the head of the list */
				fcp_port_head = hptr->port_next;
			} else {
				tptr->port_next = hptr->port_next;
			}
			break;			/* success */
		}
	}
	if (fcp_port_head == NULL) {
		fcp_cleanup_blacklist(&fcp_lun_blacklist);
	}
	mutex_exit(&fcp_global_mutex);
	return (hptr);
}


/*
 * called by fcp_scsi_hba_tgt_init to find a LUN given a
 * WWN and a LUN number
 */
/* ARGSUSED */
static struct fcp_lun *
fcp_lookup_lun(struct fcp_port *pptr, uchar_t *wwn, uint16_t lun)
{
	int hash;
	struct fcp_tgt *ptgt;
	struct fcp_lun *plun;

	ASSERT(mutex_owned(&pptr->port_mutex));

	hash = FCP_HASH(wwn);
	for (ptgt = pptr->port_tgt_hash_table[hash]; ptgt != NULL;
	    ptgt = ptgt->tgt_next) {
		if (bcmp((caddr_t)wwn, (caddr_t)&ptgt->tgt_port_wwn.raw_wwn[0],
		    sizeof (ptgt->tgt_port_wwn)) == 0) {
			mutex_enter(&ptgt->tgt_mutex);
			for (plun = ptgt->tgt_lun;
			    plun != NULL;
			    plun = plun->lun_next) {
				if (plun->lun_num == lun) {
					mutex_exit(&ptgt->tgt_mutex);
					return (plun);
				}
			}
			mutex_exit(&ptgt->tgt_mutex);
			return (NULL);
		}
	}
	return (NULL);
}

/*
 *     Function: fcp_prepare_pkt
 *
 *  Description: This function prepares the SCSI cmd pkt, passed by the caller,
 *		 for fcp_start(). It binds the data or partially maps it.
 *		 Builds the FCP header and starts the initialization of the
 *		 Fibre Channel header.
 *
 *     Argument: *pptr		FCP port.
 *		 *cmd		FCP packet.
 *		 *plun		LUN the command will be sent to.
 *
 *	Context: User, Kernel and Interrupt context.
 */
static void
fcp_prepare_pkt(struct fcp_port *pptr, struct fcp_pkt *cmd,
    struct fcp_lun *plun)
{
	fc_packet_t		*fpkt = cmd->cmd_fp_pkt;
	struct fcp_tgt		*ptgt = plun->lun_tgt;
	struct fcp_cmd		*fcmd = &cmd->cmd_fcp_cmd;

	ASSERT(cmd->cmd_pkt->pkt_comp ||
	    (cmd->cmd_pkt->pkt_flags & FLAG_NOINTR));

	if (cmd->cmd_pkt->pkt_numcookies) {
		if (cmd->cmd_pkt->pkt_dma_flags & DDI_DMA_READ) {
			fcmd->fcp_cntl.cntl_read_data = 1;
			fcmd->fcp_cntl.cntl_write_data = 0;
			fpkt->pkt_tran_type = FC_PKT_FCP_READ;
		} else {
			fcmd->fcp_cntl.cntl_read_data = 0;
			fcmd->fcp_cntl.cntl_write_data = 1;
			fpkt->pkt_tran_type = FC_PKT_FCP_WRITE;
		}

		fpkt->pkt_data_cookie = cmd->cmd_pkt->pkt_cookies;

		fpkt->pkt_data_cookie_cnt = cmd->cmd_pkt->pkt_numcookies;
		ASSERT(fpkt->pkt_data_cookie_cnt <=
		    pptr->port_data_dma_attr.dma_attr_sgllen);

		cmd->cmd_dmacount = cmd->cmd_pkt->pkt_dma_len;

		/* FCA needs pkt_datalen to be set */
		fpkt->pkt_datalen = cmd->cmd_dmacount;
		fcmd->fcp_data_len = cmd->cmd_dmacount;
	} else {
		fcmd->fcp_cntl.cntl_read_data = 0;
		fcmd->fcp_cntl.cntl_write_data = 0;
		fpkt->pkt_tran_type = FC_PKT_EXCHANGE;
		fpkt->pkt_datalen = 0;
		fcmd->fcp_data_len = 0;
	}

	/* set up the Tagged Queuing type */
	if (cmd->cmd_pkt->pkt_flags & FLAG_HTAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_HEAD_OF_Q;
	} else if (cmd->cmd_pkt->pkt_flags & FLAG_OTAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_ORDERED;
	} else if (cmd->cmd_pkt->pkt_flags & FLAG_STAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_SIMPLE;
	} else {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_UNTAGGED;
	}

	fcmd->fcp_ent_addr = plun->lun_addr;

	if (pptr->port_fcp_dma != FC_NO_DVMA_SPACE) {
		FCP_CP_OUT((uint8_t *)fcmd, fpkt->pkt_cmd,
		    fpkt->pkt_cmd_acc, sizeof (struct fcp_cmd));
	} else {
		ASSERT(fpkt->pkt_cmd_dma == NULL && fpkt->pkt_resp_dma == NULL);
	}

	cmd->cmd_pkt->pkt_reason = CMD_CMPLT;
	cmd->cmd_pkt->pkt_state = 0;
	cmd->cmd_pkt->pkt_statistics = 0;
	cmd->cmd_pkt->pkt_resid = 0;

	cmd->cmd_fp_pkt->pkt_data_dma = cmd->cmd_pkt->pkt_handle;

	if (cmd->cmd_pkt->pkt_flags & FLAG_NOINTR) {
		fpkt->pkt_tran_flags = (FC_TRAN_CLASS3 | FC_TRAN_NO_INTR);
		fpkt->pkt_comp = NULL;
	} else {
		fpkt->pkt_tran_flags = (FC_TRAN_CLASS3 | FC_TRAN_INTR);
		if (cmd->cmd_pkt->pkt_flags & FLAG_IMMEDIATE_CB) {
			fpkt->pkt_tran_flags |= FC_TRAN_IMMEDIATE_CB;
		}
		fpkt->pkt_comp = fcp_cmd_callback;
	}

	mutex_enter(&pptr->port_mutex);
	if (pptr->port_state & FCP_STATE_SUSPENDED) {
		fpkt->pkt_tran_flags |= FC_TRAN_DUMPING;
	}
	mutex_exit(&pptr->port_mutex);

	fpkt->pkt_cmd_fhdr.d_id = ptgt->tgt_d_id;
	fpkt->pkt_cmd_fhdr.s_id = pptr->port_id;

	/*
	 * Save a few kernel cycles here
	 */
#ifndef	__lock_lint
	fpkt->pkt_fca_device = ptgt->tgt_fca_dev;
#endif /* __lock_lint */
}

static void
fcp_post_callback(struct fcp_pkt *cmd)
{
	scsi_hba_pkt_comp(cmd->cmd_pkt);
}


/*
 * called to do polled I/O by fcp_start()
 *
 * return a transport status value, i.e. TRAN_ACCECPT for success
 */
static int
fcp_dopoll(struct fcp_port *pptr, struct fcp_pkt *cmd)
{
	int	rval;

#ifdef	DEBUG
	mutex_enter(&pptr->port_pkt_mutex);
	pptr->port_npkts++;
	mutex_exit(&pptr->port_pkt_mutex);
#endif /* DEBUG */

	if (cmd->cmd_fp_pkt->pkt_timeout) {
		cmd->cmd_fp_pkt->pkt_timeout = cmd->cmd_pkt->pkt_time;
	} else {
		cmd->cmd_fp_pkt->pkt_timeout = FCP_POLL_TIMEOUT;
	}

	ASSERT(cmd->cmd_fp_pkt->pkt_comp == NULL);

	cmd->cmd_state = FCP_PKT_ISSUED;

	rval = fc_ulp_transport(pptr->port_fp_handle, cmd->cmd_fp_pkt);

#ifdef	DEBUG
	mutex_enter(&pptr->port_pkt_mutex);
	pptr->port_npkts--;
	mutex_exit(&pptr->port_pkt_mutex);
#endif /* DEBUG */

	cmd->cmd_state = FCP_PKT_IDLE;

	switch (rval) {
	case FC_SUCCESS:
		if (cmd->cmd_fp_pkt->pkt_state == FC_PKT_SUCCESS) {
			fcp_complete_pkt(cmd->cmd_fp_pkt);
			rval = TRAN_ACCEPT;
		} else {
			rval = TRAN_FATAL_ERROR;
		}
		break;

	case FC_TRAN_BUSY:
		rval = TRAN_BUSY;
		cmd->cmd_pkt->pkt_resid = 0;
		break;

	case FC_BADPACKET:
		rval = TRAN_BADPKT;
		break;

	default:
		rval = TRAN_FATAL_ERROR;
		break;
	}

	return (rval);
}


/*
 * called by some of the following transport-called routines to convert
 * a supplied dip ptr to a port struct ptr (i.e. to the soft state)
 */
static struct fcp_port *
fcp_dip2port(dev_info_t *dip)
{
	int	instance;

	instance = ddi_get_instance(dip);
	return (ddi_get_soft_state(fcp_softstate, instance));
}


/*
 * called internally to return a LUN given a dip
 */
struct fcp_lun *
fcp_get_lun_from_cip(struct fcp_port *pptr, child_info_t *cip)
{
	struct fcp_tgt *ptgt;
	struct fcp_lun *plun;
	int i;


	ASSERT(mutex_owned(&pptr->port_mutex));

	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i];
		    ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			mutex_enter(&ptgt->tgt_mutex);
			for (plun = ptgt->tgt_lun; plun != NULL;
			    plun = plun->lun_next) {
				mutex_enter(&plun->lun_mutex);
				if (plun->lun_cip == cip) {
					mutex_exit(&plun->lun_mutex);
					mutex_exit(&ptgt->tgt_mutex);
					return (plun); /* match found */
				}
				mutex_exit(&plun->lun_mutex);
			}
			mutex_exit(&ptgt->tgt_mutex);
		}
	}
	return (NULL);				/* no LUN found */
}

/*
 * pass an element to the hotplug list, kick the hotplug thread
 * and wait for the element to get processed by the hotplug thread.
 * on return the element is freed.
 *
 * return zero success and non-zero on failure
 *
 * acquires/releases the target mutex
 *
 */
static int
fcp_pass_to_hp_and_wait(struct fcp_port *pptr, struct fcp_lun *plun,
    child_info_t *cip, int what, int link_cnt, int tgt_cnt, int flags)
{
	struct fcp_hp_elem	*elem;
	int			rval;

	mutex_enter(&plun->lun_tgt->tgt_mutex);
	if ((elem = fcp_pass_to_hp(pptr, plun, cip,
	    what, link_cnt, tgt_cnt, flags, 1)) == NULL) {
		mutex_exit(&plun->lun_tgt->tgt_mutex);
		fcp_log(CE_CONT, pptr->port_dip,
		    "Can not pass_to_hp: what: %d; D_ID=%x, LUN=%x\n",
		    what, plun->lun_tgt->tgt_d_id, plun->lun_num);
		return (NDI_FAILURE);
	}
	mutex_exit(&plun->lun_tgt->tgt_mutex);
	mutex_enter(&elem->mutex);
	if (elem->wait) {
		while (elem->wait) {
			cv_wait(&elem->cv, &elem->mutex);
		}
	}
	rval = (elem->result);
	mutex_exit(&elem->mutex);
	mutex_destroy(&elem->mutex);
	cv_destroy(&elem->cv);
	kmem_free(elem, sizeof (struct fcp_hp_elem));
	return (rval);
}

/*
 * pass an element to the hotplug list, and then
 * kick the hotplug thread
 *
 * return Boolean success, i.e. non-zero if all goes well, else zero on error
 *
 * acquires/releases the hotplug mutex
 *
 * called with the target mutex owned
 *
 * memory acquired in NOSLEEP mode
 * NOTE: if wait is set to 1 then the caller is responsible for waiting on
 *	 for the hp daemon to process the request and is responsible for
 *	 freeing the element
 */
static struct fcp_hp_elem *
fcp_pass_to_hp(struct fcp_port *pptr, struct fcp_lun *plun,
    child_info_t *cip, int what, int link_cnt, int tgt_cnt, int flags, int wait)
{
	struct fcp_hp_elem	*elem;
	dev_info_t *pdip;

	ASSERT(pptr != NULL);
	ASSERT(plun != NULL);
	ASSERT(plun->lun_tgt != NULL);
	ASSERT(mutex_owned(&plun->lun_tgt->tgt_mutex));

	/* create space for a hotplug element */
	if ((elem = kmem_zalloc(sizeof (struct fcp_hp_elem), KM_NOSLEEP))
	    == NULL) {
		fcp_log(CE_WARN, NULL,
		    "!can't allocate memory for hotplug element");
		return (NULL);
	}

	/* fill in hotplug element */
	elem->port = pptr;
	elem->lun = plun;
	elem->cip = cip;
	elem->old_lun_mpxio = plun->lun_mpxio;
	elem->what = what;
	elem->flags = flags;
	elem->link_cnt = link_cnt;
	elem->tgt_cnt = tgt_cnt;
	elem->wait = wait;
	mutex_init(&elem->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&elem->cv, NULL, CV_DRIVER, NULL);

	/* schedule the hotplug task */
	pdip = pptr->port_dip;
	mutex_enter(&plun->lun_mutex);
	if (elem->what == FCP_ONLINE || elem->what == FCP_OFFLINE) {
		plun->lun_event_count++;
		elem->event_cnt = plun->lun_event_count;
	}
	mutex_exit(&plun->lun_mutex);
	if (taskq_dispatch(DEVI(pdip)->devi_taskq, fcp_hp_task,
	    (void *)elem, KM_NOSLEEP) == NULL) {
		mutex_enter(&plun->lun_mutex);
		if (elem->what == FCP_ONLINE || elem->what == FCP_OFFLINE) {
			plun->lun_event_count--;
		}
		mutex_exit(&plun->lun_mutex);
		kmem_free(elem, sizeof (*elem));
		return (0);
	}

	return (elem);
}


static void
fcp_retransport_cmd(struct fcp_port *pptr, struct fcp_pkt *cmd)
{
	int			rval;
	struct scsi_address	*ap;
	struct fcp_lun	*plun;
	struct fcp_tgt	*ptgt;
	fc_packet_t	*fpkt;

	ap = &cmd->cmd_pkt->pkt_address;
	plun = ADDR2LUN(ap);
	ptgt = plun->lun_tgt;

	ASSERT(cmd->cmd_flags & CFLAG_IN_QUEUE);

	cmd->cmd_state = FCP_PKT_IDLE;

	mutex_enter(&pptr->port_mutex);
	mutex_enter(&ptgt->tgt_mutex);
	if (((plun->lun_state & (FCP_LUN_BUSY | FCP_LUN_OFFLINE)) == 0) &&
	    (!(pptr->port_state & FCP_STATE_ONLINING))) {
		fc_ulp_rscn_info_t *rscnp;

		cmd->cmd_state = FCP_PKT_ISSUED;

		/*
		 * It is possible for pkt_pd to be NULL if tgt_pd_handle was
		 * originally NULL, hence we try to set it to the pd pointed
		 * to by the SCSI device we're trying to get to.
		 */

		fpkt = cmd->cmd_fp_pkt;
		if ((fpkt->pkt_pd == NULL) && (ptgt->tgt_pd_handle != NULL)) {
			fpkt->pkt_pd = ptgt->tgt_pd_handle;
			/*
			 * We need to notify the transport that we now have a
			 * reference to the remote port handle.
			 */
			fc_ulp_hold_remote_port(ptgt->tgt_pd_handle);
		}

		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);

		ASSERT((cmd->cmd_pkt->pkt_flags & FLAG_NOINTR) == 0);

		/* prepare the packet */

		fcp_prepare_pkt(pptr, cmd, plun);

		rscnp = (fc_ulp_rscn_info_t *)cmd->cmd_fp_pkt->
		    pkt_ulp_rscn_infop;

		cmd->cmd_timeout = cmd->cmd_pkt->pkt_time ?
		    fcp_watchdog_time + cmd->cmd_pkt->pkt_time : 0;

		if (rscnp != NULL) {
			rscnp->ulp_rscn_count =
			    fc_ulp_get_rscn_count(pptr->
			    port_fp_handle);
		}

		rval = fcp_transport(pptr->port_fp_handle,
		    cmd->cmd_fp_pkt, 0);

		if (rval == FC_SUCCESS) {
			return;
		}
		cmd->cmd_state &= ~FCP_PKT_ISSUED;
	} else {
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);
	}

	fcp_queue_pkt(pptr, cmd);
}


static void
fcp_fail_cmd(struct fcp_pkt *cmd, uchar_t reason, uint_t statistics)
{
	ASSERT(cmd->cmd_flags & CFLAG_IN_QUEUE);

	cmd->cmd_flags &= ~CFLAG_IN_QUEUE;
	cmd->cmd_state = FCP_PKT_IDLE;

	cmd->cmd_pkt->pkt_reason = reason;
	cmd->cmd_pkt->pkt_state = 0;
	cmd->cmd_pkt->pkt_statistics = statistics;

	fcp_post_callback(cmd);
}

/*
 *     Function: fcp_queue_pkt
 *
 *  Description: This function queues the packet passed by the caller into
 *		 the list of packets of the FCP port.
 *
 *     Argument: *pptr		FCP port.
 *		 *cmd		FCP packet to queue.
 *
 * Return Value: None
 *
 *	Context: User, Kernel and Interrupt context.
 */
static void
fcp_queue_pkt(struct fcp_port *pptr, struct fcp_pkt *cmd)
{
	ASSERT((cmd->cmd_pkt->pkt_flags & FLAG_NOQUEUE) == NULL);

	mutex_enter(&pptr->port_pkt_mutex);
	cmd->cmd_flags |= CFLAG_IN_QUEUE;
	ASSERT(cmd->cmd_state != FCP_PKT_ISSUED);
	cmd->cmd_timeout = fcp_watchdog_time + FCP_QUEUE_DELAY;

	/*
	 * zero pkt_time means hang around for ever
	 */
	if (cmd->cmd_pkt->pkt_time) {
		if (cmd->cmd_fp_pkt->pkt_timeout > FCP_QUEUE_DELAY) {
			cmd->cmd_fp_pkt->pkt_timeout -= FCP_QUEUE_DELAY;
		} else {
			/*
			 * Indicate the watch thread to fail the
			 * command by setting it to highest value
			 */
			cmd->cmd_timeout = fcp_watchdog_time;
			cmd->cmd_fp_pkt->pkt_timeout = FCP_INVALID_TIMEOUT;
		}
	}

	if (pptr->port_pkt_head) {
		ASSERT(pptr->port_pkt_tail != NULL);

		pptr->port_pkt_tail->cmd_next = cmd;
		pptr->port_pkt_tail = cmd;
	} else {
		ASSERT(pptr->port_pkt_tail == NULL);

		pptr->port_pkt_head = pptr->port_pkt_tail = cmd;
	}
	cmd->cmd_next = NULL;
	mutex_exit(&pptr->port_pkt_mutex);
}

/*
 *     Function: fcp_update_targets
 *
 *  Description: This function applies the specified change of state to all
 *		 the targets listed.  The operation applied is 'set'.
 *
 *     Argument: *pptr		FCP port.
 *		 *dev_list	Array of fc_portmap_t structures.
 *		 count		Length of dev_list.
 *		 state		State bits to update.
 *		 cause		Reason for the update.
 *
 * Return Value: None
 *
 *	Context: User, Kernel and Interrupt context.
 *		 The mutex pptr->port_mutex must be held.
 */
static void
fcp_update_targets(struct fcp_port *pptr, fc_portmap_t *dev_list,
    uint32_t count, uint32_t state, int cause)
{
	fc_portmap_t		*map_entry;
	struct fcp_tgt	*ptgt;

	ASSERT(MUTEX_HELD(&pptr->port_mutex));

	while (count--) {
		map_entry = &(dev_list[count]);
		ptgt = fcp_lookup_target(pptr,
		    (uchar_t *)&(map_entry->map_pwwn));
		if (ptgt == NULL) {
			continue;
		}

		mutex_enter(&ptgt->tgt_mutex);
		ptgt->tgt_trace = 0;
		ptgt->tgt_change_cnt++;
		ptgt->tgt_statec_cause = cause;
		ptgt->tgt_tmp_cnt = 1;
		fcp_update_tgt_state(ptgt, FCP_SET, state);
		mutex_exit(&ptgt->tgt_mutex);
	}
}

static int
fcp_call_finish_init(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int lcount, int tcount, int cause)
{
	int rval;

	mutex_enter(&pptr->port_mutex);
	rval = fcp_call_finish_init_held(pptr, ptgt, lcount, tcount, cause);
	mutex_exit(&pptr->port_mutex);

	return (rval);
}


static int
fcp_call_finish_init_held(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    int lcount, int tcount, int cause)
{
	int	finish_init = 0;
	int	finish_tgt = 0;
	int	do_finish_init = 0;
	int	rval = FCP_NO_CHANGE;

	if (cause == FCP_CAUSE_LINK_CHANGE ||
	    cause == FCP_CAUSE_LINK_DOWN) {
		do_finish_init = 1;
	}

	if (ptgt != NULL) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_2, 0,
		    "link_cnt: %d,%d; tgt_cnt: %d,%d; tmp_cnt: %d,%d;"
		    " cause = %d, d_id = 0x%x, tgt_done = %d",
		    pptr->port_link_cnt, lcount, ptgt->tgt_change_cnt, tcount,
		    pptr->port_tmp_cnt, ptgt->tgt_tmp_cnt, cause,
		    ptgt->tgt_d_id, ptgt->tgt_done);

		mutex_enter(&ptgt->tgt_mutex);

		if (tcount && (ptgt->tgt_change_cnt != tcount)) {
			rval = FCP_DEV_CHANGE;
			if (do_finish_init && ptgt->tgt_done == 0) {
				ptgt->tgt_done++;
				finish_init = 1;
			}
		} else {
			if (--ptgt->tgt_tmp_cnt <= 0) {
				ptgt->tgt_tmp_cnt = 0;
				finish_tgt = 1;

				if (do_finish_init) {
					finish_init = 1;
				}
			}
		}
		mutex_exit(&ptgt->tgt_mutex);
	} else {
		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_2, 0,
		    "Call Finish Init for NO target");

		if (do_finish_init) {
			finish_init = 1;
		}
	}

	if (finish_tgt) {
		ASSERT(ptgt != NULL);

		mutex_enter(&ptgt->tgt_mutex);
#ifdef	DEBUG
		bzero(ptgt->tgt_tmp_cnt_stack,
		    sizeof (ptgt->tgt_tmp_cnt_stack));

		ptgt->tgt_tmp_cnt_depth = getpcstack(ptgt->tgt_tmp_cnt_stack,
		    FCP_STACK_DEPTH);
#endif /* DEBUG */
		mutex_exit(&ptgt->tgt_mutex);

		(void) fcp_finish_tgt(pptr, ptgt, lcount, tcount, cause);
	}

	if (finish_init && lcount == pptr->port_link_cnt) {
		ASSERT(pptr->port_tmp_cnt > 0);
		if (--pptr->port_tmp_cnt == 0) {
			fcp_finish_init(pptr);
		}
	} else if (lcount != pptr->port_link_cnt) {
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_2, 0,
		    "fcp_call_finish_init_held,1: state change occured"
		    " for D_ID=0x%x", (ptgt) ? ptgt->tgt_d_id : 0);
	}

	return (rval);
}

static void
fcp_reconfigure_luns(void * tgt_handle)
{
	uint32_t		dev_cnt;
	fc_portmap_t		*devlist;
	struct fcp_tgt	*ptgt = (struct fcp_tgt *)tgt_handle;
	struct fcp_port		*pptr = ptgt->tgt_port;

	/*
	 * If the timer that fires this off got canceled too late, the
	 * target could have been destroyed.
	 */

	if (ptgt->tgt_tid == NULL) {
		return;
	}

	devlist = kmem_zalloc(sizeof (*devlist), KM_NOSLEEP);
	if (devlist == NULL) {
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp%d: failed to allocate for portmap",
		    pptr->port_instance);
		return;
	}

	dev_cnt = 1;
	devlist->map_pd = ptgt->tgt_pd_handle;
	devlist->map_hard_addr.hard_addr = ptgt->tgt_hard_addr;
	devlist->map_did.port_id = ptgt->tgt_d_id;

	bcopy(&ptgt->tgt_node_wwn.raw_wwn[0], &devlist->map_nwwn, FC_WWN_SIZE);
	bcopy(&ptgt->tgt_port_wwn.raw_wwn[0], &devlist->map_pwwn, FC_WWN_SIZE);

	devlist->map_state = PORT_DEVICE_LOGGED_IN;
	devlist->map_type = PORT_DEVICE_REPORTLUN_CHANGED;
	devlist->map_flags = 0;

	fcp_statec_callback(NULL, pptr->port_fp_handle, FC_STATE_DEVICE_CHANGE,
	    pptr->port_topology, devlist, dev_cnt, pptr->port_id);

	/*
	 * Clear the tgt_tid after no more references to
	 * the fcp_tgt
	 */
	mutex_enter(&ptgt->tgt_mutex);
	ptgt->tgt_tid = NULL;
	mutex_exit(&ptgt->tgt_mutex);

	kmem_free(devlist, sizeof (*devlist));
}


static void
fcp_free_targets(struct fcp_port *pptr)
{
	int			i;
	struct fcp_tgt	*ptgt;

	mutex_enter(&pptr->port_mutex);
	for (i = 0; i < FCP_NUM_HASH; i++) {
		ptgt = pptr->port_tgt_hash_table[i];
		while (ptgt != NULL) {
			struct fcp_tgt *next_tgt = ptgt->tgt_next;

			fcp_free_target(ptgt);
			ptgt = next_tgt;
		}
	}
	mutex_exit(&pptr->port_mutex);
}


static void
fcp_free_target(struct fcp_tgt *ptgt)
{
	struct fcp_lun	*plun;
	timeout_id_t		tid;

	mutex_enter(&ptgt->tgt_mutex);
	tid = ptgt->tgt_tid;

	/*
	 * Cancel any pending timeouts for this target.
	 */

	if (tid != NULL) {
		/*
		 * Set tgt_tid to NULL first to avoid a race in the callback.
		 * If tgt_tid is NULL, the callback will simply return.
		 */
		ptgt->tgt_tid = NULL;
		mutex_exit(&ptgt->tgt_mutex);
		(void) untimeout(tid);
		mutex_enter(&ptgt->tgt_mutex);
	}

	plun = ptgt->tgt_lun;
	while (plun != NULL) {
		struct fcp_lun *next_lun = plun->lun_next;

		fcp_dealloc_lun(plun);
		plun = next_lun;
	}

	mutex_exit(&ptgt->tgt_mutex);
	fcp_dealloc_tgt(ptgt);
}

/*
 *     Function: fcp_is_retryable
 *
 *  Description: Indicates if the internal packet is retryable.
 *
 *     Argument: *icmd		FCP internal packet.
 *
 * Return Value: 0	Not retryable
 *		 1	Retryable
 *
 *	Context: User, Kernel and Interrupt context
 */
static int
fcp_is_retryable(struct fcp_ipkt *icmd)
{
	if (icmd->ipkt_port->port_state & (FCP_STATE_SUSPENDED |
	    FCP_STATE_DETACHING | FCP_STATE_POWER_DOWN)) {
		return (0);
	}

	return (((fcp_watchdog_time + icmd->ipkt_fpkt->pkt_timeout) <
	    icmd->ipkt_port->port_deadline) ? 1 : 0);
}

/*
 *     Function: fcp_create_on_demand
 *
 *     Argument: *pptr		FCP port.
 *		 *pwwn		Port WWN.
 *
 * Return Value: 0	Success
 *		 EIO
 *		 ENOMEM
 *		 EBUSY
 *		 EINVAL
 *
 *	Context: User and Kernel context
 */
static int
fcp_create_on_demand(struct fcp_port *pptr, uchar_t *pwwn)
{
	int			wait_ms;
	int			tcount;
	int			lcount;
	int			ret;
	int			error;
	int			rval = EIO;
	int			ntries;
	fc_portmap_t		*devlist;
	opaque_t		pd;
	struct fcp_lun		*plun;
	struct fcp_tgt		*ptgt;
	int			old_manual = 0;

	/* Allocates the fc_portmap_t structure. */
	devlist = kmem_zalloc(sizeof (*devlist), KM_SLEEP);

	/*
	 * If FC_INVALID_RSCN_COUNT is non-zero, we will have to init as shown
	 * in the commented statement below:
	 *
	 * devlist->map_rscn_info.ulp_rscn_count = FC_INVALID_RSCN_COUNT;
	 *
	 * Below, the deadline for the discovery process is set.
	 */
	mutex_enter(&pptr->port_mutex);
	pptr->port_deadline = fcp_watchdog_time + FCP_ICMD_DEADLINE;
	mutex_exit(&pptr->port_mutex);

	/*
	 * We try to find the remote port based on the WWN provided by the
	 * caller.  We actually ask fp/fctl if it has it.
	 */
	pd = fc_ulp_get_remote_port(pptr->port_fp_handle,
	    (la_wwn_t *)pwwn, &error, 1);

	if (pd == NULL) {
		kmem_free(devlist, sizeof (*devlist));
		return (rval);
	}

	/*
	 * The remote port was found.  We ask fp/fctl to update our
	 * fc_portmap_t structure.
	 */
	ret = fc_ulp_pwwn_to_portmap(pptr->port_fp_handle,
	    (la_wwn_t *)pwwn, devlist);
	if (ret != FC_SUCCESS) {
		kmem_free(devlist, sizeof (*devlist));
		return (rval);
	}

	/*
	 * The map flag field is set to indicates that the creation is being
	 * done at the user request (Ioclt probably luxadm or cfgadm).
	 */
	devlist->map_type = PORT_DEVICE_USER_CREATE;

	mutex_enter(&pptr->port_mutex);

	/*
	 * We check to see if fcp already has a target that describes the
	 * device being created.  If not it is created.
	 */
	ptgt = fcp_lookup_target(pptr, pwwn);
	if (ptgt == NULL) {
		lcount = pptr->port_link_cnt;
		mutex_exit(&pptr->port_mutex);

		ptgt = fcp_alloc_tgt(pptr, devlist, lcount);
		if (ptgt == NULL) {
			fcp_log(CE_WARN, pptr->port_dip,
			    "!FC target allocation failed");
			return (ENOMEM);
		}

		mutex_enter(&pptr->port_mutex);
	}

	mutex_enter(&ptgt->tgt_mutex);
	ptgt->tgt_statec_cause = FCP_CAUSE_USER_CREATE;
	ptgt->tgt_tmp_cnt = 1;
	ptgt->tgt_device_created = 0;
	/*
	 * If fabric and auto config is set but the target was
	 * manually unconfigured then reset to the manual_config_only to
	 * 0 so the device will get configured.
	 */
	if (FC_TOP_EXTERNAL(pptr->port_topology) &&
	    fcp_enable_auto_configuration &&
	    ptgt->tgt_manual_config_only == 1) {
		old_manual = 1;
		ptgt->tgt_manual_config_only = 0;
	}
	mutex_exit(&ptgt->tgt_mutex);

	fcp_update_targets(pptr, devlist, 1,
	    FCP_LUN_BUSY | FCP_LUN_MARK, FCP_CAUSE_USER_CREATE);

	lcount = pptr->port_link_cnt;
	tcount = ptgt->tgt_change_cnt;

	if (fcp_handle_mapflags(pptr, ptgt, devlist, lcount,
	    tcount, FCP_CAUSE_USER_CREATE) == TRUE) {
		if (FC_TOP_EXTERNAL(pptr->port_topology) &&
		    fcp_enable_auto_configuration && old_manual) {
			mutex_enter(&ptgt->tgt_mutex);
			ptgt->tgt_manual_config_only = 1;
			mutex_exit(&ptgt->tgt_mutex);
		}

		if (pptr->port_link_cnt != lcount ||
		    ptgt->tgt_change_cnt != tcount) {
			rval = EBUSY;
		}
		mutex_exit(&pptr->port_mutex);

		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_3, 0,
		    "fcp_create_on_demand: mapflags ptgt=%x, "
		    "lcount=%x::port_link_cnt=%x, "
		    "tcount=%x: tgt_change_cnt=%x, rval=%x",
		    ptgt, lcount, pptr->port_link_cnt,
		    tcount, ptgt->tgt_change_cnt, rval);
		return (rval);
	}

	/*
	 * Due to lack of synchronization mechanisms, we perform
	 * periodic monitoring of our request; Because requests
	 * get dropped when another one supercedes (either because
	 * of a link change or a target change), it is difficult to
	 * provide a clean synchronization mechanism (such as a
	 * semaphore or a conditional variable) without exhaustively
	 * rewriting the mainline discovery code of this driver.
	 */
	wait_ms = 500;

	ntries = fcp_max_target_retries;

	FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
	    FCP_BUF_LEVEL_3, 0,
	    "fcp_create_on_demand(1): ntries=%x, ptgt=%x, "
	    "lcount=%x::port_link_cnt=%x, "
	    "tcount=%x::tgt_change_cnt=%x, rval=%x, tgt_device_created=%x "
	    "tgt_tmp_cnt =%x",
	    ntries, ptgt, lcount, pptr->port_link_cnt,
	    tcount, ptgt->tgt_change_cnt, rval, ptgt->tgt_device_created,
	    ptgt->tgt_tmp_cnt);

	mutex_enter(&ptgt->tgt_mutex);
	while (ntries-- != 0 && pptr->port_link_cnt == lcount &&
	    ptgt->tgt_change_cnt == tcount && ptgt->tgt_device_created == 0) {
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);

		delay(drv_usectohz(wait_ms * 1000));

		mutex_enter(&pptr->port_mutex);
		mutex_enter(&ptgt->tgt_mutex);
	}


	if (pptr->port_link_cnt != lcount || ptgt->tgt_change_cnt != tcount) {
		rval = EBUSY;
	} else {
		if (ptgt->tgt_tmp_cnt == 0 && ptgt->tgt_node_state ==
		    FCP_TGT_NODE_PRESENT) {
			rval = 0;
		}
	}

	FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
	    FCP_BUF_LEVEL_3, 0,
	    "fcp_create_on_demand(2): ntries=%x, ptgt=%x, "
	    "lcount=%x::port_link_cnt=%x, "
	    "tcount=%x::tgt_change_cnt=%x, rval=%x, tgt_device_created=%x "
	    "tgt_tmp_cnt =%x",
	    ntries, ptgt, lcount, pptr->port_link_cnt,
	    tcount, ptgt->tgt_change_cnt, rval, ptgt->tgt_device_created,
	    ptgt->tgt_tmp_cnt);

	if (rval) {
		if (FC_TOP_EXTERNAL(pptr->port_topology) &&
		    fcp_enable_auto_configuration && old_manual) {
			ptgt->tgt_manual_config_only = 1;
		}
		mutex_exit(&ptgt->tgt_mutex);
		mutex_exit(&pptr->port_mutex);
		kmem_free(devlist, sizeof (*devlist));

		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_3, 0,
		    "fcp_create_on_demand(3): ntries=%x, ptgt=%x, "
		    "lcount=%x::port_link_cnt=%x, "
		    "tcount=%x::tgt_change_cnt=%x, rval=%x, "
		    "tgt_device_created=%x, tgt D_ID=%x",
		    ntries, ptgt, lcount, pptr->port_link_cnt,
		    tcount, ptgt->tgt_change_cnt, rval,
		    ptgt->tgt_device_created, ptgt->tgt_d_id);
		return (rval);
	}

	if ((plun = ptgt->tgt_lun) != NULL) {
		tcount = plun->lun_tgt->tgt_change_cnt;
	} else {
		rval = EINVAL;
	}
	lcount = pptr->port_link_cnt;

	/*
	 * Configuring the target with no LUNs will fail. We
	 * should reset the node state so that it is not
	 * automatically configured when the LUNs are added
	 * to this target.
	 */
	if (ptgt->tgt_lun_cnt == 0) {
		ptgt->tgt_node_state = FCP_TGT_NODE_NONE;
	}
	mutex_exit(&ptgt->tgt_mutex);
	mutex_exit(&pptr->port_mutex);

	while (plun) {
		child_info_t	*cip;

		mutex_enter(&plun->lun_mutex);
		cip = plun->lun_cip;
		mutex_exit(&plun->lun_mutex);

		mutex_enter(&ptgt->tgt_mutex);
		if (!(plun->lun_state & FCP_LUN_OFFLINE)) {
			mutex_exit(&ptgt->tgt_mutex);

			rval = fcp_pass_to_hp_and_wait(pptr, plun, cip,
			    FCP_ONLINE, lcount, tcount,
			    NDI_ONLINE_ATTACH);
			if (rval != NDI_SUCCESS) {
				FCP_TRACE(fcp_logq,
				    pptr->port_instbuf, fcp_trace,
				    FCP_BUF_LEVEL_3, 0,
				    "fcp_create_on_demand: "
				    "pass_to_hp_and_wait failed "
				    "rval=%x", rval);
				rval = EIO;
			} else {
				mutex_enter(&LUN_TGT->tgt_mutex);
				plun->lun_state &= ~(FCP_LUN_OFFLINE |
				    FCP_LUN_BUSY);
				mutex_exit(&LUN_TGT->tgt_mutex);
			}
			mutex_enter(&ptgt->tgt_mutex);
		}

		plun = plun->lun_next;
		mutex_exit(&ptgt->tgt_mutex);
	}

	kmem_free(devlist, sizeof (*devlist));

	if (FC_TOP_EXTERNAL(pptr->port_topology) &&
	    fcp_enable_auto_configuration && old_manual) {
		mutex_enter(&ptgt->tgt_mutex);
		/* if successful then set manual to 0 */
		if (rval == 0) {
			ptgt->tgt_manual_config_only = 0;
		} else {
			/* reset to 1 so the user has to do the config */
			ptgt->tgt_manual_config_only = 1;
		}
		mutex_exit(&ptgt->tgt_mutex);
	}

	return (rval);
}


static void
fcp_ascii_to_wwn(caddr_t string, uchar_t bytes[], unsigned int byte_len)
{
	int		count;
	uchar_t		byte;

	count = 0;
	while (*string) {
		byte = FCP_ATOB(*string); string++;
		byte = byte << 4 | FCP_ATOB(*string); string++;
		bytes[count++] = byte;

		if (count >= byte_len) {
			break;
		}
	}
}

static void
fcp_wwn_to_ascii(uchar_t wwn[], char *string)
{
	int		i;

	for (i = 0; i < FC_WWN_SIZE; i++) {
		(void) sprintf(string + (i * 2),
		    "%02x", wwn[i]);
	}

}

static void
fcp_print_error(fc_packet_t *fpkt)
{
	struct fcp_ipkt	*icmd = (struct fcp_ipkt *)
	    fpkt->pkt_ulp_private;
	struct fcp_port	*pptr;
	struct fcp_tgt	*ptgt;
	struct fcp_lun	*plun;
	caddr_t			buf;
	int			scsi_cmd = 0;

	ptgt = icmd->ipkt_tgt;
	plun = icmd->ipkt_lun;
	pptr = ptgt->tgt_port;

	buf = kmem_zalloc(256, KM_NOSLEEP);
	if (buf == NULL) {
		return;
	}

	switch (icmd->ipkt_opcode) {
	case SCMD_REPORT_LUN:
		(void) sprintf(buf, "!REPORT LUN to D_ID=0x%%x"
		    " lun=0x%%x failed");
		scsi_cmd++;
		break;

	case SCMD_INQUIRY_PAGE83:
		(void) sprintf(buf, "!INQUIRY-83 to D_ID=0x%%x"
		    " lun=0x%%x failed");
		scsi_cmd++;
		break;

	case SCMD_INQUIRY:
		(void) sprintf(buf, "!INQUIRY to D_ID=0x%%x"
		    " lun=0x%%x failed");
		scsi_cmd++;
		break;

	case LA_ELS_PLOGI:
		(void) sprintf(buf, "!PLOGI to D_ID=0x%%x failed");
		break;

	case LA_ELS_PRLI:
		(void) sprintf(buf, "!PRLI to D_ID=0x%%x failed");
		break;
	}

	if (scsi_cmd && fpkt->pkt_state == FC_PKT_SUCCESS) {
		struct fcp_rsp		response, *rsp;
		uchar_t			asc, ascq;
		caddr_t			sense_key = NULL;
		struct fcp_rsp_info	fcp_rsp_err, *bep;

		if (icmd->ipkt_nodma) {
			rsp = (struct fcp_rsp *)fpkt->pkt_resp;
			bep = (struct fcp_rsp_info *)((caddr_t)rsp +
			    sizeof (struct fcp_rsp));
		} else {
			rsp = &response;
			bep = &fcp_rsp_err;

			FCP_CP_IN(fpkt->pkt_resp, rsp, fpkt->pkt_resp_acc,
			    sizeof (struct fcp_rsp));

			FCP_CP_IN(fpkt->pkt_resp + sizeof (struct fcp_rsp),
			    bep, fpkt->pkt_resp_acc,
			    sizeof (struct fcp_rsp_info));
		}


		if (fcp_validate_fcp_response(rsp, pptr) != FC_SUCCESS) {
			(void) sprintf(buf + strlen(buf),
			    " : Bad FCP response values rsvd1=%%x, rsvd2=%%x,"
			    " sts-rsvd1=%%x, sts-rsvd2=%%x, rsplen=%%x,"
			    " senselen=%%x. Giving up");

			fcp_log(CE_WARN, pptr->port_dip, buf,
			    ptgt->tgt_d_id, plun->lun_num, rsp->reserved_0,
			    rsp->reserved_1, rsp->fcp_u.fcp_status.reserved_0,
			    rsp->fcp_u.fcp_status.reserved_1,
			    rsp->fcp_response_len, rsp->fcp_sense_len);

			kmem_free(buf, 256);
			return;
		}

		if (rsp->fcp_u.fcp_status.rsp_len_set &&
		    bep->rsp_code != FCP_NO_FAILURE) {
			(void) sprintf(buf + strlen(buf),
			    " FCP Response code = 0x%x", bep->rsp_code);
		}

		if (rsp->fcp_u.fcp_status.scsi_status & STATUS_CHECK) {
			struct scsi_extended_sense sense_info, *sense_ptr;

			if (icmd->ipkt_nodma) {
				sense_ptr = (struct scsi_extended_sense *)
				    ((caddr_t)fpkt->pkt_resp +
				    sizeof (struct fcp_rsp) +
				    rsp->fcp_response_len);
			} else {
				sense_ptr = &sense_info;

				FCP_CP_IN(fpkt->pkt_resp +
				    sizeof (struct fcp_rsp) +
				    rsp->fcp_response_len, &sense_info,
				    fpkt->pkt_resp_acc,
				    sizeof (struct scsi_extended_sense));
			}

			if (sense_ptr->es_key < NUM_SENSE_KEYS +
			    NUM_IMPL_SENSE_KEYS) {
				sense_key = sense_keys[sense_ptr->es_key];
			} else {
				sense_key = "Undefined";
			}

			asc = sense_ptr->es_add_code;
			ascq = sense_ptr->es_qual_code;

			(void) sprintf(buf + strlen(buf),
			    ": sense key=%%s, ASC=%%x," " ASCQ=%%x."
			    " Giving up");

			fcp_log(CE_WARN, pptr->port_dip, buf,
			    ptgt->tgt_d_id, plun->lun_num, sense_key,
			    asc, ascq);
		} else {
			(void) sprintf(buf + strlen(buf),
			    " : SCSI status=%%x. Giving up");

			fcp_log(CE_WARN, pptr->port_dip, buf,
			    ptgt->tgt_d_id, plun->lun_num,
			    rsp->fcp_u.fcp_status.scsi_status);
		}
	} else {
		caddr_t state, reason, action, expln;

		(void) fc_ulp_pkt_error(fpkt, &state, &reason,
		    &action, &expln);

		(void) sprintf(buf + strlen(buf), ": State:%%s,"
		    " Reason:%%s. Giving up");

		if (scsi_cmd) {
			fcp_log(CE_WARN, pptr->port_dip, buf,
			    ptgt->tgt_d_id, plun->lun_num, state, reason);
		} else {
			fcp_log(CE_WARN, pptr->port_dip, buf,
			    ptgt->tgt_d_id, state, reason);
		}
	}

	kmem_free(buf, 256);
}


static int
fcp_handle_ipkt_errors(struct fcp_port *pptr, struct fcp_tgt *ptgt,
    struct fcp_ipkt *icmd, int rval, caddr_t op)
{
	int	ret = DDI_FAILURE;
	char	*error;

	switch (rval) {
	case FC_DEVICE_BUSY_NEW_RSCN:
		/*
		 * This means that there was a new RSCN that the transport
		 * knows about (which the ULP *may* know about too) but the
		 * pkt that was sent down was related to an older RSCN. So, we
		 * are just going to reset the retry count and deadline and
		 * continue to retry. The idea is that transport is currently
		 * working on the new RSCN and will soon let the ULPs know
		 * about it and when it does the existing logic will kick in
		 * where it will change the tcount to indicate that something
		 * changed on the target. So, rediscovery will start and there
		 * will not be an infinite retry.
		 *
		 * For a full flow of how the RSCN info is transferred back and
		 * forth, see fp.c
		 */
		icmd->ipkt_retries = 0;
		icmd->ipkt_port->port_deadline = fcp_watchdog_time +
		    FCP_ICMD_DEADLINE;

		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_3, 0,
		    "fcp_handle_ipkt_errors: rval=%x  for D_ID=%x",
		    rval, ptgt->tgt_d_id);
		/* FALLTHROUGH */

	case FC_STATEC_BUSY:
	case FC_DEVICE_BUSY:
	case FC_PBUSY:
	case FC_FBUSY:
	case FC_TRAN_BUSY:
	case FC_OFFLINE:
		FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
		    FCP_BUF_LEVEL_3, 0,
		    "fcp_handle_ipkt_errors: rval=%x  for D_ID=%x",
		    rval, ptgt->tgt_d_id);
		if (icmd->ipkt_retries < FCP_MAX_RETRIES &&
		    fcp_is_retryable(icmd)) {
			fcp_queue_ipkt(pptr, icmd->ipkt_fpkt);
			ret = DDI_SUCCESS;
		}
		break;

	case FC_LOGINREQ:
		/*
		 * FC_LOGINREQ used to be handled just like all the cases
		 * above. It has been changed to handled a PRLI that fails
		 * with FC_LOGINREQ different than other ipkts that fail
		 * with FC_LOGINREQ. If a PRLI fails with FC_LOGINREQ it is
		 * a simple matter to turn it into a PLOGI instead, so that's
		 * exactly what we do here.
		 */
		if (icmd->ipkt_opcode == LA_ELS_PRLI) {
			ret = fcp_send_els(icmd->ipkt_port, icmd->ipkt_tgt,
			    icmd, LA_ELS_PLOGI, icmd->ipkt_link_cnt,
			    icmd->ipkt_change_cnt, icmd->ipkt_cause);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf, fcp_trace,
			    FCP_BUF_LEVEL_3, 0,
			    "fcp_handle_ipkt_errors: rval=%x  for D_ID=%x",
			    rval, ptgt->tgt_d_id);
			if (icmd->ipkt_retries < FCP_MAX_RETRIES &&
			    fcp_is_retryable(icmd)) {
				fcp_queue_ipkt(pptr, icmd->ipkt_fpkt);
				ret = DDI_SUCCESS;
			}
		}
		break;

	default:
		mutex_enter(&pptr->port_mutex);
		mutex_enter(&ptgt->tgt_mutex);
		if (!FCP_STATE_CHANGED(pptr, ptgt, icmd)) {
			mutex_exit(&ptgt->tgt_mutex);
			mutex_exit(&pptr->port_mutex);

			(void) fc_ulp_error(rval, &error);
			fcp_log(CE_WARN, pptr->port_dip,
			    "!Failed to send %s to D_ID=%x error=%s",
			    op, ptgt->tgt_d_id, error);
		} else {
			FCP_TRACE(fcp_logq, pptr->port_instbuf,
			    fcp_trace, FCP_BUF_LEVEL_2, 0,
			    "fcp_handle_ipkt_errors,1: state change occured"
			    " for D_ID=0x%x", ptgt->tgt_d_id);
			mutex_exit(&ptgt->tgt_mutex);
			mutex_exit(&pptr->port_mutex);
		}
		break;
	}

	return (ret);
}


/*
 * Check of outstanding commands on any LUN for this target
 */
static int
fcp_outstanding_lun_cmds(struct fcp_tgt *ptgt)
{
	struct	fcp_lun	*plun;
	struct	fcp_pkt	*cmd;

	for (plun = ptgt->tgt_lun; plun != NULL; plun = plun->lun_next) {
		mutex_enter(&plun->lun_mutex);
		for (cmd = plun->lun_pkt_head; cmd != NULL;
		    cmd = cmd->cmd_forw) {
			if (cmd->cmd_state == FCP_PKT_ISSUED) {
				mutex_exit(&plun->lun_mutex);
				return (FC_SUCCESS);
			}
		}
		mutex_exit(&plun->lun_mutex);
	}

	return (FC_FAILURE);
}

static fc_portmap_t *
fcp_construct_map(struct fcp_port *pptr, uint32_t *dev_cnt)
{
	int			i;
	fc_portmap_t		*devlist;
	fc_portmap_t		*devptr = NULL;
	struct fcp_tgt	*ptgt;

	mutex_enter(&pptr->port_mutex);
	for (i = 0, *dev_cnt = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			if (!(ptgt->tgt_state & FCP_TGT_ORPHAN)) {
				++*dev_cnt;
			}
		}
	}

	devptr = devlist = kmem_zalloc(sizeof (*devlist) * *dev_cnt,
	    KM_NOSLEEP);
	if (devlist == NULL) {
		mutex_exit(&pptr->port_mutex);
		fcp_log(CE_WARN, pptr->port_dip,
		    "!fcp%d: failed to allocate for portmap for construct map",
		    pptr->port_instance);
		return (devptr);
	}

	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			if (!(ptgt->tgt_state & FCP_TGT_ORPHAN)) {
				int ret;

				ret = fc_ulp_pwwn_to_portmap(
				    pptr->port_fp_handle,
				    (la_wwn_t *)&ptgt->tgt_port_wwn.raw_wwn[0],
				    devlist);

				if (ret == FC_SUCCESS) {
					devlist++;
					continue;
				}

				devlist->map_pd = NULL;
				devlist->map_did.port_id = ptgt->tgt_d_id;
				devlist->map_hard_addr.hard_addr =
				    ptgt->tgt_hard_addr;

				devlist->map_state = PORT_DEVICE_INVALID;
				devlist->map_type = PORT_DEVICE_OLD;

				bcopy(&ptgt->tgt_node_wwn.raw_wwn[0],
				    &devlist->map_nwwn, FC_WWN_SIZE);

				bcopy(&ptgt->tgt_port_wwn.raw_wwn[0],
				    &devlist->map_pwwn, FC_WWN_SIZE);

				devlist++;
			}
		}
	}

	mutex_exit(&pptr->port_mutex);

	return (devptr);
}
/*
 * Inimate MPxIO that the lun is busy and cannot accept regular IO
 */
static void
fcp_update_mpxio_path_verifybusy(struct fcp_port *pptr)
{
	int i;
	struct fcp_tgt	*ptgt;
	struct fcp_lun	*plun;

	for (i = 0; i < FCP_NUM_HASH; i++) {
		for (ptgt = pptr->port_tgt_hash_table[i]; ptgt != NULL;
		    ptgt = ptgt->tgt_next) {
			mutex_enter(&ptgt->tgt_mutex);
			for (plun = ptgt->tgt_lun; plun != NULL;
			    plun = plun->lun_next) {
				if (plun->lun_mpxio &&
				    plun->lun_state & FCP_LUN_BUSY) {
					if (!fcp_pass_to_hp(pptr, plun,
					    plun->lun_cip,
					    FCP_MPXIO_PATH_SET_BUSY,
					    pptr->port_link_cnt,
					    ptgt->tgt_change_cnt, 0, 0)) {
						FCP_TRACE(fcp_logq,
						    pptr->port_instbuf,
						    fcp_trace,
						    FCP_BUF_LEVEL_2, 0,
						    "path_verifybusy: "
						    "disable lun %p failed!",
						    plun);
					}
				}
			}
			mutex_exit(&ptgt->tgt_mutex);
		}
	}
}

static int
fcp_update_mpxio_path(struct fcp_lun *plun, child_info_t *cip, int what)
{
	dev_info_t		*cdip = NULL;
	dev_info_t		*pdip = NULL;

	ASSERT(plun);

	mutex_enter(&plun->lun_mutex);
	if (fcp_is_child_present(plun, cip) == FC_FAILURE) {
		mutex_exit(&plun->lun_mutex);
		return (NDI_FAILURE);
	}
	mutex_exit(&plun->lun_mutex);
	cdip = mdi_pi_get_client(PIP(cip));
	pdip = mdi_pi_get_phci(PIP(cip));

	ASSERT(cdip != NULL);
	ASSERT(pdip != NULL);

	if (what == FCP_MPXIO_PATH_CLEAR_BUSY) {
		/* LUN ready for IO */
		(void) mdi_pi_enable_path(PIP(cip), DRIVER_DISABLE_TRANSIENT);
	} else {
		/* LUN busy to accept IO */
		(void) mdi_pi_disable_path(PIP(cip), DRIVER_DISABLE_TRANSIENT);
	}
	return (NDI_SUCCESS);
}

/*
 * Caller must free the returned string of MAXPATHLEN len
 * If the device is offline (-1 instance number) NULL
 * will be returned.
 */
static char *
fcp_get_lun_path(struct fcp_lun *plun)
{
	dev_info_t	*dip = NULL;
	char		*path = NULL;
	mdi_pathinfo_t	*pip = NULL;

	if (plun == NULL) {
		return (NULL);
	}

	mutex_enter(&plun->lun_mutex);
	if (plun->lun_mpxio == 0) {
		dip = DIP(plun->lun_cip);
		mutex_exit(&plun->lun_mutex);
	} else {
		/*
		 * lun_cip must be accessed with lun_mutex held. Here
		 * plun->lun_cip either points to a valid node or it is NULL.
		 * Make a copy so that we can release lun_mutex.
		 */
		pip = PIP(plun->lun_cip);

		/*
		 * Increase ref count on the path so that we can release
		 * lun_mutex and still be sure that the pathinfo node (and thus
		 * also the client) is not deallocated. If pip is NULL, this
		 * has no effect.
		 */
		mdi_hold_path(pip);

		mutex_exit(&plun->lun_mutex);

		/* Get the client. If pip is NULL, we get NULL. */
		dip = mdi_pi_get_client(pip);
	}

	if (dip == NULL)
		goto out;
	if (ddi_get_instance(dip) < 0)
		goto out;

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (path == NULL)
		goto out;

	(void) ddi_pathname(dip, path);

	/* Clean up. */
out:
	if (pip != NULL)
		mdi_rele_path(pip);

	/*
	 * In reality, the user wants a fully valid path (one they can open)
	 * but this string is lacking the mount point, and the minor node.
	 * It would be nice if we could "figure these out" somehow
	 * and fill them in.  Otherwise, the userland code has to understand
	 * driver specific details of which minor node is the "best" or
	 * "right" one to expose.  (Ex: which slice is the whole disk, or
	 * which tape doesn't rewind)
	 */
	return (path);
}

static int
fcp_scsi_bus_config(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int64_t reset_delay;
	int rval, retry = 0;
	struct fcp_port *pptr = fcp_dip2port(parent);

	reset_delay = (int64_t)(USEC_TO_TICK(FCP_INIT_WAIT_TIMEOUT)) -
	    (ddi_get_lbolt64() - pptr->port_attach_time);
	if (reset_delay < 0) {
		reset_delay = 0;
	}

	if (fcp_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	switch (op) {
	case BUS_CONFIG_ONE:
		/*
		 * Retry the command since we need to ensure
		 * the fabric devices are available for root
		 */
		while (retry++ < fcp_max_bus_config_retries) {
			rval =	(ndi_busop_bus_config(parent,
			    flag | NDI_MDI_FALLBACK, op,
			    arg, childp, (clock_t)reset_delay));
			if (rval == 0) {
				return (rval);
			}
		}

		/*
		 * drain taskq to make sure nodes are created and then
		 * try again.
		 */
		taskq_wait(DEVI(parent)->devi_taskq);
		return (ndi_busop_bus_config(parent, flag | NDI_MDI_FALLBACK,
		    op, arg, childp, 0));

	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL: {
		/*
		 * delay till all devices report in (port_tmp_cnt == 0)
		 * or FCP_INIT_WAIT_TIMEOUT
		 */
		mutex_enter(&pptr->port_mutex);
		while ((reset_delay > 0) && pptr->port_tmp_cnt) {
			(void) cv_timedwait(&pptr->port_config_cv,
			    &pptr->port_mutex,
			    ddi_get_lbolt() + (clock_t)reset_delay);
			reset_delay =
			    (int64_t)(USEC_TO_TICK(FCP_INIT_WAIT_TIMEOUT)) -
			    (ddi_get_lbolt64() - pptr->port_attach_time);
		}
		mutex_exit(&pptr->port_mutex);
		/* drain taskq to make sure nodes are created */
		taskq_wait(DEVI(parent)->devi_taskq);
		return (ndi_busop_bus_config(parent, flag, op,
		    arg, childp, 0));
	}

	default:
		return (NDI_FAILURE);
	}
	/*NOTREACHED*/
}

static int
fcp_scsi_bus_unconfig(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg)
{
	if (fcp_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	return (ndi_busop_bus_unconfig(parent, flag, op, arg));
}


/*
 * Routine to copy GUID into the lun structure.
 * returns 0 if copy was successful and 1 if encountered a
 * failure and did not copy the guid.
 */
static int
fcp_copy_guid_2_lun_block(struct fcp_lun *plun, char *guidp)
{

	int retval = 0;

	/* add one for the null terminator */
	const unsigned int len = strlen(guidp) + 1;

	if ((guidp == NULL) || (plun == NULL)) {
		return (1);
	}

	/*
	 * if the plun->lun_guid already has been allocated,
	 * then check the size. if the size is exact, reuse
	 * it....if not free it an allocate the required size.
	 * The reallocation should NOT typically happen
	 * unless the GUIDs reported changes between passes.
	 * We free up and alloc again even if the
	 * size was more than required. This is due to the
	 * fact that the field lun_guid_size - serves
	 * dual role of indicating the size of the wwn
	 * size and ALSO the allocation size.
	 */
	if (plun->lun_guid) {
		if (plun->lun_guid_size != len) {
			/*
			 * free the allocated memory and
			 * initialize the field
			 * lun_guid_size to 0.
			 */
			kmem_free(plun->lun_guid, plun->lun_guid_size);
			plun->lun_guid = NULL;
			plun->lun_guid_size = 0;
		}
	}
	/*
	 * alloc only if not already done.
	 */
	if (plun->lun_guid == NULL) {
		plun->lun_guid = kmem_zalloc(len, KM_NOSLEEP);
		if (plun->lun_guid == NULL) {
			cmn_err(CE_WARN, "fcp_copy_guid_2_lun_block:"
			    "Unable to allocate"
			    "Memory for GUID!!! size %d", len);
			retval = 1;
		} else {
			plun->lun_guid_size = len;
		}
	}
	if (plun->lun_guid) {
		/*
		 * now copy the GUID
		 */
		bcopy(guidp, plun->lun_guid, plun->lun_guid_size);
	}
	return (retval);
}

/*
 * fcp_reconfig_wait
 *
 * Wait for a rediscovery/reconfiguration to complete before continuing.
 */

static void
fcp_reconfig_wait(struct fcp_port *pptr)
{
	clock_t		reconfig_start, wait_timeout;

	/*
	 * Quick check.	 If pptr->port_tmp_cnt is 0, there is no
	 * reconfiguration in progress.
	 */

	mutex_enter(&pptr->port_mutex);
	if (pptr->port_tmp_cnt == 0) {
		mutex_exit(&pptr->port_mutex);
		return;
	}
	mutex_exit(&pptr->port_mutex);

	/*
	 * If we cause a reconfig by raising power, delay until all devices
	 * report in (port_tmp_cnt returns to 0)
	 */

	reconfig_start = ddi_get_lbolt();
	wait_timeout = drv_usectohz(FCP_INIT_WAIT_TIMEOUT);

	mutex_enter(&pptr->port_mutex);

	while (((ddi_get_lbolt() - reconfig_start) < wait_timeout) &&
	    pptr->port_tmp_cnt) {

		(void) cv_timedwait(&pptr->port_config_cv, &pptr->port_mutex,
		    reconfig_start + wait_timeout);
	}

	mutex_exit(&pptr->port_mutex);

	/*
	 * Even if fcp_tmp_count isn't 0, continue without error.  The port
	 * we want may still be ok.  If not, it will error out later
	 */
}

/*
 * Read masking info from fp.conf and construct the global fcp_lun_blacklist.
 * We rely on the fcp_global_mutex to provide protection against changes to
 * the fcp_lun_blacklist.
 *
 * You can describe a list of target port WWNs and LUN numbers which will
 * not be configured. LUN numbers will be interpreted as decimal. White
 * spaces and ',' can be used in the list of LUN numbers.
 *
 * To prevent LUNs 1 and 2 from being configured for target
 * port 510000f010fd92a1 and target port 510000e012079df1, set:
 *
 * pwwn-lun-blacklist=
 * "510000f010fd92a1,1,2",
 * "510000e012079df1,1,2";
 */
static void
fcp_read_blacklist(dev_info_t *dip,
    struct fcp_black_list_entry **pplun_blacklist)
{
	char **prop_array	= NULL;
	char *curr_pwwn		= NULL;
	char *curr_lun		= NULL;
	uint32_t prop_item	= 0;
	int idx			= 0;
	int len			= 0;

	ASSERT(mutex_owned(&fcp_global_mutex));
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    LUN_BLACKLIST_PROP, &prop_array, &prop_item) != DDI_PROP_SUCCESS) {
		return;
	}

	for (idx = 0; idx < prop_item; idx++) {

		curr_pwwn = prop_array[idx];
		while (*curr_pwwn == ' ') {
			curr_pwwn++;
		}
		if (strlen(curr_pwwn) <= (sizeof (la_wwn_t) * 2 + 1)) {
			fcp_log(CE_WARN, NULL, "Invalid WWN %s in the blacklist"
			    ", please check.", curr_pwwn);
			continue;
		}
		if ((*(curr_pwwn + sizeof (la_wwn_t) * 2) != ' ') &&
		    (*(curr_pwwn + sizeof (la_wwn_t) * 2) != ',')) {
			fcp_log(CE_WARN, NULL, "Invalid WWN %s in the blacklist"
			    ", please check.", curr_pwwn);
			continue;
		}
		for (len = 0; len < sizeof (la_wwn_t) * 2; len++) {
			if (isxdigit(curr_pwwn[len]) != TRUE) {
				fcp_log(CE_WARN, NULL, "Invalid WWN %s in the "
				    "blacklist, please check.", curr_pwwn);
				break;
			}
		}
		if (len != sizeof (la_wwn_t) * 2) {
			continue;
		}

		curr_lun = curr_pwwn + sizeof (la_wwn_t) * 2 + 1;
		*(curr_lun - 1) = '\0';
		fcp_mask_pwwn_lun(curr_pwwn, curr_lun, pplun_blacklist);
	}

	ddi_prop_free(prop_array);
}

/*
 * Get the masking info about one remote target port designated by wwn.
 * Lun ids could be separated by ',' or white spaces.
 */
static void
fcp_mask_pwwn_lun(char *curr_pwwn, char *curr_lun,
    struct fcp_black_list_entry **pplun_blacklist)
{
	int		idx			= 0;
	uint32_t	offset			= 0;
	unsigned long	lun_id			= 0;
	char		lunid_buf[16];
	char		*pend			= NULL;
	int		illegal_digit		= 0;

	while (offset < strlen(curr_lun)) {
		while ((curr_lun[offset + idx] != ',') &&
		    (curr_lun[offset + idx] != '\0') &&
		    (curr_lun[offset + idx] != ' ')) {
			if (isdigit(curr_lun[offset + idx]) == 0) {
				illegal_digit++;
			}
			idx++;
		}
		if (illegal_digit > 0) {
			offset += (idx+1);	/* To the start of next lun */
			idx = 0;
			illegal_digit = 0;
			fcp_log(CE_WARN, NULL, "Invalid LUN %s for WWN %s in "
			    "the blacklist, please check digits.",
			    curr_lun, curr_pwwn);
			continue;
		}
		if (idx >= (sizeof (lunid_buf) / sizeof (lunid_buf[0]))) {
			fcp_log(CE_WARN, NULL, "Invalid LUN %s for WWN %s in "
			    "the blacklist, please check the length of LUN#.",
			    curr_lun, curr_pwwn);
			break;
		}
		if (idx == 0) {	/* ignore ' ' or ',' or '\0' */
			offset++;
			continue;
		}

		bcopy(curr_lun + offset, lunid_buf, idx);
		lunid_buf[idx] = '\0';
		if (ddi_strtoul(lunid_buf, &pend, 10, &lun_id) == 0) {
			fcp_add_one_mask(curr_pwwn, lun_id, pplun_blacklist);
		} else {
			fcp_log(CE_WARN, NULL, "Invalid LUN %s for WWN %s in "
			    "the blacklist, please check %s.",
			    curr_lun, curr_pwwn, lunid_buf);
		}
		offset += (idx+1);	/* To the start of next lun */
		idx = 0;
	}
}

/*
 * Add one masking record
 */
static void
fcp_add_one_mask(char *curr_pwwn, uint32_t lun_id,
    struct fcp_black_list_entry **pplun_blacklist)
{
	struct fcp_black_list_entry	*tmp_entry	= *pplun_blacklist;
	struct fcp_black_list_entry	*new_entry	= NULL;
	la_wwn_t			wwn;

	fcp_ascii_to_wwn(curr_pwwn, wwn.raw_wwn, sizeof (la_wwn_t));
	while (tmp_entry) {
		if ((bcmp(&tmp_entry->wwn, &wwn,
		    sizeof (la_wwn_t)) == 0) && (tmp_entry->lun == lun_id)) {
			return;
		}

		tmp_entry = tmp_entry->next;
	}

	/* add to black list */
	new_entry = (struct fcp_black_list_entry *)kmem_zalloc
	    (sizeof (struct fcp_black_list_entry), KM_SLEEP);
	bcopy(&wwn, &new_entry->wwn, sizeof (la_wwn_t));
	new_entry->lun = lun_id;
	new_entry->masked = 0;
	new_entry->next = *pplun_blacklist;
	*pplun_blacklist = new_entry;
}

/*
 * Check if we should mask the specified lun of this fcp_tgt
 */
static int
fcp_should_mask(la_wwn_t *wwn, uint32_t lun_id)
{
	struct fcp_black_list_entry *remote_port;

	remote_port = fcp_lun_blacklist;
	while (remote_port != NULL) {
		if (bcmp(wwn, &remote_port->wwn, sizeof (la_wwn_t)) == 0) {
			if (remote_port->lun == lun_id) {
				remote_port->masked++;
				if (remote_port->masked == 1) {
					fcp_log(CE_NOTE, NULL, "LUN %d of port "
					    "%02x%02x%02x%02x%02x%02x%02x%02x "
					    "is masked due to black listing.\n",
					    lun_id, wwn->raw_wwn[0],
					    wwn->raw_wwn[1], wwn->raw_wwn[2],
					    wwn->raw_wwn[3], wwn->raw_wwn[4],
					    wwn->raw_wwn[5], wwn->raw_wwn[6],
					    wwn->raw_wwn[7]);
				}
				return (TRUE);
			}
		}
		remote_port = remote_port->next;
	}
	return (FALSE);
}

/*
 * Release all allocated resources
 */
static void
fcp_cleanup_blacklist(struct fcp_black_list_entry **pplun_blacklist)
{
	struct fcp_black_list_entry	*tmp_entry	= *pplun_blacklist;
	struct fcp_black_list_entry	*current_entry	= NULL;

	ASSERT(mutex_owned(&fcp_global_mutex));
	/*
	 * Traverse all luns
	 */
	while (tmp_entry) {
		current_entry = tmp_entry;
		tmp_entry = tmp_entry->next;
		kmem_free(current_entry, sizeof (struct fcp_black_list_entry));
	}
	*pplun_blacklist = NULL;
}

/*
 * In fcp module,
 *   pkt@scsi_pkt, cmd@fcp_pkt, icmd@fcp_ipkt, fpkt@fc_packet, pptr@fcp_port
 */
static struct scsi_pkt *
fcp_pseudo_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen,
    int flags, int (*callback)(), caddr_t arg)
{
	fcp_port_t	*pptr = ADDR2FCP(ap);
	fcp_pkt_t	*cmd  = NULL;
	fc_frame_hdr_t	*hp;

	/*
	 * First step: get the packet
	 */
	if (pkt == NULL) {
		pkt = scsi_hba_pkt_alloc(pptr->port_dip, ap, cmdlen, statuslen,
		    tgtlen, sizeof (fcp_pkt_t) + pptr->port_priv_pkt_len,
		    callback, arg);
		if (pkt == NULL) {
			return (NULL);
		}

		/*
		 * All fields in scsi_pkt will be initialized properly or
		 * set to zero. We need do nothing for scsi_pkt.
		 */
		/*
		 * But it's our responsibility to link other related data
		 * structures. Their initialization will be done, just
		 * before the scsi_pkt will be sent to FCA.
		 */
		cmd		= PKT2CMD(pkt);
		cmd->cmd_pkt	= pkt;
		cmd->cmd_fp_pkt = &cmd->cmd_fc_packet;
		/*
		 * fc_packet_t
		 */
		cmd->cmd_fp_pkt->pkt_ulp_private = (opaque_t)cmd;
		cmd->cmd_fp_pkt->pkt_fca_private = (opaque_t)((caddr_t)cmd +
		    sizeof (struct fcp_pkt));
		cmd->cmd_fp_pkt->pkt_cmd = (caddr_t)&cmd->cmd_fcp_cmd;
		cmd->cmd_fp_pkt->pkt_cmdlen = sizeof (struct fcp_cmd);
		cmd->cmd_fp_pkt->pkt_resp = cmd->cmd_fcp_rsp;
		cmd->cmd_fp_pkt->pkt_rsplen = FCP_MAX_RSP_IU_SIZE;
		/*
		 * Fill in the Fabric Channel Header
		 */
		hp = &cmd->cmd_fp_pkt->pkt_cmd_fhdr;
		hp->r_ctl = R_CTL_COMMAND;
		hp->rsvd = 0;
		hp->type = FC_TYPE_SCSI_FCP;
		hp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
		hp->seq_id = 0;
		hp->df_ctl  = 0;
		hp->seq_cnt = 0;
		hp->ox_id = 0xffff;
		hp->rx_id = 0xffff;
		hp->ro = 0;
	} else {
		/*
		 * We need think if we should reset any elements in
		 * related data structures.
		 */
		FCP_TRACE(fcp_logq, pptr->port_instbuf,
		    fcp_trace, FCP_BUF_LEVEL_6, 0,
		    "reusing pkt, flags %d", flags);
		cmd = PKT2CMD(pkt);
		if (cmd->cmd_fp_pkt->pkt_pd) {
			cmd->cmd_fp_pkt->pkt_pd = NULL;
		}
	}

	/*
	 * Second step:	 dma allocation/move
	 */
	if (bp && bp->b_bcount != 0) {
		/*
		 * Mark if it's read or write
		 */
		if (bp->b_flags & B_READ) {
			cmd->cmd_flags |= CFLAG_IS_READ;
		} else {
			cmd->cmd_flags &= ~CFLAG_IS_READ;
		}

		bp_mapin(bp);
		cmd->cmd_fp_pkt->pkt_data = bp->b_un.b_addr;
		cmd->cmd_fp_pkt->pkt_datalen = bp->b_bcount;
		cmd->cmd_fp_pkt->pkt_data_resid = 0;
	} else {
		/*
		 * It seldom happens, except when CLUSTER or SCSI_VHCI wants
		 * to send zero-length read/write.
		 */
		cmd->cmd_fp_pkt->pkt_data = NULL;
		cmd->cmd_fp_pkt->pkt_datalen = 0;
	}

	return (pkt);
}

static void
fcp_pseudo_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	fcp_port_t	*pptr = ADDR2FCP(ap);

	/*
	 * First we let FCA to uninitilize private part.
	 */
	(void) fc_ulp_uninit_packet(pptr->port_fp_handle,
	    PKT2CMD(pkt)->cmd_fp_pkt);

	/*
	 * Then we uninitialize fc_packet.
	 */

	/*
	 * Thirdly, we uninitializae fcp_pkt.
	 */

	/*
	 * In the end, we free scsi_pkt.
	 */
	scsi_hba_pkt_free(ap, pkt);
}

static int
fcp_pseudo_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	fcp_port_t	*pptr = ADDR2FCP(ap);
	fcp_lun_t	*plun = ADDR2LUN(ap);
	fcp_tgt_t	*ptgt = plun->lun_tgt;
	fcp_pkt_t	*cmd  = PKT2CMD(pkt);
	fcp_cmd_t	*fcmd = &cmd->cmd_fcp_cmd;
	fc_packet_t	*fpkt = cmd->cmd_fp_pkt;
	int		 rval;

	fpkt->pkt_pd = ptgt->tgt_pd_handle;
	(void) fc_ulp_init_packet(pptr->port_fp_handle, cmd->cmd_fp_pkt, 1);

	/*
	 * Firstly, we need initialize fcp_pkt_t
	 * Secondly, we need initialize fcp_cmd_t.
	 */
	bcopy(pkt->pkt_cdbp, fcmd->fcp_cdb, pkt->pkt_cdblen);
	fcmd->fcp_data_len = fpkt->pkt_datalen;
	fcmd->fcp_ent_addr = plun->lun_addr;
	if (pkt->pkt_flags & FLAG_HTAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_HEAD_OF_Q;
	} else if (pkt->pkt_flags & FLAG_OTAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_ORDERED;
	} else if (pkt->pkt_flags & FLAG_STAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_SIMPLE;
	} else {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_UNTAGGED;
	}

	if (cmd->cmd_flags & CFLAG_IS_READ) {
		fcmd->fcp_cntl.cntl_read_data = 1;
		fcmd->fcp_cntl.cntl_write_data = 0;
	} else {
		fcmd->fcp_cntl.cntl_read_data = 0;
		fcmd->fcp_cntl.cntl_write_data = 1;
	}

	/*
	 * Then we need initialize fc_packet_t too.
	 */
	fpkt->pkt_timeout = pkt->pkt_time + 2;
	fpkt->pkt_cmd_fhdr.d_id = ptgt->tgt_d_id;
	fpkt->pkt_cmd_fhdr.s_id = pptr->port_id;
	if (cmd->cmd_flags & CFLAG_IS_READ) {
		fpkt->pkt_tran_type = FC_PKT_FCP_READ;
	} else {
		fpkt->pkt_tran_type = FC_PKT_FCP_WRITE;
	}

	if (pkt->pkt_flags & FLAG_NOINTR) {
		fpkt->pkt_comp = NULL;
		fpkt->pkt_tran_flags = (FC_TRAN_CLASS3 | FC_TRAN_NO_INTR);
	} else {
		fpkt->pkt_comp = fcp_cmd_callback;
		fpkt->pkt_tran_flags = (FC_TRAN_CLASS3 | FC_TRAN_INTR);
		if (pkt->pkt_flags & FLAG_IMMEDIATE_CB) {
			fpkt->pkt_tran_flags |= FC_TRAN_IMMEDIATE_CB;
		}
	}

	/*
	 * Lastly, we need initialize scsi_pkt
	 */
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;
	pkt->pkt_resid = 0;

	/*
	 * if interrupts aren't allowed (e.g. at dump time) then we'll
	 * have to do polled I/O
	 */
	if (pkt->pkt_flags & FLAG_NOINTR) {
		return (fcp_dopoll(pptr, cmd));
	}

	cmd->cmd_state = FCP_PKT_ISSUED;
	rval = fcp_transport(pptr->port_fp_handle, fpkt, 0);
	if (rval == FC_SUCCESS) {
		return (TRAN_ACCEPT);
	}

	/*
	 * Need more consideration
	 *
	 * pkt->pkt_flags & FLAG_NOQUEUE could abort other pkt
	 */
	cmd->cmd_state = FCP_PKT_IDLE;
	if (rval == FC_TRAN_BUSY) {
		return (TRAN_BUSY);
	} else {
		return (TRAN_FATAL_ERROR);
	}
}

/*
 * scsi_poll will always call tran_sync_pkt for pseudo FC-HBAs
 * SCSA will initialize it to scsi_sync_cache_pkt for physical FC-HBAs
 */
static void
fcp_pseudo_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	FCP_TRACE(fcp_logq, "fcp_pseudo_sync_pkt", fcp_trace,
	    FCP_BUF_LEVEL_2, 0, "ap-%p, scsi_pkt-%p", ap, pkt);
}

/*
 * scsi_dmafree will always call tran_dmafree, when STATE_ARQ_DONE
 */
static void
fcp_pseudo_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	FCP_TRACE(fcp_logq, "fcp_pseudo_dmafree", fcp_trace,
	    FCP_BUF_LEVEL_2, 0, "ap-%p, scsi_pkt-%p", ap, pkt);
}
