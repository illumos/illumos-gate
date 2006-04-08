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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef _OPLMSU_PROTO_H
#define	_OPLMSU_PROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	PROTOTYPE DECLARATIONS
 */

int	oplmsu_attach(dev_info_t *, ddi_attach_cmd_t);
int	oplmsu_detach(dev_info_t *, ddi_detach_cmd_t);
int	oplmsu_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
int	oplmsu_open(queue_t *, dev_t *, int, int, cred_t *);
int	oplmsu_close(queue_t *, int, cred_t *);
int	oplmsu_uwput(queue_t *, mblk_t *);
int	oplmsu_uwsrv(queue_t *);
int	oplmsu_lwsrv(queue_t *);
int	oplmsu_lrput(queue_t *, mblk_t *);
int	oplmsu_lrsrv(queue_t *);
int	oplmsu_ursrv(queue_t *);

int	oplmsu_open_msu(dev_info_t *, ldi_ident_t *, ldi_handle_t *);
int	oplmsu_plink_serial(dev_info_t *, ldi_handle_t, int *);
int	oplmsu_set_lpathnum(int, int);
int	oplmsu_dr_attach(dev_info_t *);
int	oplmsu_dr_detach(dev_info_t *);
int	oplmsu_find_serial(ser_devl_t **);
dev_info_t *oplmsu_find_ser_dip(dev_info_t *);
void	oplmsu_conf_stream(uinst_t *);
void	oplmsu_unlinks(ldi_handle_t, int *, int);
void	oplmsu_setup(uinst_t *);
int	oplmsu_create_upath(dev_info_t *);
int	oplmsu_config_new(struct msu_path *);
int	oplmsu_config_add(dev_info_t *);
int	oplmsu_config_del(struct msu_path *);
int	oplmsu_config_stop(int);
int	oplmsu_config_start(int);
int	oplmsu_config_disc(int);

/*
 *	UPPER WRITE SERVICE PROCEDURE
 */
int	oplmsu_uwioctl_iplink(queue_t *, mblk_t *);
int	oplmsu_uwioctl_ipunlink(queue_t *, mblk_t *);
int	oplmsu_uwioctl_termios(queue_t *, mblk_t *);

/*
 *	LOWER READ SERVICE PROCEDURE
 */
int	oplmsu_lrioctl_termios(queue_t *, mblk_t *);
int	oplmsu_lrmsg_error(queue_t *, mblk_t *);
int	oplmsu_lrdata_xoffxon(queue_t *, mblk_t *);

/*
 *	COMMON FUNCTIONS
 */
void	oplmsu_link_upath(upath_t *);
void	oplmsu_unlink_upath(upath_t *);
void	oplmsu_link_lpath(lpath_t *);
void	oplmsu_unlink_lpath(lpath_t *);
void	oplmsu_link_high_primsg(mblk_t **, mblk_t **, mblk_t *);
int	oplmsu_check_lpath_usable(void);
upath_t	*oplmsu_search_upath_info(int);

void	oplmsu_iocack(queue_t *, mblk_t *, int);
void	oplmsu_delete_upath_info(void);
int 	oplmsu_set_ioctl_path(lpath_t *, queue_t *, mblk_t *);
void	oplmsu_clear_ioctl_path(lpath_t *);

int	oplmsu_get_inst_status(void);
upath_t	*oplmsu_search_standby(void);
void	oplmsu_search_min_stop_path(void);
int	oplmsu_get_pathnum(void);
int	oplmsu_cmn_put_xoffxon(queue_t *, int);
void	oplmsu_cmn_putxoff_standby(void);
void	oplmsu_cmn_set_mflush(mblk_t *);
void	oplmsu_cmn_set_upath_sts(upath_t *, int, int, ulong_t);
int	oplmsu_cmn_allocmb(queue_t *, mblk_t *, mblk_t **, size_t, int);
int	oplmsu_cmn_copymb(queue_t *, mblk_t *, mblk_t **, mblk_t *, int);
void	oplmsu_cmn_bufcall(queue_t *, mblk_t *, size_t, int);
int	oplmsu_cmn_prechg(queue_t *, mblk_t *, int, mblk_t **, int *, int *);
int	oplmsu_stop_prechg(mblk_t **, int *, int *);
int	oplmsu_cmn_prechg_termio(queue_t *, mblk_t *, int, int, mblk_t **,
	    int *);
int	oplmsu_cmn_pullup_msg(queue_t *, mblk_t *);

void	oplmsu_cmn_wakeup(queue_t *);
void	oplmsu_cmn_bufcb(void *);
void	oplmsu_wbufcb_posthndl(ctrl_t *);

/*
 *	common functions for write stream
 */
int	oplmsu_wcmn_chknode(queue_t *, int, mblk_t *);
void	oplmsu_wcmn_flush_hndl(queue_t *, mblk_t *, krw_t);
int	oplmsu_wcmn_through_hndl(queue_t *, mblk_t *, int, krw_t);
mblk_t	*oplmsu_wcmn_high_getq(queue_t *);
void	oplmsu_wcmn_norm_putbq(queue_t *, mblk_t *, queue_t *);
void	oplmsu_wcmn_high_qenable(queue_t *, krw_t);

/*
 *	common functions for read stream
 */
void	oplmsu_rcmn_flush_hndl(queue_t *, mblk_t *);
int	oplmsu_rcmn_through_hndl(queue_t *, mblk_t *, int);
void	oplmsu_rcmn_high_qenable(queue_t *);


#ifdef DEBUG
void	oplmsu_cmn_trace(queue_t *, mblk_t *, int);
void	oplmsu_cmn_msglog(mblk_t *, int);
void	oplmsu_cmn_prt_pathname(dev_info_t *);
#endif


/*
 *	GLOBAL VARIABLES
 */
extern	uinst_t		*oplmsu_uinst;
extern	int		oplmsu_queue_flag;
extern	int		oplmsu_check_su;

#ifdef DEBUG
extern	int		oplmsu_debug_mode;
extern	int		oplmsu_trace_on;
extern	uint_t		oplmsu_ltrc_size;
extern	msu_trc_t	*oplmsu_ltrc_top;
extern	msu_trc_t	*oplmsu_ltrc_tail;
extern	msu_trc_t	*oplmsu_ltrc_cur;
extern	ulong_t		oplmsu_ltrc_ccnt;
extern	kmutex_t	oplmsu_ltrc_lock;
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _OPLMSU_PROTO_H */
