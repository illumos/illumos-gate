/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_1394_TARGETS_DCAM1394_DCAM_H
#define	_SYS_1394_TARGETS_DCAM1394_DCAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/1394/t1394.h>
#include <sys/dcam/dcam1394_io.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ILP32_PTR_SIZE	4	/* caller's data model type	*/
#define	LP64_PTR_SIZE 	8

#define	DCAM_POWER_OFF	0	/* power management state	*/
#define	DCAM_POWER_ON	1

#define	DCAM1394_MINOR_CTRL	0x80		/* this is the control device */

#define	DCAM1394_FLAG_ATTACH_COMPLETE	0x1  /* dcam_attach() is complete */
#define	DCAM1394_FLAG_OPEN		0x2  /* driver is open */
#define	DCAM1394_FLAG_OPEN_CAPTURE	0x4  /* device is open for capture */
#define	DCAM1394_FLAG_OPEN_CONTROL	0x8  /* device is open for control */
#define	DCAM1394_FLAG_FRAME_RCV_INIT	0x10
#define	DCAM1394_FLAG_FRAME_RCVING	0x20
#define	DCAM1394_FLAG_READ_REQ_PROC	0x40
#define	DCAM1394_FLAG_READ_REQ_INVALID	0x80

#define	IS_VALID	0x1
#define	IS_PRESENT	0x2
#define	CAP_GET		0x4
#define	CAP_SET		0x8
#define	CAP_CTRL_SET	0x10

#define	MAX_STR_LEN	50

#define	DEV_TO_INSTANCE(d) (getminor(d) & 0x7f)

typedef uint_t
    dcam1394_param_attr_t[DCAM1394_NUM_PARAM][DCAM1394_NUM_SUBPARAM];

typedef struct buff_info_s {
	uint_t			vid_mode;
	unsigned int		seq_num;
	hrtime_t		timestamp;
	caddr_t			kaddr_p;		/* kernel data buffer */
	ddi_dma_handle_t	dma_handle;		/* bind handle */
	ddi_acc_handle_t	data_acc_handle;  	/* acc handle */
	ddi_dma_cookie_t	dma_cookie;		/* cookie */
	size_t			real_len;    		/* mem len */
	uint_t			dma_cookie_count;	/* cookie count */
} buff_info_t;

#define	MAX_NUM_READ_PTRS 1

typedef struct ring_buff_s {
	size_t		 num_buffs;
	size_t		 buff_num_bytes;
	buff_info_t	*buff_info_array_p;
	int		 num_read_ptrs;
	int		 read_ptr_incr_val;
	size_t		 read_ptr_pos[MAX_NUM_READ_PTRS];
	uint_t		 status[MAX_NUM_READ_PTRS];
	size_t		 write_ptr_pos;
} ring_buff_t;

typedef struct dcam_state_s {
	dev_info_t			*dip;
	int				instance;
	int				usr_model;
	t1394_handle_t			sl_handle;
	t1394_attachinfo_t		attachinfo;
	t1394_targetinfo_t		targetinfo;
	t1394_isoch_singleinfo_t	sii;
	t1394_isoch_single_out_t	sii_output_args;
	t1394_isoch_single_handle_t	sii_hdl;
	t1394_isoch_dma_handle_t 	isoch_handle;
	kmutex_t			softc_mutex;
	kmutex_t			dcam_frame_is_done_mutex;
	dcam1394_param_attr_t		param_attr;

	ixl1394_command_t		*ixlp;

	ring_buff_t			*ring_buff_p;
	unsigned int			seq_count;
	uint_t				reader_flags[MAX_NUM_READ_PTRS];
	uint_t				flags;
	int				cur_vid_mode;
	int				cur_frame_rate;
	int				cur_ring_buff_capacity;
	int				param_status;
	struct pollhead			dcam_pollhead;
	int				camera_online;
	int				pm_open_count;
	int				pm_cable_power;
	int				suspended;
	ddi_callback_id_t		event_id;
} dcam_state_t;

int _init(void);
int _info(struct modinfo *modinfop);
int _fini(void);

int dcam_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
int dcam_power(dev_info_t *dip, int component, int level);
int dcam_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result);
int dcam_identify(dev_info_t *dip);
int dcam_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
int dcam_open(dev_t *devp, int flag, int otyp, cred_t *credp);
int dcam_close(dev_t dev, int flags, int otyp, cred_t *credp);
int dcam_read(dev_t dev, struct uio *uio, cred_t *credp);
int dcam_write(dev_t dev, struct uio *uio, cred_t *credp);
int dcam_mmap(dev_t dev, off_t off, int prot);
int dcam_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model);
int dcam_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);
int dcam_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);
int dcam_intr(caddr_t dcam_softc_p);
void dcam_bus_reset_notify(dev_info_t *dip, ddi_eventcookie_t ev_cookie,
    void *arg, void *impl_data);


ring_buff_t *ring_buff_create(dcam_state_t *softc_p, size_t num_buffs,
    size_t buff_num_bytes);
void ring_buff_free(dcam_state_t *softc_p, ring_buff_t *ring_buff_p);
int ring_buff_reader_add(ring_buff_t *ring_buff_p);
int ring_buff_reader_remove(ring_buff_t *ring_buff_p, int reader_id);
buff_info_t *ring_buff_read_ptr_buff_get(ring_buff_t *ring_buff_p, int
    reader_id);
size_t ring_buff_read_ptr_pos_get(ring_buff_t *ring_buff_p, int read_ptr_id);
void ring_buff_read_ptr_incr(ring_buff_t *ring_buff_p, int read_ptr_id);
size_t ring_buff_write_ptr_pos_get(ring_buff_t *ring_buff_p);
void ring_buff_write_ptr_incr(ring_buff_t *ring_buff_p);
int dcam_frame_rcv_stop(dcam_state_t *softc_p);
int dcam1394_ioctl_frame_rcv_start(dcam_state_t *softc_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_1394_TARGETS_DCAM1394_DCAM_H */
