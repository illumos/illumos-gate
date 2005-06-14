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
 * Copyright (c) 1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_I2O_SCSI_VAR_H
#define	_I2O_SCSI_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Convenient defines
 */

/*
 * Local static data
 */

#define	I2OHBA_INITIAL_SOFT_SPACE	2  /* assume 2 instances of hba */
#define	I2OHBA_CMD_NSEGS		17
#define	I2O_OSM_TID			0x01

#define	TGT(sp)				(CMD2PKT(sp)->pkt_address.a_target)
#define	LUN(sp)				(CMD2PKT(sp)->pkt_address.a_lun)

/*
 * Targets supported
 */
#define	N_I2OHBA_LUNS			8
#define	N_I2OHBA_TARGETS		8
#define	N_I2OHBA_TARGETS_WIDE		16

/*
 * message module defines
 */
#define	ContextSize32			0x51
#define	ContextSize64			0x71

/*
 * Default scsi-options
 */
#define	I2OHBA_DEFAULT_SCSI_OPTIONS					\
					SCSI_OPTIONS_PARITY	|	\
					SCSI_OPTIONS_DR		|	\
					SCSI_OPTIONS_SYNC	|	\
					SCSI_OPTIONS_TAG	|	\
					SCSI_OPTIONS_FAST	|	\
					SCSI_OPTIONS_WIDE


/*
 * Mutex short hands
 */
#define	I2OHBA_REQ_MUTEX(i2ohba)	(&i2ohba->i2ohba_request_mutex)
#define	I2OHBA_MUTEX_OWNED(i2ohba)	mutex_owned(I2OHBA_REQ_MUTEX(i2ohba))
#define	I2OHBA_MUTEX_ENTER(i2ohba)	mutex_enter(I2OHBA_REQ_MUTEX(i2ohba))
#define	I2OHBA_MUTEX_EXIT(i2ohba)	mutex_exit(I2OHBA_REQ_MUTEX(i2ohba))

#define	I2OHBA_RESET_MUTEX(i2ohba)	(&i2ohba->reset_mutex)
#define	I2OHBA_RESET_CV(i2ohba)		(&i2ohba->reset_cv)

/*
 * HBA interface macros
 */
#define	SDEV2TRAN(sd)		((sd)->sd_address.a_hba_tran)
#define	SDEV2ADDR(sd)		(&((sd)->sd_address))
#define	PKT2TRAN(pkt)		((pkt)->pkt_address.a_hba_tran)
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)

#define	TRAN2I2OHBA(tran)	((struct i2ohba *)(tran)->tran_hba_private)
#define	SDEV2I2OHBA(sd)		(TRAN2I2OHBA(SDEV2TRAN(sd)))
#define	PKT2I2OHBA(pkt)		(TRAN2I2OHBA(PKT2TRAN(pkt)))
#define	ADDR2I2OHBA(ap)		(TRAN2I2OHBA(ADDR2TRAN(ap)))

#define	CMD2ADDR(cmd)		(&CMD2PKT(cmd)->pkt_address)
#define	CMD2TRAN(cmd)		(CMD2PKT(cmd)->pkt_address.a_hba_tran)
#define	CMD2I2OHBA(cmd)		(TRAN2I2OHBA(CMD2TRAN(cmd)))

/*
 * Capability defines
 */
#define	I2OHBA_CAP_DISCONNECT		0x8000
#define	I2OHBA_CAP_PARITY		0x4000
#define	I2OHBA_CAP_WIDE			0x2000
#define	I2OHBA_CAP_SYNC			0x1000
#define	I2OHBA_CAP_TAG			0x0800
#define	I2OHBA_CAP_AUTOSENSE		0x0400
#define	I2OHBA_CAP_ERRSTOP		0x0200
#define	I2OHBA_CAP_ERRSYNC		0x0100

/*
 * delay time for polling loops
 */
#define	I2OHBA_NOINTR_POLL_DELAY_TIME	1000	/* usecs */

/*
 * value used to force bus reset in i2ohab_i_reset_interface()
 */
#define	I2OHBA_FORCE_BUS_RESET		0x02
#define	PERIOD_MASK(val)		((val) & 0xff)
#define	OFFSET_MASK(val)		(((val) >> 8) & 0xff)

/*
 * timeout values
 */
#define	I2OHBA_GRACE			10	/* Timeout margin (sec.) */
#define	I2OHBA_TIMEOUT_DELAY(secs, delay)	(secs * (1000000 / delay))

typedef struct i2o_tid_scsi_ent {
	uint16_t	tid;    /* associated TID */
	i2o_scsi_device_info_scalar_t  scsi_info_scalar;
} i2o_tid_scsi_ent_t;

struct i2ohba {

	/*
	 * Message request double link list chain
	 */
	struct i2ohba_cmd	*i2ohba_reqhead;
	struct i2ohba_cmd	*i2ohba_reqtail;

	/*
	 * Mutex for the request or reply link list
	 */
	kmutex_t		i2ohba_request_mutex;
	/*
	 * Mutex for utilparam msg  or reset param msg
	 */
	kmutex_t		util_param_mutex[N_I2OHBA_TARGETS_WIDE];
	kmutex_t		reset_mutex;
	kcondvar_t		util_param_cv[N_I2OHBA_TARGETS_WIDE];
	kcondvar_t		reset_cv;

	/*
	 * Bus Adapter's Tid
	 */
	uint16_t		i2ohba_tid;

	/*
	 * i2ohba shutdown flag
	 */
	uint8_t			i2ohba_shutdown;

	/*
	 * i2ohba clear queue
	 */
	uint32_t		i2ohba_throttle;
	uint32_t		i2ohba_counter;

	/*
	 * i2ohba timeout id
	 */
	timeout_id_t		i2ohba_timeout_id;

	/*
	 * flag for updating properties in i2ohba_i_watch()
	 * to avoid updating in interrupt context
	 */
	uint16_t		i2ohba_need_prop_update;

	/*
	 * Host adapter capabilities and offset/period values per target
	 * (dynamically changed by the target)
	 */
	uint16_t		i2ohba_cap[N_I2OHBA_TARGETS_WIDE];
	uint16_t		i2ohba_synch[N_I2OHBA_TARGETS_WIDE];
	uint8_t			i2ohba_offset[N_I2OHBA_TARGETS_WIDE];
	uint32_t		i2ohba_totsec[N_I2OHBA_TARGETS_WIDE];
	uint32_t		i2ohba_secsz[N_I2OHBA_TARGETS_WIDE];

	/*
	 * Transport structure for this instance of the hba
	 */
	scsi_hba_tran_t		*i2ohba_tran;

	/*
	 * dev_info_t reference can be found in the transport structure
	 */
	dev_info_t		*i2ohba_dip;

	/*
	 * IOP access handle (The IOP controls/associated with dip)
	 */
	i2o_iop_handle_t	i2ohba_iophdl;

	/*
	 * Bus Adapter's Param
	 */
	i2o_hba_scsi_controller_info_scalar_t *i2ohba_scsi_controller;

	/*
	 * TID to SCSI/LUN target map, this hba can have upto 15 devices
	 */
	i2o_tid_scsi_ent_t	i2ohba_tid_scsi_map[N_I2OHBA_TARGETS_WIDE];

	i2o_tid_scsi_ent_t	*i2ohba_tgt_id_map[N_I2OHBA_TARGETS_WIDE];

	/*
	 * scsi options, etc from ddi_getprop()
	 * default value from the UtilParamGet
	 */
	int	i2ohba_scsi_options; /* default one */
	int	i2ohba_target_scsi_option[N_I2OHBA_TARGETS_WIDE];
	int	i2ohba_initiator_id;

	/*
	 * scsi_reset_delay for i2o
	 */
	uint32_t   i2ohba_scsi_reset_delay;


	struct scsi_reset_notify_entry	*i2ohba_reset_notify_listf;


};

#ifdef	__cplusplus
}
#endif

#endif /* _I2O_SCSI_VAR_H */
