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
 * Copyright 2001 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SOCALVAR_H
#define	_SYS_SOCALVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/id32.h>

/*
 * socalvar.h - SOC+ Driver data struct definitions
 */

/*
 * Define default name and # of SOC+s to allocate to the system
 */

#define	SOCAL_PORTA_NAME	"0"	/* node for port a */
#define	SOCAL_PORTB_NAME	"1"	/* node for port b */
#define	SOCAL_NT_PORT		NULL
#define	SOCAL_INIT_ITEMS	5

/*
 * Defines for the Circular Queues
 */
#define	SOCAL_MAX_CQ_ENTRIES	256	/* Maximum number of CQ entries. */
#define	SOCAL_CQ_SIZE (sizeof (cqe_t) * SOC_MAX_CQ_ENTRIES)

#define	SOCAL_SMALL_CQ_ENTRIES	8	/* Number of CQ entries for a small Q */

#define	SOCAL_N_CQS		4	/* Number of queues we use */
#define	SOCAL_HW_N_CQS		4	/* Number of queues the hardware has */
#define	SOCAL_CQ_ALIGN		64	/* alignment boundary */

#define	SOCAL_TAKE_CORE		0x1
#define	SOCAL_FAILED_LIP	0x2

/*
 * Misc. Macros
 */
#define	SOCAL_POOL_SIZE		2112
#define	SOCAL_SVC_LENGTH	80

#define	FABRIC_FLAG	1
#define	NPORT_FLAG	2

#define	FCIO_DIAG_LBTFQ		(FIOC|203)
#define	SOC_DIAG_LBTFQ		0x0a
#define	PORT_LBF_PENDING	0x00100000
#define	SOCAL_LBF_TIMEOUT	15000000 /* usec */

/* Macros to speed handling of 32-bit IDs */
#define	SOCAL_ID_GET(x, w)	id32_alloc((x), (w))
#define	SOCAL_ID_LOOKUP(x)	id32_lookup((x))
#define	SOCAL_ID_FREE(x)	id32_free((x))

typedef	struct flb_hdr {
	uint_t max_length;
	uint_t length;
} flb_hdr_t;

struct socal_state;

/*
 * SOC UNIX circular queue descriptor.
 */

typedef struct socal_kernel_cq {
	kmutex_t	skc_mtx;	/* MT lock for CQ manipulation  */
	kcondvar_t	skc_cv;		/* cond var for CQ manipulation. */
	ddi_dma_handle_t skc_dhandle;	/* DDI DMA handle to CQ. */
	ddi_dma_cookie_t skc_dcookie;	/* DDI DMA Cookie. */
	ddi_acc_handle_t skc_acchandle;	/* DDI DMA access handle */
	soc_cq_t	*skc_xram_cqdesc; /* Pointer to XRAM CQ desc */
	caddr_t		skc_cq_raw;	/* Pointer to unaligned CQ mem pool */
	cqe_t		*skc_cq;	/* Pointer to CQ memory pool. */
	uchar_t		skc_in;		/* Current Input pointer. */
	uchar_t		skc_out;	/* Current Input pointer. */
	uchar_t		skc_last_index;	/* Last cq index. */
	uchar_t		skc_seqno;	/* Current Go Around in CQ. */
	uchar_t		skc_full;	/* Indication of full. */
	uchar_t		skc_saved_out;	/* Current Input pointer. */
	uchar_t		skc_saved_seqno;	/* Current Go Around in CQ. */
	timeout_id_t	deferred_intr_timeoutid;
	struct fcal_packet	*skc_overflowh; /* cq overflow list */
	struct fcal_packet	*skc_overflowt;
	struct socal_state	*skc_socalp;
} socal_kcq_t;

/*
 * Values for skc_full
 */
#define	SOCAL_SKC_FULL	1
#define	SOCAL_SKC_SLEEP	2

/*
 * State change callback routine descriptor
 *
 * There is one entry in this list for each hba that is attached
 * to this port.
 * This structure will need to be mutex protected when parallel
 * attaches are supported.
 */
typedef struct socal_unsol_cb {
	struct socal_unsol_cb	*next;
	uchar_t			type;
	void			(*statec_cb)(void *, uint32_t);
	void			(*els_cb)(void *, cqe_t *, caddr_t);
	void			(*data_cb)(void *, cqe_t *, caddr_t);
	void			*arg;
} socal_unsol_cb_t;

/*
 * SOC+ port status decriptor.
 */
typedef struct socal_port {
	uint32_t		sp_status;	/* port status */
	struct socal_state	*sp_board;	/* hardware for instance */

	uint32_t		sp_src_id;	/* Our nport id */
	uint32_t		sp_port;	/* Our physical port (0, 1) */
	la_wwn_t		sp_p_wwn;	/* Our Port WorldWide Name */

	socal_unsol_cb_t	*sp_unsol_cb;	/* Callback for state change */

	uint32_t		sp_open;	/* open count */

	kmutex_t		sp_mtx;		/* Per port mutex */
	kcondvar_t		sp_cv;		/* Per port condvariable */
	fcal_transport_t	*sp_transport;	/* transport structure */

	uint32_t		sp_hard_alpa;	/* Our optional Hard AL_PA */

	uint32_t		sp_lilpmap_valid;  /* lilp map cache valid  */
	fcal_lilp_map_t		sp_lilpmap;  /* lilp map cache */
} socal_port_t;

#define	PORT_FABRIC_PRESENT	0x00000001
#define	PORT_OFFLINE		0x00000002
#define	NPORT_LOGIN_SUCCESS	0x00000004
#define	PORT_LOGIN_ACTIVE	0x00000008
#define	PORT_LOGIN_RECOVERY	0x00000010
#define	PORT_ONLINE_LOOP	0x00000020
#define	PORT_ONLINE		0x00000040
#define	PORT_STATUS_FLAG	0x00000080
#define	PORT_STATUS_MASK	0x000000ff
#define	PORT_OPEN		0x00000100
#define	PORT_CHILD_INIT		0x00000200
#define	PORT_TARGET_MODE	0x00000400
#define	PORT_LILP_PENDING	0x00001000
#define	PORT_LIP_PENDING	0x00002000
#define	PORT_ABORT_PENDING	0x00004000
#define	PORT_ELS_PENDING	0x00008000
#define	PORT_BYPASS_PENDING	0x00010000
#define	PORT_OFFLINE_PENDING	0x00020000
#define	PORT_ADISC_PENDING	0x00040000
#define	PORT_RLS_PENDING	0x00080000
#define	PORT_DISABLED		0x00100000


#define	SOC_TIMEOUT_DELAY(secs, delay)  (secs * (1000000 / delay))
#define	SOCAL_NOINTR_POLL_DELAY_TIME	1000    /* usec */

#define	SOCAL_LILP_TIMEOUT		10000000 /* usec */
#define	SOCAL_LIP_TIMEOUT		30000000 /* usec */
#define	SOCAL_ABORT_TIMEOUT		10000000 /* usec */
#define	SOCAL_BYPASS_TIMEOUT		5000000	/* usec */
#define	SOCAL_OFFLINE_TIMEOUT		5000000	/* usec */
#define	SOCAL_ADISC_TIMEOUT		15000000 /* usec */
#define	SOCAL_RLS_TIMEOUT		15000000 /* usec */
#define	SOCAL_DIAG_TIMEOUT		15000000 /* usec */

/*
 * We wait for up to SOC_INITIAL_ONLINE seconds for the first
 * soc to come on line. The timeout in the soc firmware is 10 seconds.
 * The timeout is to let any outstanding commands drain before
 * coming back on line, after going off-line.
 */
#define	SOC_INITIAL_ONLINE	30	/* secs for first online from soc */

/*
 * SOC state structure
 */

typedef struct socal_state {
	dev_info_t	*dip;
	caddr_t 	socal_eeprom;		/* pointer to soc+ eeprom */
	caddr_t 	socal_xrp;		/* pointer to soc+ xram */
	socal_reg_t	*socal_rp;		/* pointer to soc+ registers */

	soc_cq_t	*xram_reqp;	/* addr of request descriptors */
	soc_cq_t	*xram_rspp;	/* addr of response descriptors */

	socal_kcq_t	request[SOCAL_N_CQS];	/* request queues */
	socal_kcq_t	response[SOCAL_N_CQS];	/* response queues */

	int32_t		socal_busy;		/* busy flag */
	uint32_t	socal_shutdown;
	uint32_t	socal_cfg;		/* copy of the config reg */

	kmutex_t	k_imr_mtx;	/* mutex for interrupt masks */
	uint32_t	socal_k_imr;	/* copy of soc+'s mask register */

	kmutex_t	abort_mtx;	/* Abort mutex. */
	kmutex_t	board_mtx;	/* Per board mutex */
	kmutex_t	ioctl_mtx;	/* mutex to serialize ioctls */
	kcondvar_t	board_cv;	/* Per board condition variable */

	ddi_iblock_cookie_t	iblkc;	/* interrupt cookies */
	ddi_idevice_cookie_t	idevc;

	uchar_t		*pool;	/* unsolicited buffer pool resources */
	ddi_dma_handle_t	pool_dhandle;
	ddi_dma_cookie_t	pool_dcookie;
	ddi_acc_handle_t	pool_acchandle;

					/* handles to soc+ ports */
	socal_port_t	port_state[N_SOCAL_NPORTS];
	la_wwn_t	socal_n_wwn;	/* Our Node WorldWide Name */
	char		socal_service_params[SOCAL_SVC_LENGTH];	/* for login */

	char			socal_name[MAXPATHLEN];
	kstat_t			*socal_ksp;
	struct socal_stats	socal_stats;	/* kstats */
	int		socal_on_intr;
} socal_state_t;

/*
 * Structure used when the soc driver needs to issue commands of its own
 */

typedef struct socal_priv_cmd {
	void			*fapktp;
	uint32_t		flags;
	caddr_t			cmd;
	caddr_t			rsp;
	ddi_dma_handle_t	cmd_handle;
	ddi_acc_handle_t	cmd_acchandle;
	ddi_dma_handle_t	rsp_handle;
	ddi_acc_handle_t	rsp_acchandle;
	void 			(*callback)();	/* callback to ULP, if any */
	void			*arg;		/* callback arg */
	caddr_t			*payload;	/* payload callback or stash */
} socal_priv_cmd_t;

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_SOCALVAR_H */
