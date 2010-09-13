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

#ifndef _OPLMSU_H
#define	_OPLMSU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* ack_flag */
#define	ACK_RES		0
#define	NAK_RES		-1

/* active_flag */
#define	ACTIVE_RES	0
#define	NOT_ACTIVE_RES	-1

/* undefined path number */
#define	UNDEFINED	-1

/* sleep and wakeup control flag */
#define	CV_WAKEUP	0
#define	CV_SLEEP	1

/* write/read control flag */
#define	MSU_WRITE_SIDE	0
#define	MSU_READ_SIDE	1

/* message priority */
#define	MSU_HIGH	1
#define	MSU_NORM	0

/* miscellaneous */
#define	SUCCESS		0
#define	FAILURE		-1
#if !defined(BUSY)	/* warning: macro redefined */
#define	BUSY		-2
#endif

/* timeout interval */
#define	MSU_TM_500MS	500000	/* 500ms */

/* XON/XOFF code */
#define	MSU_XON		0x11
#define	MSU_XOFF	0x13
#define	MSU_XON_4	(MSU_XON << 24|MSU_XON << 16|MSU_XON << 8|MSU_XON)
#define	MSU_XOFF_4	(MSU_XOFF << 24|MSU_XOFF << 16|MSU_XOFF << 8|MSU_XOFF)

/* main path code used by MSU_CMD_START ioctl */
#define	MAINPATHCODE	0x1000
#define	MSU_OBP_CONSOLE	-2

/* maximum number of minor device number */
#define	MAXDEVMINOR	256

/* node mask */
#define	USER_NODE_MASK	0x00000000	/* user control node */
#define	META_NODE_MASK	0x00010000	/* meta control node */

/* node_flag */
#define	MSU_NODE_USER		0	/* user control node */
#define	MSU_NODE_META		1	/* meta control node */

/* node_flag check macro */
#define	MSU_NODE_TYPE(dev) \
	(((dev) & (META_NODE_MASK|USER_NODE_MASK)) >> 16)

/* termio_flag */
#define	MSU_TIOS_TCSETS		1	/* TCSETS */
#define	MSU_TIOS_MSET		2	/* TIOCMSET */
#define	MSU_TIOS_PPS		3	/* TIOCSPPS */
#define	MSU_TIOS_WINSZP		4	/* TIOCSWINSZ */
#define	MSU_TIOS_SOFTCAR	5	/* TIOCSSOFTCAR */
#define	MSU_TIOS_END		6	/* termios end */

/* binding name */
#define	MSU_CMUCH_FF		"pci10cf,138f"
#define	MSU_CMUCH_DC		"pci10cf,1390"
#ifdef DEBUG
#define	MSU_CMUCH_DBG		"pci108e,8000"
#endif

/* tty-port# properties */
#define	MSU_TTY_PORT_PROP	"tty-port#"

/* board# properties */
#define	MSU_BOARD_PROP		"board#"

/*
 * oplmsu command code
 */
#define	MSU_CMD			('f' << 8)
#define	MSU_CMD_STOP		(MSU_CMD|0x14)
#define	MSU_CMD_START		(MSU_CMD|0x15)
#define	MSU_CMD_ACTIVE		(MSU_CMD|0x1a)

#define	MSU_PATH_ALL		(-1)	/* path all instruction */

/*
 * oplmsu path status for status member on upper path info table
 */
#define	MSU_PSTAT_EMPTY		0
#define	MSU_PSTAT_ACTIVE	1
#define	MSU_PSTAT_STANDBY	2
#define	MSU_PSTAT_STOP		3
#define	MSU_PSTAT_FAIL		4
#define	MSU_PSTAT_DISCON	5
#define	MSU_PSTAT_ENCAP		6

/*
 * oplmsu additional status for traditional_status member on
 * upper path info table
 */
#define	MSU_UNLINK	 0	/* initial state */
#define	MSU_EMPTY	 1	/* MSU_STAT_EMPTY(00) state */
#define	MSU_LINK_NU	 2	/* link state(no link ID, no upper path info) */
#define	MSU_SETID_NU	 3	/* set ID state(link ID, no upper path info) */
#define	MSU_MAKE_INST	 4	/* create instance node state */
#define	MSU_STOP	 5	/* MSU_STAT_STOP(03) state */
#define	MSU_WSTR_ACK	 6	/* wait ack/nak of MSU_CMD_START state */
#define	MSU_STANDBY	 7	/* MSU_STAT_STANDBY(02) state */
#define	MSU_WTCS_ACK	 8	/* wait ack/nak of TCSETS state */
#define	MSU_WTMS_ACK	 9	/* wait ack/nak of TIOCMSET state */
#define	MSU_WPPS_ACK	10	/* wait ack/nak of TIOCSPPS state */
#define	MSU_WWSZ_ACK	11	/* wait ack/nak of TIOCSWINSZ state */
#define	MSU_WCAR_ACK	12	/* wait ack/nak of TIOCSSOFTCAR state */
#define	MSU_ACTIVE	13	/* MSU_STAT_ACTIVE(01) state */
#define	MSU_WSTP_ACK	14	/* wait ack/nak of MSU_CMD_STOP state */
#define	MSU_FAIL	15	/* MSU_STAT_FAIL(04) state */
#define	MSU_WCHK_ACK	16	/* wait ack/nak of OPLMSUSELFTEST */
#define	MSU_SETID	17	/* set ID state(link ID, upper path info) */
#define	MSU_DISCON	18	/* MSU_STAT_DISCON(05) state */
#define	MSU_LINK	19	/* link state(no link ID, upper path info) */
#define	MSU_WPTH_CHG	20	/* wait ack/nak of OPLMSUPATHCHG state */

/*
 * oplmsu instance status  for inst_status member on
 * upper instance info talbe
 */
#define	INST_STAT_BUSY			-1	/* busy */
#define	INST_STAT_ONLINE		10	/* online */
#define	INST_STAT_OFFLINE		11	/* offline */
#define	INST_STAT_UNCONFIGURED		12	/* unconfigured */

/*
 * oplmsu lower path Info table ext status for ext member on
 * lower path info table
 */
#define	MSU_EXT_NOTUSED			-1	/* not used (default) */
#define	MSU_EXT_ACTIVE_CANDIDATE	-2	/* active path candidate by */
						/* MSU_CMD_START */
#define	MSU_EXT_VOID			-3	/* void status */

/* oplmsu/su pathname size */
#define	MSU_PATHNAME_SIZE		128

/* control block(path parameter) */
struct msu_path {
	int		num;		/* total number of paths */
	int		reserved;	/* reserved */
};

/* control block(device parameter) */
struct msu_dev {
	dev_info_t	*dip;		/* pointer to dev_info_t */
};

/* serial device control block */
typedef struct serial_devcb {
	dev_info_t	*dip;		/* pointer to dev_info_t */
	int		lsb;		/* LSB number */
} ser_devcb_t;

/* serial device countrl block list */
typedef struct serial_devlist {
	struct serial_devlist	*next;
	dev_info_t		*dip;	/* pointer to dev_info_t */
} ser_devl_t;

/* upper path table */
typedef struct upper_path_table {
	struct upper_path_table	*u_next;
	struct upper_path_table	*u_prev;
	struct lower_path_table	*lpath;
	int			path_no;
	int			reserved;
	int			status;
	int			prev_status;
	ulong_t			traditional_status;
	ser_devcb_t		ser_devcb;
} upath_t;

/* lower path table */
typedef struct lower_path_table {
	struct lower_path_table	*l_next;
	struct lower_path_table	*l_prev;
	mblk_t			*first_lpri_hi;
	mblk_t			*last_lpri_hi;
	mblk_t			*hndl_mp;
	queue_t			*hndl_uqueue;
	queue_t			*lower_queue;
	queue_t			*uwq_queue;
	struct upper_instance_table	*uinst;
	char			*abt_char;
	struct buf_tbl		*rbuftbl;
	bufcall_id_t		rbuf_id;
	timeout_id_t		rtout_id;
	upath_t			*src_upath;
	long			status;
	int			path_no;
	int			link_id;
	int			uwq_flag;
	int			sw_flag;
	kcondvar_t		sw_cv;
} lpath_t;

/* control table */
typedef struct control_table {
	struct control_table	*c_next;
	struct control_table	*c_prev;
	mblk_t			*first_upri_hi;
	mblk_t			*last_upri_hi;
	queue_t			*queue;
	queue_t			*lrq_queue;
	queue_t			*wait_queue;
	minor_t			minor;
	int			node_type;
	struct buf_tbl		*wbuftbl;
	bufcall_id_t		wbuf_id;
	timeout_id_t		wtout_id;
	int			lrq_flag;
	int			sleep_flag;
	kcondvar_t		cvp;
} ctrl_t;

#define	MSU_MAX_ABTSLEN	24	/* maximum length for abort sequence */

/* upper instance table */
typedef struct upper_instance_table {
	upath_t		*first_upath;
	upath_t		*last_upath;
	lpath_t		*first_lpath;
	lpath_t		*last_lpath;
	ctrl_t		*meta_ctrl;
	ctrl_t		*user_ctrl;
	queue_t		*lower_queue;
	dev_info_t	*msu_dip;
	int		inst_status;
	int		path_num;
	int		reserved[2];
	krwlock_t	lock;
	kmutex_t	u_lock;
	kmutex_t	l_lock;
	kmutex_t	c_lock;
	mblk_t		*tcsets_p;
	mblk_t		*tiocmset_p;
	mblk_t		*tiocspps_p;
	mblk_t		*tiocswinsz_p;
	mblk_t		*tiocssoftcar_p;
	char		abts[MSU_MAX_ABTSLEN];
} uinst_t;

/* queue table for bufcall() and timeout() */
struct buf_tbl {
	queue_t	*q;
	int	rw_flag;
};


/* rwlock macro */
#define	OPLMSU_RWLOCK_UPGRADE() {				\
	if (rw_tryupgrade(&oplmsu_uinst->lock) == 0) {		\
		rw_exit(&oplmsu_uinst->lock);			\
		rw_enter(&oplmsu_uinst->lock, RW_WRITER);	\
	}							\
}

#ifdef DEBUG
typedef struct tracedata {
	queue_t		*q;
	mblk_t		*mp;
	char		op[3];
	uchar_t		msg_type;
	int		pathno;
	int		msg_cmd;
	ulong_t		data;
} msu_trc_t;

#define	MSU_TRC_USER	('u' << 24|'s' << 16|'e' << 8|'r')
#define	MSU_TRC_META	('m' << 24|'e' << 16|'t' << 8|'a')

/* oplmsu_trace_on */
#define	MSU_TRACE_OFF	0
#define	MSU_TRACE_ON	1

/* oplmsu_debug_mode */
#define	MSU_DPRINT_ON	1	/* enable print log */

/* op type */
#define	MSU_TRC_UI	0	/* upper input */
#define	MSU_TRC_UO	1	/* upper output */
#define	MSU_TRC_LI	2	/* lower input */
#define	MSU_TRC_LO	3	/* lower output */
#define	MSU_TRC_OPN	4	/* open */
#define	MSU_TRC_CLS	5	/* close */

/* trace macro */
#define	OPLMSU_TRACE(q, mp, op) {		\
	if (oplmsu_trace_on == MSU_TRACE_ON) {	\
		oplmsu_cmn_trace(q, mp, op);	\
	}					\
}

/* debug print macro */
#define	DBG_PRINT(args)	{				\
	if (oplmsu_debug_mode & MSU_DPRINT_ON) {	\
		cmn_err args;				\
	}						\
}

#else	/* ! DEBUG */

/* trace macro */
#define	OPLMSU_TRACE(q, mp, op)

/* debug print macro */
#define	DBG_PRINT(args)
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _OPLMSU_H */
