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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISCSI_STATS_H
#define	_ISCSI_STATS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains all the definitions and prototypes relevant to KSTAT.
 * It also contains the declaration and initialization of data.  When including
 * this file, if _INIT_KSTAT_DATA_ is defined, the data is declared AND
 * initialized. As a consequence, this file should be included only once with
 * _INIT_KSTAT_DATA_ defined.  Failure to do so will lead to a link error.
 * Today, iscsi_stats.c is the only file defining _INIT_KSTAT_DATA_.
 *
 * Four types of KSTAT structures are created for iSCSI.
 *
 *   sun_iscsi_hba
 *   -------------
 *
 *	This structure gathers statistics relevant to an HBA. Each HBA or
 *	software state structure is given one.  It contains the following
 *	fieds:
 *
 *	  _name			iSCSI name of the HBA
 *	  _alias		iSCSI alias of the HBA
 *	  _cntr_sess		Numbers of sessions created
 *
 *   sun_iscsi_sess
 *   --------------
 *
 *	This structure gathers statistics relevant to a session.  Each session
 *	is given one.  It contains the following fields:
 *
 *	  _state		State of the session
 *	  _oid			OID of the session
 *	  _hba			HBA the session belongs to.  It is the name
 *				of the sun_iscsi_hba structure of the HBA
 *	  _cntr_conn		Number of connections
 *	  _cntr_pkt_pending	Number of scsi_pkt in the pending queue
 *	  _cmd_sn		CmdSN
 *	  _cmd_sn_exp		CmdSNExp,
 *	  _cmd_sn_max		CmdSNMax
 *
 *   sun_iscsi_sess_io
 *   -----------------
 *
 *	This structure is completely defined by the KSTAT frame work of Solaris.
 *	It contains accumulated time and queue length statistics.  It assumes
 *	the driver has a pending queue and an active.  In our implementation,
 *	the pending queue is the pending queue defined in the session context.
 *	The active queue is any queue defined in the connection context.
 *	If you want more information about the meaning of the fields of this
 *	structure you can read the nice explanation contained in the file:
 *	/usr/src/uts/common/sys/kstat.h.
 *	At any rate, all the sessions are given a sun_iscsi_sess_io structure.
 *	The fields are:
 *
 *	  nread			number of bytes read without iSCSI overhead.
 *	  nwritten		number of bytes written without iSCSI overhead.
 *	  reads			number of read operations
 *	  writes		number of write operations
 *	  wtime			cumulative wait (pre-service) time
 *	  wlentime		cumulative wait length*time product
 *	  wlastupdate		last time wait queue changed
 *	  rtime			cumulative run (service) time
 *	  rlentime		cumulative run length*time product
 *	  rlastupdate		last time run queue changed
 *	  wcnt			count of elements in wait state
 *	  rcnt			count of elements in run state
 *
 *	The time is expressed in nanoseconds.
 *
 *   sun_iscsi_conn
 *   --------------
 *
 *	This structure gathers statistics relevant to a connection.  Each
 *      connection is given one.  It contains the following fields:
 *
 *	  _state		State of the connection
 *	  _cid			iSCSI CID
 *	  _oid			OID of the connection
 *	  _session		Session the connection belongs to.  It is the
 *				name of the sun_iscsi_sess structure of the
 *				session.
 *	  _err_header_digest	Number of header digest errors
 *	  _err_data_digest	Number of data digest errors
 *	  _err_connection_reset	Number of reset
 *	  _err_protocol_error	Number of protocol errors
 *	  _cntr_tx_bytes	Number of bytes transmitted with iSCSI overhead.
 *	  _cntr_rx_bytes	Number of bytes received with iSCSI overhead.
 *	  _cntr_qactive		Number of requests in the active queue.
 *	  _stat_sn_exp		ExpStatusSN
 *	  _stat_sn_last		LastStatusSN (Last one sent to the target)
 *
 *
 *
 * The KSTAT frame work of Solaris associates a module name, a instance number
 * a class and a name to every kstat structure.  All the kstat structures of
 * iSCSI have the same module name. It is define farther down in this file to
 * "iscsi".  Regarding the class, three classes are defined here. Those classes
 * are:
 *
 *   - issci_hba
 *   - iscsi_sess
 *   - iscsi_conn
 *
 * The instance number is the number returned by ddi_get_instance.  Today the
 * the driver creates one HBA only.  Therefore, all the structures will have
 * zero as instance number.
 *
 *
 * Each kstat structure can be named.  The naming convention is the following:
 *
 *	KSTAT Struct	   Class	Name
 *
 *	sun_iscsi_hba	   iscsi_hba	"sun_iscsi_hba" + instance number
 *	sun_iscsi_sess	   iscsi_sess	"sun_iscsi_sess" + session oid
 *	sun_iscsi_sess_io  iscsi_sess	"sun_iscsi_sess_io" + session oid
 *	sun_iscsi_conn	   iscsi_conn	"sun_iscsi_conn" + connection oid
 */

/*
 * strings used by kstat (Module name and Class name).
 */
#define	iSCSI_MODULE_NAME	"iscsi"

typedef struct _kstat_item {
	char		*_name;
	uchar_t		_data_type;
} kstat_item_t;

/*
 * ========================= Connection Class Section ======================
 */

#define	iSCSI_CLASS_CONN			"iscsi_conn"
#define	iSCSI_CONN_BASE_NAME			"iscsi_conn_%d_%d_%d"

#define	ISCSI_CONN_STATE_FREE_STR		"free"
#define	ISCSI_CONN_STATE_IN_LOGIN_STR		"in_login"
#define	ISCSI_CONN_STATE_LOGGED_IN_STR		"logged_in"
#define	ISCSI_CONN_STATE_IN_LOGOUT_STR		"in_logout"
#define	ISCSI_CONN_STATE_CLEANUP_WAIT_STR	"cleanup_wait"

/*
 * WARNING: The order of this enum important.  If you change it you have to
 *          reorder the table kstat_items_conn (in the file iscsi_stats.c)
 *	    accordingly.
 */
typedef enum _kn_conn_idx {
	KN_CONN_IDX_STATE = 0,
	KN_CONN_IDX_CID,
	KN_CONN_IDX_OID,
	KN_CONN_IDX_SESS,
	KN_CONN_IDX_ERR_HDR_DIGEST,
	KN_CONN_IDX_ERR_DATA_DIGEST,
	KN_CONN_IDX_ERR_CONN_RESET,
	KN_CONN_IDX_ERR_PROTOCOL,
	KN_CONN_IDX_CNTR_TX_BYTES,
	KN_CONN_IDX_CNTR_RX_BYTES,
	KN_CONN_IDX_CNTR_QACTIVE,
	KN_CONN_IDX_EXPSTATSN,
	KN_CONN_IDX_LASTSTATSN,
	KN_CONN_IDX_MAX
} kn_conn_idx_t;

typedef struct _iscsi_conn_kstats {
	kstat_named_t	kn[KN_CONN_IDX_MAX];
	char 		sess_str[KSTAT_STRLEN];
	char 		state_str[KSTAT_STRLEN];
} iscsi_conn_stats_t;

#define	KSTAT_INC_CONN_ERR_HEADER_DIGEST(_icp_) \
	(_icp_->stats.ks_data.kn[KN_CONN_IDX_ERR_HDR_DIGEST].value.ul++)

#define	KSTAT_INC_CONN_ERR_DATA_DIGEST(_icp_) \
	(_icp_->stats.ks_data.kn[KN_CONN_IDX_ERR_DATA_DIGEST].value.ul++)

#define	KSTAT_INC_CONN_ERR_PROTOCOL(_icp_) \
	(_icp_->stats.ks_data.kn[KN_CONN_IDX_ERR_PROTOCOL].value.ul++)

#define	KSTAT_INC_CONN_ERR_RESET(_icp_) \
	(_icp_->stats.ks_data.kn[KN_CONN_IDX_ERR_CONN_RESET].value.ul++)

#define	KSTAT_ADD_CONN_TX_BYTES(_icp_, _v_) \
	(_icp_->stats.ks_data.kn[KN_CONN_IDX_CNTR_TX_BYTES].value.ui64 += \
	_v_)

#define	KSTAT_ADD_CONN_RX_BYTES(_icp_, _v_) \
	(_icp_->stats.ks_data.kn[KN_CONN_IDX_CNTR_RX_BYTES].value.ui64 += \
	_v_)

/*
 * ========================== Session Class Section ========================
 */

/* Session Class */
#define	iSCSI_CLASS_SESS			"iscsi_sess"
#define	iSCSI_SESS_BASE_NAME			"iscsi_sess_%d_%d"
#define	iSCSI_SESS_IO_BASE_NAME			"iscsi_sess_io_%d_%d"

#define	ISCSI_SESS_STATE_FREE_STR		"free"
#define	ISCSI_SESS_STATE_LOGGED_IN_STR		"logged_in"
#define	ISCSI_SESS_STATE_FAILED_STR		"failed"

/*
 * WARNING: The order of this enum important.  If you change it you have to
 *          reorder the table kstat_items_sess (in the file iscsi_stats.c)
 *	    accordingly.
 */
typedef enum _kn_sess_idx {
	KN_SESS_IDX_STATE = 0,
	KN_SESS_IDX_OID,
	KN_SESS_IDX_HBA,
	KN_SESS_IDX_CNTR_CONN,
	KN_SESS_IDX_CNTR_RESET,
	KN_SESS_IDX_CNTR_PKT_PENDING,
	KN_SESS_IDX_CMDSN,
	KN_SESS_IDX_EXPCMDSN,
	KN_SESS_IDX_MAXCMDSN,
	KN_SESS_IDX_TARGET_NAME,
	KN_SESS_IDX_TARGET_ALIAS,
	KN_SESS_IDX_TPGT,
	KN_SESS_IDX_MAX
} kn_sess_idx_t;

typedef struct _iscsi_sess_stats {
	kstat_named_t	kn[KN_SESS_IDX_MAX];
	char 		hba_str[KSTAT_STRLEN];
	char 		state_str[KSTAT_STRLEN];
	char 		target_name[ISCSI_MAX_NAME_LEN];
	char 		target_alias[ISCSI_MAX_NAME_LEN];
} iscsi_sess_stats_t;

#define	KSTAT_INC_SESS_CNTR_RESET(_isp_) \
	(_isp_->stats.ks_data.kn[KN_SESS_IDX_CNTR_RESET].value.ul++)

#define	KSTAT_INC_SESS_CNTR_CONN(_isp_) \
	(_isp_->stats.ks_data.kn[KN_SESS_IDX_CNTR_CONN].value.ul++)

#define	KSTAT_DEC_SESS_CNTR_CONN(_isp_) \
	(_isp_->stats.ks_data.kn[KN_SESS_IDX_CNTR_CONN].value.ul--)

#define	KSTAT_ADD_SESS_CNTR_TX_BYTES(_isp_, _v_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(_isp_->stats.ks_io_data.nwritten += _v_); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_ADD_SESS_CNTR_RX_BYTES(_isp_, _v_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(_isp_->stats.ks_io_data.nread += _v_); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_INC_SESS_CNTR_NWRITES(_isp_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(_isp_->stats.ks_io_data.writes++); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_INC_SESS_CNTR_NREADS(_isp_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(_isp_->stats.ks_io_data.reads++); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_WAITQ_ENTER(_isp_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(kstat_waitq_enter(&_isp_->stats.ks_io_data)); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_WAITQ_EXIT(_isp_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(kstat_waitq_exit(&_isp_->stats.ks_io_data)); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_RUNQ_ENTER(_isp_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(kstat_runq_enter(&_isp_->stats.ks_io_data)); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_RUNQ_EXIT(_isp_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(kstat_runq_exit(&_isp_->stats.ks_io_data)); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_SESS_TX_IO_DONE(_isp_, _v_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(_isp_->stats.ks_io_data.nwritten += _v_); \
	(_isp_->stats.ks_io_data.writes++); \
	mutex_exit(&_isp_->stats.ks_io_lock);

#define	KSTAT_SESS_RX_IO_DONE(_isp_, _v_) \
	mutex_enter(&_isp_->stats.ks_io_lock); \
	(_isp_->stats.ks_io_data.nread += _v_); \
	(_isp_->stats.ks_io_data.reads++); \
	mutex_exit(&_isp_->stats.ks_io_lock);

/*
 * ============================ HBA Class Section ==========================
 */

#define	iSCSI_CLASS_HBA		"iscsi_hba"
#define	iSCSI_HBA_BASE_NAME	"iscsi_hba_%d"

/*
 * WARNING: The order of this enum important.  If you change it you have to
 *          reorder the table kstat_items_hba (in iscsi_stats.c) accordingly.
 */
typedef enum _kn_hba_idx {
	KN_HBA_IDX_NAME = 0,
	KN_HBA_IDX_ALIAS,
	KN_HBA_IDX_CNTR_SESS,
	KN_HBA_IDX_MAX
} kn_hba_idx_t;

typedef struct _iscsi_hba_stats {
	kstat_named_t	kn[KN_HBA_IDX_MAX];
	char 		name[ISCSI_MAX_NAME_LEN];
	char 		alias[ISCSI_MAX_NAME_LEN];
} iscsi_hba_stats_t;

#define	KSTAT_INC_HBA_CNTR_SESS(_ihp_) \
	(_ihp_->stats.ks_data.kn[KN_HBA_IDX_CNTR_SESS].value.ul++)

#define	KSTAT_DEC_HBA_CNTR_SESS(_ihp_) \
	(_ihp_->stats.ks_data.kn[KN_HBA_IDX_CNTR_SESS].value.ul--)

#ifdef __cplusplus
}
#endif

#endif	/* _ISCSI_STATS_H */
