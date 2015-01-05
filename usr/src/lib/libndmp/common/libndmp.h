/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright 2014 Nexenta Systems, Inc.  All rights reserved. */
#ifndef	_LIBNDMP_H
#define	_LIBNDMP_H

#include <rpc/types.h>
#include <libscf.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* NDMP supported versions */
#define	NDMP_V2		2
#define	NDMP_V3		3
#define	NDMP_V4		4

/* Device type */
#define	NDMP_SINQ_SEQ_ACCESS_DEVICE	0x01
#define	NDMP_SINQ_TAPE_ROBOT		0x08

extern int ndmp_errno;

/* NDMP plugin module API */
#define	NDMP_PLUGIN_VERSION	1

typedef struct ndmp_context {
	char *nc_plname;
	uint_t nc_plversion;
	void *nc_pldata;	/* data private to the plugin */
	void *nc_cmds;
	void *nc_params;
	void *nc_ddata;		/* data private to the daemon */
} ndmp_context_t;

typedef struct ndmp_plugin {
	const char *np_plid;	/* plugin identifier */
	uint_t np_plversion;	/* plugin version */
	void *np_pldata;	/* for private use by the plugin */

	/* Plugin entry points */
	int (*np_pre_backup)(struct ndmp_plugin *, ndmp_context_t *,
		const char *);
	int (*np_post_backup)(struct ndmp_plugin *, ndmp_context_t *,
		int);
	int (*np_pre_restore)(struct ndmp_plugin *, ndmp_context_t *,
		const char *, const char *);
	int (*np_post_restore)(struct ndmp_plugin *, ndmp_context_t *,
		int);
} ndmp_plugin_t;

typedef enum ndmp_log_dma_type {
	NDMP_LOGD_NORMAL = 0,
	NDMP_LOGD_DEBUG = 1,
	NDMP_LOGD_ERROR = 2,
	NDMP_LOGD_WARNING = 3
} ndmp_log_dma_type_t;

typedef enum {
	NDMP_BUTYPE_TAR = 0,
	NDMP_BUTYPE_DUMP,
	NDMP_BUTYPE_ZFS
} ndmpd_backup_type_t;

extern ndmpd_backup_type_t ndmp_get_backup_type(ndmp_context_t *);

/* libndmp error codes */
#define	ENDMP_BASE	2000
enum {
	ENDMP_DOOR_SRV_TIMEOUT = ENDMP_BASE,
	ENDMP_INVALID_ARG,
	ENDMP_DOOR_SRV_OPERATION,
	ENDMP_DOOR_OPEN,
	ENDMP_MEM_ALLOC,
	ENDMP_DOOR_ENCODE_START,
	ENDMP_DOOR_ENCODE_FINISH,
	ENDMP_DOOR_DECODE_FINISH,
	ENDMP_SMF_PERM,
	ENDMP_SMF_INTERNAL,
	ENDMP_SMF_PROP,
	ENDMP_SMF_PROP_GRP
};

/* Tape device open mode */
typedef enum ndmp_tp_open_mode {
	NDMP_TP_READ_MODE,
	NDMP_TP_WRITE_MODE,
	NDMP_TP_RAW_MODE,
	NDMP_TP_RAW1_MODE = 0x7fffffff,
	NDMP_TP_RAW2_MODE = NDMP_TP_RAW_MODE
} ndmp_tp_open_mode_t;

/* Mover state */
typedef enum ndmp_mv_state {
	NDMP_MV_STATE_IDLE,
	NDMP_MV_STATE_LISTEN,
	NDMP_MV_STATE_ACTIVE,
	NDMP_MV_STATE_PAUSED,
	NDMP_MV_STATE_HALTED
} ndmp_mv_state_t;

/* Mover mode */
typedef enum ndmp_mv_mode {
	NDMP_MV_MODE_READ,
	NDMP_MV_MODE_WRITE,
	NDMP_MV_MODE_NOACTION
} ndmp_mv_mode_t;

/* Mover pause reson */
typedef enum ndmp_mv_pause_reason {
	NDMP_MV_PAUSE_NA,
	NDMP_MV_PAUSE_EOM,
	NDMP_MV_PAUSE_EOF,
	NDMP_MV_PAUSE_SEEK,
	NDMP_MV_PAUSE_MEDIA_ERROR,
	NDMP_MV_PAUSE_EOW
} ndmp_mv_pause_reason_t;

/* Mover halt reason */
typedef enum ndmp_mv_halt_reason {
	NDMP_MV_HALT_NA,
	NDMP_MV_HALT_CONNECT_CLOSED,
	NDMP_MV_HALT_ABORTED,
	NDMP_MV_HALT_INTERNAL_ERROR,
	NDMP_MV_HALT_CONNECT_ERROR,
	NDMP_MV_HALT_MEDIA_ERROR
} ndmp_mv_halt_reason_t;

/* Address type */
typedef enum ndmp_ad_type {
	NDMP_AD_LOCAL,
	NDMP_AD_TCP,
	NDMP_AD_FC,
	NDMP_AD_IPC
} ndmp_ad_type_t;

/* NDMP data operation */
typedef enum ndmp_dt_operation {
	NDMP_DT_OP_NOACTION,
	NDMP_DT_OP_BACKUP,
	NDMP_DT_OP_RECOVER,
	NDMP_DT_OP_RECOVER_FILEHIST
} ndmp_dt_operation_t;

/* NDMP data state */
typedef enum ndmp_dt_state {
	NDMP_DT_STATE_IDLE,
	NDMP_DT_STATE_ACTIVE,
	NDMP_DT_STATE_HALTED,
	NDMP_DT_STATE_LISTEN,
	NDMP_DT_STATE_CONNECTED
} ndmp_dt_state_t;

/* NDMP data halt reason */
typedef enum ndmp_dt_halt_reason {
	NDMP_DT_HALT_NA,
	NDMP_DT_HALT_SUCCESSFUL,
	NDMP_DT_HALT_ABORTED,
	NDMP_DT_HALT_INTERNAL_ERROR,
	NDMP_DT_HALT_CONNECT_ERROR
} ndmp_dt_halt_reason_t;

/* Device information structure */
typedef struct ndmp_devinfo {
	uint_t nd_dev_type;	/* SCSI device type */
	char *nd_name;		/* Device name */
	uint_t nd_lun;		/* Lun number */
	uint_t nd_sid;		/* Scsi id */
	char *nd_vendor;	/* Vendor name */
	char *nd_product;	/* Product name */
	char *nd_revision;	/* Revision */
	char *nd_serial;	/* Serial */
	char *nd_wwn;		/* World wide name */
} ndmp_devinfo_t;

/* Scsi device info sturcture */
typedef struct ndmp_scsi {
	int ns_scsi_open;		/* Scsi device open */
					/* -1 if not open */
	char *ns_adapter_name;		/* Scsi adapter name */
	int ns_valid_target_set;	/* Scsi valid target */
	/* scsi_id and lun are set only if valid_target_set is set */
	int ns_scsi_id;			/* Scsi id */
	int ns_lun;			/* Scsi lun */
} ndmp_scsi_t;

typedef struct ndmp_tape {
	int nt_fd;			/* Tape device file descriptor */
	/* The data below is set only if "fd" is not -1 */
	ulong_t nt_rec_count;		/* Number of records written */
	ndmp_tp_open_mode_t nt_mode;	/* Tape device open mode */
	char *nt_dev_name;		/* Device name */
	char *nt_adapter_name;		/* Adapter name */
	int nt_sid;			/* Scsi id	*/
	int nt_lun;			/* Lun number	*/
} ndmp_tape_t;

/* NDMP mover info structure */
typedef struct ndmp_mover {
	ndmp_mv_state_t nm_state;		/* Current state */
	ndmp_mv_mode_t nm_mode;			/* Current mode */
	ndmp_mv_pause_reason_t nm_pause_reason;	/* Current reason */
	ndmp_mv_halt_reason_t nm_halt_reason;	/* Current reason */
	ulong_t	nm_rec_size;			/* Tape I/O record size */
	ulong_t	nm_rec_num;			/* Current record num */
	u_longlong_t nm_mov_pos;		/* Current data stream pos */
	u_longlong_t nm_window_offset;		/* Valid data window begin */
	u_longlong_t nm_window_length;		/* Valid data window length */
	int nm_sock;				/* Data conn socket */

	/* Filled in V3 and V4 only */
	int nm_listen_sock;			/* Data conn listen socket */
	ndmp_ad_type_t nm_addr_type;		/* Current address type */
	char *nm_tcp_addr;			/* Only if addr_type is tcp */
} ndmp_mover_t;

typedef struct ndmp_dt_name {
	char *nn_name;
	char *nn_dest;
} ndmp_dt_name_t;

/* NDMP name/value pair structure */
typedef struct ndmp_dt_pval {
	char *np_name;
	char *np_value;
} ndmp_dt_pval_t;

typedef struct ndmp_dt_name_v3 {
	char *nn3_opath;
	char *nn3_dpath;
	u_longlong_t nn3_node;
	u_longlong_t nn3_fh_info;
} ndmp_dt_name_v3_t;

typedef struct ndmp_dt_v3 {
	int dv3_listen_sock;
	u_longlong_t dv3_bytes_processed;
	ndmp_dt_name_v3_t *dv3_nlist;		/* V3 recover file list */
} ndmp_dt_v3_t;

/* NDMP data structure */
typedef struct ndmp_data {
	ndmp_dt_operation_t nd_oper;		/* Current operation */
	ndmp_dt_state_t nd_state;		/* Current state */
	ndmp_dt_halt_reason_t nd_halt_reason;	/* Current reason */
	int nd_sock;				/* Listen and data socket */
	ndmp_ad_type_t nd_addr_type;		/* Current address type */
	char *nd_tcp_addr;			/* Only if addr_type is tcp */
	int nd_abort;				/* Abort operation flag */
						/* 0 = No, otherwise Yes */
	u_longlong_t nd_read_offset;		/* Data read seek offset */
	u_longlong_t nd_read_length;		/* Data read length */
	u_longlong_t nd_total_size;		/* Backup data size */
	ulong_t nd_env_len;			/* Environment length */
	ndmp_dt_pval_t *nd_env;			/* Environment from backup */
						/* or recover request */
	ulong_t nld_nlist_len;			/* Recover file list length */
	union {
		/* Filled in V2 */
		ndmp_dt_name_t *nld_nlist;	/* Recover file list */
		/* Filled in V3 */
		ndmp_dt_v3_t nld_dt_v3;		/* V3 data */
	} nd_nlist;
} ndmp_data_t;

/* NDMP session information  */
typedef struct ndmp_session_info {
	int nsi_sid;		/* Session id   */
	int nsi_pver;		/* NDMP protocol version */
	int nsi_auth;		/* Authorized ? 0="no", else "yes" */
	int nsi_eof;		/* Connection EOF flag */
				/* 0="no", else "yes" */
	char *nsi_cl_addr;	/* Client address */
	ndmp_scsi_t nsi_scsi;	/* Scsi device information */
	ndmp_tape_t nsi_tape;	/* Tape device information */
	ndmp_mover_t nsi_mover;	/* Mover information */
	ndmp_data_t nsi_data;	/* Data information */
} ndmp_session_info_t;

/* Stats data */
typedef struct ndmp_stat {
	int ns_trun;		/* Number of worker threads running */
	int ns_twait;		/* Number of blocked worker threads */
	int ns_nbk;		/* Number of backups operations running */
	int ns_nrs;		/* Number of restores operations running */
	int ns_rfile;		/* Number of files being read */
	int ns_wfile;		/* Number of files being written */
	uint64_t ns_rdisk;	/* Number of disk blocks being read */
	uint64_t ns_wdisk;	/* Number of disk blocks being written */
	uint64_t ns_rtape;	/* Number of tape blocks being read */
	uint64_t ns_wtape;	/* Number of tape blocks being written */
} ndmp_stat_t;

/* Common encode/decode functions used by door clients/servers.  */
typedef struct ndmp_door_ctx {
	char *ptr;
	char *start_ptr;
	char *end_ptr;
	int status;
} ndmp_door_ctx_t;

extern int ndmp_get_devinfo(ndmp_devinfo_t **, size_t *);
extern void ndmp_get_devinfo_free(ndmp_devinfo_t *, size_t);
extern int ndmp_get_dbglevel(void);
extern int ndmp_get_session_info(ndmp_session_info_t **, size_t *);
extern void ndmp_get_session_info_free(ndmp_session_info_t *, size_t);
extern int ndmp_get_stats(ndmp_stat_t *);
extern int ndmp_terminate_session(int);
extern int ndmp_set_dbglevel(int);
extern const char *ndmp_strerror(int);
extern int ndmp_door_status(void);
extern int ndmp_get_prop(const char *, char **);
extern int ndmp_set_prop(const char *, const char *);
extern int ndmp_service_refresh(void);
extern char *ndmp_base64_encode(const char *);
extern char *ndmp_base64_decode(const char *);
extern ndmp_door_ctx_t *ndmp_door_decode_start(char *, int);
extern int ndmp_door_decode_finish(ndmp_door_ctx_t *);
extern ndmp_door_ctx_t *ndmp_door_encode_start(char *, int);
extern int ndmp_door_encode_finish(ndmp_door_ctx_t *, unsigned int *);
extern int32_t ndmp_door_get_int32(ndmp_door_ctx_t *);
extern uint32_t ndmp_door_get_uint32(ndmp_door_ctx_t *);
extern char *ndmp_door_get_string(ndmp_door_ctx_t *);
extern void ndmp_door_put_int32(ndmp_door_ctx_t *, int32_t);
extern void ndmp_door_put_uint32(ndmp_door_ctx_t *, uint32_t);
extern void ndmp_door_put_string(ndmp_door_ctx_t *, char *);
extern void ndmp_door_free_string(char *);
extern int64_t ndmp_door_get_int64(ndmp_door_ctx_t *);
extern uint64_t ndmp_door_get_uint64(ndmp_door_ctx_t *);
extern void ndmp_door_put_uint64(ndmp_door_ctx_t *, uint64_t);
extern void ndmp_door_put_short(ndmp_door_ctx_t *, short);
extern short ndmp_door_get_short(ndmp_door_ctx_t *);
extern void ndmp_door_put_ushort(ndmp_door_ctx_t *, unsigned short);
extern unsigned short ndmp_door_get_ushort(ndmp_door_ctx_t *);
extern void ndmp_door_put_buf(ndmp_door_ctx_t *, unsigned char *, int);
extern int ndmp_door_get_buf(ndmp_door_ctx_t *, unsigned char *, int);

extern int ndmp_include_zfs(ndmp_context_t *, const char *);
extern int ndmp_iter_zfs(ndmp_context_t *, int (*)(nvlist_t *, void *), void *);
extern uint_t ndmp_context_get_version(ndmp_context_t *);
extern void ndmp_context_set_specific(ndmp_context_t *, void *);
extern void *ndmp_context_get_specific(ndmp_context_t *);
void ndmp_log_dma(ndmp_context_t *, ndmp_log_dma_type_t, const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBNDMP_H */
