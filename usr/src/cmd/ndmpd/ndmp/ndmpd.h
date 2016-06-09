/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015 by Delphix. All rights reserved.
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
/* Copyright 2014 Nexenta Systems, Inc.  All rights reserved.  */

#ifndef _NDMPD_H
#define	_NDMPD_H

#include <sys/types.h>
#include <libzfs.h>
#include <ndmpd_door.h>
#include <libndmp.h>
#include "ndmpd_common.h"
#include "tlm_buffers.h"
#include <dirent.h>
#include "ndmpd_prop.h"
#include "traverse.h"
#include <pthread.h>
#include <libndmp.h>
#include <atomic.h>

#define	MAX_RECORD_SIZE (126*512)
#define	REMOTE_RECORD_SIZE    (60*KILOBYTE)
#define	SCSI_MAX_NAME 32
#define	MD5_CHALLENGE_SIZE	64
#define	MD5_PASS_LIMIT		32

/* Test unit ready */
#define	TUR_WAIT	3000000
#define	TUR_MAX_TRY	3


/* File handler classes */
#define	HC_CLIENT	1
#define	HC_MOVER	2
#define	HC_MODULE	4
#define	HC_ALL		0xffffffff

#define	IN_ADDR(x) \
	(*(struct in_addr *)&x)

#define	FS_READONLY(fs)		(hasmntopt(fs, "ro")  ? 1 :  0)

typedef void *(*funct_t)(void *);	/* function pointer */

#define	HOSTNAMELEN	256

#define	VENDOR_NAME	"Sun Microsystems"
#define	PRODUCT_NAME	"Solaris 5.11"

/*
 * Calculate array length based on its size and size of
 * its elements.
 */
#define	ARRAY_LEN(a, t)	(sizeof (a) / sizeof (t))
/*
 * Default maximum permitted sequence number for the token-based backup.
 */
#define	NDMP_MAX_TOKSEQ	9

/*
 * Hard-limit for the sequence number in the token-based backup.
 * It's one less than the ASCII value of 'A'.  The 'A' letter
 * can be used as level in the lbr-type backups.
 */
#define	NDMP_TOKSEQ_HLIMIT	('A' - 1)


/*
 * Soft-limit for the sequence number in the token-based backup.
 */
#define	NDMP_TOKSEQ_SLIMIT	(NDMP_TOKSEQ_HLIMIT - 5)


/*
 * Root inode number of dump format in V2.
 */
#define	ROOT_INODE	2

/*
 * NDMP backup image signature
 */
#define	NDMPUTF8MAGIC "NDMPUTF8MAGIC"

/*
 * Supported BU types
 */
#define	NDMP_TAR_TYPE	"tar"
#define	NDMP_DUMP_TYPE	"dump"
#define	NDMP_ZFS_TYPE	"zfs"

/* All 1's binary maximum mover window */
#define	MAX_WINDOW_SIZE	0xffffffffffffffffULL

#define	NDMP_FREE(cp)	{ free((char *)(cp)); (cp) = NULL; }

#define	NDMP_YORN(f)	((f) ? 'Y' : 'N')
#define	NDMP_TORF(f)	((f) ? "TRUE" : "FALSE")
#define	NDMP_SVAL(cp)	((cp) ? (cp) : "NULL")

#define	NDMP_SETENV(env, nm, val) \
	{ \
		env->name = nm; \
		env->value = val; \
		env++; \
	}

#define	NDMP_CL_ADDR_LEN	24
#define	NDMP_TCP_ADDR_SIZE	32
#define	NDMP_TAPE_DEV_NAME	256

typedef struct {
	char *bk_path;
	int bk_llevel; /* last backup level */
	time_t bk_ldate; /* last backup date */
	int bk_clevel;	/* current backup level */
	time_t bk_cdate; /* current backup date */
	int bk_map;
	int bk_dirino;
	char *bk_dmpnm;
	char **bk_exl; /* exlude list */
	char **bk_inc; /* include list */
} ndmp_backup_params_t;


typedef struct {
	ulong_t rs_nf;	/* number of files to restore */
	char *rs_path;
	char *rs_bkpath;
	int *rs_restored;
	int rs_bm;
	int rs_lastidx;
} ndmp_restore_params_t;

/*
 * Tar format archiving ops table
 */
extern tm_ops_t tm_tar_ops;

/*
 * IS_LBR_BKTYPE shows if the backup type is one of these
 * 'F' of 'f': 'Full' backup type.
 * 'A' of 'a': 'Archive' backup type.
 * 'I' of 'i': 'Incremental' backup type.
 * 'D' of 'd': 'Differntial' backup type.
 */
#define	IS_LBR_BKTYPE(t)	(((t) && strchr("FAID", toupper(t))) ? 1 : 0)


/*
 * NLP flags.
 */
#define	NLPF_CHKPNTED_PATH	(1 << 0)
#define	NLPF_FH			(1 << 1)
#define	NLPF_DIRECT		(1 << 2)
#define	NLPF_UPDATE		(1 << 3)
#define	NLPF_DUMP		(1 << 4)
#define	NLPF_TAR		(1 << 5)
#define	NLPF_ABORTED		(1 << 6)
#define	NLPF_TOKENBK		(1 << 8)
#define	NLPF_LBRBK		(1 << 9)
#define	NLPF_LEVELBK		(1 << 10)
#define	NLPF_IGNCTIME		(1 << 11)
#define	NLPF_INCLMTIME		(1 << 12)
#define	NLPF_RECURSIVE		(1 << 13)

/*
 * Macros on NLP flags.
 */
#define	NLP_ISSET(n, f)	(((n)->nlp_flags & (f)) != 0)
#define	NLP_SET(n, f)	(n)->nlp_flags |= (f)
#define	NLP_UNSET(n, f)	(n)->nlp_flags &= ~(f)


#define	NLP_ISCHKPNTED(n)	NLP_ISSET(n, NLPF_CHKPNTED_PATH)
#define	NLP_SHOULD_UPDATE(n)	NLP_ISSET(n, NLPF_UPDATE)
#define	NLP_ISDUMP(n)		NLP_ISSET(n, NLPF_DUMP)
#define	NLP_ISTAR(n)		NLP_ISSET(n, NLPF_TAR)
#define	NLP_IGNCTIME(n)		NLP_ISSET(n, NLPF_IGNCTIME)
#define	NLP_INCLMTIME(n)	NLP_ISSET(n, NLPF_INCLMTIME)

/*
 * NDMP statistics
 */
#define	NS_INC(s)	(atomic_inc_32((volatile uint32_t *)&ndstat.ns_##s))
#define	NS_DEC(s)	(atomic_dec_32((volatile uint32_t *)&ndstat.ns_##s))
#define	NS_ADD(s, d)	(atomic_add_64((volatile uint64_t *)&ndstat.ns_##s, \
	(uint64_t)d))
#define	NS_UPD(s, t)	{ \
	atomic_inc_32((volatile uint32_t *)&ndstat.ns_##s); \
	atomic_dec_32((volatile uint32_t *)&ndstat.ns_##t); \
	}

#define	NLP_READY	1

typedef struct ndmp_lbr_params {
	struct ndmpd_session *nlp_session;
	int nlp_flags;

	ndmp_backup_params_t bk_params;
	ndmp_restore_params_t rs_params;
#define	nlp_backup_path	bk_params.bk_path
#define	nlp_llevel	bk_params.bk_llevel
#define	nlp_ldate	bk_params.bk_ldate
#define	nlp_clevel	bk_params.bk_clevel
#define	nlp_tokseq	nlp_clevel
#define	nlp_tokdate	nlp_ldate
#define	nlp_cdate	bk_params.bk_cdate
#define	nlp_bkmap	bk_params.bk_map
#define	nlp_bkdirino	bk_params.bk_dirino
#define	nlp_dmpnm	bk_params.bk_dmpnm
#define	nlp_exl		bk_params.bk_exl
#define	nlp_inc		bk_params.bk_inc

#define	nlp_nfiles	rs_params.rs_nf
#define	nlp_restore_path	rs_params.rs_path
#define	nlp_restore_bk_path	rs_params.rs_bkpath
#define	nlp_restored	rs_params.rs_restored
#define	nlp_rsbm	rs_params.rs_bm
#define	nlp_lastidx	rs_params.rs_lastidx

	ndmpd_module_params_t *nlp_params;
	tlm_job_stats_t *nlp_jstat;
	lbr_fhlog_call_backs_t *nlp_logcallbacks;
	tlm_commands_t nlp_cmds;

	cond_t	nlp_cv;		/* for signaling a processed request */
	mutex_t nlp_mtx;	/* mutex to synchronize access to nlp_cv */
	u_longlong_t nlp_bytes_total;
} ndmp_lbr_params_t;


typedef struct mem_ndmp_name_v3 {
	char *nm3_opath;
	char *nm3_dpath;
	char *nm3_newnm;
	u_longlong_t nm3_node;
	u_longlong_t nm3_fh_info;
	ndmp_error nm3_err;
} mem_ndmp_name_v3_t;

typedef struct ndmpd_file_handler {
	int fh_fd;
	ulong_t fh_mode;
	ulong_t fh_class;
	void *fh_cookie;
	ndmpd_file_handler_func_t *fh_func;
	struct ndmpd_file_handler *fh_next;
} ndmpd_file_handler_t;

typedef struct ndmpd_session_scsi_desc {
	int sd_is_open;
	int sd_devid;
	boolean_t sd_valid_target_set;
	int sd_sid;
	int sd_lun;
	char sd_adapter_name[SCSI_MAX_NAME];
} ndmpd_session_scsi_desc_t;

typedef struct ndmpd_session_tape_desc {
	int td_fd;			/* tape device file descriptor */
	ulong_t td_record_count;	/* number of records written */
	ndmp_tape_open_mode td_mode;	/* tape device open mode */
	u_longlong_t td_pos;	/* current position on the current tape */
	int td_sid;
	int td_lun;
	char td_adapter_name[SCSI_MAX_NAME];
} ndmpd_session_tape_desc_t;

typedef struct ndmpd_session_mover_desc {
	ndmp_mover_state md_state;	/* current state */
	ndmp_mover_mode md_mode;	/* current mode */
	ndmp_mover_pause_reason md_pause_reason;	/* current reason */
	ndmp_mover_halt_reason md_halt_reason;	/* current reason */
	u_longlong_t md_data_written;	/* total written to tape */
	u_longlong_t md_seek_position;	/* current seek position */
	u_longlong_t md_bytes_left_to_read; /* #bytes to end of seek window */
	u_longlong_t md_window_offset;	/* valid data window begin */
	u_longlong_t md_window_length;	/* valid data window length */
	u_longlong_t md_position;	/* current data stream pos */
	boolean_t md_pre_cond;		/* used for precondition checks */
	ulong_t md_record_size;	/* tape I/O record size */
	ulong_t md_record_num;	/* current record num */
	int md_listen_sock;		/* data conn listen socket */
	int md_sock;		/* data conn socket */
	ulong_t md_r_index;		/* buffer read  index */
	ulong_t md_w_index;		/* buffer write index */
	char *md_buf;		/* data buffer */
	/*
	 * V2 fields.
	 */
	ulong_t md_discard_length;	/* bytes to discard */

	/*
	 * V3 fields.
	 */
	ndmp_addr_v3 md_data_addr;
	/*
	 * V4 fields.
	 */
	ndmp_addr_v4 md_data_addr_v4;
} ndmpd_session_mover_desc_t;


typedef struct ndmpd_session_data_module {
	void *dm_module_cookie;	/* sent as abort_func param */
	module_start_func_t *dm_start_func;	/* start function */
	module_abort_func_t *dm_abort_func;	/* abort function */
	ndmpd_module_stats dm_stats;	/* statistics buffer */
} ndmpd_session_data_module_t;

typedef struct ndmpd_session_data_desc {
	/*
	 * Common fields.
	 */
	ndmp_data_operation dd_operation;	/* current operation */
	boolean_t dd_abort;		/* abort operation flag */
	boolean_t dd_io_ready;		/* mover sock read for I/O */
	ndmp_pval *dd_env;	/* environment from backup or recover request */
	ulong_t dd_env_len;		/* environment length */
	ulong_t dd_nlist_len;	/* recover file list length */
	int dd_sock;		/* listen and data socket */
	u_longlong_t dd_read_offset;	/* data read seek offset */
	u_longlong_t dd_read_length;	/* data read length */
	u_longlong_t dd_data_size;	/* data size to be backed up */
	ndmpd_session_data_module_t dd_module;

	ndmp_data_state dd_state;	/* current state */
	ndmp_data_halt_reason dd_halt_reason;		/* current reason */
	/*
	 * V2 fields.
	 */
	ndmp_name *dd_nlist;	/* recover file list */
	ndmp_mover_addr dd_mover;	/* mover address */
	/*
	 * V3 fields.
	 */
	mem_ndmp_name_v3_t *dd_nlist_v3;
	ndmp_addr_v3 dd_data_addr;
	int dd_listen_sock;	/* socket for listening for remote */
				/* mover connections */
	u_longlong_t dd_bytes_left_to_read;
	u_longlong_t dd_position;
	u_longlong_t dd_discard_length;
	/*
	 * V4 fields.
	 */
	ndmp_addr_v4 dd_data_addr_v4;
} ndmpd_session_data_desc_t;

typedef struct ndmpd_session_file_history {
	ndmp_fh_unix_path *fh_path_entries;
	ndmp_fh_unix_dir *fh_dir_entries;
	ndmp_fh_unix_node *fh_node_entries;
	char *fh_path_name_buf;
	char *fh_dir_name_buf;
	ulong_t fh_path_index;
	ulong_t fh_dir_index;
	ulong_t fh_node_index;
	ulong_t fh_path_name_buf_index;
	ulong_t fh_dir_name_buf_index;
} ndmpd_session_file_history_t;

typedef struct ndmpd_session_file_history_v3 {
	ndmp_file_v3 *fh_files;
	ndmp_dir_v3 *fh_dirs;
	ndmp_node_v3 *fh_nodes;
	ndmp_file_name_v3 *fh_file_names;
	ndmp_file_name_v3 *fh_dir_names;
	ndmp_file_stat_v3 *fh_file_stats;
	ndmp_file_stat_v3 *fh_node_stats;
	char *fh_file_name_buf;
	char *fh_dir_name_buf;
	ulong_t fh_file_index;
	ulong_t fh_dir_index;
	ulong_t fh_node_index;
	ulong_t fh_file_name_buf_index;
	ulong_t fh_dir_name_buf_index;
} ndmpd_session_file_history_v3_t;

/*
 * zfs-based backup (zfs send/recv)
 */

typedef enum {
	NDMPD_ZFS_MAJOR_0,
} ndmpd_zfs_major_t;

typedef enum {
	NDMPD_ZFS_MINOR_0,
} ndmpd_zfs_minor_t;

typedef enum {
	NDMPD_ZFS_PROP_MAJOR_0,
} ndmpd_zfs_prop_major_t;

typedef enum {
	NDMPD_ZFS_PROP_MINOR_0,
} ndmpd_zfs_prop_minor_t;

#define	NDMPD_ZFS_MAJOR_VERSION NDMPD_ZFS_MAJOR_0
#define	NDMPD_ZFS_MINOR_VERSION NDMPD_ZFS_MINOR_0
#define	NDMPD_ZFS_PROP_MAJOR_VERSION NDMPD_ZFS_PROP_MAJOR_0
#define	NDMPD_ZFS_PROP_MINOR_VERSION NDMPD_ZFS_PROP_MINOR_0

#pragma pack(1)
typedef struct {
	char nzh_magic[14]; /* NDMPUTF8MAGIC\0 */
	uint32_t nzh_major; /* major version */
	uint32_t nzh_minor; /* minor version */
	uint32_t nzh_hdrlen; /* length of hdr in bytes including magic */
	/* future extensions */
} ndmpd_zfs_header_t;
#pragma pack()

#define	PIPE_TAPE 0
#define	PIPE_ZFS 1

#define	NDMPD_ZFS_DMP_NAME_MAX 32

typedef struct ndmpd_zfs_args {
	zfs_type_t nz_type;			/* type of ZFS dataset */
	char nz_dataset[ZFS_MAX_DATASET_NAME_LEN]; /* dataset name */
	char nz_snapname[ZFS_MAX_DATASET_NAME_LEN]; /* snapname (following @) */
	char nz_fromsnap[ZFS_MAX_DATASET_NAME_LEN]; /* snap of L-1 bkup */
	char nz_snapprop[ZFS_MAXPROPLEN];	/* contents of snap incr prop */
	boolean_t nz_ndmpd_snap;		/* ndmpd-generated snap? */

	pthread_t nz_sendrecv_thread;		/* thread for send/recv */
	pthread_t nz_tape_thread;		/* thread for tape r/w */
	int32_t nz_pipe_fd[2];			/* pipe for above 2 threads */
	int32_t nz_bufsize;			/* tape r/w buf size */
	int64_t nz_window_len;			/* DMA window length */

	int nz_level;				/* val of LEVEL env var */
	char nz_zfs_mode;			/* val of ZFS_MODE env var */
	boolean_t nz_zfs_force;			/* val of ZFS_FORCE env var */
	boolean_t nz_update;			/* val of UPDATE env var */
	char nz_dmp_name[NDMPD_ZFS_DMP_NAME_MAX]; /* val of DMP_NAME env var */
	u_longlong_t nz_zfs_backup_size;	/* used for restore only */

	ndmpd_module_params_t nz_params;
	ndmp_lbr_params_t *nz_nlp;
	libzfs_handle_t *nz_zlibh;		/* session-specific lzfs hdl */
	ndmp_context_t nz_nctx;			/* used by plugin */

	ndmpd_zfs_header_t nz_tape_header;	/* tape hdr for "zfs" backup */
} ndmpd_zfs_args_t;

#define	ndmpd_zfs_params (&(ndmpd_zfs_args)->nz_params)

typedef struct ndmpd_session {
	ndmp_connection_t *ns_connection;	/* NDMP connection to client */
	boolean_t ns_eof;		/* connection EOF flag */
	ushort_t ns_protocol_version;	/* connection protocol version */
	ndmpd_session_scsi_desc_t ns_scsi;
	ndmpd_session_tape_desc_t ns_tape;
	ndmpd_session_mover_desc_t ns_mover;
	ndmpd_session_data_desc_t ns_data;
	ndmpd_session_file_history_t ns_fh;
	ndmpd_file_handler_t *ns_file_handler_list; /* for I/O multiplexing */
	int ns_nref;
	ndmp_lbr_params_t *ns_ndmp_lbr_params;
	struct ndmpd_zfs_args ns_ndmpd_zfs_args;
	ndmpd_backup_type_t ns_butype;
	mutex_t ns_lock;

	/*
	 * NDMP V3
	 * Tape, SCSI, mover, data and file handlers will
	 * be shared between V2 and V3.
	 */
	ndmpd_session_file_history_v3_t ns_fh_v3;
	unsigned char ns_challenge[MD5_CHALLENGE_SIZE];  /* For MD5 */

	/*
	 * NDMP V4 related data
	 */
	boolean_t ns_get_ext_list;
	boolean_t ns_set_ext_list;

	/* handling of hardlink, hardlink queue head */
	struct hardlink_q *hardlink_q;
} ndmpd_session_t;


/*
 * NDMP request handler functions.
 */

/* Config */
ndmp_msg_handler_func_t ndmpd_config_get_host_info_v2;
ndmp_msg_handler_func_t ndmpd_config_get_butype_attr_v2;
ndmp_msg_handler_func_t ndmpd_config_get_mover_type_v2;
ndmp_msg_handler_func_t ndmpd_config_get_auth_attr_v2;

ndmp_msg_handler_func_t ndmpd_config_get_host_info_v3;
ndmp_msg_handler_func_t ndmpd_config_get_butype_info_v3;
ndmp_msg_handler_func_t ndmpd_config_get_connection_type_v3;
ndmp_msg_handler_func_t ndmpd_config_get_auth_attr_v3;
ndmp_msg_handler_func_t ndmpd_config_get_fs_info_v3;
ndmp_msg_handler_func_t ndmpd_config_get_tape_info_v3;
ndmp_msg_handler_func_t ndmpd_config_get_scsi_info_v3;
ndmp_msg_handler_func_t ndmpd_config_get_server_info_v3;

ndmp_msg_handler_func_t ndmpd_config_get_butype_info_v4;
ndmp_msg_handler_func_t ndmpd_config_get_ext_list_v4;
ndmp_msg_handler_func_t ndmpd_config_set_ext_list_v4;


/* Scsi */
ndmp_msg_handler_func_t ndmpd_scsi_open_v2;
ndmp_msg_handler_func_t ndmpd_scsi_close_v2;
ndmp_msg_handler_func_t ndmpd_scsi_get_state_v2;
ndmp_msg_handler_func_t ndmpd_scsi_set_target_v2;
ndmp_msg_handler_func_t ndmpd_scsi_reset_device_v2;
ndmp_msg_handler_func_t ndmpd_scsi_reset_bus_v2;
ndmp_msg_handler_func_t ndmpd_scsi_execute_cdb_v2;

ndmp_msg_handler_func_t ndmpd_scsi_open_v3;
ndmp_msg_handler_func_t ndmpd_scsi_set_target_v3;


/* Tape */
ndmp_msg_handler_func_t ndmpd_tape_open_v2;
ndmp_msg_handler_func_t ndmpd_tape_close_v2;
ndmp_msg_handler_func_t ndmpd_tape_get_state_v2;
ndmp_msg_handler_func_t ndmpd_tape_mtio_v2;
ndmp_msg_handler_func_t ndmpd_tape_write_v2;
ndmp_msg_handler_func_t ndmpd_tape_read_v2;
ndmp_msg_handler_func_t ndmpd_tape_execute_cdb_v2;

ndmp_msg_handler_func_t ndmpd_tape_open_v3;
ndmp_msg_handler_func_t ndmpd_tape_get_state_v3;
ndmp_msg_handler_func_t ndmpd_tape_write_v3;
ndmp_msg_handler_func_t ndmpd_tape_read_v3;


ndmp_msg_handler_func_t ndmpd_tape_close_v4;
/* Data */
ndmp_msg_handler_func_t ndmpd_data_get_state_v2;
ndmp_msg_handler_func_t ndmpd_data_start_backup_v2;
ndmp_msg_handler_func_t ndmpd_data_start_recover_v2;
ndmp_msg_handler_func_t ndmpd_data_get_env_v2;
ndmp_msg_handler_func_t ndmpd_data_stop_v2;
ndmp_msg_handler_func_t ndmpd_data_abort_v2;

ndmp_msg_handler_func_t ndmpd_data_get_state_v3;
ndmp_msg_handler_func_t ndmpd_data_connect_v3;
ndmp_msg_handler_func_t ndmpd_data_listen_v3;
ndmp_msg_handler_func_t ndmpd_data_stop_v3;
ndmp_msg_handler_func_t ndmpd_data_abort_v3;
ndmp_msg_handler_func_t ndmpd_data_start_recover_v3;
ndmp_msg_handler_func_t ndmpd_data_start_backup_v3;

ndmp_msg_handler_func_t ndmpd_data_get_env_v4;
ndmp_msg_handler_func_t ndmpd_data_get_state_v4;
ndmp_msg_handler_func_t ndmpd_data_connect_v4;
ndmp_msg_handler_func_t ndmpd_data_listen_v4;
ndmp_msg_handler_func_t ndmpd_data_start_recover_filehist_v4;


/* Connect */
ndmp_msg_handler_func_t ndmpd_connect_open_v2;
ndmp_msg_handler_func_t ndmpd_connect_client_auth_v2;
ndmp_msg_handler_func_t ndmpd_connect_server_auth_v2;
ndmp_msg_handler_func_t ndmpd_connect_close_v2;

ndmp_msg_handler_func_t ndmpd_connect_client_auth_v3;
ndmp_msg_handler_func_t ndmpd_connect_close_v3;


/* Mover */
ndmp_msg_handler_func_t ndmpd_mover_get_state_v2;
ndmp_msg_handler_func_t ndmpd_mover_listen_v2;
ndmp_msg_handler_func_t ndmpd_mover_continue_v2;
ndmp_msg_handler_func_t ndmpd_mover_abort_v2;
ndmp_msg_handler_func_t ndmpd_mover_stop_v2;
ndmp_msg_handler_func_t ndmpd_mover_set_window_v2;
ndmp_msg_handler_func_t ndmpd_mover_read_v2;
ndmp_msg_handler_func_t ndmpd_mover_close_v2;
ndmp_msg_handler_func_t ndmpd_mover_set_record_size_v2;

ndmp_msg_handler_func_t ndmpd_mover_get_state_v3;
ndmp_msg_handler_func_t ndmpd_mover_listen_v3;
ndmp_msg_handler_func_t ndmpd_mover_continue_v3;
ndmp_msg_handler_func_t ndmpd_mover_abort_v3;
ndmp_msg_handler_func_t ndmpd_mover_set_window_v3;
ndmp_msg_handler_func_t ndmpd_mover_read_v3;
ndmp_msg_handler_func_t ndmpd_mover_set_record_size_v3;
ndmp_msg_handler_func_t ndmpd_mover_connect_v3;


ndmp_msg_handler_func_t ndmpd_mover_get_state_v4;
ndmp_msg_handler_func_t ndmpd_mover_listen_v4;
ndmp_msg_handler_func_t ndmpd_mover_connect_v4;


/*
 * Backup/recover module API functions.
 */
ndmpd_get_env_func_t ndmpd_api_get_env;
ndmpd_add_env_func_t ndmpd_api_add_env;
ndmpd_add_env_func_t ndmpd_api_set_env;
ndmpd_get_name_func_t ndmpd_api_get_name;
ndmpd_dispatch_func_t ndmpd_api_dispatch;
ndmpd_done_func_t ndmpd_api_done_v2;


ndmpd_write_func_t ndmpd_api_write_v2;
ndmpd_file_history_path_func_t ndmpd_api_file_history_path_v2;
ndmpd_file_history_dir_func_t ndmpd_api_file_history_dir_v2;
ndmpd_file_history_node_func_t ndmpd_api_file_history_node_v2;
ndmpd_read_func_t ndmpd_api_read_v2;
ndmpd_seek_func_t ndmpd_api_seek_v2;
ndmpd_file_recovered_func_t ndmpd_api_file_recovered_v2;
ndmpd_add_file_handler_func_t ndmpd_api_add_file_handler;
ndmpd_remove_file_handler_func_t ndmpd_api_remove_file_handler;


/*
 * NDMP V3
 */
ndmpd_done_func_t ndmpd_api_done_v3;
ndmpd_write_func_t ndmpd_api_write_v3;
ndmpd_read_func_t ndmpd_api_read_v3;
ndmpd_seek_func_t ndmpd_api_seek_v3;
ndmpd_file_recovered_func_t ndmpd_api_file_recovered_v3;
ndmpd_get_name_func_t ndmpd_api_get_name_v3;
ndmpd_file_history_path_func_t ndmpd_api_file_history_file_v3;
ndmpd_file_history_dir_func_t ndmpd_api_file_history_dir_v3;
ndmpd_file_history_node_func_t ndmpd_api_file_history_node_v3;

/*
 * NDMP V4
 */
ndmpd_log_func_v3_t ndmpd_api_log_v4;
ndmpd_file_recovered_func_t ndmpd_api_file_recovered_v4;

#ifndef NO_NDMP_API_LOG_PROTOTYPES
ndmpd_log_func_t ndmpd_api_log_v2;
ndmpd_log_func_v3_t ndmpd_api_log_v3;
#endif /* NO_NDMP_API_LOG_PROTOTYPES */

typedef void ndmpd_func_t(ndmp_connection_t *, void *);

/*
 * pthread call arg parameters
 */
typedef struct {
	int nw_sock;
	long nw_ipaddr;
	ndmp_con_handler_func_t nw_con_handler_func;
} ndmpd_worker_arg_t;

typedef struct {
	char *br_jname;
	ndmp_lbr_params_t *br_nlp;
	tlm_commands_t *br_cmds;
	pthread_barrier_t br_barrier;
} backup_reader_arg_t;

typedef struct {
	ndmpd_session_t *tr_session;
	ndmpd_module_params_t *tr_mod_params;
	tlm_commands_t *tr_cmds;
} ndmp_tar_reader_arg_t;

typedef struct {
	ndmpd_session_t *bs_session;
	char *bs_jname;
	char *bs_path;
} ndmp_bkup_size_arg_t;

/*
 * Variables from ndmpd_comm.c
 */
extern int ndmp_ver;
extern int ndmp_full_restore_path;
extern int ndmp_dar_support;
extern int ndmp_port;
extern ndmp_stat_t ndstat;

extern void ndmpd_main(void);
extern void connection_handler(ndmp_connection_t *);
extern void ndmpd_audit_backup(ndmp_connection_t *conn, char *path,
    int dest, char *local_path, int result);
extern void ndmpd_audit_restore(ndmp_connection_t *conn,
    char *path, int dest, char *local_path, int result);
extern void ndmpd_audit_connect(ndmp_connection_t *conn,
    int result);
extern void ndmpd_audit_disconnect(ndmp_connection_t *conn);

/* Variables from ndmpd_main.c */
extern	libzfs_handle_t	*zlibh;
extern	mutex_t	zlib_mtx;

/*
 * Utility from ndmpd_connect.c.
 */
extern int ndmp_connect_list_add(ndmp_connection_t *, int *);
extern int ndmp_connect_list_del(ndmp_connection_t *);
extern int ndmpd_connect_kill_id(int);
extern void ndmp_connect_list_get(ndmp_door_ctx_t *);
extern void ndmpd_get_devs(ndmp_door_ctx_t *);

/*
 * Utility functions form ndmpd_data.c.
 */
extern void ndmpd_data_cleanup(ndmpd_session_t *);
extern int ndmpd_data_init(ndmpd_session_t *);
extern char *ndmp_data_get_mover_mode(ndmpd_session_t *);
extern void ndmpd_data_error(ndmpd_session_t *, ndmp_data_halt_reason);


/*
 * Utility functions from ndmpd_mover.c.
 */
extern int ndmpd_mover_init(ndmpd_session_t *);
extern void ndmpd_mover_cleanup(ndmpd_session_t *);
extern ndmp_error ndmpd_mover_connect(ndmpd_session_t *,
    ndmp_mover_mode);
extern void ndmpd_mover_error(ndmpd_session_t *,
    ndmp_mover_halt_reason);
extern int ndmpd_mover_seek(ndmpd_session_t *,
    u_longlong_t,
    u_longlong_t);
extern int ndmpd_local_write(ndmpd_session_t *,
    char *,
    ulong_t);
extern int ndmpd_remote_write(ndmpd_session_t *,
    char *,
    ulong_t);
extern int ndmpd_local_read(ndmpd_session_t *,
    char *,
    ulong_t);
extern int ndmpd_remote_read(ndmpd_session_t *,
    char *,
    ulong_t);

extern void ndmpd_mover_shut_down(ndmpd_session_t *);
extern void ndmpd_mover_error(ndmpd_session_t *,
    ndmp_mover_halt_reason);
extern int ndmpd_local_write_v3(ndmpd_session_t *,
    char *,
    ulong_t);
extern int ndmpd_local_read_v3(ndmpd_session_t *,
    char *,
    ulong_t);
extern int ndmpd_remote_read_v3(ndmpd_session_t *,
    char *,
    ulong_t);


/*
 * Utility functions from ndmpd_file_history.c
 */
extern void ndmpd_file_history_init(ndmpd_session_t *);
extern void ndmpd_file_history_cleanup(ndmpd_session_t *,
    boolean_t);
extern int ndmpd_file_history_path(lbr_fhlog_call_backs_t *,
    char *,
    struct stat64 *,
    u_longlong_t);
extern int ndmpd_file_history_dir(lbr_fhlog_call_backs_t *,
    char *,
    struct stat64 *);
extern int ndmpd_file_history_node(lbr_fhlog_call_backs_t *,
    char *,
    char *,
    struct stat64 *,
    u_longlong_t);
extern int
ndmpd_path_restored(lbr_fhlog_call_backs_t *,
    char *,
    struct stat64 *,
    u_longlong_t);
extern int ndmpd_fhpath_v3_cb(lbr_fhlog_call_backs_t *,
    char *,
    struct stat64 *,
    u_longlong_t);
extern int ndmpd_fhdir_v3_cb(lbr_fhlog_call_backs_t *,
    char *,
    struct stat64 *);
extern int ndmpd_fhnode_v3_cb(lbr_fhlog_call_backs_t *,
    char *,
    char *,
    struct stat64 *,
    u_longlong_t);
extern int ndmpd_path_restored_v3(lbr_fhlog_call_backs_t *,
    char *,
    struct stat64 *,
    u_longlong_t);

extern int ndmp_send_recovery_stat_v3(ndmpd_module_params_t *,
    ndmp_lbr_params_t *,
    int,
    int);


/*
 * Utility functions from ndmpd_dtime.c
 */
extern int ndmpd_put_dumptime(char *, int, time_t);
extern int ndmpd_get_dumptime(char *, int *, time_t *);
extern int ndmpd_append_dumptime(char *, char *, int, time_t);


/*
 * Global variables from ndmpd_tar3.c
 */
extern char **ndmp_excl_list;


/*
 * Global variables from ndmpd_util.c
 */
extern int ndmp_force_bk_dirs;
extern int ndmp_rbs;
extern int ndmp_sbs;
extern boolean_t ndmp_dump_path_node;
extern boolean_t ndmp_tar_path_node;
extern boolean_t ndmp_ignore_ctime;
extern boolean_t ndmp_include_lmtime;


/*
 * Utility functions from ndmpd_util.c.
 */
extern int ndmpd_select(ndmpd_session_t *,
    boolean_t,
    ulong_t);

extern ndmp_error ndmpd_save_env(ndmpd_session_t *,
    ndmp_pval *,
    ulong_t);

extern void ndmpd_free_env(ndmpd_session_t *);
extern ndmp_error ndmpd_save_nlist_v2(ndmpd_session_t *,
    ndmp_name *,
    ulong_t);

extern void ndmpd_free_nlist(ndmpd_session_t *);
extern int ndmpd_add_file_handler(ndmpd_session_t *,
    void *,
    int,
    ulong_t,
    ulong_t,
    ndmpd_file_handler_func_t *);

extern int ndmpd_remove_file_handler(ndmpd_session_t *,
    int);

extern void ndmp_send_reply(ndmp_connection_t *,
    void *,
    char *);

extern int ndmp_mtioctl(int, int, int);

extern u_longlong_t quad_to_long_long(ndmp_u_quad);
extern ndmp_u_quad long_long_to_quad(u_longlong_t);

extern void set_socket_options(int sock);

extern long ndmp_buffer_get_size(ndmpd_session_t *);
extern int ndmp_lbr_init(ndmpd_session_t *);
extern void ndmp_lbr_cleanup(ndmpd_session_t *);

extern int ndmp_wait_for_mover(ndmpd_session_t *);
extern boolean_t is_buffer_erroneous(tlm_buffer_t *);
extern void ndmp_execute_cdb(ndmpd_session_t *,
    char *,
    int,
    int,
    ndmp_execute_cdb_request *);

extern scsi_adapter_t *scsi_get_adapter(int);
extern boolean_t is_tape_unit_ready(char *, int);

extern int ndmp_open_list_add(ndmp_connection_t *, char *, int, int, int);
extern int ndmp_open_list_del(char *, int, int);
extern void ndmp_open_list_release(ndmp_connection_t *);

extern void ndmp_stop_buffer_worker(ndmpd_session_t *);
extern void ndmp_stop_reader_thread(ndmpd_session_t *);
extern void ndmp_stop_writer_thread(ndmpd_session_t *);
extern void ndmp_free_reader_writer_ipc(ndmpd_session_t *);
extern void ndmp_waitfor_op(ndmpd_session_t *);

extern char *cctime(time_t *);
extern char *ndmp_new_job_name(char *);
extern char *ndmpd_mk_temp(char *);
extern char *ndmpd_make_bk_dir_path(char *, char *);
extern boolean_t ndmp_is_chkpnt_root(char *);
extern char **ndmpd_make_exc_list(void);
extern void ndmp_sort_nlist_v3(ndmpd_session_t *);
extern int ndmp_get_bk_dir_ino(ndmp_lbr_params_t *);
extern int ndmp_write_utf8magic(tlm_cmd_t *);
extern int ndmp_tar_writer(ndmpd_session_t *,
    ndmpd_module_params_t *,
    tlm_commands_t *);
extern void ndmp_wait_for_reader(tlm_commands_t *);
extern ndmp_error ndmpd_save_nlist_v3(ndmpd_session_t *,
    ndmp_name_v3 *,
    ulong_t);
extern void ndmpd_free_nlist_v3(ndmpd_session_t *);
extern int ndmp_create_socket(ulong_t *, ushort_t *);
extern int ndmp_connect_sock_v3(ulong_t, ushort_t);
extern void ndmp_copy_addr_v3(ndmp_addr_v3 *, ndmp_addr_v3 *);
extern void ndmp_copy_addr_v4(ndmp_addr_v4 *, ndmp_addr_v4 *);
extern char *ndmp_addr2str_v3(ndmp_addr_type);
extern boolean_t ndmp_valid_v3addr_type(ndmp_addr_type);
extern boolean_t ndmp_check_utf8magic(tlm_cmd_t *);
extern int ndmp_get_cur_bk_time(ndmp_lbr_params_t *,
    time_t *, char *);
extern char *ndmp_get_relative_path(char *, char *);

extern boolean_t ndmp_fhinode;
extern void ndmp_load_params(void);
extern void randomize(unsigned char *, int);


/*
 * Utility functions from ndmpd_tar3.c.
 */
extern ndmp_error ndmp_restore_get_params_v3(ndmpd_session_t *,
    ndmpd_module_params_t *);
extern ndmp_error ndmp_backup_get_params_v3(ndmpd_session_t *,
    ndmpd_module_params_t *);

/*
 * door init and fini function from ndmpd_door_serv.c
 */
extern int ndmp_door_init(void);
extern void ndmp_door_fini(void);
extern boolean_t ndmp_door_check(void);

extern int ndmp_get_max_tok_seq(void);

extern int get_zfsvolname(char *, int, char *);
extern int ndmp_create_snapshot(char *, char *);
extern int ndmp_remove_snapshot(char *, char *);
extern int ndmpd_mark_inodes_v2(ndmpd_session_t *, ndmp_lbr_params_t *);
extern void ndmpd_abort_marking_v2(ndmpd_session_t *);
extern int ndmpd_mark_inodes_v3(ndmpd_session_t *, ndmp_lbr_params_t *);
extern ndmp_lbr_params_t *ndmp_get_nlp(void *);

module_start_func_t ndmpd_tar_backup_starter;
module_abort_func_t ndmpd_tar_backup_abort;

module_start_func_t ndmpd_tar_restore_starter;
module_abort_func_t ndmpd_tar_restore_abort;

module_start_func_t ndmpd_tar_backup_starter_v3;
module_abort_func_t ndmpd_tar_backup_abort_v3;

module_start_func_t ndmpd_tar_restore_starter_v3;
module_abort_func_t ndmpd_tar_restore_abort_v3;

extern int ndmp_backup_extract_params(ndmpd_session_t *,
    ndmpd_module_params_t *);
extern int ndmp_restore_extract_params(ndmpd_session_t *,
    ndmpd_module_params_t *);
extern int ndmp_tar_reader(ndmp_tar_reader_arg_t *);

extern int tape_open(char *, int);
extern int tape_is_at_bot(ndmpd_session_t *);
extern int tape_is_at_bof(ndmpd_session_t *);
extern void fm_dance(ndmpd_session_t *);

extern void ndmp_session_ref(ndmpd_session_t *);
extern void ndmp_session_unref(ndmpd_session_t *);

void ndmpd_get_file_entry_type(int, ndmp_file_type *);

extern int tcp_accept(int, unsigned int *);
extern int tcp_get_peer(int, unsigned int *, int *);

extern char *gethostaddr(void);
extern char *get_default_nic_addr(void);
extern int tlm_init(void);

extern int snapshot_create(char *, char *, boolean_t, boolean_t);
extern int snapshot_destroy(char *, char *, boolean_t, boolean_t, int *);

extern boolean_t fs_is_chkpntvol(char *);
extern boolean_t fs_is_chkpnt_enabled(char *);
extern boolean_t fs_is_rdonly(char *);
extern boolean_t fs_volexist(char *);
extern boolean_t fs_is_valid_logvol(char *);
extern boolean_t rootfs_dot_or_dotdot(char *);
extern int dp_readdir(DIR *, unsigned long *, char *,
    int *, unsigned long *);

extern void scsi_find_sid_lun();
extern char *sasd_slink_name();
extern int scsi_dev_exists(char *, int, int);
extern int scsi_get_devtype(char *, int, int);
extern struct open_list *ndmp_open_list_find(char *, int, int);
extern int filecopy(char *, char *);

extern void ndmp_stop_local_reader();
extern void ndmp_stop_remote_reader();

extern boolean_t match(char *, char *);
extern char *trim_whitespace(char *);
extern int fs_getstat(char *, struct fs_fhandle *, struct stat64 *);
extern int fs_readdir(struct fs_fhandle *, char *, long *,
    char *, int *, struct fs_fhandle *, struct stat64 *);
extern int iscreated(ndmp_lbr_params_t *nlp, char *name, tlm_acls_t *tacl,
    time_t t);

extern int sasd_dev_count(void);
extern struct scsi_link *sasd_dev_slink(int);
extern struct sasd_drive *sasd_drive(int);
extern void *ndmp_malloc(size_t size);

extern ndmp_plugin_t *ndmp_pl;

#define	NDMP_APILOG(s, t, m, ...) \
{ \
	if (((ndmpd_session_t *)(s))->ns_protocol_version == NDMPV4) \
		(void) ndmpd_api_log_v4(s, t, m, __VA_ARGS__); \
	else if (((ndmpd_session_t *)(s))->ns_protocol_version == NDMPV3) \
		(void) ndmpd_api_log_v3(s, t, m, __VA_ARGS__); \
	else \
		(void) ndmpd_api_log_v2(s, __VA_ARGS__); \
}

/*
 * Backup path utility functions
 */
extern char *get_backup_path_v3(ndmpd_module_params_t *);
extern char *get_backup_path_v2(ndmpd_module_params_t *);

/*
 * Functions for zfs-based backup
 */

module_start_func_t ndmpd_zfs_backup_starter;
module_start_func_t ndmpd_zfs_restore_starter;
module_abort_func_t ndmpd_zfs_abort;

int ndmpd_zfs_init(ndmpd_session_t *);
void ndmpd_zfs_fini(ndmpd_zfs_args_t *);

boolean_t ndmpd_zfs_backup_parms_valid(ndmpd_zfs_args_t *);
boolean_t ndmpd_zfs_restore_parms_valid(ndmpd_zfs_args_t *);

int ndmpd_zfs_pre_backup(ndmpd_zfs_args_t *);
int ndmpd_zfs_pre_restore(ndmpd_zfs_args_t *);
int ndmpd_zfs_post_backup(ndmpd_zfs_args_t *);
int ndmpd_zfs_post_restore(ndmpd_zfs_args_t *);

void ndmpd_zfs_dma_log(ndmpd_zfs_args_t *, ndmp_log_type, char *, ...);

#endif /* _NDMPD_H */
