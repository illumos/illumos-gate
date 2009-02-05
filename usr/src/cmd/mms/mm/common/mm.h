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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MM_H
#define	_MM_H


#include <limits.h>
#include <mms_network.h>
#include <mms_mm_msg.h>
#include <host_ident.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	HERE _SrcFile, __LINE__

#define	MM_APP "MMS"		/* mms admin and oper application */
#define	MM_ADMIN "admin"	/* mms administrator app instance */
#define	MM_OPER "oper"		/* mms operator app instance */

#define	MM_FD_LIMIT_MIN 256 	/* mm fd limit min */
#define	MM_FD_LIMIT_MAX 65536	/* mm fd limit max */

/* Mount return codes */
#define	MM_MOUNT_ERROR 0
#define	MM_MOUNT_READY 1
#define	MM_MOUNT_NOT_READY 2
#define	MM_MOUNT_NEED_UNLOAD 3
/* UNmount return codes */
#define	MM_UNMOUNT_ERROR 4
#define	MM_UNMOUNT_READY 5
#define	MM_UNMOUNT_NOT_READY 6

#define	MM_DELETE_NOTIFY "delete from \"NOTIFY\" where "\
	"\"ConnectionID\" = '%s';"
#define	MM_DELETE_NOTIFYRULES "delete from \"NOTIFYRULES\" where "\
	"\"ConnectionID\" = '%s';"
#define	MM_DELETE_CONNECTION "delete from \"CONNECTION\" where "\
	"\"ConnectionID\" = '%s';"
#define	MM_DELETE_SESSION "delete from \"SESSION\" where "\
	"\"SessionID\" = '%s';"

/* This is the string for a PCL outside of MMS */
/* postgres trigger in mm_db_plpgsql.c must use this string */
#define	MM_NON_MMS_CART "non-MMS"

/*
 * Core on fatal
 */
#define	MM_ABORT(msg)\
{                                                       \
	syslog(LOG_ERR, "%s:%d %s", MMS_HERE, msg);      \
	abort();                                        \
}
#define	MM_ABORT_NO_MEM() MM_ABORT("no mem")

#define	MM_SET_FLAG(flags, a_flag)		\
	{					\
		flags |= a_flag;		\
}

#define	MM_IS_SET(flags, a_flag) flags & a_flag
#define	MM_UNSET_FLAG(flags, a_flag)		\
	{					\
		flags &= ~a_flag;		\
}

#define	MM_PROGNAME "mm"
#define	MM_TRACE_FN "/var/log/mms/mm/mm.debug"
#define	MM_PATHS_FN "/etc/mms/config/mm_paths.xml"
#define	MM_TYPES_FN "/etc/mms/types/mm_types.xml"
#define	UUID_PRINTF_SIZE 37
#define	CMI_NUM_FIRSTMOUNT 100
#define	CMI_NUM_ACCESSMODE 100
#define	MM_NO_TASK NULL
/* Defines the max size of MM response, default 32000? */
/* 500 to test */
#define	MM_CMD_SIZE_LIMIT 32000

/* DM Debug Options */
#define	DEBUG_DM_CONFIG 1 /* Setting this to 1 makes DM config VERY slow */

typedef enum mm_lmp_scope mm_lmp_scope_t;
enum mm_lmp_scope {
	SCOPE_FULL,
	SCOPE_PARTIAL
};

typedef	struct	mm_command	mm_command_t;
typedef char cci_ip_t[MMS_IP_IDENT_LEN+1];
typedef char uuid_text_t[UUID_PRINTF_SIZE];

#define	SQL_CMD_BUF_INCR	(1024 * 8)
#define	SQL_CHK_LEN(line, off, size, len) {				\
		if (mm_sql_chk_len(line, off, size, len)) {		\
			goto no_mem;					\
		}							\
	}

/*
 * MM config structure
 */
typedef struct mm_cfg mm_cfg_t;	/* mm configuration */
struct mm_cfg {
	mms_network_cfg_t	mm_network_cfg;	/* mm network cfg file */
	mm_db_cfg_t	mm_db_cfg;		/* database configuration */
	char		*mm_ssl_dh_file;	/* DH parameter file */
	int		mm_ssl_verify_peer;	/* client cert required */
};

/*
 * MMP begin end mode
 */
typedef enum access_mode access_mode_t; /* begin-end access mode */
enum access_mode {
	ACCESS_MODE_IMMEDIATE,	/* run now */
	ACCESS_MODE_BLOCKING	/* willing to wait for resources */
};

/*
 * MMP begin end data
 */
typedef struct begin_end begin_end_t; /* begin-end command data */
struct begin_end {
	boolean_t	 be_active;	/* active begin-end block */
	access_mode_t	 be_mode;	/* now or willing to wait */
	mms_list_t		 be_list;	/* mount / unmount list */
	mm_command_t	*be_command;	/* begin command */
};



#define	MM_NUM_STATUS_OBJS 14
#define	MM_NUM_STATUS_ATTS 50
#define	MM_NUM_CONTROL_ATTS 16

typedef struct mm_attribute_info mm_attribute_info_t;
struct mm_attribute_info {
	char *status_objs[MM_NUM_STATUS_OBJS];
	char *status_atts[MM_NUM_STATUS_ATTS];
	char *control_atts[MM_NUM_CONTROL_ATTS];
};

/*
 * MM data structure
 */
typedef struct mm_data mm_data_t;
struct mm_data {
	mm_cfg_t	mm_cfg;		/* mm configuration */
	int		mm_service_fd;	/* mm service */
	void		*mm_ssl_data;	/* mm secure socket layer context */
	mms_list_t		mm_cmd_queue;		/* active cmd queue */
	mms_list_t		mm_wka_list;
	mms_cli_host_t 	mm_host_name;
	cci_ip_t 	mm_host_ip;

	/* Db pointer */
	mm_db_t		mm_db;			/* db for worker thread */
	mm_db_t		mm_db_tm;		/* db for TM thread */
	mm_db_t		mm_db_main;		/* db for Main thread */

	pthread_mutex_t	mm_worker_mutex;	/* lock for worker thread */
	pthread_mutex_t	mm_task_man_mutex;	/* lock for task man thread */
	pthread_mutex_t	mm_notify_mutex;	/* lock for notify thread */
	pthread_mutex_t	mm_queue_mutex;		/* lock for cmd queues */
	pthread_mutex_t	mm_wka_mutex;		/* lock for wka list */
	pthread_cond_t	mm_work_cv;
	pthread_cond_t	mm_accept_cv; /* not used now */
	pthread_cond_t	mm_task_cv;
	pthread_cond_t	mm_notify_cv;
	int		mm_work_todo;
	int		mm_tm_work_todo;
	int		mm_notify_work_todo;
	int		mm_cmd_dispatchable;
	pthread_mutex_t	mm_command_mutex; /* not used now */
	mm_attribute_info_t mm_attr_info;

	pthread_mutex_t	*mm_notify_list_mutex;	/* lock for notify list */
	mms_list_t		*mm_notify_list_ptr;
	time_t		clean_drive_records_tm;
};



typedef enum mm_lang mm_lang_t;	/* mms language (mmp, dmp, lmp) */
enum mm_lang {
	MM_LANG_MMP,		/* media manager */
	MM_LANG_DMP,		/* drive manager */
	MM_LANG_LMP		/* library manager */
};

typedef enum mm_privilege mm_privilege_t;
enum mm_privilege {
	MM_PRIV_STANDARD,	/* unprivileged app */
	MM_PRIV_ADMIN,		/* privileged app */
	MM_PRIV_SYSTEM		/* super user */
};

#define	MM_SIDE_STRING "SIDE"
#define	MM_PARTITION_STRING "PARTITION"
#define	MM_VOLUME_STRING "VOLUME"

typedef enum mm_mount_type mm_mount_type_t;
enum mm_mount_type {
	MM_SIDE,
	MM_PARTITION,
	MM_VOLUME

};
typedef enum mm_mount_when mm_mount_when_t;
enum mm_mount_when {
	MM_BLOCKING,
	MM_IMMEDIATE
};

/*
 * Client MMP, DMP, LMP parser function pointer
 */
typedef int (*parser_func_t)(mms_par_node_t **, mms_list_t *, char *);
typedef struct cci cci_t;		/* client connection info */
struct cci {
	mms_cli_host_t		cci_host;
	cci_ip_t		cci_ip;
	uint_t			cci_port;
	char			*cci_client;
	char			*cci_instance;
	char			*cci_language;
	char			*cci_version;
	char			*cci_password;
	char			*cci_certificate;
	char			*cci_authentication;
	uuid_text_t		cci_uuid;
};

typedef struct cmi_mode_list cmi_mode_list_t;
struct cmi_mode_list {
	mms_list_node_t		cmi_mode_next;
	char			*cmi_accessmode[CMI_NUM_ACCESSMODE];
	int			cmi_num_accessmode;
};
typedef struct cmi_cart_list cmi_cart_list_t;
struct cmi_cart_list {
	mms_list_node_t		cmi_cart_next;
	uuid_text_t		cmi_cart_id;
	char			*cmi_side_name;
	char			*cmi_library;
	char			*cmi_cart_pcl;
	char			*cmi_cart_type;
	char			*cmi_bit_format;
	int			cmi_cart_priority;
	int			cmi_cart_num_mounts;
	mms_list_t			cmi_drive_list;
	int			cmi_remove_cart;
	int			cmi_cart_not_ready;
	int			cmi_cart_loaded;
	int			cmi_cart_used;
};

typedef struct cmi_drive_list cmi_drive_list_t;
struct cmi_drive_list {
	mms_list_node_t		cmi_drive_next;
	char			*cmi_drive_name;
	char			*cmi_dm_name;
	int			cmi_drv_priority;
	int			cmi_drv_num_mounts;
	int			cmi_mode_valid;
	int			cmi_drive_loaded;
	char			*cmi_loaded_pcl;
	int			cmi_remove_drive;
	int			cmi_drive_not_ready;
	int			cmi_dm_shape_priority;
	int			cmi_dm_density_priority;
	int			cmi_drive_used;
};

#define	MM_MOUNT 0
#define	MM_UNMOUNT 1

typedef struct cmd_mount_info cmd_mount_info_t;
struct cmd_mount_info {
	int			cmi_operation;
	char			*cmi_dm;
	char			*cmi_drive;
	char			*cmi_library;
	char			*cmi_cartridge;
	char			*cmi_pcl;
	char			*cmi_side_name;
	mm_mount_type_t		cmi_type;
	char			*cmi_capability;
	char			*cmi_handle;
	mms_list_t			cmi_cart_list;
	int			cmi_total_carts;
	int			cmi_mount_ok;

	/* Recovery */
	int			cmi_retries;
	int			cmi_fail_type;
	int			cmi_fail_state;
	int			cmi_reset_states;

	/* mount */
	mm_mount_when_t		cmi_when;
	char			*cmi_where;
	char			*cmi_firstmount[CMI_NUM_FIRSTMOUNT];
	int			cmi_num_firstmount;
	mms_list_t			cmi_mode_list;
	int			cmi_total_modes;
	char			*cmi_filename;
	char			*cmi_user;
	char			*cmi_blocksize;
	char			*cmi_filesequence;
	char			*cmi_volumeid;
	char			*cmi_retention;
	int			cmi_need_clear;
	int			cmi_mount_cart_loaded;

	/* Dispatch info */
	int			cmi_mount_type;
	char			*cmi_first_drive;
	char			*cmi_first_lib;
	char			*cmi_second_drive;
	char			*cmi_second_lib;

	/* unmount */
	int			cui_physical;
	int			cui_signature_clean;
	char			*cui_signature_type;
	char			*cui_signature;
	int			cui_skip_unload;
	int			cui_force;
	time_t			unload_tm;

};

#define	MM_CANDIDATE_LOADED 5
#define	MM_OPEN_DRIVE 6
#define	MM_UNMOUNT_DRIVE 7
#define	MM_UNMOUNT_CART 8
#define	MM_UNMOUNT_2 9

typedef struct eject_cart eject_cart_t;
struct eject_cart {
	mms_list_node_t		cart_next;
	char			*cart_cartid;
	char			*cart_cartpcl;
	char			*cart_slottype;
	char			*cart_slotname;
	char			*cart_library;
};

typedef struct cmd_eject cmd_eject_t;
struct cmd_eject {
	char			*eject_library;
	char			*eject_lm;
	char			*eject_slotgroup;
	mms_list_t			eject_list;
};

typedef enum mm_msg_sev mm_msg_sev_t;
enum mm_msg_sev {
	MESS_EMERG		= 9,
	MESS_ALERT		= 8,
	MESS_CRIT		= 7,
	MESS_ERROR		= 6,
	MESS_WARN		= 5,
	MESS_NOTICE		= 4,
	MESS_INFO		= 3,
	MESS_DEBUG		= 2,
	MESS_DEVP		= 1
};

typedef enum mm_msg_who mm_msg_who_t;
enum mm_msg_who {
	MESS_LOG,
	MESS_OPER,
	MESS_ADMIN
};

#define	MESS_MANUFACTURER	"SUNW"
#define	MESS_MODEL		"MMS"
#define	MESS_LANG		"EN"
#define	MESS_MM_STR		"MM"
#define	MESS_DM_STR		"DM"
#define	MESS_LM_STR		"LM"
#define	MESS_AI_STR		"AI"
#define	MM_TIMESTAMP		24
typedef char mm_timestamp_t[MM_TIMESTAMP];

/* message flags */
#define	MESS_FLAG_FIFO		0x1
#define	MESS_FLAG_SLOG		0x2
#define	MESS_FLAG_HANDLED	0x4

typedef struct mm_msg mm_msg_t;
struct mm_msg {
	char			*msg_client_uuid;
	uuid_text_t		msg_uuid;
	mm_msg_who_t		msg_who;
	mm_msg_sev_t		msg_severity;
	mm_timestamp_t		msg_timestamp;
	char			*msg_type;
	char			*msg_client;
	char			*msg_instance;
	char			*msg_cid;
	char			*msg_host;
	char			*msg_manufacturer;
	char			*msg_model;
	int			msg_messageid;
	char			*msg_lang;
	char			*msg_text;
	char			*msg_localized;
	mms_list_t			*msg_args;
	int			msg_flags;
};

typedef struct mm_cmd_err mm_cmd_err_t;
struct mm_cmd_err {
	mms_list_node_t		mm_cmd_err_next;
	char	*ecode;
	char	*eclass;
	char	*err_buf;
	int	err_bufsize;
	char	*retry_drive;
	char	*retry_cart;
	char	*retry_lib;
	int	err_already_used;
};

typedef	struct	mm_wka {
	cci_t			wka_conn;
	mms_list_node_t		wka_next;
	int			mm_cmd_dispatchable;
	mm_lang_t		mm_wka_mm_lang;
	parser_func_t		mm_wka_parser;
	mms_t			*mm_wka_conn;
	mm_data_t		*mm_data;
	mm_privilege_t		wka_privilege;
	boolean_t		wka_hello_needed;
	uuid_text_t		session_uuid;
	begin_end_t		wka_begin_end;
	int			wka_remove;
	pthread_mutex_t		wka_local_lock;
	int			wka_need_accept;
	int			wka_goodbye;
	int			wka_unwelcome;
}	mm_wka_t;

struct	mm_command	{
	mms_list_node_t		cmd_next;
	mms_list_node_t		cmd_depend_list_next;
	int			cmd_flags;
	/* Short name of command */
	char			*cmd_name;
	/* Continue from state */
	int			cmd_state;
	/* command root node */
	mms_par_node_t		*cmd_root;
	/* Parse tree for response */
	mms_par_node_t		*cmd_response;
	/* List of responses for each cmd */
	mms_list_t			cmd_resp_list;
	/* Generated report */
	char			*cmd_report;
	/* task string */
	char			*cmd_task;
	int			(*cmd_func) (mm_wka_t *, mm_command_t *);
	/* dispatch this cmd */

	mms_list_t			cmd_depend_list;
	char			*cmd_textcmd;
	mm_wka_t		*wka_ptr;
	uuid_text_t		cmd_uuid;
	uuid_text_t		wka_uuid;
	mm_lang_t		cmd_language;
	/* command work buffer */
	char			*cmd_buf;
	int			cmd_bufsize;
	/* command removal flag */
	int			cmd_remove;
	/* mount information */
	cmd_mount_info_t	cmd_mount_info;
	mm_data_t		*cmd_mm_data;
	/* eject information */
	cmd_eject_t		*cmd_eject;

	/* Path Information */
	int			cmd_source_num;
	int			cmd_dest_num;
	int			cmd_const_num;

	int			cmd_has_list;
	mms_list_t		cmd_source_list;
	mms_list_t		cmd_dest_list;
	mms_list_t		cmd_const_list;
	/* error list */
	mms_list_t		cmd_err_list;
	mm_cmd_err_t		*cmd_err_ptr;


	mms_list_t		cmd_beginend_list;
	int			cmd_begin_has_end;
	mm_command_t		*cmd_begin_cmd;
	/* Used for notify to clause */
	int			cmd_notify_to;
	/* command message */
	mm_msg_t		cmd_msg;

	/* command request id */
	uuid_text_t		cmd_reqid;

	/* error class */
	char			*cmd_eclass;
	char			*cmd_ecode;
};

/* Set and Unset Struct */
typedef struct cmd_set cmd_set_t;
struct cmd_set {
	mms_list_node_t		cmd_set_next;
	int			cmd_set_type;
	char			*cmd_set_obj;
	char			*cmd_set_attr;
	char			*cmd_set_value;
};

typedef struct notify_cmd notify_cmd_t;
struct notify_cmd {
	mms_list_node_t	evt_next;
	int		evt_can_dispatch;

	/* Text of the command */
	char		*evt_cmd;
	uuid_text_t	evt_cmd_uuid;

	/* Connection info about the event originator */
	uuid_text_t	evt_cli_uuid;
	uuid_text_t	evt_session_uuid;
	char		*evt_cli_name;
	char		*evt_cli_instance;

	/* object is LM, DM, etc */
	char		*evt_obj_name;
	/* object instance 'dm1' 'lm1' */
	char		*evt_obj_instance;
	/* a host associated with the obj */
	char		*evt_obj_host;
	/* If there is a lib associated with this obj */
	char		*evt_obj_library;
	/* If there is a cartid associated with this obj */
	char		*evt_obj_cartid;
	/* If there is a drive associated with this obj */
	char		*evt_obj_drive;
	/* If there is a application associated with this obj */
	char		*evt_obj_app;
	/* If there is a application instance */
	/* associated with this obj */
	char		*evt_obj_appinst;

};

typedef struct mm_lib_stat mm_lib_stat_t;
struct mm_lib_stat {
	char		*lib_stat_name;
	char		*lib_stat_online;
	char		*lib_stat_disabled;
	char		*lib_stat_broken;
	char		*lib_stat_lm;
};
typedef struct mm_lm_stat mm_lm_stat_t;
struct mm_lm_stat {
	char		*lm_stat_name;
	char		*lm_stat_hard;
	char		*lm_stat_soft;
	char		*lm_stat_disabled;
	char		*lm_stat_library;
};
typedef struct mm_drive_stat mm_drive_stat_t;
struct mm_drive_stat {
	char		*drive_stat_name;
	char		*drive_stat_disabled;
	char		*drive_stat_broken;
	char		*drive_stat_soft;
	char		*drive_stat_hard;
	char		*drive_stat_lib_acc;
	char		*drive_stat_excl_app;
	char		*drive_stat_online;
	char		*drive_stat_group;
	char		*drive_stat_library;
	char		*drive_stat_priority;
	char		*drive_stat_dm;
	char		*drive_stat_geometry;
	char		*drive_stat_serial;
	char		*drive_stat_pcl;
	char		*drive_stat_drvlib_occ;
};
typedef struct mm_dm_stat mm_dm_stat_t;
struct mm_dm_stat {
	char		*dm_stat_name;
	char		*dm_stat_soft;
	char		*dm_stat_hard;
	char		*dm_stat_drive;
	char		*dm_stat_disabled;
	char		*dm_stat_host;
};

/* For cmd_set_type */
#define	MM_SET 1
#define	MM_UNSET 2



/* Dispatcher return codes */
#define	MM_CMD_DONE 1		/* Successful completion of cmd function */
#define	MM_NO_DISPATCH 2	/* A command state completed, */
				/* no additional dispatch is necessary */
#define	MM_DISPATCH_DEPEND 3	/* Successful completion of command */
				/* that has triggered another command for */
				/* dispatch */
#define	MM_DEPEND_DONE 4	/* A command that has other commands */
				/* waiting for it has completed successfully */
#define	MM_CMD_ERROR 5		/* a command failed with an error */
#define	MM_DISPATCH_AGAIN 6	/* A command has finshed that */
				/* reqires additional commands to be */
				/* dispatched */
#define	MM_ACCEPT_NEEDED 7	/* The command is waiting for an accept */
#define	MM_WORK_TODO 8		/* A command has returned from a state */
				/* where more work is requried */
#define	MM_DEPEND_ERROR 9	/* A command that other commands are */
				/* waiting on has terminated with an error */
#define	MM_RESYNC 10		/* Used only for a mount cmd */
				/* when internal states */
				/* have gotten out of sync */

/* Command Flags */
#define	MM_CMD_DISPATCHABLE 0x01
#define	MM_CMD_NEED_ACCEPT 0x02
#define	MM_CMD_DEPEND_ERROR 0x04
#define	MM_CMD_ACCEPTED 0x08

/* DMP DM Command Types */
#define	MM_DMP_RESERVE 1
#define	MM_DMP_PRIV 2
#define	MM_DMP_LOAD 3
#define	MM_DMP_ATTACH 4
#define	MM_DMP_IDENTIFY 5
#define	MM_DMP_DETACH 6
#define	MM_DMP_UNLOAD 7
#define	MM_DMP_RELEASE 8

/* Recovery */

#define	MM_MAX_RETRY 1
#define	MM_USE_RECOVER 0
#define	NONE 0
#define	LM 1
#define	DM 2
#define	MM 3

/* Parse Error Return Codes */
#define	MM_PAR_NO_MEM 1
#define	MM_PAR_ERROR 2
#define	MM_PAR_OK 3
#define	MM_PAR_SEND_UNACC 4
#define	MM_PAR_SEND_UNWEL 5
#define	MM_PAR_IS_RESP 6

/* Number-clause range */
enum mm_range_type {
	MM_RANGE_NONE,
	MM_RANGE_FIRST_LAST,
	MM_RANGE_FIRST,
	MM_RANGE_LAST,
	MM_RANGE_NUMS,
	MM_RANGE_A_NUM
};
typedef enum mm_range_type mm_range_type_t;

typedef struct mm_range mm_range_t;
struct mm_range {
	mm_range_type_t	mm_range_type;
	int		mm_range_first;
	int		mm_range_last;
};

/* MM routines */
int mm_is_exiting(void);
int mm_rm_mount(mm_command_t *cmd);
int mm_rm_unmount(mm_command_t *cmd);
extern int mm_candidate_cartridge_ok(mm_wka_t *mm_wka,
	mm_command_t *cmd, mm_db_t *db, cmi_cart_list_t *cart);
extern int mm_candidate_drive_ok(mm_wka_t *mm_wka,
	mm_command_t *cmd, mm_db_t *db,
	char *candidate_cartid, cmi_drive_list_t *drive);
extern int mm_candidate_library_ok(mm_command_t *cmd,
    mm_db_t *db, char *candidate_library);
extern void mm_set_cmd_err_buf(mm_command_t *cmd, char *class, char *token);
extern void mm_cfg_free(mm_cfg_t *cfg);
extern int mm_cfg_read(mm_cfg_t *cfg);
extern int mm_mc_load(mm_db_t *db, char *mc_fn);
extern int mm_mmp_add_act(mm_wka_t *mm_wka, mm_command_t *mnt_cmd);
extern char *mm_check_mode(mm_wka_t *mm_wka, mm_command_t *cmd, char *drive,
	cmi_mode_list_t *mode, char *cart_id, mm_db_t *db);
extern void mm_sql_update_state(mm_data_t *data, char *object,
	char *attribute, char *value, char *instance, char *name);
extern void mm_clear_source(mm_command_t *cmd);
extern void mm_clear_dest(mm_command_t *cmd);
extern void mm_clear_const(mm_command_t *cmd);
extern int mm_notify_chg_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_get_range(mm_command_t *cmd, mm_range_t *range);
extern int mm_add_match_list(char *str, mms_list_t *list);
extern int mm_errorcode_eq(mms_par_node_t *cmd_response, char *code);
extern void delete_dm_config(mm_wka_t *mm_wka, mm_db_t *db);
extern int notify_send(notify_cmd_t *event);
extern void mm_set_mount_info_pcl(char *pcl,
			cmd_mount_info_t *mount_info);
extern void mm_set_mount_info_cart(char *cart_id,
			cmd_mount_info_t *mount_info);
extern void mm_set_mount_info_drive(char *drive,
			cmd_mount_info_t *mount_info);
extern void mm_set_mount_info_dm(char *dm,
			cmd_mount_info_t *mount_info);
extern void mm_set_mount_info_library(char *library,
			cmd_mount_info_t *mount_info);
int mm_remove_unload(char *library, char *drive, mm_data_t *mm_data);
extern int mm_schedule_unload(mm_wka_t *mm_wka, mm_command_t *cmd);
mm_command_t *
mm_dispatch_unload(char *library, char *drive, mm_command_t *cmd,
	mm_data_t *mm_data);
void mm_free_cmi_drive(cmi_drive_list_t *drive);
void mm_free_cmi_cart(cmi_cart_list_t *cart);
extern mm_command_t *mm_alloc_cmd(mm_wka_t *mm_wka);
extern void mm_system_error(mm_command_t *cmd, char *fmt, ...);
extern void mm_clear_db(PGresult **results);
extern int mm_set_cartridge_status(char *id, char *status, mm_db_t *db);
extern int mm_set_drive_statesoft(char *drive, char *state, mm_db_t *db);
extern PGresult*mm_mount_cart_results(mm_wka_t *mm_wka, mm_command_t *cmd,
	mm_db_t *db);
extern void mm_path_match_report(mm_command_t *cmd, mm_db_t *db);
extern int mm_sql_from_where(mm_command_t *cmd, mm_db_t *db);
extern int mm_mount_init_candidates(mm_command_t *cmd,
		PGresult *cart_results, mm_db_t *db);
extern int mm_mount_check_candidates(mm_wka_t *mm_wka, mm_command_t *cmd,
		mm_db_t *db);
extern void mm_print_accessmodes(mm_command_t *cmd);
extern void mm_print_mount_candidates(mm_command_t *cmd);
extern int mm_set_immediate_mount(mm_wka_t *mm_wka, mm_command_t *cmd,
	mm_db_t *db);
extern void mm_free_cmi_cart_list(mms_list_t *cart_list);
extern int mm_mount_ready(mm_wka_t *mm_wka, mm_command_t *cmd,
	mm_db_t *db, int is_retry);
extern int mm_unmount_ready(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db);
extern int mm_set_cmd_dispatch(mm_data_t *mm_data,
	char *cur_id, int need_unload);
extern int mm_add_to_source(mm_command_t *cmd, char *str);
extern int mm_add_to_dest(mm_command_t *cmd, char *str);
extern int mm_add_to_const(mm_command_t *cmd, char *str);
extern int mm_add_obj_list(mms_list_t *list, char *obj);
extern int mm_system_settings(mm_db_t *db, int *request_oper, int *auto_clear);
extern int mm_parse_mount_cmd(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_parse_unmount_cmd(mm_wka_t *mm_wka, mm_command_t *cmd);
extern PGresult*mm_unmount_cart_results(mm_wka_t *mm_wka,
	mm_command_t *cmd, mm_db_t *db);
extern void mm_print_mount_summary(mm_wka_t *mm_wka, mm_command_t *cmd);
extern mm_command_t *mm_return_unload(char *library, char *drive,
	mm_data_t *mm_data);
extern int mm_mount_candidate_loaded(mm_command_t *cmd);
extern int mm_mount_open_drive(mm_command_t *cmd);
extern int mm_mount_loaded_drive(mm_command_t *cmd, mm_db_t *db,
	char **drive_to_unload, char **lib_to_unload);
extern int mm_unmount_2_drive(mm_command_t *cmd,
	mm_db_t *db);
extern void mm_mount_clean_candidates(mm_command_t *cmd);
extern void mm_set_mount_objs(mm_command_t *cmd, mm_db_t *db);
extern void mm_set_unload_dispatch(mm_command_t *unmnt_cmd,
	mm_command_t *parent);
extern  mm_privilege_t mm_privileged(mm_wka_t *mm_wka, mm_command_t *cmd);
extern void mm_write_success(mm_command_t *cmd, char *fmt, ...);
extern int mm_notify_event_rules(mm_data_t *mm_data);
extern int mm_notify_chg_cmd_func_old(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_non_priv_const(mm_wka_t *mm_wka, mm_command_t *cmd);
extern char *mm_get_cart_pcl(mm_command_t *cmd, char *cart_id, mm_db_t *db);
extern int mm_check_drive_records(mm_data_t *mm_data, mm_db_t *db);
extern int mm_clean_drive_records(mm_data_t *mm_data, mm_db_t *db);
extern int mm_dispatch_now(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db);
extern int mm_init_types(mm_data_t *mm_data, char *fn);
extern void mm_char_list_destroy(mms_list_t *list);
extern int mm_dispatch_now(mm_wka_t *mm_wka, mm_command_t *cmd, mm_db_t *db);

/* Cmd Depend list functions */
extern void
mm_add_depend(mm_command_t *child, mm_command_t *parent);
extern int
mm_has_depend(mm_command_t *cmd);
extern mm_command_t *
mm_top_parent(mm_command_t *child);
extern mm_command_t *
mm_first_parent(mm_command_t *child);
extern int
mm_is_parent(mm_command_t *parent, mm_command_t *child);
extern void
mm_remove_all_depend(mm_command_t *cmd);
extern void
mm_remove_this_depend(mm_command_t *cmd, mm_command_t *remove);
extern void
mm_dispatch_all_depend(mm_command_t *cmd);
extern
int
mm_set_depend_error(mm_command_t *cmd);

/* MM Object Status */
/* Call these functions to get status of MM objects */
extern mm_lib_stat_t *
mm_get_library_status(char *library_name, mm_db_t *db);
extern void
mm_free_library_status(mm_lib_stat_t *lib_stat);
extern void
mm_print_library_status(mm_lib_stat_t *lib_stat);
extern mm_lm_stat_t *
mm_get_lm_status(char *lm_name, mm_db_t *db);
extern void
mm_free_lm_status(mm_lm_stat_t *lm_stat);
extern void
mm_print_lm_status(mm_lm_stat_t *lm_stat);
extern mm_drive_stat_t *
mm_get_drive_status(char *drive_name, mm_db_t *db);
extern void
mm_free_drive_status(mm_drive_stat_t *drive_stat);
extern void
mm_print_drive_status(mm_drive_stat_t *drive_stat);
extern mm_dm_stat_t *
mm_get_dm_status(char *dm_name, char *drive_name, char *host, mm_db_t *db);
extern void
mm_free_dm_status(mm_dm_stat_t *dm_stat);
extern void
mm_print_dm_status(mm_dm_stat_t *dm_stat);

/* Event Notification Functions */

extern int mm_notify_init(mm_data_t *data);
extern int mm_notify_event_table(mm_data_t *mm_data);
extern void mm_notify_close(void);
extern void mm_notify_destroy(notify_cmd_t *event);
extern notify_cmd_t *mm_notify_add(char *event_fmt, ...);
extern void mm_notify_rollback(char *cmd_uuid);
extern void mm_notify_commit(char *cmd_uuid);
extern int mm_notify_now(char *cli_uuid, char *event_fmt, ...);
extern void mm_notify_add_newcartridge(mm_wka_t *mm_wka,
	mm_command_t *cmd,
	char *cartridgepcl, char *libraryname);
extern void mm_notify_add_newdrive(mm_wka_t *mm_wka,
	mm_command_t *cmd, char *drivename,
	char *libraryname);
extern int mm_notify_add_lmup(mm_wka_t *lm_wka, mm_command_t *cmd);
extern int mm_notify_add_lmdown(mm_wka_t *lm_wka, mm_command_t *cmd);
extern int mm_notify_add_config(mm_wka_t *mm_wka, mm_command_t *cmd,
	char *type,
	char *name, char *instance, char *host);
extern int mm_notify_add_driveonline(mm_wka_t *mm_wka, mm_command_t *cmd,
	char *drivename);
extern int mm_notify_add_driveoffline(mm_wka_t *mm_wka, mm_command_t *cmd,
	char *drivename);
extern void mm_notify_add_dmup(mm_wka_t *dm_wka, mm_command_t *cmd);
extern void mm_notify_add_dmdown(mm_wka_t *dm_wka, mm_command_t *cmd);
extern int mm_notify_add_volumeadd(mm_wka_t *mm_wka, mm_command_t *cmd,
	char *volumename, char *cartid, mm_db_t *db);
extern int mm_notify_add_volumedelete(mm_wka_t *mm_wka, mm_command_t *cmd,
	char *cartid, mm_db_t *db);
extern int mm_notify_add_dmdown_dc(mm_wka_t *dm_wka, mm_db_t *db);
extern int mm_notify_add_lmdown_dc(mm_wka_t *lm_wka, mm_db_t *db);
extern int mm_notify_add_volumeinject(mm_wka_t *lm_wka, mm_command_t *cmd,
	char *pcl, mm_db_t *db);
extern int mm_notify_add_volumeeject(mm_wka_t *lm_wka, mm_command_t *cmd,
	char *pcl, mm_db_t *db);
extern void mm_notify_add_librarycreate(mm_wka_t *mm_wka, mm_command_t *cmd,
	char *libraryname);
extern void mm_notify_add_librarydelete(mm_db_t *db, mm_wka_t *mm_wka,
	mm_command_t *cmd, int match_off);
extern void mm_notify_add_drivedelete(mm_db_t *db, mm_wka_t *mm_wka,
	mm_command_t *cmd, int match_off);

/* MMP Commands */

extern int mm_hello_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_private_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_cancel_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_inject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_eject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_move_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_cpreset_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_cpexit_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_cpstart_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_cpscan_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_shutdown_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_rename_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_deallocate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_allocate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_end_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_unmount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_begin_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_privilege_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_locale_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_attribute_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_show_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_delete_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_mount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_goodbye_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_create_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_libonline_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_drvonline_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_identity_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_direct_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_setpassword_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_delay_unmount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_clear_drive_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);

/* DMP Commands */

extern int mm_dmp_attach_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_load_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_private_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_ready_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_activate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_config_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern mm_command_t *mm_dmp_add_cmd(mm_wka_t *mm_wka,
	mm_command_t *mnt_cmd, char *dm_name, int type);
extern int mm_dmp_cancel_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_reset_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_dmp_exit_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);

extern mm_command_t *mm_drive_dm_activate_enable(mm_wka_t *mm_wka);
extern int mm_drive_dm_activate_disable(mm_wka_t *mm_wka);

/* LMP Commands */

extern int mm_lmp_config_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_sql_chk_len(char **line, int off, int *bufsize, int len);
extern int mm_sql_report_clause_new(mm_command_t *command, char *objname);
extern char *mm_get_task(mms_par_node_t *root);
extern mm_command_t *mm_add_clear_drive(char *drive_name, mm_data_t *mm_data,
	mm_db_t *db,
	mm_command_t *parent_cmd, char *cart_pcl, int force, int nonphysical);
extern int mm_library_lm_clear_states(mm_db_t *db);
extern mm_wka_t *mm_library_lm_wka(mm_data_t *mm_data, char *library, char *lm);
extern int mm_library_lm_connect(mm_wka_t *mm_wka);
extern int mm_library_lm_disconnect(mm_wka_t *mm_wka);
extern int mm_library_lm_cfg_conn_rdy(mm_command_t *cmd,
						char *library, char *lm);
extern char *mm_library_lm_get_cap(mm_command_t *cmd, char *library, char *lm);
extern int mm_library_lm_activate_enable(mm_wka_t *mm_wka);
extern int mm_lmp_activate_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_ready_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_config_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_private_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_mount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_unmount_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_inject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_eject_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_scan_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_cancel_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
int
mm_add_lmp_scan(mm_data_t *mm_data, mm_command_t *parent_cmd, char *drive_name,
		char *cartridge_pcl, char *library_name);
extern int mm_lmp_reset_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_lmp_exit_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);

/* Message */

extern int mm_message_init(mm_db_t *db, mm_data_t *data);
extern void mm_message_close(void);
extern int mm_msg_tracing_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_message_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_message_command(mm_command_t *cmd);
extern int mm_msg_parse(mm_command_t *cmd, mms_par_node_t *root);
extern int mm_msg_exists(int message_id);
extern int mm_message(mm_db_t *db, mm_msg_who_t who, mm_msg_sev_t severity,
					int messageid, ...);
extern int mm_msg_set_tracing(mm_wka_t *mm_wka, mm_command_t *cmd, int id);
extern int mm_msg_set_limit(mm_db_t *db);
extern void mm_response_error(mm_command_t *cmd, char *eclass, char *ecode,
					int messageid, ...);
extern int mm_msg_send_tracing(mm_wka_t *mm_wka);
extern char *mm_msg_lang2component(mm_lang_t lang);

/* System log file */

extern int mm_slog_set_fname(mm_db_t *db);
extern int mm_slog_set_sync(mm_db_t *db);
extern int mm_slog_set_level(mm_db_t *db);
extern int mm_slog_set_size(mm_db_t *db);

/* Operator Commands */

extern int mm_make_request(mm_wka_t *mm_wka, mm_command_t *cmd, char *task,
				int priority, int messageid, ...);
extern int mm_cancel_request(mm_db_t *db, char *reqid);
extern int mm_request_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_request_disconnect(mm_db_t *db, mm_wka_t *mm_wka);
extern int mm_accept_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_respond_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_release_cmd_func(mm_wka_t *mm_wka, mm_command_t *cmd);
extern int mm_request_history_limit(mm_db_t *db);


#ifdef	__cplusplus
}
#endif

#endif	/* _MM_H */
