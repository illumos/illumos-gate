/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/note.h>
#include "ndmpd.h"

/*
 * The following macros construct the message handler.
 * ver is the suffix used to construct the handler name.
 * mver is the suffix used to construct the structure name.
 * ver and mver are not necessarily the same, specially when
 * there are different structures and there is one handler
 * for all of them.
 */

/*
 * The handler function
 * The request and reply XDR function
 * The request and reply sizes
 */
#define	HANDL(cmd, ver, mver) \
	{ \
		ndmpd_##cmd##_v##ver, \
		XDR_AND_SIZE(ndmp_##cmd##_request_v##mver), \
		XDR_AND_SIZE(ndmp_##cmd##_reply_v##mver), \
	}

/*
 * No handler function
 * The request XDR function
 * The request size
 */
#define	HANDL_RQ(cmd, mver) \
	{ \
		0, \
		XDR_AND_SIZE(ndmp_##cmd##_request_v##mver), \
		0, 0, \
	}

/*
 * The handler function
 * The reply XDR function
 * The reply size
 */
#define	HANDL_RS(cmd, ver, mver) \
	{ \
		ndmpd_##cmd##_v##ver, \
		0, 0, \
		XDR_AND_SIZE(ndmp_##cmd##_reply_v##mver), \
	}

/*
 * The handler function
 * No reply XDR function
 * No reply size
 */
#define	HANDL_NONE(cmd, ver) \
	{ \
		ndmpd_##cmd##_v##ver, \
		0, 0, \
		0, 0, \
	}

/*
 * No handler for this entry
 */
#define	HANDL_NULL \
	{ \
		0, \
		0, 0, \
		0, 0, \
	}

/*
 * LINT does not like this table as it references
 * XDR functions from ndmp_xdr.c which is not included
 * for LINT.
 */
#ifndef	lint
ndmp_handler_t ndmp_msghdl_tab[] = {
	{
		/* NONE - 0x000 */
		0,
		{
			{
				0,
				AUTH_NOT_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_NULL,
				}
			}
		}
	},
	{
		/* CONFIG - 0x100 */
		11,
		{
			{
				NDMP_CONFIG_GET_HOST_INFO,
				AUTH_REQUIRED,
				{
					HANDL_RS(config_get_host_info, 2, 2),
					HANDL_RS(config_get_host_info, 3, 3),
					HANDL_RS(config_get_host_info, 3, 4),
				}
			},
			{
				NDMP_CONFIG_GET_BUTYPE_ATTR,
				AUTH_NOT_REQUIRED,
				{
					HANDL(config_get_butype_attr, 2, 2),
					HANDL_NULL,
					HANDL_NULL,
				}
			},
			{
				NDMP_CONFIG_GET_CONNECTION_TYPE,
				AUTH_REQUIRED,
				{
				    HANDL_RS(config_get_mover_type, 2, 2),
				    HANDL_RS(config_get_connection_type, 3, 3),
				    HANDL_RS(config_get_connection_type, 3, 4),
				}
			},
			{
				NDMP_CONFIG_GET_AUTH_ATTR,
				AUTH_NOT_REQUIRED,
				{
					HANDL(config_get_auth_attr, 2, 2),
					HANDL(config_get_auth_attr, 3, 3),
					HANDL(config_get_auth_attr, 3, 4),
				}
			},
			{
				NDMP_CONFIG_GET_BUTYPE_INFO,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RS(config_get_butype_info, 3, 3),
					HANDL_RS(config_get_butype_info, 4, 4),
				}
			},
			{
				NDMP_CONFIG_GET_FS_INFO,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RS(config_get_fs_info, 3, 3),
					HANDL_RS(config_get_fs_info, 3, 4),
				}
			},
			{
				NDMP_CONFIG_GET_TAPE_INFO,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RS(config_get_tape_info, 3, 3),
					HANDL_RS(config_get_tape_info, 3, 4),
				}
			},
			{
				NDMP_CONFIG_GET_SCSI_INFO,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RS(config_get_scsi_info, 3, 3),
					HANDL_RS(config_get_scsi_info, 3, 4),
				}
			},
			{
				NDMP_CONFIG_GET_SERVER_INFO,
				AUTH_NOT_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RS(config_get_server_info, 3, 3),
					HANDL_RS(config_get_server_info, 3, 4),
				}
			},
			{
				NDMP_CONFIG_SET_EXT_LIST,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL(config_set_ext_list, 4, 4),
				}
			},
			{
				NDMP_CONFIG_GET_EXT_LIST,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_RS(config_get_ext_list, 4, 4),
				}
			}
		}
	},
	{
		/* SCSI - 0x200 */
		7,
		{
			{
				NDMP_SCSI_OPEN,
				AUTH_REQUIRED,
				{
					HANDL(scsi_open, 2, 2),
					HANDL(scsi_open, 3, 3),
					HANDL(scsi_open, 3, 4),
				}
			},
			{
				NDMP_SCSI_CLOSE,
				AUTH_REQUIRED,
				{
					HANDL_RS(scsi_close, 2, 2),
					HANDL_RS(scsi_close, 2, 3),
					HANDL_RS(scsi_close, 2, 4),
				}
			},
			{
				NDMP_SCSI_GET_STATE,
				AUTH_REQUIRED,
				{
					HANDL_RS(scsi_get_state, 2, 2),
					HANDL_RS(scsi_get_state, 2, 3),
					HANDL_RS(scsi_get_state, 2, 4),
				}
			},
			{
				NDMP_SCSI_SET_TARGET,
				AUTH_REQUIRED,
				{
					HANDL(scsi_set_target, 2, 2),
					HANDL(scsi_set_target, 3, 3),
					HANDL_NULL,
				}
			},
			{
				NDMP_SCSI_RESET_DEVICE,
				AUTH_REQUIRED,
				{
					HANDL_RS(scsi_reset_device, 2, 2),
					HANDL_RS(scsi_reset_device, 2, 3),
					HANDL_RS(scsi_reset_device, 2, 4),
				}
			},
			{
				NDMP_SCSI_RESET_BUS,
				AUTH_REQUIRED,
				{
					HANDL_RS(scsi_reset_bus, 2, 2),
					HANDL_RS(scsi_reset_bus, 2, 3),
					HANDL_NULL,
				}
			},
			{
				NDMP_SCSI_EXECUTE_CDB,
				AUTH_REQUIRED,
				{
					HANDL(scsi_execute_cdb, 2, 2),
					HANDL(scsi_execute_cdb, 2, 3),
					HANDL(scsi_execute_cdb, 2, 4),
				}
			}
		}
	},
	{
		/* TAPE - 0x300 */
		8,
		{
			{
				NDMP_TAPE_OPEN,
				AUTH_REQUIRED,
				{
					HANDL(tape_open, 2, 2),
					HANDL(tape_open, 3, 3),
					HANDL(tape_open, 3, 4),
				}
			},
			{
				NDMP_TAPE_CLOSE,
				AUTH_REQUIRED,
				{
					HANDL_RS(tape_close, 2, 2),
					HANDL_RS(tape_close, 2, 3),
					HANDL_RS(tape_close, 4, 4),
				}
			},
			{
				NDMP_TAPE_GET_STATE,
				AUTH_REQUIRED,
				{
					HANDL_RS(tape_get_state, 2, 2),
					HANDL_RS(tape_get_state, 3, 3),
					HANDL_RS(tape_get_state, 3, 4),
				}
			},
			{
				NDMP_TAPE_MTIO,
				AUTH_REQUIRED,
				{
					HANDL(tape_mtio, 2, 2),
					HANDL(tape_mtio, 2, 3),
					HANDL(tape_mtio, 2, 4),
				}
			},
			{
				NDMP_TAPE_WRITE,
				AUTH_REQUIRED,
				{
					HANDL(tape_write, 3, 2),
					HANDL(tape_write, 3, 3),
					HANDL(tape_write, 3, 4),
				}
			},
			{
				NDMP_TAPE_READ,
				AUTH_REQUIRED,
				{
					HANDL(tape_read, 2, 2),
					HANDL(tape_read, 3, 3),
					HANDL(tape_read, 3, 4),
				}
			},
			{
				NDMP_TAPE_SET_RECORD_SIZE,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_NULL,
				}
			},
			{
				NDMP_TAPE_EXECUTE_CDB,
				AUTH_REQUIRED,
				{
					HANDL(tape_execute_cdb, 2, 2),
					HANDL(tape_execute_cdb, 2, 3),
					HANDL(tape_execute_cdb, 2, 4),
				}
			}
		}
	},
	{
		/* DATA - 0x400 */
		12,
		{
			{
				NDMP_DATA_GET_STATE,
				AUTH_REQUIRED,
				{
					HANDL_RS(data_get_state, 2, 2),
					HANDL_RS(data_get_state, 3, 3),
					HANDL_RS(data_get_state, 4, 4),
				}
			},
			{
				NDMP_DATA_START_BACKUP,
				AUTH_REQUIRED,
				{
					HANDL(data_start_backup, 2, 2),
					HANDL(data_start_backup, 3, 3),
					HANDL(data_start_backup, 3, 4),
				}
			},
			{
				NDMP_DATA_START_RECOVER,
				AUTH_REQUIRED,
				{
					HANDL(data_start_recover, 2, 2),
					HANDL(data_start_recover, 3, 3),
					HANDL(data_start_recover, 3, 4),
				}
			},
			{
				NDMP_DATA_ABORT,
				AUTH_REQUIRED,
				{
					HANDL_RS(data_abort, 2, 2),
					HANDL_RS(data_abort, 3, 3),
					HANDL_RS(data_abort, 3, 4),
				}
			},
			{
				NDMP_DATA_GET_ENV,
				AUTH_REQUIRED,
				{
					HANDL_RS(data_get_env, 2, 2),
					HANDL_RS(data_get_env, 2, 3),
					HANDL_RS(data_get_env, 4, 4),
				}
			},
			{
				NDMP_DATA_RESVD1,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_NULL,
				}
			},
			{
				NDMP_DATA_RESVD2,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_NULL,
				}
			},

			{
				NDMP_DATA_STOP,
				AUTH_REQUIRED,
				{
					HANDL_RS(data_stop, 2, 2),
					HANDL_RS(data_stop, 3, 3),
					HANDL_RS(data_stop, 3, 4),
				}
			},
			{
				NDMP_DATA_CONTINUE,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_NULL,
				}
			},
			{
				NDMP_DATA_LISTEN,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL(data_listen, 3, 3),
					HANDL(data_listen, 4, 4),
				}
			},
			{
				NDMP_DATA_CONNECT,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL(data_connect, 3, 3),
					HANDL(data_connect, 4, 4),
				}
			},
			{
				NDMP_DATA_START_RECOVER_FILEHIST,
				AUTH_REQUIRED,
				{
				    HANDL_NULL,
				    HANDL_NULL,
				    HANDL_RS(data_start_recover_filehist, 4, 4),
				}
			}
		}
	},
	{
		/* NOTIFY - 0x500 */
		6,
		{
			{
				NDMP_NOTIFY_RESERVED,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_NULL,
					HANDL_NULL,
				}
			},

			{
				NDMP_NOTIFY_DATA_HALTED,
				AUTH_REQUIRED,
				{
					HANDL_RQ(notify_data_halted, 2),
					HANDL_RQ(notify_data_halted, 3),
					HANDL_RQ(notify_data_halted, 4),
				}
			},
			{
				NDMP_NOTIFY_CONNECTION_STATUS,
				AUTH_NOT_REQUIRED,
				{
					HANDL_RQ(notify_connection_status, 2),
					HANDL_RQ(notify_connection_status, 3),
					HANDL_RQ(notify_connection_status, 4),
				}
			},
			{
				NDMP_NOTIFY_MOVER_HALTED,
				AUTH_REQUIRED,
				{
					HANDL_RQ(notify_mover_halted, 2),
					HANDL_RQ(notify_mover_halted, 3),
					HANDL_RQ(notify_mover_halted, 4),
				}
			},
			{
				NDMP_NOTIFY_MOVER_PAUSED,
				AUTH_REQUIRED,
				{
					HANDL_RQ(notify_mover_paused, 2),
					HANDL_RQ(notify_mover_paused, 3),
					HANDL_RQ(notify_mover_paused, 4),
				}
			},
			{
				NDMP_NOTIFY_DATA_READ,
				AUTH_REQUIRED,
				{
					HANDL_RQ(notify_data_read, 2),
					HANDL_RQ(notify_data_read, 3),
					HANDL_RQ(notify_data_read, 4),
				}
			}
		}
	},
	{
		/* LOG - 0x600 */
		4,
		{
			{
				_NDMP_LOG_LOG,
				AUTH_REQUIRED,
				{
					HANDL_RQ(log_log, 2),
					HANDL_NULL,
					HANDL_NULL,
				}
			},
			{
				_NDMP_LOG_DEBUG,
				AUTH_REQUIRED,
				{
					HANDL_RQ(log_debug, 2),
					HANDL_NULL,
					HANDL_NULL,
				}
			},
			{
				NDMP_LOG_FILE,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RQ(log_file, 3),
					HANDL_RQ(log_file, 4),
				}
			},
			{
				NDMP_LOG_MESSAGE,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RQ(log_message, 3),
					HANDL_RQ(log_message, 4),
				}
			}
		}
	},
	{
		/* FH - 0x700 */
		6,
		{
			{
				NDMP_FH_ADD_UNIX_PATH,
				AUTH_REQUIRED,
				{
					HANDL_RQ(fh_add_unix_path, 2),
					HANDL_RQ(fh_add_unix_path, 3),
					HANDL_NULL,
				}
			},
			{
				NDMP_FH_ADD_UNIX_DIR,
				AUTH_REQUIRED,
				{
					HANDL_RQ(fh_add_unix_dir, 2),
					HANDL_RQ(fh_add_unix_dir, 3),
					HANDL_NULL,
				}
			},
			{
				NDMP_FH_ADD_UNIX_NODE,
				AUTH_REQUIRED,
				{
					HANDL_RQ(fh_add_unix_node, 2),
					HANDL_RQ(fh_add_unix_node, 3),
					HANDL_NULL,
				}
			},
			{
				NDMP_FH_ADD_FILE,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RQ(fh_add_file, 3),
					HANDL_RQ(fh_add_file, 4),
				}
			},
			{
				NDMP_FH_ADD_DIR,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RQ(fh_add_dir, 3),
					HANDL_RQ(fh_add_dir, 4),
				}
			},
			{
				NDMP_FH_ADD_NODE,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL_RQ(fh_add_node, 3),
					HANDL_RQ(fh_add_node, 4),
				}
			}
		}
	},
	{
		/* NONE - 0x800 */
		0,
	},
	{
		/* CONNECT - 0x900 */
		4,
		{
			{
				NDMP_CONNECT_OPEN,
				AUTH_NOT_REQUIRED,
				{
					HANDL(connect_open, 2, 2),
					HANDL(connect_open, 2, 3),
					HANDL(connect_open, 2, 4),
				}
			},
			{
				NDMP_CONNECT_AUTH,
				AUTH_NOT_REQUIRED,
				{
					HANDL(connect_client_auth, 2, 2),
					HANDL(connect_client_auth, 3, 3),
					HANDL(connect_client_auth, 3, 4),
				}
			},
			{
				NDMP_CONNECT_CLOSE,
				AUTH_NOT_REQUIRED,
				{
					HANDL_NONE(connect_close, 2),
					HANDL_NONE(connect_close, 3),
					HANDL_NONE(connect_close, 3),
				}
			},
			{
				NDMP_CONNECT_SERVER_AUTH,
				AUTH_REQUIRED,
				{
					HANDL(connect_server_auth, 2, 2),
					HANDL(connect_server_auth, 2, 3),
					HANDL(connect_server_auth, 2, 4),
				}
			}
		}
	},
	{
		/* MOVER - 0xa00 */
		10,
		{
			{
				NDMP_MOVER_GET_STATE,
				AUTH_REQUIRED,
				{
					HANDL_RS(mover_get_state, 2, 2),
					HANDL_RS(mover_get_state, 3, 3),
					HANDL_RS(mover_get_state, 4, 4),
				}
			},
			{
				NDMP_MOVER_LISTEN,
				AUTH_REQUIRED,
				{
					HANDL(mover_listen, 2, 2),
					HANDL(mover_listen, 3, 3),
					HANDL(mover_listen, 4, 4),
				}
			},
			{
				NDMP_MOVER_CONTINUE,
				AUTH_REQUIRED,
				{
					HANDL_RS(mover_continue, 2, 2),
					HANDL_RS(mover_continue, 3, 3),
					HANDL_RS(mover_continue, 3, 4),
				}
			},
			{
				NDMP_MOVER_ABORT,
				AUTH_REQUIRED,
				{
					HANDL_RS(mover_abort, 2, 2),
					HANDL_RS(mover_abort, 3, 3),
					HANDL_RS(mover_abort, 3, 4),
				}
			},
			{
				NDMP_MOVER_STOP,
				AUTH_REQUIRED,
				{
					HANDL_RS(mover_stop, 2, 2),
					HANDL_RS(mover_stop, 2, 3),
					HANDL_RS(mover_stop, 2, 4),
				}
			},
			{
				NDMP_MOVER_SET_WINDOW,
				AUTH_REQUIRED,
				{
					HANDL(mover_set_window, 2, 2),
					HANDL(mover_set_window, 3, 3),
					HANDL(mover_set_window, 3, 4),
				}
			},
			{
				NDMP_MOVER_READ,
				AUTH_REQUIRED,
				{
					HANDL(mover_read, 2, 2),
					HANDL(mover_read, 3, 3),
					HANDL(mover_read, 3, 4),
				}
			},
			{
				NDMP_MOVER_CLOSE,
				AUTH_REQUIRED,
				{
					HANDL_RS(mover_close, 2, 2),
					HANDL_RS(mover_close, 2, 3),
					HANDL_RS(mover_close, 2, 4),
				}
			},
			{
				NDMP_MOVER_SET_RECORD_SIZE,
				AUTH_REQUIRED,
				{
					HANDL(mover_set_record_size, 2, 2),
					HANDL(mover_set_record_size, 3, 3),
					HANDL(mover_set_record_size, 3, 4),
				}
			},
			{
				NDMP_MOVER_CONNECT,
				AUTH_REQUIRED,
				{
					HANDL_NULL,
					HANDL(mover_connect, 3, 3),
					HANDL(mover_connect, 4, 4),
				}
			}
		}
	}
};
#else	/* !lint */
ndmp_handler_t ndmp_msghdl_tab[] = {
	0
};
#endif	/* !lint */
