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

#define VER 3

const NDMPV2 = 2;
const NDMPV3 = 3;
const NDMPV4 = 4;
const NDMPVER = NDMPV4;
const NDMPPORT = 10000;

struct ndmp_u_quad
{
	u_long	high;
	u_long	low;
};

struct ndmp_pval
{
	string	name<>;
	string	value<>;
};

struct ndmp_scsi_device
{
	string	name<>;
};

struct ndmp_tape_device
{
	string	name<>;
};

enum ndmp_error  
{ 
	NDMP_NO_ERR                     =  0, /* No error */
	NDMP_NOT_SUPPORTED_ERR          =  1, /* Call is not supported */
	NDMP_DEVICE_BUSY_ERR            =  2, /* The device is in use */
	NDMP_DEVICE_OPENED_ERR          =  3, /* Another tape or scsi device is already open */
	NDMP_NOT_AUTHORIZED_ERR         =  4, /* Connection has not been authorized */
	NDMP_PERMISSION_ERR             =  5, /* Some sort of permission problem */
	NDMP_DEV_NOT_OPEN_ERR           =  6, /* SCSI device is not open */
	NDMP_IO_ERR                     =  7, /* I/O error */   
	NDMP_TIMEOUT_ERR                =  8, /* command timed out */   
	NDMP_ILLEGAL_ARGS_ERR           =  9, /* illegal arguments in request */   
	NDMP_NO_TAPE_LOADED_ERR         = 10, /* Cannot open because there is no tape loaded */   
	NDMP_WRITE_PROTECT_ERR          = 11, /* tape cannot be open for write */   
	NDMP_EOF_ERR                    = 12, /* Command encountered EOF */   
	NDMP_EOM_ERR                    = 13, /* Command encountered EOM */   
	NDMP_FILE_NOT_FOUND_ERR         = 14, /* File not found during restore */   
	NDMP_BAD_FILE_ERR               = 15, /* The file descriptor is invalid */   
	NDMP_NO_DEVICE_ERR              = 16, /* The device is not at that target */   
	NDMP_NO_BUS_ERR                 = 17, /* Invalid controller */   
	NDMP_XDR_DECODE_ERR             = 18, /* Can't decode the request argument */   
	NDMP_ILLEGAL_STATE_ERR          = 19, /* Call can't be performed at this state */   
	NDMP_UNDEFINED_ERR              = 20, /* Undefined Error */   
	NDMP_XDR_ENCODE_ERR             = 21, /* Can't encode the reply argument */   
	NDMP_NO_MEM_ERR                 = 22, /* No memory */   

	/*
	 * NDMP V3
	 */
	NDMP_CONNECT_ERR                = 23,  

	/*
	 * NDMP V4
	 */
	NDMP_SEQUENCE_NUM_ERR           = 24,    
	NDMP_READ_IN_PROGRESS_ERR       = 25, 
	NDMP_PRECONDITION_ERR           = 26,  
	NDMP_CLASS_NOT_SUPPORTED_ERR    = 27, 
	NDMP_VERSION_NOT_SUPPORTED_ERR  = 28, 
	NDMP_EXT_DUPL_CLASSES_ERR       = 29, 
	NDMP_EXT_DANDN_ILLEGAL_ERR      = 30 
}; 

enum ndmp_header_message_type
{
	NDMP_MESSAGE_REQUEST,
	NDMP_MESSAGE_REPLY
};

enum ndmp_message
{
	NDMP_CONNECT_OPEN               = 0x900, 
	NDMP_CONNECT_CLIENT_AUTH        = 0x901, 
	NDMP_CONNECT_CLOSE              = 0x902, 
	NDMP_CONNECT_SERVER_AUTH        = 0x903, 

	NDMP_CONFIG_GET_HOST_INFO       = 0x100, 
	NDMP_CONFIG_GET_BUTYPE_ATTR     = 0x101, 	/* NDMP V2 */
	NDMP_CONFIG_GET_CONNECTION_TYPE = 0x102,           
	NDMP_CONFIG_GET_AUTH_ATTR       = 0x103, 
	NDMP_CONFIG_GET_BUTYPE_INFO     = 0x104, 	/* NDMP V3,4 */
	NDMP_CONFIG_GET_FS_INFO         = 0x105,  	/* NDMP V3,4 */
	NDMP_CONFIG_GET_TAPE_INFO       = 0x106,  	/* NDMP V3,4 */
	NDMP_CONFIG_GET_SCSI_INFO       = 0x107,  	/* NDMP V3,4 */
	NDMP_CONFIG_GET_SERVER_INFO     = 0x108,  	/* NDMP V3,4 */
	NDMP_CONFIG_SET_EXT_LIST        = 0x109, 	/* NDMP V4 */
	NDMP_CONFIG_GET_EXT_LIST        = 0x10A, 	/* NDMP V4 */

	NDMP_SCSI_OPEN                  = 0x200,     
	NDMP_SCSI_CLOSE                 = 0x201, 
	NDMP_SCSI_GET_STATE             = 0x202, 
	NDMP_SCSI_SET_TARGET            = 0x203,	/* NDMP V2,3 */
	NDMP_SCSI_RESET_DEVICE          = 0x204, 
	NDMP_SCSI_RESET_BUS             = 0x205,	/* NDMP V2,3 */
	NDMP_SCSI_EXECUTE_CDB           = 0x206, 

	NDMP_TAPE_OPEN                  = 0x300, 
	NDMP_TAPE_CLOSE                 = 0x301, 
	NDMP_TAPE_GET_STATE             = 0x302, 
	NDMP_TAPE_MTIO                  = 0x303, 
	NDMP_TAPE_WRITE                 = 0x304, 
	NDMP_TAPE_READ                  = 0x305, 
	NDMP_TAPE_SET_RECORD_SIZE	= 0x306,	/* NDMP V1 */
	NDMP_TAPE_EXECUTE_CDB           = 0x307, 

	NDMP_DATA_GET_STATE             = 0x400, 
	NDMP_DATA_START_BACKUP          = 0x401, 
	NDMP_DATA_START_RECOVER         = 0x402, 
	NDMP_DATA_ABORT                 = 0x403, 
	NDMP_DATA_GET_ENV               = 0x404, 
	NDMP_DATA_RESVD1                = 0x405,
	NDMP_DATA_RESVD2                = 0x406,
	NDMP_DATA_STOP                  = 0x407, 
	NDMP_DATA_CONTINUE		= 0x408,	/* NDMP V1 */
	NDMP_DATA_LISTEN                = 0x409,  
	NDMP_DATA_CONNECT               = 0x40A, 
	NDMP_DATA_START_RECOVER_FILEHIST = 0x40B, 	/* NDMP V4 */

	NDMP_NOTIFY_RESERVED            = 0x500,
	NDMP_NOTIFY_DATA_HALTED         = 0x501,     
	NDMP_NOTIFY_CONNECTION_STATUS   = 0x502,     
	NDMP_NOTIFY_MOVER_HALTED        = 0x503, 
	NDMP_NOTIFY_MOVER_PAUSED        = 0x504, 
	NDMP_NOTIFY_DATA_READ           = 0x505, 

	_NDMP_LOG_LOG                   = 0x600, 	/* NDMP V2 */
	_NDMP_LOG_DEBUG                 = 0x601, 	/* NDMP V2 */
	NDMP_LOG_FILE                   = 0x602, 	/* NDMP V3,4 */
	NDMP_LOG_MESSAGE                = 0x603, 	/* NDMP V3,4 */ 

	NDMP_FH_ADD_UNIX_PATH           = 0x700, 	/* NDMP V2,3 */
	NDMP_FH_ADD_UNIX_DIR            = 0x701, 	/* NDMP V2,3 */
	NDMP_FH_ADD_UNIX_NODE           = 0x702, 	/* NDMP V2,3 */
	NDMP_FH_ADD_FILE                = 0x703, 	/* NDMP V3,4 */
	NDMP_FH_ADD_DIR                 = 0x704, 	/* NDMP V3,4 */
	NDMP_FH_ADD_NODE                = 0x705, 	/* NDMP V3,4 */

	NDMP_MOVER_GET_STATE            = 0xA00, 
	NDMP_MOVER_LISTEN               = 0xA01, 
	NDMP_MOVER_CONTINUE             = 0xA02, 
	NDMP_MOVER_ABORT                = 0xA03, 
	NDMP_MOVER_STOP                 = 0xA04, 
	NDMP_MOVER_SET_WINDOW           = 0xA05, 
	NDMP_MOVER_READ                 = 0xA06, 
	NDMP_MOVER_CLOSE                = 0xA07, 
	NDMP_MOVER_SET_RECORD_SIZE      = 0xA08, 
	NDMP_MOVER_CONNECT              = 0xA09, 	/* NDMP V3,4 */

	NDMP_EXT_STANDARD_BASE          = 0x10000, 

	NDMP_EXT_PROPRIETARY_BASE       = 0x20000000 

};

const NDMP_CONNECT_AUTH = NDMP_CONNECT_CLIENT_AUTH;
const NDMP_MESSAGE_POST = NDMP_MESSAGE_REQUEST; 

struct ndmp_header
{
	u_long sequence;			/* Monotonically increasing number */
	u_long time_stamp;			/* Time stamp of message */
	ndmp_header_message_type message_type;	/* What type of message */
	enum ndmp_message message;		/* Message number */
	u_long reply_sequence;			/* Reply is in response to */
	ndmp_error error;			/* Communications errors */
};


/***************************/
/*  CONNECT INTERFACE (V2) */
/***************************/

/* NDMP_CONNECT_OPEN */
struct ndmp_connect_open_request
{
	u_short	protocol_version;	/* the version of protocol supported */
};

struct ndmp_connect_open_reply
{
	ndmp_error	error;
};

/* NDMP_CONNECT_CLIENT_AUTH = NDMP_CONNECT_AUTH */
enum ndmp_auth_type
{
	NDMP_AUTH_NONE,		/* no password is required */
	NDMP_AUTH_TEXT,		/* the clear text password */
	NDMP_AUTH_MD5		/* md5 */
};

struct ndmp_auth_text
{
	string	user<>;
	string	password<>;
};

struct ndmp_auth_md5
{
	string	user<>;
	opaque	auth_digest[16];
};

union ndmp_auth_data switch (enum ndmp_auth_type auth_type)
{
	case NDMP_AUTH_NONE:
		void;
	case NDMP_AUTH_TEXT:
		struct ndmp_auth_text	auth_text;
	case NDMP_AUTH_MD5:
		struct ndmp_auth_md5	auth_md5;
};

struct ndmp_connect_client_auth_request
{
	ndmp_auth_data	auth_data;
};

struct ndmp_connect_client_auth_reply
{
	ndmp_error	error;
};


/* NDMP_CONNECT_CLOSE */
/* no request arguments */
/* no reply arguments */

/* NDMP_CONNECT_SERVER_AUTH */
union ndmp_auth_attr switch (enum ndmp_auth_type auth_type)
{
	case NDMP_AUTH_NONE:
		void;
	case NDMP_AUTH_TEXT:
		void;
	case NDMP_AUTH_MD5:
		opaque	challenge[64];
};

struct ndmp_connect_server_auth_request
{
	ndmp_auth_attr	client_attr;
};

struct ndmp_connect_server_auth_reply
{
	ndmp_error	error;
	ndmp_auth_data	auth_result;
};


/***************************/
/*  CONNECT INTERFACE (V3) */
/***************************/

/* NDMP_CONNECT_OPEN - same as V2 */

struct ndmp_auth_text_v3
{
	string	auth_id<>;
	string	auth_password<>;

};

struct ndmp_auth_md5_v3
{
	string	auth_id<>;
	opaque	auth_digest[16];
};

union ndmp_auth_data_v3 switch (enum ndmp_auth_type auth_type)
{
	case NDMP_AUTH_NONE:
		void;
	case NDMP_AUTH_TEXT:
		struct ndmp_auth_text_v3	auth_text;
	case NDMP_AUTH_MD5:
		struct ndmp_auth_md5_v3	auth_md5;
};

struct ndmp_connect_client_auth_request_v3
{
	ndmp_auth_data_v3	auth_data;
};

struct ndmp_connect_client_auth_reply_v3
{
	ndmp_error	error;
};

/* NDMP_CONNECT_CLOSE - same as V2 */

/* NDMP_CONNECT_SERVER_AUTH - same as V2 */


/***************************/
/*  CONNECT INTERFACE (V4) */
/***************************/

/* NDMP_CONNECT_OPEN - same as V3 */

/* NDMP_CONNECT_CLIENT_AUTH - same as V3 */

/* NDMP_CONNECT_CLOSE - same as V3 */

/* NDMP_CONNECT_SERVER_AUTH - same as V3 */


/*************************/
/* CONFIG INTERFACE (V2) */
/*************************/

/* NDMP_CONFIG_GET_HOST_INFO */
/* no request arguments */

struct ndmp_config_get_host_info_reply
{
	ndmp_error	error;
	string		hostname<>;	/* host name */
	string		os_type<>;	/* The operating system type (i.e. SOLARIS) */
	string		os_vers<>;	/* The version number of the OS (i.e. 2.5) */
	string		hostid<>;
	ndmp_auth_type	auth_type<>;
};

/* NDMP_CONFIG_GET_BUTYPE_ATTR */
const NDMP_NO_BACKUP_FILELIST	= 0x0001;
const NDMP_NO_BACKUP_FHINFO	= 0x0002;
const NDMP_NO_RECOVER_FILELIST	= 0x0004;
const NDMP_NO_RECOVER_FHINFO	= 0x0008;
const NDMP_NO_RECOVER_SSID	= 0x0010;
const NDMP_NO_RECOVER_INC_ONLY	= 0x0020;

struct ndmp_config_get_butype_attr_request
{
	string	name<>;		/* backup type name */
};

struct ndmp_config_get_butype_attr_reply
{
	ndmp_error	error;
	u_long		attrs;
};

/* NDMP_CONFIG_GET_MOVER_TYPE */
/* no request arguments */

enum ndmp_addr_type  
{ 
	NDMP_ADDR_LOCAL    = 0, 
	NDMP_ADDR_TCP      = 1, 
	NDMP_ADDR_FC       = 2, 	/* NDMP V2,3 */
	NDMP_ADDR_IPC      = 3 
}; 

struct ndmp_config_get_mover_type_reply
{
	ndmp_error		error;
	ndmp_addr_type		methods<>;
};

/* NDMP_CONFIG_GET_AUTH_ATTR */
struct ndmp_config_get_auth_attr_request
{
	ndmp_auth_type	auth_type;
};

struct ndmp_config_get_auth_attr_reply
{
	ndmp_error		error;
	ndmp_auth_attr		server_attr;
};


/*************************/
/* CONFIG INTERFACE (V3) */
/*************************/

/* NDMP_CONFIG_GET_HOST_INFO */
/* no request arguments */

struct ndmp_config_get_host_info_reply_v3
{
	ndmp_error	error;
	string		hostname<>;	/* host name */
	string		os_type<>;	/* The operating system type (i.e. SOLARIS) */
	string		os_vers<>;	/* The version number of the OS (i.e. 2.5) */
	string		hostid<>;
};

/* NDMP_CONFIG_GET_CONNECTION_TYPE */
/* no request arguments */

struct ndmp_config_get_connection_type_reply_v3
{
	ndmp_error	error;
	ndmp_addr_type	addr_types<>;
};

/* NDMP_CONFIG_GET_AUTH_ATTR - same as V2 */

/* NDMP_CONFIG_GET_SERVER_INFO */
/* no requset arguments */

struct ndmp_config_get_server_info_reply_v3
{
	ndmp_error	error;
	string		vendor_name<>;
	string		product_name<>;
	string		revision_number<>;
	ndmp_auth_type	auth_type<>;
};

/* Backup type attributes */
const NDMP_BUTYPE_BACKUP_FILE_HISTORY	 = 0x0001;	/* NDMP V2,3 */
const NDMP_BUTYPE_BACKUP_FILELIST        = 0x0002; 
const NDMP_BUTYPE_RECOVER_FILELIST       = 0x0004; 
const NDMP_BUTYPE_BACKUP_DIRECT          = 0x0008; 
const NDMP_BUTYPE_RECOVER_DIRECT         = 0x0010; 
const NDMP_BUTYPE_BACKUP_INCREMENTAL     = 0x0020; 
const NDMP_BUTYPE_RECOVER_INCREMENTAL    = 0x0040; 
const NDMP_BUTYPE_BACKUP_UTF8            = 0x0080; 
const NDMP_BUTYPE_RECOVER_UTF8           = 0x0100; 
const NDMP_BUTYPE_BACKUP_FH_FILE         = 0x0200; 	/* NDMP V4 */
const NDMP_BUTYPE_BACKUP_FH_DIR          = 0x0400; 	/* NDMP V4 */
const NDMP_BUTYPE_RECOVER_FILEHIST       = 0x0800; 	/* NDMP V4 */
const NDMP_BUTYPE_RECOVER_FH_FILE        = 0x1000; 	/* NDMP V4 */
const NDMP_BUTYPE_RECOVER_FH_DIR         = 0x2000; 	/* NDMP V4 */

 
struct ndmp_butype_info
{
	string		butype_name<>;
	ndmp_pval	default_env<>;
	u_long		attrs;
};

/* NDMP_CONFIG_GET_BUTYPE_INFO */
/* no request arguments */

struct ndmp_config_get_butype_info_reply_v3 
{
	ndmp_error		error;
	ndmp_butype_info	butype_info<>;
};

/* invalid bit */
const	NDMP_FS_INFO_TOTAL_SIZE_INVALID 	= 0x00000001;
const	NDMP_FS_INFO_USED_SIZE_INVALID		= 0x00000002;
const	NDMP_FS_INFO_AVAIL_SIZE_INVALID		= 0x00000004;
const	NDMP_FS_INFO_TOTAL_INODES_INVALID	= 0x00000008;
const	NDMP_FS_INFO_USED_INODES_INVALID	= 0x00000010;

struct ndmp_fs_info_v3
{
	u_long		invalid;
	string		fs_type<>;
	string		fs_logical_device<>;
	string		fs_physical_device<>;
	ndmp_u_quad	total_size;
	ndmp_u_quad	used_size;
	ndmp_u_quad	avail_size;
	ndmp_u_quad	total_inodes;
	ndmp_u_quad	used_inodes;
	ndmp_pval	fs_env<>;
	string		fs_status<>;
};

/* NDMP_CONFIG_GET_FS_INFO */
/* no request arguments */

struct ndmp_config_get_fs_info_reply_v3
{
	ndmp_error		error;
	ndmp_fs_info_v3		fs_info<>;
};

/* NDMP_CONFIG_GET_TAPE_INFO */
/* no request arguments */

/* tape attributes */
const NDMP_TAPE_ATTR_REWIND = 0x00000001; 
const NDMP_TAPE_ATTR_UNLOAD = 0x00000002; 
const NDMP_TAPE_ATTR_RAW    = 0x00000004; 


struct ndmp_device_capability_v3
{
	string		device<>;
	u_long		attr;
	ndmp_pval	capability<>;
};

struct ndmp_device_info_v3
{
	string				model<>;
	ndmp_device_capability_v3	caplist<>;

};
struct ndmp_config_get_tape_info_reply_v3 
{
	ndmp_error		error;
	ndmp_device_info_v3	tape_info<>;

};

/* NDMP_CONFIG_GET_SCSI_INFO */

/* jukebox attributes */
struct ndmp_config_get_scsi_info_reply_v3
{
	ndmp_error		error;
	ndmp_device_info_v3	scsi_info<>;
};


/*************************/
/* CONFIG INTERFACE (V4) */
/*************************/

/* NDMP_CONFIG_GET_HOST_INFO - same as V3 */

/* NDMP_CONFIG_GET_SERVER_INFO - same as V3 */

/* NDMP_CONFIG_GET_CONNECTION_TYPE - same as V3 */

/* NDMP_CONFIG_GET_AUTH_ATTR - same as V3 */


struct ndmp_config_get_butype_info_reply_v4
{ 
	ndmp_error            error; 
	ndmp_butype_info      butype_info<>; 
}; 


/* NDMP_CONFIG_GET_FS_INFO - same as V3 */

struct ndmp_class_list  
{ 
	u_short      ext_class_id; 
	u_short      ext_version<>; 
};  

struct ndmp_class_version 
{ 
	u_short      ext_class_id; 
	u_short      ext_version; 
}; 

struct ndmp_config_get_ext_list_reply 
{ 
	ndmp_error         error; 
	ndmp_class_list    class_list<>; 
}; 

struct ndmp_config_set_ext_list_request 
{ 
	ndmp_class_version    ndmp_selected_ext<>; 
};  

struct ndmp_config_set_ext_list_reply 
{ 
	ndmp_error      error; 
}; 


/***********************/
/* SCSI INTERFACE (V2) */
/***********************/

/* NDMP_SCSI_OPEN */
struct ndmp_scsi_open_request
{
	ndmp_scsi_device	device;
};

struct ndmp_scsi_open_reply
{
	ndmp_error	error;
};

/* NDMP_SCSI_CLOSE */
/* no request arguments */

struct ndmp_scsi_close_reply
{
	ndmp_error	error;
};

/* NDMP_SCSI_GET_STATE */
/* no request arguments */

struct ndmp_scsi_get_state_reply
{
	ndmp_error	error;
	short		target_controller;
	short		target_id;
	short		target_lun;
};

/* NDMP_SCSI_SET_TARGET */
struct ndmp_scsi_set_target_request
{
	ndmp_scsi_device	device;
	u_short			target_controller;
	u_short			target_id;
	u_short			target_lun;
};

struct ndmp_scsi_set_target_reply
{
	ndmp_error	error;
};

/* NDMP_SCSI_RESET_DEVICE */
/* no request arguments */

struct ndmp_scsi_reset_device_reply
{
	ndmp_error	error;
};

/* NDMP_SCSI_RESET_BUS */
/* no request arguments */

struct ndmp_scsi_reset_bus_reply
{
	ndmp_error	error;
};

/* NDMP_SCSI_EXECUTE_CDB */
const NDMP_SCSI_DATA_IN		= 0x00000001;	/* Expect data from SCSI device */
const NDMP_SCSI_DATA_OUT	= 0x00000002;	/* Transfer data to SCSI device */

struct ndmp_execute_cdb_request
{
	u_long	flags;
	u_long	timeout;
	u_long	datain_len;		/* Set for expected datain */
	opaque	cdb<>;
	opaque	dataout<>;
};

struct ndmp_execute_cdb_reply
{
	ndmp_error	error;
	u_char		status;		/* SCSI status bytes */
	u_long		dataout_len;
	opaque		datain<>;	/* SCSI datain */
	opaque		ext_sense<>;	/* Extended sense data */
};


/***********************/
/* SCSI INTERFACE (V3) */
/***********************/

/* NDMP_SCSI_OPEN */
struct ndmp_scsi_open_request_v3
{
	string	device<>;
};
/* reply the same as V2 */


/* NDMP_SCSI_CLOSE - same as V2 */

/* NDMP_SCSI_GET_STATE - same as V2 */

struct ndmp_scsi_set_target_request_v3
{
	string		device<>;
	u_short		target_controller;
	u_short		target_id;
	u_short		target_lun;
};
/* reply the same as V2 */


/* NDMP_SCSI_RESET_DEVICE - same as V2 */

/* NDMP_SCSI_RESET_BUS - same as V2 */

/* NDMP_SCSI_EXECUTE_CDB - same as V2 */


/***********************/
/* SCSI INTERFACE (V4) */
/***********************/

/* NDMP_SCSI_OPEN - same as V3 */

/* NDMP_SCSI_CLOSE - same as V3 */

/* NDMP_SCSI_GET_STATE - same as V3 */

/* NDMP_SCSI_RESET_DEVICE - same as V3 */

/* NDMP_SCSI_EXECUTE_CDB - same as V3 */


/***********************/
/* TAPE INTERFACE (V2) */
/***********************/

/* NDMP_TAPE_OPEN */
enum ndmp_tape_open_mode
{
	NDMP_TAPE_READ_MODE,
	NDMP_TAPE_WRITE_MODE,
	NDMP_TAPE_RAW_MODE,				/* NDMP V4 */
	NDMP_TAPE_RAW1_MODE = 0x7fffffff,		/* NDMP V3 */
	NDMP_TAPE_RAW2_MODE = NDMP_TAPE_RAW_MODE	/* NDMP V3 */
	
};

struct ndmp_tape_open_request
{
	ndmp_tape_device	device;
	ndmp_tape_open_mode	mode;
};

struct ndmp_tape_open_reply
{
	ndmp_error	error;
};

/* NDMP_TAPE_CLOSE */
/* no request arguments */
struct ndmp_tape_close_reply
{
	ndmp_error	error;
};

/* NDMP_TAPE_GET_STATE */
/* no request arguments */
const NDMP_TAPE_NOREWIND	= 0x0008;	/* non-rewind device */
const NDMP_TAPE_WR_PROT		= 0x0010;	/* write-protected */
const NDMP_TAPE_ERROR		= 0x0020;	/* media error */
const NDMP_TAPE_UNLOAD		= 0x0040;	/* tape will be unloaded when the device is closed */

struct ndmp_tape_get_state_reply
{
	ndmp_error	error;
	u_long		flags;
	u_long		file_num;
	u_long		soft_errors;
	u_long		block_size;
	u_long		blockno;
	ndmp_u_quad	total_space;
	ndmp_u_quad	space_remain;
};

enum ndmp_tape_mtio_op 
{ 
	NDMP_MTIO_FSF  = 0, 
	NDMP_MTIO_BSF  = 1, 
	NDMP_MTIO_FSR  = 2, 
	NDMP_MTIO_BSR  = 3, 
	NDMP_MTIO_REW  = 4, 
	NDMP_MTIO_EOF  = 5, 
	NDMP_MTIO_OFF  = 6, 
	NDMP_MTIO_TUR  = 7 	/* NDMP V4 */
}; 


struct ndmp_tape_mtio_request
{
	ndmp_tape_mtio_op	tape_op;
	u_long			count;
};

struct ndmp_tape_mtio_reply
{
	ndmp_error	error;
	u_long		resid_count;
};

/* NDMP_TAPE_WRITE */
struct ndmp_tape_write_request
{
	opaque	data_out<>;
};

struct ndmp_tape_write_reply
{
	ndmp_error	error;
	u_long		count;
};

/* NDMP_TAPE_READ */
struct ndmp_tape_read_request
{
	u_long	count;
};

struct ndmp_tape_read_reply
{
	ndmp_error	error;
	opaque		data_in<>;
};

/* NDMP_TAPE_EXECUTE_CDB */
typedef ndmp_execute_cdb_request	ndmp_tape_execute_cdb_request;
typedef ndmp_execute_cdb_reply		ndmp_tape_execute_cdb_reply;


/***********************/
/* TAPE INTERFACE (V3) */
/***********************/

/* NDMP_TAPE_OPEN */
struct ndmp_tape_open_request_v3
{
	string	device<>;
	ndmp_tape_open_mode	mode;
};
/* reply the same as V2 */


/* NDMP_TAPE_CLOSE - same as V2 */

/* NDMP_TAPE_GET_STATE */
/* no request arguments */
const NDMP_TAPE_STATE_NOREWIND	= 0x0008;	/* non-rewind device */
const NDMP_TAPE_STATE_WR_PROT	= 0x0010;	/* write-protected */
const NDMP_TAPE_STATE_ERROR	= 0x0020;	/* media error */
const NDMP_TAPE_STATE_UNLOAD	= 0x0040;	/* tape will be unloaded when the device is closed */

/* invalid bit */
const NDMP_TAPE_STATE_FILE_NUM_INVALID		= 0x00000001;
const NDMP_TAPE_STATE_SOFT_ERRORS_INVALID	= 0x00000002;
const NDMP_TAPE_STATE_BLOCK_SIZE_INVALID	= 0x00000004;
const NDMP_TAPE_STATE_BLOCKNO_INVALID		= 0x00000008;
const NDMP_TAPE_STATE_TOTAL_SPACE_INVALID	= 0x00000010;
const NDMP_TAPE_STATE_SPACE_REMAIN_INVALID	= 0x00000020;
const NDMP_TAPE_STATE_PARTITION_INVALID		= 0x00000040;

struct ndmp_tape_get_state_reply_v3
{
	u_long		invalid;
	ndmp_error	error;
	u_long		flags;
	u_long		file_num;
	u_long		soft_errors;
	u_long		block_size;
	u_long		blockno;
	ndmp_u_quad	total_space;
	ndmp_u_quad	space_remain;
	u_long		partition;
};

/* NDMP_TAPE_MTIO - same as V2 */

/* NDMP_TAPE_WRITE - same as V2 */

/* NDMP_TAPE_READ - same as V2 */

/* NDMP_TAPE_EXECUTE_CDB - same as V2 */


/***********************/
/* TAPE INTERFACE (V4) */
/***********************/

/* NDMP_TAPE_OPEN - same as V3 */

/* NDMP_TAPE_CLOSE - same as V3 */

struct ndmp_tape_get_state_reply_v4
{ 
	u_long       unsupported; 
	ndmp_error   error; 
	u_long       flags; 
	u_long       file_num; 
	u_long       soft_errors; 
	u_long       block_size; 
	u_long       blockno; 
	ndmp_u_quad  total_space; 
	ndmp_u_quad  space_remain; 
}; 

/* NDMP_TAPE_MTIO - same as V3 */

/* NDMP_TAPE_WRITE - same as V3 */

/* NDMP_TAPE_READ - same as V3 */

/* NDMP_TAPE_EXECUTE_CDB - same as V3 */


/************************/
/* MOVER INTERFACE (V2) */
/************************/
enum ndmp_mover_mode  
{ 
	NDMP_MOVER_MODE_READ            = 0,  
	NDMP_MOVER_MODE_WRITE           = 1,  
	NDMP_MOVER_MODE_NOACTION        = 2  	/* NDMP V4 */
};  

enum ndmp_mover_state 
{ 
	NDMP_MOVER_STATE_IDLE    = 0, 
	NDMP_MOVER_STATE_LISTEN  = 1, 
	NDMP_MOVER_STATE_ACTIVE  = 2, 
	NDMP_MOVER_STATE_PAUSED  = 3, 
	NDMP_MOVER_STATE_HALTED  = 4 
}; 

enum ndmp_mover_pause_reason 
{ 
	NDMP_MOVER_PAUSE_NA    = 0, 
	NDMP_MOVER_PAUSE_EOM   = 1, 
	NDMP_MOVER_PAUSE_EOF   = 2, 
	NDMP_MOVER_PAUSE_SEEK  = 3, 
	NDMP_MOVER_PAUSE_MEDIA_ERROR = 4, 	/* NDMP V2,3 */
	NDMP_MOVER_PAUSE_EOW  = 5 
}; 

enum ndmp_mover_halt_reason 
{ 
	NDMP_MOVER_HALT_NA             = 0, 
	NDMP_MOVER_HALT_CONNECT_CLOSED = 1, 
	NDMP_MOVER_HALT_ABORTED        = 2, 
	NDMP_MOVER_HALT_INTERNAL_ERROR = 3, 
	NDMP_MOVER_HALT_CONNECT_ERROR  = 4, 
	NDMP_MOVER_HALT_MEDIA_ERROR    = 5 	/* NDMP V4 */
}; 


/* NDMP_MOVER_GET_STATE */

/* no request arguments */
struct ndmp_mover_get_state_reply
{
	ndmp_error		error;
	ndmp_mover_state	state;
	ndmp_mover_pause_reason	pause_reason;
	ndmp_mover_halt_reason	halt_reason;
	u_long			record_size;
	u_long			record_num;
	ndmp_u_quad		data_written;
	ndmp_u_quad		seek_position;
	ndmp_u_quad		bytes_left_to_read;
	ndmp_u_quad		window_offset;
	ndmp_u_quad		window_length;
};

/* NDMP_MOVER_LISTEN */

struct ndmp_tcp_addr
{
	u_long	ip_addr;
	u_short	port;
};

union ndmp_mover_addr switch (ndmp_addr_type addr_type)
{
	case NDMP_ADDR_LOCAL:
		void;
	case NDMP_ADDR_TCP:
	  ndmp_tcp_addr	addr;
};

struct ndmp_mover_listen_request
{
	ndmp_mover_mode		mode;
	ndmp_addr_type		addr_type;
};

struct ndmp_mover_listen_reply
{
	ndmp_error		error;
	ndmp_mover_addr		mover;
};

/* NDMP_MOVER_SET_RECORD_SIZE */
struct ndmp_mover_set_record_size_request
{
	u_long	len;
};

struct ndmp_mover_set_record_size_reply
{
	ndmp_error	error;
};

/* NDMP_MOVER_SET_WINDOW */
struct ndmp_mover_set_window_request
{
	ndmp_u_quad	offset;
	ndmp_u_quad	length;
};

struct ndmp_mover_set_window_reply
{
	ndmp_error	error;
};

/* NDMP_MOVER_CONTINUE */
/* no request arguments */

struct ndmp_mover_continue_reply
{
	ndmp_error	error;
};


/* NDMP_MOVER_ABORT */
/* no request arguments */
struct ndmp_mover_abort_reply
{
	ndmp_error	error;
};

/* NDMP_MOVER_STOP */
/* no request arguments */

struct ndmp_mover_stop_reply
{
	ndmp_error	error;
};

/* NDMP_MOVER_READ */
struct ndmp_mover_read_request
{
	ndmp_u_quad	offset;
	ndmp_u_quad	length;
};

struct ndmp_mover_read_reply
{
	ndmp_error	error;
};

/* NDMP_MOVER_CLOSE */
/* no request arguments */

struct ndmp_mover_close_reply
{
	ndmp_error	error;
};


/************************/
/* MOVER INTERFACE (V3) */
/************************/

/* NDMP_MOVER_STATE - same as V2 */

/* NDMP_MOVER_PAUSE_REASON - same as V2 */

/* NDMP_MOVER_HALT_REASON - same as V2 */

/* NDMP_MOVER_MODE - same as V2 */

struct ndmp_fc_addr_v3
{
	u_long	loop_id;
};

struct ndmp_ipc_addr_v3
{
	opaque comm_data<>;
};

union ndmp_addr_v3 switch (ndmp_addr_type addr_type)
{
	case NDMP_ADDR_LOCAL:
		void;
	case NDMP_ADDR_TCP:
		ndmp_tcp_addr		tcp_addr;
	case NDMP_ADDR_FC:
		ndmp_fc_addr_v3		fc_addr;
	case NDMP_ADDR_IPC:
		ndmp_ipc_addr_v3	ipc_addr;
	
};

%
%
%/*
% * Macros to access the port and IP address of TCP addresses.
% */
%#ifndef tcp_ip_v3
%#define tcp_ip_v3	ndmp_addr_v3_u.tcp_addr.ip_addr
%#endif /* tcp_ip_v3 */
%#ifndef tcp_port_v3
%#define tcp_port_v3	ndmp_addr_v3_u.tcp_addr.port
%#endif /* tcp_port_v3 */

/* NDMP_MOVER_GET_STATE */
/* no request arguments */

struct ndmp_mover_get_state_reply_v3
{
	ndmp_error		error;
	ndmp_mover_state	state;
	ndmp_mover_pause_reason	pause_reason;
	ndmp_mover_halt_reason	halt_reason;
	u_long			record_size;
	u_long			record_num;
	ndmp_u_quad		data_written;
	ndmp_u_quad		seek_position;
	ndmp_u_quad		bytes_left_to_read;
	ndmp_u_quad		window_offset;
	ndmp_u_quad		window_length;
	ndmp_addr_v3		data_connection_addr;
};

/* NDMP_MOVER_LISTEN - same as v2 */

struct ndmp_mover_listen_reply_v3
{
	ndmp_error	error;
	ndmp_addr_v3	data_connection_addr;
};

/* NDMP_MOVER_CONNECT */
struct ndmp_mover_connect_request_v3
{
	ndmp_mover_mode		mode;
	ndmp_addr_v3		addr;
};

struct ndmp_mover_connect_reply_v3
{
	ndmp_error	error;
};

/* NDMP_MOVER_SET_RECORD_SIZE - same as V2 */

/* NDMP_MOVER_SET_WINDOW - same as V2 */

/* NDMP_MOVER_CONTINUE - same as V2 */

/* NDMP_MOVER_ABORT - same as V2 */

/* NDMP_MOVER_STOP - same as V2 */

/* NDMP_MOVER_READ - same as V2 */

/* NDMP_MOVER_CLOSE - same as V2 */


/************************/
/* MOVER INTERFACE (V4) */
/************************/

/* NDMP_MOVER_SET_RECORD_SIZE - same as V3 */

/* NDMP_MOVER_SET_WINDOW_SIZE - same as V3 */

%
%
%/*
% * Macros to access the port and IP address of TCP addresses.
% */
%#ifndef tcp_addr_v4
%#define tcp_addr_v4	ndmp_addr_v4_u.tcp_addr.tcp_addr_val
%#endif /* tcp_addr_v4 */
%#ifndef tcp_ip_v4
%#define tcp_ip_v4(n)	ndmp_addr_v4_u.tcp_addr.tcp_addr_val[n].ip_addr
%#endif /* tcp_ip_v4 */
%#ifndef tcp_port_v4
%#define tcp_port_v4(n)	ndmp_addr_v4_u.tcp_addr.tcp_addr_val[n].port
%#endif /* tcp_port_v4 */
%#ifndef tcp_len_v4
%#define tcp_len_v4	ndmp_addr_v4_u.tcp_addr.tcp_addr_len
%#endif /* tcp_len_v4 */
%#ifndef tcp_env_v4
%#define tcp_env_v4(n)	ndmp_addr_v4_u.tcp_addr.tcp_addr_val[n].addr_env
%#endif /* tcp_env_v4 */

struct ndmp_tcp_addr_v4
{ 
	u_long       ip_addr; 
	u_short      port; 
	ndmp_pval    addr_env<>; 
}; 

union ndmp_addr_v4
switch (ndmp_addr_type addr_type)  
{ 
	case NDMP_ADDR_LOCAL: 
		void; 
	case NDMP_ADDR_TCP: 
		ndmp_tcp_addr_v4  tcp_addr<>; 
	case NDMP_ADDR_IPC: 
		ndmp_ipc_addr_v3  ipc_addr; 
};  

struct ndmp_mover_connect_request_v4
{ 
	ndmp_mover_mode       mode; 
	ndmp_addr_v4          addr; 
}; 

struct ndmp_mover_listen_reply_v4
{ 
	ndmp_error           error; 
	ndmp_addr_v4         connect_addr; 
}; 

/* NDMP_MOVER_READ - same as v3 */

struct ndmp_mover_get_state_reply_v4
{  
	ndmp_error               error;  
	ndmp_mover_mode          mode;  
	ndmp_mover_state         state;  
	ndmp_mover_pause_reason  pause_reason;  
	ndmp_mover_halt_reason   halt_reason;  
	u_long                   record_size;  
	u_long                   record_num;  
	ndmp_u_quad              bytes_moved;  
	ndmp_u_quad              seek_position;  
	ndmp_u_quad              bytes_left_to_read;  
	ndmp_u_quad              window_offset;  
	ndmp_u_quad              window_length;  
	ndmp_addr_v4             data_connection_addr;  
};  

/* NDMP_MOVER_CONTINUE - same as V3 */

/* NDMP_MOVER_CLOSE - same as V3 */

/* NDMP_MOVER_ABORT - same as V3 */

/* NDMP_MOVER_STOP - same as V3 */


/***********************/
/* DATA INTERFACE (V2) */
/***********************/

/* NDMP_DATA_GET_STATE */
/* no request arguments */

enum ndmp_data_operation  
{  
	NDMP_DATA_OP_NOACTION           = 0,  
	NDMP_DATA_OP_BACKUP             = 1,  
	NDMP_DATA_OP_RECOVER            = 2,  
	NDMP_DATA_OP_RECOVER_FILEHIST   = 3  	/* NDMP V4 */
}; 

enum ndmp_data_state  
{ 
	NDMP_DATA_STATE_IDLE      = 0, 
	NDMP_DATA_STATE_ACTIVE    = 1, 
	NDMP_DATA_STATE_HALTED    = 2, 
	NDMP_DATA_STATE_LISTEN    = 3, 		/* NDMP V3 */
	NDMP_DATA_STATE_CONNECTED = 4 		/* NDMP V3 */
};  

enum ndmp_data_halt_reason  
{ 
	NDMP_DATA_HALT_NA             = 0, 
	NDMP_DATA_HALT_SUCCESSFUL     = 1, 
	NDMP_DATA_HALT_ABORTED        = 2, 
	NDMP_DATA_HALT_INTERNAL_ERROR = 3, 
	NDMP_DATA_HALT_CONNECT_ERROR  = 4 
}; 

struct ndmp_data_get_state_reply
{
	ndmp_error		error;
	ndmp_data_operation	operation;
	ndmp_data_state		state;
	ndmp_data_halt_reason	halt_reason;
	ndmp_u_quad		bytes_processed;
	ndmp_u_quad		est_bytes_remain;
	u_long			est_time_remain;
	ndmp_mover_addr		mover;
	ndmp_u_quad		read_offset;
	ndmp_u_quad		read_length;
};

/* NDMP_DATA_START_BACKUP */

struct ndmp_data_start_backup_request
{
	ndmp_mover_addr		mover;		/* mover to receive data */
	string			bu_type<>;	/* backup method to use */
	ndmp_pval		env<>;		/* Parameters that may modify backup */
};

struct ndmp_data_start_backup_reply
{
	ndmp_error	error;
};

/* NDMP_DATA_START_RECOVER */
struct ndmp_name
{
	string		name<>;
	string		dest<>;
	u_short		ssid;
	ndmp_u_quad	fh_info;
};

struct ndmp_data_start_recover_request
{
	ndmp_mover_addr		mover;
	ndmp_pval		env<>;
	ndmp_name		nlist<>;
	string			bu_type<>;

};

struct ndmp_data_start_recover_reply
{
	ndmp_error	error;
};

/* NDMP_DATA_ABORT */
/* no request arguments */

struct ndmp_data_abort_reply
{
	ndmp_error	error;
};

/* NDMP_DATA_STOP */
/* no request arguments */

struct ndmp_data_stop_reply
{
	ndmp_error	error;
};

/* NDMP_DATA_GET_ENV */
/* no request arguments */

struct ndmp_data_get_env_reply
{
	ndmp_error	error;
	ndmp_pval	env<>;
};
/* no reply arguments */

struct ndmp_notify_data_halted_request
{
	ndmp_data_halt_reason		reason;
	string				text_reason<>;
};
/* no reply arguments */


/***********************/
/* DATA INTERFACE (V3) */
/***********************/

/* NDMP_DATA_GET_STATE */
/* no request arguments */
/* ndmp_data_operation the same as V2 */

/* invalid bit */
const NDMP_DATA_STATE_EST_BYTES_REMAIN_INVALID	= 0x00000001;
const NDMP_DATA_STATE_EST_TIME_REMAIN_INVALID	= 0x00000002;

struct ndmp_data_get_state_reply_v3
{
	u_long			invalid;
	ndmp_error		error;
	ndmp_data_operation	operation;
	ndmp_data_state		state;
	ndmp_data_halt_reason	halt_reason;
	ndmp_u_quad		bytes_processed;
	ndmp_u_quad		est_bytes_remain;
	u_long			est_time_remain;
	ndmp_addr_v3		data_connection_addr;
	ndmp_u_quad		read_offset;
	ndmp_u_quad		read_length;
};

/* NDMP_DATA_START_BACKUP */
struct ndmp_data_start_backup_request_v3
{
	string		bu_type<>;	/* backup method to use */
	ndmp_pval	env<>;		/* Parameters that may modify backup */
};

/* NDMP_DATA_START_RECOVER */
struct ndmp_name_v3
{
	string		original_path<>;
	string		destination_dir<>;
	string		new_name<>;	/* Direct access restore only */
	string		other_name<>;	/* Direct access restore only */
	ndmp_u_quad	node;		/* Direct access restore only */
	ndmp_u_quad	fh_info;	/* Direct access restore only */
};

struct ndmp_data_start_recover_request_v3
{
	ndmp_pval	env<>;
	ndmp_name_v3	nlist<>;
	string		bu_type<>;
};

/* NDMP_DATA_ABORT - same as V2 */

/* NDMP_DATA_STOP - same as V2 */

/* NDMP_DATA_GET_ENV - same as V2 */

/* NDMP_DATA_LISTEN */
struct ndmp_data_listen_request_v3
{
	ndmp_addr_type	addr_type;
};

struct ndmp_data_listen_reply_v3
{
	ndmp_error	error;
	ndmp_addr_v3	data_connection_addr;
};

/* NDMP_DATA_CONNECT */
struct ndmp_data_connect_request_v3
{
	ndmp_addr_v3	addr;
};

struct ndmp_data_connect_reply_v3
{
	ndmp_error	error;
};


/***********************/
/* DATA INTERFACE (V4) */
/***********************/

struct ndmp_data_get_state_reply_v4
{ 
	u_long                    unsupported; 
	ndmp_error                error; 
	ndmp_data_operation       operation; 
	ndmp_data_state           state; 
	ndmp_data_halt_reason     halt_reason; 
	ndmp_u_quad               bytes_processed; 
	ndmp_u_quad               est_bytes_remain; 
	u_long                    est_time_remain; 
	ndmp_addr_v4              data_connection_addr; 
	ndmp_u_quad               read_offset; 
	ndmp_u_quad               read_length; 
}; 

struct ndmp_data_listen_reply_v4
{ 
	ndmp_error   error; 
	ndmp_addr_v4    connect_addr; 
}; 

struct ndmp_data_connect_request_v4
{ 
	ndmp_addr_v4   addr; 
};  


/* NDMP_DATA_START_BACKUP - same as V3 */

/* NDMP_DATA_START_RECOVER - same as V3 */

/* NDMP_DATA_ABORT - same as V3 */

/* NDMP_DATA_STOP - same as V3 */

/* NDMP_DATA_GET_ENV - same as V3 */


/*************************/
/* NOTIFY INTERFACE (V2) */
/*************************/

/* NDMP_NOTIFY_CONNECTED */
enum ndmp_connect_reason
{
	NDMP_CONNECTED,		/* Connect successfully */
	NDMP_SHUTDOWN,		/* Connection shutdown */
	NDMP_REFUSED		/* reach the maximum number of connections */
};

struct ndmp_notify_connected_request
{
	ndmp_connect_reason	reason;
	u_short			protocol_version;
	string			text_reason<>;
};

/* NDMP_NOTIFY_MOVER_PAUSED */
struct ndmp_notify_mover_paused_request
{
	ndmp_mover_pause_reason	reason;
	ndmp_u_quad		seek_position;
};
/* no reply arguments */

/* NDMP_NOTIFY_MOVER_HALTED */
struct ndmp_notify_mover_halted_request
{
	ndmp_mover_halt_reason	reason;
	string			text_reason<>;
};
/* no reply arguments */

/* NDMP_NOTIFY_DATA_READ */
struct ndmp_notify_data_read_request
{
	ndmp_u_quad	offset;
	ndmp_u_quad	length;
};
/* no reply arguments */


/*************************/
/* NOTIFY INTERFACE (V3) */
/*************************/

/* NDMP_NOTIFY_DATA_HALTED - same as V2 */

/* NDMP_NOTIFY_CONNECTED - same as V2 */

/* NDMP_NOTIFY_MOVER_PAUSED - same as V2 */

/* NDMP_NOTIFY_MOVER_HALTED - same as V2 */

/* NDMP_NOTIFY_DATA_READ - same as V2 */


/*************************/
/* NOTIFY INTERFACE (V4) */
/*************************/

struct ndmp_notify_data_halted_request_v4
{ 
	ndmp_data_halt_reason   reason; 
}; 

/* NDMP_NOTIFY_CONNECTION_STATUS - same as V3 */

struct ndmp_notify_mover_halted_request_v4
{ 
	ndmp_mover_halt_reason      reason; 
}; 

/* NDMP_NOTIFY_MOVER_PAUSED - same as V3 */

/* NDMP_NOTIFY_DATA_READ - same as V3 */


/**********************/
/* LOG INTERFACE (V2) */
/**********************/

/* NDMP_LOG_LOG */
struct ndmp_log_log_request
{
	string	entry<>;
};
/* no reply arguments */

/* NDMP_LOG_DEBUG */
enum ndmp_debug_level
{
	NDMP_DBG_USER_INFO,
	NDMP_DBG_USER_SUMMARY,
	NDMP_DBG_USER_DETAIL,
	NDMP_DBG_DIAG_INFO,
	NDMP_DBG_DIAG_SUMMARY,
	NDMP_DBG_DIAG_DETAIL,
	NDMP_DBG_PROG_INFO,
	NDMP_DBG_PROG_SUMMARY,
	NDMP_DBG_PROG_DETAIL
};

struct ndmp_log_debug_request
{
	ndmp_debug_level	level;
	string			message<>;
};
/* no reply arguments */

/* NDMP_LOG_FILE */
struct ndmp_log_file_request
{
	string		name<>;
	u_short		ssid;
	ndmp_error	error;
};
/* no reply arguments */


/**********************/
/* LOG INTERFACE (V3) */
/**********************/

/* NDMP_LOG_MESSAGE */
enum ndmp_log_type 
{ 
	NDMP_LOG_NORMAL  = 0, 
	NDMP_LOG_DEBUG   = 1, 
	NDMP_LOG_ERROR   = 2, 
	NDMP_LOG_WARNING = 3 
}; 

struct ndmp_log_message_request_v3
{
	ndmp_log_type		log_type;
	u_long			message_id;
	string			entry<>;
};
/* no reply arguments */

/* NDMP_LOG_FILE */
struct ndmp_log_file_request_v3
{
	string		name<>;
	ndmp_error	error;
};
/* no reply arguments */


/**********************/
/* LOG INTERFACE (V4) */
/**********************/

enum ndmp_has_associated_message 
{ 
	NDMP_NO_ASSOCIATED_MESSAGE     = 0, 
	NDMP_HAS_ASSOCIATED_MESSAGE    = 1 
}; 

enum ndmp_recovery_status 
{ 
	NDMP_RECOVERY_SUCCESSFUL                 = 0,    
	NDMP_RECOVERY_FAILED_PERMISSION          = 1, 
	NDMP_RECOVERY_FAILED_NOT_FOUND           = 2, 
	NDMP_RECOVERY_FAILED_NO_DIRECTORY        = 3, 
	NDMP_RECOVERY_FAILED_OUT_OF_MEMORY       = 4, 
	NDMP_RECOVERY_FAILED_IO_ERROR            = 5, 
	NDMP_RECOVERY_FAILED_UNDEFINED_ERROR     = 6, 
	NDMP_RECOVERY_FAILED_FILE_PATH_EXISTS    = 7 
}; 

struct ndmp_log_message_request_v4
{ 
	ndmp_log_type      log_type; 
	u_long             message_id; 
	string             entry<>; 
	ndmp_has_associated_message associated_message_valid; 
	u_long             associated_message_sequence; 
}; 

struct ndmp_log_file_request_v4
{ 
	string                   name<>; 
	ndmp_recovery_status     recovery_status; 
}; 



/*******************************/
/* FILE HISTORY INTERFACE (V2) */
/*******************************/

/* NDMP_FH_ADD_UNIX_PATH */
typedef string ndmp_unix_path<>;
enum ndmp_file_type 
{ 
	NDMP_FILE_DIR      = 0, 
	NDMP_FILE_FIFO     = 1, 
	NDMP_FILE_CSPEC    = 2, 
	NDMP_FILE_BSPEC    = 3, 
	NDMP_FILE_REG      = 4, 
	NDMP_FILE_SLINK    = 5, 
	NDMP_FILE_SOCK     = 6, 
	NDMP_FILE_REGISTRY = 7, 
	NDMP_FILE_OTHER    = 8 
}; 

struct ndmp_unix_file_stat
{
	ndmp_file_type	ftype;
	u_long			mtime;
	u_long			atime;
	u_long			ctime;
	u_long			uid;
	u_long			gid;
	u_long			mode;
	ndmp_u_quad		size;
	ndmp_u_quad		fh_info;
};

struct ndmp_fh_unix_path
{
	ndmp_unix_path		name;
	ndmp_unix_file_stat	fstat;
};

struct ndmp_fh_add_unix_path_request
{
	ndmp_fh_unix_path	paths<>;
};
/* no reply arguments */

/* NDMP_FH_ADD_UNIX_DIR */
struct ndmp_fh_unix_dir
{
	ndmp_unix_path		name;
	u_long			node;
	u_long			parent;
};

struct ndmp_fh_add_unix_dir_request
{
	ndmp_fh_unix_dir	dirs<>;
};
/* no reply arguments */

/* NDMP_FH_ADD_UNIX_NODE */
struct ndmp_fh_unix_node
{
	ndmp_unix_file_stat	fstat;
	u_long			node;
};

struct ndmp_fh_add_unix_node_request
{
	ndmp_fh_unix_node	nodes<>;
};
/* no reply arguments */


/********************************/
/* FILE HISTORY INTERFACE (V3) */
/********************************/

/* NDMP_FH_ADD_FILE */
enum ndmp_fs_type 
{ 
	NDMP_FS_UNIX   = 0, 
	NDMP_FS_NT     = 1, 
	NDMP_FS_OTHER  = 2 
}; 


typedef string ndmp_path_v3<>;
struct ndmp_nt_path_v3
{
	ndmp_path_v3	nt_path;
	ndmp_path_v3	dos_path;
};
 
union ndmp_file_name_v3 switch (ndmp_fs_type fs_type)
{
	case NDMP_FS_UNIX:
		ndmp_path_v3		unix_name;
	case NDMP_FS_NT:
		ndmp_nt_path_v3	nt_name;
	default:
		ndmp_path_v3		other_name;
};

/* invalid bit */
const NDMP_FILE_STAT_ATIME_INVALID	= 0x00000001;
const NDMP_FILE_STAT_CTIME_INVALID	= 0x00000002;
const NDMP_FILE_STAT_GROUP_INVALID	= 0x00000004;

struct ndmp_file_stat_v3
{
	u_long			invalid;
	ndmp_fs_type		fs_type;
	ndmp_file_type		ftype;
	u_long			mtime;
	u_long			atime;
	u_long			ctime;
	u_long			owner; /* uid for UNIX, owner for NT */
	u_long			group; /* gid for UNIX, NA for NT */
	u_long			fattr; /* mode for UNIX, fattr for NT */
	ndmp_u_quad		size;
	u_long			links;
};


/* one file could have both UNIX and NT name and attributes */
struct ndmp_file_v3
{
	ndmp_file_name_v3	names<>;
	ndmp_file_stat_v3	stats<>;
	ndmp_u_quad		node;		/* used for the direct access */
	ndmp_u_quad		fh_info;	/* used for the direct access */
};

struct ndmp_fh_add_file_request_v3
{
	ndmp_file_v3		files<>;
};
/* no reply arguments */

/* NDMP_FH_ADD_DIR */

struct ndmp_dir_v3
{
	ndmp_file_name_v3	names<>;
	ndmp_u_quad		node;
	ndmp_u_quad		parent;
};
 
struct ndmp_fh_add_dir_request_v3
{
	ndmp_dir_v3	dirs<>;
};
/* no reply arguments */
 
/* NDMP_FH_ADD_NODE */

struct ndmp_node_v3
{
	ndmp_file_stat_v3	stats<>;
	ndmp_u_quad		node;
	ndmp_u_quad		fh_info;
};
 
struct ndmp_fh_add_node_request_v3
{
	ndmp_node_v3	nodes<>;
};
/* no reply arguments */


/********************************/
/* FILE HISTORY INTERFACE (V4) */
/********************************/

/* NDMP_FH_ADD_FILE - same as V3 */

/* NDMP_FH_ADD_DIR - same as V3 */

/* NDMP_FH_ADD_NODE - same as V3 */



/********************************/
/* NDMP requests		*/
/********************************/
/* CONNECT */
typedef ndmp_auth_text ndmp_auth_text_v2;
typedef ndmp_auth_text_v3 ndmp_auth_text_v4;
typedef ndmp_auth_md5 ndmp_auth_md5_v2;
typedef ndmp_auth_md5_v3 ndmp_auth_md5_v4;
typedef ndmp_auth_data ndmp_auth_data_v2;
typedef ndmp_auth_data_v3 ndmp_auth_data_v4;

typedef ndmp_connect_open_request ndmp_connect_open_request_v2;
typedef ndmp_connect_open_request ndmp_connect_open_request_v3;
typedef ndmp_connect_open_request ndmp_connect_open_request_v4;
typedef ndmp_connect_open_reply ndmp_connect_open_reply_v2;
typedef ndmp_connect_open_reply ndmp_connect_open_reply_v3;
typedef ndmp_connect_open_reply ndmp_connect_open_reply_v4;
typedef ndmp_connect_client_auth_request ndmp_connect_client_auth_request_v2;
typedef ndmp_connect_client_auth_request_v3 ndmp_connect_client_auth_request_v4;
typedef ndmp_connect_client_auth_reply ndmp_connect_client_auth_reply_v2;
typedef ndmp_connect_client_auth_reply_v3 ndmp_connect_client_auth_reply_v4;
typedef ndmp_connect_server_auth_request ndmp_connect_server_auth_request_v2;
typedef ndmp_connect_server_auth_request ndmp_connect_server_auth_request_v3;
typedef ndmp_connect_server_auth_request ndmp_connect_server_auth_request_v4;
typedef ndmp_connect_server_auth_reply ndmp_connect_server_auth_reply_v2;
typedef ndmp_connect_server_auth_reply ndmp_connect_server_auth_reply_v3;
typedef ndmp_connect_server_auth_reply ndmp_connect_server_auth_reply_v4;


/* CONFIG */
typedef ndmp_config_get_host_info_reply ndmp_config_get_host_info_reply_v2;
typedef ndmp_config_get_host_info_reply_v3 ndmp_config_get_host_info_reply_v4;
typedef ndmp_config_get_butype_attr_request ndmp_config_get_butype_attr_request_v2;
typedef ndmp_config_get_butype_attr_reply ndmp_config_get_butype_attr_reply_v2;
typedef ndmp_config_get_mover_type_reply ndmp_config_get_mover_type_reply_v2;
typedef ndmp_config_get_auth_attr_request ndmp_config_get_auth_attr_request_v2;
typedef ndmp_config_get_auth_attr_request ndmp_config_get_auth_attr_request_v3;
typedef ndmp_config_get_auth_attr_request ndmp_config_get_auth_attr_request_v4;
typedef ndmp_config_get_auth_attr_reply ndmp_config_get_auth_attr_reply_v2;
typedef ndmp_config_get_auth_attr_reply ndmp_config_get_auth_attr_reply_v3;
typedef ndmp_config_get_auth_attr_reply ndmp_config_get_auth_attr_reply_v4;
typedef ndmp_config_get_connection_type_reply_v3 ndmp_config_get_connection_type_reply_v4;
typedef ndmp_config_get_server_info_reply_v3 ndmp_config_get_server_info_reply_v4;
typedef ndmp_fs_info_v3 ndmp_fs_info_v4;
typedef ndmp_config_get_fs_info_reply_v3 ndmp_config_get_fs_info_reply_v4;
typedef ndmp_device_info_v3 ndmp_device_info_v4;
typedef ndmp_config_get_tape_info_reply_v3  ndmp_config_get_tape_info_reply_v4;
typedef ndmp_config_get_scsi_info_reply_v3 ndmp_config_get_scsi_info_reply_v4;
typedef ndmp_config_get_ext_list_reply ndmp_config_get_ext_list_reply_v4;
typedef ndmp_config_set_ext_list_request ndmp_config_set_ext_list_request_v4;
typedef ndmp_config_set_ext_list_reply ndmp_config_set_ext_list_reply_v4;


/* SCSI */
typedef ndmp_scsi_open_request ndmp_scsi_open_request_v2;
typedef ndmp_scsi_open_request_v3 ndmp_scsi_open_request_v4;
typedef ndmp_scsi_open_reply ndmp_scsi_open_reply_v2;
typedef ndmp_scsi_open_reply ndmp_scsi_open_reply_v3;
typedef ndmp_scsi_open_reply ndmp_scsi_open_reply_v4;
typedef ndmp_scsi_close_reply ndmp_scsi_close_reply_v2;
typedef ndmp_scsi_close_reply ndmp_scsi_close_reply_v3;
typedef ndmp_scsi_close_reply ndmp_scsi_close_reply_v4;
typedef ndmp_scsi_get_state_reply ndmp_scsi_get_state_reply_v2;
typedef ndmp_scsi_get_state_reply ndmp_scsi_get_state_reply_v3;
typedef ndmp_scsi_get_state_reply ndmp_scsi_get_state_reply_v4;
typedef ndmp_scsi_set_target_request ndmp_scsi_set_target_request_v2;
typedef ndmp_scsi_set_target_reply ndmp_scsi_set_target_reply_v2;
typedef ndmp_scsi_set_target_reply ndmp_scsi_set_target_reply_v3;
typedef ndmp_scsi_reset_device_reply ndmp_scsi_reset_device_reply_v2;
typedef ndmp_scsi_reset_device_reply ndmp_scsi_reset_device_reply_v3;
typedef ndmp_scsi_reset_device_reply ndmp_scsi_reset_device_reply_v4;
typedef ndmp_scsi_reset_bus_reply ndmp_scsi_reset_bus_reply_v2;
typedef ndmp_scsi_reset_bus_reply ndmp_scsi_reset_bus_reply_v3;
typedef ndmp_execute_cdb_request ndmp_scsi_execute_cdb_request_v2;
typedef ndmp_execute_cdb_request ndmp_scsi_execute_cdb_request_v3;
typedef ndmp_execute_cdb_request ndmp_scsi_execute_cdb_request_v4;
typedef ndmp_execute_cdb_reply ndmp_scsi_execute_cdb_reply_v2;
typedef ndmp_execute_cdb_reply ndmp_scsi_execute_cdb_reply_v3;
typedef ndmp_execute_cdb_reply ndmp_scsi_execute_cdb_reply_v4;


/* TAPE */
typedef ndmp_tape_open_request ndmp_tape_open_request_v2;
typedef ndmp_tape_open_request_v3 ndmp_tape_open_request_v4;
typedef ndmp_tape_open_reply ndmp_tape_open_reply_v2;
typedef ndmp_tape_open_reply ndmp_tape_open_reply_v3;
typedef ndmp_tape_open_reply ndmp_tape_open_reply_v4;
typedef ndmp_tape_close_reply ndmp_tape_close_reply_v2;
typedef ndmp_tape_close_reply ndmp_tape_close_reply_v3;
typedef ndmp_tape_close_reply ndmp_tape_close_reply_v4;
typedef ndmp_tape_get_state_reply ndmp_tape_get_state_reply_v2;
typedef ndmp_tape_mtio_request ndmp_tape_mtio_request_v2;
typedef ndmp_tape_mtio_request ndmp_tape_mtio_request_v3;
typedef ndmp_tape_mtio_request ndmp_tape_mtio_request_v4;
typedef ndmp_tape_mtio_reply ndmp_tape_mtio_reply_v2;
typedef ndmp_tape_mtio_reply ndmp_tape_mtio_reply_v3;
typedef ndmp_tape_mtio_reply ndmp_tape_mtio_reply_v4;
typedef ndmp_tape_write_request ndmp_tape_write_request_v2;
typedef ndmp_tape_write_request ndmp_tape_write_request_v3;
typedef ndmp_tape_write_request ndmp_tape_write_request_v4;
typedef ndmp_tape_write_reply ndmp_tape_write_reply_v2;
typedef ndmp_tape_write_reply ndmp_tape_write_reply_v3;
typedef ndmp_tape_write_reply ndmp_tape_write_reply_v4;
typedef ndmp_tape_read_request ndmp_tape_read_request_v2;
typedef ndmp_tape_read_request ndmp_tape_read_request_v3;
typedef ndmp_tape_read_request ndmp_tape_read_request_v4;
typedef ndmp_tape_read_reply ndmp_tape_read_reply_v2;
typedef ndmp_tape_read_reply ndmp_tape_read_reply_v3;
typedef ndmp_tape_read_reply ndmp_tape_read_reply_v4;
typedef ndmp_tape_execute_cdb_request ndmp_tape_execute_cdb_request_v2;
typedef ndmp_tape_execute_cdb_request ndmp_tape_execute_cdb_request_v3;
typedef ndmp_tape_execute_cdb_request ndmp_tape_execute_cdb_request_v4;
typedef ndmp_tape_execute_cdb_reply ndmp_tape_execute_cdb_reply_v2;
typedef ndmp_tape_execute_cdb_reply ndmp_tape_execute_cdb_reply_v3;
typedef ndmp_tape_execute_cdb_reply ndmp_tape_execute_cdb_reply_v4;


/* MOVER */
typedef ndmp_fc_addr_v3 ndmp_fc_addr;
typedef ndmp_ipc_addr_v3 ndmp_ipc_addr;
typedef ndmp_mover_get_state_reply ndmp_mover_get_state_reply_v2;
typedef ndmp_mover_listen_request ndmp_mover_listen_request_v2;
typedef ndmp_mover_listen_request ndmp_mover_listen_request_v3;
typedef ndmp_mover_listen_request ndmp_mover_listen_request_v4;
typedef ndmp_mover_listen_reply ndmp_mover_listen_reply_v2;
typedef ndmp_mover_set_record_size_request ndmp_mover_set_record_size_request_v2;
typedef ndmp_mover_set_record_size_request ndmp_mover_set_record_size_request_v3;
typedef ndmp_mover_set_record_size_request ndmp_mover_set_record_size_request_v4;
typedef ndmp_mover_set_record_size_reply ndmp_mover_set_record_size_reply_v2;
typedef ndmp_mover_set_record_size_reply ndmp_mover_set_record_size_reply_v3;
typedef ndmp_mover_set_record_size_reply ndmp_mover_set_record_size_reply_v4;
typedef ndmp_mover_set_window_request ndmp_mover_set_window_request_v2;
typedef ndmp_mover_set_window_request ndmp_mover_set_window_request_v3;
typedef ndmp_mover_set_window_request ndmp_mover_set_window_request_v4;
typedef ndmp_mover_set_window_reply ndmp_mover_set_window_reply_v2;
typedef ndmp_mover_set_window_reply ndmp_mover_set_window_reply_v3;
typedef ndmp_mover_set_window_reply ndmp_mover_set_window_reply_v4;
typedef ndmp_mover_continue_reply ndmp_mover_continue_reply_v2;
typedef ndmp_mover_continue_reply ndmp_mover_continue_reply_v3;
typedef ndmp_mover_continue_reply ndmp_mover_continue_reply_v4;
typedef ndmp_mover_abort_reply ndmp_mover_abort_reply_v2;
typedef ndmp_mover_abort_reply ndmp_mover_abort_reply_v3;
typedef ndmp_mover_abort_reply ndmp_mover_abort_reply_v4;
typedef ndmp_mover_stop_reply ndmp_mover_stop_reply_v2;
typedef ndmp_mover_stop_reply ndmp_mover_stop_reply_v3;
typedef ndmp_mover_stop_reply ndmp_mover_stop_reply_v4;
typedef ndmp_mover_read_request ndmp_mover_read_request_v2;
typedef ndmp_mover_read_request ndmp_mover_read_request_v3;
typedef ndmp_mover_read_request ndmp_mover_read_request_v4;
typedef ndmp_mover_read_reply ndmp_mover_read_reply_v2;
typedef ndmp_mover_read_reply ndmp_mover_read_reply_v3;
typedef ndmp_mover_read_reply ndmp_mover_read_reply_v4;
typedef ndmp_mover_close_reply ndmp_mover_close_reply_v2;
typedef ndmp_mover_close_reply ndmp_mover_close_reply_v3;
typedef ndmp_mover_close_reply ndmp_mover_close_reply_v4;
typedef ndmp_mover_connect_reply_v3 ndmp_mover_connect_reply_v4;


/* DATA */
typedef ndmp_data_get_state_reply ndmp_data_get_state_reply_v2;
typedef ndmp_data_start_backup_request ndmp_data_start_backup_request_v2;
typedef ndmp_data_start_backup_request_v3 ndmp_data_start_backup_request_v4;
typedef ndmp_data_start_backup_reply ndmp_data_start_backup_reply_v2;
typedef ndmp_data_start_backup_reply ndmp_data_start_backup_reply_v3;
typedef ndmp_data_start_backup_reply ndmp_data_start_backup_reply_v4;
typedef ndmp_name ndmp_name_v2;
typedef ndmp_data_start_recover_request ndmp_data_start_recover_request_v2;
typedef ndmp_data_start_recover_request_v3 ndmp_data_start_recover_request_v4;
typedef ndmp_data_start_recover_reply ndmp_data_start_recover_reply_v2;
typedef ndmp_data_start_recover_reply ndmp_data_start_recover_reply_v3;
typedef ndmp_data_start_recover_reply ndmp_data_start_recover_reply_v4;
typedef ndmp_data_start_recover_reply ndmp_data_start_recover_filehist_reply_v4;
typedef ndmp_data_abort_reply ndmp_data_abort_reply_v2;
typedef ndmp_data_abort_reply ndmp_data_abort_reply_v3;
typedef ndmp_data_abort_reply ndmp_data_abort_reply_v4;
typedef ndmp_data_stop_reply ndmp_data_stop_reply_v2;
typedef ndmp_data_stop_reply ndmp_data_stop_reply_v3;
typedef ndmp_data_stop_reply ndmp_data_stop_reply_v4;
typedef ndmp_data_get_env_reply ndmp_data_get_env_reply_v2;
typedef ndmp_data_get_env_reply ndmp_data_get_env_reply_v3;
typedef ndmp_data_get_env_reply ndmp_data_get_env_reply_v4;
typedef ndmp_data_listen_request_v3 ndmp_data_listen_request_v4;
typedef ndmp_data_connect_reply_v3 ndmp_data_connect_reply_v4;


/* NOTIFY */
typedef ndmp_notify_data_halted_request ndmp_notify_data_halted_request_v2;
typedef ndmp_notify_data_halted_request ndmp_notify_data_halted_request_v3;
typedef ndmp_notify_connected_request ndmp_notify_connection_status_request_v2;
typedef ndmp_notify_connected_request ndmp_notify_connection_status_request_v3;
typedef ndmp_notify_connected_request ndmp_notify_connection_status_request_v4;
typedef ndmp_notify_mover_paused_request ndmp_notify_mover_paused_request_v2;
typedef ndmp_notify_mover_paused_request ndmp_notify_mover_paused_request_v3;
typedef ndmp_notify_mover_paused_request ndmp_notify_mover_paused_request_v4;
typedef ndmp_notify_mover_halted_request ndmp_notify_mover_halted_request_v2;
typedef ndmp_notify_mover_halted_request ndmp_notify_mover_halted_request_v3;
typedef ndmp_notify_data_read_request ndmp_notify_data_read_request_v2;
typedef ndmp_notify_data_read_request ndmp_notify_data_read_request_v3;
typedef ndmp_notify_data_read_request ndmp_notify_data_read_request_v4;


/* LOG */
typedef ndmp_log_log_request ndmp_log_log_request_v2;
typedef ndmp_log_log_request ndmp_log_log_request_v3;
typedef ndmp_log_log_request ndmp_log_log_request_v4;
typedef ndmp_log_debug_request ndmp_log_debug_request_v2;
typedef ndmp_log_debug_request ndmp_log_debug_request_v3;
typedef ndmp_log_debug_request ndmp_log_debug_request_v4;
typedef ndmp_log_file_request ndmp_log_file_request_v2;


/* FILE HISTORY */
typedef ndmp_file_v3 ndmp_file;
typedef ndmp_dir_v3 ndmp_dir;
typedef ndmp_node_v3 ndmp_node;
typedef ndmp_fh_add_unix_path_request ndmp_fh_add_unix_path_request_v2;
typedef ndmp_fh_add_unix_path_request ndmp_fh_add_unix_path_request_v3;
typedef ndmp_fh_add_file_request_v3 ndmp_fh_add_file_request_v4;
typedef ndmp_fh_add_unix_dir_request ndmp_fh_add_unix_dir_request_v2;
typedef ndmp_fh_add_unix_dir_request ndmp_fh_add_unix_dir_request_v3;
typedef ndmp_fh_add_dir_request_v3 ndmp_fh_add_dir_request_v4;
typedef ndmp_fh_add_unix_node_request ndmp_fh_add_unix_node_request_v2;
typedef ndmp_fh_add_unix_node_request ndmp_fh_add_unix_node_request_v3;
typedef ndmp_fh_add_node_request_v3 ndmp_fh_add_node_request_v4;





































