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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMSERVER_H_
#define	_SMSERVER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <door.h>
#include <thread.h>
#include <synch.h>
#include <sys/dkio.h>
#include <bsm/audit.h>

#define	RQ_LEN 18
#define	MAX_RQ_LEN 32
#define	MAX_CDB_LEN 32

#define	smedia_service	"/var/run/smedia_svc"
#define	DEFAULT_SMEDIAD_DEVDIR	"/usr/lib/smedia"

#define	INIT_NOT_DONE		0
#define	INIT_DONE		1
#define	INIT_IN_PROGRESS	2

/* SCSI FORMAT UNIT cdb[1] #defines */
#define	FMTDATA			0x10
#define	CMPLIST			0x08

/* Defect list header data[1] #defines */

#define	VS			0x1
#define	IMMED			0x2
#define	DSP			0x4
#define	IP			0x8
#define	STPF			0x10
#define	DCRT			0x20
#define	DPRY			0x40
#define	FOV			0x80

#define	DEFERRED_ERROR		0x71
#define	AWRE			0x80

#define	MODE_SENSE_PARAM_HDR_LEN		4
#define	MODE_PARAM_BLOCK_LEN			8
#define	AWRE_OFFSET	(MODE_SENSE_PARAM_HDR_LEN + MODE_PARAM_BLOCK_LEN + 2)
#define	BLOCK_LEN_OFFSET			(MODE_SENSE_PARAM_HDR_LEN + 5)
#define	SKSV_FIELD				0x80
#define	SKSV_OFFSET				15
#define	FORMAT_PROGRESS_INDICATOR_OFFSET_0	16
#define	FORMAT_PROGRESS_INDICATOR_OFFSET_1	17

/* #defines for protect medode field */

#define	UNLOCK_MODE			0x0
#define	WRITE_PROTECT_MODE		0x2
#define	PASSWD_WRITE_PROTECT_MODE	0x3
#define	READ_WRITE_PROTECT_MODE		0x5
#define	TEMP_UNLOCK_MODE		0x8

/* #defines for CARTRIDGE STATUS PAGE */

#define	CARTRIDGE_STATUS_PAGE		2
#define	NON_SENSE_HDR_LEN		0x2
#define	PROTECT_MODE_OFFSET		19
#define	DISK_STATUS_OFFSET		1


/* error reporting mechanism */
void	fatal(const char *, ...);
void	info(const char *, ...);
void	warning(const char *, ...);
void	debug(uint_t, const char *, ...);
void	setlog(const char *);
void	flushlog();
void	quit(const char *, ...);
void	noise(const char *, ...);

typedef struct server_data {
	char	sd_init_state;
	mutex_t	sd_init_lock;
	cond_t	sd_init_cv;
	int	sd_door;
	int	sd_fd;
} server_data_t;

typedef	enum {
	SMEDIA_SUCCESS = 0x0,
	SMEDIA_FAILURE			/* general failure */
} smedia_errno_t;

typedef struct door_data {
	mutex_t		dd_lock;	/* lock to protect entire structure */
	mutex_t		dd_threadlock;	/* lock to protect dd_thread field */
	sigset_t	dd_newset;	/* signal set handled by the server */
	cond_t		dd_cv;		/* client_door_descriptor cv */
	cond_t		dd_cv_bind;	/* client door descriptor bind cv */
	int32_t		dd_id;		/* for future use. To store unique id */
	door_desc_t	dd_desc[2];	/* [0] : Client Door descriptor */
					/* [1] : Death Door decriptor */
	thread_t	dd_thread;	/* thread bound to the client door */
	door_cred_t	dd_cred;	/* credentials of client */
	int32_t		dd_fd;		/* device file descriptor */
	void		*dd_buf;	/* mmapped buffer of client */
	int32_t		dd_buf_len;	/* size of the mmapped buffer */
	int32_t		dd_buffd;	/* mmapped file descriptor */
	int32_t		dd_sector_size;	/* sector size of the device */
	struct stat	dd_stat;	/* stat of the dd_fd */
	struct dk_cinfo	dd_dkinfo;

	au_id_t		audit_auid;	/* auid of user writing audit record */
	uid_t		audit_uid;	/* uid of user writing audit record */
	uid_t		audit_euid;	/* euid of user writing audit record */
	gid_t		audit_gid;	/* gid of user writing audit record */
	gid_t		audit_egid;	/* euid of user writing audit record */
	pid_t		audit_pid;	/* pid of user writing audit record */
	au_tid_addr_t	audit_tid;	/* tid of user writing audit record */
	int		audit_na;	/* 0 if event is attributable */
	au_mask_t	audit_namask;	/* not attributable flags */
	au_event_t	audit_event;	/* id of event being audited */
	int 		audit_sorf;	/* success or failure of audit_event */
	char 		*audit_user;	/* text version of audit_uid */
	au_asid_t	audit_asid;	/* asid of process writing record */
	char 		*audit_path;	/* path token */
	uint32_t	audit_policy;	/* kernel audit policy */
	struct auditpinfo_addr audit_ap;
	char		audit_text[128];
	char		audit_text1[128];
} door_data_t;

/* Symbols to simplify access of door_data_t */
#define	dd_cdoor	dd_desc[0]	/* Client Door descriptor */
#define	dd_ddoor	dd_desc[1]	/* Death Door descriptor */
#define	dd_cdoor_descriptor	dd_cdoor.d_data.d_desc.d_descriptor
#define	dd_ddoor_descriptor	dd_ddoor.d_data.d_desc.d_descriptor

typedef enum {
	SMEDIA_CNUM_OPEN_FD = 0x1,
	SMEDIA_CNUM_GET_DEVICE_INFO,
	SMEDIA_CNUM_GET_MEDIUM_PROPERTY,
	SMEDIA_CNUM_GET_PROTECTION_STATUS,
	SMEDIA_CNUM_SET_PROTECTION_STATUS,
	SMEDIA_CNUM_RAW_READ,
	SMEDIA_CNUM_RAW_WRITE,
	SMEDIA_CNUM_FORMAT,
	SMEDIA_CNUM_CHECK_FORMAT_STATUS,
	SMEDIA_CNUM_EJECT,
	SMEDIA_CNUM_REASSIGN_BLOCK,
	SMEDIA_CNUM_ERROR,
	SMEDIA_CNUM_CLOSE,
	SMEDIA_CNUM_SET_SHFD,
	SMEDIA_CNUM_PING,
	SMEDIA_CNUM_USCSI_CMD
} smedia_callnumber_t;

typedef struct {
	smedia_callnumber_t	cnum;	/* service call number */
	char			buf[1];	/* buffer containing input arguments */
} smedia_req_t;

typedef struct {
	smedia_callnumber_t	cnum;	/* service call number */
	char			buf[1];	/* buffer containing the results */
} smedia_ret_t;

typedef struct smedia_reqping {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_PING */
} smedia_reqping_t;

typedef struct smedia_retping {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_PING */
} smedia_retping_t;

	/*
	 * SMEDIA open device
	 */
typedef	struct	smedia_reqopen {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_OPEN */
	int	oflag;
	int	omode;
} smedia_reqopen_t;

typedef	struct	smedia_retopen {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_OPEN */
} smedia_retopen_t;

typedef struct smedia_requscsi_cmd {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_USCSI_CMD */
	int32_t			uscsi_flags;
	short			uscsi_timeout;
	char			uscsi_cdb[MAX_CDB_LEN];
	int32_t			uscsi_buflen;
	uchar_t			uscsi_cdblen;
	uchar_t			uscsi_rqlen;
} smedia_requscsi_cmd_t;

typedef struct smedia_retuscsi_cmd {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_USCSI_CMD */
	int32_t			uscsi_retval;
	int32_t			uscsi_errno;
	short			uscsi_status;
	int32_t			uscsi_resid;
	uchar_t			uscsi_rqstatus;
	uchar_t			uscsi_rqresid;
	char			uscsi_rqbuf[MAX_RQ_LEN];
} smedia_retuscsi_cmd_t;

typedef struct	smedia_reqget_device_info {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_GET_DEVICE_INFO */
} smedia_reqget_device_info_t;

typedef struct	smedia_reqset_shfd {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_SET_SHFD */
	int32_t	fdbuf_len;
} smedia_reqset_shfd_t;

typedef struct	smedia_retget_device_info {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_GET_DEVICE_INFO */
	smdevice_info_t		smdevinfo;
	uchar_t			sm_version;
	int32_t			sm_interface_type;
	char			sm_vendor_name[32];
	char			sm_product_name[32];
	char			sm_firmware_version[32];
} smedia_retget_device_info_t;

typedef struct	smedia_reqget_medium_property {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_GET_MEDIUM_PROPERTY */
} smedia_reqget_medium_property_t;

typedef struct	smedia_retget_medium_property {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_GET_MEDIUM_PROPERTY */
	smmedium_prop_t		smprop;
} smedia_retget_medium_property_t;

typedef struct	smedia_reqget_protection_status {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_GET_PROTECTION_STATUS */
} smedia_reqget_protection_status_t;

typedef struct	smedia_retget_protection_status {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_GET_PROTECTION_STATUS */
	smwp_state_t		prot_state;
} smedia_retget_protection_status_t;

typedef struct	smedia_reqset_protection_status {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_SET_PROTECTION_STATUS */
	smwp_state_t		prot_state;
} smedia_reqset_protection_status_t;

typedef struct	smedia_retset_protection_status {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_SET_PROTECTION_STATUS */
} smedia_retset_protection_status_t;

typedef struct	smedia_reqraw_read {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_RAW_READ */
	diskaddr_t		blockno;
	int32_t			nbytes;
} smedia_reqraw_read_t;

typedef struct	smedia_retraw_read {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_RAW_READ */
	int32_t			nbytes;	/* bytes read */
	char			buf[1];	/* buffer size is nbytes long */
} smedia_retraw_read_t;

typedef struct	smedia_reqraw_write {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_RAW_WRITE */
	diskaddr_t		blockno;
	int32_t			nbytes;
	char			buf[1];	/* buffer size is nbytes long */
} smedia_reqraw_write_t;

typedef struct	smedia_retraw_write {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_RAW_WRITE */
	int32_t			nbytes;	/* bytes written */
} smedia_retraw_write_t;

typedef struct	smedia_reqformat {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_FORMAT */
	uint_t			flavor;
	uint_t			mode;
} smedia_reqformat_t;

typedef struct	smedia_retformat {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_FORMAT */
} smedia_retformat_t;

typedef struct	smedia_reqcheck_format_status {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_CHECK_FORMAT_STATUS */
} smedia_reqcheck_format_status_t;

typedef struct	smedia_retcheck_format_status {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_CHECK_FORMAT_STATUS */
	int			percent_complete;
} smedia_retcheck_format_status_t;

typedef struct smedia_reqreassign_block {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_REASSIGN_BLOCK */
	diskaddr_t		blockno;
} smedia_reqreassign_block_t;

typedef struct smedia_retreassign_block {
	smedia_callnumber_t	cnum;	/* SMEDIA_CNUM_REASSIGN_BLOCK */
} smedia_retreassign_block_t;

typedef struct	{
	smedia_callnumber_t	cnum;		/* SMEDIA_CNUM_ERROR */
	smedia_callnumber_t	in_cnum;	/* requested service number */
	smedia_errno_t		errnum;
} smedia_reterror_t;

typedef union	{
	smedia_req_t			in;		/* req arguments */
	smedia_ret_t			out;		/* out results */
	smedia_reqping_t		reqping;
	smedia_retping_t		retping;
	smedia_reqopen_t		reqopen;
	smedia_retopen_t		retopen;
	smedia_reqget_device_info_t	reqget_device_info;
	smedia_retget_device_info_t	retget_device_info;
	smedia_reqget_medium_property_t	reqget_medium_property;
	smedia_retget_medium_property_t	retget_medium_property;
	smedia_reqget_protection_status_t	reqget_protection_status;
	smedia_retget_protection_status_t	retget_protection_status;
	smedia_reqset_protection_status_t	reqset_protection_status;
	smedia_retset_protection_status_t	retset_protection_status;
	smedia_reqraw_read_t		reqraw_read;
	smedia_retraw_read_t		retraw_read;
	smedia_reqraw_write_t		reqraw_write;
	smedia_retraw_write_t		retraw_write;
	smedia_reqformat_t		reqformat;
	smedia_retformat_t		retformat;
	smedia_reqcheck_format_status_t		reqcheck_format_status;
	smedia_retcheck_format_status_t		retcheck_format_status;
	smedia_reqreassign_block_t	reqreassign_block;
	smedia_retreassign_block_t	retreassign_block;
	smedia_reterror_t		reterror;
	smedia_reqset_shfd_t			reqset_shfd;
	smedia_requscsi_cmd_t		requscsi_cmd;
	smedia_retuscsi_cmd_t		retuscsi_cmd;
} smedia_services_t;

#define	SCSI_GENERIC	1
#define	SCSI_IOMEGA	2
#define	SCSI_FLOPPY	3

/*
 * Crude algorithm for calculating format timeout.
 * 30min + 5min/100MB =>
 * 35min for 100MB ZIP
 * 42.5 min for 250MB ZIP
 * 127 min for 2GB Jaz
 * It is OK for now as this is just an upper limit by which the
 * format should complete.
 */

#define	FORMAT_TIMEOUT(n) (1800 + ((n)/682))

#define	WA_BIT	0x10	/* The word align bit for ATAPI devices */
/*
 * Non sense data length for catridge status page.
 * Should be 63, but IDE driver panics with a non-aligned
 * data transfer.
 */

#define	ND_LENGTH 64

/*
 * Vendor specific commands from Iomega
 */

#define	IOMEGA_NONSENSE_CMD 	0x6
#define	IOMEGA_CATRIDGE_PROTECT	0xC

#ifdef __cplusplus
}
#endif

#endif	/* _SMSERVER_H_ */
