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

#ifndef	_ERRORCODES_H
#define	_ERRORCODES_H




/*
 * Include any headers you depend on.
 */

#ifdef	__cplusplus
extern "C" {
#endif


/* On the sparc platform, error codes come from stgcom.h */
#ifdef __x86

/*
 * All error numbers below this base value
 * are assumed to be UNIX error codes.
 */

#define	L_BASE				L_SCSI_ERROR

/*
 * SCSI Errors
 *
 */
/* SCSI error */
#define	L_SCSI_ERROR			0x10000

/* Receive Diagnostics: Transfer length is not word aligned */
#define	L_RD_INVLD_TRNSFR_LEN		0x11002

/* No disk element found in Receive diag. page */
#define	L_RD_NO_DISK_ELEM		0x11003

/* Illegal mode sense page length */
#define	L_ILLEGAL_MODE_SENSE_PAGE	0x11004

/* Invalid number of ENV. SENSE pages */
#define	L_INVALID_NO_OF_ENVSEN_PAGES	0x11005

/* Buffer is *too* small to hold more than 8 pages */
#define	L_INVALID_BUF_LEN		0x11006

/* Scsi_vhci errors */
#define	L_SCSI_VHCI_ERROR		0x11007
#define	L_SCSI_VHCI_ALREADY_ACTIVE	0x11008
#define	L_SCSI_VHCI_NO_STANDBY		0x11009
#define	L_SCSI_VHCI_FAILOVER_NOTSUP	0x1100a
#define	L_SCSI_VHCI_FAILOVER_BUSY	0x1100b


/*
 * Error definitions
 * for Format Errors.
 */
#define	L_INVALID_PATH			0x20200

/* Failed to open a given path */
#define	L_OPEN_PATH_FAIL		0x20001

/* Invalid password length. */
#define	L_INVALID_PASSWORD_LEN		0x20002

/* Given disk physical path is not valid. */
#define	L_INVLD_PHYS_PATH_TO_DISK	0x20004

/* Invalid name id found in the physical path */
#define	L_INVLD_ID_FOUND		0x20005

/* Invalid WWN format found */
#define	L_INVLD_WWN_FORMAT		0x20006

/* No WWN found in the disk's physical path */
#define	L_NO_WWN_FOUND_IN_PATH		0x20007

/* No Loop address found in the phys path */
#define	L_NO_LOOP_ADDRS_FOUND		0x20008

/* Invalid port number found in the phys path */
#define	L_INVLD_PORT_IN_PATH		0x20009

/* Invalid LED request */
#define	L_INVALID_LED_RQST		0x20010

/* Invalid path format */
#define	L_INVALID_PATH_FORMAT		0x20011

/* failed to get the physical path */
#define	L_NO_PHYS_PATH			0x20012

/* failed to get the ses path */
#define	L_NO_SES_PATH			0x20015

/* No "/" found in the physical path */
#define	L_INVLD_PATH_NO_SLASH_FND	0x20100

/* No "@" found in the physical path */
#define	L_INVLD_PATH_NO_ATSIGN_FND	0x20101

/* Invalid slot (slot < 0 or slot > 10). */
#define	L_INVALID_SLOT			0x20102

/* No valid path to a device */
#define	L_NO_VALID_PATH			0x20103

/* No disk devices found in /dev/rdsk directory */
#define	L_NO_DISK_DEV_FOUND		0x20104

/* No tape devices found in /dev/rmt directory */
#define	L_NO_TAPE_DEV_FOUND		0x20105

/* Device's Node WWN not found in the WWN list. */
#define	L_NO_NODE_WWN_IN_WWNLIST	0x20106

/* Device's Node WWN not found in the Box list. */
#define	L_NO_NODE_WWN_IN_BOXLIST	0x20107

/* Null WWN list found. */
#define	L_NULL_WWN_LIST			0x20108

/* No devices found. */
#define	L_NO_DEVICES_FOUND		0x20109

/* function arg error in wwn_list process */
#define	L_PROC_WWN_ARG_ERROR		0x20110

/* WWN property not found */
#define	L_NO_WWN_PROP_FOUND		0x20111

/* No driver nodes found for requested driver */
#define	L_NO_DRIVER_NODES_FOUND		0x20112

/* ULP error on device(s) */
#define	L_GET_DEV_LIST_ULP_FAILURE	0x20150

/*
 * Error definitions
 * for FC Loop (FC4 devices).
 */
/* Invalid loop map found */
#define	L_INVALID_LOOP_MAP		0x20202

/* SFIOCGMAP ioctl failed */
#define	L_SFIOCGMAP_IOCTL_FAIL		0x20203

/* FCIO_GETMAP ioctl failed */
#define	L_FCIO_GETMAP_IOCTL_FAIL	0x20204

/* FCIO_LINKSTATUS ioctl failed */
#define	L_FCIO_LINKSTATUS_FAILED	0x20205

/* FCIO_GETMAP: Invalid # of entries */
#define	L_FCIOGETMAP_INVLD_LEN		0x20206

/* FCIO_FORCE_LIP ioctl failed. */
#define	L_FCIO_FORCE_LIP_FAIL		0x20207

/* Error definitions for FC devices */
/* FCIO_RESET_LINK ioctl failed */
#define	L_FCIO_RESET_LINK_FAIL		0x20208

/* FCIO_GET_FCODE_REV_FAIL ioctl failed */
#define	L_FCIO_GET_FCODE_REV_FAIL	0x20209

/* FCIO_GET_FW_REV_FAIL ioctl failed */
#define	L_FCIO_GET_FW_REV_FAIL		0x20210

/* FCIO_GET_DEV_LIST returns invalid dev. counts */
#define	L_INVALID_DEVICE_COUNT		0x20211

/* L_FCIO_GET_NUM_DEVS_FAIL ioctl failed */
#define	L_FCIO_GET_NUM_DEVS_FAIL	0x20212

/* L_FCIO_GET_DEV_LIST_FAIL ioctl failed */
#define	L_FCIO_GET_DEV_LIST_FAIL	0x20213

/* L_FCIO_GET_LINK_STATUS ioctl failed */
#define	L_FCIO_GET_LINK_STATUS_FAIL	0x20214

/* L_FCIO_LOOPBACK_INTERNAL or FCIO_CMD/FCIO_LASER_OFF ioctl failed */
#define	L_PORT_OFFLINE_FAIL		0x20215

/* Internal Loopback or laser off ioctls not supported */
#define	L_PORT_OFFLINE_UNSUPPORTED	0x20216

/* L_FCIO_NO_LOOPBACK or FCIO_CMD/FCIO_LASER_ON ioctl failed */
#define	L_PORT_ONLINE_FAIL		0x20217

/* No-Loopback or laser on ioctls not supported */
#define	L_PORT_ONLINE_UNSUPPORTED	0x20218

/* L_FCIO_GET_HOST_PARAMS ioctl failed */
#define	L_FCIO_GET_HOST_PARAMS_FAIL	0x20219

/* Loopback mode failure */
#define	L_LOOPBACK_FAILED		0x20220

/* Loopback unsupported */
#define	L_LOOPBACK_UNSUPPORTED		0x20221

/* FCIO_FORCE_LIP ioctl failed on one of the paths, say, of an MPXIO device */
#define	L_FCIO_FORCE_LIP_PARTIAL_FAIL	0x20222

/*
 * Error definitions
 * for Fabric FC driver ioctls
 */
/* FCP_TGT_INQUIRY ioctl failed */
#define	L_FCP_TGT_INQUIRY_FAIL		0x20250

/*
 * Error definitions
 * for 24-bit address handling
 */
/* Private loop address > 0xFF found */
#define	L_INVALID_PRIVATE_LOOP_ADDRESS	0x20401

/* Encountered an unexpected fibre channel topology value */
#define	L_UNEXPECTED_FC_TOPOLOGY	0x20402

/* Fabric address was not found */
#define	L_NO_FABRIC_ADDR_FOUND		0x20403

/* The FCIO_GET_TOPOLOGY ioctl failed */
#define	L_FCIO_GET_TOPOLOGY_FAIL	0x20404

/* Invalid fabric or public loop address */
#define	L_INVALID_FABRIC_ADDRESS	0x20405

/* Point to Point fibre channel topology not supported */
#define	L_PT_PT_FC_TOP_NOT_SUPPORTED	0x20406

/*
 * Error definitions for Tapestry SAN support.
 */
/* The FCIO_DEV_LOGIN ioctl failed */
#define	L_FCIO_DEV_LOGIN_FAIL		0x20407

/* The FCIO_DEV_LOGOUT ioctl failed */
#define	L_FCIO_DEV_LOGOUT_FAIL		0x20408

/* Operation not supported on connected topology */
#define	L_OPNOSUPP_ON_TOPOLOGY		0x20409

/* Operation not supported on the path */
#define	L_INVALID_PATH_TYPE		0x20410

/* FCIO_GET_STATE ioctl failed */
#define	L_FCIO_GET_STATE_FAIL		0x20411

/* input WWN not found in dev list */
#define	L_WWN_NOT_FOUND_IN_DEV_LIST	0x20412

/*
 * Error definitions for
 * g_dev_map_init related routines.
 */
/* input addr invalid */
#define	L_INVALID_MAP_DEV_ADDR		0x20430

/* input property invalid */
#define	L_INVALID_MAP_DEV_PROP_NAME	0x20431

/* input property invalid */
#define	L_INVALID_MAP_DEV_PROP_TYPE	0x20432

/* input property name invalid */
#define	L_INVALID_MAP_DEV_PROP		0x20433

/* device not found */
#define	L_NO_SUCH_DEV_FOUND		0x20434

/* prop not found */
#define	L_NO_SUCH_PROP_FOUND		0x20435

/* invalid arg found */
#define	L_INVALID_ARG			0x20436

/*
 * Error definitions
 * for Downloading IB FW.
 */
/* Invalid download file checksum */
#define	L_DWNLD_CHKSUM_FAILED		0x20301

/* Unable to read download exec header */
#define	L_DWNLD_READ_HEADER_FAIL	0x20302

/* Number of bytes read from download file is not correct */
#define	L_DWNLD_READ_INCORRECT_BYTES	0x20303

/* Wrong text segment size */
#define	L_DWNLD_INVALID_TEXT_SIZE	0x20304

/* Error reading the download file */
#define	L_DWNLD_READ_ERROR		0x20305

/* Bad firmware magic found in the download file */
#define	L_DWNLD_BAD_FRMWARE		0x20306

/* Timeout message for the IB to be available */
#define	L_DWNLD_TIMED_OUT		0x20307

/* Error with Rec Diag page 1 */
#define	L_REC_DIAG_PG1			0x20600

/* Invalid transfer Length */
#define	L_TRANSFER_LEN			0x20601

/* A firmware file must be specified on the command line */
#define	L_REQUIRE_FILE			0x20602


/*
 * Error definitions
 * for System Errors
 */
#define	L_MALLOC_FAILED			0x30000

#define	L_MEMCPY_FAILED			0x30001

/* Cannot get status for the given path */
#define	L_LSTAT_ERROR			0x30020

/* Error reading the symbolic link */
#define	L_SYMLINK_ERROR			0x30021

/* Could not convert std. time to hrs/min/sec */
#define	L_LOCALTIME_ERROR		0x30022

/* select() system call failed to wait for specified time */
#define	L_SELECT_ERROR			0x30023

/* uname() system call failed to get the system info. */
#define	L_UNAME_FAILED			0x30024

/* Cannot get status for the given path */
#define	L_FSTAT_ERROR			0x30025

/* Cannot get status for the given path */
#define	L_STAT_ERROR			0x30026

/* di_init() failed to return snapshot of device tree */
#define	L_DEV_SNAPSHOT_FAILED		0x30027

/* di_drv_first_node() failed to find a valid driver */
#define	L_PORT_DRIVER_NOT_FOUND		0x30029

/* failed to find any device paths */
#define	L_PHYS_PATH_NOT_FOUND		0x30030

/* No device identifier found  */
#define	L_NO_DEVID			0x30031

/* Driver not supported */
#define	L_DRIVER_NOTSUPP		0x30032

/* di_prom_init failure */
#define	L_PROM_INIT_FAILED		0x30033

/*
 * Error definitions
 * for individual
 * devices.
 */
/* Device busy */
#define	L_DEV_BUSY			0x40000

/* Disk reserved */
#define	L_DEVICE_RESERVED		0x40001

/* One or more disks in enclosure are reserved */
#define	L_DISKS_RESERVED		0x40002

/* Exclusive open to a device failed. May be busy */
#define	L_EXCL_OPEN_FAILED		0x40003

/* Empty slot: Device not installed */
#define	L_SLOT_EMPTY			0x40100


/*
 * Error definitions
 * for Devctl functions.
 */
/* Devctl acquire fails */
#define	L_ACQUIRE_FAIL			0x40200


/* Power off fails. Device may be busy */
#define	L_POWER_OFF_FAIL_BUSY		0x40300


/*
 * Error definitions
 * specific to Enclosure.
 */
/* Failed to change the enclosure name */
#define	L_ENCL_NAME_CHANGE_FAIL		0x40400

/* Duplicate enclosure names found */
#define	L_DUPLICATE_ENCLOSURES		0x40401

/* Invalid no. of dsks in SENA enclosure */
#define	L_INVALID_NUM_DISKS_ENCL	0x40402

/* Path is not to a SENA ecnlosure. */
#define	L_ENCL_INVALID_PATH		0x40403

/* Cannot get the box list */
#define	L_NO_ENCL_LIST_FOUND		0x40404


/*
 * Error definitions
 * specific to IB.
 */
/* No element returned from the enclosure */
#define	L_IB_NO_ELEM_FOUND		0x40500

/* Invalid page code found in Receive Diag. page.   */
#define	L_RD_PG_INVLD_CODE		0x40501

/* Reading Receive Diag. page failed: small buffer. */
#define	L_RD_PG_MIN_BUFF		0x40502

/* Get status failed    */
#define	L_GET_STATUS_FAILED		0x40600

/* Warning define. */
#define	L_WARNING			0x90000

/* Persistant Rservation: Invalid transfer length */
#define	L_PR_INVLD_TRNSFR_LEN		0x10001

/*
 * Error definitions
 * for Format Errors.
 */
/* box name conflicts with the SSA name */
#define	L_SSA_CONFLICT			0x20013


/*
 * Error definitions
 * for System Errors
 */
/* drvconfig fail */
#define	L_DRVCONFIG_ERROR		0x31001

/* disks program failed */
#define	L_DISKS_ERROR			0x31002

/* devlinks program failed */
#define	L_DEVLINKS_ERROR		0x31003

/* fail to read /dev/rdsk directory. */
#define	L_READ_DEV_DIR_ERROR		0x31004

/* Failed to open /dev/es/ directory. */
#define	L_OPEN_ES_DIR_FAILED		0x31005

/* fail to get status from /dev/es directory. */
#define	L_LSTAT_ES_DIR_ERROR		0x31006

/* disks program failed */
#define	L_TAPES_ERROR			0x31007

/* fail to get status from /dev/rmt/directory. */
#define	L_STAT_RMT_DIR_ERROR		0x31008

/* fail to get status from /dev/rmt/directory. */
#define	L_STAT_DEV_DIR_ERROR		0x31009


/*
 * Error definitions
 * specific to Back plane.
 */
/* Backplane: Busy or reserved disks found */
#define	L_BP_BUSY_RESERVED		0x50000

/* Backplane: one or more busy disks found */
#define	L_BP_BUSY			0x50001

/* Backplane: one or more reserved disks found */
#define	L_BP_RESERVED			0x50002

/* No BP element found in the enclosure */
#define	L_NO_BP_ELEM_FOUND		0x50003

/*
 * Thread errors.
 */
#define	L_TH_CREATE			0x60000
#define	L_TH_JOIN			0x60001



#endif /* __x86 */


#ifdef	__cplusplus
}
#endif

#endif	/* _ERRORCODES_H */
