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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <syslog.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/commands.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <mms_dmd.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_drive.h>
#include <mms_sym.h>
#include <dda.h>

static	char *_SrcFile = __FILE__;

/*
 * specify timeouts for this drive. Time is specified in seconds.
 */
drv_timeout_t	drv_timeout = {
	(151 *60),			/* For really long commands */
	(20 *60),			/* Normal commands */
	(1 *60),			/* short commands */
};

/*
 * Specify the drive type.
 * Drive type must begin with "dt_"
 */
char	drv_drive_type[] = "dt_XXXXX";

/*
 * Specify the directory in which this device can be found.
 * e.g. /dev/rmt
 *
 * The DM will open each device in this directory and look for a device
 * whose serial number matches the serial number specified in
 * DRIVE.'DriveSerialNum'.
 * If this is a null string, then the full pathname of the device is specified
 * in DM.'DMTargetPath'.
 */
char	drv_dev_dir[] = "/dev/rmt";

/*
 * drv_density[]
 * - Specify density names with their density codes supported by this DM.
 * - Densities must be specified in the order of their selection priority.
 *   The ones at the beginning of the list will be selected before those
 *   at the end of the list.
 * - Density names must start with "den_" to avoid conflict with other names.
 */
mms_sym_t	drv_density[] = {
	NULL,				/* Must be the last entry */
};

/*
 * drv_shape[]
 * - Specify shape names of cartridge types supported by this DM.
 * - Shape names must be specified in the order of their selection priority.
 *   The ones at the beginning of the list will be selected before those
 *   at the end of the list.
 * - Shape name must be a well known and published name.
 */
char	*drv_shape[] = {
	NULL				/* Must be last entry */
};


/*
 * drv_shape_den[]
 * Specify the shape of a cartridge and the density on it that can be
 * written over by a readwrite density.
 * All shape names and density names must have been specified in
 * drv_density[] and drv_shape[].
 * Each entry of the array consists of:
 * {shapename, density on cart, readwrite density}.
 * If the density on cartridge is the same as the readwrite density, then
 * the drive can read and write with that density.
 * If the density on cartridge is read only, then the readwrite density
 * is NULL.
 * If the readwrite density is not NULL and it is different from the density
 * on cartridge, then the drive is able to write over the existing data
 * starting from the beginning of medium.
 */

drv_shape_density_t	drv_shape_den[] = {
	/* shapename    existing den    readwrite density */
	/*
	 * Specify readwrite density
	 */

	/*
	 * Specify readonly density
	 */
	NULL				/* Must be last entry */
};

/*
 * drv_mounted[]
 * Specify mount points of disk files that emulate cartridges.
 * Real cartridges do not have mount points.
 */
char	*drv_mounted[] = {
	"*none",			/* Real cartridge has not mount point */
	NULL,				/* Must be last entry */
};

/*
 * Specify SCSI commands that a client may not issue using USCSI
 */
int	drv_disallowed_cmds[] = {
	SCMD_PROUT,			/* persistent reserve out */
	SCMD_RESERVE,			/* reserve */
	SCMD_RELEASE,			/* release */
};
int	drv_num_disallowed_cmds =
    sizeof (drv_disallowed_cmds) / sizeof (int);

/*
 * Specify ioctl's that a client may not issue
 */
int	drv_disallowed_ioctls[] = {
	MTIOCRESERVE,
	MTIOCRELEASE,
	MTIOCFORCERESERVE,
};
int	drv_num_disallowed_ioctls =
    sizeof (drv_disallowed_ioctls) / sizeof (int);

/*
 * Sense key, asc and ascq table (skaa)
 * 0xff matches any value in lookup operation.
 */
drv_skaa_t	drv_skaa_tab[] = {
	/*
	 * Error text must be less than or equal to 80 characters.
	 */
	0xff, 0x00, 0x00, DRV_EC_NO_SENSE,
	"no additional sense information",
	0xff, 0x00, 0x01, DRV_EC_TM,
	"filemark detected",
	0xff, 0x00, 0x02, DRV_EC_EOM,
	"end-of-partition/medium detected",
	0xff, 0x00, 0x03, DRV_EC_TM,
	"setmark detected",
	0xff, 0x00, 0x04, DRV_EC_BOM,
	"beginning-of-partition/medium detected",
	0xff, 0x00, 0x05, DRV_EC_EOD,
	"end-of-data detected",
	0xff, 0x00, 0x06, DRV_EC_ERROR,
	"I/O process terminated",
	0xff, 0x00, 0x16, DRV_EC_NOT_READY,
	"operation in progress",
	0xff, 0x00, 0x17, DRV_EC_NEEDS_CLEANING,
	"cleaning requested",
	0xff, 0x00, 0x18, DRV_EC_NOT_READY,
	"erase operation in progress",
	0xff, 0x00, 0x19, DRV_EC_NOT_READY,
	"locate operation in progress",
	0xff, 0x00, 0x1a, DRV_EC_NOT_READY,
	"rewind operation in progress",
	0xff, 0x00, 0x1b, DRV_EC_NOT_READY,
	"set capacity operation in progress",
	0xff, 0x00, 0x1c, DRV_EC_NOT_READY,
	"verify operation in progress",
	0xff, 0x00, 0x1d, DRV_EC_ERROR,
	"ATA pass through information available",
	0xff, 0x03, 0x00, DRV_EC_ERROR,
	"peripheral device write fault",
	0xff, 0x03, 0x01, DRV_EC_ERROR,
	"no write current",
	0xff, 0x03, 0x02, DRV_EC_ERROR,
	"excessive write errors",
	0xff, 0x04, 0x00, DRV_EC_NOT_READY,
	"logical unit not ready, cause not reportable",
	0xff, 0x04, 0x01, DRV_EC_NOT_READY,
	"logical unit is in process of becoming ready",
	0xff, 0x04, 0x02, DRV_EC_ERROR,
	"logical unit not ready, initializing command required",
	0xff, 0x04, 0x03, DRV_EC_NOT_READY,
	"logical unit not ready, manual intervention required",
	0xff, 0x04, 0x04, DRV_EC_NOT_READY,
	"logical unit not ready, format in progress",
	0xff, 0x04, 0x05, DRV_EC_NOT_READY,
	"logical unit not ready, rebuild in progress",
	0xff, 0x04, 0x06, DRV_EC_NOT_READY,
	"logical unit not ready, recalculation in progress",
	0xff, 0x04, 0x07, DRV_EC_NOT_READY,
	"logical unit not ready, operation in progress",
	0xff, 0x04, 0x09, DRV_EC_NOT_READY,
	"logical unit not ready, self-test in progress",
	0xff, 0x04, 0x0a, DRV_EC_ERROR,
	"logical unit not accessible, asymmetric access state transition",
	0xff, 0x04, 0x0b, DRV_EC_ERROR,
	"logical unit not accessible, target port in standby state",
	0xff, 0x04, 0x0c, DRV_EC_ERROR,
	"logical unit not accessible, target port in unavailable state",
	0xff, 0x04, 0x10, DRV_EC_NOT_READY,
	"logical unit not ready, auxiliary memory not accessible",
	0xff, 0x04, 0x11, DRV_EC_NOT_READY,
	"logical unit not ready, notify (enable spinup) required",
	0xff, 0x05, 0x00, DRV_EC_ERROR,
	"logical unit does not respond to selection",
	0xff, 0x07, 0x00, DRV_EC_ERROR,
	"multiple peripheral devices selected",
	0xff, 0x08, 0x00, DRV_EC_ERROR,
	"logical unit communication failure",
	0xff, 0x08, 0x01, DRV_EC_ERROR,
	"logical unit communication time-out",
	0xff, 0x08, 0x02, DRV_EC_ERROR,
	"logical unit communication parity error",
	0xff, 0x08, 0x03, DRV_EC_ERROR,
	"logical unit communication crc error (ULTRA-DMA/32)",
	0xff, 0x08, 0x04, DRV_EC_ERROR,
	"unreachable copy target",
	0xff, 0x09, 0x00, DRV_EC_ERROR,
	"track following error",
	0xff, 0x09, 0x04, DRV_EC_ERROR,
	"head select fault",
	0xff, 0x0a, 0x00, DRV_EC_ERROR,
	"error log overflow",
	0xff, 0x0b, 0x00, DRV_EC_ERROR,
	"warning",
	0xff, 0x0b, 0x01, DRV_EC_ERROR,
	"warning - specified temperature exceeded",
	0xff, 0x0b, 0x02, DRV_EC_ERROR,
	"warning - enclosure degraded",
	0xff, 0x0b, 0x03, DRV_EC_ERROR,
	"warning - background self-test failed",
	0xff, 0x0b, 0x04, DRV_EC_ERROR,
	"warning - background pre-scan detected medium error",
	0xff, 0x0b, 0x05, DRV_EC_ERROR,
	"warning - background medium scan detected medium error",
	0xff, 0x0c, 0x00, DRV_EC_ERROR,
	"write error",
	0xff, 0x0c, 0x04, DRV_EC_ERROR,
	"compression check miscompare error",
	0xff, 0x0c, 0x05, DRV_EC_ERROR,
	"data expansion occurred during compression",
	0xff, 0x0c, 0x06, DRV_EC_ERROR,
	"block not compressible",
	0xff, 0x0c, 0x0b, DRV_EC_ERROR,
	"auxiliary memory write error",
	0xff, 0x0c, 0x0c, DRV_EC_ERROR,
	"write error - unexpected unsolicited data",
	0xff, 0x0c, 0x0d, DRV_EC_ERROR,
	"write error - not enough unsolicited data",
	0xff, 0x0d, 0x00, DRV_EC_ERROR,
	"error detected by third party temporary initiator",
	0xff, 0x0d, 0x01, DRV_EC_ERROR,
	"third party device failure",
	0xff, 0x0d, 0x02, DRV_EC_ERROR,
	"copy target device not reachable",
	0xff, 0x0d, 0x03, DRV_EC_ERROR,
	"incorrect copy target device type",
	0xff, 0x0d, 0x04, DRV_EC_ERROR,
	"copy target device data underrun",
	0xff, 0x0d, 0x05, DRV_EC_ERROR,
	"copy target device data overrun",
	0xff, 0x0e, 0x00, DRV_EC_ERROR,
	"invalid information unit",
	0xff, 0x0e, 0x01, DRV_EC_ERROR,
	"information unit too short",
	0xff, 0x0e, 0x02, DRV_EC_ERROR,
	"information unit too long",
	0xff, 0x0e, 0x03, DRV_EC_ERROR,
	"invalid field in command information unit",
	0xff, 0x10, 0x01, DRV_EC_ERROR,
	"logical block guard check failed",
	0xff, 0x10, 0x02, DRV_EC_ERROR,
	"logical block application tag check failed",
	0xff, 0x10, 0x03, DRV_EC_ERROR,
	"logical block reference tag check failed",
	0xff, 0x11, 0x00, DRV_EC_ERROR,
	"unrecovered read error",
	0xff, 0x11, 0x01, DRV_EC_ERROR,
	"read retries exhausted",
	0xff, 0x11, 0x02, DRV_EC_ERROR,
	"error too long to correct",
	0xff, 0x11, 0x03, DRV_EC_ERROR,
	"multiple read errors",
	0xff, 0x11, 0x08, DRV_EC_ERROR,
	"incomplete block read",
	0xff, 0x11, 0x09, DRV_EC_ERROR,
	"no gap found",
	0xff, 0x11, 0x0a, DRV_EC_ERROR,
	"miscorrected error",
	0xff, 0x11, 0x0d, DRV_EC_ERROR,
	"de-compression crc error",
	0xff, 0x11, 0x0e, DRV_EC_ERROR,
	"cannot decompress using declared algorithm",
	0xff, 0x11, 0x12, DRV_EC_ERROR,
	"auxiliary memory read error",
	0xff, 0x11, 0x13, DRV_EC_ERROR,
	"read error - failed retransmission request",
	0xff, 0x14, 0x00, DRV_EC_ERROR,
	"recorded entity not found",
	0xff, 0x14, 0x01, DRV_EC_ERROR,
	"record not found",
	0xff, 0x14, 0x02, DRV_EC_ERROR,
	"filemark or setmark not found",
	0xff, 0x14, 0x03, DRV_EC_ERROR,
	"end-of-data not found",
	0xff, 0x14, 0x04, DRV_EC_ERROR,
	"block sequence error",
	0xff, 0x14, 0x05, DRV_EC_ERROR,
	"record not found - recommend reassignment",
	0xff, 0x14, 0x06, DRV_EC_ERROR,
	"record not found - data auto-reallocated",
	0xff, 0x14, 0x07, DRV_EC_ERROR,
	"locate operation failure",
	0xff, 0x15, 0x00, DRV_EC_ERROR,
	"random positioning error",
	0xff, 0x15, 0x01, DRV_EC_ERROR,
	"mechanical positioning error",
	0xff, 0x15, 0x02, DRV_EC_ERROR,
	"positioning error detected by read of medium",
	0xff, 0x17, 0x00, DRV_EC_ERROR,
	"recovered data with no error correction applied",
	0xff, 0x17, 0x01, DRV_EC_ERROR,
	"recovered data with retries",
	0xff, 0x17, 0x02, DRV_EC_ERROR,
	"recovered data with positive head offset",
	0xff, 0x17, 0x03, DRV_EC_ERROR,
	"recovered data with negative head offset",
	0xff, 0x18, 0x00, DRV_EC_ERROR,
	"recovered data with error correction applied",
	0xff, 0x1a, 0x00, DRV_EC_ERROR,
	"parameter list length error",
	0xff, 0x1b, 0x00, DRV_EC_ERROR,
	"synchronous data transfer error",
	0xff, 0x1d, 0x00, DRV_EC_ERROR,
	"miscompare during verify operation",
	0xff, 0x20, 0x00, DRV_EC_ERROR,
	"invalid command operation code",
	0xff, 0x20, 0x01, DRV_EC_ERROR,
	"access denied - initiator pending-enrolled",
	0xff, 0x20, 0x02, DRV_EC_ERROR,
	"access denied - no access rights",
	0xff, 0x20, 0x03, DRV_EC_ERROR,
	"access denied - invalid mgmt id key",
	0xff, 0x20, 0x04, DRV_EC_ERROR,
	"illegal command while in write capable state",
	0xff, 0x20, 0x05, DRV_EC_ERROR,
	"obsolete",
	0xff, 0x20, 0x06, DRV_EC_ERROR,
	"illegal command while in explicit mms_address mode",
	0xff, 0x20, 0x07, DRV_EC_ERROR,
	"illegal command while in implicit mms_address mode",
	0xff, 0x20, 0x08, DRV_EC_ERROR,
	"access denied - enrollment conflict",
	0xff, 0x20, 0x09, DRV_EC_ERROR,
	"access denied - invalid lu identifier",
	0xff, 0x20, 0x0a, DRV_EC_ERROR,
	"access denied - invalid proxy token",
	0xff, 0x20, 0x0b, DRV_EC_ERROR,
	"access denied - acl lun conflict",
	0xff, 0x21, 0x00, DRV_EC_ERROR,
	"logical block mms_address out of range",
	0xff, 0x21, 0x01, DRV_EC_ERROR,
	"invalid element mms_address",
	0xff, 0x24, 0x00, DRV_EC_ERROR,
	"invalid field in cdb",
	0xff, 0x24, 0x01, DRV_EC_ERROR,
	"cdb decryption error",
	0xff, 0x24, 0x02, DRV_EC_ERROR,
	"obsolete",
	0xff, 0x24, 0x03, DRV_EC_ERROR,
	"obsolete",
	0xff, 0x25, 0x00, DRV_EC_ERROR,
	"logical unit not supported",
	0xff, 0x26, 0x00, DRV_EC_ERROR,
	"invalid field in parameter list",
	0xff, 0x26, 0x01, DRV_EC_ERROR,
	"parameter not supported",
	0xff, 0x26, 0x02, DRV_EC_ERROR,
	"parameter value invalid",
	0xff, 0x26, 0x03, DRV_EC_ERROR,
	"threshold parameters not supported",
	0xff, 0x26, 0x04, DRV_EC_ERROR,
	"invalid release of persistent reservation",
	0xff, 0x26, 0x05, DRV_EC_ERROR,
	"data decryption error",
	0xff, 0x26, 0x06, DRV_EC_ERROR,
	"too many target descriptors",
	0xff, 0x26, 0x07, DRV_EC_ERROR,
	"unsupported target descriptor type code",
	0xff, 0x26, 0x08, DRV_EC_ERROR,
	"too many segment descriptors",
	0xff, 0x26, 0x09, DRV_EC_ERROR,
	"unsupported segment descriptor type code",
	0xff, 0x26, 0x0a, DRV_EC_ERROR,
	"unexpected inexact segment",
	0xff, 0x26, 0x0b, DRV_EC_ERROR,
	"inline data length exceeded",
	0xff, 0x26, 0x0c, DRV_EC_ERROR,
	"invalid operation for copy source or destination",
	0xff, 0x26, 0x0d, DRV_EC_ERROR,
	"copy segment granularity violation",
	0xff, 0x26, 0x0e, DRV_EC_ERROR,
	"invalid parameter while port is enabled",
	0xff, 0x26, 0x10, DRV_EC_ERROR,
	"data decryption key fail limit reached",
	0xff, 0x26, 0x11, DRV_EC_ERROR,
	"incomplete key-associated data set",
	0xff, 0x26, 0x12, DRV_EC_ERROR,
	"vendor specific key reference not found",
	0xff, 0x27, 0x00, DRV_EC_ERROR,
	"write protected",
	0xff, 0x27, 0x01, DRV_EC_ERROR,
	"hardware write protected",
	0xff, 0x27, 0x02, DRV_EC_ERROR,
	"logical unit software write protected",
	0xff, 0x27, 0x03, DRV_EC_ERROR,
	"associated write protect",
	0xff, 0x27, 0x04, DRV_EC_ERROR,
	"persistent write protect",
	0xff, 0x27, 0x05, DRV_EC_ERROR,
	"permanent write protect",
	0xff, 0x28, 0x00, DRV_EC_NREADY_TO_READY,
	"not ready to ready change, medium may have changed",
	0xff, 0x28, 0x01, DRV_EC_ERROR,
	"import or export element accessed",
	0xff, 0x29, 0x00, DRV_EC_RESET,
	"power on, reset, or bus device reset occurred",
	0xff, 0x29, 0x01, DRV_EC_RESET,
	"power on occurred",
	0xff, 0x29, 0x02, DRV_EC_RESET,
	"scsi bus reset occurred",
	0xff, 0x29, 0x03, DRV_EC_RESET,
	"bus device reset function occurred",
	0xff, 0x29, 0x04, DRV_EC_RESET,
	"device internal reset",
	0xff, 0x29, 0x05, DRV_EC_ERROR,
	"transceiver mode changed to single-ended",
	0xff, 0x29, 0x06, DRV_EC_ERROR,
	"transceiver mode changed to lvd",
	0xff, 0x29, 0x07, DRV_EC_ERROR,
	"i_t nexus loss occurred",
	0xff, 0x2a, 0x00, DRV_EC_ERROR,
	"parameters changed",
	0xff, 0x2a, 0x01, DRV_EC_ERROR,
	"mode parameters changed",
	0xff, 0x2a, 0x02, DRV_EC_ERROR,
	"log parameters changed",
	0xff, 0x2a, 0x03, DRV_EC_LOST_PRSV,
	"reservations preempted",
	0xff, 0x2a, 0x04, DRV_EC_LOST_PRSV,
	"reservations released",
	0xff, 0x2a, 0x05, DRV_EC_LOST_PRSV,
	"registrations preempted",
	0xff, 0x2a, 0x06, DRV_EC_ERROR,
	"asymmetric access state changed",
	0xff, 0x2a, 0x07, DRV_EC_ERROR,
	"implicit asymmetric access state transition failed",
	0xff, 0x2a, 0x08, DRV_EC_ERROR,
	"priority changed",
	0xff, 0x2a, 0x10, DRV_EC_ERROR,
	"timestamp changed",
	0xff, 0x2a, 0x11, DRV_EC_ERROR,
	"data encryption parameters changed by another i_t nexus",
	0xff, 0x2a, 0x12, DRV_EC_ERROR,
	"data encryption parameters changed by vendor specific event",
	0xff, 0x2a, 0x13, DRV_EC_ERROR,
	"data encryption key instance counter has changed",
	0xff, 0x2b, 0x00, DRV_EC_ERROR,
	"copy cannot execute since host cannot disconnect",
	0xff, 0x2c, 0x00, DRV_EC_ERROR,
	"command sequence error",
	0xff, 0x2c, 0x07, DRV_EC_ERROR,
	"previous busy status",
	0xff, 0x2c, 0x08, DRV_EC_ERROR,
	"previous task set full status",
	0xff, 0x2c, 0x09, DRV_EC_ERROR,
	"previous reservation conflict status",
	0xff, 0x2c, 0x0b, DRV_EC_ERROR,
	"not reserved",
	0xff, 0x2d, 0x00, DRV_EC_ERROR,
	"overwrite error on update in place",
	0xff, 0x2f, 0x00, DRV_EC_ERROR,
	"commands cleared by another initiator",
	0xff, 0x2f, 0x02, DRV_EC_ERROR,
	"commands cleared by device server",
	0xff, 0x30, 0x00, DRV_EC_ERROR,
	"incompatible medium installed",
	0xff, 0x30, 0x01, DRV_EC_FORMAT,
	"cannot read medium - unknown format",
	0xff, 0x30, 0x02, DRV_EC_FORMAT,
	"cannot read medium - incompatible format",
	0xff, 0x30, 0x03, DRV_EC_FORMAT,
	"cleaning cartridge installed",
	0xff, 0x30, 0x04, DRV_EC_FORMAT,
	"cannot write medium - unknown format",
	0xff, 0x30, 0x05, DRV_EC_FORMAT,
	"cannot write medium - incompatible format",
	0xff, 0x30, 0x06, DRV_EC_FORMAT,
	"cannot format medium - incompatible medium",
	0xff, 0x30, 0x07, DRV_EC_ERROR,
	"cleaning failure",
	0xff, 0x30, 0x0a, DRV_EC_ERROR,
	"cleaning request rejected",
	0xff, 0x30, 0x0c, DRV_EC_ERROR,
	"worm medium - overwrite attempted",
	0xff, 0x30, 0x0d, DRV_EC_ERROR,
	"worm medium - integrity check",
	0xff, 0x31, 0x00, DRV_EC_ERROR,
	"medium format corrupted",
	0xff, 0x33, 0x00, DRV_EC_ERROR,
	"tape length error",
	0xff, 0x34, 0x00, DRV_EC_ERROR,
	"enclosure failure",
	0xff, 0x35, 0x00, DRV_EC_ERROR,
	"enclosure services failure",
	0xff, 0x35, 0x01, DRV_EC_ERROR,
	"unsupported enclosure function",
	0xff, 0x35, 0x02, DRV_EC_ERROR,
	"enclosure services unavailable",
	0xff, 0x35, 0x03, DRV_EC_ERROR,
	"enclosure services transfer failure",
	0xff, 0x35, 0x04, DRV_EC_ERROR,
	"enclosure services transfer refused",
	0xff, 0x35, 0x05, DRV_EC_ERROR,
	"enclosure services checksum error",
	0xff, 0x37, 0x00, DRV_EC_ERROR,
	"rounded parameter",
	0xff, 0x39, 0x00, DRV_EC_ERROR,
	"saving parameters not supported",
	0xff, 0x3a, 0x00, DRV_EC_NOT_READY,
	"medium not present",
	0xff, 0x3a, 0x01, DRV_EC_NOT_READY,
	"medium not present - tray closed",
	0xff, 0x3a, 0x02, DRV_EC_NOT_READY,
	"medium not present - tray open",
	0xff, 0x3a, 0x03, DRV_EC_NOT_READY,
	"medium not present - loadable",
	0xff, 0x3a, 0x04, DRV_EC_NOT_READY,
	"medium not present - medium auxiliary memory accessible",
	0xff, 0x3b, 0x00, DRV_EC_ERROR,
	"sequential positioning error",
	0xff, 0x3b, 0x01, DRV_EC_ERROR,
	"tape position error at beginning-of-medium",
	0xff, 0x3b, 0x02, DRV_EC_ERROR,
	"tape position error at end-of-medium",
	0xff, 0x3b, 0x08, DRV_EC_ERROR,
	"reposition error",
	0xff, 0x3b, 0x0c, DRV_EC_ERROR,
	"position past beginning of medium",
	0xff, 0x3b, 0x0d, DRV_EC_ERROR,
	"medium destination element full",
	0xff, 0x3b, 0x0e, DRV_EC_ERROR,
	"medium source element empty",
	0xff, 0x3b, 0x11, DRV_EC_ERROR,
	"medium magazine not accessible",
	0xff, 0x3b, 0x12, DRV_EC_ERROR,
	"medium magazine removed",
	0xff, 0x3b, 0x13, DRV_EC_ERROR,
	"medium magazine inserted",
	0xff, 0x3b, 0x14, DRV_EC_ERROR,
	"medium magazine locked",
	0xff, 0x3b, 0x15, DRV_EC_ERROR,
	"medium magazine unlocked",
	0xff, 0x3d, 0x00, DRV_EC_ERROR,
	"invalid bits in identify message",
	0xff, 0x3e, 0x00, DRV_EC_ERROR,
	"logical unit has not self-configured yet",
	0xff, 0x3e, 0x01, DRV_EC_ERROR,
	"logical unit failure",
	0xff, 0x3e, 0x02, DRV_EC_ERROR,
	"timeout on logical unit",
	0xff, 0x3e, 0x03, DRV_EC_ERROR,
	"logical unit failed self-test",
	0xff, 0x3e, 0x04, DRV_EC_ERROR,
	"logical unit unable to update self-test log",
	0xff, 0x3f, 0x00, DRV_EC_ERROR,
	"target operating conditions have changed",
	0xff, 0x3f, 0x01, DRV_EC_ERROR,
	"microcode has been changed",
	0xff, 0x3f, 0x02, DRV_EC_ERROR,
	"changed operating definition",
	0xff, 0x3f, 0x03, DRV_EC_ERROR,
	"inquiry data has changed",
	0xff, 0x3f, 0x04, DRV_EC_ERROR,
	"component device attached",
	0xff, 0x3f, 0x05, DRV_EC_ERROR,
	"device identifier changed",
	0xff, 0x3f, 0x06, DRV_EC_ERROR,
	"redundancy group created or modified",
	0xff, 0x3f, 0x07, DRV_EC_ERROR,
	"redundancy group deleted",
	0xff, 0x3f, 0x08, DRV_EC_ERROR,
	"spare created or modified",
	0xff, 0x3f, 0x09, DRV_EC_ERROR,
	"spare deleted",
	0xff, 0x3f, 0x0a, DRV_EC_ERROR,
	"volume set created or modified",
	0xff, 0x3f, 0x0b, DRV_EC_ERROR,
	"volume set deleted",
	0xff, 0x3f, 0x0c, DRV_EC_ERROR,
	"volume set deassigned",
	0xff, 0x3f, 0x0d, DRV_EC_ERROR,
	"volume set reassigned",
	0xff, 0x3f, 0x0e, DRV_EC_ERROR,
	"reported luns data has changed",
	0xff, 0x3f, 0x0f, DRV_EC_ERROR,
	"echo buffer overwritten",
	0xff, 0x3f, 0x10, DRV_EC_ERROR,
	"medium loadable",
	0xff, 0x3f, 0x11, DRV_EC_ERROR,
	"medium auxiliary memory accessible",
	0xff, 0x3f, 0x12, DRV_EC_ERROR,
	"iscsi ip mms_address added",
	0xff, 0x3f, 0x13, DRV_EC_ERROR,
	"iscsi ip mms_address removed",
	0xff, 0x3f, 0x14, DRV_EC_ERROR,
	"iscsi ip mms_address changed",
	0xff, 0x40, 0xff, DRV_EC_ERROR,
	"diagnostic failure on component nn (80h-ffh)",
	0xff, 0x43, 0x00, DRV_EC_ERROR,
	"message error",
	0xff, 0x44, 0x00, DRV_EC_ERROR,
	"internal target failure",
	0xff, 0x44, 0x71, DRV_EC_ERROR,
	"ata device failed set features",
	0xff, 0x45, 0x00, DRV_EC_ERROR,
	"select or reselect failure",
	0xff, 0x46, 0x00, DRV_EC_ERROR,
	"unsuccessful soft reset",
	0xff, 0x47, 0x00, DRV_EC_ERROR,
	"scsi parity error",
	0xff, 0x47, 0x01, DRV_EC_ERROR,
	"data phase crc error detected",
	0xff, 0x47, 0x02, DRV_EC_ERROR,
	"scsi parity error detected during st data phase",
	0xff, 0x47, 0x03, DRV_EC_ERROR,
	"information unit iucrc error detected",
	0xff, 0x47, 0x04, DRV_EC_ERROR,
	"asynchronous information protection error detected",
	0xff, 0x47, 0x05, DRV_EC_ERROR,
	"protocol service crc error",
	0xff, 0x47, 0x06, DRV_EC_ERROR,
	"phy test function in progress",
	0xff, 0x47, 0x7f, DRV_EC_ERROR,
	"some commands cleared by iscsi protocol event",
	0xff, 0x48, 0x00, DRV_EC_ERROR,
	"initiator detected error message received",
	0xff, 0x49, 0x00, DRV_EC_ERROR,
	"invalid message error",
	0xff, 0x4a, 0x00, DRV_EC_ERROR,
	"command phase error",
	0xff, 0x4b, 0x00, DRV_EC_ERROR,
	"data phase error",
	0xff, 0x4b, 0x01, DRV_EC_ERROR,
	"invalid target port transfer tag received",
	0xff, 0x4b, 0x02, DRV_EC_ERROR,
	"too much write data",
	0xff, 0x4b, 0x03, DRV_EC_ERROR,
	"ack/nak timeout",
	0xff, 0x4b, 0x04, DRV_EC_ERROR,
	"nak received",
	0xff, 0x4b, 0x05, DRV_EC_ERROR,
	"data offset error",
	0xff, 0x4b, 0x06, DRV_EC_ERROR,
	"initiator response timeout",
	0xff, 0x4c, 0x00, DRV_EC_ERROR,
	"logical unit failed self-configuration",
	0xff, 0x4d, 0xff, DRV_EC_ERROR,
	"tagged overlapped commands (nn = task tag)",
	0xff, 0x4e, 0x00, DRV_EC_ERROR,
	"overlapped commands attempted",
	0xff, 0x50, 0x00, DRV_EC_ERROR,
	"write append error",
	0xff, 0x50, 0x01, DRV_EC_ERROR,
	"write append position error",
	0xff, 0x50, 0x02, DRV_EC_ERROR,
	"position error related to timing",
	0xff, 0x51, 0x00, DRV_EC_ERROR,
	"erase failure",
	0xff, 0x52, 0x00, DRV_EC_ERROR,
	"cartridge fault",
	0xff, 0x53, 0x00, DRV_EC_ERROR,
	"media load or eject failed",
	0xff, 0x53, 0x01, DRV_EC_ERROR,
	"unload tape failure",
	0xff, 0x53, 0x02, DRV_EC_ERROR,
	"medium removal prevented",
	0xff, 0x53, 0x04, DRV_EC_ERROR,
	"medium thread or unthread failure",
	0xff, 0x55, 0x02, DRV_EC_ERROR,
	"insufficient reservation resources",
	0xff, 0x55, 0x03, DRV_EC_ERROR,
	"insufficient resources",
	0xff, 0x55, 0x04, DRV_EC_ERROR,
	"insufficient registration resources",
	0xff, 0x55, 0x05, DRV_EC_ERROR,
	"insufficient access control resources",
	0xff, 0x55, 0x06, DRV_EC_ERROR,
	"auxiliary memory out of space",
	0xff, 0x55, 0x08, DRV_EC_ERROR,
	"maximum number of supplemental decryption keys exceeded",
	0xff, 0x5a, 0x00, DRV_EC_ERROR,
	"operator request or state change input",
	0xff, 0x5a, 0x01, DRV_EC_ERROR,
	"operator medium removal request",
	0xff, 0x5a, 0x02, DRV_EC_ERROR,
	"operator selected write protect",
	0xff, 0x5a, 0x03, DRV_EC_ERROR,
	"operator selected write permit",
	0xff, 0x5b, 0x00, DRV_EC_ERROR,
	"log exception",
	0xff, 0x5b, 0x01, DRV_EC_ERROR,
	"threshold condition met",
	0xff, 0x5b, 0x02, DRV_EC_ERROR,
	"log counter at maximum",
	0xff, 0x5b, 0x03, DRV_EC_ERROR,
	"log list codes exhausted",
	0xff, 0x5d, 0x00, DRV_EC_ERROR,
	"failure prediction threshold exceeded",
	0xff, 0x5d, 0xff, DRV_EC_ERROR,
	"failure prediction threshold exceeded (false)",
	0xff, 0x5e, 0x00, DRV_EC_ERROR,
	"low power condition on",
	0xff, 0x5e, 0x01, DRV_EC_ERROR,
	"idle condition activated by timer",
	0xff, 0x5e, 0x02, DRV_EC_ERROR,
	"standby condition activated by timer",
	0xff, 0x5e, 0x03, DRV_EC_ERROR,
	"idle condition activated by command",
	0xff, 0x5e, 0x04, DRV_EC_ERROR,
	"standby condition activated by command",
	0xff, 0x65, 0x00, DRV_EC_ERROR,
	"voltage fault",
	0xff, 0x67, 0x0a, DRV_EC_ERROR,
	"set target port groups command failed",
	0xff, 0x67, 0x0b, DRV_EC_ERROR,
	"ata device feature not enabled",
	0xff, 0x70, 0xff, DRV_EC_ERROR,
	"decompression exception short algorithm id of nn",
	0xff, 0x71, 0x00, DRV_EC_ERROR,
	"decompression exception long algorithm id",
	0xff, 0x74, 0x00, DRV_EC_ERROR,
	"security error",
	0xff, 0x74, 0x01, DRV_EC_ERROR,
	"unable to decrypt data",
	0xff, 0x74, 0x02, DRV_EC_ERROR,
	"unencrypted data encountered while decrypting",
	0xff, 0x74, 0x03, DRV_EC_ERROR,
	"incorrect data encryption key",
	0xff, 0x74, 0x04, DRV_EC_ERROR,
	"cryptographic integrity validation failed",
	0xff, 0x74, 0x05, DRV_EC_ERROR,
	"error decrypting data",
	0xff, 0x74, 0x06, DRV_EC_ERROR,
	"unknown signature verification key",
	0xff, 0x74, 0x07, DRV_EC_ERROR,
	"encryption parameters not useable",
	0xff, 0x74, 0x08, DRV_EC_ERROR,
	"digital signature validation failure",
	0xff, 0x74, 0x09, DRV_EC_ERROR,
	"encryption mode mismatch on read",
	0xff, 0x74, 0x0a, DRV_EC_ERROR,
	"encrypted block not raw read enabled",
	0xff, 0x74, 0x0b, DRV_EC_ERROR,
	"incorrect encryption parameters",
	0xff, 0x74, 0x71, DRV_EC_ERROR,
	"logical unit access not authorized",

	/*
	 * Sense keys
	 */
	0x00, 0xff, 0xff, DRV_EC_NO_SENSE,
	"no sense",
	0x01, 0xff, 0xff, DRV_EC_RCVD_ERR,
	"recovered error",
	0x02, 0xff, 0xff, DRV_EC_NOT_READY,
	"not ready",
	0x03, 0xff, 0xff, DRV_EC_MEDIUM_ERR,
	"medium error",
	0x04, 0xff, 0xff, DRV_EC_HW_ERR,
	"hardware error",
	0x05, 0xff, 0xff, DRV_EC_ILLEGAL_REQ,
	"illegal request",
	0x06, 0xff, 0xff, DRV_EC_UNIT_ATTN,
	"unit attention",
	0x07, 0xff, 0xff, DRV_EC_DATA_PROTECT,
	"data protect",
	0x08, 0xff, 0xff, DRV_EC_BLANK_CHECK,
	"blank check",
	0x09, 0xff, 0xff, DRV_EC_VENDOR,
	"vendor specific",
	0x0a, 0xff, 0xff, DRV_EC_COPY_ABORTED,
	"copy aborted",
	0x0b, 0xff, 0xff, DRV_EC_ABORTED,
	"aborted command",
	0x0d, 0xff, 0xff, DRV_EC_VOL_OVERFLOW,
	"volume overflow",
	0x0e, 0xff, 0xff, DRV_EC_MISCOMPARE,
	"data miscompare",

	/*
	 * This must be the last entry
	 */
	0xff, 0xff, 0xff, DRV_EC_UNKNOWN_ERR,
	"Unknown error",
};

/*
 * Initialize device.
 * Real drives don't use this.
 */
void
drv_init_dev(void)
{
}

/*
 * Return array of mounted FS for disk archiving.
 * Real devices don't have mounted FS for disk archiving.x
 */
char **
drv_get_mounted(void)
{
	return (&drv_mounted[0]);
}

/*
 * drv_set_blksize - set blocksize
 */
int
drv_set_blksize(uint64_t size)
{
	drv_req_t	op;
	int		one = 1;

	TRACE((MMS_DEBUG, "Setting blocksize to %lld", size));
	op.drv_op = MTSRSZ;
	op.drv_count = size;
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}

	/*
	 * Supresse SILI
	 */
	if (size == 0) {
		dm_ioctl(MTIOCREADIGNOREILI, &one);
	}

	return (0);
}

/*
 * drv_set_blksize - set blocksize
 */
int
drv_get_blksize(uint64_t *size)
{
	drv_req_t	op;

	op.drv_op = MTGRSZ;
	op.drv_count = -1;
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	*size = op.drv_count;
	TRACE((MMS_DEBUG, "Current blocksize %lld", *size));
	return (0);
}

int64_t
drv_get_avail_capacity(void)
{
	mms_capacity_t	cap;

	if (DRV_CALL(drv_get_capacity, (&cap)) < 0) {
		return (EIO);
	}
	return (cap.mms_avail);
}

int
drv_get_capacity(mms_capacity_t *cap)
{
	uchar_t		buf[40];
	int		off;
	int		i;
	uint32_t	code;
	uint32_t	max = 0;
	uint32_t	avail = 0;
	int		page_control = 1;	/* return current value */

	if (DRV_CALL(drv_log_sense,
	    (buf, sizeof (buf), page_control, 0x31)) != 0) {
		return (EIO);
	}

	for (i = 0; i < 4; i++) {
		off = 4 + i * 8;
		char_to_uint32(buf + off, 2, &code);
		if (code == 1) {	/* Max capacity */
			char_to_uint32(buf + off + 4, 4, &avail);
			cap->mms_avail = avail;
			break;
		}
	}

	for (i = 0; i < 4; i++) {
		off = 4 + i * 8;
		char_to_uint32(buf + off, 2, &code);
		if (code == 3) {	/* capacity left */
			char_to_uint32(buf + off + 4, 4, &max);
			cap->mms_max = max;
			break;
		}
	}

	if (max > 0) {
		cap->mms_pc_avail = ((avail * 1000) / max + 5) / 10;
		if (cap->mms_pc_avail > 100) {
			cap->mms_pc_avail = 100;
		} else if ((int32_t)cap->mms_pc_avail < 0) {
			cap->mms_pc_avail = 0;
		}
	} else {
		cap->mms_pc_avail = 0;
	}

	TRACE((MMS_DEBUG, "Capacity: max %lld, avail %lld, avail %d%%",
	    cap->mms_max, cap->mms_avail, cap->mms_pc_avail));

	return (0);
}


/*
 * drv_mode_sense - issue mode sense
 * - page - page code
 * - len - allocation length
 *
 * - always return block descriptor block
 * - always get current value
 */
int
drv_mode_sense(int page, int pc, int len)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00 };

	cdb[2] = page;			/* page code */
	cdb[4] = len;			/* alloc length */
	cdb[2] |= (pc << 6);		/* PC bits */

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = cdb;
	us.uscsi_cdblen = 6;
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)drv->drv_iobuf;
	us.uscsi_buflen = len;

	TRACE((MMS_DEBUG, "Mode sense"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	return (0);
}

/*
 * drv_mode_select - issue mode select
 * - pf - page format - 0, no page data, or 1, send page data
 * - len - allocation length
 */
int
drv_mode_select(int pf, int len)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x15, 0x00, 0x00, 0x00, 0x00, 0x00 };

	drv->drv_iobuf[0] = 0;
	drv->drv_iobuf[1] = 0;
	drv->drv_iobuf[2] &= ~0x80;
	drv->drv_iobuf[8] = 0;

	cdb[1] |= (pf << 4);
	cdb[4] = len;

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_WRITE;
	us.uscsi_cdb = cdb;
	us.uscsi_cdblen = 6;
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)drv->drv_iobuf;
	us.uscsi_buflen = len;

	TRACE((MMS_DEBUG, "Mode select"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	return (0);
}

int
drv_inquiry(void)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x12, 0x00, 0x00, 0x00, DRV_INQ_LEN, 0 };

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = cdb;
	us.uscsi_cdblen = 6;
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)drv->drv_iobuf;
	us.uscsi_buflen = DRV_INQ_LEN;

	TRACE((MMS_DEBUG, "Read inquiry"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	return (0);
}

int
drv_req_sense(int len)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x03, 0x00, 0x00, 0x00, 0, 0 };

	cdb[4] = len;
	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = cdb;
	us.uscsi_cdblen = 6;
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)drv->drv_iobuf;
	us.uscsi_buflen = len;

	TRACE((MMS_DEBUG, "Request sense"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	return (0);
}

int
drv_get_drivetype(void)
{
	struct	mtdrivetype	type;
	struct	mtdrivetype_request	req = { 0, &type };

	req.size = sizeof (type);
	/*
	 * This is necessary because the MTIOCGETDRIVETYPE ioctl does not
	 * return the full length of the product id and we need the full
	 * product id.
	 */
	drv->drv_typename[0] = '\0';
	drv->drv_vend[0] = '\0';
	drv->drv_prod[0] = '\0';
	if (DRV_CALL(drv_inquiry, ()) == 0) {
		(void) strncpy(drv->drv_vend, (char *)drv->drv_iobuf + 8, 8);
		drv->drv_vend[8] = '\0';
		(void) strncpy(drv->drv_prod, (char *)drv->drv_iobuf + 16, 16);
		drv->drv_prod[16] = '\0';
	}

	/*
	 * Try doing MTIOCGETDRIVETYPE
	 */
	if (dm_ioctl(MTIOCGETDRIVETYPE, &req) != 0) {
		return (EIO);
	}
	(void) strncpy(drv->drv_typename, type.name, 64);
	drv->drv_typename[64] = '\0';
	if (drv->drv_vend[0] == '\0') {
		(void) strncpy(drv->drv_vend, type.vid, 8);
		drv->drv_vend[8] = '\0';
		(void) strncpy(drv->drv_prod, type.vid + 8, 16);
		drv->drv_prod[16] = '\0';
	}
	TRACE((MMS_DEBUG, "typename \"%s\", vendor \"%s\", prod \"%s\"",
	    drv->drv_typename, drv->drv_vend, drv->drv_prod));
	return (0);
}

int
drv_clrerr(void)
{
	int		rc = 0;

	if (dm_ioctl(MTIOCLRERR, 0) < 0) {
		rc = errno;
		TRACE((MMS_ERR, "MTIOCLRERR error: %s", strerror(rc)));
	}
	return (rc);
}

int
drv_read(char *buf, int len)
{
	int		rc;
	int		err;
	char		dumpbuf[1024];

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	TRACE((MMS_DEBUG, "Reading %d bytes", len));
	(void) memset(serr, 0, sizeof (drv_scsi_err_t));
	rc = read(drv->drv_fd, buf, len);
	if (rc <= 0) {
		err = errno;
		dm_get_mtstat(0);
		dm_get_mt_error(err);
		DRV_CALL(drv_proc_error, ());
		if (serr->se_senkey == KEY_HARDWARE_ERROR) {
			/* set DriveBroken to "yes" */
			(void) dm_send_drive_broken();
		} else if (serr->se_senkey == KEY_MEDIUM_ERROR) {
			/* Set CartridgeMediaError to "yes" */
			(void) dm_send_cartridge_media_error();
		}
		errno = err;
	} else {
		(void) mms_trace_dump(buf, rc, dumpbuf, sizeof (dumpbuf));
		TRACE((MMS_DEBUG, "Data read:\n%s", dumpbuf));
	}

	return (rc);
}

int
drv_write(char *buf, int len)
{
	int		rc = 0;
	int		err;

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	TRACE((MMS_DEBUG, "Writing %d bytes", len));

	while (rc == 0) {
		rc = write(drv->drv_fd, buf, len);
		/*
		 * If rc == 0, then we are in EOT and have to try again
		 */
	}

	if (rc != len) {
		err = errno;
		dm_get_mtstat(0);
		dm_get_mt_error(err);

		if ((drv->drv_flags & DRV_EOM) && serr->se_resid == 0) {
			/* at EOT and block was written */
			return (len);
		}
		DRV_CALL(drv_proc_error, ());

		if (serr->se_senkey == KEY_HARDWARE_ERROR) {
			/* set DriveBroken to "yes" */
(void) dm_send_drive_broken();
		} else if (serr->se_senkey == KEY_MEDIUM_ERROR) {
			/* Set CartridgeMediaError to "yes" */
(void) dm_send_cartridge_media_error();
		}
		errno = err;
	}

	return (rc);
}



/*
 * drv_wtm - write tapemarks
 * return residual
 */
int
drv_wtm(uint64_t count)
{
	drv_req_t	op = { MTWEOF, 0 };
	int		rc;

	op.drv_count = count;

	TRACE((MMS_DEBUG, "MTWEOF"));

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	rc = dm_mtiocltop(&op);
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (count != serr->se_resid) {
		drv->drv_flags |= (DRV_TERM_FILE | DRV_TM);
	}
	TRACE((MMS_DEBUG, "Wrote %lld tapemarks", count - serr->se_resid));
	if (serr->se_resid == 0) {
		rc = 0;
	}
	return (rc);
}

int
drv_tur(void)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_cdb = cdb;
	us.uscsi_cdblen = 6;
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = NULL;
	us.uscsi_buflen = 0;

	TRACE((MMS_DEBUG, "TUR"));
	for (;;) {
		if (dm_uscsi(&us) != 0 ||
		    serr->se_status != STATUS_GOOD) {
			if (serr->se_status == STATUS_CHECK &&
			    serr->se_senkey == KEY_UNIT_ATTENTION) {
				/* ignore attention for now and try again */
				continue;
			}
			return (EIO);
		}
		break;
	}
	return (0);

}

int
drv_load(void)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x1b, 0x00, 0x00, 0x00, 0x03, 0x00 };
	mms_capacity_t	cap;

	TRACE((MMS_DEBUG, "Load/Retension"));

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	(void) memset(&us, 0, sizeof (us));
	us.uscsi_cdb = cdb;
	us.uscsi_cdblen = 6;
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = NULL;
	us.uscsi_buflen = 0;
	TRACE((MMS_DEBUG, "LOAD"));
	for (;;) {
		if (dm_uscsi(&us) != 0) {
			if (serr->se_errcl == DRV_EC_NREADY_TO_READY) {
				/* Drive became ready */
				break;
			}
			if (serr->se_status != STATUS_GOOD) {
				if (serr->se_status == STATUS_CHECK &&
				    serr->se_senkey == KEY_UNIT_ATTENTION) {
					/* ignore attention and try again */
					continue;
				}
				return (EIO);
			}
		}
		break;
	}
	drv->drv_flags |= DRV_BOM;
	DRV_CALL(drv_get_capacity, (&cap));
	drv->drv_capacity = cap.mms_max;
	TRACE((MMS_DEBUG, "Cartridge \"%s\" loaded", mnt->mnt_pcl));
	return (0);
}

int
drv_unload(void)
{
	drv_req_t	op = { MTOFFL, 0 };

	TRACE((MMS_DEBUG, "Unload/Offline"));

	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	drv->drv_flags &= DRV_ATTACHED;
	if (drv->drv_vid || drv->drv_vid[0] != '\0') {
		TRACE((MMS_DEBUG, "Cartridge \"%s\" unloaded", drv->drv_vid));
	}
	return (0);
}

int
drv_rewind(void)
{
	drv_req_t	op = { MTREW, 0 };

	TRACE((MMS_DEBUG, "Rewind"));

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	drv->drv_flags |= DRV_BOM;
	TRACE((MMS_DEBUG, "Cartridge rewound"));

	return (0);
}

int
drv_seek(uint64_t count)
{
	drv_req_t	op = { MTSEEK, 0 };

	op.drv_count = count;

	TRACE((MMS_DEBUG, "Seek to logical block"));
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Seeked to logical block %d", count));
	return (0);
}

int
drv_tell(uint64_t *count)
{
	drv_req_t	op = { MTTELL, 0 };

	TRACE((MMS_DEBUG, "MTTELL"));
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	*count = op.drv_count;
	TRACE((MMS_DEBUG, "MTTELL %lld", *count));
	return (0);
}

int
drv_fsf(uint64_t count)
{
	drv_req_t	op = { MTFSF, 0 };

	op.drv_count = count;

	TRACE((MMS_DEBUG, "Forward space file"));
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	drv->drv_flags |= DRV_TM;
	TRACE((MMS_DEBUG, "Forward spaced %lld files",
	    count - serr->se_resid));
	return (0);
}

int
drv_bsf(uint64_t count)
{
	drv_req_t	op = { MTBSF, 0 };

	op.drv_count = count;

	TRACE((MMS_DEBUG, "Backward space file"));
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	drv->drv_flags |= DRV_TM;
	TRACE((MMS_DEBUG, "Backward spaced %lld files",
	    count - serr->se_resid));
	return (0);
}

int
drv_fsb(uint64_t count, int cross)
{
	drv_req_t	op = { MTFSR, 0 };
	uint64_t	resid;
	int		err = 0;
	int		rc = 0;

	op.drv_count = count;

	TRACE((MMS_DEBUG, "Forward space blocks"));
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_mtiocltop(&op) != 0) {
		err = errno;
		if (drv->drv_flags & DRV_TM) {
			/* Hit a tapemark */
			resid = serr->se_resid;
			if (cross == DRV_LOGICAL_CROSS_TM) {
				DRV_CALL(drv_fsf, (1));
			}
			serr->se_resid = resid;
		}
		rc = EIO;
	}
	TRACE((MMS_DEBUG, "Forward spaced %lld blocks",
	    count - serr->se_resid));
	errno = err;
	return (rc);
}

int
drv_bsb(uint64_t count, int cross)
{
	drv_req_t op = { MTBSR, 0 };
	uint64_t	resid;
	int		err = 0;
	int		rc = 0;

	op.drv_count = count;
	TRACE((MMS_DEBUG, "Backward space blocks"));
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_mtiocltop(&op) != 0) {
		err = errno;
		if (drv->drv_flags & DRV_TM) {
			/* Hit a tapemark */
			resid = serr->se_resid;
			if (cross == DRV_LOGICAL_CROSS_TM) {
				DRV_CALL(drv_bsf, (1));
			}
			serr->se_resid = resid;
		}
		rc = EIO;
	}
	TRACE((MMS_DEBUG, "Backward spaced %lld blocks",
	    count - serr->se_resid));
	errno = err;
	return (rc);
}

int
drv_eom(void)
{
	drv_req_t	op = { MTEOM, 0 };

	TRACE((MMS_DEBUG, "Goto EOM"));
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_mtiocltop(&op) != 0) {
		return (EIO);
	}
	return (0);
}

int
drv_get_pos(tapepos_t *pos)
{
#if 1
	if (dm_ioctl(MTIOCGETPOS, pos) != 0) {
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Read position %lld", pos->lgclblkno));
	return (0);
#else
	int		rc;
	struct		uscsi_cmd us;
	uchar_t		cdb[10] =
	    { 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)drv->drv_iobuf;
	us.uscsi_buflen = 20;

	TRACE((MMS_DEBUG, "Read position"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	(void) memset(pos, 0, sizeof (tapepos_t));
	char_to_uint64(drv->drv_iobuf + 4, 4, &pos->lgclblkno);
	TRACE((MMS_DEBUG, "Read position %lld", pos->lgclblkno));
	return (0);
#endif
}

int
drv_locate(tapepos_t *pos)
{
#if 1
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (dm_ioctl(MTIOCRESTPOS, pos) < 0) {
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Located to %lld", pos->lgclblkno));
	return (0);
#else
	int		rc;
	struct		uscsi_cmd us;
	uchar_t		cdb[10] =
	    { 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (pos->mms_type != MMS_LBLKN) {
		return (EIO);
	}
	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags |= 0;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_timeout;
	us.uscsi_bufaddr = NULL;
	us.uscsi_buflen = 0;

	int64_to_char(pos->mms_pos, cdb + 3, 4);

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	TRACE((MMS_DEBUG, "Locate"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	TRACE((MMS_DEBUG, "Located to %lld", pos->mms_pos));
	return (0);
#endif
}

int
drv_log_sense(uchar_t *buf, int len, int page_control, int page_code)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)buf;
	us.uscsi_buflen = len;

	cdb[2] = (page_control << 6) | page_code;
	int32_to_char(len, cdb + 7, 2);

	TRACE((MMS_DEBUG, "Log sense"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	return (0);
}

int
drv_blk_limit(mms_blk_limit_t *lmt)
{
	uchar_t		buf[6];
	struct		uscsi_cmd us;
	uchar_t		cdb[] = { 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };


	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)buf;
	us.uscsi_buflen = sizeof (buf);

	TRACE((MMS_DEBUG, "Read block limit"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	char_to_uint64(buf + 1, 3, &lmt->mms_max);
	char_to_uint32(buf + 4, 2, &lmt->mms_min);
	lmt->mms_gran = 2;

	return (0);
}

int
drv_release(void)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] = { 0x17, 0x00, 0x00, 0x00, 0x00, 0x00 };


	(void) memset(&us, 0, sizeof (us));

	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;

	TRACE((MMS_DEBUG, "Release unit"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	return (0);
}

int
drv_prsv_register(void)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =			/* register & ignore */
	{ 0x5f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00 };
	char		parm[24];
	uint64_t	key;

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_WRITE;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = parm;
	us.uscsi_buflen = sizeof (parm);

	(void) memset(parm, 0, sizeof (parm));
	(void) memcpy(parm + 8, DRV_PRSV_KEY, 8);
	char_to_uint64((uchar_t *)DRV_PRSV_KEY, 8, &key);
	TRACE((MMS_DEBUG, "Registering PRSV key: %16.16llx", key));

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	return (0);
}

int
drv_prsv_reserve(void)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x5f, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00 };
	char		parm[24];

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_WRITE;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = parm;
	us.uscsi_buflen = sizeof (parm);

	/*
	 * Set reservation key
	 */
	(void) memset(parm, 0, sizeof (parm));
	(void) memcpy(parm, DRV_PRSV_KEY, 8);

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	drv->drv_flags |= DRV_RESERVED;
	TRACE((MMS_DEBUG, "Drive reserved"));
	return (0);
}

int
drv_prsv_release(void)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x5f, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00 };
	char		parm[24];

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_WRITE;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = parm;
	us.uscsi_buflen = sizeof (parm);

	/*
	 * Set reservation key
	 */
	(void) memset(parm, 0, sizeof (parm));
	(void) memcpy(parm, DRV_PRSV_KEY, 8);

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	drv->drv_flags &= ~DRV_RESERVED;
	TRACE((MMS_DEBUG, "Drive released"));
	return (0);
}

int
drv_prsv_preempt(char *curkey)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x5f, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00 };
	char		parm[24];

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_WRITE;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = parm;
	us.uscsi_buflen = sizeof (parm);

	/*
	 * Set reservation key
	 */
	(void) memset(parm, 0, sizeof (parm));
	(void) memcpy(parm, DRV_PRSV_KEY, 8);
	(void) memcpy(parm + 8, curkey, 8);

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	drv->drv_flags |= DRV_RESERVED;
	TRACE((MMS_DEBUG, "Drive reserved: preempt"));
	return (0);
}

int
drv_prsv_clear(void)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x5f, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00 };
	char		parm[24];

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_WRITE;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = parm;
	us.uscsi_buflen = sizeof (parm);

	/*
	 * Set reservation key
	 */
	(void) memset(parm, 0, sizeof (parm));
	(void) memcpy(parm, DRV_PRSV_KEY, 8);

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}
	drv->drv_flags &= ~DRV_RESERVED;
	TRACE((MMS_DEBUG, "Drive released: clear"));
	return (0);
}

int
drv_prsv_read_keys(char *buf, int bufsize)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x5e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	(void) memset(&us, 0, sizeof (us));
	(void) memset(buf, 0, bufsize);
	int32_to_char(bufsize, cdb + 7, 2);
	us.uscsi_flags |= (USCSI_RQENABLE | USCSI_READ);
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = buf;
	us.uscsi_buflen = bufsize;

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	return (0);
}

int
drv_prsv_read_rsv(char *buf, int bufsize)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x5e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	(void) memset(&us, 0, sizeof (us));
	(void) memset(buf, 0, bufsize);
	int32_to_char(bufsize, cdb + 7, 2);
	us.uscsi_flags |= (USCSI_RQENABLE | USCSI_READ);
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = buf;
	us.uscsi_buflen = bufsize;

	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	return (0);
}

int
drv_reserve(void)
{
	struct		uscsi_cmd us;
	uchar_t		cdb[] = { 0x16, 0x00, 0x00, 0x00, 0x00, 0x00 };


	(void) memset(&us, 0, sizeof (us));

	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;

	TRACE((MMS_DEBUG, "Reserve unit"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	return (0);
}

int
drv_get_serial_num(char *ser)
{
	int		i;
	int		len;
	struct		uscsi_cmd us;
	uchar_t		cdb[] =
	    { 0x12, 0x01, 0x80, 0x00, MMS_READ_SER_NUM_BUF_LEN, 0x00 };

	(void) memset(&us, 0, sizeof (us));
	us.uscsi_flags = USCSI_READ;
	us.uscsi_cdb = (char *)cdb;
	us.uscsi_cdblen = sizeof (cdb);
	us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
	us.uscsi_bufaddr = (char *)drv->drv_iobuf;
	us.uscsi_buflen = 16;

	TRACE((MMS_DEBUG, "Inquiry - Serial number"));
	if (dm_uscsi(&us)) {
		return (EIO);
	}
	if (serr->se_status != STATUS_GOOD) {
		return (EIO);
	}

	(void) memset(ser, 0, MMS_SER_NUM_LEN + 1);
	len = drv->drv_iobuf[3];
	(void) strncpy(ser, (char *)drv->drv_iobuf + 4, len);
	ser[len] = '\0';
	for (i = len - 1; i >= 0; i--) {
		if (ser[i] == ' ' || ser[i] == '\0') {
			ser[i] = '\0';
		} else {
			break;
		}
	}
	return (0);
}

int
drv_get_write_protect(int *wp)
{
	char		dumpbuf[512];
	char		*buf = (char *)drv->drv_iobuf;

	/*
	 * Read mode sense data
	 */
	if (DRV_CALL(drv_mode_sense, (0x00, 0, 4)) != 0) {
		return (EIO);
	}
	(void) mms_trace_dump(buf, 4, dumpbuf, sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "Mode sense data:\n%s", dumpbuf));
	*wp = buf[2] & 0x80 ? 1 : 0;
	TRACE((MMS_DEBUG, "Cartridge write protected is %s",
	    *wp ? "yes" : "no"));
	return (0);
}

int
drv_set_compression(int comp)
{
	char		dumpbuf[512];
	char		buf[28 + 16];
	int		len;

	/*
	 * Read mode sense data and switch to desired density
	 */
	if (DRV_CALL(drv_mode_sense, (0x0f, 0x00, 28)) != 0) {
		return (EIO);
	}
	(void) mms_trace_dump((char *)drv->drv_iobuf, 28, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "Mode sense data:\n%s", dumpbuf));

	/*
	 * Set compression
	 */
	if (comp) {
		drv->drv_iobuf[14] |= 0x80;	/* enable compression */
	} else {
		drv->drv_iobuf[14] &= ~0x80;	/* disable compression */
	}

	(void) mms_trace_dump((char *)drv->drv_iobuf, 28, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "Mode select data:\n%s", dumpbuf));
	(void) memcpy(buf, (char *)drv->drv_iobuf, 28);
	len = 28;

	/*
	 * If enabling compression, set select data compression algorithm
	 * in sequencial access device config page (0x10) to 1
	 */
	if (comp) {
		if (DRV_CALL(drv_mode_sense, (0x10, 0x00, 28)) != 0) {
			return (EIO);
		}
		(void) mms_trace_dump((char *)drv->drv_iobuf, 28, dumpbuf,
		    sizeof (dumpbuf));
		TRACE((MMS_DEBUG, "Mode sense data:\n%s", dumpbuf));

		drv->drv_iobuf[26] = 1;
		(void) mms_trace_dump((char *)drv->drv_iobuf, 28, dumpbuf,
		    sizeof (dumpbuf));
		TRACE((MMS_DEBUG, "Mode select data:\n%s", dumpbuf));
		(void) memcpy(buf + 28, (char *)drv->drv_iobuf + 12, 16);
		len += 16;
	}

	(void) memcpy((char *)drv->drv_iobuf, buf, len);
	if (DRV_CALL(drv_mode_select, (1, len)) != 0) {
		return (EIO);
	}

	TRACE((MMS_DEBUG, "Compression %s",
	    (comp != 0) ? "enabled" : "disabled"));

	return (0);
}

void
drv_disallowed(void)
{
	dm_disallowed();
}

void
drv_mk_prsv_key(void)
{
	dm_mk_prsv_key();
}

int
drv_rebind_target(void)
{
	return (dm_rebind_target());
}

int
drv_bind_raw_dev(int oflags)
{
	return (dm_bind_raw_dev(oflags));
}

void
drv_proc_error(void)
{
	/*
	 * Check SCSI command status
	 */
	if (serr->se_status == STATUS_CHECK) {
		/*
		 * Handle USCSI error
		 */
		switch (serr->se_errcl) {


		case DRV_EC_ERROR :
			break;
		case DRV_EC_NOT_READY :
			break;
		case DRV_EC_NO_SENSE :
			break;
		case DRV_EC_TM :
			serr->se_senkey = SUN_KEY_EOF;
			break;
		case DRV_EC_EOD :
			serr->se_senkey = KEY_BLANK_CHECK;
			break;
		case DRV_EC_EOM :
			serr->se_senkey = SUN_KEY_EOT;
			break;
		case DRV_EC_BOM :
			serr->se_senkey = SUN_KEY_BOT;
			break;
		case DRV_EC_NEEDS_CLEANING :
			dm_send_clean_request();
			break;
		case DRV_EC_FORMAT :
			break;
		case DRV_EC_INTER_REQ :
			break;
		case DRV_EC_RESET :
			break;
		case DRV_EC_UNIT_ATTN :
			break;
		case DRV_EC_LOST_PRSV :
			break;
		case DRV_EC_RCVD_ERR :
			break;
		case DRV_EC_MEDIUM_ERR :
			break;
		case DRV_EC_HW_ERR :
			break;
		case DRV_EC_ILLEGAL_REQ :
			break;
		case DRV_EC_DATA_PROTECT :
			break;
		case DRV_EC_BLANK_CHECK :
			break;
		case DRV_EC_VENDOR :
			break;
		case DRV_EC_COPY_ABORTED :
			break;
		case DRV_EC_ABORTED :
			break;
		case DRV_EC_VOL_OVERFLOW :
			break;
		case DRV_EC_MISCOMPARE :
			break;
		case DRV_EC_NREADY_TO_READY :
			break;
		default :
			break;

		}
	}
}

int
drv_get_statistics(void)
{
	uchar_t		buf[80];
	char		dumpbuf[1024];
	uint64_t	val;

	(void) memset(buf, 0xff, sizeof (buf));
	/*
	 * log sense pages needed 0x02, 0x03, 0x0c
	 */
	/*
	 * write error counts
	 */
	DRV_CALL(drv_log_sense, (buf, 80, 1, 0x02));
	(void) mms_trace_dump((char *)buf, sizeof (buf), dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "log sense page 0x02:\n%s", dumpbuf));

	dm_get_log_sense_parm(buf, 0x0003, &val);
	dca->dca_rcvd_write_err = val;
	dm_get_log_sense_parm(buf, 0x0006, &val);
	dca->dca_write_err = val;

	DRV_CALL(drv_log_sense, (buf, 80, 1, 0x03));
	(void) mms_trace_dump((char *)buf, sizeof (buf), dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "log sense page 0x03:\n%s", dumpbuf));

	dm_get_log_sense_parm(buf, 0x0003, &val);
	dca->dca_rcvd_read_err = val;
	dm_get_log_sense_parm(buf, 0x0006, &val);
	dca->dca_read_err = val;

	DRV_CALL(drv_log_sense, (buf, 80, 1, 0x0c));
	(void) mms_trace_dump((char *)buf, sizeof (buf), dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "log sense page 0x0c:\n%s", dumpbuf));

	dm_get_log_sense_parm(buf, 0x0000, &val);
	dca->dca_bytes_written = val;
	dm_get_log_sense_parm(buf, 0x0001, &val);
	dca->dca_bytes_written_med = val;

	dm_get_log_sense_parm(buf, 0x0003, &val);
	dca->dca_bytes_read = val;
	dm_get_log_sense_parm(buf, 0x0002, &val);
	dca->dca_bytes_read_med = val;

	return (0);
}


int
drv_get_density(int *den, int *comp)
{
	char		dumpbuf[512];
	char		*buf = (char *)drv->drv_iobuf;
	int		cmp;

	/*
	 * Read mode sense data and switch to desired density
	 */
	if (DRV_CALL(drv_mode_sense, (0x0f, 0, 28)) != 0) {
		return (EIO);
	}
	(void) mms_trace_dump(buf, 28, dumpbuf, sizeof (dumpbuf));
	*den = buf[4];
	cmp = (buf[14] & 0x80) ? 1 : 0;
	if (comp != NULL) {
		*comp = cmp;
	}
	TRACE((MMS_DEBUG, "Mode sense data:\n%s", dumpbuf));
	TRACE((MMS_DEBUG, "Drive current density = %2.2x, compression is %s",
	    *den, cmp ? "enabled" : "disabled"));

	return (0);
}


int
drv_set_density(int den)
{
	char		dumpbuf[512];

	/*
	 * Read mode sense data and switch to desired density
	 */
	if (DRV_CALL(drv_mode_sense, (0x00, 0x00, 12)) != 0) {
		return (EIO);
	}
	(void) mms_trace_dump((char *)drv->drv_iobuf, 12, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "Mode sense data:\n%s", dumpbuf));

	/*
	 * Set density
	 */
	drv->drv_iobuf[4] = den;

	(void) mms_trace_dump((char *)drv->drv_iobuf, 12, dumpbuf,
	    sizeof (dumpbuf));
	TRACE((MMS_DEBUG, "Mode select data:\n%s", dumpbuf));

	if (DRV_CALL(drv_mode_select, (0, 12)) != 0) {
		return (EIO);
	}
	drv->drv_cur_den = den;		/* save current den */
	TRACE((MMS_DEBUG, "Old density %2.2x: New density %2.2x",
	    mnt->mnt_bitformat->sym_code, den));

	return (0);
}
