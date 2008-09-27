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
#include <sys/scsi/impl/uscsi.h>
#include <errno.h>
#include <mms_dmd.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_drive.h>
#include <mms_sym.h>

/* LINTED: static unused */
static	char *_SrcFile = __FILE__;

/*
 * Specify whether the persistent reserve out command is supported or not.
 * 0 - not supported
 * 1 - supported
 *
 * If the persistent reserve out command is supported, then it will be used
 * to reserve the drive.
 * If the persistent reserve out command is not supported, then the reserve
 * command will be used to reserve the drive.
 */
int	drv_prsv_supported = 1;		/* persistent reserve out supported */

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
char	drv_drive_type[] = "dt_T9940A";

/*
 * drv_density_rw[]
 * Specify readwrite densities supported by this DM.
 * drv_density_rw must be an array of mms_sym_t.
 * Density names must start with "den_" to avoid conflict with other names.
 */
mms_sym_t	drv_density[] = {
	"den_T9940A", 0x43,
	"den_T9940B", 0x44,
	NULL				/* Must be last entry */
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
	"9940",
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
	"9940", "den_T9940A", "den_T9940A",
	"9940", "den_T9940B", "den_T9940A",
	/*
	 * Specify readonly density
	 */
	NULL				/* Must be last entry */
};
