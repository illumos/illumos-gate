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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file defines the known controller types.  To add a new controller
 * type, simply add a new line to the array and define the necessary
 * ops vector in a 'driver' file.
 */
#include "global.h"
#include <sys/dkio.h>

extern	struct ctlr_ops scsiops;
extern	struct ctlr_ops ataops;
extern	struct ctlr_ops pcmcia_ataops;
extern  struct ctlr_ops genericops;

/*
 * This array defines the supported controller types
 */
struct	ctlr_type ctlr_types[] = {

	{ DKC_DIRECT,
		"ata",
		&ataops,
		CF_NOFORMAT | CF_WLIST },

	{ DKC_SCSI_CCS,
		"SCSI",
		&scsiops,
		CF_SCSI | CF_EMBEDDED },

	{ DKC_PCMCIA_ATA,
		"pcmcia",
		&pcmcia_ataops,
		CF_NOFORMAT | CF_NOWLIST },

	{ DKC_VBD,
		"virtual-dsk",
		&genericops,
		CF_NOWLIST },

	{ DKC_BLKDEV,
		"generic-block-device",
		&genericops,
		CF_NOWLIST }
};

/*
 * This variable is used to count the entries in the array so its
 * size is not hard-wired anywhere.
 */
int	nctypes = sizeof (ctlr_types) / sizeof (struct ctlr_type);
