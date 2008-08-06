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
 * Implementation of "scsi_vhci_f_sym" symmetric failover_ops.
 *
 * This file was historically meant for only symmetric implementation.  It has
 * been extended to manage SUN "supported" symmetric controllers. The supported
 * VID/PID shall be listed in the symmetric_dev_table.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>

/* Supported device table entries.  */
char *symmetric_dev_table[] = {
/*	"                  111111" */
/*	"012345670123456789012345" */
/*	"|-VID--||-----PID------|" */
				/* disks */
	"IBM     DDYFT",
	"IBM     IC",
	"SEAGATE ST",
				/* enclosures */
	"SUN     SENA",			/* SES device */
	"SUN     SESS01",		/* VICOM SVE box */
	"SUNW    SUNWGS",		/* Daktari enclosure */
				/* arrays */
	"HITACHI OPEN",			/* Hitachi storage */
	"SUN     PSX1000",		/* Pirus Matterhorn */
	"SUN     SE6920",		/* Pirus */
	"SUN     SE6940",		/* DSP - Nauset */
	"SUN     StorEdge 3510",	/* Minnow FC */
	"SUN     StorEdge 3511",	/* Minnow SATA RAID */
	"SUN     StorageTek 6920",	/* DSP */
	"SUN     StorageTek 6940",	/* DSP - Nauset */
	"SUN     StorageTek NAS",	/* StorageTek NAS */
	"SUN     MRA300_R",		/* Shamrock - Controller */
	"SUN     MRA300_E",		/* Shamrock - Expansion */

	NULL
};

/* Failover module plumbing. */
SCSI_FAILOVER_OP(SFO_NAME_SYM, symmetric);

/* ARGSUSED */
static int
symmetric_device_probe(struct scsi_device *sd, struct scsi_inquiry *stdinq,
void **ctpriv)
{
	char	**dt;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "!inq str: %s\n", stdinq->inq_vid));
	for (dt = symmetric_dev_table; *dt; dt++)
		if (strncmp(stdinq->inq_vid, *dt, strlen(*dt)) == 0)
			return (SFO_DEVICE_PROBE_VHCI);

	/*
	 * No match, check for generic Sun supported disks:
	 *
	 *	"|-VID--||-----PID------|"
	 *	"012345670123456789012345"
	 *	".................SUN..G."
	 *	".................SUN..T."
	 *	".................SUN...G"
	 *	".................SUN...T"
	 */
	if (bcmp(&stdinq->inq_pid[9], "SUN", 3) == 0) {
		if ((stdinq->inq_pid[14] == 'G' || stdinq->inq_pid[15] == 'G' ||
		    stdinq->inq_pid[14] == 'T' || stdinq->inq_pid[15] == 'T') &&
		    (stdinq->inq_dtype == DTYPE_DIRECT)) {
			return (SFO_DEVICE_PROBE_VHCI);
		}
	}
	return (SFO_DEVICE_PROBE_PHCI);
}

/* ARGSUSED */
static void
symmetric_device_unprobe(struct scsi_device *sd, void *ctpriv)
{
	/*
	 * NOP for symmetric
	 */
}

/* ARGSUSED */
static int
symmetric_path_activate(struct scsi_device *sd, char *pathclass, void *ctpriv)
{
	return (0);
}

/* ARGSUSED */
static int
symmetric_path_deactivate(struct scsi_device *sd, char *pathclass,
void *ctpriv)
{
	return (0);
}

/* ARGSUSED */
static int
symmetric_path_get_opinfo(struct scsi_device *sd,
struct scsi_path_opinfo *opinfo, void *ctpriv)
{
	opinfo->opinfo_rev = OPINFO_REV;
	(void) strcpy(opinfo->opinfo_path_attr, "primary");
	opinfo->opinfo_path_state  = SCSI_PATH_ACTIVE;
	opinfo->opinfo_pswtch_best = 0;		/* N/A */
	opinfo->opinfo_pswtch_worst = 0;	/* N/A */
	opinfo->opinfo_xlf_capable = 0;
	opinfo->opinfo_mode = SCSI_NO_FAILOVER;
	opinfo->opinfo_preferred = 1;

	return (0);
}

/* ARGSUSED */
static int
symmetric_path_ping(struct scsi_device *sd, void *ctpriv)
{
	return (1);
}

/* ARGSUSED */
static int
symmetric_analyze_sense(struct scsi_device *sd,
struct scsi_extended_sense *sense, void *ctpriv)
{
	return (SCSI_SENSE_NOFAILOVER);
}

/* ARGSUSED */
static int
symmetric_pathclass_next(char *cur, char **nxt, void *ctpriv)
{
	if (cur == NULL) {
		*nxt = PCLASS_PRIMARY;
		return (0);
	} else if (strcmp(cur, PCLASS_PRIMARY) == 0) {
		return (ENOENT);
	} else {
		return (EINVAL);
	}
}
