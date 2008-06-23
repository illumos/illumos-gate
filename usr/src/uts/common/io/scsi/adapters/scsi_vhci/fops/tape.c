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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of "scsi_vhci_f_tape" tape failover_ops.
 *
 * This file was historically meant for only tape implementation.  It has
 * been extended to manage SUN "supported" tape controllers. The supported
 * VID/PID shall be listed in the tape_dev_table.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>

/* Supported device table entries.  */
static char *tape_dev_table[] = {
/*	"                  111111" */
/*	"012345670123456789012345" */
/*	"|-VID--||-----PID------|" */
	"IBM     ULTRIUM-TD3",
	"IBM     ULTRIUM-TD4",
	NULL
};

/* Failover module plumbing. */
SCSI_FAILOVER_OP("f_tape", tape, "%I%");

/* ARGSUSED */
static int
tape_device_probe(struct scsi_device *sd, struct scsi_inquiry *inquiry,
    void **ctpriv)
{
	int i;
	int rval = SFO_DEVICE_PROBE_PHCI;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "!tape_device_probe: inquiry string %s\n",
	    inquiry->inq_vid));
	/*
	 * See if this a device type that we want to care about.
	 */
	switch (inquiry->inq_dtype & DTYPE_MASK) {
	case DTYPE_SEQUENTIAL:
		break;
	case DTYPE_CHANGER:
		rval = SFO_DEVICE_PROBE_VHCI;
		goto done;
	default:
		/*
		 * Not interested.
		 */
		return (rval);
	}

	/*
	 * If it reports that it supports tpgs and it got here it may have
	 * failed the tpgs commands. It might or might not support dual port
	 * but we'll go with it.
	 */
	if (inquiry->inq_tpgs) {
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!has tpgs bits: %s\n",
		    inquiry->inq_vid));
		rval = SFO_DEVICE_PROBE_VHCI;
	} else if (inquiry->inq_dualp) {
		/*
		 * Looks like it claims to have more then one port.
		 */
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!has dual port bits: %s\n",
		    inquiry->inq_vid));
		rval = SFO_DEVICE_PROBE_VHCI;
	} else {

		/*
		 * See if this device is on the list.
		 */
		for (i = 0; tape_dev_table[i]; i++) {

			if (strncmp(inquiry->inq_vid, tape_dev_table[i],
			    strlen(tape_dev_table[i])) == 0) {
				VHCI_DEBUG(6, (CE_NOTE, NULL,
				    "!was on the list: %s\n",
				    inquiry->inq_vid));
				rval = SFO_DEVICE_PROBE_VHCI;
				break;
			}
		}
	}
done:
	if (rval == SFO_DEVICE_PROBE_VHCI) {
		if (mdi_set_lb_policy(sd->sd_dev, LOAD_BALANCE_NONE) !=
		    MDI_SUCCESS) {
			VHCI_DEBUG(6, (CE_NOTE, NULL, "!fail load balance none"
			    ": %s\n", inquiry->inq_vid));
			return (SFO_DEVICE_PROBE_PHCI);
		}

	}
	return (rval);
}

/* ARGSUSED */
static void
tape_device_unprobe(struct scsi_device *sd, void *ctpriv)
{
	/*
	 * NO OP for tape.
	 */

}

/* ARGSUSED */
static int
tape_path_activate(struct scsi_device *sd, char *pathclass, void *ctpriv)
{
	return (0);
}

/* ARGSUSED */
static int
tape_path_deactivate(struct scsi_device *sd, char *pathclass, void *ctpriv)
{
	return (0);
}

/* ARGSUSED */
static int
tape_path_get_opinfo(struct scsi_device *sd, struct scsi_path_opinfo *opinfo,
    void *ctpriv)
{
	opinfo->opinfo_rev = OPINFO_REV;
	(void) strcpy(opinfo->opinfo_path_attr, PCLASS_PRIMARY);
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
tape_path_ping(struct scsi_device *sd, void *ctpriv)
{
	return (1);
}

/* ARGSUSED */
static int
tape_analyze_sense(struct scsi_device *sd, struct scsi_extended_sense *sense,
    void *ctpriv)
{
	if (sense->es_key == KEY_ABORTED_COMMAND &&
	    sense->es_add_code == 0x4b &&
	    sense->es_qual_code == 0x83) {
		return (SCSI_SENSE_INACTIVE);
	}
	if (sense->es_key == KEY_NOT_READY &&
	    sense->es_add_code == 0x4 &&
	    sense->es_qual_code == 0x1) {
		return (SCSI_SENSE_NOT_READY);
	}
	return (SCSI_SENSE_NOFAILOVER);
}

/* ARGSUSED */
static int
tape_pathclass_next(char *cur, char **nxt, void *ctpriv)
{
	if (cur == NULL) {
		*nxt = PCLASS_PRIMARY;
		return (0);
	} else if (strcmp(cur, PCLASS_PRIMARY) == 0) {
		return (ENOENT);
	}
	return (EINVAL);
}
