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

/*
 * Implementation of "scsi_vhci_f_tpgs_tape" T10 standard based failover_ops.
 *
 * NOTE: for sequential devices only.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>
#include <sys/scsi/adapters/scsi_vhci_tpgs.h>

/* Supported device table entries.  */
char *tpgs_tape_dev_table[] = { NULL };
static void tpgs_tape_init(void);
static int tpgs_tape_device_probe(struct scsi_device *sd,
    struct scsi_inquiry *inq, void **ctpriv);

/* Failover module plumbing. */
#ifdef	lint
#define	scsi_vhci_failover_ops	scsi_vhci_failover_ops_f_tpgs_tape
#endif	/* lint */
struct scsi_failover_ops scsi_vhci_failover_ops = {
	SFO_REV,
	"f_tpgs_tape",
	tpgs_tape_dev_table,
	tpgs_tape_init,
	tpgs_tape_device_probe,
	/* The rest of the implementation comes from SFO_NAME_TPGS import  */
};

static struct modlmisc modlmisc = {
	&mod_miscops, "f_tpgs_tape"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};



/*
 * External function definitions
 */
extern struct scsi_failover_ops	*vhci_failover_ops_by_name(char *);

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/* ARGSUSED */
static int
tpgs_tape_device_probe(struct scsi_device *sd, struct scsi_inquiry *inq,
    void **ctpriv)
{
	int		mode, state, xlf, preferred = 0;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "tpgs_tape_device_probe: vidpid %s\n",
	    inq->inq_vid));

	if (inq->inq_tpgs == 0) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "!tpgs_tape_device_probe: not a standard tpgs device"));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (inq->inq_dtype != DTYPE_SEQUENTIAL) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "!tpgs_tape_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "not yet supported\n"));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (vhci_tpgs_get_target_fo_mode(sd, &mode, &state, &xlf, &preferred)) {
		VHCI_DEBUG(4, (CE_WARN, NULL, "!unable to fetch fo "
		    "mode: sd(%p)", (void *) sd));
		return (SFO_DEVICE_PROBE_PHCI);
	}

	if (inq->inq_tpgs == SCSI_IMPLICIT_FAILOVER) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!tpgs_tape_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "with implicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	if (inq->inq_tpgs == SCSI_EXPLICIT_FAILOVER) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!tpgs_tape_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "with explicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	if (inq->inq_tpgs == SCSI_BOTH_FAILOVER) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!tpgs_tape_device_probe: Detected a "
		    "Standard Asymmetric device "
		    "which supports both implicit and explicit failover\n"));
		return (SFO_DEVICE_PROBE_VHCI);
	}
	VHCI_DEBUG(1, (CE_WARN, NULL,
	    "!tpgs_tape_device_probe: "
	    "Unknown tpgs_bits: %x", inq->inq_tpgs));
	return (SFO_DEVICE_PROBE_PHCI);
}

static void
tpgs_tape_init(void)
{
	struct scsi_failover_ops	*sfo, *ssfo, clone;

	/* clone SFO_NAME_SYM implementation for most things */
	ssfo = vhci_failover_ops_by_name(SFO_NAME_TPGS);
	if (ssfo == NULL) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!tpgs_tape: "
		    "can't import " SFO_NAME_SYM "\n"));
		return;
	}
	sfo			= &scsi_vhci_failover_ops;
	clone			= *ssfo;
	clone.sfo_rev		= sfo->sfo_rev;
	clone.sfo_name		= sfo->sfo_name;
	clone.sfo_devices	= sfo->sfo_devices;
	clone.sfo_init		= sfo->sfo_init;
	clone.sfo_device_probe	= sfo->sfo_device_probe;
	*sfo			= clone;
}
