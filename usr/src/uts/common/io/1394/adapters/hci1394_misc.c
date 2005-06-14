/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_misc.c
 *    Misc. HBA functions.  These include getinfo, open, close, shutdown, and
 *    overall driver state control functions.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/mkdev.h>

#include <sys/1394/adapters/hci1394.h>
#include <sys/1394/adapters/hci1394_extern.h>



/* ARGSUSED */
int
hci1394_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t dev;
	hci1394_state_t *soft_state;
	minor_t instance;
	int status;


	TNF_PROBE_0_DEBUG(hci1394_getinfo_enter, HCI1394_TNF_HAL_STACK, "");

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = getminor(dev);
		soft_state = ddi_get_soft_state(hci1394_statep, instance);
		if (soft_state == NULL) {
			TNF_PROBE_1(hci1394_getinfo_gss_fail,
			    HCI1394_TNF_HAL_ERROR, "", tnf_string, errmsg,
			    "ddi_get_soft_state() failed");
			TNF_PROBE_0_DEBUG(hci1394_getinfo_exit,
			    HCI1394_TNF_HAL_STACK, "");
			return (DDI_FAILURE);
		}
		*result = (void *)soft_state->drvinfo.di_dip;
		status = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev);
		*result = (void *)(uintptr_t)instance;
		status = DDI_SUCCESS;
		break;

	default:
		TNF_PROBE_1(hci1394_getinfo_def_fail, HCI1394_TNF_HAL_ERROR, "",
		    tnf_string, errmsg, "reached default in switch");
		status = DDI_FAILURE;
	}

	TNF_PROBE_0_DEBUG(hci1394_getinfo_exit, HCI1394_TNF_HAL_STACK, "");
	return (status);
}


/* ARGSUSED */
int
hci1394_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	hci1394_state_t *soft_state;


	TNF_PROBE_0_DEBUG(hci1394_open_enter, HCI1394_TNF_HAL_STACK, "");

	soft_state = ddi_get_soft_state(hci1394_statep, getminor(*devp));
	if (soft_state == NULL) {
		TNF_PROBE_1(hci1394_open_gss_fail, HCI1394_TNF_HAL_ERROR, "",
		    tnf_string, errmsg, "ddi_get_soft_state() failed");
		TNF_PROBE_0_DEBUG(hci1394_open_exit, HCI1394_TNF_HAL_STACK, "");
		return (ENXIO);
	}

	TNF_PROBE_0_DEBUG(hci1394_open_exit, HCI1394_TNF_HAL_STACK, "");
	return (0);
}


/* ARGSUSED */
int
hci1394_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	TNF_PROBE_0_DEBUG(hci1394_close_enter, HCI1394_TNF_HAL_STACK, "");

	TNF_PROBE_0_DEBUG(hci1394_close_exit, HCI1394_TNF_HAL_STACK, "");

	return (0);
}


/*
 * hci1394_shutdown()
 *    Shutdown the HW.  Something bad that we cannot recover from happened.
 */
void
hci1394_shutdown(dev_info_t *dip)
{
	hci1394_state_t *soft_state;


	/*
	 * In the debug version of the driver, we want to do an assert here so
	 * that we don't reset the hardware and can look and see what happened
	 * to cause the shutdown.
	 */
#ifndef	TEST_SHUTDOWN
	ASSERT(0);
#endif

	TNF_PROBE_0_DEBUG(hci1394_shutdown_enter, HCI1394_TNF_HAL_STACK, "");

	soft_state = ddi_get_soft_state(hci1394_statep, ddi_get_instance(dip));
	if (soft_state == NULL) {
		TNF_PROBE_1(hci1394_shutdown_gss_fail, HCI1394_TNF_HAL_ERROR,
		    "", tnf_string, errmsg, "ddi_get_soft_state() failed");
		TNF_PROBE_0_DEBUG(hci1394_shutdown_exit,
		    HCI1394_TNF_HAL_STACK, "");
		return;
	}

	/*
	 * Don't allow the HW to generate any more interrupts. Make sure we
	 * disable interrupts before setting the driver state to shutdown.
	 */
	hci1394_ohci_intr_master_disable(soft_state->ohci);

	/* don't accept anymore commands from services layer */
	(void) hci1394_state_set(&soft_state->drvinfo, HCI1394_SHUTDOWN);

	/* Reset the OHCI HW */
	(void) hci1394_ohci_soft_reset(soft_state->ohci);

	/* Flush out async DMA Q's (cancels pendingQ timeouts too) */
	hci1394_async_flush(soft_state->async);

	TNF_PROBE_0_DEBUG(hci1394_shutdown_exit, HCI1394_TNF_HAL_STACK, "");
}


/*
 * hci1394_state()
 *    returns the current state of the driver
 */
hci1394_statevar_t
hci1394_state(hci1394_drvinfo_t *drvinfo)
{
	hci1394_statevar_t hal_state;

	TNF_PROBE_0_DEBUG(hci1394_state_enter, HCI1394_TNF_HAL_STACK, "");
	mutex_enter(&drvinfo->di_drvstate.ds_mutex);
	hal_state = drvinfo->di_drvstate.ds_state;
	mutex_exit(&drvinfo->di_drvstate.ds_mutex);
	TNF_PROBE_0_DEBUG(hci1394_state_exit, HCI1394_TNF_HAL_STACK, "");

	return (hal_state);
}


/*
 * hci1394_state_set()
 *    Set the current state of the driver. This routine will return failure
 *    if the driver state is currently set to HCI1394_SHUTDOWN.  We do not
 *    allow a transition out of shutdown.
 */
int
hci1394_state_set(hci1394_drvinfo_t *drvinfo, hci1394_statevar_t state)
{
	TNF_PROBE_0_DEBUG(hci1394_state_set_enter, HCI1394_TNF_HAL_STACK, "");
	mutex_enter(&drvinfo->di_drvstate.ds_mutex);

	/* Do not allow a transition out of shutdown */
	if (drvinfo->di_drvstate.ds_state == HCI1394_SHUTDOWN) {
		mutex_exit(&drvinfo->di_drvstate.ds_mutex);
		TNF_PROBE_1(hci1394_state_set_fail, HCI1394_TNF_HAL_STACK, "",
		    tnf_string, errmsg, "driver shutdown");
		TNF_PROBE_0_DEBUG(hci1394_state_set_exit, HCI1394_TNF_HAL_STACK,
		    "");
		return (DDI_FAILURE);
	}

	drvinfo->di_drvstate.ds_state = state;
	mutex_exit(&drvinfo->di_drvstate.ds_mutex);
	TNF_PROBE_0_DEBUG(hci1394_state_set_exit, HCI1394_TNF_HAL_STACK, "");

	return (DDI_SUCCESS);
}
