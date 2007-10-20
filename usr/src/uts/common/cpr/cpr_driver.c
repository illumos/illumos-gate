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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CPR driver support routines
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/epm.h>
#include <sys/cpr.h>

#define	CPR_BUFSIZE	128

extern int devi_detach(dev_info_t *, int);
extern int devi_attach(dev_info_t *, int);

static char 	*devi_string(dev_info_t *, char *);
static int	cpr_is_real_device(dev_info_t *);
/*
 * Xen uses this code to suspend _all_ drivers quickly and easily.
 * Suspend and Resume uses it for the same reason, but also has
 * to contend with some platform specific code that Xen does not.
 * it is also used as a test entry point for developers/testers to
 * execute code without going through a complete suspend.  So additions
 * that have platform implications shall need #if[n]def's.
 */
#ifndef __xpv
extern void	i_cpr_save_configuration(dev_info_t *);
extern void	i_cpr_restore_configuration(dev_info_t *);
#endif

/*
 * Traverse the dev info tree:
 *	Call each device driver in the system via a special case
 *	of the detach() entry point to quiesce itself.
 *	Suspend children first.
 *
 * We only suspend/resume real devices.
 */

int
cpr_suspend_devices(dev_info_t *dip)
{
	int		error;
	char		buf[CPR_BUFSIZE];

	for (; dip != NULL; dip = ddi_get_next_sibling(dip)) {
		if (cpr_suspend_devices(ddi_get_child(dip)))
			return (ENXIO);
		if (!cpr_is_real_device(dip))
			continue;
		CPR_DEBUG(CPR_DEBUG2, "Suspending device %s\n",
		    devi_string(dip, buf));
		ASSERT((DEVI(dip)->devi_cpr_flags & DCF_CPR_SUSPENDED) == 0);

#ifndef __xpv
		i_cpr_save_configuration(dip);
#endif


		if (!i_ddi_devi_attached(dip)) {
			error = DDI_FAILURE;
		} else {
#ifndef __xpv
			if (cpr_test_point != DEVICE_SUSPEND_TO_RAM ||
			    (cpr_test_point == DEVICE_SUSPEND_TO_RAM &&
			    cpr_device == ddi_driver_major(dip))) {
#endif
				error = devi_detach(dip, DDI_SUSPEND);
#ifndef __xpv
			} else {
				error = DDI_SUCCESS;
			}
#endif
		}

		if (error == DDI_SUCCESS) {
			DEVI(dip)->devi_cpr_flags |= DCF_CPR_SUSPENDED;
		}

		else {
			CPR_DEBUG(CPR_DEBUG2,
			    "WARNING: Unable to suspend device %s\n",
			    devi_string(dip, buf));
			cpr_err(CE_WARN, "Unable to suspend device %s.",
			    devi_string(dip, buf));
			cpr_err(CE_WARN, "Device is busy or does not "
			    "support suspend/resume.");
#ifndef __xpv
			/*
			 * the device has failed to suspend however,
			 * if cpr_test_point == FORCE_SUSPEND_TO_RAM
			 * after putting out the warning message above,
			 * we carry on as if suspending the device had
			 * been successful
			 */
			if (cpr_test_point == FORCE_SUSPEND_TO_RAM)
				DEVI(dip)->devi_cpr_flags |= DCF_CPR_SUSPENDED;
			else
#endif
				return (ENXIO);
		}
	}
	return (0);
}

/*
 * Traverse the dev info tree:
 *	Call each device driver in the system via a special case
 *	of the attach() entry point to restore itself.
 *	This is a little tricky because it has to reverse the traversal
 *	order of cpr_suspend_devices().
 */
int
cpr_resume_devices(dev_info_t *start, int resume_failed)
{
	dev_info_t	*dip, *next, *last = NULL;
	int		did_suspend;
	int		error = resume_failed;
	char		buf[CPR_BUFSIZE];

	while (last != start) {
		dip = start;
		next = ddi_get_next_sibling(dip);
		while (next != last) {
			dip = next;
			next = ddi_get_next_sibling(dip);
		}

		/*
		 * cpr is the only one that uses this field and the device
		 * itself hasn't resumed yet, there is no need to use a
		 * lock, even though kernel threads are active by now.
		 */
		did_suspend = DEVI(dip)->devi_cpr_flags & DCF_CPR_SUSPENDED;
		if (did_suspend)
			DEVI(dip)->devi_cpr_flags &= ~DCF_CPR_SUSPENDED;

		/*
		 * Always attempt to restore device configuration before
		 * attempting resume
		 */
#ifndef __xpv
		i_cpr_restore_configuration(dip);
#endif

		/*
		 * There may be background attaches happening on devices
		 * that were not originally suspended by cpr, so resume
		 * only devices that were suspended by cpr. Also, stop
		 * resuming after the first resume failure, but traverse
		 * the entire tree to clear the suspend flag unless the
		 * FORCE_SUSPEND_TO_RAM test point is set.
		 */
#ifndef __xpv
		if (did_suspend && (!error ||
		    cpr_test_point == FORCE_SUSPEND_TO_RAM)) {
#else
		if (did_suspend && !error) {
#endif
			CPR_DEBUG(CPR_DEBUG2, "Resuming device %s\n",
			    devi_string(dip, buf));
			/*
			 * If a device suspended by cpr gets detached during
			 * the resume process (for example, due to hotplugging)
			 * before cpr gets around to issuing it a DDI_RESUME,
			 * we'll have problems.
			 */
			if (!i_ddi_devi_attached(dip)) {
				CPR_DEBUG(CPR_DEBUG2, "WARNING: Skipping "
				    "%s, device not ready for resume\n",
				    devi_string(dip, buf));
				cpr_err(CE_WARN, "Skipping %s, device "
				    "not ready for resume",
				    devi_string(dip, buf));
#ifndef __xpv
			} else if (cpr_test_point != DEVICE_SUSPEND_TO_RAM ||
			    (cpr_test_point == DEVICE_SUSPEND_TO_RAM &&
			    cpr_device == ddi_driver_major(dip))) {
#else
			} else {
#endif
				if (devi_attach(dip, DDI_RESUME) !=
				    DDI_SUCCESS) {
					error = ENXIO;
				}
			}
		}

		if (error == ENXIO) {
			CPR_DEBUG(CPR_DEBUG2,
			    "WARNING: Unable to resume device %s\n",
			    devi_string(dip, buf));
			cpr_err(CE_WARN, "Unable to resume device %s",
			    devi_string(dip, buf));
		}

		error = cpr_resume_devices(ddi_get_child(dip), error);
		last = dip;
	}

	return (error);
}

/*
 * Returns a string which contains device name and address.
 */
static char *
devi_string(dev_info_t *devi, char *buf)
{
	char *name;
	char *address;
	int size;

	name = ddi_node_name(devi);
	address = ddi_get_name_addr(devi);
	size = (name == NULL) ? strlen("<null name>") : strlen(name);
	size += (address == NULL) ? strlen("<null>") : strlen(address);

	/*
	 * Make sure that we don't over-run the buffer.
	 * There are 2 additional characters in the string.
	 */
	ASSERT((size + 2) <= CPR_BUFSIZE);

	if (name == NULL)
		(void) strcpy(buf, "<null name>");
	else
		(void) strcpy(buf, name);

	(void) strcat(buf, "@");
	if (address == NULL)
		(void) strcat(buf, "<null>");
	else
		(void) strcat(buf, address);

	return (buf);
}

/*
 * This function determines whether the given device is real (and should
 * be suspended) or not (pseudo like).  If the device has a "reg" property
 * then it is presumed to have register state to save/restore.
 */
static int
cpr_is_real_device(dev_info_t *dip)
{
	struct regspec *regbuf;
	int length;
	int rc;

	if (ddi_get_driver(dip) == NULL)
		return (0);

	/*
	 * First those devices for which special arrangements have been made
	 */
	if (DEVI(dip)->devi_pm_flags & (PMC_NEEDS_SR|PMC_PARENTAL_SR))
		return (1);
	if (DEVI(dip)->devi_pm_flags & PMC_NO_SR)
		return (0);

	/*
	 * now the general case
	 */
	rc = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&regbuf, &length);
	ASSERT(rc != DDI_PROP_NO_MEMORY);
	if (rc != DDI_PROP_SUCCESS) {
		return (0);
	} else {
		kmem_free((caddr_t)regbuf, length);
		return (1);
	}
}
