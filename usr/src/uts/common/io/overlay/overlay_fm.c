/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Overlay device FMA operations.
 *
 * For more information, see the big theory statement in
 * uts/common/io/overlay/overlay.c
 */

#include <sys/ddifm.h>
#include <sys/overlay_impl.h>

kmutex_t overlay_fm_lock;
uint_t overlay_fm_count;

void
overlay_fm_init(void)
{
	overlay_fm_count = 0;
	mutex_init(&overlay_fm_lock, NULL, MUTEX_DRIVER, NULL);
}

void
overlay_fm_fini(void)
{
	VERIFY(overlay_fm_count == 0);
	mutex_destroy(&overlay_fm_lock);
}

void
overlay_fm_degrade(overlay_dev_t *odd, const char *msg)
{
	mutex_enter(&overlay_fm_lock);
	mutex_enter(&odd->odd_lock);

	if (msg != NULL)
		(void) strlcpy(odd->odd_fmamsg, msg, OVERLAY_STATUS_BUFLEN);

	if (odd->odd_flags & OVERLAY_F_DEGRADED)
		goto out;

	odd->odd_flags |= OVERLAY_F_DEGRADED;
	overlay_fm_count++;
	if (overlay_fm_count == 1) {
		ddi_fm_service_impact(overlay_dip, DDI_SERVICE_DEGRADED);
	}
out:
	mutex_exit(&odd->odd_lock);
	mutex_exit(&overlay_fm_lock);
}

void
overlay_fm_restore(overlay_dev_t *odd)
{
	mutex_enter(&overlay_fm_lock);
	mutex_enter(&odd->odd_lock);
	if (!(odd->odd_flags & OVERLAY_F_DEGRADED))
		goto out;

	odd->odd_fmamsg[0] = '\0';
	odd->odd_flags &= ~OVERLAY_F_DEGRADED;
	overlay_fm_count--;
	if (overlay_fm_count == 0) {
		ddi_fm_service_impact(overlay_dip, DDI_SERVICE_RESTORED);
	}
out:
	mutex_exit(&odd->odd_lock);
	mutex_exit(&overlay_fm_lock);
}
