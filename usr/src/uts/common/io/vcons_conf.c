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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/ddi_impldefs.h>
#include <sys/zone.h>
#include <sys/thread.h>
#ifdef DEBUG
#include <sys/strlog.h>
#endif

#include <sys/consdev.h>
#include <sys/console.h>
#include <sys/wscons.h>
#include <sys/vt_impl.h>
#include <sys/note.h>
#include <sys/avl.h>

/* set if console driver is attached */
dev_info_t *wc_dip = NULL;
/* active virtual console minor number */
minor_t vc_active_console = VT_MINOR_INVALID;
/* vc_state_t AVL tree */
avl_tree_t vc_avl_root;
/* virtual console global lock */
kmutex_t vc_lock;

_NOTE(MUTEX_PROTECTS_DATA(vc_lock, wc_dip vc_avl_root vc_active_console))

/*
 * Called from vt devname part. Checks if dip is attached. If it is,
 * return its major number.
 */
major_t
vt_wc_attached(void)
{
	major_t maj = (major_t)-1;

	mutex_enter(&vc_lock);

	if (wc_dip)
		maj = ddi_driver_major(wc_dip);

	mutex_exit(&vc_lock);

	return (maj);
}

void
vt_getactive(char *buf, int buflen)
{
	ASSERT(buf);
	ASSERT(buflen != 0);

	mutex_enter(&vc_lock);

	if (vc_active_console == 0 || vc_active_console == VT_MINOR_INVALID)
		(void) snprintf(buf, buflen, "/dev/console");
	else
		(void) snprintf(buf, buflen, "%d", vc_active_console);

	mutex_exit(&vc_lock);
}

boolean_t
vt_minor_valid(minor_t minor)
{
	if (consmode == CONS_FW) {
		if (minor == 0)
			return (B_TRUE);

		return (B_FALSE);
	}

	mutex_enter(&vc_lock);
	if (minor < VC_INSTANCES_COUNT) {
		mutex_exit(&vc_lock);
		return (B_TRUE);
	}

	mutex_exit(&vc_lock);
	return (B_FALSE);

}
