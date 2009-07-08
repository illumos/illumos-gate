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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mtlib.h"
#include <sys/types.h>
#include <libscf.h>
#include <sys/uadmin.h>
#include <unistd.h>
#include <stdlib.h>
#include <zone.h>
#include <thread.h>
#include <dlfcn.h>
#include <atomic.h>

/*
 * Pull in the following three interfaces from libscf without introducing
 * a dependency on it, which since libscf depends on libc would be circular:
 *
 * scf_simple_prop_get
 * scf_simple_prop_next_boolean
 * scf_simple_prop_free
 */
typedef scf_simple_prop_t *(*scf_simple_prop_get_t)(scf_handle_t *,
    const char *, const char *, const char *);
static scf_simple_prop_get_t real_scf_simple_prop_get = NULL;
typedef uint8_t *(*scf_simple_prop_next_boolean_t)(scf_simple_prop_t *);
static scf_simple_prop_next_boolean_t real_scf_simple_prop_next_boolean = NULL;
typedef void (*scf_simple_prop_free_t)(scf_simple_prop_t *);
static scf_simple_prop_free_t real_scf_simple_prop_free = NULL;
static mutex_t scf_lock = DEFAULTMUTEX;

static void
load_scf(void)
{
	void *scf_handle = dlopen("libscf.so.1", RTLD_LAZY);
	scf_simple_prop_get_t scf_simple_prop_get = (scf_handle == NULL)? NULL :
	    (scf_simple_prop_get_t)dlsym(scf_handle, "scf_simple_prop_get");
	scf_simple_prop_next_boolean_t scf_simple_prop_next_boolean =
	    (scf_handle == NULL)? NULL :
	    (scf_simple_prop_next_boolean_t)dlsym(scf_handle,
	    "scf_simple_prop_next_boolean");
	scf_simple_prop_free_t scf_simple_prop_free =
	    (scf_handle == NULL)? NULL :
	    (scf_simple_prop_free_t)dlsym(scf_handle, "scf_simple_prop_free");

	lmutex_lock(&scf_lock);
	if (real_scf_simple_prop_get == NULL ||
	    real_scf_simple_prop_next_boolean == NULL ||
	    real_scf_simple_prop_free == NULL) {
		if (scf_simple_prop_get == NULL)
			real_scf_simple_prop_get = (scf_simple_prop_get_t)(-1);
		else {
			real_scf_simple_prop_get = scf_simple_prop_get;
			scf_handle = NULL;	/* don't dlclose it */
		}
		if (scf_simple_prop_next_boolean == NULL)
			real_scf_simple_prop_next_boolean =
			    (scf_simple_prop_next_boolean_t)(-1);
		else {
			real_scf_simple_prop_next_boolean =
			    scf_simple_prop_next_boolean;
			scf_handle = NULL;	/* don't dlclose it */
		}
		if (scf_simple_prop_free == NULL)
			real_scf_simple_prop_free =
			    (scf_simple_prop_free_t)(-1);
		else {
			real_scf_simple_prop_free = scf_simple_prop_free;
			scf_handle = NULL;	/* don't dlclose it */
		}
		membar_producer();
	}
	lmutex_unlock(&scf_lock);

	if (scf_handle)
		(void) dlclose(scf_handle);
}

static void
check_archive_update(void)
{
	scf_simple_prop_t *prop = NULL;
	boolean_t update_flag = B_FALSE;
	char *fmri = "svc:/system/boot-config:default";
	uint8_t *ret_val = NULL;

	if (real_scf_simple_prop_get == NULL ||
	    real_scf_simple_prop_next_boolean == NULL ||
	    real_scf_simple_prop_free == NULL) {
		load_scf();
	}
	if (real_scf_simple_prop_get == (scf_simple_prop_get_t)(-1) ||
	    real_scf_simple_prop_next_boolean ==
	    (scf_simple_prop_next_boolean_t)(-1) ||
	    real_scf_simple_prop_free == (scf_simple_prop_free_t)(-1)) {
		return;
	}

	prop = real_scf_simple_prop_get(NULL, fmri, "config",
	    "uadmin_boot_archive_sync");
	if (prop) {
		if ((ret_val = real_scf_simple_prop_next_boolean(prop)) !=
		    NULL)
			update_flag = (*ret_val == 0) ? B_FALSE :
			    B_TRUE;
		real_scf_simple_prop_free(prop);
	}

	if (update_flag == B_TRUE)
		(void) system("/sbin/bootadm update-archive");
}

int
uadmin(int cmd, int fcn, uintptr_t mdep)
{
	extern int __uadmin(int cmd, int fcn, uintptr_t mdep);

	if (geteuid() == 0 && getzoneid() == GLOBAL_ZONEID &&
	    (cmd == A_SHUTDOWN || cmd == A_REBOOT)) {
		check_archive_update();
	}

	return (__uadmin(cmd, fcn, mdep));
}
