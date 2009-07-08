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


/*
 * Wrapper function to implement reboot w/ arguments on x86
 * platforms. Extract reboot arguments and place them in
 * in a transient entry in /[stub]boot/grub/menu.lst
 * All other commands are passed through.
 */

#include "lint.h"
#include "mtlib.h"
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uadmin.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <zone.h>
#include <libscf.h>
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
static int
legal_arg(char *bargs)
{
	int i;

	for (i = 0; i < BOOTARGS_MAX; i++, bargs++) {
		if (*bargs == 0 && i > 0)
			return (i);
		if (!isprint(*bargs))
			break;
	}
	return (-1);
}

static char quote[] = "\'";

int
uadmin(int cmd, int fcn, uintptr_t mdep)
{
	extern int __uadmin(int cmd, int fcn, uintptr_t mdep);
	char *bargs, cmdbuf[256];
	struct stat sbuf;
	char *altroot;

	bargs = (char *)mdep;

	if (geteuid() == 0 && getzoneid() == GLOBAL_ZONEID &&
	    (cmd == A_SHUTDOWN || cmd == A_REBOOT)) {
		int off = 0;

		switch (fcn) {
		case AD_IBOOT:
		case AD_SBOOT:
		case AD_SIBOOT:
			/*
			 * These functions fabricate appropriate bootargs.
			 * If bootargs are passed in, map these functions
			 * to AD_BOOT.
			 */
			if (bargs == 0) {
				switch (fcn) {
				case AD_IBOOT:
					bargs = "-a";
					break;
				case AD_SBOOT:
					bargs = "-s";
					break;
				case AD_SIBOOT:
					bargs = "-sa";
					break;
				}
			}
			/*FALLTHROUGH*/
		case AD_BOOT:
		case AD_FASTREBOOT:
			if (bargs == 0)
				break;	/* no args */
			if (legal_arg(bargs) < 0)
				break;	/* bad args */

			/* avoid cancellation in system() */
			(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
			    NULL);

			/* check for /stubboot */
			if (stat("/stubboot/boot/grub/menu.lst", &sbuf) == 0) {
				altroot = "-R /stubboot ";
			} else {
				altroot = "";
			}

			if (fcn == AD_FASTREBOOT) {
				char *newarg, *head;
				char bargs_scratch[BOOTARGS_MAX];

				bzero(bargs_scratch, BOOTARGS_MAX);

				bcopy(bargs, bargs_scratch, strlen(bargs));
				head = bargs_scratch;
				newarg = strtok(bargs_scratch, " ");

				if (newarg == NULL || newarg[0] == '-')
					break;

				/* First argument is rootdir */
				if (strncmp(&newarg[strlen(newarg)-4],
				    "unix", 4) != 0) {
					newarg = strtok(NULL, " ");
					off = newarg - head;
				}

				/*
				 * If we are using alternate root via
				 * mountpoint or a different BE, don't
				 * bother to update the temp menu entry.
				 */
				if (off > 0)
					break;
			}

			/* are we rebooting to a GRUB menu entry? */
			if (isdigit(bargs[0])) {
				int entry = strtol(bargs, NULL, 10);
				(void) snprintf(cmdbuf, sizeof (cmdbuf),
				    "/sbin/bootadm set-menu %sdefault=%d",
				    altroot, entry);
			} else {
				(void) snprintf(cmdbuf, sizeof (cmdbuf),
				    "/sbin/bootadm -m update_temp %s"
				    "-o %s%s%s", altroot, quote,
				    &bargs[off], quote);
			}
			(void) system(cmdbuf);
		}
		check_archive_update();
	}

	return (__uadmin(cmd, fcn, mdep));
}
