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
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Two privilege sets are maintained. One which is the minimal privileges
 * necessary to run bhyve - 'bhyve_priv_min' - and one which is the maximum
 * privileges required - 'bhyve_priv_max'. This second set starts off identical
 * to the first, and is added to by modules during initialisation depending on
 * their requirements and their configuration.
 * Once all modules are initialised, and before the VM is set running, the
 * privileges are locked by setting the 'Permitted' privilege set from the
 * contents of the maximum set, which is now the upper bound, and dropping back
 * to the minimum set.
 *
 * Privileges are process wide, and this framework does not support threaded
 * access. The ID of the thread that first initialises privileges is recorded,
 * and all subsequent privilege operations must be done by the same thread.
 */

#include <err.h>
#include <pthread.h>
#include <priv.h>
#include <stdlib.h>
#include <string.h>
#include <upanic.h>
#include <sys/debug.h>
#include "config.h"
#include "debug.h"
#include "privileges.h"

static pthread_t priv_thread;
static priv_set_t *bhyve_priv_init;
static priv_set_t *bhyve_priv_min;
static priv_set_t *bhyve_priv_max;
static bool priv_debug = false;

#define	DPRINTF(params) \
    if (priv_debug) do { PRINTLN params; fflush(stdout); } while (0)

static void
illumos_priv_printset(const char *tag, priv_set_t *set)
{
	char *s;

	s = priv_set_to_str(set, ',', PRIV_STR_LIT);
	if (s == NULL) {
		warn("priv_set_to_str(%s) failed", tag);
		return;
	}
	DPRINTF((" + %s: %s", tag, s));
	free(s);
}

void
illumos_priv_reduce(void)
{
	VERIFY3S(pthread_equal(pthread_self(), priv_thread), !=, 0);
	DPRINTF((" + Reducing privileges to minimum"));
	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, bhyve_priv_min) != 0)
		err(4, "failed to reduce privileges");
}

static void
illumos_priv_add_set(priv_set_t *set, const char *priv, const char *src)
{
	VERIFY3S(pthread_equal(pthread_self(), priv_thread), !=, 0);
	DPRINTF((" + Adding privilege %s (%s)", priv, src));
	if (!priv_ismember(bhyve_priv_init, priv))
		errx(4, "Privilege %s (for %s) not in initial set", priv, src);
	if (priv_addset(set, priv) != 0)
		err(4, "Failed to add %s privilege for %s", priv, src);
}
void
illumos_priv_add(const char *priv, const char *src)
{
	illumos_priv_add_set(bhyve_priv_max, priv, src);
}

void
illumos_priv_add_min(const char *priv, const char *src)
{
	illumos_priv_add_set(bhyve_priv_min, priv, src);
	illumos_priv_add_set(bhyve_priv_max, priv, src);
}

void
illumos_priv_init(void)
{
	priv_debug = get_config_bool_default("privileges.debug", false);

	DPRINTF((" + Initialising privileges."));

	if (priv_debug)
		(void) setpflags(PRIV_DEBUG, 1);

	priv_thread = pthread_self();

	if ((bhyve_priv_init = priv_allocset()) == NULL)
		err(4, "failed to allocate memory for initial priv set");
	if ((bhyve_priv_min = priv_allocset()) == NULL)
		err(4, "failed to allocate memory for minimum priv set");
	if ((bhyve_priv_max = priv_allocset()) == NULL)
		err(4, "failed to allocate memory for maximum priv set");

	if (getppriv(PRIV_EFFECTIVE, bhyve_priv_init) != 0)
		err(4, "failed to fetch current privileges");

	if (priv_debug)
		illumos_priv_printset("initial", bhyve_priv_init);

	/*
	 * file_read is left in the minimum set to allow for lazy library
	 * loading.
	 */
	priv_basicset(bhyve_priv_min);
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_FILE_LINK_ANY));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_FILE_WRITE));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_NET_ACCESS));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_PROC_EXEC));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_PROC_FORK));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_PROC_INFO));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_PROC_SECFLAGS));
	VERIFY0(priv_delset(bhyve_priv_min, PRIV_PROC_SESSION));

	priv_intersect(bhyve_priv_init, bhyve_priv_min);
	priv_copyset(bhyve_priv_min, bhyve_priv_max);

	/*
	 * These are privileges that we know will always be needed.
	 * Other privileges may be added by modules as necessary during
	 * initialisation.
	 */

	illumos_priv_add(PRIV_FILE_WRITE, "init");

	/*
	 * bhyve can work without proc_clock_highres so don't enforce that
	 * it is present.
	 */
	if (priv_ismember(bhyve_priv_init, PRIV_PROC_CLOCK_HIGHRES))
		illumos_priv_add_min(PRIV_PROC_CLOCK_HIGHRES, "init");
	else
		warnx("The 'proc_clock_highres' privilege is not available");
}

void
illumos_priv_lock(void)
{
	VERIFY3S(pthread_equal(pthread_self(), priv_thread), !=, 0);

	if (bhyve_priv_init == NULL) {
		const char *msg = "attempted to re-lock privileges";
		upanic(msg, strlen(msg));
	}

	priv_intersect(bhyve_priv_init, bhyve_priv_max);

	if (priv_debug) {
		DPRINTF((" + Locking privileges"));

		illumos_priv_printset("min", bhyve_priv_min);
		illumos_priv_printset("max", bhyve_priv_max);
	}

	if (setppriv(PRIV_SET, PRIV_PERMITTED, bhyve_priv_max) != 0) {
		const char *fail = "failed to reduce permitted privileges";
		upanic(fail, strlen(fail));
	}

	if (setppriv(PRIV_SET, PRIV_LIMIT, bhyve_priv_max) != 0) {
		const char *fail = "failed to reduce limit privileges";
		upanic(fail, strlen(fail));
	}

	illumos_priv_reduce();

	priv_freeset(bhyve_priv_init);
	bhyve_priv_init = NULL;
}
