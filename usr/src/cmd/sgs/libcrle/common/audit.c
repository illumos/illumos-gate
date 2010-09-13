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

/* LINTLIBRARY */

#include	<link.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<strings.h>
#include	<limits.h>
#include	"rtld.h"
#include	"_crle.h"
#include	"msg.h"

/*
 * This file provides the LD_AUDIT interfaces for libcrle.so.1, which are
 * called for one of two reasons:
 *
 * CRLE_AUD_DEPENDS
 *		under this mode, the dependencies of the application are
 *		gathered (similar to ldd(1)) and written back to the calling
 *		process.
 *
 * CRLE_AUD_DLDUMP
 *		under this mode, the LD_CONFIG file is read to determine which
 *		objects are to be dldump()'ed. The memory range occupied by
 *		the dumped images is written back to the calling process.
 *
 * Both of these interfaces are invoked via the crle(1) calling process.  The
 * following environment variables are used to communicate between the two:
 *
 * CRLE_FD	the file descriptor on which to communicate to the calling
 *		process (used for CRLE_AUD_DEPENDS and CRLE_AUD_DUMP).
 *
 * CRLE_FLAGS 	this signals CRLE_AUD_DLDUMP mode, and indicates the required
 *		flags for the dldump(3x) calls.
 */

static int	auflag;

int		pfd;
int		dlflag = RTLD_CONFSET;

/*
 * Initial audit handshake, establish audit mode.
 */
uint_t
/* ARGSUSED */
la_version(uint_t version)
{
	char	*str;

	/*
	 * Establish the file desciptor to communicate with the calling process,
	 * If there are any errors terminate the process.
	 */
	if ((str = getenv(MSG_ORIG(MSG_ENV_AUD_FD))) == NULL)
		exit(1);
	pfd = atoi(str);

	/*
	 * Determine which audit mode is required based on the existance of
	 * CRLE_FLAGS.
	 */
	if ((str = getenv(MSG_ORIG(MSG_ENV_AUD_FLAGS))) == NULL) {
		auflag = CRLE_AUD_DEPENDS;
	} else {
		auflag = CRLE_AUD_DLDUMP;
		dlflag |= atoi(str);

		/*
		 * Fill any memory holes before anything gets mapped.
		 */
		if (filladdr() != 0)
			exit(1);
	}

	/*
	 * We need the audit interface containing la_objfilter().
	 */
	return (LAV_VERSION3);
}

/*
 * Audit interface called for each dependency.  If in CRLE_AUD_DEPENDS mode,
 * return each dependency of the primary link-map to the caller.
 */
uint_t
/* ARGSUSED2 */
la_objopen(Link_map * lmp, Lmid_t lmid, uintptr_t *cookie)
{
	if (auflag == CRLE_AUD_DLDUMP)
		return (0);

	if ((lmid == LM_ID_BASE) &&
	    !(FLAGS(LINKMAP_TO_RTMAP(lmp)) & FLG_RT_ISMAIN)) {
		char	buffer[PATH_MAX];

		(void) snprintf(buffer, PATH_MAX, MSG_ORIG(MSG_AUD_DEPEND),
		    lmp->l_name);
		(void) write(pfd, buffer, strlen(buffer));
		*cookie = (uintptr_t)lmp->l_name;
	} else
		*cookie = (uintptr_t)0;

	return (0);
}

/*
 * Audit interface called for any filter/filtee pairs.  If in CRLE_AUD_DEPENDS
 * mode, return the filter/filtee association to the caller.
 */
int
/* ARGSUSED2 */
la_objfilter(uintptr_t *fltrcook, const char *fltestr, uintptr_t *fltecook,
    uint_t flags)
{
	if (auflag == CRLE_AUD_DLDUMP)
		return (0);

	if (*fltrcook && *fltestr && *fltecook) {
		char	buffer[PATH_MAX];

		(void) snprintf(buffer, PATH_MAX, MSG_ORIG(MSG_AUD_FILTER),
		    (char *)(*fltrcook), fltestr, (char *)(*fltecook));
		(void) write(pfd, buffer, strlen(buffer));
	}
	return (1);
}

/*
 * Audit interface called before transfer of control to application.  If in
 * CRLE_AUD_DLDUMP mode read the configuration file and dldump() all necessary
 * objects.
 */
void
/* ARGSUSED */
la_preinit(uintptr_t *cookie)
{
	if (auflag == CRLE_AUD_DLDUMP) {
		if (dumpconfig() != 0)
			exit(1);
	}
	exit(0);
}
