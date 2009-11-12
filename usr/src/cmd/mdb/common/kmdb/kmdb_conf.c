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

#include <sys/isa_defs.h>
#include <sys/utsname.h>
#include <strings.h>

#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

static const char _mdb_version[] = KMDB_VERSION;

const char *
mdb_conf_version(void)
{
	return (_mdb_version);
}

const char *
mdb_conf_isa(void)
{
#if defined(__sparc)
#if defined(__sparcv9)
	return ("sparcv9");
#else	/* __sparcv9 */
	return ("sparc");
#endif	/* __sparcv9 */
#elif defined(__amd64)
	return ("amd64");
#elif defined(__i386)
	return ("i386");
#else
#error	"unknown ISA"
#endif
}

/*
 * These functions are needed for path evaluation, and must be run prior to
 * target initialization.  The kmdb symbol resolution machinery hasn't been
 * initialized at this point, so we have to rely on the kernel to look up
 * utsname and platform for us.
 */

void
mdb_conf_uname(struct utsname *utsp)
{
	bzero(utsp, sizeof (struct utsname));

	if (kmdb_dpi_get_state(NULL) == DPI_STATE_INIT) {
		struct utsname *utsaddr;

		/*
		 * The kernel is running during DPI initialization, so we'll ask
		 * it to do the lookup.  Our own symbol resolution facilities
		 * won't be available until after the debugger starts.
		 */
		if ((utsaddr = (struct utsname *)kmdb_kdi_lookup_by_name("unix",
		    "utsname")) == NULL) {
			warn("'utsname' symbol is missing from kernel\n");
			(void) strcpy(utsp->sysname, "unknown");
			return;
		}

		bcopy(utsaddr, utsp, sizeof (struct utsname));
	} else
		(void) mdb_tgt_uname(mdb.m_target, utsp);
}

const char *
mdb_conf_platform(void)
{
	if (kmdb_dpi_get_state(NULL) == DPI_STATE_INIT) {
		static char plat[SYS_NMLN];
		caddr_t plataddr;

		/*
		 * The kernel is running during DPI initialization, so we'll ask
		 * it to do the lookup.  Our own symbol resolution facilities
		 * won't be available until after the debugger starts.
		 */
		if ((plataddr = (caddr_t)kmdb_kdi_lookup_by_name("unix",
		    "platform")) == NULL) {
			warn("conf: 'platform' symbol is missing from "
			    "kernel\n");
			return ("unknown");
		}

		(void) strncpy(plat, plataddr, sizeof (plat));
		plat[sizeof (plat) - 1] = '\0';

		return (plat);
	} else
		return (mdb_tgt_platform(mdb.m_target));
}
