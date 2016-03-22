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

#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/brand.h>

#include <sys/lx_brand.h>
#include <sys/lx_impl.h>


/*
 * These flags are for what Linux calls "bug emulation".
 * (Descriptions from the personality(2) Linux man page.)
 *
 * Flags which are currently actionable in LX:
 * - READ_IMPLIES_EXEC (since Linux 2.6.8)
 *   With this flag set, PROT_READ implies PROT_EXEC for mmap(2).
 *
 * Flags which are current accepted but ignored:
 * - UNAME26 (since Linux 3.1)
 *   Have uname(2) report a 2.6.40+ version number rather than a 3.x version
 *   number.  Added as a stopgap measure to support broken applications that
 *   could not handle the kernel version- numbering switch from 2.6.x to 3.x.
 *
 * - ADDR_NO_RANDOMIZE (since Linux 2.6.12)
 *   With this flag set, disable address-space-layout randomization.
 *
 * - FDPIC_FUNCPTRS (since Linux 2.6.11)
 *   User-space function pointers to signal handlers point (on certain
 *   architectures) to descriptors.
 *
 * - MMAP_PAGE_ZERO (since Linux 2.4.0)
 *   Map page 0 as read-only (to support binaries that depend on this SVr4
 *   behavior).
 *
 * - ADDR_COMPAT_LAYOUT (since Linux 2.6.9)
 *   With this flag set, provide legacy virtual address space layout.
 *
 * - ADDR_LIMIT_32BIT (since Linux 2.2)
 *   Limit the address space to 32 bits.
 *
 * - SHORT_INODE (since Linux 2.4.0)
 *   No effects(?).
 *
 * - WHOLE_SECONDS (since Linux 1.2.0)
 *   No effects(?).
 *
 * - STICKY_TIMEOUTS (since Linux 1.2.0)
 *   With this flag set, select(2), pselect(2), and ppoll(2) do not modify the
 *   returned timeout argument when interrupted by a signal handler.
 *
 * - ADDR_LIMIT_3GB (since Linux 2.4.0)
 *   With this flag set, use 0xc0000000 as the offset at which to search a
 *   virtual memory chunk on mmap(2); otherwise use 0xffffe000.
 */

#define	LX_PER_GET	0xffffffff

long
lx_personality(unsigned int arg)
{
	lx_proc_data_t *lxpd = ptolxproc(curproc);
	unsigned int result = 0;

	mutex_enter(&curproc->p_lock);
	result = lxpd->l_personality;

	if (arg == LX_PER_GET) {
		mutex_exit(&curproc->p_lock);
		return (result);
	}

	/*
	 * Prevent changes to the personality if the process is undergoing an
	 * exec.  This will allow elfexec and friends to manipulate the
	 * personality without hinderance.
	 */
	if ((curproc->p_flag & P_PR_EXEC) != 0) {
		mutex_exit(&curproc->p_lock);
		return (set_errno(EINVAL));
	}

	/*
	 * Keep tabs when a non-Linux personality is set.  This is silently
	 * allowed to succeed, even though the emulation required is almost
	 * certainly missing.
	 */
	if ((arg & LX_PER_MASK) != LX_PER_LINUX) {
		char buf[64];

		(void) snprintf(buf, sizeof (buf), "invalid personality: %02X",
		    arg & LX_PER_MASK);
		lx_unsupported(buf);
	}

	lxpd->l_personality = arg;
	mutex_exit(&curproc->p_lock);
	return (result);
}
