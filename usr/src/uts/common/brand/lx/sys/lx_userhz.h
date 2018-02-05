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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _LX_USERHZ_H
#define	_LX_USERHZ_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Within the kernel, Linux implements an internal hz that they refer to as a
 * "jiffy". Linux can be built with different hz, but on modern kernels
 * it is frequently 250. However, Linux has a separate concept for the hz
 * that is visible outside the kernel. This is called "USER_HZ" and is the
 * value returned by 'sysconf(_SC_CLK_TCK)'. This is almost universally set to
 * 100hz. Some (lazy) applications just hardcode 100hz instead of checking.
 * To accommodate these broken applications, we always work with a USER_HZ of
 * 100 and scale accordingly. See the Linux time(7) man page for a more
 * detailed discussion of their behavior. See the comment in our
 * uts/common/conf/param.c for a discussion of valid native hz values.
 *
 * There are a few interfaces which expose a clock_t to user-land and which
 * need to be considered for USER_HZ adjustment.
 * 1) The times(2) syscall. This is handled correctly.
 * 2) The waitid(2) syscall passes a siginfo_t which contains si_stime and
 *    si_utime. Testing waitid(2) on various Linux distributions shows that the
 *    these fields are garbage. This aligns with the Linux waitid(2) man page,
 *    which describes the subset of the siginfo_t structure that is populated.
 *    Neither si_stime or si_utime are listed.
 * 3) A sigaction(2) handler can pass a siginfo_t. This is only documented to
 *    occur when the sa_flags is SA_SIGINFO. The si_stime and si_utime are
 *    documented to only be populated when the signal is SIGCHLD. However,
 *    testing on Linux seems to show that these fields are not consistent
 *    with the corresponding times(2) data for the process, even for the
 *    SIGCHLD sigaction handler case.
 * 4) Some fields in /proc/stat and /proc/pid/stat. See the Linux proc man
 *    page for references to sysconf(_SC_CLK_TCK).
 *
 * Although the siginfo_t si_stime and si_utime data for cases #2 and #3 is not
 * consistent on Linux, we populate these fields correctly to be on the safe
 * side.
 */
extern uint_t lx_hz_scale;
#define	LX_USERHZ		100
#define	HZ_TO_LX_USERHZ(x)	((x) / lx_hz_scale)

#ifdef __cplusplus
}
#endif

#endif /* _LX_USERHZ_H */
