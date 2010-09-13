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

#ifndef _SYS_XPV_SYSCTL_H
#define	_SYS_XPV_SYSCTL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header file defines things needed for access to sysctl(),
 * domctl(), and other API features that are only used by userspace
 * upstream.  On Solaris, due to privcmd and a couple of other uses, we
 * need them in the kernel, so isolate their use to this file.
 */

#define	__XEN_TOOLS__

#include <sys/hypervisor.h>
#include <xen/public/sysctl.h>
#include <xen/public/xsm/acm_ops.h>


#if !defined(__GNUC__) && defined(__i386__)
#define	set_xen_guest_handle_u(hnd, val)  do { (hnd).u.p = val; } while (0)
#define	get_xen_guest_handle_u(val, hnd)  do { val = (hnd).u.p; } while (0)
#else
#define	set_xen_guest_handle_u(hnd, val)  do { (hnd).p = val; } while (0)
#define	get_xen_guest_handle_u(val, hnd)  do { val = (hnd).p; } while (0)
#endif

extern long HYPERVISOR_xsm_op(struct xen_acmctl *);
extern long HYPERVISOR_sysctl(xen_sysctl_t *);
extern long HYPERVISOR_domctl(xen_domctl_t *domctl);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XPV_SYSCTL_H */
