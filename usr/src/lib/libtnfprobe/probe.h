/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *      Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _TNF_PROBE_H
#define	_TNF_PROBE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <tnf/writer.h>
#include <sys/tnf_probe.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interface for enabling/disabling tracing for the process.
 */
void tnf_process_disable(void);
void tnf_process_enable(void);

/*
 * Interface for enabling/disabling tracing for the calling thread.
 */
void tnf_thread_disable(void);
void tnf_thread_enable(void);

#ifdef	__cplusplus
}
#endif

#endif /* _TNF_PROBE_H */
