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
 *
 * defines auditd interface for cmd/audit; project private.
 */

#ifndef	_AUDIT_SIG_INFC_H
#define	_AUDIT_SIG_INFC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <signal.h>

/*
 * SMF definitions
 */

#define	AUDITD_FMRI \
	"svc:/system/auditd:default"

/*
 * Signals
 */
#define	AU_SIG_NEXT_DIR		SIGUSR1	/* audit -n */
#define	AU_SIG_READ_CONTROL	SIGHUP	/* audit -s */
#define	AU_SIG_DISABLE		SIGTERM	/* audit -t */

#ifdef __cplusplus
}
#endif

#endif	/* _AUDIT_SIG_INFC_H */
