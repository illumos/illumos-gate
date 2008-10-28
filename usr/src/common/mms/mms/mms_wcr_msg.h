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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__MMS_WCR_MSG_H
#define	__MMS_WCR_MSG_H


#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	WCR_MSG
#define	WCR_MSG(n, s)
#endif

/* Watcher Messages 8000-8999 */

#define	WCR_8000_MSG 8000
WCR_MSG(WCR_8000_MSG, gettext("Conflicting ssi configuration on $wcr_host$, " \
	"Same SSI port configured for different ACSLS libraries: $lmname1$ " \
	"$ssiport1$ $ssihost1$, $lmname2$ $ssiport2$ $ssihost2$"))

#define	WCR_8001_MSG 8001
WCR_MSG(WCR_8001_MSG, gettext("Error starting SSI, check that the path " \
	"$ssipath$ is correct and use cpstop/cpstart to restart the lm " \
	"service"))

#ifdef	__cplusplus
}
#endif

#endif	/* __MMS_WCR_MSG_H */
