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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FM_DISK_EVENTS_H
#define	_FM_DISK_EVENTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Event class names and payload member name definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/fm/protocol.h>

/*
 * SATA Disk EREPORTS and their Payload members
 */
#define	EREPORT_SATA		FM_EREPORT_CLASS "." FM_ERROR_IO ".sata"

#define	EREPORT_SATA_PREDFAIL	EREPORT_SATA ".predictive-failure"
#define	EV_PAYLOAD_ASC		"additional-sense-code"
#define	EV_PAYLOAD_ASCQ		"additional-sense-code-qualifier"

#define	EREPORT_SATA_OVERTEMP	EREPORT_SATA ".over-temperature"
#define	EV_PAYLOAD_CURTEMP	"current-temp"
#define	EV_PAYLOAD_THRESH	"threshold-temp"

#define	EREPORT_SATA_STFAIL	EREPORT_SATA ".self-test-failure"
#define	EV_PAYLOAD_STCODE	"self-test-result-code"

/*
 * Disk FAULT events
 */
#define	FAULT_DISK		FM_FAULT_CLASS "." FM_ERROR_IO ".disk"
#define	FAULT_DISK_PREDFAIL	FAULT_DISK ".predictive-failure"
#define	FAULT_DISK_OVERTEMP	FAULT_DISK ".over-temperature"
#define	FAULT_DISK_STFAIL	FAULT_DISK ".self-test-failure"

#ifdef __cplusplus
}
#endif

#endif /* _FM_DISK_EVENTS_H */
