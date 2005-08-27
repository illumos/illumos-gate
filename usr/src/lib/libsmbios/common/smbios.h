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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SMBIOS_H
#define	_SMBIOS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/smbios.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file defines the interfaces available from the SMBIOS access
 * library, libsmbios, and an equivalent kernel module.  This API can be used
 * to access DMTF SMBIOS data from a device, file, or raw memory buffer.
 * This is NOT yet a public interface, although it may eventually become one in
 * the fullness of time after we gain more experience with the interfaces.
 *
 * In the meantime, be aware that any program linked with this API in this
 * release of Solaris is almost guaranteed to break in the next release.
 *
 * In short, do not user this header file or these routines for any purpose.
 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SMBIOS_H */
