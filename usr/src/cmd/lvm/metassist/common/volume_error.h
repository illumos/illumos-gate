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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VOLUME_ERROR_H
#define	_VOLUME_ERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Retrieve the error string for the given error code.
 *
 * @param       error
 *              If error is less than zero, it is assumed to be a
 *              custom error code.  If error is greater than zero, it
 *              is assumed to be an error defined in errno.h.
 *
 * @return      the error string set by volume_set_error()
 *              if error < 0
 *
 * @return      the error string returned by strerror()
 *              if error > 0
 */
extern char *get_error_string(int error);

/*
 * Set the error string for the most recent error.  This message can
 * be retrieved with get_error_string(error), assuming error is less
 * than zero.
 *
 * @param       fmt
 *              printf format string
 *
 * @return      the number of characters formatted
 *              if successful
 *
 * @return      negative value
 *              if an error occurred
 */
extern int volume_set_error(char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_ERROR_H */
