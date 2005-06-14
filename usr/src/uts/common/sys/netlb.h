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
 * Copyright 1992-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NETLB_H
#define	_NETLB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following ioctls may be implemented by any network driver
 * that provides loopback functionality.
 */
#define	LB_IOC			('U' << 8)
#define	LB_GET_INFO_SIZE	(LB_IOC|0)	/* Get size of loopback info */
#define	LB_GET_INFO		(LB_IOC|1)	/* Get loopback info table   */
#define	LB_GET_MODE		(LB_IOC|2)	/* Get current loopback mode */
#define	LB_SET_MODE		(LB_IOC|3)	/* Set current loopback mode */

/*
 * The 'loopback info' is a table (array) of available loopback modes.
 * Each has a generic type (normal/external/internal), a name (e.g. the
 * speed or style of loopback implemented), and a key value, used in the
 * GET_MODE and SET_MODE commands.
 *
 * So, a loopback-test program could:
 *	open the network device
 *	use the LB_GET_INFO_SIZE ioctl (parameter: &size)
 *		to find the size of the info array
 *	allocate some space for the info array
 *	use the LB_GET_INFO ioctl (parameter: infoptr)
 *		to get the whole info array
 *	search the array for a particular type of loopback (e.g. internal),
 *	or display all the available modes for the user to select one
 *	use the LB_GET_MODE ioctl (parameter: &oldmode)
 *		to get the current mode
 *	use the LB_SET_MODE ioctl (parameter: &newmode)
 *		to set the new mode
 *	perform the test(s)
 *	use the LB_SET_MODE ioctl (parameter: &oldmode)
 *		to restore the new mode
 */

typedef uint32_t lb_info_sz_t;

typedef enum {
	normal,
	external,
	internal
} lb_type_t;

typedef struct _lb_property_t {
	lb_type_t	lb_type;
	char		key[16];
	uint32_t	value;
} lb_property_t, *p_lb_property_t;

#ifdef	__cplusplus
}
#endif

#endif /* _NETLB_H */
