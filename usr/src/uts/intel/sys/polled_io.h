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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_POLLED_IO_H
#define	_SYS_POLLED_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct polled_device {
	/*
	 * This lock is only used to lock writing from
	 * the fields on the structure.  The values in the
	 * structure can be read under obp, so the lock
	 * isn't valid then.
	 */
	kmutex_t	polled_device_lock;

	/*
	 * When we switch over the console, this is the old value
	 * so that we can restore it later.
	 */
	uint64_t	polled_old_handle;

	/*
	 * Pointer to registerd polled I/O callbacks.
	 */
	cons_polledio_t	*polled_io;

} polled_device_t;

_NOTE(MUTEX_PROTECTS_DATA(polled_device_t::polled_device_lock,
	polled_device_t))

/*
 * The lower layers did not find any characters.
 */
#define	CIF_NO_CHARACTERS	((uint_t)-2)

/*
 * Every CIF has at least 3 arguments:  0 (name), 1 (in args), and 2 (out args).
 */
#define	CIF_MIN_SIZE		3

#define	CIF_NAME		0	/* name of function */
#define	CIF_NUMBER_IN_ARGS	1	/* number of arguments passed in */
#define	CIF_NUMBER_OUT_ARGS	2	/* number of arguments for return */
#define	CIF_BUFFER_ADDRESS	3	/* address to write data */
#define	CIF_BUFFER_LENGTH	4	/* length of BUFFER_ADDRESS */
#define	CIF_RETURN_VALUE	5	/* return status of operation */


/*
 * This is the size of the structure that we are expecting to be passed
 * in.  This is based on CIF_MIN_SIZE + address + length + value (see above)
 */
#define	CIF_SIZE		6	/* size of cif structure */

/*
 * These are the types of polled I/O that this module handles.
 */
typedef enum polled_io_console_type {
	POLLED_IO_CONSOLE_INPUT = 0,
	POLLED_IO_CONSOLE_OUTPUT = 1
} polled_io_console_type_t;

/*
 * Initialize the polled I/O kernel structures
 */
void	polled_io_init(void);

/*
 * De-initialize the polled I/O kernel structures
 */
void	polled_io_fini(void);

/*
 * Register a device to be used as a console for OBP.
 */
int	polled_io_register_callbacks(cons_polledio_t *, int);

/*
 * Unregister a device to be used as a console for OBP.
 */
int	polled_io_unregister_callbacks(cons_polledio_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_POLLED_IO_H */
