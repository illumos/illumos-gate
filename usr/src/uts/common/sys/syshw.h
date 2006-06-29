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

#ifndef _SYS_SYSHW_H
#define	_SYS_SYSHW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * syshw.h:	Declarations for the common miscellaneous system hardware
 *		interface.
 */

#define	SYSHW_IDSTR_LEN	43

/*
 * Generic ioctls
 */
typedef enum {
    SYSHW_GET_ITEM = 0,	/* Retrieve item information */
    SYSHW_GET_ITEM_MAXVALUES,	/* Retrieve item Maximium values */
    SYSHW_SET_ITEM,	/* Set item values (SH_CONTROL type only) */
    SYSHW_EVREG,	/* Register for events */
    SYSHW_EVUNREG,	/* Unregister for events */
    SYSHW_CHKEV,	/* Check events. */
    SYSHW_ESCAPE	/* Module specific */
} syshw_ioctl_t;

/*
 * Response fields
 */
typedef enum {
    SH_SWITCH = 0,		/* A switch */
    SH_CONNECTION,		/* A connection */
    SH_POWER,			/* A powersource thing */
    SH_SOUND,			/* An audio thing */
    SH_VISUAL,			/* A visual thing */
    SH_ENV			/* An environment thing */
} syshw_item_type_t;

typedef struct {
    uchar_t		hw_id;
    char		id_string[SYSHW_IDSTR_LEN];
    syshw_item_type_t	type;		/* Item type */
    uint_t		capabilities;	/* Capability flags */
    boolean_t		state;		/* On/Off or Connected/Disconnected.. */
    int			values[4];	/* Free form item dependant values */
} syshw_t;

/*
 * Bits for the syshw_t capability flags field. Note that you can use
 * i = 1 -> 3;  SYSHW_VAL0_VALID << i, to get the other 3 bits.
 */
#define	SYSHW_CAN_SIGNAL_CHANGE		0x0001
#define	SYSHW_STATE_VALID		0x0010
#define	SYSHW_VAL0_VALID		0x0100
#define	SYSHW_VAL1_VALID		0x0200
#define	SYSHW_VAL2_VALID		0x0400
#define	SYSHW_VAL3_VALID		0x0800
#define	SYSHW_STATE_MODIFY		0x0020
#define	SYSHW_VAL0_MODIFY		0x1000
#define	SYSHW_VAL1_MODIFY		0x2000
#define	SYSHW_VAL2_MODIFY		0x4000
#define	SYSHW_VAL3_MODIFY		0x8000

typedef struct hwev_client {
    uint_t		events;			/* Pending event flags, this */
						/* is a bit per hw_id number. */
    int			event_sig;		/* SIGUSR1, SIGUSR2.. */
} hwev_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSHW_H */
