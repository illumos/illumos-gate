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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CNEX_H
#define	_CNEX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Channel nexus "reg" spec
 */
typedef struct cnex_regspec {
	uint64_t physaddr;
	uint64_t size;
} cnex_regspec_t;

/*
 * Channel nexus interrupt map
 */
struct cnex_intr_map {
	ldc_dev_t	devclass;	/* LDC device class */
	uint32_t	pil;		/* PIL for device class */
	int32_t		weight;		/* Interrupt weight for device class */
};

/*
 * Channel interrupt information
 */
typedef struct cnex_intr {
	uint64_t	ino;		/* dev intr number */
	uint64_t	cpuid;		/* Target CPU */
	uint64_t	icookie;	/* dev intr cookie */
	uint64_t	id;		/* LDC channel ID  */
	dev_info_t	*dip;		/* LDC channel devinfo */
	uint_t		(*hdlr)();	/* intr handler */
	caddr_t		arg1;		/* intr argument 1 */
	caddr_t		arg2;		/* intr argument 2 */
	int32_t		weight;		/* intr weight */
} cnex_intr_t;

/* cnex interrupt types */
typedef enum {
	CNEX_TX_INTR = 1,		/* transmit interrupt */
	CNEX_RX_INTR			/* receive interrupt */
} cnex_intrtype_t;

/*
 * Channel information
 */
typedef struct cnex_ldc {
	kmutex_t	lock;		/* Channel lock */
	struct cnex_ldc	*next;

	uint64_t	id;
	ldc_dev_t 	devclass;	/* Device class channel belongs to */

	cnex_intr_t	tx;		/* Transmit interrupt */
	cnex_intr_t	rx;		/* Receive interrupt */
	dev_info_t	*dip;		/* dip of the associated device */
} cnex_ldc_t;

/*
 * Channel nexus soft state pointer
 */
typedef struct cnex_soft_state {
	dev_info_t 	*devi;
	uint64_t	cfghdl;		/* cnex config handle */
	kmutex_t	clist_lock;	/* lock to protect channel list */
	cnex_ldc_t	*clist;		/* list of registered channels */
} cnex_soft_state_t;

#ifdef __cplusplus
}
#endif

#endif /* _CNEX_H */
