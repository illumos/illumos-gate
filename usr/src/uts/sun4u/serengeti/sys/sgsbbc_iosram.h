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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SGSBBC_IOSRAM_H
#define	_SYS_SGSBBC_IOSRAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/sgsbbc.h>

/*
 * IOSRAM TOC as laid out for the OS by the SC/POST
 *
 * NB Any changes in the way POST/SC lays out the SRAM
 * must be reflected here.
 */
#define	SBBC_MAX_KEYS		32

#define	SBBC_CONSOLE_KEY	1	/* Solaris Console Buffer */
#define	SBBC_TOD_KEY		2	/* Solaris TOD struct */
#define	SBBC_INTR_SC_KEY	3	/* Solaris -> SC Interrupts reason */
#define	SBBC_SC_INTR_KEY	4	/* SC -> Solaris Interrupts reason */
#define	SBBC_DOMAIN_KEY		5	/* Domain state */
#define	SBBC_KEYSWITCH_KEY	6	/* Keyswitch */
#define	SBBC_MAILBOX_KEY	7	/* Solaris<->SC Mailbox */
#define	SBBC_ENVCTRL_KEY	8	/* environmental data */
#define	SBBC_SC_INTR_ENABLED_KEY	9	/* SC -> Solaris Interrupts */
#define	SBBC_INTR_SC_ENABLED_KEY	10	/* Solaris -> SC  Interrupts */
#define	SBBC_SIGBLCK_KEY	11	/* Signature block */

/*
 * size of the IOSRAM key
 */
#define	KEY_SIZE	8
#define	MAGIC_SIZE	8

typedef struct iosram_key {
	char		key[KEY_SIZE];	/* Key value as defined above */
	uint32_t	size;		/* length of this SRAM chunk */
	uint32_t	offset;		/* Offset from base of SRAM */
} iosram_key_t;

struct iosram_toc {
	char		iosram_magic[MAGIC_SIZE];	/* magic: TOCSRAM */
	uint8_t		resvd;				/* reserved */
	/* sram type: cpu, local io, global io, etc */
	uint8_t		iosram_type;
	uint16_t	iosram_version;			/* structure version */
	uint32_t	iosram_tagno;			/* # of tags used */
	iosram_key_t	iosram_keys[SBBC_MAX_KEYS];
};


/*
 * interrupt related routines
 */
extern int	iosram_reg_intr(uint32_t, sbbc_intrfunc_t, caddr_t,
			uint_t	*, kmutex_t *);
extern int	iosram_unreg_intr(uint32_t);
extern int	iosram_send_intr(uint32_t);

/*
 * IOSRAM read write routines
 */
extern int	iosram_read(int, uint32_t, caddr_t, uint32_t);
extern int	iosram_write(int, uint32_t, caddr_t, uint32_t);

/*
 * Misc routines
 */
extern int	iosram_size(int);

/* cached chosen node_id */
extern pnode_t chosen_nodeid;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGSBBC_IOSRAM_H */
