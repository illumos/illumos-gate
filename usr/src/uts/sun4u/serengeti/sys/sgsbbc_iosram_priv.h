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

#ifndef	_SYS_SGSBBC_IOSRAM_PRIV_H
#define	_SYS_SGSBBC_IOSRAM_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include  <sys/errno.h>
#include <sys/sgsbbc_priv.h>
#include <sys/sgsbbc_iosram.h>

/*
 * The following keys are in I/O SRAM TOC
 * and  used by the OS and SC-APP
 * These are mapped to the numeric values below
 *
 * NB These must be kept in sync with POST/SC keys.
 */
#define	TOCKEY_DOMSTAT	"DOMSTAT"	/* SBBC_DOMAIN_KEY */
#define	TOCKEY_KEYSWPO	"KEYSWPO"	/* SBBC_KEYSWITCH_KEY */
#define	TOCKEY_TODDATA	"TODDATA"	/* SBBC_TOD_KEY */
#define	TOCKEY_SOLCONS	"SOLCONS"	/* SBBC_CONSOLE_KEY */
#define	TOCKEY_SOLMBOX	"SOLMBOX"	/* SBBC_MAILBOX_KEY */
#define	TOCKEY_SOLSCIR	"SOLSCIR"	/* SBBC_INTR_SC_KEY */
#define	TOCKEY_SCSOLIR	"SCSOLIR"	/* SBBC_SC_INTR_KEY */
#define	TOCKEY_ENVINFO	"ENVINFO"	/* SBBC_ENVCTRL_KEY */
/*
 * Interrupts enabled that SC can send to OS
 * read/only for SC
 */
#define	TOCKEY_SOLSCIE	"SOLSCIE"	/* SBBC_SC_INTR_ENABLED_KEY */
/*
 * Interrupts enabled that OS can send to SC
 * read/only for OS
 */
#define	TOCKEY_SCSOLIE	"SCSOLIE"	/* SBBC_INTR_SC_ENABLED_KEY */
/*
 * CPU/Domain signatures block
 */
#define	TOCKEY_SIGBLCK	"SIGBLCK"	/* SBBC_SIGBLCK_KEY */


/*
 * different sram types
 */
#define	CPU_SRAM		1
#define	LOCAL_IO_SRAM		2
#define	GLOBAL_IO_SRAM		3
#define	WCI_SRAM		4

#define	INVALID_KEY(tunnel, x)  (tunnel->tunnel_keys[(x)].key == 0)

/*
 * Macros used for version checking
 * The SBBC driver will check the major version number in the IOSRAM
 * TOC entry.  If the major version number in the TOC entry is larger
 * than the maximum number Solaris supports, Solaris will panic.
 */
#define	IOSRAM_TOC_VER_SHIFT	0x8	/* top 8 bit for major */
#define	IOSRAM_TOC_VER_MASK	0xff	/* 8-bit for major, 8-bit for minor */

/*
 * IOSRAM/TOC propertes on chosen node
 */
#define	IOSRAM_CHOSEN_PROP	"iosram"
#define	IOSRAM_TOC_PROP		"iosram-toc"

typedef struct tunnel_key {
	int			key;
	caddr_t			base;	/* VA of this tunnel SRAM area */
	int			size;
	ddi_acc_handle_t	reg_handle;
} tunnel_key_t;

typedef struct tunnel {
	tunnel_key_t	tunnel_keys[SBBC_MAX_KEYS];
} tunnel_t;

struct chosen_iosram {
	/*
	 * Global IOSRAM lock
	 */
	kmutex_t	iosram_lock;
	/*
	 * Tunnel lock to synchronize IOSRAM access
	 */
	krwlock_t	tunnel_lock;
	/*
	 * 'chosen' SBBC
	 */
	sbbc_softstate_t *iosram_sbbc;
	sbbc_softstate_t *sgsbbc;	/* cross reference */

	/*
	 * pointer to an array of SBBC_MAX_KEYS tunnel entries
	 */
	tunnel_t	*tunnel;
	/*
	 * interrupt handlers
	 */
	sbbc_intrs_t	intrs[SBBC_MAX_INTRS];
};


extern void	iosram_init(void);
extern void	iosram_fini(void);
extern int	sgsbbc_iosram_is_chosen(sbbc_softstate_t *);

/*
 * tunnel switch related routines
 */
extern int	iosram_tunnel_init(sbbc_softstate_t *);
extern int	sgsbbc_iosram_switchfrom(sbbc_softstate_t *);
extern int	iosram_switch_tunnel(int);

extern struct chosen_iosram *master_iosram;
extern struct sbbc_softstate *sgsbbc_instances;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGSBBC_IOSRAM_PRIV_H */
