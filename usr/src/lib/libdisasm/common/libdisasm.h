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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2015 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 * Copyright 2018, Joyent, Inc.
 */

#ifndef	_LIBDISASM_H
#define	_LIBDISASM_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dis_handle dis_handle_t;

#define	DIS_DEFAULT		0x0

/* SPARC disassembler flags */
#define	DIS_SPARC_V8		0x001
#define	DIS_SPARC_V9		0x002
#define	DIS_SPARC_V9_SGI	0x004
#define	DIS_SPARC_V9_OPL	0x008

/* x86 diassembler flags */
#define	DIS_X86_SIZE16		0x100
#define	DIS_X86_SIZE32		0x010
#define	DIS_X86_SIZE64		0x020

/* s390 disassembler flags */
#define	DIS_S370		0x200
#define	DIS_S390_31		0x400
#define	DIS_S390_64		0x800

/* risc-v disassembler flags */
#define	DIS_RISCV_32		0x2000
#define	DIS_RISCV_64		0x4000

/* generic disassembler flags */
#define	DIS_OCTAL		0x040
#define	DIS_NOIMMSYM		0x080

#define	DIS_ARCH_MASK		(DIS_SPARC_V8 | \
		DIS_SPARC_V9 | DIS_SPARC_V9_SGI | DIS_SPARC_V9_OPL | \
		DIS_X86_SIZE16 | DIS_X86_SIZE32 | DIS_X86_SIZE64 | \
		DIS_S370 | DIS_S390_31 | DIS_S390_64 | DIS_RISCV_32 | \
		DIS_RISCV_64)

typedef int (*dis_lookup_f)(void *, uint64_t, char *, size_t, uint64_t *,
    size_t *);
typedef int (*dis_read_f)(void *, uint64_t, void *, size_t);

extern dis_handle_t *dis_handle_create(int, void *, dis_lookup_f, dis_read_f);
extern void dis_handle_destroy(dis_handle_t *);

extern int dis_disassemble(dis_handle_t *, uint64_t, char *, size_t);
extern uint64_t dis_previnstr(dis_handle_t *, uint64_t, int n);
extern void dis_set_data(dis_handle_t *, void *);
extern void dis_flags_set(dis_handle_t *, int f);
extern void dis_flags_clear(dis_handle_t *, int f);
extern int dis_max_instrlen(dis_handle_t *);
extern int dis_min_instrlen(dis_handle_t *);
extern int dis_instrlen(dis_handle_t *, uint64_t);

/* libdisasm errors */
#define	E_DIS_NOMEM		1	/* Out of memory */
#define	E_DIS_INVALFLAG		2	/* Invalid flag for this architecture */
#define	E_DIS_UNSUPARCH		3	/* Unsupported architecture */

extern int dis_errno(void);
extern const char *dis_strerror(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDISASM_H */
