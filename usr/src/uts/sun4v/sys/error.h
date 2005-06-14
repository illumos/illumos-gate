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

#ifndef	_ERROR_H
#define	_ERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	CPU_RQ_ENTRIES		64
#define	CPU_NRQ_ENTRIES		64


/*
 * Resumable and Non-resumable queues
 */
#define	CPU_RQ			0x3e
#define	CPU_NRQ			0x3f
#define	Q_ENTRY_SIZE		64
#define	CPU_RQ_SIZE		(CPU_RQ_ENTRIES * Q_ENTRY_SIZE)
#define	CPU_NRQ_SIZE		(CPU_NRQ_ENTRIES * Q_ENTRY_SIZE)

/*
 * Sun4v Error Report error Descriptor describes the type of the error
 */
#define	ERRH_DESC_UNDEFINED	0	/* Undefined */
#define	ERRH_DESC_UCOR_RE	1	/* Uncorrected resumable error */
#define	ERRH_DESC_PR_NRE	2	/* Precise non-resumable error */
#define	ERRH_DESC_DEF_NRE	3	/* Deferred non-resumalbe error */

/*
 * Sun4v Error Report Error Attributes specifies the attributes of the error
 */
#define	ERRH_ATTR_CPU		0x00000001
#define	ERRH_ATTR_MEM		0x00000002
#define	ERRH_ATTR_PIO		0x00000004
#define	ERRH_ATTR_IRF		0x00000008	/* Integer register file */
/* Floating-point register file */
#define	ERRH_ATTR_FRF		0x00000010
#define	ERRH_ATTR_RQF		0x80000000	/* Resumablee Queue Full */

/*
 * For Excution mode
 */
#define	ERRH_MODE_MASK		0x03000000
#define	ERRH_MODE_SHIFT		24
#define	ERRH_MODE_UNKNOWN	0
#define	ERRH_MODE_USER		1
#define	ERRH_MODE_PRIV		2

#ifndef	_ASM
/*
 * For debug print out
 */
#define	ER_SZ_IN_EXT_WORD	(Q_ENTRY_SIZE / sizeof (uint64_t))

/*
 * Sun4v Error Report record
 */
typedef	struct {
	uint64_t	ehdl;		/* Unique error handle */
	uint64_t	stick;		/* Value of the %STICK register */
	uint32_t	desc;		/* Error Descriptor */
	uint32_t	attr;		/* error attributes bit field */
	uint64_t	ra;		/* Real address */
	uint32_t	sz;		/* Size of affected mem region */
	uint16_t	cpuid;		/* Virtual ID of the affected CPU */
} errh_er_t;

typedef struct errh_async_flt {
	struct async_flt 	cmn_asyncflt;	/* common fault structure */
	errh_er_t		errh_er;	/* sun4v er record */
} errh_async_flt_t;

/*
 * Global functions
 */
void mem_scrub(uint64_t, uint64_t);
void errh_cpu_run_bus_error_handlers(struct async_flt *, int);
void error_init(void);
void cpu_async_log_err(void *);
void cpu_ce_log_err(struct async_flt *);
void cpu_ue_log_err(struct async_flt *);
void mem_sync(caddr_t, size_t);

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _ERROR_H */
