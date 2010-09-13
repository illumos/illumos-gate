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

/* Copyright 2010 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_QL_ISR_H
#define	_QL_ISR_H


/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Spurious interrupts
 */
#define	MAX_SPURIOUS_INTR	4
extern	uint32_t	ql_spurious_cnt;
extern	uint32_t	ql_max_intr_loop;

/*
 * Global Data in ql_isr.c source file.
 */

/*
 * Global Function Prototypes in ql_isr.c source file.
 */
uint_t ql_isr(caddr_t);
uint_t ql_isr_aif(caddr_t, caddr_t);
uint_t ql_isr_default(caddr_t, caddr_t);

#ifdef	__cplusplus
}
#endif

#endif /* _QL_ISR_H */
