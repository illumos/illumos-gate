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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PCSER_REG_H
#define	_PCSER_REG_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Register offset definitions
 */
#define	PCSER_REGS_RBRTHR	0x00	/* Rx/Tx buffer */
#define	PCSER_REGS_IER		0x01	/* interrupt enable register */
#define	PCSER_REGS_IIR		0x02	/* interrupt identification register */
#define	PCSER_REGS_LCR		0x03	/* line control register */
#define	PCSER_REGS_MCR		0x04	/* modem control register */
#define	PCSER_REGS_LSR		0x05	/* line status register */
#define	PCSER_REGS_MSR		0x06	/* modem status register */
#define	PCSER_REGS_SCR		0x07	/* scratch pad register */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCSER_REG_H */
