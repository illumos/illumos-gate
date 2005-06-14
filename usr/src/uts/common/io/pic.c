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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/pic.h>
#include <sys/sunddi.h>

void
picsetup()
{
	/* initialize master first 				*/
	/* ICW1: Edge-triggered, Cascaded, need ICW4 	*/
	(void) outb(MCMD_PORT, PIC_ICW1BASE|PIC_NEEDICW4);

	/* ICW2: start master vectors at PIC_VECTBASE 		*/
	(void) outb(MIMR_PORT, PIC_VECTBASE);

	/* ICW3: define which lines are connected to slaves 	*/
	(void) outb(MIMR_PORT, 1 << MASTERLINE);

	/* ICW4: buffered master (?), norm eoi, mcs 86 		*/
	(void) outb(MIMR_PORT, PIC_86MODE);

	/* OCW1: Start the master with all interrupts off 	*/
	(void) outb(MIMR_PORT, 0xFF);

	/* OCW3: set master into "read isr mode" 		*/
	(void) outb(MCMD_PORT, PIC_READISR);

	/* initialize the slave 				*/
	/* ICW1: Edge-triggered, Cascaded, need ICW4 	*/
	(void) outb(SCMD_PORT, PIC_ICW1BASE|PIC_NEEDICW4);

	/* ICW2: set base of vectors 				*/
	outb(SIMR_PORT, PIC_VECTBASE +  8);

	/* ICW3: specify ID for this slave 			*/
	outb(SIMR_PORT, MASTERLINE);

	/* ICW4: buffered slave (?), norm eoi, mcs 86 		*/
	outb(SIMR_PORT, PIC_86MODE);

	/* OCW1: set interrupt mask 				*/
	outb(SIMR_PORT, 0xff);

	/* OCW3: set pic into "read isr mode" 			*/
	outb(SCMD_PORT, PIC_READISR);
}
