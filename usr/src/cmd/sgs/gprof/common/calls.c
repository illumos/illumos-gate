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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"gprof.h"

/*
 *	a namelist entry to be the child of indirect calls
 */
nltype	indirectchild = {
	"(*)",				/* the name */
	&modules,			/* module [-c only for prog txtspace] */
	(pctype)0,			/* the pc entry point */
	(pctype)0,			/* aligned entry point */
	(unsigned long)0,		/* function size */
	(unsigned char)0,		/* symbol information */
	(size_t)0,			/* ticks in this routine */
	(double)0.0,			/* ticks in this routine (as double) */
	(double)0.0,			/* cumulative ticks in children */
	(long)0,			/* how many times called */
	(long)0,			/* how many calls to self */
	(double)1.0,			/* propagation fraction */
	(double)0.0,			/* self propagation time */
	(double)0.0,			/* child propagation time */
	(bool)0,			/* print flag */
	(int)0,				/* index in the graph list */
	(int)0,				/* graph call chain top-sort order */
	(int)0,				/* internal number of cycle on */
	(struct nl *)&indirectchild,	/* pointer to head of cycle */
	(struct nl *)0,			/* pointer to next member of cycle */
	(arctype *)0,			/* list of caller arcs */
	(arctype *)0, 			/* list of callee arcs */
	(unsigned long)0		/* number of callers */
};

void
findcalls(nltype *parentp, pctype p_lowpc, pctype p_highpc)
{
	unsigned long 	instructp;
	sztype		length;
	nltype		*childp;
	pctype		destpc;

	if (textspace == 0) {
		return;
	}
	if (p_lowpc > s_highpc)
		return;
	if (p_highpc < s_lowpc)
		return;
	if (p_lowpc < s_lowpc)
		p_lowpc = s_lowpc;
	if (p_highpc > s_highpc)
		p_highpc = s_highpc;

#ifdef DEBUG
	if (debug & CALLSDEBUG) {
	    printf("[findcalls] %s: 0x%llx to 0x%llx\n",
		    parentp->name, p_lowpc, p_highpc);
	}
#endif /* DEBUG */

	length = 4;
	for (instructp = (uintptr_t)textspace + p_lowpc -  TORIGIN;
	    instructp < (uintptr_t)textspace + p_highpc - TORIGIN;
	    instructp += length) {

		switch (OP(instructp)) {
		case CALL:
			/*
			 *	May be a call, better check it out.
			 */
#ifdef DEBUG
			if (debug & CALLSDEBUG) {
				printf("[findcalls]\t0x%x:call\n",
				    PC_VAL(instructp));
			}
#endif /* DEBUG */
			destpc = (DISP30(instructp) << 2) + PC_VAL(instructp);
			break;

		case FMT3_0x10:
			if (OP3(instructp) != JMPL)
				continue;

#ifdef DEBUG
			if (debug & CALLSDEBUG)
				printf("[findcalls]\t0x%x:jmpl",
				    PC_VAL(instructp));
#endif /* DEBUG */
			if (RD(instructp) == R_G0) {
#ifdef DEBUG
				if (debug & CALLSDEBUG) {
					switch (RS1(instructp)) {
					case R_O7:
						printf("\tprobably a RETL\n");
						break;
					case R_I7:
						printf("\tprobably a RET\n");
						break;
					default:
						printf(", but not a call: "
						    "linked to g0\n");
					}
				}
#endif /* DEBUG */
				continue;
			}
#ifdef DEBUG
			if (debug & CALLSDEBUG) {
				printf("\toperands are DST = R%d,\tSRC = R%d",
				    RD(instructp), RS1(instructp));
			}
#endif /* DEBUG */
			if (IMMED(instructp)) {
#ifdef DEBUG
				if (debug & CALLSDEBUG) {
					if (SIMM13(instructp) < 0) {
						printf(" - 0x%x\n",
						    -(SIMM13(instructp)));
					} else {
						printf(" + 0x%x\n",
						    SIMM13(instructp));
					}
				}
#endif /* DEBUG */
				switch (RS1(instructp)) {
				case R_G0:
					/*
					 * absolute address, simm 13
					 */
					destpc = SIMM13(instructp);
					break;
				default:
					/*
					 * indirect call
					 */
					addarc(parentp, &indirectchild, 0);
					continue;
				}
			} else {
				/*
				 * two register sources, all cases are indirect
				 */
#ifdef DEBUG
				if (debug & CALLSDEBUG) {
					printf(" + R%d\n", RS2(instructp));
				}
#endif /* DEBUG */
				addarc(parentp, &indirectchild, 0);
				continue;
			}
			break;
		default:
			continue;
		}

		/*
		 *	Check that the destination is the address of
		 *	a function; this allows us to differentiate
		 *	real calls from someone trying to get the PC,
		 *	e.g. position independent switches.
		 */
		if (destpc >= s_lowpc && destpc <= s_highpc) {

			childp = nllookup(&modules, destpc, NULL);
#ifdef DEBUG
			if (debug & CALLSDEBUG) {
				printf("[findcalls]\tdestpc 0x%llx", destpc);
				printf(" childp->name %s", childp->name);
				printf(" childp->value 0x%llx\n",
				    childp->value);
			}
#endif /* DEBUG */
			if (childp->value == destpc) {
				/*
				 *	a hit
				 */
				addarc(parentp, childp, 0);
				continue;
			}
		}
		/*
		 *	else:
		 *	it looked like a call,
		 *	but it wasn't to anywhere.
		 */
#ifdef DEBUG
		if (debug & CALLSDEBUG) {
			printf("[findcalls]\tbut it's a switch or a botch\n");
		}
#endif /* DEBUG */
		continue;
	}
}
