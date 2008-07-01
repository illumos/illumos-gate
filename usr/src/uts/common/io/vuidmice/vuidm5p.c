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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 5-Byte Mouse Protocol
 */

#include <sys/param.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/vuid_event.h>
#include <sys/vuidmice.h>

#define	LOGI_NUMBUTTONS		3		/* Number of buttons	*/

#define	LOGI_BMASK		(uchar_t)7	/* Button mask in packet */
#define	LOGI_NOT_BMASK		(uchar_t)(~LOGI_BMASK) /* Rest of the bits */
#define	LOGI_START_CODE		(uchar_t)(0x80)	/* Start code in char	*/

#define	LOGI_START		0		/* Beginning of packet	*/
#define	LOGI_BUTTON		1		/* Got button status	*/
#define	LOGI_DELTA_X1		2		/* First of 2 delta X	*/
#define	LOGI_DELTA_Y1		3		/* First of 2 delta Y	*/
#define	LOGI_DELTA_X2		4		/* Second of 2 delta X	*/

extern void VUID_PUTNEXT(queue_t *const, uchar_t, uchar_t, uchar_t, int);

int
VUID_OPEN(queue_t *const qp)
{
	/*
	 * The current kdmconfig tables imply that this module can be used
	 * for both 2- and 3- button mice, so based on that evidence we
	 * can't assume a constant.  I don't know whether it's possible
	 * to autodetect.
	 */
	STATEP->nbuttons = 0;	/* Don't know. */

	return (0);
}

static void
vuidm5p_sendButtonEvent(queue_t *const qp)
{
	int b;

	/* for each button, see if it has changed */
	for (b = 0; b < 3; b++) {
		uchar_t mask = 4 >> b;

		if ((STATEP->buttons&mask) != (STATEP->oldbuttons&mask))
			VUID_PUTNEXT(qp, BUT(b+1), FE_PAIR_NONE, 0,
			    (STATEP->buttons & mask ? 1 : 0));
	}
}

void
vuidm5p(queue_t *const qp, mblk_t *mp)
{
	int r, code;
	uchar_t *bufp;

	bufp = mp->b_rptr;
	r = MBLKL(mp);

	for (r--; r >= 0; r--) {
		code = *bufp++;

		switch (STATEP->state) {
			/*
			 * Start state. We stay here if the start code is not
			 * received thus forcing us back into sync. When we
			 * get a start code the button mask comes with it
			 * forcing us to the next state.
			 */
		default:
resync:
		case LOGI_START:
			if ((code & LOGI_NOT_BMASK) != LOGI_START_CODE)
				break;

			STATEP->state   = LOGI_BUTTON;
			STATEP->deltax  = STATEP->deltay = 0;
			STATEP->buttons = (~code) & LOGI_BMASK;
						/* or xlate[code & ] */
			break;

		case LOGI_BUTTON:
			/*
			 * We receive the first of 2 delta x which forces us
			 * to the next state. We just add the values of each
			 * delta x together.
			 */
			if ((code & LOGI_NOT_BMASK) == LOGI_START_CODE) {
				STATEP->state = LOGI_START;
				goto resync;
			}

			/* (The cast sign extends the 8-bit value.) */
			STATEP->deltax += (signed char)code;
			STATEP->state = LOGI_DELTA_X1;
			break;

		case LOGI_DELTA_X1:
			/*
			 * The first of 2 delta y. We just add
			 * the 2 delta y together
			 */
			if ((code & LOGI_NOT_BMASK) == LOGI_START_CODE) {
				STATEP->state = LOGI_START;
				goto resync;
			}

			/* (The cast sign extends the 8-bit value.) */
			STATEP->deltay += (signed char)code;
			STATEP->state = LOGI_DELTA_Y1;
			break;

		case LOGI_DELTA_Y1:
			/*
			 * The second of 2 delta x. We just add
			 * the 2 delta x together.
			 */
			if ((code & LOGI_NOT_BMASK) == LOGI_START_CODE) {
				STATEP->state = LOGI_START;
				goto resync;
			}

			/* (The cast sign extends the 8-bit value.) */
			STATEP->deltax += (signed char)code;
			STATEP->state = LOGI_DELTA_X2;
			break;

		case LOGI_DELTA_X2:
			/*
			 * The second of 2 delta y. We just add
			 * the 2 delta y together.
			 */
			if ((code & LOGI_NOT_BMASK) == LOGI_START_CODE) {
				STATEP->state = LOGI_START;
				goto resync;
			}

			/* (The cast sign extends the 8-bit value.) */
			STATEP->deltay += (signed char)code;
			STATEP->state = LOGI_START;

			/* check if motion has occurred and send event(s)... */
			if (STATEP->deltax)
				VUID_PUTNEXT(qp,
				    (uchar_t)LOC_X_DELTA, FE_PAIR_ABSOLUTE,
				    (uchar_t)LOC_X_ABSOLUTE, STATEP->deltax);

			if (STATEP->deltay)
				VUID_PUTNEXT(qp,
				    (uchar_t)LOC_Y_DELTA, FE_PAIR_ABSOLUTE,
				    (uchar_t)LOC_Y_ABSOLUTE, STATEP->deltay);

			STATEP->deltax = STATEP->deltay = 0;

			/* see if the buttons have changed */
			if (STATEP->buttons != STATEP->oldbuttons) {
				/* buttons have changed */
				vuidm5p_sendButtonEvent(qp);

				/* update new button state */
				STATEP->oldbuttons = STATEP->buttons;
			}
		}
	}
	freemsg(mp);
}
