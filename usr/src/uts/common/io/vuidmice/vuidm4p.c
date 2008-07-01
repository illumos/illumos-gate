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
 * 4-Byte Mouse Protocol
 */

#include <sys/param.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/vuid_event.h>
#include <sys/vuidmice.h>

#ifdef	VUIDM4P_DEBUG
#define	VBUF_SIZE	511
static unsigned char vuidm4p_buf[VBUF_SIZE+1];
static int vuidm4p_ptr = 0;
#endif

#define	VUID_BUT(b)		BUT((b*2)+1)

/*
 * VUID_BUT(0)	BUT(1)		LEFT  BUTTON
 * VUID_BUT(1)	BUT(3)		RIGHT BUTTON
 */

#define	MOUSE_NUMBUTTONS	3		/* Number of buttons	*/
#define	MOUSE_BUTTON_M		(uchar_t)(0x40)	/* Middle button */
#define	MOUSE_BUTTON_L		(uchar_t)(0x20)	/* Left   button */
#define	MOUSE_BUTTON_R		(uchar_t)(0x10)	/* Right  button */

#define	MOUSE_START_CODE	(uchar_t)(0x40)	/* Start code in char	*/

#define	MOUSE_START		0		/* Beginning of packet	*/
#define	MOUSE_BUTTON		1		/* Got button status	*/
#define	MOUSE_DELTA_X		2		/* got delta X		*/
#define	MOUSE_DELTA_Y		3		/* got delta Y		*/

extern void VUID_PUTNEXT(queue_t *const, uchar_t, uchar_t, uchar_t, int);

int
VUID_OPEN(queue_t *const qp)
{
	/*
	 * The current kdmconfig tables imply that this module can be used
	 * for both 2- and 3- button mice, so based on that evidence we
	 * can't assume a constant.  It should be possible to autodetect
	 * based on the mouse's startup behavior - "M" means 2 buttons,
	 * "M3" means 3 buttons - but that's for another day.
	 */
	STATEP->nbuttons = 0;	/* Don't know. */

	return (0);
}

static void
vuidm4p_sendButtonEvent(queue_t *const qp)
{
	int b;

	/* for the LEFT and RIGHT button, see if it has changed */
	for (b = 0; b < 2; b++) {
		uchar_t mask = 0x20 >> b;

		if ((STATEP->buttons & mask) != (STATEP->oldbuttons & mask))
			VUID_PUTNEXT(qp, VUID_BUT(b), FE_PAIR_NONE, 0,
			    ((STATEP->buttons & mask) ? 1 : 0));
	}
}

void
vuidm4p(queue_t *const qp, mblk_t *mp)
{
	int r, code;
	unsigned char *bufp;

	bufp = mp->b_rptr;
	r = MBLKL(mp);

	for (r--; r >= 0; r--) {
		code = *bufp++;

#ifdef	VUIDM4P_DEBUG
		vuidm4p_buf[vuidm4p_ptr] = code;
		vuidm4p_ptr = ((vuidm4p_ptr + 1) & VBUF_SIZE);
#endif

		if (code & MOUSE_START_CODE) {
			/*
			 * sync it here
			 */
			STATEP->state = MOUSE_START;
		}

		switch (STATEP->state) {
			/*
			 * Start state. We stay here if the start code is not
			 * received thus forcing us back into sync. When we
			 * get a start code the	button mask comes with it
			 * forcing us to the next state.
			 */
		default:
		case MOUSE_START:
			/* look for sync */
			if ((code & MOUSE_START_CODE) == 0)
				break;

			STATEP->deltax = STATEP->deltay = 0;
			STATEP->buttons = 0;

			/* Get the new state for the LEFT & RIGHT Button */
			STATEP->buttons |=
			    (code & (MOUSE_BUTTON_L | MOUSE_BUTTON_R));

			/*
			 * bits 0 & 1 are bits 6 & 7 of X value
			 * (Sign extend them with the cast.)
			 */
			STATEP->deltax = (signed char)((code & 0x03) << 6);

			/*
			 * bits 2 & 3 are bits 6 & 7 of Y value
			 * (Sign extend them with the cast.)
			 */
			STATEP->deltay = (signed char)((code & 0x0c) << 4);
			STATEP->state = MOUSE_BUTTON;
				/* go to the next state */
			break;

		case MOUSE_BUTTON:
			/*
			 * We receive the remaining 6 bits of delta x,
			 * forcing us to the next state. We just piece the
			 * value of delta x together.
			 */
			STATEP->deltax |= code & 0x3f;
			STATEP->state = MOUSE_DELTA_X;
			break;

			/*
			 * The last part of delta Y, and the packet *may be*
			 * complete
			 */
		case MOUSE_DELTA_X:
			STATEP->deltay |= code & 0x3f;
			STATEP->state = MOUSE_DELTA_Y;

			STATEP->buttons |=
			    (STATEP->oldbuttons & MOUSE_BUTTON_M);

			/*
			 * If we can peek at the next two mouse characters,
			 * and  neither  of  them  is  the start of the next
			 * packet, don't use this packet.
			 */
			if (r > 1 && !(bufp[0] & MOUSE_START_CODE) &&
			    !(bufp[1] & MOUSE_START_CODE)) {
				STATEP->state = MOUSE_START;
				break;
			}

			if (STATEP->buttons != STATEP->oldbuttons) {
				vuidm4p_sendButtonEvent(qp);
			}

			/*
			 * remember state
			 */
			STATEP->oldbuttons = STATEP->buttons;

			/*
			 * generate motion Events for delta_x
			 */
			if (STATEP->deltax)
				VUID_PUTNEXT(qp,
				    (uchar_t)LOC_X_DELTA, FE_PAIR_ABSOLUTE,
				    (uchar_t)LOC_X_ABSOLUTE, STATEP->deltax);
			/*
			 * Reverse the Sign for DELTA_Y
			 */
			if (STATEP->deltay)
				VUID_PUTNEXT(qp,
				    (uchar_t)LOC_Y_DELTA, FE_PAIR_ABSOLUTE,
				    (uchar_t)LOC_Y_ABSOLUTE, -STATEP->deltay);

			STATEP->deltax = STATEP->deltay = 0;

			/* allow us to keep looking for an optional 4th byte */
			break;

		case MOUSE_DELTA_Y:
			/*
			 * We've seen delta Y.  If we do NOT have the sync
			 * bit set, this indicates the middle button's status.
			 */
			STATEP->state = MOUSE_START;

			/*
			 * if we're here, the fourth byte is indeed present
			 * to indicate something with the middle button.
			 */

			/*
			 * If we can peek at the next mouse character, and
			 * its not the start of the next packet, don't use
			 * this packet.
			 */
			if (r > 0 && !(bufp[0] & MOUSE_START_CODE))
				break;

			/*
			 * Check if the byte is a valid middle button state.
			 * It must either be 0x00 or 0x20 only.
			 */

			/*
			 * Get the new state for the MIDDLE Button
			 * Left button set in 4th byte indicates that the
			 * middle button is pressed, cleared means it
			 * has been released.
			 */
			if (code == MOUSE_BUTTON_L)
				STATEP->buttons |= MOUSE_BUTTON_M;
			else if (code == 0)
				STATEP->buttons &= ~MOUSE_BUTTON_M;
			else {
				/*
				 * Invalid data in the 4th byte of the packet.
				 * Skip this byte.
				 */
#ifdef VUIDM4P_DEBUG
				vuidm4p_break();
#endif
				break;
			}

			/*
			 * generate an Event with the middle button's status
			 */
			if (STATEP->oldbuttons != STATEP->buttons) {
				VUID_PUTNEXT(qp,
				    (uchar_t)MS_MIDDLE, FE_PAIR_NONE, 0,
				    ((STATEP->buttons & MOUSE_BUTTON_M) ?
				    1 : 0));
			}

			/*
			 * remember state
			 */
			STATEP->oldbuttons = STATEP->buttons;
			break;
		}
	}
	freemsg(mp);
}


#ifdef	VUIDM4P_DEBUG
int
vuidm4p_break()
{
	char buf[VBUF_SIZE+1];
	int i;

	for (i = 0; i <= VBUF_SIZE; i++) {
		buf[i] - vuidm4p_buf[vuidm4p_ptr];
		vuidm4p_ptr = ((vuidm4p_ptr + 1) & VBUF_SIZE);
	}

	for (i = 0; i <= VBUF_SIZE; i++) {
		vuidm4p_buf[i] = buf[i];
	}
}
#endif
