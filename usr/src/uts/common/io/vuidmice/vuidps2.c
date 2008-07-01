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
 * 			2/3/5 Button PS/2 Mouse Protocol
 *
 * This module dynamically determines the number of buttons on the mouse.
 */

#include <sys/param.h>
#include <sys/stream.h>
#include <sys/vuid_event.h>
#include <sys/vuidmice.h>
#include <sys/vuid_wheel.h>
#include <sys/mouse.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * BUT(1)		LEFT   BUTTON
 * BUT(2)		MIDDLE BUTTON (if present)
 * BUT(3)		RIGHT  BUTTON
 */

#define	PS2_BUTTONMASK		7		/* mask byte zero with this */

#define	PS2_BUTTON_L		(uchar_t)0x01	/* Left button pressed */
#define	PS2_BUTTON_R		(uchar_t)0x02	/* Right button pressed */
#define	PS2_BUTTON_M		(uchar_t)0x04	/* Middle button pressed */
#define	PS2_DATA_XSIGN		(uchar_t)0x10	/* X data sign bit */
#define	PS2_DATA_YSIGN		(uchar_t)0x20	/* Y data sign bit */

#define	PS2_START			0	/* Beginning of packet	*/
#define	PS2_BUTTON			1	/* Got button status	*/
#define	PS2_MAYBE_REATTACH		2	/* Got button status	*/
#define	PS2_DELTA_Y			3	/* Got delta X		*/
#define	PS2_WHEEL_DELTA_Z		4
#define	PS2_WHEEL5_DELTA_Z		5
#define	PS2_WAIT_RESET_ACK		6
#define	PS2_WAIT_RESET_AA		7
#define	PS2_WAIT_RESET_00		8
#define	PS2_WAIT_SETRES0_ACK1		9
#define	PS2_WAIT_SETRES0_ACK2		10	/* -+ must be consecutive */
#define	PS2_WAIT_SCALE1_1_ACK		11	/*  | */
#define	PS2_WAIT_SCALE1_2_ACK		12	/*  | */
#define	PS2_WAIT_SCALE1_3_ACK		13	/* -+ */
#define	PS2_WAIT_STATREQ_ACK		14
#define	PS2_WAIT_STATUS_1		15
#define	PS2_WAIT_STATUS_BUTTONS		16
#define	PS2_WAIT_STATUS_REV		17
#define	PS2_WAIT_STATUS_3		18
#define	PS2_WAIT_WHEEL_SMPL1_CMD_ACK	19	/* Set the sample rate to 200 */
#define	PS2_WAIT_WHEEL_SMPL1_RATE_ACK	20
#define	PS2_WAIT_WHEEL_SMPL2_CMD_ACK	21	/* Set the sample rate to 200 */
#define	PS2_WAIT_WHEEL_SMPL2_RATE_ACK	22
#define	PS2_WAIT_WHEEL_SMPL3_CMD_ACK	23	/* Set the sample rate to 80 */
#define	PS2_WAIT_WHEEL_SMPL3_RATE_ACK	24
#define	PS2_WAIT_WHEEL_DEV_CMD		25
#define	PS2_WAIT_WHEEL_DEV_ACK		26	/* Detected wheel mouse */
#define	PS2_WAIT_WHEEL5_SMPL1_CMD_ACK	27	/* Set the sample rate to 200 */
#define	PS2_WAIT_WHEEL5_SMPL1_RATE_ACK	28
#define	PS2_WAIT_WHEEL5_SMPL2_CMD_ACK	29	/* Set the sample rate to 200 */
#define	PS2_WAIT_WHEEL5_SMPL2_RATE_ACK	30
#define	PS2_WAIT_WHEEL5_SMPL3_CMD_ACK	31	/* Set the sample rate to 100 */
#define	PS2_WAIT_WHEEL5_SMPL3_RATE_ACK	32
#define	PS2_WAIT_WHEEL5_DEV_CMD		33
#define	PS2_WAIT_WHEEL5_DEV_ACK		34	/* Detected 5 button mouse */
#define	PS2_WAIT_SETRES3_CMD		35
#define	PS2_WAIT_SETRES3_ACK1		36
#define	PS2_WAIT_SETRES3_ACK2		37
#define	PS2_WAIT_STREAM_ACK		38
#define	PS2_WAIT_ON_ACK			39

#define	MSE_AA		0xaa
#define	MSE_00		0x00

#define	MOUSE_MODE_PLAIN	0	/* Normal PS/2 mouse - 3 byte msgs */
#define	MOUSE_MODE_WHEEL	1	/* Wheel mouse - 4 byte msgs */
#define	MOUSE_MODE_WHEEL5	2	/* Wheel + 5 btn mouse - 4 byte msgs */

#define	PS2_FLAG_NO_EXTN	0x08	/* Mouse doesn't obey extended cmds */
#define	PS2_FLAG_INIT_DONE	0x01	/* Mouse has been inited successfully */
#define	PS2_FLAG_INIT_TIMEOUT	0x02	/* Mouse init timeout */

/*
 * The RESET command takes more time
 * before the PS/2 mouse is ready
 */
#define	PS2_INIT_TMOUT_RESET	500000	/* 500ms for RESET command */
#define	PS2_INIT_TMOUT_PER_CMD	200000	/* 200ms for each command-response */
#define	PS2_INIT_TMOUT_PER_GROUP	500000 /* 500ms for group commands */

#define	PS2_MAX_INIT_COUNT	5


static void vuidmice_send_wheel_event(queue_t *const, uchar_t,
		uchar_t, uchar_t, int);
extern void VUID_PUTNEXT(queue_t *const, uchar_t, uchar_t, uchar_t, int);
extern void uniqtime32(struct timeval32 *);
static void VUID_INIT_TIMEOUT(void *q);

/*
 * We apply timeout to nearly each command-response
 * during initialization:
 *
 * Set timeout for RESET
 * Set timeout for SET RESOLUTION
 * Set timeout for SET SCALE
 * Set timeout for SET SAMPLE RATE
 * Set timeout for STATUS REQUEST
 * Set timeout for GET DEV
 * Set timeout for SET STREAM MODE and ENABLE.
 *
 * But for simplicity, sometimes we just apply the timeout
 * to a function with group commands (e.g. wheel-mouse detection).
 *
 */
static void
vuid_set_timeout(queue_t *const qp, clock_t time)
{
	ASSERT(STATEP->init_tid == 0);
	STATEP->init_tid = qtimeout(qp, VUID_INIT_TIMEOUT,
	    qp, drv_usectohz(time));
}

static void
vuid_cancel_timeout(queue_t *const qp)
{
	ASSERT(STATEP->init_tid != 0);
	(void) quntimeout(qp, STATEP->init_tid);
	STATEP->init_tid = 0;
}

/*
 * vuidmice_send_wheel_event
 *	Convert wheel data to firm_events
 */
static void
vuidmice_send_wheel_event(queue_t *const qp, uchar_t event_id,
    uchar_t event_pair_type, uchar_t event_pair, int event_value)
{
	mblk_t		*bp;
	Firm_event	*fep;

	if ((bp = allocb((int)sizeof (Firm_event), BPRI_HI)) == NULL) {

		return;
	}

	fep = (void *)bp->b_wptr;
	fep->id = vuid_id_addr(vuid_first(VUID_WHEEL)) |
	    vuid_id_offset(event_id);
	fep->pair_type = event_pair_type;
	fep->pair = event_pair;
	fep->value = event_value;
	uniqtime32(&fep->time);
	bp->b_wptr += sizeof (Firm_event);

	if (canput(qp->q_next)) {
		putnext(qp, bp);
	} else {
		(void) putbq(qp, bp); /* read side is blocked */
	}
}


static void
sendButtonEvent(queue_t *const qp)
{
	static int bmap[3] = {1, 3, 2};
	uint_t b;

	/* for each button, see if it has changed */
	for (b = 0; b < STATEP->nbuttons; b++) {
		uchar_t	mask = 0x1 << b;

		if ((STATEP->buttons & mask) != (STATEP->oldbuttons & mask))
			VUID_PUTNEXT(qp, (uchar_t)BUT(bmap[b]), FE_PAIR_NONE, 0,
			    (STATEP->buttons & mask ? 1 : 0));
	}
}

void
put1(queue_t *const qp, int c)
{
	mblk_t *bp;

	if (bp = allocb(1, BPRI_MED)) {
		*bp->b_wptr++ = (char)c;
		putnext(qp, bp);
	}
}

int
VUID_OPEN(queue_t *const qp)
{
	STATEP->format = VUID_FIRM_EVENT;
	STATEP->vuid_mouse_mode = MOUSE_MODE_PLAIN;
	STATEP->inited = 0;
	STATEP->nbuttons = 3;

	STATEP->state = PS2_WAIT_RESET_ACK;

	/* Set timeout for reset */
	vuid_set_timeout(qp, PS2_INIT_TMOUT_RESET);

	put1(WR(qp), MSERESET);

	while ((STATEP->state != PS2_START) &&
	    !(STATEP->inited & PS2_FLAG_INIT_TIMEOUT)) {
		if (qwait_sig(qp) == 0)
			break;
	}

	/*
	 * Later the PS/2 mouse maybe re-attach, so here
	 * clear the init_count.
	 */
	STATEP->init_count = 0;

	return (0);
}

void
VUID_CLOSE(queue_t *const qp)
{
	if (STATEP->init_tid != 0)
		vuid_cancel_timeout(qp);
}

static void
VUID_INIT_TIMEOUT(void *q)
{
	queue_t	*qp = q;

	STATEP->init_tid = 0;

	/*
	 * Some mice do not even send an error in response to
	 * the wheel mouse sample commands, so if we're in any of
	 * the PS2_WAIT_WHEEL_SMPL* states, and there has been
	 * a timeout, assume the mouse cannot handle the extended
	 * (wheel mouse) commands.
	 */
	if ((STATEP->state == PS2_WAIT_WHEEL_SMPL1_CMD_ACK) ||
	    (STATEP->state == PS2_WAIT_WHEEL_SMPL1_RATE_ACK) ||
	    (STATEP->state == PS2_WAIT_WHEEL_SMPL2_RATE_ACK) ||
	    (STATEP->state == PS2_WAIT_WHEEL_SMPL3_RATE_ACK)) {
		/*
		 * We overload 'inited' to mark the PS/2 mouse
		 * as one which doesn't respond to extended commands.
		 */

		STATEP->inited |= PS2_FLAG_NO_EXTN;
	}

	if (++STATEP->init_count >= PS2_MAX_INIT_COUNT) {
		STATEP->inited |= PS2_FLAG_INIT_TIMEOUT;
		return;
	}


	STATEP->state = PS2_WAIT_RESET_ACK;

	vuid_set_timeout(qp, PS2_INIT_TMOUT_RESET);

	/* try again */
	put1(WR(qp), MSERESET);
}

void
VUID_QUEUE(queue_t *const qp, mblk_t *mp)
{
	int code;
	clock_t now;
	clock_t elapsed;
	clock_t mouse_timeout;

	mouse_timeout = drv_usectohz(250000);
	now = ddi_get_lbolt();
	elapsed = now - STATEP->last_event_lbolt;
	STATEP->last_event_lbolt = now;

	while (mp->b_rptr < mp->b_wptr) {
		code = *mp->b_rptr++;

		switch (STATEP->state) {

		/*
		 * Start state. We stay here if the start code is not
		 * received thus forcing us back into sync. When we get a
		 * start code the button mask comes with it forcing us to
		 * to the next state.
		 */
restart:
		case PS2_START:

			/*
			 * 3-byte packet format
			 *
			 * Bit   7   6    5	4	3   2	1	0
			 * Byte ---- ---- ----- ----- -- ------ ------ ------
			 * 1    Y_Ov X_Ov Y_Sgn X_Sgn  1 MdlBtn RgtBtn LftBtn
			 * 2    |<--------------X Movement----------------->|
			 * 3    |<--------------Y Movement----------------->|
			 *
			 * 4-byte wheel packet format
			 *
			 * Bit   7    6   5	4	3   2	1	0
			 * Byte ---- ---- ----- ----- -- ------ ------ ------
			 * 1    Y_Ov X_Ov Y_Sgn X_Sgn  1 MdlBtn RgtBtn LftBtn
			 * 2    |<--------------X Movement----------------->|
			 * 3    |<--------------Y Movement----------------->|
			 * 4    |<--------------Z Movement----------------->|
			 *
			 * 4-byte wheel+5 packet format
			 *
			 * Bit   7    6   5	4	3   2	1	0
			 * Byte ---- ---- ----- ----- -- ------ ------ ------
			 * 1    Y_Ov X_Ov Y_Sgn X_Sgn  1 MdlBtn RgtBtn LftBtn
			 * 2    |<--------------X Movement----------------->|
			 * 3    |<--------------Y Movement----------------->|
			 * 4	0    0   5_Btn 4_Btn Z3   Z2	Z1	Z0
			 */

			if (!(STATEP->inited & PS2_FLAG_INIT_DONE)) {
				STATEP->sync_byte = code & 0x8;
				STATEP->inited |= PS2_FLAG_INIT_DONE;
			}
		/*
		 * the PS/2 mouse data format doesn't have any sort of sync
		 * data to make sure we are in sync with the packet stream,
		 * but the Technical Reference manual states that bits 2 & 3
		 * of the first byte are reserved.  Logitech uses bit 2 for
		 * the middle button.  We HOPE that noone uses bit 3 though,
		 * and decide we're out of sync if bit 3 is not set here.
		 */

			if ((code ^ STATEP->sync_byte) & 0x08) {
				/* bit 3 not set */
				STATEP->state = PS2_START;
				break;			/* toss the code */
			}

			/* get the button values */
			STATEP->buttons = code & PS2_BUTTONMASK;
			if (STATEP->buttons != STATEP->oldbuttons) {
				sendButtonEvent(qp);
				STATEP->oldbuttons = STATEP->buttons;
			}

			/* bit 5 indicates Y value is negative (the sign bit) */
			if (code & PS2_DATA_YSIGN)
				STATEP->deltay = -1 & ~0xff;
			else
				STATEP->deltay = 0;

			/* bit 4 is X sign bit */
			if (code & PS2_DATA_XSIGN)
				STATEP->deltax = -1 & ~0xff;
			else
				STATEP->deltax = 0;

			if (code == MSE_AA)
				STATEP->state = PS2_MAYBE_REATTACH;
			else
				STATEP->state = PS2_BUTTON;

			break;

		case PS2_MAYBE_REATTACH:
			if (code == MSE_00) {
				STATEP->state = PS2_WAIT_RESET_ACK;
				vuid_set_timeout(qp, PS2_INIT_TMOUT_RESET);
				put1(WR(qp), MSERESET);
				break;
			}
			/*FALLTHROUGH*/

		case PS2_BUTTON:
			/*
			 * Now for the 7 bits of delta x.  "Or" in
			 * the sign bit and continue.  This is ac-
			 * tually a signed 9 bit number, but I just
			 * truncate it to a signed char in order to
			 * avoid changing and retesting all of the
			 * mouse-related modules for this patch.
			 */
			if (elapsed > mouse_timeout)
				goto restart;
			STATEP->deltax |= code & 0xff;
			STATEP->state = PS2_DELTA_Y;
			break;

		case PS2_DELTA_Y:
			/*
			 * This byte is delta Y.  If this is a plain mouse,
			 * we're done.  Wheel mice have two different flavors
			 * of fourth byte.
			 */

			if (elapsed > mouse_timeout) {
				goto restart;
			}
			STATEP->deltay |= code & 0xff;

			if (STATEP->vuid_mouse_mode == MOUSE_MODE_WHEEL) {
				STATEP->state = PS2_WHEEL_DELTA_Z;
				break;
			} else if (STATEP->vuid_mouse_mode ==
			    MOUSE_MODE_WHEEL5) {
				STATEP->state = PS2_WHEEL5_DELTA_Z;
				break;
			}
			goto packet_complete;

		case PS2_WHEEL5_DELTA_Z:
			if (code & 0x10) {
				/* fourth physical button */
				VUID_PUTNEXT(qp, (uchar_t)BUT(4),
				    FE_PAIR_NONE, 0, 1);
				VUID_PUTNEXT(qp, (uchar_t)BUT(4),
				    FE_PAIR_NONE, 0, 0);
			} else if (code & 0x20) {
				/* fifth physical button */
				VUID_PUTNEXT(qp, (uchar_t)BUT(5),
				    FE_PAIR_NONE, 0, 1);
				VUID_PUTNEXT(qp, (uchar_t)BUT(5),
				    FE_PAIR_NONE, 0, 0);
			}
			/*FALLTHROUGH*/

		case PS2_WHEEL_DELTA_Z:
			/*
			 * Check whether reporting vertical wheel
			 * movements is enabled
			 */
			code &= 0xf;

			if (STATEP->wheel_state_bf & (1 <<
			    VUIDMICE_VERTICAL_WHEEL_ID)) {
				/*
				 * PS/2 mouse reports -ve values
				 * when the wheel is scrolled up. So
				 * we need to convert it into +ve as
				 * X interprets a +ve value as wheel up event.
				 * Same is true for the horizontal wheel also.
				 * The mouse reports 0xf when scrolled up
				 * and 0x1 when scrolled down. This observation
				 * is based on Logitech, HCL,
				 * Microsoft and Black Cat mouse only
				 */
				if (code == 0xf) {
					/* negative Z - wheel up */
					code |= 0xfffffff0;
					vuidmice_send_wheel_event(qp, 0,
					    FE_PAIR_NONE, 0, -code);
				} else if (code == 0x01) {
					/* positive Z - wheel down */
					vuidmice_send_wheel_event(qp, 0,
					    FE_PAIR_NONE, 0, -code);
				}
			}

			/*
			 * Check whether reporting horizontal wheel
			 * movements is enabled
			 */
			if (STATEP->wheel_state_bf &
			    (1 << VUIDMICE_HORIZONTAL_WHEEL_ID)) {

				/*
				 * The mouse return -7 and +7 when it
				 * is scrolled horizontally
				 */
				if (code == 0x09) {
					/* negative Z - wheel left */
					vuidmice_send_wheel_event(qp, 1,
					    FE_PAIR_NONE, 0, 1);
				} else if (code == 0x07) {
					/* positive Z - wheel right */
					vuidmice_send_wheel_event(qp, 1,
					    FE_PAIR_NONE, 0, -1);
				}
			}

packet_complete:
			STATEP->state = PS2_START;
			/*
			 * If we can peek at the next mouse character, and
			 * its not the start of the next packet, don't use
			 * this packet.
			 */
			if (mp->b_wptr > mp->b_rptr &&
			    ((mp->b_rptr[0] ^ STATEP->sync_byte) & 0x08)) {
				/*
				 * bit 3 not set
				 */
				break;
			}

			/*
			 * send the info to the next level --
			 * need to send multiple events if we have both
			 * a delta *AND* button event(s)
			 */

			/* motion has occurred ... */
			if (STATEP->deltax)
				VUID_PUTNEXT(qp, (uchar_t)LOC_X_DELTA,
				    FE_PAIR_ABSOLUTE, (uchar_t)LOC_X_ABSOLUTE,
				    STATEP->deltax);

			if (STATEP->deltay)
				VUID_PUTNEXT(qp, (uchar_t)LOC_Y_DELTA,
				    FE_PAIR_ABSOLUTE, (uchar_t)LOC_Y_ABSOLUTE,
				    STATEP->deltay);

			STATEP->deltax = STATEP->deltay = 0;
			break;

		case PS2_WAIT_RESET_ACK:
			if (code != MSE_ACK) {
				break;
			}

			/*
			 * On Dell latitude D800, we find that the MSE_ACK is
			 * coming up even after timeout in VUID_OPEN during
			 * early boot. So here (PS2_WAIT_RESET_ACK) we check
			 * if timeout happened before, if true, we reset the
			 * timeout to restart the initialization.
			 */
			if (STATEP->inited & PS2_FLAG_INIT_TIMEOUT) {
				STATEP->inited &= ~PS2_FLAG_INIT_TIMEOUT;
				vuid_set_timeout(qp, PS2_INIT_TMOUT_RESET);
			}

			STATEP->state = PS2_WAIT_RESET_AA;
			break;

		case PS2_WAIT_RESET_AA:
			if (code != MSE_AA) {
				break;
			}
			STATEP->state = PS2_WAIT_RESET_00;
			break;

		case PS2_WAIT_RESET_00:
			if (code != MSE_00) {
				break;
			}

			/* Reset has been ok */
			vuid_cancel_timeout(qp);

			STATEP->state = PS2_WAIT_SETRES0_ACK1;

			/* Set timeout for set res */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_GROUP);

			put1(WR(qp), MSESETRES);
			break;

		case PS2_WAIT_SETRES0_ACK1:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_SETRES0_ACK2;
			put1(WR(qp), 0);
			break;

		case PS2_WAIT_SETRES0_ACK2:
		case PS2_WAIT_SCALE1_1_ACK:
		case PS2_WAIT_SCALE1_2_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state++;
			put1(WR(qp), MSESCALE1);
			break;

		case PS2_WAIT_SCALE1_3_ACK:
			if (code != MSE_ACK) {
				break;
			}

			/* Set res and scale have been ok */
			vuid_cancel_timeout(qp);

			STATEP->state = PS2_WAIT_STATREQ_ACK;

			/* Set timeout for status request */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_GROUP);

			put1(WR(qp), MSESTATREQ);

			break;

		case PS2_WAIT_STATREQ_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_STATUS_1;
			break;

		case PS2_WAIT_STATUS_1:
			STATEP->state = PS2_WAIT_STATUS_BUTTONS;
			break;

		case PS2_WAIT_STATUS_BUTTONS:
			if (code != 0) {
				STATEP->nbuttons = (uchar_t)code;
				STATEP->state = (uchar_t)PS2_WAIT_STATUS_REV;
			} else {
#if	defined(VUID3PS2)
				/*
				 * It seems that there are some 3-button mice
				 * that don't play the Logitech autodetect
				 * game.  One is a Mouse Systems mouse OEM'ed
				 * by Intergraph.
				 *
				 * Until we find out how to autodetect these
				 * mice, we'll assume that if we're being
				 * compiled as vuid3ps2 and the mouse doesn't
				 * play the autodetect game, it's a 3-button
				 * mouse.  This effectively disables
				 * autodetect for mice using vuid3ps2, but
				 * since vuid3ps2 is used only on x86 where
				 * we currently assume manual configuration,
				 * this shouldn't be a problem.  At some point
				 * in the future when we *do* start using
				 * autodetect on x86, we should probably define
				 * VUIDPS2 instead of VUID3PS2.  Even then,
				 * we could leave this code so that *some*
				 * mice could use autodetect and others not.
				 */
				STATEP->nbuttons = 3;
#else
				STATEP->nbuttons = 2;
#endif
				STATEP->state = PS2_WAIT_STATUS_3;
			}
			break;

		case PS2_WAIT_STATUS_REV:
			/*FALLTHROUGH*/

		case PS2_WAIT_STATUS_3:

			/* Status request has been ok */
			vuid_cancel_timeout(qp);

			/* Set timeout for set res or sample rate */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_GROUP);

			/*
			 * Start the wheel-mouse detection code.  First, we look
			 * for standard wheel mice.  If we set the sample rate
			 * to 200, 100, and then 80 and finally request the
			 * device ID, a wheel mouse will return an ID of 0x03.
			 * After that, we'll try for the wheel+5 variety.  The
			 * incantation in this case is 200, 200, and 80.  We'll
			 * get 0x04 back in that case.
			 */
			if (STATEP->inited & PS2_FLAG_NO_EXTN) {
				STATEP->state = PS2_WAIT_SETRES3_ACK1;
				put1(WR(qp), MSESETRES);
			} else {
				STATEP->state = PS2_WAIT_WHEEL_SMPL1_CMD_ACK;
				put1(WR(qp), MSECHGMOD);
			}

			break;
		case PS2_WAIT_WHEEL_SMPL1_CMD_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL_SMPL1_RATE_ACK;
			put1(WR(qp), 200);
			break;
		case PS2_WAIT_WHEEL_SMPL1_RATE_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL_SMPL2_CMD_ACK;
			put1(WR(qp), MSECHGMOD);
			break;

		case PS2_WAIT_WHEEL_SMPL2_CMD_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL_SMPL2_RATE_ACK;
			put1(WR(qp), 100);
			break;

		case PS2_WAIT_WHEEL_SMPL2_RATE_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL_SMPL3_CMD_ACK;
			put1(WR(qp), MSECHGMOD);
			break;

		case PS2_WAIT_WHEEL_SMPL3_CMD_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL_SMPL3_RATE_ACK;
			put1(WR(qp), 80);
			break;

		case PS2_WAIT_WHEEL_SMPL3_RATE_ACK:
			if (code != MSE_ACK) {
				break;
			}

			/* Set sample rate has been ok */
			vuid_cancel_timeout(qp);

			STATEP->state = PS2_WAIT_WHEEL_DEV_CMD;

			/* Set timeout for get dev */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_CMD);

			put1(WR(qp), MSEGETDEV);
			break;

		case PS2_WAIT_WHEEL_DEV_CMD:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL_DEV_ACK;
			break;

		case PS2_WAIT_WHEEL_DEV_ACK:

			/* Get dev has been ok */
			vuid_cancel_timeout(qp);

			if (code != 0x03) {
				STATEP->state = PS2_WAIT_SETRES3_ACK1;

				/* Set timeout for set res */
				vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_CMD);

				put1(WR(qp), MSESETRES);

				break;
			}

			STATEP->vuid_mouse_mode = MOUSE_MODE_WHEEL;

			/*
			 * Found wheel. By default enable the wheel.
			 */
			STATEP->wheel_state_bf |= VUID_WHEEL_STATE_ENABLED;

			STATEP->state = PS2_WAIT_WHEEL5_SMPL1_CMD_ACK;

			/* Set timeout for set sample rate */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_GROUP);

			/* We're on a roll - try for wheel+5 */
			put1(WR(qp), MSECHGMOD);

			break;

		case PS2_WAIT_WHEEL5_SMPL1_CMD_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL5_SMPL1_RATE_ACK;
			put1(WR(qp), 200);
			break;

		case PS2_WAIT_WHEEL5_SMPL1_RATE_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL5_SMPL2_CMD_ACK;
			put1(WR(qp), MSECHGMOD);
			break;

		case PS2_WAIT_WHEEL5_SMPL2_CMD_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL5_SMPL2_RATE_ACK;
			put1(WR(qp), 200);
			break;

		case PS2_WAIT_WHEEL5_SMPL2_RATE_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL5_SMPL3_CMD_ACK;
			put1(WR(qp), MSECHGMOD);
			break;

		case PS2_WAIT_WHEEL5_SMPL3_CMD_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL5_SMPL3_RATE_ACK;
			put1(WR(qp), 80);
			break;

		case PS2_WAIT_WHEEL5_SMPL3_RATE_ACK:
			if (code != MSE_ACK) {
				break;
			}

			/* Set sample rate has been ok */
			vuid_cancel_timeout(qp);

			STATEP->state = PS2_WAIT_WHEEL5_DEV_CMD;

			/* Set timeout for wheel5 get dev */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_CMD);

			put1(WR(qp), MSEGETDEV);

			break;

		case PS2_WAIT_WHEEL5_DEV_CMD:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_WHEEL5_DEV_ACK;
			break;

		case PS2_WAIT_WHEEL5_DEV_ACK:
			if (code == 0x04) {
				STATEP->vuid_mouse_mode = MOUSE_MODE_WHEEL5;
				STATEP->nbuttons	= 5;

				/*
				 * Found wheel. By default enable the wheel.
				 */
				STATEP->wheel_state_bf |=
				    VUID_WHEEL_STATE_ENABLED <<
				    MOUSE_MODE_WHEEL;
			}

			/* Wheel5 get dev has been ok */
			vuid_cancel_timeout(qp);

			/* FALLTHROUGH */

		case PS2_WAIT_SETRES3_CMD:
			STATEP->state = PS2_WAIT_SETRES3_ACK1;

			/* Set timeout for set res */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_CMD);

			put1(WR(qp), MSESETRES);

			break;

		case PS2_WAIT_SETRES3_ACK1:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_SETRES3_ACK2;
			put1(WR(qp), 3);
			break;

		case PS2_WAIT_SETRES3_ACK2:
			if (code != MSE_ACK) {
				break;
			}

			/* Set res has been ok */
			vuid_cancel_timeout(qp);

			STATEP->state = PS2_WAIT_STREAM_ACK;

			/* Set timeout for enable */
			vuid_set_timeout(qp, PS2_INIT_TMOUT_PER_CMD);

			put1(WR(qp), MSESTREAM);

			break;

		case PS2_WAIT_STREAM_ACK:
			if (code != MSE_ACK) {
				break;
			}
			STATEP->state = PS2_WAIT_ON_ACK;
			put1(WR(qp), MSEON);
			break;

		case PS2_WAIT_ON_ACK:
			if (code != MSE_ACK) {
				break;
			}

			/* Enable has been ok */
			vuid_cancel_timeout(qp);

			STATEP->state = PS2_START;
			break;
		}
	}
	freemsg(mp);
}
