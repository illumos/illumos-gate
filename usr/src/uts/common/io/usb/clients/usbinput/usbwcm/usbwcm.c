/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, 2008 Bartosz Fabianowski <freebsd@chillt.de>
 * All rights reserved.
 *
 * Financed by the "Irish Research Council for Science, Engineering and
 * Technology: funded by the National Development Plan"
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/strtty.h>
#include <sys/systm.h>

#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usbai_private.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/usbinput/usbwcm/usbwcm.h>

/* debugging information */
uint_t	usbwcm_errmask = (uint_t)PRINT_MASK_ALL;
uint_t	usbwcm_errlevel = USB_LOG_L2;
static usb_log_handle_t usbwcm_log_handle;

static void
uwacom_event(usbwcm_state_t *usbwcmp, uint_t type, uint_t idx, int val)
{
	struct uwacom_softc	*sc = &usbwcmp->usbwcm_softc;
	mblk_t			*mp;

	switch (type) {
	case EVT_SYN:
		if (sc->sc_sync)
			return;
		break;

	case EVT_BTN:
		if (sc->sc_btn[idx] == val)
			return;

		sc->sc_btn[idx] = val;
		break;

	case EVT_ABS:
		if (sc->sc_abs[idx].fuzz) {
			int dist = abs(val - sc->sc_abs[idx].value);

			if (dist < sc->sc_abs[idx].fuzz >> 1) {
				return;
			} else if (dist < sc->sc_abs[idx].fuzz) {
				val = (7 * sc->sc_abs[idx].value + val) >> 3;
			} else if (dist < sc->sc_abs[idx].fuzz << 1) {
				val = (sc->sc_abs[idx].value + val) >> 1;
			}
		}
		if (sc->sc_abs[idx].value == val) {
			return;
		}

		sc->sc_abs[idx].value = val;
		break;

	case EVT_REL:
		if (!val)
			return;
		break;

	case EVT_MSC:
		break;

	default:
		return;
	}

	if ((mp = allocb(sizeof (struct event_input), BPRI_HI)) != NULL) {
		struct event_input *ev = (struct event_input *)mp->b_wptr;

		ev->type = (uint16_t)type;
		ev->code = (uint16_t)idx;
		ev->value = (int32_t)val;
		uniqtime32(&ev->time);

		mp->b_wptr += sizeof (struct event_input);
		putnext(usbwcmp->usbwcm_rq, mp);
	} else {
		return;
	}

	sc->sc_sync = (type == EVT_SYN);
}

static void
uwacom_pos_events_graphire(usbwcm_state_t *usbwcmp, int x, int y)
{
	uwacom_event(usbwcmp, EVT_ABS, ABS_X, x);
	uwacom_event(usbwcmp, EVT_ABS, ABS_Y, y);
}

static void
uwacom_pen_events_graphire(usbwcm_state_t *usbwcmp, int prs, int stl1, int stl2)
{
	uwacom_event(usbwcmp, EVT_ABS, ABS_PRESSURE, prs);
	uwacom_event(usbwcmp, EVT_BTN, BTN_TIP, prs);
	uwacom_event(usbwcmp, EVT_BTN, BTN_STYLUS_1, stl1);
	uwacom_event(usbwcmp, EVT_BTN, BTN_STYLUS_2, stl2);
}

static void
uwacom_mouse_events_graphire(usbwcm_state_t *usbwcmp, int left, int middle,
    int right, int wheel, int distance)
{
	uwacom_event(usbwcmp, EVT_BTN, BTN_LEFT, left);
	uwacom_event(usbwcmp, EVT_BTN, BTN_MIDDLE, middle);
	uwacom_event(usbwcmp, EVT_BTN, BTN_RIGHT, right);
	uwacom_event(usbwcmp, EVT_REL, REL_WHEEL, wheel);
	uwacom_event(usbwcmp, EVT_ABS, ABS_DISTANCE, distance);
}

static void
uwacom_tool_events_graphire(usbwcm_state_t *usbwcmp, int idx, int proximity)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	uwacom_event(usbwcmp, EVT_BTN, sc->sc_tool[idx], proximity);
	uwacom_event(usbwcmp, EVT_ABS, ABS_MISC, sc->sc_tool_id[idx]);
	if (sc->sc_serial[idx]) {
		uwacom_event(usbwcmp, EVT_MSC, MSC_SERIAL, sc->sc_serial[idx]);
	}

	uwacom_event(usbwcmp, EVT_SYN, SYN_REPORT, 0);
}

static void
uwacom_pad_events_graphire4(usbwcm_state_t *usbwcmp, int b0, int b1, int b4,
    int b5, int rel, int abs)
{
	uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_0, b0);
	uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_1, b1);
	uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_4, b4);
	uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_5, b5);
	uwacom_event(usbwcmp, EVT_REL, REL_WHEEL, rel);
	uwacom_event(usbwcmp, EVT_ABS, ABS_WHEEL, abs);
	uwacom_tool_events_graphire(usbwcmp, 1, b0 | b1 | b4 | b5 | rel | abs);
}

static void
usbwcm_input_graphire(usbwcm_state_t *usbwcmp, mblk_t *mp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;
	uint8_t *packet = mp->b_rptr;

	if (PACKET_BITS(0, 0, 8) != 0x02) {
		USB_DPRINTF_L1(PRINT_MASK_ALL, usbwcm_log_handle,
		    "unknown report type %02x received\n",
		    PACKET_BITS(0, 0, 8));
		return;
	}

	/* Tool in proximity */
	if (PACKET_BIT(1, 7)) {
		uwacom_pos_events_graphire(usbwcmp,
		    (PACKET_BITS(3, 0, 8) << 8) | PACKET_BITS(2, 0, 8),
		    (PACKET_BITS(5, 0, 8) << 8) | PACKET_BITS(4, 0, 8));

		if (!PACKET_BIT(1, 6)) {
			if (!PACKET_BIT(1, 5)) {
				sc->sc_tool[0] = BTN_TOOL_PEN;
				sc->sc_tool_id[0] = TOOL_ID_PEN;
			} else {
				sc->sc_tool[0] = BTN_TOOL_ERASER;
				sc->sc_tool_id[0] = TOOL_ID_ERASER;
			}

			uwacom_pen_events_graphire(usbwcmp,
			    (PACKET_BIT(7, 0) << 8) | PACKET_BITS(6, 0, 8),
			    PACKET_BIT(1, 1), PACKET_BIT(1, 2));
		} else {
			int wheel, distance;

			if (sc->sc_type->protocol == GRAPHIRE) {
				wheel = (PACKET_BIT(1, 5) ?
				    0 : -(int8_t)PACKET_BITS(6, 0, 8));
				distance = PACKET_BITS(7, 0, 6);
			} else {
				wheel = (PACKET_BIT(7, 2) << 2) -
				    PACKET_BITS(7, 0, 2);
				distance = PACKET_BITS(6, 0, 6);
			}

			sc->sc_tool[0] = BTN_TOOL_MOUSE;
			sc->sc_tool_id[0] = TOOL_ID_MOUSE;

			uwacom_mouse_events_graphire(usbwcmp, PACKET_BIT(1, 0),
			    PACKET_BIT(1, 2), PACKET_BIT(1, 1), wheel,
			    distance);
		}

		uwacom_tool_events_graphire(usbwcmp, 0, 1);

		/* Tool leaving proximity */
	} else if (sc->sc_tool_id[0]) {
		uwacom_pos_events_graphire(usbwcmp, 0, 0);

		if (sc->sc_tool[0] == BTN_TOOL_MOUSE)
			uwacom_mouse_events_graphire(usbwcmp, 0, 0, 0, 0, 0);
		else
			uwacom_pen_events_graphire(usbwcmp, 0, 0, 0);

		sc->sc_tool_id[0] = 0;
		uwacom_tool_events_graphire(usbwcmp, 0, 0);
	}

	/* Finger on pad: Graphire4 */
	if ((sc->sc_type->protocol == GRAPHIRE4) && PACKET_BITS(7, 3, 5)) {
		sc->sc_tool_id[1] = TOOL_ID_PAD;
		uwacom_pad_events_graphire4(usbwcmp, PACKET_BIT(7, 6), 0,
		    PACKET_BIT(7, 7), 0,
		    PACKET_BITS(7, 3, 2) - (PACKET_BIT(7, 5) << 2), 0);

	/* Finger on pad: MyOffice */
	} else if ((sc->sc_type->protocol == MYOFFICE) &&
	    (PACKET_BITS(7, 3, 4) || PACKET_BITS(8, 0, 8))) {
		sc->sc_tool_id[1] = TOOL_ID_PAD;
		uwacom_pad_events_graphire4(usbwcmp, PACKET_BIT(7, 3),
		    PACKET_BIT(7, 4), PACKET_BIT(7, 5), PACKET_BIT(7, 6), 0,
		    PACKET_BITS(8, 0, 7));

	/* Finger leaving pad */
	} else if (sc->sc_tool_id[1]) {
		sc->sc_tool_id[1] = 0;
		uwacom_pad_events_graphire4(usbwcmp, 0, 0, 0, 0, 0, 0);
	}
}

static void
uwacom_pos_events_intuos(usbwcm_state_t *usbwcmp, int x, int y, int distance)
{
	uwacom_event(usbwcmp, EVT_ABS, ABS_X, x);
	uwacom_event(usbwcmp, EVT_ABS, ABS_Y, y);
	uwacom_event(usbwcmp, EVT_ABS, ABS_DISTANCE, distance);
}

static void
uwacom_pen_events_intuos(usbwcm_state_t *usbwcmp, uint8_t *packet)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;
	int press, tilt_x, tilt_y, stl1, stl2;

	switch (sc->sc_type->protocol) {
	case INTUOS4S:
	case INTUOS4L:
		press = PACKET_BITS(7, 6, 10) << 1 | PACKET_BIT(1, 0);
		break;
	default:
		press = PACKET_BITS(7, 6, 10);
		break;
	}

	tilt_x = PACKET_BITS(8, 7, 7);
	tilt_y = PACKET_BITS(8, 0, 7);
	stl1 = PACKET_BIT(1, 1);
	stl2 = PACKET_BIT(1, 2);

	uwacom_event(usbwcmp, EVT_ABS, ABS_PRESSURE, press);
	uwacom_event(usbwcmp, EVT_ABS, ABS_TILT_X, tilt_x);
	uwacom_event(usbwcmp, EVT_ABS, ABS_TILT_Y, tilt_y);
	uwacom_event(usbwcmp, EVT_BTN, BTN_TIP, press);
	uwacom_event(usbwcmp, EVT_BTN, BTN_STYLUS_1, stl1);
	uwacom_event(usbwcmp, EVT_BTN, BTN_STYLUS_2, stl2);
}

static void
uwacom_mouse_events_intuos(usbwcm_state_t *usbwcmp, uint8_t *packet)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;
	int left, middle, right, extra, side, wheel;

	switch (sc->sc_type->protocol) {
	case INTUOS4S:
	case INTUOS4L:
		left = PACKET_BIT(6, 0);
		middle = PACKET_BIT(6, 1);
		right = PACKET_BIT(6, 2);
		side = PACKET_BIT(6, 3);
		extra = PACKET_BIT(6, 4);
		wheel = PACKET_BIT(7, 7) - PACKET_BIT(7, 6);
		break;

	default:
		left = PACKET_BIT(8, 2);
		middle = PACKET_BIT(8, 3);
		right = PACKET_BIT(8, 4);
		extra = PACKET_BIT(8, 5);
		side = PACKET_BIT(8, 6);
		wheel = PACKET_BIT(8, 0) - PACKET_BIT(8, 1);
		break;
	}

	uwacom_event(usbwcmp, EVT_BTN, BTN_LEFT, left);
	uwacom_event(usbwcmp, EVT_BTN, BTN_MIDDLE, middle);
	uwacom_event(usbwcmp, EVT_BTN, BTN_RIGHT, right);
	uwacom_event(usbwcmp, EVT_BTN, BTN_EXTRA, extra);
	uwacom_event(usbwcmp, EVT_BTN, BTN_SIDE, side);
	uwacom_event(usbwcmp, EVT_REL, REL_WHEEL, wheel);
}

static void
uwacom_tool_events_intuos(usbwcm_state_t *usbwcmp, int idx, int proximity)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	uwacom_event(usbwcmp, EVT_BTN, sc->sc_tool[idx], proximity);
	uwacom_event(usbwcmp, EVT_ABS, ABS_MISC, sc->sc_tool_id[idx]);
	uwacom_event(usbwcmp, EVT_MSC, MSC_SERIAL, sc->sc_serial[idx]);
	uwacom_event(usbwcmp, EVT_SYN, SYN_REPORT, 0);
}

static void
uwacom_pad_events_intuos(usbwcm_state_t *usbwcmp, uint8_t *packet)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;
	int b0, b1, b2, b3, b4, b5, b6, b7;
	int rx, ry, prox;
	int b8, whl, rot;

	switch (sc->sc_type->protocol) {
	case INTUOS4L:
		b7 = PACKET_BIT(3, 6);
		b8 = PACKET_BIT(3, 7);

		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_7, b7);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_8, b8);
	/*FALLTHRU*/
	case INTUOS4S:
		b0 = PACKET_BIT(2, 0);
		b1 = PACKET_BIT(3, 0);
		b2 = PACKET_BIT(3, 1);
		b3 = PACKET_BIT(3, 2);
		b4 = PACKET_BIT(3, 3);
		b5 = PACKET_BIT(3, 4);
		b6 = PACKET_BIT(3, 5);

		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_0, b0);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_1, b1);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_2, b2);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_3, b3);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_4, b4);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_5, b5);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_6, b6);

		whl = PACKET_BIT(1, 7);
		if (whl) {
			rot = PACKET_BITS(1, 0, 7);
			uwacom_event(usbwcmp, EVT_ABS, ABS_WHEEL, rot);
		}

		prox = b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | whl;
		uwacom_tool_events_intuos(usbwcmp, 1, prox);

		break;

	default:
		b0 = PACKET_BIT(5, 0);
		b1 = PACKET_BIT(5, 1);
		b2 = PACKET_BIT(5, 2);
		b3 = PACKET_BIT(5, 3);
		b4 = PACKET_BIT(6, 0);
		b5 = PACKET_BIT(6, 1);
		b6 = PACKET_BIT(6, 2);
		b7 = PACKET_BIT(6, 3);
		rx = PACKET_BITS(2, 0, 13);
		ry = PACKET_BITS(4, 0, 13);

		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_0, b0);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_1, b1);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_2, b2);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_3, b3);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_4, b4);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_5, b5);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_6, b6);
		uwacom_event(usbwcmp, EVT_BTN, BTN_MISC_7, b7);
		uwacom_event(usbwcmp, EVT_ABS, ABS_RX, rx);
		uwacom_event(usbwcmp, EVT_ABS, ABS_RY, ry);

		prox = b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7 | rx | ry;
		uwacom_tool_events_intuos(usbwcmp, 1, prox);

		break;
	}
}

static void
usbwcm_input_intuos(usbwcm_state_t *usbwcmp, mblk_t *mp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;
	uint8_t *packet = mp->b_rptr;

	switch (PACKET_BITS(0, 0, 8)) {
	case 0x02:
		switch (PACKET_BITS(1, 5, 2)) {
		/* Tool entering proximity */
		case 0x2:
			sc->sc_tool_id[0] = PACKET_BITS(3, 4, 12);
			sc->sc_serial[0] =
			    (PACKET_BIT(1, 1) ? PACKET_BITS(7, 4, 32) : 0);

			switch (sc->sc_tool_id[0]) {
			case 0x802: /* Intuos4 Grip Pen */
			case 0x804: /* Intuos4 Art Marker */
			case 0x823: /* Intuos3 Grip Pen */
			case 0x885: /* Intuos3 Art Marker */
				sc->sc_tool[0] = BTN_TOOL_PEN;
				break;
			case 0x80a: /* Intuos4 Grip Pen eraser */
			case 0x82b: /* Intuos3 Grip Pen eraser */
				sc->sc_tool[0] = BTN_TOOL_ERASER;
				break;
			case 0x017: /* Intuos3 2D mouse */
			case 0x806: /* Intuos4 2D mouse */
				sc->sc_tool[0] = BTN_TOOL_MOUSE;
				break;
			default:
				USB_DPRINTF_L1(PRINT_MASK_ALL,
				    usbwcm_log_handle,
				    "unknown tool ID %03x seen\n",
				    sc->sc_tool_id[0]);
				sc->sc_tool[0] = BTN_TOOL_PEN;
			}
			break;

		/* Tool leaving proximity */
		case 0x0:
			uwacom_pos_events_intuos(usbwcmp, 0, 0, 0);

			if (sc->sc_tool[0] == BTN_TOOL_MOUSE)
				uwacom_mouse_events_intuos(usbwcmp, packet);
			else
				uwacom_pen_events_intuos(usbwcmp, packet);

			sc->sc_tool_id[0] = 0;
			uwacom_tool_events_intuos(usbwcmp, 0, 0);
			break;

		/* Tool motion, outbound */
		case 0x1:
		/* Outbound tracking is unreliable on the Cintiq */
			if (sc->sc_type->protocol == CINTIQ)
				break;

		/* Tool motion */
		/*FALLTHRU*/
		case 0x3:
			uwacom_pos_events_intuos(usbwcmp,
			    (PACKET_BITS(3, 0, 16) << 1) | PACKET_BIT(9, 1),
			    (PACKET_BITS(5, 0, 16) << 1) | PACKET_BIT(9, 0),
			    PACKET_BITS(9, 2, 6));

			if (PACKET_BITS(1, 3, 2) == 0) {
				uwacom_pen_events_intuos(usbwcmp, packet);

			} else if (PACKET_BITS(1, 1, 4) == 0x5) {
				int angle = 450 - PACKET_BITS(7, 6, 10);

				if (PACKET_BIT(7, 5)) {
					angle = (angle > 0 ? 900 : -900) -
					    angle;
				}

				uwacom_event(usbwcmp, EVT_ABS, ABS_Z, angle);
				break;
			} else if (PACKET_BITS(1, 1, 4) == 0x8) {
				uwacom_mouse_events_intuos(usbwcmp, packet);
			} else {
				USB_DPRINTF_L1(PRINT_MASK_ALL,
				    usbwcm_log_handle,
				    "unsupported motion packet type %x "
				    "received\n", PACKET_BITS(1, 1, 4));
			}

			uwacom_tool_events_intuos(usbwcmp, 0, 1);
			break;
		}

		break;

	case 0x0c:
		uwacom_pad_events_intuos(usbwcmp, packet);
		break;

	default:
		USB_DPRINTF_L1(PRINT_MASK_ALL, usbwcm_log_handle,
		    "unknown report type %02x received\n",
		    PACKET_BITS(0, 0, 8));
	}
}

static void
uwacom_init_abs(usbwcm_state_t *usbwcmp, int axis, int32_t min, int32_t max,
    int32_t fuzz, int32_t flat)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	sc->sc_abs[axis].min = min;
	sc->sc_abs[axis].max = max;
	sc->sc_abs[axis].fuzz = fuzz;
	sc->sc_abs[axis].flat = flat;
}

static void
uwacom_init_graphire4(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[0], EVT_MSC);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_0);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_4);
	BM_SET_BIT(sc->sc_bm[1], BTN_TOOL_PAD);
	BM_SET_BIT(sc->sc_bm[4], MSC_SERIAL);

	sc->sc_tool[1] = BTN_TOOL_PAD;
	sc->sc_serial[1] = SERIAL_PAD_GRAPHIRE4;
}

static void
uwacom_init_myoffice(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_1);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_5);
	BM_SET_BIT(sc->sc_bm[3], ABS_WHEEL);

	uwacom_init_abs(usbwcmp, ABS_WHEEL, 0, 71, 0, 0);
}

static void
uwacom_init_intuos(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[0], EVT_MSC);

	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_0);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_1);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_2);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_3);
	BM_SET_BIT(sc->sc_bm[1], BTN_SIDE);
	BM_SET_BIT(sc->sc_bm[1], BTN_EXTRA);
	BM_SET_BIT(sc->sc_bm[1], BTN_TOOL_PAD);

	BM_SET_BIT(sc->sc_bm[3], ABS_TILT_X);
	BM_SET_BIT(sc->sc_bm[3], ABS_TILT_Y);

	BM_SET_BIT(sc->sc_bm[4], MSC_SERIAL);

	sc->sc_tool[1] = BTN_TOOL_PAD;
	sc->sc_tool_id[1] = TOOL_ID_PAD;
	sc->sc_serial[1] = SERIAL_PAD_INTUOS;
}

static void
uwacom_init_intuos3(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[3], ABS_Z);
	BM_SET_BIT(sc->sc_bm[3], ABS_RX);

	uwacom_init_abs(usbwcmp, ABS_Z, -900,  899, 0, 0);
	uwacom_init_abs(usbwcmp, ABS_RX, 0, 4096, 0, 0);
}

static void
uwacom_init_intuos3_large(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_4);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_5);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_6);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_7);

	BM_SET_BIT(sc->sc_bm[3], ABS_RY);

	uwacom_init_abs(usbwcmp, ABS_RY, 0, 4096, 0, 0);
}

static void
uwacom_init_intuos4(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_4);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_5);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_6);

	BM_SET_BIT(sc->sc_bm[3], ABS_Z);

	uwacom_init_abs(usbwcmp, ABS_Z, -900,  899, 0, 0);
}
static void
uwacom_init_intuos4_large(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_7);
	BM_SET_BIT(sc->sc_bm[1], BTN_MISC_8);
}

static int
uwacom_init(usbwcm_state_t *usbwcmp)
{
	struct uwacom_softc *sc = &usbwcmp->usbwcm_softc;

	sc->sc_id.bus = ID_BUS_USB;
	sc->sc_id.vendor = usbwcmp->usbwcm_devid.VendorId;
	sc->sc_id.product = usbwcmp->usbwcm_devid.ProductId;

	sc->sc_id.version = 0;

	for (int i = 0; i < EVT_USED; ++i)
		sc->sc_bm[i] = kmem_zalloc(bm_size[i], KM_SLEEP);

	sc->sc_btn = kmem_zalloc(BTN_USED * sizeof (int), KM_SLEEP);
	sc->sc_abs = kmem_zalloc(ABS_USED * sizeof (struct event_abs_axis),
	    KM_SLEEP);

	BM_SET_BIT(sc->sc_bm[0], EVT_SYN);
	BM_SET_BIT(sc->sc_bm[0], EVT_BTN);
	BM_SET_BIT(sc->sc_bm[0], EVT_REL);
	BM_SET_BIT(sc->sc_bm[0], EVT_ABS);

	BM_SET_BIT(sc->sc_bm[1], BTN_LEFT);
	BM_SET_BIT(sc->sc_bm[1], BTN_RIGHT);
	BM_SET_BIT(sc->sc_bm[1], BTN_MIDDLE);
	BM_SET_BIT(sc->sc_bm[1], BTN_TOOL_PEN);
	BM_SET_BIT(sc->sc_bm[1], BTN_TOOL_ERASER);
	BM_SET_BIT(sc->sc_bm[1], BTN_TOOL_MOUSE);
	BM_SET_BIT(sc->sc_bm[1], BTN_TIP);
	BM_SET_BIT(sc->sc_bm[1], BTN_STYLUS_1);
	BM_SET_BIT(sc->sc_bm[1], BTN_STYLUS_2);

	BM_SET_BIT(sc->sc_bm[2], REL_WHEEL);

	BM_SET_BIT(sc->sc_bm[3], ABS_X);
	BM_SET_BIT(sc->sc_bm[3], ABS_Y);
	BM_SET_BIT(sc->sc_bm[3], ABS_PRESSURE);
	BM_SET_BIT(sc->sc_bm[3], ABS_DISTANCE);
	BM_SET_BIT(sc->sc_bm[3], ABS_MISC);

	uwacom_init_abs(usbwcmp, ABS_X, 0, sc->sc_type->x_max, 4, 0);
	uwacom_init_abs(usbwcmp, ABS_Y, 0, sc->sc_type->y_max, 4, 0);
	uwacom_init_abs(usbwcmp, ABS_PRESSURE, 0, sc->sc_type->pressure_max,
	    0, 0);
	uwacom_init_abs(usbwcmp, ABS_DISTANCE, 0,
	    uwacom_protocols[sc->sc_type->protocol].distance_max, 0, 0);

	switch (sc->sc_type->protocol) {
		case CINTIQ:
		case INTUOS3L:
			uwacom_init_intuos3_large(usbwcmp);
		/*FALLTHRU*/
		case INTUOS3S:
			uwacom_init_intuos3(usbwcmp);
			uwacom_init_intuos(usbwcmp);
			break;

		case INTUOS4L:
			uwacom_init_intuos4_large(usbwcmp);
		/*FALLTHRU*/
		case INTUOS4S:
			uwacom_init_intuos4(usbwcmp);
			uwacom_init_intuos(usbwcmp);
			break;
		case MYOFFICE:
			uwacom_init_myoffice(usbwcmp);
		/*FALLTHRU*/
		case GRAPHIRE4:
			uwacom_init_graphire4(usbwcmp);
		/*FALLTHRU*/
		case GRAPHIRE:
			break;
	}

	return (0);
}

/*
 * usbwcm_match() :
 *	Match device with it's parameters.
 */
static const struct uwacom_type *
usbwcm_match(uint16_t vid, uint16_t pid)
{
	const struct uwacom_type *dev;

	dev = uwacom_devs;
	while (dev->devno.vid != 0 && dev->devno.pid != 0) {
		if (dev->devno.vid == vid && dev->devno.pid == pid) {
			return (dev);
		}
		dev++;
	}

	return (NULL);
}

/*
 * usbwcm_probe() :
 *	Check the device type and protocol.
 */
static int
usbwcm_probe(usbwcm_state_t *usbwcmp)
{
	queue_t		*q = usbwcmp->usbwcm_rq;
	mblk_t		*mctl_ptr;
	struct iocblk	mctlmsg;
	hid_req_t	*featr;

	/* check device IDs */
	mctlmsg.ioc_cmd = HID_GET_VID_PID;
	mctlmsg.ioc_count = 0;

	mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
	if (mctl_ptr == NULL) {
		return (ENOMEM);
	}

	putnext(usbwcmp->usbwcm_wq, mctl_ptr);
	usbwcmp->usbwcm_flags |= USBWCM_QWAIT;

	while (usbwcmp->usbwcm_flags & USBWCM_QWAIT) {
		if (qwait_sig(q) == 0) {
			usbwcmp->usbwcm_flags = 0;
			return (EINTR);
		}
	}

	usbwcmp->usbwcm_softc.sc_type =
	    usbwcm_match(usbwcmp->usbwcm_devid.VendorId,
	    usbwcmp->usbwcm_devid.ProductId);
	if (!usbwcmp->usbwcm_softc.sc_type) {
		USB_DPRINTF_L1(PRINT_MASK_ALL, usbwcm_log_handle,
		    "unsupported tablet model\n");
		return (ENXIO);
	}

	if (uwacom_init(usbwcmp) != 0) {
		return (ENXIO);
	}

	/* set feature: tablet mode */
	featr = kmem_zalloc(sizeof (hid_req_t), KM_SLEEP);
	featr->hid_req_version_no = HID_VERSION_V_0;
	featr->hid_req_wValue = REPORT_TYPE_FEATURE | 2;
	featr->hid_req_wLength = sizeof (uint8_t) * 2;
	featr->hid_req_data[0] = 2;
	featr->hid_req_data[1] = 2;

	mctlmsg.ioc_cmd = HID_SET_REPORT;
	mctlmsg.ioc_count = sizeof (featr);
	mctl_ptr = usba_mk_mctl(mctlmsg, featr, sizeof (hid_req_t));
	if (mctl_ptr != NULL) {
		putnext(usbwcmp->usbwcm_wq, mctl_ptr);

		/*
		 * Waiting for response of HID_SET_REPORT
		 * mctl for setting the feature.
		 */
		usbwcmp->usbwcm_flags |= USBWCM_QWAIT;
		while (usbwcmp->usbwcm_flags & USBWCM_QWAIT) {
			qwait(q);
		}
	} else {
		USB_DPRINTF_L1(PRINT_MASK_ALL, usbwcm_log_handle,
		    "enable tablet mode failed\n");
	}

	kmem_free(featr, sizeof (hid_req_t));

	return (0);
}

/*
 * usbwcm_copyreq() :
 *	helper function for usbwcm ioctls
 */
static int
usbwcm_copyreq(mblk_t *mp, uint_t pvtsize, uint_t state, uint_t reqsize,
    uint_t contsize, uint_t copytype)
{
	usbwcm_copyin_t	*copystat;
	mblk_t		*iocmp, *contmp;
	struct copyreq	*cq;
	struct copyresp	*cr;

	if ((pvtsize == 0) && (state != 0)) {
		cr = (struct copyresp *)mp->b_rptr;
		iocmp = cr->cp_private;
	}

	cq = (struct copyreq *)mp->b_rptr;
	if (mp->b_cont == NULL) {

		return (EINVAL);
	}

	cq->cq_addr = *((caddr_t *)mp->b_cont->b_rptr);
	cq->cq_size = reqsize;
	cq->cq_flag = 0;

	if (pvtsize) {
		iocmp = (mblk_t *)allocb(pvtsize, BPRI_MED);
		if (iocmp == NULL) {

			return (EAGAIN);
		}
		cq->cq_private = iocmp;
		iocmp = cq->cq_private;
	} else {
		/*
		 * Here we need to set cq_private even if there's
		 * no private data, otherwise its value will be
		 * TRANSPARENT (-1) on 64bit systems because it
		 * overlaps iocp->ioc_count. If user address (cq_addr)
		 * is invalid, it would cause panic later in
		 * usbwcm_copyin:
		 * 	freemsg((mblk_t *)copyresp->cp_private);
		 */
		cq->cq_private = NULL;
	}

	if (state) {
		copystat = (usbwcm_copyin_t *)iocmp->b_rptr;
		copystat->state = state;
		if (pvtsize) {  /* M_COPYIN */
			copystat->addr = cq->cq_addr;
		} else {
			cq->cq_addr = copystat->addr;
			cq->cq_private = iocmp;
		}
		iocmp->b_wptr = iocmp->b_rptr + sizeof (usbwcm_copyin_t);
	}

	if (contsize) {
		contmp = (mblk_t *)allocb(contsize, BPRI_MED);
		if (contmp == NULL) {

			return (EAGAIN);
		}
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = contmp;
		}
	}

	mp->b_datap->db_type = (unsigned char)copytype;
	mp->b_wptr = mp->b_rptr + sizeof (struct copyreq);

	return (0);
}

static void
usbwcm_miocack(queue_t *q, mblk_t *mp, int rval)
{
	struct iocblk	*iocbp = (struct iocblk *)mp->b_rptr;

	mp->b_datap->db_type = M_IOCACK;
	mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);

	iocbp->ioc_error = 0;
	iocbp->ioc_count = 0;
	iocbp->ioc_rval = rval;

	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	qreply(q, mp);
}

/*
 * usbwcm_iocpy() :
 * M_IOCDATA processing for IOCTL's
 */
static void
usbwcm_iocpy(queue_t *q, mblk_t *mp)
{
	usbwcm_state_t		*usbwcmp = (usbwcm_state_t *)q->q_ptr;
	struct uwacom_softc	*sc = &usbwcmp->usbwcm_softc;
	struct copyresp		*copyresp;
	usbwcm_copyin_t 	*copystat;
	mblk_t			*datap, *ioctmp;
	struct iocblk		*iocbp;
	int			err = 0;

	copyresp = (struct copyresp *)mp->b_rptr;
	iocbp = (struct iocblk *)mp->b_rptr;
	if (copyresp->cp_rval) {
		err = EAGAIN;

		goto out;
	}

	switch (copyresp->cp_cmd) {
	default: {
		int num = copyresp->cp_cmd & 0xff;
		int len = IOCPARM_MASK & (copyresp->cp_cmd >> 16);

		if (((copyresp->cp_cmd >> 8) & 0xFF) != 'E') {
			putnext(q, mp); /* pass it down the line */
			return;

		} else if ((copyresp->cp_cmd & IOC_INOUT) != IOC_OUT) {
			err = EINVAL;
			break;
		}

		switch (num) {
		case EUWACOMGETVERSION:
			ioctmp = copyresp->cp_private;
			copystat = (usbwcm_copyin_t *)ioctmp->b_rptr;
			if (copystat->state == USBWCM_GETSTRUCT) {
				if (mp->b_cont == NULL) {
					err = EINVAL;

					break;
				}
				datap = (mblk_t *)mp->b_cont;

				*(int *)datap->b_rptr = 0x00010000;

				if (err = usbwcm_copyreq(mp, 0,
				    USBWCM_GETRESULT, sizeof (int), 0,
				    M_COPYOUT)) {

					goto out;
				}
			} else if (copystat->state == USBWCM_GETRESULT) {
				freemsg(ioctmp);
				usbwcm_miocack(q, mp, 0);
				return;
			}
			break;

		case EUWACOMGETID:
			ioctmp = copyresp->cp_private;
			copystat = (usbwcm_copyin_t *)ioctmp->b_rptr;
			if (copystat->state == USBWCM_GETSTRUCT) {
				if (mp->b_cont == NULL) {
					err = EINVAL;

					break;
				}
				datap = (mblk_t *)mp->b_cont;

				bcopy(&sc->sc_id, datap->b_rptr,
				    sizeof (struct event_dev_id));

				if (err = usbwcm_copyreq(mp, 0,
				    USBWCM_GETRESULT,
				    sizeof (struct event_dev_id), 0,
				    M_COPYOUT)) {

					goto out;
				}
			} else if (copystat->state == USBWCM_GETRESULT) {
				freemsg(ioctmp);
				usbwcm_miocack(q, mp, 0);
				return;
			}
			break;

		default:
			if (num >= EUWACOMGETBM &&
			    num < EUWACOMGETBM + EVT_USED) {
				int idx = num - EUWACOMGETBM;
				size_t length = min(bm_size[idx], len);

				ioctmp = copyresp->cp_private;
				copystat = (usbwcm_copyin_t *)ioctmp->b_rptr;
				if (copystat->state == USBWCM_GETSTRUCT) {
					if (mp->b_cont == NULL) {
						err = EINVAL;

						break;
					}
					datap = (mblk_t *)mp->b_cont;

					bcopy(sc->sc_bm[idx], datap->b_rptr,
					    length);

					if (err = usbwcm_copyreq(mp, 0,
					    USBWCM_GETRESULT, length, 0,
					    M_COPYOUT)) {

						goto out;
					}

				} else if (copystat->state ==
				    USBWCM_GETRESULT) {
					freemsg(ioctmp);
					usbwcm_miocack(q, mp, length);
					return;
				}
				break;

			} else if (num >= EUWACOMGETABS &&
			    num < EUWACOMGETABS + ABS_USED) {
				int idx = num - EUWACOMGETABS;

				ioctmp = copyresp->cp_private;
				copystat = (usbwcm_copyin_t *)ioctmp->b_rptr;
				if (copystat->state == USBWCM_GETSTRUCT) {
					if (mp->b_cont == NULL) {
						err = EINVAL;

						break;
					}
					datap = (mblk_t *)mp->b_cont;

					bcopy(&sc->sc_abs[idx], datap->b_rptr,
					    sizeof (struct event_abs_axis));

					if (err = usbwcm_copyreq(mp, 0,
					    USBWCM_GETRESULT,
					    sizeof (struct event_abs_axis), 0,
					    M_COPYOUT)) {

						goto out;
					}

				} else if (copystat->state ==
				    USBWCM_GETRESULT) {
					freemsg(ioctmp);
					usbwcm_miocack(q, mp, 0);
					return;
				}
				break;

			} else {
				err = EINVAL;
				break;
			}
		}
	}
	}

out:
	if (err) {
		mp->b_datap->db_type = M_IOCNAK;
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = (mblk_t *)NULL;
		}
		if (copyresp->cp_private) {
			freemsg((mblk_t *)copyresp->cp_private);
			copyresp->cp_private = (mblk_t *)NULL;
		}
		iocbp->ioc_count = 0;
		iocbp->ioc_error = err;
	}

	qreply(q, mp);
}

/*
 * usbwcm_ioctl() :
 *	Process ioctls we recognize and own.  Otherwise, NAK.
 */
static void
usbwcm_ioctl(queue_t *q, mblk_t *mp)
{
	usbwcm_state_t		*usbwcmp = (usbwcm_state_t *)q->q_ptr;
	struct uwacom_softc	*sc;
	mblk_t			*datap;
	struct iocblk		*iocp;
	int			err = 0;

	if (usbwcmp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	sc = &usbwcmp->usbwcm_softc;
	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	default: {
		int num = iocp->ioc_cmd & 0xff;
		int len = IOCPARM_MASK & (iocp->ioc_cmd >> 16);

		if (((iocp->ioc_cmd >> 8) & 0xFF) != 'E') {
			putnext(q, mp); /* pass it down the line */
			return;

		} else if ((iocp->ioc_cmd & IOC_INOUT) != IOC_OUT) {
			err = EINVAL;
			break;
		}

		switch (num) {
		case EUWACOMGETVERSION:
			if (iocp->ioc_count == TRANSPARENT) {
				if (err = usbwcm_copyreq(mp,
				    sizeof (usbwcm_copyin_t), USBWCM_GETSTRUCT,
				    sizeof (int), 0, M_COPYIN)) {
					break;
				}
				freemsg(mp->b_cont);
				mp->b_cont = (mblk_t *)NULL;

				qreply(q, mp);
				return;
			}

			if (mp->b_cont == NULL ||
			    iocp->ioc_count != sizeof (int)) {
				err = EINVAL;
				break;
			}
			datap = mp->b_cont;

			*(int *)datap->b_rptr = 0x00010000;

			break;

		case EUWACOMGETID:
			if (iocp->ioc_count == TRANSPARENT) {
				if (err = usbwcm_copyreq(mp,
				    sizeof (usbwcm_copyin_t), USBWCM_GETSTRUCT,
				    sizeof (struct event_dev_id), 0,
				    M_COPYIN)) {
					break;
				}
				freemsg(mp->b_cont);
				mp->b_cont = (mblk_t *)NULL;

				qreply(q, mp);
				return;
			}

			if (mp->b_cont == NULL ||
			    iocp->ioc_count != sizeof (struct event_dev_id)) {
				err = EINVAL;
				break;
			}
			datap = mp->b_cont;

			bcopy(&sc->sc_id, datap->b_rptr,
			    sizeof (struct event_dev_id));

			break;

		default:
			if (num >= EUWACOMGETBM &&
			    num < EUWACOMGETBM + EVT_USED) {
				int idx = num - EUWACOMGETBM;
				size_t length = min(bm_size[idx], len);

				if (iocp->ioc_count == TRANSPARENT) {
					if (err = usbwcm_copyreq(mp,
					    sizeof (usbwcm_copyin_t),
					    USBWCM_GETSTRUCT, length, 0,
					    M_COPYIN)) {
						break;
					}
					freemsg(mp->b_cont);
					mp->b_cont = (mblk_t *)NULL;

					qreply(q, mp);
					return;
				}

				if (mp->b_cont == NULL ||
				    iocp->ioc_count != length) {
					err = EINVAL;
					break;
				}
				datap = mp->b_cont;

				bcopy(sc->sc_bm[idx], datap->b_rptr, length);

				break;

			} else if (num >= EUWACOMGETABS &&
			    num < EUWACOMGETABS + ABS_USED) {
				int idx = num - EUWACOMGETABS;

				if (iocp->ioc_count == TRANSPARENT) {
					if (err = usbwcm_copyreq(mp,
					    sizeof (usbwcm_copyin_t),
					    USBWCM_GETSTRUCT,
					    sizeof (struct event_abs_axis), 0,
					    M_COPYIN)) {
						break;
					}
					freemsg(mp->b_cont);
					mp->b_cont = (mblk_t *)NULL;

					qreply(q, mp);
					return;
				}

				if (mp->b_cont == NULL ||
				    iocp->ioc_count !=
				    sizeof (struct event_abs_axis)) {
					err = EINVAL;
					break;
				}
				datap = mp->b_cont;

				bcopy(&sc->sc_abs[idx], datap->b_rptr,
				    sizeof (struct event_abs_axis));

				break;

			} else {
				err = EINVAL;
				break;
			}
		}
	}
	}

	if (err != 0)
		miocnak(q, mp, 0, err);
	else {
		iocp->ioc_rval = 0;
		iocp->ioc_error = 0;
		mp->b_datap->db_type = M_IOCACK;
		qreply(q, mp);
		/* REMOVE */
	}

	return;

}

/*
 * usbwcm_input() :
 *
 *	Wacom input routine; process data received from a device and
 *	assemble into a input event for the window system.
 *
 *	Watch out for overflow!
 */
static void
usbwcm_input(usbwcm_state_t *usbwcmp, mblk_t *mp)
{
	struct uwacom_softc	*sc = &usbwcmp->usbwcm_softc;

	switch (sc->sc_type->protocol) {
	case GRAPHIRE:
	case GRAPHIRE4:
	case MYOFFICE:
		usbwcm_input_graphire(usbwcmp, mp);
		break;

	case INTUOS3S:
	case INTUOS3L:
	case INTUOS4S:
	case INTUOS4L:
	case CINTIQ:
		usbwcm_input_intuos(usbwcmp, mp);
		break;
	}
}

/*
 * usbwcm_flush() :
 *	Resets the soft state to default values
 *	and sends M_FLUSH above.
 */
static void
usbwcm_flush(usbwcm_state_t *usbwcmp)
{
	queue_t			*q;

	if ((q = usbwcmp->usbwcm_rq) != NULL && q->q_next != NULL) {
		(void) putnextctl1(q, M_FLUSH, FLUSHR);
	}
}

/*
 * usbwcm_mctl() :
 *	Handle M_CTL messages from hid.  If
 *	we don't understand the command, free message.
 */
static void
usbwcm_mctl(queue_t *q, mblk_t *mp)
{
	usbwcm_state_t	*usbwcmp = (usbwcm_state_t *)q->q_ptr;
	struct iocblk	*iocp;
	caddr_t		data = NULL;
	struct iocblk	mctlmsg;
	mblk_t		*mctl_ptr;
	hid_req_t	*featr;

	iocp = (struct iocblk *)mp->b_rptr;
	if (mp->b_cont != NULL)
		data = (caddr_t)mp->b_cont->b_rptr;

	switch (iocp->ioc_cmd) {
	case HID_GET_VID_PID:
		if ((data != NULL) &&
		    (iocp->ioc_count == sizeof (hid_vid_pid_t)) &&
		    (MBLKL(mp->b_cont) == iocp->ioc_count)) {
			bcopy(data, &usbwcmp->usbwcm_devid, iocp->ioc_count);
		}

		freemsg(mp);
		usbwcmp->usbwcm_flags &= ~USBWCM_QWAIT;
		break;

	case HID_CONNECT_EVENT:
		/* set feature: tablet mode */
		featr = kmem_zalloc(sizeof (hid_req_t), KM_SLEEP);
		featr->hid_req_version_no = HID_VERSION_V_0;
		featr->hid_req_wValue = REPORT_TYPE_FEATURE | 2;
		featr->hid_req_wLength = sizeof (uint8_t) * 2;
		featr->hid_req_data[0] = 2;
		featr->hid_req_data[1] = 2;

		mctlmsg.ioc_cmd = HID_SET_REPORT;
		mctlmsg.ioc_count = sizeof (featr);
		mctl_ptr = usba_mk_mctl(mctlmsg, featr, sizeof (hid_req_t));
		if (mctl_ptr != NULL) {
			putnext(usbwcmp->usbwcm_wq, mctl_ptr);
		} else {
		USB_DPRINTF_L1(PRINT_MASK_ALL, usbwcm_log_handle,
		    "enable tablet mode failed\n");
		}

		kmem_free(featr, sizeof (hid_req_t));
		freemsg(mp);
		break;

	case HID_SET_REPORT:
		/* FALLTHRU */

	case HID_SET_PROTOCOL:
		usbwcmp->usbwcm_flags &= ~USBWCM_QWAIT;
		/* FALLTHRU */

	default:
		freemsg(mp);
	}
}

/*
 * usbwcm_open() :
 *	open() entry point for the USB wacom module.
 */
/*ARGSUSED*/
static int
usbwcm_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	usbwcm_state_t	*usbwcmp;

	/* Clone opens are not allowed */
	if (sflag != MODOPEN)
		return (EINVAL);

	/* If the module is already open, just return */
	if (q->q_ptr) {
		return (0);
	}

	/* allocate usbwcm state structure */
	usbwcmp = kmem_zalloc(sizeof (usbwcm_state_t), KM_SLEEP);

	q->q_ptr = usbwcmp;
	WR(q)->q_ptr = usbwcmp;

	usbwcmp->usbwcm_rq = q;
	usbwcmp->usbwcm_wq = WR(q);

	qprocson(q);

	if (usbwcm_probe(usbwcmp) != 0) {

		qprocsoff(q);
		kmem_free(usbwcmp, sizeof (usbwcm_state_t));

		return (EINVAL);
	}

	usbwcm_flush(usbwcmp);

	usbwcmp->usbwcm_flags |= USBWCM_OPEN;
	return (0);
}


/*
 * usbwcm_close() :
 *	close() entry point for the USB wacom module.
 */
/*ARGSUSED*/
static int
usbwcm_close(queue_t *q, int flag, cred_t *credp)
{
	usbwcm_state_t		*usbwcmp = q->q_ptr;
	struct uwacom_softc	*sc = &usbwcmp->usbwcm_softc;

	qprocsoff(q);

	if (usbwcmp->usbwcm_bufcall) {
		qunbufcall(q, (bufcall_id_t)(long)usbwcmp->usbwcm_bufcall);
		usbwcmp->usbwcm_bufcall = 0;
	}

	if (usbwcmp->usbwcm_mioctl != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(usbwcmp->usbwcm_mioctl);
		usbwcmp->usbwcm_mioctl = NULL;
	}

	for (int i = 0; i < EVT_USED; i++)
		kmem_free(sc->sc_bm[i], bm_size[i]);

	kmem_free(sc->sc_btn, BTN_USED * sizeof (int));
	kmem_free(sc->sc_abs, ABS_USED * sizeof (struct event_abs_axis));
	kmem_free(usbwcmp, sizeof (usbwcm_state_t));

	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * usbwcm_wput() :
 *	wput() routine for the wacom module.
 *	Module below : hid, module above : consms
 */
static int
usbwcm_wput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {

	case M_FLUSH:  /* Canonical flush handling */
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
		}
		putnext(q, mp); /* pass it down the line. */
		break;

	case M_IOCTL:
		usbwcm_ioctl(q, mp);
		break;

	case M_IOCDATA:
		usbwcm_iocpy(q, mp);
		break;

	default:
		putnext(q, mp); /* pass it down the line. */
	}

	return (0);
}

/*
 * usbwcm_rput() :
 *	Put procedure for input from driver end of stream (read queue).
 */
static void
usbwcm_rput(queue_t *q, mblk_t *mp)
{
	usbwcm_state_t		*usbwcmp = q->q_ptr;
	struct uwacom_softc	*sc = &usbwcmp->usbwcm_softc;
	mblk_t			*mp0 = mp;
	int			limit;

	if (usbwcmp == 0) {
		freemsg(mp);	/* nobody's listening */
		return;
	}

	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW)
			flushq(WR(q), FLUSHDATA);

		if (*mp->b_rptr & FLUSHR)
			flushq(q, FLUSHDATA);

		freemsg(mp);
		return;

	case M_BREAK:
		/*
		 * We don't have to handle this
		 * because nothing is sent from the downstream
		 */
		freemsg(mp);
		return;

	case M_DATA:
		if (!(usbwcmp->usbwcm_flags & USBWCM_OPEN)) {
			freemsg(mp);	/* not ready to listen */

			return;
		}

		/*
		 * Make sure there are at least "limit" number of bytes.
		 */
		limit = uwacom_protocols[sc->sc_type->protocol].packet_size;
		if (MBLKL(mp0) == limit) {	/* REMOVE */
			do {
				/* REMOVE */
				usbwcm_input(usbwcmp, mp0);
				mp0 = mp0->b_cont;
			} while (mp0 != NULL);   /* next block, if any */
		}

		freemsg(mp);
		break;

	case M_CTL:
		usbwcm_mctl(q, mp);
		return;

	case M_ERROR:
		/* REMOVE */
		usbwcmp->usbwcm_flags &= ~USBWCM_QWAIT;

		freemsg(mp);
		return;
	default:
		putnext(q, mp);
		return;
	}
}


static struct module_info modinfo;

/* STREAMS entry points */

/* read side queue */
static struct qinit rinit = {
	(int (*)())usbwcm_rput,	/* put procedure not needed */
	NULL, 			/* service procedure */
	usbwcm_open,		/* called on startup */
	usbwcm_close,		/* called on finish */
	NULL,			/* for future use */
	&modinfo,		/* module information structure */
	NULL			/* module statistics structure */
};

/* write side queue */
static struct qinit winit = {
	usbwcm_wput,		/* put procedure */
	NULL,			/* no service proecedure needed */
	NULL,			/* open not used on write side */
	NULL,			/* close not used on write side */
	NULL,			/* for future use */
	&modinfo,		/* module information structure */
	NULL			/* module statistics structure */
};

/* STREAMS table */
static struct streamtab strtab = {
	&rinit,
	&winit,
	NULL,			/* not a MUX */
	NULL			/* not a MUX */
};

/* Module linkage information */

static struct fmodsw modsw = {
	"usbwcm",
	&strtab,
	D_MP | D_MTPERMOD
};


static struct modlstrmod modlstr = {
	&mod_strmodops,
	"USB Wacom STRMOD",
	&modsw
};

static struct modlinkage modlink = {
	MODREV_1,
	(void *)&modlstr,
	NULL
};

static struct module_info modinfo = {
	0x0ffff,		/* module id number */
	"usbwcm",		/* module name */
	0,			/* min packet size accepted */
	INFPSZ,			/* max packet size accepted */
	512,			/* hi-water mark */
	128			/* lo-water mark */
};


/* Module entry points */

int
_init(void)
{
	int rval = mod_install(&modlink);

	if (rval == 0) {
		usbwcm_log_handle = usb_alloc_log_hdl(NULL, "usbwcm",
		    &usbwcm_errlevel, &usbwcm_errmask, NULL, 0);
	}

	return (rval);
}

int
_fini(void)
{
	int rval = mod_remove(&modlink);

	if (rval == 0) {
		usb_free_log_hdl(usbwcm_log_handle);
	}

	return (rval);
}

int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlink, modinfop));
}
