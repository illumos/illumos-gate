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
 * Copyright 2000, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/i2c/clients/i2c_client.h>
#include <sys/hpc3130_events.h>
#include <values.h>		/* for BITSPERBYTE */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <poll.h>
#include <libintl.h>
#include <errno.h>
#include <assert.h>
#include <config_admin.h>
#include <sys/daktari.h>
#include "sf880drd.h"

/*
 * Hotplug Controller addresses.
 */
static const unsigned char controller_names[NUM_CONTROLLERS] =
	{ 0xe2, 0xe6, 0xe8, 0xec };

#define	INDEX2SLOT(INDEX)	((INDEX)%4) /* cf init_poll_events() */
#define	INDEX2CONTROLLER(INDEX)	((INDEX)/4) /* cf init_poll_events() */

/*
 *  Local variables.
 */
static struct pollfd fds[NUM_FDS];
static unsigned int fault_leds[2];
static unsigned int ok2rem_leds[2];

/*
 *  Local prototypes.
 */
static void init_poll_events(void);
static void process_event(int);
static void report_cfgadm_error(int, char *);
static void set_front_panel_led(uint8_t, boolean_t);

static int i2c_set_bit(int, int, uint8_t);
static void report_syscall_error(char *);

static void pushbutton_event(char *);
static void fault_led_event(hpc3130_event_type_t, int);
static void removable_led_event(hpc3130_event_type_t, int);

/*
 * main(): loops forever looking for events.
 */
int
main()
{
	int	i;
	int	rv;

	init_poll_events();
	for (;;) {
		/* sleep in poll() waiting an event */
		rv = poll(fds, NUM_FDS, -1);
		if (rv < 0) {
			report_syscall_error("poll");
			continue;
		}

		/* woken up from poll() process the event */
		for (i = 0; i < NUM_FDS; ++i) {
			if (fds[i].revents == POLLIN)
				process_event(i);
		}
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Set up poll fds.
 */
static void
init_poll_events()
{
	int c;
	int p;
	int i = 0;
	char buf[sizeof (HPC3130_DEV_FMT)+8];

	for (c = 0; c < NUM_CONTROLLERS; ++c) {
		for (p = 0; p < SLOTS_PER_CONTROLLER; ++p) {
			(void) sprintf(buf, HPC3130_DEV_FMT,
			    controller_names[c], p);
			fds[i].events = POLLIN;
			fds[i].fd = open(buf, O_RDWR);
			if (fds[i].fd == -1) {
				report_syscall_error(buf);
				exit(-1);
			}
			i++;
		}
	}
}

/*
 * Process poll events.
 */
static void
process_event(int fdi)
{
	struct hpc3130_event e;
	int rv;
	int slot = INDEX2SLOT(fdi);
	int cntr = INDEX2CONTROLLER(fdi);

	rv = ioctl(fds[fdi].fd, HPC3130_GET_EVENT, &e);
	if (rv == -1) {
		report_syscall_error("HPC3130_GET_EVENT");
		return;
	}

	switch (e.id) {
	case HPC3130_EVENT_INSERTION:
	case HPC3130_EVENT_REMOVAL:
	case HPC3130_EVENT_POWERON:
	case HPC3130_EVENT_POWEROFF:
		break;
	case HPC3130_EVENT_BUTTON:
		DPRINTF(("\nBUTTON EVENT slot (%s)\n", e.name));
		pushbutton_event(e.name);
		break;
	case HPC3130_LED_FAULT_ON:
		DPRINTF(("\nFAULT LED ON EVENT\n"));
		fault_led_event(e.id, fdi);
		break;
	case HPC3130_LED_FAULT_OFF:
		DPRINTF(("\nFAULT LED OFF EVENT\n"));
		fault_led_event(e.id, fdi);
		break;
	case HPC3130_LED_REMOVABLE_ON:
		DPRINTF(("\nREMOVABLE LED ON EVENT\n"));
		removable_led_event(e.id, fdi);
		break;
	case HPC3130_LED_REMOVABLE_OFF:
		DPRINTF(("\nREMOVABLE LED OFF EVENT\n"));
		removable_led_event(e.id, fdi);
		break;
	default:
		(void) fprintf(stderr, "WARNING: bogus event: %x\n", e.id);
	}
}

/*
 * Button Event handler.
 */
static void
pushbutton_event(char *ap_id)
{
	char			*errstr = NULL;
	struct cfga_list_data	*stat = NULL;
	int			nlist;
	cfga_cmd_t		cmd;
	cfga_err_t		rv;

	rv = config_list_ext(1, &ap_id, &stat, &nlist,
	    NULL, NULL, &errstr, 0);
	if (rv != CFGA_OK) {
		report_cfgadm_error(rv, errstr);
		goto out;
	}
	assert(nlist == 1);

	/* The only types of hotplug with buttons */
	assert(!(strcmp(stat->ap_class, "pci")));

	switch (stat->ap_o_state) {
	case CFGA_STAT_UNCONFIGURED:
		cmd = CFGA_CMD_CONFIGURE;
		break;
	case CFGA_STAT_CONFIGURED:
		cmd = CFGA_CMD_DISCONNECT;
		break;
	default:
		/* Should never get here */
		assert(0);
	}

	/*
	 * confp & msgp are NULL: when using the pushbutton,
	 * simply fail if prompting is required.
	 */
	rv = config_change_state(cmd, 1, &ap_id, NULL, NULL, NULL, &errstr, 0);
	if (rv != CFGA_OK) {
		report_cfgadm_error(rv, errstr);
		/* FALLTHRU to "out" */
	}

out:
	if (errstr)
		free(errstr);
	if (stat)
		free(stat);
}

static void
fault_led_event(hpc3130_event_type_t event, int fdi)
{
	int		side = 0;
	unsigned int	old;

	if (INDEX2CONTROLLER(fdi) != GPTWO_CONTROLLER) {
		/* It's a PCI slot; left side of chassis */
		side = 1;
	}

	old = fault_leds[side];

	assert(fdi <= sizeof (fault_leds[side]) * BITSPERBYTE);

	switch (event) {
	case HPC3130_LED_FAULT_ON:
		fault_leds[side] |= (1<<fdi);
		DPRINTF(("fault_led_event: HPC3130_LED_FAULT_ON\n"));
		break;
	case HPC3130_LED_FAULT_OFF:
		fault_leds[side] &= ~(1<<fdi);
		DPRINTF(("fault_led_event: HPC3130_LED_FAULT_OFF\n"));
		break;
	}

	DPRINTF(("fault_led_event: old(0x%x), fault_leds[%d](0x%x)\n",
	    old, side, fault_leds[side]));

	if ((old == 0) != (fault_leds[side] == 0) && ok2rem_leds[side] == 0) {
		/*
		 * The first FAULT LED has come on, or the last one has gone
		 * off on this side, and all the OK2REMOVE LEDS are off on this
		 * side.  So we have to update the front panel ARROW LED.
		 */
		set_front_panel_led(side ? LEFT_DOOR_ATTEN_LED :
		    RIGHT_DOOR_ATTEN_LED,
		    fault_leds[side] ? LED_ON : LED_OFF);
	}
}

static void
removable_led_event(hpc3130_event_type_t event, int fdi)
{
	int		side = 0;
	unsigned int	old;

	if (INDEX2CONTROLLER(fdi) != GPTWO_CONTROLLER) {
		/* It's a PCI slot; left side of chassis */
		side = 1;
	}

	old = ok2rem_leds[side];

	assert(fdi <= sizeof (ok2rem_leds[side]) * BITSPERBYTE);

	switch (event) {
	case HPC3130_LED_REMOVABLE_ON:
		ok2rem_leds[side] |= (1<<fdi);
		DPRINTF(("removable_led_event: HPC3130_LED_REMOVABLE_ON\n"));
		break;
	case HPC3130_LED_REMOVABLE_OFF:
		ok2rem_leds[side] &= ~(1<<fdi);
		DPRINTF(("removable_led_event: HPC3130_LED_REMOVABLE_OFF\n"));
		break;
	}

	DPRINTF(("removable_led_event: old(0x%x), ok2rem_leds[%d](0x%x)\n",
	    old, side, ok2rem_leds[side]));

	if ((old == 0) != (ok2rem_leds[side] == 0)) {
		/*
		 * The first OKAY2REMOVE LED has come on, or the last
		 * one has gone off (on this side).  We may have to update
		 * the front panel LEDs.
		 */
		if (ok2rem_leds[!side] == 0) {
			/*
			 * The OK2REMOVE LEDs are all off on the other
			 * side of the chassis, so this side determines
			 * whether the front OK2REMOVE is on or off.
			 */
			set_front_panel_led(SYS_OK2REMOVE_LED,
			    ok2rem_leds[side] ? LED_ON : LED_OFF);
		}
		if (fault_leds[side] == 0) {
			/*
			 * All the FAULT LEDs are off on this side.  So the
			 * OK2REMOVE LEDs determine whether the ARROW LED is on.
			 */
		set_front_panel_led(side ? LEFT_DOOR_ATTEN_LED :
		    RIGHT_DOOR_ATTEN_LED,
		    ok2rem_leds[side] ? LED_ON : LED_OFF);
		}
	}
}

/*
 * Set front panel system leds either on or off.
 */
static void
set_front_panel_led(uint8_t bit_num, boolean_t on_off)
{
	int		fd;
	int		rv;
	i2c_bit_t	arg;

	fd = open(SSC050_LED_PORT, O_RDWR);
	if (fd == -1) {
		report_syscall_error("ssc050");
		return;
	}

	arg.bit_num = bit_num;
	arg.bit_value = on_off;

	rv = ioctl(fd, I2C_SET_BIT, &arg);
	if (rv == -1)
		report_syscall_error("LED I2C_SET_BIT");

	(void) close(fd);
}

static int
i2c_set_bit(int fp, int bit, uint8_t value)
{
	int		rv;
	i2c_bit_t	passin;

	passin.bit_num = (uchar_t)bit;
	passin.bit_value = value;
	rv = ioctl(fp, I2C_SET_BIT, &passin);
	return (rv);
}

static void
report_cfgadm_error(int cfgerrnum, char *errstr)
{
	const char	*ep;

	ep = config_strerror(cfgerrnum);

	if (ep == NULL)
		ep = gettext("configuration administration unknown error");

	if (errstr != NULL && *errstr != '\0') {
		(void) fprintf(stderr, "%s: %s\n", ep, errstr);
	} else {
		(void) fprintf(stderr, "%s\n", ep);
	}
}

static void
report_syscall_error(char *msg)
{
	if (errno != EINTR)
		perror(msg);
}
