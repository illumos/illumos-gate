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

/*
 * Implementation to get PORT nodes state and condition information
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <locale.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <kstat.h>
#include <signal.h>
#include <assert.h>
#include <config_admin.h>

#include <picl.h>
#include "piclfrutree.h"

#define	LINK_UP 	"link_up"
#define	DUPLEX		"duplex"
#define	IF_SPEED	"ifspeed"
#define	IERRORS		"ierrors"
#define	IPACKETS	"ipackets"
#define	OERRORS		"oerrors"
#define	OPACKETS	"opackets"
#define	NOCANPUT	"nocanput"
#define	RUNT_ERRORS	"runt_errors"
#define	COLLISIONS	"collisions"

typedef int (*funcp)(kstat_ctl_t *, char *, int);

static kstat_named_t *kstat_name_lookup(kstat_ctl_t *, char *, int, char *);
static int kstat_network_port_state(kstat_ctl_t *kc, char *, int);
static int kstat_network_port_cond(kstat_ctl_t *kc, char *, int);
static int serial_port_state(kstat_ctl_t *, char *, int);
static int serial_port_cond(kstat_ctl_t *kc, char *, int);
static int parallel_port_state(kstat_ctl_t *, char *, int);
static int parallel_port_cond(kstat_ctl_t *kc, char *, int);

static funcp port_state[] = {
	kstat_network_port_state,
	serial_port_state,
	parallel_port_state
};

static funcp port_cond[] = {
	kstat_network_port_cond,
	serial_port_cond,
	parallel_port_cond
};

/*
 * kstat_port_state: returns ethernet, or serial, or parallel port status
 * 1 = up, 0 = down, anything else = unknown
 */
int
kstat_port_state(frutree_port_type_t port_type, char *driver_name,
	int driver_instance)
{
	int rc = -1;
	kstat_ctl_t	*kc = NULL;

	switch (port_type) {
	case NETWORK_PORT:
	case SERIAL_PORT:
	case PARALLEL_PORT:
		if ((kc = kstat_open()) == NULL) {
			return (-1);
		}
		rc = port_state[port_type](kc, driver_name, driver_instance);
		kstat_close(kc);
		return (rc);
	default:
		return (-1);
	}
}

/*
 * kstat_port_cond: returns ethernet, or serial, or parallel port condition
 */
int
kstat_port_cond(frutree_port_type_t port_type, char *driver_name,
	int driver_instance)
{
	int rc = -1;
	kstat_ctl_t	*kc = NULL;
	switch (port_type) {
	case NETWORK_PORT:
	case SERIAL_PORT:
	case PARALLEL_PORT:
		if ((kc = kstat_open()) == NULL) {
			return (-1);
		}
		rc = port_cond[port_type](kc, driver_name, driver_instance);
		kstat_close(kc);
		return (rc);
	default:
		return (-1);
	}
}

static kstat_named_t *
kstat_name_lookup(kstat_ctl_t *kc, char *ks_module, int ks_instance, char *name)
{
	kstat_t		*ksp;

	assert(kc);
	assert(ks_module);
	assert(name);

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, ks_module) == 0 &&
			ksp->ks_instance == ks_instance &&
			ksp->ks_type == KSTAT_TYPE_NAMED &&
			kstat_read(kc, ksp, NULL) != -1 &&
			kstat_data_lookup(ksp, name)) {

			ksp = kstat_lookup(kc, ks_module, ks_instance,
				ksp->ks_name);
			if (!ksp)
				return (NULL);
			if (kstat_read(kc, ksp, NULL) == -1)
				return (NULL);
			return ((kstat_named_t *)kstat_data_lookup(ksp, name));
		}
	}
	return (NULL);
}

/*
 * kstat_network_port_state: returns kstat info of a network port
 * 1 = up, 0 = down, anything else = unknown
 */
static int
kstat_network_port_state(kstat_ctl_t *kc, char *ks_module, int ks_instance)
{
	kstat_named_t	*port_datap = NULL;

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		LINK_UP)) == NULL) {
		return (-1);
	}
	if (port_datap == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		if (port_datap->value.ui32 == 1) {
			return (1);
		} else if (port_datap->value.ui32 == 0) {
			return (0);
		} else {
			return (-1);
		}
	} else {
		if (port_datap->value.ui64 == 1) {
			return (1);
		} else if (port_datap->value.ui64 == 0) {
			return (0);
		} else {
			return (-1);
		}
	}
}

/*
 * kstat_network_port_cond: returns kstat info of a network port
 * 0 = OK, 1 = FAILING, 2 = FAILED, 3 = TESTING, -1 = unknown
 */
static int
kstat_network_port_cond(kstat_ctl_t *kc, char *ks_module, int ks_instance)
{
	kstat_named_t	*port_datap = NULL;
	uint64_t	collisions, runt, link_up, link_duplex;
	uint64_t	ifspeed, ierrors, ipackets, oerrors, opackets;

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		LINK_UP)) == NULL) {
		return (-1);
	}

	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		link_up = port_datap->value.ui32;
	} else {
		link_up = port_datap->value.ui64;
	}
	if (link_up == 0) {
		return (2);
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		DUPLEX)) == NULL) {
		return (-1);
	}

	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		link_duplex = port_datap->value.ui32;
	} else {
		link_duplex = port_datap->value.ui64;
	}
	if (link_duplex == 0) {
		return (2);
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		IF_SPEED)) == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		ifspeed = port_datap->value.ui32;
	} else {
		ifspeed = port_datap->value.ui64;
	}
	if (ifspeed == 0) {
		return (2);
	}

	/* check for FAILING conditions */
	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		IERRORS)) == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		ierrors = port_datap->value.ui32;
	} else {
		ierrors = port_datap->value.ui64;
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		IPACKETS)) == NULL) {
		return (-1);
	}

	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		ipackets = port_datap->value.ui32;
	} else {
		ipackets = port_datap->value.ui64;
	}
	if (ierrors > ipackets/10) {
		return (1);
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		OERRORS)) == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		oerrors = port_datap->value.ui32;
	} else {
		oerrors = port_datap->value.ui64;
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		OPACKETS)) == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		opackets = port_datap->value.ui32;
	} else {
		opackets = port_datap->value.ui64;
	}
	if (oerrors > opackets/10) {
		return (1);
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		RUNT_ERRORS)) == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		runt = port_datap->value.ui32;
	} else {
		runt = port_datap->value.ui64;
	}
	if (runt > ipackets/10) {
		return (1);
	}

	if ((port_datap = kstat_name_lookup(kc, ks_module, ks_instance,
		COLLISIONS)) == NULL) {
		return (-1);
	}
	if (port_datap->data_type == KSTAT_DATA_UINT32) {
		collisions = port_datap->value.ui32;
	} else {
		collisions = port_datap->value.ui64;
	}
	if (collisions > (opackets+ipackets)/30) {
		return (1);
	}
	return (0);
}

/*
 * serial_port_state: returns status a serial port
 * 1 = up, 0 = down, anything else = unknown
 */

/* ARGSUSED */
static int
serial_port_state(kstat_ctl_t *kc, char *driver, int instance)
{
	int			fd;
	char			device[20];
	struct termios		flags;
	struct sigaction	old_sa, new_sa;
	static void		sig_alarm_handler(int);

	(void) memset(&old_sa, 0, sizeof (old_sa));
	(void) memset(&new_sa, 0, sizeof (new_sa));
	new_sa.sa_handler = sig_alarm_handler;
	(void) sigaction(SIGALRM, &new_sa, &old_sa);
	(void) alarm(1);

	(void) snprintf(device, sizeof (device), "/dev/tty%c", instance+'a');
	fd = open(device, O_RDONLY|O_NDELAY|O_NONBLOCK|O_NOCTTY);

	/* Restore sig action flags */
	(void) sigaction(SIGALRM, &old_sa, (struct sigaction *)0);
	/* Disable alarm */
	(void) alarm(0);

	if (fd == -1) {
		return (-1);
	}

	if (isatty(fd) == 0) {
		(void) close(fd);
		return (-1);
	}
	(void) memset(&flags, 0, sizeof (flags));
	if (ioctl(fd, TCGETS, &flags) != 0) {
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);
	return ((flags.c_cflag & TIOCM_LE) ? 1 : 0);
}

/* ARGSUSED */
static void
sig_alarm_handler(int signo)
{
}

/*
 * serial_port_cond: returns status of a serial port
 * 0 = OK, 1 = FAILING, 2 = FAILED, 3 = TESTING, anything else = UNKNOWN
 */
static int
serial_port_cond(kstat_ctl_t *kc, char *driver, int instance)
{
	switch (serial_port_state(kc, driver, instance)) {
	case 1:
		return (0);
	default:
		return (-1);
	}
}

/*
 * parallel_port_state: returns kstat info of a serial port
 * 1 = up, 0 = down, anything else = unknown
 */
static int
parallel_port_state(kstat_ctl_t *kc, char *ks_module, int ks_instance)
{
	kstat_t		*ksp = NULL;
	kstat_named_t	*port_datap = NULL;
	char		*data_lookup;
	char		ks_name[20];

	(void) snprintf(ks_name, sizeof (ks_name), "%s%d", ks_module,
		ks_instance);
	if ((ksp = kstat_lookup(kc, ks_module, ks_instance, ks_name)) == NULL) {
		return (-1);
	}
	if (kstat_read(kc, ksp, NULL) == -1) {
		return (-1);
	}
	data_lookup = "";
	port_datap = (kstat_named_t *)kstat_data_lookup(ksp, data_lookup);
	if (port_datap == NULL) {
		return (-1);
	}
	return (-1);
}

/*
 * parallel_port_cond: returns kstat info of a serial port
 * 1 = up, 0 = down, anything else = unknown
 */
static int
parallel_port_cond(kstat_ctl_t *kc, char *ks_module, int ks_instance)
{
	return (parallel_port_state(kc, ks_module, ks_instance));
}
