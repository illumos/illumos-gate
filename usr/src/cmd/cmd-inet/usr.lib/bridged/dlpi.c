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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * bridged - bridging control daemon.  This module provides DLPI-specific
 * functions for interface to libdlpi.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <stropts.h>
#include <stp_in.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <sys/ethernet.h>
#include <sys/pfmod.h>

#include "global.h"

static const uchar_t bridge_group_address[] = BRIDGE_GROUP_ADDRESS;

static const ushort_t bpdu_filter[] = {
	ENF_PUSHWORD | 0,		/* check for 1:80:c2:0:0:0 dest. */
	ENF_PUSHLIT | ENF_CAND,
#ifdef _BIG_ENDIAN
	0x0180,
#else
	0x8001,
#endif
	ENF_PUSHWORD | 1,
	ENF_PUSHLIT | ENF_CAND,
#ifdef _BIG_ENDIAN
	0xC200,
#else
	0x00C2,
#endif
	ENF_PUSHWORD | 2,
	ENF_PUSHZERO | ENF_CAND,
	ENF_PUSHWORD | 7,		/* check for SSAP/DSAP 42 42 */
	ENF_PUSHLIT | ENF_CAND,
	0x4242,
};

/*
 * Because we're called by dlpi_recv(), we're called with the engine lock held.
 */
/*ARGSUSED*/
static void
dlpi_notify(dlpi_handle_t dlpi, dlpi_notifyinfo_t *info, void *arg)
{
	struct portdata *port = arg;
	int rc;

	switch (info->dni_note) {
	case DL_NOTE_SPEED:
		/* libdlpi gives us Kbps, and we want Mbps */
		if (port->speed == info->dni_speed / 1000)
			break;
		port->speed = info->dni_speed / 1000;
		if ((rc = STP_IN_changed_port_speed(port->port_index,
		    port->speed)) != 0)
			syslog(LOG_ERR, "STP can't change port speed on %s: %s",
			    port->name, STP_IN_get_error_explanation(rc));
		break;

	case DL_NOTE_PHYS_ADDR:
		if (memcmp(info->dni_physaddr, port->mac_addr, ETHERADDRL) != 0)
			rstp_change_mac(port, info->dni_physaddr);
		break;

	case DL_NOTE_LINK_DOWN:
		if (!port->phys_status)
			break;
		port->phys_status = B_FALSE;
		if (!port->admin_status || protect != DLADM_BRIDGE_PROT_STP ||
		    port->sdu_failed)
			break;
		if ((rc = STP_IN_enable_port(port->port_index, False)) != 0)
			syslog(LOG_ERR, "STP can't disable port %s: %s",
			    port->name, STP_IN_get_error_explanation(rc));
		break;

	case DL_NOTE_LINK_UP:
		if (port->phys_status)
			break;
		port->phys_status = B_TRUE;
		if (!port->admin_status || protect != DLADM_BRIDGE_PROT_STP ||
		    port->sdu_failed) {
			port->bpdu_protect = B_FALSE;
			break;
		}
		/*
		 * If we're not running STP, and the link state has just come
		 * up, then clear out any protection shutdown state, and allow
		 * us to forward again.
		 */
		if (port->admin_non_stp && port->bpdu_protect) {
			port->bpdu_protect = B_FALSE;
			enable_forwarding(port);
		}
		if ((rc = STP_IN_enable_port(port->port_index, True)) != 0)
			syslog(LOG_ERR, "STP can't enable port %s: %s",
			    port->name, STP_IN_get_error_explanation(rc));
		break;
	}
}

boolean_t
port_dlpi_open(const char *portname, struct portdata *port,
    datalink_class_t class)
{
	uchar_t addrbuf[DLPI_PHYSADDR_MAX];
	size_t alen = DLPI_PHYSADDR_MAX;
	int rc;
	char addrstr[ETHERADDRL * 3];

	/*
	 * We use DLPI 'raw' mode so that we get access to the received
	 * Ethernet 802 length field.  libdlpi otherwise eats this value.  Note
	 * that 'raw' mode support is required in order to use snoop, so it's
	 * expected to be common, even if it's not documented.
	 */
	rc = dlpi_open(portname, &port->dlpi, DLPI_RAW);
	if (rc != DLPI_SUCCESS) {
		syslog(LOG_ERR, "can't open %s: %s", portname,
		    dlpi_strerror(rc));
		return (B_FALSE);
	}

	port->phys_status = B_TRUE;
	port->sdu_failed = B_FALSE;
	port->bpdu_protect = B_FALSE;

	/*
	 * Now that the driver is open, we can get at least the initial value
	 * of the interface speed.  We need to do this before establishing the
	 * notify callback, so that it can update us later.
	 */
	get_dladm_speed(port);

	/*
	 * Save off the libdlpi port name, as it's dynamically allocated, and
	 * the name we're passed is not.
	 */
	port->name = dlpi_linkname(port->dlpi);

	/*
	 * We can't bind SAP 0 or enable multicast on an etherstub.  It's ok,
	 * though, because there's no real hardware involved.
	 */
	if (class != DATALINK_CLASS_ETHERSTUB) {
		if ((rc = dlpi_bind(port->dlpi, 0, NULL)) != DLPI_SUCCESS) {
			syslog(LOG_ERR, "can't bind %s: %s", portname,
			    dlpi_strerror(rc));
			return (B_FALSE);
		}
		if ((rc = dlpi_enabmulti(port->dlpi, bridge_group_address,
		    sizeof (bridge_group_address))) != DLPI_SUCCESS) {
			syslog(LOG_ERR, "can't enable multicast on %s: %s",
			    portname, dlpi_strerror(rc));
			return (B_FALSE);
		}
	}

	if ((rc = dlpi_enabnotify(port->dlpi,
	    DL_NOTE_PHYS_ADDR | DL_NOTE_LINK_DOWN | DL_NOTE_LINK_UP |
	    DL_NOTE_SPEED, dlpi_notify, port, &port->notifyid)) !=
	    DLPI_SUCCESS) {
		syslog(LOG_WARNING, "no DLPI notification on %s: %s", portname,
		    dlpi_strerror(rc));
	}

	rc = dlpi_get_physaddr(port->dlpi, DL_CURR_PHYS_ADDR, addrbuf, &alen);
	if (rc != DLPI_SUCCESS) {
		syslog(LOG_ERR, "unable to get MAC address on %s: %s",
		    port->name, dlpi_strerror(rc));
		return (B_FALSE);
	}
	if (alen != ETHERADDRL) {
		syslog(LOG_ERR, "bad MAC address length %d on %s",
		    alen, port->name);
		return (B_FALSE);
	}
	(void) memcpy(port->mac_addr, addrbuf, ETHERADDRL);

	if (class != DATALINK_CLASS_ETHERSTUB) {
		int fd = dlpi_fd(port->dlpi);
		int lowflag = 1;

		if (strioctl(fd, DLIOCLOWLINK, &lowflag, sizeof (lowflag)) != 0)
			syslog(LOG_WARNING, "low-link notify failed on %s: %m",
			    portname);
		if (ioctl(fd, I_PUSH, "pfmod") == 0) {
			struct packetfilt pf;

			pf.Pf_Priority = 0;
			pf.Pf_FilterLen = sizeof (bpdu_filter) /
			    sizeof (*bpdu_filter);
			(void) memcpy(pf.Pf_Filter, bpdu_filter,
			    sizeof (bpdu_filter));
			if (strioctl(fd, PFIOCSETF, &pf, sizeof (pf)) == -1)
				syslog(LOG_WARNING,
				    "pfil ioctl failed on %s: %m", portname);
		} else {
			syslog(LOG_WARNING, "pfil push failed on %s: %m",
			    portname);
		}
	}

	if (debugging) {
		(void) _link_ntoa(port->mac_addr, addrstr, ETHERADDRL,
		    IFT_OTHER);
		syslog(LOG_DEBUG, "got MAC address %s on %s", addrstr,
		    port->name);
	}

	return (B_TRUE);
}
