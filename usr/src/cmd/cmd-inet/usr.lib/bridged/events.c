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
 * bridged - bridging control daemon.  This module handles events and general
 * port-related operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlbridge.h>
#include <libdlvlan.h>
#include <libdlstat.h>
#include <stp_in.h>
#include <stp_vectors.h>
#include <net/if_types.h>
#include <net/bridge.h>
#include <sys/ethernet.h>

#include "global.h"

int refresh_count = 1;	/* never zero */
dladm_bridge_prot_t protect = DLADM_BRIDGE_PROT_STP;

/*
 * The 'allports' array is an array of pointers to the struct portdata
 * structures.  We reallocate 'allports' as needed, but the portdata must
 * remain where it's initially allocated, because libdlpi's notification
 * mechanism has a copy of a pointer to this structure.
 */
uint_t nextport;
struct portdata **allports;

/* Port allocation increment (arbitrary) */
#define	ALLOCINCR	10
static uint_t numports;

static datalink_id_t main_linkid;

int control_fd;

static void
linkdown(void)
{
	(void) dladm_destroy_datalink_id(dlhandle, main_linkid,
	    DLADM_OPT_ACTIVE);
}

void
open_bridge_control(void)
{
	bridge_newbridge_t bnb;
	dladm_status_t status;
	char buf[DLADM_STRSIZE];

	if ((control_fd = open(BRIDGE_CTLPATH, O_RDWR | O_NONBLOCK)) == -1) {
		perror(BRIDGE_CTLPATH);
		exit(EXIT_FAILURE);
	}
	(void) snprintf(bnb.bnb_name, sizeof (bnb.bnb_name), "%s0",
	    instance_name);
	status = dladm_name2info(dlhandle, bnb.bnb_name, &bnb.bnb_linkid, NULL,
	    NULL, NULL);
	if (status != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "bridged: %s: %s\n", bnb.bnb_name,
		    dladm_status2str(status, buf));
		exit(EXIT_FAILURE);
	}
	if (strioctl(control_fd, BRIOC_NEWBRIDGE, &bnb, sizeof (bnb)) == -1) {
		perror("NEWBRIDGE");
		exit(EXIT_FAILURE);
	}
	main_linkid = bnb.bnb_linkid;
	if (strioctl(control_fd, BRIOC_TABLEMAX, &tablemax,
	    sizeof (tablemax)) == -1) {
		syslog(LOG_ERR, "cannot set table max %lu on bridge %s: %m",
		    tablemax, instance_name);
		exit(EXIT_FAILURE);
	}
	/*
	 * This covers for any previous incarnation where we might have crashed
	 * or been SIGKILL'd and failed to take down the datalink.
	 */
	linkdown();
	(void) atexit(linkdown);
	status = dladm_up_datalink_id(dlhandle, bnb.bnb_linkid);
	if (status != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "bridged: %s link up: %s\n",
		    bnb.bnb_name, dladm_status2str(status, buf));
		exit(EXIT_FAILURE);
	}
}

struct portdata *
find_by_linkid(datalink_id_t linkid)
{
	int i;
	struct portdata *port;

	for (i = 0; i < nextport; i++) {
		port = allports[i];
		if (port->linkid == linkid)
			return (port);
	}
	return (NULL);
}

/*ARGSUSED2*/
static int
set_vlan(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	struct portdata *port;
	dladm_status_t status;
	dladm_vlan_attr_t vinfo;
	char pointless[DLADM_STRSIZE];
	bridge_vlanenab_t bve;

	status = dladm_vlan_info(handle, linkid, &vinfo, DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_DEBUG, "can't get VLAN info on link ID %u: %s",
		    linkid, dladm_status2str(status, pointless));
		return (DLADM_WALK_CONTINUE);
	}

	port = find_by_linkid(vinfo.dv_linkid);
	if (port == NULL || !port->kern_added)
		return (DLADM_WALK_CONTINUE);

	bve.bve_linkid = port->linkid;
	bve.bve_vlan = vinfo.dv_vid;
	bve.bve_onoff = B_TRUE;
	if (strioctl(control_fd, BRIOC_VLANENAB, &bve, sizeof (bve)) == -1) {
		syslog(LOG_ERR, "unable to enable VLAN %d on linkid %u: %m",
		    vinfo.dv_vid, port->linkid);
		return (DLADM_WALK_TERMINATE);
	} else {
		return (DLADM_WALK_CONTINUE);
	}
}

/*
 * If the named port already exists, then update its configuration.  If it
 * doesn't, then create and enable it.
 */
static void
update_port(int vlan_id, const char *portname, datalink_id_t linkid,
    datalink_class_t class)
{
	int posn;
	struct portdata *port;
	struct pollfd *fds;
	int port_index;
	struct {
		datalink_id_t linkid;
		char linkname[MAXLINKNAMELEN];
	} adddata;
	bridge_setpvid_t bsv;
	uint_t propval, valcnt;
	dladm_status_t status;

	for (posn = 0; posn < nextport; posn++) {
		if (allports[posn]->linkid == linkid)
			break;
	}

	/* If we need to allocate more array space, then do so in chunks. */
	if (posn >= numports) {
		struct portdata **newarr;

		newarr = realloc(allports,
		    sizeof (*newarr) * (nextport + ALLOCINCR));
		if (newarr != NULL)
			allports = newarr;
		fds = realloc(fdarray,
		    sizeof (*fds) * (nextport + ALLOCINCR + FDOFFSET));
		if (fds != NULL)
			fdarray = fds;
		if (newarr == NULL || fds == NULL) {
			syslog(LOG_ERR, "unable to add %s; no memory",
			    portname);
			return;
		}
		numports = nextport + ALLOCINCR;
	}

	port_index = posn + 1;
	fds = fdarray + posn + FDOFFSET;

	/* If our linkid search ran to the end, then this is a new port. */
	if (posn == nextport) {
		if ((port = calloc(1, sizeof (*port))) == NULL) {
			syslog(LOG_ERR, "unable to add %s; no memory",
			    portname);
			return;
		}
		allports[posn] = port;
		port->vlan_id = vlan_id;
		port->linkid = linkid;
		port->port_index = port_index;
		port->phys_status = B_TRUE;
		port->admin_status = B_TRUE;
		port->state = BLS_BLOCKLISTEN;
		nextport++;
	} else {
		/* Located port by linkid; we're just updating existing data */
		port = allports[posn];

		/*
		 * If it changed name, then close and reopen so we log under
		 * the most current name for this port.
		 */
		if (port->name != NULL && strcmp(portname, port->name) != 0) {
			if (port->dlpi != NULL)
				dlpi_close(port->dlpi);
			port->dlpi = NULL;
			port->name = NULL;
			fds->fd = -1;
			fds->events = 0;
		}
	}

	/*
	 * If the port is not yet attached to the bridge in the kernel, then do
	 * that now.
	 */
	if (!port->kern_added) {
		adddata.linkid = linkid;
		(void) strlcpy(adddata.linkname, portname,
		    sizeof (adddata.linkname));
		if (strioctl(control_fd, BRIOC_ADDLINK, &adddata,
		    sizeof (adddata.linkid) + strlen(adddata.linkname)) == -1) {
			syslog(LOG_ERR, "cannot bridge %s: %m", portname);
			goto failure;
		}
		port->kern_added = B_TRUE;
	}

	port->referenced = B_TRUE;

	valcnt = 1;
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "forward", &propval, &valcnt);
	if (status == DLADM_STATUS_OK)
		port->admin_status = propval;

	bsv.bsv_vlan = 1;
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "default_tag", &propval, &valcnt);
	if (status == DLADM_STATUS_OK)
		bsv.bsv_vlan = propval;

	bsv.bsv_linkid = linkid;
	if (strioctl(control_fd, BRIOC_SETPVID, &bsv, sizeof (bsv)) == -1) {
		syslog(LOG_ERR, "can't set PVID on %s: %m", portname);
		goto failure;
	}

	if (port->dlpi == NULL) {
		if (!port_dlpi_open(portname, port, class))
			goto failure;
		fds->fd = dlpi_fd(port->dlpi);
		fds->events = POLLIN;
	}

	if (rstp_add_port(port))
		return;

failure:
	if (port->dlpi != NULL) {
		dlpi_close(port->dlpi);
		port->dlpi = NULL;
		port->name = NULL;
		fds->fd = -1;
		fds->events = 0;
	}
	if (port->kern_added) {
		if (strioctl(control_fd, BRIOC_REMLINK, &port->linkid,
		    sizeof (port->linkid)) == -1)
			syslog(LOG_ERR, "cannot remove from bridge %s: %m",
			    portname);
		else
			port->kern_added = B_FALSE;
	}
	if (posn + 1 == nextport) {
		free(port);
		nextport--;
	}
}

/*ARGSUSED2*/
static int
update_link(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t status;
	dladm_conf_t conf;
	char bridge[MAXLINKNAMELEN], linkname[MAXLINKNAMELEN];
	char pointless[DLADM_STRSIZE];
	datalink_class_t class;

	status = dladm_read_conf(handle, linkid, &conf);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_DEBUG, "can't get status on link ID %u: %s", linkid,
		    dladm_status2str(status, pointless));
		return (DLADM_WALK_CONTINUE);
	}

	status = dladm_bridge_getlink(handle, linkid, bridge, sizeof (bridge));
	if (status == DLADM_STATUS_OK && strcmp(bridge, instance_name) == 0) {
		status = dladm_datalink_id2info(handle, linkid, NULL, &class,
		    NULL, linkname, sizeof (linkname));
		if (status == DLADM_STATUS_OK) {
			update_port(0, linkname, linkid, class);
		} else {
			syslog(LOG_ERR, "unable to get link info for ID %u: %s",
			    linkid, dladm_status2str(status, pointless));
		}
	} else if (debugging) {
		if (status != DLADM_STATUS_OK)
			syslog(LOG_DEBUG,
			    "unable to get bridge data for ID %u: %s",
			    linkid, dladm_status2str(status, pointless));
		else
			syslog(LOG_DEBUG, "link ID %u is on bridge %s, not %s",
			    linkid, bridge, instance_name);
	}
	dladm_destroy_conf(handle, conf);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Refresh action - reread configuration properties.
 */
static void
handle_refresh(int sigfd)
{
	int i;
	struct portdata *pdp;
	struct pollfd *fdp;
	char buf[16];
	dladm_status_t status;
	boolean_t new_debug;
	uint32_t new_tablemax;

	/* Drain signal events from pipe */
	if (sigfd != -1)
		(void) read(sigfd, buf, sizeof (buf));

	status = dladm_bridge_get_privprop(instance_name, &new_debug,
	    &new_tablemax);
	if (status == DLADM_STATUS_OK) {
		if (debugging && !new_debug)
			syslog(LOG_DEBUG, "disabling debugging");
		debugging = new_debug;
		if (new_tablemax != tablemax) {
			syslog(LOG_DEBUG, "changed tablemax from %lu to %lu",
			    tablemax, new_tablemax);
			if (strioctl(control_fd, BRIOC_TABLEMAX, &new_tablemax,
			    sizeof (tablemax)) == -1)
				syslog(LOG_ERR, "cannot set table max "
				    "%lu on bridge %s: %m", tablemax,
				    instance_name);
			else
				tablemax = new_tablemax;
		}
	} else {
		syslog(LOG_ERR, "%s: unable to refresh bridge properties: %s",
		    instance_name, dladm_status2str(status, buf));
	}

	rstp_refresh();

	for (i = 0; i < nextport; i++)
		allports[i]->referenced = B_FALSE;

	/*
	 * libdladm doesn't guarantee anything about link ordering in a walk,
	 * so we do this walk twice: once to pick up the ports, and a second
	 * time to get the enabled VLANs on all ports.
	 */
	(void) dladm_walk_datalink_id(update_link, dlhandle, NULL,
	    DATALINK_CLASS_ALL, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);

	(void) dladm_walk_datalink_id(set_vlan, dlhandle, NULL,
	    DATALINK_CLASS_VLAN, DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);

	/*
	 * If any ports now show up as unreferenced, then they've been removed
	 * from the configuration.
	 */
	for (i = 0; i < nextport; i++) {
		pdp = allports[i];
		fdp = fdarray + i + FDOFFSET;
		if (!pdp->referenced) {
			if (pdp->stp_added) {
				(void) STP_IN_port_remove(pdp->vlan_id,
				    pdp->port_index);
				pdp->stp_added = B_FALSE;
			}
			if (pdp->dlpi != NULL) {
				dlpi_close(pdp->dlpi);
				pdp->dlpi = NULL;
				pdp->name = NULL;
				fdp->fd = -1;
				fdp->events = 0;
			}
			if (pdp->kern_added) {
				if (strioctl(control_fd, BRIOC_REMLINK,
				    &pdp->linkid, sizeof (pdp->linkid)) == -1)
					syslog(LOG_ERR, "cannot remove linkid "
					    "%u from bridge %s: %m",
					    pdp->linkid, instance_name);
				pdp->kern_added = B_FALSE;
			}
		}
	}

	if (++refresh_count == 0)
		refresh_count = 1;
}

/*
 * Handle messages on the common control stream.  This currently just deals
 * with port SDU mismatches.
 */
static void
handle_control(void)
{
	bridge_ctl_t bc;
	ssize_t retv;
	struct portdata *port;
	int rc;

	retv = read(control_fd, &bc, sizeof (bc));
	if (retv != sizeof (bc))
		return;
	if ((port = find_by_linkid(bc.bc_linkid)) == NULL)
		return;
	if (port->sdu_failed == bc.bc_failed)
		return;
	port->sdu_failed = bc.bc_failed;
	if (!port->phys_status || !port->admin_status ||
	    protect != DLADM_BRIDGE_PROT_STP)
		return;
	if (port->admin_non_stp) {
		bridge_setstate_t bss;

		bss.bss_linkid = port->linkid;
		bss.bss_state = !port->sdu_failed && !port->bpdu_protect ?
		    BLS_FORWARDING : BLS_BLOCKLISTEN;
		if (strioctl(control_fd, BRIOC_SETSTATE, &bss,
		    sizeof (bss)) == -1) {
			syslog(LOG_ERR, "cannot set STP state on %s: %m",
			    port->name);
		}
	}
	if ((rc = STP_IN_enable_port(port->port_index, !bc.bc_failed)) != 0)
		syslog(LOG_ERR, "STP can't %s port %s for SDU failure: %s",
		    port->name, bc.bc_failed ? "disable" : "enable",
		    STP_IN_get_error_explanation(rc));
}

static void
receive_packet(struct portdata *port)
{
	int rc;
	size_t buflen;
	uint16_t buffer[ETHERMAX / sizeof (uint16_t)];
	struct ether_header *eh;
	char sender[ETHERADDRL * 3];

	buflen = sizeof (buffer);
	rc = dlpi_recv(port->dlpi, NULL, NULL, buffer, &buflen, 1, NULL);
	if (rc != DLPI_SUCCESS) {
		if (rc != DLPI_ETIMEDOUT)
			syslog(LOG_ERR, "receive failure on %s: %s", port->name,
			    dlpi_strerror(rc));
		return;
	}

	/*
	 * If we're administratively disabled, then don't deliver packets to
	 * the STP state machine.  It will re-enable the port because it uses
	 * the same variable for both link status and administrative state.
	 */
	if (!port->admin_status || protect != DLADM_BRIDGE_PROT_STP) {
		if (debugging)
			syslog(LOG_DEBUG,
			    "discard BPDU on non-forwarding interface %s",
			    port->name);
		return;
	}

	/*
	 * There's a mismatch between the librstp and libdlpi expectations on
	 * receive.  librstp wants the packet to start with the 802 length
	 * field, not the destination address.
	 */
	eh = (struct ether_header *)buffer;
	rc = STP_IN_check_bpdu_header((BPDU_T *)&eh->ether_type, buflen);

	/*
	 * Note that we attempt to avoid calling the relatively expensive
	 * _link_ntoa function unless we're going to use the result.  In normal
	 * usage, we don't need this string.
	 */
	if (rc == 0) {
		if (port->admin_non_stp && !port->bpdu_protect) {
			bridge_setstate_t bss;

			(void) _link_ntoa(eh->ether_shost.ether_addr_octet,
			    sender, ETHERADDRL, IFT_OTHER);
			syslog(LOG_WARNING, "unexpected BPDU on %s from %s; "
			    "forwarding disabled", port->name, sender);
			port->bpdu_protect = B_TRUE;
			bss.bss_linkid = port->linkid;
			bss.bss_state = BLS_BLOCKLISTEN;
			if (strioctl(control_fd, BRIOC_SETSTATE, &bss,
			    sizeof (bss)) == -1) {
				syslog(LOG_ERR, "cannot set STP state on "
				    "%s: %m", port->name);
			}
			return;
		}
		if (debugging) {
			(void) _link_ntoa(eh->ether_shost.ether_addr_octet,
			    sender, ETHERADDRL, IFT_OTHER);
			syslog(LOG_DEBUG, "got BPDU from %s on %s; %d bytes",
			    sender, port->name, buflen);
		}
		rc = STP_IN_rx_bpdu(port->vlan_id, port->port_index,
		    (BPDU_T *)&eh->ether_type, buflen);
	}
	if (rc != 0) {
		(void) _link_ntoa(eh->ether_shost.ether_addr_octet, sender,
		    ETHERADDRL, IFT_OTHER);
		syslog(LOG_DEBUG,
		    "discarded malformed packet on %s from %s: %s",
		    port->name, sender, STP_IN_get_error_explanation(rc));
	}
}

void
get_dladm_speed(struct portdata *port)
{
	dladm_status_t status;
	uint64_t ifspeed;

	status = dladm_get_single_mac_stat(dlhandle, port->linkid, "ifspeed",
	    KSTAT_DATA_UINT64, &ifspeed);
	if (status == DLADM_STATUS_OK && ifspeed != 0)
		port->speed = ifspeed / 1000000;
	else
		port->speed = 10UL;
}

void
enable_forwarding(struct portdata *port)
{
	bridge_setstate_t bss;

	bss.bss_linkid = port->linkid;
	bss.bss_state = BLS_FORWARDING;
	if (strioctl(control_fd, BRIOC_SETSTATE, &bss, sizeof (bss)) == -1)
		syslog(LOG_ERR, "cannot set STP state on %s: %m", port->name);
}

void
event_loop(void)
{
	int i;
	hrtime_t last_time, now;
	int tout;

	if (lock_engine() != 0) {
		syslog(LOG_ERR, "mutex lock");
		exit(EXIT_FAILURE);
	}

	/* Bootstrap configuration */
	handle_refresh(-1);

	last_time = gethrtime();
	while (!shutting_down) {
		now = gethrtime();
		if (now - last_time >= 1000000000ll) {
			(void) STP_IN_one_second();
			tout = 1000;
			last_time = now;
		} else {
			tout = 1000 - (now - last_time) / 1000000ll;
		}
		unlock_engine();
		(void) poll(fdarray, nextport + FDOFFSET, tout);
		if (lock_engine() != 0) {
			syslog(LOG_ERR, "mutex lock");
			exit(EXIT_FAILURE);
		}
		if (fdarray[0].revents & POLLIN)
			handle_refresh(fdarray[0].fd);
		if (fdarray[1].revents & POLLIN)
			handle_control();
		for (i = 0; i < nextport; i++) {
			if (fdarray[i + FDOFFSET].revents & POLLIN)
				receive_packet(allports[i]);
		}
	}
	unlock_engine();
}
