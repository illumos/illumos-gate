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
 * bridged - bridging control daemon.  This module provides functions related
 * to the librstp (Rapid Spanning Tree Protocol) library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <kstat.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <stp_in.h>
#include <stp_vectors.h>
#include <net/if_types.h>
#include <net/bridge.h>
#include <sys/ethernet.h>

#include "global.h"

/* current engine configuration; access protected by engine_lock */
static UID_STP_CFG_T uid_cfg;

/*
 * Our implementation doesn't have per-VLAN forwarding entries, so we just
 * flush by the port.  If port number is zero, then flush entries.
 */
/*ARGSUSED1*/
static int
flush_lt(int port_index, int vlan_id, LT_FLASH_TYPE_T type, char *reason)
{
	struct portdata *pd;
	const char *portname;
	bridge_flushfwd_t bff;

	if (port_index > nextport || port_index < 0)
		return (0);

	if (port_index == 0) {
		type = LT_FLASH_ONLY_THE_PORT;
		portname = "all";
		bff.bff_linkid = DATALINK_INVALID_LINKID;
	} else {
		pd = allports[port_index - 1];
		portname = pd->name;
		bff.bff_linkid = pd->linkid;
	}

	if (debugging) {
		syslog(LOG_DEBUG, "flush forwarding %s %s: %s",
		    type == LT_FLASH_ONLY_THE_PORT ? "to" : "except for",
		    portname, reason);
	}

	bff.bff_exclude = (type == LT_FLASH_ALL_PORTS_EXCLUDE_THIS);

	/*
	 * If flushing fails, we can't return.  The only safe thing to do is to
	 * tear down the bridge so that we're not harming the network.
	 */
	if (strioctl(control_fd, BRIOC_FLUSHFWD, &bff, sizeof (bff)) == -1) {
		syslog(LOG_ERR, "cannot flush forwarding entries on %s %s: %m",
		    instance_name, portname);
		unlock_engine();
		exit(EXIT_FAILURE);
	}

	return (0);
}

static void
get_port_mac(int port_index, unsigned char *mac)
{
	struct portdata *pd;

	if (port_index > nextport || port_index <= 0)
		return;

	pd = allports[port_index - 1];
	(void) memcpy(mac, pd->mac_addr, ETHERADDRL);
}

/* Returns speed in megabits per second */
static unsigned long
get_port_oper_speed(unsigned int port_index)
{
	if (port_index > nextport || port_index == 0)
		return (1000UL);
	else
		return (allports[port_index - 1]->speed);
}

static int
get_port_link_status(int port_index)
{
	struct portdata *pd;

	if (port_index > nextport || port_index <= 0) {
		return (0);
	} else {
		pd = allports[port_index - 1];
		return (pd->phys_status && pd->admin_status &&
		    protect == DLADM_BRIDGE_PROT_STP && !pd->sdu_failed ?
		    1 : 0);
	}
}

static int
get_duplex(int port_index)
{
	struct portdata *pd;
	link_duplex_t link_duplex;
	dladm_status_t status;

	if (port_index > nextport || port_index <= 0)
		return (False);

	pd = allports[port_index - 1];
	status = dladm_get_single_mac_stat(dlhandle, pd->linkid, "link_duplex",
	    KSTAT_DATA_UINT32, &link_duplex);

	if (status == DLADM_STATUS_OK && link_duplex == LINK_DUPLEX_FULL)
		return (True);
	else
		return (False);
}

static const char *
bls_state(bridge_state_t bstate)
{
	switch (bstate) {
	case BLS_LEARNING:
		return ("learning");
	case BLS_FORWARDING:
		return ("forwarding");
	default:
		return ("block/listen");
	}
}

/*ARGSUSED1*/
static int
set_port_state(int port_index, int vlan_id, RSTP_PORT_STATE state)
{
	struct portdata *pd;
	bridge_setstate_t bss;

	if (port_index > nextport || port_index <= 0)
		return (1);

	pd = allports[port_index - 1];

	if (debugging)
		syslog(LOG_DEBUG, "setting port state on port %d (%s) to %d",
		    port_index, pd->name, state);
	switch (state) {
	case UID_PORT_LEARNING:
		bss.bss_state = BLS_LEARNING;
		break;
	case UID_PORT_FORWARDING:
		bss.bss_state = BLS_FORWARDING;
		break;
	default:
		bss.bss_state = BLS_BLOCKLISTEN;
		break;
	}
	bss.bss_linkid = pd->linkid;
	if (strioctl(control_fd, BRIOC_SETSTATE, &bss, sizeof (bss)) == -1) {
		syslog(LOG_ERR, "cannot set STP state on %s from %s to %s: %m",
		    pd->name, bls_state(pd->state), bls_state(bss.bss_state));
		/*
		 * If we've been unsuccessful in disabling forwarding, then the
		 * only safe thing to do is to make the daemon exit, so that
		 * the kernel will be forced to destroy the bridge state and
		 * terminate all forwarding.
		 */
		if (pd->state == BLS_FORWARDING &&
		    bss.bss_state != BLS_FORWARDING) {
			unlock_engine();
			exit(EXIT_FAILURE);
		}
	} else {
		pd->state = bss.bss_state;
	}
	return (0);
}

/*
 * Our hardware doesn't actually do anything different when STP is enabled or
 * disabled, so this function does nothing.  It would be possible to open and
 * close the DLPI stream here, if such a thing were necessary.
 */
static int
set_hardware_mode(int vlan_id, UID_STP_MODE_T mode)
{
	if (debugging)
		syslog(LOG_DEBUG, "setting hardware mode on vlan %d to %d",
		    vlan_id, mode);
	return (0);
}

/*ARGSUSED1*/
static int
tx_bpdu(int port_index, int vlan_id, unsigned char *bpdu, size_t bpdu_len)
{
	struct portdata *pdp;
	int rc;

	if (port_index > nextport || port_index <= 0)
		return (1);

	pdp = allports[port_index - 1];
	rc = dlpi_send(pdp->dlpi, NULL, 0, bpdu, bpdu_len, NULL);
	if (rc == DLPI_SUCCESS) {
		if (debugging)
			syslog(LOG_DEBUG, "transmitted %d byte BPDU on %s",
			    bpdu_len, pdp->name);
		return (0);
	} else {
		syslog(LOG_WARNING, "failed to send to %s: %s", pdp->name,
		    dlpi_strerror(rc));
		return (1);
	}
}

static const char *
get_port_name(int port_index)
{
	if (port_index > nextport || port_index <= 0)
		return ("unknown");
	else
		return (allports[port_index - 1]->name);
}

/*ARGSUSED*/
static int
get_init_stpm_cfg(int vlan_id, UID_STP_CFG_T *cfg)
{
	/* under engine_lock because it's a callback from the engine */
	*cfg = uid_cfg;
	return (0);
}

/*ARGSUSED*/
static int
get_init_port_cfg(int vlan_id, int port_index, UID_STP_PORT_CFG_T *cfg)
{
	struct portdata *pdp;
	uint_t propval, valcnt;
	datalink_id_t linkid;
	dladm_status_t status;

	if (port_index > nextport || port_index <= 0)
		return (1);

	pdp = allports[port_index - 1];

	cfg->field_mask = 0;
	cfg->port_priority = DEF_PORT_PRIO;
	cfg->admin_non_stp = DEF_ADMIN_NON_STP;
	cfg->admin_edge = DEF_ADMIN_EDGE;
	cfg->admin_port_path_cost = ADMIN_PORT_PATH_COST_AUTO;
	cfg->admin_point2point = DEF_P2P;

	valcnt = 1;
	linkid = pdp->linkid;
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "stp_priority", &propval, &valcnt);
	if (status == DLADM_STATUS_OK) {
		cfg->port_priority = propval;
		cfg->field_mask |= PT_CFG_PRIO;
	}
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "stp", &propval, &valcnt);
	if (status == DLADM_STATUS_OK) {
		cfg->admin_non_stp = !propval;
		cfg->field_mask |= PT_CFG_NON_STP;
	}
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "stp_edge", &propval, &valcnt);
	if (status == DLADM_STATUS_OK) {
		cfg->admin_edge = propval;
		cfg->field_mask |= PT_CFG_EDGE;
	}
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "stp_cost", &propval, &valcnt);
	if (status == DLADM_STATUS_OK) {
		cfg->admin_port_path_cost = propval;
		cfg->field_mask |= PT_CFG_COST;
	}
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "stp_p2p", &propval, &valcnt);
	if (status == DLADM_STATUS_OK) {
		cfg->admin_point2point = propval;
		cfg->field_mask |= PT_CFG_P2P;
	}

	/*
	 * mcheck is special.  It is actually a command, but the 802 documents
	 * define it as a variable that spontaneously resets itself.  We need
	 * to handle that behavior here.
	 */
	status = dladm_get_linkprop_values(dlhandle, linkid,
	    DLADM_PROP_VAL_PERSISTENT, "stp_mcheck", &propval, &valcnt);
	if (status == DLADM_STATUS_OK && propval != 0) {
		char *pval = "0";

		cfg->field_mask |= PT_CFG_MCHECK;
		(void) dladm_set_linkprop(dlhandle, linkid, "stp_mcheck", &pval,
		    1, DLADM_OPT_ACTIVE|DLADM_OPT_PERSIST|DLADM_OPT_NOREFRESH);
	}

	pdp->admin_non_stp = cfg->admin_non_stp;
	if (!pdp->admin_non_stp)
		pdp->bpdu_protect = B_FALSE;

	return (0);
}

static void
trace(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

static STP_VECTORS_T stp_vectors = {
	flush_lt,
	get_port_mac,
	get_port_oper_speed,
	get_port_link_status,
	get_duplex,
	set_port_state,
	set_hardware_mode,
	tx_bpdu,
	get_port_name,
	get_init_stpm_cfg,
	get_init_port_cfg,
	trace
};

void
rstp_init(void)
{
	dladm_status_t status;
	char buf[DLADM_STRSIZE];

	STP_IN_init(&stp_vectors);
	status = dladm_bridge_get_properties(instance_name, &uid_cfg, &protect);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_ERR, "%s: unable to read properties: %s",
		    instance_name, dladm_status2str(status, buf));
		exit(EXIT_FAILURE);
	}
}

/*
 * This is called by a normal refresh operation.  It gets the engine properties
 * and resets.
 */
void
rstp_refresh(void)
{
	dladm_status_t status;
	int rc;
	char buf[DLADM_STRSIZE];
	UID_STP_CFG_T new_cfg;
	dladm_bridge_prot_t new_prot;

	status = dladm_bridge_get_properties(instance_name, &new_cfg,
	    &new_prot);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_ERR, "%s: unable to refresh bridge properties: %s",
		    instance_name, dladm_status2str(status, buf));
	} else {
		if (debugging && (protect != new_prot ||
		    uid_cfg.stp_enabled != new_cfg.stp_enabled)) {
			syslog(LOG_DEBUG, "loop protection %s->%s, STP %d->%d",
			    dladm_bridge_prot2str(protect),
			    dladm_bridge_prot2str(new_prot),
			    uid_cfg.stp_enabled, new_cfg.stp_enabled);
		}

		/*
		 * The engine doesn't take kindly to parameter changes while
		 * running.  Disable first if we must do this.
		 */
		if (uid_cfg.stp_enabled &&
		    memcmp(&uid_cfg, &new_cfg, sizeof (uid_cfg)) != 0) {
			syslog(LOG_DEBUG, "resetting state machine");
			uid_cfg.stp_enabled = STP_DISABLED;
			rc = STP_IN_stpm_set_cfg(0, &uid_cfg);
			if (rc != 0)
				syslog(LOG_ERR, "STP machine reset config: %s",
				    STP_IN_get_error_explanation(rc));
		}

		uid_cfg = new_cfg;
		protect = new_prot;
		rc = STP_IN_stpm_set_cfg(0, &uid_cfg);
		if (rc != 0)
			syslog(LOG_ERR, "STP machine set config: %s",
			    STP_IN_get_error_explanation(rc));
	}
}

/*
 * This is called when a port changes its MAC address.  If it's the main port,
 * the one that supplies us our bridge ID, then we must choose a new ID, and to
 * do that we shut the bridge down and bring it back up.
 */
void
rstp_change_mac(struct portdata *port, const unsigned char *newaddr)
{
	unsigned short prio;
	unsigned char mac[ETHERADDRL];
	int rc;
	char curid[ETHERADDRL * 3];
	char newmac[ETHERADDRL * 3];

	(void) _link_ntoa(port->mac_addr, curid, ETHERADDRL, IFT_OTHER);
	(void) _link_ntoa(newaddr, newmac, ETHERADDRL, IFT_OTHER);
	STP_IN_get_bridge_id(port->vlan_id, &prio, mac);
	if (memcmp(port->mac_addr, mac, ETHERADDRL) == 0) {
		syslog(LOG_NOTICE, "bridge ID must change: ID %s on %s changed "
		    "to %s", curid, port->name, newmac);
		uid_cfg.stp_enabled = STP_DISABLED;
		if ((rc = STP_IN_stpm_set_cfg(0, &uid_cfg)) != 0)
			syslog(LOG_ERR, "STP machine set config: %s",
			    STP_IN_get_error_explanation(rc));
		(void) memcpy(port->mac_addr, newaddr, ETHERADDRL);
		uid_cfg.stp_enabled = STP_ENABLED;
		if ((rc = STP_IN_stpm_set_cfg(0, &uid_cfg)) != 0)
			syslog(LOG_ERR, "STP machine set config: %s",
			    STP_IN_get_error_explanation(rc));
	} else {
		syslog(LOG_DEBUG,
		    "MAC address on %s changed from %s to %s", port->name,
		    curid, newmac);
		(void) memcpy(port->mac_addr, newaddr, ETHERADDRL);
	}
}

boolean_t
rstp_add_port(struct portdata *port)
{
	int rc;
	UID_STP_PORT_CFG_T portcfg;
	bridge_vlanenab_t bve;
	bridge_setstate_t bss;

	if (!port->stp_added &&
	    (rc = STP_IN_port_add(port->vlan_id, port->port_index)) != 0) {
		syslog(LOG_ERR, "STP add %s %d: %s", port->name,
		    port->port_index, STP_IN_get_error_explanation(rc));
		return (B_FALSE);
	}
	port->stp_added = B_TRUE;

	/* guaranteed to succeed at this point */
	(void) get_init_port_cfg(port->vlan_id, port->port_index, &portcfg);

	/*
	 * Restore state when reenabling STP engine, set fixed state when
	 * disabling.  For TRILL, we don't control forwarding at all, but we
	 * need to turn off our controls for TRILL to do its thing.
	 */
	bss.bss_linkid = port->linkid;
	if (protect != DLADM_BRIDGE_PROT_STP) {
		bss.bss_state = port->state = BLS_BLOCKLISTEN;
	} else if (portcfg.admin_non_stp) {
		bss.bss_state = port->admin_status && !port->sdu_failed &&
		    !port->bpdu_protect ? BLS_FORWARDING : BLS_BLOCKLISTEN;
	} else {
		bss.bss_state = port->state;
	}
	if (strioctl(control_fd, BRIOC_SETSTATE, &bss, sizeof (bss)) == -1) {
		syslog(LOG_ERR, "cannot set STP state on %s: %m", port->name);
		goto failure;
	}

	rc = STP_IN_enable_port(port->port_index,
	    port->admin_status && port->phys_status && !port->sdu_failed &&
	    protect == DLADM_BRIDGE_PROT_STP);
	if (rc != 0) {
		syslog(LOG_ERR, "STP enable %s %d: %s", port->name,
		    port->port_index, STP_IN_get_error_explanation(rc));
		goto failure;
	}

	if (debugging) {
		rc = STP_IN_dbg_set_port_trace("all", True, 0,
		    port->port_index);
	} else {
		/* return to default debug state */
		rc = STP_IN_dbg_set_port_trace("all", False, 0,
		    port->port_index);
		if (rc == 0)
			rc = STP_IN_dbg_set_port_trace("sttrans", True, 0,
			    port->port_index);
	}
	if (rc != 0) {
		syslog(LOG_ERR, "STP trace %s %d: %s", port->name,
		    port->port_index, STP_IN_get_error_explanation(rc));
		goto failure;
	}

	/* Clear out the kernel's allowed VLAN set; second walk will set */
	bve.bve_linkid = port->linkid;
	bve.bve_vlan = 0;
	bve.bve_onoff = B_FALSE;
	if (strioctl(control_fd, BRIOC_VLANENAB, &bve, sizeof (bve)) == -1) {
		syslog(LOG_ERR, "unable to disable VLANs on %s: %m",
		    port->name);
		goto failure;
	}

	if ((rc = STP_IN_port_set_cfg(0, port->port_index, &portcfg)) != 0) {
		syslog(LOG_ERR, "STP port configure %s %d: %s", port->name,
		    port->port_index, STP_IN_get_error_explanation(rc));
		goto failure;
	}

	return (B_TRUE);

failure:
	(void) STP_IN_port_remove(port->vlan_id, port->port_index);
	port->stp_added = B_FALSE;
	return (B_FALSE);
}
