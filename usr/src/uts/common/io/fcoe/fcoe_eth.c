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

#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/inttypes.h>
#include <sys/strsun.h>
#include <sys/mac_client.h>

/*
 * FCoE header files
 */
#include <sys/fcoe/fcoeio.h>
#include <sys/fcoe/fcoe_common.h>

/*
 * Driver's own header files
 */
#include <fcoe.h>
#include <fcoe_eth.h>
#include <fcoe_fc.h>

static void fcoe_rx(void *arg, mac_resource_handle_t mrh,
    mblk_t *mp, boolean_t loopback);
static void fcoe_mac_notify(void *arg, mac_notify_type_t type);

/*
 * Global variable definitions
 */

/*
 * Internal tunable, used to enable p2p mode
 */
volatile uint32_t	fcoe_enable_p2pmode = 0;

int
fcoe_open_mac(fcoe_mac_t *mac, int force_promisc, fcoeio_stat_t *err_detail)
{
	int		ret;
	int		fcoe_ret;
	char		cli_name[MAXNAMELEN];
	mac_diag_t	diag;
	uint16_t	fm_open_flag = 0;

	*err_detail = 0;

	/*
	 * Open MAC interface
	 */
	ret = mac_open_by_linkid(mac->fm_linkid, &mac->fm_handle);
	if (ret != 0) {
		FCOE_LOG("fcoe", "mac_open_by_linkname %d failed %x",
		    mac->fm_linkid, ret);
		return (FCOE_FAILURE);
	}

	(void) sprintf(cli_name, "%s-%d", "fcoe", mac->fm_linkid);

	ret = mac_client_open(mac->fm_handle,
	    &mac->fm_cli_handle, cli_name, fm_open_flag);
	if (ret != 0) {
		(void) fcoe_close_mac(mac);
		return (FCOE_FAILURE);
	}
	/*
	 * Cache the pointer of the immutable MAC inforamtion and
	 * the current and primary MAC address
	 */
	mac_unicast_primary_get(mac->fm_handle, mac->fm_primary_addr);
	bcopy(mac->fm_primary_addr, mac->fm_current_addr,
	    ETHERADDRL);

	if (mac_unicast_add(mac->fm_cli_handle, NULL, MAC_UNICAST_PRIMARY,
	    &mac->fm_unicst_handle, 0, &diag)) {
		(void) fcoe_close_mac(mac);
		return (FCOE_FAILURE);
	}

	if (force_promisc) {
		mac->fm_force_promisc = B_TRUE;
	}

	/* Get mtu */
	mac_sdu_get(mac->fm_handle, NULL, &mac->fm_eport.eport_mtu);
	if (mac->fm_eport.eport_mtu < FCOE_MIN_MTU_SIZE) {
		if (!fcoe_enable_p2pmode || mac->fm_eport.eport_mtu < 1500) {
			/*
			 * Fail open if fail to get mtu, or we are not
			 * using p2p, or we are using p2p, but
			 * the mtu is too small
			 */
			(void) fcoe_close_mac(mac);
			*err_detail = FCOEIOE_NEED_JUMBO_FRAME;
			return (FCOE_FAILURE);
		}
	}

	mac->fm_eport.eport_link_speed =
	    mac_client_stat_get(mac->fm_cli_handle, MAC_STAT_IFSPEED);

	cv_init(&mac->fm_tx_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&mac->fm_mutex, NULL, MUTEX_DRIVER, NULL);
	mac->fm_running = B_TRUE;

	fcoe_ret = FCOE_SUCCESS;
	return (fcoe_ret);
}

int
fcoe_close_mac(fcoe_mac_t *mac)
{
	int ret;

	if (mac->fm_handle == NULL) {
		return (FCOE_SUCCESS);
	}

	if (mac->fm_running) {
		cv_destroy(&mac->fm_tx_cv);
		mutex_destroy(&mac->fm_mutex);
		mac->fm_running = B_FALSE;
	}

	if (mac->fm_promisc_handle != NULL) {
		mac_promisc_remove(mac->fm_promisc_handle);
		mac->fm_promisc_handle = NULL;
	} else {
		mac_rx_clear(mac->fm_cli_handle);
	}

	if (mac->fm_notify_handle != NULL) {
		ret = mac_notify_remove(mac->fm_notify_handle, B_TRUE);
		ASSERT(ret == 0);
		mac->fm_notify_handle = NULL;
	}

	if (mac->fm_unicst_handle != NULL) {
		(void) mac_unicast_remove(mac->fm_cli_handle,
		    mac->fm_unicst_handle);
		mac->fm_unicst_handle = NULL;
	}

	mac_client_close(mac->fm_cli_handle, 0);
	mac->fm_cli_handle = NULL;

	(void) mac_close(mac->fm_handle);
	mac->fm_handle = NULL;

	return (FCOE_SUCCESS);
}

int
fcoe_enable_callback(fcoe_mac_t *mac)
{
	int ret;

	/*
	 * Set message callback
	 */
	if (mac->fm_force_promisc) {
		ret = mac_promisc_add(mac->fm_cli_handle,
		    MAC_CLIENT_PROMISC_FILTERED, fcoe_rx, mac,
		    &mac->fm_promisc_handle,
		    MAC_PROMISC_FLAGS_NO_TX_LOOP);
		if (ret != 0) {
			FCOE_LOG("foce", "mac_promisc_add on %d failed %x",
			    mac->fm_linkid, ret);
			return (FCOE_FAILURE);
		}
	} else {
		mac_rx_set(mac->fm_cli_handle, fcoe_rx, mac);
	}

	/* Get the link state, if it's up, we will need to notify client */
	mac->fm_link_state =
	    mac_stat_get(mac->fm_handle, MAC_STAT_LINK_UP)?
	    FCOE_MAC_LINK_STATE_UP:FCOE_MAC_LINK_STATE_DOWN;

	mac->fm_eport.eport_link_speed =
	    mac_client_stat_get(mac->fm_cli_handle, MAC_STAT_IFSPEED);

	/*
	 * Add a notify function so that we get updates from MAC
	 */
	mac->fm_notify_handle = mac_notify_add(mac->fm_handle,
	    fcoe_mac_notify, (void *)mac);
	return (FCOE_SUCCESS);
}

int
fcoe_disable_callback(fcoe_mac_t *mac)
{
	int ret;

	if (mac->fm_promisc_handle) {
		mac_promisc_remove(mac->fm_promisc_handle);
		mac->fm_promisc_handle = NULL;
	} else {
		mac_rx_clear(mac->fm_cli_handle);
	}

	if (mac->fm_notify_handle) {
		ret = mac_notify_remove(mac->fm_notify_handle, B_TRUE);
		ASSERT(ret == 0);
		mac->fm_notify_handle = NULL;
	}

	ret = fcoe_mac_set_address(&mac->fm_eport,
	    mac->fm_primary_addr, B_FALSE);
	FCOE_SET_DEFAULT_FPORT_ADDR(mac->fm_eport.eport_efh_dst);
	return (ret);
}

/* ARGSUSED */
static void
fcoe_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp, boolean_t loopback)
{
	fcoe_mac_t	*mac = (fcoe_mac_t *)arg;
	mblk_t		*next;
	fcoe_frame_t	*frm;
	uint32_t	raw_frame_size, frame_size;
	uint16_t	frm_type;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		frm_type = ntohs(*(uint16_t *)((uintptr_t)mp->b_rptr + 12));

		if (frm_type != ETHERTYPE_FCOE) {
			/*
			 * This mp is not allocated in FCoE, but we must free it
			 */
			freeb(mp);
			mp = next;
			continue;
		}

		raw_frame_size = MBLKL(mp);
		frame_size = raw_frame_size - PADDING_SIZE;
		frm = fcoe_allocate_frame(&mac->fm_eport, frame_size, mp);
		if (frm != NULL) {
			frm->frm_clock = CURRENT_CLOCK;
			fcoe_post_frame(frm);
		}

		mp = next;
	}
}

static void
fcoe_mac_notify(void *arg, mac_notify_type_t type)
{
	fcoe_mac_t *mac = (fcoe_mac_t *)arg;

	/*
	 * We assume that the calls to this notification callback are serialized
	 * by MAC layer
	 */

	switch (type) {
	case MAC_NOTE_LINK:
		/*
		 * This notification is sent every time the MAC driver
		 * updates the link state.
		 */
		if (mac_stat_get(mac->fm_handle, MAC_STAT_LINK_UP) != 0) {
			if (mac->fm_link_state == FCOE_MAC_LINK_STATE_UP) {
				break;
			}
			/* Get speed */
			mac->fm_eport.eport_link_speed =
			    mac_client_stat_get(mac->fm_cli_handle,
			    MAC_STAT_IFSPEED);
			(void) fcoe_mac_set_address(&mac->fm_eport,
			    mac->fm_primary_addr, B_FALSE);

			FCOE_SET_DEFAULT_FPORT_ADDR(
			    mac->fm_eport.eport_efh_dst);

			mac->fm_link_state = FCOE_MAC_LINK_STATE_UP;
			FCOE_LOG(NULL,
			    "fcoe_mac_notify: link/%d arg/%p LINK up",
			    mac->fm_linkid, arg, type);
			fcoe_mac_notify_link_up(mac);
		} else {
			if (mac->fm_link_state == FCOE_MAC_LINK_STATE_DOWN) {
				break;
			}
			mac->fm_link_state = FCOE_MAC_LINK_STATE_DOWN;
			FCOE_LOG(NULL,
			    "fcoe_mac_notify: link/%d arg/%p LINK down",
			    mac->fm_linkid, arg, type);
			fcoe_mac_notify_link_down(mac);
		}
		break;

	case MAC_NOTE_TX:
		/*
		 * MAC is not so busy now, then wake up fcoe_tx_frame to try
		 */
		mutex_enter(&mac->fm_mutex);
		cv_broadcast(&mac->fm_tx_cv);
		mutex_exit(&mac->fm_mutex);

		FCOE_LOG("fcoe_mac_notify", "wake up");
		break;

	default:
		FCOE_LOG("fcoe_mac_notify", "not supported arg/%p, type/%d",
		    arg, type);
		break;
	}
}

int
fcoe_mac_set_address(fcoe_port_t *eport, uint8_t *addr, boolean_t fc_assigned)
{
	fcoe_mac_t	*mac = EPORT2MAC(eport);
	int		ret;

	if (bcmp(addr, mac->fm_current_addr, 6) == 0) {
		return (FCOE_SUCCESS);
	}

	mutex_enter(&mac->fm_mutex);
	if (mac->fm_promisc_handle == NULL) {
		ret = mac_unicast_primary_set(mac->fm_handle, addr);
		if (ret != 0) {
			mutex_exit(&mac->fm_mutex);
			FCOE_LOG("fcoe", "mac_unicast_primary_set on %d "
			    "failed %x", mac->fm_linkid, ret);
			return (FCOE_FAILURE);
		}
	}
	if (fc_assigned) {
		bcopy(addr, mac->fm_current_addr, ETHERADDRL);
	} else {
		bcopy(mac->fm_primary_addr,
		    mac->fm_current_addr, ETHERADDRL);
	}
	mutex_exit(&mac->fm_mutex);
	return (FCOE_SUCCESS);
}
