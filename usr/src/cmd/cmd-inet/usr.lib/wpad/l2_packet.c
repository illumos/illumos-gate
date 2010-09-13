/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libdlpi.h>
#include <sys/ethernet.h>
#include <netinet/in.h>

#include "wpa_impl.h"
#include "eloop.h"
#include "l2_packet.h"

static int
link_init(struct l2_packet_data *l2)
{
	int retval;
	uint8_t paddr[DLPI_PHYSADDR_MAX];
	size_t paddrlen = sizeof (paddr);

	retval = dlpi_bind(l2->dh, DLPI_ANY_SAP, NULL);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "cannot bind on %s: %s",
		    l2->ifname, dlpi_strerror(retval));
		return (-1);
	}

	retval = dlpi_promiscon(l2->dh, DL_PROMISC_SAP);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "cannot enable promiscous"
		    " mode (SAP) on %s: %s",
		    l2->ifname, dlpi_strerror(retval));
		return (-1);
	}

	retval = dlpi_get_physaddr(l2->dh, DL_CURR_PHYS_ADDR, paddr, &paddrlen);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "cannot get physical address for %s: %s",
		    l2->ifname, dlpi_strerror(retval));
		return (-1);
	}
	if (paddrlen != sizeof (l2->own_addr)) {
		wpa_printf(MSG_ERROR, "physical address for %s is not %d bytes",
		    l2->ifname, sizeof (l2->own_addr));
		return (-1);
	}
	(void) memcpy(l2->own_addr, paddr, sizeof (l2->own_addr));

	return (0);
}

/*
 * layer2 packet handling.
 */
int
l2_packet_get_own_addr(struct l2_packet_data *l2, uint8_t *addr)
{
	(void) memcpy(addr, l2->own_addr, sizeof (l2->own_addr));
	return (0);
}

int
l2_packet_send(struct l2_packet_data *l2, uint8_t *buf, size_t buflen)
{
	int retval;

	retval = dlpi_send(l2->dh, NULL, 0, buf, buflen, NULL);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "l2_packet_send: cannot send "
		    "message on %s: %s", l2->ifname, dlpi_strerror(retval));
		return (-1);
	}
	return (0);
}

/* ARGSUSED */
static void
l2_packet_receive(int fd, void *eloop_ctx, void *sock_ctx)
{
	struct l2_packet_data *l2 = eloop_ctx;
	uint64_t buf[IEEE80211_MTU_MAX / sizeof (uint64_t)];
	size_t buflen = sizeof (buf);
	struct l2_ethhdr *ethhdr;
	int retval;

	retval = dlpi_recv(l2->dh, NULL, NULL, buf, &buflen, 0, NULL);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "l2_packet_receive: cannot receive "
		    "message on %s: %s", l2->ifname, dlpi_strerror(retval));
		return;
	}

	ethhdr = (struct l2_ethhdr *)buf;
	if (buflen < sizeof (*ethhdr) ||
	    (ntohs(ethhdr->h_proto) != ETHERTYPE_EAPOL &&
	    ntohs(ethhdr->h_proto) != ETHERTYPE_RSN_PREAUTH))
		return;

	l2->rx_callback(l2->rx_callback_ctx, ethhdr->h_source,
	    (unsigned char *)(ethhdr + 1), buflen - sizeof (*ethhdr));
}

/* ARGSUSED */
struct l2_packet_data *
l2_packet_init(const char *ifname, unsigned short protocol,
	void (*rx_callback)(void *, unsigned char *, unsigned char *, size_t),
	void *rx_callback_ctx)
{
	int retval;
	struct l2_packet_data *l2;

	l2 = calloc(1, sizeof (struct l2_packet_data));
	if (l2 == NULL)
		return (NULL);

	(void) strlcpy(l2->ifname, ifname, sizeof (l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;

	retval = dlpi_open(l2->ifname, &l2->dh, DLPI_RAW);
	if (retval != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "unable to open DLPI link %s: %s",
		    l2->ifname, dlpi_strerror(retval));
		free(l2);
		return (NULL);
	}

	/* NOTE: link_init() sets l2->own_addr */
	if (link_init(l2) < 0) {
		dlpi_close(l2->dh);
		free(l2);
		return (NULL);
	}

	(void) eloop_register_read_sock(dlpi_fd(l2->dh), l2_packet_receive, l2,
	    NULL);

	return (l2);
}

void
l2_packet_deinit(struct l2_packet_data *l2)
{
	if (l2 == NULL)
		return;

	eloop_unregister_read_sock(dlpi_fd(l2->dh));
	dlpi_close(l2->dh);
	free(l2);
}
