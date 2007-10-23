/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include <libhal.h>
#include <logger.h>

#undef PACKAGE_STRING
#undef PACKAGE_VERSION

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "network-discovery.h"
#include "printer.h"

#define NP(x)   (x?x:"NULL")

static GList *new_addrs = NULL;

static void
add_snmp_device(LibHalContext *ctx, char *parent, char *name, char *community)
{
	/* most printers listen on the appsocket port (9100) */
	if (is_listening(name, 9100) == 0) {
		char device[128];

		snprintf(device, sizeof (device), "socket://%s:9100", name);

		add_network_printer(ctx, parent, name, device, community);
	}

	/*
	 * This would be a good place to detect other types of devices or other
	 * device capabilities.  scanners, removable media, storage, ...
	 */
}

static int
snmp_response_cb(int operation, struct snmp_session *sp, int reqid,
		struct snmp_pdu *pdu, void *data)
{
	struct sockaddr_in *addr = pdu->transport_data;
	char *name;

	name = inet_ntoa(addr->sin_addr);

	/* have we already seen this network device */
	if (device_seen(name) == FALSE)
		new_addrs = g_list_append(new_addrs, strdup(name));

	return (0);
}

gboolean
scan_for_devices_using_snmp(LibHalContext *ctx, char *parent, char *community,
		char *network)
{
	struct snmp_session session, *ss;
	struct snmp_pdu *request = NULL, *response = NULL;
	oid Oid[MAX_OID_LEN];
	unsigned int oid_len = MAX_OID_LEN;
	GList *elem;

	HAL_DEBUG(("scan_for_devices_using_snmp(0x%8.8x, %s, %s, %s)",
			ctx, NP(parent), NP(community), NP(network)));

	init_snmp("snmp-scan");
	init_mib();

	/* initialize the SNMP session */
	snmp_sess_init(&session);
	session.peername = network;
	session.community = (uchar_t *)community;
	session.community_len = strlen((const char *)session.community);
	session.version = SNMP_VERSION_1;

	if ((ss = snmp_open(&session)) == NULL)
		return (FALSE);

	/* initialize the request PDU */
	request = snmp_pdu_create(SNMP_MSG_GET);

	/* add the requested data (everyone should have a sysDescr.0) */
	if (!read_objid("SNMPv2-MIB::sysDescr.0", Oid, &oid_len))
		snmp_perror("sysDescr.0");
	snmp_add_null_var(request, Oid, oid_len);

	snmp_async_send(ss, request, snmp_response_cb, NULL);

	/* detect any new devices */
	while (1) {
		int fds = 0, block = 0;
		fd_set fdset;
		struct timeval timeout;

		FD_ZERO(&fdset);
		snmp_select_info(&fds, &fdset, &timeout, &block);
		fds = select(fds, &fdset, NULL, NULL, block ? NULL : &timeout);
		if (fds < 0) {
			perror("select failed");
			continue;
		} if (fds == 0) {
			break;
		} else {
			snmp_read(&fdset);
		}
	}

	snmp_close(ss);

	/* add the newly detected devices */
	for (elem = new_addrs; elem != NULL; elem = g_list_next(elem)) {
		add_snmp_device(ctx, parent, (char *)elem->data, community);
		free(elem->data);
	}
	g_list_free(new_addrs);
	new_addrs = NULL;

	return (TRUE);
}
