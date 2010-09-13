/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef NETWORK_DEVICE_COMMON_H
#define	NETWORK_DEVICE_COMMON_H

#include <libhal.h>

extern void network_device_name_to_udi(char *udi, size_t size, ...);
extern int add_network_printer(LibHalContext *ctx, char *parent, char *hostaddr,
			char *device, char *community);

extern gboolean scan_for_devices_using_snmp(LibHalContext *ctx, char *parent,
		char *community, char *network);
extern void scan_for_stale_devices(LibHalContext *ctx, time_t timestamp);
extern gboolean device_seen(char *name);

extern int is_listening(char *hostname, int port);

extern GList *broadcast_addresses();

#endif /* NETWORK_DEVICE_COMMON_H */
