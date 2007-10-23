/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <sys/stat.h>
#include <priv.h>
#include <glib.h>

#include <dbus/dbus-glib-lowlevel.h>
#include <libhal.h>

#include "../../hald/logger.h"

#include "network-discovery.h"
#include "printer.h"

#define	DBUS_INTERFACE	"org.freedesktop.Hal.Device.NetworkDiscovery"
#define	NP(x)	(x?x:"NULL")
#define	STRDUP(x)	(x?strdup(x):NULL)

typedef struct {
	LibHalContext *ctx;
	gboolean enabled;
	char *parent;
	char *community;
	char *network;
} nds_snmp_cbdata_t;

static nds_snmp_cbdata_t *snmp_cb_data = NULL;

static int
nds_snmp_scan(LibHalContext *ctx, char *parent, char *community, char *network)
{
	time_t start;

	HAL_DEBUG(("nds_snmp_scan(0x%8.8x, %s, %s, %s)",
			ctx, NP(parent), NP(community), NP(network)));
	HAL_DEBUG(("NetworkDiscovery snmp scan initated"));

	/* scan for devices */
	time(&start);
	if (network == NULL) {
		GList *elem, *list = broadcast_addresses();

		for (elem = list; elem != NULL; elem = g_list_next(elem)) {
			scan_for_devices_using_snmp(ctx, parent, community,
						(char *)elem->data);
			free(elem->data);
		}
		g_list_free(list);
	} else
		scan_for_devices_using_snmp(ctx, parent, community, network);

	/* remove devices that haven't been seen since before this scan */
	scan_for_stale_devices(ctx, start);

	HAL_DEBUG(("NetworkDiscovery snmp scan completed"));

	return (0);
}

static gboolean
nds_snmp_scan_cb(gpointer data)
{
	nds_snmp_cbdata_t *args = data;

	if (args->enabled == FALSE) {
		if (args->parent) free(args->parent);
		if (args->community) free(args->community);
		if (args->network) free(args->network);
		free(args);
		return (FALSE);
	}

	nds_snmp_scan(args->ctx, args->parent, args->community, args->network);

	return (TRUE);
}

static int
nds_EnablePrinterScanningViaSNMP(LibHalContext *ctx, char *parent, int interval,
		char *community, char *network)
{
	HAL_DEBUG(("NetworkDiscovery.EnablePrinterScanningViaSNMP(0x%8.8x, %s, %d, %s, %s)",
			ctx, NP(parent), interval, NP(community), NP(network)));

	/* are we already discoverying network devices ? */
	if (snmp_cb_data != NULL) {
		snmp_cb_data->enabled = FALSE; /* cancel it */
	}

	/* setup for network device discovery */
	if ((snmp_cb_data = calloc(1, sizeof (*snmp_cb_data))) != NULL) {
		snmp_cb_data->ctx = ctx;
		snmp_cb_data->enabled = TRUE;
		snmp_cb_data->parent = STRDUP(parent);
		snmp_cb_data->community = STRDUP(community);
		snmp_cb_data->network = STRDUP(network);

		/* prime the pump with an initial scan */
		nds_snmp_scan(ctx, parent, community, network);

		/* add a regular network scan */
		g_timeout_add(interval * 1000, nds_snmp_scan_cb, snmp_cb_data);
	}

	return (0);
}

static int
nds_DisablePrinterScanningViaSNMP(LibHalContext *ctx)
{
	HAL_DEBUG(("NetworkDiscovery.DisablePrinterScanningViaSNMP(0x%8.8x)", ctx));

	if (snmp_cb_data != NULL)
		snmp_cb_data->enabled = FALSE;
	snmp_cb_data = NULL;

	return (0);
}

static int
nds_ScanForPrintersViaSNMP(LibHalContext *ctx, char *parent, char *community,
		char *network)
{
	time_t start, stop;

	HAL_DEBUG(("NetworkDiscovery.ScanForPrintersViaSNMP(0x%8.8x, %s, %s, %s)",
			ctx, NP(parent), NP(community), NP(network)));

	return (nds_snmp_scan(ctx, parent, community, network));
}

static DBusHandlerResult
nds_filter_function(DBusConnection *connection, DBusMessage *message,
		void *user_data)
{
	LibHalContext *ctx = user_data;
	DBusMessage *reply;
	DBusError error;
	const char *member = dbus_message_get_member(message);
	const char *path = dbus_message_get_path(message);
	int rc = -1;

	dbus_error_init(&error);

	HAL_DEBUG(("DBus message: %s, %s ", member, path));

	if (dbus_message_is_method_call(message,
				DBUS_INTERFACE, "EnablePrinterScanningViaSNMP")) {
		int interval = -1;
		char *udi = getenv("UDI");
		char *community = "public";
		char *network = "0.0.0.0";

		dbus_message_get_args(message, &error,
				DBUS_TYPE_INT32, &interval,
				DBUS_TYPE_STRING, &community,
				DBUS_TYPE_STRING, &network,
				DBUS_TYPE_INVALID);

		if (strcmp(network, "0.0.0.0") == 0)
			network = NULL;

		rc = nds_EnablePrinterScanningViaSNMP(ctx, udi, interval,
				community, network);
	} else if (dbus_message_is_method_call(message,
				DBUS_INTERFACE, "ScanForPrintersViaSNMP")) {
		int interval = -1;
		char *udi = getenv("UDI");
		char *community = "public";
		char *network = "0.0.0.0";

		dbus_message_get_args(message, &error,
				DBUS_TYPE_STRING, &community,
				DBUS_TYPE_STRING, &network,
				DBUS_TYPE_INVALID);

		if (strcmp(network, "0.0.0.0") == 0)
			network = NULL;

		rc = nds_ScanForPrintersViaSNMP(ctx, udi, community, network);
	} else if (dbus_message_is_method_call(message,
				DBUS_INTERFACE, "DisablePrinterScanningViaSNMP")) {
		rc = nds_DisablePrinterScanningViaSNMP(ctx);
	} else
		HAL_WARNING(("Unknown DBus message: %s, %s ", member, path));

	if (dbus_error_is_set(&error))
		dbus_error_free(&error);

	if ((reply = dbus_message_new_method_return(message)) == NULL) {
		HAL_WARNING(("Could not allocate memory for the DBus reply"));
		return (FALSE);
	}

	dbus_message_append_args(reply, DBUS_TYPE_INT32, &rc,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send(connection, reply, NULL)) {
		HAL_WARNING(("Could not sent reply"));
	}
	dbus_connection_flush(connection);
	dbus_message_unref(reply);

	return (DBUS_HANDLER_RESULT_HANDLED);
}

static int
nds_claim_interface(LibHalContext *ctx, char *udi, DBusError *error)
{
	DBusConnection *connection;
	char *interface_xml =
		"<method name=\"EnablePrinterScanningViaSNMP\">\n"
		"  <arg name=\"interval\" direction=\"in\" type=\"i\"/>\n"
		"  <arg name=\"community\" direction=\"in\" type=\"s\"/>\n"
		"  <arg name=\"network\" direction=\"in\" type=\"s\"/>\n"
		"  <arg name=\"return_code\" direction=\"out\" type=\"i\"/>\n"
		"</method>\n"
		"<method name=\"DisablePrinterScanningViaSNMP\">\n"
		"  <arg name=\"return_code\" direction=\"out\" type=\"i\"/>\n"
		"</method>\n"
		"<method name=\"ScanForPrintersViaSNMP\">\n"
		"  <arg name=\"community\" direction=\"in\" type=\"s\"/>\n"
		"  <arg name=\"network\" direction=\"in\" type=\"s\"/>\n"
		"  <arg name=\"return_code\" direction=\"out\" type=\"i\"/>\n"
		"</method>\n";

	HAL_DEBUG(("nds_claim_interface(0x%8.8x, %s, 0x%8.8x): %s",
			ctx, udi, error, DBUS_INTERFACE));

	if ((connection = libhal_ctx_get_dbus_connection(ctx)) == NULL) {
		HAL_WARNING(("Could not get DBus connection"));
		return (-1);
	}

	if (libhal_device_claim_interface(ctx, udi,
			DBUS_INTERFACE, interface_xml, error) == 0) {
		HAL_WARNING(("Could not claim interface: %s", error->message));
		return (-1);
	}

	dbus_connection_setup_with_g_main(connection, NULL);
	dbus_connection_add_filter(connection, nds_filter_function, ctx, NULL);
	dbus_connection_set_exit_on_disconnect(connection, 0);

	return (0);
}

static void
drop_privileges()
{
	priv_set_t *pPrivSet = NULL;
	priv_set_t *lPrivSet = NULL;

	/*
	 * Start with the 'basic' privilege set and then remove any
	 * of the 'basic' privileges that will not be needed.
	 */
	if ((pPrivSet = priv_str_to_set("basic", ",", NULL)) == NULL) {
		return;
	}

	/* Clear privileges we will not need from the 'basic' set */
	(void) priv_delset(pPrivSet, PRIV_FILE_LINK_ANY);
	(void) priv_delset(pPrivSet, PRIV_PROC_EXEC);
	(void) priv_delset(pPrivSet, PRIV_PROC_FORK);
	(void) priv_delset(pPrivSet, PRIV_PROC_INFO);
	(void) priv_delset(pPrivSet, PRIV_PROC_SESSION);

	/* Set the permitted privilege set. */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, pPrivSet) != 0) {
		return;
	}

	/* Clear the limit set. */
	if ((lPrivSet = priv_allocset()) == NULL) {
		return;
	}

	priv_emptyset(lPrivSet);

	if (setppriv(PRIV_SET, PRIV_LIMIT, lPrivSet) != 0) {
		return;
	}

	priv_freeset(lPrivSet);
}


int
main(int argc, char **argv)
{
	LibHalContext *ctx = NULL;
	DBusError error;
	GMainLoop *loop = g_main_loop_new(NULL, FALSE);
	char *udi;

	if ((udi = getenv("UDI")) == NULL) {
		return (0);
	}

	drop_privileges();

	setup_logger();

	dbus_error_init(&error);

	if ((ctx = libhal_ctx_init_direct(&error)) == NULL) {
		return (0);
	}

	if (!libhal_device_addon_is_ready(ctx, udi, &error)) {
		return (0);
	}

	if (nds_claim_interface(ctx, udi, &error) != 0) {
		return (0);
	}

	g_main_loop_run(loop);

	/* NOTREACHED */
}
