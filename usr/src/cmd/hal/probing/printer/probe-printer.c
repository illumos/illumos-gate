/***************************************************************************
 *
 * probe-printer.c : Probe for prnio(7i) printer device information
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prnio.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <libhal.h>
#include <logger.h>

#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

static char *
strip_ws(char *s)
{
	if (s != NULL) {
		char *p;

		/* skip the leading whitespace */
		for (; ((*s != NULL) && (isspace(*s) != 0)); s++) ;

		/* drop the trailing whitespace */
		for (p = s + strlen(s) - 1; ((p > s) && (isspace(*p) != 0));
		     p--) ;
		*(++p) = '\0';
	}

	return (s);
}

static int
get_prnio_data(int fd, LibHalChangeSet *cs)
{
	struct prn_1284_device_id id;
	char buf[BUFSIZ];
	char *s, *iter = NULL;

	memset(&id, 0, sizeof (id));
	memset(&buf, 0, sizeof (buf));
	id.id_data = buf;
	id.id_len = sizeof (buf);

	if (ioctl(fd, PRNIOC_GET_1284_DEVID, &id) < 0) {
		return (-1);
	}

	HAL_DEBUG (("IEEE-1284 DeviceId = %s", buf));

	for (s = strtok_r(buf, ";\n", &iter); s != NULL;
	     s = strtok_r(NULL, ";\n", &iter)) {
		char *t, *u, *iter2 = NULL;

		if ((t = strtok_r(s, ":\n", &iter2)) == NULL) {
			continue;
		}

		if ((u = strtok_r(NULL, ":\n", &iter2)) == NULL) {
			continue;
		}

		if ((strcasecmp(t, "MFG") == 0) ||
		    (strcasecmp(t, "MANUFACTURER") == 0)) {
			libhal_changeset_set_property_string (cs,
					"printer.vendor", strip_ws(u));
		} else if ((strcasecmp(t, "MDL") == 0) ||
		    (strcasecmp(t, "MODEL") == 0)) {
			libhal_changeset_set_property_string (cs,
					"printer.product", strip_ws(u));
		} else if ((strcasecmp(t, "SN") == 0) ||
		    (strcasecmp(t, "SERN") == 0) ||
		    (strcasecmp(t, "SERIALNUMBER") == 0)) {
			libhal_changeset_set_property_string (cs,
					"printer.serial", strip_ws(u));
		} else if ((strcasecmp(t, "DES") == 0) ||
		    (strcasecmp(t, "DESCRIPTION") == 0)) {
			libhal_changeset_set_property_string (cs,
					"printer.description", strip_ws(u));
		} else if ((strcasecmp(t, "CMD") == 0) ||
		    (strcasecmp(t, "COMMAND SET") == 0) ||
		    (strcasecmp(t, "COMMANDSET") == 0)) {
			char *v, *iter3 = NULL;
			const char *cmds[32];
			int i = 0;

			memset(&cmds, 0, sizeof (cmds));
			for (v = strtok_r(u, ",\n", &iter3);
			     ((v != NULL) && (i < NELEM(cmds)));
			     v = strtok_r(NULL, ",\n", &iter3)) {
				cmds[i++] = strip_ws(v);
			}

			libhal_changeset_set_property_strlist(cs,
					"printer.commandset", cmds);
		}
	}

	return (0);
}

int 
main (int argc, char *argv[])
{
	int ret = 1;
	int fd = -1;
	char *udi;
	char *device_file;
	DBusError error;
	LibHalContext *ctx = NULL;
	LibHalChangeSet *cs = NULL;

	if ((udi = getenv ("UDI")) == NULL)
		goto out;
	if ((device_file = getenv ("HAL_PROP_PRINTER_DEVICE")) == NULL)
		goto out;

	setup_logger ();

	dbus_error_init (&error);
	if ((ctx = libhal_ctx_init_direct (&error)) == NULL)
		goto out;

	if ((cs = libhal_device_new_changeset (udi)) == NULL) {
		HAL_DEBUG (("Cannot allocate changeset"));
		goto out;
	}

	HAL_DEBUG (("Doing probe-printer for %s (udi=%s)", 
	     device_file, udi));

	if ((fd = open (device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		HAL_DEBUG (("Cannot open %s: %s", device_file, strerror (errno)));
		goto out;
	}

	if (get_prnio_data(fd, cs) < 0) {
		HAL_DEBUG (("Cannot get prnio data %s: %s", device_file, strerror (errno)));
		goto out;
	}

	libhal_device_commit_changeset (ctx, cs, &error);

	ret = 0;

out:
	if (cs != NULL) {
		libhal_device_free_changeset (cs);
	}

	if (fd >= 0) {
		close (fd);
	}

	if (ctx != NULL) {
		if (dbus_error_is_set(&error)) {
			dbus_error_free (&error);
		}
		libhal_ctx_shutdown (ctx, &error);
		libhal_ctx_free (ctx);
	}

	return ret;
}
