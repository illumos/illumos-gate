/***************************************************************************
 *
 * osspec.c : Solaris HAL backend entry points
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <port.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "../ids.h"
#include "osspec_solaris.h"
#include "hotplug.h"
#include "sysevent.h"
#include "devinfo.h"
#include "devinfo_storage.h"

static void mnttab_event_init ();
static gboolean mnttab_event (GIOChannel *channel, GIOCondition cond, gpointer user_data);

void
osspec_init (void)
{
	ids_init ();
	sysevent_init ();
	mnttab_event_init ();
}

void
hotplug_queue_now_empty (void)
{
        if (hald_is_initialising) {
                osspec_probe_done ();
	}
}

void 
osspec_probe (void)
{
	/* add entire device tree */
	devinfo_add (NULL, "/");

	/* start processing events */
	hotplug_event_process_queue ();
}

gboolean
osspec_device_rescan (HalDevice *d)
{
	   return (devinfo_device_rescan (d));
}

gboolean
osspec_device_reprobe (HalDevice *d)
{
	   return FALSE;
}

DBusHandlerResult
osspec_filter_function (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/** Find the closest ancestor by looking at devfs paths
 *
 *  @param  devfs_path           Path into devfs, e.g. /pci@0,0/pci1025,57@10,2/storage@1
 *  @return                      Parent Hal Device Object or #NULL if there is none
 */
HalDevice *
hal_util_find_closest_ancestor (const gchar *devfs_path, gchar **ancestor_devfs_path, gchar **hotplug_devfs_path)
{
        gchar buf[512];
	gchar c;
        HalDevice *parent;

        parent = NULL;

        strncpy (buf, devfs_path, sizeof (buf));
        do {
                char *p;

                p = strrchr (buf, '/');
                if (p == NULL)
                        break;
		c = *p;
                *p = '\0';

                parent = hal_device_store_match_key_value_string (hald_get_gdl (),
                                                                  "solaris.devfs_path",
                                                                  buf);
                if (parent != NULL) {
			if (ancestor_devfs_path != NULL) {
				*ancestor_devfs_path = g_strdup (buf);
			}
			if (hotplug_devfs_path != NULL) {
				*p = c;
				*hotplug_devfs_path = g_strdup (buf);
			}
                        break;
		}

        } while (TRUE);

        return parent;
}

char *
dsk_to_rdsk(char *dsk)
{
        int     len, pos;
        char    *p;
        char    *rdsk;

	if ((len = strlen (dsk)) < sizeof ("/dev/dsk/cN") - 1) {
		return (strdup(""));
	}
	if ((p = strstr (dsk, "/dsk/")) == NULL) {
		if ((p = strstr (dsk, "/lofi/")) == NULL) {
			p = strstr (dsk, "/diskette");
		}
	}
	if (p == NULL) {
		return (strdup(""));
	}

	pos = (uintptr_t)p - (uintptr_t)dsk;
	if ((rdsk = (char *)calloc (len + 2, 1)) != NULL) {
        	strncpy (rdsk, dsk, pos + 1);
        	rdsk[pos + 1] = 'r';
        	strcpy (rdsk + pos + 2, dsk + pos + 1);
	}

        return (rdsk);
}

/*
 * Setup to watch mnttab changes
 *
 * When mnttab changes, POLLRDBAND is set. However, glib does not
 * support POLLRDBAND, so we use Solaris ports (see port_create(3C))
 * to "map" POLLRDBAND to POLLIN:
 *
 * - create a port
 * - associate the port with mnttab file descriptor and POLLRDBAND
 * - now polling for POLLIN on the port descriptor will unblock when
 *   the associated file descriptor receives POLLRDBAND
 */
static int	mnttab_fd;
static int	mnttab_port;
static GIOChannel *mnttab_channel;

static void
mnttab_event_init ()
{
	char	buf[81];

	if ((mnttab_fd = open (MNTTAB, O_RDONLY)) < 0) {
		return;
	}
	if ((mnttab_port = port_create ()) < 0) {
		(void) close (mnttab_fd);
		return;
	}
	if (port_associate (mnttab_port, PORT_SOURCE_FD, mnttab_fd, POLLRDBAND,
	    NULL) != 0) {
		(void) close (mnttab_port);
		(void) close (mnttab_fd);
		return;
	}

	/* suppress initial event */
	(void) read(mnttab_fd, buf, (size_t)(sizeof (buf) - 1));
	(void) lseek(mnttab_fd, 0, SEEK_SET);

	mnttab_channel = g_io_channel_unix_new (mnttab_port);
	g_io_add_watch (mnttab_channel, G_IO_IN, mnttab_event, NULL);
}

static gboolean
mnttab_event (GIOChannel *channel, GIOCondition cond, gpointer user_data)
{
	port_event_t pe;
	timespec_t timeout;
	char	buf[81];

	/* if (cond & ~G_IO_ERR)
		return TRUE;
	 */
	HAL_INFO (("mnttab event"));

	/* we have to re-associate port with fd every time */
	timeout.tv_sec = timeout.tv_nsec = 0;
	(void) port_get(mnttab_port, &pe, &timeout);
	(void) port_associate(mnttab_port, PORT_SOURCE_FD,
	    mnttab_fd, POLLRDBAND, NULL);

	if (!hald_is_initialising) {
		devinfo_storage_mnttab_event (NULL);
	}

	(void) lseek(mnttab_fd, 0, SEEK_SET);
	(void) read(mnttab_fd, buf, (size_t)(sizeof (buf) - 1));

	return TRUE;
}

void
osspec_refresh_mount_state_for_block_device (HalDevice *d)
{
	devinfo_storage_mnttab_event (d);
}
