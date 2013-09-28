/***************************************************************************
 *
 * devinfo.c : main file for libdevinfo-based device enumeration
 *
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <libdevinfo.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "../hald_runner.h"
#include "osspec_solaris.h"
#include "hotplug.h"
#include "devinfo.h"
#include "devinfo_pci.h"
#include "devinfo_storage.h"
#include "devinfo_ieee1394.h"
#include "devinfo_usb.h"
#include "devinfo_misc.h"
#include "devinfo_acpi.h"
#include "devinfo_cpu.h"

void devinfo_add_subtree(HalDevice *parent, di_node_t node, gboolean is_root);
HalDevice *devinfo_add_node(HalDevice *parent, di_node_t node);

void
devinfo_add(HalDevice *parent, gchar *path)
{
	di_node_t	root;

	if (strcmp (path, "/") == 0) {
		if ((root = di_init(path, DINFOCACHE)) == DI_NODE_NIL) {
			HAL_INFO (("di_init() failed %d", errno));
			return;
		}
	} else {
		if ((root = di_init(path, DINFOCPYALL)) == DI_NODE_NIL) {
			HAL_INFO (("di_init() failed %d", errno));
			return;
		}
	}

	devinfo_add_subtree(parent, root, TRUE);

	di_fini (root);
}

void
devinfo_add_subtree(HalDevice *parent, di_node_t node, gboolean is_root)
{
	HalDevice *d;
	di_node_t root_node, child_node;

	HAL_INFO (("add_subtree: %s", di_node_name (node)));

	root_node = node;
	do {
		d = devinfo_add_node (parent, node);

		if ((d != NULL) &&
		    (child_node = di_child_node (node)) != DI_NODE_NIL) {
			devinfo_add_subtree (d, child_node, FALSE);
		}

		node = di_sibling_node (node);
	} while ((node != DI_NODE_NIL) &&
		(!is_root || di_parent_node (node) == root_node));
}

void
devinfo_set_default_properties (HalDevice *d, HalDevice *parent, di_node_t node, char *devfs_path)
{
	char	*driver_name, *s;
	const char *s1;
	char	udi[HAL_PATH_MAX];

	if (parent != NULL) {
		hal_device_property_set_string (d, "info.parent", hal_device_get_udi (parent));
	} else {
		hal_device_property_set_string (d, "info.parent", "/org/freedesktop/Hal/devices/local");
	}

	hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
				"/org/freedesktop/Hal/devices%s_%d",
				devfs_path,
				di_instance (node));
	hal_device_set_udi (d, udi);
	hal_device_property_set_string (d, "info.udi", udi);

	if (di_prop_lookup_strings (DDI_DEV_T_ANY, node, "model", &s) > 0) {
		hal_device_property_set_string (d, "info.product", s);
	} else {
		hal_device_property_set_string (d, "info.product", di_node_name (node));
	}

	hal_device_property_set_string (d, "solaris.devfs_path", devfs_path);

	if ((driver_name = di_driver_name (node)) != NULL) {
		hal_device_property_set_string (d, "info.solaris.driver",
						driver_name);
	}


	/* inherit parent's claim attributes */
	if (hal_device_property_get_bool (parent, "info.claimed")) {
		s1 = hal_device_property_get_string (parent, "info.claimed.service");
		if (s1 != NULL) {
			hal_device_property_set_bool (d, "info.claimed", TRUE);
			hal_device_property_set_string (d, "info.claimed.service", s1);
		}
	}
}

/* device handlers, ordered specific to generic */
static DevinfoDevHandler *devinfo_handlers[] = {
	&devinfo_computer_handler,
	&devinfo_cpu_handler,
	&devinfo_ide_handler,
	&devinfo_scsi_handler,
	&devinfo_blkdev_handler,
	&devinfo_floppy_handler,
	&devinfo_usb_handler,
	&devinfo_ieee1394_handler,
	&devinfo_lofi_handler,
	&devinfo_acpi_handler,
	&devinfo_power_button_handler,
	&devinfo_keyboard_handler,
	&devinfo_mouse_handler,
	&devinfo_pci_handler,
	&devinfo_default_handler,
	NULL
};

HalDevice *
devinfo_add_node(HalDevice *parent, di_node_t node)
{
	HalDevice *d = NULL;
	char	*devfs_path;
	char	*device_type = NULL;
	DevinfoDevHandler *handler;
	int	i;

	devfs_path = di_devfs_path (node);

        (void) di_prop_lookup_strings (DDI_DEV_T_ANY, node, "device_type",
	    &device_type);

	for (i = 0; (d == NULL) && (devinfo_handlers[i] != NULL); i++) {
		handler = devinfo_handlers[i];
		d = handler->add (parent, node, devfs_path, device_type);
	}

	di_devfs_path_free(devfs_path);

	HAL_INFO (("add_node: %s", d ? hal_device_get_udi (d) : "none"));
	return (d);
}

void
devinfo_hotplug_enqueue(HalDevice *d, gchar *devfs_path, DevinfoDevHandler *handler, int action, int front)
{
	HotplugEvent *hotplug_event;

	hotplug_event = g_new0 (HotplugEvent, 1);
	hotplug_event->action = action;
	hotplug_event->type = HOTPLUG_EVENT_DEVFS;
	hotplug_event->d = d;
	strlcpy (hotplug_event->un.devfs.devfs_path, devfs_path,
		sizeof (hotplug_event->un.devfs.devfs_path));
	hotplug_event->un.devfs.handler = handler;

	hotplug_event_enqueue (hotplug_event, front);
}

void
devinfo_add_enqueue(HalDevice *d, gchar *devfs_path, DevinfoDevHandler *handler)
{
	devinfo_hotplug_enqueue (d, devfs_path, handler, HOTPLUG_ACTION_ADD, 0);
}

void
devinfo_add_enqueue_at_front(HalDevice *d, gchar *devfs_path, DevinfoDevHandler *handler)
{
	devinfo_hotplug_enqueue (d, devfs_path, handler, HOTPLUG_ACTION_ADD, 1);
}

void
devinfo_remove_enqueue(gchar *devfs_path, DevinfoDevHandler *handler)
{
	devinfo_hotplug_enqueue (NULL, devfs_path, handler, HOTPLUG_ACTION_REMOVE, 0);
}

void
devinfo_callouts_add_done (HalDevice *d, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;

        /* Move from temporary to global device store */
        hal_device_store_remove (hald_get_tdl (), d);
        hal_device_store_add (hald_get_gdl (), d);

        hotplug_event_end (end_token);
}

void
devinfo_callouts_probing_done (HalDevice *d, guint32 exit_type, gint return_code, char **error, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;

        /* Discard device if probing reports failure */
        if (exit_type != HALD_RUN_SUCCESS || (return_code != 0)) {
		HAL_INFO (("Probing for %s failed %d", hal_device_get_udi (d), return_code));
                hal_device_store_remove (hald_get_tdl (), d);
                g_object_unref (d);
                hotplug_event_end (end_token);
		return;
        }

        /* Merge properties from .fdi files */
        di_search_and_merge (d, DEVICE_INFO_TYPE_INFORMATION);
        di_search_and_merge (d, DEVICE_INFO_TYPE_POLICY);

	hal_util_callout_device_add (d, devinfo_callouts_add_done, end_token, NULL);
}

void
devinfo_callouts_preprobing_done (HalDevice *d, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;
	DevinfoDevHandler *handler = (DevinfoDevHandler *) userdata2;
	void (*probing_done) (HalDevice *, guint32, gint, char **, gpointer, gpointer);
	const gchar *prober;
	int prober_timeout;

        if (hal_device_property_get_bool (d, "info.ignore")) {
		HAL_INFO (("Preprobing merged info.ignore==TRUE"));

                /* Leave device with info.ignore==TRUE so we won't pick up children */
		hal_device_property_remove (d, "info.category");
		hal_device_property_remove (d, "info.capabilities");

		hal_device_store_remove (hald_get_tdl (), d);
		hal_device_store_add (hald_get_gdl (), d);

		hotplug_event_end (end_token);
		return;
        }

        if (handler != NULL && handler->get_prober != NULL) {
                prober = handler->get_prober (d, &prober_timeout);
        } else {
                prober = NULL;
	}

	if (handler->probing_done != NULL) {
		probing_done = handler->probing_done;
	} else {
		probing_done = devinfo_callouts_probing_done;
	}

        if (prober != NULL) {
                /* probe the device */
		HAL_INFO(("Probing udi=%s", hal_device_get_udi (d)));
                hald_runner_run (d,
				prober, NULL,
				prober_timeout,
				probing_done,
				(gpointer) end_token, (gpointer) handler);
	} else {
		probing_done (d, 0, 0, NULL, userdata1, userdata2);
	}
}

/* This is the beginning of hotplug even handling */
void
hotplug_event_begin_add_devinfo (HalDevice *d, HalDevice *parent, DevinfoDevHandler *handler, void *end_token)
{
	HotplugEvent *hotplug_event = (HotplugEvent *)end_token;

	HAL_INFO(("Preprobing udi=%s", hal_device_get_udi (d)));

	if (parent == NULL && (strcmp(hotplug_event->un.devfs.devfs_path, "/") != 0)) {
		HAL_ERROR (("Parent is NULL, devfs_path=%s", hotplug_event->un.devfs.devfs_path));

		goto skip;
	}


	if (parent != NULL && hal_device_property_get_bool (parent, "info.ignore")) {
		HAL_INFO (("Ignoring device since parent has info.ignore==TRUE"));

		goto skip;
	}

	if (hal_device_store_find (hald_get_tdl (), hal_device_get_udi (d)) == NULL) {

		/* add to TDL so preprobing callouts and prober can access it */
		hal_device_store_add (hald_get_tdl (), d);
	}

        /* Process preprobe fdi files */
        di_search_and_merge (d, DEVICE_INFO_TYPE_PREPROBE);

        /* Run preprobe callouts */
        hal_util_callout_device_preprobe (d, devinfo_callouts_preprobing_done, end_token, handler);

	return;

skip:
	if (hal_device_store_find (hald_get_tdl (), hal_device_get_udi (d)))
		hal_device_store_remove (hald_get_tdl (), d);

	g_object_unref (d);
	hotplug_event_end (end_token);

	return;
}

void
devinfo_remove (gchar *devfs_path)
{
	devinfo_remove_enqueue ((gchar *)devfs_path, NULL);
}

/* generate hotplug event for each device in this branch */
void
devinfo_remove_branch (gchar *devfs_path, HalDevice *d)
{
	GSList *i;
	GSList *children;
	HalDevice *child;
	char *child_devfs_path;

	if (d == NULL) {
		d = hal_device_store_match_key_value_string (hald_get_gdl (),
			"solaris.devfs_path", devfs_path);
		if (d == NULL)
			return;
	}

	HAL_INFO (("remove_branch: %s %s\n", devfs_path, hal_device_get_udi (d)));

	/* first remove children */
	children = hal_device_store_match_multiple_key_value_string (hald_get_gdl(),
		"info.parent", hal_device_get_udi (d));
        for (i = children; i != NULL; i = g_slist_next (i)) {
                child = HAL_DEVICE (i->data);
		HAL_INFO (("remove_branch: child %s\n", hal_device_get_udi (child)));
		devinfo_remove_branch ((gchar *)hal_device_property_get_string (child, "solaris.devfs_path"), child);
	}
	g_slist_free (children);
	HAL_INFO (("remove_branch: done with children"));

	/* then remove self */
	HAL_INFO (("remove_branch: queueing %s", devfs_path));
	devinfo_remove_enqueue (devfs_path, NULL);
}

void
devinfo_callouts_remove_done (HalDevice *d, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;

        HAL_INFO (("Remove callouts completed udi=%s", hal_device_get_udi (d)));

        if (!hal_device_store_remove (hald_get_gdl (), d)) {
                HAL_WARNING (("Error removing device"));
        }
        g_object_unref (d);

        hotplug_event_end (end_token);
}

void
hotplug_event_begin_remove_devinfo (HalDevice *d, gchar *devfs_path, void *end_token)
{
	if (hal_device_has_capability (d, "volume")) {
		devinfo_volume_hotplug_begin_remove (d, devfs_path, end_token);
	} else {
		hal_util_callout_device_remove (d, devinfo_callouts_remove_done, end_token, NULL);
	}
}

gboolean
devinfo_device_rescan (HalDevice *d)
{
	if (hal_device_has_capability (d, "block")) {
		return (devinfo_storage_device_rescan (d));
	} else if (hal_device_has_capability (d, "button")) {
		return (devinfo_lid_rescan (d));
        } else { 
		return (FALSE);
	}
}

static int
walk_devlinks(di_devlink_t devlink, void *arg)
{
        char    **path= (char **)arg;

        *path = strdup(di_devlink_path(devlink));

        return (DI_WALK_TERMINATE);
}

char *
get_devlink(di_devlink_handle_t devlink_hdl, char *re, char *path)
{
        char    *devlink_path = NULL;

        (void) di_devlink_walk(devlink_hdl, re, path,
            DI_PRIMARY_LINK, &devlink_path, walk_devlinks);

        return (devlink_path);
}
