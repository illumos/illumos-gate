/***************************************************************************
 *
 * devinfo.h : definitions for libdevinfo-based device enumeration
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef DEVINFO_H
#define DEVINFO_H

#include <glib.h>
#include <libdevinfo.h>

#include "../hald.h"
#include "../device_info.h"

typedef struct DevinfoDevHandler_s
{
	HalDevice *(*add) (HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);

	/* yet unused */
	void (*remove) (char *devfs_path);

	void (*hotplug_begin_add) (HalDevice *d, HalDevice *parent, struct DevinfoDevHandler_s *handler, void *end_token);

	void (*hotplug_begin_remove) (HalDevice *d, struct DevinfoDevHandler_s *handler, void *end_token);

	void (*probing_done) (HalDevice *d, guint32 exit_type, gint return_code, char **error, gpointer userdata1, gpointer userdata2);

	const gchar *(*get_prober) (HalDevice *d, int *timeout);
} DevinfoDevHandler;

#define PROP_INT(d, node, v, diprop, halprop) \
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, diprop, &(v)) > 0) { \
		hal_device_property_set_int (d, halprop, *(v)); \
	}

#define PROP_STR(d, node, v, diprop, halprop) \
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node, diprop, &(v)) > 0) { \
		hal_device_property_set_string (d, halprop, v); \
	}

#define PROP_BOOL(d, node, v, diprop, halprop) \
	hal_device_property_set_bool (d, halprop, \
	    (di_prop_lookup_ints(DDI_DEV_T_ANY, node, diprop, &(v)) >= 0));

#define	NELEM(a)	(sizeof (a) / sizeof (*(a)))

void devinfo_add (HalDevice *parent, gchar *path);
void devinfo_set_default_properties (HalDevice *d, HalDevice *parent, di_node_t node, char *devfs_path);
void devinfo_callouts_preprobing_done (HalDevice *d, gpointer userdata1, gpointer userdata2);
void devinfo_callouts_probing_done (HalDevice *d, guint32 exit_type, gint return_code, char **error,
	gpointer userdata1, gpointer userdata2);
void devinfo_callouts_add_done (HalDevice *d, gpointer userdata1, gpointer userdata2);
void devinfo_callouts_remove_done (HalDevice *d, gpointer userdata1, gpointer userdata2);
void hotplug_event_begin_add_devinfo (HalDevice *d, HalDevice *parent, DevinfoDevHandler *handler, void *end_token);
void devinfo_remove (gchar *path);
void devinfo_remove_branch (gchar *path, HalDevice *d);
void hotplug_event_begin_remove_devinfo (HalDevice *d, gchar *devfs_path, void *end_token);
void devinfo_hotplug_enqueue(HalDevice *d, gchar *devfs_path, DevinfoDevHandler *handler, int action, int front);
void devinfo_add_enqueue(HalDevice *d, gchar *devfs_path, DevinfoDevHandler *handler);
void devinfo_add_enqueue_at_front(HalDevice *d, gchar *devfs_path, DevinfoDevHandler *handler);
void devinfo_remove_enqueue(gchar *devfs_path, DevinfoDevHandler *handler);
gboolean devinfo_device_rescan (HalDevice *d);
char *get_devlink(di_devlink_handle_t devlink_hdl, char *re, char *path);


#endif /* DEVINFO_H */
