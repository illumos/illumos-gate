/***************************************************************************
 *
 * acpi.h
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef ACPI_H
#define	ACPI_H

#include "../hald/util.h"

#define	BATTERY_POLL_TIMER		30000

gboolean battery_update(LibHalContext *ctx, const char *udi, int fd);
gboolean ac_adapter_update(LibHalContext *ctx, const char *udi, int fd);
gboolean lid_update(LibHalContext *ctx, const char *udi, int fd);
gboolean laptop_panel_update(LibHalContext *ctx, const char *udi, int fd);
gboolean update_devices(gpointer data);
int open_device(LibHalContext *ctx, char *udi);

#endif /* ACPI_H */
