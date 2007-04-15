/***************************************************************************
 *
 * battery.h 
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef BATTERY_H
#define	BATTERY_H

#include "../hald/util.h"

#define	BATTERY_POLL_TIMER		30000

gboolean battery_update(LibHalContext *ctx, const char *udi, int fd);
gboolean ac_adapter_update(LibHalContext *ctx, const char *udi, int fd);
gboolean update_devices(gpointer data);
int open_device(LibHalContext *ctx, char *udi);

#endif /* BATTERY_H */
