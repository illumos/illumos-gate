/***************************************************************************
 *
 * sysevent.h : definitions for Solaris sysevents
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef SYSEVENT_H
#define SYSEVENT_H

#include <glib.h>

gboolean sysevent_init(void);
void sysevent_fini(void);

#endif /* SYSEVENT_H */
