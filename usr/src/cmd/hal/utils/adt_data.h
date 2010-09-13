/***************************************************************************
 *
 * adt_data.h : Audit facility
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 ***************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef ADT_DATA_H
#define ADT_DATA_H

#ifdef sun
#include <bsm/adt.h>
#include <bsm/adt_event.h>

adt_export_data_t *get_audit_export_data(DBusConnection *bus, const char *invoked_by_syscon_name, size_t *data_size);

#endif  /* sun */

#endif /* ADT_DATA_H */
