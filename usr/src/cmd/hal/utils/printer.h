/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _PRINTER_H
#define	_PRINTER_H

#include <libhal.h>

extern int ieee1284_devid_to_printer_info(char *devid_string,
		char **manufacturer, char **model, char **description,
		char **class, char **serial_no, char ***command_set);

extern int add_printer_info(LibHalChangeSet *cs, char *udi, char *manufacturer,
		char *model, char *serial_number, char *description,
		char **command_set, char *device);

#endif /* _PRINTER_H */
