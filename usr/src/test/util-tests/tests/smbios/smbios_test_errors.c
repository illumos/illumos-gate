/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Robert Mustacchi
 */

/*
 * Collection of functions to be used with tests that will cause a handle to
 * fail to open.
 */

#include "smbios_test.h"

boolean_t
smbios_test_badvers_mktable(smbios_test_table_t *table)
{
	smbios_test_table_append_eot(table);
	return (B_TRUE);
}
