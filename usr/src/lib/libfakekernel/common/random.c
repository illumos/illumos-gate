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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <cryptoutil.h>

int
random_get_bytes(uint8_t *ptr, size_t len)
{
	return (pkcs11_get_random(ptr, len));
}

int
random_get_pseudo_bytes(uint8_t *ptr, size_t len)
{
	return (pkcs11_get_urandom(ptr, len));
}
