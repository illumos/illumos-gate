#!/usr/sbin/dtrace -s
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
 * Copyright 2017-2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Trace almost everything
 */
pid$target:test-*::entry,
pid$target:libpkcs11.so.1::entry,
pid$target:libsoftcrypto.so.1::entry,
pid$target:pkcs11_softtoken.so.1::entry
{
	printf("\t0x%x", arg0);
	printf("\t0x%x", arg1);
	printf("\t0x%x", arg2);
	printf("\t0x%x", arg3);
	printf("\t0x%x", arg4);
	printf("\t0x%x", arg5);
}


pid$target:test-*::return,
pid$target:libpkcs11.so.1::return,
pid$target:libsoftcrypto.so.1::return,
pid$target:pkcs11_softtoken.so.1::return
{
	printf("\t0x%x", arg1);
}
