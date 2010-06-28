/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "KMSAgentKeyCallout.h"

#ifdef METAWARE
extern "C" int ecpt_get_pc_key_and_xor( unsigned char * key );
#endif

/**
 *  Hook function to get the key in the clear (XOR is presently used)
 *  @returns 0=ok, nonzero = bad
 */
int KMSAgentKeyCallout( unsigned char io_aKey[KMS_MAX_KEY_SIZE] )
{
#ifndef METAWARE
    return 0;
#else
    return ecpt_get_pc_key_and_xor( io_aKey );
#endif    
}
