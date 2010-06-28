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

/*---------------------------------------------------------------------------
 * Module:            k_setupssl.h
 * Operating System:  Linux, Win32
 *
 * Description:
 * This is the header file of setting up OpenSSL
 */

#ifndef _K_SETUP_SSL_H
#define _K_SETUP_SSL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef METAWARE
#include "stdsoap2.h"
/**
 *  set up gSoap I/O callback functions for environments that need to customize
 *  the I/O functions, e.g. embedded agents.
 */
int K_SetupCallbacks( struct soap *i_pSoap );

int K_ssl_client_context(struct soap *i_pSoap,
                            int flags,
                            const char *keyfile,  /* NULL - SERVER */
                            const char *password, /* NULL - SERVER */
                            const char *cafile,
                            const char *capath,   /* ALWAYS NULL */
                            const char *randfile);
#endif


int K_SetupSSL();
void K_CleanupSSL();

#ifdef __cplusplus
}
#endif

#endif
