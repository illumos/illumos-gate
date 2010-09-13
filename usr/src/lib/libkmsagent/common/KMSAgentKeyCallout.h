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

/**
 * \file    KMSAgentKeyCallout.h
 *
 */

#ifndef KMSAGENT_KEYCALLOUT_H
#define KMSAGENT_KEYCALLOUT_H

#include "KMSAgent.h"

/**
 *  Behavior is up to customizers of the KMS Agent reference implementation. 
 *  A possible usage of this function is to encrypt the plaintext 
 *  key value.  This function will be invoked by the following KMS Agent API
 *  functions upon successful receipt of a key from a KMS transaction:
 *  <ul>
 *  <li>KMSAgent_CreateKey
 *  <li>KMSAgent_RetrieveKey
 *  <li>KMSAgent_RetrieveDataUnitKeys - once for each key retrieved
 *  <li>KMSAgent_RetrieveProtectAndProcessKey
 *  </ul>
 *
 *  @param io_pKey   a plaintext key
 *  @return 0 if success   
 */
int KMSAgentKeyCallout( unsigned char io_aKey[KMS_MAX_KEY_SIZE] );


#endif

