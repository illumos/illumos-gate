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

/** @file             KMSAgent.h 
 *  @defgroup         EncryptionAgent Encryption Agent API
 *
 * The Agent API is used to communicate with the KMS Appliance for the
 * purpose of registering storage devices, obtaining device keys, and
 * receiving notifications of storage device events such as destruction.
 *
 */
#ifndef KMS_AGENT_KNOWN_ANSWER_TESTS_H
#define KMS_AGENT_KNOWN_ANSWER_TESTS_H

/**
 *  This function exercises both <code>aes_key_wrap</code> and <code>aes_key_unwrap</code>
 *  in order to satisfy a FIPS 140-2 requirement for a known answer test, aka KAT.  Test
 *  vectors from RFC 3394 are used for this test.
 *  @return 0 on success, non-zero otherwise
 */
int KnownAnswerTestAESKeyWrap(void);
    
/**
 *  This function exercises both <code>rijndael_encrypt</code> and <code>rijndael_decrypt</code>
 *  in order to satisfy a FIPS 140-2 requirement for a known answer test, aka KAT.  Test
 *  vectors from Infoguard are used for this test.
 *  @return 0 if KAT passed, non-zero otherwise
 */
int KnownAnswerTestAESECB(void);

/**
 *  This function exercises  #HMACBuffers
 *  in order to satisfy a FIPS 140-2 requirement for a known answer test, aka KAT.  Test
 *  vectors from Infoguard are used for this test.
 *  @return 0 if KAT passed, non-zero otherwise
 */
int KnownAnswerTestHMACSHA1(void);

#endif


