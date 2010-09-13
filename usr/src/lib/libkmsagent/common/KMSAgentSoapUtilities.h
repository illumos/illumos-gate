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
 * \file KMSAgentSoapUtilities.h
 */

#ifndef KMSAgentSoapUtilities_h
#define KMSAgentSoapUtilities_h

/**
 *  maximum length of a network IP address 
 */
static const int g_iMAX_PEER_NETWORK_ADDRESS_LENGTH = 50;

/**
 *  maximum length of a soap fault message string 
 */
static const int g_iMAX_SOAP_FAULT_MESSAGE_LENGTH = 256;

//BEN CHANGE - removed predeclaration of struct soap
// need the real declaration
//struct soap;

/**
 *  copies at most g_iMAX_PEER_NETWORK_ADDRESS_LENGTH characters
 *  from the peer's network address from the soap runtime context.
 *  <code>o_psPeerNetworkAddress</code> should be at least 
 *  <code>g_iMAX_PEER_NETWORK_ADDRESS_LENGTH</code> in length.
 */
void GetPeerNetworkAddress( char* const  o_psPeerNetworkAddress,
                            struct soap* i_pSoap );

/**
 *  creates a soap fault message and stores it in o_psFaultMessage.  The fault message
 *  has the form:  " SoapFaultCode=%s SoapFaultString=%s SoapFaultDetail=%s" with the
 *  appropriate values substitued for %s from the soap runtime.
 *  @param o_psFaultMessage a buffer for the fault message that is at least 
 *  <code>g_iMAX_SOAP_FAULT_MESSAGE_LENGTH</code> in size.
 *  @param i_pstSoap the soap runtime context to process for fault information
 */
// BEN - removed const
void GetSoapFault(char* o_psFaultMessage, 
                  struct soap *i_pstSoap);

bool PutBinaryIntoSoapBinary(
        struct soap* i_pSoap,
        const unsigned char* i_pBinary,
        int i_iBinarySize,
        unsigned char*& o_pSoapBinary,
        int& o_iSoapBinarySize );

#endif //KMSAgentSoapUtilities_h
