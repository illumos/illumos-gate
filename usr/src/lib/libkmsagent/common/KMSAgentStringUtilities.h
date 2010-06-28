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
 * @file KMSAgentStringUtilities.h
 */

#ifndef KMSAgentStringUtilities_h
#define KMSAgentStringUtilities_h

#ifdef WIN32
#pragma warning(disable: 4786)
#endif

#include <stdio.h>

#include "SYSCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Functions for conversions between integers and strings.
//

/*---------------------------------------------------------------------------*/
/**
 *  Converts a UTF8 string to an int64.
 *
 *  @param   i_sNumber: A string representation of the number to convert.
 *  @return  The integer the input string represented.
 */
/*---------------------------------------------------------------------------*/
 int64 UTF8ToInt64( const char* i_sNumber );

/**
 * Formats an int64 into a UTF8 string.
 *
 * A note on padding: If i_bPad is true, the string will be padded to the 
 * maximum size necessary to hold a an int64 representation. For decimal this 
 * is 19, for hex it is 16.
 *
 *  @param i_iNumber The number to format.
 *  @param i_bPad If true, the string will be padded with zeroes. (See note above.)
 *  @param i_bHex Indicates whether the string format should be a hexadecimal 
 *    representation of the integer (true) or a decimal representation (false).
 *  @param o_psUTF8 the string representation of the integer
 *
 *  @return  void
 */
void Int64ToUTF8(char* const o_psUTF8, 
                 int64 i_iNumber, 
                 int i_bPad, 
                 int i_bHex );

//
// Functions for converting between binary buffer and hex string
//

/*--------------------------------------------------------------------------*/
/**
 *  Converts a UTF8 hex string to its binary representation.
 *
 *  If o_pBinaryBuffer is null, the function will return the required size.
 *  (The required size is always strlen(i_sHexString)/2.)
 *
 *  @param   i_sHexString:     The hex string to convert.
 *  @param   o_pBinaryBuffer:  The buffer in which to put the binary
 *     representation of the hex string. If this is null, the function
 *     returns the required size.
 *     If this is not null, it must be large enough to hold binary conversion.
 *
 *  @return The number of bytes put into o_pBinaryBuffer (or the number of bytes
 *     required, if o_pBinaryBuffer was null).
 */
/*---------------------------------------------------------------------------*/
int ConvertUTF8HexStringToBinary(
   const char* i_sHexString,
   unsigned char* o_pBinaryBuffer);

/**
 * Converts a binary buffer to its UTF8 hex string representation.
 * 
 *  @param i_pBinaryBuffer: The binary buffer to convert.
 *  @param i_iBinaryBufferSize: The size of i_pBinaryBuffer;
 *  @param o_sHexString The hex string representation of the
 *                      binary buffer which should be at least
 *                      (i_iBinaryBufferSize * 2) + 1 characters long
 */
void ConvertBinaryToUTF8HexString(
                             char* const                o_sHexString, 
                             const unsigned char* const i_pBinaryBuffer, 
                             int                        i_iBinaryBufferSize );

//
// Functions for date strings
//

/**
 *  populates o_psDateTimeISO8601UTC with a null terminated ISO 8601
 *  formatted timestamp string from the current UTC time of the
 *  system.  The timestamp length will be restricted to i_iLength-1
 *  characters.
 */
void GetCurrentDateTimeISO8601UTC(char* const o_psDateTimeISO8601UTC,
                                  int i_iLength);

#ifdef __cplusplus
}
#endif

#endif //KMSAgentStringUtilities_h
