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

#ifndef WIN32
#include <ctype.h>

  #ifndef METAWARE
    #include <wctype.h>
  #endif

#endif

#ifndef METAWARE
  #include <sys/timeb.h>
#endif

#include "KMSAgentStringUtilities.h"

#ifdef WIN32
#include <stdlib.h>
#include <time.h>
#define gmtime_r(clock,result) ( *(result) = *gmtime(clock), result )
#endif

// Find header in KMSAgentStringUtilities.h
int64 UTF8ToInt64( const char* i_sNumber )
{
    FATAL_ASSERT( i_sNumber );

#ifdef WIN32
    return _atoi64( i_sNumber );
#else
    return atoll( i_sNumber );
#endif
}

void Int64ToUTF8(char* const o_psUTF8, 
                 int64 i_iNumber, 
                 int i_bPad, 
                 int i_bHex )
{
    //string sFormat;
    char sFormat[10];

    if ( i_bPad && i_bHex )
    {
#ifdef WIN32
        strcpy(sFormat,"%016I64X");
#else
        strcpy(sFormat,"%016llX");
#endif
    }
    else if ( i_bPad && !i_bHex )
    {
#ifdef WIN32
        strcpy(sFormat, "%019I64d");
#else
        strcpy(sFormat, "%019lld");
#endif
    }
    else if ( !i_bPad && i_bHex )
    {
#ifdef WIN32
        strcpy(sFormat, "%I64X");
#else
        strcpy(sFormat, "%llX");
#endif
    }
    else //( !i_bPad && !i_bHex )
    {
#ifdef WIN32
        strcpy(sFormat, "%I64d");
#else
        strcpy(sFormat, "%lld");
#endif
    }

#ifndef METAWARE
    int iReturn = sprintf( o_psUTF8, sFormat, i_iNumber);

    //int iReturn = K_snprintf(o_psUTF8, iBufferSize, sFormat, i_iNumber);
#else
    int iReturn = sprintf( o_psUTF8, sFormat, i_iNumber);
#endif
    if ( iReturn < 0 )
    {
        // Our buffer wasn't big enough. Shouldn't happen.
        FATAL_ASSERT(0);
    }

    return;

}

// Find header in KMSAgentStringUtilities.h
int ConvertUTF8HexStringToBinary(
            const char* i_sHexString,
            unsigned char* o_pBinaryBuffer)
{   
    int iHexLen = i_sHexString ? strlen(i_sHexString) : 0;
    FATAL_ASSERT( (iHexLen % 2) == 0 ); // to be valid, the hex string must have an even number of characters

    if ( !o_pBinaryBuffer )
    {
       return ( iHexLen / 2 );
    }

    if ( iHexLen <= 0 )
    {
        return 0;
    }

    int iDigitValue = 0;

    for ( int i = 0; i < iHexLen; i++)
    {
        if (i_sHexString[i] >= '0' && i_sHexString[i] <= '9')
        {
            iDigitValue = i_sHexString[i] - '0';
        }
        else if (i_sHexString[i] >= 'A' && i_sHexString[i] <= 'F')
        {
            iDigitValue = i_sHexString[i] - 'A' + 10;
        }
        else if (i_sHexString[i] >= 'a' && i_sHexString[i] <= 'f')
        {
            iDigitValue = i_sHexString[i] - 'a' + 10;
        }
        else
        {
            iDigitValue = 0;
        }

        if (i % 2 == 0)
        {
            o_pBinaryBuffer[i/2] = (char)(iDigitValue << 4);
        }
        else
        {
            o_pBinaryBuffer[i/2] |= (char)iDigitValue;
        }
    }

    return ( iHexLen / 2 );
}

// Find header in KMSAgentStringUtilities.h
void ConvertBinaryToUTF8HexString(
                             char* const                o_sHexString, 
                             const unsigned char* const i_pBinaryBuffer, 
                             int                        i_iBinaryBufferSize )
{
    const char HEXCHARS[] = "0123456789ABCDEF";

    FATAL_ASSERT( o_sHexString );

    if ( (i_pBinaryBuffer == 0) || (i_iBinaryBufferSize == 0) )
    {
        strcpy(o_sHexString, "");
        return;
    }
    
    FATAL_ASSERT( i_pBinaryBuffer );
    
    for ( int i = 0; i < (2 * i_iBinaryBufferSize); i++ ) 
    {
        unsigned char ucFourBits = i_pBinaryBuffer[i / 2];
        if ( (i % 2) == 0 ) // high four bits of the current byte
            ucFourBits = (ucFourBits >> 4) & 0xF; // shift down and blank out upper bits
        else                // low four bits of the current byte
            ucFourBits = ucFourBits & 0xF; // blank out upper bits

        o_sHexString[i] = HEXCHARS[ucFourBits];
    }

    o_sHexString[i_iBinaryBufferSize * 2] = '\0';

    return;
}


// Find header in StringUtilities.h
void GetCurrentDateTimeISO8601UTC(char* const o_psDateTimeISO8601UTC,
                                  int i_iLength)
{

#ifndef METAWARE
    timeb stTime;
    ftime(&stTime);

    FATAL_ASSERT( o_psDateTimeISO8601UTC );

    struct tm* pstTime = gmtime( &(stTime.time) );

    K_snprintf( 
        o_psDateTimeISO8601UTC, 
        i_iLength,
        "%04d-%02d-%02d %02d:%02d:%02d.%03dZ",
        pstTime->tm_year+1900,
        pstTime->tm_mon+1,
        pstTime->tm_mday,
        pstTime->tm_hour,
        pstTime->tm_min,
        pstTime->tm_sec,
        stTime.millitm);

#else
    // no time functions for the metaware environment
    strcpy( o_psDateTimeISO8601UTC, "" );
#endif
    return;
}

