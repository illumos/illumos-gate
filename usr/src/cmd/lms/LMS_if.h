/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef _LMS_IF_H_
#define _LMS_IF_H_

#include "types.h"
#include "LMS_if_constants.h"

// disable the "zero-sized array" warning in Visual C++
#ifdef _MSC_VER
#pragma warning(disable:4200)
#endif

#pragma pack(1)

typedef struct {
	UINT8  MessageType;
} APF_MESSAGE_HEADER;


/**
 * APF_GENERIC_HEADER - generic request header (note that its not complete header per protocol (missing WantReply)
 *
 * @MessageType:
 * @RequestStringLength: length of the string identifies the request
 * @RequestString: the string that identifies the request
 **/

typedef struct {
	UINT8  MessageType;
	UINT32 StringLength;
	UINT8  String[0];
} APF_GENERIC_HEADER;

/**
 * TCP forward reply message
 * @MessageType - Protocol's Major version
 * @PortBound - the TCP port was bound on the server
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 PortBound;
} APF_TCP_FORWARD_REPLY_MESSAGE;

/**
 * response to ChannelOpen when channel open succeed
 * @MessageType - APF_CHANNEL_OPEN_CONFIRMATION
 * @RecipientChannel - channel number given in the open request
 * @SenderChannel - channel number assigned by the sender
 * @InitialWindowSize - Number of bytes in the window
 * @Reserved - Reserved
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 RecipientChannel;
	UINT32 SenderChannel;
	UINT32 InitialWindowSize;
	UINT32 Reserved;
} APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE;

/**
 * response to ChannelOpen when a channel open failed
 * @MessageType - APF_CHANNEL_OPEN_FAILURE
 * @RecipientChannel - channel number given in the open request
 * @ReasonCode - code for the reason channel could not be open
 * @Reserved - Reserved
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 RecipientChannel;
	UINT32 ReasonCode;
	UINT32 Reserved;
	UINT32 Reserved2;
} APF_CHANNEL_OPEN_FAILURE_MESSAGE;

/**
 * close channel message
 * @MessageType - APF_CHANNEL_CLOSE
 * @RecipientChannel - channel number given in the open request
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 RecipientChannel;
} APF_CHANNEL_CLOSE_MESSAGE;

/**
 * used to send/receive data.
 * @MessageType - APF_CHANNEL_DATA
 * @RecipientChannel - channel number given in the open request
 * @Length - Length of the data in the message
 * @Data - The data in the message
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 RecipientChannel;
	UINT32 DataLength;
	UINT8  Data[0];
} APF_CHANNEL_DATA_MESSAGE;

/**
 * used to adjust receive window size.
 * @MessageType - APF_WINDOW_ADJUST
 * @RecipientChannel - channel number given in the open request
 * @BytesToAdd - number of bytes to add to current window size value
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 RecipientChannel;
	UINT32 BytesToAdd;
} APF_WINDOW_ADJUST_MESSAGE;

/**
 * This message causes immediate termination of the connection with AMT.
 * @ReasonCode -  A Reason code for the disconnection event
 * @Reserved - Reserved must be set to 0
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 ReasonCode;
	UINT16 Reserved;
} APF_DISCONNECT_MESSAGE;

/**
 * Used to request a service identified by name
 * @ServiceNameLength -  The length of the service name string.
 * @ServiceName - The name of the service being requested.
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 ServiceNameLength;
	UINT8  ServiceName[0];
} APF_SERVICE_REQUEST_MESSAGE;

/**
 * Used to send a service accept identified by name
 * @ServiceNameLength -  The length of the service name string.
 * @ServiceName - The name of the service being requested.
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 ServiceNameLength;
	UINT8  ServiceName[0];
} APF_SERVICE_ACCEPT_MESSAGE;

/**
 * holds the protocl major and minor version implemented by AMT.
 * @MajorVersion - Protocol's Major version
 * @MinorVersion - Protocol's Minor version
 * @Trigger - The open session reason
 * @UUID - System Id
 **/
typedef struct {
	UINT8  MessageType;
	UINT32 MajorVersion;
	UINT32 MinorVersion;
	UINT32 TriggerReason;
	UINT8  UUID[16];
	UINT8  Reserved[64];
} APF_PROTOCOL_VERSION_MESSAGE;

/**
 * holds the user authentication request.
 * @UsernameLength - The length of the user name string.
 * @Username - The name of the user in ASCII encoding.
 *             Maximum allowed size is 64 bytes.
 * @ServiceNameLength - The length of the service name string.
 * @ServiceName - The name of the service to authorize.
 * @MethodNameLength - The length of the method name string.
 * @MethodName - The authentication method to use.
 **/
//typedef struct {
//	UINT8  MessageType;
//	UINT32 UsernameLength;
//	UINT8  Username[0];
//	UINT32 ServiceNameLength;
//	UINT8  ServiceName[0];
//	UINT32 MethodNameLength;
//	UINT8  MethodName[0];
//} APF_USERAUTH_REQUEST_MESSAGE;

/**
 * holds the user authentication request failure reponse.
 * @MethodNameListLength - The length of the methods list string.
 * @MethodNameList - A comma seperated string of authentication
 *			methods supported by the server in ASCII.
 **/
//typedef struct {
//	UINT8  MessageType;
//	UINT32 MethodNameListLength;
//	UINT8  MethodNameList[0];
//	UINT8  Reserved;
//} APF_USERAUTH_FAILURE_MESSAGE;

/**
 * holds the user authentication request success reponse.
 **/
typedef struct {
	UINT8  MessageType;
} APF_USERAUTH_SUCCESS_MESSAGE;

#pragma pack()

#endif

