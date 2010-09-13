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

#ifndef _LMS_IF_CONSTANTS_H_
#define _LMS_IF_CONSTANTS_H_

#define LMS_PROCOL_VERSION 4
#define LMS_PROCOL_VERSION_COMPAT 2

//
// messages opcodes
//
typedef enum {
	APF_DISCONNECT		= 1,
	APF_SERVICE_REQUEST	= 5,
	APF_SERVICE_ACCEPT	= 6,
	APF_USERAUTH_REQUEST	= 50,
	APF_USERAUTH_FAILURE	= 51,
	APF_USERAUTH_SUCCESS	= 52,
	APF_GLOBAL_REQUEST	= 80,
	APF_REQUEST_SUCCESS	= 81,
	APF_REQUEST_FAILURE	= 82,
	APF_CHANNEL_OPEN		= 90,
	APF_CHANNEL_OPEN_CONFIRMATION	= 91,
	APF_CHANNEL_OPEN_FAILURE	= 92,
	APF_CHANNEL_WINDOW_ADJUST	= 93,
	APF_CHANNEL_DATA		= 94,
	APF_CHANNEL_CLOSE		= 97,
	APF_PROTOCOLVERSION	= 192
} APF_MESSAGE_TYPE;

typedef enum {
	APF_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT             = 1,
	APF_DISCONNECT_PROTOCOL_ERROR                          = 2,
	APF_DISCONNECT_KEY_EXCHANGE_FAILED                     = 3,
	APF_DISCONNECT_RESERVED                                = 4,
	APF_DISCONNECT_MAC_ERROR                               = 5,
	APF_DISCONNECT_COMPRESSION_ERROR                       = 6,
	APF_DISCONNECT_SERVICE_NOT_AVAILABLE                   = 7,
	APF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED          = 8,
	APF_DISCONNECT_HOST_KEY_NOT_VERIFIABLE                 = 9,
	APF_DISCONNECT_CONNECTION_LOST                        = 10,
	APF_DISCONNECT_BY_APPLICATION                         = 11,
	APF_DISCONNECT_TOO_MANY_CONNECTIONS                   = 12,
	APF_DISCONNECT_AUTH_CANCELLED_BY_USER                 = 13,
	APF_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE         = 14,
	APF_DISCONNECT_ILLEGAL_USER_NAME                      = 15
} APF_DISCONNECT_REASON_CODE;

//
//strings used in global messages
//
#define APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST "tcpip-forward"
#define APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST "cancel-tcpip-forward"
#define APF_GLOBAL_REQUEST_STR_UDP_SEND_TO "udp-send-to@amt.intel.com"
#define APF_OPEN_CHANNEL_REQUEST_FORWARDED "forwarded-tcpip"
#define APF_OPEN_CHANNEL_REQUEST_DIRECT "direct-tcpip"

// APF service names
#define APF_SERVICE_PFWD "pfwd@amt.intel.com"
#define APF_SERVICE_AUTH "auth@amt.intel.com"

// APF Authentication method
#define APF_AUTH_NONE "none"
#define APF_AUTH_PASSWORD "password"

//calculate string length without the NULL terminator
#define APF_STR_SIZE_OF(s) (sizeof(s)-1)

// Trigger reason code
typedef enum {
	USER_INITIATED_REQUEST		= 1,
	ALERT_REQUEST			= 2,
	HIT_PROVISIONING_REQUEST	= 3,
	PERIODIC_REQUEST		= 4,
	LME_REQUEST			= 254
} APF_TRIGGER_REASON;

typedef enum {
	OPEN_FAILURE_REASON_ADMINISTRATIVELY_PROHIBITED = 1,
	OPEN_FAILURE_REASON_CONNECT_FAILED = 2,
	OPEN_FAILURE_REASON_UNKNOWN_CHANNEL_TYPE = 3,
	OPEN_FAILURE_REASON_RESOURCE_SHORTAGE = 4
} OPEN_FAILURE_REASON;

#endif

