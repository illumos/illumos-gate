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

#ifndef _LMS_IF_COMPAT_H_
#define _LMS_IF_COMPAT_H_

#include "types.h"

// disable the "zero-sized array" warning in Visual C++
#ifdef _MSC_VER
#pragma warning(disable:4200)
#endif

#pragma pack(1)

typedef enum {
	LMS_MESSAGE_TYPE_OPEN_CONNECTION       = 0x01,
	LMS_MESSAGE_TYPE_OPEN_CONNECTION_REPLY = 0x02,
	LMS_MESSAGE_TYPE_CLOSE_CONNECTION      = 0x03,
	LMS_MESSAGE_TYPE_SEND_DATA             = 0x04,
	LMS_MESSAGE_TYPE_IP_FQDN_REQUEST       = 0x05,
	LMS_MESSAGE_TYPE_IP_FQDN               = 0x06,
	LMS_MESSAGE_TYPE_PROTO_VERSION         = 0x07,
	LMS_MESSAGE_TYPE_PROTO_VERSION_REPLY   = 0x08,
	LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX    = 0x0a
} LMS_MESSAGE_TYPE;

typedef enum {
	LMS_PROTOCOL_TYPE_TCP_IPV4 = 0x00,
	LMS_PROTOCOL_TYPE_UDP_IPV4 = 0x01,
	LMS_PROTOCOL_TYPE_TCP_IPV6 = 0x02,
	LMS_PROTOCOL_TYPE_UDP_IPV6 = 0x03
} LMS_PROTOCOL_TYPE;

typedef enum {
	LMS_CONNECTION_STATUS_OK       = 0x00,
	LMS_CONNECTION_STATUS_FAILED   = 0x01,
	LMS_CONNECTION_STATUS_TOO_MANY = 0x02
} LMS_CONNECTION_STATUS;

typedef enum {
	LMS_CLOSE_STATUS_CLIENT   = 0x00,
	LMS_CLOSE_STATUS_INTERNAL = 0x01,
	LMS_CLOSE_STATUS_SOCKET   = 0x02,
	LMS_CLOSE_STATUS_SHUTDOWN = 0x03
} LMS_CLOSE_STATUS;

typedef enum {
	LMS_IP_ADDRESS_SHARED    = 0x00,
	LMS_IP_ADDRESS_DUAL_IPV4 = 0x01,
	LMS_IP_ADDRESS_DUAL_IPV6 = 0x02
} LMS_IP_ADDRESS_TYPE;

typedef enum {
	LMS_PROTOCOL_STATUS_OK              = 0x00,
	LMS_PROTOCOL_STATUS_PROPOSE_ANOTHER = 0x01
} LMS_PROTOCOL_STATUS;

/**
 * LMS_OPEN_CONNECTION_MESSAGE - open connection request
 *
 * @MessageType: LMS_MESSAGE_TYPE_OPEN_CONNECTION
 * @ConnectionId: 0 if sent from LMS, positive if sent from LME
 * @Protocol: One of LMS_PROTOCOL_TYPE
 * @OpenRequestId: Any number; used to match the request to the response
 * @HostIPAddress: Source IP address of the initiating application, in network
 *                 order (Big Endian). If IPv4, only the first 4 bytes are used
 *                 and the rest must be 0.
 * @HostPort: Source port of the initiating application, in network order (Big
 *            Endian).
 * @MEPort: Destination port of the initiating application, in network order
 *          (Big Endian).
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 Protocol;
	UINT8 OpenRequestId;
	UINT8 HostIPAddress[16];
	UINT16 HostPort;
	UINT16 MEPort;
} LMS_OPEN_CONNECTION_MESSAGE;

/**
 * LMS_OPEN_CONNECTION_REPLY_MESSAGE - open connection reply
 *
 * @MessageType: LMS_MESSAGE_TYPE_OPEN_CONNECTION_REPLY
 * @ConnectionId: Assigned by LME
 * @Status: One of LMS_CONNECTION_STATUS
 * @OpenRequestId: The same as the OpenRequestID value in the open connection
 *                 request message.
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 Status;
	UINT8 OpenRequestId;
} LMS_OPEN_CONNECTION_REPLY_MESSAGE;

/**
 * LMS_OPEN_CONNECTION_EX_MESSAGE - open connection request
 *
 * @MessageType: LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX
 * @ConnectionId: Unique identifier
 * @Protocol: One of LMS_PROTOCOL_TYPE
 * @Flags: If first bit is set then Host is an hostname, otherwise Host is an IP address.
 *         If second bit is set then connection is from remote console, otherwise
 *         it is from local application. The other bits must be zero.
 * @Reserved: Must be zero
 * @OpenRequestId: Any number; used to match the request to the response
 * @Host: Source IP address of the initiating application, in network
 *                 order (Big Endian). If IPv4, only the first 4 bytes are used
 *                 and the rest must be 0. 
 * @HostPort: Source port of the initiating application, in network order (Big
 *            Endian).
 * @MEPort: Destination port of the initiating application, in network order
 *          (Big Endian).
 */

#define HOSTNAME_BIT 0x1
#define REMOTE_BIT 0x2

#define FQDN_MAX_SIZE 256

typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 Protocol;
	UINT8 Flags;
	UINT32 Reserved;
	UINT8 OpenRequestId;
	UINT8 Host[FQDN_MAX_SIZE];
	UINT16 HostPort;
	UINT16 MEPort;
} LMS_OPEN_CONNECTION_EX_MESSAGE;

///**
// * LMS_OPEN_CONNECTION_EX_REPLY_MESSAGE - open connection reply
// *
// * @MessageType: LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX_REPLY
// * @ConnectionId: Should match value in connection request
// * @Status: One of LMS_CONNECTION_STATUS
// * @OpenRequestId: The same as the OpenRequestID value in the open connection
// *                 request message.
// */
//typedef struct {
//	UINT8 MessageType;
//	UINT8 ConnectionId;
//	UINT8 Status;
//	UINT8 OpenRequestId;
//} LMS_OPEN_CONNECTION_EX_REPLY_MESSAGE;

/**
 * LMS_CLOSE_CONNECTION_MESSAGE - close connection request
 *
 * @MessageType: LMS_MESSAGE_TYPE_CLOSE_CONNECTION
 * @ConnectionId: The connection ID chosen by the LME when the connection
 *                was established.
 * @ClosingReason: One of LMS_CLOSE_STATUS
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 ClosingReason;
} LMS_CLOSE_CONNECTION_MESSAGE;

/**
 * LMS_SEND_DATA_MESSAGE - sends data betwen LMS and LME
 *
 * @MessageType: LMS_MESSAGE_TYPE_SEND_DATA
 * @ConnectionId: The connection ID chosen by the LME when the connection
 *                was established.
 * @DataLength: Length of data field, in Big Endian.
 * @Data: The data to transfer
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT16 DataLength;
	UINT8 Data[0];
} LMS_SEND_DATA_MESSAGE;

/**
 * LMS_IP_FQDN_REQUEST_MESSAGE - Requests IP/FQDN data
 *
 * @MessageType: LMS_MESSAGE_TYPE_IP_FQDN_REQUEST
 * @ConnectionId: Must be 0.
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
} LMS_IP_FQDN_REQUEST_MESSAGE;

/**
 * LMS_IP_FQDN_MESSAGE - sends IP/FQDN info
 *
 * @MessageType: LMS_MESSAGE_TYPE_IP_FQDN
 * @ConnectionId: Must be 0.
 * @IPType: One of LMS_IP_ADDRESS_TYPE.
 * @Reserved: Must be 0.
 * @AMTIPAddress: The Intel(R) AMT IP address, in network order (Big Endian).
 *                If IPv4, then only the first 4 bytes are used and the rest
 *                must be 0.
 * @FQDN: A NUL terminated string specifying the Fully Qualified Domain Name.
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 IPType;
	UINT8 Reserved;
	UINT8 AMTIPAddress[16];
	UINT8 FQDN[FQDN_MAX_SIZE];
} LMS_IP_FQDN_MESSAGE;

/**
 * LMS_PROTO_VERSION_MESSAGE - sends protocol version information
 *
 * @MessageType: LMS_MESSAGE_TYPE_PROTO_VERSION
 * @ConnectionId: Must be 0.
 * @Protocol: Protocol version.
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 Protocol;
} LMS_PROTO_VERSION_MESSAGE;

/**
 * LMS_PROTO_VERSION_REPLY_MESSAGE - sends protocol version information
 *
 * @MessageType: LMS_MESSAGE_TYPE_PROTO_VERSION_REPLY
 * @ConnectionId: Must be 0.
 * @Protocol: Protocol version.
 * @Status: One of LMS_PROTOCOL_STATUS.
 */
typedef struct {
	UINT8 MessageType;
	UINT8 ConnectionId;
	UINT8 Protocol;
	UINT8 Status;
} LMS_PROTO_VERSION_REPLY_MESSAGE;

#pragma pack()

#endif

