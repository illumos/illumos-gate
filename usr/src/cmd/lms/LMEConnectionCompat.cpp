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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cerrno>
#include "types.h"
#include "LMEConnection.h"
#include "LMS_if_compat.h"
#include "Lock.h"
#include "glue.h"

#ifdef _LINUX
#define _strnicmp strncasecmp
#endif

extern glue plugin;

const GUID LMEConnection::_guidCompat = {0x3d98d9b7, 0x1ce8, 0x4252, {0xb3, 0x37, 0x2e, 0xff, 0x10, 0x6e, 0xf2, 0x9f}};

int LMEConnection::CompatSendMessage(UINT8 connID, UINT32 len, unsigned char *buffer)
{
	if (!IsInitialized()) {
		PRINT("[Compat]State: not connected to HECI.\n");
		return -1;
	}

	unsigned char sendBuf[1024 + sizeof(LMS_SEND_DATA_MESSAGE)];
	LMS_SEND_DATA_MESSAGE *msg;

	if (len > 1024) {
		return -1;
	}

	msg = (LMS_SEND_DATA_MESSAGE *)sendBuf;
	msg->MessageType = LMS_MESSAGE_TYPE_SEND_DATA;
	msg->ConnectionId = connID;
	msg->DataLength = htons(len);
	memcpy(msg->Data, buffer, len);

	return _sendMessage(sendBuf, sizeof(LMS_SEND_DATA_MESSAGE) + len);
}

void LMEConnection::CompatCloseConnection(int connID, int status)
{
	if (!IsInitialized()) {
		PRINT("[Compat]State: not connected to HECI.\n");
		return;
	}

	LMS_CLOSE_CONNECTION_MESSAGE msg;

	msg.MessageType = LMS_MESSAGE_TYPE_CLOSE_CONNECTION;
	msg.ConnectionId = connID;
	msg.ClosingReason = status;

	_sendMessage((unsigned char *)&msg, sizeof(msg));
}

bool LMEConnection::CompatProtocolVersion()
{
	if (!IsInitialized()) {
		PRINT("[Compat]State: not connected to HECI.\n");
		return false;
	}

	LMS_PROTO_VERSION_MESSAGE msg;

	memset(&msg, 0, sizeof(msg));
	msg.MessageType = LMS_MESSAGE_TYPE_PROTO_VERSION;
	msg.ConnectionId = 0;
	msg.Protocol = 0;

	PRINT("[Compat]Sending Protocol Version to LME\n");
	int bytesWritten = _sendMessage((unsigned char *)&msg, sizeof(msg));
	return (bytesWritten == sizeof(msg));
}

bool LMEConnection::CompatRequestIPFQDN()
{
	if (!IsInitialized()) {
		PRINT("[Compat]State: not connected to HECI.\n");
		return false;
	}

	LMS_IP_FQDN_REQUEST_MESSAGE msg;

	memset(&msg, 0, sizeof(msg));
	msg.MessageType = LMS_MESSAGE_TYPE_IP_FQDN_REQUEST;
	msg.ConnectionId = 0;

	PRINT("[Compat]Sending IP_FQDN request to LME\n");
	int bytesWritten = _sendMessage((unsigned char *)&msg, sizeof(msg));
	return (bytesWritten == sizeof(msg));
}

bool LMEConnection::CompatOpenConnection(in_port_t mePort, ATAddress addr, unsigned int &connID)
{
	if (!IsInitialized()) {
		PRINT("[Compat]State: not connected to HECI.\n");
		return false;
	}

	unsigned char currReqID = _reqID++;
	bool ret = false;
	LMS_OPEN_CONNECTION_EX_MESSAGE openConnectionExMsg;
	LMS_OPEN_CONNECTION_MESSAGE openConnectionMsg;
	unsigned char *msg = NULL;
	int msgLen = 0;
	size_t addrSize = 0;
	const void *inAddr = addr.inAddr(addrSize);

	if (protocolVer == LMS_PROCOL_VERSION_COMPAT) {
		memset(&openConnectionExMsg, 0, sizeof(openConnectionExMsg));
		openConnectionExMsg.MessageType = LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX;
		openConnectionExMsg.ConnectionId = 0;
		openConnectionExMsg.Protocol = LMS_PROTOCOL_TYPE_TCP_IPV4;
		openConnectionExMsg.Flags = 0;
		openConnectionExMsg.OpenRequestId = currReqID;
		memcpy(openConnectionExMsg.Host, inAddr, addrSize);
		openConnectionExMsg.HostPort = htons(addr.inPort());
		openConnectionExMsg.MEPort = htons(mePort);

		msg = (unsigned char *)&openConnectionExMsg;
		msgLen = sizeof(openConnectionExMsg);
		PRINT("[Compat]OpenConnectionEx %x (%d) p=%d mp=%d\n",
			*(int *)inAddr, addrSize, addr.inPort(), mePort);
	}
	else {
		memset(&openConnectionMsg, 0, sizeof(openConnectionMsg));
		openConnectionMsg.MessageType = LMS_MESSAGE_TYPE_OPEN_CONNECTION;
		openConnectionMsg.ConnectionId = 0;
		openConnectionMsg.Protocol = LMS_PROTOCOL_TYPE_TCP_IPV4;
		openConnectionMsg.OpenRequestId = currReqID;
		memcpy(openConnectionMsg.HostIPAddress, inAddr, addrSize);
		openConnectionMsg.HostPort = htons(addr.inPort());
		openConnectionMsg.MEPort = htons(mePort);

		msg = (unsigned char *)&openConnectionMsg;
		msgLen = sizeof(openConnectionMsg);
		PRINT("[Compat]OpenConnection %x (%d) p=%d mp=%d\n",
			*(int *)inAddr, addrSize, addr.inPort(), mePort);
	}

	// save as pending request
	CompatConnection conn;
	conn.event = new Event();
	conn.status = LMS_CONNECTION_STATUS_FAILED;
	conn.connID = 0;

	_compatMapLock.acquire();
	_compatPendingConnections[currReqID] = conn;
	_compatMapLock.release();

	int bytesWritten;
	bytesWritten = _sendMessage(msg, msgLen);
	if (bytesWritten != msgLen) {
		goto out;
	}

	if (conn.event->wait(10000) == false) {
		// no response from FW
		goto out;
	}

	ret = true;

out:
	{
		Lock ml(_compatMapLock);

		if (_compatPendingConnections[currReqID].status != LMS_CONNECTION_STATUS_OK) {
			ret = false;
		} else {
			connID = _compatPendingConnections[currReqID].connID;
		}
		_compatPendingConnections.erase(currReqID);
	}

	delete conn.event;
	conn.event = NULL;

	return ret;
}

void LMEConnection::_doRXCompat()
{
	unsigned int bytesRead;
	int status = 1;

	_threadStartedEvent.set();

	unsigned char *rxBuffer = new unsigned char[_heciCompat.GetBufferSize()];

	while (true) {
		bytesRead = (unsigned int)_receiveMessage(rxBuffer, _heciCompat.GetBufferSize());

		if ((int)bytesRead < 0) {
			PRINT("[Compat]Error receiving data from HECI\n");
			Deinit();
			break;
		}

		if (bytesRead == 0) {
			// ERROR
			continue;
		}

		PRINT("[Compat]Received from LME %d bytes (msg type %02d)\n", bytesRead, rxBuffer[0]);

		if (bytesRead < 2) {
			// ERROR
			continue;
		}

		if (plugin.preprocess(rxBuffer, bytesRead) == LMS_DROPPED) {
			continue;
		}

		switch (rxBuffer[0]) {
		case LMS_MESSAGE_TYPE_PROTO_VERSION_REPLY:
			CompatRequestIPFQDN();
			break;

		case LMS_MESSAGE_TYPE_CLOSE_CONNECTION: 
		case LMS_MESSAGE_TYPE_SEND_DATA:
		case LMS_MESSAGE_TYPE_IP_FQDN:
			_cb(_cbParam, rxBuffer, bytesRead, &status);
			break;

		case LMS_MESSAGE_TYPE_OPEN_CONNECTION_REPLY:
			{
				LMS_OPEN_CONNECTION_REPLY_MESSAGE *repMsg =
				    (LMS_OPEN_CONNECTION_REPLY_MESSAGE *)rxBuffer;

				Lock ml(_compatMapLock);

				CompatConnMap::iterator itr;
				itr = _compatPendingConnections.find(repMsg->OpenRequestId);
				if (itr != _compatPendingConnections.end()) {
					(*itr).second.connID = repMsg->ConnectionId;
					(*itr).second.status = repMsg->Status;
					(*itr).second.event->set();
					PRINT("[Compat]Open connection reply %d %d =%d\n", repMsg->OpenRequestId, repMsg->ConnectionId, repMsg->Status);
				}
			}
			break;

		case LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX:
			{
				// report incoming connection request
				_cb(_cbParam, rxBuffer, bytesRead, &status);

				if (IsInitialized() && (status == 1)) {
					if (plugin.retry(rxBuffer, bytesRead) == LMS_DROPPED) {
						continue;
					} else {
						_cb(_cbParam, rxBuffer, bytesRead, &status);
					}
				}

				LMS_OPEN_CONNECTION_EX_MESSAGE *msg =
				    (LMS_OPEN_CONNECTION_EX_MESSAGE *)rxBuffer;

				if ((msg->Flags & HOSTNAME_BIT) != 0) {
					PRINT("[Compat]Got client connection request %d for host %s, port %d\n",
						msg->ConnectionId, msg->Host, ntohs(msg->HostPort));
				}
				else {
					PRINT("[Compat]Got client connection request %d for IP %s, port %d\n",
						msg->ConnectionId, inet_ntoa(*((struct in_addr *)msg->Host)), ntohs(msg->HostPort));
				}

				LMS_OPEN_CONNECTION_REPLY_MESSAGE repMsg;
				memset(&repMsg, 0, sizeof(repMsg));

				repMsg.MessageType = LMS_MESSAGE_TYPE_OPEN_CONNECTION_REPLY;
				repMsg.ConnectionId = msg->ConnectionId;
				if (status == 0) {
					repMsg.Status = LMS_CONNECTION_STATUS_OK;
				} else {
					repMsg.Status = LMS_CONNECTION_STATUS_FAILED;
				}

				DWORD bytesWritten;
				bytesWritten = _sendMessage((unsigned char *)&repMsg, sizeof(repMsg));
				if (bytesWritten != sizeof(repMsg)) {
					PRINT("[Compat]Send Open Connection Reply failed: bytesWritten: %lu\n", bytesWritten);
				}
			}
			break;

		default:
			// Uknown request. Ignore
			break;
		}

		if (IsInitialized()) {
			plugin.postprocess(rxBuffer, bytesRead, status);
		}
	}

	if (rxBuffer != NULL) {
		delete[] rxBuffer;
	}
}

