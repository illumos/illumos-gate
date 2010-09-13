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

#if defined(__sun) || defined(_LINUX)
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif	// __sun || _LINUX

#include <cerrno>
#include "Protocol.h"
#include "LMS_if_compat.h"
#include "Lock.h"
#include "ATNetworkTool.h"

void Protocol::_LmeReceiveCompat(char *buffer, unsigned int len, int *status)
{
	int error = 0;

	PRINT("[Compat]HECI receive %d bytes (msg type 0x%02x)\n", len, buffer[0]);
	*status = 0;

	switch (buffer[0]) {
	case LMS_MESSAGE_TYPE_OPEN_CONNECTION_EX:
		{
			SOCKET s_new = INVALID_SOCKET;
			LMS_OPEN_CONNECTION_EX_MESSAGE *msg =
			    (LMS_OPEN_CONNECTION_EX_MESSAGE *)buffer;

			int type;
			switch (msg->Protocol) {
			case LMS_PROTOCOL_TYPE_UDP_IPV4:
				type = SOCK_DGRAM;
				break;
			case LMS_PROTOCOL_TYPE_TCP_IPV4:
			default:
				type = SOCK_STREAM;
				break;
			}

			if ((msg->Flags & HOSTNAME_BIT) != 0) {
				PRINT("[Compat]Got client connection request %d for host %s, port %d\n",
					msg->ConnectionId,
					msg->Host,
					ntohs(msg->HostPort));

				s_new = ATNetworkTool::Connect(
					(const char *)msg->Host,
					ntohs(msg->HostPort),
					error, PF_INET, type);
			} else {
				PRINT("[Compat]Got client connection request %d for IP %s, port %d\n",
					msg->ConnectionId,
					inet_ntoa(*((struct in_addr *)msg->Host)),
					ntohs(msg->HostPort));

				s_new = ATNetworkTool::Connect(
					inet_ntoa(*((struct in_addr *)msg->Host)),
					ntohs(msg->HostPort),
					error, PF_INET, type);
			}

			if (s_new == INVALID_SOCKET) {
				*status = 1;
				break;
			}

			Channel *c = new Channel(NULL, s_new);
			c->SetRecipientChannel(msg->ConnectionId);
			c->SetStatus(Channel::OPEN);
			c->AddBytesTxWindow(1024);
			{
				Lock l(_channelsLock);
				_openChannels[msg->ConnectionId] = c;
			}

			_signalSelect();
		}
		break;

	case LMS_MESSAGE_TYPE_CLOSE_CONNECTION:
		{
			LMS_CLOSE_CONNECTION_MESSAGE *msg =
			    (LMS_CLOSE_CONNECTION_MESSAGE *)buffer;

			PRINT("[Compat]received close connection msg from HECI for connection %d\n", msg->ConnectionId);

			Lock l(_channelsLock);

			ChannelMap::iterator it = _openChannels.find(msg->ConnectionId);
			if (it != _openChannels.end()) {
				_closeMChannel(it->second);
				_openChannels.erase(it);
			}
		}
		break;

	case LMS_MESSAGE_TYPE_SEND_DATA:
		{
			LMS_SEND_DATA_MESSAGE *msg =
			    (LMS_SEND_DATA_MESSAGE *)buffer;

			Lock l(_channelsLock);

			ChannelMap::iterator it = _openChannels.find(msg->ConnectionId);
			if (it != _openChannels.end()) {
				PRINT("[Compat]sending %d bytes from HECI connection %d to socket %d\n", ntohs(msg->DataLength), msg->ConnectionId, it->second->GetSocket());
				if (-1 == _send(it->second->GetSocket(), (char *)msg->Data, ntohs(msg->DataLength), error)) {
					if (EPIPE == error) {
						_closeMChannel(it->second);
						_openChannels.erase(it);
						*status = 1;
					}
				}
			}
		}
		break;

	case LMS_MESSAGE_TYPE_IP_FQDN:
		if (_updateIPFQDN((const char *)((LMS_IP_FQDN_MESSAGE *)buffer)->FQDN) != 0) {
			ERROR("[Compat]Error: failed to update IP/FQDN info\n");
		}
		break;

	default:
		*status = 1;
		break;
	}
}

