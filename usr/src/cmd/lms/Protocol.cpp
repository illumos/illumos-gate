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
#include <cerrno>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>

#define _stprintf_s snprintf
#define strnicmp strncasecmp
#else

#include <winsock2.h>
#include <iphlpapi.h>
#include <Ws2tcpip.h>
#include <tchar.h>

#endif	// __sun || _LINUX

#include <fstream>
#include <algorithm>
#include "Protocol.h"
#include "LMS_if.h"
#include "LMS_if_compat.h"
#include "Lock.h"
#include "ATNetworkTool.h"

const LMEProtocolVersionMessage Protocol::MIN_PROT_VERSION(1, 0);
const LMEProtocolVersionMessage Protocol::MAX_PROT_VERSION(1, 0);

Protocol::Protocol() :
#if DEBUGLOG
_lme(true),
#else
_lme(false),
#endif
_rxSocketBuffer(NULL),
_rxSocketBufferSize(0)
#ifdef _REMOTE_SUPPORT
, _cfg(true)
#endif
{
	_serverSignalSocket = INVALID_SOCKET;
	_clientSignalSocket = INVALID_SOCKET;
	_sockets_active = false;
	_handshakingStatus = NOT_INITIATED;
	_pfwdService = NOT_STARTED;
	_AmtProtVersion.MajorVersion = 0;
	_AmtProtVersion.MinorVersion = 0;
#ifdef _REMOTE_SUPPORT
	_remoteAccessEnabled = false;
#endif
	memset(_AMTFQDN, 0, sizeof(_AMTFQDN));
	oldProtocolMode = false;
	_deinitReq = false;
	_listenFailReported.clear();
}

Protocol::~Protocol()
{
	if (!oldProtocolMode) {
		_lme.Disconnect(APF_DISCONNECT_BY_APPLICATION);
	}
	DeinitFull();
	DestroySockets();
	_listenFailReported.clear();
}

bool Protocol::Init(EventLogCallback cb, void *param)
{
	_eventLog = cb;
	_eventLogParam = param;

	DeinitFull();

	{
		Lock dl(_deinitLock);
		_deinitReq = false;
	}

	if (!_lme.Init(_LmeCallback, this)) {
		return false;
	}

	oldProtocolMode = (LMS_PROCOL_VERSION != _lme.protocolVer);

	{
		Lock l(_versionLock);

		if (_handshakingStatus == NOT_INITIATED) {
			if (oldProtocolMode) {
				_lme.CompatProtocolVersion();
			} else {
				_lme.ProtocolVersion(MAX_PROT_VERSION);
			}
			_handshakingStatus = INITIATED;
		}
	}

	if (!oldProtocolMode) {
#ifdef _REMOTE_SUPPORT
		if (!_cfg.Init(true)) {
#else
		if (!_cfg.IsAMTEnabled(false)) {
#endif
			_lme.Deinit();
			return false;
		}
	}

	long bufSize = _lme.GetHeciBufferSize() - sizeof(APF_CHANNEL_DATA_MESSAGE);
	if (bufSize > 0) {
		_rxSocketBuffer = new char[bufSize];
		_rxSocketBufferSize = bufSize;
	} else {
		DeinitFull();
		return false;
	}

#ifdef _REMOTE_SUPPORT
	if (!oldProtocolMode) {
		_checkRemoteSupport(true);
	}
#endif
	return true;
}

Channel *Protocol::_getSockOpenChannel(SOCKET s)
{
	if (oldProtocolMode) {
		ChannelMap::iterator it = _openChannels.begin();
		for (; it != _openChannels.end(); it++) {
			if (it->second->GetSocket() == s) {
				return it->second;
			}
		}
	} else {
		ChannelMap::iterator it = _openChannels.find(s);
		if (it != _openChannels.end()) {
			return it->second;
		}
	}
	return NULL;
}

bool Protocol::IsDeInitialized()
{
	Lock dl(_deinitLock);
	return _deinitReq;
}


bool Protocol::IsInitialized()
{
	if (IsDeInitialized()) {
		return false;
	}

	return _lme.IsInitialized();
}

void Protocol::Deinit()
{
	Lock dl(_deinitLock);
	_deinitReq = true;

	ATNetworkTool::CloseSocket(_serverSignalSocket);
	ATNetworkTool::CloseSocket(_clientSignalSocket);

	{
		Lock l(_channelsLock);

		ChannelMap::iterator it = _openChannels.begin();

		for (; it != _openChannels.end(); it++) {
			ATNetworkTool::CloseSocket(it->second->GetSocket());
			delete it->second;
		}

		_openChannels.clear();
	}

	{
		Lock l(_portsLock);
		PortMap::iterator it = _openPorts.begin();

		for (; it != _openPorts.end(); it++) {
			if (it->second.size() > 0) {
				ATNetworkTool::CloseSocket(it->second[0]->GetListeningSocket());

				PortForwardRequestList::iterator it2 = it->second.begin();
				for (; it2 != it->second.end(); it2++) {
					delete *it2;
				}
			}
		}
		_openPorts.clear();
	}

	_lme.Deinit();

#ifdef _REMOTE_SUPPORT
	if (!oldProtocolMode) {
		_cfg.Deinit();
	}
#endif

	{
		Lock vl(_versionLock);
		_handshakingStatus = NOT_INITIATED;
		_pfwdService = NOT_STARTED;
		_AmtProtVersion.MajorVersion = 0;
		_AmtProtVersion.MinorVersion = 0;
	}

}

void Protocol::DeinitFull()
{
	Deinit();

	if (_rxSocketBuffer != NULL) {
		delete []_rxSocketBuffer;
		_rxSocketBuffer = NULL;
		_rxSocketBufferSize = 0;
	}

	_serverSignalSocket = INVALID_SOCKET;
	_clientSignalSocket = INVALID_SOCKET;
	_sockets_active = false;

#ifdef _REMOTE_SUPPORT
	_remoteAccessEnabled = false;
#endif
	memset(_AMTFQDN, 0, sizeof(_AMTFQDN));
}

bool Protocol::_checkListen(std::string address, in_port_t port, int &socket)
{
	bool exists = false;

	PortMap::iterator it = _openPorts.find(port);
	if (it != _openPorts.end()) {
		if (it->second.size() > 0) {
			socket = it->second[0]->GetListeningSocket();
			PortForwardRequestList::iterator it2 = it->second.begin();

			for (; it2 != it->second.end(); it2++) {
				if (((*it2)->GetStatus() != PortForwardRequest::NOT_ACTIVE) &&
				    ((*it2)->GetBindedAddress().compare(address) == 0)) {
					exists = true;
					break;
				}
			}

		}
	} else {
		PortForwardRequestList portForwardRequestList;
		_openPorts[port] = portForwardRequestList;
	}

	return exists;
}

int Protocol::_listenPort(in_port_t port, int &error)
{
	return ATNetworkTool::CreateServerSocket(
			port,
			error,
			false, true, PF_INET);
}

bool Protocol::_localListen(in_port_t port)
{
	int error;
	int socket = INVALID_SOCKET;
	bool exists = _checkListen("127.0.0.1", port, socket);

	int serverSocket = _listenPort(port, error);
	if (serverSocket == INVALID_SOCKET) {
		PRINT("[Compat]LMS Service cannot listen at port %d.\n", (int)port);
		if (exists) {
			//already listening
		}
		return false;
	}
	PRINT("[Compat]Listening at port %d at local interface.\n", (int)port);

	PortForwardRequest *portForwardRequest =
		new PortForwardRequest("127.0.0.1", port,
			serverSocket, _isLocalCallback, true);

	_openPorts[port].push_back(portForwardRequest);
	portForwardRequest->SetStatus(PortForwardRequest::LISTENING);

	return true;
}

bool Protocol::CreateSockets()
{
	int error;
	_sockets_active = false;

	ATNetworkTool::CloseSocket(_serverSignalSocket);
	_serverSignalSocket = ATNetworkTool::CreateServerSocket((in_port_t)0, error, true);
	if (_serverSignalSocket == INVALID_SOCKET) {
		return false;
	}

	ATNetworkTool::CloseSocket(_clientSignalSocket);
	_clientSignalSocket = ATNetworkTool::ConnectToSocket(_serverSignalSocket, error);
	if (_clientSignalSocket == INVALID_SOCKET) {
		ATNetworkTool::CloseSocket(_serverSignalSocket);
		_serverSignalSocket = INVALID_SOCKET;
		return false;
	}

	struct sockaddr_storage addr;
	socklen_t addrLen = sizeof(addr);
	SOCKET s_new = accept(_serverSignalSocket, (struct sockaddr *)&addr, &addrLen);
	if (s_new == INVALID_SOCKET) {
		ATNetworkTool::CloseSocket(_serverSignalSocket);
		ATNetworkTool::CloseSocket(_clientSignalSocket);
		_serverSignalSocket = INVALID_SOCKET;
		_clientSignalSocket = INVALID_SOCKET;
		return false;
	}

	ATNetworkTool::CloseSocket(_serverSignalSocket);
	_serverSignalSocket = s_new;

	if (oldProtocolMode) {
		if (!_localListen(16992)) {
			return false;
		}
		if (!_localListen(16993)) {
			return false;
		}
	}

	_sockets_active = true;
	return true;
}

void Protocol::DestroySockets()
{
	_sockets_active = false;

	if (_serverSignalSocket != INVALID_SOCKET) {
		ATNetworkTool::CloseSocket(_serverSignalSocket);
		_serverSignalSocket = INVALID_SOCKET;
	}
}

bool Protocol::_acceptConnection(SOCKET s, unsigned int port)
{
	ATAddress addr;
	int error = 0;
	char buf[NI_MAXHOST];

	if (!IsInitialized()) {
		return false;
	}

	SOCKET s_new = ATNetworkTool::Accept(s, addr, error);
	if (s_new == INVALID_SOCKET) {
#if DEBUGLOG
		char *msg = _getErrMsg(error);
		PRINT("Error accepting new connection (%d): %s\n", error, msg);
#endif
		return false;
	}

	const char *addrStr = addr.inNtoP(buf, NI_MAXHOST);
	if (addrStr == NULL) {
		PRINT("Error: ntop failed for new connection\n");
		ATNetworkTool::CloseSocket(s_new);
		return false;
	}

	PortForwardRequest *portForwardRequest = NULL;

	//_portsLock is already aquired by the calling function: Select().
	PortMap::iterator it = _openPorts.find(port);
	if (it != _openPorts.end()) {
		PortForwardRequestList::iterator it2 = it->second.begin();

		for (; it2 != it->second.end(); it2++) {
			if (((*it2)->GetStatus() == PortForwardRequest::LISTENING) &&
				(1 == (*it2)->IsConnectionPermitted(this, s_new))) {
				portForwardRequest = *it2;
				break;
			}
		}

	}

	if (portForwardRequest == NULL) {
		PRINT("Error: new connection is denied (addr %s)\n", addrStr);
		ATNetworkTool::CloseSocket(s_new);
		return false;
	}

	if (oldProtocolMode) {
		unsigned int connId;
		bool oret = _lme.CompatOpenConnection(port, addr, connId);
		if (!oret) {
			PRINT("[Compat]Error: failed to open new LME MEI connection\n");
			ATNetworkTool::CloseSocket(s_new);
			return false;
		}
		PRINT("[Compat]Send open connection to LME. Sender %d.\n", (int)s_new);

		Channel *c = new Channel(portForwardRequest, s_new);
		c->SetStatus(Channel::OPEN);
		c->SetRecipientChannel(connId);
		c->AddBytesTxWindow(1024);

		Lock l(_channelsLock);
		_openChannels[connId] = c;
		c->GetPortForwardRequest()->IncreaseChannelCount();
	} else {
		Channel *c = new Channel(portForwardRequest, s_new);
		c->SetStatus(Channel::NOT_OPENED);

		Lock l(_channelsLock);
		_openChannels[s_new] = c;
		c->GetPortForwardRequest()->IncreaseChannelCount();

		_lme.ChannelOpenForwardedRequest((UINT32)s_new,
			port,
			((portForwardRequest->IsLocal()) ? "127.0.0.1" : addrStr),
			addr.inPort());
		PRINT("Send channel open request to LME. Sender %d.\n", (int)s_new);
	}

	return true;
}

int Protocol::Select()
{
	fd_set rset;
	struct timeval tv;
	int res;
	int fdCount = 0;
	int fdMin = -1;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	FD_ZERO(&rset);

	FD_SET(_serverSignalSocket, &rset);
	if ((int)_serverSignalSocket > fdCount) {
		fdCount = (int)_serverSignalSocket;
	}

	{
		Lock l(_portsLock);
		PortMap::iterator it = _openPorts.begin();

		for (; it != _openPorts.end(); it++) {
			if (it->second.size() > 0) {
				SOCKET serverSocket = it->second[0]->GetListeningSocket();
				FD_SET(serverSocket, &rset);
				if ((int)serverSocket > fdCount) {
					fdCount = (int)serverSocket;
				}
			}
		}
	}

	{
		Lock l(_channelsLock);

		ChannelMap::iterator it = _openChannels.begin();

		for (; it != _openChannels.end(); it++) {
			if ((it->second->GetStatus() == Channel::OPEN) &&
			    (it->second->GetTxWindow() > 0)) {
				SOCKET socket = it->second->GetSocket();
				FD_SET(socket, &rset);
				if ((int)socket > fdCount) {
					fdCount = (int)socket;
				}
				if ((fdMin == -1) || ((int)socket < fdMin)) {
					fdMin = (int)socket;
				}
			}
		}
	}

	fdCount++;
	res = select(fdCount, &rset, NULL, NULL, &tv);
	if (res == -1) {
#if DEBUGLOG
#if defined(__sun) || defined(_LINUX)
		int err = errno;
#else
		int err = GetLastError();
#endif	// __sun || _LINUX

		char *msg = _getErrMsg(err);
		PRINT("Select error (%d): %s\n", err, msg);
#endif
		return -1;
	}

	if (res == 0) {
		return 0;
	}

	if (!IsInitialized()) {
		return 0;
	}

	if (FD_ISSET(_serverSignalSocket, &rset)) {	// Received a 'signal'
		char c = 0;
		res = recv(_serverSignalSocket, &c, 1, 0);
		FD_CLR(_serverSignalSocket, &rset);
		res--;
	}

	{
		Lock l(_portsLock);
		PortMap::iterator it = _openPorts.begin();

		for (; it != _openPorts.end(); it++) {
			if (it->second.size() > 0) {
				SOCKET serverSocket = it->second[0]->GetListeningSocket();
				if (FD_ISSET(serverSocket, &rset)) {
					// connection request
					PRINT("Connection requested on port %d\n", it->first);
					_acceptConnection(serverSocket, it->first);
					FD_CLR(serverSocket, &rset);
					res--;
				}
			}
		}
	}

	int i;
	for (i = fdMin/*0*/; (res > 0) && (i < fdCount); i++) {
		if (FD_ISSET(i, &rset)) {
			_rxFromSocket(i);
			res--;
		}
	}

	return 1;
}

int Protocol::_rxFromSocket(SOCKET s)
{
	Channel *c = NULL;

	if (!IsInitialized()) {
		return 0;
	}

	{
		Lock l(_channelsLock);

		Channel *cx = _getSockOpenChannel(s);

		if (cx == NULL) {
			// Data received from a socket that is not in the map.
			// Since we only select on our sockets, this means it was
			// in the map, but was removed, probably because we received
			// an End Connection message from the HECI.
			return 0;
		}

		c = new Channel(*cx);
	}

	int res = 0;

	int len = std::min(c->GetTxWindow(), _rxSocketBufferSize);
	res = recv(s, _rxSocketBuffer, len, 0);
	if (res > 0) {
		// send data to LME
		PRINT("Received %d bytes from socket %d. Sending to LME\n", res, (int)s);
		if (oldProtocolMode) {
			_lme.CompatSendMessage((UINT8)c->GetRecipientChannel(), res, (unsigned char *)_rxSocketBuffer);
		} else {
			_lme.ChannelData(c->GetRecipientChannel(), res, (unsigned char *)_rxSocketBuffer);
		}
		goto out;
	} else if (res == 0) {
		// connection closed
		PRINT("Received 0 bytes from socket %d.\n", (int)s);
		goto out;
	} else {
#if DEBUGLOG
#if defined(__sun) || defined(_LINUX)
		int err = errno;
#else
		int err = GetLastError();
#endif	// __sun || _LINUX

		char *msg = _getErrMsg(err);
		PRINT("Receive error on socket %d (%d): %s\n", (int)s, err, msg);
#endif
#ifdef __sun
		ATNetworkTool::CloseSocket(s);
#endif
		goto out;
	}

out:
	{
		Lock l(_channelsLock);

		Channel *cx = _getSockOpenChannel(s);

		if (cx == NULL) {
			// Data received from a socket that is not in the map.
			// Since we only select on our sockets, this means it was
			// in the map, but was removed, probably because we received
			// an End Connection message from the HECI.
			delete c;
			return 0;
		}
		if (res > 0) {
			if (!oldProtocolMode) {
				cx->AddBytesTxWindow(-res);
			}
		}
		else {
			cx->SetStatus(Channel::WAITING_CLOSE);
			if (oldProtocolMode) {
				if (res == 0) {
					_closeMChannel(cx);

					ChannelMap::iterator it = _openChannels.begin();
					for (; it != _openChannels.end(); it++) {
						if (it->second == cx) {
							break;
						}
					}
					if (it != _openChannels.end()) {
						_openChannels.erase(it);
					}
				}
				_lme.CompatCloseConnection(c->GetRecipientChannel(),
					((res == 0) ? LMS_CLOSE_STATUS_CLIENT :
						      LMS_CLOSE_STATUS_SOCKET));
			} else {
				_lme.ChannelClose(c->GetRecipientChannel());
			}
		}
	}
	delete c;

	return 0;
}

void Protocol::_signalSelect()
{
	int senderr = 0;

	_send(_clientSignalSocket, "s", 1, senderr); //Enforce a new execution of Select()
}

void Protocol::_closePortForwardRequest(PortForwardRequest *p)
{
	PortMap::iterator it = _openPorts.find(p->GetPort());
	if (it == _openPorts.end()) {
		return;
	}

	bool found = false;
	PortForwardRequestList::iterator it2 = it->second.begin();
	for (; it2 != it->second.end(); it2++) {
		if ((*it2) == p) {
			found = true;
			break;
		}
	}

	if ((*it2)->GetStatus() == PortForwardRequest::NOT_ACTIVE) {

		SOCKET serverSocket = (*it2)->GetListeningSocket();
		delete (*it2);
		it->second.erase(it2);

		if (it->second.size() == 0) {
			int res = ATNetworkTool::CloseSocket(serverSocket);
			if (res != 0) {
				int err;

#if defined(__sun) || defined(_LINUX)
				err = errno;
#else
				err = WSAGetLastError()
#endif
				PRINT("Error %d in closing server socket at port %d.\n", err, p->GetPort());
			}
			_openPorts.erase(it);
		}
	}
}

bool Protocol::_checkProtocolFlow(LMEMessage *message)
{
	switch (message->MessageType) {
	case APF_SERVICE_REQUEST:
	case APF_USERAUTH_REQUEST:
		{
			Lock l(_versionLock);
			if (_handshakingStatus != AGREED) {
				_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
				Deinit();
				return false;
			}
			return true;
		}
		break;

	case APF_GLOBAL_REQUEST:
	case APF_CHANNEL_OPEN:
	case APF_CHANNEL_OPEN_CONFIRMATION:
	case APF_CHANNEL_OPEN_FAILURE:
	case APF_CHANNEL_CLOSE:
	case APF_CHANNEL_DATA:
	case APF_CHANNEL_WINDOW_ADJUST:
		{
			Lock l(_versionLock);
			if ((_handshakingStatus != AGREED) || (_pfwdService != STARTED)) {
				_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
				Deinit();
				return false;
			}
			return true;
		}
		break;

	case APF_DISCONNECT:
	case APF_PROTOCOLVERSION:
		return true;
		break;

	default:
		{
			_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
			Deinit();
			return false;
		}
		break;
	}

	return false;
}

unsigned int Protocol::_getMinMessageLen(LMEMessage *message)
{
	switch (message->MessageType) {
	case APF_SERVICE_REQUEST:
		return sizeof(LMEServiceRequestMessage);
		break;
	case APF_USERAUTH_REQUEST:
		return sizeof(LMEUserAuthRequestMessage);
		break;
	case APF_GLOBAL_REQUEST:
		return sizeof(LMEGlobalRequestMessage);
		break;
	case APF_CHANNEL_OPEN:
		return sizeof(LMEChannelOpenRequestMessage);
		break;
	case APF_CHANNEL_OPEN_CONFIRMATION:
		return sizeof(LMEChannelOpenReplaySuccessMessage);
		break;
	case APF_CHANNEL_OPEN_FAILURE:
		return sizeof(LMEChannelOpenReplayFailureMessage);
		break;
	case APF_CHANNEL_CLOSE:
		return sizeof(LMEChannelCloseMessage);
		break;
	case APF_CHANNEL_DATA:
		return sizeof(LMEChannelDataMessage);
		break;
	case APF_CHANNEL_WINDOW_ADJUST:
		return sizeof(LMEChannelWindowAdjustMessage);
		break;
	case APF_DISCONNECT:
		return sizeof(LMEDisconnectMessage);
		break;
	case APF_PROTOCOLVERSION:
		return sizeof(LMEProtocolVersionMessage);
		break;
	default:
		return 0;
	}

	return 0;
}

bool Protocol::_checkMessageAndProtocol(LMEMessage *message, unsigned int len)
{
	if (len < sizeof(LMEMessage)) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return false;
	}

	if (!_checkProtocolFlow(message)) {
		return false;
	}
	if (len < _getMinMessageLen(message)) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return false;
	}
	return true;
}

void Protocol::_LmeCallback(void *param, void *buffer, unsigned int len, int *status)
{
	Protocol *prot = (Protocol *)param;

	if (prot->oldProtocolMode) {
		prot->_LmeReceiveCompat((char *)buffer, len, status);
	} else {
		prot->_LmeReceive(buffer, len, status);
	}
}

void Protocol::_LmeReceive(void *buffer, unsigned int len, int *status)
{
	LMEMessage *message = (LMEMessage *)buffer;
	*status = 0;

	if (!_checkMessageAndProtocol(message, len)) {
		return;
	}

	switch (message->MessageType) {
	case APF_DISCONNECT:
		{
			PRINT("LME requested to disconnect with reason code 0x%08x\n",
				((LMEDisconnectMessage *)message)->ReasonCode);
			Deinit();
			return;
		}
		break;

	case APF_SERVICE_REQUEST:
		{
			LMEServiceRequestMessage *sRMsg =
				(LMEServiceRequestMessage *)message;

			if ((sRMsg->ServiceName.compare(APF_SERVICE_AUTH) == 0) ||
				(sRMsg->ServiceName.compare(APF_SERVICE_PFWD) == 0)) {

				_lme.ServiceAccept(sRMsg->ServiceName);
				PRINT("Accepting service: %s\n",
					sRMsg->ServiceName.c_str());
				if (sRMsg->ServiceName.compare(APF_SERVICE_PFWD) == 0) {
					Lock l(_versionLock);
					_pfwdService = STARTED;
				}
			} else {
				PRINT("Requesting to disconnect from LME with reason code 0x%08x\n",
					APF_DISCONNECT_SERVICE_NOT_AVAILABLE);
				_lme.Disconnect(APF_DISCONNECT_SERVICE_NOT_AVAILABLE);
				Deinit();
				return;
			}
		}
		break;

	case APF_USERAUTH_REQUEST:
		{
			PRINT("Sending Userauth success message\n");
			_lme.UserAuthSuccess();
		}
		break;

	case APF_PROTOCOLVERSION:
		_apfProtocolVersion((LMEProtocolVersionMessage *)message);
		break;

	case APF_GLOBAL_REQUEST:
		_apfGlobalRequest((LMEGlobalRequestMessage *)message, len, status);
		break;

	case APF_CHANNEL_OPEN:
		_apfChannelOpen((LMEChannelOpenRequestMessage *)message, status);
		break;

	case APF_CHANNEL_OPEN_CONFIRMATION:
		{
			LMEChannelOpenReplaySuccessMessage *chOpenSuccMsg =
				(LMEChannelOpenReplaySuccessMessage *)message;

			Lock l(_channelsLock);

			ChannelMap::iterator it = _openChannels.find(chOpenSuccMsg->RecipientChannel);
			if (it != _openChannels.end()) {
				it->second->SetStatus(Channel::OPEN);
				it->second->SetRecipientChannel(chOpenSuccMsg->SenderChannel);
				it->second->AddBytesTxWindow(chOpenSuccMsg->InitialWindow);
			}

			_signalSelect();
		}
		break;

	case APF_CHANNEL_OPEN_FAILURE:
		{
			PortForwardRequest *clPFwdReq =
				_apfChannelOFail((LMEChannelOpenReplayFailureMessage *)message);
			if (clPFwdReq != NULL) {
				Lock l(_portsLock);
				_closePortForwardRequest(clPFwdReq);
			}
		}
		break;

	case APF_CHANNEL_CLOSE:
		{
			PortForwardRequest *clPFwdReq =
				_apfChannelClose((LMEChannelCloseMessage *)message);
			if (clPFwdReq != NULL) {
				Lock l(_portsLock);
				_closePortForwardRequest(clPFwdReq);
			}
		}
		break;

	case APF_CHANNEL_DATA:
		{
			PortForwardRequest *clPFwdReq =
				_apfChannelData((LMEChannelDataMessage *)message, status);
			if (clPFwdReq != NULL) {
				Lock l(_portsLock);
				_closePortForwardRequest(clPFwdReq);
			}
		}
		break;

	case APF_CHANNEL_WINDOW_ADJUST:
		{
			LMEChannelWindowAdjustMessage *channelWindowMessage = (LMEChannelWindowAdjustMessage *)message;

			Lock l(_channelsLock);

			ChannelMap::iterator it = _openChannels.find(channelWindowMessage->RecipientChannel);
			if (it != _openChannels.end()) {
				it->second->AddBytesTxWindow(channelWindowMessage->BytesToAdd);
				_signalSelect();
			}
		}
		break;

	default:
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		break;
	}
}

unsigned int Protocol::_getMinGlobalMsgLen(LMEGlobalRequestMessage *globalMessage)
{
	switch (globalMessage->RequestType) {
	case LMEGlobalRequestMessage::TCP_FORWARD_REQUEST:
		return sizeof(LMETcpForwardRequestMessage);
		break;
	case LMEGlobalRequestMessage::TCP_FORWARD_CANCEL_REQUEST:
		return sizeof(LMETcpForwardCancelRequestMessage);
		break;
	case LMEGlobalRequestMessage::UDP_SEND_TO:
		return sizeof(LMEUdpSendToMessage);
		break;
	default:
		return 0;
	}
	return 0;
}

void Protocol::_apfGlobalRequest(LMEGlobalRequestMessage *globalMessage,
				 unsigned int len, int *status)
{
	PRINT("Global Request type 0x%02x\n", globalMessage->RequestType);

	if (len < _getMinGlobalMsgLen(globalMessage)) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return;
	}

	switch (globalMessage->RequestType) {
	case LMEGlobalRequestMessage::TCP_FORWARD_REQUEST:
		_apfTcpForwardRequest((LMETcpForwardRequestMessage *)globalMessage, status);
		break;

	case LMEGlobalRequestMessage::TCP_FORWARD_CANCEL_REQUEST:
		_apfTcpForwardCancel((LMETcpForwardCancelRequestMessage *)globalMessage);
		break;

	case LMEGlobalRequestMessage::UDP_SEND_TO:
		_aptSendUdp((LMEUdpSendToMessage *)globalMessage, status);
		break;

	default:
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		break;
	}
}

void Protocol::_apfTcpForwardRequest(LMETcpForwardRequestMessage *tcpFwdReqMsg, int *status)
{
	IsConnectionPermittedCallback cb = NULL;
	bool failure = false;

#ifdef _REMOTE_SUPPORT
	if (tcpFwdReqMsg->Address.compare("0.0.0.0") == 0) {
		cb = _isRemoteCallback;
	}
	else
#endif
	{
		cb = _isLocalCallback;
	}

	{
		Lock l(_portsLock);
		SOCKET serverSocket = INVALID_SOCKET;
		listenPortSet::iterator lpi;

		if (_checkListen(tcpFwdReqMsg->Address, tcpFwdReqMsg->Port, serverSocket)) {
			*status = 1;
			// Log in Event Log
			TCHAR message[1024];
			_stprintf_s(message, 1024,
				TEXT("LMS Service already accepted a request at %s:%d\n"),
				tcpFwdReqMsg->Address.c_str(),
				tcpFwdReqMsg->Port);
			_eventLog(_eventLogParam, message, EVENTLOG_ERROR_TYPE);
			PRINT(message);
			// Send Failure replay to LME
			_lme.TcpForwardReplyFailure();
			return;
		}

		lpi = _listenFailReported.find(tcpFwdReqMsg->Port);

		if (serverSocket == INVALID_SOCKET) {
			int error;
			serverSocket = _listenPort(tcpFwdReqMsg->Port, error);
			if (serverSocket == INVALID_SOCKET) {
				*status = 1;
				// Log in Event Log
				TCHAR message[1024];
				_stprintf_s(message, 1024,
					TEXT("LMS Service cannot listen at port %d.\n"),
					tcpFwdReqMsg->Port);
				if (lpi == _listenFailReported.end()) {
					_eventLog(_eventLogParam, message, EVENTLOG_ERROR_TYPE);
					_listenFailReported.insert(tcpFwdReqMsg->Port);
				}
				PRINT(message);
				// Send Failure replay to LME
				_lme.TcpForwardReplyFailure();
				failure = true;
			}
		}

		if (failure != true) {
			PRINT("Listening at port %d at %s interface.\n",
				tcpFwdReqMsg->Port,
				((cb == _isLocalCallback) ? "local" : "remote"));

			PortForwardRequest *portForwardRequest =
				new PortForwardRequest(tcpFwdReqMsg->Address,
					tcpFwdReqMsg->Port,
					serverSocket, cb, (cb == _isLocalCallback));

			_openPorts[tcpFwdReqMsg->Port].push_back(portForwardRequest);

			// Send Success replay to LME
			_lme.TcpForwardReplySuccess(tcpFwdReqMsg->Port);

			portForwardRequest->SetStatus(
				(cb == _isLocalCallback) ?
				PortForwardRequest::LISTENING :
				PortForwardRequest::PENDING_REQUEST);
			if (lpi != _listenFailReported.end()) {
				_listenFailReported.erase(lpi);
			}

			_signalSelect();
		}
	}

	if (failure == true) {
		_lme.Disconnect(APF_DISCONNECT_PROTOCOL_ERROR);
		Deinit();
		return;
	}

	if (cb == _isLocalCallback) {
		if (_listenFailReported.empty()) {
			_updateIPFQDN(tcpFwdReqMsg->Address.c_str());
		}
	}
#ifdef _REMOTE_SUPPORT
	else {
		_checkRemoteSupport(true);
	}
#endif
}

void Protocol::_apfTcpForwardCancel(LMETcpForwardCancelRequestMessage *tcpFwdCnclMsg)
{
	bool found = false;
	Lock l(_portsLock);

	PortMap::iterator it = _openPorts.find(tcpFwdCnclMsg->Port);
	if (it == _openPorts.end()) {
		PRINT("Previous request on address %s and port %d doesn't exist.\n",
			tcpFwdCnclMsg->Address.c_str(), tcpFwdCnclMsg->Port);
		_lme.TcpForwardCancelReplyFailure();
		return;
	}

	PortForwardRequestList::iterator it2 = it->second.begin();
	for (; it2 != it->second.end(); it2++) {
		if (((*it2)->GetBindedAddress().compare(tcpFwdCnclMsg->Address) == 0) &&
			//((*it2)->GetPort() == tcpFwdCnclMsg->Port)) {
			((*it2)->GetStatus() != PortForwardRequest::NOT_ACTIVE)) {
				found = true;
				break;
		}
	}

	if (found) {
		(*it2)->SetStatus(PortForwardRequest::NOT_ACTIVE);
			if ((*it2)->GetChannelCount() == 0) {
			_closePortForwardRequest(*it2);
		}
		_lme.TcpForwardCancelReplySuccess();
	} else {
		PRINT("Previous request on address %s and port %d doesn't exist.\n",
			tcpFwdCnclMsg->Address.c_str(), tcpFwdCnclMsg->Port);
		_lme.TcpForwardCancelReplyFailure();
	}
}

void Protocol::_aptSendUdp(LMEUdpSendToMessage *udpSendToMessage, int *status)
{
	int error = 0;

	SOCKET s = ATNetworkTool::Connect(udpSendToMessage->Address.c_str(),
					  udpSendToMessage->Port, error,
					  PF_INET, SOCK_DGRAM);
	if (s == INVALID_SOCKET) {
		*status = 1;
		PRINT("Unable to send UDP data.\n");
		return;
	}

	int count = _send(s, (char *)udpSendToMessage->Data, udpSendToMessage->DataLength, error);
	PRINT("Sent UDP data: %d bytes of %d.\n", count, udpSendToMessage->DataLength);

	ATNetworkTool::CloseSocket(s);
}

void Protocol::_apfProtocolVersion(LMEProtocolVersionMessage *verMsg)
{
	Lock l(_versionLock);

	switch (_handshakingStatus) {
	case AGREED:
	case NOT_INITIATED:
		_lme.ProtocolVersion(MAX_PROT_VERSION);
	case INITIATED:
		if (*verMsg < MIN_PROT_VERSION) {
			PRINT("Version %d.%d is not supported.\n",
				verMsg->MajorVersion, verMsg->MinorVersion);
			_lme.Disconnect(APF_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
			Deinit();
			return;
		}
		if (*verMsg > MAX_PROT_VERSION) {
			_AmtProtVersion = MAX_PROT_VERSION;
		} else {
			_AmtProtVersion = (*verMsg);
		}
		_handshakingStatus = AGREED;
		break;

	default:
		_lme.Disconnect(APF_DISCONNECT_BY_APPLICATION);
		Deinit();
		break;
	}
}

void Protocol::_apfChannelOpen(LMEChannelOpenRequestMessage *chOpenMsg, int *status)
{
	int error = 0;

	PRINT("Got channel request from AMT. "
		" Recipient channel %d for address %s, port %d.\n",
		chOpenMsg->SenderChannel,
		chOpenMsg->Address.c_str(), chOpenMsg->Port);

	SOCKET s = ATNetworkTool::Connect(chOpenMsg->Address.c_str(),
					  chOpenMsg->Port, error, PF_INET);
	if (s == INVALID_SOCKET) {
		*status = 1;
		PRINT("Unable to open direct channel to address %s.\n",
			chOpenMsg->Address.c_str());
		return;
	}

	ATNetworkTool::SetNonBlocking(s);

	Channel *c = new Channel(NULL, s);
	c->AddBytesTxWindow(chOpenMsg->InitialWindow);
	c->SetRecipientChannel(chOpenMsg->SenderChannel);
	c->SetStatus(Channel::OPEN);

	{
		Lock l(_channelsLock);
		_openChannels[c->GetSenderChannel()] = c;
		_lme.ChannelOpenReplaySuccess(c->GetRecipientChannel(), c->GetSenderChannel());
	}

	_signalSelect();
}

PortForwardRequest *Protocol::_closeMChannel(Channel *c)
{
	PortForwardRequest *clPFwdReq = NULL;

	ATNetworkTool::CloseSocket(c->GetSocket());
	PortForwardRequest *p = c->GetPortForwardRequest();
	if ((p != NULL) && (p->DecreaseChannelCount() == 0)) {
		clPFwdReq = p;
	}
	delete c;

	return clPFwdReq;
}

PortForwardRequest *Protocol::_apfChannelOFail(LMEChannelOpenReplayFailureMessage *chFailMsg)
{
	PortForwardRequest *clPFwdReq = NULL;

	Lock l(_channelsLock);

	ChannelMap::iterator it = _openChannels.find(chFailMsg->RecipientChannel);
	if (it != _openChannels.end()) {
		clPFwdReq = _closeMChannel(it->second);
		_openChannels.erase(it);
		PRINT("Channel open request was refused. Reason code: 0x%02x reason.\n",
			chFailMsg->ReasonCode);
	}

	return clPFwdReq;
}

PortForwardRequest *Protocol::_apfChannelClose(LMEChannelCloseMessage *chClMsg)
{
	PortForwardRequest *clPFwdReq = NULL;

	Lock l(_channelsLock);

	ChannelMap::iterator it = _openChannels.find(chClMsg->RecipientChannel);
	if (it != _openChannels.end()) {
		Channel *c = it->second;
		switch(c->GetStatus()) {
		case Channel::OPEN:
			c->SetStatus(Channel::CLOSED);
			_lme.ChannelClose(c->GetRecipientChannel());
			PRINT("Channel %d was closed by AMT.\n", c->GetSenderChannel());
			break;

		case Channel::WAITING_CLOSE:
			PRINT("Received reply by AMT on closing channel %d.\n", c->GetSenderChannel());
			break;

		case Channel::CLOSED:
		case Channel::NOT_OPENED:
			break;
		}

		clPFwdReq = _closeMChannel(c);
		_openChannels.erase(it);
	}

	return clPFwdReq;
}

PortForwardRequest *Protocol::_apfChannelData(LMEChannelDataMessage *chDMsg, int *status)
{
	PortForwardRequest *clPFwdReq = NULL;

	do {
		Lock l(_channelsLock);

		ChannelMap::iterator it = _openChannels.find(chDMsg->RecipientChannel);
		if (it == _openChannels.end()) {
			break;
		}

		if ((it->second->GetStatus() != Channel::OPEN) &&
		    (it->second->GetStatus() != Channel::WAITING_CLOSE)) {
			break;
		}

		if (it->second->GetRxWindow() < chDMsg->DataLength) {
			break;
		}

		int senderr = 0;
		int count = _send(it->second->GetSocket(), (char *)chDMsg->Data,
				chDMsg->DataLength, senderr);
		PRINT("Sent %d bytes of %d from AMT to channel %d with socket %d.\n",
			count, chDMsg->DataLength, chDMsg->RecipientChannel,
			it->second->GetSocket());

		if ((count == -1) && (senderr == EPIPE)) {
			*status = 1;
			clPFwdReq = _closeMChannel(it->second);
			_openChannels.erase(it);
			PRINT("Channel send data request was refused. Broken pipe.\n");
			break;
		}
		//it->second->AddBytesRxWindow(-count);
		//if (it->second->GetRxWindow() < Channel::LMS_WINDOW_SIZE / 2) {
		_lme.ChannelWindowAdjust(it->second->GetRecipientChannel(), chDMsg->DataLength);
		//Channel::LMS_WINDOW_SIZE - it->second->GetRxWindow());
		//}
	} while (0);

	return clPFwdReq;
}

#ifdef _REMOTE_SUPPORT

bool Protocol::_compareDNSSuffix(std::string AMTDNSSuffix, std::string suffix)
{
	if (AMTDNSSuffix.size() > suffix.size()) {
		return false;
	}

	if ((AMTDNSSuffix.size() < suffix.size()) &&
	    (suffix[suffix.size()-AMTDNSSuffix.size()-1] != '.')) {
		return false;
	}

	if (strnicmp(suffix.c_str() + suffix.size()-AMTDNSSuffix.size(),
	    AMTDNSSuffix.c_str(),
	    AMTDNSSuffix.size()) == 0) {
		return true;
	}

	return false;
}

bool Protocol::_checkRemoteSupport(bool requestDnsFromAmt)
{
	if (requestDnsFromAmt) {
		std::list<std::string> amtDnsSuffixes;

		AMT_STATUS status = _cfg.RequestEntDNSSuffixList(amtDnsSuffixes);

		if (status != AMT_STATUS_SUCCESS) {
			PRINT("Remote access is disabled - AMT is not configured [%x]\n", status);
			return false;
		}

		_AMTDNSLock.acquire();
		_AMTDNSSuffixes.clear();
		_AMTDNSSuffixes.assign(amtDnsSuffixes.begin(), amtDnsSuffixes.end());
		_AMTDNSLock.release();

		amtDnsSuffixes.clear();
	}

	ATDomainMap domains;
	int error = 0;
	ATNetworkTool::GetLocalNetDomains(domains, error, PF_INET);
	_updateEnterpriseAccessStatus(domains);

	return true;
}

void Protocol::_updateEnterpriseAccessStatus(const ATDomainMap &localDNSSuffixes)
{
	_AMTDNSLock.acquire();

	std::list<std::string>::iterator remIt;
	std::list<std::string>::iterator startIt = _AMTDNSSuffixes.begin();
	std::list<std::string>::iterator endIt = _AMTDNSSuffixes.end();
	ATDomainMap::const_iterator locIt;

	bool access = false;
	ATAddress localIp;

	for (locIt = localDNSSuffixes.begin(); locIt != localDNSSuffixes.end(); locIt++) {
		remIt = find_if(startIt, endIt, bind2nd(ptr_fun(_compareDNSSuffix), locIt->second));
		if (remIt != _AMTDNSSuffixes.end()) {
			access = true;
			localIp = locIt->first;
			break;
		}
	}

	_AMTDNSLock.release();

	bool sendEntAccessMessage = true;
	if (access) {
		Lock l(_portsLock);
		for (PortMap::iterator it = _openPorts.begin(); it != _openPorts.end(); it++) {
			for (PortForwardRequestList::iterator it2 = it->second.begin();
					it2 != it->second.end(); it2++) {

				if ((*it2)->GetStatus() == PortForwardRequest::PENDING_REQUEST) {
					(*it2)->SetStatus(PortForwardRequest::LISTENING);
					sendEntAccessMessage = false;
					break;	// Assuming that there is a such request one per port
				}
			}
		}

		_signalSelect();
	}

	if (sendEntAccessMessage == false) {
		return;
	}

	AMT_STATUS status = _cfg.SendEnterpriseAccess(access, localIp);

	Lock l(_remoteAccessLock);
	_remoteAccessEnabled = (status == AMT_STATUS_SUCCESS);
	switch (status) {
	case AMT_STATUS_SUCCESS:
		PRINT("Remote access is allowed.\n");
		break;
	case AMT_STATUS_REMOTE_ACCESS_NOT_GRANTED:
		PRINT("Remote access is denied because AMT is directly connected "
			"to enterprise network.\n");
		break;
	case AMT_STATUS_REMOTE_ACCESS_HOST_VPN_IS_DISABLED:
		PRINT("Remote access is disabled.\n");
		break;
	default:
		PRINT("Remote access is disabled.\n");
		break;
	}

	//if (_remoteAccessEnabled) {
	//	Lock l(_portsLock);
	//	for (PortMap::iterator it = _openPorts.begin(); it != _openPorts.end(); it++) {
	//		for (PortForwardRequestList::iterator it2 = it->second.begin();
	//				it2 != it->second.end(); it2++) {

	//			if ((*it2)->GetStatus() == PortForwardRequest::PENDING_REQUEST) {
	//				(*it2)->SetStatus(PortForwardRequest::LISTENING);
	//				break;	// Assuming that there is a such request one per port
	//			}
	//		}
	//	}

	//	_signalSelect();
	//}

}

#endif

int Protocol::_isLocalCallback(void *const param, SOCKET s)
{
	int error = 0;

	return ((1 == ATNetworkTool::IsSockPeerLocal(s, error, PF_INET)) ? 1 : -1);
}

#ifdef _REMOTE_SUPPORT

int Protocol::_isRemoteCallback(void *const param, SOCKET s)
{
	Protocol *prot = (Protocol *)param;

	return prot->_isRemote(s);
}

int Protocol::_isRemote(SOCKET s) const
{
	int result = 0;
	int error = 0;
	int ret;
	std::string dnsSuffix;

	ret = ATNetworkTool::GetSockDomain(s, dnsSuffix, error);
	if (ret != 1) {
		return ret;
	}

	Lock l(_remoteAccessLock);

	if (_remoteAccessEnabled) {

		_AMTDNSLock.acquire();

		std::list<std::string>::const_iterator it = _AMTDNSSuffixes.begin();
		for (; it != _AMTDNSSuffixes.end(); it++) {
			if (_compareDNSSuffix(*it, dnsSuffix)) {
				result = 1;
				break;
			}
		}

		_AMTDNSLock.release();
	}

	return result;
}
#endif

int Protocol::_updateIPFQDN(const char *fqdn)
{
	if (strcmp(fqdn, _AMTFQDN) != 0) {
		char localName[FQDN_MAX_SIZE] = "\0";
		int res = gethostname(localName, sizeof(localName));

		// If AMT FQDN is equal to local FQDN than we don't do anything
		if ((res == -1) || (strcmp(fqdn, localName) != 0)) {
			if (_handleFQDNChange(fqdn) < 0) {
				ERROR("Error: failed to update FQDN info\n");
				return -1;
			}
		} else {
			if (_handleFQDNChange("") < 0) {
				ERROR("Error: failed to update FQDN info\n");
				return -1;
			}
		}
	}

	memcpy(_AMTFQDN, fqdn, sizeof(_AMTFQDN));

	PRINT("Got FQDN: %s\n", _AMTFQDN);

	return 0;
}


char *Protocol::_getErrMsg(DWORD err)
{
	static char buffer[1024];

#if defined(__sun) || defined(_LINUX)
	strerror_r(err, buffer, sizeof(buffer) - 1);
#else
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,
					err,
					0,
					buffer,
					sizeof(buffer) - 1,
					0);
#endif	// __sun || _LINUX

	return buffer;
}


int Protocol::_handleFQDNChange(const char *fqdn)
{
	const char *hostFile = "hosts";
	const char *tmpFile = "hosts-lms.tmp";
	bool hasFqdn = false;
#define LMS_MAX_FILENAME_LEN 1024
	char inFileName[LMS_MAX_FILENAME_LEN] = "";
	char oldFqdn[FQDN_MAX_SIZE + 1];
	char outFileName[LMS_MAX_FILENAME_LEN] = "";
	char host[FQDN_MAX_SIZE + 1];
#define LMS_MAX_LINE_LEN 1023
	char line[LMS_MAX_LINE_LEN + 1];
#define LMS_LINE_SIG_FIRST_WORDS "# LMS GENERATED "
#define LMS_LINE_SIG_LAST_WORD "LINE"
#define LMS_LINE_SIG_LAST_WORD_LEN 4
#define LMS_LINE_SIG LMS_LINE_SIG_FIRST_WORDS LMS_LINE_SIG_LAST_WORD
#define lmsstr(s) lmsname(s)
#define lmsname(s) #s
#define LMS_LINE_FORMAT "127.0.0.1       %s %s " LMS_LINE_SIG
#define LMS_LINE_SCAN_FORMAT "127.0.0.1 %" lmsstr(FQDN_MAX_SIZE) "s %" lmsstr(FQDN_MAX_SIZE) "s " LMS_LINE_SIG_FIRST_WORDS "%" lmsstr(LMS_LINE_SIG_LAST_WORD_LEN) "c"
	char tmpsige[LMS_LINE_SIG_LAST_WORD_LEN];

#if defined(__sun) || defined(_LINUX)

	const char *dir = "/etc/";

#else

	char *sysDrive;
	const char *dir = "\\system32\\drivers\\etc\\";

	sysDrive = getenv("SystemRoot");
	if (NULL == sysDrive) {
		return -1;
	}

	// sanity check before string copying
	if (LMS_MAX_FILENAME_LEN < (strnlen(sysDrive, LMS_MAX_FILENAME_LEN)
	                            + strnlen(dir, LMS_MAX_FILENAME_LEN)
	                            + strnlen(hostFile, LMS_MAX_FILENAME_LEN) + 1)) {
		return -1;
	}
	// sanity check before string copying
	if (LMS_MAX_FILENAME_LEN < (strnlen(sysDrive, LMS_MAX_FILENAME_LEN)
	                            + strnlen(dir, LMS_MAX_FILENAME_LEN)
	                            + strnlen(tmpFile, LMS_MAX_FILENAME_LEN) + 1)) {
		return -1;
	}

	strncpy(inFileName, sysDrive, LMS_MAX_FILENAME_LEN - 1);
	strncpy(outFileName, sysDrive, LMS_MAX_FILENAME_LEN - 1);

#endif	// __sun || _LINUX

	strncat(inFileName, dir, LMS_MAX_FILENAME_LEN - 1);
	strncat(outFileName, dir, LMS_MAX_FILENAME_LEN - 1);
	strncat(inFileName, hostFile, LMS_MAX_FILENAME_LEN - 1);
	strncat(outFileName, tmpFile, LMS_MAX_FILENAME_LEN - 1);

	FILE *ifp = fopen(inFileName, "r");
	if (NULL == ifp) {
		_eventLog(_eventLogParam, TEXT("Error: Can't open hosts file"), EVENTLOG_ERROR_TYPE);
		return -1;
	}

	FILE *ofp = fopen(outFileName, "w");
	if (NULL == ofp) {
		_eventLog(_eventLogParam, TEXT("Error: Can't create temporary hosts file"), EVENTLOG_ERROR_TYPE);
		fclose(ifp);
		return -1;
	}

	// First create a copy of the hosts file, without lines that were
	// previously added by the LMS.
	// Go over each line and copy it to the tmp file.
	while (fgets(line, sizeof(line), ifp)) {
		// don't copy the line if it was generated by the LMS
		memset(oldFqdn, 0, sizeof(oldFqdn));
		memset(tmpsige, 0, sizeof(tmpsige));
		if (0 == (
		    (3 == sscanf(line, LMS_LINE_SCAN_FORMAT, oldFqdn, host, tmpsige))
		    ? strncmp(tmpsige, LMS_LINE_SIG_LAST_WORD, LMS_LINE_SIG_LAST_WORD_LEN)
		    : (-2))
		) {
			if (0 == strncmp((char *)fqdn, oldFqdn, FQDN_MAX_SIZE)) {
				// copy the old LMS line too, since it's up to date
				fprintf(ofp, "%s", line);
				hasFqdn = true;
			}
			continue;
		}

		fprintf(ofp, "%s", line);

		while ((LMS_MAX_LINE_LEN == strnlen(line, LMS_MAX_LINE_LEN))
		    && ('\n' != line[LMS_MAX_LINE_LEN - 1])
		    && (fgets(line, sizeof(line), ifp))) {
			fprintf(ofp, "%s", line);
		}
	}

	if (hasFqdn) {
		fclose(ofp);
		fclose(ifp);
		unlink(outFileName);
		return 0;
	}

	// If the original hosts file does not end with a new line character,
	// add a new line at the end of the new file before adding our line.
	fseek(ifp, -1, SEEK_END);
	char lastChar = fgetc(ifp);
	if ('\n' != lastChar) {
		fprintf(ofp, "\n");
	}

	memset(host, 0, FQDN_MAX_SIZE + 1);
	strncpy(host, fqdn, FQDN_MAX_SIZE);
	char *lmsdot = strchr(host, '.');
	if (NULL != lmsdot) {
		lmsdot[0] = '\0';
	}

	if ((fqdn != NULL) && (fqdn[0] != 0)) {
		// Add the specified FQDN to the end of the tmp file
		fprintf(ofp, LMS_LINE_FORMAT "\n", fqdn, host);
	}

	fclose(ofp);
	fclose(ifp);

	if (0 != std::rename(outFileName, inFileName)) {
		std::string tmp2FileName = std::string(inFileName) + ".~tmp";
		std::ifstream mfile(inFileName, std::ios_base::in);
		if (!mfile.is_open()) {
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [1]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		std::ofstream wfile(tmp2FileName.c_str(), std::ios_base::out | std::ios_base::trunc);
		if (!wfile.is_open()) {
			mfile.close();
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [2]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		wfile << mfile.rdbuf();
		if (wfile.bad()) {
			mfile.close();
			wfile.close();
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [3]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		mfile.close();
		wfile.close();
		std::ifstream sfile(outFileName, std::ios_base::in);
		if (!sfile.is_open()) {
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [4]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		std::ofstream dfile(inFileName, std::ios_base::out | std::ios_base::trunc);
		if (!dfile.is_open()) {
			sfile.close();
			_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [5]"), EVENTLOG_ERROR_TYPE);
			return -1;
		}
		dfile << sfile.rdbuf();
		if (dfile.bad()) {
			sfile.close();
			dfile.close();
			unlink(inFileName);
			if (0 != std::rename(outFileName, inFileName)) {
				std::rename(tmp2FileName.c_str(), inFileName);
				_eventLog(_eventLogParam, TEXT("Error: Can't update hosts file [6]"), EVENTLOG_ERROR_TYPE);
				return -1;
			}
		}
		sfile.close();
		dfile.close();
	}

	_eventLog(_eventLogParam, TEXT("hosts file updated"), EVENTLOG_INFORMATION_TYPE);

	return 0;
}

ssize_t Protocol::_send(int s, const void *buf, size_t len, int &senderr)
{
	ssize_t result;

#if defined(_LINUX)
	if (-1 == (result = send(s, buf, len, MSG_NOSIGNAL))) {
		senderr = errno;
	}
#elif defined(__sun)
	if (-1 == (result = send(s, buf, len, 0))) {
		senderr = errno;
	}
#else
	result = send(s, buf, len);
#endif	// _LINUX

	return result;
}

