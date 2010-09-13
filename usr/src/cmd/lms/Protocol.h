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

#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <map>
#include <vector>
#include <set>
#include <string>
#include "types.h"
#include "LMS_if.h"
#include "LMEConnection.h"
#include "PortForwardRequest.h"
#include "Channel.h"
#include "Semaphore.h"

#if defined(__sun) || defined(_LINUX)

#define SOCKET int
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)
#else
#include <windows.h>
#endif	// __sun || _LINUX

#ifdef _REMOTE_SUPPORT
#include "ConfigConnection.h"
#endif

#define FQDN_MAX_SIZE 256

typedef void (*EventLogCallback)(void *param, LPCTSTR message, WORD eventType);

class Protocol
{
public:

	static const LMEProtocolVersionMessage MIN_PROT_VERSION;
	static const LMEProtocolVersionMessage MAX_PROT_VERSION;

	enum SOCKET_STATUS {
		ACTIVE = 0,
		NOT_CREATED,
		LINGER_ERROR,
		NOT_BINDED,
		NOT_EXCLUSIVE_ADDRESS,
		NOT_LISTENED
	};

	Protocol();
	~Protocol();

	bool CreateSockets();
	void DestroySockets();
	bool SocketsCreated() { return _sockets_active; }
	bool IsDeInitialized();
	bool IsInitialized();
	bool Init(EventLogCallback cb, void *param);
	int Select();
	void Deinit();
	void DeinitFull();

	bool oldProtocolMode;

private:
	static void _LmeCallback(void *param, void *buffer, unsigned int len, int *status);
	static int _isLocalCallback(void *const param, SOCKET s);
#ifdef _REMOTE_SUPPORT
	static int _isRemoteCallback(void *const param, SOCKET s);
#endif
	static char *_getErrMsg(DWORD err);

	bool _checkProtocolFlow(LMEMessage *message);
	unsigned int _getMinMessageLen(LMEMessage *message);
	unsigned int _getMinGlobalMsgLen(LMEGlobalRequestMessage *globalMessage);
	bool _checkMessageAndProtocol(LMEMessage *message, unsigned int len);
	void _closePortForwardRequest(PortForwardRequest *p);
	void _apfGlobalRequest(LMEGlobalRequestMessage *globalMessage, unsigned int len, int *status);
	void _apfTcpForwardRequest(LMETcpForwardRequestMessage *tcpFwdReqMsg, int *status);
	void _apfTcpForwardCancel(LMETcpForwardCancelRequestMessage *tcpFwdCnclMsg);
	void _aptSendUdp(LMEUdpSendToMessage *udpSendToMessage, int *status);
	void _apfProtocolVersion(LMEProtocolVersionMessage *verMsg);
	void _apfChannelOpen(LMEChannelOpenRequestMessage *chOpenMsg, int *status);
	PortForwardRequest *_closeMChannel(Channel *c);
	PortForwardRequest *_apfChannelOFail(LMEChannelOpenReplayFailureMessage *chFailMsg);
	PortForwardRequest *_apfChannelClose(LMEChannelCloseMessage *chClMsg);
	PortForwardRequest *_apfChannelData(LMEChannelDataMessage *chDMsg, int *status);
	void _LmeReceive(void *buffer, unsigned int len, int *status);
	void _LmeReceiveCompat(char *buffer, unsigned int len, int *status);
	void _signalSelect();
	bool _acceptConnection(SOCKET s, unsigned int port);
	int _rxFromSocket(SOCKET s);
	int _handleFQDNChange(const char *fqdn);
	int _updateIPFQDN(const char *fqdn);
#ifdef _REMOTE_SUPPORT
	static bool _compareDNSSuffix(std::string AMTDNSSuffix, std::string suffix);
	int _isRemote(SOCKET s) const;
	bool _checkRemoteSupport(bool requestDnsFromAmt = false);
	void _updateEnterpriseAccessStatus(const ATDomainMap &localDNSSuffixes);
#endif
	ssize_t _send(int s, const void *buf, size_t len, int &senderr);
	bool _checkListen(std::string address, in_port_t port, int &socket);
	int _listenPort(in_port_t port, int &error);
	bool _localListen(in_port_t port);
	Channel *_getSockOpenChannel(SOCKET s);


	struct Connection {
		SOCKET s;
	};

	typedef std::vector<PortForwardRequest *> PortForwardRequestList;
	typedef std::map<unsigned int, PortForwardRequestList> PortMap;
	typedef std::map<unsigned int, Channel *> ChannelMap;

	LMEConnection _lme;
	char *_rxSocketBuffer;
	unsigned int _rxSocketBufferSize;
#ifdef _REMOTE_SUPPORT
	ConfigConnection _cfg;
#endif
	SOCKET _serverSignalSocket;
	SOCKET _clientSignalSocket; // Used to notify Select() to check new available channels
	bool _sockets_active;
	PortMap _openPorts;
	ChannelMap _openChannels;
	Semaphore _portsLock;
	Semaphore _channelsLock;
#ifdef _REMOTE_SUPPORT
	std::list<std::string> _AMTDNSSuffixes;
	mutable Semaphore _AMTDNSLock;
	bool _remoteAccessEnabled;
	mutable Semaphore _remoteAccessLock;
#endif

	enum VERSION_HANDSHAKING {
		NOT_INITIATED,
		INITIATED,
		AGREED
	};

	enum SERVICE_STATUS {
		NOT_STARTED,
		STARTED
	};

	VERSION_HANDSHAKING _handshakingStatus;
	SERVICE_STATUS _pfwdService;
	LMEProtocolVersionMessage _AmtProtVersion;
	Semaphore _versionLock;

	char _AMTFQDN[FQDN_MAX_SIZE];
	EventLogCallback _eventLog;
	void *_eventLogParam;

	bool _deinitReq;
	Semaphore _deinitLock;

	typedef std::set<unsigned int> listenPortSet;
	listenPortSet _listenFailReported;
};

#endif
