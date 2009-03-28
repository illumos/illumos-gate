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

#ifndef __LME_CONNECTION_H__
#define __LME_CONNECTION_H__

#if defined(__sun) || defined(_LINUX)
#include "HECIUnix.h"
#else
#include "HECIWin.h"
#endif

#include <map>
#include <string>
#include "LMS_if.h"
#include "Thread.h"
#include "Semaphore.h"
#include "Event.h"
#include "ATNetworkTool.h"


struct AuthMethodData {
};

struct AuthPasswordData : AuthMethodData {
	std::string Password;
};

struct LMEMessage {

	LMEMessage(APF_MESSAGE_TYPE type) :
		MessageType(type) {}

	const APF_MESSAGE_TYPE MessageType;
};

struct LMEDisconnectMessage : LMEMessage {

	LMEDisconnectMessage(APF_DISCONNECT_REASON_CODE reasonCode) :
		LMEMessage(APF_DISCONNECT),
		ReasonCode(reasonCode) {}

	APF_DISCONNECT_REASON_CODE ReasonCode;
};

struct LMEServiceRequestMessage : LMEMessage {

	LMEServiceRequestMessage(std::string serviceName = "") :
		LMEMessage(APF_SERVICE_REQUEST),
		ServiceName(serviceName) {}

	std::string ServiceName;
};

struct LMEGlobalRequestMessage : LMEMessage {

	enum REQUEST_TYPE {
		TCP_FORWARD_REQUEST,
		TCP_FORWARD_CANCEL_REQUEST,
		UDP_SEND_TO
	};

	LMEGlobalRequestMessage(REQUEST_TYPE type) :
		LMEMessage(APF_GLOBAL_REQUEST),
		RequestType(type) {}

	const REQUEST_TYPE RequestType;
};

struct LMEProtocolVersionMessage : LMEMessage {

	LMEProtocolVersionMessage(UINT32 majorVersion = 0,
				  UINT32 minorVersion = 0,
				  APF_TRIGGER_REASON triggerReason = LME_REQUEST) :
		LMEMessage(APF_PROTOCOLVERSION),
		MajorVersion(majorVersion),
		MinorVersion(minorVersion),
		TriggerReason(triggerReason) {}

	UINT32 MajorVersion;
	UINT32 MinorVersion;
	APF_TRIGGER_REASON TriggerReason;

	struct LMEProtocolVersionMessage &operator=(const struct LMEProtocolVersionMessage &y)
	{
		if (this != &y) {
			this->MajorVersion = y.MajorVersion;
			this->MinorVersion = y.MinorVersion;
		}
		return *this;
	};
	bool operator<(const struct LMEProtocolVersionMessage &y) const
	{
		if (this->MajorVersion != y.MajorVersion) {
			return (this->MajorVersion < y.MajorVersion);
		}
		return (this->MinorVersion < y.MinorVersion);
	}
	bool operator>(const struct LMEProtocolVersionMessage &y) const
	{
		if (this->MajorVersion != y.MajorVersion) {
			return (this->MajorVersion > y.MajorVersion);
		}
		return (this->MinorVersion > y.MinorVersion);
	}
};

struct LMEUserAuthRequestMessage : LMEMessage {

	LMEUserAuthRequestMessage(std::string username = "",
				  std::string serviceName = "",
				  std::string methodName = "",
				  AuthMethodData *methodData = NULL) :
		LMEMessage(APF_USERAUTH_REQUEST),
		Username(username),
		ServiceName(ServiceName),
		MethodName(methodName),
		MethodData(methodData) {}

	std::string Username;
	std::string ServiceName;
	std::string MethodName;

	AuthMethodData *MethodData;
};


struct LMETcpForwardRequestMessage : LMEGlobalRequestMessage {

	LMETcpForwardRequestMessage(std::string address = "", UINT32 port = 0) :
		LMEGlobalRequestMessage(TCP_FORWARD_REQUEST),
		Address(address),
		Port(port) {}

	std::string Address;
	UINT32 Port;
};

struct LMETcpForwardCancelRequestMessage : LMEGlobalRequestMessage {

	LMETcpForwardCancelRequestMessage(std::string address = "", UINT32 port = 0) :
		LMEGlobalRequestMessage(TCP_FORWARD_CANCEL_REQUEST),
		Address(address),
		Port(port) {}

	std::string Address;
	UINT32 Port;
};

struct LMEUdpSendToMessage : LMEGlobalRequestMessage {

	LMEUdpSendToMessage(std::string address = "", UINT32 port = 0,
			    UINT32 dataLength = 0, UINT8 *data = NULL) :
		LMEGlobalRequestMessage(UDP_SEND_TO),
		Address(address),
		Port(port),
		DataLength(dataLength)
	{
		if ((data != NULL) && (dataLength != 0)) {
			Data = new UINT8[dataLength];
			memcpy(Data, data, dataLength);
		} else {
			Data = NULL;
		}

	}

	~LMEUdpSendToMessage()
	{
		if (Data != NULL) {
			delete[] Data;
			Data = NULL;
		}
	}

	std::string Address;
	UINT32 Port;
	UINT32 DataLength;
	UINT8 *Data;
};

struct LMEChannelOpenRequestMessage : LMEMessage {

	enum CHANNEL_TYPE {
		FORWARDED,
		DIRECT
	};

	LMEChannelOpenRequestMessage(CHANNEL_TYPE channelType = FORWARDED,
				     UINT32 senderChannel = 0,
				     UINT32 initialWindow = 0,
				     std::string address = "", UINT32 port = 0) :
		LMEMessage(APF_CHANNEL_OPEN),
		ChannelType(channelType),
		SenderChannel(senderChannel),
		InitialWindow(initialWindow),
		Address(address),
		Port(port) {}

	CHANNEL_TYPE ChannelType;
	UINT32 SenderChannel;
	UINT32 InitialWindow;
	std::string Address;
	UINT32 Port;
};

struct LMEChannelOpenReplaySuccessMessage : LMEMessage {

	LMEChannelOpenReplaySuccessMessage(UINT32 recipientChannel = 0,
					   UINT32 senderChannel = 0,
					   UINT32 initialWindow = 0) :
		LMEMessage(APF_CHANNEL_OPEN_CONFIRMATION),
		RecipientChannel(recipientChannel),
		SenderChannel(senderChannel),
		InitialWindow(initialWindow) {}

	UINT32 RecipientChannel;
	UINT32 SenderChannel;
	UINT32 InitialWindow;
};

struct LMEChannelOpenReplayFailureMessage : LMEMessage {

	LMEChannelOpenReplayFailureMessage(UINT32 recipientChannel = 0,
	    OPEN_FAILURE_REASON reasonCode = OPEN_FAILURE_REASON_ADMINISTRATIVELY_PROHIBITED) :
		LMEMessage(APF_CHANNEL_OPEN_FAILURE),
		RecipientChannel(recipientChannel),
		ReasonCode(reasonCode) {}

	UINT32 RecipientChannel;
	OPEN_FAILURE_REASON ReasonCode;
};

struct LMEChannelCloseMessage : LMEMessage {

	LMEChannelCloseMessage(UINT32 recipientChannel = 0) :
		LMEMessage(APF_CHANNEL_CLOSE),
		RecipientChannel(recipientChannel) {}

	UINT32 RecipientChannel;
};

struct LMEChannelDataMessage : LMEMessage {

	LMEChannelDataMessage(UINT32 recipientChannel = 0,
			      UINT32 dataLength = 0,
			      UINT8 *data = NULL) :
		LMEMessage(APF_CHANNEL_DATA),
		RecipientChannel(recipientChannel),
		DataLength(dataLength)
	{
		if ((data != NULL) && (dataLength != 0)) {
			Data = new UINT8[dataLength];
			memcpy(Data, data, dataLength);
		} else {
			Data = NULL;
		}
	}

	~LMEChannelDataMessage()
	{
		if (Data != NULL) {
			delete[] Data;
			Data = NULL;
		}
	}

	const UINT32 RecipientChannel;
	const UINT32 DataLength;
	UINT8 *Data;
};

struct LMEChannelWindowAdjustMessage : LMEMessage {

	LMEChannelWindowAdjustMessage(UINT32 recipientChannel = 0,
				      UINT32 bytesToAdd = 0) :
		LMEMessage(APF_CHANNEL_WINDOW_ADJUST),
		RecipientChannel(recipientChannel),
		BytesToAdd(bytesToAdd) {}

	UINT32 RecipientChannel;
	UINT32 BytesToAdd;
};

typedef void (*HECICallback)(void *param, void *buffer, unsigned int len, int *status);

class LMEConnection
{
public:
	LMEConnection(bool verbose = false);
	~LMEConnection();

	bool Init(HECICallback cb, void *param);
	bool IsInitialized();
	bool Disconnect(APF_DISCONNECT_REASON_CODE reasonCode);
	bool ServiceAccept(std::string serviceName);
	bool UserAuthSuccess();
	bool ProtocolVersion(const LMEProtocolVersionMessage versionMessage);
	bool TcpForwardReplySuccess(UINT32 port);
	bool TcpForwardReplyFailure();
	bool TcpForwardCancelReplySuccess();
	bool TcpForwardCancelReplyFailure();
	bool ChannelOpenForwardedRequest(UINT32 sender, UINT32 connectedPort,
					 std::string originatorIP, UINT32 originatorPort);
	bool ChannelOpenReplaySuccess(UINT32 recipient, UINT32 sender);
	bool ChannelOpenReplayFailure(UINT32 recipient, UINT32 reason);
	bool ChannelClose(UINT32 recipient);
	int  ChannelData(UINT32 recipient, UINT32 len, unsigned char *buffer);
	bool ChannelWindowAdjust(UINT32 recipient, UINT32 len);

	//BACKWARD COMPATIBLE PUBLIC - BEGIN
	bool CompatProtocolVersion();
	bool CompatRequestIPFQDN();
	bool CompatOpenConnection(in_port_t mePort, ATAddress addr, unsigned int &connID);
	int  CompatSendMessage(UINT8 connID, UINT32 len, unsigned char *buffer);
	void CompatCloseConnection(int connID, int status);
	//BACKWARD COMPATIBLE PUBLIC - END

	void Deinit();
	unsigned int GetHeciBufferSize() const;

	enum INIT_STATES {
		INIT_STATE_DISCONNECTED = 0,
		INIT_STATE_CONNECTING,
		INIT_STATE_CONNECTED
	};

	static const UINT32 RX_WINDOW_SIZE;

	unsigned char protocolVer;

private:
	static const GUID _guid;

	static void _rxThreadFunc(void *param);

	void _doRX();
	int _receiveMessage(unsigned char *buffer, int len);
	int _sendMessage(unsigned char *buffer, int len);
	bool _checkMinMsgSize(unsigned char *buf, unsigned int bytesRead);
	void _apfGlobalRequest(unsigned char *rxBuffer, unsigned int bytesRead, int *status);
	void _apfUserAuthRequest(unsigned char *rxBuffer, unsigned int bytesRead, int *status);
	void _apfChannelOpen(unsigned char *rxBuffer, unsigned int bytesRead, int *status);
	void _apfChannelOpenDirect(unsigned char *rxBuffer, unsigned int bytesRead, UINT32 *senderChannel, int *status);


	unsigned char _reqID;
	unsigned char *_txBuffer;
	Thread *_rxThread;
	HECICallback _cb;
	void *_cbParam;
	Semaphore _initLock;
	Semaphore _sendMessageLock;
	INIT_STATES _initState;
	Event _threadStartedEvent;
#if defined(__sun) || defined(_LINUX)
	HECILinux _heci;
#else
	HECIWin _heci;
#endif

	//BACKWARD COMPATIBLE PRIVATE - BEGIN
	static const GUID _guidCompat;

	void _doRXCompat();

	struct CompatConnection {
		Event *event;
		int connID;
		UINT8 status;
	};
	typedef std::map<int, CompatConnection> CompatConnMap;
	CompatConnMap _compatPendingConnections;
	Semaphore _compatMapLock;
#if defined(__sun) || defined(_LINUX)
	HECILinux _heciCompat;
#else
	HECIWin _heciCompat;
#endif
	//BACKWARD COMPATIBLE PRIVATE - END

	HECI *_pHeci;
};

#endif
