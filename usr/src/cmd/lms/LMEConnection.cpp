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
#include "LMS_if.h"
#include "Lock.h"
#include "glue.h"

#if defined(__sun) || defined(_LINUX)
#include <netinet/in.h>
#define _strnicmp strncasecmp
#endif	// __sun || _LINUX

#define HECI_IO_TIMEOUT 5000

extern glue plugin;

const GUID LMEConnection::_guid = {0x6733a4db, 0x0476, 0x4e7b, {0xb3, 0xaf, 0xbc, 0xfc, 0x29, 0xbe, 0xe7, 0xa7}};

const UINT32 LMEConnection::RX_WINDOW_SIZE = 1024;

LMEConnection::LMEConnection(bool verbose) :
_reqID(0),
_txBuffer(NULL),
_rxThread(NULL),
_cb(NULL),
_cbParam(NULL),
_initState(INIT_STATE_DISCONNECTED),
_heci(_guid, verbose),
_heciCompat(_guidCompat, verbose),
_pHeci(NULL)
{
}

LMEConnection::~LMEConnection()
{
}

bool LMEConnection::IsInitialized()
{
	Lock il(_initLock);
	return ((_initState == INIT_STATE_CONNECTED) ? true : false);
}

bool LMEConnection::Init(HECICallback cb, void *param)
{
	Lock il(_initLock);

	if (_initState == INIT_STATE_CONNECTING) {
		return false;
	}
	_initState = INIT_STATE_CONNECTING;

	_cb = cb;
	_cbParam = param;

	if (_heci.Init(LMS_PROCOL_VERSION)) {
		protocolVer = _heci.GetProtocolVersion();
		_pHeci = &_heci;
	} else if (_heciCompat.Init()) {
		protocolVer = _heciCompat.GetProtocolVersion();
		if (protocolVer > LMS_PROCOL_VERSION_COMPAT) {
			_heciCompat.Deinit();
			_initState = INIT_STATE_DISCONNECTED;
			return false;
		}
		_pHeci = &_heciCompat;
	} else {
		_initState = INIT_STATE_DISCONNECTED;
		return false;
	}

	_initState = INIT_STATE_CONNECTED;

	plugin.version(protocolVer);

	// launch RX thread
	_txBuffer = new unsigned char[_pHeci->GetBufferSize()];
	_rxThread = new Thread(_rxThreadFunc, this);
	_rxThread->start();

	_threadStartedEvent.wait();
	return true;
}

void LMEConnection::Deinit()
{
	Lock il(_initLock);

	_initState = INIT_STATE_DISCONNECTED;

	if (_pHeci != NULL) {
		_pHeci->Deinit();
		_pHeci = NULL;
	}

	if (_rxThread != NULL) {
		delete _rxThread;
		_rxThread = NULL;
	}

	if (_txBuffer != NULL) {
		delete[] _txBuffer;
		_txBuffer = NULL;
	}
}

bool LMEConnection::Disconnect(APF_DISCONNECT_REASON_CODE reasonCode)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	unsigned char buf[sizeof(APF_DISCONNECT_MESSAGE)];

	APF_DISCONNECT_MESSAGE *disconnectMessage = (APF_DISCONNECT_MESSAGE *)buf;

	memset(disconnectMessage, 0, sizeof(buf));
	disconnectMessage->MessageType = APF_DISCONNECT;
	disconnectMessage->ReasonCode = htonl(reasonCode);

	PRINT("Sending disconnect to LME.\n");
	int res = _sendMessage(buf, sizeof(buf));

	return (res == sizeof(buf));
}

bool LMEConnection::ServiceAccept(std::string serviceName)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	//APF_SERVICE_ACCEPT_MESSAGE
	//memcpy(pCurrent, "127.0.0.1", APF_STR_SIZE_OF("127.0.0.1"));
	//pCurrent += APF_STR_SIZE_OF("127.0.0.1");
	unsigned char *buf = new unsigned char[sizeof(APF_SERVICE_ACCEPT_MESSAGE) + serviceName.length()];
	if (buf == NULL) {
		PRINT("Failed to allocate memory for ServiceAccept.\n");
		return false;
	}

	unsigned char *pCurrent = buf;
	*pCurrent = APF_SERVICE_ACCEPT;
	++pCurrent;
	*((UINT32 *)pCurrent) = htonl(serviceName.size());
	pCurrent += 4;

	memcpy(pCurrent, serviceName.c_str(), serviceName.size());
	pCurrent += serviceName.size();

	PRINT("Sending service accept to LME: %s\n", serviceName.c_str());
	int len = pCurrent - buf;
	int res = _sendMessage(buf, len);

	delete [] buf;

	return (res == len);
}

bool LMEConnection::UserAuthSuccess()
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	unsigned char buf = APF_USERAUTH_SUCCESS;

	PRINT("Sending user authentication success to LME.\n");
	int res = _sendMessage(&buf, sizeof(buf));

	return (res == sizeof(buf));
}

bool LMEConnection::ProtocolVersion(const LMEProtocolVersionMessage versionMessage)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_PROTOCOL_VERSION_MESSAGE protVersion;
	memset(&protVersion, 0, sizeof(protVersion));

	protVersion.MessageType = APF_PROTOCOLVERSION;
	protVersion.MajorVersion = htonl(versionMessage.MajorVersion);
	protVersion.MinorVersion = htonl(versionMessage.MinorVersion);
	protVersion.TriggerReason = htonl(versionMessage.TriggerReason);

	PRINT("Sending protocol version to LME: %d.%d\n", versionMessage.MajorVersion, versionMessage.MinorVersion);
	int res = _sendMessage((unsigned char *)&protVersion, sizeof(protVersion));

	return (res == sizeof(protVersion));
}

bool LMEConnection::TcpForwardReplySuccess(UINT32 port)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_TCP_FORWARD_REPLY_MESSAGE message;

	message.MessageType = APF_REQUEST_SUCCESS;
	message.PortBound = htonl(port);

	PRINT("Sending TCP forward replay success to LME: Port %d.\n", port);
	int res = _sendMessage((unsigned char *)&message, sizeof(message));

	return (res == sizeof(message));
}

bool LMEConnection::TcpForwardReplyFailure()
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	unsigned char buf = APF_REQUEST_FAILURE;

	PRINT("Sending TCP forward replay failure to LME.\n");
	int res = _sendMessage(&buf, sizeof(buf));

	return (res == sizeof(buf));
}

bool LMEConnection::TcpForwardCancelReplySuccess()
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	unsigned char buf = APF_REQUEST_SUCCESS;

	PRINT("Sending TCP forward cancel replay success to LME.\n");
	int res = _sendMessage(&buf, sizeof(buf));

	return (res == sizeof(buf));
}

bool LMEConnection::TcpForwardCancelReplyFailure()
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	unsigned char buf = APF_REQUEST_FAILURE;

	PRINT("Sending TCP forward cancel replay failure to LME.\n");
	int res = _sendMessage(&buf, sizeof(buf));

	return (res == sizeof(buf));
}

bool LMEConnection::ChannelOpenForwardedRequest(UINT32 senderChannel,
						UINT32 connectedPort,
						std::string originatorIP,
						UINT32 originatorPort)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	unsigned char buf[5 + APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED) + 16 +
		APF_STR_SIZE_OF("127.0.0.1") + 8 +  16  + 4];
	unsigned char *pCurrent = buf;

	if (originatorIP.size() > 16) {
		return false;
	}

	*pCurrent = APF_CHANNEL_OPEN;
	++pCurrent;

	*((UINT32 *)pCurrent) = htonl(APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED));
	pCurrent += sizeof(UINT32);

	memcpy(pCurrent, APF_OPEN_CHANNEL_REQUEST_FORWARDED, APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED));
	pCurrent += APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_FORWARDED);

	*((UINT32 *)pCurrent) = htonl(senderChannel);
	pCurrent += sizeof(UINT32);

	*((UINT32 *)pCurrent) = htonl(RX_WINDOW_SIZE);
	pCurrent += sizeof(UINT32);

	*((UINT32 *)pCurrent) = 0xFFFFFFFF;
	pCurrent += sizeof(UINT32);

	*((UINT32 *)pCurrent) = htonl(APF_STR_SIZE_OF("127.0.0.1"));
	pCurrent += sizeof(UINT32);

	memcpy(pCurrent, "127.0.0.1", APF_STR_SIZE_OF("127.0.0.1"));
	pCurrent += APF_STR_SIZE_OF("127.0.0.1");

	*((UINT32 *)pCurrent) = htonl(connectedPort);
	pCurrent += sizeof(UINT32);

	*((UINT32 *)pCurrent) = htonl((UINT32)originatorIP.size());
	pCurrent += sizeof(UINT32);

	memcpy(pCurrent, originatorIP.c_str(), originatorIP.size());
	pCurrent += originatorIP.size();

	*((UINT32 *)pCurrent) = htonl(originatorPort);
	pCurrent += sizeof(UINT32);

	PRINT("Sending channel open request to LME. Address: %s, requested port: %d.\n",
		originatorIP.c_str(), connectedPort);
	int res = _sendMessage(buf, (int)(pCurrent - buf));

	return (res == pCurrent - buf);
}

bool LMEConnection::ChannelOpenReplaySuccess(UINT32 recipientChannel,
					     UINT32 senderChannel)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE message;

	message.MessageType = APF_CHANNEL_OPEN_CONFIRMATION;
	message.RecipientChannel = htonl(recipientChannel);
	message.SenderChannel = htonl(senderChannel);
	message.InitialWindowSize = htonl(RX_WINDOW_SIZE);
	message.Reserved = 0xFFFFFFFF;

	PRINT("Sending channel open replay success to LME. Recipient: %d.\n", recipientChannel);
	int res = _sendMessage((unsigned char *)&message, sizeof(message));

	return (res == sizeof(message));
}

bool LMEConnection::ChannelOpenReplayFailure(UINT32 recipientChannel,
					     UINT32 reason)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_CHANNEL_OPEN_FAILURE_MESSAGE message;

	message.MessageType = APF_CHANNEL_OPEN_FAILURE;
	message.RecipientChannel = htonl(recipientChannel);
	message.ReasonCode = htonl(reason);
	message.Reserved = 0x00000000;
	message.Reserved2 = 0x00000000;

	PRINT("Sending channel open replay failure to LME. Recipient: %d, Reason: %d.\n", recipientChannel, reason);
	int res = _sendMessage((unsigned char *)&message, sizeof(message));

	return (res == sizeof(message));
}

bool LMEConnection::ChannelClose(UINT32 recipientChannel)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_CHANNEL_CLOSE_MESSAGE message;

	message.MessageType = APF_CHANNEL_CLOSE;
	message.RecipientChannel = htonl(recipientChannel);

	PRINT("Sending channel close to LME. Recipient: %d.\n", recipientChannel);
	int res = _sendMessage((unsigned char *)&message, sizeof(message));

	return (res == sizeof(message));
}

int LMEConnection::ChannelData(UINT32 recipientChannel,
			       UINT32 len, unsigned char *buffer)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_CHANNEL_DATA_MESSAGE *message;

	if (len > _heci.GetBufferSize() - sizeof(APF_CHANNEL_DATA_MESSAGE)) {
		return -1;
	}

	message = (APF_CHANNEL_DATA_MESSAGE *)_txBuffer;
	message->MessageType = APF_CHANNEL_DATA;
	message->RecipientChannel = htonl(recipientChannel);
	message->DataLength = htonl(len);
	memcpy(message->Data, buffer, len);

	PRINT("Sending %d bytes to recipient channel %d.\n", len, recipientChannel);
	return _sendMessage((unsigned char *)message, sizeof(APF_CHANNEL_DATA_MESSAGE) + len);
}

bool LMEConnection::ChannelWindowAdjust(UINT32 recipientChannel, UINT32 len)
{
	if (!IsInitialized()) {
		PRINT("State: not connected to HECI.\n");
		return false;
	}

	APF_WINDOW_ADJUST_MESSAGE message;

	message.MessageType = APF_CHANNEL_WINDOW_ADJUST;
	message.RecipientChannel = htonl(recipientChannel);
	message.BytesToAdd = htonl(len);

	PRINT("Sending Window Adjust with %d bytes to recipient channel %d.\n", len, recipientChannel);
	int res = _sendMessage((unsigned char *)&message, sizeof(message));

	return (res == sizeof(message));
}

int LMEConnection::_receiveMessage(unsigned char *buffer, int len)
{
	int result;

	if (!IsInitialized()) {
		return -1;
	}

	result = _pHeci->ReceiveMessage(buffer, len, WAIT_INFINITE);

	if (result < 0 && errno == ENOENT) {
		Lock il(_initLock);
		_initState = INIT_STATE_DISCONNECTED;
	}

	return result;
}

int LMEConnection::_sendMessage(unsigned char *buffer, int len)
{
	int result;

	if (!IsInitialized()) {
		return -1;
	}

	_sendMessageLock.acquire();
	result = _pHeci->SendMessage(buffer, len, HECI_IO_TIMEOUT);
	_sendMessageLock.release();

	if (result < 0 && errno == ENOENT) {
		Lock il(_initLock);
		_initState = INIT_STATE_DISCONNECTED;
	}

	return result;
}

void LMEConnection::_rxThreadFunc(void *param)
{
	LMEConnection *connection = (LMEConnection *)param;

	try {
		if (LMS_PROCOL_VERSION == connection->protocolVer) {
			connection->_doRX();
		} else if (LMS_PROCOL_VERSION_COMPAT == connection->protocolVer) {
			connection->_doRXCompat();
		}
	}
	catch (...) {
		PRINT("LMEConnection do RX exception\n");
	}
	pthread_exit(NULL);
}

bool LMEConnection::_checkMinMsgSize(unsigned char *buf, unsigned int bytesRead)
{
	switch (buf[0]) {
	case APF_DISCONNECT:
		if (bytesRead < sizeof(APF_DISCONNECT_MESSAGE)) {
			return false;
		}
		break;
	case APF_SERVICE_REQUEST:
		if (bytesRead < sizeof(APF_SERVICE_REQUEST)) {
			return false;
		}
		if (bytesRead < (sizeof(APF_SERVICE_REQUEST) +
			ntohl(((APF_SERVICE_REQUEST_MESSAGE *)buf)->ServiceNameLength))) {
			return false;
		}
		break;
	case APF_USERAUTH_REQUEST:
		if (bytesRead < (3 * sizeof(UINT32))) {
			return false;
		}
		break;
	case APF_GLOBAL_REQUEST:
		if (bytesRead < (sizeof(APF_GENERIC_HEADER) + sizeof(UINT8))) {
			return false;
		}
		if (bytesRead < (sizeof(APF_GENERIC_HEADER) + sizeof(UINT8) +
			ntohl(((APF_GENERIC_HEADER *)buf)->StringLength))) {
			return false;
		}
		break;
	case APF_CHANNEL_OPEN:
		if (bytesRead < sizeof(APF_GENERIC_HEADER)) {
			return false;
		}
		if (bytesRead < (sizeof(APF_GENERIC_HEADER) +
			ntohl(((APF_GENERIC_HEADER *)buf)->StringLength))) {
			return false;
		}
		break;
	case APF_CHANNEL_OPEN_CONFIRMATION:
		if (bytesRead < sizeof(APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE)) {
			return false;
		}
		break;
	case APF_CHANNEL_OPEN_FAILURE:
		if (bytesRead < sizeof(APF_CHANNEL_OPEN_FAILURE_MESSAGE)) {
			return false;
		}
		break;
	case APF_CHANNEL_CLOSE:
		if (bytesRead < sizeof(APF_CHANNEL_CLOSE_MESSAGE)) {
			return false;
		}
		break;
	case APF_CHANNEL_DATA:
		if (bytesRead < sizeof(APF_CHANNEL_DATA_MESSAGE)) {
			return false;
		}
		if (bytesRead < (sizeof(APF_CHANNEL_DATA_MESSAGE) +
			ntohl(((APF_CHANNEL_DATA_MESSAGE *)buf)->DataLength))) {
			return false;
		}
		break;
	case APF_CHANNEL_WINDOW_ADJUST:
		if (bytesRead < sizeof(APF_WINDOW_ADJUST_MESSAGE)) {
			return false;
		}
		break;
	case APF_PROTOCOLVERSION:
		if (bytesRead < sizeof(APF_PROTOCOL_VERSION_MESSAGE)) {
			return false;
		}
		break;
	default:
		return false;
	}
	return true;
}

void LMEConnection::_doRX()
{
	unsigned int bytesRead;
	int status = 1;

	_threadStartedEvent.set();

	unsigned char *rxBuffer = new unsigned char[_heci.GetBufferSize()];

	while (true) {
		bytesRead = (unsigned int)_receiveMessage(rxBuffer, _heci.GetBufferSize());

		if ((int)bytesRead < 0) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			break;
		}

		if (bytesRead == 0) {
			// ERROR
			continue;
		}

		PRINT("Received from LME %d bytes (msg type %02d)\n", bytesRead, rxBuffer[0]);

		if (!_checkMinMsgSize(rxBuffer, bytesRead)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			break;
		}

		if (plugin.preprocess(rxBuffer, bytesRead) == LMS_DROPPED) {
			continue;
		}

		switch (rxBuffer[0]) {
		case APF_DISCONNECT:
			{
				LMEDisconnectMessage disconnectMessage(
				    (APF_DISCONNECT_REASON_CODE)ntohl(
					((APF_DISCONNECT_MESSAGE *)rxBuffer)->ReasonCode));

				_cb(_cbParam, &disconnectMessage, sizeof(disconnectMessage), &status);
			}
			break;

		case APF_SERVICE_REQUEST:
			{
				APF_SERVICE_REQUEST_MESSAGE *pMessage =
					(APF_SERVICE_REQUEST_MESSAGE *)rxBuffer;
				LMEServiceRequestMessage serviceRequestMessage;

				serviceRequestMessage.ServiceName.append(
					(char *)(pMessage->ServiceName),
					ntohl(pMessage->ServiceNameLength));

				_cb(_cbParam, &serviceRequestMessage, sizeof(serviceRequestMessage), &status);
			}
			break;

		case APF_USERAUTH_REQUEST:
			_apfUserAuthRequest(rxBuffer, bytesRead, &status);
			break;

		case APF_GLOBAL_REQUEST:
			_apfGlobalRequest(rxBuffer, bytesRead, &status);
			break;

		case APF_CHANNEL_OPEN:
			_apfChannelOpen(rxBuffer, bytesRead, &status);
			break;

		case APF_CHANNEL_OPEN_CONFIRMATION:
			{
				APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE *pMessage =
				    (APF_CHANNEL_OPEN_CONFIRMATION_MESSAGE *)rxBuffer;
				LMEChannelOpenReplaySuccessMessage channelOpenReply;

				channelOpenReply.RecipientChannel = ntohl(pMessage->RecipientChannel);
				channelOpenReply.SenderChannel = ntohl(pMessage->SenderChannel);
				channelOpenReply.InitialWindow = ntohl(pMessage->InitialWindowSize);
				_cb(_cbParam, &channelOpenReply, sizeof(channelOpenReply), &status);
			}
			break;

		case APF_CHANNEL_OPEN_FAILURE:
			{
				APF_CHANNEL_OPEN_FAILURE_MESSAGE *pMessage =
				    (APF_CHANNEL_OPEN_FAILURE_MESSAGE *)rxBuffer;
				LMEChannelOpenReplayFailureMessage channelOpenReply;

				channelOpenReply.RecipientChannel = ntohl(pMessage->RecipientChannel);
				channelOpenReply.ReasonCode =
					(OPEN_FAILURE_REASON)(ntohl(pMessage->ReasonCode));
				_cb(_cbParam, &channelOpenReply, sizeof(channelOpenReply), &status);
			}
			break;

		case APF_CHANNEL_CLOSE:
			{
				APF_CHANNEL_CLOSE_MESSAGE *pMessage =
				    (APF_CHANNEL_CLOSE_MESSAGE *)rxBuffer;
				LMEChannelCloseMessage channelClose;

				channelClose.RecipientChannel = ntohl(pMessage->RecipientChannel);
				_cb(_cbParam, &channelClose, sizeof(channelClose), &status);
			}
			break;

		case APF_CHANNEL_DATA:
			{
				APF_CHANNEL_DATA_MESSAGE *pMessage =
				    (APF_CHANNEL_DATA_MESSAGE *)rxBuffer;
				LMEChannelDataMessage channelData(ntohl(pMessage->RecipientChannel),
								  ntohl(pMessage->DataLength),
								  pMessage->Data);
				_cb(_cbParam, &channelData, sizeof(channelData), &status);
			}
			break;

		case APF_CHANNEL_WINDOW_ADJUST:
			{
				APF_WINDOW_ADJUST_MESSAGE *pMessage =
				    (APF_WINDOW_ADJUST_MESSAGE *)rxBuffer;
				LMEChannelWindowAdjustMessage channelWindowAdjust;

				channelWindowAdjust.RecipientChannel = ntohl(pMessage->RecipientChannel);
				channelWindowAdjust.BytesToAdd = ntohl(pMessage->BytesToAdd);
				_cb(_cbParam, &channelWindowAdjust, sizeof(channelWindowAdjust), &status);
			}
			break;

		case APF_PROTOCOLVERSION:
			{
				APF_PROTOCOL_VERSION_MESSAGE *pMessage =
				    (APF_PROTOCOL_VERSION_MESSAGE *)rxBuffer;
				LMEProtocolVersionMessage protVersion;

				protVersion.MajorVersion = ntohl(pMessage->MajorVersion);
				protVersion.MinorVersion = ntohl(pMessage->MinorVersion);
				protVersion.TriggerReason =
					(APF_TRIGGER_REASON)ntohl(pMessage->TriggerReason);
				_cb(_cbParam, &protVersion, sizeof(protVersion), &status);
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

void LMEConnection::_apfChannelOpen(unsigned char *rxBuffer, unsigned int bytesRead, int *status)
{
	APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

	if (_strnicmp((char *)pHeader->String,
		APF_OPEN_CHANNEL_REQUEST_DIRECT,
		APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT)) == 0) {

		UINT32 senderChannel = 0;

		_apfChannelOpenDirect(rxBuffer, bytesRead, &senderChannel, status);
		if (IsInitialized() && (*status == 1)) {
			if (plugin.retry(rxBuffer, bytesRead) != LMS_DROPPED) {
				_apfChannelOpenDirect(rxBuffer, bytesRead, NULL, status);
			}
		}
		if (IsInitialized() && (*status == 1)) {
			ChannelOpenReplayFailure(senderChannel,
			    OPEN_FAILURE_REASON_CONNECT_FAILED);
		}
	}
}

void LMEConnection::_apfChannelOpenDirect(unsigned char *rxBuffer, unsigned int bytesRead, UINT32 *senderChannel, int *status)
{
	unsigned char *pCurrent;
	APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

	if (bytesRead < sizeof(APF_GENERIC_HEADER) +
	    ntohl(pHeader->StringLength) +
	    7 + (5 * sizeof(UINT32))) {
		PRINT("Error receiving data from HECI\n");
		Deinit();
		return;
	}

	pCurrent = rxBuffer + sizeof(APF_GENERIC_HEADER) +
		APF_STR_SIZE_OF(APF_OPEN_CHANNEL_REQUEST_DIRECT);

	LMEChannelOpenRequestMessage channelOpenRequest;
	channelOpenRequest.ChannelType = LMEChannelOpenRequestMessage::DIRECT;

	channelOpenRequest.SenderChannel = ntohl(*((UINT32 *)pCurrent));
	if (senderChannel) {
		*senderChannel = channelOpenRequest.SenderChannel;
	}
	pCurrent += sizeof(UINT32);
	channelOpenRequest.InitialWindow = ntohl(*((UINT32 *)pCurrent));
	pCurrent += 2 * sizeof(UINT32);

	UINT32 len = ntohl(*((UINT32 *)pCurrent));
	pCurrent += sizeof(UINT32);
	channelOpenRequest.Address.append((char *)pCurrent, len);
	pCurrent += len;
	channelOpenRequest.Port = ntohl(*((UINT32 *)pCurrent));
	pCurrent += sizeof(UINT32);

	_cb(_cbParam, &channelOpenRequest, sizeof(channelOpenRequest), status);
}

void LMEConnection::_apfGlobalRequest(unsigned char *rxBuffer, unsigned int bytesRead, int *status)
{
	unsigned char *pCurrent;
	APF_GENERIC_HEADER *pHeader = (APF_GENERIC_HEADER *)rxBuffer;

	if (_strnicmp((char *)pHeader->String,
	    APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST,
	    APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST)) == 0) {
		LMETcpForwardRequestMessage tcpForwardRequest;
		unsigned int hsize = sizeof(APF_GENERIC_HEADER) +
		    APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_REQUEST) +
		    sizeof(UINT8);
		pCurrent = rxBuffer + hsize;
		bytesRead -= hsize;

		if (bytesRead < sizeof(UINT32)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		UINT32 len = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if (bytesRead < (sizeof(UINT32) + len + sizeof(UINT32))) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		tcpForwardRequest.Address.append((char *)pCurrent, len);
		pCurrent += len;
		tcpForwardRequest.Port = ntohl(*((UINT32 *)pCurrent));

		_cb(_cbParam, &tcpForwardRequest, sizeof(tcpForwardRequest), status);
	}
	else if (_strnicmp((char *)pHeader->String,
	    APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST,
	    APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST)) == 0) {
		LMETcpForwardCancelRequestMessage tcpForwardCancelRequest;
		unsigned int hsize = sizeof(APF_GENERIC_HEADER) +
		    APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_TCP_FORWARD_CANCEL_REQUEST) +
		    sizeof(UINT8);
		pCurrent = rxBuffer + hsize;
		bytesRead -= hsize;

		if (bytesRead < sizeof(UINT32)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		UINT32 len = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if (bytesRead < (sizeof(UINT32) + len + sizeof(UINT32))) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		tcpForwardCancelRequest.Address.append((char *)pCurrent, len);
		pCurrent += len;
		tcpForwardCancelRequest.Port = ntohl(*((UINT32 *)pCurrent));

		_cb(_cbParam, &tcpForwardCancelRequest, sizeof(tcpForwardCancelRequest), status);
	}
	else if (_strnicmp((char *)pHeader->String,
	    APF_GLOBAL_REQUEST_STR_UDP_SEND_TO,
	    APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_UDP_SEND_TO)) == 0) {
		unsigned int hsize = sizeof(APF_GENERIC_HEADER) +
		    APF_STR_SIZE_OF(APF_GLOBAL_REQUEST_STR_UDP_SEND_TO) +
		    sizeof(UINT8);
		pCurrent = rxBuffer + hsize;
		bytesRead -= hsize;

		if (bytesRead < sizeof(UINT32)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		UINT32 len = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if (bytesRead < (sizeof(UINT32) + len + sizeof(UINT32))) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}
		bytesRead -= (sizeof(UINT32) + len + sizeof(UINT32));

		std::string address;
		address.append((char *)pCurrent, len);
		pCurrent += len;
		UINT32 port = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if (bytesRead < sizeof(UINT32)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		// Skip Originator IP and Port
		len = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if (bytesRead < (sizeof(UINT32) + len + sizeof(UINT32))) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}
		bytesRead -= (sizeof(UINT32) + len + sizeof(UINT32));

		pCurrent += len;
		pCurrent += sizeof(UINT32);

		if (bytesRead < sizeof(UINT32)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		// Retrieve Data
		len = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if (bytesRead < (sizeof(UINT32) + len)) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		LMEUdpSendToMessage udpSendTo(address, port, len, pCurrent);

		_cb(_cbParam, &udpSendTo, sizeof(udpSendTo), status);
	}
}

void LMEConnection::_apfUserAuthRequest(unsigned char *rxBuffer, unsigned int bytesRead, int *status)
{
	unsigned char *pCurrent = rxBuffer;

	++pCurrent;

	LMEUserAuthRequestMessage userAuthRequest;

	UINT32 len = ntohl(*((UINT32 *)pCurrent));
	pCurrent += sizeof(UINT32);

	if ((bytesRead - (pCurrent - rxBuffer)) < len) {
		PRINT("Error receiving data from HECI\n");
		Deinit();
		return;
	}

	userAuthRequest.Username.append((char *)pCurrent, len);
	pCurrent += len;

	if ((unsigned int)(bytesRead - (pCurrent - rxBuffer)) < sizeof(UINT32)) {
		PRINT("Error receiving data from HECI\n");
		Deinit();
		return;
	}

	len = ntohl(*((UINT32 *)pCurrent));
	pCurrent += sizeof(UINT32);

	if ((bytesRead - (pCurrent - rxBuffer)) < len) {
		PRINT("Error receiving data from HECI\n");
		Deinit();
		return;
	}

	userAuthRequest.ServiceName.append((char *)pCurrent, len);
	pCurrent += len;

	if ((unsigned int)(bytesRead - (pCurrent - rxBuffer)) < sizeof(UINT32)) {
		PRINT("Error receiving data from HECI\n");
		Deinit();
		return;
	}

	len = ntohl(*((UINT32 *)pCurrent));
	pCurrent += sizeof(UINT32);

	if ((bytesRead - (pCurrent - rxBuffer)) < len) {
		PRINT("Error receiving data from HECI\n");
		Deinit();
		return;
	}

	userAuthRequest.MethodName.append((char *)pCurrent, len);
	pCurrent += len;

	if (_strnicmp(userAuthRequest.MethodName.c_str(), APF_AUTH_PASSWORD,
			userAuthRequest.MethodName.size()) == 0) {

		if ((unsigned int)(bytesRead - (pCurrent - rxBuffer)) < sizeof(UINT32) + 1) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		++pCurrent;

		len = ntohl(*((UINT32 *)pCurrent));
		pCurrent += sizeof(UINT32);

		if ((bytesRead - (pCurrent - rxBuffer)) < len) {
			PRINT("Error receiving data from HECI\n");
			Deinit();
			return;
		}

		AuthPasswordData authData;
		authData.Password.append((char *)pCurrent, len);
		pCurrent += len;

		userAuthRequest.MethodData = &authData;
	}

	_cb(_cbParam, &userAuthRequest, sizeof(userAuthRequest), status);
}

unsigned int LMEConnection::GetHeciBufferSize() const
{
	if (_pHeci == NULL) {
		return 0;
	}
	return _pHeci->GetBufferSize();
}

