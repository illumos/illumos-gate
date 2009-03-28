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

//----------------------------------------------------------------------------
//
//  File:       PTHICommand.cpp
//
//----------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cstdio>
#include <cstdlib>
#include "PTHICommand.h"


PTHICommand::PTHICommand(bool verbose, unsigned long sendTimeout) :
PTHIClient(HECI_PTHI, verbose),
m_sendTimeout(sendTimeout)
{
}

PTHICommand::~PTHICommand(void)
{
}

AMT_STATUS PTHICommand::_call(const unsigned char *command, UINT32 command_size, UINT8 **readBuffer, UINT32 rcmd, unsigned int expSize)
{
	UINT32 inBuffSize;
	UINT32 outBuffSize = 0;

	inBuffSize = PTHIClient.GetBufferSize();
	*readBuffer = (UINT8 *)malloc(sizeof(UINT8) * inBuffSize);
	if (NULL == *readBuffer)
	{
		return PTSDK_STATUS_RESOURCES;
	}
	memset(*readBuffer, 0, inBuffSize);

	int bytesWritten = PTHIClient.SendMessage(command, command_size, m_sendTimeout);
	if ((UINT32)bytesWritten != command_size)
	{
		return AMT_STATUS_INTERNAL_ERROR;
	}
	outBuffSize = PTHIClient.ReceiveMessage(*readBuffer, inBuffSize);
	if (0 == outBuffSize)
	{
		return PTHI_STATUS_EMPTY_RESPONSE;
	}
	AMT_STATUS status = ((PTHI_RESPONSE_MESSAGE_HEADER *)*readBuffer)->Status;
	if (status != AMT_STATUS_SUCCESS)
	{
		return status;
	}
	status = _verifyResponseHeader(rcmd, ((PTHI_RESPONSE_MESSAGE_HEADER *)*readBuffer)->Header, outBuffSize);
	if (status != AMT_STATUS_SUCCESS)
	{
		return status;
	}
	if ((expSize != 0) && (expSize != outBuffSize))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Confirms the correctness of the response message header
* and the response message size
* Arguments:
*	command	- appropriate Host interface command
*	response_header	- reference to the response message header
*	response_size	- value that holds the actual size of the
*                         response message
*	expected_size	- value that holds the expected size of the
*                         response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyResponseHeader(
	const UINT32 command, const PTHI_MESSAGE_HEADER &response_header,
	UINT32 response_size)
{
	AMT_STATUS status = AMT_STATUS_SUCCESS;

	if (response_size < sizeof(PTHI_RESPONSE_MESSAGE_HEADER)) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_size != (response_header.Length + sizeof(PTHI_MESSAGE_HEADER))) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_header.Command.cmd.val != command) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_header.Reserved != 0) {
		status = AMT_STATUS_INTERNAL_ERROR;
	} else if (response_header.Version.MajorNumber != AMT_MAJOR_VERSION
		|| response_header.Version.MinorNumber < AMT_MINOR_VERSION) {
			status = AMT_STATUS_INTERNAL_ERROR;
	}

	return status;
}

/*
* Confirms the correctness of the GetCodeVersions response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyCodeVersions(
	const CFG_GET_CODE_VERSIONS_RESPONSE &response)
{
	AMT_STATUS status = AMT_STATUS_SUCCESS;
	UINT32 codeVerLen;
	UINT32 ptVerTypeCount;
	UINT32 len = 0;
	UINT32 i;

	do {
		codeVerLen = response.Header.Header.Length - sizeof(AMT_STATUS);
		ptVerTypeCount = codeVerLen - sizeof(response.CodeVersions.BiosVersion)- sizeof(response.CodeVersions.VersionsCount);
		if (response.CodeVersions.VersionsCount != (ptVerTypeCount/sizeof(AMT_VERSION_TYPE)))
		{
			status = AMT_STATUS_INTERNAL_ERROR;
			break;
		}

		for (i = 0; i < (response.CodeVersions.VersionsCount); i ++)
		{
			len = response.CodeVersions.Versions[i].Description.Length;

			if (len > UNICODE_STRING_LEN)
			{
				status = AMT_STATUS_INTERNAL_ERROR;
				break;
			}

			len = response.CodeVersions.Versions[i].Version.Length;
			if (response.CodeVersions.Versions[i].Version.String[len] != '\0' ||
				(len != strlen((CHAR *)(response.CodeVersions.Versions[i].Version.String))))
			{
				status = AMT_STATUS_INTERNAL_ERROR;
				break;
			}
		}
	} while (0);

	return status;
}

/*
* GetVersions response message PTHI command
* Arguments:
*	response - reference to the CODE_VERSIONS struct
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	AMT_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::GetCodeVersions(CODE_VERSIONS &codeVersions)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_CODE_VERSION_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_CODE_VERSION_HEADER), sizeof(GET_CODE_VERSION_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, CODE_VERSIONS_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_CODE_VERSIONS_RESPONSE *tmp_response = (CFG_GET_CODE_VERSIONS_RESPONSE *)readBuffer;
		status = _verifyCodeVersions(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		memcpy(&codeVersions, &(tmp_response->CodeVersions), sizeof(CODE_VERSIONS));

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetProvisioningMode Host interface command
* Arguments:
*	mode - reference to the pre-allocated structure
*       which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetProvisioningMode(CFG_PROVISIONING_MODE &mode)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_PROVISIONING_MODE_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_PROVISIONING_MODE_HEADER), sizeof(GET_PROVISIONING_MODE_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, PROVISIONING_MODE_RESPONSE, sizeof(CFG_GET_PROVISIONING_MODE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_PROVISIONING_MODE_RESPONSE *tmp_response = (CFG_GET_PROVISIONING_MODE_RESPONSE *)readBuffer;

		mode = tmp_response->ProvisioningMode;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}
AMT_STATUS PTHICommand::GetProvisioningMode(CFG_PROVISIONING_MODE &mode, AMT_BOOLEAN &legacy)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_PROVISIONING_MODE_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_PROVISIONING_MODE_HEADER), sizeof(GET_PROVISIONING_MODE_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, PROVISIONING_MODE_RESPONSE, sizeof(CFG_GET_PROVISIONING_MODE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_PROVISIONING_MODE_RESPONSE *tmp_response = (CFG_GET_PROVISIONING_MODE_RESPONSE *)readBuffer;

		mode = tmp_response->ProvisioningMode;
		legacy = tmp_response->LegacyMode;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetProvisioningState Host interface command
* Arguments:
*	state - reference to the pre-allocated structure
*       which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetProvisioningState(AMT_PROVISIONING_STATE &state)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_PROVISIONING_STATE_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_PROVISIONING_STATE_HEADER), sizeof(GET_PROVISIONING_STATE_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, PROVISIONING_STATE_RESPONSE, sizeof(CFG_GET_PROVISIONING_STATE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_PROVISIONING_STATE_RESPONSE *tmp_response = (CFG_GET_PROVISIONING_STATE_RESPONSE *)readBuffer;

		state = tmp_response->ProvisioningState;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetFeatureState Host interface command
* Arguments:
*	requestID Indicates what feature status to query:
*		0	Redirection Sessions Status
*		1	System Defense Status
*		2	WebUI Status
*  requestStatus The requested feature state(the size depand on the requestID).(OUT)
*
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetFeaturesState(UINT32 requestID, AMT_BOOLEAN (&requestStatus)[2])
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(CFG_GET_FEATURES_STATE_REQUEST);
	unsigned char command[command_size];

	memcpy(command, &GET_FEATURES_STATE_HEADER, sizeof(GET_FEATURES_STATE_HEADER));
	memcpy(command + sizeof(GET_FEATURES_STATE_HEADER), &(requestID), sizeof(UINT32));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_FEATURES_STATE_RESPONSE, sizeof(CFG_GET_FEATURES_STATE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_FEATURES_STATE_RESPONSE *tmp_response = (CFG_GET_FEATURES_STATE_RESPONSE *)readBuffer;

		GET_FEATURES_REDIRECTION_SESSION_STATUS redirectionState;
		GET_FEATURES_SYSTEM_DEFENSE_STATUS_RESPONSE systemDefenseState;
		GET_FEATURES_WEB_UI_STATUS_RESPONSE webUIState;
		switch (requestID)
		{
		case REDIRECTION_SESSION:
			redirectionState = tmp_response->Data.rs;
			requestStatus[0] = redirectionState.SolOpen;
			requestStatus[1] = redirectionState.IderOpen;
			break;

		case SYSTEM_DEFENSE:
			systemDefenseState = tmp_response->Data.sd;
			requestStatus[0] = systemDefenseState.SystemDefenseActivated;
			break;

		case WEB_UI:
			webUIState = tmp_response->Data.webUI;
			requestStatus[0] = webUIState.WebUiEnabled;
			break;
		}
	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetLastHostResetReason Host interface command
* Arguments:
*	reason Indicates whether the last host reason was because of remote control operation(0)
*		or other reason(1). (OUT)
*  remoteControlTimeStamp In case the reason was due to remote control then this field
*		indicates the timestamp of when the remote control command has been executed.
*		(The timestamp is the number of seconds since 1/1/1970)
*
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetLastHostResetReason(UINT32 &reason, UINT32 &remoteControlTimeStamp)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_LAST_HOST_RESET_REASON_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_LAST_HOST_RESET_REASON_HEADER), sizeof(GET_LAST_HOST_RESET_REASON_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_LAST_HOST_RESET_REASON_RESPONSE, sizeof(CFG_GET_LAST_HOST_RESET_REASON_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_LAST_HOST_RESET_REASON_RESPONSE *tmp_response = (CFG_GET_LAST_HOST_RESET_REASON_RESPONSE *)readBuffer;

		reason = tmp_response->Reason;
		remoteControlTimeStamp = tmp_response->RemoteControlTimeStamp;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetCurrentPowerPolicy Host interface command
* Arguments:
*	 policyName The power policy name. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetCurrentPowerPolicy(AMT_ANSI_STRING &policyName)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_CURRENT_POWER_POLICY_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_CURRENT_POWER_POLICY_HEADER), sizeof(GET_CURRENT_POWER_POLICY_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_CURRENT_POWER_POLICY_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_CURRENT_POWER_POLICY_RESPONSE *tmp_response = (CFG_GET_CURRENT_POWER_POLICY_RESPONSE *)readBuffer;
		status = _verifyCurrentPowerPolicy(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		policyName.Length = tmp_response->PolicyName.Length;
		policyName.Buffer = (CHAR *)malloc(policyName.Length * sizeof(CHAR));
		if (NULL == policyName.Buffer) {
			status = AMT_STATUS_INTERNAL_ERROR;
		} else {
			memcpy(policyName.Buffer, &(tmp_response->PolicyName.Buffer),
			       policyName.Length * sizeof(CHAR));
		}
	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Confirms the correctness of the GetCurrentPowerPolicy response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyCurrentPowerPolicy(const CFG_GET_CURRENT_POWER_POLICY_RESPONSE &response)
{
	ULONG ByteCount = response.Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_CURRENT_POWER_POLICY_RESPONSE)
	                  - sizeof(PTHI_MESSAGE_HEADER) - sizeof(CHAR *)
	                  + response.PolicyName.Length))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to GetLanInterfaceSttings Host interface command
* Arguments:
*	 interfaceSettings The interface to get the settings for.
*	 lanSettings reference to a pre allocated struct which will hold the lan settings. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetLanInterfaceSettings(UINT32 interfaceSettings, LAN_SETTINGS &lanSettings)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(CFG_GET_LAN_INTERFACE_SETTINGS_REQUEST);
	unsigned char command[command_size];

	memcpy(command, &(GET_LAN_INTERFACE_SETTINGS_HEADER), sizeof(GET_LAN_INTERFACE_SETTINGS_HEADER));
	memcpy(command + sizeof(GET_LAN_INTERFACE_SETTINGS_HEADER),
	       &(interfaceSettings), sizeof(UINT32));
	
	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_LAN_INTERFACE_SETTINGS_RESPONSE, sizeof(CFG_GET_LAN_INTERFACE_SETTINGS_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_LAN_INTERFACE_SETTINGS_RESPONSE *tmp_response = (CFG_GET_LAN_INTERFACE_SETTINGS_RESPONSE *)readBuffer;

		lanSettings.Enabled = tmp_response->Enabled;
		lanSettings.Ipv4Address = tmp_response->Ipv4Address;
		lanSettings.DhcpEnabled = tmp_response->DhcpEnabled;
		lanSettings.DhcpIpMode = tmp_response->DhcpIpMode;
		lanSettings.LinkStatus = tmp_response->LinkStatus;
		memcpy(lanSettings.MacAddress, tmp_response->MacAddress, sizeof(tmp_response->MacAddress));

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/**
* Gets the HECI driver version
* Arguments:
*	heciVersion - pointewr to HECI_VERSION struct (out)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INVALID_PARAM - on failure
*/
AMT_STATUS PTHICommand::GetHeciVersion(HECI_VERSION &heciVersion)
{
	if (PTHIClient.GetHeciVersion(heciVersion)) {
		return AMT_STATUS_SUCCESS;
	}
	return AMT_STATUS_INTERNAL_ERROR;
}

/*
* Calls to GetSecurityParameters Host interface command
* Arguments:
*	tlsEnabled true if AMT on TLS mode. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetTLSEnabled(AMT_BOOLEAN &tlsEnabled)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_SECURITY_PARAMETERS_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_SECURITY_PARAMETERS_HEADER), sizeof(GET_SECURITY_PARAMETERS_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_SECURITY_PARAMETERS_RESPONSE, sizeof(CFG_GET_SECURITY_PARAMETERS_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_SECURITY_PARAMETERS_RESPONSE *tmp_response = (CFG_GET_SECURITY_PARAMETERS_RESPONSE *)readBuffer;

		tlsEnabled = tmp_response->TLSEnabled;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetDNSSuffixList Host interface command
* Arguments:
*	 dnsSuffixList reference to list of DNS suffix strings. (OUT)
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetDNSSuffixList(std::list<std::string> &dnsSuffixList)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_DNS_SUFFIX_LIST_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_DNS_SUFFIX_LIST_HEADER), sizeof(GET_DNS_SUFFIX_LIST_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_DNS_SUFFIX_LIST_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_DNS_SUFFIX_LIST_RESPONSE *tmp_response = (CFG_GET_DNS_SUFFIX_LIST_RESPONSE *)readBuffer;
		status = _verifyGetDNSSuffixList(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		char *current = (char *)tmp_response->Data;
		while (current < (char *)tmp_response->Data + tmp_response->DataLength)
		{
			std::string dnsSuffix = current;
			if (dnsSuffix.length() > tmp_response->DataLength)
			{
				status = PTSDK_STATUS_INTERNAL_ERROR;
				break;
			}
			if (!dnsSuffix.empty())
			{
				dnsSuffixList.push_back(dnsSuffix);
			}
			current += dnsSuffix.length() + 1;
		}
	} while (0);

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Confirms the correctness of the GetDNSSuffixList response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyGetDNSSuffixList(const CFG_GET_DNS_SUFFIX_LIST_RESPONSE &response)
{
	ULONG ByteCount = response.Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_DNS_SUFFIX_LIST_RESPONSE)
	                  - sizeof(PTHI_MESSAGE_HEADER)
	                  + response.DataLength))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to SetEnterpriseAccess Host interface command
* Arguments:
*	Flags flags
*	HostIPAddress host IP address for enterprise access
*	EnterpriseAccess enterprise access mode
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::SetEnterpriseAccess(UINT8 Flags, UINT8 HostIPAddress[16], UINT8 EnterpriseAccess)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(CFG_SET_ENTERPRISE_ACCESS_REQUEST);
	unsigned char command[command_size];

	memcpy(command, &(SET_ENTERPRISE_ACCESS_HEADER), sizeof(SET_ENTERPRISE_ACCESS_HEADER));
	memcpy(command + sizeof(SET_ENTERPRISE_ACCESS_HEADER), &(Flags), sizeof(UINT8));
	memcpy(command + sizeof(SET_ENTERPRISE_ACCESS_HEADER) + sizeof(UINT8), HostIPAddress, sizeof(HostIPAddress));
	memcpy(command + sizeof(SET_ENTERPRISE_ACCESS_HEADER) + sizeof(UINT8) + sizeof(HostIPAddress), &(EnterpriseAccess), sizeof(UINT8));

	AMT_STATUS status = _call(command, command_size, &readBuffer, SET_ENTERPRISE_ACCESS_RESPONSE, sizeof(CFG_SET_ENTERPRISE_ACCESS_RESPONSE));

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Get FW last reset reason
* Arguments:
*	reason - last FW reason
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetFWResetReason(UINT8 &MEResetReason)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(STATE_GET_AMT_STATE_REQUEST);
	unsigned char command[command_size];
	memcpy(command, &(GET_AMT_STATE_HEADER), sizeof(GET_AMT_STATE_HEADER));
	memcpy(command + sizeof(GET_AMT_STATE_HEADER), &(AMT_UUID_LINK_STATE), sizeof(AMT_UUID));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_AMT_STATE_RESPONSE, sizeof(STATE_GET_AMT_STATE_RESPONSE));
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		STATE_GET_AMT_STATE_RESPONSE *tmp_response = (STATE_GET_AMT_STATE_RESPONSE *)readBuffer;

		MEResetReason = tmp_response->StateData.LastMEResetReason;

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/* Calls to OpenUserInitiatedConnection Host interface command
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::OpenUserInitiatedConnection()
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(OPEN_USER_INITIATED_CONNECTION_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(OPEN_USER_INITIATED_CONNECTION_HEADER), sizeof(OPEN_USER_INITIATED_CONNECTION_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, OPEN_USER_INITIATED_CONNECTION_RESPONSE, sizeof(CFG_OPEN_USER_INITIATED_CONNECTION_RESPONSE));

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/* Calls to CloseUserInitiatedConnection Host interface command
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::CloseUserInitiatedConnection()
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(CLOSE_USER_INITIATED_CONNECTION_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(CLOSE_USER_INITIATED_CONNECTION_HEADER), sizeof(CLOSE_USER_INITIATED_CONNECTION_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, CLOSE_USER_INITIATED_CONNECTION_RESPONSE, sizeof(CFG_CLOSE_USER_INITIATED_CONNECTION_RESPONSE));

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/* Calls to GetRemoteAccessConnectionStatus Host interface command
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetRemoteAccessConnectionStatus(REMOTE_ACCESS_STATUS &remoteAccessStatus)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER), sizeof(GET_REMOTE_ACCESS_CONNECTION_STATUS_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE *tmp_response = (CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE *)readBuffer;
		status = _verifyRemoteAccessConnectionStatus(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		remoteAccessStatus.AmtNetworkConnectionStatus    = tmp_response->AmtNetworkConnectionStatus;
		remoteAccessStatus.RemoteAccessConnectionStatus  = tmp_response->RemoteAccessConnectionStatus;
		remoteAccessStatus.RemoteAccessConnectionTrigger = tmp_response->RemoteAccessConnectionTrigger;

		remoteAccessStatus.MpsHostname.Length = tmp_response->MpsHostname.Length;
		remoteAccessStatus.MpsHostname.Buffer = (CHAR *)malloc(remoteAccessStatus.MpsHostname.Length * sizeof(CHAR));
		if (NULL == remoteAccessStatus.MpsHostname.Buffer) {
			status = AMT_STATUS_INTERNAL_ERROR;
		} else {
			memcpy(remoteAccessStatus.MpsHostname.Buffer,
			       &(tmp_response->MpsHostname.Buffer),
			       tmp_response->MpsHostname.Length * sizeof(CHAR));
		}
	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Confirms the correctness of the GetRemoteAccessConnectionStatus response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyRemoteAccessConnectionStatus(const CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE &response)
{
	ULONG ByteCount = response.Header.Header.Length;
	if (ByteCount != (sizeof(CFG_GET_REMOTE_ACCESS_CONNECTION_STATUS_RESPONSE)
			  - sizeof(PTHI_MESSAGE_HEADER) - sizeof(CHAR *)
			  + response.MpsHostname.Length))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to GenerateRngKey Host interface command
* Arguments:
*	None
* Return values:
*	AMT_STATUS_SUCCESS - or AMT_STATUS_IN_PROGRESS on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GenerateRngKey()
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GENERATE_RNG_SEED_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GENERATE_RNG_SEED_HEADER), sizeof(GENERATE_RNG_SEED_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GENERATE_RNG_SEED_RESPONSE, sizeof(CFG_GENERATE_RNG_SEED_RESPONSE));

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetRngSeedStatus Host interface command
* Arguments:
*	rngStatus - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetRngSeedStatus(AMT_RNG_STATUS &rngStatus)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_RNG_SEED_STATUS_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_RNG_SEED_STATUS_HEADER), sizeof(GET_RNG_SEED_STATUS_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_RNG_SEED_STATUS_RESPONSE, sizeof(CFG_GET_RNG_SEED_STATUS_RESPONSE));

	CFG_GET_RNG_SEED_STATUS_RESPONSE *tmp_response = (CFG_GET_RNG_SEED_STATUS_RESPONSE *)readBuffer;

	rngStatus = tmp_response->RngStatus;

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to ZeroTouchEnabled Host interface command
* Arguments:
*	zeroTouchEnabled - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetZeroTouchEnabled(AMT_BOOLEAN &zeroTouchEnabled)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_ZERO_TOUCH_ENABLED_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_ZERO_TOUCH_ENABLED_HEADER), sizeof(GET_ZERO_TOUCH_ENABLED_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_ZERO_TOUCH_ENABLED_RESPONSE, sizeof(CFG_GET_ZERO_TOUCH_ENABLED_RESPONSE));

	CFG_GET_ZERO_TOUCH_ENABLED_RESPONSE *tmp_response = (CFG_GET_ZERO_TOUCH_ENABLED_RESPONSE *)readBuffer;

	zeroTouchEnabled = tmp_response->ZeroTouchEnabled;

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to GetProvisioningTlsMode Host interface command
* Arguments:
*	provisioningTlsMode - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetProvisioningTlsMode(AMT_PROVISIONING_TLS_MODE &provisioningTlsMode)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_PROVISIONING_TLS_MODE_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_PROVISIONING_TLS_MODE_HEADER), sizeof(GET_PROVISIONING_TLS_MODE_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_PROVISIONING_TLS_MODE_RESPONSE, sizeof(CFG_GET_PROVISIONING_TLS_MODE_RESPONSE));

	CFG_GET_PROVISIONING_TLS_MODE_RESPONSE *tmp_response = (CFG_GET_PROVISIONING_TLS_MODE_RESPONSE *)readBuffer;

	provisioningTlsMode = tmp_response->ProvisioningTlsMode;

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to StartConfiguration Host interface command
* Arguments:
*	None
* Return values:
*	AMT_STATUS_SUCCESS - or AMT_STATUS_CERTIFICATE_NOT_READY on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::StartConfiguration()
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(START_CONFIGURATION_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(START_CONFIGURATION_HEADER), sizeof(START_CONFIGURATION_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, START_CONFIGURATION_RESPONSE, sizeof(CFG_START_CONFIGURATION_RESPONSE));

	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to SetProvisioningServerOTP Host interface command
* Arguments:
*	passwordOTP AMT_ANSI_STRING structure of OTP password
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::SetProvisioningServerOTP(AMT_ANSI_STRING passwordOTP)
{
	if (NULL == passwordOTP.Buffer)
	{
		return PTSDK_STATUS_INVALID_PARAM;
	}

	UINT8 *readBuffer = NULL;
	UINT32 msgLength = sizeof(passwordOTP.Length) + (passwordOTP.Length * sizeof(CHAR));
	PTHI_MESSAGE_HEADER SET_PROVISIONING_SERVER_OTP_HEADER = {
		{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{SET_PROVISIONING_SERVER_OTP_REQUEST}}, msgLength
	};

	const UINT32 command_size = sizeof(SET_PROVISIONING_SERVER_OTP_HEADER) + msgLength;
	unsigned char *command;
	command = (unsigned char *)malloc(command_size);
	if (NULL == command)
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	memcpy(command, &SET_PROVISIONING_SERVER_OTP_HEADER, sizeof(SET_PROVISIONING_SERVER_OTP_HEADER));
	memcpy(command + sizeof(SET_PROVISIONING_SERVER_OTP_HEADER), &(passwordOTP.Length), sizeof(passwordOTP.Length));
	memcpy(command + sizeof(SET_PROVISIONING_SERVER_OTP_HEADER) + sizeof(passwordOTP.Length),
		passwordOTP.Buffer, passwordOTP.Length);

	AMT_STATUS status = _call(command, command_size, &readBuffer, SET_PROVISIONING_SERVER_OTP_RESPONSE, sizeof(CFG_SET_PROVISIONING_SERVER_OTP_RESPONSE));

	if (NULL != command)
	{
		free(command);
	}
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to SetDnsSuffix Host interface command
* Arguments:
*	dnsSuffix AMT_ANSI_STRING structure of DNS suffix
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::SetDnsSuffix(AMT_ANSI_STRING dnsSuffix)
{
	if (NULL == dnsSuffix.Buffer)
	{
		return PTSDK_STATUS_INVALID_PARAM;
	}

	UINT8 *readBuffer = NULL;
	UINT32 msgLength = sizeof(dnsSuffix.Length) + (dnsSuffix.Length * sizeof(CHAR));
	PTHI_MESSAGE_HEADER SET_DNS_SUFFIX_HEADER = {
		{AMT_MAJOR_VERSION, AMT_MINOR_VERSION}, 0, {{SET_DNS_SUFFIX_REQUEST}}, msgLength
	};

	const UINT32 command_size = sizeof(SET_DNS_SUFFIX_HEADER) + msgLength;
	unsigned char *command;
	command = (unsigned char *)malloc(command_size);
	if (NULL == command)
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	memcpy(command, &SET_DNS_SUFFIX_HEADER, sizeof(SET_DNS_SUFFIX_HEADER));
	memcpy(command + sizeof(SET_DNS_SUFFIX_HEADER), &(dnsSuffix.Length), sizeof(dnsSuffix.Length));
	memcpy(command + sizeof(SET_DNS_SUFFIX_HEADER) + sizeof(dnsSuffix.Length), dnsSuffix.Buffer, dnsSuffix.Length);

	AMT_STATUS status = _call(command, command_size, &readBuffer, SET_DNS_SUFFIX_RESPONSE, sizeof(CFG_SET_DNS_SUFFIX_RESPONSE));

	if (NULL != command)
	{
		free(command);
	}
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Calls to EnumerateHashHandles Host interface command
* Arguments:
*	hashHandles - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::EnumerateHashHandles(AMT_HASH_HANDLES &hashHandles)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(ENUMERATE_HASH_HANDLES_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(ENUMERATE_HASH_HANDLES_HEADER), sizeof(ENUMERATE_HASH_HANDLES_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, ENUMERATE_HASH_HANDLES_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_HASH_HANDLES_RESPONSE *tmp_response = (CFG_GET_HASH_HANDLES_RESPONSE *)readBuffer;
		status = _verifyHashHandles(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		memset(hashHandles.Handles, 0, sizeof(UINT32) * CERT_HASH_MAX_NUMBER);
		hashHandles.Length = tmp_response->HashHandles.Length;
		if (CERT_HASH_MAX_NUMBER < hashHandles.Length)
		{
			status = PTSDK_STATUS_INTERNAL_ERROR;
			break;
		}

		memcpy(hashHandles.Handles, tmp_response->HashHandles.Handles, sizeof(UINT32) * hashHandles.Length);

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}

/*
* Confirms the correctness of the EnumerateHashHandles response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyHashHandles(const CFG_GET_HASH_HANDLES_RESPONSE &response)
{
	ULONG ByteCount = response.Header.Header.Length;

	if (ByteCount !=
		sizeof(AMT_STATUS) + sizeof(response.HashHandles.Length) + (sizeof(UINT32) * response.HashHandles.Length))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}


/*
* Calls to GetCertificateHashEntry Host interface command
* Arguments:
*	passwordOTP AMT_ANSI_STRING structure of DNS suffix
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetCertificateHashEntry(UINT32 hashHandle, CERTHASH_ENTRY &hashEntry)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(CFG_GET_CERTHASH_ENTRY_REQUEST);
	unsigned char command[command_size];
	memcpy(command, &(GET_CERTHASH_ENTRY_HEADER), sizeof(GET_CERTHASH_ENTRY_HEADER));
	memcpy(command + sizeof(GET_CERTHASH_ENTRY_HEADER), &(hashHandle), sizeof(hashHandle));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_CERTHASH_ENTRY_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_CERTHASH_ENTRY_RESPONSE *tmp_response = (CFG_GET_CERTHASH_ENTRY_RESPONSE *)readBuffer;
		status = _verifyGetCertificateHashEntry(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		hashEntry.IsActive = tmp_response->Hash.IsActive;
		hashEntry.IsDefault = tmp_response->Hash.IsDefault;
		hashEntry.Name.Length = tmp_response->Hash.Name.Length;
		hashEntry.HashAlgorithm = tmp_response->Hash.HashAlgorithm;
		memcpy(hashEntry.CertificateHash, tmp_response->Hash.CertificateHash, sizeof(tmp_response->Hash.CertificateHash));
		hashEntry.Name.Buffer = (CHAR *)malloc(hashEntry.Name.Length * sizeof(CHAR));
		if (NULL == hashEntry.Name.Buffer)
		{
			status = PTSDK_STATUS_INTERNAL_ERROR;
			break;
		}
		memcpy(hashEntry.Name.Buffer, &(tmp_response->Hash.Name.Buffer), hashEntry.Name.Length * sizeof(CHAR));

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}
/*
* Confirms the correctness of the GetCertificateHashEntry response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyGetCertificateHashEntry(const CFG_GET_CERTHASH_ENTRY_RESPONSE &response)
{
	ULONG ByteCount = response.Header.Header.Length;

	if (ByteCount !=
		(sizeof(CFG_GET_CERTHASH_ENTRY_RESPONSE) - sizeof(PTHI_MESSAGE_HEADER)
		- sizeof(CHAR *) + response.Hash.Name.Length))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

/*
* Calls to GetDnsSuffix Host interface command
* Arguments:
*	dnsSuffix - reference to the pre-allocated structure
*	   which will hold the result
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	appropriate error value defined in StatusCodeDefinitions.h - on failure
*/
AMT_STATUS PTHICommand::GetDnsSuffix(AMT_ANSI_STRING &dnsSuffix)
{
	UINT8 *readBuffer = NULL;
	const UINT32 command_size = sizeof(GET_PKI_FQDN_SUFFIX_HEADER);
	unsigned char command[command_size];
	memcpy(command, &(GET_PKI_FQDN_SUFFIX_HEADER), sizeof(GET_PKI_FQDN_SUFFIX_HEADER));

	AMT_STATUS status = _call(command, command_size, &readBuffer, GET_PKI_FQDN_SUFFIX_RESPONSE, 0);
	do {
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}
		CFG_GET_PKI_FQDN_SUFFIX_RESPONSE *tmp_response = (CFG_GET_PKI_FQDN_SUFFIX_RESPONSE *)readBuffer;
		status = _verifyGetDnsSuffix(*tmp_response);
		if (status != AMT_STATUS_SUCCESS)
		{
			break;
		}

		dnsSuffix.Length = tmp_response->Suffix.Length;
		dnsSuffix.Buffer = (CHAR *)malloc(dnsSuffix.Length * sizeof(CHAR));
		if (NULL == dnsSuffix.Buffer)
		{
			status = PTSDK_STATUS_INTERNAL_ERROR;
			break;
		}
		memcpy(dnsSuffix.Buffer, &(tmp_response->Suffix.Buffer), dnsSuffix.Length * sizeof(CHAR));

	} while (0);
	if (readBuffer != NULL)
	{
		free(readBuffer);
	}
	return status;
}
/*
* Confirms the correctness of the GetDnsSuffix response message
* Arguments:
*	response - reference to the response message
* Return values:
*	AMT_STATUS_SUCCESS - on success
*	PTSDK_STATUS_INTERNAL_ERROR - on failure
*/
AMT_STATUS PTHICommand::_verifyGetDnsSuffix(const CFG_GET_PKI_FQDN_SUFFIX_RESPONSE &response)
{
	ULONG ByteCount = response.Header.Header.Length;

	if (ByteCount  !=
		sizeof(AMT_STATUS) + sizeof(response.Suffix.Length) + response.Suffix.Length * sizeof(CHAR))
	{
		return PTSDK_STATUS_INTERNAL_ERROR;
	}
	return AMT_STATUS_SUCCESS;
}

