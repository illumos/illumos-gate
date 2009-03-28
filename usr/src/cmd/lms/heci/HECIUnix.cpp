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
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <aio.h>

#ifdef __sun
#include <stdio.h>
#include <stdlib.h>
#endif	// __sun

#include "HECIUnix.h"

#pragma pack(1)

typedef struct heci_ioctl_data
{
	uint32_t size;
	char *data;
#ifndef  _LP64
	/*
	 * If lms is compiled in 32-bit, padding is needed to
	 * talk to the driver which is 64-bit only.
	 */
	char *pad;
#endif
} heci_ioctl_data_t;

/* IOCTL commands */
#undef HECI_IOCTL
#undef IOCTL_HECI_GET_VERSION
#undef IOCTL_HECI_CONNECT_CLIENT
#undef IOCTL_HECI_WD
#define HECI_IOCTL_TYPE 0x48
#define IOCTL_HECI_GET_VERSION \
    _IOWR(HECI_IOCTL_TYPE, 0x0, heci_ioctl_data_t)
#define IOCTL_HECI_CONNECT_CLIENT \
    _IOWR(HECI_IOCTL_TYPE, 0x01, heci_ioctl_data_t)
#define IOCTL_HECI_WD \
    _IOWR(HECI_IOCTL_TYPE, 0x02, heci_ioctl_data_t)
#define IAMT_HECI_GET_RECEIVED_MESSAGE_DATA \
    _IOW(HECI_IOCTL_TYPE, 0x03, heci_ioctl_data_t)

#pragma pack(0)

/***************************** public functions *****************************/

HECILinux::HECILinux(const GUID guid, bool verbose) :
HECI(guid, verbose),
_fd(-1),
m_haveHeciVersion(false)
{
}

HECILinux::~HECILinux()
{
	if (_fd != -1) {
		close(_fd);
	}
}

bool HECILinux::GetHeciVersion(HECI_VERSION &version) const
{
	if (m_haveHeciVersion) {
		memcpy(&version, &m_heciVersion, sizeof(HECI_VERSION));
		return true;
	}
	return false;
}

bool HECILinux::Init(unsigned char reqProtocolVersion)
{
	int result;
	HECI_CLIENT *heci_client;
	bool return_result = true;
	heci_ioctl_data_t version_response;
	heci_ioctl_data_t client_connect;

	m_haveHeciVersion = false;
	if (_initialized) {
		Deinit();
	}

	_fd = open("/dev/heci", O_RDWR);

	if (_fd == -1 ) {
		if (_verbose) {
			fprintf(stderr, "Error: Cannot establish a handle to the HECI driver\n");
		}
		return false;
	}
	_initialized = true;
	version_response.size = sizeof(HECI_VERSION);
	version_response.data = (char *)malloc(version_response.size);
	if (!version_response.data) {
		if (_verbose) {
			fprintf(stderr, "malloc failure.\n");
		}
		return_result = false;
		Deinit();
		goto heci_free;
	}

	result = ioctl(_fd, IOCTL_HECI_GET_VERSION, &version_response);
	if (result) {
		if (_verbose) {
			fprintf(stderr, "error in IOCTL_HECI_GET_VERSION recieve message. err=%d\n", result);
		}
		return_result = false;
		Deinit();
		goto heci_free;
	}
	memcpy(&m_heciVersion, version_response.data, sizeof(HECI_VERSION));
	m_haveHeciVersion = true;
	if (_verbose) {
		fprintf(stdout, "Connected to HECI driver, version: %d.%d.%d.%d\n",
			m_heciVersion.major, m_heciVersion.minor, m_heciVersion.hotfix, m_heciVersion.build);
		fprintf(stdout, "Size of guid = %lu\n", (unsigned long)sizeof(_guid));
	}
	client_connect.size = sizeof(_guid);
	client_connect.data = (char *)malloc(client_connect.size);
	if (!client_connect.data) {
		if (_verbose) {
			fprintf(stderr, "malloc failure.\n");
		}
		return_result = false;
		Deinit();
		goto heci_free;
	}
	memcpy(client_connect.data, &_guid, sizeof(_guid));
	result = ioctl(_fd, IOCTL_HECI_CONNECT_CLIENT, &client_connect);
	if (result) {
		if (_verbose) {
			fprintf(stderr, "error in IOCTL_HECI_CONNECT_CLIENT recieve message. err=%d\n", result);
		}
		return_result = false;
		Deinit();
		goto heci_free;
	}
	heci_client = (HECI_CLIENT *) client_connect.data;
	if (_verbose) {
		fprintf(stdout, "max_message_length %d \n", (heci_client->MaxMessageLength));
		fprintf(stdout, "protocol_version %d \n", (heci_client->ProtocolVersion));
	}

	if ((reqProtocolVersion > 0) && (heci_client->ProtocolVersion != reqProtocolVersion)) {
		if (_verbose) {
			fprintf(stderr, "Error: MEI protocol version not supported\n");
		}
		return_result = false;
		Deinit();
		goto heci_free;
	}

	_protocolVersion = heci_client->ProtocolVersion;
	_bufSize = heci_client->MaxMessageLength;

heci_free:
	if (NULL != version_response.data) {
		free(version_response.data);
	}
	if (NULL != client_connect.data) {
		free(client_connect.data);
	}
	return return_result;
}

void HECILinux::Deinit()
{
	if (_fd != -1) {
		close(_fd);
		_fd = -1;
	}

	_bufSize = 0;
	_protocolVersion = 0;
	_initialized = false;
}

int HECILinux::ReceiveMessage(unsigned char *buffer, int len, unsigned long timeout)
{
	int rv = 0;
	int error = 0;

	if (_verbose) {
		fprintf(stdout, "call read length = %d\n", len);
	}
	rv = read(_fd, (void*)buffer, len);
	if (rv < 0) {
		error = errno;
		if (_verbose) {
			fprintf(stderr, "read failed with status %d %d\n", rv, error);
		}
		Deinit();
	} else {
		if (_verbose) {
			fprintf(stderr, "read succeded with result %d\n", rv);
		}
	}
	return rv;
}

int HECILinux::SendMessage(const unsigned char *buffer, int len, unsigned long timeout)
{
	int rv = 0;
	int return_length =0;
	int error = 0;
	fd_set set;
	struct timeval tv;

	tv.tv_sec =  timeout / 1000;
	tv.tv_usec =(timeout % 1000) * 1000000;

	if (_verbose) {
		fprintf(stdout, "call write length = %d\n", len);
	}
	rv = write(_fd, (void *)buffer, len);
	if (rv < 0) {
		error = errno;
		if (_verbose) {
			fprintf(stderr,"write failed with status %d %d\n", rv, error);
		}
		goto out;
	}

	return_length = rv;

	FD_ZERO(&set);
	FD_SET(_fd, &set);
	rv = select(_fd+1 ,&set, NULL, NULL, &tv);
	if (rv > 0 && FD_ISSET(_fd, &set)) {
		if (_verbose) {
			fprintf(stderr, "write success\n");
		}
	}
	else if (rv == 0) {
		if (_verbose) {
			fprintf(stderr, "write failed on timeout with status\n");
		}
		goto out;
	}
	else { //rv<0
		if (_verbose) {
			fprintf(stderr, "write failed on select with status %d\n", rv);
		}
		goto out;
	}

	rv = return_length;

out:
	if (rv < 0) {
		Deinit();
	}

	return rv;
}

