/*
 * Copyright (c) 2000 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <efi.h>
#include <efilib.h>

EFI_HANDLE		IH;
EFI_SYSTEM_TABLE	*ST;
EFI_BOOT_SERVICES	*BS;
EFI_RUNTIME_SERVICES	*RS;

void *
efi_get_table(EFI_GUID *tbl)
{
	EFI_GUID *id;
	int i;

	for (i = 0; i < ST->NumberOfTableEntries; i++) {
		id = &ST->ConfigurationTable[i].VendorGuid;
		if (memcmp(id, tbl, sizeof (EFI_GUID)) == 0)
			return (ST->ConfigurationTable[i].VendorTable);
	}
	return (NULL);
}

EFI_STATUS
OpenProtocolByHandle(EFI_HANDLE handle, EFI_GUID *protocol, void **interface)
{
	return (BS->OpenProtocol(handle, protocol, interface, IH, NULL,
	    EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL));
}

/*
 * Allocate memory and query list of handles for indicated protocol.
 * Returns EFI status, list of handles and number of handles in list.
 * Caller needs to release the allocated memory.
 */
EFI_STATUS
efi_get_protocol_handles(EFI_GUID *protocolguid, uint_t *nhandles,
    EFI_HANDLE **handlep)
{
	UINTN bufsz = 0;
	EFI_STATUS status;
	EFI_HANDLE *handles;

	/*
	 * get buffer size
	 */
	*nhandles = 0;
	handles = NULL;
	status = BS->LocateHandle(ByProtocol, protocolguid,
	    NULL, &bufsz, handles);
	if (status != EFI_BUFFER_TOO_SMALL)
		return (status);

	handles = malloc(bufsz);
	if (handles == NULL)
		return (errno_to_efi_status(ENOMEM));

	*nhandles = (uint_t)(bufsz / sizeof (EFI_HANDLE));
	/*
	 * get handle array
	 */
	status = BS->LocateHandle(ByProtocol, protocolguid,
	    NULL, &bufsz, handles);
	if (EFI_ERROR(status)) {
		free(handles);
		*nhandles = 0;
	} else {
		*handlep = handles;
	}
	return (status);
}
