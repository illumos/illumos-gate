/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _WINSCARD_H
#define	_WINSCARD_H

/*
 * This library provides a compatibility interface with programs designed
 * against the PC SmartCard Library. This originates from Microsoft and has been
 * used on a few different forms over the years by folks. The purpose of this
 * library is for compatibility.
 *
 * At the time of this writing, Microsofts API documentation can be found here:
 * https://docs.microsoft.com/en-us/windows/win32/api/winscard/
 *
 * New consumers should not use this library and instead should leverage
 * ccid(4D) instead.
 */

#include <stdint.h>
#include <wintypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is a departure from the PCSC system which defines this as a LONG,
 * which is the same size on 32bit and 64bit Windows (ILP32 and LLP64).
 * We need to use the real native pointer size for the context handle as
 * it wouldn't fit into a LONG on our LP64 platform.
 */
typedef void *SCARDCONTEXT;
typedef void **PSCARDCONTEXT;
typedef void **LPSCARDCONTEXT;
typedef void *SCARDHANDLE;
typedef void **PSCARDHANDLE;
typedef void **LPSCARDHANDLE;

/*
 * Conventionally this is supposed to be packed.
 */
#pragma pack(1)
typedef struct {
	unsigned long dwProtocol;
	unsigned long cbPciLength;
} SCARD_IO_REQUEST, *PSCARD_IO_REQUEST, *LPSCARD_IO_REQUEST;
#pragma pack()

extern SCARD_IO_REQUEST g_rgSCardT0Pci, g_rgSCardT1Pci, g_rgSCardRawPci;
#define	SCARD_PCI_T0	(&g_rgSCardT0Pci)
#define	SCARD_PCI_T1	(&g_rgSCardT1Pci)
#define	SCARD_PCI_RAW	(&g_rgSCardRawPci)

/*
 * Return values and error codes. We strive to use the same error codes as
 * Microsoft.
 */
#define	SCARD_S_SUCCESS			((LONG)0x00000000)
#define	SCARD_F_INTERNAL_ERROR		((LONG)0x80100001)
#define	SCARD_E_CANCELLED		((LONG)0x80100002)
#define	SCARD_E_INVALID_HANDLE		((LONG)0x80100003)
#define	SCARD_E_INVALID_PARAMETER	((LONG)0x80100004)
#define	SCARD_E_NO_MEMORY		((LONG)0x80100006)
#define	SCARD_E_INSUFFICIENT_BUFFER	((LONG)0x80100008)
#define	SCARD_E_UNKNOWN_READER		((LONG)0x80100009)
#define	SCARD_E_TIMEOUT			((LONG)0x8010000a)
#define	SCARD_E_SHARING_VIOLATION	((LONG)0x8010000b)
#define	SCARD_E_NO_SMARTCARD		((LONG)0x8010000c)
#define	SCARD_E_UNKNOWN_CARD		((LONG)0x8010000d)
#define	SCARD_E_PROTO_MISMATCH		((LONG)0x8010000f)
#define	SCARD_E_INVALID_VALUE		((LONG)0x80100011)
#define	SCARD_F_COMM_ERROR		((LONG)0x80100013)
#define	SCARD_F_UNKNOWN_ERROR		((LONG)0x80100014)
#define	SCARD_E_READER_UNAVAILABLE	((LONG)0x80100017)
#define	SCARD_E_NO_SERVICE		((LONG)0x8010001D)
#define	SCARD_E_SERVICE_STOPPED		((LONG)0x8010001E)
#define	SCARD_E_UNSUPPORTED_FEATURE	((LONG)0x80100022)
#define	SCARD_E_NO_READERS_AVAILABLE	((LONG)0x8010002E)
#define	SCARD_W_UNSUPPORTED_CARD	((LONG)0x80100065)
#define	SCARD_W_UNPOWERED_CARD		((LONG)0x80100067)
#define	SCARD_W_RESET_CARD		((LONG)0x80100068)
#define	SCARD_W_REMOVED_CARD		((LONG)0x80100069)

#define	SCARD_SCOPE_USER		0x0000
#define	SCARD_SCOPE_TERMINAL		0x0001
#define	SCARD_SCOPE_SYSTEM		0x0002
#define	SCARD_SCOPE_GLOBAL		0x0003

#define	SCARD_SHARE_EXCLUSIVE		0x0001
#define	SCARD_SHARE_SHARED		0x0002
#define	SCARD_SHARE_DIRECT		0x0003

#define	SCARD_PROTOCOL_UNDEFINED	0x0000
#define	SCARD_PROTOCOL_T0		0x0001
#define	SCARD_PROTOCOL_T1		0x0002
#define	SCARD_PROTOCOL_RAW		0x0004
#define	SCARD_PROTOCOL_T15		0x0008

#define	SCARD_LEAVE_CARD		0x0000
#define	SCARD_RESET_CARD		0x0001
#define	SCARD_UNPOWER_CARD		0x0002
#define	SCARD_EJECT_CARD		0x0003

/*
 * Some versions of PCSClite treat the status value as a bitfield rather than
 * an enumeration, though their documentation also suggests that "this
 * difference may be resolved in a future version of pcsc-lite."  We use
 * bitfield-style values here in case we want to make changes in the future,
 * but presently treat this as an enumeration (returning one value) as
 * Microsoft does.
 */
#define	SCARD_UNKNOWN			0x0001
#define	SCARD_ABSENT			0x0002
#define	SCARD_PRESENT			0x0004
#define	SCARD_SWALLOWED			0x0008
#define	SCARD_POWERED			0x0010
#define	SCARD_NEGOTIABLE		0x0020
#define	SCARD_SPECIFIC			0x0040

/*
 * This is used to indicate that the framework should allocate memory.
 */
#define	SCARD_AUTOALLOCATE		UINT32_MAX

extern LONG SCardEstablishContext(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
extern LONG SCardIsValidContext(SCARDCONTEXT);
extern LONG SCardReleaseContext(SCARDCONTEXT);

extern LONG SCardListReaders(SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD);

extern LONG SCardFreeMemory(SCARDCONTEXT, LPCVOID);

extern LONG SCardConnect(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE,
    LPDWORD);
extern LONG SCardDisconnect(SCARDHANDLE, DWORD);

extern LONG SCardStatus(SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD,
    LPBYTE, LPDWORD);

extern LONG SCardBeginTransaction(SCARDHANDLE);
extern LONG SCardEndTransaction(SCARDHANDLE, DWORD);
extern LONG SCardReconnect(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD);

extern LONG SCardTransmit(SCARDHANDLE, const SCARD_IO_REQUEST *, LPCBYTE,
    DWORD, SCARD_IO_REQUEST *, LPBYTE, LPDWORD);

extern const char *pcsc_stringify_error(const LONG);

#ifdef __cplusplus
}
#endif

#endif /* _WINSCARD_H */
