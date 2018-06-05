/* $FreeBSD$ */
/*++

Copyright (c)  1999 - 2002 Intel Corporation. All rights reserved
This software and associated documentation (if any) is furnished
under a license and may only be used or copied in accordance
with the terms of the license. Except as permitted by such
license, no part of this software or documentation may be
reproduced, stored in a retrieval system, or transmitted in any
form or by any means without the express written consent of
Intel Corporation.

Module Name:

    efi.h

Abstract:

    Public EFI header files



Revision History

--*/

//
// Build flags on input
//  EFI32
//  EFI_DEBUG               - Enable debugging code
//  EFI_NT_EMULATOR         - Building for running under NT
//


#ifndef _EFI_INCLUDE_
#define _EFI_INCLUDE_

#define EFI_FIRMWARE_VENDOR         L"INTEL"
#define EFI_FIRMWARE_MAJOR_REVISION 14
#define EFI_FIRMWARE_MINOR_REVISION 62
#define EFI_FIRMWARE_REVISION ((EFI_FIRMWARE_MAJOR_REVISION <<16) | (EFI_FIRMWARE_MINOR_REVISION))

#include "efibind.h"
#include "efidef.h"
#include "efidevp.h"
#include "efipciio.h"
#include "efiprot.h"
#include "eficon.h"
#include "eficonsctl.h"
#include "efiser.h"
#include "efi_nii.h"
#include "efipxebc.h"
#include "efinet.h"
#include "efiapi.h"
#include "efifs.h"
#include "efierr.h"
#include "efigop.h"
#include "efiip.h"
#include "efiudp.h"
#include "efitcp.h"
#include "efipoint.h"
#include "efiuga.h"

/*
 * illumos UUID
 */
#define	ILLUMOS_BOOT_VAR_GUID \
	{ 0x8B54B311, 0x7163, 0x40d3, {0xA6, 0x7B, 0xE7, 0xB2, 0x95, 0x1B, 0x3D, 0x56} }
#endif
