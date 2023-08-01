/*
 * Copyright (c)  1999 - 2002 Intel Corporation. All rights reserved
 * This software and associated documentation (if any) is furnished
 * under a license and may only be used or copied in accordance
 * with the terms of the license. Except as permitted by such
 * license, no part of this software or documentation may be
 * reproduced, stored in a retrieval system, or transmitted in any
 * form or by any means without the express written consent of
 * Intel Corporation.
 *
 * Module Name:
 *
 *     devpath.h
 *
 * Abstract:
 *
 *     Defines for parsing the EFI Device Path structures
 *
 * Revision History
 */

#ifndef _DEVPATH_H
#define	_DEVPATH_H

#include <Protocol/DevicePath.h>

#define	EFI_DP_TYPE_MASK		0x7F
#define	EFI_DP_TYPE_UNPACKED		0x80

#define	END_DEVICE_PATH_LENGTH		(sizeof (EFI_DEVICE_PATH))

#define	DP_IS_END_TYPE(a)
#define	DP_IS_END_SUBTYPE(a)	\
	(((a)->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)

#define	DevicePathType(a)	(((a)->Type) & EFI_DP_TYPE_MASK)
#define	DevicePathSubType(a)	((a)->SubType)
#define	DevicePathNodeLength(a)	\
	((size_t)(((a)->Length[0]) |((a)->Length[1] << 8)))
#define	NextDevicePathNode(a)	\
	((EFI_DEVICE_PATH *)(((UINT8 *)(a)) + DevicePathNodeLength(a)))
#define	IsDevicePathType(a, t)	(DevicePathType(a) == t)
#define	IsDevicePathEndType(a)	IsDevicePathType(a, END_DEVICE_PATH_TYPE)
#define	IsDevicePathEndSubType(a)	\
	((a)->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE)
#define	IsDevicePathEnd(a)	\
	(IsDevicePathEndType(a) && IsDevicePathEndSubType(a))
#define	IsDevicePathUnpacked(a)	((a)->Type & EFI_DP_TYPE_UNPACKED)

#define	SetDevicePathNodeLength(a, l) {                  \
		(a)->Length[0] = (UINT8)(l);               \
		(a)->Length[1] = (UINT8)((l) >> 8);        \
	}

#define	SetDevicePathEndNode(a)  {                      \
		(a)->Type = END_DEVICE_PATH_TYPE;           \
		(a)->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;     \
		(a)->Length[0] = sizeof (EFI_DEVICE_PATH);   \
		(a)->Length[1] = 0;                         \
	}

#endif /* _DEVPATH_H */
