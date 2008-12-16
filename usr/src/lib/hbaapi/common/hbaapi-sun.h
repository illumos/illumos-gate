/*
 * *****************************************************************************
 *
 * Description
 *	hbaapi.h - header file for Sun extension for target mode adaptor
 * 		 support.
 *
 * License:
 *	The contents of this file are subject to the SNIA Public License
 *	Version 1.0 (the "License"); you may not use this file except in
 *	compliance with the License. You may obtain a copy of the License at
 *
 *	http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *	Software distributed under the License is distributed on an "AS IS"
 *	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *	the License for the specific language governing rights and limitations
 *	under the License.
 *
 * *******************************************************************************
 */
/*
 * 	Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * 	Use is subject to license terms.
 */

#ifdef __cplusplus
extern "C" {
#endif


#ifndef _HBA_API_SUN_H
#define _HBA_API_SUN_H

#include    <hbaapi.h>

#define	HBA_CREATE_WWN_RANDOM		1
#define	HBA_CREATE_WWN_FACTORY		2

typedef struct HBA_NPIVPortList {
	uint32_t	numPorts;
	char		hbaPaths[1][1024];
} HBA_NPIVPORTLIST, *PHBA_NPIVPORTLIST;

typedef struct HBA_PortNPIVAttributes {
	HBA_INT32	npivflag;
	HBA_WWN		NodeWWN;
	HBA_WWN		PortWWN;
	HBA_UINT32	MaxNumberOfNPIVPorts;
	HBA_UINT32	NumberOfNPIVPorts;
} HBA_PORTNPIVATTRIBUTES, *PHBA_PORTNPIVATTRIBUTES;

typedef struct HBA_NPIVAttributes {
	HBA_WWN		NodeWWN;
	HBA_WWN		PortWWN;
} HBA_NPIVATTRIBUTES, *PHBA_NPIVATTRIBUTES;

typedef struct HBA_NPIVCreateEntry {
	HBA_WWN		VNodeWWN;
	HBA_WWN		VPortWWN;
	uint32_t	vindex;
} HBA_NPIVCREATEENTRY, *PHBA_NPIVCREATEENTRY;

/* Device Level Events */
#define	HBA_EVENT_DEVICE_UNKNOWN	0x600
#define	HBA_EVENT_DEVICE_OFFLINE	0x601
#define	HBA_EVENT_DEVICE_ONLINE		0x602

HBA_API HBA_UINT32 Sun_HBA_GetNumberOfTgtAdapters();

HBA_API HBA_STATUS Sun_HBA_GetTgtAdapterName(
    HBA_UINT32		adapterindex,
    char		*adaptername
    );

HBA_API HBA_HANDLE Sun_HBA_OpenTgtAdapter(
    char*		adaptername
    );

HBA_API HBA_STATUS Sun_HBA_OpenTgtAdapterByWWN(
    HBA_HANDLE		*handle,
    HBA_WWN		wwn
    );

HBA_API HBA_STATUS Sun_HBA_NPIVGetAdapterAttributes(
    HBA_HANDLE		handle,
    HBA_ADAPTERATTRIBUTES
			*hbaattributes
    );
HBA_API HBA_STATUS Sun_HBA_GetNPIVPortInfo(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		vportindex,
    HBA_NPIVATTRIBUTES	*attributes
    );
HBA_API HBA_STATUS Sun_HBA_DeleteNPIVPort(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		vportWWN
    );
HBA_API HBA_STATUS Sun_HBA_CreateNPIVPort(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		vnodeWWN,
    HBA_WWN		vportWWN,
    HBA_UINT32		*npivportindex
    );
HBA_API HBA_STATUS Sun_HBA_GetPortNPIVAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTNPIVATTRIBUTES	*portnpivattributes
    );

HBA_STATUS Sun_HBA_AdapterCreateWWN(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		*nwwn,
    HBA_WWN		*pwwn,
    HBA_WWN		*OUI,
    HBA_INT32		method
);

HBA_STATUS Sun_HBA_AdapterReturnWWN(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		*nwwn,
    HBA_WWN		*pwwn
);

HBA_API HBA_STATUS Sun_HBA_RegisterForAdapterDeviceEvents(
    void		(*callback)(
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType,
	HBA_UINT32	fabricPortID
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_CALLBACKHANDLE	*callbackHandle
    );


#endif /* HBA_API_SUN_H */

#ifdef __cplusplus
}
#endif /* _HBA_API_SUN_H */
