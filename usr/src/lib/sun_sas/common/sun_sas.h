/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_SUN_SAS_H
#define	_SUN_SAS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <smhbaapi.h>
#include <vendorsmhbaapi.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <limits.h>
#include <syslog.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <stropts.h>
#include <libdevinfo.h>
#include <sys/time.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/scsi/impl/sense.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/varargs.h>
#include <sys/varargs.h>
#include <libsysevent.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	VSL_NUMERIC_VERSION	1
#define	VSL_STRING_VERSION	"Version 1"
#define	VSL_NAME		"Sun T11 SM-HBA Vendor Library for SAS HBAs"
#define	SMHBA_LIBRARY_VERSION1	VSL_NUMERIC_VERSION

/* The /dev links we expose */
#define	DEV_DISK_DIR		"/dev/rdsk"
#define	DEV_TAPE_DIR		"/dev/rmt"
#define	DEV_ES_DIR		"/dev/es"
#define	DEV_CFG_DIR		"/dev/cfg"
#define	DEVICES_DIR		"/devices"
#define	DEVCTL_SUFFIX		":devctl"
#define	SCSI_SUFFIX		":scsi"

/* To be consistent, when out of memory call this macro routine */
#define	OUT_OF_MEMORY(routine)  \
    log(LOG_DEBUG, routine, "Out of memory.")

#define	S_FREE(x)   (((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)

#define	IS_STUB_NODE(s) (di_instance(s) == -1 && \
	di_nodeid(s) == (DI_PROM_NODEID))

/* manf+model+10(char length of UINTMAX)+6(for 2 -'s, NULL & extra 3bytes */
#define	HANDLE_NAME_LENGTH  (64 + 256 + 10 + 6)
#define	HANDLE_ERROR	0 /* This is an error condition */

/* Some timing values */
#define	LOCK_SLEEP	    1
#define	BUSY_SLEEP	    10000 /* 1/100 second */
#define	BUSY_RETRY_TIMER    5000000000 /* Retry for 5 seconds */
#define	STATE_RETRY_TIMER   10000000000 /* Retry for 10 seconds */
#define	HR_SECOND	    1000000000
/* How many times to silently retry, before starting to print warnings */
#define	DEADLOCK_WARNING    10

#define	MAX_LUN		4096
#define	REP_LUNS_RSP_SIZE   sizeof (rep_luns_rsp_t)+  \
				(sizeof (lun_list_element_t)*(MAX_LUN - 1))

/* misc */
#define	SUN_MICROSYSTEMS	"Sun Microsystems, Inc."

mutex_t		all_hbas_lock;
mutex_t		open_handles_lock;
mutex_t		log_file_lock;
HBA_UINT32	hba_count;
HBA_UINT16	open_handle_index;


/* Internal structures that aren't exposed to clients */
struct open_handle {
	int			adapterIndex;
	HBA_UINT32		handle;
	struct open_handle	*next;
};

struct sun_sas_hba {
	HBA_UINT32		index;  /* Can be sparse */
	struct open_handle	*open_handles;
	int			fd;	    /* when open, the FD */
	/* The libdevinfo HBA path (lacking /devices) */
	char			device_path[MAXPATHLEN];
	char			handle_name[HANDLE_NAME_LENGTH];
	SMHBA_ADAPTERATTRIBUTES	adapter_attributes;

	/* State tracking */
	boolean_t		invalid;
	struct sun_sas_hba	*next;
	struct sun_sas_port	*first_port;
};

struct sun_sas_hba *global_hba_head;

struct ScsiEntryList {
	SMHBA_SCSIENTRY		entry;
	struct ScsiEntryList	*next;
};

struct phy_info {
	HBA_UINT32		index;
	boolean_t		invalid;
	SMHBA_SAS_PHY		phy;
	struct phy_info		*next;
};

struct sun_sas_port {
	HBA_UINT32		index;
	boolean_t		invalid;

	/* The libdevinfo HBA path (lacking /devices) */
	char			device_path[MAXPATHLEN];
	SMHBA_PORTATTRIBUTES	port_attributes;
	struct ScsiEntryList	*scsiInfo;
	int			cntlNumber;

	/* The following are used to track the device map */
	int			num_devices;
	struct sun_sas_port	*first_attached_port; /* Only for HBA port */
	struct phy_info		*first_phy;	/* Only for HBA port */
	struct sun_sas_port	*next;
};

typedef struct walkarg {
	char *devpath;
	boolean_t *flag;
} walkarg_t;

extern int	loadCount;

extern sysevent_handle_t *gSysEventHandle;

/* External routines */
extern HBA_STATUS SMHBA_RegisterLibrary(PSMHBA_ENTRYPOINTS);
extern HBA_UINT32 Sun_sasGetVendorLibraryAttributes(SMHBA_LIBRARYATTRIBUTES *);
extern HBA_STATUS Sun_sasGetAdapterAttributes(HBA_HANDLE,
    SMHBA_ADAPTERATTRIBUTES *);
extern HBA_UINT32 Sun_sasGetNumberOfAdapters();
extern HBA_STATUS Sun_sasGetAdapterName(HBA_UINT32, char *);
extern HBA_STATUS Sun_sasGetPortType(HBA_HANDLE, HBA_UINT32, HBA_PORTTYPE *);
extern HBA_STATUS Sun_sasGetAdapterPortAttributes(HBA_HANDLE, HBA_UINT32,
    SMHBA_PORTATTRIBUTES *);
extern HBA_STATUS Sun_sasGetPortAttributesByWWN(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_PORTATTRIBUTES *);
extern HBA_STATUS Sun_sasGetFCPhyAttributes(HBA_HANDLE, HBA_UINT32, HBA_UINT32,
    SMHBA_FC_PHY *);
extern HBA_STATUS Sun_sasGetSASPhyAttributes(HBA_HANDLE, HBA_UINT32,
    HBA_UINT32, SMHBA_SAS_PHY *);
extern HBA_STATUS Sun_sasGetProtocolStatistics(HBA_HANDLE, HBA_UINT32,
    HBA_UINT32, SMHBA_PROTOCOLSTATISTICS *);
extern HBA_STATUS Sun_sasGetPhyStatistics(HBA_HANDLE, HBA_UINT32,
    HBA_UINT32, SMHBA_PHYSTATISTICS *);
extern HBA_STATUS Sun_sasSendSMPPassThru(HBA_HANDLE, HBA_WWN,  HBA_WWN, HBA_WWN,
    void *, HBA_UINT32, void *, HBA_UINT32 *);
extern HBA_STATUS Sun_sasGetBindingCapability(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_BIND_CAPABILITY *);
extern HBA_STATUS Sun_sasGetBindingSupport(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_BIND_CAPABILITY *);
extern HBA_STATUS Sun_sasSetBindingSupport(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_BIND_CAPABILITY);
extern HBA_STATUS Sun_sasGetTargetMapping(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_TARGETMAPPING *);
extern HBA_STATUS Sun_sasGetPersistentBinding(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_BINDING *);
extern HBA_STATUS Sun_sasSetPersistentBinding(HBA_HANDLE, HBA_WWN, HBA_WWN,
    const SMHBA_BINDING *);
extern HBA_STATUS Sun_sasRemovePersistentBinding(HBA_HANDLE, HBA_WWN, HBA_WWN,
    const SMHBA_BINDING *);
extern HBA_STATUS Sun_sasRemoveAllPersistentBindings(HBA_HANDLE, HBA_WWN,
    HBA_WWN);
extern HBA_STATUS Sun_sasGetLUNStatistics(HBA_HANDLE, const HBA_SCSIID *,
    SMHBA_PROTOCOLSTATISTICS *);
extern HBA_STATUS Sun_sasRegisterForAdapterAddEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32), void *, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_sasRegisterForAdapterEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32), void *, HBA_HANDLE, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_sasRegisterForAdapterPortEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN, HBA_UINT32,
    HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_sasRegisterForAdapterPortStatEvents(void (*)(void *,
    HBA_WWN, HBA_UINT32, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN, HBA_UINT32,
    SMHBA_PROTOCOLSTATISTICS, HBA_UINT32, HBA_CALLBACKHANDLE *);
extern HBA_STATUS    Sun_sasRegisterForAdapterPhyStatEvents(void (*)(void *,
    HBA_WWN, HBA_UINT32, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN, HBA_UINT32,
    SMHBA_PHYSTATISTICS, HBA_UINT32, HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_sasRegisterForTargetEvents(void (*)(void *, HBA_WWN,
    HBA_WWN, HBA_WWN, HBA_UINT32), void *, HBA_HANDLE, HBA_WWN, HBA_WWN,
    HBA_WWN, HBA_CALLBACKHANDLE *, HBA_UINT32);
extern HBA_STATUS Sun_sasRegisterForLinkEvents(void (*)(void *, HBA_WWN,
    HBA_UINT32, void *, HBA_UINT32), void *, void *, HBA_UINT32, HBA_HANDLE,
    HBA_CALLBACKHANDLE *);
extern HBA_STATUS Sun_sasScsiInquiry(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN,
    SMHBA_SCSILUN, HBA_UINT8, HBA_UINT8, void *, HBA_UINT32 *, HBA_UINT8 *,
    void *, HBA_UINT32 *);
extern HBA_STATUS Sun_sasScsiReportLUNs(HBA_HANDLE, HBA_WWN, HBA_WWN,
    HBA_WWN, void *, HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);
extern HBA_STATUS Sun_sasScsiReadCapacity(HBA_HANDLE, HBA_WWN, HBA_WWN, HBA_WWN,
    SMHBA_SCSILUN, void *, HBA_UINT32 *, HBA_UINT8 *, void *, HBA_UINT32 *);
extern HBA_UINT32 Sun_sasGetVersion();
extern HBA_STATUS Sun_sasLoadLibrary();
extern HBA_STATUS Sun_sasFreeLibrary();
extern HBA_UINT32 Sun_sasGetNumberOfAdapters();
extern HBA_UINT32 Sun_sasGetNumberOfPorts(HBA_HANDLE, HBA_UINT32 *);
extern HBA_STATUS Sun_sasGetAdapterName(HBA_UINT32, char *);
extern HBA_HANDLE Sun_sasOpenAdapter(char *);
extern void Sun_sasCloseAdapter(HBA_HANDLE);
extern HBA_STATUS Sun_sasGetDiscoveredPortAttributes(HBA_HANDLE, HBA_UINT32,
    HBA_UINT32, SMHBA_PORTATTRIBUTES *);
extern HBA_STATUS Sun_sasGetPortAttributesByWWN(HBA_HANDLE, HBA_WWN, HBA_WWN,
    SMHBA_PORTATTRIBUTES *);
extern void Sun_sasRefreshInformation(HBA_HANDLE);
extern void Sun_sasRefreshAdapterConfiguration(void);
extern HBA_STATUS Sun_sasRemoveCallback(HBA_CALLBACKHANDLE);


/* Internal routines */
extern void log(int, const char *, char *, ...);
extern u_longlong_t wwnConversion(uchar_t *wwn);
extern HBA_STATUS devtree_attached_devices(di_node_t, struct sun_sas_port *);
extern HBA_HANDLE CreateHandle(int);
extern int RetrieveIndex(HBA_HANDLE);
extern struct open_handle *RetrieveOpenHandle(HBA_HANDLE);
extern struct sun_sas_hba *RetrieveHandle(int);
extern struct sun_sas_hba *ExtractHandle(int);
extern struct sun_sas_hba *Retrieve_Sun_sasHandle(HBA_HANDLE);
extern void lock(mutex_t *mp);
extern void unlock(mutex_t *mp);
extern void reportSense(struct scsi_extended_sense *, const char *);
extern HBA_STATUS verifyAdapter(struct sun_sas_hba *hba_ptr);
extern HBA_STATUS devtree_get_all_hbas(di_node_t root);
extern HBA_STATUS devtree_get_one_hba(di_node_t node);
extern HBA_STATUS FreeHBA(struct sun_sas_hba *hba);
extern HBA_WWN getFirstAdapterPortWWN(HBA_HANDLE handle);
extern HBA_STATUS getPortStateCounter(char *fpPath, HBA_UINT32 *stateCount);
extern HBA_STATUS lookupControllerLink(char *path, char *link);
extern HBA_STATUS lookupSMPLink(char *path, char *link);
extern void convertDevpathToDevlink(PSMHBA_TARGETMAPPING mappings);
extern void fillDomainPortWWN(struct sun_sas_port *);
extern HBA_STATUS get_phy_info(di_node_t, struct sun_sas_port *);
extern HBA_STATUS send_uscsi_cmd(const char *devpath, struct uscsi_cmd *ucmd);
extern HBA_STATUS registerSysevent();
extern HBA_STATUS validateDomainAddress(struct sun_sas_port *, HBA_WWN);

#ifdef	__cplusplus
}
#endif

#endif /* _SUN_SAS_H */
