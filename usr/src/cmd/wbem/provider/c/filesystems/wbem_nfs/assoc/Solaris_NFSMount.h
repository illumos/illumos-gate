/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOLARIS_NFSMOUNT_H
#define	_SOLARIS_NFSMOUNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <cimapi.h>
#include <cp_required.h>
#include <cp_instance.h>
#include <cp_associator.h>
#include <cp_method.h>
#include <cp_property.h>
#include <cimomhandle.h>
#include <cimeventsvc.h>
#include <cimlogsvc.h>
#include "nfsprov_include.h"
#include "nfs_mount_attr.h"

#define	PROPCOUNT 39

static nfs_prov_prop_plus_optVals_t nfsMountProps[] = {
#define	ANT 0
	{"Antecedent", cim_true, reference, NULL, NULL, NULL},

#define	ATTRCACHE (ANT + 1)
	{"AttributeCaching", cim_false, boolean, NULL, NFS_ATTRCACHE_FALSE,
	NULL},

#define	ATTRCACHEDIRMAX (ATTRCACHE + 1)
	{"AttributeCachingForDirectoriesMax", cim_false, uint16, NULL, NULL,
	NFS_ATTRCACHEDIRMAX},

#define	ATTRCACHEDIRMIN (ATTRCACHEDIRMAX + 1)
	{"AttributeCachingForDirectoriesMin", cim_false, uint16, NULL, NULL,
	NFS_ATTRCACHEDIRMIN},

#define	ATTRCACHEFILESMAX (ATTRCACHEDIRMIN + 1)
	{"AttributeCachingForRegularFilesMax", cim_false, uint16, NULL, NULL,
	NFS_ATTRCACHEFILESMAX},

#define	ATTRCACHEFILESMIN (ATTRCACHEFILESMAX + 1)
	{"AttributeCachingForRegularFilesMin", cim_false, uint16, NULL, NULL,
	NFS_ATTRCACHEFILESMIN},

#define	DEP (ATTRCACHEFILESMIN + 1)
	{"Dependent", cim_true, reference, NULL, NULL, NULL},

#define	ENABLEQUOTA (DEP + 1)
	{"EnableQuotaChecking", cim_false, boolean, NFS_ENABLEQUOTA_TRUE,
	NFS_ENABLEQUOTA_FALSE, NULL},

#define	FAILOVER (ENABLEQUOTA + 1)
	{"FailoverList", cim_false, string_array, NULL, NULL, NULL},

#define	FORCEDIRECTIO (FAILOVER + 1)
	{"ForceDirectIO", cim_false, boolean, NFS_FORCEDIRECTIO_TRUE,
	NFS_FORCEDIRECTIO_FALSE, NULL},

#define	FSTYPE (FORCEDIRECTIO + 1)
	{"FsType", cim_false, string, NULL, NULL, NULL},

#define	GRPID (FSTYPE + 1)
	{"GroupId", cim_false, boolean, NFS_GRPID_TRUE, NULL, NULL},

#define	HARDMNT (GRPID + 1)
	{"HardMount", cim_false, boolean, NFS_HARDMNT_TRUE, NFS_HARDMNT_FALSE,
	NULL},

#define	INTR (HARDMNT + 1)
	{"Interrupt", cim_false, boolean, NFS_INTR_TRUE, NFS_INTR_FALSE, NULL},

#define	MAXRETRANSATTEMPTS (INTR + 1)
	{"MaxRetransmissionAttempts", cim_false, uint16, NULL, NULL,
	NFS_MAXRETRANSATTEMPTS},

#define	MNTATBOOTENTRY (MAXRETRANSATTEMPTS + 1)
	{"MountAtBootEntry", cim_false, boolean, NULL, NULL, NULL},

#define	MNTOPTS (MNTATBOOTENTRY + 1)
	{"MountOptions", cim_false, string, NULL, NULL, NULL},

#define	MNTFAILRETRIES (MNTOPTS + 1)
	{"MountFailureRetries", cim_false, uint16, NULL, NULL,
	NFS_MNTFAILRETRIES},

#define	NOCTO (MNTFAILRETRIES + 1)
	{"NoCloseToOpenConsistency", cim_false, boolean, NFS_NOCTO_TRUE, NULL,
	NULL},

#define	NOMNTTABENT (NOCTO + 1)
	{"NoMnttabEntry", cim_false, boolean, NULL, NULL, NULL},

#define	NOSUID (NOMNTTABENT + 1)
	{"NoSuid", cim_false, boolean, NFS_NOSUID_TRUE, NFS_NOSUID_FALSE,
	NULL},

#define	OVERLAY (NOSUID + 1)
	{"Overlay", cim_false, boolean, NULL, NULL, NULL},

#define	OVERLAYED (OVERLAY + 1)
	{"Overlayed", cim_false, boolean, NULL, NULL, NULL},

#define	POSIX (OVERLAYED + 1)
	{"Posix", cim_false, boolean, NFS_POSIX_TRUE, NULL, NULL},

#define	PROTO (POSIX + 1)
	{"Protocol", cim_false, string, NULL, NULL, NFS_PROTO},

#define	PUBLIC (PROTO + 1)
	{"Public", cim_false, boolean, NFS_PUBLIC_TRUE, NULL, NULL},

#define	READBUFFSIZE (PUBLIC + 1)
	{"ReadBufferSize", cim_false, uint64, NULL, NULL, NFS_READBUFFSIZE},

#define	READONLY (READBUFFSIZE + 1)
	{"ReadOnly", cim_false, boolean, NFS_READONLY_TRUE, NFS_READONLY_FALSE,
	NULL},

#define	REPLRESOURCES (READONLY + 1)
	{"ReplicatedResources", cim_false, string_array, NULL, NULL, NULL},

#define	RETRANSTIMEO (REPLRESOURCES + 1)
	{"RetransmissionTimeout", cim_false, uint32, NULL, NULL,
	NFS_RETRANSTIMEO},

#define	FOREGROUND (RETRANSTIMEO + 1)
	{"RetryInForeground", cim_false, boolean, NFS_FOREGROUND_TRUE,
	NFS_FOREGROUND_FALSE, NULL},

#define	SECMODE (FOREGROUND + 1)
	{"SecurityMode", cim_false, string, NULL, NULL, NFS_SECMODE},

#define	SERVERCOMMPORT (SECMODE + 1)
	{"ServerCommunicationPort", cim_false, uint32, NULL, NULL,
	NFS_SERVERCOMMPORT},

#define	SERVERNAME (SERVERCOMMPORT + 1)
	{"ServerName", cim_false, string, NULL, NULL, NULL},

#define	SERVERPATH (SERVERNAME + 1)
	{"ServerPath", cim_false, string, NULL, NULL, NULL},

#define	VERS (SERVERPATH + 1)
	{"Version", cim_false, string, NULL, NULL, NFS_VERS},

#define	VFSTABENTRY (VERS + 1)
	{"VfstabEntry", cim_false, boolean, NULL, NULL, NULL},

#define	WRITEBUFFSIZE (VFSTABENTRY + 1)
	{"WriteBufferSize", cim_false, uint64, NULL, NULL, NFS_WRITEBUFFSIZE},

#define	XATTR (WRITEBUFFSIZE + 1)
	{"Xattr", cim_false, boolean, NFS_XATTR_TRUE, NFS_XATTR_FALSE, NULL}
};

#ifdef __cplusplus
}
#endif

#endif /* _SOLARIS_NFSMOUNT_H */
