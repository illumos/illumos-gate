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

#ifndef _SOLARIS_NFS_H
#define	_SOLARIS_NFS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <cimapi.h>
#include <cimprovider.h>
#include <cimomhandle.h>
#include <cimlogsvc.h>
#include <cimstructs.h>
#include "nfsprov_include.h"


#define	PROPCOUNT 48

static nfs_prov_prop_t nfsProps[] = {
#define	ATTRCACHE 0
	{"AttributeCaching", cim_false, boolean},

#define	ATTRCACHEDIRMAX (ATTRCACHE + 1)
	{"AttributeCachingForDirectoriesMax", cim_false, uint16},

#define	ATTRCACHEDIRMIN (ATTRCACHEDIRMAX + 1)
	{"AttributeCachingForDirectoriesMin", cim_false, uint16},

#define	ATTRCACHEFILESMAX (ATTRCACHEDIRMIN + 1)
	{"AttributeCachingForRegularFilesMax", cim_false, uint16},

#define	ATTRCACHEFILESMIN (ATTRCACHEFILESMAX + 1)
	{"AttributeCachingForRegularFilesMin", cim_false, uint16},

#define	AVAILSPACE (ATTRCACHEFILESMIN + 1)
	{"AvailableSpace", cim_false, uint64},

#define	BLKSIZE (AVAILSPACE + 1)
	{"BlockSize", cim_false, uint64},

#define	CAPTION (BLKSIZE + 1)
	{"Caption", cim_false, string},

#define	CASEPRES (CAPTION + 1)
	{"CasePreserved", cim_false, boolean},

#define	CASESENS (CASEPRES + 1)
	{"CaseSensitive", cim_false, boolean},

#define	CLUSTERSZ (CASESENS + 1)
	{"ClusterSize", cim_false, uint32},

#define	CODESET (CLUSTERSZ + 1)
	{"CodeSet", cim_false, uint16_array},

#define	COMPRESSMETH (CODESET + 1)
	{"CompressionMethod", cim_false, string},

#define	CSCREATCLASSNM (COMPRESSMETH + 1)
	{"CSCreationClassName", cim_true, string},

#define	CSNAME (CSCREATCLASSNM + 1)
	{"CSName", cim_true, string},

#define	CREATCLASSNM (CSNAME + 1)
	{"CreationClassName", cim_true, string},

#define	DESCRIP (CREATCLASSNM + 1)
	{"Description", cim_false, string},

#define	ENCRYPTMETH (DESCRIP + 1)
	{"EncryptionMethod", cim_false, string},

#define	FSSIZE (ENCRYPTMETH + 1)
	{"FileSystemSize", cim_false, uint64},

#define	FSTYPE (FSSIZE + 1)
	{"FileSystemType", cim_false, string},

#define	FGMOUNT (FSTYPE + 1)
	{"ForegroundMount", cim_false, boolean},

#define	GLOBAL (FGMOUNT + 1)
	{"Global", cim_false, boolean},

#define	GRPID (GLOBAL + 1)
	{"GrpId", cim_false, boolean},

#define	HARDMNT (GRPID + 1)
	{"HardMount", cim_false, boolean},

#define	INSTALLDATE (HARDMNT + 1)
	{"InstallDate", cim_false, datetime},

#define	INTR (INSTALLDATE + 1)
	{"Interrupt", cim_false, boolean},

#define	MAXFILENMLN (INTR + 1)
	{"MaxFileNameLength", cim_false, uint32},

#define	MNTFAILRETRIES (MAXFILENMLN + 1)
	{"MountFailureRetries", cim_false, uint16},

#define	NAME (MNTFAILRETRIES + 1)
	{"Name", cim_true, string},

#define	NOMNTTABENT (NAME + 1)
	{"NoMnttabEntry", cim_false, boolean},

#define	NOSUID (NOMNTTABENT + 1)
	{"NoSuid", cim_false, boolean},

#define	OVERLAY (NOSUID + 1)
	{"Overlay", cim_false, boolean},

#define	POSIX (OVERLAY + 1)
	{"Posix", cim_false, boolean},

#define	PROTO (POSIX + 1)
	{"Proto", cim_false, string},

#define	PUBLIC (PROTO + 1)
	{"Public", cim_false, boolean},

#define	QUOTA (PUBLIC + 1)
	{"Quota", cim_false, boolean},

#define	READBUFFSIZE (QUOTA + 1)
	{"ReadBufferSize", cim_false, uint64},

#define	READONLY (READBUFFSIZE + 1)
	{"ReadOnly", cim_false, boolean},

#define	REMNT (READONLY + 1)
	{"Remount", cim_false, boolean},

#define	RETRANSATTEMPTS (REMNT + 1)
	{"RetransmissionAttempts", cim_false, uint16},

#define	RETRANSTIMEO (RETRANSATTEMPTS + 1)
	{"RetransmissionTimeout", cim_false, uint32},

#define	ROOT (RETRANSTIMEO + 1)
	{"Root", cim_false, string},

#define	SECMODE (ROOT + 1)
	{"SecurityMode", cim_false, string},

#define	SERVERCOMMPORT (SECMODE + 1)
	{"ServerCommunicationPort", cim_false, uint32},

#define	STATUS (SERVERCOMMPORT + 1)
	{"Status", cim_false, string},

#define	USEDSPACE (STATUS + 1)
	{"UsedSpace", cim_false, uint64},

#define	VERS (USEDSPACE + 1)
	{"Version", cim_false, string},

#define	WRITEBUFFSIZE (VERS + 1)
	{"WriteBufferSize", cim_false, uint64}
};

#ifdef __cplusplus
}
#endif

#endif /* _SOLARIS_NFS_H */
