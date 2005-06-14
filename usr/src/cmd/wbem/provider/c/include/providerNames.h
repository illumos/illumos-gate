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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PROVIDERNAMES_H
#define	_PROVIDERNAMES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration of device providers */

#define		DISK_DRIVE  		"Solaris_DiskDrive"
#define		DISK_PARTITION  	"Solaris_DiskPartition"
#define		LOGICAL_DISK  		"Solaris_LogicalDisk"
#define		DISK  			"Solaris_Disk"
#define		REALIZES_EXTENT  	"Solaris_RealizesExtent"
#define		REALIZES_DISKPART  	"Solaris_RealizesDiskPartition"
#define		REALIZES_DISKDRIVE  	"Solaris_RealizesDiskDrive"
#define		GENERIC_CONTROLLER  	"Solaris_GenericController"
#define		IDE_CONTROLLER  	"Solaris_IDEController"
#define		SCSI_CONTROLLER  	"Solaris_SCSIController"
#define		USBSCSI_CONTROLLER  	"Solaris_USBSCSIController"
#define		MPXIO_CONTROLLER  	"Solaris_MPXIOController"
#define		MPXIO_GROUP  		"Solaris_MPXIOGroup"
#define		MPXIO_COMPONENT  	"Solaris_MPXIOComponent"
#define		MPXIO_LOGICALIDENTITY  	"Solaris_MPXIOCtrlrLogicalIdentity"
#define		MPXIO_INTERFACE  	"Solaris_MPXIOInterface"
#define		SCSI_INTERFACE  	"Solaris_SCSIInterface"
#define		IDE_INTERFACE  		"Solaris_IDEInterface"
#define		MEDIA_PRESENT  		"Solaris_MediaPresent"
#define		DISKPART_BASEDONFDISK  	"Solaris_DiskPartitionBasedOnFDisk"
#define		DISKPART_BASEDONDISK  	"Solaris_DiskPartitionBasedOnDisk"
#define		COMPUTER_SYSTEM  	"Solaris_ComputerSystem"
#define		PHYSICAL_PACKAGE	"Solaris_PhysicalPackage"

/* Forward declaration of function names */

#define		DRIVE_DESCRIPTOR_FUNC	"drive_descriptors_toCCIMInstance"
#define		PARTITION_DESCRIPTOR_FUNC "partition_descriptors_toCCIMInstance"
#define		DISK_DESCRIPTOR_FUNC	"disk_descriptors_toCCIMInstance"
#define		LOGICALDISK_DESCRIPTOR_FUNC \
			"logicaldisk_descriptors_toCCIMInstance"
#define		MPXIO_DESCRIPTOR_FUNC \
			"mpxiogroup_descriptors_toCCIMInstance"
#define		CTRL_DESCRIPTOR_FUNC	"ctrl_descriptors_toCCIMInstance"
#define		PARTBASEDON_DESCRIPTOR_FUNC \
			"partbasedon_descriptors_toCCIMInstance"
#define		REALIZESEXTENT_DESCRIPTOR_FUNC \
			"realizesextent_descriptors_toCCIMInstance"
#define		REALIZESDD_DESCRIPTOR_FUNC \
			"realizesdiskdrive_descriptors_toCCIMInstance"
#define		MEDIAPRES_DESCRIPTOR_FUNC \
			"mediapresent_descriptors_toCCIMInstance"

/* utility function names */
#define		UTIL_OPENFILE		"Util_OpenFile"
#define		UTIL_CLOSEFILE		"Util_CloseFile"
#define		UTIL_REMOVEFILE		"Util_RemoveFile"


/* c provider function names */
#define		ENUM_INSTANCES		"cp_enumInstances"
#define		ENUM_INSTANCENAMES	"cp_enumIntanceNames"
#define		GET_INSTANCE		"cp_getInstance"
#define		INVOKE_METHOD		"cp_invokeMethod"
#define		EXEC_QUERY		"cp_execQuery"
#define		ASSOCIATORS		"cp_associators"
#define		ASSOCIATOR_NAMES	"cp_associatorNames"
#define		REFERENCES		"cp_references"
#define		REFERENCE_NAMES		"cp_referenceNames"
#define		CREATE_INSTANCE		"cp_createInstance"
#define		CREATE_INSTANCELIST	"cp_createInstanceList"
#define		DELETE_INSTANCE		"cp_deleteInstance"
#define		SET_INSTANCE		"cp_setInstance"
#define		GET_PROPERTY		"cp_getProperty"
#define		SET_PROPERTY		"cp_setProperty"
#define		CREATE_OBJECT_PATH	"cim_createObjectPath"

#ifdef __cplusplus
}
#endif

#endif /* _PROVIDERNAMES_H */
