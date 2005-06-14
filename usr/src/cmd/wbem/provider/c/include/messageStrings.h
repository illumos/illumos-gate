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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MESSAGESTRINGS_H
#define	_MESSAGESTRINGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * dgettext is normally defined by including libintl.h.  However, the file
 * /usr/sadm/lib/wbem/include/cimapi.h erroneously defines gettext so that
 * they can play games with L10N in the CIM functions.  If we try to undef
 * gettext before we include libintl.h we get a complaint from hdrchk.  So,
 * just declare the extern here to work around this mess.
 */
extern char *dgettext(const char *, const char *);

/* cim failures */
#define	CREATE_PROPERTY_FAILURE \
	util_routineFailureMessage("cim_createProperty")
#define	ADD_PROPERTY_FAILURE \
	util_routineFailureMessage("cim_addProperty")
#define	ADD_INSTANCE_FAILURE \
	util_routineFailureMessage("cim_addInstance")
#define	GET_INSTANCE_FAILURE \
	util_routineFailureMessage("cim_getInstance")
#define	CREATE_INSTANCE_LIST_FAILURE \
	util_routineFailureMessage("cim_createInstanceList")
#define	CREATE_INSTANCE_FAILURE \
	util_routineFailureMessage("cim_createInstance")
#define	CREATE_OBJECT_LIST_FAILURE \
	util_routineFailureMessage("cim_createObjectPathList")
#define	CREATE_OBJECT_PATH_FAILURE \
	util_routineFailureMessage("cim_createObjectPath")
#define	ENUM_INSTANCES_FAILURE \
	util_routineFailureMessage("cim_enumerateInstances")
#define	ENUM_INSTANCENAMES_FAILURE \
	util_routineFailureMessage("cim_enumerateInstanceNames")
#define	COPY_OBJPATH_FAILURE \
	util_routineFailureMessage("cim_copyObjectPath")
#define	CREATE_REFPROP_FAILURE \
	util_routineFailureMessage("cim_createReferenceProperty")
#define	ASSOCIATOR_NAMES_FAILURE \
	util_routineFailureMessage("cim_associatorNames")

/* dm api failures */
#define	DM_GET_ATTR_FAILURE \
	util_routineFailureMessage("dm_get_attributes")
#define	DM_GET_NAME_FAILURE \
	util_routineFailureMessage("dm_get_name")
#define	DM_GET_ASSOC_FAILURE \
	util_routineFailureMessage("dm_get_associated_descriptors")
#define	DM_GET_DESC_BYNAME_FAILURE \
	util_routineFailureMessage("dm_get_descriptor_by_name")
#define	DM_GET_DESCRIPTORS \
	util_routineFailureMessage("dm_get_descriptors")

/* descriptor function failures */
#define	DRIVE_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("drive_descriptor_toCCIMInstance")
#define	PART_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("partition_descriptor_toCCIMInstance")
#define	DISK_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("disk_descriptor_toCCIMInstance")
#define	LOGICALDISK_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("logicaldisk_descriptor_toCCIMInstance")
#define	SCSICTRL_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("scsictrl_descriptor_toCCIMInstance")
#define	IDECTRL_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("idectrl_descriptor_toCCIMInstance")
#define	USBCTRL_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("usbctrl_descriptor_toCCIMInstance")
#define	FCCTRL_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("fcctrl_descriptor_toCCIMInstance")
#define	MPXIOCTRL_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("mpxioctrl_descriptor_toCCIMInstance")
#define	UCTRL_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("unknownctrl_descriptor_toCCIMInstance")
#define	MPXIOGRP_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("mpxiogroup_descriptor_toCCIMInstance")
#define	PARTBASEDON_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("diskpartbo_descriptor_toCCIMInstance")
#define	REALIZESEXT_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("realizesextent_descriptor_toCCIMInstance")
#define	REALIZESDD_DESC_TO_INSTANCE_FAILURE			\
	util_routineFailureMessage(				\
		"realizesdiskdrive_descriptor_toCCIMInstance")
#define	MEDIAPRES_DESC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("mediapresent_descriptor_toCCIMInstance")
#define	SCSIINT_ASSOC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("scsiIntAssocToInst")
#define	FCINT_ASSOC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("fcIntAssocToInst")
#define	USBINT_ASSOC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("usbIntAssocToInst")
#define	MPXIOINT_ASSOC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("mpxioIntAssocToInst")
#define	IDEINT_ASSOC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("ideIntAssocToInst")
#define	MEDIAPRES_ASSOC_TO_INSTANCE_FAILURE \
	util_routineFailureMessage("MediaPresAssocToInst")
#define	UTIL_FILEOPEN_FAILURE \
	util_routineFailureMessage("util_OpenFile")
#define	UTIL_FILECLOSE_FAILURE \
	util_routineFailureMessage("util_CloseFile")
#define	UTIL_FILEREMOVE_FAILURE \
	util_routineFailureMessage("util_RemoveFile")

/* General failures */
#define	LOW_MEMORY \
	dgettext(TEXT_DOMAIN, "Not enough memory Failure.")
#define	GENERAL_FAILURE \
	dgettext(TEXT_DOMAIN, "General Failure.")
#define	NO_SUCH_METHOD \
	dgettext(TEXT_DOMAIN, "No Such Method Defined.")
#define	NVLIST_FAILURE \
	dgettext(TEXT_DOMAIN, "The nvlist action failed.")
#define	NO_SUCH_CLASS \
	dgettext(TEXT_DOMAIN, "Class Not Found.")

#ifdef __cplusplus
}
#endif

#endif /* _MESSAGESTRINGS_H */
