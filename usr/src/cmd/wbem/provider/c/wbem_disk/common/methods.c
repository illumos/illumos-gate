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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/wait.h>
#include <errno.h>
#include <cimlogsvc.h>
#include <cimauthcheck.h>
#include <sys/param.h>
#include "libdiskmgt.h"
#include "messageStrings.h"
#include "providerNames.h"
#include "util.h"
#include "methods.h"

static int		add_fdisk_props(ulong_t *ret_array, int part_num,
			    dm_descriptor_t d);
static CIMBool		build_fdisk_file(char *fdisk_file,
			    CCIMPropertyList *params);
static CIMBool		build_fmt_file(char *fmt_file,
			    CCIMPropertyList *params);
static CIMBool		execute_cmd(char *command_line, char *err_file);
static CIMBool		check_rights(char *provider);
static void		convert_flag(long flag, char *flag_buf, int len);
static CCIMProperty	*create_result(char *status);
static CCIMProperty 	*create_result_out(char *status,
			    CCIMPropertyList *outParams);
static int 		disk_geometry(char *media_name, ulong_t *geometry);
static CIMBool		get_devpath(CCIMObjectPath *op, char *devpath, int len);
static cimchar		*get_prop_val(CCIMProperty *prop);
static dm_descriptor_t	*get_partition_descs(CCIMObjectPath *op);
static void		make_fdisk_path(char *devpath);

#define	DATALEN		256
#define	CMDLEN		2048
#define	NUM_GEOM_ELEMENTS 7

/*
 * This method formats the disk drive identified by CIMObjectPath
 * based on the values in inParams
 */

CCIMProperty *
create_partitions(CCIMPropertyList *params, CCIMObjectPath *op)
{
	char		devpath[MAXPATHLEN];
	char		fmt_file[L_tmpnam];
	char		command_line[CMDLEN];
	int		len;
	int		error;

	if (!check_rights("Solaris_Disk") || op == NULL || params == NULL) {
	    return (create_result(PROPFALSE));
	}

	if (get_devpath(op, devpath, sizeof (devpath)) == cim_false) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Create a format data file to be used by the fmthard command. */
	if (build_fmt_file(fmt_file, params) == cim_false) {
	    /* last error is set in build_fmt_file function */
	    util_removeFile(fmt_file);
	    return (create_result(PROPFALSE));
	}

	/* Create 'fmthard' command line */
	len = snprintf(command_line, sizeof (command_line),
	    "/usr/sbin/fmthard -s %s %s 2> /dev/null", fmt_file, devpath);

	if (len < 0 || (len + 1) > sizeof (command_line)) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED,
		CIM_ERR_FAILED, NULL, &error);
	    util_removeFile(fmt_file);
	    return (create_result(PROPFALSE));
	}

	/* Execute the command. */
	if (!execute_cmd(command_line, "/dev/null")) {
	    util_removeFile(fmt_file);
	    return (create_result(PROPFALSE));
	}

	util_removeFile(fmt_file);
	return (create_result(PROPTRUE));
}

CCIMProperty *
create_filesystem(CCIMObjectPath *op)
{
	char			devpath[MAXPATHLEN];
	char			command_line[CMDLEN];
	int			len;
	int			error;

	/* check to make sure caller has admin write rights */
	if (!check_rights("Solaris_DiskPartition")) {
	    return (create_result(PROPFALSE));
	}

	if (get_devpath(op, devpath, sizeof (devpath)) == cim_false) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Create 'newfs' command line */
	len = snprintf(command_line, sizeof (command_line),
	    "echo y | /usr/sbin/newfs %s 2>/dev/null", devpath);

	if (len < 0 || (len + 1) > sizeof (command_line)) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED,
		CIM_ERR_FAILED, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Execute the command. */
	if (!execute_cmd(command_line, "/dev/null")) {
	    return (create_result(PROPFALSE));
	}

	return (create_result(PROPTRUE));
}

/*
 * Function:	create_fdisk_partitions
 *
 * Parameters:  params - CCIMPropertyList pointer that dereferences
 *		to a list of not less than 4 or more than 16 CCIMProperty
 *		values.  Number of CCIMProperty values must be a multiple
 * 		of 4.
 *		op - CCIMObjectPath pointer that points to the object path
 *		of the device to fdisk.
 *
 * Returns:	Returns a CCIMProperty pointer.  The CCIMProperty referenced
 *		by the pointer will contain an mValue of cim_true for
 *		success or cim_false on failure.
 *
 * Description:	Executes the fdisk command on the device pointed to my 'op'
 *		with the parameters provided in 'params'.
 *
 * Notes:	The calling program is responsible for releasing the memory
 *		used by the returned CCIMProperty.
 */
CCIMProperty *
create_fdisk_partitions(CCIMPropertyList *params, CCIMObjectPath *op)
{
	char		devpath[MAXPATHLEN];
	char		fdisk_file[L_tmpnam];
	char		err_file[L_tmpnam];
	char		command_line[CMDLEN];
	int		len;
	int		error;

	if (!check_rights("Solaris_Disk") ||
	    op == NULL || params == NULL) {
	    return (create_result(PROPFALSE));
	}

	if (get_devpath(op, devpath, sizeof (devpath)) == cim_false) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		CIM_ERR_FAILED, NULL, &error);
	    return (create_result(PROPFALSE));
	}
	make_fdisk_path(devpath);

	/* Create a fdisk data file to be used by the fdisk command. */
	if (build_fdisk_file(fdisk_file, params) == cim_false) {
	    /* last error is set in build_fdisk_file function */
	    util_removeFile(fdisk_file);
	    return (create_result(PROPFALSE));
	}

	(void) tmpnam(err_file);

	/*
	 * Build the fdisk command line.  Some combinations of
	 * parameters can cause fdisk to output a message and wait
	 * for a y/n response, echo'ing an 'n' and piping it to
	 * fdisk solves this problem.
	 *
	 * Using the form of fdisk (-F) that takes partition information
	 * from a disk file so that multiple partitions can be created
	 * by one request.
	 */

	len = snprintf(command_line, sizeof (command_line),
	    "echo n | /usr/sbin/fdisk -F %s %s 2> %s",
	    fdisk_file, devpath, err_file);

	if (len < 0 || (len + 1) > sizeof (command_line)) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED,
		NULL, NULL, &error);
	    util_removeFile(fdisk_file);
	    return (create_result(PROPFALSE));
	}

	/* Execute the command. */
	if (!execute_cmd(command_line, err_file)) {
	    util_removeFile(fdisk_file);
	    return (create_result(PROPFALSE));
	}

	util_removeFile(fdisk_file);
	return (create_result(PROPTRUE));
}

/*
 * Function:	create_default_fdisk_partition
 *
 * Parameters:  op - CCIMObjectPath pointer that points to the object path
 *		of the device to fdisk.
 *
 * Returns:	Returns a CCIMProperty pointer.  The CCIMProperty referenced
 *		by the pointer will contain an mValue of cim_true for
 *		success or cim_false on failure.
 *
 * Description:	Executes the fdisk command on the device pointed to my 'op'
 *		with the -B parameter.
 *
 * Notes:	The calling program is responsible for releasing the memory
 *		used by the returned CCIMProperty.
 */
CCIMProperty *
create_default_fdisk_partition(CCIMObjectPath *op)
{
	char		devpath[MAXPATHLEN];
	char		err_file[L_tmpnam];
	char		command_line[CMDLEN];
	int		len;
	int		error;

	/* This function is called from Solaris_DiskDrive, not Solaris_Disk. */
	if (!check_rights("Solaris_DiskDrive") || op == NULL) {
	    return (create_result(PROPFALSE));
	}

	if (get_devpath(op, devpath, sizeof (devpath)) == cim_false) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		CIM_ERR_FAILED, NULL, &error);
	    return (create_result(PROPFALSE));
	}
	make_fdisk_path(devpath);

	(void) tmpnam(err_file);

	/*
	 * Build the fdisk command line.  Some combinations of
	 * parameters can cause fdisk to output a message and wait
	 * for a y/n response, echo'ing an 'n' and piping it to
	 * fdisk solves this problem.
	 *
	 * Using the form of fdisk (-F) that takes partition information
	 * from a disk file so that multiple partitions can be created
	 * by one request.
	 */

	len = snprintf(command_line, sizeof (command_line),
	    "echo n | /usr/sbin/fdisk -B %s 2> %s",
	    devpath, err_file);

	if (len < 0 || (len + 1) > sizeof (command_line)) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED,
		NULL, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Execute the command. */
	if (!execute_cmd(command_line, err_file)) {
	    return (create_result(PROPFALSE));
	}

	return (create_result(PROPTRUE));
}

/*
 * Function:	writeVolumeName
 *
 * Parameters:	params - CCIMPropertyList pointer.  Property list
 *		containing the new disk label name.
 *		op - CCIMObjectPath pointer.  Object path containing
 *		the deviceId of the disk to label.
 *
 * Returns:	Returns a CCIMProperty pointer.  The CCIMProperty referenced
 *		by the pointer will contain an mValue of cim_true for
 *		success or cim_false on failure.
 *
 * Description:	Executes the fmthard -n volume_name command on the device
 *		pointed to by 'op'.
 */
CCIMProperty *
label_disk(CCIMPropertyList *params, CCIMObjectPath *op)
{
	char		devpath[MAXPATHLEN];
	char		command_line[CMDLEN];
	int		len;
	cimchar		*label;
	int		error;

	if (!check_rights("Solaris_Disk") ||
	    op == NULL || params == NULL) {
	    return (create_result(PROPFALSE));
	}

	if (get_devpath(op, devpath, sizeof (devpath)) == cim_false) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Extract the label from the input parameters */
	if ((label = get_prop_val(params->mDataObject)) == NULL) {
	    return (create_result(PROPFALSE));
	}
	if (strlen(label) > 8) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Build the command line to execute */

	len = snprintf(command_line, sizeof (command_line),
	    "/usr/sbin/fmthard -n '%s' %s 2> /dev/null", label, devpath);

	if (len < 0 || (len + 1) > sizeof (command_line)) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (create_result(PROPFALSE));
	}

	/* Execute the command. */
	if (!execute_cmd(command_line, "/dev/null")) {
	    return (create_result(PROPFALSE));
	}
	return (create_result(PROPTRUE));
}

CCIMProperty *
get_disk_geometry(CCIMPropertyList *out, CCIMObjectPath *op)
{
	CCIMProperty		*prop = NULL;
	CCIMPropertyList	*prop_list = NULL;
	ulong_t			geometry[NUM_GEOM_ELEMENTS];
	char			*array_str;
	int			error;

	/*
	 * Don't use get_devpath since we are going through the API.
	 * Parse the object path to get the media name to pass in.
	 */
	if (op != NULL) {
	    prop_list = op->mKeyProperties;
	}

	for (; prop_list; prop_list = prop_list->mNext) {

	    if (((prop = prop_list->mDataObject) != NULL &&
		prop->mName != NULL &&
		strcasecmp(prop->mName, "Tag")) == 0) {
		break;
	    }
	}

	if (prop == NULL || prop->mValue == NULL) {
	    return (create_result(PROPFALSE));
	}

	cim_logDebug("get_disk_geometry", "%s", prop->mValue);
	error = disk_geometry(prop->mValue, geometry);
	if (error != 0) {
	    /* We have to put something in the out params when we fail. */
	    ulong_t		dummy [] = {0};
	    char		*array_str;
	    CCIMProperty	*p;

	    cim_logDebug("get_disk_geometry", "disk_geometry failed");
	    if ((array_str = cim_encodeUint32Array(dummy, 1)) == NULL) {
		util_handleError(DISK_DRIVE, CIM_ERR_FAILED, CIM_ERR_FAILED,
		    NULL, &error);
	    } else if ((p = cim_createProperty("geometry",
		sint32_array, array_str, NULL, cim_false)) == NULL) {
		free(array_str);
	    } else if ((cim_addPropertyToPropertyList(out, p)) == NULL) {
		cim_freeProperty(p);
	    }

	    return (create_result(PROPFALSE));
	}

	array_str = cim_encodeUint32Array(geometry, NUM_GEOM_ELEMENTS);
	if (array_str == NULL) {
	    util_handleError(DISK_DRIVE, CIM_ERR_FAILED, CIM_ERR_FAILED, NULL,
		&error);
	    return (create_result(PROPFALSE));
	}

	if ((prop = cim_createProperty("geometry", sint32_array,
	    array_str, NULL, cim_false)) == NULL) {
	    free(array_str);
	    return (create_result(PROPFALSE));
	}

	if ((cim_addPropertyToPropertyList(out, prop)) == NULL) {
	    cim_freeProperty(prop);
	    return (create_result(PROPFALSE));
	}

	return (create_result(PROPTRUE));
}

/*
 * Function:	getFdisk
 *
 * Parameters:	outParams - CCIMPropertyList pointer.  The output from
 *		the fdisk command is placed in this list.
 *		op - CCIMObjectPath pointer.  The object path contains
 *		deviceID of the device to fdisk.
 *
 * Returns:	Returns a CCIMProperty pointer.  The CCIMProperty referenced
 *		by the pointer will contain an mValue of cim_true for
 *		success or cim_false on failure.
 *
 * Notes:	The calling program is responsible for releasing the memory
 *		used by the returned CCIMProperty and the CCIMPropertyList
 *		pointed to by outParams.  I don't know why we return only
 *		four of the possible values from fdisk.  That is the way
 *		the Java provider worked and this provider was written to
 *		mimic the Java provider.
 */
CCIMProperty *
getFdisk(CCIMPropertyList *outParams, CCIMObjectPath *op)
{
	dm_descriptor_t		*da;
	int			i;
	int			cnt;
	ulong_t			*ret_array;
	int			error;
	char			*array_str;
	CCIMProperty		*prop;

	if (cim_checkRights(DISK_DRIVE, DISK_READ_RIGHT, (void *) NULL) ==
	    cim_false || op == NULL) {
		return (create_result_out(PROPFALSE, outParams));
	}

	if ((da = get_partition_descs(op)) == NULL) {
	    return (create_result_out(PROPFALSE, outParams));
	}

	/* Count the number of fdisk partitions. */
	for (cnt = 0; da[cnt]; cnt++);

	/* We return 4 values for each partition. */
	cnt = cnt * 4;

	ret_array = (ulong_t *)calloc(cnt, sizeof (ulong_t));
	if (ret_array == NULL) {
	    dm_free_descriptors(da);
	    util_handleError(DISK_DRIVE, CIM_ERR_FAILED, CIM_ERR_FAILED, NULL,
		&error);
	    return (create_result_out(PROPFALSE, outParams));
	}

	for (i = 0; da[i]; i++) {
	    if (!add_fdisk_props(ret_array, i, da[i])) {
		dm_free_descriptors(da);
		free(ret_array);
		return (create_result_out(PROPFALSE, outParams));
	    }
	}

	dm_free_descriptors(da);

	array_str = cim_encodeUint32Array(ret_array, cnt);

	free(ret_array);

	if (array_str == NULL) {
	    util_handleError(DISK_DRIVE, CIM_ERR_FAILED, CIM_ERR_FAILED, NULL,
		&error);
	    return (create_result_out(PROPFALSE, outParams));
	}

	if ((prop = cim_createProperty("FDiskPartitions", sint32_array,
	    array_str, NULL, cim_false)) == NULL) {
	    free(array_str);
	    return (create_result_out(PROPFALSE, outParams));
	}

	if ((cim_addPropertyToPropertyList(outParams, prop)) == NULL) {
	    cim_freeProperty(prop);
	    return (create_result_out(PROPFALSE, outParams));
	}

	return (create_result_out(PROPTRUE, outParams));
}

static int
add_fdisk_props(ulong_t *ret_array, int part_num, dm_descriptor_t d)
{
	int		error;
	nvlist_t	*attrs;
	int		i;
	int		result = 1;
	int		offset;
	static char	*attr_names[] = {
	    DM_PTYPE, DM_BOOTID, DM_RELSECT, DM_NSECTORS, NULL};

	attrs = dm_get_attributes(d, &error);
	if (error != 0) {
	    return (0);
	}

	/* figure out where in the array to put the values */
	offset = part_num * 4;

	for (i = 0; attr_names[i]; i++) {
	    uint32_t	val32;

	    if (nvlist_lookup_uint32(attrs, attr_names[i], &val32) != 0) {
		result = 0;
		break;
	    }

	    ret_array[offset++] = val32;
	}

	nvlist_free(attrs);
	return (result);
}

/*
 * inParams - CCIMPropertyList pointer that dereferences to a list of not less
 * than 4 or more than 16 CCIMProperty values.  Number of CCIMProperty values
 * must be a multiple of 4.
 *
 * The fdisk file will contain at least one line and not more than four lines
 * in the following format:
 *	id:act:0:0:0:0:0:0:rsect:numsect.
 * Values for id, act, rsect and numsect are taken from inParams.
 */
static CIMBool
build_fdisk_file(char *fdisk_file, CCIMPropertyList *params)
{
	FILE	*fp;
	int	i;
	int	error;
	ulong_t	*vals;
	int	cnt = 0;

	if (params == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (cim_false);
	}

	vals = cim_decodeUint32Array(get_prop_val(params->mDataObject), &cnt);

	if (cnt == 0 || cnt > 16 || (cnt % 4) != 0) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (cim_false);
	}

	(void) tmpnam(fdisk_file);

	/* Open the temporary file for writing */
	if ((fp = util_openFile(fdisk_file, "w")) == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED, NULL,
		NULL, &error);
	    return (cim_false);
	}

	/*
	 * Build a fdisk_file using 4 input parameters at a time.
	 * Check for all possible NULL parameters, parameter lists
	 * greater than 16 or not a multiple of 4.
	 */
	for (i = 0; i < cnt; i += 4) {
	    char	line_buf[DATALEN];

	    (void) snprintf(line_buf, sizeof (line_buf),
		"%lu:%lu:0:0:0:0:0:0:%lu:%lu\n",
		vals[i], vals[i + 1], vals[i + 2], vals[i + 3]);

	    /* Write the line of parameters to the fdisk_file */
	    if ((fputs(line_buf, fp)) == EOF) {
		util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		    NULL, NULL, &error);
		(void) util_closeFile(fp, fdisk_file);
		return (cim_false);
	    }
	}

	if ((util_closeFile(fp, fdisk_file)) == 0) {
	    return (cim_false);
	}

	/* Caller must delete the temporary file */
	return (cim_true);
}

/*
 * inParams - CCIMPropertyList pointer that dereferences to a list of not less
 * than 5 CCIMProperty values. The number of CCIMProperty values must be a
 * multiple of 5.
 *
 * The file will contain at least one line in the following format:
 *	part tag flag start_sect part_size
 * Values for partition, tag, flag, starting sector and partition size are
 * taken from inParams.
 */
static CIMBool
build_fmt_file(char *fmt_file, CCIMPropertyList *params)
{
	ulong_t	*vals;
	int	cnt = 0;
	FILE	*fp;
	int	error;
	int	i;

	if (params == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (cim_false);
	}

	vals = cim_decodeUint32Array(get_prop_val(params->mDataObject), &cnt);

	if (cnt == 0 || (cnt % 5) != 0) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (cim_false);
	}

	(void) tmpnam(fmt_file);

	/* Open the temporary file for writing */
	if ((fp = util_openFile(fmt_file, "w")) == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED, NULL,
		NULL, &error);
	    return (cim_false);
	}

	/*
	 * Build a data file for the fmthard command.
	 * Each line of the file consists of:
	 *
	 * part_num tag flag start_sector partition_size
	 *
	 * The fmthard command requires the starting sector fall on
	 * a cylinder boundry.
	 */
	for (i = 0; i < cnt; i += 5) {
	    char	line_buf[DATALEN];
	    char	flag_buf[DATALEN];

	    convert_flag(vals[i + 2], flag_buf, sizeof (flag_buf));

	    (void) snprintf(line_buf, sizeof (line_buf),
		"%lu %lu %s %lu %lu\n",
		vals[i], vals[i + 1], flag_buf, vals[i + 3], vals[i + 4]);

	    /* Write the line of parameters to the fdisk_file */
	    if ((fputs(line_buf, fp)) == EOF) {
		util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		    NULL, NULL, &error);
		(void) util_closeFile(fp, fmt_file);
		return (cim_false);
	    }
	}

	if ((util_closeFile(fp, fmt_file)) == 0) {
	    return (cim_false);
	}

	/* Caller must delete the file */
	return (cim_true);
}

/*
 * check_rights
 *
 * Performs check for 'admin write' rights.  Handles error
 * checking and reporting.  Returns cim_true on success and
 * cim_false on failure.
 */
static CIMBool
check_rights(char *provider)
{

	int		error;

	if ((cim_checkRights(provider, DISK_WRITE_RIGHT, (void *) NULL))
	    == cim_false) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_ACCESS_DENIED, NULL,
		NULL, &error);
	    return (cim_false);
	}
	return (cim_true);
}

/*
 * Converts decimal flag value to hex string.
 * Valid flag values are hex 00, 01, 10, 11.
 * Places result in new cimchar array and returns
 * pointer to array on success and NULL on failure.
 */
static void
convert_flag(long flag, char *flag_buf, int len)
{
	switch (flag) {
	case 1:
		(void) strlcpy(flag_buf, "0x01", len);
		break;
	case 16:
		(void) strlcpy(flag_buf, "0x10", len);
		break;
	case 17:
		(void) strlcpy(flag_buf, "0x11", len);
		break;
	default:
		(void) strlcpy(flag_buf, "0x00", len);
		break;
	}
}

static CCIMProperty *
create_result(char *status)
{
	return (cim_createProperty("result", boolean, status, NULL, cim_false));
}

static CCIMProperty *
create_result_out(char *status, CCIMPropertyList *outParams)
{
	if (strcmp(status, PROPFALSE) == 0) {
	    /* We have to put something in the out params when we fail. */
	    ulong_t		dummy [] = {0};
	    int			error;
	    char		*array_str;
	    CCIMProperty	*p;

	    if ((array_str = cim_encodeUint32Array(dummy, 1)) == NULL) {
		util_handleError(DISK_DRIVE, CIM_ERR_FAILED, CIM_ERR_FAILED,
		    NULL, &error);
	    } else if ((p = cim_createProperty("FDiskPartitions",
		sint32_array, array_str, NULL, cim_false)) == NULL) {
		free(array_str);
	    } else if ((cim_addPropertyToPropertyList(outParams, p)) == NULL) {
		cim_freeProperty(p);
	    }
	}

	return (create_result(status));
}

/*
 * Return: 1 if fails, 0 if ok.  geometry array contains:
 *     0. SectorsPerCylinder
 *     1. HeadsPerCylinder
 *     2. BytesPerCylinder
 *     3. PhysicalCylinders
 *     4. DataCylinders
 *     5. AlternateCylinders
 *     6. ActualCylinders
 */
static int
disk_geometry(char *media_name, ulong_t *geometry)
{
	int		error;
	dm_descriptor_t d;
	nvlist_t	*attrs;
	uint32_t	val32;

	d = dm_get_descriptor_by_name(DM_MEDIA, media_name, &error);
	if (error != 0) {
	    return (1);
	}

	attrs = dm_get_attributes(d, &error);
	dm_free_descriptor(d);
	if (error != 0) {
	    return (1);
	}

	/*
	 * If nsect is not in the attr list then we have media that does
	 * not have geometry info on it (e.g. EFI label).  So return a failure
	 * in this case.  Otherwise, just get the attrs we can and return
	 * their values.
	 */
	if (nvlist_lookup_uint32(attrs, DM_NSECTORS, &val32) != 0) {
	    nvlist_free(attrs);
	    return (1);
	}
	geometry[0] = val32;
	val32 = 0;

	(void) nvlist_lookup_uint32(attrs, DM_NHEADS, &val32);
	geometry[1] = val32;
	val32 = 0;
	(void) nvlist_lookup_uint32(attrs, DM_BLOCKSIZE, &val32);
	geometry[2] = (geometry[1] * geometry[0]) * val32;
	val32 = 0;
	(void) nvlist_lookup_uint32(attrs, DM_NPHYSCYLINDERS, &val32);
	geometry[3] = val32;
	val32 = 0;
	(void) nvlist_lookup_uint32(attrs, DM_NCYLINDERS, &val32);
	geometry[4] = val32;
	val32 = 0;
	(void) nvlist_lookup_uint32(attrs, DM_NALTCYLINDERS, &val32);
	geometry[5] = val32;
	val32 = 0;
	/* This one is probably there only in x86 machines. */
	(void) nvlist_lookup_uint32(attrs, DM_NACTUALCYLINDERS, &val32);
	geometry[6] = val32;

	nvlist_free(attrs);

	return (0);
}

/*
 * Use popen to execute a command.  Check for failures and
 * handle error reporting.
 * params:
 *   commandLine - the command to execute
 *   err_file - file that receives the stderr output from the
 *		command
 *
 * Returns cim_true on success, cim_false on failure.
 *
 * Note:  function removes the error file if it exists
 */
static CIMBool
execute_cmd(char *command_line, char *err_file)
{
	FILE	*cfp;
	char   	buf[BUFSIZ];
	int	result;
	int	error;

	cim_logDebug("execute_cmd", "%s ", command_line);

	/* Execute the fmthard command using popen */
	if ((cfp = popen(command_line, "r")) == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED, NULL,
		NULL, &error);
	    return (cim_false);
	}

	/* Read the commands stdout and ignore it */
	while (fgets(buf, sizeof (buf), cfp) != NULL);
	result = pclose(cfp);

	/* the buf will hold any error output */
	buf[0] = '\0';
	if (strcmp(err_file, "/dev/null") != 0) {
	    FILE	*efp;

	    if ((efp = util_openFile(err_file, "r")) == NULL) {
		/*
		 * err_file should have been created when popen executed
		 * 'commandLine', so the openFile shouldn't fail.  Treating it
		 * as a failure.
		 */
		util_handleError(INVOKE_METHOD, CIM_ERR_FAILED, NULL,
		    NULL, &error);
		util_removeFile(err_file);
		return (cim_false);
	    }

	    (void) fgets(buf, sizeof (buf), efp);
	    cim_logDebug("execute_cmd", "err output: %s", buf);
	    (void) util_closeFile(efp, err_file);
	    util_removeFile(err_file);
	}

	if (strlen(buf) != 0 ||
	    (WIFEXITED(result) != 0 && WEXITSTATUS(result) != 0)) {

	    cim_logDebug("execute_cmd", "exit: %d %d", WIFEXITED(result),
		WEXITSTATUS(result));
	    util_handleError(INVOKE_METHOD, CIM_ERR_FAILED, NULL, NULL, &error);
	    return (cim_false);
	}

	return (cim_true);
}

/*
 * Take the deviceID property from the object path and get the raw devpath
 * of the drive that corresponds to the given device ID.
 */
static CIMBool
get_devpath(CCIMObjectPath *op, char *devpath, int len)
{
	CCIMPropertyList	*prop_list = NULL;
	CCIMProperty		*prop = NULL;
	int			error;
	dm_descriptor_t		dp;
	dm_descriptor_t		*da;
	nvlist_t		*attrs;
	char			*opath;
	char			*keyprop;
	int			type = 0;
	char			*p;

	if (strcasecmp(op->mName, "Solaris_Disk") == 0) {
	    keyprop = "Tag";
	    type = 1;
	} else if (strcasecmp(op->mName, "Solaris_DiskDrive") == 0) {
	    keyprop = "deviceid";
	    type = 2;
	} else if (strcasecmp(op->mName, "Solaris_DiskPartition") == 0) {
	    keyprop = "deviceid";
	    type = 3;
	} else {
	    return (cim_false);
	}

	if (op != NULL) {
	    prop_list = op->mKeyProperties;
	}

	for (; prop_list; prop_list = prop_list->mNext) {

	    if (((prop = prop_list->mDataObject) != NULL &&
		prop->mName != NULL && strcasecmp(prop->mName, keyprop)) == 0) {
		break;
	    }
	}

	if (prop == NULL || prop->mValue == NULL) {
	    return (cim_false);
	}

	switch (type) {
	case 1:
	    dp = dm_get_descriptor_by_name(DM_MEDIA, prop->mValue, &error);
	    if (error != 0) {
		return (cim_false);
	    }

	    da = dm_get_associated_descriptors(dp, DM_DRIVE, &error);
	    dm_free_descriptor(dp);
	    if (error != 0 || da == NULL) {
		return (cim_false);
	    }

	    if (da[0] == NULL) {
		dm_free_descriptors(da);
		return (cim_false);
	    }

	    attrs = dm_get_attributes(da[0], &error);
	    dm_free_descriptors(da);
	    if (error != 0) {
		return (cim_false);
	    }

	    if (nvlist_lookup_string(attrs, DM_OPATH, &opath) != 0) {
		nvlist_free(attrs);
		return (cim_false);
	    }
	    (void) strlcpy(devpath, opath, len);
	    nvlist_free(attrs);
	    break;

	case 2:
	    dp = dm_get_descriptor_by_name(DM_DRIVE, prop->mValue, &error);
	    if (error != 0) {
		return (cim_false);
	    }

	    attrs = dm_get_attributes(dp, &error);
	    dm_free_descriptor(dp);
	    if (error != 0) {
		return (cim_false);
	    }

	    if (nvlist_lookup_string(attrs, DM_OPATH, &opath) != 0) {
		nvlist_free(attrs);
		return (cim_false);
	    }
	    (void) strlcpy(devpath, opath, len);
	    nvlist_free(attrs);
	    break;

	case 3:
	    /* Convert the Solaris_DiskPartition value to rdsk. */
	    p = strstr(prop->mValue, "/dsk/");
	    if (p == NULL || (strlen(prop->mValue) + 2) > len) {
		(void) strlcpy(devpath, prop->mValue, len);
	    } else {
		p++;
		*p = 0;
		(void) strcpy(devpath, prop->mValue);	/* copy up to dsk/ */
		*p = 'd';
		(void) strcat(devpath, "r");		/* prefix 'r' to dsk/ */
		(void) strcat(devpath, p);		/* append the rest */
	    }
	    break;
	}

	return (cim_true);
}

/*
 * Take the deviceID property from the object path and get the raw devpath
 * of the drive that corresponds to the given device ID.
 */
static dm_descriptor_t *
get_partition_descs(CCIMObjectPath *op)
{
	CCIMPropertyList	*prop_list = NULL;
	CCIMProperty		*prop = NULL;
	int			error;
	dm_descriptor_t		dp;
	dm_descriptor_t		*da;
	dm_descriptor_t		*dpa;

	if (op != NULL) {
	    prop_list = op->mKeyProperties;
	}

	for (; prop_list; prop_list = prop_list->mNext) {

	    if (((prop = prop_list->mDataObject) != NULL &&
		prop->mName != NULL &&
		strcasecmp(prop->mName, "deviceid")) == 0) {
		break;
	    }
	}

	if (prop == NULL || prop->mValue == NULL) {
	    return (NULL);
	}

	dp = dm_get_descriptor_by_name(DM_DRIVE, prop->mValue, &error);
	if (error != 0) {
	    return (NULL);
	}

	da = dm_get_associated_descriptors(dp, DM_MEDIA, &error);
	dm_free_descriptor(dp);
	if (error != 0 || da == NULL) {
	    return (NULL);
	}

	if (da[0] == NULL) {
	    dm_free_descriptors(da);
	    return (NULL);
	}

	dpa = dm_get_associated_descriptors(da[0], DM_PARTITION, &error);
	dm_free_descriptors(da);
	if (error != 0 || dpa == NULL) {
	    return (NULL);
	}

	if (dpa[0] == NULL) {
	    dm_free_descriptors(dpa);
	    return (NULL);
	}

	return (dpa);
}

static cimchar *
get_prop_val(CCIMProperty *prop)
{

	int		error;

	if (prop == NULL || prop->mValue == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((cimchar *)NULL);
	}
	return (prop->mValue);
}

static void
make_fdisk_path(char *devpath)
{
	int len;

	len = strlen(devpath) - 2;
	if (len <= 0 || *(devpath + len) != 's') {
	    return;
	}

	*(devpath + len) = 'p';
}
