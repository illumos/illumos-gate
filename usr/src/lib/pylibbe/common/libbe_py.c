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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
 */

#include <Python.h>
#include <sys/varargs.h>
#include <stdio.h>
#include <libnvpair.h>

#include <libbe.h>
#include <libbe_priv.h>

enum {
	BE_PY_SUCCESS = 0,
	BE_PY_ERR_APPEND = 6000,
	BE_PY_ERR_DICT,
	BE_PY_ERR_LIST,
	BE_PY_ERR_NVLIST,
	BE_PY_ERR_PARSETUPLE,
	BE_PY_ERR_PRINT_ERR,
	BE_PY_ERR_VAR_CONV,
} bePyErr;

/*
 * public libbe functions
 */

PyObject *beCreateSnapshot(PyObject *, PyObject *);
PyObject *beCopy(PyObject *, PyObject *);
PyObject *beList(PyObject *, PyObject *);
PyObject *beActivate(PyObject *, PyObject *);
PyObject *beDestroy(PyObject *, PyObject *);
PyObject *beDestroySnapshot(PyObject *, PyObject *);
PyObject *beRename(PyObject *, PyObject *);
PyObject *beMount(PyObject *, PyObject *);
PyObject *beUnmount(PyObject *, PyObject *);
PyObject *bePrintErrors(PyObject *, PyObject *);
PyObject *beGetErrDesc(PyObject *, PyObject *);
char *beMapLibbePyErrorToString(int);
void initlibbe_py();

static boolean_t convertBEInfoToDictionary(be_node_list_t *be,
    PyObject **listDict);
static boolean_t convertDatasetInfoToDictionary(be_dataset_list_t *ds,
    PyObject **listDict);
static boolean_t convertSnapshotInfoToDictionary(be_snapshot_list_t *ss,
    PyObject **listDict);
static boolean_t convertPyArgsToNvlist(nvlist_t **nvList, int numArgs, ...);


/* ~~~~~~~~~~~~~~~ */
/* Public Funtions */
/* ~~~~~~~~~~~~~~~ */

/*
 * Function:    beCreateSnapshot
 * Description: Convert Python args to nvlist pairs and
 *              call libbe:be_create_snapshot to create a
 *              snapshot of all the datasets within a BE
 * Parameters:
 *   args -          pointer to a python object containing:
 *        beName -   The name of the BE to create a snapshot of
 *        snapName - The name of the snapshot to create (optional)
 *
 *        The following public attribute values. defined by libbe.h,
 *        are used by this function:
 *
 * Returns a pointer to a python object and an optional snapshot name:
 *      0, [snapName] - Success
 *      1, [snapName] - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beCreateSnapshot(PyObject *self, PyObject *args)
{
	char	*beName = NULL;
	char	*snapName = NULL;
	int	ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;
	PyObject	*retVals = NULL;

	if (!PyArg_ParseTuple(args, "z|z", &beName, &snapName)) {
		return (Py_BuildValue("[is]", BE_PY_ERR_PARSETUPLE, NULL));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 4,
	    BE_ATTR_ORIG_BE_NAME, beName,
	    BE_ATTR_SNAP_NAME, snapName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("[is]", BE_PY_ERR_NVLIST, NULL));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if ((ret = be_create_snapshot(beAttrs)) != 0) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("[is]", ret, NULL));
	}
	if (snapName == NULL) {
		if (nvlist_lookup_pairs(beAttrs, NV_FLAG_NOENTOK,
		    BE_ATTR_SNAP_NAME, DATA_TYPE_STRING, &snapName,
		    NULL) != 0) {
			nvlist_free(beAttrs);
			return (Py_BuildValue("[is]",
			    BE_PY_ERR_NVLIST, NULL));
		}
		retVals = Py_BuildValue("[is]", ret, snapName);
		nvlist_free(beAttrs);
		return (retVals);
	}
	nvlist_free(beAttrs);

	return (Py_BuildValue("[is]", ret, NULL));
}

/*
 * Function:    beCopy
 * Description: Convert Python args to nvlist pairs and call libbe:be_copy
 *              to create a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     trgtBeName - The name of the BE to create
 *     srcBeName - The name of the BE used to create trgtBeName (optional)
 *     rpool - The pool to create the new BE in (optional)
 *     srcSnapName - The snapshot name (optional)
 *     beNameProperties - The properties to use when creating
 *                        the BE (optional)
 *
 * Returns a pointer to a python object. That Python object will consist of
 * the return code and optional attributes, trgtBeName and snapshotName
 *      BE_SUCCESS, [trgtBeName], [trgtSnapName] - Success
 *      1, [trgtBeName], [trgtSnapName] - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beCopy(PyObject *self, PyObject *args)
{
	char	*trgtBeName = NULL;
	char	*srcBeName = NULL;
	char	*srcSnapName = NULL;
	char	*trgtSnapName = NULL;
	char	*rpool = NULL;
	char	*beDescription = NULL;
	Py_ssize_t	pos = 0;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;
	nvlist_t	*beProps = NULL;
	PyObject	*beNameProperties = NULL;
	PyObject	*pkey = NULL;
	PyObject	*pvalue = NULL;
	PyObject	*retVals = NULL;

	if (!PyArg_ParseTuple(args, "|zzzzOz", &trgtBeName, &srcBeName,
	    &srcSnapName, &rpool, &beNameProperties, &beDescription)) {
		return (Py_BuildValue("[iss]", BE_PY_ERR_PARSETUPLE,
		    NULL, NULL));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 10,
	    BE_ATTR_NEW_BE_NAME, trgtBeName,
	    BE_ATTR_ORIG_BE_NAME, srcBeName,
	    BE_ATTR_SNAP_NAME, srcSnapName,
	    BE_ATTR_NEW_BE_POOL, rpool,
	    BE_ATTR_NEW_BE_DESC, beDescription)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("[iss]", BE_PY_ERR_NVLIST, NULL, NULL));
	}

	if (beNameProperties != NULL) {
		if (nvlist_alloc(&beProps, NV_UNIQUE_NAME, 0) != 0) {
			(void) printf("nvlist_alloc failed.\n");
			nvlist_free(beAttrs);
			return (Py_BuildValue("[iss]", BE_PY_ERR_NVLIST,
			    NULL, NULL));
		}
		while (PyDict_Next(beNameProperties, &pos, &pkey, &pvalue)) {
			if (!convertPyArgsToNvlist(&beProps, 2,
			    PyString_AsString(pkey),
			    PyString_AsString(pvalue))) {
				nvlist_free(beProps);
				nvlist_free(beAttrs);
				return (Py_BuildValue("[iss]", BE_PY_ERR_NVLIST,
				    NULL, NULL));
			}
		}
	}

	if (beProps != NULL && beAttrs != NULL &&
	    nvlist_add_nvlist(beAttrs, BE_ATTR_ZFS_PROPERTIES,
	    beProps) != 0) {
		nvlist_free(beProps);
		nvlist_free(beAttrs);
		return (Py_BuildValue("[iss]", BE_PY_ERR_NVLIST,
		    NULL, NULL));
	}

	if (beProps != NULL) nvlist_free(beProps);

	if (trgtBeName == NULL) {
		/*
		 * Caller wants to get back the BE_ATTR_NEW_BE_NAME and
		 * BE_ATTR_SNAP_NAME
		 */
		if ((ret = be_copy(beAttrs)) != BE_SUCCESS) {
			nvlist_free(beAttrs);
			return (Py_BuildValue("[iss]", ret, NULL, NULL));
		}

		/*
		 * When no trgtBeName is passed to be_copy, be_copy
		 * returns an auto generated beName and snapshot name.
		 */
		if (nvlist_lookup_string(beAttrs, BE_ATTR_NEW_BE_NAME,
		    &trgtBeName) != 0) {
			nvlist_free(beAttrs);
			return (Py_BuildValue("[iss]", BE_PY_ERR_NVLIST,
			    NULL, NULL));
		}
		if (nvlist_lookup_string(beAttrs, BE_ATTR_SNAP_NAME,
		    &trgtSnapName) != 0) {
			nvlist_free(beAttrs);
			return (Py_BuildValue("[iss]", BE_PY_ERR_NVLIST,
			    NULL, NULL));
		}

		retVals = Py_BuildValue("[iss]", BE_PY_SUCCESS,
		    trgtBeName, trgtSnapName);
		nvlist_free(beAttrs);
		return (retVals);

	} else {
		ret = be_copy(beAttrs);
		nvlist_free(beAttrs);
		return (Py_BuildValue("[iss]", ret, NULL, NULL));
	}
}

/*
 * Function:    beList
 * Description: Convert Python args to nvlist pairs and call libbe:be_list
 *              to gather information about Boot Environments
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the BE to list (optional)
 *
 * Returns a pointer to a python object. That Python object will consist of
 * the return code and a list of Dicts or NULL.
 *      BE_PY_SUCCESS, listOfDicts - Success
 *      bePyErr or be_errno_t, NULL - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beList(PyObject *self, PyObject *args)
{
	char	*beName = NULL;
	int	ret = BE_PY_SUCCESS;
	be_node_list_t *list = NULL;
	be_node_list_t *be = NULL;
	PyObject *dict = NULL;
	PyObject *listOfDicts = NULL;

	if ((listOfDicts = PyList_New(0)) == NULL) {
		ret = BE_PY_ERR_DICT;
		listOfDicts = Py_None;
		goto done;
	}

	if (!PyArg_ParseTuple(args, "|z", &beName)) {
		ret = BE_PY_ERR_PARSETUPLE;
		goto done;
	}

	if ((ret = be_list(beName, &list)) != BE_SUCCESS) {
		goto done;
	}

	for (be = list; be != NULL; be = be->be_next_node) {
		be_dataset_list_t *ds = be->be_node_datasets;
		be_snapshot_list_t *ss = be->be_node_snapshots;

		if ((dict = PyDict_New()) == NULL) {
			ret = BE_PY_ERR_DICT;
			goto done;
		}

		if (!convertBEInfoToDictionary(be, &dict)) {
			/* LINTED */
			Py_DECREF(dict);
			ret = BE_PY_ERR_VAR_CONV;
			goto done;
		}

		if (PyList_Append(listOfDicts, dict) != 0) {
			/* LINTED */
			Py_DECREF(dict);
			ret = BE_PY_ERR_APPEND;
			goto done;
		}

		/* LINTED */
		Py_DECREF(dict);

		while (ds != NULL) {
			if ((dict = PyDict_New()) == NULL) {
				ret = BE_PY_ERR_DICT;
				goto done;
			}

			if (!convertDatasetInfoToDictionary(ds, &dict)) {
				/* LINTED */
				Py_DECREF(dict);
				ret = BE_PY_ERR_VAR_CONV;
				goto done;
			}

			if (PyList_Append(listOfDicts, dict) != 0) {
				/* LINTED */
				Py_DECREF(dict);
				ret = BE_PY_ERR_APPEND;
				goto done;
			}

			ds = ds->be_next_dataset;

			/* LINTED */
			Py_DECREF(dict);
		}


		while (ss != NULL) {
			if ((dict = PyDict_New()) == NULL) {
				/* LINTED */
				Py_DECREF(dict);
				ret = BE_PY_ERR_DICT;
				goto done;
			}

			if (!convertSnapshotInfoToDictionary(ss, &dict)) {
				/* LINTED */
				Py_DECREF(dict);
				ret = BE_PY_ERR_VAR_CONV;
				goto done;
			}

			if (PyList_Append(listOfDicts, dict) != 0) {
				/* LINTED */
				Py_DECREF(dict);
				ret = BE_PY_ERR_APPEND;
				goto done;
			}

			ss = ss->be_next_snapshot;

			/* LINTED */
			Py_DECREF(dict);
		}
	}

done:
	if (list != NULL)
		be_free_list(list);
	return (Py_BuildValue("[iO]", ret, listOfDicts));
}

/*
 * Function:    beActivate
 * Description: Convert Python args to nvlist pairs and call libbe:be_activate
 *              to activate a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the BE to activate
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beActivate(PyObject *self, PyObject *args)
{
	char		*beName = NULL;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "z", &beName)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 2, BE_ATTR_ORIG_BE_NAME, beName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_activate(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    beDestroy
 * Description: Convert Python args to nvlist pairs and call libbe:be_destroy
 *              to destroy a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the BE to destroy
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beDestroy(PyObject *self, PyObject *args)
{
	char		*beName = NULL;
	int		destroy_snaps = 0;
	int		force_unmount = 0;
	int		destroy_flags = 0;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "z|ii", &beName, &destroy_snaps,
	    &force_unmount)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (destroy_snaps == 1)
		destroy_flags |= BE_DESTROY_FLAG_SNAPSHOTS;

	if (force_unmount == 1)
		destroy_flags |= BE_DESTROY_FLAG_FORCE_UNMOUNT;

	if (!convertPyArgsToNvlist(&beAttrs, 2, BE_ATTR_ORIG_BE_NAME, beName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (nvlist_add_uint16(beAttrs, BE_ATTR_DESTROY_FLAGS, destroy_flags)
	    != 0) {
		(void) printf("nvlist_add_uint16 failed for "
		    "BE_ATTR_DESTROY_FLAGS (%d).\n", destroy_flags);
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_destroy(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    beDestroySnapshot
 * Description: Convert Python args to nvlist pairs and call libbe:be_destroy
 *              to destroy a snapshot of a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the BE to destroy
 *     snapName - The name of the snapshot to destroy
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beDestroySnapshot(PyObject *self, PyObject *args)
{
	char		*beName = NULL;
	char		*snapName = NULL;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "zz", &beName, &snapName)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 4,
	    BE_ATTR_ORIG_BE_NAME, beName,
	    BE_ATTR_SNAP_NAME, snapName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_destroy_snapshot(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    beRename
 * Description: Convert Python args to nvlist pairs and call libbe:be_rename
 *              to rename a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     oldBeName - The name of the old Boot Environment
 *     newBeName - The name of the new Boot Environment
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beRename(PyObject *self, PyObject *args)
{
	char		*oldBeName = NULL;
	char		*newBeName = NULL;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "zz", &oldBeName, &newBeName)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 4,
	    BE_ATTR_ORIG_BE_NAME, oldBeName,
	    BE_ATTR_NEW_BE_NAME, newBeName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_rename(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    beMount
 * Description: Convert Python args to nvlist pairs and call libbe:be_mount
 *              to mount a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the Boot Environment to mount
 *     mountpoint - The path of the mountpoint to mount the
 *                  Boot Environment on (optional)
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beMount(PyObject *self, PyObject *args)
{
	char		*beName = NULL;
	char		*mountpoint = NULL;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "zz", &beName, &mountpoint)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 4,
	    BE_ATTR_ORIG_BE_NAME, beName,
	    BE_ATTR_MOUNTPOINT, mountpoint)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_mount(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    beUnmount
 * Description: Convert Python args to nvlist pairs and call libbe:be_unmount
 *              to unmount a Boot Environment
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the Boot Environment to unmount
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beUnmount(PyObject *self, PyObject *args)
{
	char 		*beName = NULL;
	int		force_unmount = 0;
	int		unmount_flags = 0;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "z|i", &beName, &force_unmount)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (force_unmount == 1)
		unmount_flags |= BE_UNMOUNT_FLAG_FORCE;

	if (!convertPyArgsToNvlist(&beAttrs, 2,
	    BE_ATTR_ORIG_BE_NAME, beName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (nvlist_add_uint16(beAttrs, BE_ATTR_UNMOUNT_FLAGS, unmount_flags)
	    != 0) {
		(void) printf("nvlist_add_uint16 failed for "
		    "BE_ATTR_UNMOUNT_FLAGS (%d).\n", unmount_flags);
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_unmount(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    beRollback
 * Description: Convert Python args to nvlist pairs and call libbe:be_rollback
 *              to rollback a Boot Environment to a previously taken
 *               snapshot.
 * Parameters:
 *   args -     pointer to a python object containing:
 *     beName - The name of the Boot Environment to unmount
 *
 * Returns a pointer to a python object:
 *      BE_SUCCESS - Success
 *      bePyErr or be_errno_t - Failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beRollback(PyObject *self, PyObject *args)
{
	char		*beName = NULL;
	char		*snapName = NULL;
	int		ret = BE_PY_SUCCESS;
	nvlist_t	*beAttrs = NULL;

	if (!PyArg_ParseTuple(args, "zz", &beName, &snapName)) {
		return (Py_BuildValue("i", BE_PY_ERR_PARSETUPLE));
	}

	if (!convertPyArgsToNvlist(&beAttrs, 4,
	    BE_ATTR_ORIG_BE_NAME, beName,
	    BE_ATTR_SNAP_NAME, snapName)) {
		nvlist_free(beAttrs);
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	if (beAttrs == NULL) {
		return (Py_BuildValue("i", BE_PY_ERR_NVLIST));
	}

	ret = be_rollback(beAttrs);
	nvlist_free(beAttrs);
	return (Py_BuildValue("i", ret));
}

/*
 * Function:    bePrintErrors
 * Description: Convert Python args to boolean and call libbe_print_errors to
 *			turn on/off error output for the library.
 * Parameter:
 *   args -     pointer to a python object containing:
 *		print_errors - Boolean that turns library error
 *			       printing on or off.
 * Parameters:
 *   args -     pointer to a python object containing:
 *     0 - do not print errors - Python boolean "False"
 *     1 - print errors - Python boolean "True"
 *
 * Returns 1 on missing or invalid argument, 0 otherwise
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
bePrintErrors(PyObject *self, PyObject *args)
{
	int		print_errors;

	if (!PyArg_ParseTuple(args, "i", &print_errors) ||
	    (print_errors != 1 && print_errors != 0))
		return (Py_BuildValue("i", BE_PY_ERR_PRINT_ERR));
	libbe_print_errors(print_errors == 1);
	return (Py_BuildValue("i", BE_PY_SUCCESS));
}

/*
 * Function:    beGetErrDesc
 * Description: Convert Python args to an int and call be_err_to_str to
 *			map an error code to an error string.
 * Parameter:
 *   args -     pointer to a python object containing:
 *		errCode - value to map to an error string.
 *
 * Returns: error string or NULL
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beGetErrDesc(PyObject *self, PyObject *args)
{
	int	errCode = 0;
	char	*beErrStr = NULL;

	if (!PyArg_ParseTuple(args, "i", &errCode)) {
		return (Py_BuildValue("s", NULL));
	}

	/*
	 * First check libbe_py errors. If NULL is returned check error codes
	 * in libbe.
	 */

	if ((beErrStr = beMapLibbePyErrorToString(errCode)) == NULL) {
		beErrStr = be_err_to_str(errCode);
	}

	return (Py_BuildValue("s", beErrStr));
}

/*
 * Function:    beVerifyBEName
 * Description: Call be_valid_be_name() to verify the BE name.
 * Parameter:
 *   args -     pointer to a python object containing:
 *		string - value to map to a string.
 *
 * Returns:  0 for success or 1 for failure
 * Scope:
 *      Public
 */
/* ARGSUSED */
PyObject *
beVerifyBEName(PyObject *self, PyObject *args)
{
	char	*string = NULL;

	if (!PyArg_ParseTuple(args, "s", &string)) {
		return (Py_BuildValue("i", 1));
	}

	if (be_valid_be_name(string)) {
		return (Py_BuildValue("i", 0));
	} else {
		return (Py_BuildValue("i", 1));
	}
}

/* ~~~~~~~~~~~~~~~~~ */
/* Private Functions */
/* ~~~~~~~~~~~~~~~~~ */

static boolean_t
convertBEInfoToDictionary(be_node_list_t *be, PyObject **listDict)
{
	if (be->be_node_name != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_ORIG_BE_NAME,
		    PyString_FromString(be->be_node_name)) != 0) {
			return (B_FALSE);
		}
	}

	if (be->be_rpool != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_ORIG_BE_POOL,
		    PyString_FromString(be->be_rpool)) != 0) {
			return (B_FALSE);
		}
	}

	if (be->be_mntpt != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_MOUNTPOINT,
		    PyString_FromString(be->be_mntpt)) != 0) {
			return (B_FALSE);
		}
	}

	if (PyDict_SetItemString(*listDict, BE_ATTR_MOUNTED,
	    (be->be_mounted ? Py_True : Py_False)) != 0) {
		return (B_FALSE);
	}

	if (PyDict_SetItemString(*listDict, BE_ATTR_ACTIVE,
	    (be->be_active ? Py_True : Py_False)) != 0) {
		return (B_FALSE);
	}

	if (PyDict_SetItemString(*listDict, BE_ATTR_ACTIVE_ON_BOOT,
	    (be->be_active_on_boot ? Py_True : Py_False)) != 0) {
		return (B_FALSE);
	}

	if (PyDict_SetItemString(*listDict, BE_ATTR_GLOBAL_ACTIVE,
	    (be->be_global_active ? Py_True : Py_False)) != 0) {
		return (B_FALSE);
	}

	if (be->be_space_used != 0) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_SPACE,
		    PyLong_FromUnsignedLongLong(be->be_space_used)) != 0) {
			return (B_FALSE);
		}
	}

	if (be->be_root_ds != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_ROOT_DS,
		    PyString_FromString(be->be_root_ds)) != 0) {
			return (B_FALSE);
		}
	}

	if (be->be_node_creation != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_DATE,
		    PyLong_FromLong(be->be_node_creation)) != 0) {
			return (B_FALSE);
		}
	}

	if (be->be_policy_type != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_POLICY,
		    PyString_FromString(be->be_policy_type)) != 0) {
			return (B_FALSE);
		}
	}

	if (be->be_uuid_str != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_UUID_STR,
		    PyString_FromString(be->be_uuid_str)) != 0) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
convertDatasetInfoToDictionary(be_dataset_list_t *ds, PyObject **listDict)
{
	if (ds->be_dataset_name != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_DATASET,
		    PyString_FromString(ds->be_dataset_name)) != 0) {
			return (B_FALSE);
		}
	}

	if (PyDict_SetItemString(*listDict, BE_ATTR_STATUS,
	    (ds->be_ds_mounted ? Py_True : Py_False)) != 0) {
			return (B_FALSE);
	}

	if (ds->be_ds_mntpt != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_MOUNTPOINT,
		    PyString_FromString(ds->be_ds_mntpt)) != 0) {
			return (B_FALSE);
		}
	}

	if (PyDict_SetItemString(*listDict, BE_ATTR_MOUNTED,
	    (ds->be_ds_mounted ? Py_True : Py_False)) != 0) {
		return (B_FALSE);
	}

	if (ds->be_ds_space_used != 0) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_SPACE,
		    PyLong_FromUnsignedLongLong(ds->be_ds_space_used))
		    != 0) {
			return (B_FALSE);
		}
	}

	if (ds->be_dataset_name != 0) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_DATASET,
		    PyString_FromString(ds->be_dataset_name)) != 0) {
			return (B_FALSE);
		}
	}

	if (ds->be_ds_plcy_type != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_POLICY,
		    PyString_FromString(ds->be_ds_plcy_type)) != 0) {
			return (B_FALSE);
		}
	}

	if (ds->be_ds_creation != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_DATE,
		    PyLong_FromLong(ds->be_ds_creation)) != 0) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
convertSnapshotInfoToDictionary(be_snapshot_list_t *ss, PyObject **listDict)
{
	if (ss->be_snapshot_name != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_SNAP_NAME,
		    PyString_FromString(ss->be_snapshot_name)) != 0) {
			return (B_FALSE);
		}
	}

	if (ss->be_snapshot_creation != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_DATE,
		    PyLong_FromLong(ss->be_snapshot_creation)) != 0) {
			return (B_FALSE);
		}
	}

	if (ss->be_snapshot_type != NULL) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_POLICY,
		    PyString_FromString(ss->be_snapshot_type)) != 0) {
			return (B_FALSE);
		}
	}

	if (ss->be_snapshot_space_used != 0) {
		if (PyDict_SetItemString(*listDict, BE_ATTR_SPACE,
		    PyLong_FromUnsignedLongLong(ss->be_snapshot_space_used))
		    != 0) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Convert string arguments to nvlist attributes
 */

static boolean_t
convertPyArgsToNvlist(nvlist_t **nvList, int numArgs, ...)
{
	char *pt, *pt2;
	va_list ap;
	int i;

	if (*nvList == NULL) {
		if (nvlist_alloc(nvList, NV_UNIQUE_NAME, 0) != 0) {
			(void) printf("nvlist_alloc failed.\n");
			return (B_FALSE);
		}
	}

	va_start(ap, numArgs);

	for (i = 0; i < numArgs; i += 2) {
		if ((pt = va_arg(ap, char *)) == NULL ||
		    (pt2 = va_arg(ap, char *)) == NULL) {
			continue;
		}
		if (nvlist_add_string(*nvList, pt, pt2) != 0) {
			(void) printf("nvlist_add_string failed for %s (%s).\n",
			    pt, pt2);
			nvlist_free(*nvList);
			return (B_FALSE);
		}
	}

	va_end(ap);

	return (B_TRUE);
}

/*
 * Function:    beMapLibbePyErrorToString
 * Description: Convert Python args to an int and map an error code to an
 *			error string.
 * Parameter:
 *		errCode - value to map to an error string.
 *
 * Returns error string or NULL
 * Scope:
 *      Public
 */

char *
beMapLibbePyErrorToString(int errCode)
{
	switch (errCode) {
	case BE_PY_ERR_APPEND:
		return ("Unable to append a dictionary to a list "
		    "of dictinaries.");
	case BE_PY_ERR_DICT:
		return ("Creation of a Python dictionary failed.");
	case BE_PY_ERR_LIST:
		return ("beList() failed.");
	case BE_PY_ERR_NVLIST:
		return ("An nvlist operation failed.");
	case BE_PY_ERR_PARSETUPLE:
		return ("PyArg_ParseTuple() failed to convert variable to C.");
	case BE_PY_ERR_PRINT_ERR:
		return ("bePrintErrors() failed.");
	case BE_PY_ERR_VAR_CONV:
		return ("Unable to add variables to a Python dictionary.");
	default:
		return (NULL);
	}
}

/* Private python initialization structure */

static struct PyMethodDef libbeMethods[] = {
	{"beCopy", (PyCFunction)beCopy, METH_VARARGS, "Create/Copy a BE."},
	{"beCreateSnapshot", (PyCFunction)beCreateSnapshot, METH_VARARGS,
	    "Create a snapshot."},
	{"beDestroy", (PyCFunction)beDestroy, METH_VARARGS, "Destroy a BE."},
	{"beDestroySnapshot", (PyCFunction)beDestroySnapshot, METH_VARARGS,
	    "Destroy a snapshot."},
	{"beMount", (PyCFunction)beMount, METH_VARARGS, "Mount a BE."},
	{"beUnmount", (PyCFunction)beUnmount, METH_VARARGS, "Unmount a BE."},
	{"beList", (PyCFunction)beList, METH_VARARGS, "List BE info."},
	{"beRename", (PyCFunction)beRename, METH_VARARGS, "Rename a BE."},
	{"beActivate", (PyCFunction)beActivate, METH_VARARGS, "Activate a BE."},
	{"beRollback", (PyCFunction)beRollback, METH_VARARGS, "Rollback a BE."},
	{"bePrintErrors", (PyCFunction)bePrintErrors, METH_VARARGS,
	    "Enable/disable error printing."},
	{"beGetErrDesc", (PyCFunction)beGetErrDesc, METH_VARARGS,
	    "Map Error codes to strings."},
	{"beVerifyBEName", (PyCFunction)beVerifyBEName, METH_VARARGS,
	    "Verify BE name."},
	{NULL, NULL, 0, NULL}
};

void
initlibbe_py()
{
	/* PyMODINIT_FUNC; */
	(void) Py_InitModule("libbe_py", libbeMethods);
}
