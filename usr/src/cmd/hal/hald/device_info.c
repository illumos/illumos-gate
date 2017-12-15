/***************************************************************************
 * CVSID: $Id$
 *
 * device_store.c : Search for .fdi files and merge on match
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <expat.h>
#include <assert.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <math.h>

#include "hald.h"
#include "logger.h"
#include "device_info.h"
#include "device_store.h"
#include "util.h"

/**
 * @defgroup DeviceInfo Device Info File Parsing
 * @ingroup HalDaemon
 * @brief Parsing of device info files
 * @{
 */


/** Maximum nesting depth */
#define MAX_DEPTH 32

/** Maximum amount of CDATA */
#define CDATA_BUF_SIZE  1024

/** Max length of property key */
#define MAX_KEY_SIZE 128

/** Possible elements the parser can process */
enum {
	/** Not processing a known tag */
	CURELEM_UNKNOWN = -1,

	/** Processing a deviceinfo element */
	CURELEM_DEVICE_INFO = 0,

	/** Processing a device element */
	CURELEM_DEVICE = 1,

	/** Processing a match element */
	CURELEM_MATCH = 2,

	/** Processing a merge element */
	CURELEM_MERGE = 3,

	/** Processing an append element */
	CURELEM_APPEND = 4,

	/** Processing a prepend element */
	CURELEM_PREPEND = 5,

	/** Processing a remove element */
	CURELEM_REMOVE = 6,

	/** Processing a clear element */
	CURELEM_CLEAR = 7,

	/** Processing a spawn element */
	CURELEM_SPAWN = 8
};

/** What and how to merge */
enum {
	MERGE_TYPE_UNKNOWN       = 0,
	MERGE_TYPE_STRING        = 1,
	MERGE_TYPE_BOOLEAN       = 2,
	MERGE_TYPE_INT32         = 3,
	MERGE_TYPE_UINT64        = 4,
	MERGE_TYPE_DOUBLE        = 5,
	MERGE_TYPE_COPY_PROPERTY = 6,
	MERGE_TYPE_STRLIST       = 7,
	MERGE_TYPE_REMOVE        = 8,
	MERGE_TYPE_CLEAR         = 9,
	MERGE_TYPE_SPAWN         = 10
};

/** Parsing Context
 */
typedef struct {
	/** Name of file being parsed */
	char *file;

	/** Parser object */
	XML_Parser parser;

	/** Device we are trying to match*/
	HalDevice *device;

	/** Buffer to put CDATA in */
	char cdata_buf[CDATA_BUF_SIZE];

	/** Current length of CDATA buffer */
	int cdata_buf_len;
	
	/** Current depth we are parsing at */
	int depth;

	/** Element currently being processed */
	int curelem;

	/** Stack of elements being processed */
	int curelem_stack[MAX_DEPTH];

	/** #TRUE if parsing of document have been aborted */
	dbus_bool_t aborted;


	/** Depth of match-fail */
	int match_depth_first_fail;

	/** #TRUE if all matches on prior depths have been OK */
	dbus_bool_t match_ok;



	/** When merging, the key to store the value in */
	char merge_key[MAX_KEY_SIZE];

	/** Type to merge*/
	int merge_type;

	/** Set to #TRUE if a device is matched */
	dbus_bool_t device_matched;

} ParsingContext;

/** Resolve a udi-property path as used in .fdi files. 
 *
 *  Examples of udi-property paths:
 *
 *   info.udi
 *   /org/freedesktop/Hal/devices/computer:kernel.name
 *   @block.storage_device:storage.bus
 *   @block.storage_device:@storage.physical_device:ide.channel
 *
 *  @param  source_udi          UDI of source device
 *  @param  path                The given path
 *  @param  udi_result          Where to store the resulting UDI
 *  @param  udi_result_size     Size of UDI string
 *  @param  prop_result         Where to store the resulting property name
 *  @param  prop_result_size    Size of property string
 *  @return                     TRUE if and only if the path resolved.
 */
static gboolean
resolve_udiprop_path (const char *path, const char *source_udi,
		      char *udi_result, size_t udi_result_size, 
		      char *prop_result, size_t prop_result_size)
{
	int i;
	gchar **tokens = NULL;
	gboolean rc;

	rc = FALSE;

	/*HAL_INFO (("Looking at '%s' for udi='%s'", path, source_udi));*/

	/* Split up path into ':' tokens */
	tokens = g_strsplit (path, ":", 64);

	/* Detect trivial property access, e.g. path='foo.bar'   */
	if (tokens == NULL || tokens[0] == NULL || tokens[1] == NULL) {
		strncpy (udi_result, source_udi, udi_result_size);
		strncpy (prop_result, path, prop_result_size);
		rc = TRUE;
		goto out;
	}

	/* Start with the source udi */
	strncpy (udi_result, source_udi, udi_result_size);

	for (i = 0; tokens[i] != NULL; i++) {
		HalDevice *d;
		gchar *curtoken;

		/*HAL_INFO (("tokens[%d] = '%s'", i, tokens[i]));*/

		d = hal_device_store_find (hald_get_gdl (), udi_result);
		if (d == NULL)
			d = hal_device_store_find (hald_get_tdl (), udi_result);
		if (d == NULL)
			goto out;

		curtoken = tokens[i];

		/* process all but the last tokens as UDI paths */
		if (tokens[i+1] == NULL) {
			strncpy (prop_result, curtoken, prop_result_size);
			rc = TRUE;
			goto out;
		}


		/* Check for indirection */
		if (curtoken[0] == '@') {
			const char *udiprop;
			const char *newudi;

			udiprop = curtoken + 1;

			newudi = hal_device_property_get_string (d, udiprop);
			if (newudi == NULL)
				goto out;

			/*HAL_INFO (("new_udi = '%s' (from indirection)", newudi));*/

			strncpy (udi_result, newudi, udi_result_size);
		} else {
			/*HAL_INFO (("new_udi = '%s'", curtoken));*/
			strncpy (udi_result, curtoken, udi_result_size);
		}

	}

out:

/*
	HAL_INFO (("success     = '%s'", rc ? "yes" : "no"));
	HAL_INFO (("udi_result  = '%s'", udi_result));
	HAL_INFO (("prop_result = '%s'", prop_result));
*/

	g_strfreev (tokens);

	return rc;
}

/* Compare the value of a property on a hal device object against a string value
 * and return the result. Note that this works for several types, e.g. both strings
 * and integers - in the latter case the given right side string will be interpreted
 * as a number.
 *
 * The comparison might not make sense if you are comparing a property which is an integer
 * against a string in which case this function returns FALSE. Also, if the property doesn't
 * exist this function will also return FALSE.
 *
 * @param  d                    hal device object
 * @param  key                  Key of the property to compare
 * @param  right_side           Value to compare against
 * @param  result               Pointer to where to store result
 * @return                      TRUE if, and only if, the comparison could take place
 */
static gboolean
match_compare_property (HalDevice *d, const char *key, const char *right_side, dbus_int64_t *result)
{
	gboolean rc;
	int proptype;

	rc = FALSE;

	if (!hal_device_has_property (d, key))
		goto out;

	proptype = hal_device_property_get_type (d, key);
	switch (proptype) {
	case HAL_PROPERTY_TYPE_STRING:
		*result = (dbus_int64_t) strcmp (hal_device_property_get_string (d, key), right_side);
		rc = TRUE;
		break;

	case HAL_PROPERTY_TYPE_INT32:
		*result = ((dbus_int64_t) hal_device_property_get_int (d, key)) - strtoll (right_side, NULL, 0);
		rc = TRUE;
		break;

	case HAL_PROPERTY_TYPE_UINT64:
		*result = ((dbus_int64_t) hal_device_property_get_uint64 (d, key)) - ((dbus_int64_t) strtoll (right_side, NULL, 0));
		rc = TRUE;
		break;

	case HAL_PROPERTY_TYPE_DOUBLE:
		*result = (dbus_int64_t) ceil (hal_device_property_get_double (d, key) - atof (right_side));
		rc = TRUE;
		break;

	default:
		/* explicit fallthrough */
	case HAL_PROPERTY_TYPE_BOOLEAN:
		/* explicit blank since this doesn't make sense */
		break;
	}

out:
	return rc;
}

/** Called when the match element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  attr                Attribute key/value pairs
 *  @return                     #FALSE if the device in question didn't
 *                              match the data in the attributes
 */
static dbus_bool_t
handle_match (ParsingContext * pc, const char **attr)
{
	char udi_to_check[256];
	char prop_to_check[256];
	const char *key;
	int num_attrib;
	HalDevice *d;

	for (num_attrib = 0; attr[num_attrib] != NULL; num_attrib++);

	if (num_attrib != 4)
		return FALSE;

	if (strcmp (attr[0], "key") != 0)
		return FALSE;
	key = attr[1];

	/* Resolve key paths like 'someudi/foo/bar/baz:prop.name' '@prop.here.is.an.udi:with.prop.name' */
	if (!resolve_udiprop_path (key,
				   pc->device->udi,
				   udi_to_check, sizeof (udi_to_check),
				   prop_to_check, sizeof (prop_to_check))) {
		HAL_ERROR (("Could not resolve keypath '%s' on udi '%s'", key, pc->device->udi));
		return FALSE;
	}

	d = hal_device_store_find (hald_get_gdl (), udi_to_check);
	if (d == NULL) {
		d = hal_device_store_find (hald_get_tdl (), udi_to_check);
	}
	if (d == NULL) {
		HAL_ERROR (("Could not find device with udi '%s'", udi_to_check));
		return FALSE;
	}
	

	if (strcmp (attr[2], "string") == 0) {
		const char *value;

		/* match string property */

		value = attr[3];

		/*HAL_INFO(("Checking that key='%s' is a string that "
		  "equals '%s'", key, value)); */

		if (hal_device_property_get_type (d, prop_to_check) != HAL_PROPERTY_TYPE_STRING)
			return FALSE;

		if (strcmp (hal_device_property_get_string (d, prop_to_check),
			    value) != 0)
			return FALSE;

		/*HAL_INFO (("*** string match for key %s", key));*/
		return TRUE;
	} else if (strcmp (attr[2], "int") == 0) {
		dbus_int32_t value;

		/* match integer property */
		value = strtol (attr[3], NULL, 0);
		
		/** @todo Check error condition */

		/*HAL_INFO (("Checking that key='%s' is a int that equals %d", 
		  key, value));*/

		if (hal_device_property_get_type (d, prop_to_check) != HAL_PROPERTY_TYPE_INT32)
			return FALSE;

		if (hal_device_property_get_int (d, prop_to_check) != value) {
			return FALSE;
		}

		return TRUE;
	} else if (strcmp (attr[2], "uint64") == 0) {
		dbus_uint64_t value;

		/* match integer property */
		value = strtoull (attr[3], NULL, 0);
		
		/** @todo Check error condition */

		/*HAL_INFO (("Checking that key='%s' is a int that equals %d", 
		  key, value));*/

		if (hal_device_property_get_type (d, prop_to_check) != HAL_PROPERTY_TYPE_UINT64)
			return FALSE;

		if (hal_device_property_get_uint64 (d, prop_to_check) != value) {
			return FALSE;
		}

		return TRUE;
	} else if (strcmp (attr[2], "bool") == 0) {
		dbus_bool_t value;

		/* match string property */

		if (strcmp (attr[3], "false") == 0)
			value = FALSE;
		else if (strcmp (attr[3], "true") == 0)
			value = TRUE;
		else
			return FALSE;

		/*HAL_INFO (("Checking that key='%s' is a bool that equals %s", 
		  key, value ? "TRUE" : "FALSE"));*/

		if (hal_device_property_get_type (d, prop_to_check) != 
		    HAL_PROPERTY_TYPE_BOOLEAN)
			return FALSE;

		if (hal_device_property_get_bool (d, prop_to_check) != value)
			return FALSE;

		/*HAL_INFO (("*** bool match for key %s", key));*/
		return TRUE;
	} else if (strcmp (attr[2], "exists") == 0) {
		dbus_bool_t should_exist = TRUE;

		if (strcmp (attr[3], "false") == 0)
			should_exist = FALSE;

		if (should_exist) {
			if (hal_device_has_property (d, prop_to_check))
				return TRUE;
			else
				return FALSE;
		} else {
			if (hal_device_has_property (d, prop_to_check))
				return FALSE;
			else
				return TRUE;
		}
	} else if (strcmp (attr[2], "empty") == 0) {
		int type;
		dbus_bool_t is_empty = TRUE;
		dbus_bool_t should_be_empty = TRUE;


		if (strcmp (attr[3], "false") == 0)
			should_be_empty = FALSE;

		type = hal_device_property_get_type (d, prop_to_check);
		switch (type) {
		case HAL_PROPERTY_TYPE_STRING: 
			if (hal_device_has_property (d, prop_to_check))
				if (strlen (hal_device_property_get_string (d, prop_to_check)) > 0)
					is_empty = FALSE;
			break;
		case HAL_PROPERTY_TYPE_STRLIST:
			if (hal_device_has_property (d, prop_to_check))
				if (!hal_device_property_strlist_is_empty(d, prop_to_check))
					is_empty = FALSE;
			break;
		default:
			/* explicit fallthrough */
			return FALSE;
			break;
		} 
	
		if (should_be_empty) {
			if (is_empty)
				return TRUE;
			else
				return FALSE;
		} else {
			if (is_empty)
				return FALSE;
			else
				return TRUE;
		}
	} else if (strcmp (attr[2], "is_ascii") == 0) {
		dbus_bool_t is_ascii = TRUE;
		dbus_bool_t should_be_ascii = TRUE;
		unsigned int i;
		const char *str;

		if (strcmp (attr[3], "false") == 0)
			should_be_ascii = FALSE;

		if (hal_device_property_get_type (d, prop_to_check) != HAL_PROPERTY_TYPE_STRING)
			return FALSE;

		is_ascii = TRUE;

		str = hal_device_property_get_string (d, prop_to_check);
		for (i = 0; str[i] != '\0'; i++) {
			if (((unsigned char) str[i]) > 0x7f)
				is_ascii = FALSE;
		}

		if (should_be_ascii) {
			if (is_ascii)
				return TRUE;
			else
				return FALSE;
		} else {
			if (is_ascii)
				return FALSE;
			else
				return TRUE;
		}
	} else if (strcmp (attr[2], "is_absolute_path") == 0) {
		const char *path = NULL;
		dbus_bool_t is_absolute_path = FALSE;
		dbus_bool_t should_be_absolute_path = TRUE;

		if (strcmp (attr[3], "false") == 0)
			should_be_absolute_path = FALSE;

		/*HAL_INFO (("d->udi='%s', prop_to_check='%s'", d->udi, prop_to_check));*/

		if (hal_device_property_get_type (d, prop_to_check) != HAL_PROPERTY_TYPE_STRING)
			return FALSE;

		if (hal_device_has_property (d, prop_to_check)) {
			path = hal_device_property_get_string (d, prop_to_check);
			if (g_path_is_absolute (path))
				is_absolute_path = TRUE;
		}

		/*HAL_INFO (("is_absolute=%d, should_be=%d, path='%s'", is_absolute_path, should_be_absolute_path, path));*/

		if (should_be_absolute_path) {
			if (is_absolute_path)
				return TRUE;
			else
				return FALSE;
		} else {
			if (is_absolute_path)
				return FALSE;
			else
				return TRUE;
		}
	} else if (strcmp (attr[2], "contains") == 0) {
		const char *needle;
		dbus_bool_t contains = FALSE;

		needle = attr[3];

		if (hal_device_property_get_type (d, prop_to_check) == HAL_PROPERTY_TYPE_STRING) {
			if (hal_device_has_property (d, prop_to_check)) {
				const char *haystack;
				
				haystack = hal_device_property_get_string (d, prop_to_check);
				if (needle != NULL && haystack != NULL && strstr (haystack, needle)) {
					contains = TRUE;
				}
				
			}
		} else if (hal_device_property_get_type (d, prop_to_check) == HAL_PROPERTY_TYPE_STRLIST && 
			   needle != NULL) {
			GSList *i;
			GSList *value;

			value = hal_device_property_get_strlist (d, prop_to_check);
			for (i = value; i != NULL; i = g_slist_next (i)) {
				const char *str = i->data;
				if (strcmp (str, needle) == 0) {
					contains = TRUE;
					break;
				}
			}
		} else {
			return FALSE;
		}

		return contains;
	} else if (strcmp (attr[2], "contains_ncase") == 0) {
		const char *needle;
		dbus_bool_t contains_ncase = FALSE;

		needle = attr[3];

		if (hal_device_property_get_type (d, prop_to_check) == HAL_PROPERTY_TYPE_STRING) {
			if (hal_device_has_property (d, prop_to_check)) {
				char *needle_lowercase;
				char *haystack_lowercase;
				
				needle_lowercase   = g_utf8_strdown (needle, -1);
				haystack_lowercase = g_utf8_strdown (hal_device_property_get_string (d, prop_to_check), -1);
				if (needle_lowercase != NULL && haystack_lowercase != NULL && strstr (haystack_lowercase, needle_lowercase)) {
					contains_ncase = TRUE;
				}
				
				g_free (needle_lowercase);
				g_free (haystack_lowercase);
			}
		} else if (hal_device_property_get_type (d, prop_to_check) == HAL_PROPERTY_TYPE_STRLIST && 
			   needle != NULL) {
			GSList *i;
			GSList *value;

			value = hal_device_property_get_strlist (d, prop_to_check);
			for (i = value; i != NULL; i = g_slist_next (i)) {
				const char *str = i->data;
				if (g_ascii_strcasecmp (str, needle) == 0) {
					contains_ncase = TRUE;
					break;
				}
			}
		} else {
			return FALSE;
		}

		return contains_ncase;
	} else if (strcmp (attr[2], "compare_lt") == 0) {
		dbus_int64_t result;
		if (!match_compare_property (d, prop_to_check, attr[3], &result)) {
			return FALSE;
		} else {
			return result < 0;
		}
	} else if (strcmp (attr[2], "compare_le") == 0) {
		dbus_int64_t result;
		if (!match_compare_property (d, prop_to_check, attr[3], &result))
			return FALSE;
		else
			return result <= 0;
	} else if (strcmp (attr[2], "compare_gt") == 0) {
		dbus_int64_t result;
		if (!match_compare_property (d, prop_to_check, attr[3], &result))
			return FALSE;
		else
			return result > 0;
	} else if (strcmp (attr[2], "compare_ge") == 0) {
		dbus_int64_t result;
		if (!match_compare_property (d, prop_to_check, attr[3], &result))
			return FALSE;
		else
			return result >= 0;
	}
	
	return FALSE;
}


/** Called when the merge element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  attr                Attribute key/value pairs
 */
static void
handle_merge (ParsingContext * pc, const char **attr)
{
	int num_attrib;

	pc->merge_type = MERGE_TYPE_UNKNOWN;


	for (num_attrib = 0; attr[num_attrib] != NULL; num_attrib++) {
		;
	}

	if (num_attrib != 4)
		return;

	if (strcmp (attr[0], "key") != 0)
		return;
	strncpy (pc->merge_key, attr[1], MAX_KEY_SIZE);

	if (strcmp (attr[2], "type") != 0)
		return;

	if (strcmp (attr[3], "string") == 0) {
		/* match string property */
		pc->merge_type = MERGE_TYPE_STRING;
		return;
	} else if (strcmp (attr[3], "bool") == 0) {
		/* match string property */
		pc->merge_type = MERGE_TYPE_BOOLEAN;
		return;
	} else if (strcmp (attr[3], "int") == 0) {
		/* match string property */
		pc->merge_type = MERGE_TYPE_INT32;
		return;
	} else if (strcmp (attr[3], "uint64") == 0) {
		/* match string property */
		pc->merge_type = MERGE_TYPE_UINT64;
		return;
	} else if (strcmp (attr[3], "double") == 0) {
		/* match string property */
		pc->merge_type = MERGE_TYPE_DOUBLE;
		return;
	} else if (strcmp (attr[3], "strlist") == 0) {
		/* match string property */
		pc->merge_type = MERGE_TYPE_STRLIST;
		return;
	} else if (strcmp (attr[3], "copy_property") == 0) {
		/* copy another property */
		pc->merge_type = MERGE_TYPE_COPY_PROPERTY;
		return;
	}

	return;
}

/** Called when the append or prepend element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  attr                Attribute key/value pairs
 */
static void
handle_append_prepend (ParsingContext * pc, const char **attr)
{
	int num_attrib;

	pc->merge_type = MERGE_TYPE_UNKNOWN;

	for (num_attrib = 0; attr[num_attrib] != NULL; num_attrib++) {
		;
	}

	if (num_attrib != 4)
		return;

	if (strcmp (attr[0], "key") != 0)
		return;
	strncpy (pc->merge_key, attr[1], MAX_KEY_SIZE);

	if (strcmp (attr[2], "type") != 0)
		return;

	if (strcmp (attr[3], "string") == 0) {
		/* append to a string */
		pc->merge_type = MERGE_TYPE_STRING;
		return;
	} else if (strcmp (attr[3], "strlist") == 0) {
		/* append to a string list*/
		pc->merge_type = MERGE_TYPE_STRLIST;
		return;
	} else if (strcmp (attr[3], "copy_property") == 0) {
		/* copy another property */
		pc->merge_type = MERGE_TYPE_COPY_PROPERTY;
		return;
	}

	return;
}


/** Called when the spawn element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  attr                Attribute key/value pairs
 */
static void
handle_spawn (ParsingContext * pc, const char **attr)
{
	int num_attrib;

	pc->merge_type = MERGE_TYPE_UNKNOWN;

	for (num_attrib = 0; attr[num_attrib] != NULL; num_attrib++) {
		;
	}

	if (num_attrib != 2)
		return;

	if (strcmp (attr[0], "udi") != 0)
		return;

	strncpy (pc->merge_key, attr[1], MAX_KEY_SIZE);

	pc->merge_type = MERGE_TYPE_SPAWN;
	return;
}

/** Called when the remove element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  attr                Attribute key/value pairs
 */
static void
handle_remove (ParsingContext * pc, const char **attr)
{
	int num_attrib;

	pc->merge_type = MERGE_TYPE_UNKNOWN;

	for (num_attrib = 0; attr[num_attrib] != NULL; num_attrib++) {
		;
	}

	if (num_attrib != 2 && num_attrib != 4)
		return;

	if (strcmp (attr[0], "key") != 0)
		return;
	strncpy (pc->merge_key, attr[1], MAX_KEY_SIZE);

	if (num_attrib == 4) {
		if (strcmp (attr[2], "type") != 0)
			return;

		if (strcmp (attr[3], "strlist") == 0) {
			/* remove from strlist */
			pc->merge_type = MERGE_TYPE_STRLIST;
			return;
		} else {
			pc->merge_type = MERGE_TYPE_UNKNOWN;
			return;
		}
	} else {
		pc->merge_type = MERGE_TYPE_REMOVE;
	}

	return;
}

/** Called when the clear element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  attr                Attribute key/value pairs
 */
static void
handle_clear (ParsingContext * pc, const char **attr)
{
	int num_attrib;

	pc->merge_type = MERGE_TYPE_UNKNOWN;

	for (num_attrib = 0; attr[num_attrib] != NULL; num_attrib++) {
		;
	}

	if (num_attrib != 4)
		return;
	
	if (strcmp (attr[0], "key") != 0)
		return;


	if (strcmp (attr[3], "strlist") != 0)
		return;
	
	strncpy (pc->merge_key, attr[1], MAX_KEY_SIZE);
	
	pc->merge_type = MERGE_TYPE_CLEAR;

	return;
}

/** Abort parsing of document
 *
 *  @param  pc                  Parsing context
 */
static void
parsing_abort (ParsingContext * pc)
{
	/* Grr, expat can't abort parsing */
	HAL_ERROR (("Aborting parsing of document"));
	pc->aborted = TRUE;
}

/** Called by expat when an element begins.
 *
 *  @param  pc                  Parsing context
 *  @param  el                  Element name
 *  @param  attr                Attribute key/value pairs
 */
static void
start (ParsingContext * pc, const char *el, const char **attr)
{
	if (pc->aborted)
		return;

	pc->cdata_buf_len = 0;

	pc->merge_type = MERGE_TYPE_UNKNOWN;

/*
    for (i = 0; i < pc->depth; i++)
        printf("  ");
    
    printf("%s", el);
    
    for (i = 0; attr[i]; i += 2) {
        printf(" %s='%s'", attr[i], attr[i + 1]);
    }

    printf("   curelem=%d\n", pc->curelem);
*/

	if (strcmp (el, "match") == 0) {
		if (pc->curelem != CURELEM_DEVICE
		    && pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <match> can only be "
				    "inside <device> and <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_MATCH;

		/* don't bother checking if matching at lower depths failed */
		if (pc->match_ok) {
			if (!handle_match (pc, attr)) {
				/* No match */
				pc->match_depth_first_fail = pc->depth;
				pc->match_ok = FALSE;
			}
		}
	} else if (strcmp (el, "merge") == 0) {
		if (pc->curelem != CURELEM_DEVICE
		    && pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <merge> can only be "
				    "inside <device> and <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_MERGE;
		if (pc->match_ok) {
			handle_merge (pc, attr);
		} else {
			/*HAL_INFO(("No merge!")); */
		}
	} else if (strcmp (el, "append") == 0) {
		if (pc->curelem != CURELEM_DEVICE
		    && pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <append> can only be "
				    "inside <device> and <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_APPEND;
		if (pc->match_ok) {
			handle_append_prepend (pc, attr);
		} else {
			/*HAL_INFO(("No merge!")); */
		}
	} else if (strcmp (el, "prepend") == 0) {
		if (pc->curelem != CURELEM_DEVICE
		    && pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <prepend> can only be "
				    "inside <device> and <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_PREPEND;
		if (pc->match_ok) {
			handle_append_prepend (pc, attr);
		} else {
			/*HAL_INFO(("No merge!")); */
		}
	} else if (strcmp (el, "remove") == 0) {
		if (pc->curelem != CURELEM_DEVICE
		    && pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <remove> can only be "
				    "inside <device> and <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_REMOVE;
		if (pc->match_ok) {
			handle_remove (pc, attr);
		} else {
			/*HAL_INFO(("No merge!")); */
		}
	} else if (strcmp (el, "clear") == 0) {
		if (pc->curelem != CURELEM_DEVICE
		    && pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <remove> can only be "
				    "inside <device> and <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_CLEAR;
		if (pc->match_ok) {
			handle_clear (pc, attr);
		} else {
			/*HAL_INFO(("No merge!")); */
		}
	} else if (strcmp (el, "device") == 0) {
		if (pc->curelem != CURELEM_DEVICE_INFO) {
			HAL_ERROR (("%s:%d:%d: Element <device> can only be "
				    "inside <deviceinfo>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}
		pc->curelem = CURELEM_DEVICE;
	} else if (strcmp (el, "deviceinfo") == 0) {
		if (pc->curelem != CURELEM_UNKNOWN) {
			HAL_ERROR (("%s:%d:%d: Element <deviceinfo> must be "
				    "a top-level element", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}
		pc->curelem = CURELEM_DEVICE_INFO;
	} else if (strcmp (el, "spawn") == 0) {
		if (pc->curelem != CURELEM_MATCH) {
			HAL_ERROR (("%s:%d:%d: Element <spawn> can only be "
				    "inside <match>", 
				    pc->file, 
				    XML_GetCurrentLineNumber (pc->parser), 
				    XML_GetCurrentColumnNumber (pc->parser)));
			parsing_abort (pc);
		}

		pc->curelem = CURELEM_SPAWN;
		if (pc->match_ok) {
			handle_spawn (pc, attr);
		} 

	} else {
		HAL_ERROR (("%s:%d:%d: Unknown element <%s>",
			    pc->file,
			    XML_GetCurrentLineNumber (pc->parser),
			    XML_GetCurrentColumnNumber (pc->parser), el));
		parsing_abort (pc);
	}

	/* Nasty hack */
	assert (pc->depth < MAX_DEPTH);

	pc->depth++;

	/* store depth */
	pc->curelem_stack[pc->depth] = pc->curelem;

}

static void 
spawned_device_callouts_add_done (HalDevice *d, gpointer userdata1, gpointer userdata2)
{
	HAL_INFO (("Add callouts completed udi=%s", d->udi));

	/* Move from temporary to global device store */
	hal_device_store_remove (hald_get_tdl (), d);
	hal_device_store_add (hald_get_gdl (), d);

}

/** Called by expat when an element ends.
 *
 *  @param  pc                  Parsing context
 *  @param  el                  Element name
 */
static void
end (ParsingContext * pc, const char *el)
{
	if (pc->aborted)
		return;

	pc->cdata_buf[pc->cdata_buf_len] = '\0';

/*    printf("   curelem=%d\n", pc->curelem);*/

	if (pc->curelem == CURELEM_MERGE && pc->match_ok) {
		/* As soon as we are merging, we have matched the device... */
		pc->device_matched = TRUE;

		switch (pc->merge_type) {
		case MERGE_TYPE_STRING:
			hal_device_property_set_string (pc->device, pc->merge_key, pc->cdata_buf);
			break;

		case MERGE_TYPE_STRLIST:
		{
			int type = hal_device_property_get_type (pc->device, pc->merge_key);
			if (type == HAL_PROPERTY_TYPE_STRLIST || type == HAL_PROPERTY_TYPE_INVALID) {
				hal_device_property_remove (pc->device, pc->merge_key);
				hal_device_property_strlist_append (pc->device, pc->merge_key, pc->cdata_buf);
			}
			break;
		}

		case MERGE_TYPE_INT32:
			{
				dbus_int32_t value;

				/* match integer property */
				value = strtol (pc->cdata_buf, NULL, 0);

				/** @todo FIXME: Check error condition */

				hal_device_property_set_int (pc->device,
						     pc->merge_key, value);
				break;
			}

		case MERGE_TYPE_UINT64:
			{
				dbus_uint64_t value;

				/* match integer property */
				value = strtoull (pc->cdata_buf, NULL, 0);

				/** @todo FIXME: Check error condition */

				hal_device_property_set_uint64 (pc->device,
						     pc->merge_key, value);
				break;
			}

		case MERGE_TYPE_BOOLEAN:
			hal_device_property_set_bool (pc->device, pc->merge_key,
					      (strcmp (pc->cdata_buf,
						       "true") == 0) 
					      ? TRUE : FALSE);
			break;

		case MERGE_TYPE_DOUBLE:
			hal_device_property_set_double (pc->device, pc->merge_key,
						atof (pc->cdata_buf));
			break;

		case MERGE_TYPE_COPY_PROPERTY:
		{
			char udi_to_merge_from[256];
			char prop_to_merge[256];

			/* Resolve key paths like 'someudi/foo/bar/baz:prop.name' 
			 * '@prop.here.is.an.udi:with.prop.name'
			 */
			if (!resolve_udiprop_path (pc->cdata_buf,
						   pc->device->udi,
						   udi_to_merge_from, sizeof (udi_to_merge_from),
						   prop_to_merge, sizeof (prop_to_merge))) {
				HAL_ERROR (("Could not resolve keypath '%s' on udi '%s'", pc->cdata_buf, pc->device->udi));
			} else {
				HalDevice *d;

				d = hal_device_store_find (hald_get_gdl (), udi_to_merge_from);
				if (d == NULL) {
					d = hal_device_store_find (hald_get_tdl (), udi_to_merge_from);
				}
				if (d == NULL) {
					HAL_ERROR (("Could not find device with udi '%s'", udi_to_merge_from));
				} else {
					hal_device_copy_property (d, prop_to_merge, pc->device, pc->merge_key);
				}
			}
			break;
		}

		default:
			HAL_ERROR (("Unknown merge_type=%d='%c'",
				    pc->merge_type, pc->merge_type));
			break;
		}
	} else if (pc->curelem == CURELEM_APPEND && pc->match_ok && 
		   (hal_device_property_get_type (pc->device, pc->merge_key) == HAL_PROPERTY_TYPE_STRING ||
		    hal_device_property_get_type (pc->device, pc->merge_key) == HAL_PROPERTY_TYPE_STRLIST ||
		    hal_device_property_get_type (pc->device, pc->merge_key) == HAL_PROPERTY_TYPE_INVALID)) {
		char buf[256];
		char buf2[256];

		/* As soon as we are appending, we have matched the device... */
		pc->device_matched = TRUE;

		if (pc->merge_type == MERGE_TYPE_STRLIST) {
			hal_device_property_strlist_append (pc->device, pc->merge_key, pc->cdata_buf);
		} else {
			const char *existing_string;
			
			switch (pc->merge_type) {
			case MERGE_TYPE_STRING:
				strncpy (buf, pc->cdata_buf, sizeof (buf));
				break;
				
			case MERGE_TYPE_COPY_PROPERTY:
				hal_device_property_get_as_string (pc->device, pc->cdata_buf, buf, sizeof (buf));
				break;
				
			default:
				HAL_ERROR (("Unknown merge_type=%d='%c'", pc->merge_type, pc->merge_type));
				break;
			}
			
			existing_string = hal_device_property_get_string (pc->device, pc->merge_key);
			if (existing_string != NULL) {
				strncpy (buf2, existing_string, sizeof (buf2));
				strncat (buf2, buf, sizeof (buf2) - strlen(buf2));
			} else {
				strncpy (buf2, buf, sizeof (buf2));
			}
			hal_device_property_set_string (pc->device, pc->merge_key, buf2);
		}
	} else if (pc->curelem == CURELEM_PREPEND && pc->match_ok && 
		   (hal_device_property_get_type (pc->device, pc->merge_key) == HAL_PROPERTY_TYPE_STRING ||
		    hal_device_property_get_type (pc->device, pc->merge_key) == HAL_PROPERTY_TYPE_STRLIST ||
		    hal_device_property_get_type (pc->device, pc->merge_key) == HAL_PROPERTY_TYPE_INVALID)) {
		char buf[256];
		char buf2[256];

		/* As soon as we are prepending, we have matched the device... */
		pc->device_matched = TRUE;

		if (pc->merge_type == MERGE_TYPE_STRLIST) {
			hal_device_property_strlist_prepend (pc->device, pc->merge_key, pc->cdata_buf);
		} else {
			const char *existing_string;
			
			switch (pc->merge_type) {
			case MERGE_TYPE_STRING:
				strncpy (buf, pc->cdata_buf, sizeof (buf));
				break;
				
			case MERGE_TYPE_COPY_PROPERTY:
				hal_device_property_get_as_string (pc->device, pc->cdata_buf, buf, sizeof (buf));
				break;
				
			default:
				HAL_ERROR (("Unknown merge_type=%d='%c'", pc->merge_type, pc->merge_type));
				break;
			}
			
			existing_string = hal_device_property_get_string (pc->device, pc->merge_key);
			if (existing_string != NULL) {
				strncpy (buf2, buf, sizeof (buf2));
				strncat (buf2, existing_string, sizeof (buf2) - strlen(buf2));
			} else {
				strncpy (buf2, buf, sizeof (buf2));
			}
			hal_device_property_set_string (pc->device, pc->merge_key, buf2);
		}
	} else if (pc->curelem == CURELEM_REMOVE && pc->match_ok) {

		if (pc->merge_type == MERGE_TYPE_STRLIST) {
			/* covers <remove key="foobar" type="strlist">blah</remove> */
			hal_device_property_strlist_remove (pc->device, pc->merge_key, pc->cdata_buf);
		} else {
			/* only allow <remove key="foobar"/>, not <remove key="foobar">blah</remove> */
			if (strlen (pc->cdata_buf) == 0) {
				hal_device_property_remove (pc->device, pc->merge_key);
			}
		}
	} else if (pc->merge_type == MERGE_TYPE_SPAWN) {
		HalDevice *spawned;

		spawned = hal_device_store_find (hald_get_gdl (), pc->merge_key);
		if (spawned == NULL)
			spawned = hal_device_store_find (hald_get_tdl (), pc->merge_key);

		if (spawned == NULL) {
			HAL_INFO (("Spawning new device object '%s' caused by <spawn> on udi '%s'", 
				   pc->merge_key, pc->device->udi));

			spawned = hal_device_new ();
			hal_device_property_set_string (spawned, "info.bus", "unknown");
			hal_device_property_set_string (spawned, "info.udi", pc->merge_key);
			hal_device_property_set_string (spawned, "info.parent", pc->device->udi);
			hal_device_set_udi (spawned, pc->merge_key);
			
			hal_device_store_add (hald_get_tdl (), spawned);
			
			di_search_and_merge (spawned, DEVICE_INFO_TYPE_INFORMATION);
			di_search_and_merge (spawned, DEVICE_INFO_TYPE_POLICY);
			
			hal_util_callout_device_add (spawned, spawned_device_callouts_add_done, NULL, NULL);
		}

	} else if (pc->curelem == CURELEM_CLEAR && pc->match_ok) {
		if (pc->merge_type == MERGE_TYPE_CLEAR) {
			hal_device_property_strlist_clear (pc->device, pc->merge_key);
		}
	}


	pc->cdata_buf_len = 0;
	pc->depth--;

	/* maintain curelem */
	pc->curelem = pc->curelem_stack[pc->depth];

	/* maintain pc->match_ok */
	if (pc->depth <= pc->match_depth_first_fail)
		pc->match_ok = TRUE;
}

/** Called when there is CDATA 
 *
 *  @param  pc                  Parsing context
 *  @param  s                   Pointer to data
 *  @param  len                 Length of data
 */
static void
cdata (ParsingContext * pc, const char *s, int len)
{
	int bytes_left;
	int bytes_to_copy;

	if (pc->aborted)
		return;

	bytes_left = CDATA_BUF_SIZE - pc->cdata_buf_len;
	if (len > bytes_left) {
		HAL_ERROR (("CDATA in element larger than %d",
			    CDATA_BUF_SIZE));
	}

	bytes_to_copy = len;
	if (bytes_to_copy > bytes_left)
		bytes_to_copy = bytes_left;

	if (bytes_to_copy > 0)
		memcpy (pc->cdata_buf + pc->cdata_buf_len, s,
			bytes_to_copy);

	pc->cdata_buf_len += bytes_to_copy;
}


/** Process a device information info file.
 *
 *  @param  dir                 Directory file resides in
 *  @param  filename            File name
 *  @param  device              Device to match on
 *  @return                     #TRUE if file matched device and information
 *                              was merged
 */
static dbus_bool_t
process_fdi_file (const char *dir, const char *filename,
		  HalDevice * device)
{
	int rc;
	char buf[512];
	FILE *file;
	int filesize;
	char *filebuf;
	dbus_bool_t device_matched;
	XML_Parser parser;
	ParsingContext *parsing_context;

	file = NULL;
	filebuf = NULL;
	parser = NULL;
	parsing_context = NULL;

	device_matched = FALSE;

	snprintf (buf, sizeof (buf), "%s/%s", dir, filename);

	/*HAL_INFO(("analyzing file %s", buf));*/

	/* open file and read it into a buffer; it's a small file... */
	file = fopen (buf, "r");
	if (file == NULL) {
		HAL_ERROR (("Could not open file %s", buf));
		goto out;
	}

	fseek (file, 0L, SEEK_END);
	filesize = (int) ftell (file);
	rewind (file);
	filebuf = (char *) malloc (filesize);
	if (filebuf == NULL) {
		HAL_ERROR (("Could not allocate %d bytes for file %s", filesize, buf));
		goto out;
	}
	(void) fread (filebuf, sizeof (char), filesize, file);

	/* initialize parsing context */
	parsing_context =
	    (ParsingContext *) malloc (sizeof (ParsingContext));
	if (parsing_context == NULL) {
		HAL_ERROR (("Could not allocate parsing context"));
		goto out;
	}

	/* TODO: reuse parser
	 */
	parser = XML_ParserCreate (NULL);
	if (parser == NULL) {
		HAL_ERROR (("Could not allocate XML parser"));
		goto out;
	}

	parsing_context->depth = 0;
	parsing_context->device_matched = FALSE;
	parsing_context->match_ok = TRUE;
	parsing_context->curelem = CURELEM_UNKNOWN;
	parsing_context->aborted = FALSE;
	parsing_context->file = buf;
	parsing_context->parser = parser;
	parsing_context->device = device;
	parsing_context->match_depth_first_fail = -1;

	XML_SetElementHandler (parser,
			       (XML_StartElementHandler) start,
			       (XML_EndElementHandler) end);
	XML_SetCharacterDataHandler (parser,
				     (XML_CharacterDataHandler) cdata);
	XML_SetUserData (parser, parsing_context);

	rc = XML_Parse (parser, filebuf, filesize, 1);
	/*printf("XML_Parse rc=%d\r\n", rc); */

	if (rc == 0) {
		/* error parsing document */
		HAL_ERROR (("Error parsing XML document %s at line %d, "
			    "column %d : %s", 
			    buf, 
			    XML_GetCurrentLineNumber (parser), 
			    XML_GetCurrentColumnNumber (parser), 
			    XML_ErrorString (XML_GetErrorCode (parser))));
		device_matched = FALSE;
	} else {
		/* document parsed ok */
		device_matched = parsing_context->device_matched;
	}

out:
	if (filebuf != NULL)
		free (filebuf);
	if (file != NULL)
		fclose (file);
	if (parser != NULL)
		XML_ParserFree (parser);
	if (parsing_context != NULL)
		free (parsing_context);

	return device_matched;
}



static int
#ifdef __GLIBC__
my_alphasort(const void *a, const void *b)
#else
my_alphasort(const struct dirent **a, const struct dirent **b)
#endif
{
	return -alphasort (a, b);
}


/** Scan all directories and subdirectories in the given directory and
 *  process each *.fdi file
 *
 *  @param  d                   Device to merge information into
 *  @return                     #TRUE if information was merged
 */
static dbus_bool_t
scan_fdi_files (const char *dir, HalDevice * d)
{
	int i;
	int num_entries;
	dbus_bool_t found_fdi_file;
	struct dirent **name_list;

	found_fdi_file = 0;

	/*HAL_INFO(("scan_fdi_files: Processing dir '%s'", dir));*/

	num_entries = scandir (dir, &name_list, 0, my_alphasort);
	if (num_entries == -1) {
		return FALSE;
	}

	for (i = num_entries - 1; i >= 0; i--) {
		int len;
		char *filename;
		gchar *full_path;					     

		filename = name_list[i]->d_name;
		len = strlen (filename);

		full_path = g_strdup_printf ("%s/%s", dir, filename);
		/*HAL_INFO (("Full path = %s", full_path));*/

		/* Mmm, d_type can be DT_UNKNOWN, use glib to determine
		 * the type
		 */
		if (g_file_test (full_path, (G_FILE_TEST_IS_REGULAR))) {
			/* regular file */

			if (len >= 5 &&
			    filename[len - 4] == '.' &&
			    filename[len - 3] == 'f' &&
			    filename[len - 2] == 'd' &&
			    filename[len - 1] == 'i') {
				/*HAL_INFO (("scan_fdi_files: Processing file '%s'", filename));*/
				found_fdi_file = process_fdi_file (dir, filename, d);
				if (found_fdi_file) {
					HAL_INFO (("*** Matched file %s/%s", dir, filename));
					/*break;*/
				}
			}

		} else if (g_file_test (full_path, (G_FILE_TEST_IS_DIR)) 
			   && strcmp (filename, ".") != 0
			   && strcmp (filename, "..") != 0) {
			int num_bytes;
			char *dirname;

			/* Directory; do the recursion thingy but not 
			 * for . and ..
			 */

			num_bytes = len + strlen (dir) + 1 + 1;
			dirname = (char *) malloc (num_bytes);
			if (dirname == NULL) {
				HAL_ERROR (("couldn't allocated %d bytes",
					    num_bytes));
				break;
			}

			snprintf (dirname, num_bytes, "%s/%s", dir,
				  filename);
			found_fdi_file = scan_fdi_files (dirname, d);
			free (dirname);
			/*
			if (found_fdi_file)
				break;
			*/
		}

		g_free (full_path);

		free (name_list[i]);
	}

	for (; i >= 0; i--) {
		free (name_list[i]);
	}

	free (name_list);

	return found_fdi_file;
}

/** Search the device info file repository for a .fdi file to merge
 *  more information into the device object.
 *
 *  @param  d                   Device to merge information into
 *  @return                     #TRUE if information was merged
 */
dbus_bool_t
di_search_and_merge (HalDevice *d, DeviceInfoType type)
{
	static gboolean have_checked_hal_fdi_source = FALSE;
	static char *hal_fdi_source_preprobe = NULL;
	static char *hal_fdi_source_information = NULL;
	static char *hal_fdi_source_policy = NULL;
	dbus_bool_t ret;
	char *s1;
	char *s2;
	char *s3;

	ret = FALSE;

	if (!have_checked_hal_fdi_source) {
		hal_fdi_source_preprobe    = getenv ("HAL_FDI_SOURCE_PREPROBE");
		hal_fdi_source_information = getenv ("HAL_FDI_SOURCE_INFORMATION");
		hal_fdi_source_policy      = getenv ("HAL_FDI_SOURCE_POLICY");
		have_checked_hal_fdi_source = TRUE;
	}

	switch (type) {
	case DEVICE_INFO_TYPE_PREPROBE:
		if (hal_fdi_source_preprobe != NULL) {
			s1 = hal_fdi_source_preprobe;
			s2 = NULL;
			s3 = NULL;
		} else {
			s1 = PACKAGE_OLD_DATA_DIR "/hal/fdi/preprobe";
			s2 = PACKAGE_DATA_DIR "/hal/fdi/preprobe";
			s3 = PACKAGE_SYSCONF_DIR "/hal/fdi/preprobe";
		}
		break;

	case DEVICE_INFO_TYPE_INFORMATION:
		if (hal_fdi_source_information != NULL) {
			s1 = hal_fdi_source_information;
			s2 = NULL;
			s3 = NULL;
		} else {
			s1 = PACKAGE_OLD_DATA_DIR "/hal/fdi/information";
			s2 = PACKAGE_DATA_DIR "/hal/fdi/information";
			s3 = PACKAGE_SYSCONF_DIR "/hal/fdi/information";
		}
		break;

	case DEVICE_INFO_TYPE_POLICY:
		if (hal_fdi_source_policy != NULL) {
			s1 = hal_fdi_source_policy;
			s2 = NULL;
			s3 = NULL;
		} else {
			s1 = PACKAGE_OLD_DATA_DIR "/hal/fdi/policy";
			s2 = PACKAGE_DATA_DIR "/hal/fdi/policy";
			s3 = PACKAGE_SYSCONF_DIR "/hal/fdi/policy";
		}
		break;

	default:
		s1 = NULL;
		s2 = NULL;
		s3 = NULL;
		HAL_ERROR (("Bogus device information type %d", type));
		break;
	}

	if (s1 != NULL)
		ret = scan_fdi_files (s1, d) || ret;
	if (s2 != NULL)
		ret = scan_fdi_files (s2, d) || ret;
	if (s3 != NULL)
		ret = scan_fdi_files (s3, d) || ret;

	return ret;
}

/** @} */
