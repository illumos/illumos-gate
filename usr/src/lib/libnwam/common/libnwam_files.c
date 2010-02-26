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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <dirent.h>
#include <ctype.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Implementation of files backend for libnwam configuration objects.
 * /etc/dladm/datalink.conf-like format is used.
 */
#define	NWAM_FILE_LINE_MAX		2048
#define	NWAM_FILE_PROP_ESCAPE		'\\'
#define	NWAM_FILE_PROP_DELIMITER	';'
#define	NWAM_FILE_PROP_ASSIGN		'='
#define	NWAM_FILE_VALUE_DELIMITER	','
#define	NWAM_FILE_BOOLEAN_TRUE		"true"
#define	NWAM_FILE_BOOLEAN_FALSE		"false"

/*
 * strtok_r-like function that takes a string, finds the next unescaped
 * delimiter char after in, nullifies it and sets nextp to point to the
 * remaining string (if any). Returns in, setting nextp to NULL if no such
 * delimiter is found.
 */
char *
nwam_tokenize_by_unescaped_delim(char *in, char delim, char **nextp)
{
	boolean_t escaped = B_FALSE;
	size_t totlen;

	if (in == NULL)
		return (NULL);

	totlen = strlen(in);

	for (*nextp = in; (*nextp - in) < strlen(in); (*nextp)++) {
		if ((*nextp)[0] == NWAM_FILE_PROP_ESCAPE) {
			escaped = !escaped;
		} else if (!escaped && (*nextp)[0] == delim) {
			/* Nullify delimiter */
			(*nextp)[0] = '\0';
			/*
			 * If more string left to go, nextp points to string
			 * after delimiter, otherwise NULL.
			 */
			(*nextp)++;
			*nextp = ((*nextp - in) < totlen) ? (*nextp) : NULL;
			return (in);
		} else {
			escaped = B_FALSE;
		}
	}
	*nextp = NULL;
	return (in);
}

/* Add escape chars to value string */
static void
value_add_escapes(char *in, char *out)
{
	int i, j = 0;

	/*
	 * It is safe to use strlen() as we sanitycheck string length on value
	 * creation, so no string longer than NWAM_MAX_VALUE_LEN is accepted.
	 */
	for (i = 0; i < strlen(in); i++) {
		switch (in[i]) {
		case NWAM_FILE_VALUE_DELIMITER:
		case NWAM_FILE_PROP_DELIMITER:
		case NWAM_FILE_PROP_ESCAPE:
			out[j++] = NWAM_FILE_PROP_ESCAPE;
			out[j++] = in[i];
			break;
		default:
			out[j++] = in[i];
			break;
		}
	}
	out[j] = '\0';
}

static char *
value_remove_escapes(char *in)
{
	char *out;
	int i, j = 0;

	if ((out = strdup(in)) == NULL)
		return (NULL);

	/*
	 * It is safe to use strlen() as we sanitycheck string length on value
	 * creation (i.e. before they are written to the file), so no string
	 * longer than NWAM_MAX_VALUE_LEN is accepted.
	 */
	for (i = 0; i < strlen(in); i++) {
		if (in[i] == NWAM_FILE_PROP_ESCAPE)
			out[j++] = in[++i];
		else
			out[j++] = in[i];
	}
	out[j] = '\0';
	return (out);
}


/*
 * Parse line into name and object list of properties.
 * Each line has the format:
 *
 * objname	[prop=type:val1[,val2..];..]
 */
nwam_error_t
nwam_line_to_object(char *line, char **objname, void *proplist)
{
	char *next = line, *prop, *nextprop, *propname, *proptypestr, *nextval;
	char **valstr, **newvalstr;
	boolean_t *valbool, *newvalbool;
	int64_t *valint, *newvalint;
	uint64_t *valuint, *newvaluint;
	uint_t nelem, i;
	nwam_value_type_t proptype;
	nwam_value_t val = NULL;
	nwam_error_t err;

	if ((err = nwam_alloc_object_list(proplist)) != NWAM_SUCCESS)
		return (err);

	*objname = line;

	if ((*objname = nwam_tokenize_by_unescaped_delim(line, '\t', &prop))
	    == NULL) {
		nwam_free_object_list(*((char **)proplist));
		return (NWAM_ENTITY_INVALID);
	}

	while ((prop = nwam_tokenize_by_unescaped_delim(prop,
	    NWAM_FILE_PROP_DELIMITER, &nextprop)) != NULL) {
		/*
		 * Parse property into name=type,val[,val]
		 */
		if ((propname = nwam_tokenize_by_unescaped_delim(prop,
		    NWAM_FILE_PROP_ASSIGN, &next)) == NULL ||
		    (proptypestr = nwam_tokenize_by_unescaped_delim(next,
		    NWAM_FILE_VALUE_DELIMITER, &next)) == NULL) {
			nwam_free_object_list(*((char **)proplist));
			return (NWAM_ENTITY_INVALID);
		}
		if ((proptype = nwam_string_to_value_type(proptypestr)) ==
		    NWAM_VALUE_TYPE_UNKNOWN) {
			nwam_free_object_list(*((char **)proplist));
			return (NWAM_ENTITY_INVALID);
		}
		valbool = NULL;
		valint = NULL;
		valstr = NULL;
		switch (proptype) {
		case NWAM_VALUE_TYPE_BOOLEAN:
			valbool = calloc(NWAM_MAX_NUM_VALUES,
			    sizeof (boolean_t));
			break;
		case NWAM_VALUE_TYPE_INT64:
			valint = calloc(NWAM_MAX_NUM_VALUES,
			    sizeof (int64_t));
			break;
		case NWAM_VALUE_TYPE_UINT64:
			valuint = calloc(NWAM_MAX_NUM_VALUES,
			    sizeof (uint64_t));
			break;
		case NWAM_VALUE_TYPE_STRING:
			valstr = calloc(NWAM_MAX_NUM_VALUES,
			    sizeof (char *));
			break;
		default:
			nwam_free_object_list(*((char **)proplist));
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		if (valbool == NULL && valint == NULL && valuint == NULL &&
		    valstr == NULL) {
			/* Memory allocation failed */
			nwam_free_object_list(*((char **)proplist));
			return (NWAM_NO_MEMORY);
		}
		nelem = 0;
		while ((nextval = nwam_tokenize_by_unescaped_delim(next,
		    NWAM_FILE_VALUE_DELIMITER, &next)) != NULL) {
			nelem++;
			switch (proptype) {
			case NWAM_VALUE_TYPE_BOOLEAN:
				if (strncmp(nextval, NWAM_FILE_BOOLEAN_TRUE,
				    strlen(nextval)) == 0) {
					valbool[nelem - 1] = B_TRUE;
				} else if (strncmp(nextval,
				    NWAM_FILE_BOOLEAN_FALSE, strlen(nextval))
				    == 0) {
					valbool[nelem - 1] = B_FALSE;
				} else {
					nwam_free_object_list
					    (*((char **)proplist));
					return (NWAM_ENTITY_INVALID_VALUE);
				}
				break;
			case NWAM_VALUE_TYPE_INT64:
				valint[nelem - 1] = (int64_t)atoll(nextval);
				break;
			case NWAM_VALUE_TYPE_UINT64:
				valuint[nelem - 1] = (uint64_t)atoll(nextval);
				break;
			case NWAM_VALUE_TYPE_STRING:
				valstr[nelem - 1] =
				    value_remove_escapes(nextval);
				break;
			default:
				nwam_free_object_list(*((char **)proplist));
				return (NWAM_ENTITY_INVALID_VALUE);
			}
		}
		switch (proptype) {
		case NWAM_VALUE_TYPE_BOOLEAN:
			if ((newvalbool = realloc(valbool,
			    nelem * sizeof (boolean_t))) == NULL) {
				nwam_free_object_list(*((char **)proplist));
				return (NWAM_NO_MEMORY);
			}
			if ((err = nwam_value_create_boolean_array(newvalbool,
			    nelem, &val)) != NWAM_SUCCESS ||
			    (err = nwam_set_prop_value(*((char **)proplist),
			    propname, val)) != NWAM_SUCCESS) {
				free(newvalbool);
				nwam_value_free(val);
				nwam_free_object_list(*((char **)proplist));
				return (err);
			}
			free(newvalbool);
			nwam_value_free(val);
			break;
		case NWAM_VALUE_TYPE_INT64:
			if ((newvalint = realloc(valint,
			    nelem * sizeof (int64_t))) == NULL) {
				nwam_free_object_list(*((char **)proplist));
				return (NWAM_NO_MEMORY);
			}
			if ((err = nwam_value_create_int64_array(newvalint,
			    nelem, &val)) != NWAM_SUCCESS ||
			    (err = nwam_set_prop_value(*((char **)proplist),
			    propname, val)) != NWAM_SUCCESS) {
				free(newvalint);
				nwam_value_free(val);
				nwam_free_object_list(*((char **)proplist));
				return (err);
			}
			free(newvalint);
			nwam_value_free(val);
			break;
		case NWAM_VALUE_TYPE_UINT64:
			if ((newvaluint = realloc(valuint,
			    nelem * sizeof (uint64_t))) == NULL) {
				nwam_free_object_list(*((char **)proplist));
				return (NWAM_NO_MEMORY);
			}
			if ((err = nwam_value_create_uint64_array(newvaluint,
			    nelem, &val)) != NWAM_SUCCESS ||
			    (err = nwam_set_prop_value(*((char **)proplist),
			    propname, val)) != NWAM_SUCCESS) {
				free(newvaluint);
				nwam_value_free(val);
				nwam_free_object_list(*((char **)proplist));
				return (err);
			}
			free(newvaluint);
			nwam_value_free(val);
			break;
		case NWAM_VALUE_TYPE_STRING:
			if ((newvalstr = realloc(valstr,
			    nelem * sizeof (char *))) == NULL) {
				nwam_free_object_list(*((char **)proplist));
				return (NWAM_NO_MEMORY);
			}
			if ((err = nwam_value_create_string_array(newvalstr,
			    nelem, &val)) != NWAM_SUCCESS ||
			    (err = nwam_set_prop_value(*((char **)proplist),
			    propname, val)) != NWAM_SUCCESS) {
				for (i = 0; i < nelem; i++)
					free(newvalstr[i]);
				free(newvalstr);
				nwam_value_free(val);
				nwam_free_object_list(*((char **)proplist));
				return (err);
			}
			for (i = 0; i < nelem; i++)
				free(newvalstr[i]);
			free(newvalstr);
			nwam_value_free(val);
			break;
		}
		prop = nextprop;
	}

	return (NWAM_SUCCESS);
}

/*
 * Create list of NCP files used for walk of NCPs and for case-insensitive
 * matching of NCP name to file.
 */
static nwam_error_t
create_ncp_file_list(char ***ncpfilesp, uint_t *num_filesp)
{
	DIR *dirp = NULL;
	struct dirent *dp;
	char *ncpname, **ncpfiles = NULL;
	nwam_error_t err = NWAM_SUCCESS;
	uint_t i;

	ncpfiles = calloc(NWAM_MAX_NUM_OBJECTS, sizeof (char *));
	if (ncpfiles == NULL)
		return (NWAM_NO_MEMORY);
	*num_filesp = 0;

	/*
	 * Construct NCP list by finding all files in NWAM directory
	 * that match the NCP filename format.
	 */
	if ((dirp = opendir(NWAM_CONF_DIR)) == NULL) {
		err = nwam_errno_to_nwam_error(errno);
		goto done;
	}

	while ((dp = readdir(dirp)) != NULL) {
		uint_t filenamelen;

		/* Ensure filename is valid */
		if (nwam_ncp_file_to_name(dp->d_name, &ncpname) != NWAM_SUCCESS)
			continue;
		free(ncpname);
		filenamelen = strlen(NWAM_CONF_DIR) + strlen(dp->d_name) + 1;
		if ((ncpfiles[*num_filesp] = malloc(filenamelen)) == NULL) {
			err = NWAM_NO_MEMORY;
			goto done;
		}
		(void) strlcpy(ncpfiles[*num_filesp], NWAM_CONF_DIR,
		    strlen(NWAM_CONF_DIR) + 1);
		(void) strlcpy(ncpfiles[*num_filesp] + strlen(NWAM_CONF_DIR),
		    dp->d_name, filenamelen - strlen(NWAM_CONF_DIR));
		(*num_filesp)++;
	}
done:
	if (dirp != NULL)
		(void) closedir(dirp);

	if (err != NWAM_SUCCESS) {
		for (i = 0; i < *num_filesp; i++)
			free(ncpfiles[i]);
		free(ncpfiles);
	} else {
		*ncpfilesp = realloc(ncpfiles, sizeof (char *) * (*num_filesp));
		if (*ncpfilesp == NULL)
			err = NWAM_NO_MEMORY;
	}
	return (err);
}

/*
 * Read object specified by objname from file, converting it to
 * an object list.  If filename is NULL, a list of configuration object
 * containers is returned, represented as an object lists with elements "enms"
 * "locs" and "ncps". Each of these is a list of configuration files for each
 * object. This corresponds to the enm.conf file, loc.conf file and list of
 * ncp conf files. If objname is NULL, read all objects, and create
 * an nvlist with one element - "object-list" - which has as its values
 * the names of the objects found.  Otherwise obj points to an object list
 * of properties for the first object in the file that case-insensitively
 * matches objname.  We write the found name into objname so that it can be
 * returned to the caller (and set in the object handle).
 */
/* ARGSUSED2 */
nwam_error_t
nwam_read_object_from_files_backend(char *filename, char *objname,
    uint64_t flags, void *obj)
{
	char line[NWAM_FILE_LINE_MAX];
	char *cp, *foundobjname, **objnames = NULL, **ncpfiles = NULL;
	uint_t num_files = 0;
	FILE *fp = NULL;
	nwam_error_t err;
	void *objlist = NULL, *proplist = NULL;
	uint_t i = 0, j = 0;
	nwam_value_t objnamesval = NULL;

	assert(obj != NULL);

	*((char **)obj) = NULL;

	if (filename == NULL) {
		nwam_value_t enmval = NULL, locval = NULL, ncpval = NULL;

		/*
		 * When the filename is not specified, it signifies a
		 * request for the list of configuration object containers -
		 * in this case files.
		 *
		 * A list of all object files is returned. For ENMs
		 * and locations, only the default loc.conf and enm.conf
		 * files are used, but for NCPs we need to walk the
		 * files in the NWAM directory retrieving each one that
		 * matches the NCP pattern.
		 */
		if ((err = nwam_alloc_object_list(&objlist)) != NWAM_SUCCESS)
			return (err);

		if ((err = nwam_value_create_string(NWAM_ENM_CONF_FILE,
		    &enmval)) != NWAM_SUCCESS ||
		    (err = nwam_value_create_string(NWAM_LOC_CONF_FILE,
		    &locval)) != NWAM_SUCCESS ||
		    (err = nwam_set_prop_value(objlist, NWAM_ENM_OBJECT_STRING,
		    enmval)) != NWAM_SUCCESS ||
		    (err = nwam_set_prop_value(objlist, NWAM_LOC_OBJECT_STRING,
		    locval)) != NWAM_SUCCESS)
			goto done_with_containers;

		/*
		 * Construct NCP list by finding all files in NWAM directory
		 * that match the NCP filename format.
		 */
		if ((err = create_ncp_file_list(&ncpfiles, &num_files))
		    != NWAM_SUCCESS)
			goto done_with_containers;

		if ((err = nwam_value_create_string_array(ncpfiles, num_files,
		    &ncpval)) == NWAM_SUCCESS) {
			err = nwam_set_prop_value(objlist,
			    NWAM_NCP_OBJECT_STRING, ncpval);
		}

done_with_containers:
		nwam_value_free(enmval);
		nwam_value_free(locval);
		nwam_value_free(ncpval);
		if (ncpfiles != NULL) {
			for (j = 0; j < num_files; j++)
				free(ncpfiles[j]);
			free(ncpfiles);
		}
		if (err != NWAM_SUCCESS)
			nwam_free_object_list(objlist);
		else
			*((char **)obj) = objlist;
		return (err);
	}

	if (objname == NULL) {
		/* Allocate string array to store object names */
		if ((objnames = calloc(NWAM_MAX_NUM_OBJECTS, sizeof (char *)))
		    == NULL)
			return (NWAM_NO_MEMORY);
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		if (errno != ENOENT) {
			if (objname == NULL)
				free(objnames);
			return (NWAM_ERROR_INTERNAL);
		}

		/*
		 * Check NCP file list in case filename passed in was derived
		 * from a case-insensitive NCP name.
		 */
		if ((err = create_ncp_file_list(&ncpfiles, &num_files))
		    == NWAM_SUCCESS) {
			for (j = 0; j < num_files; j++) {
				if (strcasecmp(ncpfiles[j], filename) == 0) {
					fp = fopen(ncpfiles[j], "r");
					if (fp != NULL) {
						/* Copy real filename back */
						(void) strlcpy(filename,
						    ncpfiles[j],
						    strlen(filename) + 1);
						break;
					}
				}
			}
			for (j = 0; j < num_files; j++)
				free(ncpfiles[j]);
			free(ncpfiles);
		}
		/* Return NOT_FOUND if file not found */
		if (fp == NULL) {
			if (objname == NULL)
				free(objnames);
			return (NWAM_ENTITY_NOT_FOUND);
		}
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;

		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		if ((err = nwam_line_to_object(cp, &foundobjname, &proplist))
		    != NWAM_SUCCESS)
			goto done;

		if (objname != NULL) {
			/*
			 * Is this the specified object?  If so set objname and
			 * obj and bail.
			 */
			if (strcasecmp(objname, foundobjname) == 0) {
				*((char **)obj) = proplist;
				(void) strlcpy(objname, foundobjname,
				    NWAM_MAX_NAME_LEN);
				break;
			} else {
				nwam_free_object_list(proplist);
			}
		} else {
			objnames[i] = strdup(foundobjname);
			nwam_free_object_list(proplist);
			if (objnames[i] == NULL) {
				err = NWAM_NO_MEMORY;
				goto done;
			}
			i++;
		}

	}
	if (objname == NULL) {
		/*
		 * Allocate object list with one value named
		 * NWAM_OBJECT_NAMES_STRING - it's values are the names of
		 * the objects found.
		 */
		if ((err = nwam_alloc_object_list(&objlist)) == NWAM_SUCCESS &&
		    (err = nwam_value_create_string_array(objnames, i,
		    &objnamesval)) == NWAM_SUCCESS) {
			err = nwam_set_prop_value(objlist,
			    NWAM_OBJECT_NAMES_STRING, objnamesval);
		}
	}

done:
	if (fp != NULL)
		(void) fclose(fp);

	/*
	 * We're done, either we have success, and return our object list
	 * containing object names, or we have failure and we need to free
	 * the object list.
	 */
	if (objname == NULL) {
		for (j = 0; j < i; j++)
			free(objnames[j]);
		free(objnames);
		nwam_value_free(objnamesval);
		if (err == NWAM_SUCCESS) {
			*((char **)obj) = objlist;
		} else {
			*((char **)obj) = NULL;
			nwam_free_object_list(objlist);
		}
	} else {
		/* Check if to-be-read object was not found */
		if (*((char **)obj) == NULL && err == NWAM_SUCCESS)
			return (NWAM_ENTITY_NOT_FOUND);
	}

	return (err);
}

nwam_error_t
nwam_object_to_line(FILE *fp, const char *objname, void *proplist)
{
	char *propname, *lastpropname = NULL;
	boolean_t *valbool;
	int64_t *valint;
	uint64_t *valuint;
	char **valstr;
	uint_t nelem, i;
	nwam_value_t val;
	nwam_value_type_t type;

	(void) fprintf(fp, "%s\t", objname);

	while (nwam_next_object_prop(proplist, lastpropname, &propname, &val)
	    == NWAM_SUCCESS) {

		(void) fprintf(fp, "%s%c", propname, NWAM_FILE_PROP_ASSIGN);

		if (nwam_value_get_type(val, &type) != NWAM_SUCCESS)
			return (NWAM_INVALID_ARG);

		switch (type) {
		case NWAM_VALUE_TYPE_BOOLEAN:
			(void) fprintf(fp, "%s",
			    nwam_value_type_to_string(NWAM_VALUE_TYPE_BOOLEAN));
			if (nwam_value_get_boolean_array(val, &valbool, &nelem)
			    != NWAM_SUCCESS) {
				nwam_value_free(val);
				return (NWAM_INVALID_ARG);
			}
			for (i = 0; i < nelem; i++) {
				(void) fprintf(fp, "%c",
				    NWAM_FILE_VALUE_DELIMITER);
				if (valbool[i]) {
					(void) fprintf(fp,
					    NWAM_FILE_BOOLEAN_TRUE);
				} else {
					(void) fprintf(fp,
					    NWAM_FILE_BOOLEAN_FALSE);
				}
			}
			break;

		case NWAM_VALUE_TYPE_INT64:
			(void) fprintf(fp, "%s",
			    nwam_value_type_to_string(NWAM_VALUE_TYPE_INT64));
			if (nwam_value_get_int64_array(val, &valint, &nelem)
			    != NWAM_SUCCESS) {
				nwam_value_free(val);
				return (NWAM_INVALID_ARG);
			}
			for (i = 0; i < nelem; i++) {
				(void) fprintf(fp, "%c%lld",
				    NWAM_FILE_VALUE_DELIMITER, valint[i]);
			}
			break;

		case NWAM_VALUE_TYPE_UINT64:
			(void) fprintf(fp, "%s",
			    nwam_value_type_to_string(NWAM_VALUE_TYPE_UINT64));
			if (nwam_value_get_uint64_array(val, &valuint, &nelem)
			    != NWAM_SUCCESS) {
				nwam_value_free(val);
				return (NWAM_INVALID_ARG);
			}
			for (i = 0; i < nelem; i++) {
				(void) fprintf(fp, "%c%lld",
				    NWAM_FILE_VALUE_DELIMITER, valuint[i]);
			}
			break;

		case NWAM_VALUE_TYPE_STRING:
			(void) fprintf(fp, "%s",
			    nwam_value_type_to_string(NWAM_VALUE_TYPE_STRING));
			if (nwam_value_get_string_array(val, &valstr, &nelem)
			    != NWAM_SUCCESS) {
				nwam_value_free(val);
				return (NWAM_INVALID_ARG);
			}
			for (i = 0; i < nelem; i++) {
				char evalstr[NWAM_MAX_VALUE_LEN];
				/* Add escape chars as necessary */
				value_add_escapes(valstr[i], evalstr);
				(void) fprintf(fp, "%c%s",
				    NWAM_FILE_VALUE_DELIMITER, evalstr);
			}
			break;
		default:
			nwam_value_free(val);
			return (NWAM_INVALID_ARG);
		}
		nwam_value_free(val);
		(void) fprintf(fp, "%c", NWAM_FILE_PROP_DELIMITER);

		lastpropname = propname;

	}
	(void) fprintf(fp, "\n");
	return (NWAM_SUCCESS);
}

/*
 * Write object specified by objname to file.  If objname is NULL, objlist
 * must be a list of lists, where each list corresponds to an
 * object to write to the file.  Otherwise objlist should point to a list of
 * properties for the object specified by objname.  The write operation is
 * first done to filename.new, and if this succeeds, the file is renamed to
 * filename.  Since rename(2) is atomic, this approach guarantees a complete
 * configuration will end up in filename as a result of an aborted operation.
 */
nwam_error_t
nwam_write_object_to_files_backend(const char *filename, const char *objname,
    uint64_t flags, void *objlist)
{
	void *proplist;
	char *currobjname, *lastobjname = NULL;
	int fd, cmd;
	nwam_error_t err = NWAM_SUCCESS;
	char *dir;
	char tmpfilename[MAXPATHLEN], filename_copy[MAXPATHLEN];
	FILE *fp;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	mode_t dirmode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	struct flock fl = { F_WRLCK, SEEK_SET, 0, 0, 0};
	struct flock fu = { F_UNLCK, SEEK_SET, 0, 0, 0};

	assert(filename != NULL);

	/* Create the directory in case it does not exist. */
	(void) strlcpy(filename_copy, filename, MAXPATHLEN);
	if ((dir = dirname(filename_copy)) == NULL)
		return (nwam_errno_to_nwam_error(errno));
	if (mkdir(dir, dirmode) != 0) {
		if (errno != EEXIST)
			return (nwam_errno_to_nwam_error(errno));
	}

	(void) snprintf(tmpfilename, MAXPATHLEN, "%s.new", filename);

	if ((fd = open(tmpfilename, O_RDWR | O_CREAT | O_TRUNC, mode)) < 0)
			return (nwam_errno_to_nwam_error(errno));

	if ((fp = fdopen(fd, "w")) == NULL) {
		err = nwam_errno_to_nwam_error(errno);
		goto done;
	}
	/*
	 * Need to lock filename.new to prevent multiple commits colliding
	 * at this point.
	 */
	if (flags & NWAM_FLAG_BLOCKING)
		cmd = F_SETLKW;
	else
		cmd = F_SETLK;
	if (fcntl(fd, cmd, &fl) != 0) {
		if (errno == EAGAIN)
			return (NWAM_ENTITY_IN_USE);
		else
			return (NWAM_ERROR_INTERNAL);
	}

	if (objname != NULL) {
		/* Only one object to write */
		err = nwam_object_to_line(fp, objname, objlist);
	} else {
		if (objlist == NULL) {
			err = NWAM_SUCCESS;
			goto done;
		}
		/* Otherwise, write each object in turn. */
		while ((err = nwam_next_object_list(objlist, lastobjname,
		    &currobjname, &proplist)) == NWAM_SUCCESS) {
			if ((err = nwam_object_to_line(fp, currobjname,
			    proplist)) != NWAM_SUCCESS)
				break;
			lastobjname = currobjname;
		}
		if (err == NWAM_LIST_END)
			err = NWAM_SUCCESS;
	}
done:
	if (err == NWAM_SUCCESS) {
		if (rename(tmpfilename, filename) == 0) {
			(void) fcntl(fd, F_SETLKW, &fu);
			(void) fclose(fp);
			return (NWAM_SUCCESS);
		} else {
			err = nwam_errno_to_nwam_error(errno);
		}
	}
	(void) fcntl(fd, F_SETLKW, &fu);
	(void) fclose(fp);
	(void) unlink(tmpfilename);

	return (err);
}

/*
 * Read in all objects from file and update object corresponding to objname
 * with properties recorded in proplist, and then write results to filename.
 * If objname is empty, no object needs to be updated.  If proplist is NULL,
 * object is to be removed (this is done by simply not adding it to the list
 * of objects).
 */
nwam_error_t
nwam_update_object_in_files_backend(char *filename, char *objname,
    uint64_t flags, void *proplist)
{
	nwam_error_t err;
	void *objlist, *objnamelist;
	char **object_names;
	nwam_value_t value = NULL;
	uint_t i, num_objects;

	assert(filename != NULL);

	/*  If we find existing object, fail if creation was specified */
	if (flags & NWAM_FLAG_CREATE) {
		char discard_objname[NWAM_MAX_NAME_LEN];
		void *discard_objlist;

		(void) strlcpy(discard_objname, objname,
		    sizeof (discard_objname));
		if ((err = nwam_read_object_from_files_backend(filename,
		    discard_objname, 0, &discard_objlist)) == NWAM_SUCCESS) {
			nwam_free_object_list(discard_objlist);
			return (NWAM_ENTITY_EXISTS);
		}
	}

	/* Get existing list of object names (if any) */
	err = nwam_read_object_from_files_backend(filename, NULL, flags,
	    &objnamelist);
	switch (err) {
	case NWAM_SUCCESS:
		/*
		 * For each object name on list other than the one to be
		 * updated,  add an object list consisting of its properties.
		 * The object to be updated (if any) will be added below.
		 */
		if ((err = nwam_alloc_object_list(&objlist)) != NWAM_SUCCESS) {
			nwam_free_object_list(objnamelist);
			return (err);
		}
		if ((err = nwam_get_prop_value(objnamelist,
		    NWAM_OBJECT_NAMES_STRING, &value)) != NWAM_SUCCESS ||
		    (err = nwam_value_get_string_array(value, &object_names,
		    &num_objects)) != NWAM_SUCCESS) {
			nwam_value_free(value);
			nwam_free_object_list(objnamelist);
			nwam_free_object_list(objlist);
			return (err);
		}
		nwam_free_object_list(objnamelist);

		for (i = 0; i < num_objects; i++) {
			void *oproplist = NULL;

			if (objname != NULL &&
			    strcmp(objname, object_names[i]) == 0)
					continue;

			if ((err = nwam_read_object_from_files_backend(filename,
			    object_names[i], flags, &oproplist))
			    != NWAM_SUCCESS ||
			    (err = nwam_object_list_add_object_list(objlist,
			    object_names[i], oproplist)) != NWAM_SUCCESS) {
				nwam_free_object_list(oproplist);
				nwam_free_object_list(objlist);
				nwam_value_free(value);
				return (err);
			}
			nwam_free_object_list(oproplist);
		}
		nwam_value_free(value);
		break;

	case NWAM_ENTITY_NOT_FOUND:
		/*
		 * Just need to write/remove this single object.
		 */
		return (nwam_write_object_to_files_backend(filename, objname,
		    flags, proplist));

	default:
		return (err);
	}

	/*
	 * Add the object to be updated to our list of objects if the
	 * property list is non-NULL (NULL signifies remove the object).
	 */
	if (objname != NULL && proplist != NULL) {
		if ((err = nwam_object_list_add_object_list(objlist,
		    (char *)objname, proplist)) != NWAM_SUCCESS) {
			nwam_free_object_list(objlist);
			return (err);
		}
	}

	err = nwam_write_object_to_files_backend(filename, NULL, flags,
	    objlist);

	nwam_free_object_list(objlist);

	return (err);
}

/*
 * Remove specified object from file by reading in the list of objects,
 * removing objname and writing the remainder.
 */
nwam_error_t
nwam_remove_object_from_files_backend(char *filename, char *objname,
    uint64_t flags)
{
	int uerr;

	assert(filename != NULL);

	if (objname == NULL) {
		/*
		 * NULL objname signifies remove file.
		 */
		uerr = unlink(filename);
		if (uerr != 0)
			return (nwam_errno_to_nwam_error(errno));
		return (NWAM_SUCCESS);
	}

	return (nwam_update_object_in_files_backend(filename, objname, flags,
	    NULL));
}
