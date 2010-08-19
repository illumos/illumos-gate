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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * SCSI Enclosure Services Log Transport Module
 *
 * This transport module is responsible for accessing the ses devices seen
 * from this host, reading their logs, generating ereports for targeted
 * entries, and then writing the log contents to a well known location in
 * the filesystem.
 *
 */

#include <ctype.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <fm/topo_mod.h>
#include <limits.h>
#include <string.h>
#include <sys/fm/io/scsi.h>
#include <sys/fm/protocol.h>
#include <stdio.h>
#include <time.h>
#include <fm/libseslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * This struct contains the default property values.  These may
 * be overridden by entries in a ses_log_transport.conf file.
 * The severity is set to -1 here so that the _fmd_init routine will
 * determine the default severity based on the constants in libseslog.h.
 */
static const fmd_prop_t fmd_props[] = {
	{ "interval",	FMD_TYPE_TIME,	    "60s"},
	{ "severity",	FMD_TYPE_INT32,	    "-1"},
	{ "path",	FMD_TYPE_STRING,    "/var/fm/fmd/ses_logs/"},
	{ "logcount",	FMD_TYPE_UINT32,    "5"},
	{ "maxlogsize", FMD_TYPE_UINT32,    "1000000"},
	{ NULL, 0,	NULL}
};

/* Maintains statistics on dropped ereports. */
static struct slt_stat
{
	fmd_stat_t dropped;
} slt_stats = {
	{ "dropped", FMD_TYPE_UINT64, "number of dropped ereports"}
};

/*
 * This structure maintains a reference to the input values, transport, and
 * other data which is held by FMD and retrieved whenever an entry point
 * is called.
 */
typedef struct ses_log_monitor
{
	fmd_hdl_t *slt_hdl;	    /* opaque handle for this transport */
	fmd_xprt_t *slt_xprt;	    /* ereport transport */
	id_t slt_timer;		    /* Timer for FMD polling use */
	hrtime_t slt_interval;	    /* Polling interval */
	int32_t slt_severity;	    /* Min severity for logging ereports */
	char *slt_path;		    /* Output path for log files */
	int32_t slt_log_count;	    /* Max rolled logs to keep  */
	int32_t slt_max_log_size;   /* Max log size before rolling */
	nvlist_t *slt_expanders;    /* List of expander log entries */
} ses_log_monitor_t;

/* Contains expander log data retrieved from a topology node */
typedef struct expander
{
	char slt_label[MAXNAMELEN]; /* The expander name */
	char slt_pid[MAXNAMELEN];   /* The system product id */
	char slt_key[MAXNAMELEN];   /* The expander key (sas address) */
	char slt_path[MAXPATHLEN];  /* The ses path to the expander */
	nvlist_t *fmri;		    /* The fmri for this target */
} expander_t;

#define	DATA_FIELD		"data"	    /* Label for the expander details */
#define	DEFAULT_DATA		"0"	    /* Default expander details value */
#define	MIN_LOG_SIZE		100000	    /* The minimum log file size. */
#define	MIN_LOG_COUNT		1	    /* Num of rolled files to keep */
#define	EXAMINE_FMRI_VALUE	0	    /* Extract fmri val */
#define	INVERT_FMRI_INSTANCE	1	    /* Invert an FMRI instance value */
#define	FATAL_ERROR		"fatal"	    /* ereport val for fatal errors */
#define	NON_FATAL_ERROR		"non-fatal" /* val for non fatal errors */
#define	INVALID_OPERATION	0x01	    /* Invalid access_fmri operation */
#define	NULL_LOG_DATA		0x02	    /* Lib returned NULL log ref */
#define	INVALID_SEVERITY	0x03	    /* Invalid severity value */
#define	DATE_STRING_SIZE	16	    /* Size of date string prefix. */

/* Prototype needed for use in declaring and populating tables */
static int invert_fmri(ses_log_monitor_t *, nvlist_t *);

/* Holds a code-operation pair.  Contains a log code an a function ptr */
typedef struct code_operation {
	int code;
	int (*func_ptr)(ses_log_monitor_t *, nvlist_t *);
} code_operation_t;

/* Holds a platform type and a list of code-operation structures */
typedef struct platform {
	const char *pid;
	int count;
	code_operation_t *codes;
} platform_t;

/* Holds a reference to all of the platforms */
typedef struct platforms {
	int pcount;
	platform_t *plist;
} platforms_t;

/* This is the genesis list of codes and functions. */
static code_operation_t genesis_codes[] = {
	{ 684002, invert_fmri },    /* Alternate expander is down */
	{ 685002, invert_fmri }	    /* Alternate expander is down */
};

/* This is the list of all platforms and their associated code op pairs. */
static platform_t platform_list[] = {
	{ "SUN-GENESIS",
	    sizeof (genesis_codes) / sizeof (code_operation_t),
	    genesis_codes }
};

/* This structure holds a reference to the platform list. */
static const platforms_t platforms = {
	sizeof (platform_list) / sizeof (platform_t),
	platform_list
};

/*
 * Post ereports using this method.
 */
static void
slt_post_ereport(fmd_hdl_t *hdl, fmd_xprt_t *xprt, const char *ereport_class,
    uint64_t ena, nvlist_t *detector, nvlist_t *payload)
{
	nvlist_t *nvl;
	int e = 0;
	char fullclass[PATH_MAX];

	(void) snprintf(fullclass, sizeof (fullclass), "%s.io.sas.log.%s",
	    FM_EREPORT_CLASS, ereport_class);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0) {

		e |= nvlist_add_string(nvl, FM_CLASS, fullclass);
		e |= nvlist_add_uint8(nvl, FM_VERSION, FM_EREPORT_VERSION);
		e |= nvlist_add_uint64(nvl, FM_EREPORT_ENA, ena);
		e |= nvlist_add_nvlist(nvl, FM_EREPORT_DETECTOR, detector);
		e |= nvlist_merge(nvl, payload, 0);

		if (e == 0) {
			fmd_xprt_post(hdl, xprt, nvl, 0);
		} else {
			nvlist_free(nvl);
			fmd_hdl_debug(hdl, "Error adding fields to ereport");
			slt_stats.dropped.fmds_value.ui64++;
		}
	} else {
		fmd_hdl_debug(hdl, "Could not allocate space for ereport");
		slt_stats.dropped.fmds_value.ui64++;
	}
}

/*
 * Create a directory if it doesn't exist.
 * Parameters:
 * path: The directory path to create.
 * mode: The mode used when creating the directory.
 */
static int
do_mkdir(const char *path, mode_t mode)
{
	struct stat st;
	int status = 0;

	if (stat(path, &st) != 0) {
		/* Directory does not exist */
		if (mkdir(path, mode) != 0)
			status = -1;
	} else if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		status = -1;
	}

	return (status);
}

/*
 * Validates that all directories in path exist
 * path: The directory path to create.
 * mode: The mode used when creating the directory.
 */
static int
mkpath(char *path, mode_t mode)
{
	char *pp;
	char *sp;
	int status = 0;

	pp = path;
	while (status == 0 && (sp = strchr(pp, '/')) != 0) {
		if (sp != pp) {
			/* Neither root nor double slash in path */
			*sp = '\0';
			status = do_mkdir(path, mode);
			*sp = '/';
		}
		pp = sp + 1;
	}

	return (status);
}

/*
 * Rotate the file from base.max-1->base.max, ... base.1->base.2, base->base.1
 * Parameter:
 * file: The name of the current log file.
 */
void
check_file_size(ses_log_monitor_t *slmp, char *file, int byte_count)
{
	int i;
	char newFile[MAXPATHLEN];
	char oldName[MAXPATHLEN];
	struct stat st;
	int size;

	stat(file, &st);
	size = st.st_size;
	/*
	 * If current file size plus what will be added is larger
	 * than max file size, rotate the logs
	 * For check to see if larger than configured max size.
	 */
	if (size + byte_count < slmp->slt_max_log_size) {
		/* next log entries can fit */
		return;
	}
	/* next log entries could make log entries too large */
	for (i = slmp->slt_log_count; i > 1; i--) {
		(void) snprintf(newFile, MAXPATHLEN, "%s.%x", file, i);
		(void) snprintf(oldName, MAXPATHLEN, "%s.%x", file, i - 1);
		(void) rename(oldName, newFile);
	}
	/* Finally move base to base.1 */
	(void) rename(file, oldName);

}

/*
 * This method exists to give access into the fmri.  One purpose is to flip the
 * instance number on the FMRI for a given hc-list entry. It is also
 * used to pull the value of an hc-list entry.  In all cases, the function
 * returns the value of the hc-list entry found, NULL if no value was found.
 */
static char *
access_fmri(ses_log_monitor_t *slmp, nvlist_t *fmri, char *target,
    int operation, int *err)
{
	int i;
	nvpair_t *nvp;
	nvpair_t *nvp2;
	uint_t nelem;
	nvlist_t **nvl_array;
	char *name;
	int ival;
	char ivs[25];
	char *target_val = NULL;

	if ((*err = nvlist_lookup_nvpair(fmri, "hc-list", &nvp)) != 0) {
		fmd_hdl_debug(slmp->slt_hdl, "No hc-list in the fmri");
		return (NULL);
	}

	/* hc-list is an array of nvlists */
	(void) nvpair_value_nvlist_array(nvp, &nvl_array, &nelem);

	/*
	 * Loop until you find the list that has hc-name that equals the
	 * passed in "target" value (such as controller) in it.
	 */
	for (i = 0; i < nelem; i++) {

		/* Skip this pair if it is not labeled hc-name */
		if ((nvlist_lookup_nvpair(nvl_array[i], "hc-name", &nvp2))
		    != 0) {
			continue;
		}

		/*
		 * Extract the value of the name. Continue on an error because
		 * we want to check all of the hc-name entries.
		 */
		if (nvpair_value_string(nvp2, &name) != 0) {
			continue;
		}

		/* If this isn't the target, go to the next pair. */
		if (strcmp(name, target) != 0) {
			continue;
		}

		if ((*err = nvlist_lookup_nvpair(nvl_array[i], "hc-id", &nvp2))
		    != 0) {

			fmd_hdl_debug(slmp->slt_hdl,
			    "Could not find hc-id in the fmri for %s", target);
			return (NULL);
		}

		/*
		 * This is the target pair.  If we can't get the value then
		 * exit out and log an error.
		 */
		if ((*err = nvpair_value_string(nvp2, &target_val)) != 0) {
			fmd_hdl_debug(slmp->slt_hdl,
			    "Target value not returned.");
			return (NULL);
		}

		switch (operation) {

		case INVERT_FMRI_INSTANCE:

			ival = atoi(target_val);
			ival = (ival + 1) % 2;

			(void) snprintf(ivs, sizeof (ivs), "%d", ival);

			if ((*err = nvlist_remove_nvpair(nvl_array[i], nvp2))
			    == 0) {

				if ((*err = nvlist_add_string(nvl_array[i],
				    "hc-id", ivs)) != 0) {

					fmd_hdl_debug(slmp->slt_hdl,
					    "Error setting ivalue.");
				}
			} else {
				fmd_hdl_debug(slmp->slt_hdl,
				    "Error removing original ivalue.");
			}

			break;

		case EXAMINE_FMRI_VALUE:
			/*
			 * target_val is already set. Return without modifying
			 * its value.
			 */
			break;

		/* Can return target_val as is (NULL) */
		default:
			*err = INVALID_OPERATION;
			break;

		} /* End switch on operation */


		/* Exit the loop.  You have found the target */
		break;
	}

	return (target_val);
}

/*
 * Generate a filename based on the target path
 * Parameters:
 * filename: The space for the generated output log file name.
 * expander: An expander_t struct containing path, pid etc info from the node.
 * slmp: A pointer to the transport data structure which contains the
 * configurable file parameters.
 * byte_count: The number of bytes that will be added to the target file for
 * this expander.
 */
static int
create_filename(char *fileName, expander_t *expander, ses_log_monitor_t *slmp,
    int byte_count)
{
	char *ses_node;
	int i;
	int label_length;
	int status = 0;
	char *subchassis_val = NULL;

	/*
	 * Add the file name with the path root
	 * and append a forward slash if one is not there.
	 */
	(void) snprintf(fileName, MAXPATHLEN, "%s", slmp->slt_path);

	ses_node = strrchr(fileName, '/');

	if ((ses_node != NULL) && (ses_node[0] != '\0')) {
		(void) strlcat(fileName, "/", MAXPATHLEN);
	}

	ses_node = strrchr(expander->slt_path, '/');

	(void) strlcat(fileName, ses_node + 1, MAXPATHLEN);

	/*
	 * If a subchassis is defined, include it in the file name.
	 * Errors are logged in the function.  There may legitimately be no
	 * subchassis, so simply continue if none is found.
	 */
	subchassis_val =  access_fmri(slmp, expander->fmri, SUBCHASSIS,
	    EXAMINE_FMRI_VALUE, &status);

	if (subchassis_val != NULL) {
		(void) strlcat(fileName, "_", MAXPATHLEN);
		(void) strlcat(fileName, SUBCHASSIS, MAXPATHLEN);
		(void) strlcat(fileName, subchassis_val, MAXPATHLEN);
	}

	(void) strlcat(fileName, "_", MAXPATHLEN);
	/* remove spaces and forward slashes from name */
	label_length = strlen(expander->slt_label);
	for (i = 0; i < label_length; i++) {
		if ((!isspace(expander->slt_label[i])) &&
		    ('/' != expander->slt_label[i])) {
			(void) strncat(fileName, &expander->slt_label[i], 1);
		}
	}
	(void) strlcat(fileName, "/log", MAXPATHLEN);

	/*
	 * Ensure directory structure exists for log file.
	 */
	status = mkpath(fileName, 0744);

	/*
	 * Check size of file and rotate if necessary.
	 */
	check_file_size(slmp, fileName, byte_count);

	return (status);

}

/*
 * Determines the error class type based on the severity of the entry.
 * Parameter
 * severity: A severity level from a log entry.
 */
static char *
error_type(int severity)
{
	char *rval;

	switch (severity) {
	case SES_LOG_LEVEL_FATAL:
		rval = FATAL_ERROR;
		break;

	case SES_LOG_LEVEL_ERROR:
		rval = NON_FATAL_ERROR;
		break;

	default:
		rval = NULL;
		break;
	}

	return (rval);
}

/*
 * Allocates and adds an entry for a given expander to the expander list.
 * Parameters
 * slmp: A pointer to the ses_log_monitor_t struct for this transport.
 * key: A unique identifier for this expander.
 */
static int
add_expander_record(ses_log_monitor_t *slmp, char *key)
{
	nvlist_t *expanderDetails;
	int status = 0;


	if ((status = nvlist_alloc(&expanderDetails, NV_UNIQUE_NAME, 0)) != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Error allocating expander detail space (%d)", status);
		return (status);
	}

	if ((status = nvlist_add_string(expanderDetails, DATA_FIELD,
	    DEFAULT_DATA)) != 0) {

		fmd_hdl_debug(slmp->slt_hdl,
		    "Error adding default data to expander details (%d)",
		    status);
	} else {

		if ((status = nvlist_add_nvlist(slmp->slt_expanders, key,
		    expanderDetails)) != 0) {

			fmd_hdl_debug(slmp->slt_hdl,
			    "Error storing the default expander details (%d)",
			    status);
		}
	}

	nvlist_free(expanderDetails);

	return (status);

}

/*
 * Retrieves the expander record nvlist that is associated with the
 * expander identified by the given key.  If no match is found, an
 * entry is created with default values.
 * Parameters
 * slmp: A pointer to the ses_log_monitor_t struct for this transport.
 * key: A pointer to the key for an expander.
 * expdata: A pointer to a pointer for the last log entry data for this
 * expander.
 */
static int
get_last_entry(ses_log_monitor_t *slmp, char *key, char **expdata)
{
	nvlist_t *expanderRecord;
	int err = 0;

	/*
	 * Retrieve the expander record that matches this expander.  A default
	 * entry will be returned if no matching entry is found.
	 */
	if ((err = nvlist_lookup_nvlist(slmp->slt_expanders, key,
	    &expanderRecord)) != 0) {

		if ((err = add_expander_record(slmp, key)) != 0) {
			fmd_hdl_debug(slmp->slt_hdl,
			    "Expander add failed for %s", key);
			return (err);
		}

		if ((err = nvlist_lookup_nvlist(slmp->slt_expanders, key,
		    &expanderRecord)) != 0) {

			fmd_hdl_debug(slmp->slt_hdl,
			    "Could not retrieve the data after adding it", key);
			return (err);
		}
	}


	if ((err = nvlist_lookup_string(expanderRecord, DATA_FIELD, expdata))
	    != 0) {

		fmd_hdl_debug(slmp->slt_hdl,
		    "Could not retrieve the expander data field (%d)", err);
		return (err);
	}

	return (err);
}

/*
 * Searches the platform lists for target codes.  If a match is found then
 * it calls then indicated function.
 */
static int
check_code(ses_log_monitor_t *slmp, nvlist_t *fmri, char *pid, int code)
{
	int status = 0;
	int i, x;

	for (i = 0; i < platforms.pcount; i++) {
		if (strcmp(platforms.plist[i].pid, pid) == 0) {

			for (x = 0; x < platforms.plist[i].count; x++) {
				if (code == platforms.plist[i].codes[x].code) {
					status = platforms.plist[i].codes[x].
					    func_ptr(slmp, fmri);

					break;
				}
			}
			break;
		}
	}

	if (status != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Error checking for a code action (%d)", status);
	}

	return (status);
}

/*
 * Searches the platform lists for for a match on the supplied product id.
 * Returns non zero if supported, zero otherwise.
 */
static int
platform_supported(char *pid)
{
	int supported = 0;
	int i;

	for (i = 0; i < platforms.pcount; i++) {
		if (strcmp(platforms.plist[i].pid, pid) == 0) {
			supported = 1;
			break;
		}
	}

	return (supported);
}

/*
 * Inverts the controller instance and the expander instance in the
 * specified FMRI.
 */
static int
invert_fmri(ses_log_monitor_t *slmp, nvlist_t *fmri)
{
	int err = 0;

	(void) access_fmri(slmp, fmri, CONTROLLER, INVERT_FMRI_INSTANCE, &err);
	if (err != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "error inverting the controller instance: %d", err);
		return (err);
	}

	(void) access_fmri(slmp, fmri, SASEXPANDER, INVERT_FMRI_INSTANCE, &err);
	if (err != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "error inverting sas-expander instance: %d", err);
	}

	return (err);
}

/*
 * Checks the severity of the log entry against the configured boundary,
 * generates and ereport, and writes the data out to the log file.
 * Parameters
 * slmp: A pointer to the ses_log_monitor_t struct for this transport.
 * entry: The log entry
 * ena: the ena for this transport.
 * expander: Contains derived information for this expander.
 * format_time: The formatted time to append to this entry.
 * fp: A file pointer for the data to be written out to.
 */
static int
handle_log_entry(ses_log_monitor_t *slmp, nvpair_t *entry,
    expander_t *expander, char *format_time, FILE *fp)
{
	nvlist_t *entry_data;
	char *log_entry;
	char *severity;
	int severityValue = 0;
	char *code;
	char *class_sev = NULL;
	uint64_t ena;
	int rval = 0;

	if ((rval = nvpair_value_nvlist(entry, &entry_data)) != 0) {
		fmd_hdl_debug(slmp->slt_hdl, "Unable to retrieve entry");
		return (rval);
	}

	if ((rval = nvlist_lookup_string(entry_data, ENTRY_SEVERITY, &severity))
	    == 0) {

		severityValue = atoi(severity);

		if (severityValue >= slmp->slt_severity) {
			/*
			 * Pull the code and check to see if there are any
			 * special operations to perform for it on the given
			 * platform.
			 */
			if ((rval = nvlist_lookup_string(entry_data, ENTRY_CODE,
			    &code)) != 0) {

				fmd_hdl_debug(slmp->slt_hdl,
				    "Error retrieving code: %d", rval);
				return (rval);
			}

			/*
			 * Check this code for any actions specific
			 * to this platform.
			 */
			(void) check_code(slmp, expander->fmri,
			    expander->slt_pid, atoi(code));

			class_sev = error_type(severityValue);
			if (class_sev == NULL) {
				fmd_hdl_debug(slmp->slt_hdl,
				    "log severity %d mapped to NULL", severity);
				return (INVALID_SEVERITY);
			}

			/* Create the ENA for this ereport */
			ena = fmd_event_ena_create(slmp->slt_hdl);

			slt_post_ereport(slmp->slt_hdl, slmp->slt_xprt,
			    class_sev, ena, expander->fmri, entry_data);

		}
	} else {

		fmd_hdl_debug(slmp->slt_hdl,
		    "Unable to pull severity from the entry.");
		return (rval);
	}

	/*
	 * Append the log entry to the log file.
	 */
	if (fp) {

		if ((rval = nvlist_lookup_string(entry_data, ENTRY_LOG,
		    &log_entry)) == 0) {

			(void) fprintf(fp, "%s %s\n", format_time,
			    log_entry);
		} else {

			fmd_hdl_debug(slmp->slt_hdl,
			    "Unable to pull log from the entry.");
		}
	}

	return (rval);

}

/*
 * The function performs the work of deallocating the space used for an
 * expander_t structure.
 * Parameters:
 * slmp: A pointer to t ses_log_monitor_t struct for this transport.
 * exp: A pointer to an expander_t structure that identifies an expander.
 */
static void
free_expander(ses_log_monitor_t *slmp, expander_t *exp)
{
	if (exp != NULL) {
		if (exp->fmri != NULL) {
			nvlist_free(exp->fmri);
		}
		fmd_hdl_free(slmp->slt_hdl, exp, sizeof (expander_t));
	}
}

/*
 * This function performs the log read on a target
 *
 * Parameters:
 * slmp: A pointer to the ses log monitor structure.
 * expander: A pointer to an expander object that contains info required
 * for a call to the libseslog library.
 * lib_param: The structure used to pass data to and from the library.  This
 * contains the target's information as well as a ponter to returned data.
 */
static int
get_log(ses_log_monitor_t *slmp, expander_t *expander,
    struct ses_log_call_struct *lib_param)
{
	char *expdata;
	int err;
	nvlist_t *expanderRecord;

	/* Retrieve the last entry for this expander for the lib call */
	if ((err = get_last_entry(slmp, expander->slt_key, &expdata)) != 0) {

		fmd_hdl_debug(slmp->slt_hdl, "Error collecting expander entry");
		return (err);
	}
	(void) strncpy(lib_param->target_path, expander->slt_path, MAXPATHLEN);
	(void) strncpy(lib_param->product_id, expander->slt_pid, MAXNAMELEN);
	(void) strncpy(lib_param->last_log_entry, expdata, MAXNAMELEN);
	lib_param->poll_time = slmp->slt_interval;

	/*
	 * If the library call returned non zero, log it, however, the call
	 * may still have returned valid log data.  Check the log data.  If it
	 * is NULL, return an error.  Otherwise continue processing.
	 */
	if ((err = access_ses_log(lib_param)) != 0) {
		fmd_hdl_debug(slmp->slt_hdl, "Library access error: %d", err);
	}

	/* Double check that log data actually exists. */
	if (lib_param->log_data == NULL) {
		if (err != 0) {
			return (err);
		}
		return (NULL_LOG_DATA);
	}

	/*
	 * If we can retrieve the expander details for this expander then store
	 * the last log entry returned from the library.  Otherwise log it
	 * and continue processing.
	 */
	if ((err = nvlist_lookup_nvlist(slmp->slt_expanders, expander->slt_key,
	    &expanderRecord)) == 0) {

		if (nvlist_add_string(expanderRecord, DATA_FIELD,
		    lib_param->last_log_entry) != 0) {

			fmd_hdl_debug(slmp->slt_hdl,
			    "Error saving buffer data in expander details");
		}
	} else {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Could not retrieve expander to store last entry: %d", err);
	}

	return (err);

}

/*
 * This function processes the log data from a target.  This includes
 * writing the data to the filesystem and initiating generation of ereports
 * as needed by calling slt_post_ereport.
 *
 *
 * Parameters:
 * slmp: A pointer to the ses log monitor structure.
 * expander: A pointer to an expander object that contains info about the
 * expander.
 * lib_param: The structure used to pass data to and from the library.  This
 * contains the target's information as well as a ponter to returned data.
 */
static int
process_log(ses_log_monitor_t *slmp, expander_t *expander,
    struct ses_log_call_struct *lib_param)
{
	nvlist_t *result;
	int err;

	char *pairName;
	nvpair_t *entry = NULL;
	FILE *fp = NULL;
	char fileName[MAXPATHLEN];
	time_t now;
	char format_time[30];
	struct tm tim;
	int output_count;

	/*
	 * Determine how many bytes will be written out with this response,
	 * pass this count to a function that will determine whether or not
	 * to roll the logs, and will return the name of the file path to use.
	 */
	output_count = lib_param->number_log_entries * DATE_STRING_SIZE +
	    lib_param->size_of_log_entries;

	err = create_filename(fileName, expander, slmp, output_count);

	if (err == 0) {
		fp = fopen(fileName, "a");
		if (fp == NULL) {
			fmd_hdl_debug(slmp->slt_hdl, "File open failed");
		}
	}

	/* Format the time to prepend to the log entry */
	now = time(NULL);
	tim = *(localtime(&now));
	(void) strftime(format_time, 30, "%b %d %H:%M:%S ", &tim);

	/*
	 * For each entry returned, generate an ereport if the severity
	 * is at or above the target level, then append all entries to
	 * the appropriate log file.
	 */
	result = lib_param->log_data;
	while ((entry = nvlist_next_nvpair(result, entry)) != NULL) {

		pairName = nvpair_name(entry);
		/*
		 * Process each entry in the result data returned from
		 * the library call.  These are log entries and may
		 * warrant an ereport.
		 */
		if (strncmp(ENTRY_PREFIX, pairName, 5) == 0) {

			err = handle_log_entry(slmp, entry, expander,
			    format_time, fp);
		}
	}

	/* Close the log file */
	if (fp) {
		(void) fclose(fp);
		fp = NULL;
	}

	/* Free the space used for the result and the fmri. */
	nvlist_free(result);

	return (0);

}

/*
 * This function performs the log read and processing of the logs for a target
 * as well as writing the data to the filesystem.  Ereports are generated
 * as needed by calling slt_post_ereport.
 *
 * Access the log data for a specific ses.
 * If a log entry should generate an ereport, call slt_post_ereport
 * Format and store the data at the appropriate location.
 */
static int
slt_process_ses_log(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	ses_log_monitor_t *slmp = arg;
	nvlist_t *fmri;
	expander_t *expander;
	struct ses_log_call_struct lib_param;

	int err = 0;
	char *label = NULL;
	char *target_path = NULL;
	char *product_id = NULL;
	char *sas_address = NULL;

	if (strcmp(SASEXPANDER, topo_node_name(node)) != 0) {
		/* Not the type of node we are looking for */
		return (TOPO_WALK_NEXT);
	}

	if (topo_prop_get_string(node, "authority", "product-id",
	    &product_id, &err) != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Error collecting product_id %d", err);
		return (TOPO_WALK_NEXT);
	}

	/* If the current system type is unsupported stop processing the node */
	if (platform_supported(product_id) == 0) {
		fmd_hdl_debug(slmp->slt_hdl, "Unsupported platform %d",
		    product_id);
		topo_hdl_strfree(thp, product_id);
		return (TOPO_WALK_NEXT);
	}

	/* Allocate space for the holder structure */
	expander = (expander_t *)fmd_hdl_zalloc(slmp->slt_hdl,
	    sizeof (expander_t), FMD_SLEEP);

	(void) snprintf(expander->slt_pid, MAXNAMELEN, "%s", product_id);
	topo_hdl_strfree(thp, product_id);

	if (topo_prop_get_string(node, "protocol", "label", &label, &err)
	    != 0) {
		fmd_hdl_debug(slmp->slt_hdl, "Error collecting label %d", err);
		free_expander(slmp, expander);
		return (TOPO_WALK_NEXT);
	}
	(void) snprintf(expander->slt_label, MAXNAMELEN, "%s", label);
	topo_hdl_strfree(thp, label);

	if (topo_prop_get_string(node, TOPO_PGROUP_SES,
	    TOPO_PROP_SES_DEV_PATH, &target_path, &err) != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Error collecting ses-devfs-path for %s: %d",
		    expander->slt_label, err);
		free_expander(slmp, expander);
		return (TOPO_WALK_NEXT);
	}
	(void) snprintf(expander->slt_path, MAXPATHLEN, "%s", target_path);
	topo_hdl_strfree(thp, target_path);

	if (topo_prop_get_string(node, TOPO_PGROUP_STORAGE,
	    TOPO_PROP_SAS_ADDR, &sas_address, &err) != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Error collecting sas_address for %s: %d",
		    expander->slt_label, err);
		free_expander(slmp, expander);
		return (TOPO_WALK_NEXT);
	}
	if (strlen(sas_address) != 16) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "sas-address length is not 16: (%s)", sas_address);
		free_expander(slmp, expander);
		topo_hdl_strfree(thp, sas_address);
		return (TOPO_WALK_NEXT);
	}
	(void) snprintf(expander->slt_key, MAXNAMELEN, "%s", sas_address);
	topo_hdl_strfree(thp, sas_address);

	/* Obtain the fmri for this node and save a reference to it. */
	if (topo_node_resource(node, &fmri, &err) != 0) {
		fmd_hdl_debug(slmp->slt_hdl, "failed to get fmri for %s: %s",
		    expander->slt_label, topo_strerror(err));

		free_expander(slmp, expander);
		return (TOPO_WALK_NEXT);
	} else {
		expander->fmri = fmri;
	}

	if ((err = get_log(slmp, expander, &lib_param)) != 0) {
		/*
		 * NULL_LOG_DATA means that no data was returned from the
		 * library.  (i.e. There were no log entries.) Just free memory
		 * and return.
		 */
		if (err != NULL_LOG_DATA) {
			fmd_hdl_debug(slmp->slt_hdl,
			    "Error retrieving logs from %s: %d",
			    expander->slt_label, err);
		}
		free_expander(slmp, expander);
		return (TOPO_WALK_NEXT);
	}

	if ((err = process_log(slmp, expander, &lib_param)) != 0) {
		fmd_hdl_debug(slmp->slt_hdl,
		    "Error processing logs from %s: %d",
		    expander->slt_label, err);
	}

	/* Free the expander structure before exiting. */
	free_expander(slmp, expander);

	return (TOPO_WALK_NEXT);
}

/*
 * Called by the FMD after the specified timeout has expired.
 * This initiates the processing of the SES device logs.
 * slt_process_ses_log() performs the actual log retrieval and analysis.
 *
 * The last action is to reset the timer so that this method is called again.
 */
/*ARGSUSED*/
static void
slt_timeout(fmd_hdl_t *hdl, id_t id, void *data)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	/* Retrieve the SES log monitor structure. */
	ses_log_monitor_t *slmp = fmd_hdl_getspecific(hdl);

	if (slmp == NULL) {
		fmd_hdl_abort(hdl, "Unable to retrieve log monitor structure.");
		return;
	}
	slmp->slt_hdl = hdl;

	thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);

	/*
	 * This initializes a topology walk structure for stepping through
	 * the snapshot associated with thp.  Note that a callback function
	 * is supplied (slt_process_ses_log in this case).
	 */
	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, slt_process_ses_log,
	    slmp, &err)) == NULL) {

		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_abort(hdl, "failed to get topology: %s\n",
		    topo_strerror(err));
		return;
	}

	/*
	 * This function walks through the snapshot and invokes the callback
	 * function supplied when it was set up above.
	 */
	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		topo_walk_fini(twp);
		fmd_hdl_topo_rele(hdl, thp);
		fmd_hdl_abort(hdl, "failed to walk topology\n");
		return;
	}

	/* This releases the walk structure. */
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);

	/* Reset the timer for the next iteration. */
	slmp->slt_timer = fmd_timer_install(hdl, NULL, NULL,
	    slmp->slt_interval);

}

/*
 * Entry points for the FMD to access this transport.
 */
static const fmd_hdl_ops_t fmd_ops = {
	NULL, /* fmdo_recv */
	slt_timeout, /* fmdo_timeout */
	NULL, /* fmdo_close */
	NULL, /* fmdo_stats */
	NULL, /* fmdo_gc */
	NULL, /* fmdo_send */
	NULL, /* fmdo_topo_change */
};

static const fmd_hdl_info_t fmd_info = {
	"SES Log Transport Agent", "1.0", &fmd_ops, fmd_props
};

/*
 * Initialize the transport.
 */
void
_fmd_init(fmd_hdl_t *hdl)
{
	ses_log_monitor_t *slmp;
	int error;
	nvlist_t *expanderList;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (slt_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&slt_stats);

	slmp = fmd_hdl_zalloc(hdl, sizeof (ses_log_monitor_t), FMD_SLEEP);
	fmd_hdl_setspecific(hdl, slmp);

	slmp->slt_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);
	if (slmp->slt_xprt == NULL) {
		fmd_hdl_error(hdl,
		    "Unable to obtain a reference to the transport");
		fmd_hdl_free(hdl, slmp, sizeof (*slmp));
		fmd_hdl_unregister(hdl);
		return;
	}

	/*
	 * interval is validity checked by the framework since it is of type
	 * FMD_TYPE_TIME.
	 */
	slmp->slt_interval = fmd_prop_get_int64(hdl, "interval");

	/*
	 * Use default the severity if it is out of range.
	 * Setting the severity too high is allowed as this has the effect
	 * of preventing any ereports from being generated.
	 */
	slmp->slt_severity = fmd_prop_get_int32(hdl, "severity");
	if (slmp->slt_severity < SES_LOG_LEVEL_NOTICE) {

		slmp->slt_severity = SES_LOG_LEVEL_ERROR;
	}

	slmp->slt_log_count = fmd_prop_get_int32(hdl, "logcount");
	if (slmp->slt_log_count < MIN_LOG_COUNT) {
		slmp->slt_log_count = MIN_LOG_COUNT;
	}

	slmp->slt_max_log_size = fmd_prop_get_int32(hdl, "maxlogsize");
		if (slmp->slt_max_log_size < MIN_LOG_SIZE) {
		slmp->slt_max_log_size = MIN_LOG_SIZE;
	}

	/* Invalid paths will be handled by logging and skipping log creation */
	slmp->slt_path = fmd_prop_get_string(hdl, "path");

	/* Allocate space for the expander id holder */
	if ((error = nvlist_alloc(&expanderList, NV_UNIQUE_NAME, 0)) != 0) {
		fmd_xprt_close(hdl, slmp->slt_xprt);
		fmd_hdl_strfree(hdl, slmp->slt_path);
		fmd_hdl_free(hdl, slmp, sizeof (*slmp));

		fmd_hdl_error(hdl,
		    "Error allocating space for the expander list: %d", error);
		fmd_hdl_unregister(hdl);
		return;
	}

	slmp->slt_expanders = expanderList;

	/*
	 * Call our initial timer routine, starting the periodic timeout.
	 */
	slmp->slt_timer = fmd_timer_install(hdl, NULL, NULL, 0);
}

/*
 * Shut down the transport.  The primary responsibility is to release any
 * allocated memory.
 */
void
_fmd_fini(fmd_hdl_t *hdl)
{
	ses_log_monitor_t *slmp;

	slmp = fmd_hdl_getspecific(hdl);
	if (slmp) {
		fmd_timer_remove(hdl, slmp->slt_timer);
		fmd_xprt_close(hdl, slmp->slt_xprt);
		fmd_prop_free_string(hdl, slmp->slt_path);
		nvlist_free(slmp->slt_expanders);
		fmd_hdl_free(hdl, slmp, sizeof (*slmp));
	}
}
