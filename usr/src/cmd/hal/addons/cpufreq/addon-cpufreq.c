/***************************************************************************
 *
 * addon-cpufreq.c : Routines to support CPUFreq interface
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 ***************************************************************************/


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <priv.h>
#include <pwd.h>

#include <syslog.h>

#include <libhal.h>
#include "../../hald/logger.h"
#include "../../utils/adt_data.h"

#include <pwd.h>
#ifdef HAVE_POLKIT
#include <libpolkit.h>
#endif

#ifdef sun
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <sys/pm.h>
#endif

#define	POWER_CONF_FILE "/etc/power.conf"
#define	PMCONFIG "/usr/sbin/pmconfig -f"
#define	PM "/dev/pm"

#define	FILE_ARR_SIZE 256
#define	EDIT_TYPE_SIZE 64
#define	ERR_BUF_SIZE 256

#define	WAIT_TIME 30

char TMP_CONF_FILE[64] = "/tmp/power.conf.XXXXXX";
const char *sender;
unsigned long uid;

/*
 * Specify different CPUFreq related HAL activities that can be done
 */
enum hal_type {
	CPU_GOV,
	CPU_PERFORMANCE
};
typedef enum hal_type power_conf_hal_type;

/*
 * Various CPUFreq related editable parameters in the power.conf file
 */
typedef struct {
	char	cpu_gov[EDIT_TYPE_SIZE];
	int	cpu_th;
} pconf_edit_type;

/*
 * CPUFreq interospect XML that exports the various CPUFreq HAL interface
 * supported methods
 */
const char *cpufreq_introspect_xml = \
	"	<method name= \"SetCPUFreqGovernor\">\n \
		<arg type= \"s\" name= \"governor\" direction= \"in\"/>\n \
	</method>\n \
	<method name= \"GetCPUFreqGovernor\">\n \
		<type= \"s\" direction= \"out\"/>\n \
	</method>\n \
	<method name= \"SetCPUFreqPerformance\">\n \
		<arg type=\"i\" direction=\"in\"/>\n \
	</method>\n \
	<method name= \"GetCPUFreqPerformance\">\n \
		<type=\"i\" direction=\"out\"/>\n \
	</method>\n \
	<method name= \"GetCPUFreqAvailableGovernors\">\n \
		<type=\"s\" direction=\"out\"/>\n \
	</method>\n";

/*
 * List of governors that are currently supported
 */
char *const gov_list[] = {
	"ondemand",
	"performance",
	NULL
};

static char current_gov[EDIT_TYPE_SIZE];

/*
 * Free up the mem allocated to hold the DBusError
 */
static void
check_and_free_error(DBusError *error)
{
	if (dbus_error_is_set (error)) {
		dbus_error_free (error);
	}
}

/*
 * Edit the /etc/power.conf file to update the cpupm and cpupm_threshold values
 * Return 0 on success
 *	  1 if the governor is not available or supported
 *	 -1 all other errors
 * NOTE: Before modifying power.conf, it is first copied into a temp file, and
 * pmconfig is executed on the temp file with -f option, which uses temp file
 * to set the PM config and then replaces power.conf with the temp file.
 */
static int
edit_power_conf_file(pconf_edit_type pc_edit_type,
    power_conf_hal_type pc_hal_type, char *tmp_file)
{
	FILE	*pfile;
	char	tstr[FILE_ARR_SIZE];
	char	temp_str[FILE_ARR_SIZE];
	long	fset = 0;
	long	next_fset = 0;
	char	*file_edit_type;
	char    *file_edit_value;
	char    file_edit_threshold[FILE_ARR_SIZE];
	char	file_update_str[FILE_ARR_SIZE];
	int	res = 0;
	char	cp_cmd_str[128];
	int	tmp_fd;

	/*
	 * Copy /etc/power.conf to temp file
	 */
	if (tmp_file == NULL) {
		HAL_INFO ((" Invalid temp file name"));
		return (EINVAL);
	}
	sprintf (cp_cmd_str, "/usr/bin/cp %s %s", POWER_CONF_FILE, tmp_file);
	if (system (cp_cmd_str) != 0) {
		HAL_ERROR ((" Error in copying %s to %s, %s",
		    POWER_CONF_FILE, tmp_file, strerror (errno)));
		return (errno);
	}

	pfile = fopen (tmp_file, "r+");
	if (pfile == NULL) {
		HAL_INFO (("Cannot open file %s: %s",
		    tmp_file, strerror (errno)));
		return (errno);
	}

	switch (pc_hal_type) {
	case CPU_GOV:
		if ((pc_edit_type.cpu_gov == NULL) ||
		    ((strcmp (pc_edit_type.cpu_gov, "ondemand") != 0) &&
		    (strcmp (pc_edit_type.cpu_gov, "performance") != 0))) {
			HAL_INFO ((" CPU governor is not available/valid."
			    " Should be either ondemand or performance"));
			res = EINVAL;
			goto out;
		}
		file_edit_type = "cpupm";
		if (strcmp (pc_edit_type.cpu_gov, "ondemand") == 0) {
			file_edit_value = " enable";
		} else {
			file_edit_value = "disable";
		}
		break;
	case CPU_PERFORMANCE:
		if (pc_edit_type.cpu_th == 0) {
			HAL_INFO ((" CPU Threshold is not valid."));
			res = EINVAL;
			goto out;
		}
		file_edit_type = "cpu-threshold";
		sprintf (file_edit_threshold, "%d", pc_edit_type.cpu_th);
		file_edit_value = file_edit_threshold;
		break;
	default:
		HAL_DEBUG ((" Cannot recognize the type of change being"
		    " made to /etc/power.conf"));
			res = EINVAL;
			goto out;
	}

	while (fgets (tstr, FILE_ARR_SIZE, pfile) != NULL) {
		if ((tstr == NULL) || (strlen (tstr) <= 0))
			continue;
		/*
		 * Look for line containing "cpupm" or "cpu-threshold"
		 */

		if (strstr (tstr, file_edit_type) == NULL) {
			fset = fset + strlen (tstr);
			continue;
		}
		/*
		 * If the required value already present. Just
		 * return
		 */
		if (strstr (tstr, file_edit_value) != NULL) {
			res = 0;
			goto out;
		}

		if (fseek (pfile, fset, SEEK_SET) != 0) {
			HAL_ERROR (("\n Error in fseek %s: %s",
			    POWER_CONF_FILE, strerror (errno)));
			res = errno;
			goto out;
		}
		/*
		 * Update the file with new values
		 */
		sprintf (file_update_str, "%s %s \n",
		    file_edit_type, file_edit_value);

		/*
		 * Check if the currrent line is the last one. If not,
		 * to avoid overwriting and wasting space, move remaining
		 * lines upwards and update at the end
		 */
		next_fset = fset + strlen(tstr);
		if (fseek (pfile, next_fset, SEEK_SET) != 0) {
			HAL_ERROR (("\n Error in fseek %s: %s",
			    tmp_file, strerror (errno)));
			res = errno;
			goto out;
		}
		if (fgets (tstr, FILE_ARR_SIZE, pfile) != NULL) {
			do {
				snprintf (temp_str, FILE_ARR_SIZE,
				    "%s\n", tstr);
				fseek (pfile, fset, SEEK_SET);
				fputs (temp_str, pfile);
				fset = fset + strlen(tstr);
				next_fset = next_fset + strlen(tstr);
				fseek (pfile, next_fset, SEEK_SET);

			} while (fgets (tstr, FILE_ARR_SIZE, pfile) != NULL);
		}

		fseek (pfile, fset, SEEK_SET);

		if (fputs (file_update_str, pfile) == EOF) {
			HAL_ERROR (("\n Error in writing to"
			    " %s: %s", POWER_CONF_FILE,
			    strerror (errno)));
			res = errno;
			goto out;
		}

		if (fflush (pfile) == EOF) {
			HAL_ERROR (("\n Error in flushing to"
			    " %s: %s", POWER_CONF_FILE,
			    strerror (errno)));
		}
		res = 0;
		goto out;
	}

	/*
	 * If the pointer comes here, then the property is not already present.
	 * Have to append to the file
	 */
	HAL_DEBUG (("\n Passed value not found. Will append to the file"));
	if (fseek (pfile, 0, SEEK_END) != 0) {
		HAL_ERROR (("\n Error in fseek to %s: %s",
		    POWER_CONF_FILE, strerror (errno)));
		res = errno;
		goto out;
	}

	/*
	 * Update the file with new values
	 */
	sprintf (file_update_str, "%s %s \n", file_edit_type, file_edit_value);

	if (fputs (file_update_str, pfile) == EOF) {
		HAL_ERROR (("Error in writing to file %s: %s",
		    POWER_CONF_FILE, strerror (errno)));
		res = errno;
		goto out;
	}

	if (fflush (pfile) == EOF) {
		HAL_ERROR (("\n Error in flushing to %s: %s",
		    POWER_CONF_FILE, strerror (errno)));
	}
	res = 0;
out:
	fclose (pfile);
	return (res);
}

/*
 * Depending on the type(cpupm or cpu-threshold) to read, check if they are
 * present. If present, return the corresponding value through pc_value arg
 * and return 1 from the function. If there is no corresponding entry,return 0.
 * Return -1 on error
 */

static int
read_power_conf_file(pconf_edit_type *pc_value,
    power_conf_hal_type pc_hal_type)
{

	FILE	*pfile;
	char	tstr[FILE_ARR_SIZE];
	long	fset = 0;
	char	*file_edit_type;
	char	*tpstr;
	int	res = 0;

	pfile = fopen (POWER_CONF_FILE, "r");
	if (pfile == NULL) {
		HAL_INFO (("\n Cannot open the file %s: %s",
		    POWER_CONF_FILE, strerror (errno)));
		return (-1);
	}

	switch (pc_hal_type) {
	case CPU_GOV:
		file_edit_type = "cpupm";
		break;
	case CPU_PERFORMANCE:
		file_edit_type = "cpu-threshold";
		break;
	default :
		HAL_DEBUG (("Cannot recognize the HAL type to get value"));
		res = -1;
		goto out;
	}

	while (fgets (tstr, FILE_ARR_SIZE, pfile) != NULL) {
		if ((tstr == NULL) || (strlen (tstr) <= 0))
			continue;
		/*
		 * Look for line containing "cpupm" or "cpu-threshold"
		 */
		if (strstr (tstr, file_edit_type) == NULL)
			continue;

		/*
		 * If the required value already present. Just
		 * get the value
		 */
		tpstr = strtok (tstr, " ");
		tpstr = strtok (NULL, " ");
		if (tpstr == NULL) {
			HAL_INFO (("Value of %s in %s is not valid",
			    file_edit_type, POWER_CONF_FILE));
			res = -1;
			goto out;
		}

		if (pc_hal_type == CPU_GOV) {
			/*
			 * Copy the corresponding governor
			 */
			if (strcmp (tpstr, "enable") == 0) {
				sprintf (pc_value->cpu_gov,
				    "%s", "ondemand");
			} else {
				sprintf (pc_value->cpu_gov,
				    "%s", "performance");
			}
		} else {
			pc_value->cpu_th = atoi (tpstr);
		}
		res = 1;
		goto out;
	}
	/*
	 * Entry not found in the file
	 */
	HAL_DEBUG ((" No entry of %s in %s", file_edit_type, POWER_CONF_FILE));
	res = 0;

out:
	fclose (pfile);
	return (res);
}


/*
 * Depending on the type(Governor or Perfromance) to read, get the current
 * values through PM ioctls().
 * For "Governor", return the cpupm state and for "Performance" return the
 * current cpu threshold.
 * Return the corresponding value through cur_value and return 1 from the
 * function for success. Return -1 on error
 */

static int
get_cur_val(pconf_edit_type *cur_value,
    power_conf_hal_type pc_hal_type)
{

	int pm_fd;
	int res = -1;
	int pm_ret;

	pm_fd = open (PM, O_RDONLY);
	if (pm_fd == -1) {
		HAL_ERROR (("Error opening %s: %s \n", PM, strerror (errno)));
		return (res);
	}

	switch (pc_hal_type) {
	case CPU_GOV:
		/*
		 * First check the PM_GET_CPUPM_STATE. If it is not available
		 * then check PM_GET_PM_STATE
		 */
		pm_ret = ioctl (pm_fd, PM_GET_CPUPM_STATE);
		if (pm_ret < 0) {
			HAL_ERROR (("Error in ioctl PM_GET_CPUPM_STATE: %s \n",
			    strerror (errno)));
			goto out;
		}
		switch (pm_ret) {
		case PM_CPU_PM_ENABLED:
			sprintf (cur_value->cpu_gov, "%s", "ondemand");
			res = 1;
			goto out;
		case PM_CPU_PM_DISABLED:
			sprintf (cur_value->cpu_gov, "%s", "performance");
			res = 1;
			goto out;
		case PM_CPU_PM_NOTSET:
			/*
			 * Check for PM_GET_PM_STATE
			 */
			pm_ret = ioctl (pm_fd, PM_GET_PM_STATE);
			if (pm_ret < 0) {
				HAL_ERROR (("Error in ioctl PM_GET_PM_STATE: "
				    "%s", strerror (errno)));
				goto out;
			}
			switch (pm_ret) {
			case PM_SYSTEM_PM_ENABLED:
				sprintf (cur_value->cpu_gov, "%s", "ondemand");
				res = 1;
				goto out;
			case PM_SYSTEM_PM_DISABLED:
				sprintf (cur_value->cpu_gov, "%s",
				    "performance");
				res = 1;
				goto out;
			default:
				HAL_ERROR (("PM Internal error during ioctl "
				    "PM_GET_PM_STATE"));
				goto out;
			}
		default:
			HAL_ERROR (("Unknown value ioctl PM_GET_CPUPM_STATE"));
			goto out;
		}
	case CPU_PERFORMANCE:
		/*
		 * First check the PM_GET_CPU_THRESHOLD. If it is not available
		 * then check PM_GET_SYSTEM_THRESHOLD
		 */
		pm_ret = ioctl (pm_fd, PM_GET_CPU_THRESHOLD);
		if (pm_ret >= 0) {
			cur_value->cpu_th = pm_ret;
			res = 1;
			goto out;
		} else if ((pm_ret == EINVAL) || (pm_ret == ENOTTY)) {
			/*
			 * PM_GET_CPU_THRESHOLD is not available
			 */
			pm_ret = ioctl (pm_fd, PM_GET_SYSTEM_THRESHOLD);
			if (res >= 0) {
				cur_value->cpu_th = pm_ret;
				res = 1;
				goto out;
			} else {
				HAL_ERROR (("Error in PM_GET_CPU_THRESHOLD: %s",
				    strerror (errno)));
				goto out;
			}
		} else {
			HAL_ERROR ((" Error in ioctl PM_GET_CPU_THRESHOLD: %s",
			    strerror (errno)));
			goto out;
		}
	default :
		HAL_DEBUG (("Cannot recognize the HAL type to get value"));
		goto out;
	}
out:
	close (pm_fd);
	return (res);
}
/*
 * Send an error message as a response to the pending call
 */
static void
generate_err_msg(DBusConnection *con,
    DBusMessage *msg,
    const char *err_name,
    char *fmt, ...)
{

	DBusMessage	*err_msg;
	char		err_buf[ERR_BUF_SIZE];
	va_list		va_args;

	va_start (va_args, fmt);
	vsnprintf (err_buf, ERR_BUF_SIZE, fmt, va_args);
	va_end (va_args);

	HAL_DEBUG ((" Sending error message: %s", err_buf));

	err_msg = dbus_message_new_error (msg, err_name, err_buf);
	if (err_msg == NULL) {
		HAL_ERROR (("No Memory for DBUS error msg"));
		return;
	}

	if (!dbus_connection_send (con, err_msg, NULL)) {
		HAL_ERROR ((" Out Of Memory!"));
	}
	dbus_connection_flush (con);

}

static void
gen_unknown_gov_err(DBusConnection *con,
    DBusMessage *msg,
    char *err_str)
{

	generate_err_msg (con,
	    msg,
	    "org.freedesktop.Hal.CPUFreq.UnknownGovernor",
	    "Unknown CPUFreq Governor: %s",
	    err_str);
}

static void
gen_no_suitable_gov_err(DBusConnection *con,
    DBusMessage *msg,
    char *err_str)
{

	generate_err_msg (con,
	    msg,
	    "org.freedesktop.Hal.CPUFreq.NoSuitableGovernor",
	    "Could not find a suitable governor: %s",
	    err_str);
}

static void
gen_cpufreq_err(DBusConnection *con,
    DBusMessage *msg,
    char *err_str)
{
	generate_err_msg (con,
	    msg,
	    "org.freedesktop.Hal.CPUFreq.Error",
	    "%s: Syslog might give more information",
	    err_str);
}


/*
 * Puts the required cpufreq audit data and calls adt_put_event()
 * to generate auditing
 */
static void
audit_cpufreq(const adt_export_data_t *imported_state, au_event_t event_id,
    int result, const char *auth_used, const int cpu_thr_value)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	struct passwd		*msg_pwd;
	uid_t			gid;

	if (adt_start_session (&ah, imported_state, 0) != 0) {
		HAL_INFO (("adt_start_session failed: %s", strerror (errno)));
		return;
	}

	if ((event = adt_alloc_event (ah, event_id)) == NULL) {
		HAL_INFO(("adt_alloc_event audit_cpufreq failed: %s",
		    strerror (errno)));
		return;
	}

	switch (event_id) {
	case ADT_cpu_ondemand:
		event->adt_cpu_ondemand.auth_used = (char *)auth_used;
		break;
	case ADT_cpu_performance:
		event->adt_cpu_performance.auth_used = (char *)auth_used;
		break;
	case ADT_cpu_threshold:
		event->adt_cpu_threshold.auth_used = (char *)auth_used;
		event->adt_cpu_threshold.threshold = cpu_thr_value;
		break;
	default:
		goto clean;
	}

	if (result == 0) {
		if (adt_put_event (event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			HAL_INFO (("adt_put_event(%d, ADT_SUCCESS) failed",
			    event_id));
		}
	} else {
		if (adt_put_event (event, ADT_FAILURE, result) != 0) {
			HAL_INFO (("adt_put_event(%d, ADT_FAILURE) failed",
			    event_id));
		}
	}

clean:
	adt_free_event (event);
	(void) adt_end_session (ah);
}

/*
 * Check if the cpufreq related operations are authorized
 */

static int
check_authorization(DBusConnection *con, DBusMessage *msg)
{
	int		adt_res = 0;
#ifdef HAVE_POLKIT
	char		user_id[128];
	char		*udi;
	char		*privilege;
	DBusError	error;
	gboolean	is_priv_allowed;
	gboolean	is_priv_temporary;
	DBusConnection	*system_bus = NULL;
	LibPolKitContext *pol_ctx = NULL;

	/*
	 * Check for authorization before proceeding
	 */
	udi = getenv ("HAL_PROP_INFO_UDI");
	privilege = "hal-power-cpu";

	dbus_error_init (&error);
	system_bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (system_bus == NULL) {
		HAL_INFO (("Cannot connect to the system bus"));
		LIBHAL_FREE_DBUS_ERROR (&error);
		gen_cpufreq_err (con, msg, "Cannot connect to the system bus");
		adt_res = EINVAL;
		goto out;
	}

	sender = dbus_message_get_sender (msg);
	HAL_INFO (("Auth Sender: %s", sender));

	if (sender == NULL) {
		HAL_INFO (("Could not get the sender of the message"));
		gen_cpufreq_err (con, msg,
		    "Could not get the sender of the message");
		adt_res = ADT_FAIL_VALUE_AUTH;
		goto out;
	}

	dbus_error_init (&error);
	uid = dbus_bus_get_unix_user (system_bus, sender, &error);
	if (dbus_error_is_set (&error)) {
		HAL_INFO (("Could not get the user id of the message"));
		LIBHAL_FREE_DBUS_ERROR (&error);
		gen_cpufreq_err (con, msg,
		    "Could not get the user id of the message sender");
		adt_res = ADT_FAIL_VALUE_AUTH;
		goto out;
	}

	snprintf (user_id, sizeof (user_id), "%d", uid);
	HAL_DEBUG ((" User id is : %d", uid));

	pol_ctx = libpolkit_new_context (system_bus);
	if (pol_ctx == NULL) {
		HAL_INFO (("Cannot get libpolkit context"));
		gen_cpufreq_err (con, msg,
		    "Cannot get libpolkit context to check privileges");
		adt_res = ADT_FAIL_VALUE_AUTH;
		goto out;
	}

	if (libpolkit_is_uid_allowed_for_privilege (pol_ctx,
	    NULL,
	    user_id,
	    privilege,
	    udi,
	    &is_priv_allowed,
	    &is_priv_temporary,
	    NULL) != LIBPOLKIT_RESULT_OK) {
		HAL_INFO (("Cannot lookup privilege from PolicyKit"));
		gen_cpufreq_err (con, msg,
		    "Error looking up privileges from Policykit");
		adt_res = ADT_FAIL_VALUE_AUTH;
		goto out;
	}

	if (!is_priv_allowed) {
		HAL_INFO (("Caller doesn't possess required privilege to"
		    " change the governor"));
		gen_cpufreq_err (con, msg,
		    "Caller doesn't possess required "
		    "privilege to change the governor");
		adt_res = ADT_FAIL_VALUE_AUTH;
		goto out;
	}

	HAL_DEBUG ((" Privilege Succeed"));

#endif
out:
	return (adt_res);
}

/*
 * Sets the CPU Freq governor. It sets the gov name in the /etc/power.conf
 * and executes pmconfig. If governor is "ondemand" then "cpupm" is enabled in
 * and if governor is performance, then "cpupm" is disabled
 */
static void
set_cpufreq_gov(DBusConnection *con, DBusMessage *msg, void *udata)
{
	DBusMessageIter arg_iter;
	DBusMessage	*msg_reply;
	char		*arg_val;
	int		arg_type;
	int		pid;
	int		done_flag = 0;
	int		sleep_time = 0;
	int		status;
	int		adt_res = 0;
	char		tmp_conf_file[64] = "/tmp/power.conf.XXXXXX";
	int		tmp_fd;
	char		pmconfig_cmd[128];
	pconf_edit_type pc_edit_type;
#ifdef sun
	adt_export_data_t *adt_data;
	size_t		adt_data_size;
	DBusConnection	*system_bus = NULL;
	DBusError	error;
#endif

	if (! dbus_message_iter_init (msg, &arg_iter)) {
		HAL_DEBUG (("Incoming message has no arguments"));
		gen_unknown_gov_err (con, msg, "No governor specified");
		adt_res = EINVAL;
		goto out;
	}
	arg_type = dbus_message_iter_get_arg_type (&arg_iter);

	if (arg_type != DBUS_TYPE_STRING) {
		HAL_DEBUG (("Incomming message arg type is not string"));
		gen_unknown_gov_err (con, msg,
		    "Specified governor is not a string");
		adt_res = EINVAL;
		goto out;
	}
	dbus_message_iter_get_basic (&arg_iter, &arg_val);
	if (arg_val != NULL) {
		HAL_DEBUG (("SetCPUFreqGov is: %s", arg_val));
	} else {
		HAL_DEBUG (("Could not get SetCPUFreqGov from message iter"));
		adt_res = EINVAL;
		goto out;
	}

	adt_res = check_authorization (con, msg);

	if (adt_res != 0) {
		goto out;
	}

	/*
	 * Update the /etc/power.conf file.
	 */
	tmp_fd = mkstemp (tmp_conf_file);
	if (tmp_fd == -1) {
		HAL_ERROR ((" Error in creating a temp conf file"));
		adt_res = EINVAL;
		goto out;
	}
	strcpy (pc_edit_type.cpu_gov, arg_val);
	adt_res = edit_power_conf_file (pc_edit_type, CPU_GOV, tmp_conf_file);
	if (adt_res != 0) {
		HAL_DEBUG (("Error in edit /etc/power.conf"));
		gen_cpufreq_err (con, msg,
		    "Internal Error while setting the governor");
		unlink (tmp_conf_file);
		goto out;
	}

	/*
	 * Execute pmconfig
	 */
	sprintf (pmconfig_cmd, "%s %s", PMCONFIG, tmp_conf_file);
	if (system (pmconfig_cmd) != 0) {
		HAL_ERROR ((" Error in executing pmconfig: %s",
		    strerror (errno)));
		adt_res = errno;
		gen_cpufreq_err (con, msg, "Error in executing pmconfig");
		unlink (tmp_conf_file);
		goto out;
	}
	unlink (tmp_conf_file);
	HAL_DEBUG (("Executed pmconfig"));
	sprintf (current_gov, "%s", arg_val);

	/*
	 * Just return an empty response, so that if the client
	 * is waiting for any response will not keep waiting
	 */
	msg_reply = dbus_message_new_method_return (msg);
	if (msg_reply == NULL) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg,
		    "Out of memory to create a response");
		adt_res = ENOMEM;
		goto out;
	}

	if (!dbus_connection_send (con, msg_reply, NULL)) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg,
		    "Out of memory to create a response");
		adt_res = ENOMEM;
		goto out;
	}

	dbus_connection_flush (con);

out:

#ifdef sun
	/*
	 * Audit the new governor change
	 */
	dbus_error_init (&error);
	system_bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (system_bus == NULL) {
		HAL_INFO (("Cannot connect to the system bus %s",
		    error.message));
		LIBHAL_FREE_DBUS_ERROR (&error);
		return;
	}

	adt_data = get_audit_export_data (system_bus, sender, &adt_data_size);
	if (adt_data != NULL) {
		if (strcmp (arg_val, "ondemand") == 0) {
			audit_cpufreq (adt_data, ADT_cpu_ondemand, adt_res,
			    "solaris.system.power.cpu", 0);
		} else if (strcmp (arg_val, "performance") == 0) {
			audit_cpufreq (adt_data, ADT_cpu_performance, adt_res,
			    "solaris.system.power.cpu", 0);
		}
		free (adt_data);
	} else {
		HAL_INFO ((" Could not get audit export data"));
	}
#endif /* sun */
}

/*
 * Sets the CPU Freq performance. It sets the cpu-threshold in the
 * /etc/power.conf and executes pmconfig. The performnace value should
 * be between 1 to 100. The cpu-threshold = ((performance val) * 15) secs.
 */
static void
set_cpufreq_performance(DBusConnection *con, DBusMessage *msg, void *udata)
{

	DBusMessageIter arg_iter;
	DBusMessage	*msg_reply;
	int		arg_val;
	int		arg_type;
	int		pid;
	int		done_flag = 0;
	int		sleep_time = 0;
	int		adt_res = 0;
	char		tmp_conf_file[64] = "/tmp/power.conf.XXXXXX";
	int		tmp_fd;
	char		pmconfig_cmd[128];
	pconf_edit_type pc_edit_type;
#ifdef sun
	adt_export_data_t *adt_data;
	size_t		adt_data_size;
	DBusConnection	*system_bus = NULL;
	DBusError	error;
#endif

	adt_res = check_authorization (con, msg);

	if (adt_res != 0) {
		goto out;
	}

	/*
	 * Performance can only be set to dynamic governors. Currently the
	 * only supported dynamic governor is ondemand.
	 */
	if (current_gov[0] == 0) {
		/*
		 * Read the current governor from /etc/power.conf
		 */
		if (read_power_conf_file (&pc_edit_type, CPU_GOV) != 1) {
			HAL_ERROR ((" Error in reading from /etc/power.conf"));
			gen_cpufreq_err (con, msg, "Internal error while "
			    "getting the governor");
			adt_res = EINVAL;
			goto out;
		}
		sprintf (current_gov, "%s", pc_edit_type.cpu_gov);
	}

	if (strcmp (current_gov, "ondemand") != 0) {
		HAL_DEBUG (("To set performance the current gov should be "
		    "dynamic like ondemand"));
		gen_no_suitable_gov_err (con, msg, "Cannot set performance "
		    "to the current governor");
		adt_res = EINVAL;
		goto out;
	}

	if (! dbus_message_iter_init (msg, &arg_iter)) {
		HAL_DEBUG (("Incoming message has no arguments"));
		gen_no_suitable_gov_err(con, msg, "No performance specified");
		adt_res = EINVAL;
		goto out;
	}
	arg_type = dbus_message_iter_get_arg_type (&arg_iter);

	if (arg_type != DBUS_TYPE_INT32) {
		HAL_DEBUG (("Incomming message arg type is not Integer"));
		gen_no_suitable_gov_err (con, msg,
		    "Specified performance is not a Integer");
		adt_res = EINVAL;
		goto out;
	}
	dbus_message_iter_get_basic (&arg_iter, &arg_val);
	if ((arg_val < 1) || (arg_val > 100)) {
		HAL_INFO (("SetCPUFreqPerformance should be between 1 to 100"
		    ": %d", arg_val));
		gen_no_suitable_gov_err (con, msg,
		    "Performance value should be between 1 and 100");
		adt_res = EINVAL;
		goto out;
	}

	HAL_DEBUG (("SetCPUFreqPerformance is: %d", arg_val));

	/*
	 * Update the /etc/power.conf file
	 */
	tmp_fd = mkstemp (tmp_conf_file);
	if (tmp_fd == -1) {
		HAL_ERROR ((" Error in creating a temp conf file"));
		adt_res = EINVAL;
		goto out;
	}
	pc_edit_type.cpu_th = arg_val * 15;
	adt_res = edit_power_conf_file (pc_edit_type, CPU_PERFORMANCE,
	    tmp_conf_file);
	if (adt_res != 0) {
		HAL_DEBUG (("Error while editing /etc/power.conf"));
		gen_cpufreq_err (con, msg,
		    "Internal error while setting the performance");
		unlink (tmp_conf_file);
		goto out;
	}

	/*
	 * Execute pmconfig
	 */
	sprintf (pmconfig_cmd, "%s %s", PMCONFIG, tmp_conf_file);
	if (system (pmconfig_cmd) != 0) {
		HAL_ERROR ((" Error in executing pmconfig: %s",
		    strerror (errno)));
		adt_res = errno;
		gen_cpufreq_err (con, msg,
		    "Internal error while setting the performance");
		unlink (tmp_conf_file);
		goto out;
	}
	unlink (tmp_conf_file);
	HAL_DEBUG (("Executed pmconfig"));

	/*
	 * Just return an empty response, so that if the client
	 * is waiting for any response will not keep waiting
	 */

	msg_reply = dbus_message_new_method_return (msg);
	if (msg_reply == NULL) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg,
		    "Out of memory to create a response");
		adt_res = ENOMEM;
		goto out;
	}

	if (!dbus_connection_send (con, msg_reply, NULL)) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg,
		    "Out of memory to create a response");
		adt_res = ENOMEM;
		goto out;
	}

	dbus_connection_flush (con);
out:
#ifdef sun

	/*
	 * Audit the new performance change
	 */
	dbus_error_init (&error);
	system_bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (system_bus == NULL) {
		HAL_INFO (("Cannot connect to the system bus %s",
		    error.message));
		LIBHAL_FREE_DBUS_ERROR (&error);
		return;
	}

	adt_data = get_audit_export_data (system_bus, sender, &adt_data_size);
	if (adt_data != NULL) {
		audit_cpufreq (adt_data, ADT_cpu_threshold, adt_res,
		    "solaris.system.power.cpu", arg_val);
		free (adt_data);
	} else {
		HAL_INFO ((" Could not get audit export data"));
	}

#endif /* sun */
}

/*
 * Returns in the dbus message the current gov.
 */
static void
get_cpufreq_gov(DBusConnection *con, DBusMessage *msg, void *udata)
{

	DBusMessageIter rep_iter;
	DBusMessage	*msg_reply;
	int		res;
	pconf_edit_type pc_type;
	char		*param;

	/*
	 * Get the governor type from /etc/power.conf if it is present.
	 */
	res = get_cur_val (&pc_type, CPU_GOV);
	if (res != 1) {
		HAL_INFO ((" Error in getting the current governor"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the governor");
		return;
	}

	HAL_DEBUG ((" Current governor is: %s", pc_type.cpu_gov));

	msg_reply = dbus_message_new_method_return (msg);
	if (msg_reply == NULL) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg,
		    "Internal error while getting the governor");
		return;
	}

	/*
	 * Append reply arguments
	 */
	param = (char *) malloc (sizeof (char) * 250);
	if (param == NULL) {
		HAL_ERROR (("\n Could not allocate mem to param"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the governor");
		return;
	}
	sprintf (param, "%s",  pc_type.cpu_gov);

	dbus_message_iter_init_append (msg_reply, &rep_iter);
	if (!dbus_message_iter_append_basic (&rep_iter, DBUS_TYPE_STRING,
	    &param)) {
		HAL_ERROR (("\n Out Of Memory!\n"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the governor");
		free (param);
		return;
	}

	if (!dbus_connection_send (con, msg_reply, NULL)) {
		HAL_ERROR (("\n Out Of Memory!\n"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the governor");
		free (param);
		return;
	}
	dbus_connection_flush (con);
	free (param);
}

/*
 * Returns in the dbus message the current performance value
 */
static void
get_cpufreq_performance(DBusConnection *con, DBusMessage *msg, void *udata)
{

	DBusMessageIter rep_iter;
	DBusMessage	*msg_reply;
	int		res;
	pconf_edit_type pc_type;
	int		param_int;

	/*
	 * Get the performance value
	 */
	res = get_cur_val (&pc_type, CPU_PERFORMANCE);
	if (res != 1) {
		HAL_INFO ((" Error in getting current performance"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the performance value");
		return;
	}

	HAL_DEBUG ((" The current performance: %d", pc_type.cpu_th));

	msg_reply = dbus_message_new_method_return (msg);
	if (msg_reply == NULL) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the performance value");
		return;
	}

	/*
	 * Append reply arguments.pc_type.cpu_th gives the current cputhreshold
	 * vlaue in seconds. Have to convert it into CPU HAL interface
	 * performance value
	 */
	if (pc_type.cpu_th < 15)
		param_int = 1;
	else
		param_int = (pc_type.cpu_th / 15);

	HAL_DEBUG (("Performance: %d \n", param_int));

	dbus_message_iter_init_append (msg_reply, &rep_iter);
	if (!dbus_message_iter_append_basic (&rep_iter, DBUS_TYPE_INT32,
	    &param_int)) {
		HAL_ERROR (("\n Out Of Memory!\n"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the performance value");
		return;
	}

	if (!dbus_connection_send (con, msg_reply, NULL)) {
		HAL_ERROR (("\n Out Of Memory!\n"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the performance value");
		return;
	}
	dbus_connection_flush (con);
}

/*
 * Returns list of available governors. Currently just two governors are
 * supported. They are "ondemand" and "performance"
 */

static void
get_cpufreq_avail_gov(DBusConnection *con, DBusMessage *msg, void *udata)
{

	DBusMessageIter rep_iter;
	DBusMessageIter array_iter;
	DBusMessage	*msg_reply;
	int		ngov;

	msg_reply = dbus_message_new_method_return (msg);
	if (msg_reply == NULL) {
		HAL_ERROR (("Out of memory to msg reply"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the list of governors");
		return;
	}

	/*
	 * Append reply arguments
	 */
	dbus_message_iter_init_append (msg_reply, &rep_iter);

	if (!dbus_message_iter_open_container (&rep_iter,
	    DBUS_TYPE_ARRAY,
	    DBUS_TYPE_STRING_AS_STRING,
	    &array_iter)) {
		HAL_ERROR (("\n Out of memory to msg reply array"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the list of governors");
		return;
	}

	for (ngov = 0; gov_list[ngov] != NULL; ngov++) {
		if (gov_list[ngov])
			HAL_DEBUG (("\n%d Gov Name: %s", ngov, gov_list[ngov]));
			dbus_message_iter_append_basic (&array_iter,
			    DBUS_TYPE_STRING,
			    &gov_list[ngov]);
	}
	dbus_message_iter_close_container (&rep_iter, &array_iter);

	if (!dbus_connection_send (con, msg_reply, NULL)) {
		HAL_ERROR (("\n Out Of Memory!\n"));
		gen_cpufreq_err (con, msg, "Internal error while getting"
		    " the list of governors");
		return;
	}
	dbus_connection_flush (con);
}

static DBusHandlerResult
hald_dbus_cpufreq_filter(DBusConnection *con, DBusMessage *msg, void *udata)
{
	HAL_DEBUG ((" Inside CPUFreq filter:%s", dbus_message_get_path(msg)));
	/*
	 * Check for method types
	 */
	if (!dbus_connection_get_is_connected (con))
		HAL_DEBUG (("Connection disconnected in cpufreq addon"));

	if (dbus_message_is_method_call (msg,
	    "org.freedesktop.Hal.Device.CPUFreq",
	    "SetCPUFreqGovernor")) {
		HAL_DEBUG (("---- SetCPUFreqGovernor is called "));

		set_cpufreq_gov (con, msg, udata);

	} else if (dbus_message_is_method_call (msg,
	    "org.freedesktop.Hal.Device.CPUFreq",
	    "GetCPUFreqGovernor")) {
		HAL_DEBUG (("---- GetCPUFreqGovernor is called "));

		get_cpufreq_gov (con, msg, udata);
	} else if (dbus_message_is_method_call (msg,
	    "org.freedesktop.Hal.Device.CPUFreq",
	    "GetCPUFreqAvailableGovernors")) {
		HAL_DEBUG (("---- GetCPUFreqAvailableGovernors is called "));

		get_cpufreq_avail_gov (con, msg, udata);
	} else if (dbus_message_is_method_call (msg,
	    "org.freedesktop.Hal.Device.CPUFreq",
	    "SetCPUFreqPerformance")) {
		HAL_DEBUG (("---- SetCPUFreqPerformance is called "));

		set_cpufreq_performance (con, msg, udata);
	} else if (dbus_message_is_method_call (msg,
	    "org.freedesktop.Hal.Device.CPUFreq",
	    "GetCPUFreqPerformance")) {
		HAL_DEBUG (("---- GetCPUFreqPerformance is called "));

		get_cpufreq_performance (con, msg, udata);
	} else {
		HAL_DEBUG (("---Not Set/Get cpufreq gov---"));
	}

	return (DBUS_HANDLER_RESULT_HANDLED);

}

static void
drop_privileges()
{
	priv_set_t *pPrivSet = NULL;
	priv_set_t *lPrivSet = NULL;

	/*
	 * Start with the 'basic' privilege set and then add any
	 * of the privileges that will be required.
	 */
	if ((pPrivSet = priv_str_to_set ("basic", ",", NULL)) == NULL) {
		HAL_INFO (("Error in setting the priv"));
		return;
	}

	(void) priv_addset (pPrivSet, PRIV_SYS_DEVICES);

	if (setppriv (PRIV_SET, PRIV_INHERITABLE, pPrivSet) != 0) {
		HAL_INFO (("Could not set the privileges"));
		priv_freeset (pPrivSet);
		return;
	}

	(void) priv_addset (pPrivSet, PRIV_PROC_AUDIT);
	(void) priv_addset (pPrivSet, PRIV_SYS_CONFIG);

	if (setppriv (PRIV_SET, PRIV_PERMITTED, pPrivSet) != 0) {
		HAL_INFO (("Could not set the privileges"));
		priv_freeset (pPrivSet);
		return;
	}

	priv_freeset (pPrivSet);

}

int
main(int argc, char **argv)
{

	LibHalContext *ctx = NULL;
	char *udi;
	DBusError error;
	DBusConnection *conn;

	GMainLoop *loop = g_main_loop_new (NULL, FALSE);

	drop_privileges ();
	openlog ("hald-addon-cpufreq", LOG_PID, LOG_DAEMON);
	setup_logger ();

	bzero (current_gov, EDIT_TYPE_SIZE-1);

	if ((udi = getenv ("UDI")) == NULL) {
		HAL_INFO (("\n Could not get the UDI in addon-cpufreq"));
		return (0);
	}

	dbus_error_init (&error);
	if ((ctx = libhal_ctx_init_direct (&error)) == NULL) {
		HAL_ERROR (("main(): init_direct failed\n"));
		return (0);
	}
	dbus_error_init (&error);
	if (!libhal_device_addon_is_ready (ctx, getenv ("UDI"), &error)) {
		check_and_free_error (&error);
		return (0);
	}

	/*
	 * Claim the cpufreq interface
	 */

	HAL_DEBUG (("cpufreq Introspect XML: %s", cpufreq_introspect_xml));

	if (!libhal_device_claim_interface (ctx,
	    udi,
	    "org.freedesktop.Hal.Device.CPUFreq",
	    cpufreq_introspect_xml,
	    &error)) {
		HAL_DEBUG ((" Cannot claim the CPUFreq interface"));
		check_and_free_error (&error);
		return (0);
	}

	conn = libhal_ctx_get_dbus_connection (ctx);

	/*
	 * Add the cpufreq capability
	 */
	if (!libhal_device_add_capability (ctx,
	    udi,
	    "cpufreq_control",
	    &error)) {
		HAL_DEBUG ((" Could not add cpufreq_control capability"));
		check_and_free_error (&error);
		return (0);
	}
	/*
	 * Watches and times incoming messages
	 */

	dbus_connection_setup_with_g_main (conn, NULL);

	/*
	 * Add a filter function which gets called when a message comes in
	 * and processes the message
	 */

	if (!dbus_connection_add_filter (conn,
	    hald_dbus_cpufreq_filter,
	    NULL,
	    NULL)) {
		HAL_INFO ((" Cannot add the CPUFreq filter function"));
		return (0);
	}

	dbus_connection_set_exit_on_disconnect (conn, 0);

	g_main_loop_run (loop);
}
