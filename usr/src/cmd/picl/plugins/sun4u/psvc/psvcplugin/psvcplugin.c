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

/*
 * PICL plug-in to create environment tree nodes.
 * This plugin should only be installed in the platform directories
 * of supported systems, such as /usr/platform/picl/plugins/SUNW,<>.
 */

#include <picl.h>
#include <picltree.h>
#include <stdio.h>
#include <time.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include  <ctype.h>
#include <pthread.h>
#include <libintl.h>
#include <errno.h>
#include <semaphore.h>
#include <sched.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <psvc_objects.h>
#include <psvc_objects_class.h>

#define	BUFSZ	512

typedef struct {
	char	name[32];
} EName_t;

typedef struct {
	void *hdl;
	int32_t (*funcp)(void *, char *);
	int32_t	num_objects;
	EName_t *obj_list;
	char    routine[64];
} ETask_t;

typedef struct interval_info {
	volatile int32_t   interval;
	int32_t	  num_tasks;
	ETask_t   *task_list;
	pthread_t thread;
	int32_t   has_thread;
	struct interval_info *next;
} EInterval_t;

static EInterval_t *first_interval;

static psvc_opaque_t hdlp;

sem_t timer_sem;
pthread_mutex_t timer_mutex;
pthread_cond_t timer_cond;
pthread_t timer_thread_id;

extern int ptree_get_node_by_path(const char *, picl_nodehdl_t *);

/* Timer states */
#define	NOT_READY	0
#define	READY		1
#define	HAVE_REQUEST	2
#define	ACTIVE		3
#define	TIMER_SHUTDOWN	4

int timer_state = NOT_READY;

int app_timeout;

/* Lock State Loop State Definitions */
#define	STATE_CHANGED		1
#define	STATE_NOT_CHANGED	0

#ifdef DEBUG
static int32_t debug_flag = 1;
#else
static int32_t debug_flag = 0;
#endif

static char library[PATH_MAX];

#define	PSVC_PLUGIN_VERSION	PICLD_PLUGIN_VERSION_1

#pragma init(psvc_plugin_register)	/* place in .init section */

typedef struct  {
	char	parent_path[256];
	char    child_name[32];
	picl_nodehdl_t	child_node;
} psvc_name_t;
psvc_name_t *psvc_paths;

#define	MUTEX_LOCK_FAILED_MSG	gettext("platsvcd: pthread_mutex_lock %s\n")
#define	CV_WAIT_FAILED_MSG	gettext("platsvcd: pthread_cond_wait %s\n")
#define	CV_TWAIT_FAILED_MSG gettext("platsvcd: pthread_cond_timed_wait %s\n")
#define	SEM_WAIT_FAILED_MSG	gettext("platsvcd: sem_wait failed %s\n")
#define	PSVC_APP_DEATH_MSG	gettext("PSVC application death detected\n")
#define	POLICY_FAILED_MSG	gettext("ERROR running %s on %s (%d)")
#define	ID_NOT_FOUND_MSG	gettext("%s: Can't determine id of %s\n")
#define	CLASS_NOT_FOUND_MSG	gettext("%s: Can't determine class of %s\n")
#define	SUBCLASS_NOT_FOUND_MSG	gettext("%s: Can't determine subclass of %s\n")
#define	NODE_NOT_FOUND_MSG	gettext("%s: Can't determine node of %s\n")
#define	SIZE_NOT_FOUND_MSG	gettext("%s: Couldn't determine size of %s\n")
#define	PTREE_CREATE_TABLE_FAILED_MSG		\
	gettext("%s: ptree_create_table failed, %s\n")
#define	PTREE_CREATE_PROP_FAILED_MSG		\
	gettext("%s: ptree_create_prop failed, %s\n")
#define	PTREE_CREATE_NODE_FAILED_MSG		\
	gettext("%s: ptree_create_node failed, %s\n")
#define	PTREE_ADD_ROW_FAILED_MSG gettext("%s: ptree_add_row_to_table: %s\n")
#define	PTREE_ADD_NODE_FAILED_MSG gettext("%s: ptree_add_node: %s\n")
#define	PTREE_ADD_PROP_FAILED_MSG gettext("%s: ptree_add_prop: %s\n")
#define	PTREE_GET_ROOT_FAILED_MSG gettext("%s: ptree_get_root: %s\n")
#define	CREATE_PROP_FAILED_MSG	gettext("%s: Error creating property %s\n")
#define	INVALID_FILE_FORMAT_MSG		gettext("%s: Invalid file format\n")
#define	INVALID_FILE_FORMAT1_MSG	gettext("%s: Invalid file format %s\n")
#define	PSVC_INIT_ERR_MSG	gettext("%s: Error in psvc_init(): %s\n")
#define	SYSINFO_FAILED_MSG	gettext("%s: Can't determine platform type\n")
#define	FILE_OPEN_FAILED_MSG	gettext("%s: Can't open file %s\n")
#define	MALLOC_FAILED_MSG	gettext("%s: malloc failed, %s\n")
#define	UNKNOWN_CLASS_MSG	gettext("%s: Unknown class\n")
#define	NODE_PROP_FAILED_MSG	gettext("%s: node_property: %s\n")

#define	LOCK_STRING_MAX 32

picl_nodehdl_t system_node;
static picl_nodehdl_t lock_node;
static char env_lock_state[LOCK_STRING_MAX] = PSVC_LOCK_ENABLED;
static pthread_mutex_t env_lock_mutex;

static char *class_name[] = {
"temperature-sensor",
"fan",
"led",
"picl",
"digital-sensor",
"digital-control",
"gpio",
"fan-tachometer",
"switch",
"keyswitch",
"gpio",
"i2c"
};
#define	NUM_CLASSES (sizeof (class_name) / sizeof (char *))

struct proj_prop {	/* projected property */
	picl_prophdl_t	handle;
	picl_nodehdl_t  dst_node;
	char		name[32];
};

struct propinfo {
	char		*name;
	uint32_t	type;
	uint32_t	size;
	uint32_t	access;
};

struct propinfo common[] = {
	{"State", PICL_PTYPE_CHARSTRING, 32,
	PICL_READ | PICL_WRITE | PICL_VOLATILE},
	{"FaultInformation", PICL_PTYPE_CHARSTRING, 32,
	PICL_READ | PICL_VOLATILE}
};
#define	COMMON_COUNT (sizeof (common) / sizeof (struct propinfo))

struct propinfo led_properties[] = {
	{"Color", PICL_PTYPE_CHARSTRING, 32, PICL_READ | PICL_VOLATILE},
	{"IsLocator", PICL_PTYPE_CHARSTRING, 32, PICL_READ | PICL_VOLATILE},
	{"LocatorName", PICL_PTYPE_CHARSTRING, 32, PICL_READ | PICL_VOLATILE}
};
/*
 * We define the amount of LED properties to 1 because not all LED's have
 * the two remainding properties.  This number is augmented in psvc_plugin_init
 * when it sees an LED of subclass 2.
 */
#define	LED_COUNT 1

struct propinfo temperature_sensor_properties[] = {
	{"Temperature", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"LowWarningThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"LowShutdownThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"HighWarningThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"HighShutdownThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE}
};
#define	TEMP_SENSOR_COUNT \
	(sizeof (temperature_sensor_properties) / sizeof (struct propinfo))

struct propinfo digi_sensor_properties[] = {
	{"AtoDSensorValue", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"LowWarningThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"LowShutdownThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"HighWarningThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE},
	{"HighShutdownThreshold", PICL_PTYPE_INT, 4, PICL_READ | PICL_VOLATILE}
};
#define	DIGI_SENSOR_COUNT \
	(sizeof (digi_sensor_properties) / sizeof (struct propinfo))

struct propinfo boolgpio_properties[] = {
	{"Gpio-value", PICL_PTYPE_UNSIGNED_INT, sizeof (boolean_t),
	PICL_READ | PICL_WRITE | PICL_VOLATILE},
	{"#Bits", PICL_PTYPE_UNSIGNED_INT, 4, PICL_READ |PICL_VOLATILE}
};
#define	BOOLGPIO_COUNT (sizeof (boolgpio_properties) / sizeof (struct propinfo))

struct propinfo gpio8_properties[] = {
	{"Gpio-value", PICL_PTYPE_UNSIGNED_INT, 1,
	PICL_READ | PICL_WRITE | PICL_VOLATILE},
	{"#Bits", PICL_PTYPE_UNSIGNED_INT, 4, PICL_READ |PICL_VOLATILE}
};
#define	GPIO8_COUNT (sizeof (gpio8_properties) / sizeof (struct propinfo))

struct propinfo digictrl_properties[] = {
	{"DtoAControlValue", PICL_PTYPE_INT, 4,
	PICL_READ | PICL_WRITE | PICL_VOLATILE},
};
#define	DIGICTRL_COUNT (sizeof (digictrl_properties) / sizeof (struct propinfo))

struct classinfo {
	struct propinfo	*props;
	int32_t		count;
} class_properties[] =
{
	{temperature_sensor_properties, TEMP_SENSOR_COUNT}, /* temp sensor */
	{0, 0},				/* fan, only has projected properties */
	{led_properties, LED_COUNT},
	{0, 0},						  /* system class */
	{digi_sensor_properties, DIGI_SENSOR_COUNT}, /* digital sensor */
	{digictrl_properties, DIGICTRL_COUNT},
	{boolgpio_properties, BOOLGPIO_COUNT},
	{digi_sensor_properties, DIGI_SENSOR_COUNT}, /* fan tach */
	{0, 0},
	{0, 0},
	{gpio8_properties, GPIO8_COUNT},
	{0, 0},
};

struct prop_trans {
	char *picl_class;
	char *picl_prop;
	int32_t psvc_prop;
} picl_prop_trans[] =
{
	{"digital-sensor", "AtoDSensorValue", PSVC_SENSOR_VALUE_ATTR},
	{"digital-sensor", "LowWarningThreshold", PSVC_LO_WARN_ATTR},
	{"digital-sensor", "LowShutdownThreshold", PSVC_LO_SHUT_ATTR},
	{"digital-sensor", "HighWarningThreshold", PSVC_HI_WARN_ATTR},
	{"digital-sensor", "HighShutdownThreshold", PSVC_HI_SHUT_ATTR},
	{"digital-control", "DtoAControlValue", PSVC_CONTROL_VALUE_ATTR},
	{"fan-tachometer", "AtoDSensorValue", PSVC_SENSOR_VALUE_ATTR},
	{"fan-tachometer", "LowWarningThreshold", PSVC_LO_WARN_ATTR},
	{"fan-tachometer", "LowShutdownThreshold", PSVC_LO_SHUT_ATTR},
	{"fan-tachometer", "HighWarningThreshold", PSVC_HI_WARN_ATTR},
	{"fan-tachometer", "HighShutdownThreshold", PSVC_HI_SHUT_ATTR},
	{"temperature-sensor", "Temperature", PSVC_SENSOR_VALUE_ATTR},
	{"temperature-sensor", "LowWarningThreshold", PSVC_LO_WARN_ATTR},
	{"temperature-sensor", "LowShutdownThreshold", PSVC_LO_SHUT_ATTR},
	{"temperature-sensor", "HighWarningThreshold", PSVC_HI_WARN_ATTR},
	{"temperature-sensor", "HighShutdownThreshold", PSVC_HI_SHUT_ATTR},
	{"led", "State", PSVC_LED_STATE_ATTR},
	{"led", "Color", PSVC_LED_COLOR_ATTR},
	{"switch", "State", PSVC_SWITCH_STATE_ATTR},
	{"keyswitch", "State", PSVC_SWITCH_STATE_ATTR},
	{"i2c", "State", PSVC_PROBE_RESULT_ATTR}
};

#define	PICL_PROP_TRANS_COUNT \
	(sizeof (picl_prop_trans) / sizeof (struct prop_trans))


typedef struct {
	char		name[32];
	picl_nodehdl_t	node;
} picl_psvc_t;

struct assoc_pair {
	char	antecedent[32];
	char	dependent[32];
};

struct handle {
	uint32_t    obj_count;
	picl_psvc_t *objects;
	FILE	*fp;
} psvc_hdl;

struct proj_prop *prop_list;
uint32_t proj_prop_count;

int psvc_picl_nodes;

void psvc_plugin_init(void);
void psvc_plugin_fini(void);

picld_plugin_reg_t psvc_reg = {
	PSVC_PLUGIN_VERSION,
	PICLD_PLUGIN_CRITICAL,
	"PSVC",
	psvc_plugin_init,
	psvc_plugin_fini
};

/*
 * psvcplugin_add_children was written so that devices which are hotplugable
 * will be able to add in all thier children and children's children. The
 * routine takes in the path of a parent and then searches the psvc_paths
 * array to find all of it's children.  It in turns adds the child and then
 * recursively check to see if it had children and add them too.
 */
void
psvcplugin_add_children(char *parent_path)
{
	int i;
	picl_nodehdl_t parent_node;
	char next_path[256];

	for (i = 0; i < psvc_picl_nodes; ++i) {
		if (strcmp(parent_path, psvc_paths[i].parent_path) == 0) {
			ptree_get_node_by_path(parent_path, &parent_node);
			ptree_add_node(parent_node, psvc_paths[i].child_node);
			(void) snprintf(next_path, sizeof (next_path), "%s/%s",
			    parent_path, psvc_paths[i].child_name);
			psvcplugin_add_children(next_path);
		}
	}
}

void
psvcplugin_lookup(char *name, char *parent, picl_nodehdl_t *node)
{
	int i;

	for (i = 0; i < psvc_picl_nodes; ++i) {
		if (strcmp(name, psvc_paths[i].child_name) == 0) {
			(void) strcpy(parent, psvc_paths[i].parent_path);
			*node = psvc_paths[i].child_node;
		}
	}
}

void
timer_thread(void)
{
	struct timespec timeout;
	int status;


	status = pthread_mutex_lock(&timer_mutex);
	if (status != 0) {
		syslog(LOG_ERR, MUTEX_LOCK_FAILED_MSG, strerror(status));
	}

	for (;;) {
		/* wait for thread to tell us to start timer */
		timer_state = READY;
		do {
			status = pthread_cond_wait(&timer_cond, &timer_mutex);
		} while (timer_state == READY && status == 0);

		if (timer_state == TIMER_SHUTDOWN) {
			pthread_exit(NULL);
			/* not reached */
		}

		if (status != 0) {
			syslog(LOG_ERR, CV_WAIT_FAILED_MSG, strerror(status));
		}

		/*
		 * Will get signalled after semaphore acquired,
		 * or when timeout occurs.
		 */
		(void) clock_gettime(CLOCK_REALTIME, &timeout);
		timeout.tv_sec += app_timeout;

		if (timer_state == HAVE_REQUEST) {
			timer_state = ACTIVE;
			do {
				status = pthread_cond_timedwait(&timer_cond,
				    &timer_mutex, &timeout);
			} while (timer_state == ACTIVE && status == 0);
		}

		if (status != 0) {
			if (status == ETIMEDOUT) {
				syslog(LOG_ERR, PSVC_APP_DEATH_MSG);
				(void) pthread_mutex_lock(&env_lock_mutex);
				(void) strlcpy(env_lock_state,
				    PSVC_LOCK_ENABLED, LOCK_STRING_MAX);
				(void) pthread_mutex_unlock(&env_lock_mutex);
			} else {
				syslog(LOG_ERR, CV_TWAIT_FAILED_MSG,
				    strerror(status));
			}
		}
	}
}

static int
lock_state_loop(char *set_lock_state)
{
	(void) pthread_mutex_lock(&env_lock_mutex);
	if (strcmp(env_lock_state, PSVC_LOCK_ENABLED) == 0) {
		(void) strlcpy(env_lock_state, set_lock_state, LOCK_STRING_MAX);
		(void) pthread_mutex_unlock(&env_lock_mutex);
		return (STATE_NOT_CHANGED);
	}
	(void) pthread_mutex_unlock(&env_lock_mutex);
	return (STATE_CHANGED);
}

static int timed_lock_wait(char *set_lock_state)
{
	int32_t status;

	/* Only want one timer active at a time */
	do {
		status = sem_wait(&timer_sem);
	} while (status == -1 && errno == EINTR);
	if (status == -1)
		return (status);

	while (timer_state != READY)
		(void) sched_yield();
	(void) pthread_mutex_lock(&timer_mutex);
	timer_state = HAVE_REQUEST;
	(void) pthread_cond_signal(&timer_cond);	/* start timer */
	(void) pthread_mutex_unlock(&timer_mutex);

	/*
	 * We now spin checking the state env_lock_state for it to change to
	 * enabled.
	 */
	while (lock_state_loop(set_lock_state))
		(void) sleep(1);

	(void) pthread_mutex_lock(&timer_mutex);
	if (timer_state == ACTIVE) {
		timer_state = NOT_READY;
		(void) pthread_cond_signal(&timer_cond);	/* stop timer */
	}
	if (timer_state == HAVE_REQUEST) {		/* cancel request */
		timer_state = NOT_READY;
	}
	(void) pthread_mutex_unlock(&timer_mutex);
	(void) sem_post(&timer_sem);
	return (0);
}

static void lock_and_run(ETask_t *tp, int32_t obj_num)
{
	int32_t status;

	/* Grab mutex to stop the env_lock from being changed. */
	(void) pthread_mutex_lock(&env_lock_mutex);
	/*
	 * Check to see if the lock is anything but Enabled. If so, we then
	 * goto our timer routine to wait for it to become enabled.
	 * If not then set it to RUNNING and run policy.
	 */
	if (strcmp(env_lock_state, PSVC_LOCK_ENABLED) != 0) {
		/* drop mutex and goto timer */
		(void) pthread_mutex_unlock(&env_lock_mutex);
		status = timed_lock_wait(PSVC_LOCK_RUNNING);
		if (status == -1) {
			syslog(LOG_ERR, SEM_WAIT_FAILED_MSG);
		}
	} else {
		(void) strlcpy(env_lock_state, PSVC_LOCK_RUNNING,
		    LOCK_STRING_MAX);
		(void) pthread_mutex_unlock(&env_lock_mutex);
	}
	status = (*tp->funcp)(hdlp, (tp->obj_list + obj_num)->name);
	if (status == PSVC_FAILURE && errno != ENODEV) {
		char dev_name[32];

		psvc_get_attr(hdlp, (tp->obj_list + obj_num)->name,
		    PSVC_LABEL_ATTR, dev_name);
		syslog(LOG_ERR, POLICY_FAILED_MSG, tp->routine, dev_name,
		    (tp->obj_list + obj_num)->name);
		syslog(LOG_ERR, "%s", strerror(errno));
	}

	/* The policy is done so set the lock back to ENABLED. */
	(void) pthread_mutex_lock(&env_lock_mutex);
	(void) strlcpy(env_lock_state, PSVC_LOCK_ENABLED, LOCK_STRING_MAX);
	(void) pthread_mutex_unlock(&env_lock_mutex);
}

static void *
run_policies(void *ptr)
{
	EInterval_t *ip = ptr;
	ETask_t *tp;
	int32_t i, j;

	do {
		if (ip->interval) {
			int remaining = ip->interval;
			do {
				/* check to see if we've been told to exit */
				if (ip->has_thread && (ip->interval == 0))
					break;
				remaining = sleep(remaining);
			} while (remaining > 0);
		}
		for (i = 0; i < ip->num_tasks; ++i) {
			tp = &ip->task_list[i];
			for (j = 0; j < tp->num_objects; ++j) {
				/* check to see if we've been told to exit */
				if (ip->has_thread && (ip->interval == 0))
					break;
				lock_and_run(tp, j);
			}
			if (ip->has_thread && (ip->interval == 0))
				break;
		}
	} while (ip->interval);

	return (NULL);
}

static void thread_setup(EInterval_t *ip)
{
	int32_t status;

	status = pthread_create(&ip->thread, NULL, run_policies, ip);
	if (status != 0) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		exit(-1);
	}
	ip->has_thread = 1;
}

static int32_t load_policy(const char *library, ETask_t *tp)
{
	tp->hdl = dlopen(library, RTLD_NOW | RTLD_GLOBAL);
	if (tp->hdl == NULL) {
		if (debug_flag) {
			char *errstr = dlerror();
			syslog(LOG_ERR, "%s", errstr);
		}
		exit(1);
	}
	tp->funcp = (int32_t (*)(void *, char *))dlsym(tp->hdl, tp->routine);
	if (tp->funcp == NULL) {
		if (debug_flag) {
			char *errstr = dlerror();
			syslog(LOG_ERR, "%s", errstr);
		}
		exit(1);
	}
	return (0);
}

static int32_t get_timeout(FILE *fp, int *timeout)
{
	char buf[BUFSZ];
	char name[32];
	char *cp;

	/* skip blank lines */
	do {
		cp = fgets(buf, BUFSZ, fp);
		if (cp == NULL)
			return (1);
		while (isspace(*cp))
			++cp;
		(void) sscanf(buf, "%31s %d", name, timeout);
	} while (*cp == 0 || *cp == '\n' || strcmp(name, "TIMEOUT") != 0);

	if (strcmp(name, "TIMEOUT") != 0) {
		errno = EINVAL;
		return (-1);
	}
	return (0);

}

static int32_t load_interval(FILE *fp, EInterval_t **ipp)
{
	char buf[BUFSZ];
	int32_t found;
	EInterval_t *ip;
	ETask_t *tp;
	int32_t tasks;
	int32_t status, i, j;
	int32_t interval;
	char name[32];
	char *cp;

	/* skip blank lines */
	do {
		cp = fgets(buf, BUFSZ, fp);
		if (cp == NULL)
			return (1);
		while (isspace(*cp))
			++cp;
	} while (*cp == 0 || *cp == '\n');
	found = sscanf(buf, "%31s %d %d", name, &interval, &tasks);
	if (found != 3) {
		errno = EINVAL;
		return (-1);
	}

	if (strcmp(name, "INTERVAL") != 0) {
		errno = EINVAL;
		return (-1);
	}

	ip = (EInterval_t *)malloc(sizeof (EInterval_t));
	if (ip == NULL)
		return (-1);
	ip->num_tasks = tasks;
	ip->interval = interval;
	ip->next = NULL;
	ip->has_thread = 0;

	/* allocate and load table */
	ip->task_list = (ETask_t *)malloc(ip->num_tasks * sizeof (ETask_t));
	if (ip->task_list == NULL)
		return (-1);
	for (i = 0; i < ip->num_tasks; ++i) {
		tp = &ip->task_list[i];

		(void) fgets(buf, BUFSZ, fp);
		found = sscanf(buf, "%31s %1023s %63s",
		    name, library, tp->routine);
		if (found != 3) {
			errno = EINVAL;
			return (-1);
		}

		status = load_policy(library, tp);
		if (status == -1)
			return (-1);
		found = fscanf(fp, "%d", &tp->num_objects);
		if (found != 1) {
			if (debug_flag)
				syslog(LOG_ERR, "No list of objects for task");
			errno = EINVAL;
			return (-1);
		}
		tp->obj_list =
		    (EName_t *)malloc(tp->num_objects * sizeof (EName_t));
		if (tp->obj_list == NULL)
			return (-1);

		for (j = 0; j < tp->num_objects; ++j) {
			found = fscanf(fp, "%31s", (char *)(tp->obj_list + j));
			if (found != 1) {
				if (debug_flag)
					syslog(LOG_ERR,
					"Wrong number of objects for task");
				errno = EINVAL;
				return (-1);
			}
		}
		(void) fgets(buf, BUFSZ, fp);  /* reads newline on data line */
		(void) fgets(buf, BUFSZ, fp);
		if (strncmp(buf, "TASK_END", 8) != 0) {
			if (debug_flag)
				syslog(LOG_ERR, "Expected TASK_END, task %s",
				    tp->routine);
			errno = EINVAL;
			return (-1);
		}
	}

	(void) fgets(buf, BUFSZ, fp);
	if (strncmp(buf, "INTERVAL_END", 12) != 0) {
		if (debug_flag)
			syslog(LOG_ERR, "Expected INTERVAL_END");
		errno = EINVAL;
		return (-1);
	}

	*ipp = ip;
	return (0);
}

void
fini_daemon(void)
{
	EInterval_t *ip;

	/* shut down the threads running the policies */
	for (ip = first_interval; ip != NULL; ip = ip->next) {
		if (ip->has_thread) {
			/*
			 * there is a thread for this interval; tell it to stop
			 * by clearing the interval
			 */
			ip->interval = 0;
		}
	}
	for (ip = first_interval; ip != NULL; ip = ip->next) {
		if (ip->has_thread) {
			(void) pthread_join(ip->thread, NULL);
		}
	}
	/* shut down the timer thread */
	while (timer_state != READY)
		(void) sched_yield();
	(void) pthread_mutex_lock(&timer_mutex);
	timer_state = TIMER_SHUTDOWN;
	(void) pthread_cond_signal(&timer_cond);
	(void) pthread_mutex_unlock(&timer_mutex);
	(void) pthread_join(timer_thread_id, NULL);
	(void) pthread_mutex_destroy(&env_lock_mutex);
	(void) pthread_mutex_destroy(&timer_mutex);
	(void) pthread_cond_destroy(&timer_cond);
	(void) sem_destroy(&timer_sem);
}

void
init_daemon(void)
{
	int32_t intervals = 0;
	int32_t threads = 0;
	int32_t status;
	FILE *fp;
	char filename[PATH_MAX];
	char platform[64];
	EInterval_t *ip, *prev;

	if (sysinfo(SI_PLATFORM, platform, sizeof (platform)) == -1) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}

	(void) snprintf(filename, sizeof (filename),
	    "/usr/platform/%s/lib/platsvcd.conf", platform);
	if ((fp = fopen(filename, "r")) == NULL) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}

	status = get_timeout(fp, &app_timeout);
	if (status != 0) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}

	status = sem_init(&timer_sem, 0, 1);
	if (status == -1) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}

	(void) strlcpy(env_lock_state, PSVC_LOCK_ENABLED, LOCK_STRING_MAX);
	(void) pthread_mutex_init(&env_lock_mutex, NULL);
	(void) pthread_mutex_init(&timer_mutex, NULL);
	(void) pthread_cond_init(&timer_cond, NULL);

	timer_state = NOT_READY;
	status = pthread_create(&timer_thread_id, NULL,
	    (void *(*)())timer_thread, 0);
	if (status != 0) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}

	/* get timer thread running */
	while (timer_state != READY)
		(void) sched_yield();

	for (;;) {
		status = load_interval(fp, &ip);
		if (status != 0)
			break;

#ifdef	lint
		prev = NULL;
#endif
		if (first_interval == 0)
			first_interval = ip;
		else
			prev->next = ip;
		prev = ip;

		++intervals;
		if (ip->interval == 0) {
			run_policies(ip);
		} else {
			thread_setup(ip);
			++threads;
		}
	}
	if (intervals == 0) {
		if (debug_flag)
			syslog(LOG_ERR, "ERROR: No policies started");
		return;
	}

	if (status == -1) {
		if (debug_flag)
			syslog(LOG_ERR, "%s", strerror(errno));
		return;
	}
}


static int32_t count_records(FILE *fp, char *end, uint32_t *countp)
{
	long first_record;
	char *ret;
	char buf[BUFSZ];
	uint32_t count = 0;

	first_record = ftell(fp);

	while ((ret = fgets(buf, BUFSZ, fp)) != NULL) {
		if (strncmp(end, buf, strlen(end)) == 0)
			break;
		++count;
	}

	if (ret == NULL) {
		errno = EINVAL;
		return (-1);
	}

	(void) fseek(fp, first_record, SEEK_SET);
	*countp = count;
	return (0);
}

/*
 * Find start of a section within the config file,
 * Returns number of records in the section.
 * FILE *fd is set to first data record within section.
 */
static int32_t
find_file_section(FILE *fd, char *start)
{
	char *ret;
	char buf[BUFSZ];
	char name[32];
	int found;

	(void) fseek(fd, 0, SEEK_SET);
	while ((ret = fgets(buf, BUFSZ, fd)) != NULL) {
		if (strncmp(start, buf, strlen(start)) == 0)
			break;
	}

	if (ret == NULL) {
		errno = EINVAL;
		return (-1);
	}

	found = sscanf(buf, "%31s", name);
	if (found != 1) {
		errno = EINVAL;
		return (-1);
	} else {
		return (0);
	}

}

static int32_t name_compare_qsort(picl_psvc_t *s1, picl_psvc_t *s2)
{
	return (strcmp(s1->name, s2->name));
}

static int32_t name_compare_bsearch(char *s1, picl_psvc_t *s2)
{
	return (strcmp(s1, s2->name));
}

/*
 * Create a property and add it to the specified node.
 * PICL will take a segmentation violation if a volatile property
 * has a non-zero size.
 */
static int32_t node_property(picl_nodehdl_t node,
	int (*read)(ptree_rarg_t *, void *),
	int (*write)(ptree_warg_t *, const void *), picl_prop_type_t type,
	unsigned int size, unsigned int accessmode, char *name, void *value)
{
	ptree_propinfo_t propinfo;
	picl_prophdl_t prophdl;
	int err;

	propinfo.version = PSVC_PLUGIN_VERSION;
	if (accessmode & PICL_VOLATILE) {
		propinfo.read = read;
		propinfo.write = write;
	} else {
		propinfo.read = NULL;
		propinfo.write = NULL;
	}
	propinfo.piclinfo.type = type;
	propinfo.piclinfo.accessmode = accessmode;
	propinfo.piclinfo.size = size;
	(void) strcpy(propinfo.piclinfo.name, name);

	err = ptree_create_prop(&propinfo, value, &prophdl);
	if (err != 0) {
		return (err);
	}

	err = ptree_add_prop(node, prophdl);
	if (err != 0)
		return (err);

	return (0);
}

static void init_err(const char *fmt, char *arg1, char *arg2)
{
	char msg[256];

	(void) snprintf(msg, sizeof (msg), fmt, arg1, arg2);
	syslog(LOG_ERR, "%s", msg);
}

static int
projected_lookup(picl_prophdl_t proph, struct proj_prop **dstp)
{
	int i;

	for (i = 0; i < proj_prop_count; ++i) {
		if (prop_list[i].handle == proph) {
			*dstp = &prop_list[i];
			return (PICL_SUCCESS);
		}
	}

	return (PICL_INVALIDHANDLE);
}

int
projected_read(ptree_rarg_t *rarg, void *buf)
{
	ptree_propinfo_t propinfo;
	struct proj_prop *dstinfo;
	int err;

	err = projected_lookup(rarg->proph, &dstinfo);
	if (err != 0) {
		return (PICL_FAILURE);
	}


	err = ptree_get_propinfo(rarg->proph, &propinfo);
	if (err != 0)
		return (err);
	err = ptree_get_propval_by_name(dstinfo->dst_node,
	    dstinfo->name, buf, propinfo.piclinfo.size);
	if (err != 0)
		return (err);
	return (PICL_SUCCESS);
}

int
projected_write(ptree_warg_t *warg, const void *buf)
{
	ptree_propinfo_t propinfo;
	struct proj_prop *dstinfo;
	int err;

	err = projected_lookup(warg->proph, &dstinfo);
	if (err != 0) {
		return (PICL_FAILURE);
	}

	err = ptree_get_propinfo(warg->proph, &propinfo);
	if (err != 0)
		return (err);
	err = ptree_update_propval_by_name(dstinfo->dst_node,
	    dstinfo->name, buf, propinfo.piclinfo.size);
	if (err != 0)
		return (err);
	return (PICL_SUCCESS);
}

int
psvc_read_volatile(ptree_rarg_t *rarg, void *buf)
{
	ptree_propinfo_t propinfo;
	char name[32], class[32];
	int err, i;
	int32_t attr_num = -1;
	int32_t use_attr_num = 0;

	err = ptree_get_propval_by_name(rarg->nodeh, "name", name,
	    sizeof (name));
	if (err != 0) {
		return (err);
	}

	err = ptree_get_propval_by_name(rarg->nodeh, "_class", class,
	    sizeof (class));
	if (err != 0) {
		return (err);
	}

	err = ptree_get_propinfo(rarg->proph, &propinfo);
	if (err != 0) {
		return (err);
	}

	for (i = 0; i < PICL_PROP_TRANS_COUNT; i++) {
		if ((strcmp(class, picl_prop_trans[i].picl_class) == 0) &&
		    (strcmp(propinfo.piclinfo.name,
		    picl_prop_trans[i].picl_prop) == 0)) {
			attr_num = i;
			break;
		}
	}

	if (attr_num == -1)
		for (i = 0; i < ATTR_STR_TAB_SIZE; i++) {
			if (strcmp(propinfo.piclinfo.name,
			    attr_str_tab[i]) == 0) {
				attr_num = i;
				use_attr_num = 1;
				break;
			}
		}

	if (use_attr_num)
		err = psvc_get_attr(hdlp, name, attr_num, buf);
	else
		err = psvc_get_attr(hdlp, name,
		    picl_prop_trans[attr_num].psvc_prop,
		    buf);

	if (err != 0) {
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

int
psvc_write_volatile(ptree_warg_t *warg, const void *buf)
{
	ptree_propinfo_t propinfo;
	char name[32], class[32];
	int err, i;
	int32_t attr_num = -1;
	int32_t use_attr_num = 0;

	if (warg->cred.dc_euid != 0)
		return (PICL_PERMDENIED);

	err = ptree_get_propval_by_name(warg->nodeh, "name", name,
	    sizeof (name));
	if (err != 0) {
		return (err);
	}

	err = ptree_get_propval_by_name(warg->nodeh, "_class", class,
	    sizeof (class));
	if (err != 0) {
		return (err);
	}

	err = ptree_get_propinfo(warg->proph, &propinfo);
	if (err != 0) {
		return (err);
	}

	for (i = 0; i < PICL_PROP_TRANS_COUNT; i++) {
		if ((strcmp(class, picl_prop_trans[i].picl_class) == 0) &&
		    (strcmp(propinfo.piclinfo.name,
		    picl_prop_trans[i].picl_prop) == 0)) {
			attr_num = i;
			break;
		}
	}

	if (attr_num == -1)
		for (i = 0; i < ATTR_STR_TAB_SIZE; i++) {
			if (strcmp(propinfo.piclinfo.name,
			    attr_str_tab[i]) == 0) {
			attr_num = i;
			use_attr_num = 1;
			break;
			}
		}

	if (use_attr_num)
		err = psvc_set_attr(hdlp, name, attr_num, (void *)buf);
	else
		err = psvc_set_attr(hdlp, name,
		    picl_prop_trans[attr_num].psvc_prop,
		    (void *)buf);

	if (err != 0) {
		return (PICL_FAILURE);
	}

	return (PICL_SUCCESS);
}

void create_reference_properties(struct assoc_pair *assoc_tbl, int32_t count,
	char *assoc_name)
{
	picl_psvc_t *aobjp, *dobjp;
	picl_prophdl_t tbl_hdl;
	picl_nodehdl_t *dep_list;
	ptree_propinfo_t propinfo;
	char *funcname = "create_reference_properties";
	char name[PICL_PROPNAMELEN_MAX];
	int32_t i, j, offset;
	int32_t dependents;
	int32_t err;
	char class[PICL_CLASSNAMELEN_MAX];

	for (i = 0; i < count; ++i) {
		/* antecedent */
		aobjp = (picl_psvc_t *)bsearch(assoc_tbl[i].antecedent,
		    psvc_hdl.objects, psvc_hdl.obj_count,
		    sizeof (picl_psvc_t),
		    (int (*)(const void *, const void *))
		    name_compare_bsearch);
		if (aobjp == NULL) {
			init_err(ID_NOT_FOUND_MSG,
			    funcname, assoc_tbl[i].antecedent);
			return;
		}

		/* skip if table already created */
		if (ptree_get_propval_by_name(aobjp->node, assoc_name,
		    &tbl_hdl, sizeof (tbl_hdl)) == 0) {
			continue;
		}

		/* create a new table */
		err = ptree_create_table(&tbl_hdl);
		if (err != 0) {
			init_err(PTREE_CREATE_TABLE_FAILED_MSG,
			    funcname, picl_strerror(err));
			return;
		}

		err = node_property(aobjp->node, NULL, NULL,
		    PICL_PTYPE_TABLE, sizeof (tbl_hdl), PICL_READ,
		    assoc_name, &tbl_hdl);
		if (err != 0) {
			init_err(CREATE_PROP_FAILED_MSG, funcname,
			    picl_strerror(err));
			return;
		}

		/* determine number of elements in the table */
		dependents = 0;
		for (j = i; j < count; ++j) {
			if (strcmp(aobjp->name, assoc_tbl[j].antecedent) == 0)
				++dependents;
		}

		dep_list = (picl_nodehdl_t *)malloc(sizeof (picl_nodehdl_t) *
		    dependents);
		if (dep_list == NULL) {
			init_err(MALLOC_FAILED_MSG, funcname, strerror(errno));
			return;
		}
		/* build row of reference properties */
		offset = 0;
		for (j = i; j < count; ++j) {
			if (strcmp(aobjp->name, assoc_tbl[j].antecedent) != 0)
				continue;

			dobjp = (picl_psvc_t *)bsearch(assoc_tbl[j].dependent,
			    psvc_hdl.objects,
			    psvc_hdl.obj_count, sizeof (picl_psvc_t),
			    (int (*)(const void *, const void *))
			    name_compare_bsearch);
			if (dobjp == NULL) {
				init_err(ID_NOT_FOUND_MSG,
				    funcname, assoc_tbl[j].dependent);
				return;
			}

			/*
			 * Reference property name must be
			 * _classname_propertyname
			 */
			err = ptree_get_propval_by_name(dobjp->node,
			    "_class", class, sizeof (class));
			if (err != 0) {
				init_err(CLASS_NOT_FOUND_MSG, funcname,
				    assoc_tbl[j].dependent);
				return;
			}
			(void) snprintf(name, sizeof (name), "_%s_subclass",
			    class);

			propinfo.version = PSVC_PLUGIN_VERSION;
			propinfo.read = NULL;
			propinfo.write = NULL;
			propinfo.piclinfo.type = PICL_PTYPE_REFERENCE;
			propinfo.piclinfo.accessmode = PICL_READ;
			propinfo.piclinfo.size = sizeof (picl_nodehdl_t);
			(void) strcpy(propinfo.piclinfo.name, name);

			err = ptree_create_prop(&propinfo, &dobjp->node,
			    dep_list + offset);
			if (err != 0) {
				init_err(PTREE_CREATE_PROP_FAILED_MSG,
				    name, picl_strerror(err));
				return;
			}

			++offset;
		}

		/* add row to table */
		err = ptree_add_row_to_table(tbl_hdl, dependents, dep_list);
		if (err != 0) {
			init_err(PTREE_ADD_ROW_FAILED_MSG, funcname,
			    picl_strerror(err));
			return;
		}

	}


}

/* Load projected properties */
static void
load_projected_properties(FILE *fp)
{
	int32_t found;
	ptree_propinfo_t propinfo;
	ptree_propinfo_t dstinfo;
	picl_prophdl_t src_prophdl, dst_prophdl;
	picl_nodehdl_t src_node, dst_node;
	int err, i;
	picl_psvc_t *srcobjp, *dstobjp;
	char src[32], dst[256];
	char src_prop[32], dst_prop[32];
	char buf[BUFSZ];
	char *funcname = "load_projected_properties";

	if (find_file_section(fp, "PROJECTED_PROPERTIES") != 0)
		return;

	if (count_records(fp, "PROJECTED_PROPERTIES_END", &proj_prop_count) !=
	    0) {
		init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
		return;
	}

	prop_list = (struct proj_prop *)malloc(sizeof (struct proj_prop)
	    * proj_prop_count);
	if (prop_list == NULL) {
		init_err(MALLOC_FAILED_MSG, funcname, strerror(errno));
		return;
	}

	for (i = 0; i < proj_prop_count; ++i) {
		buf[0] = '\0';
		(void) fgets(buf, BUFSZ, fp);
		found = sscanf(buf, "%31s %31s %255s %31s", src, src_prop, dst,
		    dst_prop);
		if (found != 4) {
			init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
			return;
		}

		/* find src node */
		if (src[0] == '/') {
			/* picl node name, outside psvc subtree */
			err = ptree_get_node_by_path(src, &src_node);
			if (err != 0) {
				init_err(NODE_NOT_FOUND_MSG, funcname, src);
				return;
			}
		} else {
			srcobjp = (picl_psvc_t *)bsearch(src, psvc_hdl.objects,
			    psvc_hdl.obj_count, sizeof (picl_psvc_t),
			    (int (*)(const void *, const void *))
			    name_compare_bsearch);
			if (srcobjp == NULL) {
				init_err(ID_NOT_FOUND_MSG, funcname, src);
				return;
			}
			src_node = srcobjp->node;
		}

		/* find dest node */
		if (dst[0] == '/') {
			/* picl node name, outside psvc subtree */
			err = ptree_get_node_by_path(dst, &dst_node);
			if (err != 0) {
				init_err(NODE_NOT_FOUND_MSG, funcname, dst);
				return;
			}
			prop_list[i].dst_node = dst_node;
		} else {
			dstobjp = (picl_psvc_t *)bsearch(dst, psvc_hdl.objects,
			    psvc_hdl.obj_count, sizeof (picl_psvc_t),
			    (int (*)(const void *, const void *))
			    name_compare_bsearch);
			if (dstobjp == NULL) {
				init_err(ID_NOT_FOUND_MSG, funcname, dst);
				return;
			}
			dst_node = dstobjp->node;
			prop_list[i].dst_node = dst_node;
		}

		/* determine destination property size */
		err = ptree_get_first_prop(dst_node, &dst_prophdl);
		while (err == 0) {
			err = ptree_get_propinfo(dst_prophdl, &dstinfo);
			if (err != 0)
				break;
			if (strcmp(dst_prop, dstinfo.piclinfo.name) == 0)
				break;
			err = ptree_get_next_prop(dst_prophdl, &dst_prophdl);
		}
		if (err != 0) {
			init_err(SIZE_NOT_FOUND_MSG, funcname, dst_prop);
			return;
		}

		propinfo.version = PSVC_PLUGIN_VERSION;
		propinfo.read = projected_read;
		propinfo.write = projected_write;
		propinfo.piclinfo.type = dstinfo.piclinfo.type;
		propinfo.piclinfo.accessmode =
		    PICL_READ | PICL_WRITE | PICL_VOLATILE;
		propinfo.piclinfo.size = dstinfo.piclinfo.size;
		(void) strcpy(propinfo.piclinfo.name, src_prop);

		err = ptree_create_prop(&propinfo, 0, &src_prophdl);
		if (err != 0) {
			init_err(PTREE_CREATE_PROP_FAILED_MSG, funcname,
			    picl_strerror(err));
			return;
		}

		err = ptree_add_prop(src_node, src_prophdl);
		if (err != 0) {
			init_err(PTREE_ADD_PROP_FAILED_MSG, funcname,
			    picl_strerror(err));
			return;
		}

		prop_list[i].handle = src_prophdl;
		(void) strcpy(prop_list[i].name, dst_prop);

	}
}

/* Load the association table */
static void load_associations(FILE *fp)
{
	char *funcname = "load_associations";
	uint32_t count;
	int found;
	int j;
	char assoc_name[32];
	struct assoc_pair *assoc_tbl;
	char name1[32];
	char buf[BUFSZ];

	/*
	 * ignore count in the file, correct count is highest
	 * association id + 1, now figured when loading ASSOC_STR
	 * section.
	 */
	if (find_file_section(fp, "ASSOCIATIONS") != 0)
		return;

	buf[0] = '\0';
	(void) fgets(buf, BUFSZ, fp);
	while (strncmp("ASSOCIATIONS_END", buf, 16) != 0) {
		found = sscanf(buf, "%31s %31s", name1, assoc_name);
		if (found != 2) {
			init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
			return;
		}

		if (count_records(fp, "ASSOCIATION_END", &count) != 0) {
			init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
			return;
		}

		assoc_tbl = (struct assoc_pair *)malloc(
		    sizeof (struct assoc_pair) * count);
		if (assoc_tbl == NULL) {
			init_err(MALLOC_FAILED_MSG, funcname, strerror(errno));
			return;
		}

		for (j = 0; j < count; ++j) {
			buf[0] = '\0';
			(void) fgets(buf, BUFSZ, fp);
			found = sscanf(buf, "%31s %31s",
			    assoc_tbl[j].antecedent, assoc_tbl[j].dependent);
			if (found != 2) {
				init_err(INVALID_FILE_FORMAT_MSG, funcname,
				    0);
				return;
			}

		}
		buf[0] = '\0';
		(void) fgets(buf, BUFSZ, fp);
		if (strncmp(buf, "ASSOCIATION_END", 15) != 0) {
			init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
			return;
		}

		/* Create separate list of dependents for each antecedent */
		if (strcmp(assoc_name, "PSVC_TABLE") != 0) {
			create_reference_properties(assoc_tbl, count,
			    assoc_name);
		}

		free(assoc_tbl);
		buf[0] = '\0';
		(void) fgets(buf, BUFSZ, fp);
	}

}

/* Enviornmental Lock Object's Read and Write routine */
/* ARGSUSED */
static int
env_lock_read(ptree_rarg_t *rarg, void *buf)
{
	(void) strlcpy((char *)buf, env_lock_state, LOCK_STRING_MAX);
	return (PSVC_SUCCESS);
}

/* ARGSUSED */
static int
env_lock_write(ptree_warg_t *warg, const void *buf)
{
	int32_t status = PSVC_SUCCESS;
	char *var = (char *)buf;

	/*
	 * Check to make sure that the value is either Disabled or Enabled
	 * as these are the only 2 states that this object can be set to.
	 */
	if ((strcmp(var, PSVC_LOCK_DISABLED) != 0) &&
	    (strcmp(var, PSVC_LOCK_ENABLED) != 0)) {
		errno = EINVAL;
		return (PSVC_FAILURE);
	}

	(void) pthread_mutex_lock(&env_lock_mutex);

	/*
	 * If the state is already Enabled we can set the state to Disabled
	 * to stop the policies.
	 */
	if (strcmp(env_lock_state, PSVC_LOCK_ENABLED) == 0) {
		(void) pthread_mutex_unlock(&env_lock_mutex);
		status = timed_lock_wait(PSVC_LOCK_DISABLED);
		if (status == -1) {
			syslog(LOG_ERR, SEM_WAIT_FAILED_MSG);
		}
		return (status);
	}

	/*
	 * If the state is Running we must go into timed_lock_wait to aquire
	 * the env_lock.
	 */
	if (strcmp(env_lock_state, PSVC_LOCK_RUNNING) == 0) {
		(void) pthread_mutex_unlock(&env_lock_mutex);
		status = timed_lock_wait(PSVC_LOCK_DISABLED);
		if (status == -1) {
			syslog(LOG_ERR, SEM_WAIT_FAILED_MSG);
		}
		return (status);
	}

	/*
	 * If the state is already Disabled we need to first check to see if
	 * we are resetting it to Disabled or changing it to Enabled. If we
	 * are resetting it to Disabled then we need to stop the timer and
	 * restart it. If we are changing it to Enabled we just set it to
	 * enabled.
	 */
	if (strcmp(env_lock_state, PSVC_LOCK_DISABLED) == 0) {
		if (strcmp(var, PSVC_LOCK_DISABLED) == 0) {
			(void) pthread_mutex_lock(&timer_mutex);
			if (timer_state == ACTIVE) {
				timer_state = NOT_READY;
				/* stop timer */
				(void) pthread_cond_signal(&timer_cond);
				(void) pthread_mutex_unlock(&timer_mutex);
				/* wait for timer to reset */
				while (timer_state != READY)
					(void) sched_yield();
				(void) pthread_mutex_lock(&timer_mutex);
				timer_state = HAVE_REQUEST;
				/* restart timer */
				(void) pthread_cond_signal(&timer_cond);
			}
			(void) pthread_mutex_unlock(&timer_mutex);
		} else {
			(void) strlcpy(env_lock_state, var, LOCK_STRING_MAX);
		}
	}
	(void) pthread_mutex_unlock(&env_lock_mutex);
	return (PSVC_SUCCESS);
}

static int
init_env_lock_node(picl_nodehdl_t root_node)
{
	int err;
	ptree_propinfo_t propinfo;
	char *funcname = "init_env_lock_node";

	/* Here we are creating a Enviornmental Lock Node */
	err = ptree_create_node("/plugins/environmental", "picl", &lock_node);
	if (err != PICL_SUCCESS) {
		init_err(PTREE_CREATE_NODE_FAILED_MSG, funcname,
		    picl_strerror(err));
		return (err);
	}

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION_1,
	    PICL_PTYPE_CHARSTRING, PICL_READ | PICL_WRITE | PICL_VOLATILE,
	    32, "State", env_lock_read, env_lock_write);
	if (err != PICL_SUCCESS) {
		init_err(NODE_PROP_FAILED_MSG, funcname, picl_strerror(err));
		return (err);
	}

	err = ptree_create_and_add_prop(lock_node, &propinfo,
	    NULL, NULL);
	if (err != PICL_SUCCESS) {
		init_err(PTREE_ADD_PROP_FAILED_MSG, funcname,
		    picl_strerror(err));
		return (err);
	}

	err = ptree_add_node(root_node, lock_node);
	if (err != PICL_SUCCESS) {
		init_err(PTREE_ADD_NODE_FAILED_MSG, funcname,
		    picl_strerror(err));
		return (err);
	}

	return (PSVC_SUCCESS);
}

void
psvc_plugin_init(void)
{
	struct classinfo *cp;
	picl_nodehdl_t root_node;
	picl_nodehdl_t parent_node;
	char *funcname = "psvc_plugin_init";
	char platform[32];
	char filename[256];
	char buf[BUFSZ];
	int32_t i, j;
	int err, found;

	psvc_paths = NULL;
	psvc_hdl.obj_count = 0;
	psvc_hdl.objects = NULL;
	psvc_hdl.fp = NULL;
	first_interval = NULL;

	/*
	 * So the volatile read/write routines can retrieve data from
	 * psvc or picl
	 */
	err = psvc_init(&hdlp);
	if (err != 0) {
		init_err(PSVC_INIT_ERR_MSG, funcname, strerror(errno));
	}

	if (sysinfo(SI_PLATFORM, platform, sizeof (platform)) == -1) {
		init_err(SYSINFO_FAILED_MSG, funcname, 0);
		return;
	}

	(void) snprintf(filename, sizeof (filename),
	    "/usr/platform/%s/lib/psvcobj.conf", platform);
	if ((psvc_hdl.fp = fopen(filename, "r")) == NULL) {
		init_err(FILE_OPEN_FAILED_MSG, funcname, filename);
		return;
	}

	/* Create all PICL nodes */
	if (find_file_section(psvc_hdl.fp, "OBJECT_INFO") == -1) {
		init_err(INVALID_FILE_FORMAT1_MSG, funcname, filename);
		return;
	}
	if (count_records(psvc_hdl.fp, "OBJECT_INFO_END", &psvc_hdl.obj_count)
	    == -1) {
		init_err(INVALID_FILE_FORMAT1_MSG, funcname, filename);
		return;
	}
	if ((psvc_hdl.objects = (picl_psvc_t *)malloc(sizeof (picl_psvc_t) *
	    psvc_hdl.obj_count)) == NULL) {
		init_err(MALLOC_FAILED_MSG, funcname, strerror(errno));
		return;
	}
	(void) memset(psvc_hdl.objects, 0,
	    sizeof (picl_psvc_t) * psvc_hdl.obj_count);

	err = ptree_get_root(&root_node);
	if (err != 0) {
		init_err(PTREE_GET_ROOT_FAILED_MSG, funcname,
		    picl_strerror(err));
		return;
	}

	/* Following array is  accessed directly by the psvc policies. */
	psvc_paths = (psvc_name_t *)malloc(sizeof (psvc_name_t) *
	    psvc_hdl.obj_count);
	psvc_picl_nodes = psvc_hdl.obj_count;
	if (psvc_paths == NULL) {
		init_err(MALLOC_FAILED_MSG, funcname, strerror(errno));
		return;
	}
	for (i = 0; i < psvc_hdl.obj_count; ++i) {
		char *start;
		int32_t class;
		int32_t subclass;
		int32_t	cp_count;
		picl_psvc_t *objp = &psvc_hdl.objects[i];
		buf[0] = '\0';
		(void) fgets(buf, BUFSZ, psvc_hdl.fp);
		if (strncmp(buf, "OBJECT_INFO_END", 15) == 0)
			break;

		start = strrchr(buf, '/');
		if (start == NULL) {
			init_err(INVALID_FILE_FORMAT1_MSG, funcname,
			    filename);
			return;
		}
		found = sscanf(start + 1, "%31s",  objp->name);
		if (found != 1) {
			init_err(INVALID_FILE_FORMAT1_MSG, funcname,
			    filename);
			return;
		}

		/* get class */
		err = psvc_get_attr(hdlp, objp->name, PSVC_CLASS_ATTR, &class);
		if (err != PSVC_SUCCESS) {
			init_err(CLASS_NOT_FOUND_MSG, funcname, objp->name);
			return;
		}
		if (class > NUM_CLASSES) {
			init_err(UNKNOWN_CLASS_MSG, funcname, 0);
			return;
		}

		err = psvc_get_attr(hdlp, objp->name, PSVC_SUBCLASS_ATTR,
		    &subclass);
		if (err != PSVC_SUCCESS) {
			init_err(SUBCLASS_NOT_FOUND_MSG, funcname, objp->name);
			return;
		}

		err = ptree_create_node(objp->name, class_name[class],
		    &objp->node);
		if (err != 0) {
			init_err(PTREE_CREATE_NODE_FAILED_MSG, funcname,
			    picl_strerror(err));
			return;
		}
		if (strcmp(objp->name, PSVC_CHASSIS) == 0)
			system_node = objp->node;

		for (j = 0; j < COMMON_COUNT; ++j) {

			err = node_property(objp->node,
			    common[j].access & PICL_READ ?
			    psvc_read_volatile : 0,
			    common[j].access & PICL_WRITE ?
			    psvc_write_volatile : 0,
			    common[j].type, common[j].size,
			    common[j].access, common[j].name, 0);
			if (err != PSVC_SUCCESS) {
				init_err(NODE_PROP_FAILED_MSG, funcname,
				    picl_strerror(err));
				return;
			}
		}
		cp = &class_properties[class];
		/* Locator LED Support */
		if (class == 2 && subclass == 2) {
			cp_count = 3;
		} else {
			cp_count = cp->count;
		}

		for (j = 0; j < cp_count; ++j) {
			err = node_property(objp->node, psvc_read_volatile,
			    psvc_write_volatile, cp->props[j].type,
			    cp->props[j].size,
			    cp->props[j].access, cp->props[j].name, 0);
			if (err != PSVC_SUCCESS) {
				init_err(NODE_PROP_FAILED_MSG, funcname,
				    picl_strerror(err));
				return;
			}
		}

		/* Link the nodes into the PICL tree */
		*start = 0;
		if (start == buf) {	/* no parent */
			parent_node = root_node;
		} else {
			err = ptree_get_node_by_path(buf, &parent_node);
			if (err != PICL_SUCCESS) {
				init_err(NODE_NOT_FOUND_MSG, funcname, buf);
				return;
			}
		}

		err = ptree_add_node(parent_node, objp->node);
		if (err != PICL_SUCCESS) {
			init_err(PTREE_ADD_NODE_FAILED_MSG, funcname,
			    picl_strerror(err));
			return;
		}
		(void) strcpy(psvc_paths[i].parent_path, buf);
		(void) strcpy(psvc_paths[i].child_name, objp->name);
		psvc_paths[i].child_node = objp->node;
	}

	qsort(psvc_hdl.objects, psvc_hdl.obj_count, sizeof (picl_psvc_t),
	    (int (*)(const void *, const void *))name_compare_qsort);

	load_associations(psvc_hdl.fp);
	load_projected_properties(psvc_hdl.fp);

	if (init_env_lock_node(root_node) != PSVC_SUCCESS)
		return;

	init_daemon();
}

void
psvc_plugin_fini(void)
{
	int32_t i;
	EInterval_t *ip, *next;

	fini_daemon();
	for (ip = first_interval; ip != 0; ip = next) {
		for (i = 0; i < ip->num_tasks; ++i) {
			(void) dlclose(ip->task_list[i].hdl);
			free(ip->task_list[i].obj_list);
		}
		free(ip->task_list);
		next = ip->next;
		free(ip);
	}
	free(prop_list);
	free(psvc_paths);
	free(psvc_hdl.objects);
	if (psvc_hdl.fp != NULL)
		(void) fclose(psvc_hdl.fp);
	psvc_fini(hdlp);
}

void
psvc_plugin_register(void)
{
	picld_plugin_register(&psvc_reg);
}
