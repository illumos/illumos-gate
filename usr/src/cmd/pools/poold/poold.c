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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * poold - dynamically adjust pool configuration according to load.
 */
#include <errno.h>
#include <jni.h>
#include <libintl.h>
#include <limits.h>
#include <link.h>
#include <locale.h>
#include <poll.h>
#include <pool.h>
#include <priv.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include "utils.h"

#define	POOLD_DEF_CLASSPATH	"/usr/lib/pool/JPool.jar"
#define	POOLD_DEF_LIBPATH	"/usr/lib/pool"
#define	SMF_SVC_INSTANCE	"svc:/system/pools/dynamic:default"

#define	CLASS_FIELD_DESC(class_desc)	"L" class_desc ";"

#define	LEVEL_CLASS_DESC	"java/util/logging/Level"
#define	POOLD_CLASS_DESC	"com/sun/solaris/domain/pools/Poold"
#define	SEVERITY_CLASS_DESC	"com/sun/solaris/service/logging/Severity"
#define	STRING_CLASS_DESC	"java/lang/String"
#define	SYSTEM_CLASS_DESC	"java/lang/System"
#define	LOGGER_CLASS_DESC	"java/util/logging/Logger"

extern char *optarg;

static const char *pname;

static enum {
	LD_TERMINAL = 1,
	LD_SYSLOG,
	LD_JAVA
} log_dest = LD_SYSLOG;

static const char PNAME_FMT[] = "%s: ";
static const char ERRNO_FMT[] = ": %s";

static pthread_mutex_t jvm_lock = PTHREAD_MUTEX_INITIALIZER;
static JavaVM *jvm;		/* protected by jvm_lock */
static int instance_running;	/* protected by jvm_lock */
static int lflag;		/* specifies poold logging mode */

static jmethodID log_mid;
static jobject severity_err;
static jobject severity_notice;
static jobject base_log;
static jclass poold_class;
static jobject poold_instance;

static sigset_t hdl_set;

static void pu_notice(const char *fmt, ...);
static void pu_die(const char *fmt, ...) __NORETURN;

static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage:\t%s [-l <level>]\n"), pname);

	exit(E_USAGE);
}

static void
check_thread_attached(JNIEnv **env)
{
	int ret;

	ret = (*jvm)->GetEnv(jvm, (void **)env, JNI_VERSION_1_4);
	if (*env == NULL) {
		if (ret == JNI_EVERSION) {
			/*
			 * Avoid recursively calling
			 * check_thread_attached()
			 */
			if (log_dest == LD_JAVA)
				log_dest = LD_TERMINAL;
			pu_notice(gettext("incorrect JNI version"));
			exit(E_ERROR);
		}
		if ((*jvm)->AttachCurrentThreadAsDaemon(jvm, (void **)env,
		    NULL) != 0) {
			/*
			 * Avoid recursively calling
			 * check_thread_attached()
			 */
			if (log_dest == LD_JAVA)
				log_dest = LD_TERMINAL;
			pu_notice(gettext("thread attach failed"));
			exit(E_ERROR);
		}
	}
}

/*
 * Output a message to the designated logging destination.
 *
 * severity - Specified the severity level when using LD_JAVA logging
 * fmt - specified the format of the output message
 * alist - varargs used in the output message
 */
static void
pu_output(int severity, const char *fmt, va_list alist)
{
	int err = errno;
	char line[255] = "";
	jobject jseverity;
	jobject jline;
	JNIEnv *env = NULL;

	if (pname != NULL && log_dest == LD_TERMINAL)
		(void) snprintf(line, sizeof (line), gettext(PNAME_FMT), pname);

	(void) vsnprintf(line + strlen(line), sizeof (line) - strlen(line),
	    fmt, alist);

	if (line[strlen(line) - 1] != '\n')
		(void) snprintf(line + strlen(line), sizeof (line) -
		    strlen(line), gettext(ERRNO_FMT), strerror(err));
	else
		line[strlen(line) - 1] = 0;

	switch (log_dest) {
	case LD_TERMINAL:
		(void) fprintf(stderr, "%s\n", line);
		(void) fflush(stderr);
		break;
	case LD_SYSLOG:
		syslog(LOG_ERR, "%s", line);
		break;
	case LD_JAVA:
		if (severity == LOG_ERR)
			jseverity = severity_err;
		else
			jseverity = severity_notice;

		if (jvm) {
			check_thread_attached(&env);
			if ((jline = (*env)->NewStringUTF(env, line)) != NULL)
				(*env)->CallVoidMethod(env, base_log, log_mid,
				    jseverity, jline);
		}
	}
}

/*
 * Notify the user with the supplied message.
 */
/*PRINTFLIKE1*/
static void
pu_notice(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	pu_output(LOG_NOTICE, fmt, alist);
	va_end(alist);
}

/*
 * Stop the application executing inside the JVM. Always ensure that jvm_lock
 * is held before invoking this function.
 */
static void
halt_application(void)
{
	JNIEnv *env = NULL;
	jmethodID poold_shutdown_mid;

	if (jvm && instance_running) {
		check_thread_attached(&env);
		if ((poold_shutdown_mid = (*env)->GetMethodID(
		    env, poold_class, "shutdown", "()V")) != NULL) {
			(*env)->CallVoidMethod(env, poold_instance,
			    poold_shutdown_mid);
		} else {
			if (lflag && (*env)->ExceptionOccurred(env)) {
				(*env)->ExceptionDescribe(env);
				pu_notice("could not invoke proper shutdown\n");
			}
		}
		instance_running = 0;
	}
}

/*
 * Warn the user with the supplied error message, halt the application,
 * destroy the JVM and then exit the process.
 */
/*PRINTFLIKE1*/
static void
pu_die(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	pu_output(LOG_ERR, fmt, alist);
	va_end(alist);
	halt_application();
	if (jvm) {
		(*jvm)->DestroyJavaVM(jvm);
		jvm = NULL;
	}
	exit(E_ERROR);
}

/*
 * Warn the user with the supplied error message and halt the
 * application. This function is very similar to pu_die(). However,
 * this function is designed to be called from the signal handling
 * routine (handle_sig()) where although we wish to let the user know
 * that an error has occurred, we do not wish to destroy the JVM or
 * exit the process.
 */
/*PRINTFLIKE1*/
static void
pu_terminate(const char *fmt, ...)
{
	va_list alist;

	va_start(alist, fmt);
	pu_output(LOG_ERR, fmt, alist);
	va_end(alist);
	halt_application();
}

/*
 * If SIGHUP is invoked, we should just re-initialize poold. Since
 * there is no easy way to determine when it's safe to re-initialzie
 * poold, simply update a dummy property on the system element to
 * force pool_conf_update() to detect a change.
 *
 * Both SIGTERM and SIGINT are interpreted as instructions to
 * shutdown.
 */
/*ARGSUSED*/
static void *
handle_sig(void *arg)
{
	pool_conf_t *conf = NULL;
	pool_elem_t *pe;
	pool_value_t *val;
	const char *err_desc;
	int keep_handling = 1;

	while (keep_handling) {
		int sig;
		char buf[SIG2STR_MAX];

		if ((sig = sigwait(&hdl_set)) < 0) {
			/*
			 * We used forkall() previously to ensure that
			 * all threads started by the JVM are
			 * duplicated in the child. Since forkall()
			 * can cause blocking system calls to be
			 * interrupted, check to see if the errno is
			 * EINTR and if it is wait again.
			 */
			if (errno == EINTR)
				continue;
			(void) pthread_mutex_lock(&jvm_lock);
			pu_terminate("unexpected error: %d\n", errno);
			keep_handling = 0;
		} else
			(void) pthread_mutex_lock(&jvm_lock);
		(void) sig2str(sig, buf);
		switch (sig) {
		case SIGHUP:
			if ((conf = pool_conf_alloc()) == NULL) {
				err_desc = pool_strerror(pool_error());
				goto destroy;
			}
			if (pool_conf_open(conf, pool_dynamic_location(),
			    PO_RDWR) != 0) {
				err_desc = pool_strerror(pool_error());
				goto destroy;
			}

			if ((val = pool_value_alloc()) == NULL) {
				err_desc = pool_strerror(pool_error());
				goto destroy;
			}
			pe = pool_conf_to_elem(conf);
			pool_value_set_bool(val, 1);
			if (pool_put_property(conf, pe, "system.poold.sighup",
			    val) != PO_SUCCESS) {
				err_desc = pool_strerror(pool_error());
				pool_value_free(val);
				goto destroy;
			}
			pool_value_free(val);
			(void) pool_rm_property(conf, pe,
			    "system.poold.sighup");
			if (pool_conf_commit(conf, 0) != PO_SUCCESS) {
				err_desc = pool_strerror(pool_error());
				goto destroy;
			}
			(void) pool_conf_close(conf);
			pool_conf_free(conf);
			break;
destroy:
			if (conf) {
				(void) pool_conf_close(conf);
				pool_conf_free(conf);
			}
			pu_terminate(err_desc);
			keep_handling = 0;
			break;
		case SIGINT:
		case SIGTERM:
		default:
			pu_terminate("terminating due to signal: SIG%s\n", buf);
			keep_handling = 0;
			break;
		}
		(void) pthread_mutex_unlock(&jvm_lock);
	}
	pthread_exit(NULL);
	/*NOTREACHED*/
	return (NULL);
}

/*
 * Return the name of the process
 */
static const char *
pu_getpname(const char *arg0)
{
	char *p;

	/*
	 * Guard against '/' at end of command invocation.
	 */
	for (;;) {
		p = strrchr(arg0, '/');
		if (p == NULL) {
			pname = arg0;
			break;
		} else {
			if (*(p + 1) == '\0') {
				*p = '\0';
				continue;
			}

			pname = p + 1;
			break;
		}
	}

	return (pname);
}

int
main(int argc, char *argv[])
{
	char c;
	char log_severity[16] = "";
	JavaVMInitArgs vm_args;
	JavaVMOption vm_opts[5];
	int nopts = 0;
	const char *classpath;
	const char *libpath;
	size_t len;
	const char *err_desc;
	JNIEnv *env;
	jmethodID poold_getinstancewcl_mid;
	jmethodID poold_run_mid;
	jobject log_severity_string = NULL;
	jobject log_severity_obj = NULL;
	jclass severity_class;
	jmethodID severity_cons_mid;
	jfieldID base_log_fid;
	pthread_t hdl_thread;
	FILE *p;

	(void) pthread_mutex_lock(&jvm_lock);
	pname = pu_getpname(argv[0]);
	openlog(pname, 0, LOG_DAEMON);
	(void) chdir("/");

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined with cc -D. */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't. */
#endif
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;
	while ((c = getopt(argc, argv, "l:P")) != EOF) {
		switch (c) {
		case 'l':	/* -l option */
			lflag++;
			(void) strlcpy(log_severity, optarg,
			    sizeof (log_severity));
			log_dest = LD_TERMINAL;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	/*
	 * Check permission
	 */
	if (!priv_ineffect(PRIV_SYS_RES_CONFIG))
		pu_die(gettext(ERR_PRIVILEGE), PRIV_SYS_RES_CONFIG);

	/*
	 * In order to avoid problems with arbitrary thread selection
	 * when handling asynchronous signals, dedicate a thread to
	 * look after these signals.
	 */
	if (sigemptyset(&hdl_set) < 0 ||
	    sigaddset(&hdl_set, SIGHUP) < 0 ||
	    sigaddset(&hdl_set, SIGTERM) < 0 ||
	    sigaddset(&hdl_set, SIGINT) < 0 ||
	    pthread_sigmask(SIG_BLOCK, &hdl_set, NULL) ||
	    pthread_create(&hdl_thread, NULL, handle_sig, NULL))
		pu_die(gettext("can't install signal handler"));

	/*
	 * If the -l flag is supplied, terminate the SMF service and
	 * run interactively from the command line.
	 */
	if (lflag) {
		char *cmd = "/usr/sbin/svcadm disable -st " SMF_SVC_INSTANCE;

		if (getenv("SMF_FMRI") != NULL)
			pu_die("-l option illegal: %s\n", SMF_SVC_INSTANCE);
		/*
		 * Since disabling a service isn't synchronous, use the
		 * synchronous option from svcadm to achieve synchronous
		 * behaviour.
		 * This is not very satisfactory, but since this is only
		 * for use in debugging scenarios, it will do until there
		 * is a C API to synchronously shutdown a service in SMF.
		 */
		if ((p = popen(cmd, "w")) == NULL || pclose(p) != 0)
			pu_die("could not temporarily disable service: %s\n",
			    SMF_SVC_INSTANCE);
	} else {
		/*
		 * Check if we are running as a SMF service. If we
		 * aren't, terminate this process after enabling the
		 * service.
		 */
		if (getenv("SMF_FMRI") == NULL) {
			char *cmd = "/usr/sbin/svcadm enable -s " \
			    SMF_SVC_INSTANCE;
			if ((p = popen(cmd, "w")) == NULL || pclose(p) != 0)
				pu_die("could not enable "
				    "service: %s\n", SMF_SVC_INSTANCE);
			return (E_PO_SUCCESS);
		}
	}

	/*
	 * Establish the classpath and LD_LIBRARY_PATH for native
	 * methods, and get the interpreter going.
	 */
	if ((classpath = getenv("POOLD_CLASSPATH")) == NULL) {
		classpath = POOLD_DEF_CLASSPATH;
	} else {
		const char *cur = classpath;

		/*
		 * Check the components to make sure they're absolute
		 * paths.
		 */
		while (cur != NULL && *cur) {
			if (*cur != '/')
				pu_die(gettext(
				    "POOLD_CLASSPATH must contain absolute "
				    "components\n"));
			cur = strchr(cur + 1, ':');
		}
	}
	vm_opts[nopts].optionString = malloc(len = strlen(classpath) +
	    strlen("-Djava.class.path=") + 1);
	(void) strlcpy(vm_opts[nopts].optionString, "-Djava.class.path=", len);
	(void) strlcat(vm_opts[nopts++].optionString, classpath, len);

	if ((libpath = getenv("POOLD_LD_LIBRARY_PATH")) == NULL)
		libpath = POOLD_DEF_LIBPATH;
	vm_opts[nopts].optionString = malloc(len = strlen(libpath) +
	    strlen("-Djava.library.path=") + 1);
	(void) strlcpy(vm_opts[nopts].optionString, "-Djava.library.path=",
	    len);
	(void) strlcat(vm_opts[nopts++].optionString, libpath, len);

	vm_opts[nopts++].optionString = "-Xrs";
	vm_opts[nopts++].optionString = "-enableassertions";

	vm_args.options = vm_opts;
	vm_args.nOptions = nopts;
	vm_args.ignoreUnrecognized = JNI_FALSE;
	vm_args.version = 0x00010002;

	if (JNI_CreateJavaVM(&jvm, (void **)&env, &vm_args) < 0)
		pu_die(gettext("can't create Java VM"));

	/*
	 * Locate the Poold class and construct an instance.  A side
	 * effect of this is that the poold instance's logHelper will be
	 * initialized, establishing loggers for logging errors from
	 * this point on.  (Note, in the event of an unanticipated
	 * exception, poold will invoke die() itself.)
	 */
	err_desc = gettext("JVM-related error initializing poold\n");
	if ((poold_class = (*env)->FindClass(env, POOLD_CLASS_DESC)) == NULL)
		goto destroy;
	if ((poold_getinstancewcl_mid = (*env)->GetStaticMethodID(env,
	    poold_class, "getInstanceWithConsoleLogging", "("
	    CLASS_FIELD_DESC(SEVERITY_CLASS_DESC) ")"
	    CLASS_FIELD_DESC(POOLD_CLASS_DESC))) == NULL)
		goto destroy;
	if ((poold_run_mid = (*env)->GetMethodID(env, poold_class, "run",
	    "()V")) == NULL)
		goto destroy;
	if ((severity_class = (*env)->FindClass(env, SEVERITY_CLASS_DESC))
	    == NULL)
		goto destroy;
	if ((severity_cons_mid = (*env)->GetStaticMethodID(env, severity_class,
	    "getSeverityWithName", "(" CLASS_FIELD_DESC(STRING_CLASS_DESC) ")"
	    CLASS_FIELD_DESC(SEVERITY_CLASS_DESC))) == NULL)
		goto destroy;

	/*
	 * -l <level> was specified, indicating that messages are to be
	 * logged to the console only.
	 */
	if (strlen(log_severity) > 0) {
		if ((log_severity_string = (*env)->NewStringUTF(env,
		    log_severity)) == NULL)
			goto destroy;
		if ((log_severity_obj = (*env)->CallStaticObjectMethod(env,
		    severity_class, severity_cons_mid, log_severity_string)) ==
		    NULL) {
			err_desc = gettext("invalid level specified\n");
			goto destroy;
		}
	} else
		log_severity_obj = NULL;

	if ((poold_instance = (*env)->CallStaticObjectMethod(env, poold_class,
	    poold_getinstancewcl_mid, log_severity_obj)) == NULL)
		goto destroy;

	/*
	 * Grab a global reference to poold for use in our signal
	 * handlers.
	 */
	poold_instance = (*env)->NewGlobalRef(env, poold_instance);

	/*
	 * Ready LD_JAVA logging.
	 */
	err_desc = gettext("cannot initialize logging\n");
	if ((log_severity_string = (*env)->NewStringUTF(env, "err")) == NULL)
		goto destroy;
	if (!(severity_err = (*env)->CallStaticObjectMethod(env, severity_class,
	    severity_cons_mid, log_severity_string)))
		goto destroy;
	if (!(severity_err = (*env)->NewGlobalRef(env, severity_err)))
		goto destroy;

	if ((log_severity_string = (*env)->NewStringUTF(env, "notice")) == NULL)
		goto destroy;
	if (!(severity_notice = (*env)->CallStaticObjectMethod(env,
	    severity_class, severity_cons_mid, log_severity_string)))
		goto destroy;
	if (!(severity_notice = (*env)->NewGlobalRef(env, severity_notice)))
		goto destroy;

	if (!(base_log_fid = (*env)->GetStaticFieldID(env, poold_class,
	    "BASE_LOG", CLASS_FIELD_DESC(LOGGER_CLASS_DESC))))
		goto destroy;
	if (!(base_log = (*env)->GetStaticObjectField(env, poold_class,
	    base_log_fid)))
		goto destroy;
	if (!(base_log = (*env)->NewGlobalRef(env, base_log)))
		goto destroy;
	if (!(log_mid = (*env)->GetMethodID(env, (*env)->GetObjectClass(env,
	    base_log), "log", "(" CLASS_FIELD_DESC(LEVEL_CLASS_DESC)
	    CLASS_FIELD_DESC(STRING_CLASS_DESC) ")V")))
		goto destroy;
	log_dest = LD_JAVA;

	/*
	 * If invoked directly and -l is specified, forking is not
	 * desired.
	 */
	if (!lflag)
		switch (forkall()) {
		case 0:
			(void) setsid();
			(void) fclose(stdin);
			(void) fclose(stdout);
			(void) fclose(stderr);
			break;
		case -1:
			pu_die(gettext("cannot fork"));
			/*NOTREACHED*/
		default:
			return (E_PO_SUCCESS);
		}

	instance_running = 1;
	(void) pthread_mutex_unlock(&jvm_lock);

	(*env)->CallVoidMethod(env, poold_instance, poold_run_mid);

	(void) pthread_mutex_lock(&jvm_lock);
	if ((*env)->ExceptionOccurred(env)) {
		goto destroy;
	}
	if (jvm) {
		(*jvm)->DestroyJavaVM(jvm);
		jvm = NULL;
	}
	(void) pthread_mutex_unlock(&jvm_lock);
	return (E_PO_SUCCESS);

destroy:
	if (lflag && (*env)->ExceptionOccurred(env))
		(*env)->ExceptionDescribe(env);
	pu_die(err_desc);
}
