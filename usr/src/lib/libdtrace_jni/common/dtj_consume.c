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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/wait.h>
#include <limits.h>
#include <signal.h>
#include <libproc.h>
#include <pthread.h>
#include <dtrace_jni.h>

/*
 * Implements the work done in the running consumer loop.  The native Java
 * methods (JNI layer) are implemented in dtrace_jni.c.
 */

/* Record handler passed to dtrace_work() */
static int dtj_chewrec(const dtrace_probedata_t *, const dtrace_recdesc_t *,
    void *);
/* Probe data handler passed to dtrace_work() */
static int dtj_chew(const dtrace_probedata_t *, void *);

/* Processes requests from LocalConsumer enqueued during dtrace_sleep() */
static dtj_status_t dtj_process_requests(dtj_java_consumer_t *);

/*
 * Callback handlers set in dtj_set_callback_handlers(), called from libdtrace
 * in the consumer loop (from dtrace_work())
 */
static int dtj_drophandler(const dtrace_dropdata_t *, void *);
static int dtj_errhandler(const dtrace_errdata_t *, void *);
static void dtj_prochandler(struct ps_prochandle *, const char *, void *);
static int dtj_setopthandler(const dtrace_setoptdata_t *, void *);
/*
 * Buffered output handler called from libdtrace in both the consumer loop (from
 * dtrace_work()) and the get_aggregate() function (from
 * dtrace_aggregate_print()).
 */
static int dtj_bufhandler(const dtrace_bufdata_t *, void *);

/* Conversion of libdtrace data into Java Objects */
static jobject dtj_recdata(dtj_java_consumer_t *, uint32_t, caddr_t);
static jobject dtj_bytedata(JNIEnv *, uint32_t, caddr_t);
static jobject dtj_new_stack_record(const caddr_t, const dtrace_recdesc_t *,
    dtj_java_consumer_t *);
static jobject dtj_new_probedata_stack_record(const dtrace_probedata_t *,
    const dtrace_recdesc_t *, dtj_java_consumer_t *);
static jobject dtj_new_symbol_record(const caddr_t, const dtrace_recdesc_t *,
    dtj_java_consumer_t *);
static jobject dtj_new_probedata_symbol_record(const dtrace_probedata_t *,
    const dtrace_recdesc_t *, dtj_java_consumer_t *);
/* Aggregation data */
static jobject dtj_new_tuple_stack_record(const dtrace_aggdata_t *,
    const dtrace_recdesc_t *, const char *, dtj_java_consumer_t *);
static jobject dtj_new_tuple_symbol_record(const dtrace_aggdata_t *,
    const dtrace_recdesc_t *, const char *, dtj_java_consumer_t *);
static jobject dtj_new_distribution(const dtrace_aggdata_t *,
    const dtrace_recdesc_t *, dtj_java_consumer_t *);
static jobject dtj_new_aggval(dtj_java_consumer_t *, const dtrace_aggdata_t *,
    const dtrace_recdesc_t *);
static int64_t dtj_average(caddr_t, uint64_t);
static int64_t dtj_avg_total(caddr_t, uint64_t);
static int64_t dtj_avg_count(caddr_t);
static jobject dtj_stddev(JNIEnv *, caddr_t, uint64_t);

/* Aggregation functions */
static void dtj_aggwalk_init(dtj_java_consumer_t *);
static int dtj_agghandler(const dtrace_bufdata_t *, dtj_java_consumer_t *);
static boolean_t dtj_is_included(const dtrace_aggdata_t *,
    dtj_java_consumer_t *);
static void dtj_attach_frames(dtj_java_consumer_t *, jobject, jobjectArray);
static void dtj_attach_name(dtj_java_consumer_t *, jobject, jstring);
static boolean_t dtj_is_stack_action(dtrace_actkind_t);
static boolean_t dtj_is_symbol_action(dtrace_actkind_t);
static int dtj_clear(const dtrace_aggdata_t *, void *);

/*
 * The consumer loop needs to protect calls to libdtrace functions with a global
 * lock.  JNI native method calls in dtrace_jni.c are already protected and do
 * not need this function.
 */
dtj_status_t
dtj_get_dtrace_error(dtj_java_consumer_t *jc, dtj_error_t *e)
{
	JNIEnv *jenv = jc->dtjj_jenv;
	dtrace_hdl_t *dtp = jc->dtjj_consumer->dtjc_dtp;

	/* Must not call MonitorEnter with a pending exception */
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (DTJ_ERR);
	}
	/* Grab global lock */
	(*jenv)->MonitorEnter(jenv, g_caller_jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (DTJ_ERR);
	}
	e->dtje_number = dtrace_errno(dtp);
	e->dtje_message = dtrace_errmsg(dtp, e->dtje_number);
	(*jenv)->MonitorExit(jenv, g_caller_jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (DTJ_ERR);
	}
	return (DTJ_OK);
}

/*
 * Protected by global lock (LocalConsumer.class) that protects call to
 * Java_org_opensolaris_os_dtrace_LocalConsumer__1go()
 */
dtj_status_t
dtj_set_callback_handlers(dtj_java_consumer_t *jc)
{
	dtrace_hdl_t *dtp = jc->dtjj_consumer->dtjc_dtp;
	dtrace_optval_t optval;

	if (dtrace_handle_buffered(dtp, &dtj_bufhandler, NULL) == -1) {
		dtj_throw_dtrace_exception(jc,
		    "failed to establish buffered handler: %s",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (DTJ_ERR);
	}

	if (dtrace_handle_drop(dtp, &dtj_drophandler, NULL) == -1) {
		dtj_throw_dtrace_exception(jc,
		    "failed to establish drop handler: %s",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (DTJ_ERR);
	}

	if (dtrace_handle_err(dtp, &dtj_errhandler, NULL) == -1) {
		dtj_throw_dtrace_exception(jc,
		    "failed to establish error handler: %s",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (DTJ_ERR);
	}

	if (dtrace_handle_proc(dtp, &dtj_prochandler, NULL) == -1) {
		dtj_throw_dtrace_exception(jc,
		    "failed to establish proc handler: %s",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (DTJ_ERR);
	}

	if (dtrace_getopt(dtp, "flowindent", &optval) == -1) {
		dtj_throw_dtrace_exception(jc,
		    "couldn't get option %s: %s", "flowindent",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (DTJ_ERR);
	}

	jc->dtjj_consumer->dtjc_flow = (optval != DTRACEOPT_UNSET);

	if (dtrace_handle_setopt(dtp, &dtj_setopthandler, NULL) == -1) {
		dtj_throw_dtrace_exception(jc,
		    "failed to establish setopt handler: %s",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		return (DTJ_ERR);
	}

	return (DTJ_OK);
}

static int
/* ARGSUSED */
dtj_drophandler(const dtrace_dropdata_t *data, void *arg)
{
	dtj_java_consumer_t *jc;
	JNIEnv *jenv;

	const char *dropkind;

	jstring msg = NULL;
	jstring kind = NULL;
	jobject drop = NULL;

	jc = pthread_getspecific(g_dtj_consumer_key);
	jenv = jc->dtjj_jenv;

	msg = dtj_NewStringNative(jenv, data->dtdda_msg);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (DTRACE_HANDLE_ABORT);
	}
	switch (data->dtdda_kind) {
	case DTRACEDROP_PRINCIPAL:
		dropkind = "PRINCIPAL";
		break;
	case DTRACEDROP_AGGREGATION:
		dropkind = "AGGREGATION";
		break;
	case DTRACEDROP_DYNAMIC:
		dropkind = "DYNAMIC";
		break;
	case DTRACEDROP_DYNRINSE:
		dropkind = "DYNRINSE";
		break;
	case DTRACEDROP_DYNDIRTY:
		dropkind = "DYNDIRTY";
		break;
	case DTRACEDROP_SPEC:
		dropkind = "SPEC";
		break;
	case DTRACEDROP_SPECBUSY:
		dropkind = "SPECBUSY";
		break;
	case DTRACEDROP_SPECUNAVAIL:
		dropkind = "SPECUNAVAIL";
		break;
	case DTRACEDROP_STKSTROVERFLOW:
		dropkind = "STKSTROVERFLOW";
		break;
	case DTRACEDROP_DBLERROR:
		dropkind = "DBLERROR";
		break;
	default:
		dropkind = "UNKNOWN";
	}
	kind = (*jenv)->NewStringUTF(jenv, dropkind);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, msg);
		return (DTRACE_HANDLE_ABORT);
	}
	drop = (*jenv)->NewObject(jenv, g_drop_jc, g_dropinit_jm,
	    data->dtdda_cpu, kind, data->dtdda_drops, data->dtdda_total, msg);
	(*jenv)->DeleteLocalRef(jenv, kind);
	(*jenv)->DeleteLocalRef(jenv, msg);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (DTRACE_HANDLE_ABORT);
	}
	(*jenv)->CallVoidMethod(jenv, jc->dtjj_caller, g_drop_jm, drop);
	(*jenv)->DeleteLocalRef(jenv, drop);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (DTRACE_HANDLE_ABORT);
	}

	return (DTRACE_HANDLE_OK);
}

static int
/* ARGSUSED */
dtj_errhandler(const dtrace_errdata_t *data, void *arg)
{
	dtj_java_consumer_t *jc;
	JNIEnv *jenv;

	const char *f;
	int64_t addr;

	jobject probe = NULL;
	jstring fault = NULL;
	jstring msg = NULL;
	jobject error = NULL;

	jc = pthread_getspecific(g_dtj_consumer_key);
	jenv = jc->dtjj_jenv;

	probe = dtj_new_probedesc(jc, data->dteda_pdesc);
	if (!probe) {
		return (DTRACE_HANDLE_ABORT);
	}
	f = dtj_get_fault_name(data->dteda_fault);
	if (f) {
		fault = (*jenv)->NewStringUTF(jenv, f);
		if ((*jenv)->ExceptionCheck(jenv)) {
			(*jenv)->DeleteLocalRef(jenv, probe);
			return (DTRACE_HANDLE_ABORT);
		}
	}
	switch (data->dteda_fault) {
	case DTRACEFLT_BADADDR:
	case DTRACEFLT_BADALIGN:
	case DTRACEFLT_BADSTACK:
		addr = data->dteda_addr;
		break;
	default:
		addr = -1;
	}
	msg = dtj_NewStringNative(jenv, data->dteda_msg);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, probe);
		(*jenv)->DeleteLocalRef(jenv, fault);
		return (DTRACE_HANDLE_ABORT);
	}
	error = (*jenv)->NewObject(jenv, g_error_jc, g_errinit_jm,
	    probe,
	    data->dteda_edesc->dtepd_epid,
	    data->dteda_cpu,
	    data->dteda_action,
	    data->dteda_offset,
	    fault, addr, msg);
	(*jenv)->DeleteLocalRef(jenv, msg);
	(*jenv)->DeleteLocalRef(jenv, fault);
	(*jenv)->DeleteLocalRef(jenv, probe);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (DTRACE_HANDLE_ABORT);
	}
	(*jenv)->CallVoidMethod(jenv, jc->dtjj_caller, g_error_jm, error);
	(*jenv)->DeleteLocalRef(jenv, error);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (DTRACE_HANDLE_ABORT);
	}

	return (DTRACE_HANDLE_OK);
}

/*
 * Since the function signature does not allow us to return an abort signal, we
 * need to temporarily clear any pending exception before returning, since
 * without the abort we can't guarantee that the exception will be checked in
 * time to prevent invalid JNI function calls.
 */
static void
/* ARGSUSED */
dtj_prochandler(struct ps_prochandle *P, const char *msg, void *arg)
{
	dtj_java_consumer_t *jc;
	JNIEnv *jenv;

	const psinfo_t *prp = Ppsinfo(P);
	int pid = Pstatus(P)->pr_pid;
	int signal = -1;
	char signame[SIG2STR_MAX];
	const char *statusname;
	int exit = INT_MAX; /* invalid initial status */

	jstring status = NULL;
	jstring signalName = NULL;
	jstring message = NULL;
	jobject process = NULL;

	jc = pthread_getspecific(g_dtj_consumer_key);
	jenv = jc->dtjj_jenv;

	switch (Pstate(P)) {
	case PS_RUN:
		statusname = "RUN";
		break;
	case PS_STOP:
		statusname = "STOP";
		break;
	case PS_UNDEAD:
		statusname = "UNDEAD";
		if (prp != NULL) {
			exit = WEXITSTATUS(prp->pr_wstat);
		}
		if (prp != NULL && WIFSIGNALED(prp->pr_wstat)) {
			signal = WTERMSIG(prp->pr_wstat);
			(void) proc_signame(signal, signame, sizeof (signame));
			signalName = (*jenv)->NewStringUTF(jenv, signame);
			if ((*jenv)->ExceptionCheck(jenv)) {
				goto proc_end;
			}
		}
		++jc->dtjj_consumer->dtjc_procs_ended;
		break;
	case PS_LOST:
		statusname = "LOST";
		++jc->dtjj_consumer->dtjc_procs_ended;
		break;
	case PS_DEAD:
		/*
		 * PS_DEAD not handled by dtrace.c prochandler, still this is a
		 * case of process termination and it can't hurt to handle it.
		 */
		statusname = "DEAD";
		++jc->dtjj_consumer->dtjc_procs_ended;
		break;
	default:
		/*
		 * Unexpected, but erring on the side of tolerance by not
		 * crashing the consumer.  Failure to notify listeners of
		 * process state not handled by the dtrace.c prochandler does
		 * not seem serious.
		 */
		return;
	}

	status = (*jenv)->NewStringUTF(jenv, statusname);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, signalName);
		goto proc_end;
	}
	if (msg) {
		message = dtj_NewStringNative(jenv, msg);
		if (!message) {
			(*jenv)->DeleteLocalRef(jenv, status);
			(*jenv)->DeleteLocalRef(jenv, signalName);
			goto proc_end;
		}
	}
	process = (*jenv)->NewObject(jenv, g_process_jc, g_procinit_jm,
	    pid, status, signal, signalName, NULL, message);
	(*jenv)->DeleteLocalRef(jenv, status);
	(*jenv)->DeleteLocalRef(jenv, signalName);
	(*jenv)->DeleteLocalRef(jenv, message);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto proc_end;
	}
	if (exit != INT_MAX) {
		/* valid exit status */
		(*jenv)->CallVoidMethod(jenv, process, g_procexit_jm, exit);
		if ((*jenv)->ExceptionCheck(jenv)) {
			(*jenv)->DeleteLocalRef(jenv, process);
			goto proc_end;
		}
	}
	(*jenv)->CallVoidMethod(jenv, jc->dtjj_caller, g_proc_jm, process);
	(*jenv)->DeleteLocalRef(jenv, process);

proc_end:

	if ((*jenv)->ExceptionCheck(jenv)) {
		/*
		 * Save the exception so we can rethrow it later when it's safe.
		 */
		if (!jc->dtjj_exception) {
			jthrowable e = (*jenv)->ExceptionOccurred(jenv);
			jc->dtjj_exception = e;
		}
		(*jenv)->ExceptionClear(jenv);
	}
}

static int
/* ARGSUSED */
dtj_setopthandler(const dtrace_setoptdata_t *data, void *arg)
{
	dtj_java_consumer_t *jc;

	jc = pthread_getspecific(g_dtj_consumer_key);
	if (strcmp(data->dtsda_option, "flowindent") == 0) {
		jc->dtjj_consumer->dtjc_flow =
		    (data->dtsda_newval != DTRACEOPT_UNSET);
	}
	return (DTRACE_HANDLE_OK);
}

/*
 * Most of this function lifted from libdtrace/common/dt_consume.c
 * dt_print_bytes().
 */
static jobject
dtj_bytedata(JNIEnv *jenv, uint32_t nbytes, caddr_t addr)
{
	/*
	 * If the byte stream is a series of printable characters, followed by
	 * a terminating byte, we print it out as a string.  Otherwise, we
	 * assume that it's something else and just print the bytes.
	 */
	int i, j;
	char *c = addr;

	jobject jobj = NULL; /* return value */

	if (nbytes == 0) {
		return ((*jenv)->NewStringUTF(jenv, ""));
	}

	for (i = 0; i < nbytes; i++) {
		/*
		 * We define a "printable character" to be one for which
		 * isprint(3C) returns non-zero, isspace(3C) returns non-zero,
		 * or a character which is either backspace or the bell.
		 * Backspace and the bell are regrettably special because
		 * they fail the first two tests -- and yet they are entirely
		 * printable.  These are the only two control characters that
		 * have meaning for the terminal and for which isprint(3C) and
		 * isspace(3C) return 0.
		 */
		if (isprint(c[i]) || isspace(c[i]) ||
		    c[i] == '\b' || c[i] == '\a')
			continue;

		if (c[i] == '\0' && i > 0) {
			/*
			 * This looks like it might be a string.  Before we
			 * assume that it is indeed a string, check the
			 * remainder of the byte range; if it contains
			 * additional non-nul characters, we'll assume that
			 * it's a binary stream that just happens to look like
			 * a string.
			 */
			for (j = i + 1; j < nbytes; j++) {
				if (c[j] != '\0')
					break;
			}

			if (j != nbytes)
				break;

			/* It's a string */
			return (dtj_NewStringNative(jenv, (char *)addr));
		}

		break;
	}

	if (i == nbytes) {
		/*
		 * The byte range is all printable characters, but there is
		 * no trailing nul byte.  We'll assume that it's a string.
		 */
		char *s = malloc(nbytes + 1);
		if (!s) {
			dtj_throw_out_of_memory(jenv,
			    "failed to allocate string value");
			return (NULL);
		}
		(void) strncpy(s, c, nbytes);
		s[nbytes] = '\0';
		jobj = dtj_NewStringNative(jenv, s);
		free(s);
		return (jobj);
	}

	/* return byte array */
	jobj = (*jenv)->NewByteArray(jenv, nbytes);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (NULL);
	}
	(*jenv)->SetByteArrayRegion(jenv, (jbyteArray)jobj, 0, nbytes,
	    (const jbyte *)c);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		(*jenv)->DeleteLocalRef(jenv, jobj);
		return (NULL);
	}
	return (jobj);
}

/*
 * Return NULL if memory could not be allocated (OutOfMemoryError is thrown in
 * that case).
 */
static jobject
dtj_recdata(dtj_java_consumer_t *jc, uint32_t size, caddr_t addr)
{
	JNIEnv *jenv = jc->dtjj_jenv;
	jobject jobj;
	jobject jrec;

	switch (size) {
	case 1:
		jobj = (*jenv)->NewObject(jenv, g_int_jc,
		    g_intinit_jm, (int)(*((uint8_t *)addr)));
		break;
	case 2:
		jobj = (*jenv)->NewObject(jenv, g_int_jc,
		    /* LINTED - alignment */
		    g_intinit_jm, (int)(*((uint16_t *)addr)));
		break;
	case 4:
		jobj = (*jenv)->NewObject(jenv, g_int_jc,
		    /* LINTED - alignment */
		    g_intinit_jm, *((int32_t *)addr));
		break;
	case 8:
		jobj = (*jenv)->NewObject(jenv, g_long_jc,
		    /* LINTED - alignment */
		    g_longinit_jm, *((int64_t *)addr));
		break;
	default:
		jobj = dtj_bytedata(jenv, size, addr);
		break;
	}

	if (!jobj) {
		return (NULL); /* OutOfMemoryError pending */
	}

	jrec = (*jenv)->NewObject(jenv, g_scalar_jc,
	    g_scalarinit_jm, jobj, size);
	(*jenv)->DeleteLocalRef(jenv, jobj);

	return (jrec);
}

/*
 * This is the record handling function passed to dtrace_work().  It differs
 * from the bufhandler registered with dtrace_handle_buffered() as follows:
 *
 * 1.  It does not have access to libdtrace formatted output.
 * 2.  It is called once for every D program statement, not for every
 *     output-producing D action or aggregation record.  A statement may be a
 *     variable assignment, having no size and producing no output.
 * 3.  It is called for the D exit() action; the bufhandler is not.
 * 4.  In response to the printa() action, it is called with a record having an
 *     action of type DTRACEACT_PRINTA.  The bufhandler never sees that action
 *     value.  It only sees the output-producing aggregation records.
 * 5.  It is called with a NULL record at the end of each probedata.
 */
static int
dtj_chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec,
    void *arg)
{
	dtj_java_consumer_t *jc = arg;
	JNIEnv *jenv = jc->dtjj_jenv;

	const dtrace_eprobedesc_t *edesc = data->dtpda_edesc;
	dtrace_actkind_t act;
	int r;

	/*
	 * Update the record index to that of the current record, or to that of
	 * the last record if rec is NULL (signalling end of probe data).
	 */
	if (rec == NULL) {
		r = edesc->dtepd_nrecs; /* end of probe data */
	} else {
		/*
		 * This record handler is called once for the printf() action,
		 * but there may be multiple records in the probedata
		 * corresponding to the unformatted elements of that printf().
		 * We don't know ahead of time how many probedata records
		 * libdtrace will consume to produce output for one printf()
		 * action, so we look back at the previous call to dtj_chewrec()
		 * to see how many probedata records were consumed.  All
		 * non-null elements in the range from the previous record index
		 * up to and not including the current record index are assumed
		 * to be unformatted printf() elements, and will be attached to
		 * the PrintfRecord from the previous call.  A null element in
		 * that range is the result of a D program statement preceding
		 * the printf() that is not a D action.  These generate
		 * probedata records accounted for by the null placeholder, but
		 * do not advance the probedata offset and are not part of the
		 * subsequent printf().
		 *
		 * If rec->dtrd_size == 0, the record represents a D program
		 * statement that is not a D action.  It has no size and does
		 * not advance the offset in the probedata.  Handle it normally
		 * without special-casing or premature return, since in all
		 * cases we look at the previous record later in this function.
		 */
		for (r = jc->dtjj_consumer->dtjc_probedata_rec_i;
		    ((r < edesc->dtepd_nrecs) &&
		    (edesc->dtepd_rec[r].dtrd_offset < rec->dtrd_offset));
		    ++r) {
		}
	}

	/*
	 * Attach the Java representations of the libdtrace data elements
	 * pertaining to the previous call to this record handler to the
	 * previous Java Record.  (All data elements belonging to the current
	 * probedata are added to a single list by the probedata consumer
	 * function dtj_chew() before this record consumer function is ever
	 * called.) For example, if the previous Record was generated by the
	 * printf() action, and dtj_chew() listed 3 records for its 3
	 * unformatted elements, those 3 libdtrace records comprise 1
	 * PrintfRecord.  Note that we cannot know how many data elements apply
	 * to the current rec until we find out the data index where the next
	 * rec starts.  (The knowledge of how many probedata records to consume
	 * is private to libdtrace.)
	 */
	if (jc->dtjj_consumer->dtjc_probedata_act == DTRACEACT_PRINTF) {
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataattach_jm,
		    jc->dtjj_consumer->dtjc_probedata_rec_i, r - 1);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_CONSUME_ABORT);
		}
	}

	if (rec == NULL) {
		/*
		 * End of probe data.  Notify listeners of the new ProbeData
		 * instance.
		 */
		if (jc->dtjj_probedata) {
			/* previous probedata */
			(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
			    g_pdataclear_jm);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				return (DTRACE_CONSUME_ABORT);
			}
			(*jenv)->CallVoidMethod(jenv, jc->dtjj_caller,
			    g_pdatanext_jm, jc->dtjj_probedata);
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_probedata);
			jc->dtjj_probedata = NULL;
			if ((*jenv)->ExceptionCheck(jenv)) {
				/*
				 * Do not wrap exception thrown from
				 * ConsumerListener.
				 */
				return (DTRACE_CONSUME_ABORT);
			}
		}
		(*jenv)->DeleteLocalRef(jenv, jc->dtjj_printa_buffer);
		jc->dtjj_printa_buffer = NULL;
		return (DTRACE_CONSUME_NEXT);
	}

	act = rec->dtrd_action;

	/* Set previous record action and data index to current */
	jc->dtjj_consumer->dtjc_probedata_act = act;
	jc->dtjj_consumer->dtjc_probedata_rec_i = r;

	switch (act) {
	case DTRACEACT_DIFEXPR:
		if (rec->dtrd_size == 0) {
			/*
			 * The current record is not a D action, but a program
			 * statement such as a variable assignment, not to be
			 * confused with the trace() action.
			 */
			break;
		}
		/*
		 * Add a Record for the trace() action that references the
		 * native probedata element listed at the current index.
		 */
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataadd_trace_jm,
		    jc->dtjj_consumer->dtjc_probedata_rec_i);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_CONSUME_ABORT);
		}
		break;
	case DTRACEACT_PRINTF:
		/*
		 * Just add an empty PrintfRecord for now.  We'll attach the
		 * unformatted elements in a subsequent call to this function.
		 * (We don't know how many there will be.)
		 */
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataadd_printf_jm);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_CONSUME_ABORT);
		}
		/* defer formatted string to dtj_bufhandler() */
		break;
	case DTRACEACT_PRINTA: {
		jobject jbuf = NULL;

		dtj_aggwalk_init(jc);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_CONSUME_ABORT);
		}
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataadd_printa_jm,
		    jc->dtjj_consumer->dtjc_printa_snaptime,
		    (rec->dtrd_format != 0));
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_CONSUME_ABORT);
		}
		if (jc->dtjj_printa_buffer == NULL) {
			/*
			 * Create a StringBuilder to collect the pieces of
			 * formatted output into a single String.
			 */
			jbuf = (*jenv)->NewObject(jenv, g_buf_jc,
			    g_bufinit_jm);
			if (!jbuf) {
				/* OutOfMemoryError pending */
				return (DTRACE_CONSUME_ABORT);
			}
			jc->dtjj_printa_buffer = jbuf;
		}
		/* defer aggregation records to dtj_bufhandler() */
		break;
	}
	case DTRACEACT_EXIT:
		/*
		 * Add a Record for the exit() action that references the native
		 * probedata element listed at the current index.
		 */
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataadd_exit_jm,
		    jc->dtjj_consumer->dtjc_probedata_rec_i);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_CONSUME_ABORT);
		}
		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS);
}

/*
 * This is the probe handling function passed to dtrace_work().  It is is called
 * once every time a probe fires.  It is the first of all the callbacks for the
 * current probe.  It is followed by multiple callbacks to dtj_chewrec(), one
 * for each probedata record.  Each call to dtj_chewrec() is followed by zero or
 * more callbacks to the bufhandler, one for each output-producing action or
 * aggregation record.
 */
static int
dtj_chew(const dtrace_probedata_t *data, void *arg)
{
	dtj_java_consumer_t *jc = arg;
	JNIEnv *jenv = jc->dtjj_jenv;

	dtrace_eprobedesc_t *edesc;
	dtrace_probedesc_t *pdesc;
	dtrace_recdesc_t *rec;
	int epid;
	int cpu;
	int nrecs;
	int i;

	jobject jpdata = NULL;
	jobject jprobe = NULL;
	jobject jflow = NULL;
	jstring jflowkind = NULL;
	jobject jobj = NULL;

	edesc = data->dtpda_edesc;
	epid = (int)edesc->dtepd_epid;
	pdesc = data->dtpda_pdesc;
	cpu = (int)data->dtpda_cpu;
	if ((jprobe = dtj_new_probedesc(jc, pdesc)) == NULL) {
		/* java exception pending */
		return (DTRACE_CONSUME_ABORT);
	}
	nrecs = edesc->dtepd_nrecs;

	if (jc->dtjj_consumer->dtjc_flow) {
		const char *kind;
		switch (data->dtpda_flow) {
		case DTRACEFLOW_ENTRY:
			kind = "ENTRY";
			break;
		case DTRACEFLOW_RETURN:
			kind = "RETURN";
			break;
		case DTRACEFLOW_NONE:
			kind = "NONE";
			break;
		default:
			kind = NULL;
		}
		if (kind != NULL) {
			int depth;
			jflowkind = (*jenv)->NewStringUTF(jenv, kind);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				(*jenv)->DeleteLocalRef(jenv, jprobe);
				return (DTRACE_CONSUME_ABORT);
			}
			/*
			 * Use the knowledge that libdtrace indents 2 spaces per
			 * level in the call stack to calculate the depth.
			 */
			depth = (data->dtpda_indent / 2);
			jflow = (*jenv)->NewObject(jenv, g_flow_jc,
			    g_flowinit_jm, jflowkind, depth);
			(*jenv)->DeleteLocalRef(jenv, jflowkind);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				(*jenv)->DeleteLocalRef(jenv, jprobe);
				return (DTRACE_CONSUME_ABORT);
			}
		}
	}

	/* Create ProbeData instance */
	jpdata = (*jenv)->NewObject(jenv, g_pdata_jc, g_pdatainit_jm,
	    epid, cpu, jprobe, jflow, nrecs);
	(*jenv)->DeleteLocalRef(jenv, jprobe);
	(*jenv)->DeleteLocalRef(jenv, jflow);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (DTRACE_CONSUME_ABORT);
	}

	/*
	 * Populate the ProbeData list of Java data elements in advance so we
	 * don't need to peek back in the record handler at libdtrace records
	 * that have already been consumed.  In the Java API, each ProbeData
	 * Record is generated by one D action, while in the native libdtrace
	 * there may be more than one probedata record (each a single data
	 * element) per D action.  For example PrintfRecord has multiple
	 * unformatted elements, each represented by a native probedata record,
	 * but combined by the API into a single PrintfRecord.
	 */
	for (i = 0; i < nrecs; ++i) {
		rec = &edesc->dtepd_rec[i];
		/*
		 * A statement that is not a D action, such as assignment to a
		 * variable, has no size.  Add a NULL placeholder to the scratch
		 * list of Java probedata elements in that case.
		 */
		jobj = NULL; /* initialize object reference to null */
		if (rec->dtrd_size > 0) {
			if (dtj_is_stack_action(rec->dtrd_action)) {
				jobj = dtj_new_probedata_stack_record(data,
				    rec, jc);
			} else if (dtj_is_symbol_action(rec->dtrd_action)) {
				jobj = dtj_new_probedata_symbol_record(data,
				    rec, jc);
			} else {
				jobj = dtj_recdata(jc, rec->dtrd_size,
				    (data->dtpda_data + rec->dtrd_offset));
			}
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				(*jenv)->DeleteLocalRef(jenv, jpdata);
				return (DTRACE_CONSUME_ABORT);
			}
		}

		(*jenv)->CallVoidMethod(jenv, jpdata, g_pdataadd_jm, jobj);
		(*jenv)->DeleteLocalRef(jenv, jobj);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			(*jenv)->DeleteLocalRef(jenv, jpdata);
			return (DTRACE_CONSUME_ABORT);
		}
	}

	if (jc->dtjj_probedata != NULL) {
		dtj_throw_illegal_state(jenv, "unfinished probedata");
		WRAP_EXCEPTION(jenv);
		(*jenv)->DeleteLocalRef(jenv, jpdata);
		return (DTRACE_CONSUME_ABORT);
	}
	jc->dtjj_probedata = jpdata;

	/* Initialize per-consumer probedata fields */
	jc->dtjj_consumer->dtjc_probedata_rec_i = 0;
	jc->dtjj_consumer->dtjc_probedata_act = DTRACEACT_NONE;
	dtj_aggwalk_init(jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (DTRACE_CONSUME_ABORT);
	}

	return (DTRACE_CONSUME_THIS);
}

/*
 * This is the buffered output handler registered with dtrace_handle_buffered().
 * It's purpose is to make the output of the libdtrace print routines available
 * to this API, without writing any of it to a file (such as stdout).  This is
 * needed for the stack(), ustack(), and jstack() actions to get human-readable
 * stack values, since there is no public function in libdtrace to convert stack
 * values to strings.  It is also used to get the formatted output of the D
 * printf() and printa() actions.
 *
 * The bufhandler is called once for each output-producing, non-aggregating D
 * action, such as trace() or printf(), and once for each libdtrace aggregation
 * record (whether in response to the D printa() action, or the Consumer
 * getAggregate() method).  In the simple printa() case that takes one
 * aggregation and does not specify a format string, there is one libdtrace
 * record per tuple element plus one for the corresponding value.  The complete
 * tuple/value pair becomes a single AggregationRecord exported by the API.
 * When multiple aggregations are passed to printa(), each tuple is associated
 * with a list of values, one from each aggregation.  If a printa() format
 * string does not specify placeholders for every aggregation value and tuple
 * member, callbacks for those values and tuple members are omitted (and the
 * data is omitted from the resulting PrintaRecord).
 *
 * Notes to characterize some non-obvious bufhandler behavior:
 *
 * 1. dtj_bufhandler() is never called with bufdata->dtbda_recdesc->dtrd_action
 * DTRACEACT_PRINTA.  That action only appears in the probedata consumer
 * functions dtj_chew() and dtj_chewrec() before the bufhandler is called with
 * subsequent aggregation records.
 *
 * 2. If printa() specifies a format string argument, then the bufhandler is
 * called only for those elements of the tuple/value pair that are included in
 * the format string.  If a stack() tuple member is omitted from the format
 * string, its human-readable representation will not be available to this API,
 * so the stack frame array is also omitted from the resulting
 * AggregationRecord.  The bufhandler is also called once for each string of
 * characters surrounding printa() format string placeholders.  For example,
 * "  %@d %d stack%k\n" results in the following callbacks:
 *  - two spaces
 *  - the aggregation value
 *  - a single space
 *  - the first tuple member (an integer)
 *  - " stack"
 *  - the second tuple member (a stack)
 *  - a newline
 * A NULL record (NULL dtbda_recdesc) distinguishes a callback with interstitial
 * format string characters from a callback with a tuple member or aggregation
 * value (which has a non-NULL recdesc).  The contents are also distinguished by
 * the following flags:
 *  DTRACE_BUFDATA_AGGKEY
 *  DTRACE_BUFDATA_AGGVAL
 *  DTRACE_BUFDATA_AGGFORMAT
 *  DTRACE_BUFDATA_AGGLAST
 *
 * There is no final callback with the complete formatted string, so that must
 * be concatenated across multiple callbacks to the bufhandler.
 *
 * 3. bufdata->dtbda_probe->dtpda_data may be overwritten by libdtrace print
 * routines.  The address is cached in the dtj_chew() function in case it is
 * needed in the bufhandler.
 */
static int
/* ARGSUSED */
dtj_bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
	dtj_java_consumer_t *jc;
	JNIEnv *jenv;
	const dtrace_recdesc_t *rec;
	dtrace_actkind_t act = DTRACEACT_NONE;
	const char *s;

	jobject jstr = NULL;

	/*
	 * Get the thread-specific java consumer.  The bufhandler needs access
	 * to the correct JNI state specific to either the consumer loop or the
	 * getAggregate() call (aggregation snapshots can be requested
	 * asynchronously while the consumer loop generates PrintaRecords in
	 * dtrace_work() for ConsumerListeners).
	 */
	jc = pthread_getspecific(g_dtj_consumer_key);
	jenv = jc->dtjj_jenv;

	/*
	 * In at least one corner case (printa with multiple aggregations and a
	 * format string that does not completely specify the tuple), returning
	 * DTRACE_HANDLE_ABORT does not prevent a subsequent callback to this
	 * bufhandler.  This check ensures that the invalid call is ignored.
	 */
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (DTRACE_HANDLE_ABORT);
	}

	if (bufdata->dtbda_aggdata) {
		return (dtj_agghandler(bufdata, jc));
	}

	s = bufdata->dtbda_buffered;
	if (s == NULL) {
		return (DTRACE_HANDLE_OK);
	}

	rec = bufdata->dtbda_recdesc;
	if (rec) {
		act = rec->dtrd_action;
	}

	switch (act) {
	case DTRACEACT_DIFEXPR:
		/* trace() action */
		break;
	case DTRACEACT_PRINTF:
		/*
		 * Only the formatted string was not available to dtj_chewrec(),
		 * so we attach that now.
		 */
		jstr = dtj_NewStringNative(jenv, s);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataset_formatted_jm, jstr);
		(*jenv)->DeleteLocalRef(jenv, jstr);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
		break;
	case DTRACEACT_STACK:
	case DTRACEACT_USTACK:
	case DTRACEACT_JSTACK:
		/* stand-alone stack(), ustack(), or jstack() action */
		jstr = (*jenv)->NewStringUTF(jenv, s);
		if (!jstr) {
			/* OutOfMemoryError pending */
			return (DTRACE_HANDLE_ABORT);
		}
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataadd_stack_jm,
		    jc->dtjj_consumer->dtjc_probedata_rec_i, jstr);
		(*jenv)->DeleteLocalRef(jenv, jstr);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
		break;
	case DTRACEACT_USYM:
	case DTRACEACT_UADDR:
	case DTRACEACT_UMOD:
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
		/* stand-alone symbol lookup action */
		jstr = (*jenv)->NewStringUTF(jenv, s);
		if (!jstr) {
			/* OutOfMemoryError pending */
			return (DTRACE_HANDLE_ABORT);
		}
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
		    g_pdataadd_symbol_jm,
		    jc->dtjj_consumer->dtjc_probedata_rec_i, jstr);
		(*jenv)->DeleteLocalRef(jenv, jstr);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
		break;
	default:
		/*
		 * The record handler dtj_chewrec() defers nothing else to this
		 * bufhandler.
		 */
		break;
	}

	return (DTRACE_HANDLE_OK);
}

static boolean_t
dtj_is_stack_action(dtrace_actkind_t act)
{
	boolean_t stack_action;
	switch (act) {
	case DTRACEACT_STACK:
	case DTRACEACT_USTACK:
	case DTRACEACT_JSTACK:
		stack_action = B_TRUE;
		break;
	default:
		stack_action = B_FALSE;
	}
	return (stack_action);
}

static boolean_t
dtj_is_symbol_action(dtrace_actkind_t act)
{
	boolean_t symbol_action;
	switch (act) {
	case DTRACEACT_USYM:
	case DTRACEACT_UADDR:
	case DTRACEACT_UMOD:
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
		symbol_action = B_TRUE;
		break;
	default:
		symbol_action = B_FALSE;
	}
	return (symbol_action);
}

/*
 * Called by get_aggregate() to clear only those aggregations specified by the
 * caller.
 */
static int
dtj_clear(const dtrace_aggdata_t *data, void *arg)
{
	dtj_java_consumer_t *jc = arg;
	jboolean cleared = JNI_FALSE;

	jstring jname = NULL;

	if (jc->dtjj_aggregate_spec) {
		JNIEnv *jenv = jc->dtjj_jenv;

		dtrace_aggdesc_t *aggdesc = data->dtada_desc;

		jname = (*jenv)->NewStringUTF(jenv, aggdesc->dtagd_name);
		if (!jname) {
			/* java exception pending */
			return (DTRACE_AGGWALK_ABORT);
		}

		cleared = (*jenv)->CallBooleanMethod(jenv,
		    jc->dtjj_aggregate_spec, g_aggspec_cleared_jm, jname);
		(*jenv)->DeleteLocalRef(jenv, jname);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_AGGWALK_ABORT);
		}
	}

	return (cleared ? DTRACE_AGGWALK_CLEAR : DTRACE_AGGWALK_NEXT);
}

static int64_t
dtj_average(caddr_t addr, uint64_t normal)
{
	/* LINTED - alignment */
	int64_t *data = (int64_t *)addr;

	return (data[0] ?
	    (data[1] / (int64_t)normal / data[0]) : 0);
}

static int64_t
dtj_avg_total(caddr_t addr, uint64_t normal)
{
	/* LINTED - alignment */
	int64_t *data = (int64_t *)addr;

	return (data[1] / (int64_t)normal);
}

static int64_t
dtj_avg_count(caddr_t addr)
{
	/* LINTED - alignment */
	int64_t *data = (int64_t *)addr;

	return (data[0]);
}

static jobject
dtj_stddev_total_squares(JNIEnv *jenv, caddr_t addr, uint64_t normal)
{
	jobject val128;

	/* LINTED - alignment */
	uint64_t *data = (uint64_t *)addr;

	if (data[0] == 0) {
		val128 = (*jenv)->CallStaticObjectMethod(jenv, g_bigint_jc,
		    g_bigint_val_jsm, (uint64_t)0);
	} else {
		val128 = dtj_int128(jenv, data[3], data[2]);

		if (normal != 1) {
			jobject divisor;
			jobject tmp;

			divisor = (*jenv)->CallStaticObjectMethod(jenv,
			    g_bigint_jc, g_bigint_val_jsm, normal);
			tmp = val128;
			val128 = (*jenv)->CallObjectMethod(jenv, tmp,
			    g_bigint_div_jm, divisor);
			(*jenv)->DeleteLocalRef(jenv, tmp);
			(*jenv)->DeleteLocalRef(jenv, divisor);
		}
	}

	return (val128);
}

/*
 * Return NULL if a java exception is pending, otherwise return a new
 * StddevValue instance.
 */
static jobject
dtj_stddev(JNIEnv *jenv, caddr_t addr, uint64_t normal)
{
	jobject total_squares;
	jobject stddev;

	total_squares = dtj_stddev_total_squares(jenv, addr, normal);
	stddev = (*jenv)->NewObject(jenv, g_aggstddev_jc, g_aggstddevinit_jm,
	    dtj_avg_count(addr), dtj_avg_total(addr, normal), total_squares);
	(*jenv)->DeleteLocalRef(jenv, total_squares);

	return (stddev);
}

static jobject
dtj_new_probedata_stack_record(const dtrace_probedata_t *data,
    const dtrace_recdesc_t *rec, dtj_java_consumer_t *jc)
{
	caddr_t addr;

	/* Get raw stack data */
	addr = data->dtpda_data + rec->dtrd_offset;
	return (dtj_new_stack_record(addr, rec, jc));
}

static jobject
dtj_new_tuple_stack_record(const dtrace_aggdata_t *data,
    const dtrace_recdesc_t *rec, const char *s, dtj_java_consumer_t *jc)
{
	caddr_t addr;
	JNIEnv *jenv = jc->dtjj_jenv;

	jobjectArray frames = NULL;
	jobject jobj = NULL; /* tuple element */
	jstring jstr = NULL;

	/* Get raw stack data */
	addr = data->dtada_data + rec->dtrd_offset;
	jobj = dtj_new_stack_record(addr, rec, jc);
	if (!jobj) {
		return (NULL); /* java exception pending */
	}

	jstr = dtj_NewStringNative(jenv, s);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jobj);
		return (NULL);
	}
	frames = (*jenv)->CallStaticObjectMethod(jenv, g_stack_jc,
	    g_parsestack_jsm, jstr);
	(*jenv)->DeleteLocalRef(jenv, jstr);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jobj);
		return (NULL);
	}
	dtj_attach_frames(jc, jobj, frames);
	(*jenv)->DeleteLocalRef(jenv, frames);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}

	return (jobj);
}

static jobject
dtj_new_probedata_symbol_record(const dtrace_probedata_t *data,
    const dtrace_recdesc_t *rec, dtj_java_consumer_t *jc)
{
	caddr_t addr;

	addr = data->dtpda_data + rec->dtrd_offset;
	return (dtj_new_symbol_record(addr, rec, jc));
}

static jobject
dtj_new_tuple_symbol_record(const dtrace_aggdata_t *data,
    const dtrace_recdesc_t *rec, const char *s, dtj_java_consumer_t *jc)
{
	caddr_t addr;
	JNIEnv *jenv = jc->dtjj_jenv;

	jobject jobj = NULL; /* tuple element */
	jstring jstr = NULL; /* lookup value */
	jstring tstr = NULL; /* trimmed lookup value */

	addr = data->dtada_data + rec->dtrd_offset;
	jobj = dtj_new_symbol_record(addr, rec, jc);
	if (!jobj) {
		return (NULL); /* java exception pending */
	}

	/* Get symbol lookup */
	jstr = (*jenv)->NewStringUTF(jenv, s);
	if (!jstr) {
		/* OutOfMemoryError pending */
		(*jenv)->DeleteLocalRef(jenv, jobj);
		return (NULL);
	}
	/* Trim leading and trailing whitespace */
	tstr = (*jenv)->CallObjectMethod(jenv, jstr, g_trim_jm);
	/* trim() returns a new string; don't leak the old one */
	(*jenv)->DeleteLocalRef(jenv, jstr);
	jstr = tstr;
	tstr = NULL;

	dtj_attach_name(jc, jobj, jstr);
	(*jenv)->DeleteLocalRef(jenv, jstr);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}

	return (jobj);
}

/* Caller must be holding per-consumer lock */
static void
dtj_aggwalk_init(dtj_java_consumer_t *jc)
{
	jc->dtjj_consumer->dtjc_aggid = -1;
	jc->dtjj_consumer->dtjc_expected = -1;
	if (jc->dtjj_tuple != NULL) {
		/* assert without crashing */
		dtj_throw_illegal_state(jc->dtjj_jenv,
		    "stale aggregation tuple");
	}
}

static jobject
dtj_new_stack_record(const caddr_t addr, const dtrace_recdesc_t *rec,
    dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	dtrace_actkind_t act;
	uint64_t *pc;
	pid_t pid = -1;
	int size; /* size of raw bytes not including trailing zeros */
	int i; /* index of last non-zero byte */

	jbyteArray raw = NULL;
	jobject stack = NULL; /* return value */

	/* trim trailing zeros */
	for (i = rec->dtrd_size - 1; (i >= 0) && !addr[i]; --i) {
	}
	size = (i + 1);
	raw = (*jenv)->NewByteArray(jenv, size);
	if (!raw) {
		return (NULL); /* OutOfMemoryError pending */
	}
	(*jenv)->SetByteArrayRegion(jenv, raw, 0, size,
	    (const jbyte *)addr);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		(*jenv)->DeleteLocalRef(jenv, raw);
		return (NULL);
	}

	/* Create StackValueRecord instance from raw stack data */
	act = rec->dtrd_action;
	switch (act) {
	case DTRACEACT_STACK:
		stack = (*jenv)->NewObject(jenv, g_stack_jc,
		    g_stackinit_jm, raw);
		break;
	case DTRACEACT_USTACK:
	case DTRACEACT_JSTACK:
		/* Get pid of user process */
		pc = (uint64_t *)(uintptr_t)addr;
		pid = (pid_t)*pc;
		stack = (*jenv)->NewObject(jenv, g_ustack_jc,
		    g_ustackinit_jm, pid, raw);
		break;
	default:
		dtj_throw_illegal_argument(jenv,
		    "Expected stack action, got %d\n", act);
	}
	(*jenv)->DeleteLocalRef(jenv, raw);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}
	return (stack);
}

static jobject
dtj_new_symbol_record(const caddr_t addr, const dtrace_recdesc_t *rec,
    dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	dtrace_actkind_t act;
	uint64_t *pc;
	pid_t pid = -1;

	jobject symbol = NULL; /* return value */

	act = rec->dtrd_action;
	switch (act) {
	case DTRACEACT_SYM:
	case DTRACEACT_MOD:
		/* LINTED - alignment */
		pc = (uint64_t *)addr;
		symbol = (*jenv)->NewObject(jenv, g_symbol_jc,
		    g_symbolinit_jm, *pc);
		break;
	case DTRACEACT_USYM:
	case DTRACEACT_UADDR:
	case DTRACEACT_UMOD:
		/* Get pid of user process */
		pc = (uint64_t *)(uintptr_t)addr;
		pid = (pid_t)*pc;
		++pc;
		symbol = (*jenv)->NewObject(jenv, g_usymbol_jc,
		    g_usymbolinit_jm, pid, *pc);
		break;
	default:
		dtj_throw_illegal_argument(jenv,
		    "Expected stack action, got %d\n", act);
	}
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}
	return (symbol);
}

/*
 * Return NULL if java exception pending, otherwise return Distribution value.
 */
static jobject
dtj_new_distribution(const dtrace_aggdata_t *data, const dtrace_recdesc_t *rec,
    dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	jlongArray jbuckets = NULL;
	jobject jdist = NULL; /* return value */

	dtrace_actkind_t act = rec->dtrd_action;
	/* LINTED - alignment */
	int64_t *aggbuckets = (int64_t *)
	    (data->dtada_data + rec->dtrd_offset);
	size_t size = rec->dtrd_size;
	int64_t value;
	uint64_t normal = data->dtada_normal;
	int64_t base, step;
	int levels;
	int n; /* number of buckets */

	/* distribution */
	if (act == DTRACEAGG_LQUANTIZE) {
		/* first "bucket" used for range and step */
		value = *aggbuckets++;
		base = DTRACE_LQUANTIZE_BASE(value);
		step = DTRACE_LQUANTIZE_STEP(value);
		levels = DTRACE_LQUANTIZE_LEVELS(value);
		size -= sizeof (int64_t); /* exclude non-bucket */
		/*
		 * Add one for the base bucket and one for the bucket of values
		 * less than the base.
		 */
		n = levels + 2;
	} else {
		n = DTRACE_QUANTIZE_NBUCKETS;
		levels = n - 1; /* levels excludes base */
	}
	if (size != (n * sizeof (uint64_t)) || n < 1) {
		dtj_throw_illegal_state(jenv,
		    "size mismatch: record %d, buckets %d", size,
		    (n * sizeof (uint64_t)));
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}

	jbuckets = (*jenv)->NewLongArray(jenv, n);
	if (!jbuckets) {
		return (NULL); /* exception pending */
	}
	if (n > 0) {
		(*jenv)->SetLongArrayRegion(jenv, jbuckets, 0, n, aggbuckets);
		/* check for ArrayIndexOutOfBounds */
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			(*jenv)->DeleteLocalRef(jenv, jbuckets);
			return (NULL);
		}
	}

	if (act == DTRACEAGG_LQUANTIZE) {
		/* Must pass 64-bit base and step or constructor gets junk. */
		jdist = (*jenv)->NewObject(jenv, g_ldist_jc, g_ldistinit_jm,
		    base, step, jbuckets);
	} else {
		jdist = (*jenv)->NewObject(jenv, g_dist_jc, g_distinit_jm,
		    jbuckets);
	}

	(*jenv)->DeleteLocalRef(jenv, jbuckets);
	if (!jdist) {
		return (NULL); /* exception pending */
	}

	if (normal != 1) {
		(*jenv)->CallVoidMethod(jenv, jdist, g_dist_normal_jm, normal);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			(*jenv)->DeleteLocalRef(jenv, jdist);
			return (NULL);
		}
	}
	return (jdist);
}

static void
dtj_attach_frames(dtj_java_consumer_t *jc, jobject stack,
    jobjectArray frames)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	if ((*jenv)->IsInstanceOf(jenv, stack, g_stack_jc)) {
		(*jenv)->CallVoidMethod(jenv, stack, g_stackset_frames_jm,
		    frames);
	} else if ((*jenv)->IsInstanceOf(jenv, stack, g_ustack_jc)) {
		(*jenv)->CallVoidMethod(jenv, stack, g_ustackset_frames_jm,
		    frames);
	}
}

static void
dtj_attach_name(dtj_java_consumer_t *jc, jobject symbol, jstring s)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	if ((*jenv)->IsInstanceOf(jenv, symbol, g_symbol_jc)) {
		(*jenv)->CallVoidMethod(jenv, symbol, g_symbolset_name_jm, s);
	} else if ((*jenv)->IsInstanceOf(jenv, symbol, g_usymbol_jc)) {
		(*jenv)->CallVoidMethod(jenv, symbol, g_usymbolset_name_jm, s);
	}
}

/*
 * Note: It is not valid to look outside the current libdtrace record in the
 * given aggdata (except to get the aggregation ID from the first record).
 *
 * Return DTRACE_HANDLE_ABORT if java exception pending, otherwise
 * DTRACE_HANDLE_OK.
 */
static int
dtj_agghandler(const dtrace_bufdata_t *bufdata, dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	const dtrace_aggdata_t *aggdata = bufdata->dtbda_aggdata;
	const dtrace_aggdesc_t *aggdesc;
	const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
	const char *s = bufdata->dtbda_buffered;
	dtrace_actkind_t act = DTRACEACT_NONE;
	int64_t aggid;

	jobject jobj = NULL;

	if (aggdata == NULL) {
		/* Assert without crashing */
		dtj_throw_illegal_state(jenv, "null aggdata");
		WRAP_EXCEPTION(jenv);
		return (DTRACE_HANDLE_ABORT);
	}
	aggdesc = aggdata->dtada_desc;

	/*
	 * Get the aggregation ID from the first record.
	 */
	/* LINTED - alignment */
	aggid = *((int64_t *)(aggdata->dtada_data +
	    aggdesc->dtagd_rec[0].dtrd_offset));
	if (aggid < 0) {
		/* Assert without crashing */
		dtj_throw_illegal_argument(jenv, "negative aggregation ID");
		WRAP_EXCEPTION(jenv);
		return (DTRACE_HANDLE_ABORT);
	}

	if (jc->dtjj_consumer->dtjc_printa_snaptime) {
		/* Append buffered output if this is a printa() callback. */
		jstring jstr = dtj_NewStringNative(jenv, s);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
		/*
		 * StringBuilder append() returns a reference to the
		 * StringBuilder; must not leak the returned reference.
		 */
		jobj = (*jenv)->CallObjectMethod(jenv,
		    jc->dtjj_printa_buffer, g_buf_append_str_jm, jstr);
		(*jenv)->DeleteLocalRef(jenv, jstr);
		(*jenv)->DeleteLocalRef(jenv, jobj);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
	} else {
		/*
		 * Test whether to include the aggregation if this is a
		 * getAggregate() call.  Optimization: perform the inclusion
		 * test only when the aggregation has changed.
		 */
		if (aggid != jc->dtjj_consumer->dtjc_aggid) {
			jc->dtjj_consumer->dtjc_included =
			    dtj_is_included(aggdata, jc);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				return (DTRACE_HANDLE_ABORT);
			}
		}
		if (!jc->dtjj_consumer->dtjc_included) {
			return (DTRACE_HANDLE_OK);
		}
	}
	jc->dtjj_consumer->dtjc_aggid = aggid;

	/*
	 * Determine the expected number of tuple members.  While it is not
	 * technically valid to look outside the current record in the current
	 * aggdata, this implementation does so without a known failure case.
	 * Any method relying only on the current callback record makes riskier
	 * assumptions and still does not cover every corner case (for example,
	 * counting the records from index 1 up to and not including the index
	 * of the current DTRACE_BUFDATA_AGGVAL record, which fails when a
	 * format string specifies the value ahead of one or more tuple
	 * elements).  Knowing that the calculation of the expected tuple size
	 * is technically invalid (because it looks outside the current record),
	 * we make the calculation at the earliest opportunity, before anything
	 * might happen to invalidate any part of the aggdata.  It ought to be
	 * safe in any case: dtrd_action and dtrd_size do not appear ever to be
	 * overwritten, and dtrd_offset is not used outside the current record.
	 *
	 * It is possible (if the assumptions here ever prove untrue) that the
	 * libdtrace buffered output handler may need to be enhanced to provide
	 * the expected number of tuple members.
	 */
	if (jc->dtjj_consumer->dtjc_expected < 0) {
		int r;
		for (r = 1; r < aggdesc->dtagd_nrecs; ++r) {
			act = aggdesc->dtagd_rec[r].dtrd_action;
			if (DTRACEACT_ISAGG(act) ||
			    aggdesc->dtagd_rec[r].dtrd_size == 0) {
				break;
			}
		}
		jc->dtjj_consumer->dtjc_expected = r - 1;
	}

	if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGKEY) {
		/* record value is a tuple member */

		if (jc->dtjj_tuple == NULL) {
			jc->dtjj_tuple = (*jenv)->NewObject(jenv,
			    g_tuple_jc, g_tupleinit_jm);
			if (!jc->dtjj_tuple) {
				/* java exception pending */
				return (DTRACE_HANDLE_ABORT);
			}
		}

		act = rec->dtrd_action;

		switch (act) {
		case DTRACEACT_STACK:
		case DTRACEACT_USTACK:
		case DTRACEACT_JSTACK:
			jobj = dtj_new_tuple_stack_record(aggdata, rec, s, jc);
			break;
		case DTRACEACT_USYM:
		case DTRACEACT_UADDR:
		case DTRACEACT_UMOD:
		case DTRACEACT_SYM:
		case DTRACEACT_MOD:
			jobj = dtj_new_tuple_symbol_record(aggdata, rec, s, jc);
			break;
		default:
			jobj = dtj_recdata(jc, rec->dtrd_size,
			    (aggdata->dtada_data + rec->dtrd_offset));
		}

		if (!jobj) {
			/* java exception pending */
			return (DTRACE_HANDLE_ABORT);
		}

		(*jenv)->CallVoidMethod(jenv, jc->dtjj_tuple,
		    g_tupleadd_jm, jobj);
		(*jenv)->DeleteLocalRef(jenv, jobj);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
	} else if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGVAL) {
		/*
		 * Record value is that of an aggregating action.  The printa()
		 * format string may place the tuple ahead of the aggregation
		 * value(s), so we can't be sure we have the tuple until we get
		 * the AGGLAST flag indicating the last callback associated with
		 * the current tuple.  Save the aggregation value or values
		 * (multiple values if more than one aggregation is passed to
		 * printa()) until then.
		 */
		dtj_aggval_t *aggval;

		jstring jvalue = NULL;

		jvalue = dtj_new_aggval(jc, aggdata, rec);
		if (!jvalue) {
			/* java exception pending */
			WRAP_EXCEPTION(jenv);
			return (DTRACE_HANDLE_ABORT);
		}
		aggval = dtj_aggval_create(jenv, jvalue, aggdesc->dtagd_name,
		    aggid);
		if (!aggval) {
			/* OutOfMemoryError pending */
			(*jenv)->DeleteLocalRef(jenv, jvalue);
			return (DTRACE_HANDLE_ABORT);
		}
		if (!dtj_list_add(jc->dtjj_aggval_list, aggval)) {
			/* deletes jvalue reference */
			dtj_aggval_destroy(aggval, jenv);
			dtj_throw_out_of_memory(jenv, "Failed to add aggval");
			return (DTRACE_HANDLE_ABORT);
		}
	}

	if (bufdata->dtbda_flags & DTRACE_BUFDATA_AGGLAST) {
		/* No more values associated with the current tuple. */

		dtj_aggval_t *aggval;
		uu_list_walk_t *itr;
		int tuple_member_count;

		jobject jrec = NULL;
		jstring jname = NULL;

		if (jc->dtjj_consumer->dtjc_expected == 0) {
			/*
			 * singleton aggregation declared in D with no square
			 * brackets
			 */
			jc->dtjj_tuple = (*jenv)->GetStaticObjectField(jenv,
			    g_tuple_jc, g_tuple_EMPTY_jsf);
			if (jc->dtjj_tuple == NULL) {
				dtj_throw_out_of_memory(jenv,
				    "Failed to reference Tuple.EMPTY");
				return (DTRACE_HANDLE_ABORT);
			}
		}

		if (jc->dtjj_tuple == NULL) {
			(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
			    g_pdatainvalidate_printa_jm);
			goto printa_output;
		}

		tuple_member_count = (*jenv)->CallIntMethod(jenv,
		    jc->dtjj_tuple, g_tuplesize_jm);
		if (tuple_member_count <
		    jc->dtjj_consumer->dtjc_expected) {
			(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
			    g_pdatainvalidate_printa_jm);
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_tuple);
			jc->dtjj_tuple = NULL;
			goto printa_output;
		}

		itr = uu_list_walk_start(jc->dtjj_aggval_list, 0);
		while ((aggval = uu_list_walk_next(itr)) != NULL) {
			/*
			 * new AggregationRecord:  Combine the aggregation value
			 * with the saved tuple and add it to the current
			 * Aggregate or PrintaRecord.
			 */
			jrec = (*jenv)->NewObject(jenv, g_aggrec_jc,
			    g_aggrecinit_jm, jc->dtjj_tuple,
			    aggval->dtja_value);
			(*jenv)->DeleteLocalRef(jenv, aggval->dtja_value);
			aggval->dtja_value = NULL;
			if (!jrec) {
				/* java exception pending */
				WRAP_EXCEPTION(jenv);
				return (DTRACE_HANDLE_ABORT);
			}

			/* aggregation name */
			jname = (*jenv)->NewStringUTF(jenv,
			    aggval->dtja_aggname);
			if (!jname) {
				/* OutOfMemoryError pending */
				(*jenv)->DeleteLocalRef(jenv, jrec);
				return (DTRACE_HANDLE_ABORT);
			}

			/*
			 * If the printa() format string specifies the value of
			 * the aggregating action multiple times, PrintaRecord
			 * ignores the attempt to add the duplicate record.
			 */
			if (jc->dtjj_consumer->dtjc_printa_snaptime) {
				/* add to PrintaRecord */
				(*jenv)->CallVoidMethod(jenv,
				    jc->dtjj_probedata,
				    g_pdataadd_aggrec_jm,
				    jname, aggval->dtja_aggid, jrec);
			} else {
				/* add to Aggregate */
				(*jenv)->CallVoidMethod(jenv,
				    jc->dtjj_aggregate, g_aggaddrec_jm,
				    jname, aggval->dtja_aggid, jrec);
			}

			(*jenv)->DeleteLocalRef(jenv, jrec);
			(*jenv)->DeleteLocalRef(jenv, jname);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				return (DTRACE_HANDLE_ABORT);
			}
		}
		uu_list_walk_end(itr);
		dtj_list_clear(jc->dtjj_aggval_list, dtj_aggval_destroy,
		    jenv);

printa_output:
		if (jc->dtjj_consumer->dtjc_printa_snaptime) {
			/*
			 * Get the formatted string associated with the current
			 * tuple if this is a printa() callback.
			 */
			jstring jstr = (*jenv)->CallObjectMethod(jenv,
			    jc->dtjj_printa_buffer, g_tostring_jm);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				return (DTRACE_HANDLE_ABORT);
			}
			/*
			 * Clear the StringBuilder: this does not throw
			 * exceptions.  Reuse the StringBuilder until the end of
			 * the current probedata then dispose of it.
			 */
			(*jenv)->CallVoidMethod(jenv, jc->dtjj_printa_buffer,
			    g_bufsetlen_jm, 0);
			/* Add formatted string to PrintaRecord */
			(*jenv)->CallVoidMethod(jenv, jc->dtjj_probedata,
			    g_pdataadd_printa_str_jm, jc->dtjj_tuple, jstr);
			(*jenv)->DeleteLocalRef(jenv, jstr);
			if ((*jenv)->ExceptionCheck(jenv)) {
				WRAP_EXCEPTION(jenv);
				return (DTRACE_HANDLE_ABORT);
			}
		}

		(*jenv)->DeleteLocalRef(jenv, jc->dtjj_tuple);
		jc->dtjj_tuple = NULL;
		jc->dtjj_consumer->dtjc_expected = -1;
	}

	return (DTRACE_HANDLE_OK);
}

/*
 * Return B_TRUE if the aggregation is included, B_FALSE otherwise.  Only in the
 * latter case might there be an exception pending.
 */
static boolean_t
dtj_is_included(const dtrace_aggdata_t *data, dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	if (jc->dtjj_aggregate_spec) {
		jboolean included;
		jstring aggname = NULL;

		const dtrace_aggdesc_t *aggdesc = data->dtada_desc;
		aggname = (*jenv)->NewStringUTF(jenv, aggdesc->dtagd_name);
		if (!aggname) {
			/* java exception pending */
			return (B_FALSE);
		}

		included = (*jenv)->CallBooleanMethod(jenv,
		    jc->dtjj_aggregate_spec, g_aggspec_included_jm,
		    aggname);
		(*jenv)->DeleteLocalRef(jenv, aggname);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (B_FALSE);
		}

		return (included);
	}

	return (B_TRUE);
}

/*
 * Return NULL if a java exception is pending, otherwise return a new
 * AggregationValue instance.
 */
static jobject
dtj_new_aggval(dtj_java_consumer_t *jc, const dtrace_aggdata_t *data,
    const dtrace_recdesc_t *rec)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	jobject jvalue = NULL; /* return value */

	dtrace_actkind_t act;
	uint64_t normal;
	caddr_t addr;
	int64_t value;

	act = rec->dtrd_action;
	normal = data->dtada_normal;
	addr = data->dtada_data + rec->dtrd_offset;
	if (act == DTRACEAGG_AVG) {
		value = dtj_average(addr, normal);
	} else {
		/* LINTED - alignment */
		value = (*((int64_t *)addr)) / normal;
	}

	if (act == DTRACEAGG_QUANTIZE || act == DTRACEAGG_LQUANTIZE) {
		jvalue = dtj_new_distribution(data, rec, jc);
	} else {
		switch (act) {
		case DTRACEAGG_COUNT:
			jvalue = (*jenv)->NewObject(jenv, g_aggcount_jc,
			    g_aggcountinit_jm, value);
			break;
		case DTRACEAGG_SUM:
			jvalue = (*jenv)->NewObject(jenv, g_aggsum_jc,
			    g_aggsuminit_jm, value);
			break;
		case DTRACEAGG_AVG:
			jvalue = (*jenv)->NewObject(jenv, g_aggavg_jc,
			    g_aggavginit_jm, value, dtj_avg_total(addr,
			    normal), dtj_avg_count(addr));
			break;
		case DTRACEAGG_MIN:
			jvalue = (*jenv)->NewObject(jenv, g_aggmin_jc,
			    g_aggmininit_jm, value);
			break;
		case DTRACEAGG_MAX:
			jvalue = (*jenv)->NewObject(jenv, g_aggmax_jc,
			    g_aggmaxinit_jm, value);
			break;
		case DTRACEAGG_STDDEV:
			jvalue = dtj_stddev(jenv, addr, normal);
			break;
		default:
			jvalue = NULL;
			dtj_throw_illegal_argument(jenv,
			    "unexpected aggregation action: %d", act);
		}
	}

	return (jvalue);
}

/*
 * Stops the given consumer if it is running.  Throws DTraceException if
 * dtrace_stop() fails and no other exception is already pending.  Clears and
 * rethrows any pending exception in order to grab the global lock safely.
 */
void
dtj_stop(dtj_java_consumer_t *jc)
{
	JNIEnv *jenv;
	int rc;
	jthrowable e;

	switch (jc->dtjj_consumer->dtjc_state) {
	case DTJ_CONSUMER_GO:
	case DTJ_CONSUMER_START:
		break;
	default:
		return;
	}

	jenv = jc->dtjj_jenv;
	e = (*jenv)->ExceptionOccurred(jenv);
	if (e) {
		(*jenv)->ExceptionClear(jenv);
	}

	(*jenv)->MonitorEnter(jenv, g_caller_jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto rethrow;
	}

	rc = dtrace_status(jc->dtjj_consumer->dtjc_dtp);
	if (rc != DTRACE_STATUS_STOPPED) {
		rc = dtrace_stop(jc->dtjj_consumer->dtjc_dtp);
	}

	(*jenv)->MonitorExit(jenv, g_caller_jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto rethrow;
	}

	if (rc == -1) {
		(*jenv)->MonitorEnter(jenv, g_caller_jc);
		if ((*jenv)->ExceptionCheck(jenv)) {
			goto rethrow;
		}
		/* Do not wrap DTraceException */
		dtj_throw_dtrace_exception(jc,
		    "couldn't stop tracing: %s",
		    dtrace_errmsg(jc->dtjj_consumer->dtjc_dtp,
		    dtrace_errno(jc->dtjj_consumer->dtjc_dtp)));
		/* safe to call with pending exception */
		(*jenv)->MonitorExit(jenv, g_caller_jc);
	} else {
		jc->dtjj_consumer->dtjc_state = DTJ_CONSUMER_STOP;
	}

rethrow:
	if (e) {
		if ((*jenv)->ExceptionCheck(jenv)) {
			/*
			 * Favor earlier pending exception over
			 * exception thrown in this function.
			 */
			(*jenv)->ExceptionClear(jenv);
		}
		(*jenv)->Throw(jenv, e);
		(*jenv)->DeleteLocalRef(jenv, e);
	}
}

/*
 * Return Aggregate instance, or null if java exception pending.
 */
jobject
dtj_get_aggregate(dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;
	hrtime_t snaptime;
	int rc;

	jobject aggregate = NULL;

	/* Must not call MonitorEnter with a pending exception */
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}

	/*
	 * Aggregations must be snapped, walked, and cleared atomically,
	 * otherwise clearing loses data accumulated since the most recent snap.
	 * This per-consumer lock prevents dtrace_work() from snapping or
	 * clearing aggregations while we're in the middle of this atomic
	 * operation, so we continue to hold it until done clearing.
	 */
	(*jenv)->MonitorEnter(jenv, jc->dtjj_consumer_lock);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}

	dtj_aggwalk_init(jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}

	/*
	 * Snap aggregations
	 *
	 * We need to record the snaptime here for the caller.  Leaving it to
	 * the caller to record the snaptime before calling getAggregate() may
	 * be inaccurate because of the indeterminate delay waiting on the
	 * consumer lock before calling dtrace_aggregate_snap().
	 */
	snaptime = gethrtime();
	if (dtrace_aggregate_snap(jc->dtjj_consumer->dtjc_dtp) != 0) {
		dtj_error_t e;

		/*
		 * The dataDropped() ConsumerListener method can throw an
		 * exception in the getAggregate() thread if the drop handler is
		 * invoked during dtrace_aggregate_snap().
		 */
		if ((*jenv)->ExceptionCheck(jenv)) {
			/* Do not wrap exception thrown from ConsumerListener */
			/* release per-consumer lock */
			(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
			return (NULL);
		}

		if (dtj_get_dtrace_error(jc, &e) == DTJ_OK) {
			/* Do not wrap DTraceException */
			dtj_throw_dtrace_exception(jc, e.dtje_message);
		}
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}

	if ((*jenv)->ExceptionCheck(jenv)) {
		/*
		 * Wrap the exception thrown from ConsumerListener in this case,
		 * so we can see that it unexpectedly reached this spot in
		 * native code (dtrace_aggregate_snap should have returned
		 * non-zero).
		 */
		WRAP_EXCEPTION(jenv);
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}

	/* Create the Java representation of the aggregate snapshot. */
	aggregate = (*jenv)->NewObject(jenv, g_agg_jc, g_agginit_jm,
	    snaptime);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}
	jc->dtjj_aggregate = aggregate;

	/*
	 * Walk the aggregate, converting the data into Java Objects. Traverse
	 * in the order determined by libdtrace, respecting the various
	 * "aggsort" options, just as dtrace_work does when generating
	 * aggregations for the printa() action. libdtrace ordering is preserved
	 * in the "ordinal" property of AggregationRecord, since it would
	 * otherwise be lost when the records are hashed into the Aggregation's
	 * map. Neither the consumer loop nor the competing getAggregate()
	 * thread should depend on any particular record ordering (such as
	 * ordering by tuple key) to process records correctly.
	 *
	 * It is impractical to hold the global lock around
	 * dtrace_aggregate_print(), since it may take a long time (e.g. an
	 * entire second) if it performs expensive conversions such as that
	 * needed for user stack traces.  Most libdtrace functions are not
	 * guaranteed to be MT-safe, even when each thread has its own dtrace
	 * handle; or even if they are safe, there is no guarantee that future
	 * changes may not make them unsafe.  Fortunately in this case, however,
	 * only a per-consumer lock is necessary to avoid conflict with
	 * dtrace_work() running in another thread (the consumer loop).
	 */
	rc = dtrace_aggregate_print(jc->dtjj_consumer->dtjc_dtp, NULL, NULL);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}
	if (rc != 0) {
		dtj_error_t e;
		if (dtj_get_dtrace_error(jc, &e) != DTJ_OK) {
			/* release per-consumer lock */
			(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
			return (NULL);
		}

		if (e.dtje_number != EINTR) {
			/* Do not wrap DTraceException */
			dtj_throw_dtrace_exception(jc, e.dtje_message);
			/* release per-consumer lock */
			(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
			return (NULL);
		}
	}

	dtj_aggwalk_init(jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}

	/*
	 * dtrace_aggregate_clear() clears all aggregations, and we need to
	 * clear aggregations selectively.  It also fails to preserve the
	 * lquantize() range and step size; using aggregate_walk() to clear
	 * aggregations does not have this problem.
	 */
	rc = dtrace_aggregate_walk(jc->dtjj_consumer->dtjc_dtp, dtj_clear, jc);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}
	if (rc != 0) {
		dtj_error_t e;
		if (dtj_get_dtrace_error(jc, &e) == DTJ_OK) {
			/* Do not wrap DTraceException */
			dtj_throw_dtrace_exception(jc, e.dtje_message);
		}
		/* release per-consumer lock */
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		return (NULL);
	}

	(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
	if ((*jenv)->ExceptionCheck(jenv)) {
		WRAP_EXCEPTION(jenv);
		return (NULL);
	}

	aggregate = jc->dtjj_aggregate;
	jc->dtjj_aggregate = NULL;

	return (aggregate);
}

/*
 * Process any requests, such as the setting of runtime options, enqueued during
 * dtrace_sleep().  A Java exception is pending if this function returns
 * DTJ_ERR.
 */
static dtj_status_t
dtj_process_requests(dtj_java_consumer_t *jc)
{
	dtj_request_t *r;
	uu_list_t *list = jc->dtjj_consumer->dtjc_request_list;
	pthread_mutex_t *list_lock = &jc->dtjj_consumer->
	    dtjc_request_list_lock;
	const char *opt;
	const char *val;

	(void) pthread_mutex_lock(list_lock);
	while (!dtj_list_empty(list)) {
		r = uu_list_first(list);
		uu_list_remove(list, r);

		switch (r->dtjr_type) {
		case DTJ_REQUEST_OPTION:
			opt = dtj_string_list_first(r->dtjr_args);
			val = dtj_string_list_last(r->dtjr_args);
			if (dtrace_setopt(jc->dtjj_consumer->dtjc_dtp, opt,
			    val) == -1) {
				/* Do not wrap DTraceException */
				dtj_throw_dtrace_exception(jc,
				    "failed to set %s: %s", opt,
				    dtrace_errmsg(jc->dtjj_consumer->dtjc_dtp,
				    dtrace_errno(jc->dtjj_consumer->dtjc_dtp)));
				dtj_request_destroy(r, NULL);
				(void) pthread_mutex_unlock(list_lock);
				return (DTJ_ERR);
			}
			break;
		}
		dtj_request_destroy(r, NULL);
	}
	(void) pthread_mutex_unlock(list_lock);
	return (DTJ_OK);
}

/*
 * Return DTJ_OK if the consumer loop is stopped normally by either the exit()
 * action or the Consumer stop() method.  Otherwise return DTJ_ERR if the
 * consumer loop terminates abnormally with an exception pending.
 */
dtj_status_t
dtj_consume(dtj_java_consumer_t *jc)
{
	JNIEnv *jenv = jc->dtjj_jenv;
	dtrace_hdl_t *dtp = jc->dtjj_consumer->dtjc_dtp;
	boolean_t done = B_FALSE;
	dtj_error_t e;

	do {
		if (!jc->dtjj_consumer->dtjc_interrupt) {
			dtrace_sleep(dtp);
		}

		if (jc->dtjj_consumer->dtjc_interrupt) {
			done = B_TRUE;
			dtj_stop(jc);
			if ((*jenv)->ExceptionCheck(jenv)) {
				/*
				 * Exception left pending by Consumer
				 * getAggregate() method.
				 */
				return (DTJ_ERR);
			}
		} else if (jc->dtjj_consumer->dtjc_process_list != NULL) {
			int nprocs = uu_list_numnodes(jc->dtjj_consumer->
			    dtjc_process_list);
			if (jc->dtjj_consumer->dtjc_procs_ended == nprocs) {
				done = B_TRUE;
				dtj_stop(jc);
			}
		}

		/*
		 * Functions like dtrace_setopt() are not safe to call during
		 * dtrace_sleep().  Check the request list every time we wake up
		 * from dtrace_sleep().
		 */
		if (!done) {
			if (dtj_process_requests(jc) != DTJ_OK) {
				/* Do not wrap DTraceException */
				return (DTJ_ERR);
			}
		}

		/* Must not call MonitorEnter with a pending exception */
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTJ_ERR);
		}

		/*
		 * Use the per-consumer lock to avoid conflict with
		 * get_aggregate() called from another thread.
		 */
		(*jenv)->MonitorEnter(jenv, jc->dtjj_consumer_lock);
		if ((*jenv)->ExceptionCheck(jenv)) {
			WRAP_EXCEPTION(jenv);
			return (DTJ_ERR);
		}
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_caller,
		    g_interval_began_jm);
		if ((*jenv)->ExceptionCheck(jenv)) {
			/* Don't wrap exception thrown from ConsumerListener */
			(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
			return (DTJ_ERR);
		}
		jc->dtjj_consumer->dtjc_printa_snaptime = gethrtime();
		switch (dtrace_work(dtp, NULL, dtj_chew, dtj_chewrec, jc)) {
		case DTRACE_WORKSTATUS_DONE:
			done = B_TRUE;
			break;
		case DTRACE_WORKSTATUS_OKAY:
			break;
		default:
			/*
			 * Check for a pending exception that got us to this
			 * error workstatus case.
			 */
			if ((*jenv)->ExceptionCheck(jenv)) {
				/*
				 * Ensure valid initial state before releasing
				 * the consumer lock
				 */
				jc->dtjj_consumer->dtjc_printa_snaptime = 0;
				/* Do not wrap DTraceException */
				/* Release per-consumer lock */
				(*jenv)->MonitorExit(jenv,
				    jc->dtjj_consumer_lock);
				return (DTJ_ERR);
			}

			if (dtj_get_dtrace_error(jc, &e) != DTJ_OK) {
				/* java exception pending */
				jc->dtjj_consumer->dtjc_printa_snaptime = 0;
				/* Release per-consumer lock */
				(*jenv)->MonitorExit(jenv,
				    jc->dtjj_consumer_lock);
				return (DTJ_ERR);
			}

			if (e.dtje_number != EINTR) {
				/* Do not wrap DTraceException */
				dtj_throw_dtrace_exception(jc, e.dtje_message);
				jc->dtjj_consumer->dtjc_printa_snaptime = 0;
				/* Release per-consumer lock */
				(*jenv)->MonitorExit(jenv,
				    jc->dtjj_consumer_lock);
				return (DTJ_ERR);
			}
		}
		/*
		 * Check for ConsumerException before doing anything else with
		 * the JNIEnv.
		 */
		if ((*jenv)->ExceptionCheck(jenv)) {
			/*
			 * Do not wrap exception thrown from ConsumerListener.
			 */
			jc->dtjj_consumer->dtjc_printa_snaptime = 0;
			/* Release per-consumer lock */
			(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
			return (DTJ_ERR);
		}
		jc->dtjj_consumer->dtjc_printa_snaptime = 0;
		/*
		 * Notify ConsumerListeners the the dtrace_work() interval ended
		 * before releasing the lock.
		 */
		(*jenv)->CallVoidMethod(jenv, jc->dtjj_caller,
		    g_interval_ended_jm);
		(*jenv)->MonitorExit(jenv, jc->dtjj_consumer_lock);
		if ((*jenv)->ExceptionCheck(jenv)) {
			/* Don't wrap exception thrown from ConsumerListener */
			return (DTJ_ERR);
		}

		/*
		 * Check for a temporarily cleared exception set by a handler
		 * that could not safely leave the exception pending because it
		 * could not return an abort signal.  Rethrow it now that it's
		 * safe to do so (when it's possible to ensure that no JNI calls
		 * will be made that are unsafe while an exception is pending).
		 */
		if (jc->dtjj_exception) {
			(*jenv)->Throw(jenv, jc->dtjj_exception);
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_exception);
			jc->dtjj_exception = NULL;
			return (DTJ_ERR);
		}
	} while (!done);

	return (DTJ_OK);
}
