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

#ifndef	_DTRACE_JNI_H
#define	_DTRACE_JNI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libuutil.h>
#include <jni.h>
#include <dtrace.h>
#include <dtj_util.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Java DTrace API native library */


/*
 * Thread-specific data key used to obtain JNI state specific to either the
 * consumer loop (calls dtrace_work()) or the getAggregate() method (calls
 * dtrace_aggregate_print()).
 */
extern pthread_key_t g_dtj_consumer_key;

typedef enum dtj_consumer_state {
	DTJ_CONSUMER_INIT,
	DTJ_CONSUMER_GO,
	DTJ_CONSUMER_START,
	DTJ_CONSUMER_STOP
} dtj_consumer_state_t;

typedef struct dtj_error {
	int dtje_number;		/* dtrace_errno() */
	const char *dtje_message;	/* dtrace_errmsg() */
} dtj_error_t;

/*
 * Identifies which function should handle a request dequeued after
 * dtrace_sleep().
 */
typedef enum dtj_request_type {
	DTJ_REQUEST_OPTION		/* set DTrace runtime option */
} dtj_request_type_t;

/*
 * A request made from Java (by native method call) that is unsafe to process
 * until just after the consumer loop wakes up from dtrace_sleep().
 */
typedef struct dtj_request {
	dtj_request_type_t dtjr_type;	/* request handler ID */
	uu_list_t *dtjr_args;		/* string args to request handler */
	uu_list_node_t dtjr_node;	/* points to next and prev requests */
} dtj_request_t;

typedef enum dtj_program_type {
	DTJ_PROGRAM_NONE,
	DTJ_PROGRAM_STRING,		/* dtrace_program_strcompile() */
	DTJ_PROGRAM_FILE		/* dtrace_program_fcompile() */
} dtj_program_type_t;

/* Identifier and description of a compiled DTrace program */
typedef struct dtj_program {
	dtj_program_type_t dtjp_type;	/* string or file */
	const char *dtjp_name;		/* string or filename for err msg */
	dtrace_prog_t *dtjp_program;	/* libdtrace program handle */
	dtrace_proginfo_t dtjp_info;	/* program attributes */
	boolean_t dtjp_enabled;		/* dtrace_program_exec() flag */
	uu_list_node_t dtjp_node;	/* points to next and prev programs */
} dtj_program_t;

/*
 * An entry used to maintain the association between the value of an aggregating
 * action (such as count()) and the aggregation to which the value belongs until
 * all the data associated with a single tuple is available to the callback
 * handler.
 */
typedef struct dtj_aggval {
	jobject dtja_value;		/* value of aggregating action */
	const char *dtja_aggname;	/* aggregation name */
	int64_t dtja_aggid;		/* libdtrace aggregation ID */
	uu_list_node_t dtja_node;	/* points to next and prev aggvals */
} dtj_aggval_t;

/*
 * Per-consumer state, including the libdtrace consumer handle, is valid across
 * multiple threads.  One consumer entry is added to a global table per
 * dtrace_open().
 */
typedef struct dtj_consumer {
	/* Consumer state */

	dtrace_hdl_t *dtjc_dtp;		/* libdtrace consumer handle */
	uu_list_t *dtjc_program_list;	/* program_t list */
	uu_list_t *dtjc_process_list;	/* proc handle list */

	/*
	 * Count of processes that have ended.  The consumer is stopped when
	 * this count equals the number of outstanding target processes and
	 * grabbed processes (see the Java Consumer createProcess() and
	 * grabProcess() methods).
	 */
	int dtjc_procs_ended;

	/*
	 * Bit-field passed to dtrace_program_strcompile() and
	 * dtrace_program_fcompile() containing compile flags.  The flags are
	 * set from Java by the setOption() Consumer method (just like the
	 * runtime options handled by dtrace_setopt(), except that they must be
	 * set before program compilation to have any effect).
	 */
	uint_t dtjc_cflags;

	boolean_t dtjc_flow;	/* current value of the flowindent option */
	dtj_consumer_state_t dtjc_state; /* execution state */
	boolean_t dtjc_interrupt;	/* flag that stops consumer */

	/* Pending requests */
	uu_list_t *dtjc_request_list;	/* request_t queue */
	pthread_mutex_t dtjc_request_list_lock;


	/* Cached for optimization and for use across functions */

	/*
	 * Nanosecond timestamp cached in the consumer loop just before
	 * dtrace_work().  The timestamp is applied to each Java PrintaRecord
	 * generated in that iteration of the consumer loop.  A value of zero
	 * indicates that we are not in the consumer loop, but that the
	 * callback was triggered instead by the Consumer getAggregate() method
	 * (from dtrace_aggregate_print()).
	 */
	hrtime_t dtjc_printa_snaptime;

	/*
	 * The aggregation ID is used to optimize aggregation inclusion by
	 * testing for inclusion only when the aggregation has changed.
	 */
	int64_t dtjc_aggid;
	boolean_t dtjc_included;

	/*
	 * The expected tuple member count is used to determine whether or not
	 * the aggregation tuple values are completely specified in the printa()
	 * format string.
	 */
	int dtjc_expected;

	int dtjc_probedata_rec_i;	/* probe data record index */

	/*
	 * The current DTrace action may apply across multiple libdtrace probe
	 * data records.
	 */
	dtrace_actkind_t dtjc_probedata_act;

	/* Placeholder used when listing probes */
	dtrace_ecbdesc_t *dtjc_last_probe;

	/* Function used by statement iterator when listing probes */
	dtrace_probe_f *dtjc_plistfunc;
} dtj_consumer_t;

/*
 * A view of a dtj_consumer_t that lasts only as long as a single native method
 * call.  This view attaches state needed for interaction with Java and specific
 * to the JNI.
 */
typedef struct dtj_java_consumer {
	/* Per-consumer state in global consumer table */
	dtj_consumer_t *dtjj_consumer;

	JNIEnv *dtjj_jenv;	/* Java environment pointer */
	jobject dtjj_caller;	/* Java Consumer to call back with probe data */

	/*
	 * Java Object references used across function boundaries, valid only
	 * within the current native method call.
	 */

	jobject dtjj_probedata;	/* instance of class ProbeData */

	/*
	 * StringBuffer used to concatenate buffered printa() output associated
	 * with the current tuple.
	 */
	jobject dtjj_printa_buffer;

	jobject dtjj_aggregate;	/* instance of class Aggregate */
	jobject dtjj_tuple;	/* instance of class Tuple */

	/*
	 * AggregationValue instances cached until we receive the
	 * DTRACE_BUFDATA_AGGLAST flag indicating the last callback associated
	 * with the current tuple.
	 */
	uu_list_t *dtjj_aggval_list;

	/* AggregateSpec used by get_aggregate() */
	jobject dtjj_aggregate_spec;

	jobject dtjj_probelist;	/* java.util.List returned by listProbes() */

	/*
	 * Exception temporarily cleared by callback handlers who cannot return
	 * a signal to abort the consumer.  At a safe point when the consumer
	 * loop gets control back from libdtrace, the exception is rethrown.
	 */
	jthrowable dtjj_exception;

	jobject dtjj_consumer_lock; /* per-consumer lock */

} dtj_java_consumer_t;

/*
 * Cache of jclass, jmethodID, and jfieldID values, usable across multiple
 * native method calls and multiple threads.  Caching all of them up front
 * rather than as-needed guarantees early detection of incorrect class, method,
 * or field definitions, and eliminates the need for test cases to cover
 * seldom-used definitions.
 *
 * Suffix conventions:
 *   jc  java class
 *   jm  java method
 *   jsm java static method
 *   jf  java field
 *   jsf java static field
 */

/* LocalConsumer */
extern jclass g_caller_jc;
extern jmethodID g_gethandle_jm;
extern jmethodID g_sethandle_jm;
extern jmethodID g_pdatanext_jm;
extern jmethodID g_drop_jm;
extern jmethodID g_error_jm;
extern jmethodID g_proc_jm;
extern jmethodID g_interval_began_jm;
extern jmethodID g_interval_ended_jm;
extern jfieldID g_consumer_lock_jf;

/* DTraceException */
extern jclass g_dtx_jc;
extern jmethodID g_dtxinit_jm;

/* InterfaceAttributes */
extern jclass g_attr_jc;
extern jmethodID g_attrinit_jm;
extern jmethodID g_attrset_name_jm;
extern jmethodID g_attrset_data_jm;
extern jmethodID g_attrset_class_jm;

/* ProbeDescription */
extern jclass g_probedesc_jc;
extern jmethodID g_probedescinit_jm;
extern jfieldID g_probedesc_id_jf;

/* ProbeInfo */
extern jclass g_probeinfo_jc;
extern jmethodID g_probeinfoinit_jm;

/* Probe */
extern jclass g_probe_jc;
extern jmethodID g_probeinit_jm;

/* Program */
extern jclass g_program_jc;
extern jmethodID g_proginit_jm;
extern jfieldID g_progid_jf;
extern jfieldID g_proginfo_jf;

/* Program.File */
extern jclass g_programfile_jc;
extern jmethodID g_fproginit_jm;

/* ProgramInfo */
extern jclass g_proginfo_jc;
extern jmethodID g_proginfoinit_jm;

/* Flow */
extern jclass g_flow_jc;
extern jmethodID g_flowinit_jm;

/* ProbeData */
extern jclass g_pdata_jc;
extern jmethodID g_pdatainit_jm;
extern jmethodID g_pdataadd_jm;
extern jmethodID g_pdataadd_rec_jm;
extern jmethodID g_pdataadd_trace_jm;
extern jmethodID g_pdataadd_stack_jm;
extern jmethodID g_pdataadd_symbol_jm;
extern jmethodID g_pdataadd_printf_jm;
extern jmethodID g_pdataadd_printa_jm;
extern jmethodID g_pdatainvalidate_printa_jm;
extern jmethodID g_pdataadd_aggrec_jm;
extern jmethodID g_pdataadd_printa_str_jm;
extern jmethodID g_pdataadd_exit_jm;
extern jmethodID g_pdataattach_jm;
extern jmethodID g_pdataset_formatted_jm;
extern jmethodID g_pdataclear_jm;

/* Drop */
extern jclass g_drop_jc;
extern jmethodID g_dropinit_jm;

/* Error */
extern jclass g_error_jc;
extern jmethodID g_errinit_jm;

/* ProcessState */
extern jclass g_process_jc;
extern jmethodID g_procinit_jm;
extern jmethodID g_procexit_jm;

/* Aggregate */
extern jclass g_agg_jc;
extern jmethodID g_agginit_jm;
extern jmethodID g_aggaddrec_jm;

/* AggregateSpec */
extern jclass g_aggspec_jc;
extern jmethodID g_aggspec_included_jm;
extern jmethodID g_aggspec_cleared_jm;

/* Tuple */
extern jclass g_tuple_jc;
extern jmethodID g_tupleinit_jm;
extern jmethodID g_tupleadd_jm;
extern jmethodID g_tuplesize_jm;
extern jfieldID g_tuple_EMPTY_jsf;

/* AggregationRecord */
extern jclass g_aggrec_jc;
extern jmethodID g_aggrecinit_jm;
extern jmethodID g_aggrecget_tuple_jm;

/* SumValue */
extern jclass g_aggsum_jc;
extern jmethodID g_aggsuminit_jm;

/* CountValue */
extern jclass g_aggcount_jc;
extern jmethodID g_aggcountinit_jm;

/* AvgValue */
extern jclass g_aggavg_jc;
extern jmethodID g_aggavginit_jm;

/* MinValue */
extern jclass g_aggmin_jc;
extern jmethodID g_aggmininit_jm;

/* MaxValue */
extern jclass g_aggmax_jc;
extern jmethodID g_aggmaxinit_jm;

/* StddevValue */
extern jclass g_aggstddev_jc;
extern jmethodID g_aggstddevinit_jm;

/* KernelStackRecord */
extern jclass g_stack_jc;
extern jmethodID g_parsestack_jsm;
extern jmethodID g_stackinit_jm;
extern jmethodID g_stackset_frames_jm;

/* UserStackRecord */
extern jclass g_ustack_jc;
extern jmethodID g_ustackinit_jm;
extern jmethodID g_ustackset_frames_jm;

/* Distribution */
extern jclass g_adist_jc;
extern jmethodID g_dist_normal_jm;

/* LogDistribution */
extern jclass g_dist_jc;
extern jmethodID g_distinit_jm;

/* LinearDistribution */
extern jclass g_ldist_jc;
extern jmethodID g_ldistinit_jm;

/* KernelSymbolRecord */
extern jclass g_symbol_jc;
extern jmethodID g_symbolinit_jm;
extern jmethodID g_symbolset_name_jm;

/* UserSymbolRecord */
extern jclass g_usymbol_jc;
extern jmethodID g_usymbolinit_jm;
extern jmethodID g_usymbolset_name_jm;

/* ScalarRecord */
extern jclass g_scalar_jc;
extern jmethodID g_scalarinit_jm;

/*
 * Populates the java class references and associated method and field IDs
 * declared in this file (above).
 *
 * Throws NoClassDefFoundError, NoSuchMethodError, or NoSuchFieldError if any
 * dtj_table_entry_t in dtj_jnitab.c is incorrect.
 */
extern dtj_status_t dtj_load(JNIEnv *);

/*
 * Functions that create a structure return NULL if out of memory.  A Java
 * OutOfMemoryError is pending in that case.
 */
extern dtj_request_t *dtj_request_create(JNIEnv *, dtj_request_type_t, ...);
extern dtj_program_t *dtj_program_create(JNIEnv *, dtj_program_type_t,
    const char *);
extern dtj_aggval_t *dtj_aggval_create(JNIEnv *, jobject, const char *,
    int64_t);

/*
 * uu_list_t element destructors' signatures match uuwrap_value_destroy_f
 */
extern void dtj_request_destroy(void *, void *); /* expects NULL user arg */
extern void dtj_program_destroy(void *, void *); /* expects NULL user arg */
extern void dtj_aggval_destroy(void *, void *);	/* expects JNIEnv * user arg */

/* Allocates and frees per-consumer state kept in the global consumer table */
extern dtj_consumer_t *dtj_consumer_create(JNIEnv *);
extern void dtj_consumer_destroy(dtj_consumer_t *);

/* Sets callback handlers before calling dtrace_go() */
extern dtj_status_t dtj_set_callback_handlers(dtj_java_consumer_t *);

/*
 * Initializes Java Object references cached across multiple functions called
 * within the consumer loop.  Deletes the references after exiting the consumer
 * loop.  It is only necessary to initialize and finalize a dtj_java_consumer_t
 * if the native method call will enter the consumer loop.
 */
extern dtj_status_t dtj_java_consumer_init(JNIEnv *, dtj_java_consumer_t *);
extern void dtj_java_consumer_fini(JNIEnv *, dtj_java_consumer_t *);

/*
 * Throws a DTraceException with a message constructed from the given format
 * string and variable arg list.
 */
extern void dtj_throw_dtrace_exception(dtj_java_consumer_t *,
    const char *, ...);

/* Returns NULL if pending Java Exception or OutOfMemoryError */
extern jobject dtj_new_probedesc(dtj_java_consumer_t *,
    const dtrace_probedesc_t *);
extern jobject dtj_new_probeinfo(dtj_java_consumer_t *,
    const dtrace_probeinfo_t *);
extern jobject dtj_new_attribute(dtj_java_consumer_t *,
    const dtrace_attribute_t *);

/*
 * Returns NULL if the given fault is unrecognized, otherwise returns the name
 * of the fault, guaranteed not to change across multiple versions of this API
 * even if the integer value changes in libdtrace.
 */
extern const char *dtj_get_fault_name(int);

/* Gets the libdtrace error number and message */
extern dtj_status_t dtj_get_dtrace_error(dtj_java_consumer_t *, dtj_error_t *);

/* Stops the DTrace consumer */
extern void dtj_stop(dtj_java_consumer_t *);

/*
 * The Consumer getAggregate() method runs in the caller's current thread
 * separate from the consumer loop.
 */
extern jobject dtj_get_aggregate(dtj_java_consumer_t *);

/*
 * A blocking call that runs the consumer loop.  If this function returns an
 * error status, it is necessary to call stop() in order to dtrace_stop() the
 * consumer in libdtrace (it is safe to call stop() in either case).
 */
extern dtj_status_t dtj_consume(dtj_java_consumer_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DTRACE_JNI_H */
