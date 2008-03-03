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

#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <strings.h>
#include <pthread.h>
#include <dtrace_jni.h>

/*
 * dtj_jnitab.c defines the JNI table of classes, methods, and fields belonging
 * to the Java DTrace API.  Another JNI table defining classes from the JDK is
 * defined in dtj_util.c.  Utility functions specific to the Java DTrace API are
 * also defined here, while general utilities are defined in dtj_util.c.
 */

static uu_list_pool_t *g_request_pool = NULL;
static uu_list_pool_t *g_program_pool = NULL;
static uu_list_pool_t *g_aggval_pool = NULL;

static boolean_t dtj_check_request_pool(void);
static boolean_t dtj_check_program_pool(void);
static boolean_t dtj_check_aggval_pool(void);

/* LocalConsumer */
jclass g_caller_jc = 0;
jmethodID g_gethandle_jm = 0;
jmethodID g_sethandle_jm = 0;
jmethodID g_pdatanext_jm = 0;
jmethodID g_drop_jm = 0;
jmethodID g_error_jm = 0;
jmethodID g_proc_jm = 0;
jmethodID g_interval_began_jm = 0;
jmethodID g_interval_ended_jm = 0;
jfieldID g_consumer_lock_jf = 0;

/* DTraceException */
jclass g_dtx_jc = 0;
jmethodID g_dtxinit_jm = 0;

/* InterfaceAttributes */
jclass g_attr_jc = 0;
jmethodID g_attrinit_jm = 0;
jmethodID g_attrset_name_jm = 0;
jmethodID g_attrset_data_jm = 0;
jmethodID g_attrset_class_jm = 0;

/* ProbeDescription */
jclass g_probedesc_jc = 0;
jmethodID g_probedescinit_jm = 0;
jfieldID g_probedesc_id_jf = 0;

/* ProbeInfo */
jclass g_probeinfo_jc = 0;
jmethodID g_probeinfoinit_jm = 0;

/* Probe */
jclass g_probe_jc = 0;
jmethodID g_probeinit_jm = 0;

/* Program */
jclass g_program_jc = 0;
jmethodID g_proginit_jm = 0;
jfieldID g_progid_jf = 0;
jfieldID g_proginfo_jf = 0;

/* Program.File */
jclass g_programfile_jc = 0;
jmethodID g_fproginit_jm = 0;

/* ProgramInfo */
jclass g_proginfo_jc = 0;
jmethodID g_proginfoinit_jm = 0;

/* Flow */
jclass g_flow_jc = 0;
jmethodID g_flowinit_jm = 0;

/* ProbeData */
jclass g_pdata_jc = 0;
jmethodID g_pdatainit_jm = 0;
jmethodID g_pdataadd_jm = 0;
jmethodID g_pdataadd_rec_jm = 0;
jmethodID g_pdataadd_trace_jm = 0;
jmethodID g_pdataadd_stack_jm = 0;
jmethodID g_pdataadd_symbol_jm = 0;
jmethodID g_pdataadd_printf_jm = 0;
jmethodID g_pdataadd_printa_jm = 0;
jmethodID g_pdatainvalidate_printa_jm = 0;
jmethodID g_pdataadd_aggrec_jm = 0;
jmethodID g_pdataadd_printa_str_jm = 0;
jmethodID g_pdataadd_exit_jm = 0;
jmethodID g_pdataattach_jm = 0;
jmethodID g_pdataset_formatted_jm = 0;
jmethodID g_pdataclear_jm = 0;

/* Drop */
jclass g_drop_jc = 0;
jmethodID g_dropinit_jm = 0;

/* Error */
jclass g_error_jc = 0;
jmethodID g_errinit_jm = 0;

/* ProcessState */
jclass g_process_jc = 0;
jmethodID g_procinit_jm = 0;
jmethodID g_procexit_jm = 0;

/* Aggregate */
jclass g_agg_jc = 0;
jmethodID g_agginit_jm = 0;
jmethodID g_aggaddrec_jm = 0;

/* AggregateSpec */
jclass g_aggspec_jc = 0;
jmethodID g_aggspec_included_jm = 0;
jmethodID g_aggspec_cleared_jm = 0;

/* Tuple */
jclass g_tuple_jc = 0;
jmethodID g_tupleinit_jm = 0;
jmethodID g_tupleadd_jm = 0;
jmethodID g_tuplesize_jm = 0;
jfieldID g_tuple_EMPTY_jsf = 0;

/* AggregationRecord */
jclass g_aggrec_jc = 0;
jmethodID g_aggrecinit_jm = 0;
jmethodID g_aggrecget_tuple_jm = 0;

/* SumValue */
jclass g_aggsum_jc = 0;
jmethodID g_aggsuminit_jm = 0;

/* CountValue */
jclass g_aggcount_jc = 0;
jmethodID g_aggcountinit_jm = 0;

/* AvgValue */
jclass g_aggavg_jc = 0;
jmethodID g_aggavginit_jm = 0;

/* MinValue */
jclass g_aggmin_jc = 0;
jmethodID g_aggmininit_jm = 0;

/* MaxValue */
jclass g_aggmax_jc = 0;
jmethodID g_aggmaxinit_jm = 0;

/* StddevValue */
jclass g_aggstddev_jc = 0;
jmethodID g_aggstddevinit_jm = 0;

/* KernelStackRecord */
jclass g_stack_jc = 0;
jmethodID g_parsestack_jsm = 0;
jmethodID g_stackinit_jm = 0;
jmethodID g_stackset_frames_jm = 0;

/* UserStackRecord */
jclass g_ustack_jc = 0;
jmethodID g_ustackinit_jm = 0;
jmethodID g_ustackset_frames_jm = 0;

/* Distribution */
jclass g_adist_jc = 0;
jmethodID g_dist_normal_jm = 0;

/* LogDistribution */
jclass g_dist_jc = 0;
jmethodID g_distinit_jm = 0;

/* LinearDistribution */
jclass g_ldist_jc = 0;
jmethodID g_ldistinit_jm = 0;

/* KernelSymbolRecord */
jclass g_symbol_jc = 0;
jmethodID g_symbolinit_jm = 0;
jmethodID g_symbolset_name_jm = 0;

/* UserSymbolRecord */
jclass g_usymbol_jc = 0;
jmethodID g_usymbolinit_jm = 0;
jmethodID g_usymbolset_name_jm = 0;

/* ScalarRecord */
jclass g_scalar_jc = 0;
jmethodID g_scalarinit_jm = 0;


static dtj_status_t
dtj_table_load(JNIEnv *jenv)
{
	/*
	 * If you change this table, increment DTRACE_JNI_VERSION in
	 * dtrace_jni.c.
	 */
	static const dtj_table_entry_t table[] = {
		/* LocalConsumer */
		{ JCLASS,  &g_caller_jc,
			"org/opensolaris/os/dtrace/LocalConsumer" },
		{ JMETHOD, &g_gethandle_jm, "getHandle", "()I" },
		{ JMETHOD, &g_sethandle_jm, "setHandle", "(I)V" },
		{ JMETHOD, &g_pdatanext_jm, "nextProbeData",
			"(Lorg/opensolaris/os/dtrace/ProbeData;)V" },
		{ JMETHOD, &g_drop_jm, "dataDropped",
			"(Lorg/opensolaris/os/dtrace/Drop;)V" },
		{ JMETHOD, &g_error_jm, "errorEncountered",
			"(Lorg/opensolaris/os/dtrace/Error;)V" },
		{ JMETHOD, &g_proc_jm, "processStateChanged",
			"(Lorg/opensolaris/os/dtrace/ProcessState;)V" },
		{ JMETHOD, &g_interval_began_jm, "intervalBegan", "()V" },
		{ JMETHOD, &g_interval_ended_jm, "intervalEnded", "()V" },
		{ JFIELD,  &g_consumer_lock_jf, "consumerLock",
			"Ljava/lang/Object;" },

		/* DTraceException */
		{ JCLASS,  &g_dtx_jc,
			"org/opensolaris/os/dtrace/DTraceException" },
		{ JMETHOD, &g_dtxinit_jm, CONSTRUCTOR,
			"(Ljava/lang/String;)V" },

		/* InterfaceAttributes */
		{ JCLASS,  &g_attr_jc,
			"org/opensolaris/os/dtrace/InterfaceAttributes" },
		{ JMETHOD, &g_attrinit_jm, CONSTRUCTOR, "()V" },
		{ JMETHOD, &g_attrset_name_jm, "setNameStability",
			"(Ljava/lang/String;)V" },
		{ JMETHOD, &g_attrset_data_jm, "setDataStability",
			"(Ljava/lang/String;)V" },
		{ JMETHOD, &g_attrset_class_jm, "setDependencyClass",
			"(Ljava/lang/String;)V" },

		/* ProbeDescription */
		{ JCLASS,  &g_probedesc_jc,
			"org/opensolaris/os/dtrace/ProbeDescription" },
		{ JMETHOD, &g_probedescinit_jm, CONSTRUCTOR,
			"(Ljava/lang/String;Ljava/lang/String;"
			    "Ljava/lang/String;Ljava/lang/String;)V" },
		{ JFIELD,  &g_probedesc_id_jf, "id", "I" },

		/* ProbeInfo */
		{ JCLASS,  &g_probeinfo_jc,
			"org/opensolaris/os/dtrace/ProbeInfo" },
		{ JMETHOD, &g_probeinfoinit_jm, CONSTRUCTOR,
			"(Lorg/opensolaris/os/dtrace/InterfaceAttributes;"
			    "Lorg/opensolaris/os/dtrace/InterfaceAttributes;"
			    ")V" },

		/* Probe */
		{ JCLASS,  &g_probe_jc, "org/opensolaris/os/dtrace/Probe" },
		{ JMETHOD, &g_probeinit_jm, CONSTRUCTOR,
			"(Lorg/opensolaris/os/dtrace/ProbeDescription;"
			    "Lorg/opensolaris/os/dtrace/ProbeInfo;)V" },

		/* Program */
		{ JCLASS,  &g_program_jc,
			"org/opensolaris/os/dtrace/Program" },
		{ JMETHOD, &g_proginit_jm, CONSTRUCTOR, "()V" },
		{ JFIELD,  &g_progid_jf, "id", "I" },
		{ JFIELD,  &g_proginfo_jf, "info",
			"Lorg/opensolaris/os/dtrace/ProgramInfo;" },

		/* Program.File */
		{ JCLASS,  &g_programfile_jc,
			"org/opensolaris/os/dtrace/Program$File" },
		{ JMETHOD, &g_fproginit_jm, CONSTRUCTOR, "()V" },

		/* ProgramInfo */
		{ JCLASS,  &g_proginfo_jc,
			"org/opensolaris/os/dtrace/ProgramInfo" },
		{ JMETHOD, &g_proginfoinit_jm, CONSTRUCTOR,
			"(Lorg/opensolaris/os/dtrace/InterfaceAttributes;"
			    "Lorg/opensolaris/os/dtrace/InterfaceAttributes;"
			    "I)V" },

		/* Flow */
		{ JCLASS,  &g_flow_jc, "org/opensolaris/os/dtrace/Flow" },
		{ JMETHOD, &g_flowinit_jm, CONSTRUCTOR,
			"(Ljava/lang/String;I)V" },

		/* ProbeData */
		{ JCLASS,  &g_pdata_jc,
			"org/opensolaris/os/dtrace/ProbeData" },
		{ JMETHOD, &g_pdatainit_jm, CONSTRUCTOR,
			"(IILorg/opensolaris/os/dtrace/ProbeDescription;"
			    "Lorg/opensolaris/os/dtrace/Flow;I)V" },
		{ JMETHOD, &g_pdataadd_jm, "addDataElement",
			"(Lorg/opensolaris/os/dtrace/Record;)V" },
		{ JMETHOD, &g_pdataadd_rec_jm, "addRecord",
			"(Lorg/opensolaris/os/dtrace/Record;)V" },
		{ JMETHOD, &g_pdataadd_trace_jm, "addTraceRecord", "(I)V" },
		{ JMETHOD, &g_pdataadd_stack_jm, "addStackRecord",
			"(ILjava/lang/String;)V" },
		{ JMETHOD, &g_pdataadd_symbol_jm, "addSymbolRecord",
			"(ILjava/lang/String;)V" },
		{ JMETHOD, &g_pdataadd_printf_jm, "addPrintfRecord", "()V" },
		{ JMETHOD, &g_pdataadd_printa_jm, "addPrintaRecord", "(JZ)V" },
		{ JMETHOD, &g_pdatainvalidate_printa_jm,
			"invalidatePrintaRecord", "()V" },
		{ JMETHOD, &g_pdataadd_aggrec_jm, "addAggregationRecord",
			"(Ljava/lang/String;J"
			    "Lorg/opensolaris/os/dtrace/AggregationRecord;)V" },
		{ JMETHOD, &g_pdataadd_printa_str_jm,
			"addPrintaFormattedString",
			"(Lorg/opensolaris/os/dtrace/Tuple;"
			    "Ljava/lang/String;)V" },
		{ JMETHOD, &g_pdataadd_exit_jm, "addExitRecord", "(I)V" },
		{ JMETHOD, &g_pdataattach_jm, "attachRecordElements",
			"(II)V" },
		{ JMETHOD, &g_pdataset_formatted_jm, "setFormattedString",
			"(Ljava/lang/String;)V" },
		{ JMETHOD, &g_pdataclear_jm, "clearNativeElements", "()V" },

		/* Drop */
		{ JCLASS,  &g_drop_jc, "org/opensolaris/os/dtrace/Drop" },
		{ JMETHOD, &g_dropinit_jm, CONSTRUCTOR,
			"(ILjava/lang/String;JJLjava/lang/String;)V" },

		/* Error */
		{ JCLASS,  &g_error_jc, "org/opensolaris/os/dtrace/Error" },
		{ JMETHOD, &g_errinit_jm, CONSTRUCTOR,
			"(Lorg/opensolaris/os/dtrace/ProbeDescription;IIII"
			    "Ljava/lang/String;JLjava/lang/String;)V" },

		/* ProcessState */
		{ JCLASS,  &g_process_jc,
			"org/opensolaris/os/dtrace/ProcessState" },
		{ JMETHOD, &g_procinit_jm, CONSTRUCTOR,
			"(ILjava/lang/String;ILjava/lang/String;"
			    "Ljava/lang/Integer;Ljava/lang/String;)V" },
		{ JMETHOD, &g_procexit_jm, "setExitStatus", "(I)V" },

		/* Aggregate */
		{ JCLASS,  &g_agg_jc, "org/opensolaris/os/dtrace/Aggregate" },
		{ JMETHOD, &g_agginit_jm, CONSTRUCTOR, "(J)V" },
		{ JMETHOD, &g_aggaddrec_jm, "addRecord",
		    "(Ljava/lang/String;J"
			"Lorg/opensolaris/os/dtrace/AggregationRecord;)V" },

		/* AggregateSpec */
		{ JCLASS,  &g_aggspec_jc,
			"org/opensolaris/os/dtrace/AggregateSpec" },
		{ JMETHOD, &g_aggspec_included_jm, "isIncluded",
			"(Ljava/lang/String;)Z" },
		{ JMETHOD, &g_aggspec_cleared_jm, "isCleared",
			"(Ljava/lang/String;)Z" },

		/* Tuple */
		{ JCLASS,  &g_tuple_jc, "org/opensolaris/os/dtrace/Tuple" },
		{ JMETHOD, &g_tupleinit_jm, CONSTRUCTOR, "()V" },
		{ JMETHOD, &g_tupleadd_jm, "addElement",
			"(Lorg/opensolaris/os/dtrace/ValueRecord;)V" },
		{ JMETHOD, &g_tuplesize_jm, "size", "()I" },
		{ JFIELD_STATIC, &g_tuple_EMPTY_jsf, "EMPTY",
			"Lorg/opensolaris/os/dtrace/Tuple;" },

		/* AggregationRecord */
		{ JCLASS,  &g_aggrec_jc,
			"org/opensolaris/os/dtrace/AggregationRecord" },
		{ JMETHOD, &g_aggrecinit_jm, CONSTRUCTOR,
			"(Lorg/opensolaris/os/dtrace/Tuple;"
			    "Lorg/opensolaris/os/dtrace/AggregationValue;)V" },
		{ JMETHOD, &g_aggrecget_tuple_jm, "getTuple",
			"()Lorg/opensolaris/os/dtrace/Tuple;" },

		/* SumValue */
		{ JCLASS,  &g_aggsum_jc,
			"org/opensolaris/os/dtrace/SumValue" },
		{ JMETHOD, &g_aggsuminit_jm, CONSTRUCTOR, "(J)V" },

		/* CountValue */
		{ JCLASS,  &g_aggcount_jc,
			"org/opensolaris/os/dtrace/CountValue" },
		{ JMETHOD, &g_aggcountinit_jm, CONSTRUCTOR, "(J)V" },

		/* AvgValue */
		{ JCLASS,  &g_aggavg_jc,
			"org/opensolaris/os/dtrace/AvgValue" },
		{ JMETHOD, &g_aggavginit_jm, CONSTRUCTOR, "(JJJ)V" },

		/* MinValue */
		{ JCLASS,  &g_aggmin_jc,
			"org/opensolaris/os/dtrace/MinValue" },
		{ JMETHOD, &g_aggmininit_jm, CONSTRUCTOR, "(J)V" },

		/* MaxValue */
		{ JCLASS,  &g_aggmax_jc,
			"org/opensolaris/os/dtrace/MaxValue" },
		{ JMETHOD, &g_aggmaxinit_jm, CONSTRUCTOR, "(J)V" },

		/* StddevValue */
		{ JCLASS,  &g_aggstddev_jc,
			"org/opensolaris/os/dtrace/StddevValue" },
		{ JMETHOD, &g_aggstddevinit_jm, CONSTRUCTOR,
			"(JJLjava/math/BigInteger;)V" },

		/* KernelStackRecord */
		{ JCLASS,  &g_stack_jc,
			"org/opensolaris/os/dtrace/KernelStackRecord" },
		{ JMETHOD_STATIC, &g_parsestack_jsm, "parse",
			"(Ljava/lang/String;)"
			    "[Lorg/opensolaris/os/dtrace/StackFrame;" },
		{ JMETHOD, &g_stackinit_jm, CONSTRUCTOR, "([B)V" },
		{ JMETHOD, &g_stackset_frames_jm, "setStackFrames",
			"([Lorg/opensolaris/os/dtrace/StackFrame;)V" },

		/* UserStackRecord */
		{ JCLASS,  &g_ustack_jc,
			"org/opensolaris/os/dtrace/UserStackRecord" },
		{ JMETHOD, &g_ustackinit_jm, CONSTRUCTOR, "(I[B)V" },
		{ JMETHOD, &g_ustackset_frames_jm, "setStackFrames",
			"([Lorg/opensolaris/os/dtrace/StackFrame;)V" },

		/* Distribution */
		{ JCLASS,  &g_adist_jc,
			"org/opensolaris/os/dtrace/Distribution" },
		{ JMETHOD, &g_dist_normal_jm, "normalizeBuckets", "(J)V" },

		/* LogDistribution */
		{ JCLASS,  &g_dist_jc,
			"org/opensolaris/os/dtrace/LogDistribution" },
		{ JMETHOD,  &g_distinit_jm, CONSTRUCTOR, "([J)V" },

		/* LinearDistribution */
		{ JCLASS,  &g_ldist_jc,
			"org/opensolaris/os/dtrace/LinearDistribution" },
		{ JMETHOD,  &g_ldistinit_jm, CONSTRUCTOR, "(JJ[J)V" },

		/* KernelSymbolRecord */
		{ JCLASS,  &g_symbol_jc,
			"org/opensolaris/os/dtrace/KernelSymbolRecord" },
		{ JMETHOD,  &g_symbolinit_jm, CONSTRUCTOR, "(J)V" },
		{ JMETHOD,  &g_symbolset_name_jm, "setSymbol",
			"(Ljava/lang/String;)V" },

		/* UserSymbolRecord */
		{ JCLASS,  &g_usymbol_jc,
			"org/opensolaris/os/dtrace/UserSymbolRecord" },
		{ JMETHOD,  &g_usymbolinit_jm, CONSTRUCTOR, "(IJ)V" },
		{ JMETHOD,  &g_usymbolset_name_jm, "setSymbol",
			"(Ljava/lang/String;)V" },

		/* ScalarRecord */
		{ JCLASS,  &g_scalar_jc,
			"org/opensolaris/os/dtrace/ScalarRecord" },
		{ JMETHOD,  &g_scalarinit_jm, CONSTRUCTOR,
			"(Ljava/lang/Object;I)V" },

		{ DTJ_TYPE_END }
	};

	return (dtj_cache_jni_classes(jenv, table));
}

dtj_status_t
dtj_load(JNIEnv *jenv)
{
	if (dtj_load_common(jenv) != DTJ_OK) {
		/* Java Error pending */
		return (DTJ_ERR);
	}

	return (dtj_table_load(jenv));
}

static boolean_t
dtj_check_request_pool(void)
{
	if (!g_request_pool) {
		g_request_pool = uu_list_pool_create("g_request_pool",
		    sizeof (dtj_request_t),
		    offsetof(dtj_request_t, dtjr_node),
		    dtj_pointer_list_entry_cmp,
		    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
		if (!g_request_pool) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

dtj_request_t *
dtj_request_create(JNIEnv *jenv, dtj_request_type_t type, ...)
{
	dtj_request_t *r;

	if (!dtj_check_request_pool()) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate request pool");
		return (NULL);
	}

	r = uu_zalloc(sizeof (dtj_request_t));
	if (r) {
		uu_list_node_init(r, &r->dtjr_node, g_request_pool);
		r->dtjr_type = type;
		r->dtjr_args = dtj_string_list_create();
		if (r->dtjr_args) {
			va_list ap;
			const char *arg;
			int i, len;

			va_start(ap, type);
			switch (type) {
			case DTJ_REQUEST_OPTION:
				len = 2;
				break;
			default:
				len = 0;
			}

			for (i = 0; i < len; ++i) {
				arg = va_arg(ap, char *);
				if (!dtj_string_list_add(r->dtjr_args, arg)) {
					dtj_throw_out_of_memory(jenv,
					    "Failed to add request arg");
					uu_list_node_fini(r, &r->dtjr_node,
					    g_request_pool);
					dtj_request_destroy(r, NULL);
					r = NULL;
				}
			}
			va_end(ap);
		} else {
			dtj_throw_out_of_memory(jenv,
			    "Failed to allocate request arglist");
			uu_list_node_fini(r, &r->dtjr_node, g_request_pool);
			dtj_request_destroy(r, NULL);
			r = NULL;
		}
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate request");
	}

	return (r);
}

static boolean_t
dtj_check_program_pool(void)
{
	if (!g_program_pool) {
		g_program_pool = uu_list_pool_create("g_program_pool",
		    sizeof (dtj_program_t),
		    offsetof(dtj_program_t, dtjp_node),
		    dtj_pointer_list_entry_cmp,
		    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
		if (!g_program_pool) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

dtj_program_t *
dtj_program_create(JNIEnv *jenv, dtj_program_type_t type, const char *name)
{
	dtj_program_t *p;

	if (!dtj_check_program_pool()) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate program pool");
		return (NULL);
	}

	p = uu_zalloc(sizeof (dtj_program_t));
	if (p) {
		char *program_name;

		uu_list_node_init(p, &p->dtjp_node, g_program_pool);
		p->dtjp_type = type;
		program_name = malloc((size_t)
		    (sizeof (char)) * (strlen(name) + 1));
		if (program_name) {
			(void) strcpy(program_name, name);
			p->dtjp_name = program_name;
			p->dtjp_enabled = B_FALSE;
		} else {
			dtj_throw_out_of_memory(jenv,
			    "Failed to allocate program name");
			uu_list_node_fini(p, &p->dtjp_node, g_program_pool);
			dtj_program_destroy(p, NULL);
			p = NULL;
		}
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate program");
	}

	return (p);
}

static boolean_t
dtj_check_aggval_pool(void)
{
	if (!g_aggval_pool) {
		g_aggval_pool = uu_list_pool_create("g_aggval_pool",
		    sizeof (dtj_aggval_t),
		    offsetof(dtj_aggval_t, dtja_node),
		    dtj_pointer_list_entry_cmp,
		    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
		if (!g_aggval_pool) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

dtj_aggval_t *
dtj_aggval_create(JNIEnv *jenv, jobject aggval, const char *aggname,
    int64_t aggid)
{
	dtj_aggval_t *e;

	if (!dtj_check_aggval_pool()) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate aggval entry pool");
		return (NULL);
	}

	e = uu_zalloc(sizeof (dtj_aggval_t));
	if (e) {
		char *a_name;

		uu_list_node_init(e, &e->dtja_node, g_aggval_pool);
		e->dtja_value = aggval;
		a_name = malloc((size_t)
		    (sizeof (char)) * (strlen(aggname) + 1));
		if (a_name) {
			(void) strcpy(a_name, aggname);
			e->dtja_aggname = a_name;
		} else {
			dtj_throw_out_of_memory(jenv,
			    "Failed to allocate aggregation name");
			uu_list_node_fini(e, &e->dtja_node, g_aggval_pool);
			/* caller responsible for input java reference */
			e->dtja_value = NULL;
			dtj_aggval_destroy(e, jenv);
			e = NULL;
		}
		e->dtja_aggid = aggid;
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate aggval entry");
	}

	return (e);
}

dtj_status_t
dtj_java_consumer_init(JNIEnv *jenv, dtj_java_consumer_t *jc)
{
	if (!dtj_check_aggval_pool()) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate aggval pool");
		return (DTJ_ERR);
	}

	jc->dtjj_aggval_list = uu_list_create(g_aggval_pool, NULL,
	    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
	if (!jc->dtjj_aggval_list) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate aggval list");
		return (DTJ_ERR);
	}

	/* Does not throw exceptions */
	jc->dtjj_consumer_lock = (*jenv)->GetObjectField(jenv, jc->dtjj_caller,
	    g_consumer_lock_jf);

	return (DTJ_OK);
}

void
dtj_java_consumer_fini(JNIEnv *jenv, dtj_java_consumer_t *jc)
{
	if (jc) {
		if (jc->dtjj_probedata) {
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_probedata);
			jc->dtjj_probedata = NULL;
		}
		if (jc->dtjj_printa_buffer) {
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_printa_buffer);
			jc->dtjj_printa_buffer = NULL;
		}
		if (jc->dtjj_aggregate) {
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_aggregate);
			jc->dtjj_aggregate = NULL;
		}
		if (jc->dtjj_tuple) {
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_tuple);
			jc->dtjj_tuple = NULL;
		}
		if (jc->dtjj_aggval_list) {
			dtj_list_destroy(jc->dtjj_aggval_list,
			    dtj_aggval_destroy, jenv);
			jc->dtjj_aggval_list = NULL;
		}

		/*
		 * aggregate_spec records an input argument to a native JNI
		 * function (a reference we did not create), so we are not
		 * responsible for it.
		 */
		jc->dtjj_aggregate_spec = NULL;

		/*
		 * probelist records an in-out argument to a native JNI function
		 * (a reference we did not create), so we are not responsible
		 * for it.
		 */
		jc->dtjj_probelist = NULL;

		if (jc->dtjj_exception) {
			(*jenv)->DeleteLocalRef(jenv, jc->dtjj_exception);
			jc->dtjj_exception = NULL;
		}
		(*jenv)->DeleteLocalRef(jenv, jc->dtjj_consumer_lock);
		jc->dtjj_consumer_lock = NULL;
	}
}

dtj_consumer_t *
dtj_consumer_create(JNIEnv *jenv)
{
	dtj_consumer_t *c;

	if (!dtj_check_request_pool()) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate request pool");
		return (NULL);
	}

	if (!dtj_check_program_pool()) {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate program pool");
		return (NULL);
	}

	c = uu_zalloc(sizeof (dtj_consumer_t));
	if (c) {
		c->dtjc_request_list = uu_list_create(g_request_pool, NULL,
		    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
		if (!c->dtjc_request_list) {
			dtj_throw_out_of_memory(jenv,
			    "Failed to allocate consumer request list");
			dtj_consumer_destroy(c);
			return (NULL);
		}
		(void) pthread_mutex_init(&c->dtjc_request_list_lock, NULL);

		c->dtjc_program_list = uu_list_create(g_program_pool, NULL,
		    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
		if (!c->dtjc_program_list) {
			dtj_throw_out_of_memory(jenv,
			    "Failed to allocate consumer program list");
			dtj_consumer_destroy(c);
			return (NULL);
		}

		c->dtjc_probedata_rec_i = 0;
		c->dtjc_probedata_act = DTRACEACT_NONE;
		c->dtjc_aggid = -1;
		c->dtjc_expected = -1;
		c->dtjc_state = DTJ_CONSUMER_INIT;
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate consumer");
	}

	return (c);
}

void
/* ARGSUSED */
dtj_request_destroy(void *v, void *arg)
{
	if (v) {
		dtj_request_t *r = v;
		dtj_string_list_destroy(r->dtjr_args);
		uu_list_node_fini(r, &r->dtjr_node, g_request_pool);
		bzero(v, sizeof (dtj_request_t));
		uu_free(v);
	}
}

void
/* ARGSUSED */
dtj_program_destroy(void *v, void *arg)
{
	if (v) {
		dtj_program_t *p = v;
		if (p->dtjp_name) {
			free((void *)p->dtjp_name);
		}
		uu_list_node_fini(p, &p->dtjp_node, g_program_pool);
		bzero(v, sizeof (dtj_program_t));
		uu_free(v);
	}
}

void
dtj_aggval_destroy(void *v, void *arg)
{
	if (v) {
		dtj_aggval_t *a = v;
		if (a->dtja_value && arg) {
			JNIEnv *jenv = arg;
			(*jenv)->DeleteLocalRef(jenv, a->dtja_value);
		}
		if (a->dtja_aggname) {
			free((void *)a->dtja_aggname);
		}
		uu_list_node_fini(a, &a->dtja_node, g_aggval_pool);
		bzero(v, sizeof (dtj_aggval_t));
		uu_free(v);
	}
}

/*
 * Frees per-consumer state.  Assumes that the DTrace handle has been closed
 * already.
 */
void
dtj_consumer_destroy(dtj_consumer_t *c)
{
	if (c) {
		dtj_list_destroy(c->dtjc_request_list, dtj_request_destroy,
		    NULL);
		(void) pthread_mutex_destroy(&c->dtjc_request_list_lock);
		dtj_list_destroy(c->dtjc_program_list, dtj_program_destroy,
		    NULL);
		/*
		 * Cannot dtrace_proc_release the c->process_list proc
		 * elements here, because we need the dtrace handle for that.
		 * By the time this destructor is called, the dtrace handle is
		 * already closed.  The proc elements are released in
		 * dtrace_jni.c _close().
		 */
		if (c->dtjc_process_list) {
			dtj_list_destroy(c->dtjc_process_list, NULL, NULL);
		}
		bzero(c, sizeof (dtj_consumer_t));
		uu_free(c);
	}
}

void
dtj_throw_dtrace_exception(dtj_java_consumer_t *jc, const char *fmt, ...)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	va_list ap;
	char msg[DTJ_MSG_SIZE];

	jobject message = NULL;
	jobject exception = NULL;

	va_start(ap, fmt);
	(void) vsnprintf(msg, sizeof (msg), fmt, ap);
	va_end(ap);

	message = dtj_NewStringNative(jenv, msg);
	if (!message) {
		return; /* java exception pending */
	}

	exception = (*jenv)->NewObject(jenv, g_dtx_jc, g_dtxinit_jm, message);
	(*jenv)->DeleteLocalRef(jenv, message);
	if (exception) {
		(*jenv)->Throw(jenv, exception);
		(*jenv)->DeleteLocalRef(jenv, exception);
	}
}
