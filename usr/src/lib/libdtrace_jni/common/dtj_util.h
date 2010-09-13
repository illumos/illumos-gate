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

#ifndef	_DTJ_UTIL_H
#define	_DTJ_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>
#include <libuutil.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * dtj_util.h separates functionality that is generally useful from
 * that which is specific to the Java DTrace API.  If moved to a separate
 * library, this functionality could be shared by other JNI wrappers.
 */

#ifdef JNI_VERSION_1_4
#define	JNI_VERSION JNI_VERSION_1_4
#else
#define	JNI_VERSION JNI_VERSION_1_2
#endif

#define	CONSTRUCTOR "<init>"
#define	DTJ_MSG_SIZE 1024
#define	DTJ_INVALID_PTR ((void *)-1)
#define	DTJ_INVALID_STR ((const char *)-1)

#define	WRAP_EXCEPTION(JENV)	dtj_wrap_exception((JENV), __FILE__, __LINE__)

extern boolean_t g_dtj_util_debug;

typedef enum dtj_status {
	DTJ_OK = JNI_OK,
	DTJ_ERR = JNI_ERR
} dtj_status_t;

typedef enum dtj_type {
	JCLASS,
	JMETHOD,
	JMETHOD_STATIC,
	JFIELD,
	JFIELD_STATIC,
	DTJ_TYPE_END = -1
} dtj_type_t;

/*
 * Convenient description format for java classes, methods, and fields.  The
 * java_class_t, java_method_t, and java_field_t structures derived from these
 * descriptions are used to create a table of usable JNI jclass, jmethodID, and
 * jfieldID instances.
 */
typedef struct dtj_table_entry {
	dtj_type_t djte_type;	/* JNI type */
	void *djte_addr;	/* jclass, jmethodID, or jfieldID address */
	char *djte_name;	/* symbol name declared in Java */
	char *djte_desc;	/* JNI descriptor (string format) */
} dtj_table_entry_t;

typedef struct dtj_java_class {
	jclass *djc_ptr;	/* address in user-defined structure */
	char *djc_name;		/* fully qualified '/' delimited class name */
	uu_list_t *djc_methods;	/* element type (java_method_t *) */
	uu_list_t *djc_fields;	/* element type (java_field_t *) */
	uu_list_node_t djc_node;
} dtj_java_class_t;

typedef struct dtj_java_method {
	jmethodID *djm_ptr;	/* address in user-defined structure */
	char *djm_name;		/* method name in java source file */
	char *djm_signature;	/* javap -s method signature string */
	boolean_t djm_static;	/* flag indicating static qualifier */
	uu_list_node_t djm_node;
} dtj_java_method_t;

typedef struct dtj_java_field {
	jfieldID *djf_ptr;	/* address in user-defined structure */
	char *djf_name;		/* field name in java source file */
	char *djf_type;		/* javap -s field type string */
	boolean_t djf_static;	/* flag indicating static qualifier */
	uu_list_node_t djf_node;
} dtj_java_field_t;

/*
 * Table of cached jclass, jmethodID, and jfieldID values usable across multiple
 * native method calls and multiple threads.
 *
 * Suffix conventions:
 *   jc  java class
 *   jm  java method
 *   jsm java static method
 *   jf  java field
 *   jsf java static field
 */

/* NativeException */
extern jclass g_nx_jc;
extern jmethodID g_nxinit_jm;

/* java.io.Serializable */
extern jclass g_serial_jc;

/* java.lang.Number */
extern jclass g_number_jc;
extern jmethodID g_shortval_jm;
extern jmethodID g_intval_jm;
extern jmethodID g_longval_jm;

/* java.lang.Byte */
extern jclass g_byte_jc;
extern jmethodID g_byteinit_jm;

/* java.lang.Character */
extern jclass g_char_jc;
extern jmethodID g_charinit_jm;
extern jmethodID g_charval_jm;

/* java.lang.Short */
extern jclass g_short_jc;
extern jmethodID g_shortinit_jm;

/* java.lang.Integer */
extern jclass g_int_jc;
extern jmethodID g_intinit_jm;

/* java.lang.Long */
extern jclass g_long_jc;
extern jmethodID g_longinit_jm;

/* java.math.BigInteger */
extern jclass g_bigint_jc;
extern jmethodID g_bigint_val_jsm;
extern jmethodID g_bigint_div_jm;
extern jmethodID g_bigint_shl_jm;
extern jmethodID g_bigint_or_jm;
extern jmethodID g_bigint_setbit_jm;

/* java.lang.String */
extern jclass g_string_jc;
extern jmethodID g_strinit_bytes_jm;
extern jmethodID g_strbytes_jm;
extern jmethodID g_trim_jm;

/* java.lang.StringBuffer */
extern jclass g_buf_jc;
extern jmethodID g_bufinit_jm;
extern jmethodID g_buf_append_char_jm;
extern jmethodID g_buf_append_int_jm;
extern jmethodID g_buf_append_long_jm;
extern jmethodID g_buf_append_str_jm;
extern jmethodID g_buf_append_obj_jm;
extern jmethodID g_buflen_jm;
extern jmethodID g_bufsetlen_jm;

/* java.lang.Object */
extern jclass g_object_jc;
extern jmethodID g_tostring_jm;
extern jmethodID g_equals_jm;

/* java.lang.Enum */
extern jclass g_enum_jc;
extern jmethodID g_enumname_jm;

/* List */
extern jclass g_list_jc;
extern jmethodID g_listclear_jm;
extern jmethodID g_listadd_jm;
extern jmethodID g_listget_jm;
extern jmethodID g_listsize_jm;

/*
 * Populates the common java class references and associated method and field
 * IDs declared in this file (above) using the dtj_cache_jni_classes() method.
 */
extern dtj_status_t dtj_load_common(JNIEnv *);

/*
 * Populates the user-declared java class references and associated method and
 * field IDs described in the given table.  Because the class references are
 * created as global JNI references, the method and field IDs remain valid
 * across multiple native method calls and across multiple threads.
 *
 * This function assumes that the given table of java class, method, and field
 * descriptions is terminated by an entry with DTJ_TYPE_END, and that the
 * method and field descriptions immediately follow the description of their
 * containing class.
 *
 * Throws NoClassDefFoundError, NoSuchMethodError, or NoSuchFieldError if any
 * dtj_table_entry_t in common_jni_table.c is incorrect.
 */
extern dtj_status_t dtj_cache_jni_classes(JNIEnv *, const dtj_table_entry_t *);

/* Common utilities */

/*
 * The following functions each create a pending Java Error or Exception:
 *
 * OutOfMemoryError
 * NullPointerException
 * IllegalArgumentException
 * IllegalStateException
 * NoSuchElementException
 * ClassCastException
 * AssertionError
 * org.opensolaris.os.dtrace.ResourceLimitException
 *
 * Control should be returned to Java immediately afterwards.
 */
extern void dtj_throw_out_of_memory(JNIEnv *, const char *, ...);
extern void dtj_throw_null_pointer(JNIEnv *, const char *, ...);
extern void dtj_throw_illegal_argument(JNIEnv *, const char *, ...);
extern void dtj_throw_illegal_state(JNIEnv *, const char *, ...);
extern void dtj_throw_no_such_element(JNIEnv *, const char *, ...);
extern void dtj_throw_class_cast(JNIEnv *, const char *, ...);
extern void dtj_throw_assertion(JNIEnv *, const char *, ...);
extern void dtj_throw_resource_limit(JNIEnv *, const char *, ...);

/*
 * Attaches native filename and line number to the currently pending java
 * exception, since that information is not present in the exception stack
 * trace.
 */
extern void dtj_wrap_exception(JNIEnv *, const char *, int);

/*
 * Calls the toString() method of the given object and prints the value to
 * stdout (useful for debugging).  If an exception is thrown in this function,
 * it is described on stdout and cleared.  It's guaranteed that no exception is
 * pending when this function returns.
 */
extern void dtj_print_object(JNIEnv *jenv, jobject obj);

/*
 * Gets a java.math.BigInteger representing a 64-bit unsigned integer.
 */
extern jobject dtj_uint64(JNIEnv *jenv, uint64_t);

/*
 * Gets a java.math.BigInteger representing a 128-bit integer given as 64 high
 * bits (1st arg) and 64 low bits (2nd arg).
 */
extern jobject dtj_int128(JNIEnv *jenv, uint64_t, uint64_t);

/*
 * Gets a formatted String (local reference) from a format and a variable
 * argument list of placeholder values.  Returns NULL if OutOfMemoryError is
 * thrown.
 */
extern jstring dtj_format_string(JNIEnv *jenv, const char *fmt, ...);

/*
 * Internationalization support.  These functions taken (not verbatim) from
 * Section 8.2 of The Java Native Interface by Sheng Liang, The Java Series.
 * Use these functions for locale-specific strings such as file names.
 */
extern jstring dtj_NewStringNative(JNIEnv *jenv, const char *str);
extern char *dtj_GetStringNativeChars(JNIEnv *jenv, jstring jstr);
extern void dtj_ReleaseStringNativeChars(JNIEnv *jenv, jstring jstr,
    const char *str);

/*
 * Converts the args array of main(String[] args) in Java into a native
 * dynamically allocated array of strings.  The returned array must be
 * deallocated by calling free_argv().  A java exception is pending if this
 * function returns NULL (in that case, any allocations made up to the point of
 * failure in get_argv() are automatically freed).
 *
 * Returns a NULL-terminated array that works with functions that expect a
 * terminating NULL rather than relying on an element count.  The argc parameter
 * is also overwritten with the number of returned array elements (not including
 * the terminating NULL).
 */
extern char **dtj_get_argv(JNIEnv *jenv, jobjectArray args, int *argc);
/*
 * Tokenizes a command string to create a native dynamically allocated array of
 * strings.  The first element of the returned array is assumed to be the name
 * of the command, and subsequent elements are arguments to that command.
 * Otherwise behaves exactly like get_argv() above, including requiring a
 * subsequent call to free_argv() on the returned array.
 * Throws NullPointerException if cmd is NULL.
 * Throws IllegalArgumentException if cmd is empty.
 */
extern char **dtj_make_argv(JNIEnv *jenv, jstring cmd, int *argc);
extern void dtj_free_argv(char **argv);


/* Wrappers for uu_list_t */

/*
 * List element destructor.
 * params: node pointer, user arg (may be NULL)
 */
typedef void dtj_value_destroy_f(void *, void *);

/*
 * uu_list_t generic entry type for pointers compared by pointer value, similar
 * to Java's default Object.equals() implementation (referenced objects are
 * equal only if they have the same address in memory).  Used with
 * pointer_list_entry_cmp.
 */
typedef struct dtj_pointer_list_entry {
	void *dple_ptr;
	uu_list_node_t dple_node;
} dtj_pointer_list_entry_t;

typedef struct dtj_string_list_entry {
	char *dsle_value;
	uu_list_node_t dsle_node;
} dtj_string_list_entry_t;

/* Comparison functions, uu_compare_fn_t signature */
extern int dtj_pointer_list_entry_cmp(const void *, const void *, void *);
extern int dtj_string_list_entry_cmp(const void *, const void *, void *);

/* Constructors */
extern uu_list_t *dtj_pointer_list_create(void);
extern dtj_pointer_list_entry_t *dtj_pointer_list_entry_create(void *);
extern uu_list_t *dtj_string_list_create(void);
extern dtj_string_list_entry_t *dtj_string_list_entry_create(const char *);

/* Destructors */
extern void dtj_pointer_list_entry_destroy(void *, dtj_value_destroy_f *,
    void *);
extern void dtj_string_list_entry_destroy(void *, void *);
/*
 * Convenience function destroys a uu_list_t and its values.
 *
 * param list: list to be destroyed, call is a no-op if list is NULL
 * param value_destroy: optional destructor; if non-NULL, it is called on each
 *	list value
 * param arg: user argument to the optional destructor
 */
extern void dtj_list_destroy(uu_list_t *, dtj_value_destroy_f *, void *);
extern void dtj_pointer_list_destroy(uu_list_t *, dtj_value_destroy_f *,
    void *);
extern void dtj_string_list_destroy(uu_list_t *);

/*
 * Convenience functions clear a uu_list_t without destroying it.  Destroys all
 * list elements and leaves the list empty.  The *_list_destroy() functions
 * implicitly clear the list before destroying it.
 */
extern void dtj_list_clear(uu_list_t *, dtj_value_destroy_f *, void *);
extern void dtj_pointer_list_clear(uu_list_t *, dtj_value_destroy_f *,
    void *);
extern void dtj_string_list_clear(uu_list_t *);

extern boolean_t dtj_list_empty(uu_list_t *);
/* Return B_TRUE if successful, B_FALSE otherwise */
extern boolean_t dtj_list_add(uu_list_t *, void *);
extern boolean_t dtj_pointer_list_add(uu_list_t *, void *);
extern boolean_t dtj_string_list_add(uu_list_t *, const char *);
/* Return INVALID_PTR if list is empty (NULL is a valid list element) */
extern void * dtj_pointer_list_first(uu_list_t *);
extern void * dtj_pointer_list_last(uu_list_t *);
/* Return INVALID_STR if list is empty (NULL is a valid list element) */
extern const char *dtj_string_list_first(uu_list_t *);
extern const char *dtj_string_list_last(uu_list_t *);
/* Return INVALID_PTR at end of list (NULL is a valid list element) */
extern void *dtj_pointer_list_walk_next(uu_list_walk_t *);
/* Return INVALID_STR at end of list (NULL is a valid list element) */
extern const char *dtj_string_list_walk_next(uu_list_walk_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DTJ_UTIL_H */
