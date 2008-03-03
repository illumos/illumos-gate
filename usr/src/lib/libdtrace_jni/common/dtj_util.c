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
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include <dtj_util.h>

/*
 * dtj_util.c separates functionality that is generally useful from
 * that which is specific to the Java DTrace API.  If moved to a separate
 * library, this functionality could be shared by other JNI wrappers.
 */

boolean_t g_dtj_util_debug = B_FALSE;
static boolean_t g_dtj_load_common = B_FALSE;

/* NativeException */
jclass g_nx_jc = 0;
jmethodID g_nxinit_jm = 0;

/* java.io.Serializable */
jclass g_serial_jc = 0;

/* java.lang.Number */
jclass g_number_jc = 0;
jmethodID g_shortval_jm = 0;
jmethodID g_intval_jm = 0;
jmethodID g_longval_jm = 0;

/* java.lang.Byte */
jclass g_byte_jc = 0;
jmethodID g_byteinit_jm = 0;

/* java.lang.Character */
jclass g_char_jc = 0;
jmethodID g_charinit_jm = 0;
jmethodID g_charval_jm = 0;

/* java.lang.Short */
jclass g_short_jc = 0;
jmethodID g_shortinit_jm = 0;

/* java.lang.Integer */
jclass g_int_jc = 0;
jmethodID g_intinit_jm = 0;

/* java.lang.Long */
jclass g_long_jc = 0;
jmethodID g_longinit_jm = 0;

/* java.math.BigInteger */
jclass g_bigint_jc = 0;
jmethodID g_bigint_val_jsm = 0;
jmethodID g_bigint_div_jm = 0;
jmethodID g_bigint_shl_jm = 0;
jmethodID g_bigint_or_jm = 0;
jmethodID g_bigint_setbit_jm = 0;

/* java.lang.String */
jclass g_string_jc = 0;
jmethodID g_strinit_bytes_jm = 0;
jmethodID g_strbytes_jm = 0;
jmethodID g_trim_jm = 0;

/* java.lang.StringBuilder */
jclass g_buf_jc = 0;
jmethodID g_bufinit_jm = 0;
jmethodID g_buf_append_char_jm = 0;
jmethodID g_buf_append_int_jm = 0;
jmethodID g_buf_append_long_jm = 0;
jmethodID g_buf_append_str_jm = 0;
jmethodID g_buf_append_obj_jm = 0;
jmethodID g_buflen_jm = 0;
jmethodID g_bufsetlen_jm = 0;

/* java.lang.Object */
jclass g_object_jc = 0;
jmethodID g_tostring_jm = 0;
jmethodID g_equals_jm = 0;

/* java.lang.Enum */
jclass g_enum_jc = 0;
jmethodID g_enumname_jm = 0;

/* List */
jclass g_list_jc = 0;
jmethodID g_listclear_jm = 0;
jmethodID g_listadd_jm = 0;
jmethodID g_listget_jm = 0;
jmethodID g_listsize_jm = 0;

/* Global list pools */
static uu_list_pool_t *g_pointer_pool = NULL;
static uu_list_pool_t *g_string_pool = NULL;

static dtj_status_t dtj_get_jni_classes(JNIEnv *, uu_list_t *, uu_list_pool_t *,
    uu_list_pool_t *, uu_list_pool_t *, const dtj_table_entry_t *);
static dtj_status_t dtj_cache_jni_methods(JNIEnv *, dtj_java_class_t *);
static dtj_status_t dtj_cache_jni_fields(JNIEnv *, dtj_java_class_t *);

/* Constructors */
static dtj_java_class_t *dtj_java_class_create(JNIEnv *, jclass *, char *,
    uu_list_pool_t *, uu_list_pool_t *, uu_list_pool_t *);
static dtj_java_method_t *dtj_java_method_create(JNIEnv *, jmethodID *, char *,
    char *, uu_list_pool_t *);
static dtj_java_method_t *dtj_java_static_method_create(JNIEnv *, jmethodID *,
    char *, char *, uu_list_pool_t *);
static dtj_java_field_t *dtj_java_field_create(JNIEnv *, jfieldID *, char *,
    char *, uu_list_pool_t *);
static dtj_java_field_t *dtj_java_static_field_create(JNIEnv *, jfieldID *,
    char *, char *, uu_list_pool_t *);

/* Destructors */
static void dtj_java_class_destroy(void *, void *);
static void dtj_java_method_destroy(void *, void *);
static void dtj_java_field_destroy(void *, void *);

/* Comparison functions, uu_compare_fn_t signature */
static int dtj_java_class_cmp(const void *, const void *, void *);
static int dtj_java_method_cmp(const void *, const void *, void *);
static int dtj_java_field_cmp(const void *, const void *, void *);

/* Java Throwable */
static void dtj_throw(JNIEnv *, jclass, const char *, va_list *);

/* Support for uu_list_t wrappers */
static boolean_t dtj_check_pointer_pool(void);
static boolean_t dtj_check_string_pool(void);

dtj_status_t
dtj_load_common(JNIEnv *jenv)
{
	dtj_status_t status;

	static const dtj_table_entry_t table[] = {
		/* NativeException */
		{ JCLASS,  &g_nx_jc,
			"org/opensolaris/os/dtrace/NativeException" },
		{ JMETHOD, &g_nxinit_jm, CONSTRUCTOR,
			"(Ljava/lang/String;ILjava/lang/Throwable;)V" },

		/* java.io.Serializable */
		{ JCLASS,  &g_serial_jc, "java/io/Serializable" },

		/* java.lang.Number */
		{ JCLASS,  &g_number_jc, "java/lang/Number" },
		{ JMETHOD, &g_shortval_jm, "shortValue", "()S" },
		{ JMETHOD, &g_intval_jm, "intValue", "()I" },
		{ JMETHOD, &g_longval_jm, "longValue", "()J" },

		/* java.lang.Byte */
		{ JCLASS,  &g_byte_jc, "java/lang/Byte" },
		{ JMETHOD, &g_byteinit_jm, CONSTRUCTOR, "(B)V" },

		/* java.lang.Character */
		{ JCLASS,  &g_char_jc, "java/lang/Character" },
		{ JMETHOD, &g_charinit_jm, CONSTRUCTOR, "(C)V" },
		{ JMETHOD, &g_charval_jm, "charValue", "()C" },

		/* java.lang.Short */
		{ JCLASS,  &g_short_jc, "java/lang/Short" },
		{ JMETHOD, &g_shortinit_jm, CONSTRUCTOR, "(S)V" },

		/* java.lang.Integer */
		{ JCLASS,  &g_int_jc, "java/lang/Integer" },
		{ JMETHOD, &g_intinit_jm, CONSTRUCTOR, "(I)V" },

		/* java.lang.Long */
		{ JCLASS,  &g_long_jc, "java/lang/Long" },
		{ JMETHOD, &g_longinit_jm, CONSTRUCTOR, "(J)V" },

		/* java.math.BigInteger */
		{ JCLASS,  &g_bigint_jc, "java/math/BigInteger" },
		{ JMETHOD_STATIC, &g_bigint_val_jsm, "valueOf",
			"(J)Ljava/math/BigInteger;" },
		{ JMETHOD, &g_bigint_div_jm, "divide",
			"(Ljava/math/BigInteger;)Ljava/math/BigInteger;" },
		{ JMETHOD, &g_bigint_shl_jm, "shiftLeft",
			"(I)Ljava/math/BigInteger;" },
		{ JMETHOD, &g_bigint_or_jm, "or",
			"(Ljava/math/BigInteger;)Ljava/math/BigInteger;" },
		{ JMETHOD, &g_bigint_setbit_jm, "setBit",
			"(I)Ljava/math/BigInteger;" },

		/* java.lang.String */
		{ JCLASS,  &g_string_jc, "java/lang/String" },
		{ JMETHOD, &g_strinit_bytes_jm, CONSTRUCTOR, "([B)V" },
		{ JMETHOD, &g_strbytes_jm, "getBytes", "()[B" },
		{ JMETHOD, &g_trim_jm, "trim", "()Ljava/lang/String;" },

		/* java.lang.StringBuilder */
		{ JCLASS,  &g_buf_jc, "java/lang/StringBuilder" },
		{ JMETHOD, &g_bufinit_jm, CONSTRUCTOR, "()V" },
		{ JMETHOD, &g_buf_append_char_jm, "append",
			"(C)Ljava/lang/StringBuilder;" },
		{ JMETHOD, &g_buf_append_int_jm, "append",
			"(I)Ljava/lang/StringBuilder;" },
		{ JMETHOD, &g_buf_append_long_jm, "append",
			"(J)Ljava/lang/StringBuilder;" },
		{ JMETHOD, &g_buf_append_str_jm, "append",
			"(Ljava/lang/String;)Ljava/lang/StringBuilder;" },
		{ JMETHOD, &g_buf_append_obj_jm, "append",
			"(Ljava/lang/Object;)Ljava/lang/StringBuilder;" },
		{ JMETHOD, &g_buflen_jm, "length", "()I" },
		{ JMETHOD, &g_bufsetlen_jm, "setLength", "(I)V" },

		/* java.lang.Object */
		{ JCLASS,  &g_object_jc, "java/lang/Object" },
		{ JMETHOD, &g_tostring_jm, "toString",
			"()Ljava/lang/String;" },
		{ JMETHOD, &g_equals_jm, "equals",
			"(Ljava/lang/Object;)Z" },

		/* java.lang.Enum */
		{ JCLASS,  &g_enum_jc, "java/lang/Enum" },
		{ JMETHOD, &g_enumname_jm, "name",
			"()Ljava/lang/String;" },

		/* List */
		{ JCLASS, &g_list_jc, "java/util/List" },
		{ JMETHOD, &g_listclear_jm, "clear", "()V" },
		{ JMETHOD, &g_listadd_jm, "add", "(Ljava/lang/Object;)Z" },
		{ JMETHOD, &g_listget_jm, "get", "(I)Ljava/lang/Object;" },
		{ JMETHOD, &g_listsize_jm, "size", "()I" },

		{ DTJ_TYPE_END }
	};

	status = dtj_cache_jni_classes(jenv, table);
	if (status == DTJ_OK) {
		g_dtj_load_common = B_TRUE;
	}
	return (status);
}

static int
/* ARGSUSED */
dtj_java_class_cmp(const void * v1, const void * v2, void *arg)
{
	const dtj_java_class_t *c1 = v1;
	const dtj_java_class_t *c2 = v2;
	return (strcmp(c1->djc_name, c2->djc_name));
}

static int
/* ARGSUSED */
dtj_java_method_cmp(const void *v1, const void *v2, void *arg)
{
	int cmp;
	const dtj_java_method_t *m1 = v1;
	const dtj_java_method_t *m2 = v2;
	cmp = strcmp(m1->djm_name, m2->djm_name);
	if (cmp == 0) {
		cmp = strcmp(m1->djm_signature, m2->djm_signature);
	}
	return (cmp);
}

static int
/* ARGSUSED */
dtj_java_field_cmp(const void *v1, const void *v2, void *arg)
{
	const dtj_java_field_t *f1 = v1;
	const dtj_java_field_t *f2 = v2;
	return (strcmp(f1->djf_name, f2->djf_name));
}

static dtj_java_class_t *
dtj_java_class_create(JNIEnv *jenv, jclass *jc, char *name,
    uu_list_pool_t *classpool, uu_list_pool_t *methodpool,
    uu_list_pool_t *fieldpool)
{
	dtj_java_class_t *c = uu_zalloc(sizeof (dtj_java_class_t));
	if (c) {
		uu_list_node_init(c, &c->djc_node, classpool);
		c->djc_ptr = jc;
		c->djc_name = name;
		c->djc_methods = uu_list_create(methodpool, NULL,
		    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
		if (!c->djc_methods) {
			dtj_throw_out_of_memory(jenv,
			    "Failed method list creation");
			uu_list_node_fini(c, &c->djc_node, classpool);
			free(c);
			c = NULL;
		}
		c->djc_fields = uu_list_create(fieldpool, NULL,
		    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
		if (!c->djc_fields) {
			dtj_throw_out_of_memory(jenv,
			    "Failed field list creation");
			uu_list_destroy(c->djc_methods);
			c->djc_methods = NULL;
			uu_list_node_fini(c, &c->djc_node, classpool);
			free(c);
			c = NULL;
		}
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate class description");
	}
	return (c);
}

static dtj_java_method_t *
dtj_java_method_create(JNIEnv *jenv, jmethodID *jm, char *name, char *signature,
    uu_list_pool_t *methodpool)
{
	dtj_java_method_t *m = uu_zalloc(sizeof (dtj_java_method_t));
	if (m) {
		uu_list_node_init(m, &m->djm_node, methodpool);
		m->djm_ptr = jm;
		m->djm_name = name;
		m->djm_signature = signature;
		m->djm_static = B_FALSE;
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate method description");
	}
	return (m);
}

static dtj_java_method_t *
dtj_java_static_method_create(JNIEnv *jenv, jmethodID *jm, char *name,
    char *signature, uu_list_pool_t *methodpool)
{
	dtj_java_method_t *m = dtj_java_method_create(jenv, jm, name, signature,
	    methodpool);
	if (m) {
		m->djm_static = B_TRUE;
	}
	return (m);
}

static dtj_java_field_t *
dtj_java_field_create(JNIEnv *jenv, jfieldID *jf, char *name, char *type,
    uu_list_pool_t *fieldpool)
{
	dtj_java_field_t *f = uu_zalloc(sizeof (dtj_java_field_t));
	if (f) {
		uu_list_node_init(f, &f->djf_node, fieldpool);
		f->djf_ptr = jf;
		f->djf_name = name;
		f->djf_type = type;
		f->djf_static = B_FALSE;
	} else {
		dtj_throw_out_of_memory(jenv,
		    "Failed to allocate field description");
	}
	return (f);
}

static dtj_java_field_t *
dtj_java_static_field_create(JNIEnv *jenv, jfieldID *jf, char *name, char *type,
    uu_list_pool_t *fieldpool)
{
	dtj_java_field_t *f = dtj_java_field_create(jenv, jf, name, type,
	    fieldpool);
	if (f) {
		f->djf_static = B_TRUE;
	}
	return (f);
}

static void
/* ARGSUSED */
dtj_java_class_destroy(void *v, void *arg)
{
	if (v) {
		dtj_java_class_t *c = v;
		c->djc_ptr = NULL;  /* do not free user-defined storage */
		c->djc_name = NULL; /* string literal */
		dtj_list_destroy(c->djc_methods, dtj_java_method_destroy, NULL);
		dtj_list_destroy(c->djc_fields, dtj_java_field_destroy, NULL);
		c->djc_methods = NULL;
		c->djc_fields = NULL;
		uu_free(v);
	}
}

static void
/* ARGSUSED */
dtj_java_method_destroy(void *v, void *arg)
{
	if (v) {
		dtj_java_method_t *m = v;
		m->djm_ptr = NULL;	/* do not free user-defined space */
		m->djm_name = NULL;	/* string literal */
		m->djm_signature = NULL;	/* string literal */
		uu_free(v);
	}
}

static void
/* ARGSUSED */
dtj_java_field_destroy(void *v, void *arg)
{
	if (v) {
		dtj_java_field_t *f = v;
		f->djf_ptr = NULL;  /* do not free user-defined space */
		f->djf_name = NULL; /* string literal */
		f->djf_type = NULL; /* string literal */
		uu_free(f);
	}
}

dtj_status_t
dtj_cache_jni_classes(JNIEnv *jenv, const dtj_table_entry_t *table)
{
	dtj_java_class_t *class;
	uu_list_pool_t *classpool;
	uu_list_pool_t *methodpool;
	uu_list_pool_t *fieldpool;
	uu_list_t *classes;
	uu_list_walk_t *itr;
	jclass jc;
	jclass gjc;
	dtj_status_t status;

	classpool = uu_list_pool_create("classpool",
	    sizeof (dtj_java_class_t),
	    offsetof(dtj_java_class_t, djc_node), dtj_java_class_cmp,
	    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
	if (!classpool) {
		dtj_throw_out_of_memory(jenv, "failed class pool creation");
		return (DTJ_ERR);
	}
	methodpool = uu_list_pool_create("methodpool",
	    sizeof (dtj_java_method_t),
	    offsetof(dtj_java_method_t, djm_node), dtj_java_method_cmp,
	    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
	if (!methodpool) {
		dtj_throw_out_of_memory(jenv, "failed method pool creation");
		return (DTJ_ERR);
	}
	fieldpool = uu_list_pool_create("fieldpool",
	    sizeof (dtj_java_field_t),
	    offsetof(dtj_java_field_t, djf_node), dtj_java_field_cmp,
	    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
	if (!fieldpool) {
		dtj_throw_out_of_memory(jenv, "failed field pool creation");
		return (DTJ_ERR);
	}

	classes = uu_list_create(classpool, NULL,
	    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
	if (!classes) {
		dtj_throw_out_of_memory(jenv, "failed class list creation");
		return (DTJ_ERR);
	}

	status = dtj_get_jni_classes(jenv, classes, classpool, methodpool,
	    fieldpool, table);
	if (status != DTJ_OK) {
		/* java error pending */
		return (status);
	}

	itr = uu_list_walk_start(classes, 0);
	while ((class = uu_list_walk_next(itr)) != NULL) {
		jc = (*jenv)->FindClass(jenv, class->djc_name);
		if (!jc) {
			/* NoClassDefFoundError pending */
			return (DTJ_ERR);
		}
		gjc = (*jenv)->NewGlobalRef(jenv, jc);
		(*jenv)->DeleteLocalRef(jenv, jc);
		if (!gjc) {
			dtj_throw_out_of_memory(jenv,
			    "Failed to create global class reference");
			return (DTJ_ERR);
		}
		*(class->djc_ptr) = gjc;
		status = dtj_cache_jni_methods(jenv, class);
		if (status != DTJ_OK) {
			/* java error pending */
			return (status);
		}
		status = dtj_cache_jni_fields(jenv, class);
		if (status != DTJ_OK) {
			/* java error pending */
			return (status);
		}
	}
	uu_list_walk_end(itr);
	dtj_list_destroy(classes, dtj_java_class_destroy, NULL);
	uu_list_pool_destroy(classpool);
	uu_list_pool_destroy(methodpool);
	uu_list_pool_destroy(fieldpool);
	return (DTJ_OK);
}

/*
 * Converts JNI table entry desriptions into java_class_t descriptors.
 */
static dtj_status_t
dtj_get_jni_classes(JNIEnv *jenv, uu_list_t *classes,
    uu_list_pool_t *classpool, uu_list_pool_t *methodpool,
    uu_list_pool_t *fieldpool, const dtj_table_entry_t *table)
{
	int i;
	dtj_java_class_t *c = NULL;
	dtj_java_method_t *m;
	dtj_java_field_t *f;

	for (i = 0; table[i].djte_type != DTJ_TYPE_END; ++i) {
		/*
		 * Class not added until all of its method and field information
		 * is attached, so we defer adding a class until the next
		 * element with type JCLASS.
		 */
		switch (table[i].djte_type) {
		case JCLASS:
			if (c) {
				/* previous class */
				if (!dtj_list_add(classes, c)) {
					dtj_throw_out_of_memory(jenv,
					    "Failed to add class description");
					/*
					 * In response to an error return value,
					 * the caller will delete the class
					 * descriptions list with any
					 * descriptions created so far.
					 */
					return (DTJ_ERR);
				}
			}
			c = dtj_java_class_create(jenv,
			    (jclass *)table[i].djte_addr, table[i].djte_name,
			    classpool, methodpool, fieldpool);
			if (!c) {
				/* OutOfMemoryError pending */
				return (DTJ_ERR);
			}
			break;
		case JMETHOD:
			if (!c) {
				dtj_throw_illegal_state(jenv,
				    "method description not preceded "
				    "by class description");
				return (DTJ_ERR);
			}
			m = dtj_java_method_create(jenv,
			    (jmethodID *)table[i].djte_addr,
			    table[i].djte_name, table[i].djte_desc,
			    methodpool);
			if (!m) {
				/* OutOfMemoryError pending */
				return (DTJ_ERR);
			}
			if (!dtj_list_add(c->djc_methods, m)) {
				dtj_throw_out_of_memory(jenv,
				    "Failed to add method description");
				return (DTJ_ERR);
			}
			break;
		case JMETHOD_STATIC:
			if (!c) {
				dtj_throw_illegal_state(jenv,
				    "static method description not preceded "
				    "by class description");
				return (DTJ_ERR);
			}
			m = dtj_java_static_method_create(jenv,
			    (jmethodID *)table[i].djte_addr,
			    table[i].djte_name, table[i].djte_desc,
			    methodpool);
			if (!m) {
				/* OutOfMemoryError pending */
				return (DTJ_ERR);
			}
			if (!dtj_list_add(c->djc_methods, m)) {
				dtj_throw_out_of_memory(jenv,
				    "Failed to add static method description");
				return (DTJ_ERR);
			}
			break;
		case JFIELD:
			if (!c) {
				dtj_throw_illegal_state(jenv,
				    "field description not preceded "
				    "by class description");
				return (DTJ_ERR);
			}
			f = dtj_java_field_create(jenv,
			    (jfieldID *)table[i].djte_addr,
			    table[i].djte_name, table[i].djte_desc,
			    fieldpool);
			if (!f) {
				/* OutOfMemoryError pending */
				return (DTJ_ERR);
			}
			if (!dtj_list_add(c->djc_fields, f)) {
				dtj_throw_out_of_memory(jenv,
				    "Failed to add field description");
				return (DTJ_ERR);
			}
			break;
		case JFIELD_STATIC:
			if (!c) {
				dtj_throw_illegal_state(jenv,
				    "static field description not preceded "
				    "by class description");
				return (DTJ_ERR);
			}
			f = dtj_java_static_field_create(jenv,
			    (jfieldID *)table[i].djte_addr,
			    table[i].djte_name, table[i].djte_desc,
			    fieldpool);
			if (!f) {
				/* OutOfMemoryError pending */
				return (DTJ_ERR);
			}
			if (!dtj_list_add(c->djc_fields, f)) {
				dtj_throw_out_of_memory(jenv,
				    "Failed to add static field description");
				return (DTJ_ERR);
			}
			break;
		default:
			dtj_throw_illegal_state(jenv,
			    "Unexpected jni_type_e: %d", table[i].djte_type);
			return (DTJ_ERR);
		}
	}
	if (c) {
		/* last class */
		if (!dtj_list_add(classes, c)) {
			dtj_throw_out_of_memory(jenv,
			    "Failed to add class description");
			return (DTJ_ERR);
		}
	}

	return (DTJ_OK);
}

static dtj_status_t
dtj_cache_jni_methods(JNIEnv *jenv, dtj_java_class_t *c)
{
	dtj_java_method_t *method;
	jmethodID jm;
	uu_list_walk_t *itr;
	itr = uu_list_walk_start(c->djc_methods, 0);
	while ((method = uu_list_walk_next(itr)) != NULL) {
		if (method->djm_static) {
			jm = (*jenv)->GetStaticMethodID(jenv, *(c->djc_ptr),
			    method->djm_name, method->djm_signature);
		} else {
			jm = (*jenv)->GetMethodID(jenv, *(c->djc_ptr),
			    method->djm_name, method->djm_signature);
		}
		if (jm == 0) {
			/*
			 * The pending NoSuchMethodError gives only the
			 * method name, which is not so helpful for
			 * overloaded methods and methods such as <init>
			 * that have the same name in multiple classes.
			 * Clear the pending error and throw one that
			 * includes the class name and the method
			 * signature.
			 */
			jclass jc;
			char msg[DTJ_MSG_SIZE];
			(*jenv)->ExceptionClear(jenv);
			(void) snprintf(msg, sizeof (msg), "%s %s %s",
			    c->djc_name, method->djm_name,
			    method->djm_signature);

			jc = (*jenv)->FindClass(jenv,
			    "java/lang/NoSuchMethodError");
			(*jenv)->ThrowNew(jenv, jc, msg);
			(*jenv)->DeleteLocalRef(jenv, jc);
			return (DTJ_ERR);
		}
		*(method->djm_ptr) = jm;
	}
	uu_list_walk_end(itr);
	return (DTJ_OK);
}

static dtj_status_t
dtj_cache_jni_fields(JNIEnv *jenv, dtj_java_class_t *c)
{
	dtj_java_field_t *field;
	jfieldID jf;
	uu_list_walk_t *itr;
	itr = uu_list_walk_start(c->djc_fields, 0);
	while ((field = uu_list_walk_next(itr)) != NULL) {
		if (field->djf_static) {
			jf = (*jenv)->GetStaticFieldID(jenv, *(c->djc_ptr),
			    field->djf_name, field->djf_type);
		} else {
			jf = (*jenv)->GetFieldID(jenv, *(c->djc_ptr),
			    field->djf_name, field->djf_type);
		}
		if (jf == 0) {
			jclass jc;
			char msg[DTJ_MSG_SIZE];
			(*jenv)->ExceptionClear(jenv);
			(void) snprintf(msg, sizeof (msg),
			    "%s.%s signature: %s", c->djc_name,
			    field->djf_name, field->djf_type);

			jc = (*jenv)->FindClass(jenv,
			    "java/lang/NoSuchFieldError");
			(*jenv)->ThrowNew(jenv, jc, msg);
			(*jenv)->DeleteLocalRef(jenv, jc);
			return (DTJ_ERR);
		}
		*(field->djf_ptr) = jf;
	}
	uu_list_walk_end(itr);
	return (DTJ_OK);
}


/* Common utilities */

static void
dtj_throw(JNIEnv *jenv, jclass jc, const char *fmt, va_list *ap)
{
	char msg[DTJ_MSG_SIZE];
	(void) vsnprintf(msg, sizeof (msg), fmt, *ap);
	(*jenv)->ThrowNew(jenv, jc, msg);
}

void
dtj_throw_out_of_memory(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc;
	/*
	 * JNI documentation unclear whether NewGlobalRef() can throw
	 * OutOfMemoryError, so we'll make this function safe in case
	 * OutOfMemoryError has already been thrown
	 */
	if ((*jenv)->ExceptionCheck(jenv)) {
		return;
	}
	jc = (*jenv)->FindClass(jenv,
	    "java/lang/OutOfMemoryError");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_null_pointer(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "java/lang/NullPointerException");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_illegal_state(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "java/lang/IllegalStateException");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_illegal_argument(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "java/lang/IllegalArgumentException");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_no_such_element(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "java/util/NoSuchElementException");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_class_cast(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "java/lang/ClassCastException");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_assertion(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "java/lang/AssertionError");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_throw_resource_limit(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	jclass jc = (*jenv)->FindClass(jenv,
	    "org/opensolaris/os/dtrace/ResourceLimitException");
	va_start(ap, fmt);
	dtj_throw(jenv, jc, fmt, &ap);
	(*jenv)->DeleteLocalRef(jenv, jc);
	va_end(ap);
}

void
dtj_wrap_exception(JNIEnv *jenv, const char *file, int line)
{
	jthrowable e = NULL;
	jthrowable nx = NULL;
	jstring jfile = NULL;

	e = (*jenv)->ExceptionOccurred(jenv);
	if (!e) {
		return;
	}

	if (!g_dtj_load_common) {
		return;
	}

	(*jenv)->ExceptionClear(jenv);

	/* Unsafe to test while exception pending */
	if ((*jenv)->IsInstanceOf(jenv, e, g_nx_jc)) {
		/* Already wrapped */
		(*jenv)->Throw(jenv, e);
		(*jenv)->DeleteLocalRef(jenv, e);
		return;
	}

	jfile = dtj_NewStringNative(jenv, file);
	if ((*jenv)->ExceptionCheck(jenv)) {
		/*
		 * Only wrap the exception if possible, otherwise just throw the
		 * original exception.
		 */
		(*jenv)->ExceptionClear(jenv);
		(*jenv)->Throw(jenv, e);
		(*jenv)->DeleteLocalRef(jenv, e);
		return;
	}

	nx = (jthrowable)(*jenv)->NewObject(jenv, g_nx_jc, g_nxinit_jm,
	    jfile, line, e);
	(*jenv)->DeleteLocalRef(jenv, jfile);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->ExceptionClear(jenv);
		(*jenv)->Throw(jenv, e);
		(*jenv)->DeleteLocalRef(jenv, e);
		return;
	}

	(*jenv)->DeleteLocalRef(jenv, e);
	(*jenv)->Throw(jenv, nx);
	(*jenv)->DeleteLocalRef(jenv, nx);
}

/*
 * Calls the given java object's toString() method and prints the value to
 * stdout.  Useful for debugging.  Guaranteed that no exception is pending when
 * this function returns.
 */
void
dtj_print_object(JNIEnv *jenv, jobject jobj)
{
	jstring jstr;
	const char *cstr;

	if (!g_dtj_load_common) {
		dtj_throw_illegal_state(jenv,
		    "dtj_load_common() has not been called");
		(*jenv)->ExceptionDescribe(jenv); /* clears the exception */
		return;
	}

	if (!jobj) {
		(void) printf("null\n");
		return;
	}

	jstr = (*jenv)->CallObjectMethod(jenv, jobj, g_tostring_jm);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->ExceptionDescribe(jenv); /* clears the exception */
		return;
	}
	cstr = (*jenv)->GetStringUTFChars(jenv, jstr, 0);
	if (cstr) {
		(void) printf("%s\n", cstr);
	} else {
		(*jenv)->ExceptionDescribe(jenv); /* clears the exception */
		(*jenv)->DeleteLocalRef(jenv, jstr);
		return;
	}
	(*jenv)->ReleaseStringUTFChars(jenv, jstr, cstr);
	(*jenv)->DeleteLocalRef(jenv, jstr);
}

jobject
dtj_uint64(JNIEnv *jenv, uint64_t u)
{
	int64_t i = (int64_t)u;
	jobject val64;

	if (i >= 0) {
		val64 = (*jenv)->CallStaticObjectMethod(jenv, g_bigint_jc,
		    g_bigint_val_jsm, u);
	} else {
		jobject tmp;

		u ^= ((uint64_t)0x1 << 63);
		val64 = (*jenv)->CallStaticObjectMethod(jenv, g_bigint_jc,
		    g_bigint_val_jsm, u);
		tmp = val64;
		val64 = (*jenv)->CallObjectMethod(jenv, tmp,
		    g_bigint_setbit_jm, 63);
		(*jenv)->DeleteLocalRef(jenv, tmp);
	}

	return (val64);
}

jobject
dtj_int128(JNIEnv *jenv, uint64_t high, uint64_t low)
{
	jobject val128;
	jobject low64;
	jobject tmp;

	val128 = (*jenv)->CallStaticObjectMethod(jenv, g_bigint_jc,
	    g_bigint_val_jsm, high);
	tmp = val128;
	val128 = (*jenv)->CallObjectMethod(jenv, tmp, g_bigint_shl_jm, 64);
	(*jenv)->DeleteLocalRef(jenv, tmp);
	low64 = dtj_uint64(jenv, low);
	tmp = val128;
	val128 = (*jenv)->CallObjectMethod(jenv, tmp, g_bigint_or_jm, low64);
	(*jenv)->DeleteLocalRef(jenv, tmp);
	(*jenv)->DeleteLocalRef(jenv, low64);

	return (val128);
}

jstring
dtj_format_string(JNIEnv *jenv, const char *fmt, ...)
{
	va_list ap;
	char str[DTJ_MSG_SIZE];

	jstring jstr = NULL;

	va_start(ap, fmt);
	(void) vsnprintf(str, sizeof (str), fmt, ap);
	va_end(ap);

	jstr = dtj_NewStringNative(jenv, str);
	/* return NULL if OutOfMemoryError pending */
	return (jstr);
}

jstring
dtj_NewStringNative(JNIEnv *jenv, const char *str)
{
	jstring result;
	jbyteArray bytes = 0;
	int len;

	if (!g_dtj_load_common) {
		dtj_throw_illegal_state(jenv,
		    "dtj_load_common() has not been called");
		return (NULL);
	}

	len = strlen(str);

	bytes = (*jenv)->NewByteArray(jenv, len);
	if (!bytes) {
		return (NULL); /* OutOfMemoryError pending */
	}
	(*jenv)->SetByteArrayRegion(jenv, bytes, 0, len,
	    (jbyte *)str);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, bytes);
		return (NULL); /* ArrayIndexOutOfBoundsException pending */
	}
	result = (*jenv)->NewObject(jenv, g_string_jc, g_strinit_bytes_jm,
	    bytes);
	(*jenv)->DeleteLocalRef(jenv, bytes);
	/* return NULL result if exception pending */
	return (result);
}

char *
dtj_GetStringNativeChars(JNIEnv *jenv, jstring jstr)
{
	jbyteArray bytes = NULL;

	jint len;
	char *result = NULL;

	if (!g_dtj_load_common) {
		dtj_throw_illegal_state(jenv,
		    "dtj_load_common() has not been called");
		return (NULL);
	}

	bytes = (*jenv)->CallObjectMethod(jenv, jstr, g_strbytes_jm);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (NULL); /* OutOfMemoryError pending */
	}
	/* Does not throw exceptions */
	len = (*jenv)->GetArrayLength(jenv, bytes);
	result = malloc(len + 1);
	if (!result) {
		(*jenv)->DeleteLocalRef(jenv, bytes);
		dtj_throw_out_of_memory(jenv,
		    "could not allocate native chars");
		return (NULL);
	}

	/* Skip check for ArrayIndexOutOfBoundsException */
	(*jenv)->GetByteArrayRegion(jenv, bytes, 0, len,
	    (jbyte *)result);
	(*jenv)->DeleteLocalRef(jenv, bytes);
	result[len] = '\0'; /* NUL-terminate */

	return (result);
}

void
/* ARGSUSED */
dtj_ReleaseStringNativeChars(JNIEnv *jenv, jstring jstr, const char *str)
{
	free((void *)str);
}

char **
dtj_get_argv(JNIEnv *jenv, jobjectArray args, int *argc)
{
	char **argv = NULL; /* return value */
	const char *str;
	int i;

	jstring jstr = NULL;

	if (!g_dtj_load_common) {
		dtj_throw_illegal_state(jenv,
		    "dtj_load_common() has not been called");
		return (NULL);
	}

	*argc = (*jenv)->GetArrayLength(jenv, args);
	/*
	 * Initialize all string pointers to NULL so that in case of an error
	 * filling in the array, free_argv() will not attempt to free the
	 * unallocated elements.  Also NULL-terminate the string array for
	 * functions that expect terminating NULL rather than rely on argc.
	 */
	argv = uu_zalloc((sizeof (char *)) * (*argc + 1));
	if (!argv) {
		dtj_throw_out_of_memory(jenv, "Failed to allocate args array");
		return (NULL);
	}

	for (i = 0; i < *argc; ++i) {
		jstr = (*jenv)->GetObjectArrayElement(jenv, args, i);
		if ((*jenv)->ExceptionCheck(jenv)) {
			dtj_free_argv(argv);
			return (NULL);
		}
		str = dtj_GetStringNativeChars(jenv, jstr);
		if ((*jenv)->ExceptionCheck(jenv)) {
			dtj_free_argv(argv);
			(*jenv)->DeleteLocalRef(jenv, jstr);
			return (NULL);
		}
		argv[i] = malloc(strlen(str) + 1);
		if (!argv[i]) {
			dtj_throw_out_of_memory(jenv, "Failed to allocate arg");
			dtj_free_argv(argv);
			dtj_ReleaseStringNativeChars(jenv, jstr, str);
			(*jenv)->DeleteLocalRef(jenv, jstr);
			return (NULL);
		}
		(void) strcpy(argv[i], str);
		dtj_ReleaseStringNativeChars(jenv, jstr, str);
		(*jenv)->DeleteLocalRef(jenv, jstr);
		jstr = NULL;
	}

	return (argv);
}

char **
dtj_make_argv(JNIEnv *jenv, jstring command, int *argc)
{
	const char *ws = "\f\n\r\t\v ";
	char **argv = NULL; /* return value */
	const char *cmd; /* native command string */
	char *s; /* writable command */
	char *tok; /* token */
	int len;

	if (!g_dtj_load_common) {
		dtj_throw_illegal_state(jenv,
		    "dtj_load_common() has not been called");
		return (NULL);
	}

	if (!command) {
		dtj_throw_null_pointer(jenv, "command is null");
		return (NULL);
	} else if ((*jenv)->GetStringLength(jenv, command) == 0) {
		dtj_throw_illegal_argument(jenv, "command is empty");
		return (NULL);
	}

	cmd = dtj_GetStringNativeChars(jenv, command);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (NULL);
	}
	len = strlen(cmd);
	s = malloc(len + 1);
	if (!s) {
		dtj_throw_out_of_memory(jenv,
		    "failed to allocate command string");
		dtj_ReleaseStringNativeChars(jenv, command, cmd);
		return (NULL);
	}
	(void) strcpy(s, cmd);
	/*
	 * Initialize all string pointers to NULL so that in case of an error
	 * filling in the array, free_argv() will not attempt to free the
	 * unallocated elements.  Also NULL-terminate the string array for
	 * functions that expect terminating NULL rather than rely on argc.
	 * Allow for maximum length resulting from single-character tokens
	 * separated by single spaces.
	 */
	argv = uu_zalloc(sizeof (char *) * (len / 2 + 1));
	if (!argv) {
		dtj_throw_out_of_memory(jenv, "failed to allocate args array");
		free(s);
		dtj_ReleaseStringNativeChars(jenv, command, cmd);
		return (NULL);
	}

	*argc = 0;
	for (tok = strtok(s, ws); tok != NULL; tok = strtok(NULL, ws)) {
		argv[*argc] = malloc(strlen(tok) + 1);
		if (!argv[*argc]) {
			dtj_throw_out_of_memory(jenv, "Failed to allocate arg");
			dtj_free_argv(argv);
			free(s);
			dtj_ReleaseStringNativeChars(jenv, command, cmd);
			return (NULL);
		}
		(void) strcpy(argv[(*argc)++], tok);
	}

	if (*argc == 0) {
		dtj_throw_illegal_argument(jenv, "command is blank");
		dtj_free_argv(argv);
		free(s);
		dtj_ReleaseStringNativeChars(jenv, command, cmd);
		return (NULL);
	}

	free(s);
	dtj_ReleaseStringNativeChars(jenv, command, cmd);
	return (argv);
}

void
dtj_free_argv(char **argv)
{
	if (argv) {
		char **s = argv;
		while (*s) {
			free((void *)*s);
			*s++ = NULL;
		}
		free((void *)argv);
	}
}


/* Wrappers for uu_list_t */

int
/* ARGSUSED */
dtj_pointer_list_entry_cmp(const void *v1, const void *v2, void *arg)
{
	const dtj_pointer_list_entry_t *p1 = v1;
	const dtj_pointer_list_entry_t *p2 = v2;

	/*
	 * It is not valid to compare pointers using the relational operators
	 * unless they point to elements in the same array.
	 */
	uint64_t x = (uintptr_t)p1->dple_ptr;
	uint64_t y = (uintptr_t)p2->dple_ptr;
	int rc;
	rc = ((x > y) ? 1 : ((x < y) ? -1 : 0));
	return (rc);
}

int
/* ARGSUSED */
dtj_string_list_entry_cmp(const void *v1, const void *v2, void *arg)
{
	const dtj_string_list_entry_t *p1 = v1;
	const dtj_string_list_entry_t *p2 = v2;
	const char *s1 = p1->dsle_value;
	const char *s2 = p2->dsle_value;
	if (s1 == NULL) {
		return (s2 == NULL ? 0 : -1);
	}
	if (s2 == NULL) {
		return (1);
	}
	return (strcmp(s1, s2));
}

static boolean_t
dtj_check_pointer_pool(void)
{
	if (g_pointer_pool == NULL) {
		g_pointer_pool = uu_list_pool_create("g_pointer_pool",
		    sizeof (dtj_pointer_list_entry_t),
		    offsetof(dtj_pointer_list_entry_t, dple_node),
		    dtj_pointer_list_entry_cmp,
		    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
		if (g_pointer_pool == NULL) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

uu_list_t *
dtj_pointer_list_create(void)
{
	uu_list_t *list;

	if (!dtj_check_pointer_pool()) {
		return (NULL);
	}

	list = uu_list_create(g_pointer_pool, NULL,
	    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
	return (list);
}

dtj_pointer_list_entry_t *
dtj_pointer_list_entry_create(void *p)
{
	dtj_pointer_list_entry_t *e;

	if (!dtj_check_pointer_pool()) {
		return (NULL);
	}

	e = uu_zalloc(sizeof (dtj_pointer_list_entry_t));
	if (e) {
		uu_list_node_init(e, &e->dple_node, g_pointer_pool);
		e->dple_ptr = p;
	}
	return (e);
}

static boolean_t
dtj_check_string_pool(void)
{
	if (g_string_pool == NULL) {
		g_string_pool = uu_list_pool_create("g_string_pool",
		    sizeof (dtj_string_list_entry_t),
		    offsetof(dtj_string_list_entry_t, dsle_node),
		    dtj_string_list_entry_cmp,
		    (g_dtj_util_debug ? UU_LIST_POOL_DEBUG : 0));
		if (g_string_pool == NULL) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

uu_list_t *
dtj_string_list_create(void)
{
	uu_list_t *list;

	if (!dtj_check_string_pool()) {
		return (NULL);
	}

	list = uu_list_create(g_string_pool, NULL,
	    (g_dtj_util_debug ? UU_LIST_DEBUG : 0));
	return (list);
}

dtj_string_list_entry_t *
dtj_string_list_entry_create(const char *s)
{
	dtj_string_list_entry_t *e;

	if (!dtj_check_string_pool()) {
		return (NULL);
	}

	e = uu_zalloc(sizeof (dtj_string_list_entry_t));
	if (e) {
		uu_list_node_init(e, &e->dsle_node, g_string_pool);
		if (s) {
			e->dsle_value = malloc(strlen(s) + 1);
			if (e->dsle_value) {
				(void) strcpy(e->dsle_value, s);
			} else {
				uu_list_node_fini(e, &e->dsle_node,
				    g_string_pool);
				uu_free(e);
				e = NULL;
			}
		}
	}
	return (e);
}

void
dtj_pointer_list_entry_destroy(void *v,
    dtj_value_destroy_f *value_destroy, void *arg)
{
	if (v) {
		dtj_pointer_list_entry_t *e = v;
		if (value_destroy) {
			value_destroy(e->dple_ptr, arg);
		}
		uu_list_node_fini(e, &e->dple_node, g_pointer_pool);
		e->dple_ptr = NULL;
		uu_free(v);
	}
}

void
/* ARGSUSED */
dtj_string_list_entry_destroy(void *v, void *arg)
{
	if (v) {
		dtj_string_list_entry_t *e = v;
		free(e->dsle_value);
		uu_list_node_fini(e, &e->dsle_node, g_string_pool);
		e->dsle_value = NULL;
		uu_free(v);
	}
}

void
dtj_list_clear(uu_list_t *list, dtj_value_destroy_f *value_destroy,
    void *arg)
{
	void *cookie; /* needed for uu_list_teardown */
	void *value;

	if (!list) {
		return;
	}

	cookie = NULL;
	if (value_destroy) {
		while ((value = uu_list_teardown(list, &cookie)) != NULL) {
			value_destroy(value, arg);
		}
	} else {
		while ((value = uu_list_teardown(list, &cookie)) != NULL) {
		}
	}
}

void
dtj_list_destroy(uu_list_t *list,
    dtj_value_destroy_f *value_destroy, void *arg)
{
	dtj_list_clear(list, value_destroy, arg);
	uu_list_destroy(list);
}

void
dtj_pointer_list_clear(uu_list_t *list,
    dtj_value_destroy_f *value_destroy, void *arg)
{
	void *cookie; /* needed for uu_list_teardown */
	dtj_pointer_list_entry_t *e;

	if (!list) {
		return;
	}

	cookie = NULL;
	while ((e = uu_list_teardown(list, &cookie)) != NULL) {
		dtj_pointer_list_entry_destroy(e, value_destroy, arg);
	}
}

void
dtj_pointer_list_destroy(uu_list_t *list,
    dtj_value_destroy_f *value_destroy, void *arg)
{
	dtj_pointer_list_clear(list, value_destroy, arg);
	uu_list_destroy(list);
}

void
dtj_string_list_clear(uu_list_t *list)
{
	dtj_list_clear(list, dtj_string_list_entry_destroy, NULL);
}

void
dtj_string_list_destroy(uu_list_t *list)
{
	dtj_list_destroy(list, dtj_string_list_entry_destroy, NULL);
}

boolean_t
dtj_list_empty(uu_list_t *list)
{
	return (uu_list_numnodes(list) == 0);
}

boolean_t
dtj_list_add(uu_list_t *list, void *value)
{
	return (uu_list_insert_before(list, NULL, value) == 0);
}

boolean_t
dtj_pointer_list_add(uu_list_t *list, void *p)
{
	dtj_pointer_list_entry_t *e = dtj_pointer_list_entry_create(p);
	if (!e) {
		return (B_FALSE);
	}
	return (dtj_list_add(list, e));
}

void *
dtj_pointer_list_walk_next(uu_list_walk_t *itr)
{
	dtj_pointer_list_entry_t *e = uu_list_walk_next(itr);
	if (!e) {
		return (DTJ_INVALID_PTR);
	}
	return (e->dple_ptr);
}

void *
dtj_pointer_list_first(uu_list_t *list)
{
	dtj_pointer_list_entry_t *e = uu_list_first(list);
	if (!e) {
		/* NULL is a valid value; use -1 for invalid */
		return (DTJ_INVALID_PTR);
	}
	return (e->dple_ptr);
}

void *
dtj_pointer_list_last(uu_list_t *list)
{
	dtj_pointer_list_entry_t *e = uu_list_last(list);
	if (!e) {
		/* NULL is a valid value; use -1 for invalid */
		return (DTJ_INVALID_PTR);
	}
	return (e->dple_ptr);
}

boolean_t
dtj_string_list_add(uu_list_t *list, const char *s)
{
	dtj_string_list_entry_t *e = dtj_string_list_entry_create(s);
	if (!e) {
		return (B_FALSE);
	}
	return (dtj_list_add(list, e));
}

const char *
dtj_string_list_walk_next(uu_list_walk_t *itr)
{
	dtj_string_list_entry_t *e = uu_list_walk_next(itr);
	if (!e) {
		return (DTJ_INVALID_STR);
	}
	return (e->dsle_value);
}

const char *
dtj_string_list_first(uu_list_t *list)
{
	dtj_string_list_entry_t *e = uu_list_first(list);
	if (!e) {
		/* NULL is a valid string value; use -1 for invalid */
		return (DTJ_INVALID_STR);
	}
	return (e->dsle_value);
}

const char *
dtj_string_list_last(uu_list_t *list)
{
	dtj_string_list_entry_t *e = uu_list_last(list);
	if (!e) {
		/* NULL is a valid string value; use -1 for invalid */
		return (DTJ_INVALID_STR);
	}
	return (e->dsle_value);
}
