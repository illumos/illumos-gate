/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <jni.h>
#include <pool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>

#include "jpool.h"

struct pool_callback {
	jobject	pc_user;
	jobject	pc_handler;
	jobject	pc_elem;
	JNIEnv	*pc_env;
};

static void throwException(JNIEnv *, const char *, const char *);
static void throw_pe(JNIEnv *);
static jobject makeUnsignedInt64(JNIEnv *, uint64_t);
static int pool_property_walker(pool_conf_t *, pool_elem_t *p, const char *,
    pool_value_t *, void *);
static jobject copyArray(JNIEnv *, void **);

/*
 * Cached class, method, and field IDs.
 */
static jclass ui64class;
static jmethodID ui64cons_mid;

/*
 * Throw an exception of the specified class with the specified message.
 */
void
throwException(JNIEnv *env, const char *class, const char *msg)
{
	jclass clazz;

	clazz = (*env)->FindClass(env, class);

	(*env)->ThrowNew(env, clazz, msg);
}

/*
 * Throw a PoolsException.
 */
void
throw_pe(JNIEnv *jenv)
{
	jclass clazz;
	jmethodID mid;
	jthrowable throwObj;

	clazz = (*jenv)->FindClass(jenv,
	    "com/sun/solaris/service/pools/PoolsException");
	mid = (*jenv)->GetMethodID(jenv, clazz, "<init>", "()V");
	throwObj = (*jenv)->NewObject(jenv, clazz, mid);
	(*jenv)->Throw(jenv, throwObj);
}

/*
 * Return an instance of an UnsignedInt64 class which encapsulates the
 * supplied value.
 */
jobject
makeUnsignedInt64(JNIEnv *env, uint64_t value)
{
	jobject valueObj;
	jobject byteArray;
	jbyte *bytes;
	int i;

	if (!(byteArray = (*env)->NewByteArray(env, 9)))
		return (NULL); /* OutOfMemoryError thrown */
	if (!(bytes = (*env)->GetByteArrayElements(env, byteArray, NULL)))
		return (NULL); /* OutOfMemoryError thrown */

	/*
	 * Interpret the uint64_t as a 9-byte big-endian signed quantity
	 * suitable for constructing an UnsignedInt64 or BigInteger.
	 */
	for (i = 8; i >= 1; i--) {
		bytes[i] = value & 0xff;
		value >>= 8;
	}
	bytes[0] = 0;
	(*env)->ReleaseByteArrayElements(env, byteArray, bytes, 0);

	if (!(valueObj = (*env)->NewObject(env, ui64class, ui64cons_mid,
	    byteArray)))
		return (NULL); /* exception thrown */

	return (valueObj);
}

/*
 * Create an array list and then copy the native array into it
 */
jobject
copyArray(JNIEnv *jenv, void **nativeArray)
{
	int i;
	jobject jresult = NULL;

	if (nativeArray != NULL) {
		jclass ALclazz;
		jmethodID ALinit, ALadd;
		jclass Lclazz;
		jmethodID Linit;

		ALclazz = (*jenv)->FindClass(jenv,
		    "java/util/ArrayList");
		ALinit = (*jenv)->GetMethodID(jenv,
		    ALclazz, "<init>", "()V");
		ALadd = (*jenv)->GetMethodID(jenv,
		    ALclazz, "add", "(Ljava/lang/Object;)Z");
		jresult = (*jenv)->NewObject(jenv, ALclazz, ALinit);
		Lclazz = (*jenv)->FindClass(jenv, "java/lang/Long");
		Linit = (*jenv)->GetMethodID(jenv,
		    Lclazz, "<init>", "(J)V");
		for (i = 0; nativeArray[i] != NULL; i++) {
			jobject L;
			/* Build longs and add them */
			L = (*jenv)->NewObject(jenv,
			    Lclazz, Linit, (jlong)(uintptr_t)nativeArray[i]);
			(*jenv)->CallBooleanMethod(jenv,
			    jresult, ALadd, L);
		}
		free(nativeArray);
	}
	return (jresult);
}

/*
 * pool_version(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1version(JNIEnv *jenv,
    jclass jcls, jlong jver)
{
	return ((jlong)pool_version((uint_t)jver));
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POX_1NATIVE(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POX_NATIVE);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POX_1TEXT(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POX_TEXT);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1INVAL(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POC_INVAL);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1UINT(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POC_UINT);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1INT(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POC_INT);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1DOUBLE(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POC_DOUBLE);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1BOOL(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POC_BOOL);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1STRING(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POC_STRING);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1NONE(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POV_NONE);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1LOOSE(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POV_LOOSE);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1STRICT(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POV_STRICT);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1RUNTIME(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POV_RUNTIME);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1INVALID(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POF_INVALID);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1VALID(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POF_VALID);
}

/*
 * native constant accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1DESTROY(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)POF_DESTROY);
}

/*
 * pool_error(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1error(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)pool_error());
}

/*
 * pool_strerror(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1strerror(JNIEnv *jenv,
    jclass jcls, jint jperr)
{
	jstring jresult = NULL;
	char *result;

	result = (char *)pool_strerror((int)jperr);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	return (jresult);
}

/*
 * strerror(3c) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1strerror_1sys(JNIEnv *
    jenv, jclass jcls)
{
	jstring jresult = NULL;
	char *result;

	result = (char *)strerror(errno);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	return (jresult);
}

/*
 * errno(3c) accessor
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolsException_getErrno(JNIEnv *jenv,
    jclass jcls)
{
	return ((jint)errno);
}

/*
 * pool_resource_type_list(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1type_1list(
    JNIEnv *jenv, jclass jcls, jlong jreslist, jlong jnumres)
{
	char **reslist = (char **)(uintptr_t)jreslist;
	uint_t *numres = (uint_t *)(uintptr_t)jnumres;

	return ((jint)pool_resource_type_list((char const **)reslist, numres));
}

/*
 * pool_get_status(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1status(JNIEnv *jenv,
    jclass jcls)
{
	int status;
	int err;

	err = pool_get_status(&status);
	if (err == -1)
		return ((jint)PO_FAIL);
	else
		return ((jint)status);
}

/*
 * pool_set_status(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1set_1status(JNIEnv *jenv,
    jclass jcls, jint jstate)
{
	return ((jint)pool_set_status((int)jstate));
}

/*
 * pool_conf_alloc(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1alloc(JNIEnv *jenv,
    jclass jcls)
{
	return ((jlong)(uintptr_t)pool_conf_alloc());
}

/*
 * pool_conf_free(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1free(JNIEnv *jenv,
    jclass jcls, jlong jconf)
{
	pool_conf_free((pool_conf_t *)(uintptr_t)jconf);
}

/*
 * pool_conf_status(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1status(JNIEnv *jenv,
    jclass jcls, jlong jconf)
{
	return ((jint)pool_conf_status((pool_conf_t *)(uintptr_t)jconf));
}

/*
 * pool_conf_close(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1close(JNIEnv *jenv,
    jclass jcls, jlong jconf)
{
	return ((jint)pool_conf_close((pool_conf_t *)(uintptr_t)jconf));
}

/*
 * pool_conf_remove(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1remove(JNIEnv *jenv,
    jclass jcls, jlong jconf)
{
	return ((jint)pool_conf_remove((pool_conf_t *)(uintptr_t)jconf));
}

/*
 * pool_conf_open(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1open(JNIEnv *jenv,
    jclass jcls, jlong jconf, jstring jlocation, jint jflags)
{
	const char *location;
	int result;

	location = (jlocation) ? (*jenv)->GetStringUTFChars(jenv,
	    jlocation, 0) : NULL;
	result = (int)pool_conf_open((pool_conf_t *)(uintptr_t)jconf, location,
	    (int)jflags);

	if (location)
		(*jenv)->ReleaseStringUTFChars(jenv, jlocation, location);
	return ((jint)result);
}

/*
 * pool_conf_rollback(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1rollback(
    JNIEnv *jenv, jclass jcls, jlong jconf)
{
	return ((jint)pool_conf_rollback((pool_conf_t *)(uintptr_t)jconf));
}

/*
 * pool_conf_commit(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1commit(JNIEnv *jenv,
    jclass jcls, jlong jconf, jint jactive)
{
	return ((jint)pool_conf_commit(
	    (pool_conf_t *)(uintptr_t)jconf, (int)jactive));
}

/*
 * pool_conf_export(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1export(JNIEnv *jenv,
    jclass jcls, jlong jconf, jstring jlocation, jint jformat)
{
	const char *location;
	int result;

	location = (jlocation) ? (*jenv)->GetStringUTFChars(jenv,
	    jlocation, 0) : NULL;
	result = (int)pool_conf_export((pool_conf_t *)(uintptr_t)jconf,
	    location, (pool_export_format_t)jformat);

	if (location)
		(*jenv)->ReleaseStringUTFChars(jenv, jlocation, location);
	return ((jint)result);
}

/*
 * pool_conf_validate(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1validate(
    JNIEnv *jenv, jclass jcls, jlong jconf, jint jlevel)
{
	return ((jint)pool_conf_validate((pool_conf_t *)(uintptr_t)jconf,
	    (pool_valid_level_t)jlevel));
}

/*
 * pool_conf_update(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1update(JNIEnv *jenv,
    jclass jcls, jlong jconf)
{
	int changed;
	int result;

	result = pool_conf_update((pool_conf_t *)(uintptr_t)jconf, &changed);

	if (result != PO_SUCCESS) {
		throw_pe(jenv);
	}

	return ((jint)changed);
}

/*
 * pool_get_pool(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1pool(JNIEnv *jenv,
    jclass jcls, jlong jconf, jstring jname)
{
	const char *name;
	pool_t *result;

	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) :
	    NULL;
	result = (pool_t *)pool_get_pool((pool_conf_t *)(uintptr_t)jconf, name);

	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jlong)(uintptr_t)result);
}

/*
 * pool_query_pools(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1pools(JNIEnv *jenv,
    jclass jcls, jlong jconf, jobject jprops)
{
	pool_value_t **props;
	pool_t **result;
	jclass Lclazz;
	jmethodID Lsize;
	jint size;
	uint_t nelem;
	int i;


	/*
	 * Initialize the target parameter for case when input is null
	 */
	props = NULL;
	if (jprops != NULL) {
		Lclazz = (*jenv)->GetObjectClass(jenv, jprops);
		Lsize = (*jenv)->GetMethodID(jenv, Lclazz, "size", "()I");
		size = (*jenv)->CallIntMethod(jenv, jprops, Lsize);

		if (size != 0) {
			jmethodID Lget;

			Lget = (*jenv)->GetMethodID(jenv, Lclazz, "get",
			    "(I)Ljava/lang/Object;");
			/*
			 * Allocate space for the props array
			 */

			if ((props = calloc(size + 1, sizeof (pool_value_t *)))
			    == NULL) {
				throwException(jenv, "java/lang/Exception",
				    "Could not allocate props array");
				return (NULL);
			}
			/*
			 * Copy in the array
			 */
			for (i = 0; i < size; i++) {
				jobject aVal;
				jclass Vclazz;
				jfieldID Vthis;
				jlong this;

				aVal = (*jenv)->CallObjectMethod(jenv, jprops,
				    Lget, (jint) i);
				Vclazz = (*jenv)->GetObjectClass(jenv, aVal);
				Vthis = (*jenv)->GetFieldID(jenv, Vclazz,
				    "_this", "J");
				this = (*jenv)->GetLongField(jenv, aVal, Vthis);
				props[i] = (pool_value_t *)(uintptr_t)this;
			}
		}
	}
	result = pool_query_pools((pool_conf_t *)(uintptr_t)jconf, &nelem,
	    props);
	free(props);
	return (copyArray(jenv, (void **)result));
}

/*
 * pool_get_resource(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1resource(
    JNIEnv *jenv, jclass jcls, jlong jconf, jstring jtype, jstring jname)
{
	const char *type;
	const char *name;
	pool_resource_t *result;

	type = (jtype) ? (*jenv)->GetStringUTFChars(jenv, jtype, 0) :
	    NULL;
	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) :
	    NULL;
	result = pool_get_resource((pool_conf_t *)(uintptr_t)jconf, type, name);

	if (type)
		(*jenv)->ReleaseStringUTFChars(jenv, jtype, type);
	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jlong)(uintptr_t)result);
}

/*
 * pool_query_resources(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1resources(
    JNIEnv *jenv, jclass jcls, jlong jconf, jobject jprops)
{
	pool_value_t **props;
	pool_resource_t **result;
	jclass Lclazz;
	jmethodID Lsize;
	jint size;
	uint_t nelem;
	int i;

	/*
	 * Initialize the target parameter for case when input is null
	 */
	props = NULL;
	if (jprops != NULL) {
		Lclazz = (*jenv)->GetObjectClass(jenv, jprops);
		Lsize = (*jenv)->GetMethodID(jenv, Lclazz, "size", "()I");
		size = (*jenv)->CallIntMethod(jenv, jprops, Lsize);

		if (size != 0) {
			jmethodID Lget;

			Lget = (*jenv)->GetMethodID(jenv, Lclazz, "get",
			    "(I)Ljava/lang/Object;");
			/*
			 * Allocate space for the props array
			 */
			if ((props = calloc(size + 1, sizeof (pool_value_t *)))
			    == NULL) {
				throwException(jenv, "java/lang/Exception",
				    "Could not allocate props array");
				return (NULL);
			}
			/*
			 * Copy in the array
			 */
			for (i = 0; i < size; i++) {
				jobject aVal;
				jclass Vclazz;
				jfieldID Vthis;
				jlong this;


				aVal = (*jenv)->CallObjectMethod(jenv, jprops,
				    Lget, (jint) i);
				Vclazz = (*jenv)->GetObjectClass(jenv, aVal);
				Vthis = (*jenv)->GetFieldID(jenv, Vclazz,
				    "_this", "J");
				this = (*jenv)->GetLongField(jenv, aVal, Vthis);
				props[i] = (pool_value_t *)(uintptr_t)this;
			}
		}
	}
	result = pool_query_resources((pool_conf_t *)(uintptr_t)jconf, &nelem,
	    props);
	free(props);
	return (copyArray(jenv, (void *)result));
}

/*
 * pool_query_components(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1components(
    JNIEnv *jenv, jclass jcls, jlong jconf, jobject jprops)
{
	pool_value_t **props;
	pool_component_t **result;
	jclass Lclazz;
	jmethodID Lsize;
	jint size;
	uint_t nelem;
	int i;

	/*
	 * Initialize the target parameter for case when input is null
	 */
	props = NULL;
	if (jprops != NULL) {
		Lclazz = (*jenv)->GetObjectClass(jenv, jprops);
		Lsize = (*jenv)->GetMethodID(jenv, Lclazz, "size", "()I");
		size = (*jenv)->CallIntMethod(jenv, jprops, Lsize);

		if (size != 0) {
			jmethodID Lget;

			Lget = (*jenv)->GetMethodID(jenv, Lclazz, "get",
			    "(I)Ljava/lang/Object;");
			/*
			 * Allocate space for the props array
			 */

			if ((props = calloc(size + 1, sizeof (pool_value_t *)))
			    == NULL) {
				throwException(jenv, "java/lang/Exception",
				    "Could not allocate props array");
				return (NULL);
			}
			/*
			 * Copy in the array
			 */
			for (i = 0; i < size; i++) {
				jobject aVal;
				jclass Vclazz;
				jfieldID Vthis;
				jlong this;

				aVal = (*jenv)->CallObjectMethod(jenv, jprops,
				    Lget, (jint) i);
				Vclazz = (*jenv)->GetObjectClass(jenv, aVal);
				Vthis = (*jenv)->GetFieldID(jenv, Vclazz,
				    "_this", "J");
				this = (*jenv)->GetLongField(jenv, aVal, Vthis);
				props[i] = (pool_value_t *)(uintptr_t)this;
			}
		}
	}
	result = pool_query_components((pool_conf_t *)(uintptr_t)jconf, &nelem,
	    props);
	free(props);
	return (copyArray(jenv, (void **)result));
}

/*
 * pool_conf_location(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1location(
    JNIEnv *jenv, jclass jcls, jlong jconf)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_conf_location((pool_conf_t *)(uintptr_t)jconf);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	return (jresult);
}

/*
 * pool_conf_info(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1info(JNIEnv *jenv,
    jclass jcls, jlong jconf, jint jflags)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_conf_info((pool_conf_t *)(uintptr_t)jconf, (int)jflags);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	free((void *)result);
	return (jresult);
}

/*
 * pool_resource_create(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1create(
    JNIEnv *jenv, jclass jcls, jlong jconf, jstring jtype, jstring jname)
{
	const char *type;
	const char *name;
	pool_resource_t *result;

	type = (jtype) ? (*jenv)->GetStringUTFChars(jenv, jtype, 0) :
	    NULL;
	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) :
	    NULL;
	result =
	    pool_resource_create((pool_conf_t *)(uintptr_t)jconf, type, name);

	if (type)
		(*jenv)->ReleaseStringUTFChars(jenv, jtype, type);
	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jlong)(uintptr_t)result);
}

/*
 * pool_resource_destroy(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1destroy(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource)
{
	return ((jint)pool_resource_destroy((pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jresource));
}

/*
 * pool_resource_transfer(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1transfer(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jsource, jlong jtarget,
    jlong jsize)
{
	return (pool_resource_transfer((pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jsource,
	    (pool_resource_t *)(uintptr_t)jtarget,
	    (uint64_t)jsize));
}

/*
 * pool_resource_xtransfer(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1xtransfer(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jsource, jlong jtarget,
    jobject jcomponents)
{
	pool_component_t **components;
	int result;
	jclass Lclazz;
	jmethodID Lsize;
	jint size;

	/*
	 * Initialize the target parameter for case when input is null
	 */
	components = NULL;
	if (jcomponents != NULL) {
		Lclazz = (*jenv)->GetObjectClass(jenv, jcomponents);
		Lsize = (*jenv)->GetMethodID(jenv, Lclazz, "size", "()I");
		size = (*jenv)->CallIntMethod(jenv, jcomponents, Lsize);

		if (size != 0) {
			jmethodID Lget;
			int i;

			Lget = (*jenv)->GetMethodID(jenv,
			    Lclazz, "get", "(I)Ljava/lang/Object;");
			/* Allocate space for the components array */

			if ((components = calloc(size + 1,
			    sizeof (pool_component_t *))) == NULL) {
				throwException(jenv, "java/lang/Exception",
				    "Could not allocate component array");
				return (0);
			}
			/*
			 * Copy in the array
			 */
			for (i = 0; i < size; i++) {
				jobject aVal;
				jclass Vclazz;
				jlong this;
				jmethodID Vthis;

				aVal = (*jenv)->CallObjectMethod(jenv,
				    jcomponents, Lget, (jint) i);
				Vclazz = (*jenv)->GetObjectClass(jenv,
				    aVal);
				Vthis = (*jenv)->GetMethodID(jenv,
				    Vclazz, "getComponent", "()J");
				this = (*jenv)->CallLongMethod(jenv,
				    aVal, Vthis);
				components[i] =
				    (pool_component_t *)(uintptr_t)this;
			}
		}
	}
	result = (int)pool_resource_xtransfer((pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jsource,
	    (pool_resource_t *)(uintptr_t)jtarget,
	    components);
	free(components);

	return ((jint)result);
}

/*
 * pool_query_resource_components(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1resource_\
1components(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource,
    jobject jprops)
{
	pool_value_t **props;
	pool_component_t **result;
	jclass Lclazz;
	jmethodID Lsize;
	uint_t nelem;
	jint size;

	/*
	 * Initialize the target parameter for case when input is null
	 */
	props = NULL;
	if (jprops != NULL) {
		Lclazz = (*jenv)->GetObjectClass(jenv, jprops);
		Lsize = (*jenv)->GetMethodID(jenv, Lclazz, "size", "()I");
		size = (*jenv)->CallIntMethod(jenv, jprops, Lsize);

		if (size != 0) {
			jmethodID Lget;
			int i;

			Lget = (*jenv)->GetMethodID(jenv, Lclazz, "get",
			    "(I)Ljava/lang/Object;");
			/*
			 * Allocate space for the props array
			 */
			if ((props = calloc(size + 1, sizeof (pool_value_t *)))
			    == NULL) {
				throwException(jenv, "java/lang/Exception",
				    "Could not allocate props array");
				return (NULL);
			}
			/*
			 * Copy in the array
			 */
			for (i = 0; i < size; i++) {
				jobject aVal;
				jclass Vclazz;
				jfieldID Vthis;
				jlong this;

				aVal = (*jenv)->CallObjectMethod(jenv, jprops,
				    Lget, (jint) i);
				Vclazz = (*jenv)->GetObjectClass(jenv, aVal);
				Vthis = (*jenv)->GetFieldID(jenv, Vclazz,
				    "_this", "J");
				this = (*jenv)->GetLongField(jenv, aVal, Vthis);
				props[i] = (pool_value_t *)(uintptr_t)this;
			}
		}
	}
	result = pool_query_resource_components(
	    (pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jresource, &nelem, props);
	free(props);
	return (copyArray(jenv, (void **)result));
}

/*
 * pool_resource_info(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1info(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource, jint jflags)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_resource_info((pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jresource, (int)jflags);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	free((void *)result);
	return (jresult);
}

/*
 * pool_create(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1create(JNIEnv *jenv,
    jclass jcls, jlong jconf, jstring jname)
{
	const char *name;
	pool_t *result;

	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) :
	    NULL;
	result = pool_create((pool_conf_t *)(uintptr_t)jconf, name);

	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jlong)(uintptr_t)result);
}

/*
 * pool_destroy(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1destroy(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jpool)
{
	return ((jint)pool_destroy((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool));
}

/*
 * pool_associate(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1associate(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jpool, jlong jresource)
{
	return ((jint)pool_associate((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool,
	    (pool_resource_t *)(uintptr_t)jresource));
}

/*
 * pool_dissociate(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1dissociate(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jpool, jlong jresource)
{
	return ((jint)pool_dissociate((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool,
	    (pool_resource_t *)(uintptr_t)jresource));
}

/*
 * pool_info(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1info(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jpool, jint jflags)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_info((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool, (int)jflags);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	free((void *)result);
	return (jresult);
}

/*
 * pool_query_pool_resources(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1pool_1resources(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, jobject jprops)
{
	pool_value_t **props;
	pool_resource_t **result;
	jclass Lclazz;
	jmethodID Lsize;
	uint_t nelem;
	jint size;

	/*
	 * Initialize the target parameter for case when input is null
	 */
	props = NULL;
	if (jprops != NULL) {
		Lclazz = (*jenv)->GetObjectClass(jenv, jprops);
		Lsize = (*jenv)->GetMethodID(jenv, Lclazz, "size", "()I");
		size = (*jenv)->CallIntMethod(jenv, jprops, Lsize);

		if (size != 0) {
			jmethodID Lget;
			int i;

			Lget = (*jenv)->GetMethodID(jenv,
			    Lclazz, "get", "(I)Ljava/lang/Object;");
			/*
			 * Allocate space for the props array
			 */

			if ((props = calloc(size + 1, sizeof (pool_value_t *)))
			    == NULL) {
				throwException(jenv, "java/lang/Exception",
				    "Could not allocate props array");
				return (NULL);
			}
			/*
			 * Copy in the array
			 */
			for (i = 0; i < size; i++) {
				jobject aVal;
				jclass Vclazz;
				jfieldID Vthis;
				jlong this;

				aVal = (*jenv)->CallObjectMethod(jenv, jprops,
				    Lget, (jint) i);
				Vclazz = (*jenv)->GetObjectClass(jenv, aVal);
				Vthis = (*jenv)->GetFieldID(jenv, Vclazz,
				    "_this", "J");
				this = (*jenv)->GetLongField(jenv, aVal, Vthis);
				props[i] = (pool_value_t *)(uintptr_t)this;
			}
		}
	}
	result = pool_query_pool_resources((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool, &nelem, props);
	free(props);
	return (copyArray(jenv, (void **)result));
}

/*
 * pool_get_owning_resource(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1owning_1resource(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jcomponent)
{
	return ((jlong)(uintptr_t)pool_get_owning_resource(
	    (pool_conf_t *)(uintptr_t)jconf,
	    (pool_component_t *)(uintptr_t)jcomponent));
}

/*
 * pool_component_info(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1component_1info(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jcomponent, jint jflags)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_component_info((pool_conf_t *)(uintptr_t)jconf,
	    (pool_component_t *)(uintptr_t)jcomponent, (int)jflags);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	free((void *)result);
	return (jresult);
}

/*
 * pool_get_property(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1property(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, jstring jname,
    jlong jproperty)
{
	const char *name;
	int result;

	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) :
	    NULL;
	result = pool_get_property((pool_conf_t *)(uintptr_t)jconf,
	    (pool_elem_t *)(uintptr_t)jelem, name,
	    (pool_value_t *)(uintptr_t)jproperty);

	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jint)result);
}

/*
 * pool_put_property(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1put_1property(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, jstring jname,
    jlong jvalue)
{
	const char *name;
	int result;

	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) : NULL;
	result = (int)pool_put_property((pool_conf_t *)(uintptr_t)jconf,
	    (pool_elem_t *)(uintptr_t)jelem, name,
	    (pool_value_t *)(uintptr_t)jvalue);

	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jint)result);
}

/*
 * pool_rm_property(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1rm_1property(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jelem, jstring jname)
{
	const char *name;
	int result;

	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) : NULL;
	result = pool_rm_property((pool_conf_t *)(uintptr_t)jconf,
	    (pool_elem_t *)(uintptr_t)jelem, name);

	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jint)result);
}

/*
 * pool_walk_properties(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1properties(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, jlong jarg,
    jlong jcallback)
{
	int result;

	result = (int)pool_walk_properties((pool_conf_t *)(uintptr_t)jconf,
	    (pool_elem_t *)(uintptr_t)jelem, (void *)(uintptr_t)jarg,
	    (int (*)(pool_conf_t *, pool_elem_t *, char const *,
	    pool_value_t *, void *))(uintptr_t)jcallback);

	return ((jint)result);
}

/*
 * pool_conf_to_elem(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1to_1elem(
    JNIEnv *jenv, jclass jcls, jlong jconf)
{
	return ((jlong)(uintptr_t)pool_conf_to_elem(
	    (pool_conf_t *)(uintptr_t)jconf));
}

/*
 * pool_to_elem(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1to_1elem(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jpool)
{
	return ((jlong)(uintptr_t)pool_to_elem((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool));
}

/*
 * pool_resource_to_elem(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1to_1elem(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource)
{
	return ((jlong)(uintptr_t)pool_resource_to_elem(
	    (pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jresource));
}

/*
 * pool_component_to_elem(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1component_1to_1elem(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jcomponent)
{
	return ((jlong)(uintptr_t)pool_component_to_elem(
	    (pool_conf_t *)(uintptr_t)jconf,
	    (pool_component_t *)(uintptr_t)jcomponent));
}

/*
 * pool_value_get_type(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1get_1type(
    JNIEnv *jenv, jclass jcls, jlong jvalue)
{
	return ((jint)pool_value_get_type((pool_value_t *)(uintptr_t)jvalue));
}

/*
 * pool_value_set_uint64(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1uint64(
    JNIEnv *jenv, jclass jcls, jlong jvalue, jlong jui64)
{
	pool_value_set_uint64(
	    (pool_value_t *)(uintptr_t)jvalue, (uint64_t)jui64);
}

/*
 * pool_value_set_int64(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1int64(
    JNIEnv *jenv, jclass jcls, jlong jvalue, jlong ji64)
{
	pool_value_set_int64((pool_value_t *)(uintptr_t)jvalue, (int64_t)ji64);
}

/*
 * pool_value_set_double(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1double(
    JNIEnv *jenv, jclass jcls, jlong jvalue, jdouble jd)
{
	pool_value_set_double((pool_value_t *)(uintptr_t)jvalue, (double)jd);
}

/*
 * pool_value_set_bool(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1bool(
    JNIEnv *jenv, jclass jcls, jlong jvalue, jshort jb)
{
	pool_value_set_bool((pool_value_t *)(uintptr_t)jvalue, (uchar_t)jb);
}

/*
 * pool_value_set_string(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1string(
    JNIEnv * jenv, jclass jcls, jlong jvalue, jstring jstr)
{
	const char *str;
	int result;

	str = (jstr) ? (*jenv)->GetStringUTFChars(jenv, jstr, 0) : NULL;
	result = pool_value_set_string((pool_value_t *)(uintptr_t)jvalue, str);

	if (str)
		(*jenv)->ReleaseStringUTFChars(jenv, jstr, str);
	return ((jint)result);
}

/*
 * pool_value_get_name(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1get_1name(
    JNIEnv *jenv, jclass jcls, jlong jvalue)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_value_get_name((pool_value_t *)(uintptr_t)jvalue);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	return (jresult);
}

/*
 * pool_value_set_name(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1name(
    JNIEnv *jenv, jclass jcls, jlong jvalue, jstring jname)
{
	const char *name;
	int result;

	name = (jname) ? (*jenv)->GetStringUTFChars(jenv, jname, 0) : NULL;
	result = pool_value_set_name((pool_value_t *)(uintptr_t)jvalue, name);

	if (name)
		(*jenv)->ReleaseStringUTFChars(jenv, jname, name);
	return ((jint)result);
}

/*
 * pool_value_alloc(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1alloc(JNIEnv *jenv,
    jclass jcls)
{
	return ((jlong)(uintptr_t)pool_value_alloc());
}

/*
 * pool_value_free(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1free(JNIEnv *jenv,
    jclass jcls, jlong jvalue)
{
	pool_value_free((pool_value_t *)(uintptr_t)jvalue);
}

/*
 * pool_static_location(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1static_1location(
    JNIEnv *jenv, jclass jcls)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_static_location();

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	return (jresult);
}

/*
 * pool_dynamic_location(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1dynamic_1location(JNIEnv *
    jenv, jclass jcls)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_dynamic_location();

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	return (jresult);
}

/*
 * pool_set_binding(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1set_1binding(JNIEnv *jenv,
    jclass jcls, jstring jpool, jint jidtype, jint jpid)
{
	const char *pool;
	int result;

	pool = (jpool) ? (*jenv)->GetStringUTFChars(jenv, jpool, 0) : NULL;
	result = (int)pool_set_binding(pool, (idtype_t)jidtype, (id_t)jpid);

	if (pool)
		(*jenv)->ReleaseStringUTFChars(jenv, jpool, pool);
	return ((jint)result);
}

/*
 * pool_get_binding(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1binding(JNIEnv *jenv,
    jclass jcls, jint jpid)
{
	jstring jresult = NULL;
	const char *result;

	result = pool_get_binding((pid_t)jpid);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	free((void *)result);
	return (jresult);
}

/*
 * pool_get_resource_binding(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1resource_1binding(
    JNIEnv *jenv, jclass jcls, jstring jtype, jint jpid)
{
	jstring jresult = NULL;
	const char *type;
	const char *result;

	type = (jtype) ? (*jenv)->GetStringUTFChars(jenv, jtype, 0) : NULL;
	result = pool_get_resource_binding(type, (pid_t)jpid);

	if (result)
		jresult = (*jenv)->NewStringUTF(jenv, result);
	free((void *)result);
	if (type)
		(*jenv)->ReleaseStringUTFChars(jenv, jtype, type);
	return (jresult);
}

/*
 * pool_walk_pools(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1pools(JNIEnv *jenv,
    jclass jcls, jlong jconf, jlong jarg, jlong jcallback)
{
	int result;

	result = pool_walk_pools((pool_conf_t *)(uintptr_t)jconf,
	    (void *)(uintptr_t)jarg,
	    (int (*)(pool_conf_t *, pool_t *, void *))(uintptr_t)jcallback);
	return ((jint)result);
}

/*
 * pool_walk_resources(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1resources(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, jlong jarg,
    jlong jcallback)
{
	int result;

	result = pool_walk_resources((pool_conf_t *)(uintptr_t)jconf,
	    (pool_t *)(uintptr_t)jpool, (void *)(uintptr_t)jarg,
	    (int (*)(pool_conf_t *, pool_resource_t *, void *))
	    (uintptr_t)jcallback);
	return ((jint)result);
}

/*
 * pool_walk_components(3pool) wrapper
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1components(
    JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource, jlong jarg,
    jlong jcallback)
{
	int result;

	result = pool_walk_components((pool_conf_t *)(uintptr_t)jconf,
	    (pool_resource_t *)(uintptr_t)jresource, (void *)(uintptr_t)jarg,
	    (int (*)(pool_conf_t *, pool_component_t *, void *))
	    (uintptr_t)jcallback);
	return ((jint)result);
}

/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_pools_Element_walkProps(JNIEnv *env,
    jobject obj, jlong conf, jlong elem, jobject handler, jobject userobj)
{
	struct pool_callback pc;

	pc.pc_user = userobj;
	pc.pc_handler = handler;
	pc.pc_elem = obj;
	pc.pc_env = env;
	return (pool_walk_properties((pool_conf_t *)*(void**)&conf,
	    (pool_elem_t *)*(void**)&elem, (void *)&pc, pool_property_walker));
}

/*ARGSUSED*/
static int
pool_property_walker(pool_conf_t *conf, pool_elem_t *pe, const char *name,
    pool_value_t *pv, void *user)
{
	jclass clazz, vclazz;
	jmethodID mgetwalk, mvcon;
	struct pool_callback *pc = (struct pool_callback *)user;
	jobject valueObj;
	pool_value_t *pv_new;
	uint64_t uval;
	int64_t ival;
	double dval;
	uchar_t bval;
	const char *sval;

	/*
	 * Since we intend to embed our value into a Java Value object
	 * and then reclaim the value when the object is garbage
	 * collected we must create a new pool value and then pass this
	 * to the constructor.  We must not use the pool value which is
	 * passed to us.
	 */

	if ((pv_new = pool_value_alloc()) == NULL)
		return (PO_FAIL);
	switch (pool_value_get_type(pv)) {
	case POC_UINT:
		(void) pool_value_get_uint64(pv, &uval);
		(void) pool_value_set_uint64(pv_new, uval);
		break;
	case POC_INT:
		(void) pool_value_get_int64(pv, &ival);
		(void) pool_value_set_int64(pv_new, ival);
		break;
	case POC_DOUBLE:
		(void) pool_value_get_double(pv, &dval);
		(void) pool_value_set_double(pv_new, dval);
		break;
	case POC_BOOL:
		(void) pool_value_get_bool(pv, &bval);
		(void) pool_value_set_bool(pv_new, bval);
		break;
	case POC_STRING:
		(void) pool_value_get_string(pv, &sval);
		(void) pool_value_set_string(pv_new, sval);
		break;
	default:
		pool_value_free(pv_new);
		return (PO_FAIL);
	}
	if (pool_value_set_name(pv_new, name) != PO_SUCCESS ||
	    (vclazz = (*pc->pc_env)->FindClass(pc->pc_env,
	    "com/sun/solaris/service/pools/Value")) == NULL ||
	    (mvcon = (*pc->pc_env)->GetMethodID(pc->pc_env, vclazz,
	    "<init>", "(J)V")) == NULL ||
	    (valueObj = (*pc->pc_env)->NewObject(pc->pc_env, vclazz, mvcon,
	    pv_new)) == NULL ||
	    (clazz = (*pc->pc_env)->GetObjectClass(pc->pc_env, pc->pc_handler))
	    == NULL ||
	    (mgetwalk = (*pc->pc_env)->GetMethodID(pc->pc_env,
	    clazz, "walk",
	    "(Lcom/sun/solaris/service/pools/Element;Lcom/sun/solaris/"
	    "service/pools/Value;Ljava/lang/Object;)I")) == NULL)
		return (PO_FAIL);
	return ((*pc->pc_env)->CallIntMethod(pc->pc_env,
	    pc->pc_handler, mgetwalk, pc->pc_elem, valueObj, pc->pc_user));
}

/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_pools_Value_getLongValue(JNIEnv *jenv,
    jclass class, jlong pointer)
{
	int64_t arg2;
	int result;

	result =
	    pool_value_get_int64((pool_value_t *)(uintptr_t)pointer, &arg2);

	if (result != PO_SUCCESS) { /* it could be a uint64 */
		result =
		    pool_value_get_uint64((pool_value_t *)(uintptr_t)pointer,
		    (uint64_t *)&arg2);
		if (result != PO_SUCCESS) {
			throw_pe(jenv);
		}
		/*
		 * Unfortunately, Java has no unsigned types, so we lose some
		 * precision by forcing the top bit clear
		 */
		arg2 &= 0x7fffffffffffffffULL;
	}
	return ((jlong)arg2);
}

/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_solaris_service_pools_Value_getStringValue(JNIEnv *jenv,
    jclass class, jlong pointer)
{
	const char *arg2;
	int result;

	result =
	    pool_value_get_string((pool_value_t *)(uintptr_t)pointer, &arg2);
	if (result != PO_SUCCESS)
		throw_pe(jenv);
	return ((*jenv)->NewStringUTF(jenv, arg2));
}

/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_com_sun_solaris_service_pools_Value_getBoolValue(JNIEnv *jenv,
    jclass class, jlong pointer)
{
	uchar_t arg2;
	int result;

	result = pool_value_get_bool((pool_value_t *)(uintptr_t)pointer, &arg2);

	if (result != PO_SUCCESS) {
		throw_pe(jenv);
	}
	if (arg2 == PO_TRUE)
		return (JNI_TRUE);
	else
		return (JNI_FALSE);
}

/*ARGSUSED*/
JNIEXPORT jdouble JNICALL
Java_com_sun_solaris_service_pools_Value_getDoubleValue(JNIEnv *jenv,
    jclass class, jlong pointer)
{
	double arg2;
	int result;

	result =
	    pool_value_get_double((pool_value_t *)(uintptr_t)pointer, &arg2);

	if (result != PO_SUCCESS) {
		throw_pe(jenv);
	}
	return ((jdouble)arg2);
}

/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_Value_getUnsignedInt64Value(JNIEnv *jenv,
    jclass class, jlong pointer)
{
	uint64_t arg2;
	int result;

	result =
	    pool_value_get_uint64((pool_value_t *)(uintptr_t)pointer, &arg2);

	if (result != PO_SUCCESS) {
		throw_pe(jenv);
	}
	return (makeUnsignedInt64(jenv, arg2));
}

/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_pools_HRTime_timestamp(JNIEnv *env, jobject obj)
{
	return (makeUnsignedInt64(env, gethrtime()));
}

/*
 * Cache class, method, and field IDs.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_pools_PoolInternal_init(JNIEnv *env, jclass clazz)
{
	jclass ui64class_lref;

	if (!(ui64class_lref = (*env)->FindClass(env,
	    "com/sun/solaris/service/pools/UnsignedInt64")))
		return; /* exception thrown */
	if (!(ui64class = (*env)->NewGlobalRef(env, ui64class_lref)))
		return; /* exception thrown */
	ui64cons_mid = (*env)->GetMethodID(env, ui64class, "<init>", "([B)V");
}
