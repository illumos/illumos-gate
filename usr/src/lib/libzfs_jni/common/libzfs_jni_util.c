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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libzfs_jni_util.h"
#include <strings.h>

/*
 * Package-private functions
 */

void
zjni_free_array(void **array, zjni_free_f freefunc)
{
	if (array != NULL) {
		if (freefunc != NULL) {
			int i;
			for (i = 0; array[i] != NULL; i++) {
				freefunc(array[i]);
			}
		}
		free(array);
	}
}

/*PRINTFLIKE2*/
void
zjni_throw_exception(JNIEnv *env, const char *fmt, ...)
{
	char error[1024];
	va_list ap;
	jclass class_UnsupportedOperationException;

	va_start(ap, fmt);
	(void) vsnprintf(error, sizeof (error), fmt, ap);
	va_end(ap);

	class_UnsupportedOperationException =
	    (*env)->FindClass(env, "java/lang/UnsupportedOperationException");

	(*env)->ThrowNew(env, class_UnsupportedOperationException, error);
}

jstring
zjni_get_matched_string(JNIEnv *env, char *name, regmatch_t *match)
{
	jstring stringUTF = NULL;
	if (match->rm_so != -1 && match->rm_eo != -1) {
		char *end = name + match->rm_eo;
		char tmp = *end;
		*end = '\0';
		stringUTF = (*env)->NewStringUTF(env, name + match->rm_so);
		*end = tmp;
	}
	return (stringUTF);
}

void
zjni_get_dataset_from_snapshot(const char *snapshot, char *dataset,
    size_t len)
{
	char *at;
	(void) strncpy(dataset, snapshot, len);
	at = strchr(dataset, '@');
	if (at != NULL) {
		*at = '\0';
	}
}

/* Convert a zjni_Collection to a (Java) array */
jobjectArray
zjni_Collection_to_array(JNIEnv *env, zjni_Collection_t *list, char *class)
{
	/* Get size of zjni_Collection */
	jint length = (*env)->CallIntMethod(
	    env, ((zjni_Object_t *)list)->object,
	    ((zjni_Collection_t *)list)->method_size);

	/* Create array to hold elements of list */
	jobjectArray array = (*env)->NewObjectArray(
	    env, length, (*env)->FindClass(env, class), NULL);

	/* Copy list elements to array */
	return (*env)->CallObjectMethod(env, ((zjni_Object_t *)list)->object,
	    ((zjni_Collection_t *)list)->method_toArray, array);
}

/* Create a zjni_Collection */
void
new_Collection(JNIEnv *env, zjni_Collection_t *collection)
{
	zjni_Object_t *object = (zjni_Object_t *)collection;

	collection->method_add = (*env)->GetMethodID(
	    env, object->class, "add", "(Ljava/lang/Object;)Z");

	collection->method_size =
	    (*env)->GetMethodID(env, object->class, "size", "()I");

	collection->method_toArray =
	    (*env)->GetMethodID(env, object->class, "toArray",
		"([Ljava/lang/Object;)[Ljava/lang/Object;");
}

/* Create an zjni_ArrayList */
void
zjni_new_ArrayList(JNIEnv *env, zjni_ArrayList_t *list)
{
	zjni_Object_t *object = (zjni_Object_t *)list;

	if (object->object == NULL) {
		object->class = (*env)->FindClass(env, "java/util/ArrayList");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object = (*env)->NewObject(
		    env, object->class, object->constructor);
	}

	new_Collection(env, (zjni_Collection_t *)list);
}

/* Create an zjni_DatasetSet */
void
zjni_new_DatasetSet(JNIEnv *env, zjni_DatasetSet_t *list)
{
	zjni_Object_t *object = (zjni_Object_t *)list;

	if (object->object == NULL) {
		object->class = (*env)->FindClass(
		    env, "com/sun/zfs/common/util/DatasetSet");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object = (*env)->NewObject(
		    env, object->class, object->constructor);
	}

	new_Collection(env, (zjni_Collection_t *)list);
}

jobject
zjni_int_to_boolean(JNIEnv *env, uint64_t value)
{
	jclass class_Boolean = (*env)->FindClass(
	    env, "java/lang/Boolean");

	jfieldID id = (*env)->GetStaticFieldID(env, class_Boolean,
	    value ? "TRUE" : "FALSE", "Ljava/lang/Boolean;");

	return (*env)->GetStaticObjectField(env, class_Boolean, id);
}

jobject
zjni_int_to_enum(JNIEnv *env, int value, char *class_name,
    char *default_field_name, zjni_field_mapping_t *mapping)
{
	int i;
	char *field_name;
	jclass class;
	jfieldID id;
	jobject field_value = NULL;
	int found = 0;

	for (i = 0; mapping[i].name != NULL; i++) {
		if (value == mapping[i].value) {
			field_name = mapping[i].name;
			found = 1;
			break;
		}
	}

	if (!found) {
		field_name = default_field_name;
	}

	if (field_name != NULL) {
		char signature[1024];

		(void) snprintf(signature, sizeof (signature), "L%s;",
		    class_name);

		class = (*env)->FindClass(env, class_name);
		id = (*env)->GetStaticFieldID(
		    env, class, field_name, signature);
		field_value = (*env)->GetStaticObjectField(env, class, id);
	}

	return (field_value);
}

jobject
zjni_str_to_long(JNIEnv *env, char *str)
{
	jobject value = NULL;
	jclass class_Long = (*env)->FindClass(env, "java/lang/Long");

	jmethodID method_valueOf = (*env)->GetStaticMethodID(env,
	    class_Long, "valueOf", "(Ljava/lang/String;)Ljava/lang/Long;");

	jstring utf = (*env)->NewStringUTF(env, str);

	/* May throw a NumberFormatException */
	value = (*env)->CallStaticObjectMethod(
	    env, class_Long, method_valueOf, utf);

	return (value);
}

jobject
zjni_long_to_Long(JNIEnv *env, uint64_t value)
{
	jclass class_Long = (*env)->FindClass(env, "java/lang/Long");

	jmethodID constructor_Long = (*env)->GetMethodID(
	    env, class_Long, "<init>", "(J)V");

	jobject obj = (*env)->NewObject(
	    env, class_Long, constructor_Long, value);

	return (obj);
}

jobject
zjni_str_to_date(JNIEnv *env, char *str)
{
	jobject date = NULL;
	jclass class_Long = (*env)->FindClass(env, "java/lang/Long");

	jmethodID method_parseLong = (*env)->GetStaticMethodID(env,
	    class_Long, "parseLong", "(Ljava/lang/String;)J");

	jstring utf = (*env)->NewStringUTF(env, str);
	if (utf != NULL) {

		/* May throw a NumberFormatException */
		jlong time = (*env)->CallStaticLongMethod(
		    env, class_Long, method_parseLong, utf);

		if ((*env)->ExceptionOccurred(env) == NULL) {

			jclass class_Date = (*env)->FindClass(env,
			    "java/util/Date");

			jmethodID constructor_Date = (*env)->GetMethodID(
			    env, class_Date, "<init>", "(J)V");

			/* Date constructor takes epoch milliseconds */
			time *= 1000;

			date = (*env)->NewObject(
			    env, class_Date, constructor_Date, time);
		}
	}

	return (date);
}

jobjectArray
zjni_c_string_array_to_java(JNIEnv *env, char **array, int n)
{
	int i;
	jclass class_String = (*env)->FindClass(env, "java/lang/String");
	jobjectArray jarray =
	    (*env)->NewObjectArray(env, n, class_String, NULL);

	for (i = 0; i < n; i++) {
		jstring elementUTF = (*env)->NewStringUTF(env, array[i]);
		(void) (*env)->SetObjectArrayElement(env, jarray, i,
		    elementUTF);
	}

	return (jarray);
}

/*
 * Converts the non-null elements of the given Java String array into
 * a NULL-terminated char* array.  When done, each element and then
 * the array itself must be free()d.  Returns NULL if memory could not
 * be allocated.
 */
char **
zjni_java_string_array_to_c(JNIEnv *env, jobjectArray array)
{
	int i, n;
	jsize length = (*env)->GetArrayLength(env, array);
	char **result = (char **)calloc(length + 1, sizeof (char *));

	if (result != NULL) {
		for (i = 0, n = 0; i < length; i++) {
			jboolean isCopy;

			/* Retrive String from array */
			jstring string = (*env)->GetObjectArrayElement(
			    env, array, i);

			if (string != NULL) {
				/* Convert to char* */
				const char *converted =
				    (*env)->GetStringUTFChars(env, string,
					&isCopy);

				result[n] = strdup(converted);

				if (isCopy == JNI_TRUE) {
					/* Free chars in Java space */
					(void) (*env)->ReleaseStringUTFChars(
					    env, string, converted);
				}

				if (result[n++] == NULL) {
					/* strdup failed */
					zjni_free_array((void *)result, free);
					break;
				}
			}
		}

		/* Terminate array */
		result[n] = NULL;
	}

	return (result);
}

/*
 * Counts the number of elements in the given NULL-terminated array.
 * Does not include the terminating NULL in the count.
 */
int
zjni_count_elements(void **array)
{
	int i = 0;
	if (array != NULL) {
		for (; array[i] != NULL; i++);
	}
	return (i);
}

/*
 * Get a handle to the next nvpair with the specified name and data
 * type in the list following the given nvpair.
 *
 * This function is needed because the nvlist_lookup_* routines can
 * only be used with nvlists allocated with NV_UNIQUE_NAME or
 * NV_UNIQUE_NAME_TYPE, ie. lists of unique name/value pairs.
 *
 * Some variation of this function will likely appear in the libnvpair
 * library per 4981923.
 *
 * @param       nvl
 *              the nvlist_t to search
 *
 * @param       name
 *              the string key for the pair to find in the list, or
 *              NULL to match any name
 *
 * @param       type
 *              the data type for the pair to find in the list, or
 *              DATA_TYPE_UNKNOWN to match any type
 *
 * @param       nvp
 *              the pair to search from in the list, or NULL to search
 *              from the beginning of the list
 *
 * @return      the next nvpair in the list matching the given
 *              criteria, or NULL if no matching nvpair is found
 */
nvpair_t *
zjni_nvlist_walk_nvpair(nvlist_t *nvl, const char *name, data_type_t type,
    nvpair_t *nvp)
{
	/* For each nvpair in the list following nvp... */
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {

		/* Does this pair's name match the given name? */
		if ((name == NULL || strcmp(nvpair_name(nvp), name) == 0) &&

		    /* Does this pair's type match the given type? */
		    (type == DATA_TYPE_UNKNOWN || type == nvpair_type(nvp))) {
			return (nvp);
		}
	}

	return (NULL);
}
