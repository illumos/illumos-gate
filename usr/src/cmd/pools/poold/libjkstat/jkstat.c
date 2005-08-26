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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <kstat.h>

#include "jkstat.h"

/*
 * Class descriptors
 */
#define	DOUBLE_CLASS_DESC	"java/lang/Double"
#define	LONG_CLASS_DESC		"java/lang/Long"
#define	UI64_CLASS_DESC		"com/sun/solaris/service/pools/UnsignedInt64"
#define	HRTIME_CLASS_DESC	"com/sun/solaris/service/pools/HRTime"
#define	KSTAT_CLASS_DESC	"com/sun/solaris/service/kstat/Kstat"
#define	KSTATCTL_CLASS_DESC	"com/sun/solaris/service/kstat/KstatCtl"
#define	KSTAT_READ_EX_CLASS_DESC \
	"com/sun/solaris/service/kstat/KstatReadException"
#define	KSTAT_TNS_EX_CLASS_DESC	\
	"com/sun/solaris/service/kstat/KstatTypeNotSupportedException"
#define	THROWABLE_CLASS_DESC	"java/lang/Throwable"

#define	CLASS_FIELD_DESC(class_desc)	"L" class_desc ";"

/*
 * Cached class, method, and field IDs.
 */
static jclass doubleclass;
static jclass hrtimeclass;
static jclass kstatclass;
static jclass kstatctlclass;
static jclass longclass;
static jclass ui64class;
static jfieldID kstat_kctl_fieldid;
static jfieldID kstat_ksp_fieldid;
static jfieldID kstatctl_kctl_fieldid;
static jmethodID doublecons_mid;
static jmethodID hrtimecons_mid;
static jmethodID kstatcons_mid;
static jmethodID longcons_mid;
static jmethodID ui64cons_mid;

static jobject
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
 * Return a Long object with the given value.
 */
static jobject
makeLong(JNIEnv *env, jlong value)
{
	jobject valueObj;

	if (!(valueObj = (*env)->NewObject(env, longclass, longcons_mid,
	    value)))
		return (NULL); /* exception thrown */

	return (valueObj);
}

/*
 * Return a Double object with the given value.
 */
static jobject
makeDouble(JNIEnv *env, jdouble value)
{
	jobject valueObj;

	if (!(valueObj = (*env)->NewObject(env, doubleclass, doublecons_mid,
	    value)))
		return (NULL); /* exception thrown */

	return (valueObj);
}

/*
 * Returns the kctl_t * from kstat_open(3kstat).
 */
/*ARGSUSED*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_kstat_KstatCtl_open(JNIEnv *env, jobject obj)
{
	return ((jlong)(uintptr_t)kstat_open());
}

/*
 * Invokes kstat_close(3kstat).
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_kstat_KstatCtl_close(JNIEnv *env, jobject obj,
    jlong kctl)
{
	if (kctl)
		return (kstat_close((kstat_ctl_t *)(uintptr_t)kctl));
	else
		return (0);
}

/*
 * Invoke kstat_read(3kstat) for the given Kstat object.
 */
JNIEXPORT void JNICALL Java_com_sun_solaris_service_kstat_Kstat_read(
    JNIEnv *env, jobject obj)
{
	kstat_ctl_t *kctl =
	    ((kstat_ctl_t *)(uintptr_t)(*env)->GetLongField(env, obj,
	    kstat_kctl_fieldid));
	kstat_t *ksp = ((kstat_t *)(uintptr_t)(*env)->GetLongField(env, obj,
	    kstat_ksp_fieldid));
	kid_t kid;

	if (!ksp || !kctl)
		return; /* exception thronw */

	kid = kstat_read((kstat_ctl_t *)kctl, (kstat_t *)ksp, NULL);
	if (kid == -1) {
		jclass e;
		if (!(e = (*env)->FindClass(env, KSTAT_READ_EX_CLASS_DESC)))
			return; /* exception thrown */

		(*env)->Throw(env, (*env)->NewObject(env, e,
		    (*env)->GetStaticMethodID(env, e, "<init>",
		    "()" CLASS_FIELD_DESC(THROWABLE_CLASS_DESC))));
	}
}

/*
 * Return a Kstat object corresponding to the result of
 * kstat_lookup(3kstat).
 */
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_kstat_KstatCtl_lookup(JNIEnv *env, jobject obj,
    jstring moduleObj, jint instance, jstring nameObj)
{
	const char *module = NULL;
	const char *name = NULL;
	kstat_ctl_t *kctl;
	kstat_t *ksp;
	jobject kstatObject = NULL;

	if (moduleObj == NULL || nameObj == NULL)
		return (NULL);

	if (!(module = (*env)->GetStringUTFChars(env, moduleObj, NULL)))
		goto done; /* exception thrown */
	if (!(name = (*env)->GetStringUTFChars(env, nameObj, NULL)))
		goto done; /* exception thrown */

	kctl = (kstat_ctl_t *)(uintptr_t)(*env)->GetLongField(env, obj,
	    kstatctl_kctl_fieldid);
	ksp = kstat_lookup(kctl, (char *)module, instance, (char *)name);
	if (ksp)
		kstatObject = (*env)->NewObject(env, kstatclass, kstatcons_mid,
		    (jlong)(uintptr_t)kctl, (jlong)(uintptr_t)ksp);

done:
	if (name)
		(*env)->ReleaseStringUTFChars(env, nameObj, name);
	if (module)
		(*env)->ReleaseStringUTFChars(env, moduleObj, module);

	return (kstatObject);
}

/*
 * Returns the named value -- the value of the named kstat, or field in
 * a raw kstat, as applicable, and available.  Returns <i>null</i> if no
 * such named kstat or field is available.
 *
 * Throws KstatTypeNotSupportedException if the raw kstat is not
 * understood.  (Presently, none are.)
 */
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_kstat_Kstat_getValue(JNIEnv *env, jobject obj,
    jstring nameObj)
{
	kstat_t *ksp = ((kstat_t *)(uintptr_t)(*env)->GetLongField(env, obj,
	    kstat_ksp_fieldid));
	jobject valueObj = NULL;
	kstat_named_t *ksnp;
	const char *name;
	jclass exceptionClass;

	if (!nameObj)
		return (NULL);

	if (!(name = (*env)->GetStringUTFChars(env, nameObj, NULL)))
		return (NULL); /* exception thrown */

	if (!(exceptionClass = (*env)->FindClass(env,
	    KSTAT_TNS_EX_CLASS_DESC))) {
		(*env)->ReleaseStringUTFChars(env, nameObj, name);
		return (NULL); /* exception thrown */
	}

	switch (ksp->ks_type) {
	case KSTAT_TYPE_NAMED:
		ksnp = kstat_data_lookup(ksp, (char *)name);
		if (ksnp == NULL)
			break;
		switch (ksnp->data_type) {
		case KSTAT_DATA_CHAR:
			valueObj = makeLong(env, ksnp->value.c[0]);
			break;
		case KSTAT_DATA_INT32:
			valueObj = makeLong(env, ksnp->value.i32);
			break;
		case KSTAT_DATA_UINT32:
			valueObj = makeLong(env, ksnp->value.ui32);
			break;
		case KSTAT_DATA_INT64:
			valueObj = makeLong(env, ksnp->value.i64);
			break;
		case KSTAT_DATA_UINT64:
			valueObj = makeUnsignedInt64(env, ksnp->value.ui64);
			break;
		case KSTAT_DATA_STRING:
			valueObj = (*env)->NewStringUTF(env,
			    KSTAT_NAMED_STR_PTR(ksnp));
			break;
		case KSTAT_DATA_FLOAT:
			valueObj = makeDouble(env, ksnp->value.f);
			break;
		case KSTAT_DATA_DOUBLE:
			valueObj = makeDouble(env, ksnp->value.d);
			break;
		default:
			goto fail;
		}
		break;
	default:
		goto fail;
	}

	(*env)->ReleaseStringUTFChars(env, nameObj, name);
	return (valueObj);

fail:
	(*env)->ReleaseStringUTFChars(env, nameObj, name);
	(*env)->Throw(env, (*env)->NewObject(env, exceptionClass,
	    (*env)->GetStaticMethodID(env, exceptionClass, "<init>",
	    "()" CLASS_FIELD_DESC(THROWABLE_CLASS_DESC))));

	return (valueObj);
}

/*
 * Given a Kstat object, return, as an HRTime object, its kstat_t's
 * field at the given offset.
 */
static jobject
ksobj_get_hrtime(JNIEnv *env, jobject obj, offset_t ksfieldoff)
{
	kstat_t *ksp = ((kstat_t *)(uintptr_t)(*env)->GetLongField(env, obj,
	    kstat_ksp_fieldid));

	if (!ksp)
		return (NULL); /* exception thrown */

	return ((*env)->NewObject(env, hrtimeclass, hrtimecons_mid,
	    makeUnsignedInt64(env, *((hrtime_t *)ksp + ksfieldoff *
	    sizeof (hrtime_t)))));
}

/*
 * Given a Kstat object, return as an HRTime object its ks_snaptime
 * field.
 */
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_kstat_Kstat_getSnapTime(JNIEnv *env, jobject obj)
{
	return (ksobj_get_hrtime(env, obj, offsetof(kstat_t, ks_snaptime)));
}

/*
 * Given a Kstat object, return as an HRTime object its ks_crtime
 * field.
 */
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_kstat_Kstat_getCreationTime(JNIEnv *env,
    jobject obj)
{
	return (ksobj_get_hrtime(env, obj, offsetof(kstat_t, ks_crtime)));
}

/*
 * Invoke kstat_chain_update(3kstat) for the kstat chain corresponding
 * to the given KstatCtl object.
 */
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_kstat_KstatCtl_chainUpdate(JNIEnv *env,
    jobject obj)
{
	kstat_ctl_t *kctl;

	kctl = (kstat_ctl_t *)(uintptr_t)(*env)->GetLongField(env, obj,
	    kstatctl_kctl_fieldid);

	(void) kstat_chain_update(kctl);
}

/*
 * Cache class, method, and field IDs.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_kstat_KstatCtl_init(JNIEnv *env, jclass clazz)
{
	jclass doubleclass_lref;
	jclass hrtimeclass_lref;
	jclass kstatclass_lref;
	jclass kstatctlclass_lref;
	jclass longclass_lref;
	jclass ui64class_lref;

	if (!(doubleclass_lref = (*env)->FindClass(env, DOUBLE_CLASS_DESC)))
		return; /* exception thrown */
	if (!(doubleclass = (*env)->NewGlobalRef(env, doubleclass_lref)))
		return; /* exception thrown */
	if (!(doublecons_mid = (*env)->GetMethodID(env, doubleclass, "<init>",
	    "(D)V")))
		return; /* exception thrown */

	if (!(hrtimeclass_lref = (*env)->FindClass(env, HRTIME_CLASS_DESC)))
		return; /* exception thrown */
	if (!(hrtimeclass = (*env)->NewGlobalRef(env, hrtimeclass_lref)))
		return; /* exception thrown */
	if (!(hrtimecons_mid = (*env)->GetMethodID(env, hrtimeclass, "<init>",
	    "(" CLASS_FIELD_DESC(UI64_CLASS_DESC) ")V")))
		return; /* exception thrown */

	if (!(kstatclass_lref = (*env)->FindClass(env, KSTAT_CLASS_DESC)))
		return; /* exception thrown */
	if (!(kstatclass = (*env)->NewGlobalRef(env, kstatclass_lref)))
		return; /* exception thrown */
	if (!(kstatcons_mid = (*env)->GetMethodID(env, kstatclass, "<init>",
	    "(JJ)V")))
		return; /* exception thrown */
	if (!(kstat_kctl_fieldid = (*env)->GetFieldID(env, kstatclass, "kctl",
	    "J")))
		return; /* exception thrown */
	if (!(kstat_ksp_fieldid = (*env)->GetFieldID(env, kstatclass, "ksp",
	    "J")))
		return; /* exception thrown */

	if (!(kstatctlclass_lref = (*env)->FindClass(env, KSTATCTL_CLASS_DESC)))
		return; /* exception thrown */
	if (!(kstatctlclass = (*env)->NewGlobalRef(env, kstatctlclass_lref)))
		return; /* exception thrown */
	if (!(kstatctl_kctl_fieldid = (*env)->GetFieldID(env, kstatctlclass,
	    "kctl", "J")))
		return; /* exception thrown */

	if (!(longclass_lref = (*env)->FindClass(env, LONG_CLASS_DESC)))
		return; /* exception thrown */
	if (!(longclass = (*env)->NewGlobalRef(env, longclass_lref)))
		return; /* exception thrown */
	if (!(longcons_mid = (*env)->GetMethodID(env, longclass, "<init>",
	    "(J)V")))
		return; /* exception thrown */

	if (!(ui64class_lref = (*env)->FindClass(env, UI64_CLASS_DESC)))
		return; /* exception thrown */
	if (!(ui64class = (*env)->NewGlobalRef(env, ui64class_lref)))
		return; /* exception thrown */
	ui64cons_mid = (*env)->GetMethodID(env, ui64class, "<init>", "([B)V");
}
