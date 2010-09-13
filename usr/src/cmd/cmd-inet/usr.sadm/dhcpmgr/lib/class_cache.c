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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <synch.h>
#include <jni.h>

#include "class_cache.h"

/*
 * Only certain classes are deemed worthy of caching. These be them.
 */
#define	DCR_NAME		"com/sun/dhcpmgr/data/DhcpClientRecord"
#define	DTR_NAME		"com/sun/dhcpmgr/data/DhcptabRecord"
#define	NET_NAME		"com/sun/dhcpmgr/data/Network"
#define	MAC_NAME		"com/sun/dhcpmgr/data/Macro"
#define	OPT_NAME		"com/sun/dhcpmgr/data/Option"
#define	DS_NAME			"com/sun/dhcpmgr/data/DhcpDatastore"
#define	CFG_NAME		"com/sun/dhcpmgr/data/DhcpdOptions"
#define	RES_NAME		"com/sun/dhcpmgr/data/DhcpResource"
#define	IP_NAME			"com/sun/dhcpmgr/data/IPAddress"
#define	IPIF_NAME		"com/sun/dhcpmgr/data/IPInterface"

/*
 * As with classes, only certain methods are cached.
 */
#define	DCR_CONS_NAME		"<init>"
#define	DCR_GETCID_NAME		"getClientId"
#define	DCR_GETFLAG_NAME	"getFlagString"
#define	DCR_GETCIP_NAME		"getClientIPAddress"
#define	DCR_GETSIP_NAME		"getServerIPAddress"
#define	DCR_GETEXP_NAME		"getExpirationTime"
#define	DCR_GETSIG_NAME		"getSignature"
#define	DCR_GETMAC_NAME		"getMacro"
#define	DCR_GETCMT_NAME		"getComment"
#define	DTR_GETKEY_NAME		"getKey"
#define	DTR_GETFLAG_NAME	"getFlag"
#define	DTR_GETSIG_NAME		"getSignature"
#define	DTR_GETVAL_NAME		"getValue"
#define	NET_CONS_NAME		"<init>"
#define	MAC_CONS_NAME		"<init>"
#define	OPT_CONS_NAME		"<init>"
#define	DS_CONS_NAME		"<init>"
#define	DS_GETRSRC_NAME		"getResource"
#define	DS_GETLOC_NAME		"getLocation"
#define	DS_GETRSRCCFG_NAME	"getConfig"
#define	DS_GETVER_NAME		"getVersion"
#define	CFG_CONS_NAME		"<init>"
#define	CFG_SET_NAME		"set"
#define	CFG_GETALL_NAME		"getAll"
#define	RES_GETKEY_NAME		"getKey"
#define	RES_GETVAL_NAME		"getValue"
#define	RES_ISCOM_NAME		"isComment"
#define	IP_CONS_NAME		"<init>"
#define	IPIF_CONS_NAME		"<init>"

/*
 * Signatures for the methods can be found below.
 */
#define	DCR_CONS_SIG		"(Ljava/lang/String;Ljava/lang/String;"\
				"Ljava/lang/String;Ljava/lang/String;"\
				"Ljava/lang/String;Ljava/lang/String;"\
				"Ljava/lang/String;Ljava/lang/String;)V"

#define	DCR_GETCID_SIG		"()Ljava/lang/String;"
#define	DCR_GETFLAG_SIG		"()Ljava/lang/String;"
#define	DCR_GETCIP_SIG		"()Ljava/lang/String;"
#define	DCR_GETSIP_SIG		"()Ljava/lang/String;"
#define	DCR_GETEXP_SIG		"()Ljava/lang/String;"
#define	DCR_GETSIG_SIG		"()Ljava/lang/String;"
#define	DCR_GETMAC_SIG		"()Ljava/lang/String;"
#define	DCR_GETCMT_SIG		"()Ljava/lang/String;"
#define	DTR_GETKEY_SIG		"()Ljava/lang/String;"
#define	DTR_GETFLAG_SIG		"()Ljava/lang/String;"
#define	DTR_GETSIG_SIG		"()Ljava/lang/String;"
#define	DTR_GETVAL_SIG		"()Ljava/lang/String;"
#define	NET_CONS_SIG		"(Ljava/lang/String;I)V"
#define	MAC_CONS_SIG		"(Ljava/lang/String;Ljava/lang/String;"\
				"Ljava/lang/String;)V"
#define	OPT_CONS_SIG		"(Ljava/lang/String;B[Ljava/lang/String;"\
				"SBIILjava/lang/String;Z)V"
#define	DS_CONS_SIG		"(Ljava/lang/String;IZ)V"
#define	DS_GETRSRC_SIG		"()Ljava/lang/String;"
#define	DS_GETLOC_SIG		"()Ljava/lang/String;"
#define	DS_GETRSRCCFG_SIG	"()Ljava/lang/String;"
#define	DS_GETVER_SIG		"()I"
#define	CFG_CONS_SIG		"()V"
#define	CFG_SET_SIG		"(Ljava/lang/String;Ljava/lang/String;Z)V"
#define	CFG_GETALL_SIG		"()[Ljava/lang/Object;"
#define	RES_GETKEY_SIG		"()Ljava/lang/String;"
#define	RES_GETVAL_SIG		"()Ljava/lang/String;"
#define	RES_ISCOM_SIG		"()Z"
#define	IP_CONS_SIG		"(Ljava/lang/String;)V"
#define	IPIF_CONS_SIG		"(Ljava/lang/String;Ljava/lang/String;"\
				"Ljava/lang/String;)V"
/*
 * Class map.
 */
typedef struct {
	jclass		cl_class;
	char		*cl_name;
} cl_map_t;

/*
 * Note that the order of the entries in this table must match
 * exactly with the CC_CLASSMAP_ID enumeration in class_cache.h.
 */
static cl_map_t classMap[] = {
	{ NULL, DCR_NAME },	/* DCR_CLASS */
	{ NULL, DTR_NAME },	/* DTR_CLASS */
	{ NULL, NET_NAME },	/* NET_CLASS */
	{ NULL, MAC_NAME },	/* MAC_CLASS */
	{ NULL, OPT_NAME },	/* OPT_CLASS */
	{ NULL, DS_NAME },	/* DS_CLASS */
	{ NULL, CFG_NAME },	/* CFG_CLASS */
	{ NULL, RES_NAME },	/* RES_CLASS */
	{ NULL, IP_NAME },	/* IP_CLASS */
	{ NULL, IPIF_NAME }	/* IPIF_CLASS */
};

/*
 * Method ID map.
 */
typedef struct {
	jmethodID	mi_methodID;
	char		*mi_name;
	char		*mi_signature;
} mi_map_t;

/*
 * Note that the order of the entries in this table must match
 * exactly with the CC_METHODMAP_ID enumeration in class_cache.h.
 */
static mi_map_t methodIDMap[] = {
	{ NULL, DCR_CONS_NAME, DCR_CONS_SIG },		/* DCR_CONS */
	{ NULL, DCR_GETCID_NAME, DCR_GETCID_SIG },	/* DCR_GETCID */
	{ NULL, DCR_GETFLAG_NAME, DCR_GETFLAG_SIG },	/* DCR_GETFLAG */
	{ NULL, DCR_GETCIP_NAME, DCR_GETCIP_SIG },	/* DCR_GETCIP */
	{ NULL, DCR_GETSIP_NAME, DCR_GETSIP_SIG },	/* DCR_GETSIP */
	{ NULL, DCR_GETEXP_NAME, DCR_GETEXP_SIG },	/* DCR_GETEXP */
	{ NULL, DCR_GETSIG_NAME, DCR_GETSIG_SIG },	/* DCR_GETSIG */
	{ NULL, DCR_GETMAC_NAME, DCR_GETMAC_SIG },	/* DCR_GETMAC */
	{ NULL, DCR_GETCMT_NAME, DCR_GETCMT_SIG },	/* DCR_GETCMT */
	{ NULL, DTR_GETKEY_NAME, DTR_GETKEY_SIG },	/* DTR_GETKEY */
	{ NULL, DTR_GETFLAG_NAME, DTR_GETFLAG_SIG },	/* DTR_GETFLAG */
	{ NULL, DTR_GETSIG_NAME, DTR_GETSIG_SIG },	/* DTR_GETSIG */
	{ NULL, DTR_GETVAL_NAME, DTR_GETVAL_SIG },	/* DTR_GETVAL */
	{ NULL, NET_CONS_NAME, NET_CONS_SIG },		/* NET_CONS */
	{ NULL, MAC_CONS_NAME, MAC_CONS_SIG },		/* MAC_CONS */
	{ NULL, OPT_CONS_NAME, OPT_CONS_SIG },		/* OPT_CONS */
	{ NULL, DS_CONS_NAME, DS_CONS_SIG },		/* DS_CONS */
	{ NULL, DS_GETRSRC_NAME, DS_GETRSRC_SIG },	/* DS_GETRSRC */
	{ NULL, DS_GETLOC_NAME, DS_GETLOC_SIG },	/* DS_GETLOC */
	{ NULL, DS_GETRSRCCFG_NAME, DS_GETRSRCCFG_SIG }, /* DS_GETRSRCCFG */
	{ NULL, DS_GETVER_NAME, DS_GETVER_SIG },	/* DS_GETVER */
	{ NULL, CFG_CONS_NAME, CFG_CONS_SIG },		/* CFG_CONS */
	{ NULL, CFG_SET_NAME, CFG_SET_SIG },		/* CFG_SET */
	{ NULL, CFG_GETALL_NAME, CFG_GETALL_SIG },	/* CFG_GETALL */
	{ NULL, RES_GETKEY_NAME, RES_GETKEY_SIG },	/* RES_GETKEY */
	{ NULL, RES_GETVAL_NAME, RES_GETVAL_SIG },	/* RES_GETVAL */
	{ NULL, RES_ISCOM_NAME, RES_ISCOM_SIG },	/* RES_ISCOM */
	{ NULL, IP_CONS_NAME, IP_CONS_SIG },		/* IP_CONS */
	{ NULL, IPIF_CONS_NAME, IPIF_CONS_SIG }		/* IPIF_CONS */
};

/*
 * The locks to protect the class and method maps.
 */
static mutex_t cmap_lock;
static mutex_t mmap_lock;

void
init_class_cache(void) {
	(void) mutex_init(&cmap_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&mmap_lock, USYNC_THREAD, NULL);
}

/*
 * Get a dhcpmgr class from the cache.
 */
jclass
find_class(JNIEnv *env, CC_CLASSMAP_ID id) {

	jclass *class;

	assert(id >= 0 && id <= CC_CLASSMAP_NUM);

	/*
	 * If the class has not been cached yet, go find it and cache it.
	 */
	class = &classMap[id].cl_class;
	if (*class == NULL) {
		/*
		 * Check again with the lock held this time.
		 */
		(void) mutex_lock(&cmap_lock);
		if (*class == NULL) {
			char *name = classMap[id].cl_name;
			jclass local = (*env)->FindClass(env, name);
			if (local != NULL) {
				*class = (*env)->NewGlobalRef(env, local);
				(*env)->DeleteLocalRef(env, local);
			}
		}
		(void) mutex_unlock(&cmap_lock);
	}

	return (*class);
}

/*
 * Get a dhcpmgr class methodid from the cache.
 */
jmethodID
get_methodID(JNIEnv *env, jclass class, CC_METHODMAP_ID id) {

	jmethodID *methodID;

	assert(id >= 0 && id <= CC_METHODMAP_NUM);

	/*
	 * If the methodID has not been cached, go find it and cache it.
	 */
	methodID = &methodIDMap[id].mi_methodID;
	if (*methodID == NULL) {
		/*
		 * Check again with the lock held this time.
		 */
		(void) mutex_lock(&mmap_lock);
		if (*methodID == NULL) {
			char *name = methodIDMap[id].mi_name;
			char *signature = methodIDMap[id].mi_signature;
			*methodID = (*env)->GetMethodID(env, class, name,
			    signature);
		}
		(void) mutex_unlock(&mmap_lock);
	}

	return (*methodID);
}
