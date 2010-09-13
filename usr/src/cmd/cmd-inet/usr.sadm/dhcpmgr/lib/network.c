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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <dhcp_svc_private.h>
#include <dhcp_svc_confkey.h>
#include <libinetutil.h>
#include <libintl.h>
#include <stdlib.h>
#include <ctype.h>
#include <malloc.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <jni.h>
#include <com_sun_dhcpmgr_bridge_Bridge.h>

#include "exception.h"
#include "dd_misc.h"
#include "class_cache.h"

/*
 * Create a dn_rec from a DhcpClientRecord.
 */
static dn_rec_t *
create_dnrec(JNIEnv *env,
	jobject dhcpClientRecord)
{
	jclass dcr_class;

	dn_rec_t *dnrec = NULL;
	char *str;
	unsigned int cid_len;

	/* Locate the class we need */
	dcr_class = find_class(env, DCR_CLASS);
	if (dcr_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	dnrec = malloc(sizeof (dn_rec_t));
	if (dnrec == NULL) {
		throw_memory_exception(env);
		return (NULL);
	}

	/*
	 * Get the cid and the cid_len.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETCID, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	cid_len = DN_MAX_CID_LEN;
	if (hexascii_to_octet(str, strlen(str), dnrec->dn_cid, &cid_len) != 0) {
		free(str);
		free_dnrec(dnrec);
		throw_memory_exception(env);
		return (NULL);
	}
	dnrec->dn_cid_len = cid_len;
	free(str);

	/*
	 * Get the flags.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETFLAG, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	dnrec->dn_flags = atoi(str);
	free(str);

	/*
	 * Get the client IP.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETCIP, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	dnrec->dn_cip.s_addr = ntohl(inet_addr(str));
	free(str);

	/*
	 * Get the server IP.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETSIP, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	dnrec->dn_sip.s_addr = ntohl(inet_addr(str));
	free(str);

	/*
	 * Get the expiration.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETEXP, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	dnrec->dn_lease = atol(str);
	free(str);

	/*
	 * Get the signature.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETSIG, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	dnrec->dn_sig = atoll(str);
	free(str);

	/*
	 * Get the macro.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETMAC, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	(void) strlcpy(dnrec->dn_macro, str, sizeof (dnrec->dn_macro));
	free(str);

	/*
	 * Get the comment.
	 */
	if (!dd_get_str_attr(env, dcr_class, DCR_GETCMT, dhcpClientRecord,
		&str)) {
		/* exception thrown */
		free_dnrec(dnrec);
		return (NULL);
	}
	(void) strlcpy(dnrec->dn_comment, str, sizeof (dnrec->dn_comment));
	free(str);

	return (dnrec);
}

/*
 * Create a DhcpClientRecord from a dn_rec.
 */
static jobject
create_DhcpClientRecord(
	JNIEnv *env,
	dn_rec_t *dnrec)
{
	jclass dcr_class;
	jmethodID dcr_cons;
	jobject dhcpClientRecord;
	struct in_addr tmpaddr;

	char ascii_cid[DN_MAX_CID_LEN * 2 + 1];
	char ascii_flags[2 + 1];
	char ascii_cip[IPADDR_MAX_CHAR + 1];
	char ascii_sip[IPADDR_MAX_CHAR + 1];
	char ascii_lease[ULONG_MAX_CHAR + 1];
	char ascii_sig[UINT64_MAX_CHAR + 1];
	char ascii_macro[DSVC_MAX_MACSYM_LEN + 1];
	char ascii_comment[DN_MAX_COMMENT_LEN + 1];

	uint_t cid_len;
	int err;

	/* Find the class */
	dcr_class = find_class(env, DCR_CLASS);
	if (dcr_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Locate the constructor we need */
	dcr_cons = get_methodID(env, dcr_class, DCR_CONS);
	if (dcr_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	cid_len = DN_MAX_CID_LEN * 2 + 1;
	err = octet_to_hexascii(dnrec->dn_cid, dnrec->dn_cid_len, ascii_cid,
	    &cid_len);
	if (err != 0) {
		throw_bridge_exception(env, strerror(err));
		return (NULL);
	}
	ascii_cid[cid_len] = '\0';

	(void) sprintf(ascii_flags, "%02hu", dnrec->dn_flags);

	tmpaddr.s_addr = htonl(dnrec->dn_cip.s_addr);
	(void) strcpy(ascii_cip, inet_ntoa(tmpaddr));
	tmpaddr.s_addr = htonl(dnrec->dn_sip.s_addr);
	(void) strcpy(ascii_sip, inet_ntoa(tmpaddr));

	(void) sprintf(ascii_lease, "%d", dnrec->dn_lease);
	(void) sprintf(ascii_sig, "%lld", dnrec->dn_sig);

	(void) strlcpy(ascii_macro, dnrec->dn_macro, sizeof (ascii_macro));
	(void) strlcpy(ascii_comment, dnrec->dn_comment,
	    sizeof (ascii_comment));

	dhcpClientRecord = (*env)->NewObject(env, dcr_class, dcr_cons,
		(*env)->NewStringUTF(env, ascii_cid),
		(*env)->NewStringUTF(env, ascii_flags),
		(*env)->NewStringUTF(env, ascii_cip),
		(*env)->NewStringUTF(env, ascii_sip),
		(*env)->NewStringUTF(env, ascii_lease),
		(*env)->NewStringUTF(env, ascii_macro),
		(*env)->NewStringUTF(env, ascii_comment),
		(*env)->NewStringUTF(env, ascii_sig));

	return (dhcpClientRecord);
}

/*
 * Given a network name, find it's IP address.
 */
static boolean_t
getNetIPByName(const char *netname, char *netip) {

	struct netent *ne;
	ulong_t addr;
	boolean_t result = B_FALSE;

	if ((ne = getnetbyname(netname)) != NULL &&
		ne->n_addrtype == AF_INET) {

		int i;
		ulong_t tl;
		int count;

		for (i = 0, tl = (ulong_t)0xff000000, count = 0;
			i < 4; i++, tl >>= 8) {

			if ((ne->n_net & tl) == 0)
				count += 8;
			else
				break;
		}

		addr = ne->n_net << count;
		(void) sprintf(netip, "%ld.%ld.%ld.%ld",
		((addr & 0xff000000) >> 24), ((addr & 0x00ff0000) >> 16),
		((addr & 0x0000ff00) >> 8), (addr & 0x000000ff));

		result = B_TRUE;
	}

	return (result);
}

/*
 * Create a Network object for a network IP address.
 */
static jobject
createNetwork(
	JNIEnv *env,
	const char *network)
{
	jclass net_class;
	jmethodID net_cons;
	jobject net;

	struct in_addr addr;
	struct in_addr mask;
	jstring jstr;

	/* Locate the class and methods we need */
	net_class = find_class(env, NET_CLASS);
	if (net_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	net_cons = get_methodID(env, net_class, NET_CONS);
	if (net_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	addr.s_addr = ntohl(inet_addr(network));
	get_netmask4(&addr, &mask);

	jstr = (*env)->NewStringUTF(env, network);
	if (jstr == NULL) {
		/* exception thrown */
		return (NULL);
	}

	net = (*env)->NewObject(env, net_class, net_cons, jstr, mask.s_addr);

	return (net);
}


/*
 * Get the Network object for the network argument.
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getNetwork(
	JNIEnv *env,
	jobject obj,
	jstring jnet)
{

	jobject netObj;
	char *net;

	char *netip = NULL;
	char ascii_ip[IPADDR_MAX_CHAR + 1];

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		return (NULL);
	}

	/*
	 * If net looks like an IP address, assume it is,
	 * otherwise go get its IP
	 */
	if (!isdigit(*net)) {
		if (getNetIPByName(net, ascii_ip)) {
			netip = ascii_ip;
		}
	} else {
		netip = net;
	}

	/* If we could not find an IP for net, then return NULL object */
	if (netip == NULL) {
		free(net);
		return (NULL);
	}

	/* Create a Network object */
	netObj = createNetwork(env, netip);
	if (netObj == NULL) {
		/* exception thrown */
		free(net);
		return (NULL);
	}

	/* free up resources */
	free(net);

	/* return the object */
	return (netObj);
}

/*
 * List the networks currently under DHCP management.  Return as an array
 * of Network objects including the subnet mask for each network.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getNetworks(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{
	jclass net_class;
	jobjectArray jlist = NULL;
	jobject net;
	uint32_t count;
	char **list = NULL;
	dsvc_datastore_t datastore;
	int rcode;
	int i;

	/* Locate the class. */
	net_class = find_class(env, NET_CLASS);
	if (net_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Get the list of network tables */
	rcode = list_dd(&datastore, DSVC_DHCPNETWORK, &list, &count);

	dd_free_datastore_t(&datastore);

	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		return (NULL);
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, count, net_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		for (i = 0; i < count; i++) {
		    free(list[i]);
		}
		free(list);
		return (NULL);
	}

	/* For each network, create an object and add it to the array */
	for (i = 0; i < count; i++) {
		net = createNetwork(env, list[i]);
		if (net == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, net);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	/*
	 * Free the list now.
	 */
	for (i = 0; i < count; i++) {
	    free(list[i]);
	}
	free(list);

	return (jlist);
}

/*
 * Use the current datastore to create a network table in a new datastore.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_cvtNetwork(
    JNIEnv *env,
    jobject obj,
    jstring jnet,
    jobject jdatastore)
{
	dn_rec_t record;
	dn_rec_list_t *recordList;
	dn_rec_list_t *originalList = NULL;
	uint32_t query;
	uint32_t count = 0;
	struct in_addr tmpaddr;
	char ascii_cip[IPADDR_MAX_CHAR + 1];

	dsvc_handle_t curHandle;
	dsvc_handle_t newHandle;
	dsvc_datastore_t curDatastore;
	dsvc_datastore_t newDatastore;

	char *net;
	int rcode;
	int i;

	/* Get the current data store configuration */
	if (!dd_get_conf_datastore_t(env, &curDatastore)) {
		/* exception thrown */
		return;
	}

	/* Make a "new" dsvc_datastore_t */
	if (!dd_make_datastore_t(env, &newDatastore, jdatastore)) {
		/* exception thrown */
		dd_free_datastore_t(&curDatastore);
		return;
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&curDatastore);
		dd_free_datastore_t(&newDatastore);
		return;
	}

	/* Open the current network table */
	rcode = open_dd(&curHandle, &curDatastore, DSVC_DHCPNETWORK, net,
		DSVC_READ);

	dd_free_datastore_t(&curDatastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		dd_free_datastore_t(&newDatastore);
		free(net);
		return;
	}

	/* Open the new network table */
	rcode = open_dd(&newHandle, &newDatastore, DSVC_DHCPNETWORK, net,
		DSVC_CREATE | DSVC_READ | DSVC_WRITE);

	dd_free_datastore_t(&newDatastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		(void) close_dd(&curHandle);
		free(net);
		return;
	}
	free(net);

	/* Get the records */
	DSVC_QINIT(query);
	rcode = lookup_dd(curHandle, B_FALSE, query, -1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&curHandle);
	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		(void) close_dd(&newHandle);
		return;
	}

	if (count != 0) {
		originalList = recordList;
	}

	/* For each row, write client record to new table */
	for (i = 0; i < count; i++) {
		/* Now add the record */
		rcode = add_dd_entry(newHandle, recordList->dnl_rec);

		if (rcode != DSVC_SUCCESS) {
			tmpaddr.s_addr =
				htonl(recordList->dnl_rec->dn_cip.s_addr);
			(void) strcpy(ascii_cip, inet_ntoa(tmpaddr));
			throw_add_dd_entry_exception(env, rcode, ascii_cip);
			break;
		}

		recordList = recordList->dnl_next;
	}

	(void) close_dd(&newHandle);

	if (originalList != NULL) {
		free_dnrec_list(originalList);
	}
}

/*
 * Retrieve all of the records in a particular network table.  Returns an
 * array of DhcpClientRecord.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_loadNetwork(
    JNIEnv *env,
    jobject obj,
    jstring jnet,
    jobject jdatastore)
{
	jclass dcr_class;
	jobjectArray jlist = NULL;
	jobject dhcpClientRecord;
	int i;

	dsvc_handle_t handle;
	dsvc_datastore_t datastore;

	dn_rec_t record;
	dn_rec_list_t *recordList = NULL;
	dn_rec_list_t *originalList = NULL;
	uint32_t query;
	uint32_t count = 0;

	char *net;
	int rcode;

	/* Locate the class and constructor we need */
	dcr_class = find_class(env, DCR_CLASS);
	if (dcr_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return (NULL);
	}

	rcode = open_dd(&handle, &datastore, DSVC_DHCPNETWORK, net, DSVC_READ);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		free(net);
		return (NULL);
	}
	free(net);

	/* Get the records */
	DSVC_QINIT(query);
	rcode = lookup_dd(handle, B_FALSE, query, -1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		return (NULL);
	}

	/* Save original pointer so we can free it correctly at end */
	originalList = recordList;

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, count, dcr_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		if (originalList != NULL) {
			free_dnrec_list(originalList);
		}
		return (NULL);
	}

	/* For each client, create an object and add it to the array */
	for (i = 0; i < count; i++) {
		dhcpClientRecord = create_DhcpClientRecord(env,
					recordList->dnl_rec);
		if (dhcpClientRecord == NULL) {
			/* exception thrown */
			break;
		}
		recordList = recordList->dnl_next;

		(*env)->SetObjectArrayElement(env, jlist, i, dhcpClientRecord);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	if (originalList != NULL) {
		free_dnrec_list(originalList);
	}

	return (jlist);
}

/*
 * Create a client record
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_createDhcpClientRecord(
    JNIEnv *env,
    jobject obj,
    jobject jrec,
    jstring jnet,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	dn_rec_t *dnrec;
	char *net;
	int rcode;

	struct in_addr tmpaddr;
	char ascii_cip[IPADDR_MAX_CHAR + 1];

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	dnrec = create_dnrec(env, jrec);
	if (dnrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		free(net);
		return;
	}

	rcode = open_dd(&handle, &datastore, DSVC_DHCPNETWORK,
		net, DSVC_WRITE);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		free(net);
		free_dnrec(dnrec);
		return;
	}
	free(net);

	/* Now add the record */
	rcode = add_dd_entry(handle, dnrec);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		tmpaddr.s_addr = htonl(dnrec->dn_cip.s_addr);
		(void) strcpy(ascii_cip, inet_ntoa(tmpaddr));
		throw_add_dd_entry_exception(env, rcode, ascii_cip);
	}

	free_dnrec(dnrec);

}

/*
 * Modify a client record.  Supply both old and new record and table in
 * which they're to be modified.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_modifyDhcpClientRecord(
    JNIEnv *env,
    jobject obj,
    jobject joldrec,
    jobject jnewrec,
    jstring jnet,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	dn_rec_t *dnoldrec;
	dn_rec_t *dnnewrec;

	struct in_addr tmpaddr;
	char old_ascii_cip[IPADDR_MAX_CHAR + 1];
	char new_ascii_cip[IPADDR_MAX_CHAR + 1];

	char *net;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	dnoldrec = create_dnrec(env, joldrec);
	if (dnoldrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		free(net);
		return;
	}

	dnnewrec = create_dnrec(env, jnewrec);
	if (dnnewrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		free(net);
		free_dnrec(dnoldrec);
		return;
	}

	rcode = open_dd(&handle, &datastore, DSVC_DHCPNETWORK,
		net, DSVC_WRITE);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		free(net);
		free_dnrec(dnoldrec);
		free_dnrec(dnnewrec);
		return;
	}
	free(net);

	/* Modify the record */
	rcode = modify_dd_entry(handle, dnoldrec, dnnewrec);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		tmpaddr.s_addr = htonl(dnoldrec->dn_cip.s_addr);
		(void) strcpy(old_ascii_cip, inet_ntoa(tmpaddr));
		tmpaddr.s_addr = htonl(dnnewrec->dn_cip.s_addr);
		(void) strcpy(new_ascii_cip, inet_ntoa(tmpaddr));
		throw_modify_dd_entry_exception(env, rcode, old_ascii_cip,
			new_ascii_cip);
	}

	free_dnrec(dnnewrec);
	free_dnrec(dnoldrec);
}

/*
 * Delete a client record
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_deleteDhcpClientRecord(
    JNIEnv *env,
    jobject obj,
    jobject jrec,
    jstring jnet,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	dn_rec_t *dnrec;

	struct in_addr tmpaddr;
	char ascii_cip[IPADDR_MAX_CHAR + 1];

	char *net;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	dnrec = create_dnrec(env, jrec);
	if (dnrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		free(net);
		return;
	}

	rcode = open_dd(&handle, &datastore, DSVC_DHCPNETWORK,
		net, DSVC_WRITE);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		free(net);
		free_dnrec(dnrec);
		return;
	}
	free(net);

	/* Delete the record */
	rcode = delete_dd_entry(handle, dnrec);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		tmpaddr.s_addr = htonl(dnrec->dn_cip.s_addr);
		(void) strcpy(ascii_cip, inet_ntoa(tmpaddr));
		throw_delete_dd_entry_exception(env, rcode, ascii_cip);
	}

	free_dnrec(dnrec);
}

/*
 * Retrieve a client record
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getDhcpClientRecord(
    JNIEnv *env,
    jobject obj,
    jobject jrec,
    jstring jnet,
    jobject jdatastore)
{
	jclass dcr_class;
	jmethodID dcr_getcip;
	jobject dhcpClientRecord = NULL;
	jstring jaddr;

	dsvc_handle_t handle;
	dsvc_datastore_t datastore;

	char *net;
	char *addr;
	int rcode;

	dn_rec_t record;
	dn_rec_list_t *recordList;
	uint32_t query;
	uint32_t count = 0;

	/* Find the class and method we need */
	dcr_class = find_class(env, DCR_CLASS);
	if (dcr_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Locate the method id we need */
	dcr_getcip = get_methodID(env, dcr_class, DCR_GETCIP);
	if (dcr_getcip == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Get the address from the record */
	jaddr = (*env)->CallObjectMethod(env, jrec, dcr_getcip);
	if (jaddr == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return (NULL);
	}

	/* Convert the address to a native string */
	if (!dd_jstring_to_UTF(env, jaddr, &addr)) {
		/* exception thrown */
		throw_memory_exception(env);
		dd_free_datastore_t(&datastore);
		free(net);
		return (NULL);
	}

	rcode = open_dd(&handle, &datastore, DSVC_DHCPNETWORK, net, DSVC_READ);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, net);
		free(addr);
		free(net);
		return (NULL);
	}
	free(net);

	/* Get the record */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCIP);
	record.dn_cip.s_addr = ntohl(inet_addr(addr));

	rcode = lookup_dd(handle, B_FALSE, query, 1, &record,
			(void **)&recordList, &count);

	(void) close_dd(&handle);
	if (rcode == DSVC_SUCCESS) {
		if (count == 1) {
			dhcpClientRecord = create_DhcpClientRecord(env,
						recordList->dnl_rec);
			free_dnrec_list(recordList);
		} else {
			throw_noent_exception(env, addr);
		}
	} else {
		throw_libdhcpsvc_exception(env, rcode);
	}

	free(addr);


	return (dhcpClientRecord);
}

/*
 * Create a network table.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_createDhcpNetwork(
    JNIEnv *env,
    jobject obj,
    jstring jnet,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	char *net;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	rcode = open_dd(&handle, &datastore, DSVC_DHCPNETWORK, net,
		DSVC_CREATE | DSVC_READ | DSVC_WRITE);

	dd_free_datastore_t(&datastore);

	/*
	 * If open was successful, then close. Otherwise, if unsuccessful
	 * opening table, then map error to exception.
	 */
	if (rcode == DSVC_SUCCESS) {
		(void) close_dd(&handle);
	} else {
		throw_open_dd_exception(env, rcode, net);
	}

	free(net);
}

/*
 * Delete a network table.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_deleteDhcpNetwork(
    JNIEnv *env,
    jobject obj,
    jstring jnet,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	char *net;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* Retrieve the net argument */
	if (!dd_jstring_to_UTF(env, jnet, &net)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	rcode = remove_dd(&datastore, DSVC_DHCPNETWORK, net);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_remove_dd_exception(env, rcode, net);
	}

	free(net);
}
