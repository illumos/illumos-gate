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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <jni.h>
#include <kadm5/admin.h>
#include <adm_err.h>
#include <sys/signal.h>
#include <netdb.h>
#include <iconv.h>
#include <langinfo.h>
#include <clnt/client_internal.h>
#include <etypes.h>

static int Principal_to_kadmin(JNIEnv *, jobject, int, krb5_principal *,
	kadm5_principal_ent_rec *, long *, char **, char **,
	kadm5_config_params *);
static int kadmin_to_Principal(kadm5_principal_ent_rec *, JNIEnv *, jobject,
	const char *, char *);
static int Policy_to_kadmin(JNIEnv *, jobject, int, kadm5_policy_ent_rec *,
	long *);
static int kadmin_to_Policy(kadm5_policy_ent_rec *, JNIEnv *, jobject);
static int edit_comments(kadm5_principal_ent_rec *, krb5_principal, char *);
static int format_comments(kadm5_principal_ent_rec *, long *, char *);
static int extract_comments(kadm5_principal_ent_rec *, char **);
static int set_password(krb5_principal, char *, kadm5_config_params *);
static void handle_error(JNIEnv *, int);
static char *qualify(char *name);

static void *server_handle = NULL;
static char *cur_realm = NULL;

static iconv_t cd = (iconv_t)-1;

static char *
qualify(char *name)
{
	char *fullname;
	int len;

	if (strchr(name, '@') != NULL)
		return (strdup(name));
	len = strlen(name) + strlen(cur_realm) + 2;
	fullname = malloc(len);
	if (fullname)
		snprintf(fullname, len, "%s@%s", name, cur_realm);
	return (fullname);
}


/*
 * Class:     Kadmin
 * Method:    sessionInit
 * Signature:
 * (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_sessionInit(JNIEnv *env, jobject obj, jstring name,
	jstring passwd, jstring realm, jstring server, jint port)
{
	const char *cname = NULL, *cpasswd = NULL;
	const char *crealm = NULL, *cserver = NULL;
	int cport = 749;
	kadm5_config_params params;
	kadm5_ret_t ret;
	char *ka_service = NULL;
	char *ka_name = NULL;
	char *codeset;
	int len;

	if (server_handle != NULL)
		kadm5_destroy(server_handle);

	if (cd == (iconv_t)-1) {
		codeset = nl_langinfo(CODESET);
		/* fprintf(stderr, "codeset returned %s\n", codeset);  XXX */
		if (strcmp("UTF-8", codeset) != 0)
			cd = iconv_open("UTF-8", codeset);
	}

	/* Get hold of string arguments */
	cname = (*env)->GetStringUTFChars(env, name, NULL);
	if (!cname) {
		ret = KADM_JNI_STRING;
		goto err;
	}
	cpasswd = (*env)->GetStringUTFChars(env, passwd, NULL);
	if (!cpasswd) {
		ret = KADM_JNI_STRING;
		goto err;
	}
	crealm = (*env)->GetStringUTFChars(env, realm, NULL);
	if (!crealm) {
		ret = KADM_JNI_STRING;
		goto err;
	}
	if (cur_realm)
		free(cur_realm);
	cur_realm = strdup(crealm);
	cserver = (*env)->GetStringUTFChars(env, server, NULL);
	if (!cserver) {
		ret = KADM_JNI_STRING;
		goto err;
	}
	if (port != 0)
		cport = port;
	else {
		/*
		 * Look for a services map entry
		 * Note that this will be in network byte order,
		 * and that the API requires native byte order.
		 */
		struct servent *rec = getservbyname("kerberos-adm", NULL);
		if (rec)
			cport = (int)ntohs((uint16_t)rec->s_port);
	}

	/*
	 * Build kadm5_config_params with realm name and server name
	 */
	memset((char *)&params, 0, sizeof (params));
	params.realm = (char *)crealm;
	params.admin_server = (char *)cserver;
	params.mask = KADM5_CONFIG_REALM | KADM5_CONFIG_ADMIN_SERVER;
	params.kadmind_port = cport;
	params.mask |= KADM5_CONFIG_KADMIND_PORT;
	len = strlen("kadmin") + strlen(cserver) + 2;
	ka_service = malloc(len);
	if (!ka_service) {
		ret = KADM_ENOMEM;
		goto err;
	}
	snprintf(ka_service, len, "%s@%s", "kadmin", cserver);
	ka_name = qualify((char *)cname);
	if (!ka_name) {
		ret = KADM_ENOMEM;
		goto err;
	}

	ret = kadm5_init_with_password(ka_name, (char *)cpasswd,
	    ka_service, &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_2,
	    NULL, &server_handle);

	/* Release string arguments and variables */
	if (cname)
		(*env)->ReleaseStringUTFChars(env, name, cname);
	if (cpasswd)
		(*env)->ReleaseStringUTFChars(env, passwd, cpasswd);
	if (crealm)
		(*env)->ReleaseStringUTFChars(env, realm, crealm);
	if (cserver)
		(*env)->ReleaseStringUTFChars(env, server, cserver);
	if (ka_name)
		free(ka_name);
	if (ka_service)
		free(ka_service);

err:
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}
	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    sessionExit
 * Signature: ()V
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_Kadmin_sessionExit(JNIEnv *env, jobject obj)
{
	kadm5_ret_t ret;

	/*
	 * Use persistant handle to close
	 */
	ret = kadm5_destroy(server_handle);
	if (ret)
		handle_error(env, ret);
	server_handle = NULL;
	if (cur_realm) {
		free(cur_realm);
		cur_realm = NULL;
	}
}

/*
 * Class:     Kadmin
 * Method:    getPrivs
 * Signature: ()I
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_Kadmin_getPrivs(JNIEnv *env, jobject obj)
{
	long privs = 0;
	kadm5_ret_t ret;

	/*
	 * Get ACL for this user
	 */
	ret = kadm5_get_privs(server_handle, &privs);
	if (ret)
		handle_error(env, ret);
	return (privs);
}

static int
charcmp(const void *a, const void *b)
{
	char    **sa = (char **)a;
	char    **sb = (char **)b;

	return (strcmp(*sa, *sb));
}

/*
 * Class:     Kadmin
 * Method:    getEncList
 * Signature: ()[Ljava/lang/String;
 */

/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_Kadmin_getEncList(JNIEnv *env,
	jobject obj)
{
	jclass stringclass;
	jobjectArray elist;
	jstring s;
	kadm5_ret_t ret;
	int i, j, k, *grp = NULL;
	krb5_int32 num_keysalts;
	krb5_key_salt_tuple *keysalts;
	krb5_enctype e_type;
	kadm5_server_handle_t handle;
	char *e_str, e_buf[BUFSIZ];
	krb5_error_code kret;
	krb5_boolean similar;
	krb5_context context;

	if (kret = krb5_init_context(&context)) {
		handle_error(env, kret);
		return (NULL);
	}

	/*
	 * Create and populate a Java String array
	 */
	stringclass = (*env)->FindClass(env, "java/lang/String");
	if (!stringclass) {
		handle_error(env, KADM_JNI_CLASS);
		return (NULL);
	}

	handle = server_handle;
	num_keysalts = handle->params.num_keysalts;
	keysalts = handle->params.keysalts;
	elist = (*env)->NewObjectArray(env, num_keysalts, stringclass, NULL);
	if (!elist) {
		handle_error(env, KADM_JNI_ARRAY);
		return (NULL);
	}

	/*
	 * Populate groupings for encryption types that are similar.
	 */
	grp = malloc(sizeof (int) * num_keysalts);
	if (grp == NULL) {
		handle_error(env, errno);
		return (NULL);
	}
	for (i = 0; i < num_keysalts; i++)
		grp[i] = i;

	for (i = 0; i < num_keysalts; i++) {
		if (grp[i] != i)
			continue;
		for (j = i + 1; j < num_keysalts; j++) {
			if (kret = krb5_c_enctype_compare(context,
			    keysalts[i].ks_enctype, keysalts[j].ks_enctype,
			    &similar)) {
				free(grp);
				handle_error(env, kret);
				return (NULL);
			}
			if (similar)
				grp[j] = grp[i];
		}
	}

	/*
	 * Populate from params' supported enc type list from the initial kadmin
	 * session, this is documented default that the client can handle.
	 */
	for (i = 0; i < num_keysalts; i++) {
		e_type = keysalts[i].ks_enctype;

		for (j = 0; j < krb5_enctypes_length; j++) {
			if (e_type == krb5_enctypes_list[j].etype) {
				e_str = krb5_enctypes_list[j].in_string;
				(void) snprintf(e_buf, sizeof (e_buf),
				    "%d %s:normal", grp[i], e_str);
				s = (*env)->NewStringUTF(env, e_buf);
				if (!s) {
					free(grp);
					handle_error(env, KADM_JNI_NEWSTRING);
					return (NULL);
				}
				(*env)->SetObjectArrayElement(env, elist, i, s);
				break;
			}
		}
	}

	free(grp);
	return (elist);
}

/*
 * Class:     Kadmin
 * Method:    getPrincipalList
 * Signature: ()[Ljava/lang/String;
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_Kadmin_getPrincipalList(JNIEnv *env,
	jobject obj)
{
	jclass stringclass;
	jobjectArray plist;
	jstring s;
	char **princs;
	int i, count;
	kadm5_ret_t ret;

	/*
	 * Get the list
	 */
	ret = kadm5_get_principals(server_handle, NULL, &princs, &count);
	if (ret) {
		handle_error(env, ret);
		return (NULL);
	}
	qsort(princs, count, sizeof (princs[0]), charcmp);

	/*
	 * Create and populate a Java String array
	 */
	stringclass = (*env)->FindClass(env, "java/lang/String");
	if (!stringclass) {
		handle_error(env, KADM_JNI_CLASS);
		return (NULL);
	}
	plist = (*env)->NewObjectArray(env, count, stringclass, NULL);
	if (!plist) {
		handle_error(env, KADM_JNI_ARRAY);
		return (NULL);
	}
	for (i = 0; i < count; i++) {
		s = (*env)->NewStringUTF(env, princs[i]);
		if (!s) {
			handle_error(env, KADM_JNI_NEWSTRING);
			return (NULL);
		}
		(*env)->SetObjectArrayElement(env, plist, i, s);
	}
	kadm5_free_name_list(server_handle, princs, count);
	return (plist);
}

/*
 * Class:     Kadmin
 * Method:    getPrincipalList2
 * Signature: ()Ljava/lang/String;
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_Kadmin_getPrincipalList2(JNIEnv *env, jobject obj)
{
	jstring plist;
	char **princs;
	char *princlist = NULL;
	int i, count, n, used = 0, size = 0;
	kadm5_ret_t ret;

	/*
	 * Get the list
	 */
	ret = kadm5_get_principals(server_handle, NULL, &princs, &count);
	if (ret) {
		handle_error(env, ret);
		return (NULL);
	}
	qsort(princs, count, sizeof (princs[0]), charcmp);

	/*
	 * Build one large C string to hold list
	 */
	used = 0;
	princlist = malloc(size += 2048);
	if (!princlist)
		return (NULL);
	for (i = 0; i < count; i++) {
		n = strlen(princs[i]);
		if (used + n + 2 > size) {
			princlist = realloc(princlist, size += 2048);
			if (!princlist)
				return (NULL);
		}
		strncpy(&princlist[used], princs[i], n);
		used += n + 1;
		princlist[used-1] = ' ';
		princlist[used] = '\0';
	}

	/*
	 * Create a Java String
	 */
	plist = (*env)->NewStringUTF(env, princlist);
	free(princlist);
	kadm5_free_name_list(server_handle, princs, count);
	return (plist);
}


/*
 * Class:     Kadmin
 * Method:    loadPrincipal
 * Signature: (Ljava/lang/String;LPrincipal;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_loadPrincipal(JNIEnv *env, jobject obj, jstring name, jobject prin)
{
	const char *cname;
	char *fullname;
	char *comments = NULL;
	kadm5_principal_ent_rec pr_rec;
	kadm5_ret_t ret;
	long mask = KADM5_PRINCIPAL_NORMAL_MASK | KADM5_TL_DATA |
	    KADM5_KEY_DATA;
	krb5_principal kprin = NULL;
	krb5_context context;

	cname = (*env)->GetStringUTFChars(env, name, NULL);
	if (!cname) {
		handle_error(env, KADM_JNI_STRING);
		return (JNI_FALSE);
	}
	fullname = qualify((char *)cname);
	if (!fullname) {
		handle_error(env, KADM_JNI_STRING);
		return (JNI_FALSE);
	}

	/*
	 * Get the principal
	 */
	ret = krb5_init_context(&context);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}
	ret = krb5_parse_name(context, fullname, &kprin);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}
	memset((char *)&pr_rec, 0, sizeof (pr_rec));
	ret = kadm5_get_principal(server_handle, kprin, &pr_rec, mask);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	/*
	 * Pull the comments out of the tl_data array
	 */
	ret = extract_comments(&pr_rec, &comments);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	/*
	 * Fill in our Principal object
	 */
	ret = kadmin_to_Principal(&pr_rec, env, prin, cname, comments);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	kadm5_free_principal_ent(server_handle, &pr_rec);
	krb5_free_principal(context, kprin);
	(*env)->ReleaseStringUTFChars(env, name, cname);
	free(fullname);

	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    savePrincipal
 * Signature: (LPrincipal;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_savePrincipal(JNIEnv *env, jobject obj, jobject prin)
{
	kadm5_principal_ent_rec pr_rec;
	long mask;
	char *pw = NULL;
	char *comments = NULL;
	kadm5_ret_t ret;
	krb5_principal kprin = NULL;
	kadm5_config_params params;

	/*
	 * Convert principal object to the kadmin API structure
	 */
	memset((char *)&pr_rec, 0, sizeof (pr_rec));
	memset((char *)&params, 0, sizeof (params));
	ret = Principal_to_kadmin(env, prin, 0, &kprin, &pr_rec, &mask,
	    &pw, &comments, &params);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	/*
	 * Save the principal
	 */
	ret = kadm5_modify_principal(server_handle, &pr_rec, mask);
	if (ret) {
		handle_error(env, ret);
		ret = JNI_FALSE;
		goto out;
	}

	/*
	 * Handle any comments with read-modify-write
	 */
	ret = edit_comments(&pr_rec, kprin, comments);
	if (ret) {
		handle_error(env, ret);
		ret = JNI_FALSE;
		goto out;
	}

	/*
	 * Set the password if changed
	 */
	ret = set_password(kprin, pw, &params);
	if (params.keysalts != NULL)
		free(params.keysalts);
	if (ret) {
		handle_error(env, ret);
		ret = JNI_FALSE;
		goto out;
	}
	ret = JNI_TRUE;

out:
	kadm5_free_principal_ent(server_handle, &pr_rec);
	return (ret);
}

/*
 * Class:     Kadmin
 * Method:    createPrincipal
 * Signature: (LPrincipal;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_createPrincipal(JNIEnv *env, jobject obj, jobject prin)
{
	kadm5_principal_ent_rec pr_rec;
	long mask;
	char *pw = NULL;
	char *comments = NULL;
	kadm5_ret_t ret;
	krb5_principal kprin = NULL;
	kadm5_config_params params;

	/*
	 * Convert principal object to the kadmin API structure
	 */
	memset((char *)&pr_rec, 0, sizeof (pr_rec));
	memset((char *)&params, 0, sizeof (params));
	ret = Principal_to_kadmin(env, prin, 1, &kprin, &pr_rec, &mask,
	    &pw, &comments, &params);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	/*
	 * Create the new principal
	 */
	if (params.mask & KADM5_CONFIG_ENCTYPES) {
		ret = kadm5_create_principal_3(server_handle, &pr_rec, mask,
		    params.num_keysalts, params.keysalts, pw);
		if (params.keysalts != NULL)
			free(params.keysalts);
	} else
		ret = kadm5_create_principal(server_handle, &pr_rec, mask, pw);
	if (ret) {
		handle_error(env, ret);
		ret = JNI_FALSE;
		goto out;
	}

	/*
	 * Handle any comments with read-modify-write
	 */
	ret = edit_comments(&pr_rec, kprin, comments);
	if (ret) {
		handle_error(env, ret);
		ret = JNI_FALSE;
		goto out;
	}

	ret = JNI_TRUE;
out:
	kadm5_free_principal_ent(server_handle, &pr_rec);
	return (ret);
}

/*
 * Class:     Kadmin
 * Method:    deletePrincipal
 * Signature: (Ljava/lang/String;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_deletePrincipal(JNIEnv *env, jobject obj, jstring name)
{
	kadm5_ret_t ret;
	const char *cname;
	char *fullname;
	krb5_principal kprin = NULL;
	krb5_context context;

	/*
	 * Get name and call the delete function
	 */
	cname = (*env)->GetStringUTFChars(env, name, NULL);
	if (!cname) {
		handle_error(env, KADM_JNI_STRING);
		return (JNI_FALSE);
	}
	fullname = qualify((char *)cname);
	if (!fullname) {
		handle_error(env, KADM_JNI_STRING);
		return (JNI_FALSE);
	}

	ret = krb5_init_context(&context);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}
	ret = krb5_parse_name(context, fullname, &kprin);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}
	ret = kadm5_delete_principal(server_handle, kprin);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	krb5_free_principal(context, kprin);
	(*env)->ReleaseStringUTFChars(env, name, cname);
	free(fullname);

	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    getPolicyList
 * Signature: ()[Ljava/lang/String;
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_Kadmin_getPolicyList(JNIEnv *env, jobject obj)
{
	jclass stringclass;
	jobjectArray plist;
	jstring s;
	char **pols;
	int i, count;
	kadm5_ret_t ret;

	/*
	 * Get the list
	 */
	ret = kadm5_get_policies(server_handle, NULL, &pols, &count);
	if (ret) {
		handle_error(env, ret);
		return (NULL);
	}
	qsort(pols, count, sizeof (pols[0]), charcmp);

	/*
	 * Create and populate a Java String array
	 */
	stringclass = (*env)->FindClass(env, "java/lang/String");
	if (!stringclass) {
		handle_error(env, KADM_JNI_CLASS);
		return (NULL);
	}
	plist = (*env)->NewObjectArray(env, count, stringclass, NULL);
	if (!plist) {
		handle_error(env, KADM_JNI_ARRAY);
		return (NULL);
	}
	for (i = 0; i < count; i++) {
		s = (*env)->NewStringUTF(env, pols[i]);
		if (!s) {
			handle_error(env, KADM_JNI_NEWSTRING);
			return (NULL);
		}
		(*env)->SetObjectArrayElement(env, plist, i, s);
	}
	kadm5_free_name_list(server_handle, pols, count);
	return (plist);
}

/*
 * Class:     Kadmin
 * Method:    loadPolicy
 * Signature: (Ljava/lang/String;LPolicy;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_loadPolicy(JNIEnv *env, jobject obj, jstring name, jobject pol)
{
	const char *cname;
	kadm5_policy_ent_rec po_rec;
	kadm5_ret_t ret;

	cname = (*env)->GetStringUTFChars(env, name, NULL);
	if (!cname) {
		handle_error(env, KADM_JNI_STRING);
		return (JNI_FALSE);
	}

	ret = kadm5_get_policy(server_handle, (char *)cname, &po_rec);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	ret = kadmin_to_Policy(&po_rec, env, pol);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	kadm5_free_policy_ent(server_handle, &po_rec);
	(*env)->ReleaseStringUTFChars(env, name, cname);

	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    savePolicy
 * Signature: (LPolicy;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_savePolicy(JNIEnv *env, jobject obj, jobject pol)
{
	kadm5_policy_ent_rec po_rec;
	kadm5_ret_t ret;
	long mask;

	ret = Policy_to_kadmin(env, pol, 0, &po_rec, &mask);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	ret = kadm5_modify_policy(server_handle, &po_rec, mask);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    createPolicy
 * Signature: (LPolicy;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_createPolicy(JNIEnv * env, jobject obj, jobject pol)
{
	kadm5_policy_ent_rec po_rec;
	kadm5_ret_t ret;
	long mask;

	ret = Policy_to_kadmin(env, pol, 1, &po_rec, &mask);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	ret = kadm5_create_policy(server_handle, &po_rec, mask);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}

	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    deletePolicy
 * Signature: (Ljava/lang/String;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_deletePolicy(JNIEnv * env, jobject obj, jstring name)
{
	const char *cname;
	kadm5_ret_t ret;

	cname = (*env)->GetStringUTFChars(env, name, NULL);
	if (!cname) {
		handle_error(env, KADM_JNI_STRING);
		return (JNI_FALSE);
	}

	ret = kadm5_delete_policy(server_handle, (char *)cname);
	if (ret) {
		handle_error(env, ret);
		return (JNI_FALSE);
	}
	return (JNI_TRUE);
}

#ifdef needtoknowmore
/*
 * Class:     Kadmin
 * Method:    loadDefaults
 * Signature: (LConfig;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_loadDefaults(JNIEnv *env, jobject obj, jobject config)
{
	/*
	 *
	 */
	return (JNI_TRUE);
}

/*
 * Class:     Kadmin
 * Method:    saveDefaults
 * Signature: (LConfig;)Z
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_Kadmin_saveDefaults(JNIEnv *env, jobject obj, jobject config)
{
	/*
	 *
	 */
	return (JNI_TRUE);
}
#endif

static int
Principal_to_kadmin(JNIEnv *env, jobject prin, int new, krb5_principal *kprin,
	kadm5_principal_ent_rec *p, long *mask, char **pw, char **comments,
	kadm5_config_params *pparams)
{
	jstring s;
	jclass prcl, dateclass, intclass;
	jfieldID f;
	jmethodID mid;
	jobject obj;
	const char *str;
	jlong l;
	jint i;
	jboolean b;
	kadm5_ret_t ret;
	krb5_context context;
	jfieldID flagsID;
	jobject flagsObj;
	jclass flagsClass;
	char *fullname;

	*mask = 0;

	prcl = (*env)->GetObjectClass(env, prin);
	if (!prcl)
		return (KADM_JNI_CLASS);
	dateclass = (*env)->FindClass(env, "java/util/Date");
	if (!dateclass)
		return (KADM_JNI_CLASS);
	intclass = (*env)->FindClass(env, "java/lang/Integer");
	if (!intclass)
		return (KADM_JNI_CLASS);

	f = (*env)->GetFieldID(env, prcl, "PrName", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	s = (jstring)obj;
	str = (*env)->GetStringUTFChars(env, s, NULL);
	if (!str)
		return (KADM_JNI_STRING);
	fullname = qualify((char *)str);
	if (!fullname)
		return (KADM_ENOMEM);
	ret = krb5_init_context(&context);
	if (ret)
		return (ret);
	ret = krb5_parse_name(context, fullname, kprin);
	if (ret)
		return (ret);
	p->principal = *kprin;
	(*env)->ReleaseStringUTFChars(env, s, str);
	if (new)
		*mask |= KADM5_PRINCIPAL;

	f = (*env)->GetFieldID(env, prcl, "PrExpireTime", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, dateclass, "getTime", "()J");
	if (!mid)
		return (KADM_JNI_METHOD);
	l = (*env)->CallLongMethod(env, obj, mid);
	p->princ_expire_time = (long)(l / 1000LL);
	*mask |= KADM5_PRINC_EXPIRE_TIME;

	f = (*env)->GetFieldID(env, prcl, "EncTypes", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	s = (jstring)obj;
	str = (*env)->GetStringUTFChars(env, s, NULL);
	if (!str)
		return (KADM_JNI_STRING);
	if (strlen(str)) {
		ret = krb5_string_to_keysalts((char *)str, ", \t", ":.-", 0,
		    &(pparams->keysalts), &(pparams->num_keysalts));
		if (ret) {
			(*env)->ReleaseStringUTFChars(env, s, str);
			return (ret);
		}
		pparams->mask |= KADM5_CONFIG_ENCTYPES;
	}
	(*env)->ReleaseStringUTFChars(env, s, str);

	f = (*env)->GetFieldID(env, prcl, "Policy", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	s = (jstring)obj;
	str = (*env)->GetStringUTFChars(env, s, NULL);
	if (!str)
		return (KADM_JNI_STRING);
	p->policy = strdup(str);
	if (!p->policy)
		return (KADM_ENOMEM);
	(*env)->ReleaseStringUTFChars(env, s, str);
	if (strlen(p->policy))
		*mask |= KADM5_POLICY;
	else if (!new)
		*mask |= KADM5_POLICY_CLR;

	f = (*env)->GetFieldID(env, prcl, "PwExpireTime", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (obj) {
		mid = (*env)->GetMethodID(env, dateclass, "getTime", "()J");
		if (!mid)
			return (KADM_JNI_METHOD);
		l = (*env)->CallLongMethod(env, obj, mid);
		p->pw_expiration = (long)(l / 1000LL);
		*mask |= KADM5_PW_EXPIRATION;
	}

	f = (*env)->GetFieldID(env, prcl, "MaxLife", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->max_life = i;
	*mask |= KADM5_MAX_LIFE;

	f = (*env)->GetFieldID(env, prcl, "MaxRenew", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->max_renewable_life = i;
	*mask |= KADM5_MAX_RLIFE;

	/*
	 * Comments: because of API rules on the TL_DATA entries,
	 * which say that a load-modify-write is always necessary,
	 * we will only deal with comments if they are newly changed.
	 */
	f = (*env)->GetFieldID(env, prcl, "newComments", "Z");
	if (!f)
		return (KADM_JNI_FIELD);
	b = (*env)->GetBooleanField(env, prin, f);
	if (b == JNI_TRUE) {

		f = (*env)->GetFieldID(env, prcl, "Comments",
		    "Ljava/lang/String;");
		if (!f)
			return (KADM_JNI_FIELD);
		obj = (*env)->GetObjectField(env, prin, f);
		if (!obj)
			return (KADM_JNI_OFIELD);
		s = (jstring)obj;
		str = (*env)->GetStringUTFChars(env, s, NULL);
		if (!str)
			return (KADM_JNI_STRING);
		*comments = strdup(str);
		if (!*comments)
			return (KADM_ENOMEM);
		(*env)->ReleaseStringUTFChars(env, s, str);
	}

	f = (*env)->GetFieldID(env, prcl, "Kvno", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->kvno = i;
	*mask |= KADM5_KVNO;

	/*
	 * Get the Principal.flags field id
	 */
	flagsID = (*env)->GetFieldID(env, prcl, "flags",
	    "LFlags;");
	if (!f)
		return (KADM_JNI_FIELD);

	/*
	 * Get the Principal.Flags object
	 */
	flagsObj = (*env)->GetObjectField(env, prin, flagsID);
	if (!obj)
		return (KADM_JNI_OFIELD);

	/*
	 * Get the Flags object's class
	 */
	flagsClass = (*env)->GetObjectClass(env, flagsObj);
	if (!flagsClass)
		return (KADM_JNI_CLASS);

	/*
	 * Now get the Flags.flags field's value
	 */
	f = (*env)->GetFieldID(env, flagsClass, "flags", "I");
	if (!f)
		return (KADM_JNI_FIELD);

	i = (*env)->GetIntField(env, flagsObj, f);
	p->attributes = i & ~65536;

	*mask |= KADM5_ATTRIBUTES;

	f = (*env)->GetFieldID(env, prcl, "PrPasswd", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	s = (jstring)obj;
	str = (*env)->GetStringUTFChars(env, s, NULL);
	if (!str)
		return (KADM_JNI_STRING);
	*pw = strdup(str);
	if (!*pw)
		return (KADM_ENOMEM);
	(*env)->ReleaseStringUTFChars(env, s, str);

	free(fullname);
	return (0);
}

static int
kadmin_to_Principal(kadm5_principal_ent_rec *p, JNIEnv *env, jobject prin,
		const char *prname, char *comments)
{
	jstring s;
	jclass prcl, dateclass, intclass;
	jfieldID f;
	jmethodID mid;
	jobject obj;
	int i, j, n, used = 0, size = 0;
	kadm5_ret_t ret;
	krb5_context context;
	char *ptr, *enclist = NULL, *e_str = NULL, *i_str;
	char *cstr;

	jfieldID flagsID;
	jobject flagsObj;
	jclass flagsClass;

	prcl = (*env)->GetObjectClass(env, prin);
	if (!prcl)
		return (KADM_JNI_CLASS);
	dateclass = (*env)->FindClass(env, "java/util/Date");
	if (!dateclass)
		return (KADM_JNI_CLASS);
	intclass = (*env)->FindClass(env, "java/lang/Integer");
	if (!intclass)
		return (KADM_JNI_CLASS);

	f = (*env)->GetFieldID(env, prcl, "PrName", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	s = (*env)->NewStringUTF(env, prname);
	if (!s)
		return (KADM_JNI_NEWSTRING);
	(*env)->SetObjectField(env, prin, f, s);

	f = (*env)->GetFieldID(env, prcl, "PrExpireTime", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, dateclass, "setTime", "(J)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	(*env)->CallVoidMethod(env, obj, mid,
	    (jlong) (p->princ_expire_time * 1000LL));

	f = (*env)->GetFieldID(env, prcl, "EncTypes", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	used = 0;
	enclist = malloc(size += 2048);
	if (enclist == NULL)
		return (errno);
	for (i = 0; i < p->n_key_data; i++) {
		krb5_key_data *key_data = &p->key_data[i];
		for (j = 0; j < krb5_enctypes_length; j++) {
			if (key_data->key_data_type[0] ==
			    krb5_enctypes_list[j].etype) {
				i_str = krb5_enctypes_list[j].in_string;
				n = strlen(i_str) + strlen(":normal");
				e_str = malloc(n);
				if (e_str == NULL) {
					free(enclist);
					return (errno);
				}
				(void) snprintf(e_str, n + 1, "%s:normal",
				    i_str);
				/*
				 * We reallocate if existing + what we need +
				 * 2 (the null byte and a space for the list).
				 */
				if (used + n + 2 > size) {
					enclist = realloc(enclist,
					    size += 2048);
					if (enclist == NULL) {
						free(e_str);
						return (errno);
					}
				}
				(void) strncpy(&enclist[used], e_str, n);
				free(e_str);
				e_str = NULL;
				used += n + 1;
				enclist[used-1] = ' ';
				enclist[used] = '\0';
				break;
			}
		}
	}
	s = (*env)->NewStringUTF(env, enclist);
	free(enclist);
	if (!s)
		return (KADM_JNI_NEWSTRING);
	(*env)->SetObjectField(env, prin, f, s);

	f = (*env)->GetFieldID(env, prcl, "Policy", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	cstr = strdup(p->policy ? p->policy : "");
	if (!cstr)
		return (KADM_ENOMEM);
	s = (*env)->NewStringUTF(env, cstr);
	if (!s)
		return (KADM_JNI_NEWSTRING);
	(*env)->SetObjectField(env, prin, f, s);
	free(cstr);

	f = (*env)->GetFieldID(env, prcl, "LastPwChange", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, dateclass, "setTime", "(J)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	(*env)->CallVoidMethod(env, obj, mid,
	    (jlong) (p->last_pwd_change * 1000LL));

	f = (*env)->GetFieldID(env, prcl, "PwExpireTime", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, dateclass, "setTime", "(J)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	(*env)->CallVoidMethod(env, obj, mid,
	    (jlong) (p->pw_expiration * 1000LL));

	f = (*env)->GetFieldID(env, prcl, "MaxLife", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, (jint) p->max_life);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, prin, f, obj);

	f = (*env)->GetFieldID(env, prcl, "MaxRenew", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid,
	    (jint) p->max_renewable_life);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, prin, f, obj);

	f = (*env)->GetFieldID(env, prcl, "ModTime", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, dateclass, "setTime", "(J)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	(*env)->CallVoidMethod(env, obj, mid,
	    (jlong) (p->mod_date * 1000LL));

	ret = krb5_init_context(&context);
	if (ret)
		return (ret);
	ret = krb5_unparse_name(context, p->mod_name, &ptr);
	if (ret)
		return (ret);
	f = (*env)->GetFieldID(env, prcl, "ModName", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	s = (*env)->NewStringUTF(env, ptr);
	if (!s)
		return (KADM_JNI_NEWSTRING);
	(*env)->SetObjectField(env, prin, f, s);
	krb5_xfree(ptr);

	f = (*env)->GetFieldID(env, prcl, "LastSuccess", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, dateclass, "setTime", "(J)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	(*env)->CallVoidMethod(env, obj, mid,
	    (jlong) (p->last_success * 1000LL));

	f = (*env)->GetFieldID(env, prcl, "LastFailure", "Ljava/util/Date;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, dateclass, "setTime", "(J)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->GetObjectField(env, prin, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	(*env)->CallVoidMethod(env, obj, mid,
	    (jlong) (p->last_failed * 1000LL));

	f = (*env)->GetFieldID(env, prcl, "NumFailures", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid,
	    (jint) p->fail_auth_count);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, prin, f, obj);

	f = (*env)->GetFieldID(env, prcl, "Comments", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	cstr = strdup(comments ? comments : "");
	if (!cstr)
		return (KADM_ENOMEM);
	s = (*env)->NewStringUTF(env, cstr);
	if (!s)
		return (KADM_JNI_NEWSTRING);
	(*env)->SetObjectField(env, prin, f, s);
	free(cstr);

	f = (*env)->GetFieldID(env, prcl, "Kvno", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->kvno);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, prin, f, obj);

	f = (*env)->GetFieldID(env, prcl, "Mkvno", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->mkvno);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, prin, f, obj);

	i = p->attributes;

	/*
	 * Get the Principal.flags field id
	 */
	flagsID = (*env)->GetFieldID(env, prcl, "flags",
	    "LFlags;");
	if (!f)
		return (KADM_JNI_FIELD);

	/*
	 * Get the Principal.Flags object
	 */
	flagsObj = (*env)->GetObjectField(env, prin, flagsID);
	if (!obj)
		return (KADM_JNI_OFIELD);

	/*
	 * Get the Flags object's class
	 */
	flagsClass = (*env)->GetObjectClass(env, flagsObj);

	/*
	 * Now set the Flags.flags field's value
	 */
	f = (*env)->GetFieldID(env, flagsClass, "flags", "I");
	if (!f)
		return (KADM_JNI_FIELD);
	(*env)->SetIntField(env, flagsObj, f, i);

	return (0);
}

static int
Policy_to_kadmin(JNIEnv *env, jobject pol, int new,
	kadm5_policy_ent_rec *p, long *mask)
{
	jstring s;
	jclass pocl, intclass;
	jfieldID f;
	jmethodID mid;
	jobject obj;
	const char *str;
	int i;

	*mask = 0;

	pocl = (*env)->GetObjectClass(env, pol);
	if (!pocl)
		return (KADM_JNI_CLASS);
	intclass = (*env)->FindClass(env, "java/lang/Integer");
	if (!intclass)
		return (KADM_JNI_CLASS);

	f = (*env)->GetFieldID(env, pocl, "PolicyName", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, pol, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	s = (jstring)obj;
	str = (*env)->GetStringUTFChars(env, s, NULL);
	if (!str)
		return (KADM_JNI_STRING);
	p->policy = strdup(str);
	if (!p->policy)
		return (KADM_ENOMEM);
	if (new)
		*mask |= KADM5_POLICY;
	(*env)->ReleaseStringUTFChars(env, s, str);

	f = (*env)->GetFieldID(env, pocl, "PwMinLife", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, pol, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->pw_min_life = i;
	*mask |= KADM5_PW_MIN_LIFE;

	f = (*env)->GetFieldID(env, pocl, "PwMaxLife", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, pol, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->pw_max_life = i;
	*mask |= KADM5_PW_MAX_LIFE;

	f = (*env)->GetFieldID(env, pocl, "PwMinLength", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, pol, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->pw_min_length = i;
	*mask |= KADM5_PW_MIN_LENGTH;

	f = (*env)->GetFieldID(env, pocl, "PwMinClasses",
	    "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, pol, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->pw_min_classes = i;
	*mask |= KADM5_PW_MIN_CLASSES;

	f = (*env)->GetFieldID(env, pocl, "PwSaveCount", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	obj = (*env)->GetObjectField(env, pol, f);
	if (!obj)
		return (KADM_JNI_OFIELD);
	mid = (*env)->GetMethodID(env, intclass, "intValue", "()I");
	if (!mid)
		return (KADM_JNI_METHOD);
	i = (*env)->CallIntMethod(env, obj, mid);
	p->pw_history_num = i;
	*mask |= KADM5_PW_HISTORY_NUM;

	return (0);
}

static int
kadmin_to_Policy(kadm5_policy_ent_rec *p, JNIEnv *env, jobject pol)
{
	jstring s;
	jclass pocl, intclass;
	jfieldID f;
	jmethodID mid;
	jobject obj;

	pocl = (*env)->GetObjectClass(env, pol);
	if (!pocl)
		return (KADM_JNI_CLASS);
	intclass = (*env)->FindClass(env, "java/lang/Integer");
	if (!intclass)
		return (KADM_JNI_CLASS);

	f = (*env)->GetFieldID(env, pocl, "PolicyName", "Ljava/lang/String;");
	if (!f)
		return (KADM_JNI_FIELD);
	s = (*env)->NewStringUTF(env, p->policy);
	if (!s)
		return (KADM_JNI_NEWSTRING);
	(*env)->SetObjectField(env, pol, f, s);

	f = (*env)->GetFieldID(env, pocl, "PwMinLife", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->pw_min_life);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, pol, f, obj);

	f = (*env)->GetFieldID(env, pocl, "PwMaxLife", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->pw_max_life);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, pol, f, obj);

	f = (*env)->GetFieldID(env, pocl, "PwMinLength", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->pw_min_length);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, pol, f, obj);

	f = (*env)->GetFieldID(env, pocl, "PwMinClasses",
	    "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->pw_min_classes);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, pol, f, obj);

	f = (*env)->GetFieldID(env, pocl, "PwSaveCount", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->pw_history_num);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, pol, f, obj);

	f = (*env)->GetFieldID(env, pocl, "RefCount", "Ljava/lang/Integer;");
	if (!f)
		return (KADM_JNI_FIELD);
	mid = (*env)->GetMethodID(env, intclass, "<init>", "(I)V");
	if (!mid)
		return (KADM_JNI_METHOD);
	obj = (*env)->NewObject(env, intclass, mid, p->policy_refcnt);
	if (!obj)
		return (KADM_JNI_OBJECT);
	(*env)->SetObjectField(env, pol, f, obj);

	return (0);
}

#define	SUNSOFT_COMMENTS	256

/*
 * The new principal has been saved; now we do a load-modify-store
 * to get the comments into the TL_DATA array.
 */
static int
edit_comments(kadm5_principal_ent_rec *p, krb5_principal kprin, char *comments)
{
	long mask = KADM5_PRINCIPAL | KADM5_TL_DATA;
	kadm5_ret_t ret;

	if (!comments || !strlen(comments))
		return (0);

	ret = kadm5_get_principal(server_handle, kprin, p, mask);
	if (ret)
		return (ret);

	mask = 0;
	ret = format_comments(p, &mask, comments);
	if (ret)
		return (ret);

	if (mask) {
		ret = kadm5_modify_principal(server_handle, p, mask);
		if (ret)
			return (ret);
	}

	return (0);
}

/*
 * Put the comments into TL_DATA.
 */
static int
format_comments(kadm5_principal_ent_rec *p, long *mask, char *comments)
{
	krb5_tl_data *t, *t1, *tdp;
	char *s;

	if (!comments || !strlen(comments))
		return (0);
	tdp = malloc(sizeof (krb5_tl_data));
	if (!tdp)
		return (KADM_ENOMEM);
	s = strdup(comments);
	if (!s)
		return (KADM_ENOMEM);

	/*
	 * Search for existing comments field, or find next-to-last
	 */
	for (t = t1 = p->tl_data; t; t1 = t, t = t->tl_data_next)
		if (t->tl_data_type == SUNSOFT_COMMENTS)
			break;
	if (t) {
		t->tl_data_length = strlen(comments);
		free(t->tl_data_contents);
		t->tl_data_contents = (krb5_octet *)s;
	} else {
		tdp->tl_data_next = NULL;
		tdp->tl_data_type = SUNSOFT_COMMENTS;
		tdp->tl_data_length = strlen(comments)+1;
		tdp->tl_data_contents = (krb5_octet *)s;
		if (t1)
			t1->tl_data_next = tdp;
		else
			p->tl_data = tdp;
		p->n_tl_data++;
	}
	*mask |= KADM5_TL_DATA;
	return (0);
}

/*
 * The principal has been loaded, so we pluck the comments out of TL_DATA.
 */
static int
extract_comments(kadm5_principal_ent_rec *p, char **comments)
{
	krb5_tl_data *t;
	char *s;

	/*
	 * Search for existing comments field, or find next-to-last
	 */
	if (!p->n_tl_data)
		return (0);
	for (t = p->tl_data; t; t = t->tl_data_next)
		if (t->tl_data_type == SUNSOFT_COMMENTS)
			break;
	if (t && t->tl_data_length) {
		s = strdup((char *)t->tl_data_contents);
		if (!s)
			return (KADM_ENOMEM);
		s[t->tl_data_length] = 0;
		*comments = s;
	}
	return (0);
}

/*
 * Set password for the modified principal
 */
static int
set_password(krb5_principal kprin, char *pw, kadm5_config_params *pparams)
{
	kadm5_ret_t ret;
	int keepold = 0;

	if (!pw || !strlen(pw))
		return (0);

	if (pparams->mask & KADM5_CONFIG_ENCTYPES)
		ret = kadm5_chpass_principal_3(server_handle, kprin, keepold,
		    pparams->num_keysalts, pparams->keysalts, pw);
	else
		ret = kadm5_chpass_principal(server_handle, kprin, pw);

	if (ret)
		return (ret);
	return (0);
}

static void
handle_error(JNIEnv *env, int error)
{
	char *s;
	char    from[BUFSIZ], to[BUFSIZ];
	char    *tptr;
	const char  *fptr;
	size_t  ileft, oleft, ret;

	s = (char *)error_message(error);
	/* fprintf(stderr, "Kadmin: %s (%d)\n", s, error); XXX */
	if (cd != (iconv_t)-1) {
		ileft = strlen(s);
		strncpy(from, s, ileft);
		fptr = from;
		oleft = BUFSIZ;
		tptr = to;
		ret = iconv(cd, &fptr, &ileft, &tptr, &oleft);
		if (ret != (size_t)-1) {
			to[BUFSIZ-oleft] = '\0';
			s = to;
		/* fprintf(stderr, "Kadmin: %s (%d)\n", s, error); XXX */
		}
	}
	(*env)->ThrowNew(env, (*env)->FindClass(env, "java/lang/Exception"),
	    (const char *)s);
}
