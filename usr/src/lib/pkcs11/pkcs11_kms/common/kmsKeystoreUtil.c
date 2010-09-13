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
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cryptoutil.h>
#include <unistd.h>
#include <utmpx.h>
#include <pthread.h>
#include <pwd.h>
#include <sha2.h>
#include <security/cryptoki.h>
#include <aes_impl.h>
#include <sys/avl.h>

#include "kmsSession.h"
#include "kmsGlobal.h"
#include "kmsObject.h"

static CK_RV
GetPKCS11StatusFromAgentStatus(KMS_AGENT_STATUS status);

static char		keystore_path[BUFSIZ];
static boolean_t	keystore_path_initialized = B_FALSE;
static time_t		last_objlist_mtime = 0;
pthread_mutex_t		objlist_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t		flock_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct flock fl = {
	0,
	0,
	0,
	0,
	0,
	0,
	{0, 0, 0, 0}
};

#define	KEYSTORE_PATH			"/var/kms"
#define	ALTERNATE_KEYSTORE_PATH		"KMSTOKEN_DIR"
#define	KMS_PROFILE_FILENAME		"profile.cfg"
#define	KMS_DATAUNIT_DESCRIPTION	"Oracle PKCS11/KMS"
#define	KMS_ATTR_DESC_PFX		"PKCS#11v2.20: "
#define	KMSTOKEN_CONFIG_FILENAME	"kmstoken.cfg"
#define	KMSTOKEN_LABELLIST_FILENAME	"objlabels.lst"

static void
kms_hash_string(char *label, uchar_t *hash)
{
	SHA2_CTX ctx;

	SHA2Init(SHA256, &ctx);
	SHA2Update(&ctx, label, strlen(label));
	SHA2Final(hash, &ctx);
}

static char *
get_username(char *username, int len)
{
	struct passwd pwd, *user_info;
	long buflen;
	char *pwdbuf = NULL;

	bzero(username, len);

	buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buflen == -1)
		return (username); /* should not happen */

	pwdbuf = calloc(1, buflen);
	if (pwdbuf == NULL)
		return (username); /* zero-ed earlier */

	user_info = getpwuid_r(getuid(), &pwd, pwdbuf, buflen);

	if (user_info != NULL)
		(void) strlcpy(username, user_info->pw_name, len);

	free(pwdbuf);
	return (username);
}

static char *
kms_get_keystore_path()
{
	char *env_val;
	char username[sizeof (((struct utmpx *)0)->ut_user)];

	if (!keystore_path_initialized) {
		env_val = getenv(ALTERNATE_KEYSTORE_PATH);
		bzero(keystore_path, sizeof (keystore_path));
		/*
		 * If it isn't set or is set to the empty string use the
		 * default location.  We need to check for the empty string
		 * because some users "unset" environment variables by giving
		 * them no value, this isn't the same thing as removing it
		 * from the environment.
		 */
		if ((env_val == NULL) || (strcmp(env_val, "") == 0)) {
			/* alternate path not specified, use /var/kms/$USER */
			(void) snprintf(keystore_path,
			    sizeof (keystore_path), "%s/%s",
			    KEYSTORE_PATH,
			    get_username(username, sizeof (username)));
		} else {
			(void) strlcpy(keystore_path, env_val,
			    sizeof (keystore_path));
		}
		keystore_path_initialized = B_TRUE;
	}
	return (keystore_path);
}

static char *
get_non_comment_line(char *cfgbuf, size_t cfglen, char *buf, size_t buflen)
{
	char *s = cfgbuf;
	char *end = cfgbuf + cfglen;
	char *f;

	/* Skip over blank lines CR/LF */
	while (s < end && (*s == '#' || *s == '\n' || *s == '\r')) {
		/* check for comment sign */
		if (*s == '#') {
			/* skip the rest of the line */
			while ((*s != '\n' || *s == '\r') && s < end)
				s++;
		}
		if ((s < end) && (*s == '\n' || *s == '\r'))
			s++;
	}

	if (s < end) {
		char save, *e;
		f = s; /* mark the beginning. */
		/* Find the end of the line and null terminate it. */
		while (*s != '\n' && *s != '\r' && *s != '#' && s < end) s++;
		save = *s;
		*s = 0x00;
		(void) strncpy(buf, f, buflen);
		*s = save;

		/* Strip trailing whitespace */
		f = buf;
		e = f + strlen(buf) - 1;
		while (e >= f && isspace(*e)) {
			*e = 0x00;
			e--;
		}

	} else {
		/* If we reached the end, return NULL */
		s = NULL;
	}
done:
	return (s);
}

static int
flock_fd(int fd, int cmd, pthread_mutex_t *mutex)
{
	int ret = 0;

	(void) pthread_mutex_lock(mutex);

	fl.l_type = cmd;

	while ((ret = fcntl(fd, F_SETLKW, &fl)) == -1) {
		if (errno != EINTR)
			break;
	}
	(void) pthread_mutex_unlock(mutex);
	return (ret);
}

/*
 * Open the keystore description file in the specified mode.
 * If the keystore doesn't exist, the "do_create_keystore"
 * argument determines if the keystore should be created
 */
static int
open_and_lock_file(char *filename, int cmd, mode_t mode,
    pthread_mutex_t *mutex)
{
	int fd;

	fd = open_nointr(filename, mode|O_NONBLOCK);
	if (fd < 0)
		return (fd);

	if (flock_fd(fd, cmd, mutex)) {
		if (fd > 0)
			(void) close(fd);
		return (-1);
	}

	return (fd);
}

static int
kms_slurp_file(char *file, char *buf, size_t buflen)
{
	int n, fd, total = 0;

	fd = open_and_lock_file(file, F_RDLCK, O_RDONLY, &flock_mutex);
	if (fd == -1)
		return (-1);

	do {
		n = readn_nointr(fd, &buf[total], buflen - total);
		if (n != (buflen - total))
			break;
		else
			total += n;
	} while (total < buflen);

	if (flock_fd(fd, F_UNLCK, &flock_mutex))
		total = -1;

	(void) close(fd);

	return (total);
}

/*
 * The KMS token is considered "initialized" if the file with the token
 * configuration information is present.
 */
CK_BBOOL
kms_is_initialized()
{
	CK_BBOOL rv;
	char *ksdir;
	char cfgfile_path[BUFSIZ];
	struct stat statp;

	ksdir = kms_get_keystore_path();
	if (ksdir == NULL)
		return (CKR_FUNCTION_FAILED);

	(void) snprintf(cfgfile_path, sizeof (cfgfile_path),
	    "%s/%s", ksdir, KMSTOKEN_CONFIG_FILENAME);

	if (stat(cfgfile_path, &statp))
		rv = FALSE;
	else
		rv = TRUE;

	return (rv);
}

static CK_RV
kms_read_config_data(char *path, kms_cfg_info_t *cfginfo)
{
	CK_RV rv = CKR_OK;
	char	*cfgbuf = NULL;
	char	*ptr;
	char	buf[BUFSIZ];
	size_t	buflen = 0, remain;
	struct	stat statp;

	if (path == NULL || cfginfo == NULL)
		return (CKR_ARGUMENTS_BAD);

	if (stat(path, &statp) == -1) {
		return (CKR_FUNCTION_FAILED);
	}

	cfgbuf = calloc(1, statp.st_size);
	if (cfgbuf == NULL)
		return (CKR_HOST_MEMORY);

	buflen = kms_slurp_file(path, cfgbuf, statp.st_size);
	if (buflen != statp.st_size) {
		free(cfgbuf);
		return (CKR_FUNCTION_FAILED);
	}

	remain = buflen;
	ptr = cfgbuf;
	ptr = get_non_comment_line(ptr, remain,
	    cfginfo->name, sizeof (cfginfo->name));
	if (ptr == NULL) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	remain = buflen - (ptr - cfgbuf);
	ptr = get_non_comment_line(ptr, remain,
	    cfginfo->agentId, sizeof (cfginfo->agentId));
	if (ptr == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	remain = buflen - (ptr - cfgbuf);
	ptr = get_non_comment_line(ptr, remain,
	    cfginfo->agentAddr, sizeof (cfginfo->agentAddr));
	if (ptr == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	remain = buflen - (ptr - cfgbuf);
	ptr = get_non_comment_line(ptr, remain, buf, sizeof (buf));
	if (ptr == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	cfginfo->transTimeout = atoi(buf);

	remain = buflen - (ptr - cfgbuf);
	ptr = get_non_comment_line(ptr, remain, buf, sizeof (buf));
	if (ptr == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	cfginfo->failoverLimit = atoi(buf);

	remain = buflen - (ptr - cfgbuf);
	ptr = get_non_comment_line(ptr, remain, buf, sizeof (buf));
	if (ptr == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	cfginfo->discoveryFreq = atoi(buf);

	remain = buflen - (ptr - cfgbuf);
	ptr = get_non_comment_line(ptr, remain, buf, sizeof (buf));
	if (ptr == 0) {
		rv = CKR_FUNCTION_FAILED;
		goto done;
	}
	cfginfo->securityMode = atoi(buf);
done:
	if (cfgbuf != NULL)
		free(cfgbuf);
	return (rv);
}

CK_BBOOL
kms_is_pin_set()
{
	CK_BBOOL rv = TRUE;
	kms_cfg_info_t kmscfg;
	struct stat statp;
	char *ksdir;
	char filepath[BUFSIZ];

	ksdir = kms_get_keystore_path();
	if (ksdir == NULL)
		return (FALSE);

	(void) snprintf(filepath, sizeof (filepath),
	    "%s/%s", ksdir, KMSTOKEN_CONFIG_FILENAME);

	if ((rv = kms_read_config_data(filepath, &kmscfg)))
		return (FALSE);

	/*
	 * The PK12 file is only established once the user has enrolled
	 * and is thus considered having a PIN set.
	 */
	(void) snprintf(filepath, sizeof (filepath),
	    "%s/%s/%s", ksdir, kmscfg.agentId, CLIENT_PK12_FILE);

	if (stat(filepath, &statp))
		rv = FALSE; /* file doesn't exist. */
	else
		rv = TRUE; /* File exists, PIN is set */

	return (rv);
}

void
kms_clear_label_list(avl_tree_t *tree)
{
	void *cookie = NULL;
	objlabel_t *node;

	while ((node = avl_destroy_nodes(tree, &cookie)) != NULL) {
		free(node->label);
		free(node);
	}
}

static void
add_label_node(avl_tree_t *tree, char *label)
{
	avl_index_t where;
	objlabel_t  *node;
	objlabel_t *newnode;
	int i;

	if (tree == NULL || label == NULL)
		return;

	/* Remove trailing CR */
	i = strlen(label) - 1;
	while (i > 0 && label[i] == '\n')
		label[i--] = 0x00;

	newnode = calloc(1, sizeof (objlabel_t));
	newnode->label = (char *)strdup(label);
	if (newnode->label == NULL) {
		free(newnode);
		return;
	}
	/* see if this entry already exists */
	node = avl_find(tree, newnode, &where);
	if (node == NULL) {
		avl_insert(tree, newnode, where);
	} else {
		/* It's a dup, don't add it */
		free(newnode->label);
		free(newnode);
	}
}

CK_RV
kms_reload_labels(kms_session_t *sp)
{
	CK_RV rv = CKR_OK;
	char *cfgbuf = NULL, *ptr, buffer[BUFSIZ];
	size_t buflen, remain;
	struct stat statp;
	char *ksdir;
	char labelfile[BUFSIZ];

	ksdir = kms_get_keystore_path();
	if (ksdir == NULL)
		return (CKR_GENERAL_ERROR);

	(void) snprintf(labelfile, sizeof (labelfile),
	    "%s/%s", ksdir, KMSTOKEN_LABELLIST_FILENAME);

	bzero(&statp, sizeof (statp));
	if (stat(labelfile, &statp) == -1) {
		if (errno == ENOENT) {
			FILE *fp;
			/* Create it */
			fp = fopen(labelfile, "w");
			if (fp == NULL)
				return (CKR_GENERAL_ERROR);
			(void) fclose(fp);
		}
	}

	if (statp.st_size == 0) {
		return (CKR_OK);
	}

	cfgbuf = calloc(1, statp.st_size);
	if (cfgbuf == NULL)
		return (CKR_HOST_MEMORY);

	buflen = kms_slurp_file(labelfile, cfgbuf, statp.st_size);
	if (buflen != statp.st_size) {
		free(cfgbuf);
		return (CKR_FUNCTION_FAILED);
	}

	if (statp.st_mtime == last_objlist_mtime) {
		/* No change */
		goto end;
	}

	/* If we got here, we need to refresh the entire list */
	kms_clear_label_list(&sp->objlabel_tree);

	/*
	 * Read each line and add it as a label node.
	 */
	remain = buflen;
	ptr = cfgbuf;
	while (remain > 0) {
		ptr = get_non_comment_line(ptr, remain,
		    buffer, sizeof (buffer));
		if (ptr == NULL) {
			goto end;
		}
		add_label_node(&sp->objlabel_tree, buffer);
		remain = buflen - (ptr - cfgbuf);
	}
end:
	if (cfgbuf)
		free(cfgbuf);

	return (rv);
}

static CK_RV
kms_get_object_label(kms_object_t *obj, char *label, int len)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE stLabel;

	bzero(label, len);

	stLabel.type = CKA_LABEL;
	stLabel.pValue = label;
	stLabel.ulValueLen = len;

	/*
	 * The caller MUST provide a CKA_LABEL when deleting.
	 */
	rv = kms_get_attribute(obj, &stLabel);

	return (rv);
}

/*
 * Retrieve a data unit associated with the label.
 */
static CK_RV
kms_get_data_unit(kms_session_t *session, char *label,
    KMSAgent_DataUnit *pDataUnit)
{
	KMS_AGENT_STATUS status;
	const utf8cstr pDescription = KMS_DATAUNIT_DESCRIPTION;
	uchar_t	externalUniqueId[SHA256_DIGEST_LENGTH];

	/* Find the data unit that holds the key */
	kms_hash_string(label, externalUniqueId);

	status = KMSAgent_RetrieveDataUnitByExternalUniqueID(
	    &session->kmsProfile,
	    (const unsigned char *)externalUniqueId,
	    sizeof (externalUniqueId),
	    label,
	    pDescription,
	    pDataUnit);

	if (status != KMS_AGENT_STATUS_OK) {
		return (GetPKCS11StatusFromAgentStatus(status));
	}

	return (CKR_OK);
}

static CK_RV
kms_decode_description(char *description, kms_object_t *pKey)
{
	CK_RV rv = CKR_OK;
	char *ptr;
	uint32_t keylen;
	u_longlong_t boolattrs;

	/* If it doesn't start with the expected prefix, return */
	if (strncmp(description, KMS_ATTR_DESC_PFX,
	    strlen(KMS_ATTR_DESC_PFX)))
		return (rv);

	ptr = description + strlen(KMS_ATTR_DESC_PFX);

	/*
	 * Decode as follows:
	 * CK_OBJECT_CLASS (2 bytes)
	 * CK_KEY_TYPE (2 bytes)
	 * CKA_VALUE_LEN (4 bytes)
	 * CK_CERTIFICATE_TYPE (2 bytes - not used)
	 * CK_MECHANISM_TYPE (4 bytes)
	 * boolean attributes (3 bytes)
	 * extra attributes (1 byte)
	 * non-boolean attributes
	 */
	if (sscanf(ptr,
	    "%02lx%02lx%02x00%04lx%06llx00",
	    &pKey->class,
	    &pKey->key_type,
	    &keylen,
	    &pKey->mechanism,
	    &boolattrs) != 5)
		/* We didn't get the full set of attributes */
		rv = CKR_ATTRIBUTE_TYPE_INVALID;
	pKey->bool_attr_mask = boolattrs;

	return (rv);
}

/*
 * Create a new PKCS#11 object record for the KMSAgent_Key.
 */
static CK_RV
kms_new_key_object(
	char *label,
	KMSAgent_DataUnit *dataUnit,
	KMSAgent_Key *pKey,
	kms_object_t **pObj)
{
	CK_RV rv = CKR_OK;
	CK_BBOOL bTrue = B_TRUE;
	CK_KEY_TYPE keytype = CKK_AES;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_ULONG	keylen;
	kms_object_t *newObj;

	CK_ATTRIBUTE template[] = {
		{CKA_TOKEN, NULL, sizeof (bTrue)},
		{CKA_LABEL, NULL, 0},
		{CKA_KEY_TYPE, NULL, sizeof (keytype)},
		{CKA_CLASS, NULL, sizeof (class)},
		{CKA_VALUE, NULL, NULL},
		{CKA_VALUE_LEN, NULL, NULL},
		{CKA_PRIVATE, NULL, sizeof (bTrue)},
	};

	keylen = (CK_ULONG)pKey->m_iKeyLength;

	template[0].pValue = &bTrue;
	template[1].pValue = label;
	template[1].ulValueLen = strlen(label);
	template[2].pValue = &keytype;
	template[3].pValue = &class;
	template[4].pValue = pKey->m_acKey;
	template[4].ulValueLen = pKey->m_iKeyLength;
	template[5].pValue = &keylen;
	template[5].ulValueLen = sizeof (keylen);
	template[6].pValue = &bTrue;

	newObj = kms_new_object();
	if (newObj == NULL)
		return (CKR_HOST_MEMORY);

	/*
	 * Decode the DataUnit description field to find various
	 * object attributes.
	 */
	rv = kms_decode_description(dataUnit->m_acDescription, newObj);
	if (rv) {
		free(newObj);
		return (rv);
	}
	/*
	 * Set the template keytype and class according to the
	 * data parsed from the description.
	 */
	if (newObj->key_type)
		keytype = newObj->key_type;
	if (newObj->class)
		class = newObj->class;

	rv = kms_build_object(template, 7, newObj);
	if (rv) {
		free(newObj);
		return (rv);
	}

	newObj->bool_attr_mask |= TOKEN_BOOL_ON;

	*pObj = newObj;
	return (rv);
}

static CK_RV
kms_get_data_unit_keys(kms_session_t *sp, KMSAgent_DataUnit *dataUnit,
	KMSAgent_ArrayOfKeys **keylist, int *numkeys)
{
	CK_RV rv = CKR_OK;
	KMSAgent_ArrayOfKeys *kmskeys = NULL;
	KMS_AGENT_STATUS status;
	int keysLeft = 0;

	status = KMSAgent_RetrieveDataUnitKeys(
	    &sp->kmsProfile, dataUnit,
	    KMS_MAX_PAGE_SIZE, 0,
	    (int * const)&keysLeft,
	    NULL, /* KeyID */
	    &kmskeys);

	if (status != KMS_AGENT_STATUS_OK) {
		return (GetPKCS11StatusFromAgentStatus(status));
	}

	if (keylist != NULL && kmskeys != NULL)
		*keylist = kmskeys;

	if (numkeys != NULL && kmskeys != NULL)
		*numkeys = kmskeys->m_iSize;

	if (keylist == NULL && kmskeys != NULL)
		KMSAgent_FreeArrayOfKeys(kmskeys);

	return (rv);
}


/*
 * Retrieve a key from KMS.  We can't use "RetrieveKey" because
 * we don't know the key id.  Instead get all keys associated
 * with our data unit (there should be only 1.
 */
CK_RV
KMS_RetrieveKeyObj(kms_session_t *sp, char *label, kms_object_t **pobj)
{
	CK_RV rv = CKR_OK;
	KMSAgent_DataUnit dataUnit;
	KMSAgent_ArrayOfKeys *kmsKeys = NULL;
	KMSAgent_Key *pKey;

	rv = kms_get_data_unit(sp, label, &dataUnit);
	if (rv != CKR_OK)
		return (rv);

	rv = kms_get_data_unit_keys(sp, &dataUnit, &kmsKeys, NULL);

	if (rv != CKR_OK || kmsKeys == NULL || kmsKeys->m_iSize == 0)
		return (CKR_GENERAL_ERROR);

	pKey = &kmsKeys->m_pKeys[0];

	rv = kms_new_key_object(label, &dataUnit, pKey, pobj);

	KMSAgent_FreeArrayOfKeys(kmsKeys);
	return (rv);
}

CK_RV
KMS_RefreshObjectList(kms_session_t *sp, kms_slot_t *pslot)
{
	kms_object_t *pObj;
	char label[BUFSIZ];
	CK_RV rv;
	objlabel_t  *node;

	rv = kms_reload_labels(sp);
	if (rv != CKR_OK)
		return (rv);

	/*
	 * If an object is not in the list, reload it from KMS.
	 */
	node = avl_first(&sp->objlabel_tree);
	while (node != NULL) {
		boolean_t found = FALSE;
		/* Search object list for matching object */
		pObj = pslot->sl_tobj_list;
		while (pObj != NULL && !found) {
			(void) pthread_mutex_lock(&pObj->object_mutex);
			if ((rv = kms_get_object_label(pObj, label,
			    sizeof (label))) != CKR_OK) {
				(void) pthread_mutex_unlock(
				    &pObj->object_mutex);
				return (rv);
			}
			(void) pthread_mutex_unlock(&pObj->object_mutex);
			found = (strcmp(label, node->label) == 0);
			pObj = pObj->next;
		}
		if (!found) {
			/*
			 * Fetch KMS key and prepend it to the
			 * token object list for the slot.
			 */
			rv = KMS_RetrieveKeyObj(sp, node->label, &pObj);
			if (rv == CKR_OK) {
				if (pslot->sl_tobj_list == NULL) {
					pslot->sl_tobj_list = pObj;
					pObj->prev = NULL;
					pObj->next = NULL;
				} else {
					pObj->next = pslot->sl_tobj_list;
					pObj->prev = NULL;
					pslot->sl_tobj_list = pObj;
				}
			}
		}
		node = AVL_NEXT(&sp->objlabel_tree, node);
	}
	return (rv);
}

CK_RV
KMS_Initialize(void)
{
	char *ksdir;
	struct stat fn_stat;
	KMS_AGENT_STATUS kmsrv;

	ksdir = kms_get_keystore_path();
	if (ksdir == NULL)
		return (CKR_GENERAL_ERROR);

	/*
	 * If the keystore directory doesn't exist, create it.
	 */
	if ((stat(ksdir, &fn_stat) != 0) && (errno == ENOENT)) {
		if (mkdir(ksdir, S_IRUSR|S_IWUSR|S_IXUSR) < 0) {
			if (errno != EEXIST)
				return (CKR_GENERAL_ERROR);
		}
	}

	if ((kmsrv = KMSAgent_InitializeLibrary(ksdir, FALSE)) !=
	    KMS_AGENT_STATUS_OK) {
		return (GetPKCS11StatusFromAgentStatus(kmsrv));
	}

	return (CKR_OK);
}

CK_RV
KMS_Finalize()
{
	last_objlist_mtime = 0;

	return (KMSAgent_FinalizeLibrary() == KMS_AGENT_STATUS_OK) ?
	    CKR_OK : CKR_FUNCTION_FAILED;
}

CK_RV
KMS_ChangeLocalPWD(kms_session_t *session,
	const char *pOldPassword,
	const char *pNewPassword)
{
	KMS_AGENT_STATUS status;

	status = KMSAgent_ChangeLocalPWD(
	    &session->kmsProfile,
	    (char * const)pOldPassword,
	    (char * const)pNewPassword);

	return (GetPKCS11StatusFromAgentStatus(status));
}

CK_RV
KMS_GetConfigInfo(kms_cfg_info_t *cfginfo)
{
	CK_RV rv = CKR_OK;
	char cfgfile_path[BUFSIZ];
	char *ksdir = kms_get_keystore_path();

	if (ksdir == NULL)
		return (CKR_GENERAL_ERROR);

	(void) snprintf(cfgfile_path, sizeof (cfgfile_path),
	    "%s/%s", ksdir, KMSTOKEN_CONFIG_FILENAME);

	rv = kms_read_config_data(cfgfile_path, cfginfo);

	return (rv);
}

CK_RV
KMS_LoadProfile(KMSClientProfile *profile,
	kms_cfg_info_t *kmscfg,
	const char *pPassword,
	size_t iPasswordLength)
{
	KMS_AGENT_STATUS status;
	CK_RV rv;
	char *sPassword;
	char cfgfile_path[BUFSIZ];
	char *ksdir;

	sPassword = calloc(1, iPasswordLength + 1);
	if (sPassword == NULL)
		return (CKR_FUNCTION_FAILED);

	(void) memcpy(sPassword, pPassword, iPasswordLength);

	ksdir = kms_get_keystore_path();
	if (ksdir == NULL)
		return (CKR_GENERAL_ERROR);

	(void) snprintf(cfgfile_path, sizeof (cfgfile_path),
	    "%s/%s", ksdir, KMSTOKEN_CONFIG_FILENAME);

	if ((rv = kms_read_config_data(cfgfile_path, kmscfg))) {
		free(sPassword);
		return (rv);
	}

	/* First, try to load existing profile */
	status = KMSAgent_LoadProfile(
	    profile,
	    kmscfg->name,
	    kmscfg->agentId,
	    sPassword,
	    kmscfg->agentAddr,
	    kmscfg->transTimeout,
	    kmscfg->failoverLimit,
	    kmscfg->discoveryFreq,
	    kmscfg->securityMode);

	free(sPassword);
	return (GetPKCS11StatusFromAgentStatus(status));
}

static CK_RV
GetPKCS11StatusFromAgentStatus(KMS_AGENT_STATUS status)
{
	switch (status) {
		case KMS_AGENT_STATUS_OK:
		return (CKR_OK);

		case KMS_AGENT_STATUS_GENERIC_ERROR:
		return (CKR_GENERAL_ERROR);

		case KMS_AGENT_STATUS_NO_MEMORY:
		return (CKR_HOST_MEMORY);

		case KMS_AGENT_STATUS_INVALID_PARAMETER:
		return (CKR_ARGUMENTS_BAD);

		case KMS_AGENT_STATUS_PROFILE_NOT_LOADED:
		return (CKR_CRYPTOKI_NOT_INITIALIZED);

		case KMS_AGENT_STATUS_KMS_UNAVAILABLE:
		case KMS_AGENT_STATUS_KMS_NO_READY_KEYS:
		return (CKR_DEVICE_MEMORY);

		case KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE:
		return (CKR_GENERAL_ERROR);

		case KMS_AGENT_STATUS_PROFILE_ALREADY_LOADED:
		return (CKR_USER_ANOTHER_ALREADY_LOGGED_IN);

		case KMS_AGENT_STATUS_FIPS_KAT_AES_KEYWRAP_ERROR:
		case KMS_AGENT_STATUS_FIPS_KAT_AES_ECB_ERROR:
		case KMS_AGENT_STATUS_FIPS_KAT_HMAC_SHA1_ERROR:
		return (CKR_DEVICE_ERROR);

		case KMS_AGENT_STATUS_ACCESS_DENIED:
		case KMS_AGENT_LOCAL_AUTH_FAILURE:
		return (CKR_PIN_INCORRECT);

		case KMS_AGENT_STATUS_SERVER_BUSY:
		case KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS:
		case KMS_AGENT_STATUS_DATA_UNIT_ID_NOT_FOUND_EXTERNAL_ID_EXISTS:
		case KMS_AGENT_STATUS_KEY_DOES_NOT_EXIST:
		case KMS_AGENT_STATUS_KEY_DESTROYED:
		case KMS_AGENT_AES_KEY_UNWRAP_ERROR:
		case KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR:
		case KMS_AGENT_STATUS_KEY_CALLOUT_FAILURE:
		default:
		return (CKR_GENERAL_ERROR);
	}
}

void
KMS_UnloadProfile(KMSClientProfile *kmsProfile)
{
	(void) KMSAgent_UnloadProfile(kmsProfile);
}

/*
 * kms_update_label_file
 *
 * KMS doesn't provide an API to allow one to query for available
 * data units (which map 1-1 to keys).  To allow for PKCS11 to
 * query for a list of available objects, we keep a local list
 * and update it when an object is added or deleted.
 */
static CK_RV
kms_update_label_file(kms_session_t *sp)
{
	CK_RV rv = CKR_OK;
	objlabel_t *node;
	char *ksdir, *tmpfile, labelfile[BUFSIZ];
	FILE *fp;
	int fd;
	struct stat statp;

	ksdir = kms_get_keystore_path();
	if (ksdir == NULL)
		return (CKR_GENERAL_ERROR);

	(void) snprintf(labelfile, sizeof (labelfile),
	    "%s/%s", ksdir, KMSTOKEN_LABELLIST_FILENAME);

	tmpfile = tempnam(ksdir, "kmspk11");
	if (tmpfile == NULL)
		return (CKR_HOST_MEMORY);

	fp = fopen(tmpfile, "w");
	if (fp == NULL) {
		free(tmpfile);
		return (CKR_GENERAL_ERROR);
	}

	/* Lock it even though its a temporary file */
	fd = fileno(fp);
	if ((rv = flock_fd(fd, F_WRLCK, &objlist_mutex))) {
		(void) fclose(fp);
		free(tmpfile);
		return (rv);
	}

	node = avl_first(&sp->objlabel_tree);
	while (node != NULL) {
		if (node->label != NULL)
			(void) fprintf(fp, "%s\n", node->label);
		node = AVL_NEXT(&sp->objlabel_tree, node);
	}

	/* Update the last mtime */
	if (fstat(fd, &statp) == 0) {
		last_objlist_mtime = statp.st_mtime;
	}

	(void) flock_fd(fd, F_UNLCK, &objlist_mutex);
	(void) fclose(fp);

	(void) unlink(labelfile);
	if (rename(tmpfile, labelfile))
		rv = CKR_GENERAL_ERROR;

	free(tmpfile);
	return (rv);
}

/*
 * Destroy a key in the KMS by disassociating an entire data unit.
 * The KMSAgent API does not have an interface for destroying an
 * individual key.
 */
CK_RV
KMS_DestroyKey(kms_session_t *session, kms_object_t *i_oKey)
{
	CK_RV rv;
	KMSAgent_DataUnit oDataUnit;
	KMS_AGENT_STATUS status;
	char label[BUFSIZ];
	objlabel_t  labelnode, *tnode;
	avl_index_t	where = 0;

	/*
	 * The caller MUST provide a CKA_LABEL when deleting.
	 */
	(void) pthread_mutex_lock(&i_oKey->object_mutex);
	if ((rv = kms_get_object_label(i_oKey, label, sizeof (label)))) {
		(void) pthread_mutex_unlock(&i_oKey->object_mutex);
		return (rv);
	}

	rv = kms_get_data_unit(session, label, &oDataUnit);
	if (rv != CKR_OK)
		return (rv);

	status = KMSAgent_DisassociateDataUnitKeys(
	    &session->kmsProfile, &oDataUnit);

	/*
	 * Remove the label from the label list and update
	 * the file that tracks active keys.
	 */
	bzero(&labelnode, sizeof (labelnode));
	labelnode.label = label;

	if ((tnode = avl_find(&session->objlabel_tree,
	    &labelnode, &where)) != NULL)
		avl_remove(&session->objlabel_tree, tnode);

	/* rewrite the list of labels to disk */
	rv = kms_update_label_file(session);
	if (rv)
		/* Ignore error here */
		rv = CKR_OK;

	(void) pthread_mutex_unlock(&i_oKey->object_mutex);

	return (GetPKCS11StatusFromAgentStatus(status));
}

void
kms_encode_attributes(kms_object_t *pKey, char *attrstr, int len)
{
	char *ptr;

	bzero(attrstr, len);

	(void) strlcpy(attrstr, KMS_ATTR_DESC_PFX, len);
	ptr = attrstr + strlen(attrstr);

	/*
	 * Encode as follows:
	 * CK_OBJECT_CLASS (2 bytes)
	 * CK_KEY_TYPE (2 bytes)
	 * CKA_VALUE_LEN (4 bytes)
	 * CK_CERTIFICATE_TYPE (2 bytes - not used)
	 * CK_MECHANISM_TYPE (4 bytes)
	 * boolean attributes (3 bytes)
	 * extra attributes (1 byte)
	 * non-boolean attributes
	 */
	(void) snprintf(ptr, len - strlen(attrstr),
	    "%02x%02x%02x00%04x%06x00",
	    pKey->class,
	    pKey->key_type,
	    32,
	    pKey->mechanism,
	    (pKey->bool_attr_mask & 0x00FFFFFF));
}

CK_RV
KMS_GenerateKey(kms_session_t *session, kms_object_t *i_oKey)
{
	CK_RV			rv;
	CK_ATTRIBUTE		stLabel;
	KMSAgent_DataUnit	oDataUnit;
	KMSAgent_Key		oKey;
	KMS_AGENT_STATUS	status;
	char			label[128];
	uchar_t			externalUniqueId[SHA256_DIGEST_LENGTH];
	char			pDescription[KMS_MAX_DESCRIPTION + 1];

	(void) pthread_mutex_lock(&i_oKey->object_mutex);

	stLabel.type = CKA_LABEL;
	stLabel.pValue = label;
	stLabel.ulValueLen = sizeof (label);

	/*
	 * The caller MUST provide a CKA_LABEL for storing in the KMS.
	 */
	if ((rv = kms_get_attribute(i_oKey, &stLabel)) != CKR_OK) {
		(void) pthread_mutex_unlock(&i_oKey->object_mutex);
		return (rv);
	}

	label[stLabel.ulValueLen] = '\0';

	kms_hash_string(label, externalUniqueId);

	/* Encode attributes in Description */
	kms_encode_attributes(i_oKey, pDescription,
	    sizeof (pDescription));

	status = KMSAgent_CreateDataUnit(
	    &session->kmsProfile,
	    (const unsigned char *)externalUniqueId,
	    sizeof (externalUniqueId),
	    label,	/* externalTag */
	    pDescription,
	    &oDataUnit);

	/*
	 * If the DataUnit exists, check to see if it has any keys.
	 * If it has no keys, then it is OK to continue.
	 */
	if (status == KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS) {
		int numkeys = 0;

		rv = kms_get_data_unit(session, label, &oDataUnit);
		if (rv != CKR_OK)
			return (rv);

		rv = kms_get_data_unit_keys(session,
		    &oDataUnit, NULL, &numkeys);

		if (rv !=  CKR_OK || numkeys > 0)
			/*
			 * This would be better if there were PKCS#11
			 * error codes for duplicate objects or
			 * something like that.
			 */
			return (CKR_ARGUMENTS_BAD);

		/* If no keys associated with data unit, continue */
		status = KMS_AGENT_STATUS_OK;
	}

	if (status != KMS_AGENT_STATUS_OK) {
		(void) pthread_mutex_unlock(&i_oKey->object_mutex);
		return (GetPKCS11StatusFromAgentStatus(status));
	}

	status = KMSAgent_CreateKey(&session->kmsProfile,
	    &oDataUnit, "", &oKey);

	if (status != KMS_AGENT_STATUS_OK) {
		/*
		 * Clean up the old data unit.
		 */
		(void) pthread_mutex_unlock(&i_oKey->object_mutex);
		return (GetPKCS11StatusFromAgentStatus(status));
	}

	/*
	 * KMS Agent only creates AES-256 keys, so ignore what the user
	 * requested at this point.
	 */
	OBJ_SEC_VALUE(i_oKey) = malloc(oKey.m_iKeyLength);
	if (OBJ_SEC_VALUE(i_oKey) == NULL) {
		(void) pthread_mutex_unlock(&i_oKey->object_mutex);
		return (CKR_HOST_MEMORY);
	}
	(void) memcpy(OBJ_SEC_VALUE(i_oKey), oKey.m_acKey,
	    oKey.m_iKeyLength);
	OBJ_SEC_VALUE_LEN(i_oKey) = oKey.m_iKeyLength;

	/*
	 * Add the label to the local list of available objects
	 */
	add_label_node(&session->objlabel_tree, label);

	rv = kms_update_label_file(session);

	(void) pthread_mutex_unlock(&i_oKey->object_mutex);

	return (GetPKCS11StatusFromAgentStatus(status));
}
