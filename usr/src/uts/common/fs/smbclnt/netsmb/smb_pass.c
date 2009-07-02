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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Password Keychain storage mechanism.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/pathname.h>
#include <sys/mount.h>
#include <sys/sdt.h>
#include <fs/fs_subr.h>
#include <sys/devops.h>
#include <sys/thread.h>
#include <sys/mkdev.h>
#include <sys/avl.h>
#include <sys/avl_impl.h>
#include <sys/u8_textprep.h>

#include <netsmb/smb_osdep.h>

#include <netsmb/smb.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_pass.h>

/*
 * The smb_ptd is a cache of Uid's, User names, passwords and domain names.
 * It will be used for storing the password information for a user and will
 * be used to for connections without entering the pasword again if its
 * already keyed in by the user. Its a kind of Key-Chain mechanism
 * implemented by Apple folks.
 */

/*
 * Information stored in the nodes:
 * UID:  Uid of the person who initiated the login request.
 * ZoneID: ZoneID of the zone from where the login request is initiated.
 * Username: Username in the CIFS server.
 * Srvdom: Domain name/ Server name of the CIFS server.
 * Password: Password of the user.
 * For more information, see smb_pass.h and sys/avl.h
 */

/*
 * Information retrieved from the node.
 * Node/password information can only be retrived with a call
 * to smb_pkey_getpw(). Password never gets copied to the userspace.
 * It will be copied to the Kernel data structure smbioc_ossn->ioc_password
 * when needed for doing the "Session Setup". All other calls will return
 * either a success or a failure.
 */

avl_tree_t smb_ptd; /* AVL password tree descriptor */
unsigned int smb_list_len = 0;	/* No. of elements in the tree. */
kmutex_t smb_ptd_lock; 	/* Mutex lock for controlled access */

int smb_pkey_check(smbioc_pk_t *pk, cred_t *cr);
int smb_pkey_deluid(uid_t ioc_uid, cred_t *cr);

/*
 * This routine is called by AVL tree calls when they want to find a
 * node, find the next position in the tree to add or for deletion.
 * Compare nodes from the tree to find the actual node based on
 * uid/zoneid/username/domainname.
 */
int
smb_pkey_cmp(const void *a, const void *b)
{
	const smb_passid_t *pa = (smb_passid_t *)a;
	const smb_passid_t *pb = (smb_passid_t *)b;
	int duser, dsrv, error;

	ASSERT(MUTEX_HELD(&smb_ptd_lock));

	/*
	 * The nodes are added sorted on the uid/zoneid/domainname/username
	 * We will do this:
	 * Compare uid's. The owner who stored the node gets access.
	 * Then zoneid to check if the access is from the same zone.
	 * Compare usernames.
	 * If the above are same, then compare domain/server names.
	 */
	if (pa->uid < pb->uid)
		return (-1);
	if (pa->uid > pb->uid)
		return (+1);
	if (pa->zoneid < pb->zoneid)
		return (-1);
	if (pa->zoneid > pb->zoneid)
		return (+1);
	dsrv = u8_strcmp(pa->srvdom, pb->srvdom, 0,
	    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &error);
	if (dsrv < 0)
		return (-1);
	if (dsrv > 0)
		return (+1);
	duser = u8_strcmp(pa->username, pb->username, 0,
	    U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &error);
	if (duser < 0)
		return (-1);
	if (duser > 0)
		return (+1);
	return (0);
}

/*
 * Initialization of the code that deals with uid and passwords.
 */
void
smb_pkey_init()
{
	avl_create(&smb_ptd,
	    smb_pkey_cmp,
	    sizeof (smb_passid_t),
	    offsetof(smb_passid_t,
	    cpnode));
	mutex_init(&smb_ptd_lock, NULL, MUTEX_DEFAULT, NULL);
}

/*
 * Destroy the full AVL tree.
 * Called just before unload.
 */
void
smb_pkey_fini()
{
	smb_pkey_deluid((uid_t)-1, kcred);
	avl_destroy(&smb_ptd);
	mutex_destroy(&smb_ptd_lock);
}

/*
 * Driver unload calls this to ask if we
 * have any stored passwords
 */
int
smb_pkey_idle()
{
	int n;

	mutex_enter(&smb_ptd_lock);
	n = avl_numnodes(&smb_ptd);
	mutex_exit(&smb_ptd_lock);

	return ((n) ? EBUSY : 0);
}

int
smb_node_delete(smb_passid_t *tmp)
{
	ASSERT(MUTEX_HELD(&smb_ptd_lock));
	avl_remove(&smb_ptd, tmp);
	strfree(tmp->srvdom);
	strfree(tmp->username);
	kmem_free(tmp, sizeof (*tmp));
	return (0);
}


/*
 * Remove a node from the AVL tree identified by cpid.
 */
int
smb_pkey_del(smbioc_pk_t *pk, cred_t *cr)
{
	avl_index_t where;
	smb_passid_t buf, *cpid, *tmp;
	uid_t uid;

	tmp = &buf;
	uid = pk->pk_uid;
	if (uid == (uid_t)-1)
		uid = crgetruid(cr);
	else {
		if (secpolicy_smbfs_login(cr, uid))
			return (EPERM);
	}
	tmp->uid = uid;
	tmp->zoneid = getzoneid();
	tmp->srvdom = pk->pk_dom;
	tmp->username = pk->pk_usr;

	mutex_enter(&smb_ptd_lock);
	if ((cpid = (smb_passid_t *)avl_find(&smb_ptd,
	    tmp, &where)) != NULL) {
		smb_node_delete(cpid);
	}
	mutex_exit(&smb_ptd_lock);

	return (0);
}

/*
 * Delete the entries owned by a particular user
 * based on uid. We go through all the nodes and
 * delete the nodes whereever the uid matches.
 *
 * Also implements "delete all" when uid == -1.
 *
 * You must have privilege to use any uid other
 * than your real uid.
 */
int
smb_pkey_deluid(uid_t ioc_uid, cred_t *cr)
{
	smb_passid_t *cpid, *tmp;

	if (secpolicy_smbfs_login(cr, ioc_uid))
		return (EPERM);

	mutex_enter(&smb_ptd_lock);
	for (tmp = avl_first(&smb_ptd); tmp != NULL;
	    tmp = cpid) {
		cpid = AVL_NEXT(&smb_ptd, tmp);
		if (ioc_uid == (uid_t)-1 ||
		    ioc_uid == tmp->uid) {
			/*
			 * Delete the node.
			 */
			smb_node_delete(tmp);
		}
	}
	mutex_exit(&smb_ptd_lock);

	return (0);
}

/*
 * Add entry or modify existing.
 * Check for existing entry..
 * If present, delete.
 * Now, add the new entry.
 */
int
smb_pkey_add(smbioc_pk_t *pk, cred_t *cr)
{
	avl_tree_t *t = &smb_ptd;
	avl_index_t	where;
	smb_passid_t *tmp, *cpid;
	int ret;
	uid_t uid;

	uid = pk->pk_uid;
	if (uid == (uid_t)-1)
		uid = crgetruid(cr);
	else {
		if (secpolicy_smbfs_login(cr, uid))
			return (EPERM);
	}
	cpid = kmem_zalloc(sizeof (smb_passid_t), KM_SLEEP);
	cpid->uid = uid;
	cpid->zoneid = getzoneid();
	cpid->srvdom = strdup(pk->pk_dom);
	cpid->username = strdup(pk->pk_usr);
	bcopy(pk->pk_lmhash, cpid->lmhash, SMBIOC_HASH_SZ);
	bcopy(pk->pk_nthash, cpid->nthash, SMBIOC_HASH_SZ);

	/*
	 * XXX: Instead of calling smb_pkey_check here,
	 * should call avl_find directly, and hold the
	 * lock across: avl_find, avl_remove, avl_insert.
	 */

	/* If it already exists, delete it. */
	ret = smb_pkey_check(pk, cr);
	if (ret == 0) {
		smb_pkey_del(pk, cr);
	}

	mutex_enter(&smb_ptd_lock);
	tmp = (smb_passid_t *)avl_find(t, cpid, &where);
	if (tmp == NULL) {
		avl_insert(t, cpid, where);
	} else {
		strfree(cpid->srvdom);
		strfree(cpid->username);
		kmem_free(cpid, sizeof (smb_passid_t));
	}
	mutex_exit(&smb_ptd_lock);

	return (0);
}

/*
 * Determine if a node with uid,zoneid, uname & dname exists in the tree
 * given the information, and if found, return the hashes.
 */
int
smb_pkey_check(smbioc_pk_t *pk, cred_t *cr)
{
	avl_tree_t *t = &smb_ptd;
	avl_index_t	where;
	smb_passid_t *tmp, *cpid;
	int error = ENOENT;
	uid_t uid;

	uid = pk->pk_uid;
	if (uid == (uid_t)-1)
		uid = crgetruid(cr);
	else {
		if (secpolicy_smbfs_login(cr, uid))
			return (EPERM);
	}
	cpid = kmem_alloc(sizeof (smb_passid_t), KM_SLEEP);
	cpid->uid = uid;
	cpid->zoneid = getzoneid();
	cpid->srvdom = pk->pk_dom;
	cpid->username = pk->pk_usr;

	mutex_enter(&smb_ptd_lock);
	tmp = (smb_passid_t *)avl_find(t, cpid, &where);
	mutex_exit(&smb_ptd_lock);

	if (tmp != NULL) {
		bcopy(tmp->lmhash, pk->pk_lmhash, SMBIOC_HASH_SZ);
		bcopy(tmp->nthash, pk->pk_nthash, SMBIOC_HASH_SZ);
		error = 0;
	}

	kmem_free(cpid, sizeof (smb_passid_t));
	return (error);
}


int
smb_pkey_ioctl(int cmd, intptr_t arg, int flags, cred_t *cr)
{
	smbioc_pk_t  *pk;
	uid_t uid;
	int err = 0;

	pk = kmem_alloc(sizeof (*pk), KM_SLEEP);

	switch (cmd) {
	case SMBIOC_PK_ADD:
	case SMBIOC_PK_DEL:
	case SMBIOC_PK_CHK:
		if (ddi_copyin((void *)arg, pk,
		    sizeof (*pk), flags)) {
			err = EFAULT;
			goto out;
		}
		/* Make strlen (etc) on these safe. */
		pk->pk_dom[SMBIOC_MAX_NAME-1] = '\0';
		pk->pk_usr[SMBIOC_MAX_NAME-1] = '\0';
		break;
	}

	switch (cmd) {
	case SMBIOC_PK_ADD:
		err = smb_pkey_add(pk, cr);
		break;

	case SMBIOC_PK_DEL:
		err = smb_pkey_del(pk, cr);
		break;

	case SMBIOC_PK_CHK:
		err = smb_pkey_check(pk, cr);
		/* This is just a hash now. */
		(void) ddi_copyout(pk, (void *)arg,
		    sizeof (*pk), flags);
		break;

	case SMBIOC_PK_DEL_OWNER:
		uid = crgetruid(cr);
		err = smb_pkey_deluid(uid, cr);
		break;

	case SMBIOC_PK_DEL_EVERYONE:
		uid = (uid_t)-1;
		err = smb_pkey_deluid(uid, cr);
		break;

	default:
		err = ENODEV;
	}

out:
	kmem_free(pk, sizeof (*pk));
	return (err);
}
