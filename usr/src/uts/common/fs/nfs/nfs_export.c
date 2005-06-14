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

/*
 *  	Copyright 1983, 1984, 1985, 1986, 1987, 1988, 1989  AT&T.
 *		All rights reserved.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/tiuser.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/acl.h>
#include <sys/utsname.h>
#include <netinet/in.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/svc.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>
#include <nfs/nfs_log.h>
#include <nfs/lm.h>

#define	EXPTABLESIZE 16

struct exportinfo *exptable[EXPTABLESIZE];

static int	unexport(fsid_t *, fid_t *, vnode_t *);
static void	exportfree(struct exportinfo *);
static int	loadindex(struct exportdata *);

extern void	nfsauth_cache_free(struct exportinfo *);
extern int	sec_svc_loadrootnames(int, int, caddr_t **, model_t);
extern void	sec_svc_freerootnames(int, int, caddr_t *);

#ifdef VOLATILE_FH_TEST
static struct ex_vol_rename *find_volrnm_fh(struct exportinfo *, nfs_fh4 *);
static uint32_t find_volrnm_fh_id(struct exportinfo *, nfs_fh4 *);
static void free_volrnm_list(struct exportinfo *);
#endif /* VOLATILE_FH_TEST */

/*
 * exported_lock	Read/Write lock that protects the exportinfo list.
 *			This lock must be held when searching or modifiying
 *			the exportinfo list.
 */
krwlock_t exported_lock;

/*
 * "public" and default (root) location for public filehandle
 */
struct exportinfo *exi_public, *exi_root;

fid_t exi_rootfid;	/* for checking the default public file handle */

fhandle_t nullfh2;	/* for comparing V2 filehandles */

#define	exptablehash(fsid, fid) (nfs_fhhash((fsid), (fid)) & (EXPTABLESIZE - 1))

/*
 * File handle hash function, good for producing hash values 16 bits wide.
 */
int
nfs_fhhash(fsid_t *fsid, fid_t *fid)
{
	short *data;
	int i, len;
	short h;

	ASSERT(fid != NULL);

	data = (short *)fid->fid_data;

	/* fid_data must be aligned on a short */
	ASSERT((((uintptr_t)data) & (sizeof (short) - 1)) == 0);

	if (fid->fid_len == 10) {
		/*
		 * probably ufs: hash on bytes 4,5 and 8,9
		 */
		return (fsid->val[0] ^ data[2] ^ data[4]);
	}

	if (fid->fid_len == 6) {
		/*
		 * probably hsfs: hash on bytes 0,1 and 4,5
		 */
		return ((fsid->val[0] ^ data[0] ^ data[2]));
	}

	/*
	 * Some other file system. Assume that every byte is
	 * worth hashing.
	 */
	h = (short)fsid->val[0];

	/*
	 * Sanity check the length before using it
	 * blindly in case the client trashed it.
	 */
	if (fid->fid_len > NFS_FHMAXDATA)
		len = 0;
	else
		len = fid->fid_len / sizeof (short);

	/*
	 * This will ignore one byte if len is not a multiple of
	 * of sizeof (short). No big deal since we at least get some
	 * variation with fsid->val[0];
	 */
	for (i = 0; i < len; i++)
		h ^= data[i];

	return ((int)h);
}

/*
 * Counted byte string compare routine, optimized for file ids.
 */
int
nfs_fhbcmp(char *d1, char *d2, int l)
{
	int k;

	if (l > NFS_FHMAXDATA)
		return (1);

	/*
	 * We are always passed pointers to the data portions of
	 * two fids, where pointers are always 2 bytes from 32 bit
	 * alignment. If the length is also 2 bytes off word alignment,
	 * we can do word compares, because the two bytes before the fid
	 * data are always the length packed into a 16 bit short, so we
	 * can safely start our comparisons at d1-2 and d2-2.
	 * If the length is 2 bytes off word alignment, that probably
	 * means that first two bytes are zeroes. This means that
	 * first word in each fid, including the length are going to be
	 * equal (we wouldn't call fhbcmp if the lengths weren't the
	 * same). Thus it makes the most sense to start comparing the
	 * last words of each data portion.
	 */

	if ((l & 0x3) == 2) {
		/*
		 * We are going move the data pointers to the
		 * last word. Adding just the length, puts us to the
		 * word past end of the data. So reduce length by one
		 * word length.
		 */
		k = l - 4;
		/*
		 * Both adjusted length and the data pointer are offset two
		 * bytes from word alignment. Adding them together gives
		 * us word alignment.
		 */
		d1 += k;
		d2 += k;
		l += 2;
		while (l -= 4) {
			if (*(int *)d1 != *(int *)d2)
				return (1);
			d1 -= 4;
			d2 -= 4;
		}
	} else {
		while (l--) {
			if (*d1++ != *d2++)
				return (1);
		}
	}
	return (0);
}

/*
 * Free the memory allocated within a secinfo entry.
 */
void
srv_secinfo_entry_free(struct secinfo *secp)
{
	if (secp->s_rootcnt > 0 && secp->s_rootnames != NULL) {
		sec_svc_freerootnames(secp->s_secinfo.sc_rpcnum,
				secp->s_rootcnt, secp->s_rootnames);
		secp->s_rootcnt = 0;
	}

	if ((secp->s_secinfo.sc_rpcnum == RPCSEC_GSS) &&
	    (secp->s_secinfo.sc_gss_mech_type)) {
		kmem_free(secp->s_secinfo.sc_gss_mech_type->elements,
			secp->s_secinfo.sc_gss_mech_type->length);
		kmem_free(secp->s_secinfo.sc_gss_mech_type,
			sizeof (rpc_gss_OID_desc));
		secp->s_secinfo.sc_gss_mech_type = NULL;
	}

}

/*
 * Free a list of secinfo allocated in the exportdata structure.
 */
void
srv_secinfo_list_free(struct secinfo *secinfo, int cnt)
{
	int i;

	if (cnt == 0)
		return;

	for (i = 0; i < cnt; i++)
		srv_secinfo_entry_free(&secinfo[i]);

	kmem_free(secinfo, cnt * sizeof (struct secinfo));
}

/*
 * Allocate and copy a secinfo data from "from" to "to".
 *
 * This routine is used by srv_secinfo_add() to add a new flavor to an
 * ancestor's export node. The rootnames are not copied because the
 * allowable rootname access only applies to the explicit exported node,
 * not its ancestor's.
 *
 * "to" should have already been allocated and zeroed before calling
 * this routine.
 *
 * This routine is used under the protection of exported_lock (RW_WRITER).
 */
void
srv_secinfo_copy(struct secinfo *from, struct secinfo *to)
{
	to->s_secinfo.sc_nfsnum = from->s_secinfo.sc_nfsnum;
	to->s_secinfo.sc_rpcnum = from->s_secinfo.sc_rpcnum;

	if (from->s_secinfo.sc_rpcnum == RPCSEC_GSS) {
		to->s_secinfo.sc_service = from->s_secinfo.sc_service;
		bcopy(from->s_secinfo.sc_name, to->s_secinfo.sc_name,
			strlen(from->s_secinfo.sc_name));
		bcopy(from->s_secinfo.sc_gss_mech, to->s_secinfo.sc_gss_mech,
			strlen(from->s_secinfo.sc_gss_mech));

		/* copy mechanism oid */
		to->s_secinfo.sc_gss_mech_type =
			kmem_alloc(sizeof (rpc_gss_OID_desc), KM_SLEEP);
		to->s_secinfo.sc_gss_mech_type->length =
			from->s_secinfo.sc_gss_mech_type->length;
		to->s_secinfo.sc_gss_mech_type->elements =
			kmem_alloc(from->s_secinfo.sc_gss_mech_type->length,
					KM_SLEEP);
		bcopy(from->s_secinfo.sc_gss_mech_type->elements,
			to->s_secinfo.sc_gss_mech_type->elements,
			from->s_secinfo.sc_gss_mech_type->length);
	}

	to->s_refcnt = from->s_refcnt;
	to->s_window = from->s_window;
	/* no need to copy the mode bits - s_flags */
}

/*
 * Add the new security flavors from newdata to the current list, curdata.
 * Upon return, curdata has the newly merged secinfo list.
 *
 * There should be at least 1 secinfo entry in newdata.
 *
 * This routine is used under the protection of exported_lock (RW_WRITER).
 */
void
srv_secinfo_add(struct exportdata *curdata, struct exportdata *newdata)
{
	int ccnt, c;		/* sec count in current data - curdata */
	int ncnt, n;		/* sec count in new data - newdata */
	int tcnt, mcnt;		/* total sec count after merge */
	struct secinfo *msec;	/* merged secinfo list */

	ccnt = curdata->ex_seccnt;
	ncnt = newdata->ex_seccnt;

	ASSERT(ncnt > 0);
	tcnt = ccnt + ncnt;

	for (n = 0; n < ncnt; n++) {
		for (c = 0; c < ccnt; c++) {
		    if (newdata->ex_secinfo[n].s_secinfo.sc_nfsnum ==
			curdata->ex_secinfo[c].s_secinfo.sc_nfsnum) {

			/*
			 * add the reference count of the newdata
			 * to the curdata for this nfs flavor.
			 */
			curdata->ex_secinfo[c].s_refcnt +=
				newdata->ex_secinfo[n].s_refcnt;

			tcnt--;
			break;
		    }
		}
	}

	if (tcnt == ccnt)
		return; /* no change; no new flavors */

	msec = kmem_zalloc(tcnt * sizeof (struct secinfo), KM_SLEEP);

	/* move current secinfo list data to the new list */
	for (c = 0; c < ccnt; c++) {

		bcopy(&curdata->ex_secinfo[c], &msec[c],
			sizeof (struct secinfo));
	}

	/* Add the flavor that's not in the current data */
	mcnt = ccnt;
	for (n = 0; n < ncnt; n++) {
		for (c = 0; c < ccnt; c++) {
		    if (newdata->ex_secinfo[n].s_secinfo.sc_nfsnum ==
			curdata->ex_secinfo[c].s_secinfo.sc_nfsnum)
				break;
		}

		/* This is the one. Add it. */
		if (c == ccnt) {
		    srv_secinfo_copy(&newdata->ex_secinfo[n], &msec[mcnt]);
		    if (curdata->ex_flags & EX_PSEUDO)
			msec[mcnt].s_flags = M_RO;
		    mcnt++;
		}
	}

	ASSERT(mcnt == tcnt);
	/*
	 * Done. Update curdata.
	 * Free up the existing secinfo list in curdata and
	 * set the new value.
	 */
	if (ccnt > 0)
		kmem_free(curdata->ex_secinfo, ccnt * sizeof (struct secinfo));
	curdata->ex_seccnt = tcnt;
	curdata->ex_secinfo = msec;
}

/*
 * For NFS V4.
 * Remove the security data of the unexported node from its ancestors.
 * Assume there is at least one flavor entry in the current data, curdata.
 *
 * This routine is used under the protection of exported_lock (RW_WRITER).
 */
void
srv_secinfo_remove(struct exportdata *curdata, struct exportdata *remdata)
{
	int ccnt, c;		/* sec count in current data - curdata */
	int rcnt, r;		/* sec count in removal data - remdata */
	int tcnt, mcnt;		/* total sec count after removing */
	struct secinfo *msec;	/* final secinfo list after removing */

	ASSERT(curdata->ex_seccnt > 0);
	ccnt = curdata->ex_seccnt;
	rcnt = remdata->ex_seccnt;
	tcnt = ccnt;

	for (r = 0; r < rcnt; r++) {

	    if (SEC_REF_EXPORTED(&remdata->ex_secinfo[r])) {
		/*
		 * Remove a flavor only if the flavor was a shared flavor for
		 * the remdata exported node that's being unshared. Otherwise,
		 * this flavor is for the children of remdata, need to keep it.
		 */
		for (c = 0; c < ccnt; c++) {
		    if (remdata->ex_secinfo[r].s_secinfo.sc_nfsnum ==
			curdata->ex_secinfo[c].s_secinfo.sc_nfsnum) {

			/*
			 * Decrement secinfo reference count by 1.
			 * If this entry is invalid after decrementing
			 * the count (i.e. count < 1), this entry will
			 * be removed.
			 */
			curdata->ex_secinfo[c].s_refcnt--;
			if (SEC_REF_INVALID(&curdata->ex_secinfo[c]))
				tcnt--;

			break;
		    }
		}
	    }
	}

	ASSERT(tcnt >= 0);
	if (tcnt == ccnt)
		return; /* no change; no flavors to remove */

	if (tcnt == 0) {
		srv_secinfo_list_free(curdata->ex_secinfo, ccnt);
		curdata->ex_seccnt = 0;
		curdata->ex_secinfo = NULL;
		return;
	}

	msec = kmem_zalloc(tcnt * sizeof (struct secinfo), KM_SLEEP);

	/* walk thru the given secinfo list to remove the flavors */
	mcnt = 0;
	for (c = 0; c < ccnt; c++) {

		if (SEC_REF_INVALID(&curdata->ex_secinfo[c])) {
			srv_secinfo_entry_free(&curdata->ex_secinfo[c]);
		} else {
			bcopy(&curdata->ex_secinfo[c], &msec[mcnt],
				sizeof (struct secinfo));
			mcnt++;
		}
	}

	ASSERT(mcnt == tcnt);
	/*
	 * Done. Update curdata.
	 * Free the existing secinfo list in curdata. All pointers
	 * within the list have either been moved to msec or freed
	 * if it's invalid.
	 */
	kmem_free(curdata->ex_secinfo, ccnt * sizeof (struct secinfo));
	curdata->ex_seccnt = tcnt;
	curdata->ex_secinfo = msec;
}

/*
 * Upon re-sharing an export node, if there is more than 1 export reference
 * to an old flavor (i.e. some of its children shared with this flavor), this
 * flavor information needs to be transfered to the new shared node.
 *
 * Expect at least 1 secinfo entry in the old shared node - olddata.
 * Expect both curdata and olddata are not pseudo nodes.
 *
 * This routine is used under the protection of exported_lock (RW_WRITER).
 */
void
srv_secinfo_exp2exp(struct exportdata *curdata, struct exportdata *olddata)
{
	int ccnt, c;		/* sec count in current data - curdata */
	int ocnt, o;		/* sec count in old data - olddata */
	int tcnt, mcnt;		/* total sec count after the transfer */
	struct secinfo *msec;	/* merged secinfo list */

	ccnt = curdata->ex_seccnt;
	ocnt = olddata->ex_seccnt;

	ASSERT(ocnt > 0);
	ASSERT(!(olddata->ex_flags & EX_PSEUDO));
	ASSERT(!(curdata->ex_flags & EX_PSEUDO));

	/*
	 * If the olddata has flavors with more than 1 reference count,
	 * transfer the information to the curdata.
	 */
	tcnt = ccnt + ocnt;

	for (o = 0; o < ocnt; o++) {

	    if (SEC_REF_SELF(&olddata->ex_secinfo[o])) {
		tcnt--;
	    } else {
		for (c = 0; c < ccnt; c++) {
		    if (olddata->ex_secinfo[o].s_secinfo.sc_nfsnum ==
			curdata->ex_secinfo[c].s_secinfo.sc_nfsnum) {

			/* add old reference to the current secinfo count */
			curdata->ex_secinfo[c].s_refcnt +=
				olddata->ex_secinfo[o].s_refcnt;

			/* delete the old export flavor reference */
			if (SEC_REF_EXPORTED(&olddata->ex_secinfo[o]))
				curdata->ex_secinfo[c].s_refcnt--;
			tcnt--;
			break;
		    }
		}
	    }
	}

	if (tcnt == ccnt)
		return; /* no more transfer to do */

	/*
	 * olddata has flavors refered by its children that are not
	 * in the current (new) export flavor list. Add these flavors.
	 */
	msec = kmem_zalloc(tcnt * sizeof (struct secinfo), KM_SLEEP);

	/* move current secinfo list data to the new list */
	for (c = 0; c < ccnt; c++) {
		bcopy(&curdata->ex_secinfo[c], &msec[c],
			sizeof (struct secinfo));
	}

	/*
	 * Add the flavor that's not in the new export, but still
	 * referred by its children.
	 */
	mcnt = ccnt;
	for (o = 0; o < ocnt; o++) {
	    if (! SEC_REF_SELF(&olddata->ex_secinfo[o])) {
		for (c = 0; c < ccnt; c++) {
		    if (olddata->ex_secinfo[o].s_secinfo.sc_nfsnum ==
			curdata->ex_secinfo[c].s_secinfo.sc_nfsnum)
				break;
		}

		/*
		 * This is the one. Add it. Decrement the reference count
		 * by 1 if the flavor is an explicitly shared flavor for
		 * the olddata export node.
		 */
		if (c == ccnt) {
		    srv_secinfo_copy(&olddata->ex_secinfo[o], &msec[mcnt]);
		    if (SEC_REF_EXPORTED(&olddata->ex_secinfo[o]))
			msec[mcnt].s_refcnt--;
		    mcnt++;
		}
	    }
	}

	ASSERT(mcnt == tcnt);
	/*
	 * Done. Update curdata.
	 * Free up the existing secinfo list in curdata and
	 * set the new value.
	 */
	if (ccnt > 0)
		kmem_free(curdata->ex_secinfo, ccnt * sizeof (struct secinfo));
	curdata->ex_seccnt = tcnt;
	curdata->ex_secinfo = msec;
}

/*
 * When unsharing an old export node and the old node becomes a pseudo node,
 * if there is more than 1 export reference to an old flavor (i.e. some of
 * its children shared with this flavor), this flavor information needs to
 * be transfered to the new shared node.
 *
 * This routine is used under the protection of exported_lock (RW_WRITER).
 */
void
srv_secinfo_exp2pseu(struct exportdata *curdata, struct exportdata *olddata)
{
	int ocnt, o;		/* sec count in transfer data - trandata */
	int tcnt, mcnt;		/* total sec count after transfer */
	struct secinfo *msec;	/* merged secinfo list */

	ASSERT(curdata->ex_flags & EX_PSEUDO);
	ASSERT(curdata->ex_seccnt == 0);

	ocnt = olddata->ex_seccnt;

	/*
	 * If the olddata has flavors with more than 1 reference count,
	 * transfer the information to the curdata.
	 */
	tcnt = ocnt;

	for (o = 0; o < ocnt; o++) {
	    if (SEC_REF_SELF(&olddata->ex_secinfo[o]))
		tcnt--;
	}

	if (tcnt == 0)
		return; /* no transfer to do */

	msec = kmem_zalloc(tcnt * sizeof (struct secinfo), KM_SLEEP);

	mcnt = 0;
	for (o = 0; o < ocnt; o++) {
	    if (! SEC_REF_SELF(&olddata->ex_secinfo[o])) {

		/*
		 * Decrement the reference count by 1 if the flavor is
		 * an explicitly shared flavor for the olddata export node.
		 */
		srv_secinfo_copy(&olddata->ex_secinfo[o], &msec[mcnt]);
		msec[mcnt].s_flags = M_RO; /* for a pseudo node */
		if (SEC_REF_EXPORTED(&olddata->ex_secinfo[o]))
			msec[mcnt].s_refcnt--;
		mcnt++;
	    }
	}

	ASSERT(mcnt == tcnt);
	/*
	 * Done. Update curdata.
	 * Free up the existing secinfo list in curdata and
	 * set the new value.
	 */
	curdata->ex_seccnt = tcnt;
	curdata->ex_secinfo = msec;
}

/*
 * For NFS V4.
 * Add or remove the newly exported or unexported security flavors of the
 * given exportinfo from its ancestors upto the system root.
 */
int
srv_secinfo_treeclimb(struct exportinfo *exip, bool_t isadd)
{
	vnode_t *dvp, *vp;
	fid_t fid;
	int error = 0;
	int exportdir;
	struct exportinfo *exi;
	struct exportdata *exdata;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	exdata = &exip->exi_export;
	if (exdata->ex_seccnt == 0)
		return (0);

	vp = exip->exi_vp;
	VN_HOLD(vp);
	exportdir = 1;

	for (;;) {

		bzero(&fid, sizeof (fid));
		fid.fid_len = MAXFIDSZ;
		error = vop_fid_pseudo(vp, &fid);
		if (error)
			break;

		if (! exportdir) {

			exi = checkexport4(&vp->v_vfsp->vfs_fsid, &fid, vp);

			if (exi != NULL) {

			    if (isadd) {
				/*
				 * Add the new security flavors to the
				 * export entry of the current directory.
				 */
				srv_secinfo_add(&exi->exi_export, exdata);
			    } else {
				/*
				 * Remove the unexported secinfo entries.
				 */
				srv_secinfo_remove(&exi->exi_export, exdata);
			    }
			}
		}

		/*
		 * If at the root of the filesystem, need
		 * to traverse across the mountpoint
		 * and continue the climb on the mounted-on
		 * filesystem.
		 */
		if (vp->v_flag & VROOT) {

			if (VN_CMP(vp, rootdir)) {
				/* at system root */
				break;
			}

			vp = untraverse(vp);
			exportdir = 0;
			continue;
		}

		/*
		 * Now, do a ".." to find parent dir of vp.
		 */
		error = VOP_LOOKUP(vp, "..", &dvp, NULL, 0, NULL, CRED());

		if (error == ENOTDIR && exportdir) {
			dvp = exip->exi_dvp;
			ASSERT(dvp != NULL);
			VN_HOLD(dvp);
			error = 0;
		}

		if (error)
			break;

		exportdir = 0;
		VN_RELE(vp);
		vp = dvp;
	}

	VN_RELE(vp);
	return (error);
}

void
export_link(struct exportinfo *exi) {
	int exporthash;

	exporthash = exptablehash(&exi->exi_fsid, &exi->exi_fid);
	exi->exi_hash = exptable[exporthash];
	exptable[exporthash] = exi;
}

/*
 * Initialization routine for export routines. Should only be called once.
 */
int
nfs_exportinit(void)
{
	int error;

	rw_init(&exported_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Allocate the place holder for the public file handle, which
	 * is all zeroes. It is initially set to the root filesystem.
	 */
	exi_root = kmem_zalloc(sizeof (*exi_root), KM_SLEEP);
	exi_public = exi_root;

	exi_root->exi_export.ex_flags = EX_PUBLIC;
	exi_root->exi_export.ex_pathlen = 2;	/* length of "/" */
	exi_root->exi_export.ex_path =
		kmem_alloc(exi_root->exi_export.ex_pathlen, KM_SLEEP);
	exi_root->exi_export.ex_path[0] = '/';
	exi_root->exi_export.ex_path[1] = '\0';

	exi_root->exi_count = 1;
	mutex_init(&exi_root->exi_lock, NULL, MUTEX_DEFAULT, NULL);

	exi_root->exi_vp = rootdir;
	exi_rootfid.fid_len = MAXFIDSZ;
	error = vop_fid_pseudo(exi_root->exi_vp, &exi_rootfid);
	if (error) {
		mutex_destroy(&exi_root->exi_lock);
		kmem_free(exi_root, sizeof (*exi_root));
		return (error);
	}

	/* setup the fhandle template */
	exi_root->exi_fh.fh_fsid = rootdir->v_vfsp->vfs_fsid;
	exi_root->exi_fh.fh_xlen = exi_rootfid.fid_len;
	bcopy(exi_rootfid.fid_data, exi_root->exi_fh.fh_xdata,
			exi_rootfid.fid_len);
	exi_root->exi_fh.fh_len = sizeof (exi_root->exi_fh.fh_data);

	/*
	 * Publish the exportinfo in the hash table
	 */
	export_link(exi_root);

	nfslog_init();

	return (0);
}

/*
 * Finalization routine for export routines. Called to cleanup previoulsy
 * initializtion work when the NFS server module could not be loaded correctly.
 */
void
nfs_exportfini(void)
{
	/*
	 * Deallocate the place holder for the public file handle.
	 */
	srv_secinfo_list_free(exi_root->exi_export.ex_secinfo,
				exi_root->exi_export.ex_seccnt);
	mutex_destroy(&exi_root->exi_lock);
	kmem_free(exi_root, sizeof (*exi_root));

	rw_destroy(&exported_lock);
}

/*
 *  Check if 2 gss mechanism identifiers are the same.
 *
 *  return FALSE if not the same.
 *  return TRUE if the same.
 */
static bool_t
nfs_mech_equal(rpc_gss_OID mech1, rpc_gss_OID mech2)
{
	if ((mech1->length == 0) && (mech2->length == 0))
		return (TRUE);

	if (mech1->length != mech2->length)
		return (FALSE);

	return (bcmp(mech1->elements, mech2->elements, mech1->length) == 0);
}

/*
 *  This routine is used by rpc to map rpc security number
 *  to nfs specific security flavor number.
 *
 *  The gss callback prototype is
 *  callback(struct svc_req *, gss_cred_id_t *, gss_ctx_id_t *,
 *				rpc_gss_lock_t *, void **),
 *  since nfs does not use the gss_cred_id_t/gss_ctx_id_t arguments
 *  we cast them to void.
 */
/*ARGSUSED*/
bool_t
rfs_gsscallback(struct svc_req *req, gss_cred_id_t deleg, void *gss_context,
    rpc_gss_lock_t *lock, void **cookie)
{
	int i, j;
	rpc_gss_rawcred_t *raw_cred;
	struct exportinfo *exi;

	/*
	 * We don't deal with delegated credentials.
	 */
	if (deleg != GSS_C_NO_CREDENTIAL)
		return (FALSE);

	raw_cred = lock->raw_cred;
	*cookie = NULL;

	rw_enter(&exported_lock, RW_READER);
	for (i = 0; i < EXPTABLESIZE; i++) {
	    exi = exptable[i];
	    while (exi) {
		if (exi->exi_export.ex_seccnt > 0) {
		    struct secinfo *secp;

		    secp = exi->exi_export.ex_secinfo;
		    for (j = 0; j < exi->exi_export.ex_seccnt; j++) {
			/*
			 *  If there is a map of the triplet
			 *  (mechanism, service, qop) between raw_cred and
			 *  the exported flavor, get the psudo flavor number.
			 *  Also qop should not be NULL, it should be "default"
			 *  or something else.
			 */
			if ((secp[j].s_secinfo.sc_rpcnum == RPCSEC_GSS) &&
			(nfs_mech_equal(secp[j].s_secinfo.sc_gss_mech_type,
			raw_cred->mechanism)) &&
			(secp[j].s_secinfo.sc_service == raw_cred->service) &&
			(raw_cred->qop == secp[j].s_secinfo.sc_qop)) {
				*cookie = (void *)(uintptr_t)
				    secp[j].s_secinfo.sc_nfsnum;
				goto done;
			}
		    }
		}
		exi = exi->exi_hash;
	    }
	}
done:
	rw_exit(&exported_lock);

	/*
	 * If no nfs pseudo number mapping can be found in the export
	 * table, assign the nfsflavor to NFS_FLAVOR_NOMAP. In V4, we may
	 * recover the flavor mismatch from NFS layer (NFS4ERR_WRONGSEC).
	 *
	 * For example:
	 *	server first shares with krb5i;
	 *	client mounts with krb5i;
	 *	server re-shares with krb5p;
	 *	client tries with krb5i, but no mapping can be found;
	 *	rpcsec_gss module calls this routine to do the mapping,
	 *		if this routine fails, request is rejected from
	 *		the rpc layer.
	 *	What we need is to let the nfs layer rejects the request.
	 *	For V4, we can reject with NFS4ERR_WRONGSEC and the client
	 *	may recover from it by getting the new flavor via SECINFO.
	 *
	 * nfs pseudo number for RPCSEC_GSS mapping (see nfssec.conf)
	 * is owned by IANA (see RFC 2623).
	 *
	 * XXX NFS_FLAVOR_NOMAP is defined in Solaris to work around
	 * the implementation issue. This number should not overlap with
	 * any new IANA defined pseudo flavor numbers.
	 */
	if (*cookie == NULL)
		*cookie = (void *)NFS_FLAVOR_NOMAP;

	lock->locked = TRUE;

	return (TRUE);
}


/*
 * Exportfs system call; credentials should be checked before
 * calling this function.
 */
int
exportfs(struct exportfs_args *args, model_t model, cred_t *cr)
{
	vnode_t *vp;
	vnode_t *dvp;
	struct exportdata *kex;
	struct exportinfo *exi;
	struct exportinfo *ex, *prev;
	fid_t fid;
	fsid_t fsid;
	int error;
	size_t allocsize;
	struct secinfo *sp;
	struct secinfo *exs;
	rpc_gss_callback_t cb;
	char *pathbuf;
	char *log_buffer;
	char *tagbuf;
	int callback;
	int allocd_seccnt;
	STRUCT_HANDLE(exportfs_args, uap);
	STRUCT_DECL(exportdata, uexi);
	int i;

	STRUCT_SET_HANDLE(uap, model, args);

	error = lookupname(STRUCT_FGETP(uap, dname), UIO_USERSPACE,
	    FOLLOW, &dvp, &vp);
	if (error == EINVAL) {
		/*
		 * if fname resolves to / we get EINVAL error
		 * since we wanted the parent vnode. Try again
		 * with NULL dvp.
		 */
		error = lookupname(STRUCT_FGETP(uap, dname), UIO_USERSPACE,
		    FOLLOW, NULL, &vp);
		dvp = NULL;
	}
	if (!error && vp == NULL) {
		/*
		 * Last component of fname not found
		 */
		if (dvp != NULL) {
			VN_RELE(dvp);
		}
		error = ENOENT;
	}
	if (error)
		return (error);

	/*
	 * 'vp' may be an AUTOFS node, so we perform a
	 * VOP_ACCESS() to trigger the mount of the
	 * intended filesystem, so we can share the intended
	 * filesystem instead of the AUTOFS filesystem.
	 */
	(void) VOP_ACCESS(vp, 0, 0, cr);

	/*
	 * We're interested in the top most filesystem.
	 * This is specially important when uap->dname is a trigger
	 * AUTOFS node, since we're really interested in sharing the
	 * filesystem AUTOFS mounted as result of the VOP_ACCESS()
	 * call not the AUTOFS node itself.
	 */
	if (vn_mountedvfs(vp) != NULL) {
		if (error = traverse(&vp)) {
			VN_RELE(vp);
			if (dvp != NULL)
				VN_RELE(dvp);
			return (error);
		}
	}

	/*
	 * Get the vfs id
	 */
	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	error = VOP_FID(vp, &fid);
	fsid = vp->v_vfsp->vfs_fsid;
	if (error) {
		VN_RELE(vp);
		if (dvp != NULL)
			VN_RELE(dvp);
		/*
		 * If VOP_FID returns ENOSPC then the fid supplied
		 * is too small.  For now we simply return EREMOTE.
		 */
		if (error == ENOSPC)
			error = EREMOTE;
		return (error);
	}

	if (STRUCT_FGETP(uap, uex) == NULL) {
		error = unexport(&fsid, &fid, vp);
		VN_RELE(vp);
		if (dvp != NULL)
			VN_RELE(dvp);
		return (error);
	}
	exi = kmem_zalloc(sizeof (*exi), KM_SLEEP);
	exi->exi_fsid = fsid;
	exi->exi_fid = fid;
	exi->exi_vp = vp;
	exi->exi_count = 1;
	exi->exi_volatile_dev = (vfssw[vp->v_vfsp->vfs_fstype].vsw_flag &
				VSW_VOLATILEDEV) ? 1 : 0;
	mutex_init(&exi->exi_lock, NULL, MUTEX_DEFAULT, NULL);
	exi->exi_dvp = dvp;

	/*
	 * Initialize auth cache lock
	 */
	rw_init(&exi->exi_cache_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Build up the template fhandle
	 */
	exi->exi_fh.fh_fsid = fsid;
	if (exi->exi_fid.fid_len > sizeof (exi->exi_fh.fh_xdata)) {
		error = EREMOTE;
		goto out1;
	}
	exi->exi_fh.fh_xlen = exi->exi_fid.fid_len;
	bcopy(exi->exi_fid.fid_data, exi->exi_fh.fh_xdata,
	    exi->exi_fid.fid_len);

	exi->exi_fh.fh_len = sizeof (exi->exi_fh.fh_data);

	kex = &exi->exi_export;

	/*
	 * Load in everything, and do sanity checking
	 */
	STRUCT_INIT(uexi, model);
	if (copyin(STRUCT_FGETP(uap, uex), STRUCT_BUF(uexi),
	    STRUCT_SIZE(uexi))) {
		error = EFAULT;
		goto out1;
	}

	kex->ex_version = STRUCT_FGET(uexi, ex_version);
	if (kex->ex_version != EX_CURRENT_VERSION) {
		error = EINVAL;
		cmn_err(CE_WARN,
		"NFS: exportfs requires export struct version 2 - got %d\n",
		kex->ex_version);
		goto out1;
	}

	/*
	 * Must have at least one security entry
	 */
	kex->ex_seccnt = STRUCT_FGET(uexi, ex_seccnt);
	if (kex->ex_seccnt < 1) {
		error = EINVAL;
		goto out1;
	}

	kex->ex_path = STRUCT_FGETP(uexi, ex_path);
	kex->ex_pathlen = STRUCT_FGET(uexi, ex_pathlen);
	kex->ex_flags = STRUCT_FGET(uexi, ex_flags);
	kex->ex_anon = STRUCT_FGET(uexi, ex_anon);
	kex->ex_secinfo = STRUCT_FGETP(uexi, ex_secinfo);
	kex->ex_index = STRUCT_FGETP(uexi, ex_index);
	kex->ex_log_buffer = STRUCT_FGETP(uexi, ex_log_buffer);
	kex->ex_log_bufferlen = STRUCT_FGET(uexi, ex_log_bufferlen);
	kex->ex_tag = STRUCT_FGETP(uexi, ex_tag);
	kex->ex_taglen = STRUCT_FGET(uexi, ex_taglen);

	/*
	 * Copy the exported pathname into
	 * an appropriately sized buffer.
	 */
	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (copyinstr(kex->ex_path, pathbuf, MAXPATHLEN, &kex->ex_pathlen)) {
		kmem_free(pathbuf, MAXPATHLEN);
		error = EFAULT;
		goto out1;
	}
	kex->ex_path = kmem_alloc(kex->ex_pathlen + 1, KM_SLEEP);
	bcopy(pathbuf, kex->ex_path, kex->ex_pathlen);
	kex->ex_path[kex->ex_pathlen] = '\0';
	kmem_free(pathbuf, MAXPATHLEN);

	/*
	 * Get the path to the logging buffer and the tag
	 */
	if (kex->ex_flags & EX_LOG) {
		log_buffer = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (copyinstr(kex->ex_log_buffer, log_buffer, MAXPATHLEN,
		    &kex->ex_log_bufferlen)) {
			kmem_free(log_buffer, MAXPATHLEN);
			error = EFAULT;
			goto out2;
		}
		kex->ex_log_buffer =
			kmem_alloc(kex->ex_log_bufferlen + 1, KM_SLEEP);
		bcopy(log_buffer, kex->ex_log_buffer, kex->ex_log_bufferlen);
		kex->ex_log_buffer[kex->ex_log_bufferlen] = '\0';
		kmem_free(log_buffer, MAXPATHLEN);

		tagbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		if (copyinstr(kex->ex_tag, tagbuf, MAXPATHLEN,
		    &kex->ex_taglen)) {
			kmem_free(tagbuf, MAXPATHLEN);
			error = EFAULT;
			goto out3;
		}
		kex->ex_tag = kmem_alloc(kex->ex_taglen + 1, KM_SLEEP);
		bcopy(tagbuf, kex->ex_tag, kex->ex_taglen);
		kex->ex_tag[kex->ex_taglen] = '\0';
		kmem_free(tagbuf, MAXPATHLEN);
	}

	/*
	 * Load the security information for each flavor
	 */
	allocsize = kex->ex_seccnt * SIZEOF_STRUCT(secinfo, model);
	sp = kmem_zalloc(allocsize, KM_SLEEP);
	if (copyin(kex->ex_secinfo, sp, allocsize)) {
		kmem_free(sp, allocsize);
		error = EFAULT;
		goto out4;
	}

	/*
	 * All of these nested structures need to be converted to
	 * the kernel native format.
	 */
	if (model != DATAMODEL_NATIVE) {
		size_t allocsize2;
		struct secinfo *sp2;

		allocsize2 = kex->ex_seccnt * sizeof (struct secinfo);
		sp2 = kmem_zalloc(allocsize2, KM_SLEEP);

		for (i = 0; i < kex->ex_seccnt; i++) {
			STRUCT_HANDLE(secinfo, usi);

			STRUCT_SET_HANDLE(usi, model,
			    (struct secinfo *)((caddr_t)sp +
			    (i * SIZEOF_STRUCT(secinfo, model))));
			bcopy(STRUCT_FGET(usi, s_secinfo.sc_name),
			    sp2[i].s_secinfo.sc_name, MAX_NAME_LEN);
			sp2[i].s_secinfo.sc_nfsnum =
			    STRUCT_FGET(usi, s_secinfo.sc_nfsnum);
			sp2[i].s_secinfo.sc_rpcnum =
			    STRUCT_FGET(usi, s_secinfo.sc_rpcnum);
			bcopy(STRUCT_FGET(usi, s_secinfo.sc_gss_mech),
			    sp2[i].s_secinfo.sc_gss_mech, MAX_NAME_LEN);
			sp2[i].s_secinfo.sc_gss_mech_type =
			    STRUCT_FGETP(usi, s_secinfo.sc_gss_mech_type);
			sp2[i].s_secinfo.sc_qop =
			    STRUCT_FGET(usi, s_secinfo.sc_qop);
			sp2[i].s_secinfo.sc_service =
			    STRUCT_FGET(usi, s_secinfo.sc_service);

			sp2[i].s_flags = STRUCT_FGET(usi, s_flags);
			sp2[i].s_window = STRUCT_FGET(usi, s_window);
			sp2[i].s_rootcnt = STRUCT_FGET(usi, s_rootcnt);
			sp2[i].s_rootnames = STRUCT_FGETP(usi, s_rootnames);
		}
		kmem_free(sp, allocsize);
		sp = sp2;
		allocsize = allocsize2;
	}

	kex->ex_secinfo = sp;

	/*
	 * And now copy rootnames for each individual secinfo.
	 */
	callback = 0;
	allocd_seccnt = 0;
	while (allocd_seccnt < kex->ex_seccnt) {

		exs = &sp[allocd_seccnt];
		if (exs->s_rootcnt > 0) {
			if (!sec_svc_loadrootnames(exs->s_secinfo.sc_rpcnum,
			    exs->s_rootcnt, &exs->s_rootnames, model)) {
				error = EFAULT;
				goto out5;
			}
		}

		if (exs->s_secinfo.sc_rpcnum == RPCSEC_GSS) {
			rpc_gss_OID mech_tmp;
			STRUCT_DECL(rpc_gss_OID_s, umech_tmp);
			caddr_t elements_tmp;

			/* Copyin mechanism type */
			STRUCT_INIT(umech_tmp, model);
			mech_tmp = kmem_alloc(sizeof (*mech_tmp), KM_SLEEP);
			if (copyin(exs->s_secinfo.sc_gss_mech_type,
			    STRUCT_BUF(umech_tmp), STRUCT_SIZE(umech_tmp))) {
				kmem_free(mech_tmp, sizeof (*mech_tmp));
				error = EFAULT;
				goto out5;
			}
			mech_tmp->length = STRUCT_FGET(umech_tmp, length);
			mech_tmp->elements = STRUCT_FGETP(umech_tmp, elements);

			elements_tmp = kmem_alloc(mech_tmp->length, KM_SLEEP);
			if (copyin(mech_tmp->elements, elements_tmp,
			    mech_tmp->length)) {
				kmem_free(elements_tmp, mech_tmp->length);
				kmem_free(mech_tmp, sizeof (*mech_tmp));
				error = EFAULT;
				goto out5;
			}
			mech_tmp->elements = elements_tmp;
			exs->s_secinfo.sc_gss_mech_type = mech_tmp;
			allocd_seccnt++;

			callback = 1;
		} else
			allocd_seccnt++;
	}

	/*
	 * Init the secinfo reference count and mark these flavors
	 * explicitly exported flavors.
	 */
	for (i = 0; i < kex->ex_seccnt; i++) {
		kex->ex_secinfo[i].s_flags |= M_4SEC_EXPORTED;
		kex->ex_secinfo[i].s_refcnt++;  /* 1 reference count */
	}

	/*
	 *  Set up rpcsec_gss callback routine entry if any.
	 */
	if (callback) {
		cb.callback = rfs_gsscallback;
		cb.program = NFS_ACL_PROGRAM;
		for (cb.version = NFS_ACL_VERSMIN;
		    cb.version <= NFS_ACL_VERSMAX; cb.version++) {
			(void) sec_svc_control(RPC_SVC_SET_GSS_CALLBACK,
			    (void *)&cb);
		}

		cb.program = NFS_PROGRAM;
		for (cb.version = NFS_VERSMIN;
		    cb.version <= NFS_VERSMAX; cb.version++) {
			(void) sec_svc_control(RPC_SVC_SET_GSS_CALLBACK,
			    (void *)&cb);
		}
	}

	/*
	 * Check the index flag. Do this here to avoid holding the
	 * lock while dealing with the index option (as we do with
	 * the public option).
	 */
	if (kex->ex_flags & EX_INDEX) {
		if (!kex->ex_index) {	/* sanity check */
			error = EINVAL;
			goto out5;
		}
		if (error = loadindex(kex))
			goto out5;
	}

	if (kex->ex_flags & EX_LOG) {
		if (error = nfslog_setup(exi))
			goto out6;
	}

	/*
	 * Insert the new entry at the front of the export list
	 */
	rw_enter(&exported_lock, RW_WRITER);

	export_link(exi);

	/*
	 * Check the rest of the list for an old entry for the fs.
	 * If one is found then unlink it, wait until this is the
	 * only reference and then free it.
	 */
	prev = exi;
	for (ex = prev->exi_hash; ex != NULL; prev = ex, ex = ex->exi_hash) {
		if (ex != exi_root && VN_CMP(ex->exi_vp, vp)) {
			prev->exi_hash = ex->exi_hash;
			break;
		}
	}

	/*
	 * If the public filehandle is pointing at the
	 * old entry, then point it back at the root.
	 */
	if (ex != NULL && ex == exi_public)
		exi_public = exi_root;

	/*
	 * If the public flag is on, make the global exi_public
	 * point to this entry and turn off the public bit so that
	 * we can distinguish it from the place holder export.
	 */
	if (kex->ex_flags & EX_PUBLIC) {
		exi_public = exi;
		kex->ex_flags &= ~EX_PUBLIC;
	}

#ifdef VOLATILE_FH_TEST
	/*
	 * Set up the volatile_id value if volatile on share.
	 * The list of volatile renamed filehandles is always destroyed,
	 * if the fs was reshared.
	 */
	if (kex->ex_flags & EX_VOLFH)
		exi->exi_volatile_id = gethrestime_sec();

	mutex_init(&exi->exi_vol_rename_lock, NULL, MUTEX_DEFAULT, NULL);
#endif /* VOLATILE_FH_TEST */

	/*
	 * If this is a new export, then climb up
	 * the tree and check if any pseudo exports
	 * need to be created to provide a path for
	 * NFS v4 clients.
	 */
	if (ex == NULL)
		error = treeclimb_export(exi);

	if (!error)
		error = srv_secinfo_treeclimb(exi, TRUE);

	/*
	 * If re-sharing an old export entry, update the secinfo data
	 * depending on if the old entry is a pseudo node or not.
	 */
	if (!error && ex != NULL) {
		if (PSEUDO(ex)) {
		    srv_secinfo_add(&exi->exi_export, &ex->exi_export);
		} else {
		    srv_secinfo_exp2exp(&exi->exi_export, &ex->exi_export);
		    error = srv_secinfo_treeclimb(ex, FALSE);
		}
	}

	if (error)
		goto out7;

	/*
	 * If it's a re-export and the old entry has a visible list,
	 * then transfer its visible list to the new export.
	 * Note: only VROOT node may have a visible list either
	 * it is a PSEUDO node or a real export node.
	 */
	if (ex != NULL && (ex->exi_visible != NULL)) {
		exi->exi_visible = ex->exi_visible;
		ex->exi_visible = NULL;
	}

	rw_exit(&exported_lock);

	if (exi_public == exi || kex->ex_flags & EX_LOG) {
		/*
		 * Log share operation to this buffer only.
		 */
		nfslog_share_record(exi, cr);
	}

	if (ex != NULL)
		exi_rele(ex);

	return (0);

out7:
	/*
	 * Cleaning up the tree. Assuming *treeclimb* routines
	 * will fail at the same place in the tree.
	 */
	(void) treeclimb_unexport(exi);
	(void) srv_secinfo_treeclimb(exi, FALSE);

	/*
	 * Unlink and re-link the new and old export in exptable.
	 */
	(void) export_unlink(&exi->exi_fsid, &exi->exi_fid, exi->exi_vp, NULL);
	if (ex != NULL)
		export_link(ex);

	rw_exit(&exported_lock);
out6:
	if (kex->ex_flags & EX_INDEX)
		kmem_free(kex->ex_index, strlen(kex->ex_index) + 1);
out5:
	/* free partially completed allocation */
	while (--allocd_seccnt >= 0) {
		exs = &kex->ex_secinfo[allocd_seccnt];
		srv_secinfo_entry_free(exs);
	}

	if (kex->ex_secinfo) {
		kmem_free(kex->ex_secinfo,
			kex->ex_seccnt * sizeof (struct secinfo));
	}

out4:
	if ((kex->ex_flags & EX_LOG) && kex->ex_tag != NULL)
		kmem_free(kex->ex_tag, kex->ex_taglen + 1);
out3:
	if ((kex->ex_flags & EX_LOG) && kex->ex_log_buffer != NULL)
		kmem_free(kex->ex_log_buffer, kex->ex_log_bufferlen + 1);
out2:
	kmem_free(kex->ex_path, kex->ex_pathlen + 1);
out1:
	VN_RELE(vp);
	if (dvp != NULL)
		VN_RELE(dvp);
	mutex_destroy(&exi->exi_lock);
	rw_destroy(&exi->exi_cache_lock);
	kmem_free(exi, sizeof (*exi));
	return (error);
}

/*
 * Remove the exportinfo from the export list
 */
int
export_unlink(fsid_t *fsid, fid_t *fid, vnode_t *vp, struct exportinfo **exip)
{
	struct exportinfo **tail;

	ASSERT(RW_WRITE_HELD(&exported_lock));

	tail = &exptable[exptablehash(fsid, fid)];
	while (*tail != NULL) {
		if (exportmatch(*tail, fsid, fid)) {
			/*
			 * If vp is given, check if vp is the
			 * same vnode as the exported node.
			 *
			 * Since VOP_FID of a lofs node returns the
			 * fid of its real node (ufs), the exported
			 * node for lofs and (pseudo) ufs may have
			 * the same fsid and fid.
			 */
			if (vp == NULL || vp == (*tail)->exi_vp) {

				if (exip != NULL)
					*exip = *tail;
				*tail = (*tail)->exi_hash;

				return (0);
			}
		}
		tail = &(*tail)->exi_hash;
	}

	return (EINVAL);
}

/*
 * Unexport an exported filesystem
 */
int
unexport(fsid_t *fsid, fid_t *fid, vnode_t *vp)
{
	struct exportinfo *exi = NULL;
	int error;

	rw_enter(&exported_lock, RW_WRITER);

	error = export_unlink(fsid, fid, vp, &exi);

	if (error) {
		rw_exit(&exported_lock);
		return (error);
	}

	/* pseudo node is not a real exported filesystem */
	if (PSEUDO(exi)) {
		/*
		 * Put the pseudo node back into the export table
		 * before erroring out.
		 */
		export_link(exi);
		rw_exit(&exported_lock);
		return (EINVAL);
	}

	/*
	 * If there's a visible list, then need to leave
	 * a pseudo export here to retain the visible list
	 * for paths to exports below.
	 */
	if (exi->exi_visible) {
		error = pseudo_exportfs(exi->exi_vp, exi->exi_visible,
						&exi->exi_export);
		if (error)
			goto done;

		exi->exi_visible = NULL;
	} else {
		error = treeclimb_unexport(exi);
		if (error)
			goto done;
	}

	error = srv_secinfo_treeclimb(exi, FALSE);
	if (error)
		goto done;

	rw_exit(&exported_lock);

	/*
	 * Need to call into the NFSv4 server and release all data
	 * held on this particular export.  This is important since
	 * the v4 server may be holding file locks or vnodes under
	 * this export.
	 */
	rfs4_clean_state_exi(exi);

	/*
	 * Notify the lock manager that the filesystem is being
	 * unexported.
	 */
	lm_unexport(exi);

	/*
	 * If this was a public export, restore
	 * the public filehandle to the root.
	 */
	if (exi == exi_public) {
		exi_public = exi_root;

		nfslog_share_record(exi_public, CRED());
	}

	if (exi->exi_export.ex_flags & EX_LOG) {
		nfslog_unshare_record(exi, CRED());
	}

	exi_rele(exi);
	return (error);

done:
	rw_exit(&exported_lock);
	exi_rele(exi);
	return (error);
}

/*
 * Get file handle system call.
 * Takes file name and returns a file handle for it.
 * Credentials must be verified before calling.
 */
int
nfs_getfh(struct nfs_getfh_args *args, model_t model, cred_t *cr)
{
	fhandle_t fh;
	vnode_t *vp;
	vnode_t *dvp;
	struct exportinfo *exi;
	int error;
	STRUCT_HANDLE(nfs_getfh_args, uap);

#ifdef lint
	model = model;		/* STRUCT macros don't always use it */
#endif

	STRUCT_SET_HANDLE(uap, model, args);

	error = lookupname(STRUCT_FGETP(uap, fname), UIO_USERSPACE,
	    FOLLOW, &dvp, &vp);
	if (error == EINVAL) {
		/*
		 * if fname resolves to / we get EINVAL error
		 * since we wanted the parent vnode. Try again
		 * with NULL dvp.
		 */
		error = lookupname(STRUCT_FGETP(uap, fname), UIO_USERSPACE,
		    FOLLOW, NULL, &vp);
		dvp = NULL;
	}
	if (!error && vp == NULL) {
		/*
		 * Last component of fname not found
		 */
		if (dvp != NULL) {
			VN_RELE(dvp);
		}
		error = ENOENT;
	}
	if (error)
		return (error);

	/*
	 * 'vp' may be an AUTOFS node, so we perform a
	 * VOP_ACCESS() to trigger the mount of the
	 * intended filesystem, so we can share the intended
	 * filesystem instead of the AUTOFS filesystem.
	 */
	(void) VOP_ACCESS(vp, 0, 0, cr);

	/*
	 * We're interested in the top most filesystem.
	 * This is specially important when uap->dname is a trigger
	 * AUTOFS node, since we're really interested in sharing the
	 * filesystem AUTOFS mounted as result of the VOP_ACCESS()
	 * call not the AUTOFS node itself.
	 */
	if (vn_mountedvfs(vp) != NULL) {
		if (error = traverse(&vp)) {
			VN_RELE(vp);
			if (dvp != NULL)
				VN_RELE(dvp);
			return (error);
		}
	}

	exi = nfs_vptoexi(dvp, vp, cr, NULL, &error, FALSE);
	if (!error) {
		error = makefh(&fh, vp, exi);
		if (!error && exi->exi_export.ex_flags & EX_LOG) {
			nfslog_getfh(exi, &fh, STRUCT_FGETP(uap, fname),
				UIO_USERSPACE, cr);
		}
		exi_rele(exi);
		if (!error) {
			if (copyout(&fh, STRUCT_FGETP(uap, fhp), sizeof (fh)))
				error = EFAULT;
		}
	}
	VN_RELE(vp);
	if (dvp != NULL) {
		VN_RELE(dvp);
	}
	return (error);
}

/*
 * Strategy: if vp is in the export list, then
 * return the associated file handle. Otherwise, ".."
 * once up the vp and try again, until the root of the
 * filesystem is reached.
 */
struct   exportinfo *
nfs_vptoexi(vnode_t *dvp, vnode_t *vp, cred_t *cr, int *walk,
	int *err,  bool_t v4srv)
{
	fid_t fid;
	int error;
	struct exportinfo *exi;

	ASSERT(vp);
	VN_HOLD(vp);
	if (dvp != NULL) {
		VN_HOLD(dvp);
	}
	if (walk != NULL)
		*walk = 0;

	for (;;) {
		bzero(&fid, sizeof (fid));
		fid.fid_len = MAXFIDSZ;
		error = vop_fid_pseudo(vp, &fid);
		if (error) {
			/*
			 * If vop_fid_pseudo returns ENOSPC then the fid
			 * supplied is too small. For now we simply
			 * return EREMOTE.
			 */
			if (error == ENOSPC)
				error = EREMOTE;
			break;
		}

		if (v4srv)
			exi = checkexport4(&vp->v_vfsp->vfs_fsid, &fid, vp);
		else
			exi = checkexport(&vp->v_vfsp->vfs_fsid, &fid);

		if (exi != NULL) {
			/*
			 * Found the export info
			 */
			break;
		}

		/*
		 * We have just failed finding a matching export.
		 * If we're at the root of this filesystem, then
		 * it's time to stop (with failure).
		 */
		if (vp->v_flag & VROOT) {
			error = EINVAL;
			break;
		}

		if (walk != NULL)
			(*walk)++;

		/*
		 * Now, do a ".." up vp. If dvp is supplied, use it,
		 * otherwise, look it up.
		 */
		if (dvp == NULL) {
			error = VOP_LOOKUP(vp, "..", &dvp, NULL, 0, NULL, cr);
			if (error)
				break;
		}
		VN_RELE(vp);
		vp = dvp;
		dvp = NULL;
	}
	VN_RELE(vp);
	if (dvp != NULL) {
		VN_RELE(dvp);
	}
	if (error != 0) {
		if (err != NULL)
			*err = error;
		return (NULL);
	}
	return (exi);
}

bool_t
chk_clnt_sec(struct exportinfo *exi, struct svc_req *req)
{
	int i, nfsflavor;
	struct secinfo *sp;
	bool_t sec_found = FALSE;

	/*
	 *  Get the nfs flavor number from xprt.
	 */
	nfsflavor = (int)(uintptr_t)req->rq_xprt->xp_cookie;

	sp = exi->exi_export.ex_secinfo;
	for (i = 0; i < exi->exi_export.ex_seccnt; i++) {
		if (nfsflavor == sp[i].s_secinfo.sc_nfsnum) {
			sec_found = TRUE;
			break;
		}
	}
	return (sec_found);
}

/*
 * Make an fhandle from a vnode
 */
int
makefh(fhandle_t *fh, vnode_t *vp, struct exportinfo *exi)
{
	int error;

	*fh = exi->exi_fh;	/* struct copy */

	error = VOP_FID(vp, (fid_t *)&fh->fh_len);
	if (error) {
		/*
		 * Should be something other than EREMOTE
		 */
		return (EREMOTE);
	}
	return (0);
}

/*
 * This routine makes an overloaded V2 fhandle which contains
 * sec modes.
 *
 * Note that the first four octets contain the length octet,
 * the status octet, and two padded octets to make them XDR
 * four-octet aligned.
 *
 *   1   2   3   4                                          32
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+   +---+
 * | l | s |   |   |     sec_1     |...|     sec_n     |...|   |
 * +---+---+---+---+---+---+---+---+   +---+---+---+---+   +---+
 *
 * where
 *
 *   the status octet s indicates whether there are more security
 *   flavors (1 means yes, 0 means no) that require the client to
 *   perform another 0x81 LOOKUP to get them,
 *
 *   the length octet l is the length describing the number of
 *   valid octets that follow.  (l = 4 * n, where n is the number
 *   of security flavors sent in the current overloaded filehandle.)
 */
int
makefh_ol(fhandle_t *fh, struct exportinfo *exi, uint_t sec_index)
{
	static int max_cnt = (NFS_FHSIZE/sizeof (int)) - 1;
	int totalcnt, i, *ipt, cnt;
	char *c;

	if (fh == (fhandle_t *)NULL ||
		exi == (struct exportinfo *)NULL ||
		sec_index > exi->exi_export.ex_seccnt ||
		sec_index < 1)
		return (EREMOTE);

	totalcnt = exi->exi_export.ex_seccnt-sec_index+1;
	cnt = totalcnt > max_cnt? max_cnt : totalcnt;

	c = (char *)fh;
	/*
	 * Encode the length octet representing the number of
	 * security flavors (in bytes) in this overloaded fh.
	 */
	*c = cnt * sizeof (int);

	/*
	 * Encode the status octet that indicates whether there
	 * are more security flavors the client needs to get.
	 */
	*(c+1) = totalcnt > max_cnt;

	/*
	 * put security flavors in the overloaded fh
	 */
	ipt = (int *)(c + sizeof (int32_t));
	for (i = 0; i < cnt; i++) {
		*ipt++ = htonl(exi->exi_export.ex_secinfo[i+sec_index-1].
				s_secinfo.sc_nfsnum);
	}
	return (0);
}

/*
 * Make an nfs_fh3 from a vnode
 */
int
makefh3(nfs_fh3 *fh, vnode_t *vp, struct exportinfo *exi)
{
	int error;

	fh->fh3_length = sizeof (fh->fh3_u.nfs_fh3_i);
	fh->fh3_u.nfs_fh3_i.fh3_i = exi->exi_fh;	/* struct copy */

	error = VOP_FID(vp, (fid_t *)&fh->fh3_len);

	if (error) {
		/*
		 * Should be something other than EREMOTE
		 */
		return (EREMOTE);
	}
	return (0);
}

/*
 * This routine makes an overloaded V3 fhandle which contains
 * sec modes.
 *
 *  1        4
 * +--+--+--+--+
 * |    len    |
 * +--+--+--+--+
 *                                               up to 64
 * +--+--+--+--+--+--+--+--+--+--+--+--+     +--+--+--+--+
 * |s |  |  |  |   sec_1   |   sec_2   | ... |   sec_n   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+     +--+--+--+--+
 *
 * len = 4 * (n+1), where n is the number of security flavors
 * sent in the current overloaded filehandle.
 *
 * the status octet s indicates whether there are more security
 * mechanisms (1 means yes, 0 means no) that require the client
 * to perform another 0x81 LOOKUP to get them.
 *
 * Three octets are padded after the status octet.
 */
int
makefh3_ol(nfs_fh3 *fh, struct exportinfo *exi, uint_t sec_index)
{
	static int max_cnt = NFS3_FHSIZE/sizeof (int) - 1;
	int totalcnt, cnt, *ipt, i;
	char *c;

	if (fh == (nfs_fh3 *)NULL ||
		exi == (struct exportinfo *)NULL ||
		sec_index > exi->exi_export.ex_seccnt ||
		sec_index < 1) {
		return (EREMOTE);
	}

	totalcnt = exi->exi_export.ex_seccnt-sec_index+1;
	cnt = totalcnt > max_cnt? max_cnt : totalcnt;

	/*
	 * Place the length in fh3_length representing the number
	 * of security flavors (in bytes) in this overloaded fh.
	 */
	fh->fh3_length = (cnt+1) * sizeof (int32_t);

	c = (char *)&fh->fh3_u.nfs_fh3_i.fh3_i;
	/*
	 * Encode the status octet that indicates whether there
	 * are more security flavors the client needs to get.
	 */
	*c = totalcnt > max_cnt;

	/*
	 * put security flavors in the overloaded fh
	 */
	ipt = (int *)(c + sizeof (int32_t));
	for (i = 0; i < cnt; i++) {
		*(ipt+i) = htonl(
		exi->exi_export.ex_secinfo[i+sec_index-1].s_secinfo.sc_nfsnum);
	}
	return (0);
}

/*
 * Make an nfs_fh4 from a vnode
 */
int
makefh4(nfs_fh4 *fh, vnode_t *vp, struct exportinfo *exi)
{
	int error;
	nfs_fh4_fmt_t *fh_fmtp = (nfs_fh4_fmt_t *)fh->nfs_fh4_val;
	fid_t fid;

	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	/*
	 * vop_fid_pseudo() is used to set up NFSv4 namespace, so
	 * use vop_fid_pseudo() here to get the fid instead of VOP_FID.
	 */
	error = vop_fid_pseudo(vp, &fid);
	if (error)
		return (error);

	fh->nfs_fh4_len = NFS_FH4_LEN;

	fh_fmtp->fh4_i = exi->exi_fh;	/* copy the fhandle template */
	fh_fmtp->fh4_len = fid.fid_len;
	ASSERT(fid.fid_len <= sizeof (fh_fmtp->fh4_data));
	bcopy(fid.fid_data, fh_fmtp->fh4_data, fid.fid_len);
	fh_fmtp->fh4_flag = 0;

#ifdef VOLATILE_FH_TEST
	/*
	 * XXX (temporary?)
	 * Use the rnode volatile_id value to add volatility to the fh.
	 *
	 * For testing purposes there are currently two scenarios, based
	 * on whether the filesystem was shared with "volatile_fh"
	 * or "expire_on_rename". In the first case, use the value of
	 * export struct share_time as the volatile_id. In the second
	 * case use the vnode volatile_id value (which is set to the
	 * time in which the file was renamed).
	 *
	 * Note that the above are temporary constructs for testing only
	 * XXX
	 */
	if (exi->exi_export.ex_flags & EX_VOLRNM) {
		fh_fmtp->fh4_volatile_id = find_volrnm_fh_id(exi, fh);
	} else if (exi->exi_export.ex_flags & EX_VOLFH) {
		fh_fmtp->fh4_volatile_id = exi->exi_volatile_id;
	} else {
		fh_fmtp->fh4_volatile_id = 0;
	}
#endif /* VOLATILE_FH_TEST */

	return (0);
}

/*
 * Convert an fhandle into a vnode.
 * Uses the file id (fh_len + fh_data) in the fhandle to get the vnode.
 * WARNING: users of this routine must do a VN_RELE on the vnode when they
 * are done with it.
 */
vnode_t *
nfs_fhtovp(fhandle_t *fh, struct exportinfo *exi)
{
	vfs_t *vfsp;
	vnode_t *vp;
	int error;
	fid_t *fidp;

	TRACE_0(TR_FAC_NFS, TR_FHTOVP_START,
		"fhtovp_start");

	if (exi == NULL) {
		TRACE_1(TR_FAC_NFS, TR_FHTOVP_END,
			"fhtovp_end:(%S)", "exi NULL");
		return (NULL);	/* not exported */
	}

	ASSERT(exi->exi_vp != NULL);

	if (PUBLIC_FH2(fh)) {
		if (exi->exi_export.ex_flags & EX_PUBLIC) {
			TRACE_1(TR_FAC_NFS, TR_FHTOVP_END,
				"fhtovp_end:(%S)", "root not exported");
			return (NULL);
		}
		vp = exi->exi_vp;
		VN_HOLD(vp);
		return (vp);
	}

	vfsp = exi->exi_vp->v_vfsp;
	ASSERT(vfsp != NULL);
	fidp = (fid_t *)&fh->fh_len;

	error = VFS_VGET(vfsp, &vp, fidp);
	if (error || vp == NULL) {
		TRACE_1(TR_FAC_NFS, TR_FHTOVP_END,
			"fhtovp_end:(%S)", "VFS_GET failed or vp NULL");
		return (NULL);
	}
	TRACE_1(TR_FAC_NFS, TR_FHTOVP_END,
		"fhtovp_end:(%S)", "end");
	return (vp);
}

/*
 * Convert an fhandle into a vnode.
 * Uses the file id (fh_len + fh_data) in the fhandle to get the vnode.
 * WARNING: users of this routine must do a VN_RELE on the vnode when they
 * are done with it.
 * This is just like nfs_fhtovp() but without the exportinfo argument.
 */

vnode_t *
lm_fhtovp(fhandle_t *fh)
{
	register vfs_t *vfsp;
	vnode_t *vp;
	int error;

	vfsp = getvfs(&fh->fh_fsid);
	if (vfsp == NULL)
		return (NULL);

	error = VFS_VGET(vfsp, &vp, (fid_t *)&(fh->fh_len));
	VFS_RELE(vfsp);
	if (error || vp == NULL)
		return (NULL);

	return (vp);
}

/*
 * Convert an nfs_fh3 into a vnode.
 * Uses the file id (fh_len + fh_data) in the file handle to get the vnode.
 * WARNING: users of this routine must do a VN_RELE on the vnode when they
 * are done with it.
 */
vnode_t *
nfs3_fhtovp(nfs_fh3 *fh, struct exportinfo *exi)
{
	vfs_t *vfsp;
	vnode_t *vp;
	int error;
	fid_t *fidp;

	if (exi == NULL)
		return (NULL);	/* not exported */

	ASSERT(exi->exi_vp != NULL);

	if (PUBLIC_FH3(fh)) {
		if (exi->exi_export.ex_flags & EX_PUBLIC)
			return (NULL);
		vp = exi->exi_vp;
		VN_HOLD(vp);
		return (vp);
	}

	if (fh->fh3_length != NFS3_CURFHSIZE)
		return (NULL);

	vfsp = exi->exi_vp->v_vfsp;
	ASSERT(vfsp != NULL);
	fidp = (fid_t *)&fh->fh3_len;

	error = VFS_VGET(vfsp, &vp, fidp);
	if (error || vp == NULL)
		return (NULL);

	return (vp);
}

/*
 * Convert an nfs_fh3 into a vnode.
 * Uses the file id (fh_len + fh_data) in the file handle to get the vnode.
 * WARNING: users of this routine must do a VN_RELE on the vnode when they
 * are done with it.
 * BTW: This is just like nfs3_fhtovp() but without the exportinfo arg.
 * Also, vfsp is accessed through getvfs() rather using exportinfo !!
 */

vnode_t *
lm_nfs3_fhtovp(nfs_fh3 *fh)
{
	vfs_t *vfsp;
	vnode_t *vp;
	int error;

	if (fh->fh3_length != NFS3_CURFHSIZE)
		return (NULL);

	vfsp = getvfs(&fh->fh3_fsid);
	if (vfsp == NULL)
		return (NULL);

	error = VFS_VGET(vfsp, &vp, (fid_t *)&(fh->fh3_len));
	VFS_RELE(vfsp);
	if (error || vp == NULL)
		return (NULL);

	return (vp);
}

/*
 * Convert an nfs_fh4 into a vnode.
 * Uses the file id (fh_len + fh_data) in the file handle to get the vnode.
 * WARNING: users of this routine must do a VN_RELE on the vnode when they
 * are done with it.
 */
vnode_t *
nfs4_fhtovp(nfs_fh4 *fh, struct exportinfo *exi, nfsstat4 *statp)
{
	vfs_t *vfsp;
	vnode_t *vp = NULL;
	int error;
	fid_t *fidp;
	nfs_fh4_fmt_t *fh_fmtp;
#ifdef VOLATILE_FH_TEST
	uint32_t volatile_id = 0;
#endif /* VOLATILE_FH_TEST */

	if (exi == NULL) {
		*statp = NFS4ERR_STALE;
		return (NULL);	/* not exported */
	}
	ASSERT(exi->exi_vp != NULL);

	/* caller should have checked this */
	ASSERT(fh->nfs_fh4_len >= NFS_FH4_LEN);

	fh_fmtp = (nfs_fh4_fmt_t *)fh->nfs_fh4_val;
	vfsp = exi->exi_vp->v_vfsp;
	ASSERT(vfsp != NULL);
	fidp = (fid_t *)&fh_fmtp->fh4_len;

#ifdef VOLATILE_FH_TEST
	/* XXX check if volatile - should be changed later */
	if (exi->exi_export.ex_flags & (EX_VOLRNM | EX_VOLFH)) {
		/*
		 * Filesystem is shared with volatile filehandles
		 */
		if (exi->exi_export.ex_flags & EX_VOLRNM)
			volatile_id = find_volrnm_fh_id(exi, fh);
		else
			volatile_id = exi->exi_volatile_id;

		if (fh_fmtp->fh4_volatile_id != volatile_id) {
			*statp = NFS4ERR_FHEXPIRED;
			return (NULL);
		}
	}
	/*
	 * XXX even if test_volatile_fh false, the fh may contain a
	 * volatile id if obtained when the test was set.
	 */
	fh_fmtp->fh4_volatile_id = (uchar_t)0;
#endif /* VOLATILE_FH_TEST */

	error = VFS_VGET(vfsp, &vp, fidp);
	/*
	 * If we can not get vp from VFS_VGET, perhaps this is
	 * an nfs v2/v3/v4 node in an nfsv4 pseudo filesystem.
	 * Check it out.
	 */
	if (error && PSEUDO(exi))
		error = nfs4_vget_pseudo(exi, &vp, fidp);

	if (error || vp == NULL) {
		*statp = NFS4ERR_STALE;
		return (NULL);
	}
	/* XXX - disgusting hack */
	if (vp->v_type == VNON && vp->v_flag & V_XATTRDIR)
		vp->v_type = VDIR;
	*statp = NFS4_OK;
	return (vp);
}

/*
 * Find the export structure associated with the given filesystem.
 * If found, then increment the ref count (exi_count).
 */
struct exportinfo *
checkexport(fsid_t *fsid, fid_t *fid)
{
	struct exportinfo *exi;

	rw_enter(&exported_lock, RW_READER);
	for (exi = exptable[exptablehash(fsid, fid)];
	    exi != NULL;
	    exi = exi->exi_hash) {
		if (exportmatch(exi, fsid, fid)) {
			/*
			 * If this is the place holder for the
			 * public file handle, then return the
			 * real export entry for the public file
			 * handle.
			 */
			if (exi->exi_export.ex_flags & EX_PUBLIC) {
				exi = exi_public;
			}
			mutex_enter(&exi->exi_lock);
			exi->exi_count++;
			mutex_exit(&exi->exi_lock);
			rw_exit(&exported_lock);
			return (exi);
		}
	}
	rw_exit(&exported_lock);
	return (NULL);
}


/*
 * "old school" version of checkexport() for NFS4.  NFS4
 * rfs4_compound holds exported_lock for duration of compound
 * processing.  This version doesn't manipulate exi_count
 * since NFS4 breaks fundamental assumptions in the exi_count
 * design.
 */
struct exportinfo *
checkexport4(fsid_t *fsid, fid_t *fid, vnode_t *vp)
{
	struct exportinfo *exi;

	ASSERT(RW_LOCK_HELD(&exported_lock));

	for (exi = exptable[exptablehash(fsid, fid)];
	    exi != NULL;
	    exi = exi->exi_hash) {
		if (exportmatch(exi, fsid, fid)) {
			/*
			 * If this is the place holder for the
			 * public file handle, then return the
			 * real export entry for the public file
			 * handle.
			 */
			if (exi->exi_export.ex_flags & EX_PUBLIC) {
				exi = exi_public;
			}

			/*
			 * If vp is given, check if vp is the
			 * same vnode as the exported node.
			 *
			 * Since VOP_FID of a lofs node returns the
			 * fid of its real node (ufs), the exported
			 * node for lofs and (pseudo) ufs may have
			 * the same fsid and fid.
			 */
			if (vp == NULL || vp == exi->exi_vp)
				return (exi);
		}
	}

	return (NULL);
}

/*
 * Free an entire export list node
 */
void
exportfree(struct exportinfo *exi)
{
	struct exportdata *ex;

	ex = &exi->exi_export;

	ASSERT(exi->exi_vp != NULL && !(exi->exi_export.ex_flags & EX_PUBLIC));
	VN_RELE(exi->exi_vp);
	if (exi->exi_dvp != NULL)
		VN_RELE(exi->exi_dvp);

	if (ex->ex_flags & EX_INDEX)
		kmem_free(ex->ex_index, strlen(ex->ex_index) + 1);

	kmem_free(ex->ex_path, ex->ex_pathlen + 1);
	nfsauth_cache_free(exi);

	if (exi->exi_logbuffer != NULL)
		nfslog_disable(exi);

	if (ex->ex_flags & EX_LOG) {
		kmem_free(ex->ex_log_buffer, ex->ex_log_bufferlen + 1);
		kmem_free(ex->ex_tag, ex->ex_taglen + 1);
	}

	if (exi->exi_visible)
		free_visible(exi->exi_visible);

	srv_secinfo_list_free(ex->ex_secinfo, ex->ex_seccnt);

#ifdef VOLATILE_FH_TEST
	free_volrnm_list(exi);
	mutex_destroy(&exi->exi_vol_rename_lock);
#endif /* VOLATILE_FH_TEST */

	mutex_destroy(&exi->exi_lock);
	rw_destroy(&exi->exi_cache_lock);

	kmem_free(exi, sizeof (*exi));
}

/*
 * load the index file from user space into kernel space.
 */
static int
loadindex(struct exportdata *kex)
{
	int error;
	char index[MAXNAMELEN+1];
	size_t len;

	/*
	 * copyinstr copies the complete string including the NULL and
	 * returns the len with the NULL byte included in the calculation
	 * as long as the max length is not exceeded.
	 */
	if (error = copyinstr(kex->ex_index, index, sizeof (index), &len))
		return (error);

	kex->ex_index = kmem_alloc(len, KM_SLEEP);
	bcopy(index, kex->ex_index, len);

	return (0);
}

/*
 * When a thread completes using exi, it should call exi_rele().
 * exi_rele() decrements exi_count. It releases exi if exi_count == 0, i.e.
 * if this is the last user of exi and exi is not on exportinfo list anymore
 */
void
exi_rele(struct exportinfo *exi)
{
	mutex_enter(&exi->exi_lock);
	exi->exi_count--;
	if (exi->exi_count == 0) {
		mutex_exit(&exi->exi_lock);
		exportfree(exi);
	} else
		mutex_exit(&exi->exi_lock);
}

#ifdef VOLATILE_FH_TEST
/*
 * Test for volatile fh's - add file handle to list and set its volatile id
 * to time it was renamed. If EX_VOLFH is also on and the fs is reshared,
 * the vol_rename queue is purged.
 *
 * XXX This code is for unit testing purposes only... To correctly use it, it
 * needs to tie a rename list to the export struct and (more
 * important), protect access to the exi rename list using a write lock.
 */

/*
 * get the fh vol record if it's in the volatile on rename list. Don't check
 * volatile_id in the file handle - compare only the file handles.
 */
static struct ex_vol_rename *
find_volrnm_fh(struct exportinfo *exi, nfs_fh4 *fh4p)
{
	struct ex_vol_rename *p = NULL;
	fhandle_t *fhp;

	/* XXX shouldn't we assert &exported_lock held? */
	ASSERT(MUTEX_HELD(&exi->exi_vol_rename_lock));

	if (fh4p->nfs_fh4_len != NFS_FH4_LEN) {
		return (NULL);
	}
	fhp = &((struct nfs_fh4_fmt *)fh4p->nfs_fh4_val)->fh4_i;
	for (p = exi->exi_vol_rename; p != NULL; p = p->vrn_next) {
		if (bcmp(fhp, &p->vrn_fh_fmt.fh4_i, sizeof (fhandle_t)) == 0)
			break;
	}
	return (p);
}

/*
 * get the volatile id for the fh (if there is - else return 0). Ignore the
 * volatile_id in the file handle - compare only the file handles.
 */
static uint32_t
find_volrnm_fh_id(struct exportinfo *exi, nfs_fh4 *fh4p)
{
	struct ex_vol_rename *p;
	uint32_t volatile_id;

	mutex_enter(&exi->exi_vol_rename_lock);
	p = find_volrnm_fh(exi, fh4p);
	volatile_id = (p ? p->vrn_fh_fmt.fh4_volatile_id :
				exi->exi_volatile_id);
	mutex_exit(&exi->exi_vol_rename_lock);
	return (volatile_id);
}

/*
 * Free the volatile on rename list - will be called if a filesystem is
 * unshared or reshared without EX_VOLRNM
 */
static void
free_volrnm_list(struct exportinfo *exi)
{
	struct ex_vol_rename *p, *pnext;

	/* no need to hold mutex lock - this one is called from exportfree */
	for (p = exi->exi_vol_rename; p != NULL; p = pnext) {
		pnext = p->vrn_next;
		kmem_free(p, sizeof (*p));
	}
	exi->exi_vol_rename = NULL;
}

/*
 * Add a file handle to the volatile on rename list.
 */
void
add_volrnm_fh(struct exportinfo *exi, vnode_t *vp)
{
	struct ex_vol_rename *p;
	char fhbuf[NFS4_FHSIZE];
	nfs_fh4 fh4;
	int error;

	fh4.nfs_fh4_val = fhbuf;
	error = makefh4(&fh4, vp, exi);
	if ((error) || (fh4.nfs_fh4_len != sizeof (p->vrn_fh_fmt))) {
		return;
	}

	mutex_enter(&exi->exi_vol_rename_lock);

	p = find_volrnm_fh(exi, &fh4);

	if (p == NULL) {
		p = kmem_alloc(sizeof (*p), KM_SLEEP);
		bcopy(fh4.nfs_fh4_val, &p->vrn_fh_fmt, sizeof (p->vrn_fh_fmt));
		p->vrn_next = exi->exi_vol_rename;
		exi->exi_vol_rename = p;
	}

	p->vrn_fh_fmt.fh4_volatile_id = gethrestime_sec();
	mutex_exit(&exi->exi_vol_rename_lock);
}

#endif /* VOLATILE_FH_TEST */
