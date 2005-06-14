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
 * Copyright (c) 1991-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ported from
 *	"@(#)nis_xx_proc.c 1.34 91/04/13 Copyr 1990 Sun Micro";
 *
 *	nis_xx_proc.c
 *
 * This module contains various routines needed by the NIS version 3
 * service and all of the replicate management routines.
 * NB : It provides the routines that the dispatch function in nis_svc.c
 * call. That file, nis_svc.c, is automatically generated and reflects the
 * interface definition that is described in the nis.x file. When the
 * nis.x file changes, you must make sure that any parameters that change
 * get reflected in these routines.
 *
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <pwd.h>
#include <malloc.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_callback.h>
#include <rpc/des_crypt.h>
#include "nis_svc.h"
#include "nis_proc.h"
#include "nis_mt.h"

/* Statistic variables */
extern struct ops_stats nisopstats[];
extern int nislookups;
extern int dircachecall;
extern int dircachemiss;
extern int dircachehit;
extern int __nis_ss_used;

extern int emulate_yp;
extern int resolv_flag;

extern nis_object *get_root_object();

static void rmdir_update(char *);

/*
 * This is the signature function, it should sign the data in the
 * buffer so that when the client cache routines pass it to the
 * cache manager it can trust the answer it gets.
 * returns 1 on success and 0 if some error.
 */
#ifdef SIGN_RESULTS
static int
__sign_off(requester, res)
	nis_name	requester;
	fd_result	*res;
{
	char 			s_netname[MAXNETNAMELEN+1];
	char 			pkey[HEXKEYBYTES+1];
	unsigned char 		*digest;
	unsigned int 		digestlen;
	des_block		deskey;
	keybuf			requester_pkey;
	int			err;
	nis_attr		qry[3];
	char			srch[2048];
	nis_object		*d_obj;
	nis_name		dirname;
	struct ticks		t;
	nis_db_list_result	*dbres;

	/*
	 * no need to sign for these special cases.
	 * these are used by nisinit, when the principal names haven't
	 * been set up.
	 * "multicast" should also be added when that is implemented
	 */

	if ((strcmp(requester, "broadcast") == 0) ||
	    (strcmp(requester, "nobody") == 0))
		return (0);

	/* get the netname and the publickey of the requester machine */
	if (!host2netname(s_netname, requester, NULL)) {
		if (verbose)
			syslog(LOG_ERR,
			"__sign_off: host2netname failed for: %s", requester);
		return (0);
	}
	dirname = nis_domain_of(requester);
	if (! dirname || (*dirname  == '.'))
		return (0);

	err = __directory_object(dirname, &t, 0, &d_obj);
	pkey[0] = 0;
	/* we serve this directory so we "know" the public key. */
	if (d_obj) {
		qry[0].zattr_ndx = "auth_name";
		qry[0].zattr_val.zattr_val_len = strlen(s_netname) + 1;
		qry[0].zattr_val.zattr_val_val = &s_netname[0];
		qry[1].zattr_ndx = "auth_type";
		qry[1].zattr_val.zattr_val_len = 4;
		qry[1].zattr_val.zattr_val_val = "DES";
		sprintf(srch, "cred.org_dir.%s", nis_domain_of(requester));
		dbres = db_list(srch, 2, &qry[0]);
		if (dbres->status == NIS_SUCCESS) {
			strncpy(pkey, ENTRY_VAL(dbres->objs[0].o, 3),
								HEXKEYBYTES);
		}
	} else {
		getpublickey(s_netname, pkey);
	}
	if (pkey[0] == 0) {
		syslog(LOG_ERR,
			"__sign_off: Unable to get publickey for: %s",
								s_netname);
		return (0);
	}
	/* get the conversation key from the keyserver */
	memset((void *)requester_pkey, 0, sizeof (keybuf));
	memcpy((char *)requester_pkey, pkey, HEXKEYBYTES);
	if (key_get_conv(requester_pkey, &deskey) != 0) {
		if (verbose)
			syslog(LOG_ERR,
			"__sign_off: Could not get conversation key for: %s",
								requester);
		return (0);
	}
	/* calculate the md5 checksum of XDR'ed data and encrypt it */
	digest = NULL;
	__nis_calculate_encrypted_cksum(res->dir_data.dir_data_len,
					res->dir_data.dir_data_val,
					(char *)&deskey, &digestlen, &digest);
	if (!digest)
		return (0);

	res->signature.signature_val = (char *)digest;
	res->signature.signature_len = digestlen;
	return (1);
}
#else
static int
__sign_off(req, res)
	nis_name	req;
	fd_result	*res;
{
	return (1);
}
#endif


/*
 * Return a Find Directory result.
 */
fd_result *
__fd_res(requester, stat, o)
	nis_name	requester;
	nis_error	stat;
	directory_obj	*o;
{
	fd_result		*res;
	int			status, size1;
	XDR			xdrs;
	static fd_result	mem_err = {NIS_NOMEMORY, 0};

	res = (fd_result *)XCALLOC(1, sizeof (fd_result));
	if (! res) {
		syslog(LOG_CRIT,
		"find_directory_svc: Out of memory, location request aborted.");
		return (&mem_err);
	}
	add_cleanup((void (*)())XFREE, (char *)res, "fd_res: result");

	res->status = stat;
	res->source = nis_local_principal();
	if (res->source == NULL) {
		res->status = NIS_NOMEMORY;	/* probable cause */
		return (res);
	}
	/*
	 * If this is the answer, or "closer" to the
	 * name they want then just return it.
	 */
	if (o) {
		size1 = xdr_sizeof(xdr_directory_obj, o);
		res->dir_data.dir_data_val = (char *)XMALLOC(size1);
		if (res->dir_data.dir_data_val) {
			add_cleanup((void (*)())XFREE,
					(char *)res->dir_data.dir_data_val,
								"fd_res: data");

			xdrmem_create(&xdrs, res->dir_data.dir_data_val,
							size1, XDR_ENCODE);
			status = xdr_directory_obj(&xdrs, o);
			if (!status)
				syslog(LOG_ERR,
				"Unable to encode resulting directory object.");
			res->dir_data.dir_data_len = size1;
			res->signature.signature_val = NULL;
			res->signature.signature_len = 0;
			/* sign the result */
			__sign_off(requester, res);

		} else {
			syslog(LOG_CRIT,
		"find_directory_svc: Out of memory, location request aborted.");
			res->status = NIS_NOMEMORY;
			return (res);		}
	}
	return (res);
}

/*
 * nis_finddirectory, this routine is called by clients that are looking for
 * the names of machines serving the directory they are interested
 * in. It responds with a directory object of the directory that the client
 * is looking for or the directory object for a directory that is closer to
 * the desired directory than this one is. If the server is the desired
 * directory it returns an object containing itself.
 * NB: There are three possible results :
 *		This Directory
 * 		My Parent Directory
 *		A sub directory.
 *
 */

fd_result *
nis_finddirectory_svc(argp, reqstp)
	fd_args 	*argp;
	struct svc_req	*reqstp;
{
	directory_obj	*dobj; 	/* The proposed answer  */
	char		*in, *s, *t;
	name_pos	p;
	int		i_serve, i;
	struct fd_result	*res;
	nis_db_result	*dbres = NULL;
	nis_error	stat;
	static fd_result	mem_err = {NIS_NOMEMORY, 0};

	if (verbose)
		syslog(LOG_INFO,
			"FINDDIR_SVC: Location request for directory %s",
				argp->dir_name);

	/*
	 * If we serve this object, it seems a bit silly to look in the
	 * shared cache. Even if it's there (not at all certain, if it
	 * isn't our cold start directory), the shared cache copy is probably
	 * at best up-to-date with the real one. We use __directory_object()
	 * to check the directory list ('dl') cache, or to retrieve a copy
	 * from the real database.
	 */
	{
		nis_object *tmpobj;
		struct ticks ticks;
		nis_error dostatus;

		dostatus = __directory_object_msg(argp->dir_name, &ticks, 0,
						&tmpobj, 0);
		if (dostatus == NIS_SUCCESS) {
			return (__fd_res(argp->requester, NIS_SUCCESS,
					&(tmpobj->DI_data)));
		}
	}

	/* Allocate some memory to hold our directory object */
	dobj = (directory_obj *)XMALLOC(sizeof (*dobj));
	if (! dobj) {
		syslog(LOG_CRIT, "find_directory_svc: No memory.");
		return (&mem_err);
	}

	/* Read the cache first (won't recurse) */
	stat = __nis_CacheSearch(argp->dir_name, dobj);
	if (stat != NIS_SUCCESS) {
		XFREE(dobj);
		syslog(LOG_ERR, "Location cache failure on server:%s",
			nis_sperrno(stat));
		return (__fd_res(argp->requester,  stat, NULL));
	}

	/*
	 * The location algorithm works as follows: start on the
	 * easy cases and then work up to the hard ones.
	 */
	p = nis_dir_cmp(argp->dir_name, dobj->do_name);
	if (p == BAD_NAME) {
		xdr_free(xdr_directory_obj, (char *)(dobj));
		XFREE(dobj);
		return (__fd_res(argp->requester, NIS_BADNAME, NULL));
	} else if (p == SAME_NAME) {
		/* Real easy, the cache returned the answer. */
		add_xdr_cleanup(xdr_directory_obj, (char *)dobj,
							"fd_res: dirobj");
		return (__fd_res(argp->requester, NIS_SUCCESS, dobj));
	}

	s = nis_local_host();

	/*
	 * Step 1. Next easiest
	 * If the cache result returned is above my directory, I cannot
	 * possibly serve it. And if the target name is below the
	 * cache result then we're one step closer to resolving it
	 * so just return the cache result.
	 */
	if ((p == LOWER_NAME) &&
	    (nis_dir_cmp(dobj->do_name, __nis_rpc_domain())
							== HIGHER_NAME)) {
		add_xdr_cleanup(xdr_directory_obj, (char *)dobj,
							"fd_res: dirobj");
		return (__fd_res(argp->requester, NIS_SUCCESS, dobj));
	}

	/* determine whether I serve this directory */
	for (i = 0; i < dobj->do_servers.do_servers_len; i++) {
		t = dobj->do_servers.do_servers_val[i].name;
		if (nis_dir_cmp(s, t) == SAME_NAME)
			break;
	}
	i_serve = (i < dobj->do_servers.do_servers_len);

	/*
	 * Step 2, a bit tougher.
	 * If the directory being located is either above us in
	 * the tree or above us and down another branch (a sibling), we
	 * have two options. If the directory the cache produced was one
	 * that I serve, we return our parent, otherwise we return the
	 * cached result. If the name is above us and we are the root
	 * server, we return an error or our parent object
	 */
	if ((p == HIGHER_NAME) || (p == NOT_SEQUENTIAL)) {
		if (! i_serve) {
			/* I don't serve it so it is a valid answer */
			add_xdr_cleanup(xdr_directory_obj, (char *)dobj,
						"fd_res: dobj (cache result)");
			return (__fd_res(argp->requester, NIS_SUCCESS, dobj));
		}
	}
	/* free data in the previous directory object */
	xdr_free(xdr_directory_obj, (char *)(dobj));

	if (nis_dir_cmp(argp->dir_name, __nis_rpc_domain()) == HIGHER_NAME) {
		if (root_server) {
			nis_object	*obj;

			/* Won't need the directory object anymore */
			XFREE(dobj);

			obj = nis_read_obj(nis_data(PARENT_OBJ));
			if (! obj)
				return (__fd_res(argp->requester,
							NIS_NOSUCHNAME, NULL));

			add_xdr_cleanup(xdr_nis_object, (char *)obj,
					"fd_res: parent obj (cache result)");
			if (obj->DI_data.do_type == NIS)
				return (__fd_res(argp->requester, NIS_SUCCESS,
							&(obj->DI_data)));
			else
				return (__fd_res(argp->requester, NIS_FOREIGNNS,
							    &(obj->DI_data)));
		} else {
			stat = __nis_CacheSearch(__nis_rpc_domain(), dobj);
			if (stat == NIS_SUCCESS) {
				add_xdr_cleanup(xdr_directory_obj,
					(char *)dobj, "fd_res: dobj (parent)");
				return (__fd_res(argp->requester, NIS_SUCCESS,
									dobj));
			} else {
				XFREE(dobj);
				return (__fd_res(argp->requester, stat, NULL));
			}
		}
	}


	if (nis_dir_cmp(argp->dir_name, __nis_rpc_domain()) ==
	    NOT_SEQUENTIAL) {
		if (root_server) {
			XFREE(dobj);
			return (__fd_res(argp->requester,
					NIS_NOSUCHNAME, NULL));
		}
	}

	/*
	 * Step 3, toughest one
	 * By process of elimination I know the name is below
	 * some cache entry that got returned. That could be either
	 * something I serve or the pointer to my parent. In either
	 * case, I start searching my database from the name passed
	 * upward toward the root. Four things can happen
	 *  1)	If I find the one we're looking for then great, I'll
	 *	just return it.
	 *  2)	If I never find any thing closer (ie a directory object
	 *	in it's path then my parent can deal with it.
	 *  3)	If I find a directory in the desired directories "path"
	 *	that I don't serve, we pass the request on to those
	 *	servers.
	 *  4)	If I find a directory that I serve above it in the name
	 *	space then the target directory cannot exist. Because
	 *	if it did I would have found it's directory object
	 *	before finding a directory that I serve.
	 *
	 * We start using the whole name and selectively pick off
	 * leaves until we're up to the our local directory.
	 */

	in = argp->dir_name;
	while (nis_dir_cmp(in, __nis_rpc_domain()) == LOWER_NAME) {
		if (verbose)
			syslog(LOG_INFO, "Locating %s in the database.", in);
		dbres = db_lookup(in);
		if (dbres->status == NIS_SUCCESS) {

			/*
			 * POLICY : You can't link directories with
			 *	    LINK objects.
			 * ANSWER : Because the recursion could become
			 *	    infinite.
			 */
			XFREE(dobj); /* won't be needing this any more */
			if (__type_of(dbres->obj) != NIS_DIRECTORY_OBJ) {
				if (verbose)
					syslog(LOG_INFO,
						"Object %s isn't a directory.",
							dbres->obj->zo_name);
				res = __fd_res(argp->requester, NIS_BADOBJECT,
									NULL);
			} else {
				/*
				 * we found a directory object in the "path"
				 * of the desired object.
				 */
				if (verbose)
					syslog(LOG_INFO,
						"Found a directory %s",
							dbres->obj->zo_name);
				dobj = &(dbres->obj->DI_data);
				p = nis_dir_cmp(dobj->do_name, argp->dir_name);
				if (p == SAME_NAME) {
					res = __fd_res(argp->requester,
							NIS_SUCCESS, dobj);
				/*
				 * It isn't the answer (#1) so let's see if we
				 * serve it. (#3 or #4)
				 */
				} else {
					s = nis_local_host();
					for (i = 0;
					    i < dobj->do_servers.do_servers_len;
					    i++) {
						t =
					dobj->do_servers.do_servers_val[i].name;
						if (nis_dir_cmp(s, t)
								== SAME_NAME)
							break;
					}
					if (i < dobj->do_servers.do_servers_len)
						res = __fd_res(argp->requester,
							NIS_NOSUCHNAME, NULL);
					else
						res = __fd_res(argp->requester,
							NIS_SUCCESS, dobj);
				}
			}
			return (res);
		} else if (dbres->status == NIS_NOTFOUND) {
			XFREE(dobj);
			return (__fd_res(argp->requester, NIS_NOSUCHNAME,
									NULL));
		}
		in = nis_domain_of(in);
	}

	if (verbose) {
		syslog(LOG_INFO, "Unable to locate directory : %s",
							argp->dir_name);
	}

	/* Option #2, let my parent deal with it. */
	stat = __nis_CacheSearch(__nis_rpc_domain(), dobj);
	if (stat == NIS_SUCCESS) {
		add_xdr_cleanup(xdr_directory_obj, (char *)dobj,
						"fd_res: dobj (parent)");
		return (__fd_res(argp->requester, NIS_SUCCESS, dobj));
	}
	XFREE(dobj);
	return (__fd_res(argp->requester, stat, NULL));
}

/*
 * nis_callback_svc
 *
 * Check on the state of a child process or thread who is calling back to the
 * client.
 */

bool_t *
nis_callback_svc(argp, reqstp)
	netobj *argp;
	struct svc_req *reqstp;
{
#define	res		(__nis_get_tsd()->nis_callback_svc_res)
	pthread_t	id;
	anonid_t	anonid;
	char		pname[1024], id_pname[1024];

	if (argp->n_bytes == 0 || argp->n_len != sizeof (anonid_t)) {
		syslog(LOG_ERR, "CALLBACK_SVC: bad argument");
		res = FALSE;
		return (&res);
	}

	/* Get name of principal calling us */
	nis_getprincipal(pname, reqstp);

	/*
	 * If an unauthenticated user issued a nis_list() for a table on
	 * which "nobody" has read rights, then the callback rpc.nisd
	 * will be running on behalf of nobody. Hence, it is not appropriate
	 * for us to verify authentication; we just check that the
	 * principal behind the NIS_CALLBACK, and the one who initiated the
	 * callback, is one and the same. If the initator name is "nobody",
	 * anything goes.
	 */

	/* Obtain pid and principal on whose behalf pid is running */
	anonid = *((anonid_t *)argp->n_bytes);
	id_pname[0] = '\0';
	id = nis_get_callback_id(anonid, id_pname, sizeof (id_pname));

	if (verbose)
		syslog(LOG_INFO,
	"CALLBACK_SVC: ID = %ld, anon id = %ld, pname = %s, id_pname = %s",
			id, anonid, pname, id_pname);

	/* Verify caller principal same as pid principal */
	if (secure_level >= 2 && strcmp(pname, id_pname) != 0 &&
	    strcmp("nobody", id_pname) != 0) {
		res = FALSE;
		return (&res);
	}

	res = (pthread_kill(id, 0) == 0);

	return (&res);
}

#undef	res


/* Names of the operations for statistics functions. */
static char *opnames[] = {
	"NULLPROC", 	/* 0 */
	"LOOKUP", 	/* 1 */
	"ADD", 		/* 2 */
	"MODIFY", 	/* 3 */
	"REMOVE", 	/* 4 */
	"LIST", 	/* 5 */
	"ADDENTRY", 	/* 6 */
	"MODENTRY", 	/* 7 */
	"REMENTEY", 	/* 8 */
	"FIRSTENTRY", 	/* 9 */
	"NEXTENTRY", 	/* 10 */
	"RSRVD1", 	/* 11 */
	"FINDDIR",  	/* 12 */
	"RSRVD2", 	/* 13 */
	"STATUS", 	/* 14 */
	"DUMPLOG", 	/* 15 */
	"DUMP", 	/* 16 */
	"CALLBACK", 	/* 17 */
	"CPTIME", 	/* 18 */
	"CHECKPOINT", 	/* 19 */
	"PING", 	/* 20 */
	"SERVSTATE", 	/* 21 */
	"MKDIR", 	/* 22 */
	"RMDIR", 	/* 23 */
	"UPDKEYS" 	/* 24 */
};

static char *
prtop(p)
	int p;
{
	int	i;
	struct ops_stats *op;
	ulong_t	avgtime = 0;
	static char opbuf[80];

	if (p < 0 || p >= (sizeof (opnames) / sizeof (opnames[0]))) {
		sprintf(opbuf, "<unknown operation %d>", p);
		return (opbuf);
	}
	RLOCK(nisopstats);
	op = &(nisopstats[p]);
	for (i = 0; (i < 16) && op->tsamps[i]; i++)
		avgtime += op->tsamps[i];
	if (i)
		avgtime = avgtime / i;
	sprintf(opbuf, "\nOP=%s:C=%d:E=%d:T=%d", opnames[p], op->calls,
						op->errors, avgtime);
	RULOCK(nisopstats);
	return (opbuf);
}

extern struct timeval start_time;

static void
up_since(s)
	char	*s;
{
	struct timeval	tv;
	long	days, hrs, mins, secs;

	gettimeofday(&tv, NULL);
	secs = tv.tv_sec - start_time.tv_sec;
	days = secs / 86400;
	hrs = (secs - (days * 86400)) / 3600;
	mins = (secs - (days * 86400) - (hrs * 3600)) / 60;
	secs = secs % 60;
	sprintf(s, "up %dD, %02d:%02d:%02d", days, hrs, mins, secs);
}

static void
free_taglist(nis_taglist *tl)
{
	nis_freetags(tl->tags.tags_val, tl->tags.tags_len);
	free((void *)tl);
}

#define	CHECK_TAG_S_ACC(tag) \
			if (!nis_op_access("NIS_STATUS", tag, 0, 0, \
						reqstp)) { \
				strcpy(tag_data, "<permission denied>"); \
				break; \
			}

/*
 * nis_status, return status on the nis server.
 */
nis_taglist *
nis_status_svc(argp, reqstp)
	nis_taglist *argp;
	struct svc_req *reqstp;
{
	int 	i, nt, j;
	nis_tag	*tlist;
	char	tag_data[1024];	/* Enough for any tag other than DIR_LIST */
	char	*dirs;		/* malloc:ed string for DIR_LIST */
	nis_taglist *res;
	int grpcachecall;
	int grpcachemiss;
	int grpcachehit;
	extern int __nis_group_cache_stats(int *, int *, int *);
	extern unsigned int heap_start;

	if (verbose)
		syslog(LOG_INFO, "STATUS_SVC: %d tags passed",
				argp->tags.tags_len);
	nt = argp->tags.tags_len;
	tlist = argp->tags.tags_val;

	/* malloc memory for result */
	res = (nis_taglist *)XCALLOC(1, sizeof (nis_taglist));
	if (res == NULL) {
		syslog(LOG_ERR, "nis_status_svc: no memory.");
		return (NULL);
	}
	add_cleanup((void (*)())free_taglist, res, "tag list");

	res->tags.tags_val = (nis_tag *)XCALLOC(nt, sizeof (nis_tag));
	res->tags.tags_len = nt;
	if (res->tags.tags_val == NULL) {
		syslog(LOG_ERR, "nis_status_svc: no memory.");
		return (NULL);
	}

	for (i = 0; i < nt; i++) {
		switch (tlist[i].tag_type) {
			case TAG_UPTIME :
				CHECK_TAG_S_ACC("TAG_UPTIME");
				up_since(tag_data);
				break;
			case TAG_S_DCACHE :
				CHECK_TAG_S_ACC("TAG_S_DCACHE");
				RLOCK(dircachestats);
				if (dircachecall)
					sprintf(tag_data,
						"C=%d:H=%d:M=%d:HR=%2.0f%%",
						dircachecall, dircachehit,
						dircachemiss,
				((dircachecall-dircachemiss)*(float)100)/
						dircachecall);
				else
					sprintf(tag_data,
							"C=0:H=0:M=0:HR=100%%");
				RULOCK(dircachestats);
				break;
			case TAG_S_STORAGE :
				CHECK_TAG_S_ACC("TAG_S_STORAGE");
				sprintf(tag_data, "%d", __nis_ss_used);
				break;
			case TAG_S_GCACHE :
				CHECK_TAG_S_ACC("TAG_S_GCACHE");
				if (__nis_group_cache_stats(&grpcachecall,
					&grpcachehit, &grpcachemiss) &&
				    grpcachecall != 0)
					sprintf(tag_data,
					    "C=%d:H=%d:M=%d:HR=%2.0f%%",
						grpcachecall, grpcachehit,
						grpcachemiss,
				((grpcachecall-grpcachemiss)*(float)100)/
						grpcachecall);
				else
					sprintf(tag_data,
						"C=0:H=0:M=0:HR=100%%");
				break;
			case TAG_OPSTATS :
				CHECK_TAG_S_ACC("TAG_OPSTATS");
				if ((*(tlist[i].tag_val) == '\0') ||
				    (strcmp(tlist[i].tag_val, "all") == 0)) {
					tag_data[0] = '\0';
					for (j = 0; j < 24; j++) {
						if (! nisopstats[j].calls)
							continue;
						strcat(tag_data, prtop(j));
					}
				} else {
					j = atoi(tlist[i].tag_val);
					sprintf(tag_data, "%s", prtop(j));
				}
				break;
			case TAG_HEAP :
				CHECK_TAG_S_ACC("TAG_HEAP");
				sprintf(tag_data, "%u",
					(unsigned int) sbrk(0) - heap_start);
				break;
			case TAG_DIRLIST:
				CHECK_TAG_S_ACC("TAG_DIRLIST");
				if (nis_server_control(SERVING_LIST,
						DIR_GETLIST, &dirs) == 0) {
					dirs = NULL;
				}
				break;
			case TAG_NISCOMPAT:
				CHECK_TAG_S_ACC("TAG_NISCOMPAT");
				if (emulate_yp)
					strcpy(tag_data, "ON");
				else
					strcpy(tag_data, "OFF");
				break;
			case TAG_DNSFORWARDING:
				CHECK_TAG_S_ACC("TAG_DNSFORWARDING");
				if (resolv_flag)
					strcpy(tag_data, "ON");
				else
					strcpy(tag_data, "OFF");
				break;
			case TAG_SECURITY_LEVEL:
				CHECK_TAG_S_ACC("TAG_SECURITY_LEVEL");
				sprintf(tag_data, "%d", secure_level);
				break;
			case TAG_ROOTSERVER:
				CHECK_TAG_S_ACC("TAG_ROOTSERVER");
				if (root_server)
					strcpy(tag_data, "ON");
				else
					strcpy(tag_data, "OFF");
				break;
			default :
				strcpy(tag_data, "<Unknown Statistic>");
				break;
		}
		if (tlist[i].tag_type == TAG_DIRLIST)
			res->tags.tags_val[i].tag_val = dirs;
		else
			res->tags.tags_val[i].tag_val = strdup(tag_data);
		if (res->tags.tags_val[i].tag_val == NULL) {
			syslog(LOG_ERR, "nis_status_svc: no memory.");
			return (NULL);
		}
		res->tags.tags_val[i].tag_type = tlist[i].tag_type;
	}
	return (res);
}

/*
 * nis_cptime()
 *
 * This function will return the timestamp of the last stable transaction
 * from the server. All of the timestamps that are maintained in a cluster
 * are generated by the master so there is no time skew. This function
 * is used by the master to ping replicas and figure out whether it can
 * truncate the log or not.
 */
uint_t *
nis_cptime_svc(argp, reqstp)
	nis_name *argp;
	struct svc_req *reqstp;
{
#define	res	(__nis_get_tsd()->nis_cptime_svc_res)

	if (verbose)
		syslog(LOG_INFO, "CPTIME_SVC: '%s'", *argp);

	if (!nis_op_access("NIS_CPTIME", 0, *argp, 0, reqstp)) {
		if (verbose)
			syslog(LOG_INFO,
			"CPTIME_SVC: authorization error on \"%s\"", *argp);
		res = 0;
		return (&res);
	}

	res = last_update(*argp);
	return (&res);
}

#undef	res

/*
 * nis_checkpoint()
 *
 * This function sets up a checkpoint to be done, as you might want to do
 * if the log were getting too full. The parameter is the name of the
 * directory you want to checkpoint. In addition to checkpointing the
 * NIS+ log, it checkpoints and local database logs that may need this.
 * Note that the actual checkpointing is done later, in the
 * main server loop, after the server has forked a read-only child.
 * Should not fork here because we're in the middle of an RPC.
 *
 */
cp_result *
nis_checkpoint_svc(argp, reqstp)
	nis_name *argp;
	struct svc_req *reqstp;
{
	cp_result *res;
	nis_error stat;
	struct ticks t;
	nis_object *dobj;
	/* xxx static should be const */
	static cp_result mem_err = {NIS_NOMEMORY, 0, 0};

	if (verbose)
		syslog(LOG_INFO, "CHECKPOINT_SVC: '%s'", *argp);

	res = (cp_result *)XCALLOC(1, sizeof (cp_result));
	if (! res)
		return (&mem_err);
	add_cleanup((void (*)())XFREE, (char *)res, "chkpnt result");

	if (!nis_op_access("NIS_CHECKPOINT", 0, *argp, 0, reqstp)) {
		if (verbose)
			syslog(LOG_INFO,
			"CHECKPOINT_SVC: authorization error on \"%s\"",
				*argp);
		res->cp_status = NIS_PERMISSION;
		return (res);
	}

	__start_clock(0);

	/*
	 *  Maintain '*argp' in a list of directories to be checkpointed.
	 *  and perform  do_checkpoint_dir(*argp) over list when checkpointing
	 *  eventually occurs.
	 *  If argument is null string, checkpoint all.
	 */
	if (*argp == 0 || **argp == 0) {
		clear_checkpoint_list();   /* delete remembered items */
		checkpoint_all = 1;
	} else {
		/* Otherwise, specified directory.  make sure we serve it. */
		stat = __directory_object(*argp, &t, 0, &dobj);
		if (stat != NIS_SUCCESS) {
			res->cp_status = stat;
			res->cp_zticks = __stop_clock(0);
			return (res);
		}

		/* Only add to list if we are not going to cp entire db */
		if (!checkpoint_all)
			add_pingitem_with_name(*argp, 0, 0, &checkpoint_list);
	}

	/*
	 * Set status to SUCCESS here to indicate that directory
	 * object is valid and will be checkpointed.
	 */

	res->cp_status = NIS_SUCCESS;
	res->cp_zticks = __stop_clock(0);
	force_checkpoint = 1;

	/*
	 * The non-MT code will try to checkpoint immediately, so in order
	 * to preserve that behavior, we wake up the servloop() thread.
	 */
	wakeup_servloop();

	return (res);
}

/*
 * nis_dumplog, dump the log from the indicated timestamp on.
 */
log_result *
nis_dumplog_svc(argp, reqstp)
	dump_args *argp;
	struct svc_req *reqstp;
{
	log_result *tmp;
	char	pname[1024];
	nis_object	*dobj;
	nis_result	*lres;
	nis_server	*srvs;
	int	ns;
	int	i;



	tmp = (log_result *)XCALLOC(1, sizeof (log_result));
	add_xdr_cleanup(xdr_log_result, (char *)tmp, "dumplog result");

	if (argp->da_time == 0) {
		if (verbose)
			syslog(LOG_INFO,
			"nis_dumplog_svc: replica asking for time 0. RESYNC.");
		tmp->lr_status = NIS_RESYNC;
		return (tmp);
	}

	/*
	 * Now we verify that a valid replica is actually asking for this data.
	 * NB: We look up the object from the master server to pickup the
	 * latest copy of the object. This lets us see new replicas as
	 * they are added.
	 */
	lres = nis_lookup(argp->da_dir, MASTER_ONLY);
	if (lres->status != NIS_SUCCESS) {
		if (verbose)
			syslog(LOG_INFO,
				"nis_dump_svc: No directory object, error %s.",
					nis_sperrno(lres->status));
		tmp->lr_status = lres->status;
		nis_freeresult(lres);
		return (tmp);
	}

	/*
	 * Make sure it is a directory they want dumped.
	 */
	dobj = lres->objects.objects_val;
	if (__type_of(dobj) != NIS_DIRECTORY_OBJ) {
		syslog(LOG_ERR,
		"nis_dump_svc: request to dump %s.%s which isn't a directory!",
			dobj->zo_name, dobj->zo_domain);
		tmp->lr_status = NIS_BADOBJECT;
		nis_freeresult(lres);
		return (tmp);
	}

	/*
	 * Make sure that we are the master server for that directory.
	 */
	ns = dobj->DI_data.do_servers.do_servers_len;
	srvs = dobj->DI_data.do_servers.do_servers_val;
	if (nis_dir_cmp(srvs[0].name, nis_local_host()) != SAME_NAME) {
		nis_freeresult(lres);
		tmp->lr_status = NIS_NOTMASTER;
		return (tmp);
	}

	/*
	 * Check to see that a valid replica is asking for the dump
	 */
	nis_getprincipal(pname, reqstp);
	if (secure_level) {
		for (i = 1; (i < ns) &&
			(nis_dir_cmp(pname, srvs[i].name) != SAME_NAME); i++)
			;

		if (i == ns) {
			if (verbose)
				syslog(LOG_INFO,
				"nis_dump_svc: invalid replica '%s'", pname);
			nis_freeresult(lres);
			tmp->lr_status = NIS_PERMISSION;
			return (tmp);
		}
	}

	if (verbose)
		syslog(LOG_INFO, "DUMPLOG_SVC : dumping '%s' to host '%s'",
			argp->da_dir, pname);

	/*
	 * Pass the whole directory object so that entries_since()
	 * can add it to the ping list should it not return all
	 * entries this time.
	 */
	entries_since(dobj, argp->da_time, tmp);

	/* don't need this anymore */
	nis_freeresult(lres);

	if (verbose)
		syslog(LOG_INFO,
		    "nis_dumplog_svc: returning status of '%s', and %d deltas.",
						nis_sperrno(tmp->lr_status),
						tmp->lr_entries.lr_entries_len);
	return (tmp);
}

/*
 * nis_dump_svc, dump the entire contents of the named directory.
 */
#define	CB_BUF_SIZE 128

log_result *
nis_dump_svc(argp, reqstp)
	dump_args	*argp;
	struct svc_req 	*reqstp;
{
	log_result		*res;
	CLIENT			*cback = NULL;
	char			pname[1024];
	dumpsvc_thread_arg_t	*mtdumparg;
	pthread_t		tid;
	pthread_attr_t		attr;
	int			stat;
	int			i;
	nis_server		*srvs;
	int			ns;
	log_entry		*le = NULL;
	nis_object		*dobj;
	ulong_t			ttime;
	nis_result		*lres;
	nis_server		cbsrv;
	struct netbuf		*rpc_origin;
	endpoint		*org_endpoint, *alt_endpoint, epbuf;
	char			uaddrbuf[256], *uaddr = uaddrbuf;


	if (verbose)
		syslog(LOG_INFO, "DUMP_SVC : Dump directory '%s'",
								argp->da_dir);
	res = (log_result *) XCALLOC(1, sizeof (log_result));
	add_cleanup((void (*)())XFREE, (char *)res, "dump result");

	/*
	 * Start the series of checks that need to be met before dumping
	 * can begin.
	 */
	if (argp->da_cbhost.da_cbhost_len != 1) {
		if (verbose)
			syslog(LOG_INFO, "nis_dump_svc: missing callback.");
		res->lr_status = NIS_CBERROR;
		return (res);
	}

	/*
	 * XXX Do we need to limit the number of dumping threads ?
	 * No, for now, we just rely on the serialization implicit
	 * in the use of the __nis_callback_lock mutex in nis_dump()
	 * (in libnsl).
	 */

	/*
	 * Now we verify that a valid replica is actually asking for this data.
	 * NB: We look up the object from the master server to pickup the
	 *	latest copy of the object. This lets us see new replicas as
	 *	they are added.
	 */
	lres = nis_lookup(argp->da_dir, MASTER_ONLY);
	if (lres->status != NIS_SUCCESS) {
		if (verbose)
			syslog(LOG_INFO,
				"nis_dump_svc: No directory object, error %s.",
						    nis_sperrno(lres->status));
		res->lr_status = lres->status;
		nis_freeresult(lres);
		return (res);
	}

	/*
	 * Make sure it is a directory they want dumped.
	 */
	dobj = lres->objects.objects_val;
	if (__type_of(dobj) != NIS_DIRECTORY_OBJ) {
		syslog(LOG_ERR,
		"nis_dump_svc: request to dump %s.%s which isn't a directory!",
						dobj->zo_name, dobj->zo_domain);
		res->lr_status = NIS_BADOBJECT;
		nis_freeresult(lres);
		return (res);
	}

	/*
	 * Make sure that we are the master server for that directory.
	 */
	ns = dobj->DI_data.do_servers.do_servers_len;
	srvs = dobj->DI_data.do_servers.do_servers_val;
	if (nis_dir_cmp(srvs[0].name, nis_local_host()) != SAME_NAME) {
		nis_freeresult(lres);
		res->lr_status = NIS_NOTMASTER;
		return (res);
	}

	/*
	 * Check to see that a valid replica is asking for the dump
	 */
	nis_getprincipal(pname, reqstp);
	if (secure_level) {
		for (i = 1; (i < ns) &&
			(nis_dir_cmp(pname, srvs[i].name) != SAME_NAME); i++)
			;

		if (i == ns) {
			if (verbose)
				syslog(LOG_INFO,
				"nis_dump_svc: invalid replica '%s'", pname);
			res->lr_status = NIS_PERMISSION;
			return (res);
		}
	}

	/*
	 * The replica supplied an address for the callback service.
	 * However, we may not be able to reach that address, so
	 * try the source address of the RPC request first.
	 *
	 * Note: The alt_endpoint array (which usually contains just
	 * a single element) is a copy of of org_endpoint, including
	 * pointers, except for the uaddr of one element. This uaddr
	 * contains a merged version of the RPC source address and the
	 * port number specified by the client in the callback data.
	 *
	 * The copying tp 'cbsrv' and 'epbuf' below is done so that we
	 * can free any allocated memory immediately, and won't have to
	 * worry about that later.
	 */
	cbsrv = *argp->da_cbhost.da_cbhost_val;
	org_endpoint = cbsrv.ep.ep_val;
	rpc_origin = svc_getrpccaller(reqstp->rq_xprt);
	if (argp->da_cbhost.da_cbhost_val->ep.ep_len == 1 &&
		(alt_endpoint = __nis_alt_callback_server(org_endpoint,
				argp->da_cbhost.da_cbhost_val->ep.ep_len,
				rpc_origin,
				&uaddr, sizeof (uaddrbuf))) != 0) {
		epbuf = alt_endpoint[0];
		cbsrv.ep.ep_val = &epbuf;
		free(alt_endpoint);
	}

	/*
	 * XXX now, do we use the handle that was passed us? or do we use
	 * the one in the object?
	 */
	cback = nis_make_rpchandle(argp->da_cbhost.da_cbhost_val, 1,
				CB_PROG, 1, ZMH_VC+ZMH_AUTH, 128, 8192);

	if (! cback) {
		if (verbose)
			syslog(LOG_INFO,
				"nis_dump_svc: unable to create callback.");
		res->lr_status = NIS_CBERROR;
		nis_freeresult(lres);
		return (res);
	}

	/* don't need this anymore */
	nis_freeresult(lres);

	ttime = last_update(argp->da_dir);
	if (ttime == time(0)) {
		syslog(LOG_INFO,
		    "nis_dump_svc: Current updates found, try later");
		res->lr_status = NIS_DUMPLATER;
		return (res);
	} else if (ttime == 0)
		syslog(LOG_INFO,
			"nis_dump_svc: directory %s has no update timestamp.",
				argp->da_dir);
	else {
		le = (log_entry *) XCALLOC(1, sizeof (log_entry));
		if (! le) {
			syslog(LOG_INFO, "nis_dump_svc: out of memory.");
			res->lr_status = NIS_NOMEMORY;
			auth_destroy(cback->cl_auth);
			clnt_destroy(cback);
			return (res);
		}
		add_cleanup((void (*)())XFREE, (char *)le, "dump logent");
		le->le_princp = XSTRDUP(nis_local_principal());
		add_cleanup((void (*)())XFREE, (char *)le->le_princp,
						"dump logent->princp");
		le->le_time = ttime;
		le->le_type = UPD_STAMP;
		le->le_name = XSTRDUP(argp->da_dir);
		add_cleanup((void (*)())XFREE, (char *)le->le_name,
						"dump logent->name");
		__type_of(&(le->le_object)) = NIS_NO_OBJ;
		le->le_object.zo_name = "";
		le->le_object.zo_owner = "";
		le->le_object.zo_group = "";
		le->le_object.zo_domain = le->le_name;
		res->lr_entries.lr_entries_len = 1;
		res->lr_entries.lr_entries_val = le;
	}

	if ((mtdumparg = calloc(1, sizeof (*mtdumparg))) == 0) {
		syslog(LOG_WARNING,
			"nis_dump_svc: memory allocation failed for %d bytes",
			sizeof (*mtdumparg));
		res->lr_status = NIS_NOMEMORY;
		auth_destroy(cback->cl_auth);
		clnt_destroy(cback);
		return (res);
	}
	(void) strcpy(mtdumparg->da_dir, argp->da_dir);
	(void) strcpy(mtdumparg->pname, pname);
	mtdumparg->cback = cback;
	mtdumparg->ttime = ttime;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if ((stat = pthread_create(&tid, &attr, dumpsvc_thread, mtdumparg)) ==
		0) {
		if (verbose)
			syslog(LOG_INFO,
			"nis_dump_svc: created callback thread %d", tid);
		res->lr_status = NIS_CBRESULTS;
		res->lr_cookie.n_bytes = (char *)malloc(sizeof (anonid_t));
		if (res->lr_cookie.n_bytes != NULL) {
			add_cleanup((void (*)())XFREE, res->lr_cookie.n_bytes,
					"anonid");
			res->lr_cookie.n_len = sizeof (anonid_t);
			memcpy(res->lr_cookie.n_bytes, &tid,
				sizeof (anonid_t));
		} else {
			res->lr_cookie.n_len = 0;
			syslog(LOG_WARNING,
			"nis_dump_svc: no memory for callback id cookie");
		}
		if (verbose)
			syslog(LOG_INFO,
				"nis_dump_svc: Parent thread returning");
	} else {
		if (verbose)
			syslog(LOG_ERR,
			"nis_dump_svc: callback thread create failed: %d",
			stat);
		auth_destroy(cback->cl_auth);
		clnt_destroy(cback);
		res->lr_status = NIS_TRYAGAIN;
	}
	(void) pthread_attr_destroy(&attr);
	return (res);
}

/*
 * nis_ping()
 *
 * This function receives a "ping" and schedules an update session.
 */
void *
nis_ping_svc(argp, reqstp)
	ping_args 	*argp;
	struct svc_req 	*reqstp;
{
	static int	foo;
	struct ticks	t;
	nis_object	*obj;
	nis_error	err;

	if (verbose)
		syslog(LOG_INFO, "PING_SVC: dir = '%s'", argp->dir);

	if (!nis_op_access("NIS_PING", 0, argp->dir, 0, reqstp)) {
		if (verbose)
			syslog(LOG_INFO,
		"PING_SVC: unauthorized ping for \"%s\" ignored", argp->dir);
		return (0);
	}

	/* Check to see if we're replicating the root object */
	if (root_object_p(argp->dir)) {
		/*
		 * Note that we cannot check whether we have the root object
		 * because this ping might be asking to add me as replica
		 */
		err = NIS_SUCCESS;
		if (last_update(argp->dir) < argp->stamp)
			add_pingitem_with_name(argp->dir,
						0, argp->stamp, &upd_list);
	} else {
		err = __directory_object(argp->dir, &t, NO_CACHE, &obj);
		if ((err == NIS_SUCCESS) && (obj != NULL) &&
		    (last_update(argp->dir) < argp->stamp))
			add_pingitem(obj, argp->stamp, &upd_list);
	}

	if ((verbose) && (err != NIS_SUCCESS))
		syslog(LOG_INFO, "PING_SVC: error %s.", nis_sperrno(err));
	else if (verbose)
		syslog(LOG_INFO, "PING_SVC: done.");

	/*
	 * The non-MT code would have tried to execute the resync
	 * immediately. In order to preserve those semantics, we wake
	 * up the servloop() thread now.
	 */
	wakeup_servloop();

	return (&foo);
}

#define	TAG_VAL(n)	argp->tags.tags_val[n].tag_val
#define	TAG_TYPE(n)	argp->tags.tags_val[n].tag_type
#define	CHECK_TAG_ACC(tag) \
			if (!nis_op_access("NIS_SERVSTATE", tag, 0, 0, \
						reqstp)) { \
				free(TAG_VAL(i)); \
				TAG_VAL(i) = strdup("<permission denied>"); \
				break; \
			}

/*
 * This function allows the client to change various "state"
 * bits in the server. The primary uses are to turn verbosity
 * on and off, and to turn statistics on and off.
 */
nis_taglist *
nis_servstate_svc(argp, reqstp)
	nis_taglist	*argp;
	struct svc_req	*reqstp;
{
	int	i;

	if (verbose)
		syslog(LOG_INFO, "SERVSTATE_SVC: %d tags.",
			argp->tags.tags_len);

	if (argp->tags.tags_len > 0) {
		for (i = 0; i < argp->tags.tags_len; i++) {
			switch (TAG_TYPE(i)) {
			case TAG_DEBUG :
				CHECK_TAG_ACC("TAG_DEBUG");
				if (strcmp(TAG_VAL(i), "on") == 0)
					verbose = 1;
				else if (strcmp(TAG_VAL(i), "off") == 0)
					verbose = 0;
				else {
					free(TAG_VAL(i));
					TAG_VAL(i) = strdup("unchanged");
				}
				break;
			case TAG_DCACHE_ONE:
				CHECK_TAG_ACC("TAG_DCACHE_ONE");
				if (TAG_VAL(i) && strlen(TAG_VAL(i))) {
					flush_dircache(TAG_VAL(i), NULL);
				} else {
					free(TAG_VAL(i));
					TAG_VAL(i) = strdup("Name missing");
				}
				break;
			case TAG_DCACHE_ONE_REFRESH:
				CHECK_TAG_ACC("TAG_DCACHE_ONE_REFRESH");
				if (TAG_VAL(i) && strlen(TAG_VAL(i))) {
					flush_dircache_refresh(TAG_VAL(i));
				} else {
					free(TAG_VAL(i));
					TAG_VAL(i) = strdup("Name missing");
				}
				break;
			case TAG_DCACHE_ALL:
				/* This flushes _all_ directory objects */
				CHECK_TAG_ACC("TAG_DCACHE_ALL");
				flush_dircache_all();
				break;
			case TAG_TCACHE_ONE :
				CHECK_TAG_ACC("TAG_TCACHE_ONE");
				if (TAG_VAL(i) && strlen(TAG_VAL(i))) {
					flush_tablecache(TAG_VAL(i));
				} else {
					free(TAG_VAL(i));
					TAG_VAL(i) = strdup("Name missing");
				}
				break;
			case TAG_TCACHE_ALL:
				/* This flushes _all_ table caches */
				CHECK_TAG_ACC("TAG_TCACHE_ALL");
				flush_tablecache_all();
				break;
			case TAG_GCACHE_ONE :
				CHECK_TAG_ACC("TAG_GCACHE_ONE");
				if (TAG_VAL(i) && strlen(TAG_VAL(i))) {
					flush_groupcache(TAG_VAL(i));
				} else {
					free(TAG_VAL(i));
					TAG_VAL(i) = strdup("Name missing");
				}
				break;
			case TAG_GCACHE_ALL :
				CHECK_TAG_ACC("TAG_GCACHE_ALL");
				flush_groupcache_all();
				break;
			case TAG_HEAP :
				CHECK_TAG_ACC("TAG_HEAP");
#ifdef MEM_DEBUG
				xdump();
#else  /* MEM_DEBUG */
				TAG_VAL(i) = strdup("<Not enabled>");
#endif /* MEM_DEBUG */
				break;
			case TAG_READONLY:
				/* Disables updates, used for nisbackup(1M) */
				CHECK_TAG_ACC("TAG_READONLY");
				if ((CHILDPROC) || (readonly)) {
					TAG_VAL(i) = strdup("Try again");
					break;
				}
				readonly = 1;
				break;
			case TAG_READWRITE:
				/* Reset to read/write, used by nisbackup(1M) */
				CHECK_TAG_ACC("TAG_READWRITE");
				if ((CHILDPROC) || (readonly == 0)) {
					TAG_VAL(i) = strdup("Invalid request");
					break;
				}
				readonly = 0;
				break;

			default :
				syslog(LOG_INFO, "Unknown tag %d",
					TAG_TYPE(i));
				TAG_VAL(i) = strdup("<Unknown tag>");
				break;
			}
		}
	}
	return (argp);
}

extern table_obj tbl_prototype;

/*
 * nis_mkdir_svc()
 *
 * This function allows a client to "make" a directory table remotely.
 * The purpose of this function is to allow for the addition of NIS+
 * directories by an application rather than by hand. See the companion
 * function below, nis_rmdir_svc(). Note: It _depends_ on the fact that
 * if the directory object exists, and this server is included as one
 * of the valid servers, then it is allowed to create the directory.
 * This means that if the addition of the directory object to the namespace
 * is managed, the subsequent creation of the table will just follow along.
 * It also means that if your namespace is compromised you could create
 * a bogus directory. During that time you can run in "max-secure" mode
 * which disables both the make and remove directory functions.
 */
nis_error *
nis_mkdir_svc(argp, rqstp)
	nis_name	*argp;
	struct svc_req	*rqstp;
{
#define	result		(__nis_get_tsd()->nis_mkdir_svc_result)
	directory_obj		*da;
	nis_object		*obj;
	nis_result		*res;
	int			i;
	time_t			ttime;
	nis_server		*srvs;
	nis_name		s;
	name_pos		p;


	/* Go look for the object for this new directory. */
	if (verbose)
		syslog(LOG_INFO, "MKDIR_SVC : Creating directory : %s", *argp);

	if (readonly) {
		syslog(LOG_INFO,
		"nis_mkdir_svc: readonly child called to mkdir, ignored.");
		result = NIS_TRYAGAIN;
		return (&result);
	}

	/* Check NIS_MKDIR access to parent directory */
	if (!nis_op_access("NIS_MKDIR", 0, nis_domain_of(*argp), 0, rqstp)) {
		if (verbose)
			syslog(LOG_INFO,
			"MKDIR_SVC : authorization error on \"%s\"",
				nis_domain_of(*argp));
		result = NIS_PERMISSION;
		return (&result);
	}

	/*
	 * We see if we can find the directory object for the directory
	 * that we are "making". If not then we abort.
	 * NOTE: The nis_lookup should recurse to our local version of
	 * __nis_core_lookup.
	 */
	res = nis_lookup(*argp, MASTER_ONLY);
	/* Schedule this to be cleaned up when we return */
	add_cleanup(nis_freeresult, (char *)res, "mkdir lookup res");
	result = res->status;
	if (result != NIS_SUCCESS) {
		if (verbose)
			syslog(LOG_WARNING,
	    "nis_mkdir_svc: could not get the directory object for %s: %s",
				*argp, nis_sperrno(result));
		return (&result);
	}

	obj = res->objects.objects_val;
	/*
	 * Now we either have an object that is a directory object or
	 * we don't.
	 */
	if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
		result = NIS_BADOBJECT;
		syslog(LOG_ERR, "nis_mkdir_svc: %s is not a directory object",
			*argp);
		return (&result);
	}

	/*
	 * verify that we serve it.
	 */
	da = &(obj->DI_data);
	s = nis_local_host(); /* optimization */
	srvs = da->do_servers.do_servers_val;
	for (i = 0; i < da->do_servers.do_servers_len; i++) {
		if (nis_dir_cmp(srvs[i].name, s) == SAME_NAME)
			break;
	}

	if (i == da->do_servers.do_servers_len) {
		syslog(LOG_ERR,
	"nis_mkdir_svc: Attempt to add a directory %s which we don't serve!",
								*argp);
		result = NIS_NOT_ME;
		return (&result);
	}

	p = nis_dir_cmp(*argp, __nis_rpc_domain());
	if (p != LOWER_NAME) {
		syslog(LOG_ERR,
		    "nis_mkdir_svc: Attempt to create illegal directory %s",
									*argp);
		result = NIS_BADNAME;
		return (&result);
	}

	/*
	 * Now we check to see if we can read anything out of the
	 * directories database.
	 */
	result = db_find_table(*argp);
	if (result == NIS_NOSUCHTABLE) {
		if ((result = db_create(*argp, &tbl_prototype)) !=
		    NIS_SUCCESS) {
			syslog(LOG_ERR, "Unable to create table %s: %s.",
				*argp, nis_sperrno(result));
			return (&result);
		}
		/* Give it a stability timestamp. */
		ttime = time(0);
		make_stamp(*argp, ttime);
		/* Add it to the list of directories that it serves */
		nis_server_control(SERVING_LIST, DIR_ADD, *argp);
	}
	if (verbose)
		syslog(LOG_INFO, "Successful creation.");

	return (&result);
}

#undef	result

/*
 * nis_rmdir_svc()
 *
 * This is the opposite of mkdir. It will iterate through a directory
 * removing all tables in that directory, and then remove the directory
 * itself. Beware recursing on yourself, since if this function makes
 * a request to this server you will deadlock.
 *
 * Note, rmdir is a little weird. If we are removing the directory
 * completely, (i.e out of the name space) then there won't be a
 * directory object to verify it. The easy case is if we are just
 * getting dropped of the list of servers that serve it.
 */
nis_error *
nis_rmdir_svc(argp, rqstp)
	nis_name	*argp;
	struct svc_req	*rqstp;
{
#define	result		(__nis_get_tsd()->nis_rmdir_svc_result)
	directory_obj		*da;		/* Temp pointing to our data */
	int			i;		/* Loop counter		*/
	nis_name		s;		/* Another temporary	*/
	nis_server		*srvs;		/* Another temporary	*/
	nis_result		*res;		/* Result of nis lookup	*/
	nis_object		*obj;		/* object temporary	*/
	nis_db_result		*dbres,		/* Result db lookup	*/
				*rrs;		/* From removing entries */
	nis_fn_result		*fnr,		/* Result of iteration	*/
				*tlist;
	char			namebuf[1024];	/* buffer where we cons name */
	nis_error		error;
	int			xid;
	int			complete_removal = 1;
	char			*principal = 0;

	/* Go look for the object for this new directory. */
	if (verbose)
		syslog(LOG_INFO, "RMDIR_SVC : Removing directory : %s", *argp);

	if (readonly) {
		syslog(LOG_INFO,
		"nis_rmdir_svc: readonly child called to rmdir, ignored.");
		result = NIS_TRYAGAIN;
		return (&result);
	}

	/*
	 * If 'rqstp' is NULL, we've been called internally, and supply the
	 * local principal.
	 */
	if (rqstp == 0)
		principal = nis_local_principal();

	/* Check NIS_RMDIR access to directory */
	if (!nis_op_access("NIS_RMDIR", 0, *argp, principal, rqstp)) {
		if (verbose)
			syslog(LOG_INFO,
			"RMDIR_SVC : authorization error on \"%s\"", *argp);
		result = NIS_PERMISSION;
		return (&result);
	}

	/*
	 * First we get the directory object. If it doesn't exist we consider
	 * that to be an ok error since we could have been its only server etc.
	 */
	res = nis_lookup(*argp, MASTER_ONLY);

	/* schedule a cleanup of these results */
	result = res->status;
	obj = res->objects.objects_val;

	if ((result != NIS_SUCCESS) && (result != NIS_NOTFOUND))
		return (&result);

	/*
	 * Now determine whether or not the object we lookup up is a
	 * directory and that we no longer serve it.
	 */
	if (res->status == NIS_SUCCESS) {
		if (__type_of(obj) != NIS_DIRECTORY_OBJ) {
			result = NIS_BADOBJECT;
			return (&result);
		}

		da = &(obj->DI_data);
		s = nis_local_host(); /* optimization */
		srvs = da->do_servers.do_servers_val;
		for (i = 0; i < da->do_servers.do_servers_len; i++) {
			if (nis_dir_cmp(srvs[i].name, s) == SAME_NAME) {
				syslog(LOG_ERR,
	"nis_rmdir_svc: Attempt to remove directory %s which we still serve!",
									*argp);
				result = NIS_NOT_ME;
				return (&result);
			}
		}
		/*
		 * A complete directory removal works by first removing the
		 * directory object from the name space and then doing
		 * individual 'rmdir' operations on each server.
		 *
		 * If directory object still exists, that means we are not
		 * doing a complete removal and hence cannot be its master.
		 *
		 * If directory object does not exist, we act as if we are
		 * master (because we cannot tell without the directory obj)
		 * and abort the removal if it contains subdirectories.
		 * Continuing with the removal in that case would leave
		 * the subdirectories orphaned and inaccessible.
		 *
		 * Note that we cannot tell if it is a replica trying
		 * to clean up after the directory has already been removed
		 * earlier, or it is doing a rmdir at the time or the remove.
		 */
		complete_removal = 0;
	}

	/*
	 * Now, we definitely know that the directory needs to be deleted.
	 * So we attempt the actual removal of the directory. We wish to remove
	 * every object and all tables in the directory. To accomplish this
	 * we need to iterate over the entire contents. This is accomplished
	 * by calling db_firstib() and if the object returned is a table, we
	 * delete the table contents. The entire operation is bracketed in
	 * a transaction to allow us to abort it if something goes wrong.
	 */
	fnr = db_firstib(*argp, 0, NULL,
			FN_NORAGS+FN_NOMANGLE+FN_NOERROR, NULL);
	result = NIS_SUCCESS;
	if (fnr->status == NIS_NOSUCHTABLE) {
		XFREE(fnr);
		return (&result);
	} else if (fnr->status == NIS_NOTFOUND) {
		/* table is empty */
		if ((result = db_destroy(*argp)) != NIS_SUCCESS) {
			syslog(LOG_WARNING,
		"nis_rmdir_svc: Could not remove directory table %s: %s.",
				*argp, nis_sperrno(result));
			result = NIS_S_SUCCESS;
		}
		make_stamp(*argp, 0); /* Make a tombstone. */
		XFREE(fnr);
		rmdir_update(*argp);
		return (&result);
	} else if (fnr->status != NIS_SUCCESS) {
		result = fnr->status;
		XFREE(fnr);
		return (&result);
	}
	error = NIS_SUCCESS;
	xid = begin_transaction(nis_local_principal());
	if (! xid) {
		XFREE(fnr->cookie.n_bytes);
		nis_destroy_object(fnr->obj);
		XFREE(fnr);
		result = NIS_TRYAGAIN;
		return (&result);
	}
	while (fnr->status == NIS_SUCCESS) {
		sprintf(namebuf, "%s.%s", fnr->obj->zo_name,
							fnr->obj->zo_domain);
		/*
		 * If we are getting rid of a directory with subdirectories,
		 * abort.
		 */
		if (__type_of(fnr->obj) == NIS_DIRECTORY_OBJ &&
						complete_removal) {
				error = NIS_NOTEMPTY;
				break;
		}
		if (__type_of(fnr->obj) == NIS_TABLE_OBJ) {
			tlist = db_firstib(namebuf, 0, NULL,
						FN_NORAGS+FN_NOERROR, NULL);
			while (tlist->status == NIS_SUCCESS) {
				struct obj_list	ol;

				ol.o = tlist->obj;
				ol.r = 1;
				/* free this since we won't be using it */
				rrs = db_remib(namebuf, 0, NULL, &ol, 1,
						fnr->obj, (ulong_t)time(0));
				if (rrs->status != NIS_SUCCESS) {
					error = NIS_FAIL;
					break;
				}
				/*
				 * Note : We call firstib again, rather than
				 *	  calling nextib because our removing
				 *	  the entry may have screwed up the
				 *	  internal database ptrs. db_firstib()
				 *	  always works.
				 */
				XFREE(tlist->cookie.n_bytes);
				nis_destroy_object(tlist->obj);
				XFREE(tlist);
				tlist = db_firstib(namebuf, 0, NULL,
						    FN_NORAGS+FN_NOERROR, NULL);
			}
			if (tlist->status == NIS_SUCCESS) {
				XFREE(tlist->cookie.n_bytes);
				nis_destroy_object(tlist->obj);
			}
			if (tlist->status != NIS_NOTFOUND)
				error = NIS_FAIL;
			XFREE(tlist);
		}
		if (error != NIS_SUCCESS)
			break;
		/* This remove will also destroy the table */
		dbres = db_remove(namebuf, fnr->obj, (ulong_t)time(0));
		if (dbres->status != NIS_SUCCESS) {
			error = dbres->status;
			break;
		}
		/* free this because we aren't going to call nextib */
		XFREE(fnr->cookie.n_bytes);
		nis_destroy_object(fnr->obj);
		XFREE(fnr);
		fnr = db_firstib(*argp, 0, NULL, FN_NORAGS+FN_NOERROR, NULL);
	}
	if (fnr->status == NIS_SUCCESS) {
		XFREE(fnr->cookie.n_bytes);
		nis_destroy_object(fnr->obj);
	}
	if (error != NIS_SUCCESS) {
		syslog(LOG_ERR,
		"nis_rmdir_svc: Could not remove directory table %s: %s.",
				*argp, nis_sperrno(error));
		abort_transaction(xid);
		result = error;
	} else {
		end_transaction(xid);
		if ((result = db_destroy(*argp)) != NIS_SUCCESS) {
			syslog(LOG_WARNING,
		"nis_rmdir_svc: Could not remove directory table %s: %s.",
				*argp, nis_sperrno(result));
			result = NIS_S_SUCCESS;
		}
		make_stamp(*argp, 0); /* Make a tombstone. */
		rmdir_update(*argp);
	}

	XFREE(fnr);
	return (&result);
}

#undef	result

/*
 *  If we serve the parent directory or the directory is
 *  the root, then do an update of that directory so that
 *  we see the change to the parent directory or root
 *  object.  If we don't do this, then we will continue
 *  to see the removed directory in the database until
 *  the master server pings us.
 */
static
void
rmdir_update(name)
	char *name;
{
	nis_server *srv;
	nis_object *rootobj = get_root_object();
	nis_object *d_obj = NULL;
	nis_result *lres = NULL;
	char *parent = nis_domain_of(name);

	if (rootobj &&
		nis_dir_cmp(rootobj->DI_data.do_name, name) == SAME_NAME) {
			parent = name;
			d_obj = rootobj;
	} else if (parent) {
		lres = nis_lookup(parent, MASTER_ONLY);
		if (lres && lres->status == NIS_SUCCESS) {
			d_obj = lres->objects.objects_val;
			if (__type_of(d_obj) != DIRECTORY_OBJ)
				d_obj = NULL;
		}
	}

	/* if we can't get the directory object, we can't do an update */
	if (d_obj == NULL)
		goto skip_update;

	/*
	 *  If we are running on the master server, or if we don't
	 *  serve the parent directory, then skip the update.
	 */
	srv = &d_obj->DI_data.do_servers.do_servers_val[0];
	if (nis_dir_cmp(srv->name, nis_local_host()) == SAME_NAME ||
	    nis_server_control(SERVING_LIST, DIR_SERVED, parent) == 0)
		goto skip_update;

	/*
	 *  If we get here, then we are a replica and we need to update
	 *  the parent directory.
	 */
	if (d_obj == rootobj) {
		/*
		 *  Updating root object.
		 */
		root_replica_update();
	} else {
		/*
		 *  Use a very large timestamp to force an
		 *  update to the directory.
		 */
		add_pingitem_with_name(parent, d_obj, 0xffffffff, &upd_list);
	}

skip_update:
	if (rootobj)
		nis_destroy_object(rootobj);
	if (lres)
		nis_freeresult(lres);

	/* Delete name from the list of directories that we serve */
	nis_server_control(SERVING_LIST, DIR_DELETE, name);
}
