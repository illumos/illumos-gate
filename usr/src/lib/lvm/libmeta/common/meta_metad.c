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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#include <meta.h>
#include <metad.h>
#include <devid.h>

static md_setkey_t	*my_cl_sk = NULL;

#define	CL_DEF_TMO	30L

/*
 * Convert an old style mddrivename_t into a new style
 * mddrivename_t. Meant to be used *ONLY* by rpc.metad
 */
void
meta_conv_drvname_old2new(
	o_mddrivename_t		*v1_dp,
	mddrivename_t		*v2_dp
)
{
	int 		sliceno;
	o_mdname_t	*v1_np;
	mdname_t	*v2_np;

	/* fields that haven't changed */
	v2_dp->cname   = v1_dp->cname;
	v2_dp->rname   = v1_dp->rname;
	v2_dp->type    = v1_dp->type;
	v2_dp->errnum  = v1_dp->errnum;

	/* geometry information */
	v2_dp->geom.ncyl  = v1_dp->geom.ncyl;
	v2_dp->geom.nhead = v1_dp->geom.nhead;
	v2_dp->geom.nsect = v1_dp->geom.nsect;
	v2_dp->geom.rpm   = v1_dp->geom.rpm;
	v2_dp->geom.write_reinstruct = v1_dp->geom.write_reinstruct;
	v2_dp->geom.read_reinstruct  = v1_dp->geom.read_reinstruct;
	v2_dp->geom.blk_sz = 0;

	/* controller information */
	v2_dp->cinfo = v1_dp->cinfo;

	/* vtoc information */
	v2_dp->vtoc.nparts    = v1_dp->vtoc.nparts;
	v2_dp->vtoc.first_lba = 0;
	v2_dp->vtoc.last_lba  = 0;
	v2_dp->vtoc.lbasize   = 0;

	for (sliceno = 0; sliceno < (MD_MAX_PARTS - 1); sliceno++) {
		v2_dp->vtoc.parts[sliceno].start =
		    (diskaddr_t)v1_dp->vtoc.parts[sliceno].start;
		v2_dp->vtoc.parts[sliceno].size =
		    (diskaddr_t)v1_dp->vtoc.parts[sliceno].size;
		v2_dp->vtoc.parts[sliceno].tag =
		    v1_dp->vtoc.parts[sliceno].tag;
		v2_dp->vtoc.parts[sliceno].flag =
		    v1_dp->vtoc.parts[sliceno].flag;
		v2_dp->vtoc.parts[sliceno].label =
		    (diskaddr_t)v1_dp->vtoc.parts[sliceno].label;
	}

	/* The new style vtoc has 17 partitions */
	v2_dp->vtoc.parts[MD_MAX_PARTS - 1].start = 0;
	v2_dp->vtoc.parts[MD_MAX_PARTS - 1].size  = 0;
	v2_dp->vtoc.parts[MD_MAX_PARTS - 1].tag   = 0;
	v2_dp->vtoc.parts[MD_MAX_PARTS - 1].flag  = 0;
	v2_dp->vtoc.parts[MD_MAX_PARTS - 1].label = 0;

	v2_dp->vtoc.typename = v1_dp->vtoc.typename;

	/* partition information */
	v2_dp->parts.parts_len = v1_dp->parts.parts_len;
	for (sliceno = 0; sliceno < v1_dp->parts.parts_len; sliceno++) {
		v1_np = &v1_dp->parts.parts_val[sliceno];
		v2_np = &v2_dp->parts.parts_val[sliceno];

		/*
		 * We speculate that if cname for a particular
		 * partition does not exist, the other fields
		 * don't exist either. In such a case, we don't
		 * need to do anything for that partition.
		 */
		if (v1_np->cname != NULL) {
			v2_np->cname = v1_np->cname;
			v2_np->bname = v1_np->bname;
			v2_np->rname = v1_np->rname;
			v2_np->devicesname = v1_np->devicesname;
			v2_np->dev = meta_expldev(v1_np->dev);
			v2_np->key = v1_np->key;
			v2_np->end_blk = (diskaddr_t)v1_np->end_blk;
			v2_np->start_blk = (diskaddr_t)v1_np->start_blk;
		}
		v2_np->drivenamep = v2_dp;
	}

	/* We don't care about the rest of the fields */
	v2_dp->side_names = v1_dp->side_names;
	v2_dp->side_names_key = v1_dp->side_names_key;
	v2_dp->miscname = v1_dp->miscname;
}

/*
 * Convert a new style mddrivename_t into an old style
 * mddrivename_t. Meant to be used *ONLY* by rpc.metad
 */
void
meta_conv_drvname_new2old(
	o_mddrivename_t		*v1_dp,
	mddrivename_t		*v2_dp
)
{
	int 		sliceno;
	o_mdname_t	*v1_np;
	mdname_t	*v2_np;

	/* fields that haven't changed */
	v1_dp->cname   = v2_dp->cname;
	v1_dp->rname   = v2_dp->rname;
	v1_dp->type    = v2_dp->type;
	v1_dp->errnum  = v2_dp->errnum;

	/* geometry information */
	v1_dp->geom.ncyl  = v2_dp->geom.ncyl;
	v1_dp->geom.nhead = v2_dp->geom.nhead;
	v1_dp->geom.nsect = v2_dp->geom.nsect;
	v1_dp->geom.rpm   = v2_dp->geom.rpm;
	v1_dp->geom.write_reinstruct = v2_dp->geom.write_reinstruct;
	v1_dp->geom.read_reinstruct  = v2_dp->geom.read_reinstruct;

	/* controller information */
	v1_dp->cinfo = v2_dp->cinfo;

	/* vtoc information */
	v1_dp->vtoc.typename = v2_dp->vtoc.typename;
	v1_dp->vtoc.nparts   = v2_dp->vtoc.nparts;

	for (sliceno = 0; sliceno < (MD_MAX_PARTS - 1); sliceno++) {
		v1_dp->vtoc.parts[sliceno].start =
		    (daddr_t)v2_dp->vtoc.parts[sliceno].start;
		v1_dp->vtoc.parts[sliceno].size  =
		    (daddr_t)v2_dp->vtoc.parts[sliceno].size;
		v1_dp->vtoc.parts[sliceno].tag   =
		    v2_dp->vtoc.parts[sliceno].tag;
		v1_dp->vtoc.parts[sliceno].flag  =
		    v2_dp->vtoc.parts[sliceno].flag;
		v1_dp->vtoc.parts[sliceno].label =
		    (daddr_t)v2_dp->vtoc.parts[sliceno].label;
	}

	/* partition information */
	v1_dp->parts.parts_len = v2_dp->parts.parts_len;

	for (sliceno = 0; sliceno < v2_dp->parts.parts_len; sliceno++) {
		v1_np = &v1_dp->parts.parts_val[sliceno];
		v2_np = &v2_dp->parts.parts_val[sliceno];

		/*
		 * We speculate that if cname for a particular
		 * partition does not exist then the rest of
		 * the fields a partition don't exist either.
		 * In such a case, we don't need to do anything
		 * for that partition.
		 */
		if (v2_np->cname != NULL) {
			v1_np->cname = v2_np->cname;
			v1_np->bname = v2_np->bname;
			v1_np->rname = v2_np->rname;
			v1_np->devicesname = v2_np->devicesname;
			v1_np->dev = meta_cmpldev(v2_np->dev);
			v1_np->key = v2_np->key;
			v1_np->end_blk = (daddr_t)v2_np->end_blk;
			v1_np->start_blk = (daddr_t)v2_np->start_blk;
		}
		v1_np->drivenamep = v1_dp;
	}

	/* We don't care about the rest of the fields */
	v1_dp->side_names = v2_dp->side_names;
	v1_dp->side_names_key = v2_dp->side_names_key;
	v1_dp->miscname = v2_dp->miscname;
}

/*
 * Convert an old style md_drive_desc_t into a new style
 * md_drive_desc_t. Meant to be used *ONLY* by rpc.metad
 */
void
meta_conv_drvdesc_old2new(
	o_md_drive_desc		*v1_dd,
	md_drive_desc		*v2_dd
)
{
	md_drive_desc	*dd;
	o_md_drive_desc	*o_dd;

	dd = v2_dd;

	for (o_dd = v1_dd; o_dd != NULL; o_dd = o_dd->dd_next) {
		dd->dd_ctime = o_dd->dd_ctime;
		dd->dd_genid = o_dd->dd_genid;
		dd->dd_flags = o_dd->dd_flags;
		meta_conv_drvname_old2new(o_dd->dd_dnp, dd->dd_dnp);
		dd->dd_dbcnt = o_dd->dd_dbcnt;
		dd->dd_dbsize = o_dd->dd_dbsize;
		dd = dd->dd_next;
	}
}

/*
 * Convert an new style md_drive_desc_t into a old style
 * md_drive_desc_t. Meant to be used *ONLY* by rpc.metad
 */
void
meta_conv_drvdesc_new2old(
	o_md_drive_desc		*v1_dd,
	md_drive_desc		*v2_dd
)
{
	md_drive_desc	*dd;
	o_md_drive_desc	*o_dd;

	o_dd = v1_dd;

	for (dd = v2_dd; dd != NULL; dd = dd->dd_next) {
		o_dd->dd_ctime = dd->dd_ctime;
		o_dd->dd_genid = dd->dd_genid;
		o_dd->dd_flags = dd->dd_flags;
		meta_conv_drvname_new2old(o_dd->dd_dnp, dd->dd_dnp);
		o_dd->dd_dbcnt = dd->dd_dbcnt;
		o_dd->dd_dbsize = dd->dd_dbsize;
		o_dd = o_dd->dd_next;
	}
}

/*
 * Allocate memory for v1 drive descriptor
 * depending upon the number of drives in the
 * v2 drive descriptor
 */
void
alloc_olddrvdesc(
	o_md_drive_desc		**v1_dd,
	md_drive_desc		*v2_dd
)
{
	md_drive_desc	*dd;
	o_md_drive_desc *new, *head;

	head = NULL;

	for (dd = v2_dd; dd != NULL; dd = dd->dd_next) {
		new = Zalloc(sizeof (o_md_drive_desc));
		new->dd_dnp = Zalloc(sizeof (o_mddrivename_t));
		new->dd_dnp->parts.parts_val = Zalloc(sizeof (o_mdname_t) *
		    dd->dd_dnp->parts.parts_len);
		new->dd_next = head;
		head = new;
	}
	*v1_dd = head;
}

/*
 * Allocate memory for v2 drive descriptor
 * depending upon the number of drives in the
 * v1 drive descriptor
 */
void
alloc_newdrvdesc(
	o_md_drive_desc		*v1_dd,
	md_drive_desc		**v2_dd
)
{
	md_drive_desc	*new, *head;
	o_md_drive_desc	*o_dd;

	head = NULL;

	for (o_dd = v1_dd; o_dd != NULL; o_dd = o_dd->dd_next) {
		new = Zalloc(sizeof (md_drive_desc));
		new->dd_dnp = Zalloc(sizeof (mddrivename_t));
		new->dd_dnp->parts.parts_val = Zalloc(sizeof (mdname_t) *
		    o_dd->dd_dnp->parts.parts_len);
		new->dd_next = head;
		head = new;
	}
	*v2_dd = head;
}

void
free_olddrvdesc(
	o_md_drive_desc		*v1_dd
)
{
	o_md_drive_desc	*o_dd, *head;

	head = v1_dd;

	while (head != NULL) {
		o_dd = head;
		head = head->dd_next;
		free(o_dd->dd_dnp->parts.parts_val);
		free(o_dd->dd_dnp);
		free(o_dd);
	}
}

void
free_newdrvdesc(
	md_drive_desc		*v2_dd
)
{
	md_drive_desc	*dd, *head;

	head = v2_dd;

	while (head != NULL) {
		dd = head;
		head = head->dd_next;
		free(dd->dd_dnp->parts.parts_val);
		free(dd->dd_dnp);
		free(dd);
	}
}

/*
 * Return the device id for a given device
 */
char *
meta_get_devid(
	char	*rname
)
{
	ddi_devid_t	devid;
	int		fd;
	char		*enc_devid, *dup_enc_devid = NULL;

	if ((fd = open(rname, O_RDWR | O_NDELAY, 0)) < 0)
		return (NULL);

	if (devid_get(fd, &devid) == -1) {
		(void) close(fd);
		return (NULL);
	}
	(void) close(fd);

	enc_devid = devid_str_encode(devid, NULL);
	devid_free(devid);

	if (enc_devid != NULL) {
		dup_enc_devid = strdup(enc_devid);
		devid_str_free(enc_devid);
	}

	return (dup_enc_devid);
}

/*
 * Add side names for the diskset drive records
 * NOTE: these go into the local set's namespace.
 */
int
clnt_add_drv_sidenms(
	char			*hostname,
	char			*this_host,
	mdsetname_t		*sp,
	md_set_desc		*sd,
	int			node_c,
	char			**node_v,
	md_error_t		*ep
)
{
	CLIENT				*clntp;
	mdrpc_drv_sidenm_args		v1_args;
	mdrpc_drv_sidenm_2_args		v2_args;
	mdrpc_drv_sidenm_2_args_r1	*v21_args;
	mdrpc_generic_res		res;
	int				rval;
	int				version;
	int				i, j;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_drv_sidenm_2_args_u.rev1;
	v21_args->hostname = this_host;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->sp = sp;
	v21_args->sd = sd;
	v21_args->node_v.node_v_len = node_c;
	v21_args->node_v.node_v_val = node_v;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_add_drv_sidenms_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */

			v1_args.sd = Zalloc(sizeof (o_md_set_desc));
			alloc_olddrvdesc(&v1_args.sd->sd_drvs, sd->sd_drvs);

			/* build args */
			v1_args.hostname = this_host;
			v1_args.cl_sk = cl_get_setkey(sp->setno, sp->setname);
			v1_args.sp = sp;
			/* set descriptor */
			v1_args.sd->sd_ctime = sd->sd_ctime;
			v1_args.sd->sd_genid = sd->sd_genid;
			v1_args.sd->sd_setno = sd->sd_setno;
			v1_args.sd->sd_flags = sd->sd_flags;
			for (i = 0; i < MD_MAXSIDES; i++) {
				v1_args.sd->sd_isown[i] = sd->sd_isown[i];

				for (j = 0; j < MD_MAX_NODENAME_PLUS_1; j ++)
					v1_args.sd->sd_nodes[i][j] =
					    sd->sd_nodes[i][j];
			}
			v1_args.sd->sd_med = sd->sd_med;
			meta_conv_drvdesc_new2old(v1_args.sd->sd_drvs,
			    sd->sd_drvs);
			v1_args.node_v.node_v_len = node_c;
			v1_args.node_v.node_v_val = node_v;

			rval = mdrpc_add_drv_sidenms_1(&v1_args, &res, clntp);

			free_olddrvdesc(v1_args.sd->sd_drvs);
			free(v1_args.sd);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad add drive sidenames"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {			/* version 2 */
			rval = mdrpc_add_drv_sidenms_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad add drive sidenames"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Adding drives via metaimport to disksets. Some of the drives may
 * not be available so we need more information than the basic clnt_adddrvs
 * offers us.
 */
int
clnt_imp_adddrvs(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		*dd,
	md_timeval32_t		timestamp,
	ulong_t			genid,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_drives_2_args	v2_args;
	mdrpc_drives_2_args_r1	*v21_args;
	mdrpc_generic_res	res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_drives_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivedescs = dd;
	v21_args->timestamp = timestamp;
	v21_args->genid = genid;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v1 procedure
		 */
		bool = mdrpc_imp_adddrvs_2(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, NULL);
			metarpcclose(clntp);
			return (-1);
		} else {
			rval = mdrpc_imp_adddrvs_2(&v2_args, &res, clntp);
			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad imp add drives"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}


/*
 * Add drives to disksets.
 */
int
clnt_adddrvs(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		*dd,
	md_timeval32_t		timestamp,
	ulong_t			genid,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_drives_args	v1_args;
	mdrpc_drives_2_args	v2_args;
	mdrpc_drives_2_args_r1	*v21_args;
	mdrpc_generic_res	res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_drives_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivedescs = dd;
	v21_args->timestamp = timestamp;
	v21_args->genid = genid;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_adddrvs_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */

			alloc_olddrvdesc(&v1_args.drivedescs, dd);

			/* build args */
			v1_args.sp = sp;
			v1_args.cl_sk = cl_get_setkey(sp->setno, sp->setname);
			meta_conv_drvdesc_new2old(v1_args.drivedescs, dd);
			v1_args.timestamp = timestamp;
			v1_args.genid = genid;

			rval = mdrpc_adddrvs_1(&v1_args, &res, clntp);

			free_olddrvdesc(v1_args.drivedescs);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad add drives"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {			/* version 2 */
			rval = mdrpc_adddrvs_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad add drives"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Add hosts to disksets.
 */
int
clnt_addhosts(
	char			*hostname,
	mdsetname_t		*sp,
	int			node_c,
	char			**node_v,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_host_args		*args;
	mdrpc_host_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_host_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->hosts.hosts_len = node_c;
	args->hosts.hosts_val = node_v;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int bool;
		bool = mdrpc_addhosts_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version and invoke
		 * the appropriate version of the remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_addhosts_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad add hosts"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_addhosts_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad add hosts"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Create disksets.
 */
int
clnt_createset(
	char			*hostname,
	mdsetname_t		*sp,
	md_node_nm_arr_t	nodes,
	md_timeval32_t		timestamp,
	ulong_t			genid,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_createset_args	*args;
	mdrpc_createset_2_args	v2_args;
	mdrpc_generic_res	res;
	int			i;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_createset_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->timestamp = timestamp;
	args->genid = genid;
	for (i = 0; i < MD_MAXSIDES; i++)
		(void) strcpy(args->nodes[i], nodes[i]);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_createset_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version and invoke
		 * the appropriate version of the remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_createset_1(args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad create set"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_createset_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad create set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Create MN disksets.
 */
int
clnt_mncreateset(
	char			*hostname,
	mdsetname_t		*sp,
	md_mnnode_desc		*nodelist,
	md_timeval32_t		timestamp,
	ulong_t			genid,
	md_node_nm_t		master_nodenm,
	int			master_nodeid,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_mncreateset_args	*args;
	mdrpc_mncreateset_2_args v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_mncreateset_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->timestamp = timestamp;
	args->genid = genid;
	(void) strlcpy(args->master_nodenm, master_nodenm, MD_MAX_NODENAME);
	args->master_nodeid = master_nodeid;
	args->nodelist = nodelist;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_mncreateset_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_mncreateset_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad mncreate set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Join MN set
 */
int
clnt_joinset(
	char			*hostname,
	mdsetname_t		*sp,
	int			flags,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_flags_args	*args;
	mdrpc_sp_flags_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_flags_2_args_u.rev1;
	args->sp = sp;
	args->flags = flags;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_joinset_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_joinset_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad join set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Withdraw from MN set
 */
int
clnt_withdrawset(
	char			*hostname,
	mdsetname_t		*sp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_withdrawset_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_withdrawset_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad withdraw set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Delete side names for the diskset drive records
 * NOTE: these are removed from the local set's namespace.
 */
int
clnt_del_drv_sidenms(
	char			*hostname,
	mdsetname_t		*sp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_del_drv_sidenms_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		if (metaget_setdesc(sp, ep) == NULL) {
			if (! mdisok(ep))
				return (-1);
			mdclrerror(ep);
		}

		/*
		 * Check the client handle for the version and invoke
		 * the appropriate version of the remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_del_drv_sidenms_1(args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad delete drive sidenames"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_del_drv_sidenms_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad delete drive sidenames"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * delete drives from the set
 */
int
clnt_deldrvs(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		*dd,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_drives_args	v1_args;
	mdrpc_drives_2_args	v2_args;
	mdrpc_drives_2_args_r1	*v21_args;
	mdrpc_generic_res	res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_drives_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivedescs = dd;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_deldrvs_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */

			alloc_olddrvdesc(&v1_args.drivedescs, dd);

			/* build args */
			v1_args.sp = sp;
			v1_args.cl_sk = cl_get_setkey(sp->setno, sp->setname);
			meta_conv_drvdesc_new2old(v1_args.drivedescs, dd);

			rval = mdrpc_deldrvs_1(&v1_args, &res, clntp);

			free_olddrvdesc(v1_args.drivedescs);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad delete drives"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {			/* version 2 */
			rval = mdrpc_deldrvs_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad delete drives"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * delete host(s) from a set.
 */
int
clnt_delhosts(
	char			*hostname,
	mdsetname_t		*sp,
	int			node_c,
	char			**node_v,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_host_args		*args;
	mdrpc_host_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_host_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->hosts.hosts_len = node_c;
	args->hosts.hosts_val = node_v;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_delhosts_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_delhosts_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad delete hosts"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_delhosts_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad delete hosts"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Delete diskset.
 */
int
clnt_delset(
	char			*hostname,
	mdsetname_t		*sp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_delset_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_delset_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad delete set"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_delset_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad delete set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * return remote device info
 */
int
clnt_devinfo(
	char			*hostname,
	mdsetname_t		*sp,
	mddrivename_t		*dp,
	md_dev64_t		*ret_dev,
	time_t			*ret_timestamp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_devinfo_args	v1_args;
	mdrpc_devinfo_2_args	v2_args;
	mdrpc_devinfo_2_args_r1	*v21_args;
	mdrpc_devinfo_res	v1_res;
	mdrpc_devinfo_2_res	v2_res;
	int			rval, version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&v1_res,  0, sizeof (v1_res));
	(void) memset(&v2_res, 	0, sizeof (v2_res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_devinfo_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivenamep = dp;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure.
		 */
		bool = mdrpc_devinfo_2_svc(&v2_args, &v2_res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &v1_res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of
		 * the remote procedure.
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			v1_args.drivenamep =
			    Zalloc(sizeof (o_mddrivename_t));
			v1_args.drivenamep->parts.parts_val =
			    Zalloc((sizeof (o_mdname_t)) *
			    dp->parts.parts_len);

			/* build args */
			v1_args.sp = sp;
			v1_args.cl_sk = cl_get_setkey(sp->setno,
			    sp->setname);

			/*
			 * Convert v2 arguments to v1 arguments
			 * before sending over the wire.
			 */
			meta_conv_drvname_new2old(v1_args.drivenamep,
			    v21_args->drivenamep);

			rval = mdrpc_devinfo_1(&v1_args, &v1_res, clntp);

			free(v1_args.drivenamep->parts.parts_val);
			free(v1_args.drivenamep);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad device info"));
			else
				(void) mdstealerror(ep, &v1_res.status);
		} else {			/* version 2 */
			rval = mdrpc_devinfo_2(&v2_args, &v2_res, clntp);
			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad device info"));
			else
				(void) mdstealerror(ep, &v2_res.status);
		}

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_dev != NULL) {
			if (version == METAD_VERSION)
				*ret_dev = meta_expldev(v1_res.dev);
			else
				*ret_dev = v2_res.dev;
		}

		if (ret_timestamp != NULL) {
			if (version == METAD_VERSION)
				*ret_timestamp = v1_res.vtime;
			else
				*ret_timestamp = v2_res.vtime;
		}
	}

	if (version == METAD_VERSION)
		xdr_free(xdr_mdrpc_devinfo_res, (char *)&v1_res);
	else
		xdr_free(xdr_mdrpc_devinfo_2_res, (char *)&v2_res);

	return (rval);
}

/*
 * return remote device info
 */
int
clnt_devid(
	char			*hostname,
	mdsetname_t		*sp,
	mddrivename_t		*dp,
	char			**ret_encdevid,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_devid_args	*args;
	mdrpc_devid_2_args	v2_args;
	mdrpc_devid_res		res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_devid_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->drivenamep = dp;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure.
		 */
		bool = mdrpc_devid_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) {	/* version 1 */
			(void) mddserror(ep, MDE_DS_DRIVENOTONHOST, sp->setno,
			    hostname, dp->cname, sp->setname);
		} else {			/* version 2 */
			rval = mdrpc_devid_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
			    (void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad devid info"));
			else
			    (void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_encdevid != NULL)
			*ret_encdevid = strdup(res.enc_devid);

	}

	xdr_free(xdr_mdrpc_devid_res, (char *)&res);

	return (rval);
}

/*
 * Get the device information of a disk on a remote host. The information
 * retrieved is the device's name, the associated driver and the dev_t.
 * The lookup is performed by using the devid of the disk as this is
 * unique to the disk.  The device name on the originating node is passed
 * in.  If that devname is found when doing the devid to namelist translation
 * then that value is used to make the device names as consistent as possible
 * across the nodes.
 *
 * An attempt is made to retrieve this information by calling
 * mdrpc_devinfo_by_devid_name_2_svc.  Locally this call should always
 * succeed.  In the case where a call is made through a CLIENT handle,
 * it is possible that the function hasn't been implemented on the called
 * node.  If this is the case fall back to mdrpc_devinfo_by_devidstr_2_svc.
 *
 * Returns:
 * 	-1 	Error
 * 	ENOTSUP Operation not supported i.e. procedure not supported on
 * 		the remote node
 * 	0	Success
 */
int
clnt_devinfo_by_devid(
	char		*hostname,
	mdsetname_t	*sp,
	char		*devidstr,
	md_dev64_t	*ret_dev,
	char		*orig_devname,
	char		**ret_devname,
	char		**ret_driver,
	md_error_t	*ep
)
{
	CLIENT			*clntp;
	mdrpc_devidstr_args	devid_args;
	mdrpc_devid_name_args	*args;
	mdrpc_devid_name_2_args	v2_args;
	mdrpc_devinfo_2_res	res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_devid_name_2_args_u.rev1;
	args->enc_devid = devidstr;
	args->orig_devname = orig_devname;
	args->sp = sp;

	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * We are calling this locally so call the function
		 * directly.
		 */
		bool = mdrpc_devinfo_by_devid_name_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {

		/* open connection */
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL) {
			return (-1);
		}

		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) { /* Version 1 */
			metarpcclose(clntp);
			return (ENOTSUP);
		}

		rval = mdrpc_devinfo_by_devid_name_2(&v2_args, &res, clntp);

		if (rval != RPC_SUCCESS) {
			/* try falling back to devidstr_2_svc */
			(void) memset(&devid_args, 0, sizeof (devid_args));
			(void) memset(&res, 0, sizeof (res));

			devid_args.enc_devid = devidstr;
			devid_args.sp = sp;

			rval = mdrpc_devinfo_by_devid_2(
					&devid_args, &res, clntp);

			if (rval != RPC_SUCCESS) {
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad devinfo by devid"));
			} else {
				(void) mdstealerror(ep, &res.status);
			}
		} else {
			(void) mdstealerror(ep, &res.status);
		}
		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		rval = 0;
		if (ret_dev != NULL)
			*ret_dev = res.dev;

		if (ret_devname != NULL && res.devname != NULL)
			*ret_devname = Strdup(res.devname);

		if (ret_driver != NULL && res.drivername != NULL)
			*ret_driver = Strdup(res.drivername);
	}

	xdr_free(xdr_mdrpc_devinfo_2_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);

}


/*
 * return status of whether driver is used, mount
 */
int
clnt_drvused(
	char			*hostname,
	mdsetname_t		*sp,
	mddrivename_t		*dp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_drvused_args	v1_args;
	mdrpc_drvused_2_args	v2_args;
	mdrpc_drvused_2_args_r1	*v21_args;
	mdrpc_generic_res	res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_drvused_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivenamep = dp;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_drvused_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		/* open connection */
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			v1_args.drivenamep =
			    Zalloc(sizeof (o_mddrivename_t));
			v1_args.drivenamep->parts.parts_val =
			    Zalloc((sizeof (o_mdname_t)) *
			    dp->parts.parts_len);

			/* build args */
			v1_args.sp = sp;
			v1_args.cl_sk = cl_get_setkey(sp->setno, sp->setname);

			/* Convert v2 args to v1 args */
			meta_conv_drvname_new2old(v1_args.drivenamep,
			    v21_args->drivenamep);

			rval = mdrpc_drvused_1(&v1_args, &res, clntp);

			free(v1_args.drivenamep->parts.parts_val);
			free(v1_args.drivenamep);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad drive used"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {			/* version 2 */
			rval = mdrpc_drvused_2(&v2_args, &res, clntp);
			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad drive used"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

void
free_sr(md_set_record *sr)
{
	mdrpc_getset_res	res;
	mdrpc_mngetset_res	mnres;

	if (md_in_daemon)
		return;

	/*
	 * dummy up a result struct, to do a deep free of the (mn)sr.
	 * (A deep free means that the xdr_free code will free the
	 * linked list of drive records for the sr and will also free
	 * the linked list of node records for the mnsr.)
	 */
	if (MD_MNSET_REC(sr)) {
		(void) memset(&mnres, 0, sizeof (mnres));
		mnres.mnsr = (struct md_mnset_record *)sr;
		xdr_free(xdr_mdrpc_mngetset_res, (char *)&mnres);
	} else {
		(void) memset(&res, 0, sizeof (res));
		res.sr = sr;
		xdr_free(xdr_mdrpc_getset_res, (char *)&res);
	}
}

void
short_circuit_getset(
	mdrpc_getset_args	*args,
	mdrpc_getset_res	*res
)
{
	if (args->setname != NULL)
		res->sr = metad_getsetbyname(args->setname, &res->status);
	else
		res->sr = metad_getsetbynum(args->setno, &res->status);
}

void
short_circuit_mngetset(
	mdrpc_getset_args	*args,
	mdrpc_mngetset_res	*res
)
{
	md_set_record		*sr;
	if (args->setname != NULL)
		sr = metad_getsetbyname(args->setname, &res->status);
	else
		sr = metad_getsetbynum(args->setno, &res->status);

	if (MD_MNSET_REC(sr)) {
		res->mnsr = (struct md_mnset_record *)sr;
	} else {
		res->mnsr = NULL;
	}
}

static int
is_auto_take_set(char *setname, set_t setno)
{
	if (setname != NULL)
	    return (metad_isautotakebyname(setname));
	else
	    return (metad_isautotakebynum(setno));
}

/*
 * return the diskset record, and drive records.
 * If record is a MNdiskset record, then only the first md_set_record
 * bytes were copied from the daemon.
 */
int
clnt_getset(
	char			*hostname,
	char			*setname,
	set_t			setno,
	md_set_record		**ret_sr,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_getset_args	*args;
	mdrpc_getset_2_args	v2_args;
	mdrpc_getset_res	res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_getset_2_args_u.rev1;
	args->setname = setname;
	args->setno   = setno;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		short_circuit_getset(args, &res);
		(void) mdstealerror(ep, &res.status);
	} else {
	    if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL) {
		/*
		 * This has to work during the boot up before the rpc.metad can
		 * run.  Check to see if we can handle this as a strictly local
		 * diskset.
		 */
		if (is_auto_take_set(setname, setno)) {
		    mdclrerror(ep);
		    short_circuit_getset(args, &res);
		    res.sr = setdup(res.sr);
		    (void) mdstealerror(ep, &res.status);
		} else {
		    return (-1);
		}
	    } else {

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_getset_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad get set"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_getset_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad get set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	    }
	}

	if (mdisok(ep)) {
		rval = 0;
		if (ret_sr != NULL)
			*ret_sr = res.sr;
		else
			if (! md_in_daemon)
				xdr_free(xdr_mdrpc_getset_res, (char *)&res);
	}

	return (rval);
}

/*
 * return the multi-node diskset record, drive records and node records.
 */
int
clnt_mngetset(
	char			*hostname,
	char			*setname,
	set_t			setno,
	md_mnset_record		**ret_mnsr,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_getset_args	*args;
	mdrpc_getset_2_args	v2_args;
	mdrpc_mngetset_res	res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_getset_2_args_u.rev1;
	args->setname = setname;
	args->setno   = setno;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		short_circuit_mngetset(args, &res);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
				setno, hostname, NULL, setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_mngetset_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad mn get set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	/* If no ep error and no version mismatch - rpc call worked ok */
	if (mdisok(ep)) {
		rval = 0;
		if (ret_mnsr != NULL)
			*ret_mnsr = res.mnsr;
		else
			if (! md_in_daemon)
				xdr_free(xdr_mdrpc_mngetset_res, (char *)&res);
	}

	return (rval);
}

/*
 * Set master nodeid and nodename in multi-node set record.
 */
int
clnt_mnsetmaster(
	char			*hostname,
	mdsetname_t		*sp,
	md_node_nm_t		master_nodenm,
	int			master_nodeid,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_mnsetmaster_args	*args;
	mdrpc_mnsetmaster_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_mnsetmaster_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	(void) strlcpy(args->master_nodenm, master_nodenm, MD_MAX_NODENAME);
	args->master_nodeid = master_nodeid;

	/* do it */
	if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
		return (-1);

	/*
	 * Check the client handle for the version
	 */
	CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

	/*
	 * If the client is version 1, return error
	 * otherwise, make the remote procedure call.
	 */
	if (version == METAD_VERSION) { /* version 1 */
		(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			sp->setno, hostname, NULL, sp->setname);
		metarpcclose(clntp);
		return (-1);
	} else {
		if (mdrpc_mnsetmaster_2(&v2_args, &res, clntp) != RPC_SUCCESS)
			(void) mdrpcerror(ep, clntp, hostname,
			dgettext(TEXT_DOMAIN, "metad multi-owner set master"));
		else
			(void) mdstealerror(ep, &res.status);
	}

	metarpcclose(clntp);

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Get the MH timeout values.
 */
int
clnt_gtimeout(
	char			*hostname,
	mdsetname_t		*sp,
	mhd_mhiargs_t		*ret_mhiargs,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_gtimeout_res	res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_gtimeout_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_gtimeout_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad get timeout"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_gtimeout_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad get timeout"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {

		/* do something with the results */
		rval = 0;

		/* copy md_mhiargs_t */
		if (ret_mhiargs != NULL)
			*ret_mhiargs = *res.mhiargsp;
	}

	xdr_free(xdr_mdrpc_gtimeout_res, (char *)&res);

	return (rval);
}

/*
 * get real hostname from remote host
 */
int
clnt_hostname(
	char			*hostname,
	char			**ret_hostname,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_null_args		args;
	mdrpc_hostname_res	res;
	int			rval = -1;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	args.cl_sk = NULL;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_hostname_1_svc(&args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		if (mdrpc_hostname_1(&args, &res, clntp) != RPC_SUCCESS)
			(void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad hostname"));
		else
			(void) mdstealerror(ep, &res.status);

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_hostname != NULL)
			*ret_hostname = Strdup(res.hostname);
	}

	xdr_free(xdr_mdrpc_hostname_res, (char *)&res);

	return (rval);
}

/*
 * NULLPROC - just returns a response
 */
int
clnt_nullproc(
	char			*hostname,
	md_error_t		*ep
)
{
	CLIENT			*clntp;

	/* initialize */
	mdclrerror(ep);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_nullproc_1_svc(NULL, ep, NULL);
		assert(bool == TRUE);
	} else {
		if ((clntp = metarpcopen(hostname, CL_DEF_TMO, ep)) == NULL)
			return (-1);

		if (mdrpc_nullproc_1(NULL, ep, clntp) != RPC_SUCCESS)
			(void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad nullproc"));

		metarpcclose(clntp);
	}

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * does host own the set?
 */
int
clnt_ownset(
	char			*hostname,
	mdsetname_t		*sp,
	int			*ret_bool,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_bool_res		res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_ownset_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
	    if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL) {
		/*
		 * This has to work in the code path from libpreen which is
		 * running within fsck before the rpc.metad can run.  Check
		 * to see if we should handle this as an auto-take diskset.
		 */
		if (is_auto_take_set(sp->setname, sp->setno)) {
		    /* Can't call mdrpc_ownset_2_svc since not in daemon */
		    mdclrerror(ep);
		    if (s_ownset(sp->setno, ep))
			res.value = TRUE;
		    else
			res.value = FALSE;
		} else {
		    return (-1);
		}

	    } else {

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_ownset_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad own set"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_ownset_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad own set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	    }
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_bool != NULL)
			*ret_bool = res.value;
	}

	xdr_free(xdr_mdrpc_bool_res, (char *)&res);

	return (rval);
}

/*
 * Valid set name.
 */
int
clnt_setnameok(
	char			*hostname,
	mdsetname_t		*sp,
	int			*ret_bool,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_bool_res		res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_setnameok_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_setnameok_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad setname ok"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_setnameok_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad setname ok"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_bool != NULL)
			*ret_bool = res.value;
	}

	xdr_free(xdr_mdrpc_bool_res, (char *)&res);

	return (rval);
}

/*
 * Is set number in-use?
 */
int
clnt_setnumbusy(
	char			*hostname,
	set_t			setno,
	int			*ret_bool,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_setno_args	*args;
	mdrpc_setno_2_args	v2_args;
	mdrpc_bool_res		res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_setno_2_args_u.rev1;
	args->setno = setno;
	args->cl_sk = NULL;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_setnumbusy_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_setnumbusy_1(args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad setnumber busy"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_setnumbusy_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad setnumber busy"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_bool != NULL)
			*ret_bool = res.value;
	}

	xdr_free(xdr_mdrpc_bool_res, (char *)&res);

	return (rval);
}

/*
 * Set the timeout values used into the drive records.
 */
int
clnt_stimeout(
	char			*hostname,
	mdsetname_t		*sp,
	mhd_mhiargs_t		*mhiargsp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_stimeout_args	*args;
	mdrpc_stimeout_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_stimeout_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->mhiargsp = mhiargsp;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_stimeout_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_stimeout_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad set timeout"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_stimeout_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad set timeout"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * update drive records
 */
int
clnt_upd_dr_dbinfo(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		*dd,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_drives_args	v1_args;
	mdrpc_drives_2_args	v2_args;
	mdrpc_drives_2_args_r1	*v21_args;
	mdrpc_generic_res	res;
	int			rval;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_drives_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivedescs = dd;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_upd_dr_dbinfo_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */

			alloc_olddrvdesc(&v1_args.drivedescs, dd);

			/* build args */
			v1_args.sp = sp;
			v1_args.cl_sk = cl_get_setkey(sp->setno, sp->setname);
			meta_conv_drvdesc_new2old(v1_args.drivedescs, dd);

			rval = mdrpc_upd_dr_dbinfo_1(&v1_args, &res, clntp);

			free_olddrvdesc(v1_args.drivedescs);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad update drive dbinfo"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {			/* version 2 */
			rval = mdrpc_upd_dr_dbinfo_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad update drive dbinfo"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * update dr_flags field of drive record.
 */
int
clnt_upd_dr_flags(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		*dd,
	uint_t			new_flags,
	md_error_t		*ep
)
{
	CLIENT				*clntp;
	mdrpc_upd_dr_flags_args		v1_args;
	mdrpc_upd_dr_flags_2_args	v2_args;
	mdrpc_upd_dr_flags_2_args_r1	*v21_args;
	mdrpc_generic_res		res;
	int				rval;
	int				version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v1_args, 0, sizeof (v1_args));
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_upd_dr_flags_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	v21_args->drivedescs = dd;
	v21_args->new_flags = new_flags;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_upd_dr_flags_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */

			alloc_olddrvdesc(&v1_args.drivedescs, dd);

			/* build args */
			v1_args.sp = sp;
			v1_args.cl_sk = cl_get_setkey(sp->setno, sp->setname);
			meta_conv_drvdesc_new2old(v1_args.drivedescs, dd);
			v1_args.new_flags = new_flags;

			rval = mdrpc_upd_dr_flags_1(&v1_args, &res, clntp);

			free_olddrvdesc(v1_args.drivedescs);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad update drive flags"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {			/* version 2 */
			rval = mdrpc_upd_dr_flags_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad update drive flags"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * update set record flags
 * This replaces all of the sr_flags with the new_flags.  It relies on the
 * caller to "do the right thing" to preserve the existing flags that should
 * not be reset.
 */
static int
upd_sr_flags_common(
	char			*hostname,
	mdsetname_t		*sp,
	uint_t			new_flags,
	md_error_t		*ep
)
{
	CLIENT				*clntp;
	mdrpc_upd_sr_flags_args		*args;
	mdrpc_upd_sr_flags_2_args	v2_args;
	mdrpc_generic_res		res;
	int				version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_upd_sr_flags_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	args->new_flags = new_flags;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_upd_sr_flags_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_upd_sr_flags_1(args, &res, clntp) !=
			    RPC_SUCCESS)
			    (void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad update set flags"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_upd_sr_flags_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
			    (void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad update set flags"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Enable bits in the set record flags field.  This just turns on the specified
 * bits and leaves the other bits alone.
 */
int
clnt_enable_sr_flags(
	char			*hostname,
	mdsetname_t		*sp,
	uint_t			flags,
	md_error_t		*ep
)
{
	uint_t		new_flags;
	md_set_desc	*sd;

	mdclrerror(ep);

	/* Get the flags from the current set */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Turn on the specified bits */
	new_flags = (sd->sd_flags | flags);

	/* do it */
	return (upd_sr_flags_common(hostname, sp, new_flags, ep));
}

/*
 * Disable bits in the set record flags field.  This just turns off the
 * specified bits and leaves the other bits alone.
 */
int
clnt_disable_sr_flags(
	char			*hostname,
	mdsetname_t		*sp,
	uint_t			flags,
	md_error_t		*ep
)
{
	uint_t		new_flags;
	md_set_desc	*sd;

	mdclrerror(ep);

	/* Get the flags from the current set */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* Turn off the specified bits */
	new_flags = (sd->sd_flags & ~flags);

	/* do it */
	return (upd_sr_flags_common(hostname, sp, new_flags, ep));
}

/*
 * Assign the flags as the new value(s) for the MD_SR_STATE_FLAGS within the
 * set record flags field.  This actually can set any bits but only clears
 * the bits within the MD_SR_STATE_FLAGS subfield and leaves any other
 * bits turned on.  It can be used to clear (state) and set bits all in one
 * rpc call.
 */
int
clnt_upd_sr_flags(
	char			*hostname,
	mdsetname_t		*sp,
	uint_t			flags,
	md_error_t		*ep
)
{
	uint_t		new_flags;
	md_set_desc	*sd;

	mdclrerror(ep);

	/* Get the flags from the current set */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	/* clear the existing state flags */
	sd->sd_flags &= ~MD_SR_STATE_FLAGS;

	/* Or in the new value */
	new_flags = (sd->sd_flags | flags);

	/* do it */
	return (upd_sr_flags_common(hostname, sp, new_flags, ep));
}

md_setkey_t *
cl_get_setkey(set_t setno, char *setname)
{

	if (my_cl_sk == NULL) {
		my_cl_sk = Zalloc(sizeof (md_setkey_t));
		my_cl_sk->sk_setno = setno;
		my_cl_sk->sk_setname = Strdup(setname);
		my_cl_sk->sk_host = Strdup(mynode());
	} else {
		my_cl_sk->sk_setno = setno;
		if (my_cl_sk->sk_setname != NULL)
			Free(my_cl_sk->sk_setname);
		my_cl_sk->sk_setname = Strdup(setname);
	}

	return (my_cl_sk);
}

void
cl_set_setkey(md_setkey_t *cl_sk)
{
	if ((cl_sk != NULL) && (my_cl_sk != NULL)) {
		assert(my_cl_sk->sk_setno == cl_sk->sk_setno);
		assert(strcmp(my_cl_sk->sk_setname, cl_sk->sk_setname) == 0);
		assert(strcmp(my_cl_sk->sk_host, cl_sk->sk_host) == 0);
		my_cl_sk->sk_key = cl_sk->sk_key;
		return;
	}

	if (my_cl_sk != NULL) {
		if (my_cl_sk->sk_setname != NULL)
			Free(my_cl_sk->sk_setname);
		if (my_cl_sk->sk_host != NULL)
			Free(my_cl_sk->sk_host);
		Free(my_cl_sk);
	}

	my_cl_sk = NULL;

	/* get here, if set called before get */
	if (cl_sk != NULL) {
		my_cl_sk = Zalloc(sizeof (md_setkey_t));
		my_cl_sk->sk_host = Strdup(cl_sk->sk_host);
		my_cl_sk->sk_setno = cl_sk->sk_setno;
		my_cl_sk->sk_setname = Strdup(cl_sk->sk_setname);
		my_cl_sk->sk_key = cl_sk->sk_key;
	}
}

/*
 * Unlock the set after operation is complete.
 */
int
clnt_unlock_set(
	char			*hostname,
	md_setkey_t		*cl_sk,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_null_args		args;
	mdrpc_setlock_res	res;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	args.cl_sk = cl_sk;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_unlock_set_1_svc(&args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		if (mdrpc_unlock_set_1(&args, &res, clntp) != RPC_SUCCESS)
			(void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad unlock set"));
		else
			(void) mdstealerror(ep, &res.status);

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_setlock_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Lock set so that only operators with valid keys are allowed in the daemon.
 */
int
clnt_lock_set(
	char			*hostname,
	mdsetname_t		*sp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_null_args		args;
	mdrpc_setlock_res	res;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	args.cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_lock_set_1_svc(&args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		if (mdrpc_lock_set_1(&args, &res, clntp) != RPC_SUCCESS)
			(void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad lock set"));
		else
			(void) mdstealerror(ep, &res.status);

		metarpcclose(clntp);
	}

	if (mdisok(ep))
		cl_set_setkey(res.cl_sk);

	xdr_free(xdr_mdrpc_setlock_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Add mediator hosts to disksets.
 */
int
clnt_updmeds(
	char			*hostname,
	mdsetname_t		*sp,
	md_h_arr_t		*medp,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_updmeds_args	*args;
	mdrpc_updmeds_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_updmeds_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->meds = *medp;			/* structure assignment */

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int bool;
		bool = mdrpc_updmeds_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		if (version == METAD_VERSION) {	/* version 1 */
			if (mdrpc_updmeds_1(args, &res, clntp) != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad add hosts"));
			else
				(void) mdstealerror(ep, &res.status);
		} else {
			if (mdrpc_updmeds_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad add hosts"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * update nr_flags field of node records based
 * on given action.
 */
int
clnt_upd_nr_flags(
	char			*hostname,
	mdsetname_t		*sp,
	md_mnnode_desc		*nd,
	uint_t			flag_action,
	uint_t			flags,
	md_error_t		*ep
)
{
	CLIENT				*clntp;
	mdrpc_upd_nr_flags_args		*args;
	mdrpc_upd_nr_flags_2_args	v2_args;
	mdrpc_generic_res		res;
	int				version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_upd_nr_flags_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->nodedescs = nd;
	args->flag_action = flag_action;
	args->flags = flags;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_upd_nr_flags_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
				sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_upd_nr_flags_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad set node flags"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Clear set locks for all MN disksets.
 * Used during reconfig cycle to recover from failed nodes.
 */
int
clnt_clr_mnsetlock(
	char			*hostname,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_null_args		args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* do it */
	if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
		return (-1);

	/*
	 * Check the client handle for the version
	 */
	CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

	/*
	 * If the client is version 1, return error
	 * otherwise, make the remote procedure call.
	 */
	if (version == METAD_VERSION) { /* version 1 */
		(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			NULL, hostname, NULL, NULL);
		metarpcclose(clntp);
		return (-1);
	} else {
		if (mdrpc_clr_mnsetlock_2(&args, &res, clntp) != RPC_SUCCESS)
			(void) mdrpcerror(ep, clntp, hostname,
			    dgettext(TEXT_DOMAIN, "metad clr mnsetlock"));
		else
			(void) mdstealerror(ep, &res.status);
	}

	metarpcclose(clntp);

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Calls to suspend, resume or reinit the rpc.mdcommd daemon.
 * This allows a node to remotely suspend, reinit and resume the
 * rpc.mdcommd daemon on the given hostname node.  Used by libmeta
 * to lock out class 1 messages (metainit, etc) on all nodes when running
 * metaset and metadb commands on this node.
 *
 * When suspending the commd, the suspend request will fail until all
 * messages have been drained from the rpc.mdcommd.  This routine will
 * spin sending the suspend request until the rpc.mdcommd is drained
 * or until rpc.mdcommd returns a failure other than MDMNE_SET_NOT_DRAINED.
 *
 * Also used to send the rpc.mdcommd daemon a new nodelist by draining all
 * messages from the mdcommd and sending a reinit command to have mdcommd
 * get the new nodelist from rpc.metad.  Used when nodelist is changed
 * during:
 *	- addition or deletion of host from diskset
 *	- join or withdrawal of host from diskset
 *	- addition of first disk to diskset (joins all nodes)
 *	- removal of last disk from diskset (withdraws all nodes)
 */
int
clnt_mdcommdctl(
	char			*hostname,
	int			flag_action,
	mdsetname_t		*sp,
	md_mn_msgclass_t	class,
	uint_t			flags,
	md_error_t		*ep
)
{
	CLIENT				*clntp;
	mdrpc_mdcommdctl_args		*args;
	mdrpc_mdcommdctl_2_args		v2_args;
	mdrpc_generic_res		res;
	int				version;
	int				suspend_spin = 0;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_mdcommdctl_2_args_u.rev1;
	args->flag_action = flag_action;
	args->setno = sp->setno;
	args->class = class;
	args->flags = flags;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		/*
		 * Call v2 procedure directly if rpc.metad on this node is
		 * sending message to itself.
		 */
		if (flag_action == COMMDCTL_SUSPEND) {
			suspend_spin = 1;
			while (suspend_spin) {
				suspend_spin = 0;
				bool = mdrpc_mdcommdctl_2_svc(&v2_args, &res,
					NULL);
				assert(bool == TRUE);
				/*
				 * If set not yet drained, wait a second
				 * and try again.
				 */
				if (mdisdserror(&(res.status),
				    MDE_DS_COMMDCTL_SUSPEND_NYD)) {
					/* Wait a second and try again */
					mdclrerror(&(res.status));
					(void) sleep(1);
					suspend_spin = 1;
				}
			}
		} else {
			bool = mdrpc_mdcommdctl_2_svc(&v2_args, &res, NULL);
			assert(bool == TRUE);
		}
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
				sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		}

		if (flag_action == COMMDCTL_SUSPEND) {
			suspend_spin = 1;
			while (suspend_spin) {
				suspend_spin = 0;
				if (mdrpc_mdcommdctl_2(&v2_args, &res,
				    clntp) != RPC_SUCCESS) {
					(void) mdrpcerror(ep, clntp,
					    hostname,
					    dgettext(TEXT_DOMAIN,
					    "metad commd control"));
				} else {
					/*
					 * If set not yet drained,
					 * wait a second and
					 * and try again.
					 */
					if (mdisdserror(&(res.status),
					    MDE_DS_COMMDCTL_SUSPEND_NYD)) {
						mdclrerror(&(res.status));
						(void) sleep(1);
						suspend_spin = 1;
					} else {
						(void) mdstealerror(ep,
						    &res.status);
					}
				}
			}
		} else {
			if (mdrpc_mdcommdctl_2(&v2_args, &res, clntp)
			    != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad commd control"));
			else
				(void) mdstealerror(ep, &res.status);
		}
		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Is owner node stale?
 */
int
clnt_mn_is_stale(
	char			*hostname,
	mdsetname_t		*sp,
	int			*ret_bool,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_setno_args	*args;
	mdrpc_setno_2_args	v2_args;
	mdrpc_bool_res		res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_setno_2_args_u.rev1;
	args->setno = sp->setno;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		/*
		 * Call v2 procedure directly if rpc.metad on this node is
		 * sending message to itself.
		 */
		bool = mdrpc_mn_is_stale_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_mn_is_stale_2(&v2_args, &res, clntp) !=
			    RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN, "metad mn is stale"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_bool != NULL)
			*ret_bool = res.value;
	}

	xdr_free(xdr_mdrpc_bool_res, (char *)&res);

	return (rval);
}

/*
 * Free md_drive_desc linked list of drive descriptors that was alloc'd
 * from a call to the RPC routine clnt_getdrivedesc.  Drive descriptors
 * are from another node.
 */
void
free_rem_dd(md_drive_desc *dd)
{
	mdrpc_getdrivedesc_res	res;

	/*
	 * dummy up a result struct, to do a deep free of the dd.
	 * (A deep free means that the xdr_free code will free the
	 * linked list of drive descs.)
	 */
	(void) memset(&res, 0, sizeof (res));
	res.dd = (struct md_drive_desc *)dd;
	xdr_free(xdr_mdrpc_getdrivedesc_res, (char *)&res);
}

/*
 * Get a partially filled in drive desc from remote node.  Used in MN
 * disksets during the reconfig cycle to get the diskset drive
 * information from another host in order to sync up all nodes.
 * Used when the drive record information isn't good enough
 * since the drive record doesn't give the name of
 * the drive, but just a key into that other node's nodespace.
 * Returned drive desc has the drive name filled in but no other strings
 * in the drivename structure.
 *
 * Returns a 0 if RPC was successful, 1 otherwise.
 */
int
clnt_getdrivedesc(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		**ret_dd,
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_sp_args		*args;
	mdrpc_sp_2_args		v2_args;
	mdrpc_getdrivedesc_res	res;
	int			version;
	int			rval = -1;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_sp_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_getdrivedesc_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_getdrivedesc_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad get drive desc set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	/* If no ep error and no version mismatch - rpc call worked ok */
	if (mdisok(ep)) {
		rval = 0;
		if (ret_dd != NULL)
			*ret_dd = res.dd;
		else
			xdr_free(xdr_mdrpc_getdrivedesc_res, (char *)&res);
	}

	return (rval);
}

/*
 * update dr_flags field of drive record.
 * Also sync up genid of drive descriptors and make set
 * record and node records match the genid.
 *
 * Returns a 0 if RPC was successful, 1 otherwise.
 */
int
clnt_upd_dr_reconfig(
	char			*hostname,
	mdsetname_t		*sp,
	md_drive_desc		*dd,
	md_error_t		*ep
)
{
	CLIENT				*clntp;
	mdrpc_upd_dr_flags_2_args	v2_args;
	mdrpc_upd_dr_flags_2_args_r1	*v21_args;
	mdrpc_generic_res		res;
	int				rval;
	int				version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	v21_args = &v2_args.mdrpc_upd_dr_flags_2_args_u.rev1;
	v21_args->sp = sp;
	v21_args->drivedescs = dd;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;

		/*
		 * If the server is local, we call the v2 procedure
		 */
		bool = mdrpc_upd_dr_reconfig_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);
		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
				sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			rval = mdrpc_upd_dr_reconfig_2(&v2_args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN,
				    "metad update drive reconfig"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Reset mirror owner(s) if mirror owner(s) is in the list of
 * node's specified in the array of nodeids.
 * This is called when a node has been deleted or withdrawn
 * from the diskset.
 */
int
clnt_reset_mirror_owner(
	char			*hostname,
	mdsetname_t		*sp,
	int			node_c,
	int			node_id[],
	md_error_t		*ep
)
{
	CLIENT			*clntp;
	mdrpc_nodeid_args	*args;
	mdrpc_nodeid_2_args	v2_args;
	mdrpc_generic_res	res;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_nodeid_2_args_u.rev1;
	args->sp = sp;
	args->cl_sk = cl_get_setkey(sp->setno, sp->setname);
	args->nodeid.nodeid_len = node_c;
	args->nodeid.nodeid_val = &node_id[0];

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		bool = mdrpc_reset_mirror_owner_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 * and invoke the appropriate version of the
		 * remote procedure
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    sp->setno, hostname, NULL, sp->setname);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_reset_mirror_owner_2(&v2_args, &res, clntp)
			    != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
					"metad reset mirror owner"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Call to suspend and resume I/O for given diskset(s).
 * This allows a node to remotely suspend and resume I/O on
 * a MN diskset.  A diskset number of 0 represents all MN disksets.
 */
int
clnt_mn_susp_res_io(
	char			*hostname,
	set_t			setno,
	int			cmd,
	md_error_t		*ep
)
{
	CLIENT					*clntp;
	mdrpc_mn_susp_res_io_args		*args;
	mdrpc_mn_susp_res_io_2_args		v2_args;
	mdrpc_generic_res			res;
	int					version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&v2_args, 0, sizeof (v2_args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	v2_args.rev = MD_METAD_ARGS_REV_1;
	args = &v2_args.mdrpc_mn_susp_res_io_2_args_u.rev1;
	args->susp_res_cmd = cmd;
	args->susp_res_setno = setno;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		/*
		 * Call v2 procedure directly if rpc.metad on this node is
		 * sending message to itself.
		 */
		bool = mdrpc_mn_susp_res_io_2_svc(&v2_args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    setno, hostname, NULL, NULL);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_mn_susp_res_io_2(&v2_args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad mn_susp_res_io control"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Resnarf the set after the set has been imported
 *
 * We should never be making this procedure call
 * over the wire, it's sole purpose is to snarf
 * the imported set on the localhost.
 */
int
clnt_resnarf_set(
	char		*hostname,
	set_t		setno,
	md_error_t	*ep
)
{
	CLIENT			*clntp;
	mdrpc_setno_2_args	args;
	mdrpc_generic_res	res;
	int			rval = -1;
	int			version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	args.rev = MD_METAD_ARGS_REV_1;
	args.mdrpc_setno_2_args_u.rev1.setno = setno;
	args.mdrpc_setno_2_args_u.rev1.cl_sk = NULL;

	/* do it */
	if (strcmp(mynode(), hostname) == 0) {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/* Check the client handle for the version */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/* If the client is version 1, return error */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_CANTRESNARF, MD_SET_BAD,
			    mynode(), NULL, NULL);
		} else {
			rval = mdrpc_resnarf_set_2(&args, &res, clntp);

			if (rval != RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				    dgettext(TEXT_DOMAIN, "metad resnarf set"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);

	} else {
		(void) mddserror(ep, MDE_DS_CANTRESNARF, MD_SET_BAD,
		    mynode(), NULL, NULL);
	}

	if (mdisok(ep))
		rval = 0;

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	return (rval);
}

/*
 * Call to start a resync for a given diskset.
 * Used when a node has been added to a diskset.
 * Should be called after rpc.mdcommd is resumed.
 */
int
clnt_mn_mirror_resync_all(
	char			*hostname,
	set_t			setno,
	md_error_t		*ep
)
{
	CLIENT					*clntp;
	mdrpc_setno_2_args			args;
	mdrpc_generic_res			res;
	int					version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	args.rev = MD_METAD_ARGS_REV_1;
	args.mdrpc_setno_2_args_u.rev1.setno = setno;
	args.mdrpc_setno_2_args_u.rev1.cl_sk = NULL;

	/* do it */
	if (md_in_daemon && strcmp(mynode(), hostname) == 0) {
		int	bool;
		/*
		 * Call v2 procedure directly if rpc.metad on this node is
		 * sending message to itself.
		 */
		bool = mdrpc_mn_mirror_resync_all_2_svc(&args, &res, NULL);
		assert(bool == TRUE);
		(void) mdstealerror(ep, &res.status);
	} else {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    setno, hostname, NULL, NULL);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_mn_mirror_resync_all_2(&args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad mn_mirror_resync_all"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		if (strcmp(mynode(), hostname) == 0)
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}

/*
 * Call to update the ABR state for all soft partitions.
 * Used when a node has been added to a diskset.
 * Should be called after rpc.mdcommd is resumed.
 */
int
clnt_mn_sp_update_abr(
	char			*hostname,
	set_t			setno,
	md_error_t		*ep
)
{
	CLIENT					*clntp;
	mdrpc_setno_2_args			args;
	mdrpc_generic_res			res;
	int					version;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	args.rev = MD_METAD_ARGS_REV_1;
	args.mdrpc_setno_2_args_u.rev1.setno = setno;
	args.mdrpc_setno_2_args_u.rev1.cl_sk = NULL;

	/*
	 * No need to call function if adding local node as ABR cannot
	 * be set.
	 */
	if (strcmp(mynode(), hostname) != 0) {
		if ((clntp = metarpcopen(hostname, CL_LONG_TMO, ep)) == NULL)
			return (-1);

		/*
		 * Check the client handle for the version
		 */
		CLNT_CONTROL(clntp, CLGET_VERS, (char *)&version);

		/*
		 * If the client is version 1, return error
		 * otherwise, make the remote procedure call.
		 */
		if (version == METAD_VERSION) { /* version 1 */
			(void) mddserror(ep, MDE_DS_RPCVERSMISMATCH,
			    setno, hostname, NULL, NULL);
			metarpcclose(clntp);
			return (-1);
		} else {
			if (mdrpc_mn_sp_update_abr_2(&args, &res, clntp)
							!= RPC_SUCCESS)
				(void) mdrpcerror(ep, clntp, hostname,
				dgettext(TEXT_DOMAIN,
				    "metad mn_sp_update_abr"));
			else
				(void) mdstealerror(ep, &res.status);
		}

		metarpcclose(clntp);
	}

	xdr_free(xdr_mdrpc_generic_res, (char *)&res);

	if (! mdisok(ep)) {
		if (! mdanyrpcerror(ep))
			return (-1);
		mdclrerror(ep);
	}

	return (0);
}
