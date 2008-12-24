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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * Mediator functions
 */

#include <meta.h>
#include <metamed.h>
#include <dlfcn.h>
#include <sdssc.h>

/*
 * There are too many external factors that affect the timing of the
 * operations, so we set the timeout to a very large value, in this
 * case 1 day, which should handle HW timeouts, large configurations,
 * and other potential delays.
 */
#define	CL_LONG_TMO	86400L			/* 1 day */
#define	CL_MEDIUM_TMO	3600L			/* 1 hour */
#define	CL_SHORT_TMO	600L			/* 10 minutes */
#define	CL_DEF_TMO	10L			/* 10 seconds */

static	md_timeval32_t def_rpcb_timeout =  { MD_CLNT_CREATE_TOUT, 0 };

/*
 * RPC handle
 */
typedef struct {
	char	*hostname;
	CLIENT	*clntp;
} med_handle_t;

/*
 * Data to be sent from med_clnt_create_timed to med_create_helper via
 * meta_client_create_retry.
 */
typedef struct {
	rpcprog_t	mcd_program;	/* RPC program designation */
	rpcvers_t	mcd_version;	/* RPC version */
	char		*mcd_nettype;	/* Type of network to use for RPC */
} med_create_data_t;

/*
 * Perform the work of actually doing the clnt_create for
 * meta_client_create_retry.
 */
static CLIENT *
med_create_helper(char *hostname, void *private, struct timeval *time_out)
{
	med_create_data_t	*cd = (med_create_data_t *)private;

	return (clnt_create_timed(hostname, cd->mcd_program, cd->mcd_version,
	    cd->mcd_nettype, time_out));
}

static
CLIENT *med_clnt_create_timed(
	char *hostname,
	const ulong_t prog,
	const ulong_t vers,
	char *nettype,
	const md_timeval32_t *tp
)
{
	med_create_data_t	cd;	/* Create data. */

	cd.mcd_program = prog;
	cd.mcd_version = vers;
	cd.mcd_nettype = nettype;
	return (meta_client_create_retry(hostname, med_create_helper,
	    (void *)&cd, (time_t)tp->tv_sec, NULL));
}

/*
 * Set the timeout value for this client handle.
 */
static int
cl_sto_medd(
	CLIENT		*clntp,
	char		*hostname,
	long		time_out,
	md_error_t	*ep
)
{
	md_timeval32_t	nto;

	(void) memset(&nto, '\0', sizeof (nto));

	nto.tv_sec = time_out;

	if (clnt_control(clntp, CLSET_TIMEOUT, (char *)&nto) != TRUE)
		return (mdrpcerror(ep, clntp, hostname,
		    dgettext(TEXT_DOMAIN, "metad client set timeout")));

	return (0);
}

/*
 * close RPC connection
 */
static void
close_medd(
	med_handle_t	*hp
)
{
	assert(hp != NULL);
	if (hp->hostname != NULL) {
		Free(hp->hostname);
	}
	if (hp->clntp != NULL) {
		auth_destroy(hp->clntp->cl_auth);
		clnt_destroy(hp->clntp);
	}
	Free(hp);
}

/*
 * open RPC connection to rpc.medd
 */
static med_handle_t *
open_medd(
	char		*hostname,
	long		time_out,
	md_error_t	*ep
)
{
	CLIENT		*clntp;
	med_handle_t	*hp;

	/* default to local host */
	if ((hostname == NULL) || (*hostname == '\0'))
		hostname = mynode();

	/* open RPC connection */
	assert(hostname != NULL);
	if ((clntp = med_clnt_create_timed(hostname, MED_PROG, MED_VERS,
	    "tcp", &def_rpcb_timeout)) == NULL) {
		if (rpc_createerr.cf_stat != RPC_PROGNOTREGISTERED)
			clnt_pcreateerror(hostname);
		(void) mdrpccreateerror(ep, hostname,
		    "medd med_clnt_create_timed");
		return (NULL);
	} else {
		auth_destroy(clntp->cl_auth);
		clntp->cl_auth = authsys_create_default();
		assert(clntp->cl_auth != NULL);
	}

	if (cl_sto_medd(clntp, hostname, time_out, ep) != 0)
		return (NULL);

	/* return connection */
	hp = Zalloc(sizeof (*hp));
	hp->hostname = Strdup(hostname);
	hp->clntp = clntp;

	return (hp);
}

/*
 * steal and convert med_err_t
 */
int
meddstealerror(
	md_error_t	*ep,
	med_err_t	*medep
)
{
	char		buf[BUFSIZ];
	char		*p = buf;
	size_t		psize = BUFSIZ;
	char		*emsg;
	int		rval = -1;

	/* no error */
	if (medep->med_errno == 0) {
		/* assert(medep->name == NULL); */
		rval = 0;
		goto out;
	}

	/* steal error */
	if ((medep->med_node != NULL) && (medep->med_node[0] != '\0')) {
		(void) snprintf(p, psize, "%s: ", medep->med_node);
		p = &buf[strlen(buf)];
		psize = buf + BUFSIZ - p;
	}

	if ((medep->med_misc != NULL) && (medep->med_misc[0] != '\0')) {
		(void) snprintf(p, psize, "%s: ", medep->med_misc);
		p = &buf[strlen(buf)];
		psize = buf + BUFSIZ - p;
	}

	if (medep->med_errno < 0) {
		if ((emsg = med_errnum_to_str(medep->med_errno)) != NULL)
			(void) snprintf(p, psize, "%s", emsg);
		else
			(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
			    "unknown mediator errno %d\n"), medep->med_errno);
	} else {
		if ((emsg = strerror(medep->med_errno)) != NULL)
			(void) snprintf(p, psize, "%s", emsg);
		else
			(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
			    "errno %d out of range"), medep->med_errno);
	}
	(void) mderror(ep, MDE_MED_ERROR, buf);

	/* cleanup, return success */
out:
	if (medep->med_node != NULL)
		Free(medep->med_node);
	if (medep->med_misc != NULL)
		Free(medep->med_misc);
	(void) memset(medep, 0, sizeof (*medep));
	return (rval);
}

static med_handle_t *
open_medd_wrap(
	md_h_t		*mdhp,
	long		time_out,
	md_error_t	*ep
)
{
	med_handle_t		*hp = NULL;
	int			i;
	char    		*hnm;

	assert(mdhp && mdhp->a_cnt > 0);

	/* Loop through the hosts listed */
	i = min(mdhp->a_cnt, MAX_HOST_ADDRS) - 1;
	for (; i >= 0; i--) {
		hnm = mdhp->a_nm[i];

		if ((hp = open_medd(hnm, time_out, ep)) == NULL) {
			if (mdanyrpcerror(ep) && i != 0) {
				mdclrerror(ep);
				continue;
			}
		}
		return (hp);
	}

	rpc_createerr.cf_stat = RPC_CANTSEND;
	rpc_createerr.cf_error.re_status = 0;
	(void) mdrpccreateerror(ep, mdhp->a_nm[0],
	    dgettext(TEXT_DOMAIN, "medd open wrap"));

	return (NULL);
}

static int
setup_med_transtab(md_error_t *ep)
{
	mddb_med_t_parm_t	*tp = NULL;
	struct	stat		statb;
	int			i;
	size_t			alloc_size = 0;
	int			err = 0;


	if ((tp = Zalloc(sizeof (mddb_med_t_parm_t))) == NULL)
		return (mdsyserror(ep, ENOMEM, "setup_med_transtab"));

	if (metaioctl(MD_MED_GET_TLEN, tp, &tp->med_tp_mde, NULL) != 0) {
		err = mdstealerror(ep, &tp->med_tp_mde);
		goto out;
	}

	if (tp->med_tp_setup == 1)
		goto out;

	alloc_size = (sizeof (mddb_med_t_parm_t) - sizeof (mddb_med_t_ent_t)) +
	    (sizeof (mddb_med_t_ent_t) * tp->med_tp_nents);

	if ((tp = Realloc(tp, alloc_size)) == NULL) {
		err = mdsyserror(ep, ENOMEM, "setup_med_transtab");
		goto out;
	}

	if (metaioctl(MD_MED_GET_T, tp, &tp->med_tp_mde, NULL) != 0) {
		err = mdstealerror(ep, &tp->med_tp_mde);
		goto out;
	}

	for (i = 0; i < tp->med_tp_nents; i++) {
		if (meta_stat(tp->med_tp_ents[i].med_te_nm, &statb) == -1) {
			md_perror("setup_med_transtab(): stat():");
			tp->med_tp_ents[i].med_te_dev = NODEV64;
		} else {
			tp->med_tp_ents[i].med_te_dev =
			    meta_expldev(statb.st_rdev);
		}
	}

	if (metaioctl(MD_MED_SET_T, tp, &tp->med_tp_mde, NULL) != 0)
		err = mdstealerror(ep, &tp->med_tp_mde);

out:
	Free(tp);
	return (err);
}

/*
 * Externals
 */

/*
 * NULLPROC - just returns a response
 */
int
clnt_med_null(
	char			*hostname,
	md_error_t		*ep
)
{
	med_handle_t		*hp;
	med_err_t		res;

	/* initialize */
	mdclrerror(ep);

	/* do it */
	if ((hp = open_medd(hostname, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_null_1(NULL, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hostname,
		    dgettext(TEXT_DOMAIN, "medd nullproc"));

	close_medd(hp);

	xdr_free(xdr_med_err_t, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Update the mediator information on the mediator.
 * This function does the same functionality as
 * clnt_med_upd_data() except that it takes different
 * argument so that host which is just a mediator, can
 * still update its mediator record.
 */
int
clnt_user_med_upd_data(
	md_h_t	*mdhp,
	bool_t	obandiskset,
	char	*setname,
	uint_t	setnum,
	med_data_t	*meddp,
	md_error_t	*ep
)
{
	med_handle_t    	*hp;
	med_upd_data_args_t	args;
	med_err_t		res;

	/* Initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* Build args */
	if (obandiskset)
		args.med.med_caller = Strdup(MED_MN_CALLER);
	else
		args.med.med_caller = Strdup(mynode());

	args.med.med_setname = Strdup(setname);
	args.med.med_setno = setnum;
	args.med_data = *meddp;

	if ((hp = open_medd_wrap(mdhp, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_upd_data_1(&args, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "medd get record"));
	else
		(void) meddstealerror(ep, &res);

	close_medd(hp);

	xdr_free(xdr_med_upd_data_args_t, (char *)&args);
	xdr_free(xdr_med_err_t, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Get the mediator information from the client.
 * The code does same functinality as clnt_med_get_data()
 * except that it takes different arguments so that
 * host which doesn't have set information, can still
 * get access to mediator information
 */
int
clnt_user_med_get_data(
	md_h_t	*mdhp,
	bool_t	obandiskset,
	char	*setname,
	uint_t	setnum,
	med_data_t	*meddp,
	md_error_t	*ep
)
{
	int			rval = -1;
	med_handle_t		*hp;
	med_args_t		args;
	med_get_data_res_t	res;

	/* Initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* Build args */
	if (obandiskset)
		args.med.med_caller = Strdup(MED_MN_CALLER);
	else
		args.med.med_caller = Strdup(mynode());

	args.med.med_setname = Strdup(setname);
	args.med.med_setno = setnum;

	if ((hp = open_medd_wrap(mdhp, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_get_data_1(&args, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "medd get record"));
	else
		(void) meddstealerror(ep, &res.med_status);

	close_medd(hp);

	if (mdisok(ep)) {
		/* copy the mediator data in meddp */
		(void) memmove(meddp, &res.med_data, sizeof (med_data_t));
		rval = 0;
	}

	xdr_free(xdr_med_args_t, (char *)&args);
	xdr_free(xdr_med_get_data_res_t, (char *)&res);

	return (rval);
}


/*
 * Update the mediator information on the mediator.
 * *** This is not normally called from user code, the kernel does this! ***
 */
int
clnt_med_upd_data(
	md_h_t			*mdhp,
	mdsetname_t		*sp,
	med_data_t		*meddp,
	md_error_t		*ep
)
{
	med_handle_t		*hp;
	med_upd_data_args_t	args;
	med_err_t		res;
	md_set_desc		*sd;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd))
		/*
		 * In the MN diskset, use a generic nodename, multiowner, as
		 * the node initiating the RPC request.  This allows
		 * any node to access mediator information.
		 *
		 * MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 *
		 * In the traditional diskset, only a calling node that is
		 * in the mediator record's diskset nodelist can access
		 * mediator data.
		 */
		args.med.med_caller = Strdup(MED_MN_CALLER);
	else
		args.med.med_caller = Strdup(mynode());
	args.med.med_setname = Strdup(sp->setname);
	args.med.med_setno = sp->setno;
	args.med_data = *meddp;

	/* do it */
	if ((hp = open_medd_wrap(mdhp, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_upd_data_1(&args, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "medd update data"));
	else
		(void) meddstealerror(ep, &res);

	close_medd(hp);

	xdr_free(xdr_med_upd_data_args_t, (char *)&args);
	xdr_free(xdr_med_err_t, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Get the mediator data for this client from the mediator
 */
int
clnt_med_get_data(
	md_h_t			*mdhp,
	mdsetname_t		*sp,
	med_data_t		*meddp,
	md_error_t		*ep
)
{
	med_handle_t		*hp;
	med_args_t		args;
	med_get_data_res_t	res;
	int			rval = -1;
	md_set_desc		*sd;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd))
		/*
		 * In the MN diskset, use a generic nodename, multiowner, as
		 * the node initiating the RPC request.  This allows
		 * any node to access mediator information.
		 *
		 * MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 *
		 * In the traditional diskset, only a calling node that is
		 * in the mediator record's diskset nodelist can access
		 * mediator data.
		 */
		args.med.med_caller = Strdup(MED_MN_CALLER);
	else
		args.med.med_caller = Strdup(mynode());
	args.med.med_setname = Strdup(sp->setname);
	args.med.med_setno = sp->setno;

	/* do it */
	if ((hp = open_medd_wrap(mdhp, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_get_data_1(&args, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "medd get data"));
	else
		(void) meddstealerror(ep, &res.med_status);

	close_medd(hp);

	if (mdisok(ep)) {
		/* do something with the results */
		(void) memmove(meddp, &res.med_data, sizeof (med_data_t));
		rval = 0;
	}

	xdr_free(xdr_med_args_t, (char *)&args);
	xdr_free(xdr_med_get_data_res_t, (char *)&res);

	return (rval);
}

/*
 * Update the mediator record on the mediator.
 */
int
clnt_med_upd_rec(
	md_h_t			*mdhp,
	mdsetname_t		*sp,
	med_rec_t		*medrp,
	md_error_t		*ep
)
{
	med_handle_t		*hp;
	med_upd_rec_args_t	args;
	med_err_t		res;
	md_set_desc		*sd;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd))
		/*
		 * In the MN diskset, use a generic nodename, multiowner, as
		 * the node initiating the RPC request.  This allows
		 * any node to access mediator information.
		 *
		 * MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 *
		 * In the traditional diskset, only a calling node that is
		 * in the mediator record's diskset nodelist can access
		 * mediator data.
		 */
		args.med.med_caller = Strdup(MED_MN_CALLER);
	else
		args.med.med_caller = Strdup(mynode());
	args.med.med_setname = Strdup(sp->setname);
	args.med.med_setno = sp->setno;
	args.med_flags = 0;
	args.med_rec = *medrp;			/* structure assignment */

	/* do it */
	if ((hp = open_medd_wrap(mdhp, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_upd_rec_1(&args, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "medd update record"));
	else
		(void) meddstealerror(ep, &res);

	close_medd(hp);

	xdr_free(xdr_med_upd_rec_args_t, (char *)&args);
	xdr_free(xdr_med_err_t, (char *)&res);

	if (! mdisok(ep))
		return (-1);

	return (0);
}

/*
 * Get the mediator record for this client from the mediator
 */
int
clnt_med_get_rec(
	md_h_t			*mdhp,
	mdsetname_t		*sp,
	med_rec_t		*medrp,
	md_error_t		*ep
)
{
	med_handle_t		*hp;
	med_args_t		args;
	med_get_rec_res_t	res;
	int			rval = -1;
	md_set_desc		*sd;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&res, 0, sizeof (res));

	/* build args */
	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (MD_MNSET_DESC(sd))
		/*
		 * In the MN diskset, use a generic nodename, multiowner, as
		 * the node initiating the RPC request.  This allows
		 * any node to access mediator information.
		 *
		 * MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 *
		 * In the traditional diskset, only a calling node that is
		 * in the mediator record's diskset nodelist can access
		 * mediator data.
		 */
		args.med.med_caller = Strdup(MED_MN_CALLER);
	else
		args.med.med_caller = Strdup(mynode());
	args.med.med_setname = Strdup(sp->setname);
	args.med.med_setno = sp->setno;

	/* do it */
	if ((hp = open_medd_wrap(mdhp, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_get_rec_1(&args, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "medd get record"));
	else
		(void) meddstealerror(ep, &res.med_status);

	close_medd(hp);

	if (mdisok(ep)) {
		/* do something with the results */
		(void) memmove(medrp, &res.med_rec, sizeof (med_rec_t));
		rval = 0;
	}

	xdr_free(xdr_med_args_t, (char *)&args);
	xdr_free(xdr_med_get_rec_res_t, (char *)&res);

	return (rval);
}

/*
 * Get the name of the host from the mediator daemon.
 */
int
clnt_med_hostname(
	char			*hostname,
	char			**ret_hostname,
	md_error_t		*ep
)
{
	med_handle_t		*hp;
	med_hnm_res_t		res;
	int			rval = -1;

	/* initialize */
	mdclrerror(ep);
	(void) memset(&res, 0, sizeof (res));

	/* No args */

	/* do it */
	if ((hp = open_medd(hostname, CL_DEF_TMO, ep)) == NULL)
		return (-1);

	if (med_hostname_1(NULL, &res, hp->clntp) != RPC_SUCCESS)
		(void) mdrpcerror(ep, hp->clntp, hostname,
		    dgettext(TEXT_DOMAIN, "medd hostname"));
	else
		(void) meddstealerror(ep, &res.med_status);

	close_medd(hp);

	if (mdisok(ep)) {
		/* do something with the results */
		rval = 0;

		if (ret_hostname != NULL)
			*ret_hostname = Strdup(res.med_hnm);
	}

	xdr_free(xdr_med_hnm_res_t, (char *)&res);

	return (rval);
}

int
meta_med_hnm2ip(md_hi_arr_t *mp, md_error_t *ep)
{
	int		i, j;
	int		max_meds;

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	for (i = 0; i < max_meds; i++) {
		mp->n_lst[i].a_flg = 0;
		/* See if this is the local host */
		if (mp->n_lst[i].a_cnt > 0 &&
		    strcmp(mp->n_lst[i].a_nm[0], mynode()) == NULL)
			mp->n_lst[i].a_flg |= NMIP_F_LOCAL;

		for (j = 0; j < mp->n_lst[i].a_cnt; j++) {
			struct hostent	*hp;
			char		*hnm = mp->n_lst[i].a_nm[j];

			/*
			 * Cluster nodename support
			 *
			 * See if the clustering code can give us an IP addr
			 * for the stored name. If not, find it the old way
			 * which will use the public interface.
			 */
			if (sdssc_get_priv_ipaddr(mp->n_lst[i].a_nm[j],
			    (struct in_addr *)&mp->n_lst[i].a_ip[j]) !=
			    SDSSC_OKAY) {
				if ((hp = gethostbyname(hnm)) == NULL)
					return (mdsyserror(ep, EADDRNOTAVAIL,
					    hnm));

				/* We only do INET addresses */
				if (hp->h_addrtype != AF_INET)
					return (mdsyserror(ep, EPFNOSUPPORT,
					    hnm));

				/* We take the first address only */
				if (*hp->h_addr_list) {
					(void) memmove(&mp->n_lst[i].a_ip[j],
					    *hp->h_addr_list,
					    sizeof (struct in_addr));
				} else
					return (mdsyserror(ep, EADDRNOTAVAIL,
					    hnm));
			}

		}
	}
	return (0);
}

int
meta_h2hi(md_h_arr_t *mdhp, md_hi_arr_t *mdhip, md_error_t *ep)
{
	int			i, j;
	int			max_meds;

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	mdhip->n_cnt = mdhp->n_cnt;

	for (i = 0; i < max_meds; i++) {
		mdhip->n_lst[i].a_flg = 0;
		mdhip->n_lst[i].a_cnt = mdhp->n_lst[i].a_cnt;
		if (mdhp->n_lst[i].a_cnt == 0)
			continue;
		for (j = 0; j < mdhp->n_lst[i].a_cnt; j++)
			(void) strcpy(mdhip->n_lst[i].a_nm[j],
			    mdhp->n_lst[i].a_nm[j]);
	}
	return (0);
}

int
meta_hi2h(md_hi_arr_t *mdhip, md_h_arr_t *mdhp, md_error_t *ep)
{
	int			i, j;
	int			max_meds;

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	mdhp->n_cnt = mdhip->n_cnt;
	for (i = 0; i < max_meds; i++) {
		mdhp->n_lst[i].a_cnt = mdhip->n_lst[i].a_cnt;
		if (mdhip->n_lst[i].a_cnt == 0)
			continue;
		for (j = 0; j < mdhip->n_lst[i].a_cnt; j++)
			(void) strcpy(mdhp->n_lst[i].a_nm[j],
			    mdhip->n_lst[i].a_nm[j]);
	}
	return (0);
}

int
setup_med_cfg(
	mdsetname_t		*sp,
	mddb_config_t		*cp,
	int			force,
	md_error_t		*ep
)
{
	md_set_desc		*sd;
	int			i;
	int			max_meds;

	if (metaislocalset(sp))
		return (0);

	if ((sd = metaget_setdesc(sp, ep)) == NULL)
		return (-1);

	if (setup_med_transtab(ep))
		return (-1);

	if (meta_h2hi(&sd->sd_med, &cp->c_med, ep))
		return (-1);

	/* Make sure the ip addresses are current */
	if (meta_med_hnm2ip(&cp->c_med, ep))
		return (-1);

	if (force)
		return (0);

	if ((max_meds = get_max_meds(ep)) == 0)
		return (-1);

	/* Make sure metamedd still running on host - only chk nodename */
	for (i = 0; i < max_meds; i++) {
		char		*hostname;
		char		*hnm;

		if (sd->sd_med.n_lst[i].a_cnt == 0)
			continue;

		hnm = sd->sd_med.n_lst[i].a_nm[0];

		if (clnt_med_hostname(hnm, &hostname, ep))
			return (mddserror(ep, MDE_DS_NOMEDONHOST, sp->setno,
			    hnm, NULL, sp->setname));
		Free(hostname);
	}
	return (0);
}

/*
 * This is a general routine to get mediator information from
 * file /etc/lvm/meddb. Commands medstat and metainit use this
 * routine to get mediator information from all mediator hosts or update
 * its mediator record respectively.
 */
int
meta_mediator_info_from_file(char *sname, int verbose, md_error_t *ep)
{
	uint_t		c;
	int		i;
	int		j;
	int		fd;
	int		rec_size;
	char		*setname;
	uint_t		setnum;
	med_rec_t	*rec_buf = NULL;
	med_db_hdr_t	*dbhbr;
	med_rec_t	*medrecp;
	med_data_t	medd;
	med_data_t	*save_medd;
	md_h_t		mdh;
	uint_t		latest_med_dat_cc = 0;
	int		retval = 0;
	int		medok = 0;
	int		golden = 0;
	bool_t		obandiskset;

	/* Open the meddb file */
	if ((fd = open(MED_DB_FILE, O_RDONLY, 0)) == -1) {

		/*
		 * During the start up of the SVM services, this function
		 * will be called with an empty sname. In that case it is
		 * entirely possible for the MED_DB_FILE not to exist.
		 * If so, then no need to report an error.
		 */
		if (sname != NULL) {
			(void) mdsyserror(ep, errno, MED_DB_FILE);
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Error in opening meddb file"));
			return (1);
		}
		return (0);
	}

	/* Initialize rec_size */
	rec_size = roundup(sizeof (med_rec_t), DEV_BSIZE);

	/* Allocate a record buffer */
	if ((rec_buf = malloc(rec_size)) == NULL) {
		(void) mdsyserror(ep, errno, MED_DB_FILE);
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Error in allocating memory"));
		goto out;
	}

	/* read the file header */
	if ((read(fd, rec_buf, rec_size)) != rec_size) {
		(void) mdsyserror(ep, EINVAL, MED_DB_FILE);
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Error in reading mediator record"));
		goto out;
	}

	dbhbr = (med_db_hdr_t *)rec_buf;

	/* Number of records in the mediator file */
	c = dbhbr->med_dbh_nm;

	for (i = 0; i < c; i++) {
		(void) memset(rec_buf, 0, rec_size);

		if (read(fd, rec_buf, rec_size) == -1) {
			(void) mdsyserror(ep, errno, MED_DB_FILE);
			mde_perror(ep, dgettext(TEXT_DOMAIN,
			    "Error in reading mediator record"));
			goto out;
		}

		medrecp = (med_rec_t *)rec_buf;

		/*
		 * For oban diskset first entry in the rec_nodes field is
		 * "multiowner" and all other entries are null
		 * Check if this is really multiowner diskset.
		 */

		if ((strcmp(medrecp->med_rec_nodes[0], MED_MN_CALLER) == 0) &&
		    (medrecp->med_rec_nodes[1] == NULL))
			obandiskset = TRUE;
		else
			obandiskset = FALSE;

		if (sname != NULL) {
			/*
			 * Continue if the set name is not in our interest.
			 * This is required when this routine is called
			 * from medstat
			 */

			if (strcmp(sname, medrecp->med_rec_snm) != 0) {
				continue;
			}

			if (verbose)
				(void) printf("%8.8s\t\t%6.6s\t%6.6s\n",
				    gettext("Mediator"), gettext("Status"),
				    gettext("Golden"));

			if (medrecp->med_rec_meds.n_cnt == 0) {
				if (verbose)
					(void) printf(gettext(
					    "No mediator hosts configured for"
					    " set \"%s\".\n"),
					    sname);
				goto out;
			}
			setname = sname;
		} else {
			setname = medrecp->med_rec_snm;
		}
		setnum = medrecp->med_rec_sn;

		for (j = 0; j < medrecp->med_rec_meds.n_cnt; j ++) {
			(void) memset(&medd, 0, sizeof (medd));
			(void) memset(&mdh, 0, sizeof (mdh));
			mdh = medrecp->med_rec_meds.n_lst[j];

			if ((sname != NULL) && (verbose))
				(void) printf("%-17.17s\t",
				    medrecp->med_rec_meds.n_lst[j].a_nm[0]);

			if (clnt_user_med_get_data(&mdh, obandiskset,
			    setname, setnum, &medd, ep) == -1) {
				if (sname == NULL) {
					continue;
				} else {
					if (mdanyrpcerror(ep)) {
						if (verbose)
							(void) printf("%s\n",
							    gettext("Unreach"
							    "able"));
						continue;
					} else if (mdiserror(ep,
					    MDE_MED_ERROR)) {
						if (verbose)
							(void) printf("%s\n",
							    gettext("Bad"));
					} else {
						if (verbose)
							(void) printf("%s\n",
							    gettext("Fatal"));
					}
					mde_perror(ep, "");
					if (mdiserror(ep, MDE_MED_ERROR))
						continue;
					goto out;
				}
			} else {
				if (sname == NULL) {
					if (latest_med_dat_cc <
					    medd.med_dat_cc) {
						latest_med_dat_cc =
						    medd.med_dat_cc;
						save_medd = &medd;
					}
				} else {
					if (verbose)
						(void) printf("%s",
						    gettext("Ok"));
					if (medd.med_dat_fl & MED_DFL_GOLDEN) {
						if (verbose)
							(void) printf("\t%s",
							    gettext("Yes"));
						golden++;
					} else {
						if (verbose)
							(void) printf("\t%s",
							    gettext("No"));
					}
					if (verbose)
						(void) printf("\n");
						medok++;
				}
			}
		}
		if (sname == NULL) {
			/*
			 * Update the latest mediator information
			 * on this node
			 */
			(void) strlcpy(mdh.a_nm[0], mynode(),
			    sizeof (mdh.a_nm[0]));
			if (clnt_user_med_upd_data(&mdh, obandiskset,
			    setname, setnum, save_medd, ep) == -1) {
				/*
				 * We had some errors while updaing the
				 * record. This means this metaset is
				 * not updated with latest mediator
				 * information.
				 */
				mde_perror(ep, "");
				continue;
			}
		} else {
			if (golden) {
				retval = 0;
				goto out;
			}
			if (medok < ((medrecp->med_rec_meds.n_cnt / 2) + 1))
				retval = 1;
		}
	}

out:
	if (rec_buf != NULL)
		Free(rec_buf);
	if (close(fd) < 0) {
		(void) mdsyserror(ep, errno, MED_DB_FILE);
		mde_perror(ep, dgettext(TEXT_DOMAIN,
		    "Error in closing meddb file"));
		return (1);
	}
	return (retval);
}
