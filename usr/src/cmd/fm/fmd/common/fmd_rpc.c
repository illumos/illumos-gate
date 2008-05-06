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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/fm/util.h>

#include <netdir.h>
#include <strings.h>
#include <alloca.h>
#include <limits.h>
#include <unistd.h>
#include <ucred.h>
#include <priv.h>

#include <fmd_rpc_api.h>
#include <fmd_rpc_adm.h>
#include <rpc/svc_mt.h>

#include <fmd_subr.h>
#include <fmd_error.h>
#include <fmd_thread.h>
#include <fmd_conf.h>
#include <fmd_api.h>
#include <fmd.h>

/*
 * Define range of transient RPC program numbers to use for transient bindings.
 * These are defined in the Solaris ONC+ Developer's Guide, Appendix B, but
 * are cleverly not defined in any ONC+ standard system header file.
 */
#define	RPC_TRANS_MIN	0x40000000
#define	RPC_TRANS_MAX	0x5fffffff

/*
 * We use our own private version of svc_create() which registers our services
 * only on loopback transports and enables an option whereby Solaris ucreds
 * are associated with each connection, permitting us to check privilege bits.
 */
static int
fmd_rpc_svc_create_local(void (*disp)(struct svc_req *, SVCXPRT *),
    rpcprog_t prog, rpcvers_t vers, uint_t ssz, uint_t rsz, int force)
{
	struct netconfig *ncp;
	struct netbuf buf;
	SVCXPRT *xprt;
	void *hdl;
	int fd, n = 0;

	char door[PATH_MAX];
	time_t tm;

	if ((hdl = setnetconfig()) == NULL) {
		fmd_error(EFMD_RPC_REG, "failed to iterate over "
		    "netconfig database: %s\n", nc_sperror());
		return (fmd_set_errno(EFMD_RPC_REG));
	}

	if (force)
		svc_unreg(prog, vers); /* clear stale rpcbind registrations */

	buf.buf = alloca(_SS_MAXSIZE);
	buf.maxlen = _SS_MAXSIZE;
	buf.len = 0;

	while ((ncp = getnetconfig(hdl)) != NULL) {
		if (strcmp(ncp->nc_protofmly, NC_LOOPBACK) != 0)
			continue;

		if (!force && rpcb_getaddr(prog, vers, ncp, &buf, HOST_SELF)) {
			(void) endnetconfig(hdl);
			return (fmd_set_errno(EFMD_RPC_BOUND));
		}

		if ((fd = t_open(ncp->nc_device, O_RDWR, NULL)) == -1) {
			fmd_error(EFMD_RPC_REG, "failed to open %s: %s\n",
			    ncp->nc_device, t_strerror(t_errno));
			continue;
		}

		svc_fd_negotiate_ucred(fd); /* enable ucred option on xprt */

		if ((xprt = svc_tli_create(fd, ncp, NULL, ssz, rsz)) == NULL) {
			(void) t_close(fd);
			continue;
		}

		if (svc_reg(xprt, prog, vers, disp, ncp) == FALSE) {
			fmd_error(EFMD_RPC_REG, "failed to register "
			    "rpc service on %s\n", ncp->nc_netid);
			svc_destroy(xprt);
			continue;
		}

		n++;
	}

	(void) endnetconfig(hdl);

	/*
	 * If we failed to register services (n == 0) because rpcbind is down,
	 * then check to see if the RPC door file exists before attempting an
	 * svc_door_create(), which cleverly destroys any existing door file.
	 * The RPC APIs have no stable errnos, so we use rpcb_gettime() as a
	 * hack to determine if rpcbind itself is down.
	 */
	if (!force && n == 0 && rpcb_gettime(HOST_SELF, &tm) == FALSE &&
	    snprintf(door, sizeof (door), RPC_DOOR_RENDEZVOUS,
	    prog, vers) > 0 && access(door, F_OK) == 0)
		return (fmd_set_errno(EFMD_RPC_BOUND));

	/*
	 * Attempt to create a door server for the RPC program as well.  Limit
	 * the maximum request size for the door transport to the receive size.
	 */
	if ((xprt = svc_door_create(disp, prog, vers, ssz)) == NULL) {
		fmd_error(EFMD_RPC_REG, "failed to create door for "
		    "rpc service 0x%lx/0x%lx\n", prog, vers);
	} else {
		(void) svc_control(xprt, SVCSET_CONNMAXREC, &rsz);
		n++;
	}

	return (n);
}

static int
fmd_rpc_svc_init(void (*disp)(struct svc_req *, SVCXPRT *),
    const char *name, const char *path, const char *prop,
    rpcprog_t pmin, rpcprog_t pmax, rpcvers_t vers,
    uint_t sndsize, uint_t rcvsize, int force)
{
	rpcprog_t prog;
	char buf[16];
	FILE *fp;

	for (prog = pmin; prog <= pmax; prog++) {
		if (fmd_rpc_svc_create_local(disp, prog, vers,
		    sndsize, rcvsize, force) > 0) {
			fmd_dprintf(FMD_DBG_RPC, "registered %s rpc service "
			    "as 0x%lx.%lx\n", name, prog, vers);

			/*
			 * To aid simulator scripts, save our RPC "digits" in
			 * the specified file for rendezvous with libfmd_adm.
			 */
			if (path != NULL && (fp = fopen(path, "w")) != NULL) {
				(void) fprintf(fp, "%ld\n", prog);
				(void) fclose(fp);
			}

			(void) snprintf(buf, sizeof (buf), "%ld", prog);
			(void) fmd_conf_setprop(fmd.d_conf, prop, buf);

			return (0);
		}
	}

	return (-1); /* errno is set for us */
}

void
fmd_rpc_init(void)
{
	int err, prog, mode = RPC_SVC_MT_USER;
	uint64_t sndsize = 0, rcvsize = 0;
	const char *s;

	if (rpc_control(RPC_SVC_MTMODE_SET, &mode) == FALSE)
		fmd_panic("failed to enable user-MT rpc mode");

	(void) fmd_conf_getprop(fmd.d_conf, "rpc.sndsize", &sndsize);
	(void) fmd_conf_getprop(fmd.d_conf, "rpc.rcvsize", &rcvsize);

	/*
	 * Infer whether we are the "default" fault manager or an alternate one
	 * based on whether the initial setting of rpc.adm.prog is non-zero.
	 */
	(void) fmd_conf_getprop(fmd.d_conf, "rpc.adm.prog", &prog);
	(void) fmd_conf_getprop(fmd.d_conf, "rpc.adm.path", &s);

	if (prog != 0) {
		err = fmd_rpc_svc_init(fmd_adm_1, "FMD_ADM", s, "rpc.adm.prog",
		    FMD_ADM, FMD_ADM, FMD_ADM_VERSION_1,
		    (uint_t)sndsize, (uint_t)rcvsize, TRUE);
	} else {
		err = fmd_rpc_svc_init(fmd_adm_1, "FMD_ADM", s, "rpc.adm.prog",
		    RPC_TRANS_MIN, RPC_TRANS_MAX, FMD_ADM_VERSION_1,
		    (uint_t)sndsize, (uint_t)rcvsize, FALSE);
	}

	if (err != 0)
		fmd_error(EFMD_EXIT, "failed to create rpc server bindings");

	if (fmd_thread_create(fmd.d_rmod, (fmd_thread_f *)svc_run, 0) == NULL)
		fmd_error(EFMD_EXIT, "failed to create rpc server thread");
}

void
fmd_rpc_fini(void)
{
	rpcprog_t prog;

	svc_exit(); /* force svc_run() threads to exit */

	(void) fmd_conf_getprop(fmd.d_conf, "rpc.adm.prog", &prog);
	svc_unreg(prog, FMD_ADM_VERSION_1);

	(void) fmd_conf_getprop(fmd.d_conf, "rpc.api.prog", &prog);
	svc_unreg(prog, FMD_API_VERSION_1);
}

/*
 * Utillity function to fetch the XPRT's ucred and determine if we should deny
 * the request.  For now, we implement a simple policy of rejecting any caller
 * who does not have the PRIV_SYS_CONFIG bit in their Effective privilege set,
 * unless the caller is loading a module, which requires all privileges.
 */
int
fmd_rpc_deny(struct svc_req *rqp)
{
	ucred_t *ucp = alloca(ucred_size());
	const priv_set_t *psp;

	if (!fmd.d_booted) {
		(void) pthread_mutex_lock(&fmd.d_fmd_lock);
		while (!fmd.d_booted)
			(void) pthread_cond_wait(&fmd.d_fmd_cv,
			    &fmd.d_fmd_lock);
		(void) pthread_mutex_unlock(&fmd.d_fmd_lock);
	}

	if (svc_getcallerucred(rqp->rq_xprt, &ucp) != 0 ||
	    (psp = ucred_getprivset(ucp, PRIV_EFFECTIVE)) == NULL)
		return (1); /* deny access if we can't get credentials */

#ifndef DEBUG
	/*
	 * For convenience of testing, we only require all privileges for a
	 * module load when running a non-DEBUG fault management daemon.
	 */
	if (rqp->rq_proc == FMD_ADM_MODLOAD)
		return (!priv_isfullset(psp));
#endif
	return (!priv_ismember(psp, PRIV_SYS_CONFIG));
}
