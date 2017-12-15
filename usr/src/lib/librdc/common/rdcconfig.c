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


#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <thread.h>
#include <pthread.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/rdc_prot.h>
#include <sys/nsctl/librdc.h>
#include <sys/nsctl/rdcrules.h>
#include <sys/nsctl/rdcerr.h>
#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_dtrinkets.h>
#include <sys/unistat/spcs_etrinkets.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <rpc/rpc_com.h>
#include <rpc/rpc.h>

struct netbuf svaddr, *svp;
struct netconfig nconf, *conf;
struct knetconfig knconf;

/*
 * libdscfg type stuff here
 */
extern int sv_enable(CFGFILE *cfg, rdcconfig_t *rdc);
extern int add_to_rdc_cfg(rdcconfig_t *rdcs);
extern int remove_from_rdc_cfg(rdcconfig_t *rdcs);
extern int replace_cfgfield(rdcconfig_t *rdcs, char *field, char *value);
extern int reverse_in_cfg(rdcconfig_t *rdcs);

rdcconfig_t *
rdc_dup_config(rdcconfig_t *orig)
{
	rdcconfig_t *rc;

	rc = (rdcconfig_t *)calloc(1, sizeof (*rc));
	if (!rc) {
		rdc_set_error(NULL, RDC_OS, RDC_FATAL, NULL);
		return (NULL);
	}

	*rc = *orig;
	rc->next = NULL; /* don't want to hook into wrong chaing */
	return (rc);
}

/*
 * takes in a chain of rdcconfig_t's and a chain
 * of rdc_rc_t's, checks for success in the rdc_rc_t,
 * then adds the corresponding rdcconfig_t to the return
 * chain.
 */
rdcconfig_t *
chain_successful(rdcconfig_t *rdcs, rdc_rc_t *rcs)
{
	rdc_rc_t *rcp;
	rdcconfig_t *rdcp;
	rdcconfig_t *ret = NULL;
	rdcconfig_t *retp = NULL;

	rcp = rcs;
	rdcp = rdcs;

	while (rcp) {
		if (rcp->rc == 0) {
			if ((ret == NULL) && (rdcp->persist)) {
				retp = ret = rdc_dup_config(rdcp);

			} else if ((ret) && (rdcp->persist)) {
				retp->next = rdc_dup_config(rdcp);
				retp = retp->next;
			}
		}
		rcp = rcp->next;
		rdcp = rdcp->next;
	}
	return (ret);

}

rdc_set_t
config2set(rdcconfig_t *rdc)
{
	rdc_set_t urdc;

	bzero(&urdc, sizeof (rdc_set_t));
	strncpy(urdc.primary.intf, rdc->phost, MAX_RDC_HOST_SIZE);
	strncpy(urdc.primary.file, rdc->pfile, NSC_MAXPATH);
	strncpy(urdc.primary.bitmap, rdc->pbmp, NSC_MAXPATH);
	strncpy(urdc.secondary.intf, rdc->shost, MAX_RDC_HOST_SIZE);
	strncpy(urdc.secondary.file, rdc->sfile, NSC_MAXPATH);
	strncpy(urdc.secondary.bitmap, rdc->sbmp, NSC_MAXPATH);
	strncpy(urdc.group_name, rdc->group, NSC_MAXPATH);

	return (urdc);
}

rdc_rc_t *
new_rc()
{
	rdc_rc_t *rc;

	rc = (rdc_rc_t *)calloc(1, sizeof (*rc));
	if (rc == NULL) {
		rdc_set_error(NULL, RDC_OS, RDC_FATAL, NULL);
		return (NULL);
	}
	return (rc);
}

rdc_rc_t
rdc_config(rdc_config_t *rdccfg)
{
	rdc_rc_t rc;
	rdc_set_t *set;
	spcs_s_info_t ustatus;

	bzero(&rc, sizeof (rc));
	ustatus = spcs_s_ucreate();

	if (self_check(rdccfg->rdc_set->primary.intf)) {
		rdccfg->options |= RDC_OPT_PRIMARY;
		/* this needs changin if we do campus */
		rdccfg->rdc_set->direct_file[0] = 0;
	} else {
		rdccfg->options |= RDC_OPT_SECONDARY;
	}

	/* set up return stuff.. */
	set = &rdccfg->rdc_set[0];
	strncpy(rc.set.phost, set->primary.intf, MAX_RDC_HOST_SIZE);
	strncpy(rc.set.pfile, set->primary.file, NSC_MAXPATH);
	strncpy(rc.set.shost, set->secondary.intf, MAX_RDC_HOST_SIZE);
	strncpy(rc.set.sfile, set->secondary.file, NSC_MAXPATH);

	rc.rc = RDC_IOCTL(RDC_CONFIG, rdccfg, NULL, 0, 0, 0, ustatus);

	if (rc.rc < 0) {
		rdc_set_error(&ustatus, RDC_SPCS, 0, 0);
		strncpy(rc.msg, rdc_error(NULL), RDC_ERR_SIZE);
	}

	return (rc);
}

void *
rdc_mtconfig(void *rdc)
{
	rdc_rc_t *rc[1];
	rdc_set_t *set;
	spcs_s_info_t ustatus;
	rdc_config_t *rdccfg = (rdc_config_t *)rdc;

	ustatus = spcs_s_ucreate();

	if (self_check(rdccfg->rdc_set->primary.intf)) {
		rdccfg->options |= RDC_OPT_PRIMARY;
		/* this needs changin if we do campus */
		rdccfg->rdc_set->direct_file[0] = 0;
	} else {
		rdccfg->options |= RDC_OPT_SECONDARY;
	}

	set = &rdccfg->rdc_set[0];
	*rc = new_rc();

	strncpy(rc[0]->set.phost, set->primary.intf, MAX_RDC_HOST_SIZE);
	strncpy(rc[0]->set.pfile, set->primary.file, NSC_MAXPATH);
	strncpy(rc[0]->set.pbmp, set->primary.bitmap, NSC_MAXPATH);
	strncpy(rc[0]->set.shost, set->secondary.intf, MAX_RDC_HOST_SIZE);
	strncpy(rc[0]->set.sfile, set->secondary.file, NSC_MAXPATH);
	strncpy(rc[0]->set.sbmp, set->secondary.bitmap, NSC_MAXPATH);

	rc[0]->rc = RDC_IOCTL(RDC_CONFIG, rdccfg, NULL, 0, 0, 0, ustatus);

	if (rc[0]->rc < 0) {
		rdc_set_error(&ustatus, RDC_SPCS, 0, 0);
		strncpy(rc[0]->msg, rdc_error(NULL), RDC_ERR_SIZE);
	}

	sleep(1); /* give thr_join a chance to be called */
	free(rdccfg);
	thr_exit((void **) *rc);
	return (NULL);
}
int
populate_addrs(rdc_set_t *urdc, int isenable)
{
	struct t_info tinfo;
	struct hostent *hp;
	char toname[MAX_RDC_HOST_SIZE];
	char fromname[MAX_RDC_HOST_SIZE];

	strncpy(fromname, urdc->primary.intf, MAX_RDC_HOST_SIZE);
	strncpy(toname, urdc->secondary.intf, MAX_RDC_HOST_SIZE);

	if ((fromname[0] == '\0') || (fromname[0] == '\0')) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_FATAL,
		    "NULL hostname recieved");
		return (-1);
	}

	hp = gethost_byname(fromname);
	strncpy(fromname, hp->h_name, MAX_RDC_HOST_SIZE);
	hp = gethost_byname(toname);
	strncpy(toname, hp->h_name, MAX_RDC_HOST_SIZE);

	if (self_check(fromname) && self_check(toname)) {
		rdc_set_error(NULL, RDC_INTERNAL, RDC_FATAL, "");
	}

	if (isenable) {
		svp = get_addr(toname, RDC_PROGRAM, RDC_VERS_MIN,
		    &conf, NULL, "rdc", &tinfo, 0);
		if (svp == NULL)
			return (-1);
		svaddr = *svp;
	} else {
		bzero(&svaddr, sizeof (svaddr));
	}

	urdc->secondary.addr.len = svaddr.len;
	urdc->secondary.addr.maxlen = svaddr.maxlen;
	urdc->secondary.addr.buf = (void*)svaddr.buf;

	if (isenable) {
		svp = get_addr(fromname, RDC_PROGRAM, RDC_VERS_MIN,
		    &conf, NULL, "rdc", &tinfo, 0);
		if (svp == NULL)
			return (-1);
		svaddr = *svp;
	} else {
		bzero(&svaddr, sizeof (svaddr));
	}

	urdc->primary.addr.len = svaddr.len;
	urdc->primary.addr.maxlen = svaddr.maxlen;
	urdc->primary.addr.buf = (void*)svaddr.buf;

	if (isenable) {
		convert_nconf_to_knconf(conf, &knconf);
		urdc->netconfig = &knconf;
	} else {
		urdc->netconfig = NULL;
	}
	urdc->syshostid = (int32_t)gethostid();

	return (1);

}
void
rdc_free_config(rdcconfig_t *rdc, int all)
{
	rdcconfig_t *rdcp;
	rdcconfig_t *rdcq;

	rdcp = rdc;
	if (all == RDC_FREEONE) {
		free(rdcp);
	} else while (rdcp) {
		rdcq = rdcp->next;
		free(rdcp);
		rdcp = rdcq;
	}
	rdc = NULL;
}

void
rdc_free_rclist(rdc_rc_t *rc)
{
	rdc_rc_t *rcp, *rcq;

	rcp = rc;
	while (rcp) {
		rcq = rcp->next;
		free(rcp);
		rcp = rcq;
	}

}
/*ARGSUSED*/
rdcconfig_t *
rdc_alloc_config(const char *phost, const char *pfile,
    const char *pbmp, const char *shost, const char *sfile, const char *sbmp,
    const char *mode, const char *group, const char *ctag, const char *options,
    int persist)
{
	rdcconfig_t *rc;

	rc = (rdcconfig_t *)calloc(1, sizeof (*rc));
	if (!rc) {
		rdc_set_error(NULL, RDC_OS, RDC_FATAL, NULL);
		return (NULL);
	}
	if (phost)
		strncpy(rc->phost, phost, NSC_MAXPATH);
	if (pfile)
		strncpy(rc->pfile, pfile, NSC_MAXPATH);
	if (pbmp)
		strncpy(rc->pbmp, pbmp, NSC_MAXPATH);
	if (shost)
		strncpy(rc->shost, shost, NSC_MAXPATH);
	if (sfile)
		strncpy(rc->sfile, sfile, NSC_MAXPATH);
	if (sbmp)
		strncpy(rc->sbmp, sbmp, NSC_MAXPATH);

	strncpy(rc->direct, "ip", 2);

	if (mode)
		strncpy(rc->mode, mode, NSC_MAXPATH);
	if (ctag)
		strncpy(rc->ctag, ctag, NSC_MAXPATH);
	if (options)
		strncpy(rc->options, options, NSC_MAXPATH);

	rc->persist = persist;
	rc->next = NULL;

	return (rc);

}

void
populate_rc(rdc_rc_t *rcp, rdcconfig_t *rdcp)
{
	rcp->rc = -1;
	strncpy(rcp->msg, rdc_error(NULL), RDC_ERR_SIZE);
	strncpy(rcp->set.phost, rdcp->phost, NSC_MAXPATH);
	strncpy(rcp->set.pfile, rdcp->pfile, NSC_MAXPATH);
	strncpy(rcp->set.shost, rdcp->shost, NSC_MAXPATH);
	strncpy(rcp->set.sfile, rdcp->sfile, NSC_MAXPATH);
}

/*
 * rdc_enable
 * return values
 * NULL on error
 * pointer to rdc_rc_t list of return values
 */
rdc_rc_t *
rdc_enable(rdcconfig_t *rdc)
{
	rdc_config_t 	rdccfg;
	rdcconfig_t 	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) { /* error already set */
		return (NULL);
	}
	rcp = rc;
	while (rdcp) {
		if (!rdcp->mode) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    RDC_EINVAL);
			return (NULL);
		}
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_ENABLE;
		rdccfg.options = RDC_OPT_SETBMP;
		if (strncmp(rdcp->mode, "sync", NSC_MAXPATH) == 0) {
			rdccfg.options |= RDC_OPT_SYNC;
		} else if (strncmp(rdc->mode, "async", NSC_MAXPATH) == 0) {
			rdccfg.options |= RDC_OPT_ASYNC;
		} else {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    RDC_EINVAL);
			return (NULL);
		}

		populate_addrs(&rdccfg.rdc_set[0], 1);

		if (can_enable(rdcp)) {
			/* do the operation */
			*rcp = rdc_config(&rdccfg);

		} else { /* set up what rdc_config would've set up */

			populate_rc(rcp, rdcp);

		}
		if ((rcp->rc == 0) && (!rdcp->persist)) {
			/*
			 * if we are not persisting, do this now,
			 * otherwise we will do it when
			 * we have a lock on the cfg in add_to_rdc_cfg
			 */
			sv_enable(NULL, rdcp);
		}

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp) {
			/* dont free here, return what you have */
			break;
		}
	}

	/*
	 * travel the rc chain and rdc chain checking results,
	 * building a new chain, and updating dscfg
	 */
	rcp = rc;
	rdcp = rdc;

	cfg_rdcs = chain_successful(rdcp, rcp);

	if (add_to_rdc_cfg(cfg_rdcs) < 0) {
		/* XXX should disable or something here */
		return (rc);
	}
	rdc_free_config(cfg_rdcs, RDC_FREEALL);
	return (rc);

}

rdc_rc_t *
rdc_enable_clrbmp(rdcconfig_t *rdc)
{
	rdc_config_t 	rdccfg;
	rdcconfig_t 	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = (rdc_rc_t *)calloc(1, sizeof (rdc_rc_t));
	if (!rc) {
		rdc_set_error(NULL, RDC_OS, RDC_FATAL, NULL);
		return (NULL);
	}
	rcp = rc;
	while (rdcp) {
		if (!rdcp->mode) {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    RDC_EINVAL);
			return (NULL);
		}
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_ENABLE;
		rdccfg.options = RDC_OPT_CLRBMP;
		if (strncmp(rdcp->mode, "sync", NSC_MAXPATH) == 0) {
			rdccfg.options |= RDC_OPT_SYNC;
		} else if (strncmp(rdc->mode, "async", NSC_MAXPATH) == 0) {
			rdccfg.options |= RDC_OPT_ASYNC;
		} else {
			rdc_set_error(NULL, RDC_INTERNAL, RDC_NONFATAL,
			    RDC_EINVAL);
			return (NULL);
		}

		populate_addrs(&rdccfg.rdc_set[0], 1);

		if (can_enable(rdcp)) {
			/* do the operation */
			*rcp = rdc_config(&rdccfg);

		} else { /* set up what rdc_config would've set up */

			populate_rc(rcp, rdcp);

		}
		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = (rdc_rc_t *)calloc(1, sizeof (rdc_rc_t));
		rcp = rcp->next;
		if (!rcp)
			break;
	}

	/*
	 * travel the rc chain and rdc chain checking results,
	 * building a new chain, and updating dscfg
	 */
	rcp = rc;
	rdcp = rdc;

	cfg_rdcs = chain_successful(rdcp, rcp);

	if (add_to_rdc_cfg(cfg_rdcs) < 0) {
		/* XXX should disable or something here */
		return (rc);
	}
	rdc_free_config(cfg_rdcs, RDC_FREEALL);

	return (rc);

}

rdc_rc_t *
rdc_disable(rdcconfig_t *rdc)
{
	rdc_config_t	rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {

		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_DISABLE;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			return (rc);

	}
	rcp = rc;
	rdcp = rdc;

	cfg_rdcs = chain_successful(rdcp, rcp);

	remove_from_rdc_cfg(cfg_rdcs);

	rdc_free_config(cfg_rdcs, RDC_FREEALL);

	return (rc);
}

rdc_rc_t *
rdc_log(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_LOG;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	return (rc);
}

rdc_rc_t *
rdc_usync(rdcconfig_t *rdc)
{
	rdc_config_t *rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;
	rdc_rc_t	*tmprc;

	rdcp = rdc;

	while (rdcp) {
		/* freed in rdc_mtconfig */
		rdccfg = (rdc_config_t *)calloc(1, sizeof (rdc_config_t));
		rdccfg->rdc_set[0] = config2set(rdcp);
		rdccfg->command = RDC_CMD_COPY;
		rdccfg->options = RDC_OPT_UPDATE|RDC_OPT_FORWARD;
		populate_addrs(&rdccfg->rdc_set[0], 0);
		(void) thr_create(NULL, 0, rdc_mtconfig,
		    (void **) rdccfg, THR_BOUND, NULL);
		rdcp = rdcp->next;
		if (!rdcp)
			break;

	}

	/*
	 * collect status here from thr_join-status,
	 * and add to rdc_rc_t chain ?
	 * this will block, but caller could always thread too
	 */
	while (thr_join(NULL, NULL, (void**) &tmprc) == 0) {
		if (rc == NULL) {
			rcp = rc = (rdc_rc_t *)tmprc;
		} else {
			rcp->next = (rdc_rc_t *)tmprc;
			rcp = rcp->next;
		}
	}

	return (rc);
}

rdc_rc_t *
rdc_fsync(rdcconfig_t *rdc)
{
	rdc_config_t *rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;
	rdc_rc_t	*tmprc = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		/* freed in rdc_mtconfig */
		rdccfg = (rdc_config_t *)calloc(1, sizeof (rdc_config_t));
		rdccfg->rdc_set[0] = config2set(rdcp);
		rdccfg->command = RDC_CMD_COPY;
		rdccfg->options = RDC_OPT_FULL|RDC_OPT_FORWARD;
		populate_addrs(&rdccfg->rdc_set[0], 0);
		(void) thr_create(NULL, 0, rdc_mtconfig,
		    (void **) rdccfg, THR_BOUND, NULL);
		rdcp = rdcp->next;
		if (!rdcp)
			break;

	}

	/*
	 * collect status here from thr_join-status,
	 * and add to rdc_rc_t chain ?
	 * this will block, but caller could always thread too
	 */
	while (thr_join(NULL, NULL, (void**) &tmprc) == 0) {
		if (rc == NULL) {
			rcp = rc = (rdc_rc_t *)tmprc;
		} else {
			rcp->next = (rdc_rc_t *)tmprc;
			rcp = rcp->next;
		}
	}

	return (rc);
}

rdc_rc_t *
rdc_rsync(rdcconfig_t *rdc)
{
	rdc_config_t *rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;
	rdc_rc_t	*tmprc = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		tmprc = cant_rsync(rdcp);
		if (tmprc != NULL) {
			if (rc == NULL) {
				rcp = rc = tmprc;
			} else {
				rcp->next = tmprc;
				rcp = rcp->next;
			}
			goto next;
		}

		/* freed in rdc_mtconfig */
		rdccfg = (rdc_config_t *)calloc(1, sizeof (rdc_config_t));
		rdccfg->rdc_set[0] = config2set(rdcp);
		rdccfg->command = RDC_CMD_COPY;
		rdccfg->options = RDC_OPT_REVERSE|RDC_OPT_FULL;
		populate_addrs(&rdccfg->rdc_set[0], 0);
		(void) thr_create(NULL, 0, rdc_mtconfig,
		    (void **) rdccfg, THR_BOUND, NULL);
next:
		rdcp = rdcp->next;
		if (!rdcp)
			break;
	}

	/*
	 * collect status here from thr_join-status,
	 * and add to rdc_rc_t chain ?
	 * this will block, but caller could always thread too
	 */
	while (thr_join(NULL, NULL, (void**) &tmprc) == 0) {
		if (rc == NULL) {
			rcp = rc = (rdc_rc_t *)tmprc;
		} else {
			rcp->next = (rdc_rc_t *)tmprc;
			rcp = rcp->next;
		}
	}

	return (rc);
}

rdc_rc_t *
rdc_ursync(rdcconfig_t *rdc)
{
	rdc_config_t *rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;
	rdc_rc_t	*tmprc = NULL;

	rdcp = rdc;

	while (rdcp) {
		tmprc = cant_rsync(rdcp);
		if (tmprc != NULL) {
			if (rc == NULL) {
				rcp = rc = tmprc;
			} else {
				rcp->next = tmprc;
				rcp = rcp->next;
			}
			goto next;
		}

		/* freed in rdc_mtconfig */
		rdccfg = (rdc_config_t *)calloc(1, sizeof (rdc_config_t));
		rdccfg->rdc_set[0] = config2set(rdcp);
		rdccfg->command = RDC_CMD_COPY;
		rdccfg->options = RDC_OPT_REVERSE | RDC_OPT_UPDATE;
		populate_addrs(&rdccfg->rdc_set[0], 0);
		(void) thr_create(NULL, 0, rdc_mtconfig,
		    (void **) rdccfg, THR_BOUND, NULL);
next:
		rdcp = rdcp->next;
		if (!rdcp)
			break;

	}

	/*
	 * collect status here from thr_join-status,
	 * and add to rdc_rc_t chain ?
	 * this will block, but caller could always thread too
	 */
	while (thr_join(NULL, NULL, (void**) &tmprc) == 0) {
		if (rc == NULL) {
			rcp = rc = (rdc_rc_t *)tmprc;
		} else {
			rcp->next = (rdc_rc_t *)tmprc;
			rcp = rcp->next;
		}
	}

	return (rc);
}

rdc_rc_t *
rdc_wait(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_WAIT;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	return (rc);
}

rdc_rc_t *
rdc_set_autosync(rdcconfig_t *rdc, int autosync)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_TUNABLE;
		rdccfg.rdc_set[0].autosync = autosync;
		rdccfg.rdc_set[0].maxqitems = -1;
		rdccfg.rdc_set[0].maxqfbas = -1;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	return (rc);
}

rdc_rc_t *
rdc_set_maxqfbas(rdcconfig_t *rdc, int maxqfbas)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_TUNABLE;
		rdccfg.rdc_set[0].autosync = -1;
		rdccfg.rdc_set[0].maxqitems = -1;
		rdccfg.rdc_set[0].maxqfbas = maxqfbas;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	return (rc);
}

rdc_rc_t *
rdc_set_maxqitems(rdcconfig_t *rdc, int maxqitems)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();

	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdc);
		rdccfg.command = RDC_CMD_TUNABLE;
		rdccfg.rdc_set[0].autosync = -1;
		rdccfg.rdc_set[0].maxqitems = maxqitems;
		rdccfg.rdc_set[0].maxqfbas = -1;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	return (rc);
}

rdc_set_t
rdc_status(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;

	bzero(&rdccfg, sizeof (rdc_config_t));
	rdccfg.rdc_set[0] = config2set(rdc);
	rdccfg.command = RDC_CMD_STATUS;
	populate_addrs(&rdccfg.rdc_set[0], 0);
	rdc_config(&rdccfg);

	return (rdccfg.rdc_set[0]);
}

int
rdc_get_autosync(rdcconfig_t *rdc)
{
	rdc_set_t rdcset;

	rdcset = rdc_status(rdc);
	return (rdcset.autosync);
}

int
rdc_get_maxqfbas(rdcconfig_t *rdc)
{
	rdc_set_t rdcset;

	rdcset = rdc_status(rdc);
	return (rdcset.maxqfbas);

}

int
rdc_get_maxqitems(rdcconfig_t *rdc)
{
	rdc_set_t rdcset;

	rdcset = rdc_status(rdc);
	return (rdcset.maxqitems);

}

int
set_mode(rdcconfig_t *rdc)
{
	if (strcmp(rdc->mode, "async") == 0)
		return (RDC_OPT_ASYNC);
	else
		return (RDC_OPT_SYNC);
}

/*
 * reconfig bitmaps are single set only ops
 * for obvious reasons
 */
rdc_rc_t *
rdc_reconfig_pbmp(rdcconfig_t *rdc, char *pbmp)
{
	rdc_config_t rdccfg;
	rdc_rc_t *rc;

	rc = new_rc();
	if ((!rc) || (!pbmp))
		return (NULL);

	bzero(&rdccfg, sizeof (rdc_config_t));
	rdccfg.rdc_set[0] = config2set(rdc);
	strncpy(rdccfg.rdc_set[0].primary.bitmap, pbmp, NSC_MAXPATH);
	rdccfg.command = RDC_CMD_RECONFIG;
	rdccfg.options |= set_mode(rdc);
	populate_addrs(&rdccfg.rdc_set[0], 0);

	if (can_reconfig_pbmp(rdc, pbmp))
		*rc = rdc_config(&rdccfg);
	else
		populate_rc(rc, rdc);

	if ((rc->rc == 0) && (rdc->persist))
		if (replace_cfgfield(rdc, "pbitmap", pbmp) < 0) {
			rc->rc = -1;
			strncpy(rc->msg, rdc_error(NULL), RDC_ERR_SIZE);
		}
	return (rc);
}

rdc_rc_t *
rdc_reconfig_sbmp(rdcconfig_t *rdc, char *sbmp)
{
	rdc_config_t rdccfg;
	rdc_rc_t *rc;

	rc = new_rc();
	if (!rc)
		return (NULL);

	bzero(&rdccfg, sizeof (rdc_config_t));
	rdccfg.rdc_set[0] = config2set(rdc);
	strncpy(rdccfg.rdc_set[0].secondary.bitmap, sbmp, NSC_MAXPATH);
	rdccfg.command = RDC_CMD_RECONFIG;
	rdccfg.options |= set_mode(rdc);
	populate_addrs(&rdccfg.rdc_set[0], 0);

	if (can_reconfig_sbmp(rdc, sbmp))
		*rc = rdc_config(&rdccfg);
	else
		populate_rc(rc, rdc);

	if ((rc->rc == 0) && (rdc->persist))
		replace_cfgfield(rdc, "sbitmap", sbmp);

	return (rc);
}

rdc_rc_t *
rdc_reconfig_group(rdcconfig_t *rdc, char *group)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		/* just in case */
		strncpy(rdcp->group, group, NSC_MAXPATH);
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_RECONFIG;
		rdccfg.options |= set_mode(rdcp);
		populate_addrs(&rdccfg.rdc_set[0], 0);

		/* reconfig group rules enforced in kernel */
		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	rcp = rc;
	rdcp = rdc;
	cfg_rdcs = chain_successful(rdcp, rcp);
	replace_cfgfield(cfg_rdcs, "group", group);
	rdc_free_config(cfg_rdcs, RDC_FREEALL);

	return (rc);
}
/*ARGSUSED*/
rdc_rc_t *
rdc_reconfig_ctag(rdcconfig_t *rdc, char *ctag)
{
	return (NULL);
}

rdc_rc_t *
rdc_set_sync(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdc);
		rdccfg.command = RDC_CMD_RECONFIG;
		rdccfg.options |= RDC_OPT_SYNC;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}

	rcp = rc;
	rdcp = rdc;
	cfg_rdcs = chain_successful(rdcp, rcp);
	replace_cfgfield(cfg_rdcs, "mode", "sync");
	rdc_free_config(cfg_rdcs, RDC_FREEALL);

	return (rc);
}

rdc_rc_t *
rdc_set_async(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_RECONFIG;
		rdccfg.options |= RDC_OPT_ASYNC;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	rcp = rc;
	rdcp = rdc;
	cfg_rdcs = chain_successful(rdcp, rcp);
	replace_cfgfield(cfg_rdcs, "mode", "async");
	rdc_free_config(cfg_rdcs, RDC_FREEALL);

	return (rc);
}

rdc_rc_t *
rdc_health(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_HEALTH;
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;

		if (!rcp)
			break;

	}
	return (rc);
}

rdc_rc_t *
rdc_reverse_role(rdcconfig_t *rdc)
{
	rdc_config_t rdccfg;
	rdcconfig_t	*rdcp = NULL;
	rdcconfig_t	*cfg_rdcs = NULL;
	rdc_rc_t	*rc = NULL;
	rdc_rc_t	*rcp = NULL;

	rdcp = rdc;
	rc = new_rc();
	if (!rc) {
		return (NULL);
	}
	rcp = rc;

	while (rdcp) {
		bzero(&rdccfg, sizeof (rdc_config_t));
		rdccfg.rdc_set[0] = config2set(rdcp);
		rdccfg.command = RDC_CMD_RECONFIG;
		rdccfg.options |= RDC_OPT_REVERSE_ROLE;
		rdccfg.options |= set_mode(rdcp);
		populate_addrs(&rdccfg.rdc_set[0], 0);

		*rcp = rdc_config(&rdccfg);

		rdcp = rdcp->next;
		if (!rdcp)
			break;

		rcp->next = new_rc();
		rcp = rcp->next;
		if (!rcp)
			break;
	}
	rcp = rc;
	rdcp = rdc;
	cfg_rdcs = chain_successful(rdcp, rcp);
	reverse_in_cfg(cfg_rdcs);
	rdc_free_config(cfg_rdcs, RDC_FREEALL);

	return (rc);
}
