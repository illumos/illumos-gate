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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <kstat.h>
#include <ofmt.h>
#include <libilb.h>
#include "ilbadm.h"

#define	ILBST_TIMESTAMP_HEADER	0x01	/* a timestamp w. every header */
#define	ILBST_DELTA_INTERVAL	0x02	/* delta over specified interval */
#define	ILBST_ABS_NUMBERS	0x04	/* print absolute numbers, no d's */
#define	ILBST_ITEMIZE		0x08	/* itemize */
#define	ILBST_VERBOSE		0x10	/* verbose error info */

#define	ILBST_OLD_VALUES	0x20	/* for internal processing */
#define	ILBST_RULES_CHANGED	0x40

typedef struct {
	char		is_name[KSTAT_STRLEN];
	uint64_t	is_value;
} ilbst_stat_t;

static ilbst_stat_t rulestats[] = {
	{"num_servers", 0},
	{"bytes_not_processed", 0},
	{"pkt_not_processed", 0},
	{"bytes_dropped", 0},
	{"pkt_dropped", 0},
	{"nomem_bytes_dropped", 0},
	{"nomem_pkt_dropped", 0},
	{"noport_bytes_dropped", 0},
	{"noport_pkt_dropped", 0},
	{"icmp_echo_processed", 0},
	{"icmp_dropped", 0},
	{"icmp_too_big_processed", 0},
	{"icmp_too_big_dropped", 0}
};

/* indices into array above, to avoid searching */
#define	RLSTA_NUM_SRV		0
#define	RLSTA_BYTES_U		1
#define	RLSTA_PKT_U		2
#define	RLSTA_BYTES_D		3
#define	RLSTA_PKT_D		4
#define	RLSTA_NOMEMBYTES_D	5
#define	RLSTA_NOMEMPKT_D	6
#define	RLSTA_NOPORTBYTES_D	7
#define	RLSTA_NOPORTPKT_D	8
#define	RLSTA_ICMP_P		9
#define	RLSTA_ICMP_D		10
#define	RLSTA_ICMP2BIG_P	11
#define	RLSTA_ICMP2BIG_D	12

static ilbst_stat_t servstats[] = {
	{"bytes_processed", 0},
	{"pkt_processed", 0}
};
/* indices into array above, to avoid searching */
#define	SRVST_BYTES_P	0
#define	SRVST_PKT_P	1

/* values used for of_* commands as id */
#define	ILBST_PKT_P		0
#define	ILBST_BYTES_P		1
#define	ILBST_PKT_U		2
#define	ILBST_BYTES_U		3
#define	ILBST_PKT_D		4
#define	ILBST_BYTES_D		5
#define	ILBST_ICMP_P		6
#define	ILBST_ICMP_D		7
#define	ILBST_ICMP2BIG_P	8
#define	ILBST_ICMP2BIG_D	9
#define	ILBST_NOMEMP_D		10
#define	ILBST_NOPORTP_D		11
#define	ILBST_NOMEMB_D		12
#define	ILBST_NOPORTB_D		13

#define	ILBST_ITEMIZE_SNAME	97
#define	ILBST_ITEMIZE_RNAME	98
#define	ILBST_TIMESTAMP		99

/* approx field widths */
#define	ILBST_PKTCTR_W		8
#define	ILBST_BYTECTR_W		10
#define	ILBST_TIME_W		15

static boolean_t of_rule_stats(ofmt_arg_t *, char *, uint_t);
static boolean_t of_server_stats(ofmt_arg_t *, char *, uint_t);
static boolean_t of_itemize_stats(ofmt_arg_t *, char *, uint_t);
static boolean_t of_timestamp(ofmt_arg_t *, char *, uint_t);

static ofmt_field_t stat_itemize_fields[] = {
	{"RULENAME", ILB_NAMESZ,	ILBST_ITEMIZE_RNAME, of_itemize_stats},
	{"SERVERNAME", ILB_NAMESZ,	ILBST_ITEMIZE_SNAME, of_itemize_stats},
	{"PKT_P",   ILBST_PKTCTR_W,	ILBST_PKT_P, of_itemize_stats},
	{"BYTES_P", ILBST_BYTECTR_W,	ILBST_BYTES_P, of_itemize_stats},
	{"TIME",    ILBST_TIME_W,	ILBST_TIMESTAMP, of_timestamp},
	{NULL,	    0, 0, NULL}
};
static ofmt_field_t stat_stdfields[] = {
	{"PKT_P",   ILBST_PKTCTR_W,	ILBST_PKT_P, of_server_stats},
	{"BYTES_P", ILBST_BYTECTR_W,	ILBST_BYTES_P, of_server_stats},
	{"PKT_U",   ILBST_PKTCTR_W,	ILBST_PKT_U, of_rule_stats},
	{"BYTES_U", ILBST_BYTECTR_W,	ILBST_BYTES_U, of_rule_stats},
	{"PKT_D",   ILBST_PKTCTR_W,	ILBST_PKT_D, of_rule_stats},
	{"BYTES_D", ILBST_BYTECTR_W,	ILBST_BYTES_D, of_rule_stats},
	{"ICMP_P",  ILBST_PKTCTR_W,	ILBST_ICMP_P, of_rule_stats},
	{"ICMP_D",  ILBST_PKTCTR_W,	ILBST_ICMP_D, of_rule_stats},
	{"ICMP2BIG_P", 11,		ILBST_ICMP2BIG_P, of_rule_stats},
	{"ICMP2BIG_D", 11,		ILBST_ICMP2BIG_D, of_rule_stats},
	{"NOMEMP_D", ILBST_PKTCTR_W,	ILBST_NOMEMP_D, of_rule_stats},
	{"NOPORTP_D", ILBST_PKTCTR_W,	ILBST_NOPORTP_D, of_rule_stats},
	{"NOMEMB_D", ILBST_PKTCTR_W,	ILBST_NOMEMB_D, of_rule_stats},
	{"NOPORTB_D", ILBST_PKTCTR_W,	ILBST_NOPORTB_D, of_rule_stats},
	{"TIME",    ILBST_TIME_W,	ILBST_TIMESTAMP, of_timestamp},
	{NULL,	    0, 0, NULL}
};

static char stat_stdhdrs[] = "PKT_P,BYTES_P,PKT_U,BYTES_U,PKT_D,BYTES_D";
static char stat_stdv_hdrs[] = "PKT_P,BYTES_P,PKT_U,BYTES_U,PKT_D,BYTES_D,"
	"ICMP_P,ICMP_D,ICMP2BIG_P,ICMP2BIG_D,NOMEMP_D,NOPORTP_D";
static char stat_itemize_rule_hdrs[] = "SERVERNAME,PKT_P,BYTES_P";
static char stat_itemize_server_hdrs[] = "RULENAME,PKT_P,BYTES_P";

#define	RSTAT_SZ	(sizeof (rulestats)/sizeof (rulestats[0]))
#define	SSTAT_SZ	(sizeof (servstats)/sizeof (servstats[0]))

typedef struct {
	char		isd_servername[KSTAT_STRLEN]; /* serverID */
	ilbst_stat_t	isd_serverstats[SSTAT_SZ];
	hrtime_t	isd_crtime;	/* save for comparison purpose */
} ilbst_srv_desc_t;

/*
 * this data structure stores statistics for a rule - both an old set
 * and a current/new set. we use pointers to the actual stores and switch
 * the pointers for every round. old_is_old in ilbst_arg_t indicates
 * which pointer points to the "old" data struct (ie, if true, _o pointer
 * points to old)
 */
typedef struct {
	char			ird_rulename[KSTAT_STRLEN];
	int			ird_num_servers;
	int			ird_num_servers_o;
	int			ird_srv_ind;
	hrtime_t		ird_crtime;	/* save for comparison */
	hrtime_t		ird_crtime_o;	/* save for comparison */
	ilbst_srv_desc_t	*ird_srvlist;
	ilbst_srv_desc_t	*ird_srvlist_o;
	ilbst_stat_t		ird_rstats[RSTAT_SZ];
	ilbst_stat_t		ird_rstats_o[RSTAT_SZ];
	ilbst_stat_t		*ird_rulestats;
	ilbst_stat_t		*ird_rulestats_o;
} ilbst_rule_desc_t;

/*
 * overall "container" for information pertaining to statistics, and
 * how to display them.
 */
typedef struct {
	int			ilbst_flags;
	/* fields representing user input */
	char			*ilbst_rulename;	/* optional */
	char 			*ilbst_server;	/* optional */
	int			ilbst_interval;
	int			ilbst_count;
	/* "internal" fields for data and data presentation */
	ofmt_handle_t		ilbst_oh;
	boolean_t		ilbst_old_is_old;
	ilbst_rule_desc_t	*ilbst_rlist;
	int			ilbst_rcount;	  /* current list count */
	int			ilbst_rcount_prev; /* prev (different) count */
	int			ilbst_rlist_sz; /* number of alloc'ed rules */
	int			ilbst_rule_index; /* for itemizes display */
} ilbst_arg_t;

/* ARGSUSED */
static boolean_t
of_timestamp(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	time_t		now;
	struct tm	*now_tm;

	now = time(NULL);
	now_tm = localtime(&now);

	(void) strftime(buf, bufsize, "%F:%H.%M.%S", now_tm);
	return (B_TRUE);
}

static boolean_t
i_sum_per_rule_processed(ilbst_rule_desc_t *rp, uint64_t *resp, int index,
    int flags)
{
	int			i, num_servers;
	ilbst_srv_desc_t	*srv, *o_srv, *n_srv;
	uint64_t		res = 0;
	boolean_t		valid = B_TRUE;
	boolean_t		old = flags & ILBST_OLD_VALUES;
	boolean_t		check_valid;

	/* if we do abs. numbers, we never look at the _o fields */
	assert((old && (flags & ILBST_ABS_NUMBERS)) == B_FALSE);

	/* we only check for validity under certain conditions */
	check_valid = !(old || (flags & ILBST_ABS_NUMBERS));

	if (check_valid && rp->ird_num_servers != rp->ird_num_servers_o)
		valid = B_FALSE;

	num_servers = old ? rp->ird_num_servers_o : rp->ird_num_servers;

	for (i = 0; i < num_servers; i++) {
		n_srv = &rp->ird_srvlist[i];
		o_srv = &rp->ird_srvlist_o[i];

		if (old)
			srv = o_srv;
		else
			srv = n_srv;

		res += srv->isd_serverstats[index].is_value;
		/*
		 * if creation times don't match, comparison is wrong; if
		 * if we already know something is invalid, we don't
		 * need to compare again.
		 */
		if (check_valid && valid == B_TRUE &&
		    o_srv->isd_crtime != n_srv->isd_crtime) {
			valid = B_FALSE;
			break;
		}
	}
	/*
	 * save the result even though it may be imprecise  - let the
	 * caller decide what to do
	 */
	*resp = res;

	return (valid);
}

typedef boolean_t (*sumfunc_t)(ilbst_rule_desc_t *, uint64_t *, int);

static boolean_t
i_sum_per_rule_pkt_p(ilbst_rule_desc_t *rp, uint64_t *resp, int flags)
{
	return (i_sum_per_rule_processed(rp, resp, SRVST_PKT_P, flags));
}

static boolean_t
i_sum_per_rule_bytes_p(ilbst_rule_desc_t *rp, uint64_t *resp, int flags)
{
	return (i_sum_per_rule_processed(rp, resp, SRVST_BYTES_P, flags));
}

static boolean_t
of_server_stats(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbst_arg_t	*sta = (ilbst_arg_t *)of_arg->ofmt_cbarg;
	uint64_t	count = 0, val;
	int		i;
	boolean_t	valid = B_TRUE;
	sumfunc_t	sumfunc;

	switch (of_arg->ofmt_id) {
	case ILBST_PKT_P: sumfunc = i_sum_per_rule_pkt_p;
		break;
	case ILBST_BYTES_P: sumfunc = i_sum_per_rule_bytes_p;
		break;
	}

	for (i = 0; i < sta->ilbst_rcount; i++) {
		valid = sumfunc(&sta->ilbst_rlist[i], &val, sta->ilbst_flags);
		if (!valid)
			return (valid);
		count += val;
	}

	if ((sta->ilbst_flags & ILBST_ABS_NUMBERS) != 0)
		goto out;

	for (i = 0; i < sta->ilbst_rcount; i++) {
		(void) sumfunc(&sta->ilbst_rlist[i], &val,
		    sta->ilbst_flags | ILBST_OLD_VALUES);
		count -= val;
	}

out:
	/*
	 * normally, we print "change per second", which we calculate
	 * here. otherwise, we print "change over interval"
	 */
	if ((sta->ilbst_flags & (ILBST_DELTA_INTERVAL|ILBST_ABS_NUMBERS)) == 0)
		count /= sta->ilbst_interval;

	(void) snprintf(buf, bufsize, "%llu", count);
	return (B_TRUE);
}

/*
 * this function is called when user wants itemized stats of every
 * server for a named rule, or vice vera.
 * i_do_print sets sta->rule_index and the proper ird_srv_ind so
 * we don't have to differentiate between these two cases here.
 */
static boolean_t
of_itemize_stats(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbst_arg_t	*sta = (ilbst_arg_t *)of_arg->ofmt_cbarg;
	int		stat_ind;
	uint64_t	count;
	int		rule_index = sta->ilbst_rule_index;
	int		srv_ind = sta->ilbst_rlist[rule_index].ird_srv_ind;
	boolean_t	ret = B_TRUE;
	ilbst_srv_desc_t *srv, *osrv;

	srv = &sta->ilbst_rlist[rule_index].ird_srvlist[srv_ind];

	switch (of_arg->ofmt_id) {
	case ILBST_PKT_P: stat_ind = SRVST_PKT_P;
		break;
	case ILBST_BYTES_P: stat_ind = SRVST_BYTES_P;
		break;
	case ILBST_ITEMIZE_RNAME:
		(void) snprintf(buf, bufsize, "%s",
		    sta->ilbst_rlist[rule_index].ird_rulename);
		return (B_TRUE);
	case ILBST_ITEMIZE_SNAME:
		(void) snprintf(buf, bufsize, "%s", srv->isd_servername);
		return (B_TRUE);
	}

	count = srv->isd_serverstats[stat_ind].is_value;

	if ((sta->ilbst_flags & ILBST_ABS_NUMBERS) != 0)
		goto out;

	osrv = &sta->ilbst_rlist[rule_index].ird_srvlist_o[srv_ind];
	if (srv->isd_crtime != osrv->isd_crtime)
		ret = B_FALSE;

	count -= osrv->isd_serverstats[stat_ind].is_value;
out:
	/*
	 * normally, we print "change per second", which we calculate
	 * here. otherwise, we print "change over interval" or absolute
	 * values.
	 */
	if ((sta->ilbst_flags & (ILBST_DELTA_INTERVAL|ILBST_ABS_NUMBERS)) == 0)
		count /= sta->ilbst_interval;

	(void) snprintf(buf, bufsize, "%llu", count);
	return (ret);

}

static boolean_t
of_rule_stats(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	ilbst_arg_t	*sta = (ilbst_arg_t *)of_arg->ofmt_cbarg;
	int		i, ind;
	uint64_t	count = 0;

	switch (of_arg->ofmt_id) {
	case ILBST_PKT_U: ind = RLSTA_PKT_U;
		break;
	case ILBST_BYTES_U: ind = RLSTA_BYTES_U;
		break;
	case ILBST_PKT_D: ind = RLSTA_PKT_D;
		break;
	case ILBST_BYTES_D: ind = RLSTA_BYTES_D;
		break;
	case ILBST_ICMP_P: ind = RLSTA_ICMP_P;
		break;
	case ILBST_ICMP_D: ind = RLSTA_ICMP_D;
		break;
	case ILBST_ICMP2BIG_P: ind = RLSTA_ICMP2BIG_P;
		break;
	case ILBST_ICMP2BIG_D: ind = RLSTA_ICMP2BIG_D;
		break;
	case ILBST_NOMEMP_D: ind  = RLSTA_NOMEMPKT_D;
		break;
	case ILBST_NOPORTP_D: ind = RLSTA_NOPORTPKT_D;
		break;
	case ILBST_NOMEMB_D: ind = RLSTA_NOMEMBYTES_D;
		break;
	case ILBST_NOPORTB_D: ind = RLSTA_NOPORTBYTES_D;
		break;
	}

	for (i = 0; i < sta->ilbst_rcount; i++)
		count += sta->ilbst_rlist[i].ird_rulestats[ind].is_value;

	if ((sta->ilbst_flags & ILBST_ABS_NUMBERS) != 0)
		goto out;

	/*
	 * the purist approach: if we can't say 100% that what we
	 * calculate is correct, don't.
	 */
	if (sta->ilbst_flags & ILBST_RULES_CHANGED)
		return (B_FALSE);

	for (i = 0; i < sta->ilbst_rcount; i++) {
		if (sta->ilbst_rlist[i].ird_crtime_o != 0 &&
		    sta->ilbst_rlist[i].ird_crtime !=
		    sta->ilbst_rlist[i].ird_crtime_o)
			return (B_FALSE);

		count -= sta->ilbst_rlist[i].ird_rulestats_o[ind].is_value;
	}
out:
	/*
	 * normally, we print "change per second", which we calculate
	 * here. otherwise, we print "change over interval"
	 */
	if ((sta->ilbst_flags & (ILBST_DELTA_INTERVAL|ILBST_ABS_NUMBERS)) == 0)
		count /= sta->ilbst_interval;

	(void) snprintf(buf, bufsize, "%llu", count);
	return (B_TRUE);
}

/*
 * Get the number of kstat instances. Note that when rules are being
 * drained the number of kstats instances may be different than the
 * kstat counter num_rules (ilb:0:global:num_rules").
 *
 * Also there can be multiple instances of a rule in the following
 * scenario:
 *
 * A rule named rule A has been deleted but remains in kstats because
 * its undergoing connection draining. During this time, the user adds
 * a new rule with the same name(rule A). In this case, there would
 * be two kstats instances for rule A. Currently ilbadm's aggregate
 * results will include data from both instances of rule A. In,
 * future we should have ilbadm stats only consider the latest instance
 * of the rule (ie only consider the the instance that corresponds
 * to the rule that was just added).
 *
 */
static int
i_get_num_kinstances(kstat_ctl_t *kctl)
{
	kstat_t		*kp;
	int		num_instances = 0; /* nothing found, 0 rules */

	for (kp = kctl->kc_chain; kp != NULL; kp = kp->ks_next) {
		if (strncmp("rulestat", kp->ks_class, 8) == 0 &&
		    strncmp("ilb", kp->ks_module, 3) == 0) {
			num_instances++;
		}
	}

	return (num_instances);
}


/*
 * since server stat's classname is made up of <rulename>-sstat,
 * we walk the rule list to construct the comparison
 * Return:	pointer to rule whose name matches the class
 *		NULL if no match
 */
static ilbst_rule_desc_t *
match_2_rnames(char *class, ilbst_rule_desc_t *rlist, int rcount)
{
	int i;
	char	classname[KSTAT_STRLEN];

	for (i = 0; i < rcount; i++) {
		(void) snprintf(classname, sizeof (classname), "%s-sstat",
		    rlist[i].ird_rulename);
		if (strncmp(classname, class, sizeof (classname)) == 0)
			return (&rlist[i]);
	}
	return (NULL);
}

static int
i_stat_index(kstat_named_t *knp, ilbst_stat_t *stats, int count)
{
	int	i;

	for (i = 0; i < count; i++) {
		if (strcasecmp(stats[i].is_name, knp->name) == 0)
			return (i);
	}

	return (-1);
}

static void
i_copy_sstats(ilbst_srv_desc_t *sp, kstat_t *kp)
{
	kstat_named_t	*knp;
	int		i, ind;

	knp = KSTAT_NAMED_PTR(kp);
	for (i = 0; i < kp->ks_ndata; i++, knp++) {
		ind = i_stat_index(knp, servstats, SSTAT_SZ);
		if (ind == -1)
			continue;
		(void) strlcpy(sp->isd_serverstats[ind].is_name, knp->name,
		    sizeof (sp->isd_serverstats[ind].is_name));
		sp->isd_serverstats[ind].is_value = knp->value.ui64;
		sp->isd_crtime = kp->ks_crtime;
	}
}


static ilbadm_status_t
i_get_server_descs(ilbst_arg_t *sta, kstat_ctl_t *kctl)
{
	ilbadm_status_t	rc = ILBADM_OK;
	kstat_t		*kp;
	int		i = -1;
	ilbst_rule_desc_t	*rp;
	ilbst_rule_desc_t	*rlist = sta->ilbst_rlist;
	int			rcount = sta->ilbst_rcount;

	/*
	 * find all "server" kstats, or the one specified in
	 * sta->server
	 */
	for (kp = kctl->kc_chain; kp != NULL; kp = kp->ks_next) {
		if (strncmp("ilb", kp->ks_module, 3) != 0)
			continue;
		if (sta->ilbst_server != NULL &&
		    strcasecmp(sta->ilbst_server, kp->ks_name) != 0)
			continue;
		rp = match_2_rnames(kp->ks_class, rlist, rcount);
		if (rp == NULL)
			continue;

		(void) kstat_read(kctl, kp, NULL);
		i = rp->ird_srv_ind++;

		rc = ILBADM_OK;
		/*
		 * This means that a server is added after we check last
		 * time...  Just make the array bigger.
		 */
		if (i+1 > rp->ird_num_servers) {
			ilbst_srv_desc_t  *srvlist;

			if ((srvlist = realloc(rp->ird_srvlist, (i+1) *
			    sizeof (*srvlist))) == NULL) {
				rc = ILBADM_ENOMEM;
				break;
			}
			rp->ird_srvlist = srvlist;
			rp->ird_num_servers = i;
		}

		(void) strlcpy(rp->ird_srvlist[i].isd_servername, kp->ks_name,
		    sizeof (rp->ird_srvlist[i].isd_servername));
		i_copy_sstats(&rp->ird_srvlist[i], kp);
	}

	for (i = 0; i < rcount; i++)
		rlist[i].ird_srv_ind = 0;

	if (sta->ilbst_server != NULL && i == -1)
		rc = ILBADM_ENOSERVER;
	return (rc);
}

static void
i_copy_rstats(ilbst_rule_desc_t *rp, kstat_t *kp)
{
	kstat_named_t	*knp;
	int		i, ind;

	knp = KSTAT_NAMED_PTR(kp);
	for (i = 0; i < kp->ks_ndata; i++, knp++) {
		ind = i_stat_index(knp, rulestats, RSTAT_SZ);
		if (ind == -1)
			continue;

		(void) strlcpy(rp->ird_rulestats[ind].is_name, knp->name,
		    sizeof (rp->ird_rulestats[ind].is_name));
		rp->ird_rulestats[ind].is_value = knp->value.ui64;
	}
}

static void
i_set_rlstats_ptr(ilbst_rule_desc_t *rp, boolean_t old_is_old)
{
	if (old_is_old) {
		rp->ird_rulestats = rp->ird_rstats;
		rp->ird_rulestats_o = rp->ird_rstats_o;
	} else {
		rp->ird_rulestats = rp->ird_rstats_o;
		rp->ird_rulestats_o = rp->ird_rstats;
	}
}
/*
 * this function walks the array of rules and switches pointer to old
 * and new stats as well as serverlists.
 */
static void
i_swap_rl_pointers(ilbst_arg_t *sta, int rcount)
{
	int			i, tmp_num;
	ilbst_rule_desc_t	*rlist = sta->ilbst_rlist;
	ilbst_srv_desc_t	*tmp_srv;

	for (i = 0; i < rcount; i++) {
		/* swap srvlist pointers */
		tmp_srv = rlist[i].ird_srvlist;
		rlist[i].ird_srvlist = rlist[i].ird_srvlist_o;
		rlist[i].ird_srvlist_o = tmp_srv;

		/*
		 * swap server counts - we need the old one to
		 * save reallocation calls
		 */
		tmp_num = rlist[i].ird_num_servers_o;
		rlist[i].ird_num_servers_o = rlist[i].ird_num_servers;
		rlist[i].ird_num_servers = tmp_num;

		/* preserve creation time */
		rlist[i].ird_crtime_o = rlist[i].ird_crtime;

		i_set_rlstats_ptr(&rlist[i], sta->ilbst_old_is_old);
		rlist[i].ird_srv_ind = 0;
	}
}

static void
i_init_rulelist(ilbst_arg_t *sta, int rcount)
{
	int			 i;
	ilbst_rule_desc_t	*rlist = sta->ilbst_rlist;

	for (i = 0; i < rcount; i++) {
		rlist[i].ird_rulestats = rlist[i].ird_rstats;
		rlist[i].ird_rulestats_o = rlist[i].ird_rstats_o;
		rlist[i].ird_srv_ind = 0;
	}
}


/*
 * this function searches for kstats describing individual rules and
 * saves name, # of servers, and the kstat_t * describing them (this is
 * for sta->rulename == NULL);
 * if sta->rulename != NULL, it names the rule we're looking for
 * and this function will fill in the other data (like the all_rules case)
 * Returns:	ILBADM_ENORULE	named rule not found
 *		ILBADM_ENOMEM	no mem. available
 */
static ilbadm_status_t
i_get_rule_descs(ilbst_arg_t *sta, kstat_ctl_t *kctl)
{
	ilbadm_status_t	rc = ILBADM_OK;
	kstat_t		*kp;
	kstat_named_t	*knp;
	int		i;
	int		num_servers;
	ilbst_rule_desc_t	*rlist = sta->ilbst_rlist;
	int		rcount = sta->ilbst_rcount;

	/*
	 * find all "rule" kstats, or the one specified in
	 * sta->ilbst_rulename.
	 */
	for (i = 0, kp = kctl->kc_chain; i < rcount && kp != NULL;
	    kp = kp->ks_next) {
		if (strncmp("rulestat", kp->ks_class, 8) != 0 ||
		    strncmp("ilb", kp->ks_module, 3) != 0)
			continue;

		(void) kstat_read(kctl, kp, NULL);

		knp = kstat_data_lookup(kp, "num_servers");
		if (knp == NULL) {
			ilbadm_err(gettext("kstat_data_lookup() failed: %s"),
			    strerror(errno));
			rc = ILBADM_LIBERR;
			break;
		}
		if (sta->ilbst_rulename != NULL) {
			if (strcasecmp(kp->ks_name, sta->ilbst_rulename)
			    != 0)
				continue;
		}
		(void) strlcpy(rlist[i].ird_rulename, kp->ks_name,
		    sizeof (rlist[i].ird_rulename));

		/* only alloc the space we need, set counter here ... */
		if (sta->ilbst_server != NULL)
			num_servers = 1;
		else
			num_servers = (int)knp->value.ui64;

		/* ... furthermore, only reallocate if necessary */
		if (num_servers != rlist[i].ird_num_servers) {
			ilbst_srv_desc_t  *srvlist;

			rlist[i].ird_num_servers = num_servers;

			if (rlist[i].ird_srvlist == NULL)
				srvlist = calloc(num_servers,
				    sizeof (*srvlist));
			else
				srvlist = realloc(rlist[i].ird_srvlist,
				    sizeof (*srvlist) * num_servers);
			if (srvlist == NULL) {
				rc = ILBADM_ENOMEM;
				break;
			}
			rlist[i].ird_srvlist = srvlist;
		}
		rlist[i].ird_srv_ind = 0;
		rlist[i].ird_crtime = kp->ks_crtime;

		i_copy_rstats(&rlist[i], kp);
		i++;

		/* if we know we're done, return */
		if (sta->ilbst_rulename != NULL || i == rcount) {
			rc = ILBADM_OK;
			break;
		}
	}

	if (sta->ilbst_rulename != NULL && i == 0)
		rc = ILBADM_ENORULE;
	return (rc);
}

static void
i_do_print(ilbst_arg_t *sta)
{
	int	i;

	/* non-itemized display can go right ahead */
	if ((sta->ilbst_flags & ILBST_ITEMIZE) == 0) {
		ofmt_print(sta->ilbst_oh, sta);
		return;
	}

	/*
	 * rulename is given, list a line per server
	 * here's how we do it:
	 *	the _ITEMIZE flag indicates to the print function (called
	 *	from ofmt_print()) to look at server [ird_srv_ind] only.
	 */
	if (sta->ilbst_rulename != NULL) {
		sta->ilbst_rule_index = 0;
		for (i = 0; i < sta->ilbst_rlist->ird_num_servers; i++) {
			sta->ilbst_rlist->ird_srv_ind = i;
			ofmt_print(sta->ilbst_oh, sta);
		}
		sta->ilbst_rlist->ird_srv_ind = 0;
		return;
	}

	/* list one line for every rule for a given server */
	for (i = 0; i < sta->ilbst_rcount; i++) {
		/*
		 * if a rule doesn't contain a given server, there's no
		 * need to print it. Luckily, we can check that
		 * fairly easily
		 */
		if (sta->ilbst_rlist[i].ird_srvlist[0].isd_servername[0] ==
		    '\0')
			continue;

		sta->ilbst_rule_index = i;
		sta->ilbst_rlist[i].ird_srv_ind = 0;
		ofmt_print(sta->ilbst_oh, sta);
	}
	sta->ilbst_rule_index = 0;
}

static ilbadm_status_t
i_do_show_stats(ilbst_arg_t *sta)
{
	kstat_ctl_t	*kctl;
	kid_t		nkid;
	int		rcount = 1, i;
	ilbadm_status_t	rc = ILBADM_OK;
	ilbst_rule_desc_t	*rlist, *rp;
	boolean_t	pseudo_abs = B_FALSE; /* for first pass */

	if ((kctl = kstat_open()) == NULL) {
		ilbadm_err(gettext("kstat_open() failed: %s"), strerror(errno));
		return (ILBADM_LIBERR);
	}


	if (sta->ilbst_rulename == NULL)
		rcount = i_get_num_kinstances(kctl);

	rlist = calloc(sizeof (*rlist), rcount);
	if (rlist == NULL) {
		rc = ILBADM_ENOMEM;
		goto out;
	}

	sta->ilbst_old_is_old = B_TRUE;
	sta->ilbst_rlist = rlist;
	sta->ilbst_rcount = sta->ilbst_rcount_prev = rcount;
	sta->ilbst_rlist_sz = rcount;

	/*
	 * in the first pass, we always print absolute numbers. We
	 * need to remember whether we wanted abs. numbers for
	 * other samples as well
	 */
	if ((sta->ilbst_flags & ILBST_ABS_NUMBERS) == 0) {
		sta->ilbst_flags |= ILBST_ABS_NUMBERS;
		pseudo_abs = B_TRUE;
	}

	i_init_rulelist(sta, rcount);
	do {
		rc = i_get_rule_descs(sta, kctl);
		if (rc != ILBADM_OK)
			goto out;

		rc = i_get_server_descs(sta, kctl);
		if (rc != ILBADM_OK)
			goto out;

		i_do_print(sta);

		if (sta->ilbst_count == -1 || --(sta->ilbst_count) > 0)
			(void) sleep(sta->ilbst_interval);
		else
			break;

		nkid = kstat_chain_update(kctl);
		sta->ilbst_flags &= ~ILBST_RULES_CHANGED;
		/*
		 * we only need to continue with most of the rest of this if
		 * the kstat chain id has changed
		 */
		if (nkid == 0)
			goto swap_old_new;
		if (nkid == -1) {
			ilbadm_err(gettext("kstat_chain_update() failed: %s"),
			    strerror(errno));
			rc = ILBADM_LIBERR;
			break;
		}

		/*
		 * find out whether the number of rules has changed.
		 * if so, adjust rcount and _o; if number has increased,
		 * expand array to hold all rules.
		 * we only shrink if rlist_sz is larger than both rcount and
		 * rcount_prev;
		 */
		if (sta->ilbst_rulename == NULL)
			rcount = i_get_num_kinstances(kctl);
		if (rcount != sta->ilbst_rcount) {
			sta->ilbst_flags |= ILBST_RULES_CHANGED;
			sta->ilbst_rcount_prev = sta->ilbst_rcount;
			sta->ilbst_rcount = rcount;

			if (rcount > sta->ilbst_rcount_prev) {
				rlist = realloc(sta->ilbst_rlist,
				    sizeof (*sta->ilbst_rlist) * rcount);
				if (rlist == NULL) {
					rc = ILBADM_ENOMEM;
					break;
				}
				sta->ilbst_rlist = rlist;
				/* realloc doesn't zero out memory */
				for (i = sta->ilbst_rcount_prev;
				    i < rcount; i++) {
					rp = &sta->ilbst_rlist[i];
					bzero(rp, sizeof (*rp));
					i_set_rlstats_ptr(rp,
					    sta->ilbst_old_is_old);
				}
				/*
				 * even if rlist_sz was > rcount, it's now
				 * shrunk to rcount
				 */
				sta->ilbst_rlist_sz = sta->ilbst_rcount;
			}
		}

		/*
		 * we may need to shrink the allocated slots down to the
		 * actually required number - we need to make sure we
		 * don't delete old or new stats.
		 */
		if (sta->ilbst_rlist_sz > MAX(sta->ilbst_rcount,
		    sta->ilbst_rcount_prev)) {
			sta->ilbst_rlist_sz =
			    MAX(sta->ilbst_rcount, sta->ilbst_rcount_prev);
			rlist = realloc(sta->ilbst_rlist,
			    sizeof (*sta->ilbst_rlist) * sta->ilbst_rlist_sz);
			if (rlist == NULL) {
				rc = ILBADM_ENOMEM;
				break;
			}
			sta->ilbst_rlist = rlist;
		}

		/*
		 * move pointers around so what used to point to "old"
		 * stats now points to new, and vice versa
		 * if we're printing absolute numbers, this rigmarole is
		 * not necessary.
		 */
swap_old_new:
		if (pseudo_abs)
			sta->ilbst_flags &= ~ILBST_ABS_NUMBERS;

		if ((sta->ilbst_flags & ILBST_ABS_NUMBERS) == 0) {
			sta->ilbst_old_is_old = !sta->ilbst_old_is_old;
			i_swap_rl_pointers(sta, rcount);
		}
		_NOTE(CONSTCOND)
	} while (B_TRUE);

out:
	(void) kstat_close(kctl);
	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));

	if (sta->ilbst_rlist != NULL)
		free(sta->ilbst_rlist);

	return (rc);
}

/*
 * read ilb's kernel statistics and (periodically) display
 * them.
 */
/* ARGSUSED */
ilbadm_status_t
ilbadm_show_stats(int argc, char *argv[])
{
	ilbadm_status_t	rc;
	int		c;
	ilbst_arg_t	sta;
	int		oflags = 0;
	char		*fieldnames = stat_stdhdrs;
	ofmt_field_t	*fields = stat_stdfields;
	boolean_t	r_opt = B_FALSE, s_opt = B_FALSE, i_opt = B_FALSE;
	boolean_t	o_opt = B_FALSE, p_opt = B_FALSE, t_opt = B_FALSE;
	boolean_t	v_opt = B_FALSE, A_opt = B_FALSE, d_opt = B_FALSE;
	ofmt_status_t	oerr;
	ofmt_handle_t	oh = NULL;

	bzero(&sta, sizeof (sta));
	sta.ilbst_interval = 1;
	sta.ilbst_count = 1;

	while ((c = getopt(argc, argv, ":tdAr:s:ivo:p")) != -1) {
		switch ((char)c) {
		case 't': sta.ilbst_flags |= ILBST_TIMESTAMP_HEADER;
			t_opt = B_TRUE;
			break;
		case 'd': sta.ilbst_flags |= ILBST_DELTA_INTERVAL;
			d_opt = B_TRUE;
			break;
		case 'A': sta.ilbst_flags |= ILBST_ABS_NUMBERS;
			A_opt = B_TRUE;
			break;
		case 'r': sta.ilbst_rulename = optarg;
			r_opt = B_TRUE;
			break;
		case 's': sta.ilbst_server = optarg;
			s_opt = B_TRUE;
			break;
		case 'i': sta.ilbst_flags |= ILBST_ITEMIZE;
			i_opt = B_TRUE;
			break;
		case 'o': fieldnames = optarg;
			o_opt = B_TRUE;
			break;
		case 'p': oflags |= OFMT_PARSABLE;
			p_opt = B_TRUE;
			break;
		case 'v': sta.ilbst_flags |= ILBST_VERBOSE;
			v_opt = B_TRUE;
			fieldnames = stat_stdv_hdrs;
			break;
		case ':': ilbadm_err(gettext("missing option-argument"
			    " detected for %c"), (char)optopt);
			exit(1);
			/* not reached */
			break;
		case '?': /* fallthrough */
		default:
			unknown_opt(argv, optind-1);
			/* not reached */
			break;
		}
	}

	if (s_opt && r_opt) {
		ilbadm_err(gettext("options -s and -r are mutually exclusive"));
		exit(1);
	}

	if (i_opt) {
		if (!(s_opt || r_opt)) {
			ilbadm_err(gettext("option -i requires"
			    " either -r or -s"));
			exit(1);
		}
		if (v_opt) {
			ilbadm_err(gettext("option -i and -v are mutually"
			    " exclusive"));
			exit(1);
		}
		/* only use "std" headers if none are specified */
		if (!o_opt)
			if (r_opt)
				fieldnames = stat_itemize_rule_hdrs;
			else /* must be s_opt */
				fieldnames = stat_itemize_server_hdrs;
		fields = stat_itemize_fields;
	}

	if (p_opt) {
		if (!o_opt) {
			ilbadm_err(gettext("option -p requires -o"));
			exit(1);
		}
		if (v_opt) {
			ilbadm_err(gettext("option -o and -v are mutually"
			    " exclusive"));
			exit(1);
		}
		if (strcasecmp(fieldnames, "all") == 0) {
			ilbadm_err(gettext("option -p requires"
			    " explicit field names"));
			exit(1);
		}
	}

	if (t_opt) {
		if (v_opt) {
			fieldnames = "all";
		} else {
			int  len = strlen(fieldnames) + 6;
			char *fnames;

			fnames = malloc(len);
			if (fnames == NULL) {
				rc = ILBADM_ENOMEM;
				return (rc);
			}
			(void) snprintf(fnames, len, "%s,TIME", fieldnames);
			fieldnames = fnames;
		}
	}

	if (A_opt && d_opt) {
		ilbadm_err(gettext("options -d and -A are mutually exclusive"));
		exit(1);
	}

	/* find and parse interval and count arguments if present */
	if (optind < argc) {
		sta.ilbst_interval = atoi(argv[optind]);
		if (sta.ilbst_interval < 1) {
			ilbadm_err(gettext("illegal interval spec %s"),
			    argv[optind]);
			exit(1);
		}
		sta.ilbst_count = -1;
		if (++optind < argc) {
			sta.ilbst_count = atoi(argv[optind]);
			if (sta.ilbst_count < 1) {
				ilbadm_err(gettext("illegal count spec %s"),
				    argv[optind]);
				exit(1);
			}
		}
	}

	oerr = ofmt_open(fieldnames, fields, oflags, 80, &oh);
	if (oerr != OFMT_SUCCESS) {
		char	e[80];

		ilbadm_err(gettext("ofmt_open failed: %s"),
		    ofmt_strerror(oh, oerr, e, sizeof (e)));
		return (ILBADM_LIBERR);
	}

	sta.ilbst_oh = oh;

	rc = i_do_show_stats(&sta);

	ofmt_close(oh);
	return (rc);
}
