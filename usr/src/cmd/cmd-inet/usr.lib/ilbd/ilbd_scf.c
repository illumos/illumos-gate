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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/list.h>
#include <libilb.h>
#include <assert.h>
#include <libscf.h>
#include "libilb_impl.h"
#include "ilbd.h"

#define	ILBD_PG_NAME_RULE "rule_"
#define	ILBD_PG_NAME_SG "sg_"
#define	ILBD_PG_NAME_HC "hc_"
#define	ILBD_SVC_FMRI "svc:/network/loadbalancer/ilb"
#define	ILBD_INST_NAME "default"

typedef enum {
	ILBD_RULE_STATUS,
	ILBD_RULE_VIP,
	ILBD_RULE_PROTO,
	ILBD_RULE_PORT,
	ILBD_RULE_ALGO,
	ILBD_RULE_TOPO,
	ILBD_RULE_NAT_STR,
	ILBD_RULE_NAT_END,
	ILBD_RULE_STI_MASK,
	ILBD_RULE_SGNAME,
	ILBD_RULE_HCNAME,
	ILBD_RULE_HCPORT,
	ILBD_RULE_HCPFLAG,
	ILBD_RULE_DRAINTIME,
	ILBD_RULE_NAT_TO,
	ILBD_RULE_PERS_TO,

	ILBD_SG_SERVER,

	ILBD_HC_TEST,
	ILBD_HC_TIMEOUT,
	ILBD_HC_INTERVAL,
	ILBD_HC_DEF_PING,
	ILBD_HC_COUNT,

	ILBD_VAR_INVALID
} ilbd_var_type_t;

typedef struct prop_tbl_entry {
	ilbd_var_type_t val_type;
	const char *scf_propname;
	scf_type_t scf_proptype;
} prop_tbl_entry_t;

/*
 * this table contains a map of all SCF properties, including rules,
 * servergroups and health checks. The place to add new property needs to be
 * watched carefully. When new properties are added, corresponding *VAR_NUM
 * needs to be adjusted to reflect the correct index of the table
 */
prop_tbl_entry_t prop_tbl[] = {
	/* entried for rule */
	{ILBD_RULE_STATUS, "status", SCF_TYPE_BOOLEAN},
	/* SCF_TYPE_NET_ADDR_V4 or SCF_TYPE_NET_ADDR_V6 */
	{ILBD_RULE_VIP, "vip", SCF_TYPE_INVALID},
	{ILBD_RULE_PROTO, "protocol", SCF_TYPE_ASTRING},
	{ILBD_RULE_PORT, "port", SCF_TYPE_ASTRING},
	{ILBD_RULE_ALGO, "ilb-algo", SCF_TYPE_ASTRING},
	{ILBD_RULE_TOPO, "ilb-type", SCF_TYPE_ASTRING},
	{ILBD_RULE_NAT_STR, "ilb-nat-start", SCF_TYPE_INVALID},
	{ILBD_RULE_NAT_END, "ilb-nat-end", SCF_TYPE_INVALID},
	{ILBD_RULE_STI_MASK, "ilb-sti-mask", SCF_TYPE_INVALID},
	{ILBD_RULE_SGNAME, "servergroup", SCF_TYPE_ASTRING},
	{ILBD_RULE_HCNAME, "healthcheck", SCF_TYPE_ASTRING},
	{ILBD_RULE_HCPORT, "hc-port", SCF_TYPE_INTEGER},
	{ILBD_RULE_HCPFLAG, "hcp-flag", SCF_TYPE_INTEGER},
	{ILBD_RULE_DRAINTIME, "drain-time", SCF_TYPE_INTEGER},
	{ILBD_RULE_NAT_TO, "nat-timeout", SCF_TYPE_INTEGER},
	{ILBD_RULE_PERS_TO, "pers-timeout", SCF_TYPE_INTEGER},
	/* add new rule related prop here */
	/* entries for sg */
	{ILBD_SG_SERVER, "server", SCF_TYPE_ASTRING},
	/* add new sg related prop here */
	/* entries for hc */
	{ILBD_HC_TEST, "test", SCF_TYPE_ASTRING},
	{ILBD_HC_TIMEOUT, "timeout", SCF_TYPE_INTEGER},
	{ILBD_HC_INTERVAL, "interval", SCF_TYPE_INTEGER},
	{ILBD_HC_DEF_PING, "ping", SCF_TYPE_BOOLEAN},
	/* add new hc related prop here */
	{ILBD_HC_COUNT, "count", SCF_TYPE_INTEGER}
};

#define	ILBD_PROP_VAR_NUM (ILBD_HC_COUNT + 1)
#define	ILBD_RULE_VAR_NUM (ILBD_SG_SERVER)
#define	ILBD_SG_VAR_NUM (ILBD_HC_TEST - ILBD_SG_SERVER)
#define	ILBD_HC_VAR_NUM (ILBD_PROP_VAR_NUM - ILBD_HC_TEST)

static ilb_status_t ilbd_scf_set_prop(scf_propertygroup_t *, const char *,
    scf_type_t, scf_value_t *);
static ilb_status_t ilbd_scf_retrieve_pg(const char *, scf_propertygroup_t **,
    boolean_t);
static ilb_status_t ilbd_scf_delete_pg(scf_propertygroup_t *);
static ilb_status_t ilbd_scf_get_prop_val(scf_propertygroup_t *, const char *,
    scf_value_t **);

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

int
ilbd_scf_limit(int type)
{
	return (MIN(scf_limit(type), 120));
}

/*
 * Translate libscf error to libilb status
 */
ilb_status_t
ilbd_scf_err_to_ilb_err()
{
	switch (scf_error()) {
	case SCF_ERROR_NONE:
		return (ILB_STATUS_OK);
	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_HANDLE_DESTROYED:
	case SCF_ERROR_VERSION_MISMATCH:
	case SCF_ERROR_NOT_BOUND:
	case SCF_ERROR_CONSTRAINT_VIOLATED:
	case SCF_ERROR_NOT_SET:
	case SCF_ERROR_TYPE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
		return (ILB_STATUS_EINVAL);
	case SCF_ERROR_NO_MEMORY:
	case SCF_ERROR_NO_RESOURCES:
		return (ILB_STATUS_ENOMEM);
	case SCF_ERROR_NOT_FOUND:
	case SCF_ERROR_DELETED:
		return (ILB_STATUS_ENOENT);
	case SCF_ERROR_EXISTS:
		return (ILB_STATUS_EEXIST);
	case SCF_ERROR_PERMISSION_DENIED:
		return (ILB_STATUS_PERMIT);
	case SCF_ERROR_CALLBACK_FAILED:
		return (ILB_STATUS_CALLBACK);
	case SCF_ERROR_IN_USE:
		return (ILB_STATUS_INUSE);
	default:
		return (ILB_STATUS_INTERNAL);
	}
}

static void
ilbd_name_to_scfpgname(ilbd_scf_pg_type_t pg_type, const char *pgname,
    char *scf_pgname)
{
	switch (pg_type) {
	case ILBD_SCF_RULE:
		(void) snprintf(scf_pgname, ILBD_MAX_NAME_LEN,
		    ILBD_PG_NAME_RULE "%s", pgname);
		return;
	case ILBD_SCF_SG:
		(void) snprintf(scf_pgname, ILBD_MAX_NAME_LEN,
		    ILBD_PG_NAME_SG "%s", pgname);
		return;
	case ILBD_SCF_HC:
		(void) snprintf(scf_pgname, ILBD_MAX_NAME_LEN,
		    ILBD_PG_NAME_HC "%s", pgname);
		return;
	/* Should not happen.  Log it and put ILB service in maintenance. */
	default:
		logerr("ilbd_name_to_scfpgname: invalid pg type %d for pg %s",
		    pg_type, pgname);
		(void) smf_maintain_instance(ILB_FMRI, SMF_IMMEDIATE);
		exit(EXIT_FAILURE);
		return;
	}
}

static void
ilbd_scf_destroy(scf_handle_t *h, scf_service_t *s, scf_instance_t *inst,
    scf_propertygroup_t *pg)
{
	if (pg != NULL)
		scf_pg_destroy(pg);
	if (inst != NULL)
		scf_instance_destroy(inst);
	if (s != NULL)
		scf_service_destroy(s);
	if (h != NULL)
		scf_handle_destroy(h);
}


static ilb_status_t
ilbd_scf_get_inst(scf_handle_t **h, scf_service_t **svc, scf_instance_t **inst)
{
	if ((*h = scf_handle_create(SCF_VERSION)) == NULL)
		return (ILB_STATUS_INTERNAL);

	if (scf_handle_bind(*h) != 0) {
		ilbd_scf_destroy(*h, NULL, NULL, NULL);
		return (ilbd_scf_err_to_ilb_err());
	}

	if ((*svc = scf_service_create(*h)) == NULL) {
		ilbd_scf_destroy(*h, NULL, NULL, NULL);
		return (ilbd_scf_err_to_ilb_err());
	}

	if (scf_handle_decode_fmri(*h, ILBD_SVC_FMRI, NULL, *svc, NULL, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		ilbd_scf_destroy(*h, *svc, NULL, NULL);
		return (ilbd_scf_err_to_ilb_err());
	}

	if ((*inst = scf_instance_create(*h)) == NULL) {
		ilbd_scf_destroy(*h, *svc, NULL, NULL);
		return (ilbd_scf_err_to_ilb_err());
	}

	if (scf_service_get_instance(*svc, ILBD_INST_NAME, *inst) != 0) {
		ilbd_scf_destroy(*h, *svc, *inst, NULL);
		return (ilbd_scf_err_to_ilb_err());
	}
	return (ILB_STATUS_OK);
}

/*
 * If create is set, create a new prop group, destroy the old one if exists.
 * If create not set, try to find the prop group with given name.
 * The created or found entry is returned as *pg.
 * Caller frees *pg and its handle scf_pg_handle(pg)
 */
static ilb_status_t
ilbd_scf_retrieve_pg(const char *pgname, scf_propertygroup_t **pg,
    boolean_t create)
{
	scf_instance_t *inst;
	scf_handle_t *h;
	scf_service_t *svc;
	ilb_status_t ret;

	ret = ilbd_scf_get_inst(&h, &svc, &inst);
	if (ret != ILB_STATUS_OK)
		return (ret);

	*pg = scf_pg_create(h);
	if (*pg == NULL)
		return (ILB_STATUS_INTERNAL);

	if (scf_instance_get_pg(inst, pgname, *pg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND ||
		    (scf_error() == SCF_ERROR_NOT_FOUND && (!create))) {
			ilbd_scf_destroy(h, svc, inst, *pg);
			*pg = NULL;
			return (ilbd_scf_err_to_ilb_err());
		}
	} else {
		/*
		 * Found pg, don't want to create, return EEXIST.  Note that
		 * h cannot be destroyed here since the caller needs to use it.
		 * The caller gets it by calling scf_pg_handle().
		 */
		if (!create) {
			ilbd_scf_destroy(NULL, svc, inst, NULL);
			return (ILB_STATUS_EEXIST);
		}
		/* found pg, need to create, destroy the existing one */
		else
			(void) ilbd_scf_delete_pg(*pg);
	}

	if (create) {
		if (scf_instance_add_pg(inst, pgname,
		    SCF_GROUP_APPLICATION, 0, *pg) != 0) {
			ilbd_scf_destroy(h, svc, inst, *pg);
			*pg = NULL;
			return (ilbd_scf_err_to_ilb_err());
		}
	}

	/*
	 * Note that handle cannot be destroyed here, caller sometimes needs
	 * to use it.  It gets the handle by calling scf_pg_handle().
	 */
	ilbd_scf_destroy(NULL, svc, inst, NULL);
	return (ILB_STATUS_OK);
}

struct algo_tbl_entry {
	ilb_algo_t algo_type;
	const char *algo_str;
} algo_tbl[] = {
	{ILB_ALG_ROUNDROBIN, "ROUNDROBIN"},
	{ILB_ALG_HASH_IP, "HASH-IP"},
	{ILB_ALG_HASH_IP_SPORT, "HASH-IP-PORT"},
	{ILB_ALG_HASH_IP_VIP, "HASH-IP-VIP"}
};

#define	ILBD_ALGO_TBL_SIZE (sizeof (algo_tbl) / \
	sizeof (*algo_tbl))

void
ilbd_algo_to_str(ilb_algo_t algo_type, char *valstr)
{
	int i;

	for (i = 0; i < ILBD_ALGO_TBL_SIZE; i++) {
		if (algo_type == algo_tbl[i].algo_type) {
			(void) strlcpy(valstr, algo_tbl[i].algo_str,
			    ILBD_MAX_VALUE_LEN);
			return;
		}
	}
	logerr("ilbd_algo_to_str: algo not found");
}

static void
ilbd_scf_str_to_algo(ilb_algo_t *algo_type, char *valstr)
{
	int i;

	for (i = 0; i < ILBD_ALGO_TBL_SIZE; i++) {
		if (strcmp(valstr, algo_tbl[i].algo_str) == 0) {
			*algo_type = algo_tbl[i].algo_type;
			return;
		}
	}
	logerr("ilbd_scf_str_to_algo: algo not found");
}

struct topo_tbl_entry {
	ilb_topo_t topo_type;
	const char *topo_str;
} topo_tbl[] = {
	{ILB_TOPO_DSR, "DSR"},
	{ILB_TOPO_NAT, "NAT"},
	{ILB_TOPO_HALF_NAT, "HALF-NAT"}
};

#define	ILBD_TOPO_TBL_SIZE (sizeof (topo_tbl) / \
	sizeof (*topo_tbl))

void
ilbd_topo_to_str(ilb_topo_t topo_type, char *valstr)
{
	int i;

	for (i = 0; i < ILBD_TOPO_TBL_SIZE; i++) {
		if (topo_type == topo_tbl[i].topo_type) {
			(void) strlcpy(valstr, topo_tbl[i].topo_str,
			    ILBD_MAX_VALUE_LEN);
			return;
		}
	}
	logerr("ilbd_scf_topo_to_str: topo not found");
}

static void
ilbd_scf_str_to_topo(ilb_topo_t *topo_type, char *valstr)
{
	int i;

	for (i = 0; i < ILBD_TOPO_TBL_SIZE; i++) {
		if (strcmp(valstr, topo_tbl[i].topo_str) == 0) {
			*topo_type = topo_tbl[i].topo_type;
			return;
		}
	}
	logerr("ilbd_scf_str_to_topo: topo not found");
}

static void
ilbd_get_svr_field(char *valstr, struct in6_addr *sgs_addr,
    int32_t *min_port, int32_t *max_port, int32_t *sgs_flags)
{
	char *ipaddr, *ipverstr, *portstr, *flagstr;
	int ip_ver;
	ilb_ip_addr_t temp_ip;
	void *addrptr;
	char *max_portstr;

	ipaddr = strtok(valstr, ";");
	ipverstr = strtok(NULL, ";");
	portstr = strtok(NULL, ";");
	flagstr = strtok(NULL, ";");

	if (ipaddr == NULL || ipverstr == NULL || portstr == NULL ||
	    flagstr == NULL) {
		logerr("%s: invalid server fields", __func__);
		(void) smf_maintain_instance(ILB_FMRI, SMF_IMMEDIATE);
		exit(EXIT_FAILURE);
	}
	ip_ver = atoi(ipverstr);
	addrptr = (ip_ver == AF_INET) ? (void *)&temp_ip.ia_v4 :
	    (void *)&temp_ip.ia_v6;
	if (inet_pton(ip_ver, ipaddr, addrptr) == 0) {
		logerr("ilbd_get_svr_field: inet_pton failed");
		return;
	}

	if (ip_ver == AF_INET) {
		IN6_INADDR_TO_V4MAPPED(&(temp_ip.ia_v4), sgs_addr);
	} else {
		(void) memcpy(sgs_addr, &(temp_ip.ia_v6),
		    sizeof (struct in6_addr));
	}

	*sgs_flags = atoi(flagstr);
	*min_port = atoi(strtok(portstr, "-"));
	*min_port = ntohs(*min_port);
	max_portstr = strtok(NULL, "-");
	if (max_portstr != NULL) {
		*max_port = atoi(max_portstr);
		*max_port = ntohs(*max_port);
	}
}

/*
 * Convert the info of a server to its SCF string value representation.
 * Argument value is assumed to be of size ILBD_MAX_VALUE_LEN.
 */
static void
ilbd_srv_scf_val(ilbd_srv_t *srv, char *value)
{
	char ipstr[INET6_ADDRSTRLEN];
	int ipver;

	if (GET_AF(&srv->isv_addr) == AF_INET) {
		struct in_addr v4_addr;

		IN6_V4MAPPED_TO_INADDR(&srv->isv_addr, &v4_addr);
		(void) inet_ntop(AF_INET, &v4_addr, ipstr, sizeof (ipstr));
		ipver = AF_INET;
	} else {
		(void) inet_ntop(AF_INET6, &srv->isv_addr, ipstr,
		    sizeof (ipstr));
		ipver = AF_INET6;
	}
	(void) snprintf(value, ILBD_MAX_VALUE_LEN, "%s;%d;%d-%d;%d",
	    ipstr, ipver, ntohs(srv->isv_minport), ntohs(srv->isv_maxport),
	    srv->isv_flags);
}

/* get the "ip:port:status" str of the #num server in the servergroup */
ilb_status_t
ilbd_get_svr_info(ilbd_sg_t *sg, int num, char *valstr, char *svrname)
{
	int i;
	ilbd_srv_t *tmp_srv = NULL;

	tmp_srv = list_head(&sg->isg_srvlist);
	if (tmp_srv == NULL)
		return (ILB_STATUS_ENOENT);

	for (i = 0; i < num; i++)
		tmp_srv = list_next(&sg->isg_srvlist, tmp_srv);

	assert(tmp_srv != NULL);
	if (valstr != NULL)
		ilbd_srv_scf_val(tmp_srv, valstr);

	if (svrname != NULL) {
		(void) snprintf(svrname, ILBD_MAX_NAME_LEN, "server%d",
		    tmp_srv->isv_id);
	}

	return (ILB_STATUS_OK);
}

/* convert a struct in6_addr to valstr */
ilb_status_t
ilbd_scf_ip_to_str(uint16_t ipversion, struct in6_addr *addr,
    scf_type_t *scftype, char *valstr)
{
	size_t vallen;
	ilb_ip_addr_t ipaddr;
	void *addrptr;

	vallen = (ipversion == AF_INET) ? INET_ADDRSTRLEN :
	    INET6_ADDRSTRLEN;
	if (scftype != NULL)
		*scftype = (ipversion == AF_INET) ? SCF_TYPE_NET_ADDR_V4 :
		    SCF_TYPE_NET_ADDR_V6;

	IP_COPY_IMPL_2_CLI(addr, &ipaddr);
	addrptr = (ipversion == AF_INET) ?
	    (void *)&ipaddr.ia_v4 : (void *)&ipaddr.ia_v6;
	(void) inet_ntop(ipversion, (void *)addrptr, valstr, vallen);
	return (ILB_STATUS_OK);
}

/*
 * This function takes a ilbd internal data struct and translate its value to
 * scf value. The data struct is passed in within "data".
 * Upon successful return, the scf val will be stored in "val" and the scf type
 * will be returned in "scftype" if scftype != NULL, the number of values
 * translated will be in "numval"
 * If it failed, no data will be written to SCF
 */
static ilb_status_t
ilbd_data_to_scfval(ilbd_scf_pg_type_t pg_type, ilbd_var_type_t type,
    scf_handle_t *h, void *data, scf_value_t ***val, scf_type_t *scftype,
    int *numval)
{
	scf_value_t *v, **varray = NULL;
	int ret = ILB_STATUS_OK;
	int i;
	int scf_val_len = ILBD_MAX_VALUE_LEN;
	char *valstr = NULL;
	int valint;
	uint8_t valbool = 0;
	ilbd_rule_t *r_ent = NULL;
	ilbd_sg_t *s_ent = NULL;
	ilbd_hc_t *h_ent = NULL;

	switch (pg_type) {
	case ILBD_SCF_RULE:
		r_ent = (ilbd_rule_t *)data;
		break;
	case ILBD_SCF_SG:
		s_ent = (ilbd_sg_t *)data;
		break;
	case ILBD_SCF_HC:
		h_ent = (ilbd_hc_t *)data;
		break;
	}

	v = scf_value_create(h);
	if (v == NULL)
		return (ILB_STATUS_INTERNAL);

	if ((valstr = malloc(scf_val_len)) == NULL)
			return (ILB_STATUS_ENOMEM);
	switch (type) {
	case ILBD_RULE_STATUS:
		valbool = r_ent->irl_flags & ILB_FLAGS_RULE_ENABLED;
		break;
	case ILBD_RULE_VIP:
		ret = ilbd_scf_ip_to_str(r_ent->irl_ipversion, &r_ent->irl_vip,
		    scftype, valstr);
		if (ret != ILB_STATUS_OK) {
			free(valstr);
			scf_value_destroy(v);
			return (ret);
		}
		break;
	case ILBD_RULE_PROTO: {
		struct protoent *protoent;

		protoent = getprotobynumber(r_ent->irl_proto);
		(void) strlcpy(valstr, protoent->p_name, scf_val_len);
		break;
	}
	case ILBD_RULE_PORT:
		(void) snprintf(valstr, scf_val_len, "%d-%d",
		    r_ent->irl_minport, r_ent->irl_maxport);
		break;
	case ILBD_RULE_ALGO:
		ilbd_algo_to_str(r_ent->irl_algo, valstr);
		break;
	case ILBD_RULE_TOPO:
		ilbd_topo_to_str(r_ent->irl_topo, valstr);
		break;
	case ILBD_RULE_NAT_STR:
		ret = ilbd_scf_ip_to_str(r_ent->irl_ipversion,
		    &r_ent->irl_nat_src_start, scftype, valstr);
		if (ret != ILB_STATUS_OK) {
			free(valstr);
			scf_value_destroy(v);
			return (ret);
		}
		break;
	case ILBD_RULE_NAT_END:
		ret = ilbd_scf_ip_to_str(r_ent->irl_ipversion,
		    &r_ent->irl_nat_src_end, scftype, valstr);
		if (ret != ILB_STATUS_OK) {
			free(valstr);
			scf_value_destroy(v);
			return (ret);
		}
		break;
	case ILBD_RULE_STI_MASK:
		ret = ilbd_scf_ip_to_str(r_ent->irl_ipversion,
		    &r_ent->irl_stickymask, scftype, valstr);
		if (ret != ILB_STATUS_OK) {
			free(valstr);
			scf_value_destroy(v);
			return (ret);
		}
		break;
	case ILBD_RULE_SGNAME:
		(void) strlcpy(valstr, r_ent->irl_sgname, scf_val_len);
		break;
	case ILBD_RULE_HCNAME:
		if (r_ent->irl_hcname[0] != '\0')
			(void) strlcpy(valstr, r_ent->irl_hcname,
			    scf_val_len);
		else
			bzero(valstr, ILBD_MAX_VALUE_LEN);
		break;
	case ILBD_RULE_HCPORT:
		valint = r_ent->irl_hcport;
		break;
	case ILBD_RULE_HCPFLAG:
		valint = r_ent->irl_hcpflag;
		break;
	case ILBD_RULE_DRAINTIME:
		valint = r_ent->irl_conndrain;
		break;
	case ILBD_RULE_NAT_TO:
		valint = r_ent->irl_nat_timeout;
		break;
	case ILBD_RULE_PERS_TO:
		valint = r_ent->irl_sticky_timeout;
		break;

	case ILBD_SG_SERVER:
		if (s_ent->isg_srvcount == 0) {
			(void) strlcpy(valstr, "EMPTY_SERVERGROUP",
			    scf_val_len);
			break;
		}

		varray = calloc(sizeof (*varray), s_ent->isg_srvcount);
		if (varray == NULL) {
			scf_value_destroy(v);
			free(valstr);
			return (ILB_STATUS_ENOMEM);
		}

		for (i = 0; i < s_ent->isg_srvcount; i++) {
			if (v == NULL) {
				for (i--; i >= 0; i--)
					scf_value_destroy(varray[i]);
				free(valstr);
				return (ILB_STATUS_ENOMEM);
			}

			ret = ilbd_get_svr_info(s_ent, i, valstr, NULL);
			if (ret != ILB_STATUS_OK) {
				scf_value_destroy(v);
				for (i--; i >= 0; i--)
					scf_value_destroy(varray[i]);
				free(valstr);
				free(varray);
				return (ret);
			}
			(void) scf_value_set_astring(v, valstr);
			varray[i] = v;
			v = scf_value_create(h);
		}
		/* the last 'v' we created will go unused, so drop it */
		scf_value_destroy(v);
		*numval = s_ent->isg_srvcount;
		*val = varray;
		free(valstr);
		return (ret);
	case ILBD_HC_TEST:
		(void) strlcpy(valstr, h_ent->ihc_test, scf_val_len);
		break;
	case ILBD_HC_TIMEOUT:
		valint = h_ent->ihc_timeout;
		break;
	case ILBD_HC_INTERVAL:
		valint = h_ent->ihc_interval;
		break;
	case ILBD_HC_DEF_PING:
		valbool = h_ent->ihc_def_ping;
		break;
	case ILBD_HC_COUNT:
		valint = h_ent->ihc_count;
		break;
	}

	switch (*scftype) {
	case SCF_TYPE_BOOLEAN:
		scf_value_set_boolean(v, valbool);
		break;
	case SCF_TYPE_ASTRING:
		(void) scf_value_set_astring(v, valstr);
		break;
	case SCF_TYPE_INTEGER:
		scf_value_set_integer(v, valint);
		break;
	case SCF_TYPE_NET_ADDR_V4:
		(void) scf_value_set_from_string(v, SCF_TYPE_NET_ADDR_V4,
		    valstr);
		break;
	case SCF_TYPE_NET_ADDR_V6:
		(void) scf_value_set_from_string(v, SCF_TYPE_NET_ADDR_V6,
		    valstr);
		break;
	}
	free(valstr);

	varray = calloc(1, sizeof (*varray));
	if (varray == NULL) {
		scf_value_destroy(v);
		return (ILB_STATUS_ENOMEM);
	}
	varray[0] = v;
	*val = varray;
	*numval = 1;
	return (ret);
}

/*
 * create a scf property group
 */
ilb_status_t
ilbd_create_pg(ilbd_scf_pg_type_t pg_type, void *data)
{
	ilb_status_t ret;
	char *pgname;
	scf_propertygroup_t *pg = NULL;
	scf_value_t **val;
	scf_handle_t *h;
	int scf_name_len = ILBD_MAX_NAME_LEN;
	char  *scfpgbuf; /* property group name or group type */
	int i, i_st, i_end;

	switch (pg_type) {
	case ILBD_SCF_RULE: {
		ilbd_rule_t *r_ent = (ilbd_rule_t *)data;

		pgname = r_ent->irl_name;
		i_st = 0;
		i_end = ILBD_RULE_VAR_NUM;
		break;
	}
	case ILBD_SCF_SG: {
		ilbd_sg_t *s_ent = (ilbd_sg_t *)data;

		pgname = s_ent->isg_name;
		i_st = ILBD_RULE_VAR_NUM;
		i_end = ILBD_RULE_VAR_NUM + ILBD_SG_VAR_NUM;
		break;
	}
	case ILBD_SCF_HC: {
		ilbd_hc_t *h_ent = (ilbd_hc_t *)data;

		pgname = h_ent->ihc_name;
		i_st = ILBD_RULE_VAR_NUM + ILBD_SG_VAR_NUM;
		i_end = ILBD_PROP_VAR_NUM;
		break;
	}
	default:
		logdebug("ilbd_create_pg: invalid pg type %d for pg %s",
		    pg_type, pgname);
		return (ILB_STATUS_EINVAL);
	}
	if ((scfpgbuf = malloc(scf_name_len)) == NULL)
		return (ILB_STATUS_ENOMEM);

	ilbd_name_to_scfpgname(pg_type, pgname, scfpgbuf);

	ret = ilbd_scf_retrieve_pg(scfpgbuf, &pg, B_TRUE);
	if (ret != ILB_STATUS_OK) {
		free(scfpgbuf);
		return (ret);
	}
	h = scf_pg_handle(pg);

	/* fill in props */
	for (i = i_st; i < i_end; i++) {
		int num, j;
		scf_type_t scftype = prop_tbl[i].scf_proptype;

		ret = ilbd_data_to_scfval(pg_type, prop_tbl[i].val_type, h,
		    data, &val, &scftype, &num);
		if (ret != ILB_STATUS_OK)
			goto done;

		for (j = 0; j < num; j++) {
			if (pg_type == ILBD_SCF_SG) {
				ret = ilbd_get_svr_info(data, j, NULL,
				    scfpgbuf);
				if (ret == ILB_STATUS_ENOENT) {
					(void) strlcpy(scfpgbuf,
					    "EMPTY_SERVER", scf_name_len);
				}
				ret = ilbd_scf_set_prop(pg, scfpgbuf,
				    scftype, val[j]);
			} else {
				ret = ilbd_scf_set_prop(pg,
				    prop_tbl[i].scf_propname, scftype, val[j]);
			}
			scf_value_destroy(val[j]);
		}
		free(val);
	}

done:
	free(scfpgbuf);
	ilbd_scf_destroy(h, NULL, NULL, pg);
	return (ret);
}

/*
 * destroy a scf property group
 */
static ilb_status_t
ilbd_scf_delete_pg(scf_propertygroup_t *pg)
{
	if (scf_pg_delete(pg) != 0)
		return (ilbd_scf_err_to_ilb_err());
	return (ILB_STATUS_OK);
}

/* sg can have same name as rule */
ilb_status_t
ilbd_destroy_pg(ilbd_scf_pg_type_t pg_t, const char *pgname)
{
	ilb_status_t ret;
	scf_propertygroup_t *pg;
	int scf_name_len = ILBD_MAX_NAME_LEN;
	char *scfname;

	if ((scfname = malloc(scf_name_len)) == NULL)
		return (ILB_STATUS_ENOMEM);
	ilbd_name_to_scfpgname(pg_t, pgname, scfname);

	ret = ilbd_scf_retrieve_pg(scfname, &pg, B_FALSE);
	free(scfname);
	if (ret != ILB_STATUS_EEXIST)
		return (ret);
	ret = ilbd_scf_delete_pg(pg);
	ilbd_scf_destroy(scf_pg_handle(pg), NULL, NULL, pg);
	return (ret);
}

/*
 * Set named property to scf value specified.  If property is new,
 * create it.
 */
static ilb_status_t
ilbd_scf_set_prop(scf_propertygroup_t *pg, const char *propname,
    scf_type_t proptype, scf_value_t *val)
{
	scf_handle_t *h = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *oldval = NULL;
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *ent = NULL;
	boolean_t new = B_FALSE;
	ilb_status_t ret = ILB_STATUS_OK;
	int commit_ret;

	h = scf_pg_handle(pg);
	if (h == NULL || propname == NULL)
		return (ILB_STATUS_EINVAL);

	ret = ilbd_scf_get_prop_val(pg, propname, &oldval);
	if (oldval != NULL)
		scf_value_destroy(oldval);
	if (ret == ILB_STATUS_ENOENT)
		new = B_TRUE;
	else if (ret != ILB_STATUS_OK)
		return (ret);

	if ((prop = scf_property_create(h)) == NULL)
		return (ilbd_scf_err_to_ilb_err());
	if ((tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL) {
		ret = ilbd_scf_err_to_ilb_err();
		logdebug("ilbd_scf_set_prop: create scf transaction failed\n");
		goto out;
	}

	if (scf_transaction_start(tx, pg) == -1) {
		ret = ilbd_scf_err_to_ilb_err();
		logdebug("ilbd_scf_set_prop: start scf transaction failed\n");
		goto out;
	}

	if (new) {
		if (scf_transaction_property_new(tx, ent, propname,
		    proptype) == -1) {
			ret = ilbd_scf_err_to_ilb_err();
			logdebug("ilbd_scf_set_prop: create scf prop failed\n");
			goto out;
		}
	} else {
		if (scf_transaction_property_change(tx, ent, propname, proptype)
		    == -1) {
			ret = ilbd_scf_err_to_ilb_err();
			logdebug("ilbd_scf_set_prop: change scf prop failed\n");
			goto out;
		}
	}

	if (scf_entry_add_value(ent, val) != 0) {
		logdebug("ilbd_scf_set_prop: add scf entry failed\n");
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}

	commit_ret = scf_transaction_commit(tx);
	switch (commit_ret) {
	case 1:
		ret = ILB_STATUS_OK;
		/* update pg here, so subsequent property setting  succeeds */
		(void) scf_pg_update(pg);
		break;
	case 0:
		/* transaction failed due to not having most recent pg */
		ret = ILB_STATUS_INUSE;
		break;
	default:
		ret = ilbd_scf_err_to_ilb_err();
		break;
	}
out:
	if (tx != NULL)
		scf_transaction_destroy(tx);
	if (ent != NULL)
		scf_entry_destroy(ent);
	if (prop != NULL)
		scf_property_destroy(prop);

	return (ret);
}

/*
 * get a prop's scf val
 */
static ilb_status_t
ilbd_scf_get_prop_val(scf_propertygroup_t *pg, const char *propname,
    scf_value_t **val)
{
	scf_handle_t *h = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	ilb_status_t ret = ILB_STATUS_OK;

	h = scf_pg_handle(pg);
	if (h == NULL || propname == NULL)
		return (ILB_STATUS_EINVAL);

	if ((prop = scf_property_create(h)) == NULL)
		return (ilbd_scf_err_to_ilb_err());

	if (scf_pg_get_property(pg, propname, prop) != 0) {
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}

	if ((value = scf_value_create(h)) == NULL) {
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}

	if (scf_property_get_value(prop, value) != 0) {
		scf_value_destroy(value);
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}

	*val = value;
out:
	if (prop != NULL)
		scf_property_destroy(prop);

	return (ret);
}

typedef struct ilbd_data
{
	union {
		ilb_sg_info_t *sg_info;
		ilb_hc_info_t *hc_info;
		ilb_rule_info_t *rule_info;
	} data;
	ilbd_scf_pg_type_t pg_type;	/* type of data */
#define	sg_data data.sg_info
#define	hc_data data.hc_info
#define	rule_data data.rule_info
} ilbd_data_t;

void
ilbd_scf_str_to_ip(int ipversion, char *ipstr, struct in6_addr *addr)
{
	ilb_ip_addr_t ipaddr;
	void *addrptr;

	addrptr = (ipversion == AF_INET) ?
	    (void *)&ipaddr.ia_v4 : (void *)&ipaddr.ia_v6;
	(void) inet_pton(ipversion, ipstr, addrptr);
	if (ipversion == AF_INET) {
		IN6_INADDR_TO_V4MAPPED(&(ipaddr.ia_v4), addr);
	} else {
		(void) memcpy(addr, &(ipaddr.ia_v6),
		    sizeof (struct in6_addr));
	}
}

/*
 * This function takes a scf value and writes it to the correct field of the
 * corresponding data struct.
 */
static ilb_status_t
ilbd_scfval_to_data(const char *propname, ilbd_var_type_t ilb_type,
    scf_value_t *val, ilbd_data_t *ilb_data)
{

	scf_type_t scf_type = scf_value_type(val);
	ilbd_scf_pg_type_t pg_type = ilb_data->pg_type;
	int ret = 0;
	ilb_rule_info_t *r_ent = NULL;
	ilb_sg_info_t *s_ent = NULL;
	ilb_hc_info_t *h_ent = NULL;
	char ipstr[INET6_ADDRSTRLEN];
	char *valstr;
	int64_t valint;
	uint8_t valbool;
	int ipversion;

	switch (pg_type) {
	case ILBD_SCF_RULE:
		r_ent = ilb_data->rule_data;
		break;
	case ILBD_SCF_HC:
		h_ent = ilb_data->hc_data;
		break;
	case ILBD_SCF_SG:
		s_ent = ilb_data->sg_data;
		break;
	}

	/* get scf value out */
	if ((valstr = malloc(ILBD_MAX_VALUE_LEN)) == NULL)
		return (ILB_STATUS_ENOMEM);
	switch (scf_type) {
		case SCF_TYPE_NET_ADDR_V4:
			if (scf_value_get_as_string_typed(val,
			    SCF_TYPE_NET_ADDR_V4, ipstr, INET_ADDRSTRLEN) < 0) {
				free(valstr);
				return (ILB_STATUS_INTERNAL);
			}
			ipversion = AF_INET;
			break;
		case SCF_TYPE_NET_ADDR_V6:
			if (scf_value_get_as_string_typed(val,
			    SCF_TYPE_NET_ADDR_V6, ipstr,
			    INET6_ADDRSTRLEN) < 0) {
				free(valstr);
				return (ILB_STATUS_INTERNAL);
			}
			ipversion = AF_INET6;
			break;
		case SCF_TYPE_BOOLEAN:
			if (scf_value_get_boolean(val, &valbool) < 0) {
				free(valstr);
				return (ILB_STATUS_INTERNAL);
			}
			break;
		case SCF_TYPE_ASTRING:
			if (scf_value_get_astring(val, valstr,
			    ILBD_MAX_VALUE_LEN) < 0) {
				free(valstr);
				return (ILB_STATUS_INTERNAL);
			}
			break;
		case SCF_TYPE_INTEGER:
			if (scf_value_get_integer(val, &valint) < 0) {
				free(valstr);
				return (ILB_STATUS_INTERNAL);
			}
			break;
		default:
			free(valstr);
			return (ILB_STATUS_INTERNAL);
	}

	ret = ILB_STATUS_OK;
	switch (ilb_type) {
	case ILBD_RULE_STATUS:
		if (valbool)
			r_ent->rl_flags |= ILB_FLAGS_RULE_ENABLED;
		break;
	case ILBD_RULE_VIP:
		r_ent->rl_ipversion = ipversion;
		ilbd_scf_str_to_ip(ipversion, ipstr, &r_ent->rl_vip);
		break;
	case ILBD_RULE_PROTO: {
		struct protoent *protoent;

		protoent = getprotobyname(valstr);
		r_ent->rl_proto = protoent->p_proto;
		break;
	}
	case ILBD_RULE_PORT: {
		char *token1, *token2;

		token1 = strtok(valstr, "-");
		token2 = strtok(NULL, "-");
		r_ent->rl_minport = atoi(token1);
		r_ent->rl_maxport = atoi(token2);
		break;
	}
	case ILBD_RULE_ALGO:
		ilbd_scf_str_to_algo(&(r_ent->rl_algo), valstr);
		break;
	case ILBD_RULE_TOPO:
		ilbd_scf_str_to_topo(&(r_ent->rl_topo), valstr);
		break;
	case ILBD_RULE_NAT_STR:
		ilbd_scf_str_to_ip(ipversion, ipstr, &r_ent->rl_nat_src_start);
		break;
	case ILBD_RULE_NAT_END:
		ilbd_scf_str_to_ip(ipversion, ipstr, &r_ent->rl_nat_src_end);
		break;
	case ILBD_RULE_STI_MASK:
		ilbd_scf_str_to_ip(ipversion, ipstr, &r_ent->rl_stickymask);
		if (ipversion == AF_INET) {
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&r_ent->rl_stickymask))
				r_ent->rl_flags |= ILB_FLAGS_RULE_STICKY;
		} else {
			if (!IN6_IS_ADDR_UNSPECIFIED(&r_ent->rl_stickymask))
				r_ent->rl_flags |= ILB_FLAGS_RULE_STICKY;
		}
		break;
	case ILBD_RULE_SGNAME:
		(void) strlcpy(r_ent->rl_sgname, valstr,
		    sizeof (r_ent->rl_sgname));
		break;
	case ILBD_RULE_HCNAME:
		(void) strlcpy(r_ent->rl_hcname, valstr,
		    sizeof (r_ent->rl_hcname));
		break;
	case ILBD_RULE_HCPORT:
		r_ent->rl_hcport = valint;
		break;
	case ILBD_RULE_HCPFLAG:
		r_ent->rl_hcpflag = valint;
		break;
	case ILBD_RULE_DRAINTIME:
		r_ent->rl_conndrain = valint;
		break;
	case ILBD_RULE_NAT_TO:
		r_ent->rl_nat_timeout = valint;
		break;
	case ILBD_RULE_PERS_TO:
		r_ent->rl_sticky_timeout = valint;
		break;

	case ILBD_SG_SERVER: {
		int svr_cnt = s_ent->sg_srvcount;

		/* found a new server, increase the svr count of this sg */
		s_ent->sg_srvcount++;

		/*
		 * valstr contains information of one server in the servergroup
		 * valstr is in the format of "ip:minport-maxport:enable"
		 */
		s_ent = realloc(s_ent, sizeof (ilb_sg_info_t) +
		    s_ent->sg_srvcount * sizeof (ilb_sg_srv_t));

		/* sgs_srvID is the sg name, leave it blank */
		/*
		 * sgs_id is the digit in propname, propname is in a format of
		 * "server" + the digital serverID. We get the serverID by
		 * reading from the 7th char of propname.
		 */
		s_ent->sg_servers[svr_cnt].sgs_id = atoi(&propname[6]);

		ilbd_get_svr_field(valstr,
		    &s_ent->sg_servers[svr_cnt].sgs_addr,
		    &s_ent->sg_servers[svr_cnt].sgs_minport,
		    &s_ent->sg_servers[svr_cnt].sgs_maxport,
		    &s_ent->sg_servers[svr_cnt].sgs_flags);
		ilb_data->sg_data = s_ent;

		break;
	}
	case ILBD_HC_TEST:
		(void) strlcpy(h_ent->hci_test, valstr,
		    sizeof (h_ent->hci_test));
		break;
	case ILBD_HC_TIMEOUT:
		h_ent->hci_timeout = valint;
		break;
	case ILBD_HC_INTERVAL:
		h_ent->hci_interval = valint;
		break;
	case ILBD_HC_DEF_PING:
		h_ent->hci_def_ping = valbool;
		break;
	case ILBD_HC_COUNT:
		h_ent->hci_count = valint;
		break;
	case ILBD_VAR_INVALID:
		/*
		 * An empty server group is represented by an invalid
		 * SCF property.  So when loading a server group, this
		 * case can be hit.  But it should happen only for this
		 * single case.  So if it happens in another case, move
		 * the service into maintenance mode.
		 */
		if (pg_type != ILBD_SCF_SG || scf_type != SCF_TYPE_ASTRING) {
			logerr("%s: invalid ilb type", __func__);
			(void) smf_maintain_instance(ILB_FMRI, SMF_IMMEDIATE);
		} else {
			logdebug("%s: invalid ilb type", __func__);
		}
		break;
	}

	free(valstr);
	return (ret);
}

static ilbd_var_type_t
ilbd_name_to_valtype(const char *prop_name)
{
	int i;

	for (i = 0; i < ILBD_PROP_VAR_NUM; i++)
		if (strncmp(prop_name, prop_tbl[i].scf_propname,
		    strlen(prop_tbl[i].scf_propname)) == 0)
			return (prop_tbl[i].val_type);

	logdebug("ilbd_name_to_valtype: couldn't find prop %s", prop_name);
	return (ILBD_VAR_INVALID);
}

/* callback for pg_walk_prop, arg is ilbd_data_t */
static ilb_status_t
ilbd_scf_load_prop(scf_propertygroup_t *pg, const char *prop_name, void *arg)
{
	scf_handle_t *h;
	scf_value_t *val;
	ilb_status_t ret;
	ilbd_data_t *ilb_data = (ilbd_data_t *)arg;
	ilbd_var_type_t val_type = ilbd_name_to_valtype(prop_name);

	h = scf_pg_handle(pg);
	if (h == NULL)
		return (ILB_STATUS_EINVAL);

	ret = ilbd_scf_get_prop_val(pg, prop_name, &val);
	if (ret == ILB_STATUS_ENOENT)
		return (ILB_STATUS_OK);
	else if (ret != ILB_STATUS_OK)
		return (ret);

	/*
	 * Load value to ilb_data.
	 */
	ret = ilbd_scfval_to_data(prop_name, val_type, val, ilb_data);

out:
	if (val != NULL)
		scf_value_destroy(val);

	return (ret);
}

/*
 * walk properties in one prop group, arg is ilbd_data
 * cb is ilbd_scf_load_prop()
 */
static ilb_status_t
ilbd_scf_pg_walk_props(scf_propertygroup_t *pg,
    ilb_status_t (*cb)(scf_propertygroup_t *, const char *, void *),
    void *arg)
{
	scf_handle_t *h;
	scf_iter_t *propiter;
	scf_property_t *prop;
	int scf_name_len = ILBD_MAX_NAME_LEN;
	char *prop_name = NULL;
	ilb_status_t ret = ILB_STATUS_OK;
	int scf_ret = -1;

	h = scf_pg_handle(pg);
	if (h == NULL)
		return (ILB_STATUS_EINVAL);

	prop = scf_property_create(h);
	propiter = scf_iter_create(h);
	if (prop == NULL || propiter == NULL)
		goto out;

	if (scf_iter_pg_properties(propiter, pg) != 0)
		goto out;

	if ((prop_name = malloc(scf_name_len)) == NULL) {
		ret = ILB_STATUS_ENOMEM;
		goto out;
	}
	while ((scf_ret = scf_iter_next_property(propiter, prop)) == 1) {
		if (scf_property_get_name(prop, prop_name, scf_name_len)
		    < 0) {
			ret = ilbd_scf_err_to_ilb_err();
			goto out;
		}
		ret = cb(pg, prop_name, arg);
		if (ret != ILB_STATUS_OK)
			break;
	}
out:
	if (prop_name != NULL)
		free(prop_name);
	if (scf_ret == -1)
		ret = ilbd_scf_err_to_ilb_err();
	if (prop != NULL)
		scf_property_destroy(prop);
	if (propiter != NULL)
		scf_iter_destroy(propiter);

	return (ret);
}

/* cbs are libd_create_X */
static ilb_status_t
ilbd_scf_instance_walk_pg(scf_instance_t *inst,
    ilbd_scf_pg_type_t pg_type,
    ilb_status_t (*cb)(void *, int, struct passwd *, ucred_t *),
    void *arg1, void *arg2)
{
	int			scf_ret;
	ilb_status_t		ret;
	scf_handle_t		*h;
	scf_iter_t		*pgiter;
	scf_propertygroup_t	*newpg;
	int			port = *((int *)arg1);
	int scf_name_len = ILBD_MAX_NAME_LEN;
	char *pg_name = NULL;

	if (inst == NULL)
		return (ILB_STATUS_EINVAL);

	h = scf_instance_handle(inst);
	if (h == NULL)
		return (ILB_STATUS_EINVAL);

	if ((newpg = scf_pg_create(h)) == NULL)
		return (ilbd_scf_err_to_ilb_err());

	if ((pgiter = scf_iter_create(h)) == NULL) {
		scf_pg_destroy(newpg);
		return (ilbd_scf_err_to_ilb_err());
	}

	if ((scf_ret = scf_iter_instance_pgs(pgiter, inst)) < 0)
		goto out;

	if ((pg_name = malloc(scf_name_len)) == NULL) {
		ret = ILB_STATUS_ENOMEM;
		goto out;
	}
	while ((scf_ret = scf_iter_next_pg(pgiter, newpg)) > 0) {
		ilbd_data_t data;

		if (scf_pg_get_name(newpg, pg_name, scf_name_len) < 0) {
			ret = ilbd_scf_err_to_ilb_err();
			goto out;
		}

		/*
		 * if pg name indicates it's a ilb configuration, walk its prop
		 */
		data.pg_type = pg_type;
		data.hc_data = NULL;
		data.sg_data = NULL;
		data.rule_data = NULL;

		switch (pg_type) {
		case ILBD_SCF_RULE:
			if (strncmp(ILBD_PG_NAME_RULE, pg_name,
			    strlen(ILBD_PG_NAME_RULE)) == 0) {
				data.rule_data = calloc(1,
				    sizeof (ilb_rule_info_t));
				if (data.rule_data == NULL) {
					ret = ILB_STATUS_ENOMEM;
					goto out;
				}
				ret = ilbd_scf_pg_walk_props(newpg,
				    ilbd_scf_load_prop, &data);
				if (ret != ILB_STATUS_OK)
					goto out;
				assert(data.rule_data != NULL);
				/* set rule name */
				(void) strlcpy(data.rule_data->rl_name,
				    &pg_name[strlen(ILBD_PG_NAME_RULE)],
				    sizeof (data.rule_data->rl_name));

				ret = cb(data.rule_data, port, arg2, NULL);
				free(data.rule_data);
				if (ret != ILB_STATUS_OK)
					goto out;
			}
			break;
		case ILBD_SCF_SG:
			if (strncmp(ILBD_PG_NAME_SG, pg_name,
			    strlen(ILBD_PG_NAME_SG)) == 0) {
				data.sg_data = calloc(1,
				    sizeof (ilb_sg_info_t));
				if (data.sg_data == NULL) {
					ret = ILB_STATUS_ENOMEM;
					goto out;
				}
				ret = ilbd_scf_pg_walk_props(newpg,
				    ilbd_scf_load_prop, &data);
				if (ret != ILB_STATUS_OK) {
					free(data.sg_data);
					goto out;
				}
				assert(data.sg_data != NULL);
				/* set sg name */
				(void) strlcpy(data.sg_data->sg_name,
				    &pg_name[strlen(ILBD_PG_NAME_SG)],
				    sizeof (data.sg_data->sg_name));
				ret = cb(data.sg_data, port, arg2, NULL);
				if (ret != ILB_STATUS_OK) {
					free(data.sg_data);
					goto out;
				}
				/*
				 * create a servergroup is two-step operation.
				 * 1. create an empty servergroup.
				 * 2. add server(s) to the group.
				 *
				 * since we are here from:
				 * main_loop()->ilbd_read_config()->
				 * ilbd_walk_sg_pgs()
				 * there is no cli to send. So in this
				 * path auditing will skip the
				 * adt_set_from_ucred() check
				 */
				if (data.sg_data->sg_srvcount > 0) {
					ret = ilbd_add_server_to_group(
					    data.sg_data, port, NULL, NULL);
					if (ret != ILB_STATUS_OK) {
						free(data.sg_data);
						goto out;
					}
					free(data.sg_data);
				}
			}
			break;
		case ILBD_SCF_HC:
			if (strncmp(ILBD_PG_NAME_HC, pg_name,
			    strlen(ILBD_PG_NAME_HC)) == 0) {
				data.hc_data = calloc(1,
				    sizeof (ilb_hc_info_t));
				if (data.hc_data == NULL) {
					ret = ILB_STATUS_ENOMEM;
					goto out;
				}
				ret = ilbd_scf_pg_walk_props(newpg,
				    ilbd_scf_load_prop, &data);
				if (ret != ILB_STATUS_OK)
					goto out;
				assert(data.hc_data != NULL);
				/* set hc name */
				(void) strlcpy(data.hc_data->hci_name,
				    &pg_name[strlen(ILBD_PG_NAME_HC)],
				    sizeof (data.hc_data->hci_name));
				ret = cb(data.hc_data, port, arg2, NULL);
				free(data.hc_data);
				if (ret != ILB_STATUS_OK)
					goto out;
			}
			break;
		}
	}

out:
	if (pg_name != NULL)
		free(pg_name);
	if (scf_ret < 0)
		ret = ilbd_scf_err_to_ilb_err();
	scf_pg_destroy(newpg);
	scf_iter_destroy(pgiter);
	return (ret);
}

typedef ilb_status_t (*ilbd_scf_walker_fn)(void *, int, struct passwd *,
    ucred_t *);

ilb_status_t
ilbd_walk_rule_pgs(ilb_status_t (*func)(ilb_rule_info_t *, int,
    const struct passwd *, ucred_t *), void *arg1, void *arg2)
{
	scf_instance_t *inst;
	scf_handle_t *h;
	scf_service_t *svc;
	ilb_status_t ret;

	ret = ilbd_scf_get_inst(&h, &svc, &inst);
	if (ret != ILB_STATUS_OK)
		return (ret);

	/* get rule prop group, transfer it to ilb_lrule_info_t */
	ret = ilbd_scf_instance_walk_pg(inst, ILBD_SCF_RULE,
	    (ilbd_scf_walker_fn)func, arg1, arg2);
	ilbd_scf_destroy(h, svc, inst, NULL);
	return (ret);
}

ilb_status_t
ilbd_walk_sg_pgs(ilb_status_t (*func)(ilb_sg_info_t *, int,
    const struct passwd *, ucred_t *), void *arg1, void *arg2)
{
	scf_instance_t *inst;
	scf_handle_t *h;
	scf_service_t *svc;
	ilb_status_t ret;

	ret = ilbd_scf_get_inst(&h, &svc, &inst);
	if (ret != ILB_STATUS_OK)
		return (ret);

	ret = ilbd_scf_instance_walk_pg(inst, ILBD_SCF_SG,
	    (ilbd_scf_walker_fn)func, arg1, arg2);
	ilbd_scf_destroy(h, svc, inst, NULL);
	return (ret);
}

ilb_status_t
ilbd_walk_hc_pgs(ilb_status_t (*func)(const ilb_hc_info_t *, int,
    const struct passwd *, ucred_t *), void *arg1, void *arg2)
{
	scf_instance_t *inst;
	scf_handle_t *h;
	scf_service_t *svc;
	ilb_status_t ret;

	ret = ilbd_scf_get_inst(&h, &svc, &inst);
	if (ret != ILB_STATUS_OK)
		return (ret);

	ret = ilbd_scf_instance_walk_pg(inst, ILBD_SCF_HC,
	    (ilbd_scf_walker_fn)func, arg1, arg2);
	ilbd_scf_destroy(h, svc, inst, NULL);
	return (ret);
}

ilb_status_t
ilbd_change_prop(ilbd_scf_pg_type_t pg_type, const char *pg_name,
    const char *prop_name, void *new_val)
{
	int ret;
	scf_propertygroup_t *scfpg = NULL;
	char *scf_pgname = NULL;
	scf_type_t scftype;
	scf_value_t *scfval;
	scf_handle_t *h;

	if ((scf_pgname = malloc(ILBD_MAX_NAME_LEN)) == NULL)
		return (ILB_STATUS_ENOMEM);
	ilbd_name_to_scfpgname(pg_type, pg_name, scf_pgname);
	ret = ilbd_scf_retrieve_pg(scf_pgname, &scfpg, B_FALSE);
	free(scf_pgname);

	if (ret != ILB_STATUS_EEXIST)
		return (ret);

	assert(scfpg != NULL);

	h = scf_pg_handle(scfpg);
	if (h == NULL) {
		ret = ILB_STATUS_EINVAL;
		goto done;
	}

	if ((scfval = scf_value_create(h)) == NULL) {
		ret = ILB_STATUS_ENOMEM;
		goto done;
	}

	if (pg_type == ILBD_SCF_RULE) {
		scftype = SCF_TYPE_BOOLEAN;
		scf_value_set_boolean(scfval, *(boolean_t *)new_val);
	} else if (pg_type == ILBD_SCF_SG) {
		scftype = SCF_TYPE_ASTRING;
		(void) scf_value_set_astring(scfval, (char *)new_val);
	}
	ret = ilbd_scf_set_prop(scfpg, prop_name, scftype, scfval);

done:
	if (scf_pg_handle(scfpg) != NULL)
		scf_handle_destroy(scf_pg_handle(scfpg));
	if (scfpg != NULL)
		scf_pg_destroy(scfpg);
	if (scfval != NULL)
		scf_value_destroy(scfval);
	return (ret);
}

/*
 * Update the persistent configuration with a new server, srv, added to a
 * server group, sg.
 */
ilb_status_t
ilbd_scf_add_srv(ilbd_sg_t *sg, ilbd_srv_t *srv)
{
	scf_propertygroup_t *pg;
	scf_handle_t *h;
	scf_value_t *val;
	ilb_status_t ret;
	int scf_name_len = ILBD_MAX_NAME_LEN;
	char *buf = NULL;

	if ((buf = malloc(scf_name_len)) == NULL)
		return (ILB_STATUS_ENOMEM);

	ilbd_name_to_scfpgname(ILBD_SCF_SG, sg->isg_name, buf);
	ret = ilbd_scf_retrieve_pg(buf, &pg, B_FALSE);
	/*
	 * The server group does not exist in persistent storage.  This
	 * cannot happen.  Should probably transition the service to
	 * maintenance since it should be there.
	 */
	if (ret != ILB_STATUS_EEXIST) {
		logerr("ilbd_scf_add_srv: SCF update failed - entering"
		    " maintenance mode");
		(void) smf_maintain_instance(ILB_FMRI, SMF_IMMEDIATE);
		free(buf);
		return (ILB_STATUS_INTERNAL);
	}

	if ((h = scf_pg_handle(pg)) == NULL) {
		ilbd_scf_destroy(NULL, NULL, NULL, pg);
		free(buf);
		return (ilbd_scf_err_to_ilb_err());
	}

	if ((val = scf_value_create(h)) == NULL) {
		ilbd_scf_destroy(h, NULL, NULL, pg);
		free(buf);
		return (ILB_STATUS_ENOMEM);
	}
	ilbd_srv_scf_val(srv, buf);
	(void) scf_value_set_astring(val, buf);

	(void) snprintf(buf, scf_name_len, "server%d", srv->isv_id);
	ret = ilbd_scf_set_prop(pg, buf, SCF_TYPE_ASTRING, val);
	free(buf);
	ilbd_scf_destroy(h, NULL, NULL, pg);
	scf_value_destroy(val);

	return (ret);
}

/*
 * Delete a server, srv, of a server group, sg, from the persistent
 * configuration.
 */
ilb_status_t
ilbd_scf_del_srv(ilbd_sg_t *sg, ilbd_srv_t *srv)
{
	ilb_status_t ret;
	scf_propertygroup_t *pg;
	scf_handle_t *h;
	int scf_name_len = ILBD_MAX_NAME_LEN;
	char *buf;
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *entry = NULL;

	if ((buf = malloc(scf_name_len)) == NULL)
		return (ILB_STATUS_ENOMEM);
	ilbd_name_to_scfpgname(ILBD_SCF_SG, sg->isg_name, buf);
	ret = ilbd_scf_retrieve_pg(buf, &pg, B_FALSE);
	/*
	 * The server group does not exist in persistent storage.  This
	 * cannot happen. THe caller of this function puts service in
	 * maintenance mode.
	 */
	if (ret != ILB_STATUS_EEXIST) {
		free(buf);
		return (ILB_STATUS_INTERNAL);
	}
	ret = ILB_STATUS_OK;

	if ((h = scf_pg_handle(pg)) == NULL) {
		logdebug("ilbd_scf_del_srv: scf_pg_handle: %s\n",
		    scf_strerror(scf_error()));
		ilbd_scf_destroy(NULL, NULL, NULL, pg);
		free(buf);
		return (ilbd_scf_err_to_ilb_err());
	}

	if ((tx = scf_transaction_create(h)) == NULL ||
	    (entry = scf_entry_create(h)) == NULL) {
		logdebug("ilbd_scf_del_srv: create scf transaction failed: "
		    "%s\n", scf_strerror(scf_error()));
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}

	(void) snprintf(buf, scf_name_len, "server%d", srv->isv_id);

	if (scf_transaction_start(tx, pg) == -1) {
		logdebug("ilbd_scf_set_prop: start scf transaction failed: "
		    "%s\n", scf_strerror(scf_error()));
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}
	if (scf_transaction_property_delete(tx, entry, buf) == -1) {
		logdebug("ilbd_scf_set_prop: delete property failed: %s\n",
		    scf_strerror(scf_error()));
		ret = ilbd_scf_err_to_ilb_err();
		goto out;
	}
	if (scf_transaction_commit(tx) != 1) {
		logdebug("ilbd_scf_set_prop: commit transaction failed: %s\n",
		    scf_strerror(scf_error()));
		ret = ilbd_scf_err_to_ilb_err();
	}

out:
	free(buf);
	if (entry != NULL)
		scf_entry_destroy(entry);
	if (tx != NULL)
		scf_transaction_destroy(tx);
	ilbd_scf_destroy(h, NULL, NULL, pg);

	return (ret);
}
