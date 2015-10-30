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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_ADUTILS_IMPL_H
#define	_ADUTILS_IMPL_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ldap.h>
#include <pthread.h>
#include "addisc.h"
#include "libadutils.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DBG(type, lev)	\
	(ad_debug[AD_DEBUG_##type] >= (lev) || \
	    ad_debug[AD_DEBUG_ALL] >= (lev))
extern int ad_debug[AD_DEBUG_MAX + 1];

#define	ADUTILS_SEARCH_TIMEOUT	3
#define	ADUTILS_LDAP_OPEN_TIMEOUT	1


typedef struct adutils_sid {
	uchar_t		version;
	uchar_t		sub_authority_count;
	uint64_t	authority;  /* really, 48-bits */
	uint32_t	sub_authorities[ADUTILS_SID_MAX_SUB_AUTHORITIES];
} adutils_sid_t;

struct adutils_host;

struct known_domain {
	char		name[MAXDOMAINNAME];
	char		sid[MAXSTRSID];
};


/* A set of DSs for a given AD partition */
struct adutils_ad {
	int			num_known_domains;
	struct known_domain	*known_domains;
	pthread_mutex_t		lock;
	uint32_t		ref;
	struct adutils_host	*last_adh;
	adutils_ad_partition_t	partition;	/* Data or global catalog? */
	/* If this is a reference to DC, this is the base DN for that DC */
	char			*basedn;
};

typedef struct adutils_attr {
	char	*attr_name;
	uint_t	num_values;
	char	**attr_values;
} adutils_attr_t;

/* typedef in libadutils.h */
struct adutils_entry {
	uint_t			num_nvpairs;
	adutils_attr_t		*attr_nvpairs;
	struct adutils_entry	*next;
};

/* typedef in libadutils.h */
struct adutils_result {
	uint_t		num_entries;
	adutils_entry_t	*entries;
};

/* A single DS */
typedef struct adutils_host {
	struct adutils_host	*next;
	struct adutils_ad	*owner;		/* ad_t to which this belongs */
	pthread_mutex_t		lock;
	LDAP			*ld;		/* LDAP connection */
	uint32_t		ref;		/* ref count */
	time_t			idletime;	/* time since last activity */
	int			dead;		/* error on LDAP connection */
	/*
	 * Used to distinguish between different instances of LDAP
	 * connections to this same DS.  We need this so we never mix up
	 * results for a given msgID from one connection with those of
	 * another earlier connection where two batch state structures
	 * share this adutils_host object but used different LDAP connections
	 * to send their LDAP searches.
	 */
	uint64_t		generation;

	/* LDAP DS info */
	char			*host;
	int			port;

	/* hardwired to SASL GSSAPI only for now */
	char			*saslmech;
	unsigned		saslflags;

	/* Number of outstanding search requests */
	uint32_t		max_requests;
	uint32_t		num_requests;
} adutils_host_t;

/*  A place to put the results of a batched (async) query */
typedef struct adutils_q {
	const char		*edomain;	/* expected domain name */
	struct adutils_result	**result;	/* The LDAP search result */
	adutils_rc		*rc;
	int			msgid;		/* LDAP message ID */
} adutils_q_t;

/* Batch context structure */
struct adutils_query_state {
	struct adutils_query_state	*next;
	int			qsize;		/* Size of queries */
	int			ref_cnt;	/* reference count */
	pthread_cond_t		cv;		/* Condition wait variable */
	uint32_t		qcount;		/* Number of items queued */
	uint32_t		qinflight;	/* how many queries in flight */
	uint16_t		qdead;		/* oops, lost LDAP connection */
	adutils_host_t		*qadh;		/* LDAP connection */
	uint64_t		qadh_gen;	/* same as qadh->generation */
	adutils_ldap_res_search_cb ldap_res_search_cb;
	void			*ldap_res_search_argp;
	adutils_q_t		queries[1];	/* array of query results */
};

/* Private routines */

char *DN_to_DNS(const char *dn_name);

int adutils_getsid(BerValue *bval, adutils_sid_t *sidp);

char *adutils_sid2txt(adutils_sid_t *sidp);

int saslcallback(LDAP *ld, unsigned flags, void *defaults, void *prompts);

int adutils_set_thread_functions(LDAP *ld);

/* Global logger function */

extern adutils_logger logger;

#ifdef	__cplusplus
}
#endif

#endif	/* _ADUTILS_IMPL_H */
