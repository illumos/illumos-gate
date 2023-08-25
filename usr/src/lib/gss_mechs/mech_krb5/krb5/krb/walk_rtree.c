/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/krb/walk_rtree.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * krb5_walk_realm_tree()
 */

/* ANL - Modified to allow Configurable Authentication Paths.
 * This modification removes the restriction on the choice of realm
 * names, i.e. they nolonger have to be hierarchical. This
 * is allowed by RFC 1510: "If a hierarchical orginization is not used
 * it may be necessary to consult some database in order to construct
 * an authentication path between realms."  The database is contained
 * in the [capaths] section of the krb5.conf file.
 * Client to server paths are defined. There are n**2 possible
 * entries, but only those entries which are needed by the client
 * or server need be present in its krb5.conf file. (n entries or 2*n
 * entries if the same krb5.conf is used for clients and servers)
 *
 * for example: ESnet will be running a KDC which will share
 * inter-realm keys with its many orginizations which include among
 * other ANL, NERSC and PNL. Each of these orginizations wants to
 * use its DNS name in the realm, ANL.GOV. In addition ANL wants
 * to authenticatite to HAL.COM via a K5.MOON and K5.JUPITER
 * A [capaths] section of the krb5.conf file for the ANL.GOV clients
 * and servers would look like:
 *
 * [capaths]
 * ANL.GOV = {
 *		NERSC.GOV = ES.NET
 *		PNL.GOV = ES.NET
 *		ES.NET = .
 * 		HAL.COM = K5.MOON
 * 		HAL.COM = K5.JUPITER
 * }
 * NERSC.GOV = {
 *		ANL.GOV = ES.NET
 * }
 * PNL.GOV = {
 *		ANL.GOV = ES.NET
 * }
 * ES.NET = {
 * 		ANL.GOV = .
 * }
 * HAL.COM = {
 *		ANL.GOV = K5.JUPITER
 *		ANL.GOV = K5.MOON
 * }
 *
 * In the above a "." is used to mean directly connected since the
 * the profile routines cannot handle a null entry.
 *
 * If no client-to-server path is found, the default hierarchical path
 * is still generated.
 *
 * This version of the Configurable Authentication Path modification
 * differs from the previous versions prior to K5 beta 5 in that
 * the profile routines are used, and the explicite path from
 * client's realm to server's realm must be given. The modifications
 * will work together.
 * DEE - 5/23/95
 */
#define CONFIGURABLE_AUTHENTICATION_PATH
#include "k5-int.h"
#include "int-proto.h"
#include <locale.h>

/* internal function, used by krb5_get_cred_from_kdc() */

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#define max(x,y) ((x) > (y) ? (x) : (y))
#endif

/*
 * xxx The following function is very confusing to read and probably
 * is buggy.  It should be documented better.  Here is what I've
 * learned about it doing a quick bug fixing walk through.  The
 * function takes a client and server realm name and returns the set
 * of realms (in a field called tree) that you need to get tickets in
 * in order to get from the source realm to the destination realm.  It
 * takes a realm separater character (normally ., but presumably there
 * for all those X.500 realms) .  There are two modes it runs in: the
 * ANL krb5.conf mode and the hierarchy mode.  The ANL mode is
 * fairly obvious.  The hierarchy mode looks for common components in
 * both the client and server realms.  In general, the pointer scp and
 * ccp are used to walk through the client and server realms.  The
 * com_sdot and com_cdot pointers point to (I think) the beginning of
 * the common part of the realm names.  I.E. strcmp(com_cdot,
 * com_sdot) ==0 is roughly an invarient.  However, there are cases
 * where com_sdot and com_cdot are set to point before the start of
 * the client or server strings.  I think this only happens when there
 * are no common components.  --hartmans 2002/03/14
 */

krb5_error_code
krb5_walk_realm_tree(krb5_context context, const krb5_data *client, const krb5_data *server, krb5_principal **tree, int realm_branch_char)
{
    krb5_error_code retval;
    krb5_principal *rettree;
    register char *ccp, *scp;
    register char *prevccp = 0, *prevscp = 0;
    char *com_sdot = 0, *com_cdot = 0;
    register int i, links = 0;
    int clen, slen = -1;
    krb5_data tmpcrealm, tmpsrealm;
    int nocommon = 1;

#ifdef CONFIGURABLE_AUTHENTICATION_PATH
    const char *cap_names[4];
    char *cap_client, *cap_server;
    char **cap_nodes;
    krb5_error_code cap_code;
#endif

#ifdef DEBUG_REFERRALS
    printf("krb5_walk_realm_tree starting\n");
    printf("  client is %s\n",client->data);
    printf("  server is %s\n",server->data);
#endif

    if (!(client->data && server->data)) {
	/* Solaris Kerberos - enhance error message */
	if (!client->data && !server->data) {
	    krb5_set_error_message(context, KRB5_NO_TKT_IN_RLM,
				dgettext(TEXT_DOMAIN,
					"Cannot find ticket for requested realm: unknown client and server"));
	} else {
	    if (!client->data) {
		krb5_set_error_message(context, KRB5_NO_TKT_IN_RLM,
				    dgettext(TEXT_DOMAIN,
					    "Cannot find ticket for requested realm: unknown client"));
	    } else {
	       krb5_set_error_message(context, KRB5_NO_TKT_IN_RLM,
				    dgettext(TEXT_DOMAIN,
					    "Cannot find ticket for requested realm: unknown server"));
	    }
	}
	return KRB5_NO_TKT_IN_RLM;
    }
#ifdef CONFIGURABLE_AUTHENTICATION_PATH
    if ((cap_client = (char *)malloc(client->length + 1)) == NULL)
	return ENOMEM;
    strncpy(cap_client, client->data, client->length);
    cap_client[client->length] = '\0';
    if ((cap_server = (char *)malloc(server->length + 1)) == NULL) {
	krb5_xfree(cap_client);
	return ENOMEM;
    }
    strncpy(cap_server, server->data, server->length);
    cap_server[server->length] = '\0';
    cap_names[0] = "capaths";
    cap_names[1] = cap_client;
    cap_names[2] = cap_server;
    cap_names[3] = 0;
    cap_code = profile_get_values(context->profile, cap_names, &cap_nodes);
    krb5_xfree(cap_client);  /* done with client string */
    cap_names[1] = 0;
    if (cap_code == 0) {     /* found a path, so lets use it */
	links = 0;
	if (*cap_nodes[0] != '.') { /* a link of . means direct */
	    while(cap_nodes[links]) {
		links++;
	    }
	}
	if (cap_nodes[links] != NULL)
	    krb5_xfree(cap_nodes[links]);

	cap_nodes[links] = cap_server; /* put server on end of list */
	/* this simplifies the code later and make */
	/* cleanup eaiser as well */
	links++;		/* count the null entry at end */
    } else {			/* no path use hierarchical method */
	krb5_xfree(cap_server); /* failed, don't need server string */
	cap_names[2] = 0;
#endif
	clen = client->length;
	slen = server->length;

	for (com_cdot = ccp = client->data + clen - 1,
		 com_sdot = scp = server->data + slen - 1;
	     clen && slen && *ccp == *scp ;
	     ccp--, scp--, 	clen--, slen--) {
	    if (*ccp == realm_branch_char) {
		com_cdot = ccp;
		com_sdot = scp;
		nocommon = 0;
	    }
	}

	/* ccp, scp point to common root.
	   com_cdot, com_sdot point to common components. */
	/* handle case of one ran out */
	if (!clen) {
	    /* construct path from client to server, down the tree */
	    if (!slen) {
		/* in the same realm--this means there is no ticket
		   in this realm. */
	        krb5_set_error_message(context, KRB5_NO_TKT_IN_RLM,
				    dgettext(TEXT_DOMAIN,
					    "Cannot find ticket for requested realm: client is '%s', server is '%s'"),
				    client->data, server->data);
		return KRB5_NO_TKT_IN_RLM;
	    }
	    if (*scp == realm_branch_char) {
		/* one is a subdomain of the other */
		com_cdot = client->data;
		com_sdot = scp;
		nocommon = 0;
	    } /* else normal case of two sharing parents */
	}
	if (!slen) {
	    /* construct path from client to server, up the tree */
	    if (*ccp == realm_branch_char) {
		/* one is a subdomain of the other */
		com_sdot = server->data;
		com_cdot = ccp;
		nocommon = 0;
	    } /* else normal case of two sharing parents */
	}
	/* determine #links to/from common ancestor */
	if (nocommon)
	    links = 1;
	else
	    links = 2;
	/* if no common ancestor, artificially set up common root at the last
	   component, then join with special code */
	for (ccp = client->data; ccp < com_cdot; ccp++) {
	    if (*ccp == realm_branch_char) {
		links++;
		if (nocommon)
		    prevccp = ccp;
	    }
	}

	for (scp = server->data; scp < com_sdot; scp++) {
	    if (*scp == realm_branch_char) {
		links++;
		if (nocommon)
		    prevscp = scp;
	    }
	}
	if (nocommon) {
	    if (prevccp)
		com_cdot = prevccp;
	    if (prevscp)
		com_sdot = prevscp;

	    if(com_cdot == client->data + client->length -1)
		com_cdot = client->data - 1 ;
	    if(com_sdot == server->data + server->length -1)
		com_sdot = server->data - 1 ;
	}
#ifdef CONFIGURABLE_AUTHENTICATION_PATH
    }		/* end of if use hierarchical method */
#endif

    if (!(rettree = (krb5_principal *)calloc(links+2,
					     sizeof(krb5_principal)))) {
	return ENOMEM;
    }
    i = 1;
    if ((retval = krb5_tgtname(context, client, client, &rettree[0]))) {
	krb5_xfree(rettree);
	return retval;
    }
#ifdef CONFIGURABLE_AUTHENTICATION_PATH
    links--;				/* dont count the null entry on end */
    if (cap_code == 0) {    /* found a path above */
	tmpcrealm.data = client->data;
	tmpcrealm.length = client->length;
	while( i-1 <= links) {

	    tmpsrealm.data = cap_nodes[i-1];
	    /* don't count trailing whitespace from profile_get */
	    tmpsrealm.length = strcspn(cap_nodes[i-1],"\t ");
	    if ((retval = krb5_tgtname(context,
				       &tmpsrealm,
				       &tmpcrealm,
				       &rettree[i]))) {
		while (i) {
		    krb5_free_principal(context, rettree[i-1]);
		    i--;
		}
		krb5_xfree(rettree);
				/* cleanup the cap_nodes from profile_get */
		for (i = 0; i<=links; i++) {
		    krb5_xfree(cap_nodes[i]);
		}
		krb5_xfree((char *)cap_nodes);
		return retval;
	    }
	    tmpcrealm.data = tmpsrealm.data;
	    tmpcrealm.length = tmpsrealm.length;
	    i++;
	}
	/* cleanup the cap_nodes from profile_get last one has server */
	for (i = 0; i<=links; i++) {
	    krb5_xfree(cap_nodes[i]);
	}
	krb5_xfree((char *)cap_nodes);
    } else {  /* if not cap then use hierarchical method */
#endif
	for (prevccp = ccp = client->data;
	     ccp <= com_cdot;
	     ccp++) {
	    if (*ccp != realm_branch_char)
		continue;
	    ++ccp;				/* advance past dot */
	    tmpcrealm.data = prevccp;
	    tmpcrealm.length = client->length -
		(prevccp - client->data);
	    tmpsrealm.data = ccp;
	    tmpsrealm.length = client->length -
		(ccp - client->data);
	    if ((retval = krb5_tgtname(context, &tmpsrealm, &tmpcrealm,
				       &rettree[i]))) {
		while (i) {
		    krb5_free_principal(context, rettree[i-1]);
		    i--;
		}
		krb5_xfree(rettree);
		return retval;
	    }
	    prevccp = ccp;
	    i++;
	}
	if (nocommon) {
	    tmpcrealm.data = com_cdot + 1;
	    tmpcrealm.length = client->length -
		(com_cdot + 1 - client->data);
	    tmpsrealm.data = com_sdot + 1;
	    tmpsrealm.length = server->length -
		(com_sdot + 1 - server->data);
	    if ((retval = krb5_tgtname(context, &tmpsrealm, &tmpcrealm,
				       &rettree[i]))) {
		while (i) {
		    krb5_free_principal(context, rettree[i-1]);
		    i--;
		}
		krb5_xfree(rettree);
		return retval;
	    }
	    i++;
	}

	for (prevscp = com_sdot + 1, scp = com_sdot - 1;
	     scp > server->data;
	     scp--) {
	    if (*scp != realm_branch_char)
		continue;
	    if (scp - 1 < server->data)
		break;			/* XXX only if . starts realm? */
	    tmpcrealm.data = prevscp;
	    tmpcrealm.length = server->length -
		(prevscp - server->data);
	    tmpsrealm.data = scp + 1;
	    tmpsrealm.length = server->length -
		(scp + 1 - server->data);
	    if ((retval = krb5_tgtname(context, &tmpsrealm, &tmpcrealm,
				       &rettree[i]))) {
		while (i) {
		    krb5_free_principal(context, rettree[i-1]);
		    i--;
		}
		krb5_xfree(rettree);
		return retval;
	    }
	    prevscp = scp + 1;
	    i++;
	}
	if (slen && com_sdot >= server->data) {
	    /* only necessary if building down tree from ancestor or client */
	    /* however, we can get here if we have only one component
	       in the server realm name, hence we make sure we found a component
	       separator there... */
	    tmpcrealm.data = prevscp;
	    tmpcrealm.length = server->length -
		(prevscp - server->data);
	    if ((retval = krb5_tgtname(context, server, &tmpcrealm,
				       &rettree[i]))) {
		while (i) {
		    krb5_free_principal(context, rettree[i-1]);
		    i--;
		}
		krb5_xfree(rettree);
		return retval;
	    }
	}
#ifdef CONFIGURABLE_AUTHENTICATION_PATH
    }
#endif
    *tree = rettree;

#ifdef DEBUG_REFERRALS
    printf("krb5_walk_realm_tree ending; tree (length %d) is:\n",links);
    for(i=0;i<links+2;i++) {
        if ((*tree)[i])
	    krb5int_dbgref_dump_principal("krb5_walk_realm_tree tree",(*tree)[i]);
	else
	    printf("tree element %i null\n");
    }
#endif
    return 0;
}

#ifdef DEBUG_REFERRALS
void krb5int_dbgref_dump_principal(char *d, krb5_principal p)
{
    int n;

    printf("  **%s: ",d);
    for (n=0;n<p->length;n++)
	printf("%s<%.*s>",(n>0)?"/":"",p->data[n].length,p->data[n].data);
    printf("@<%.*s>  (length %d, type %d)\n",p->realm.length,p->realm.data,
	   p->length, p->type);
}
#endif
