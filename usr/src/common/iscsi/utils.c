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
#include <sys/socket.h>


#ifdef _KERNEL
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/utsname.h>

/*
 * NOTE: This routine is found in libnsl. There's apparently no prototype to
 * be found in any of the header files in /usr/include so defining a prototype
 * here to keep the compiler happy.
 */
int getdomainname(char *, int);

static const char *iqn_template		= "iqn.2004-02.%s";
#endif

#include <sys/scsi/adapters/iscsi_if.h>

typedef struct utils_val_name {
	int	u_val;
	char	*u_name;
} utils_val_name_t;

utils_val_name_t param_names[] = {
	{ ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER, "Sequence In Order"},
	{ ISCSI_LOGIN_PARAM_IMMEDIATE_DATA, "Immediate Data"},
	{ ISCSI_LOGIN_PARAM_INITIAL_R2T, "Inital R2T"},
	{ ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER, "Data PDU In Order"},
	{ ISCSI_LOGIN_PARAM_HEADER_DIGEST, "Header Digest"},
	{ ISCSI_LOGIN_PARAM_DATA_DIGEST, "Data Digest"},
	{ ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN, "Default Time To Retain"},
	{ ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT, "Default Time To Wait"},
	{ ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH,
	    "Max Recv Data Segment Length"},
	{ ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH, "First Burst Length"},
	{ ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH, "Max Burst Length"},
	{ ISCSI_LOGIN_PARAM_MAX_CONNECTIONS, "Max Connections"},
	{ ISCSI_LOGIN_PARAM_OUTSTANDING_R2T, "Outstanding R2T"},
	{ ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL, "Error Recovery Level"},
	{ 0, NULL }
};

/*
 * utils_map_param -- Given a parameter return it's ascii name
 *
 * This routine was created because previously an array contained in order
 * the parameter names. Once or twice the parameters value changed which
 * changed the order, but not the array. To avoid further confusion we'll
 * do a simple lookup. This code is rarely called so it shouldn't be an
 * issue.
 */
char *
utils_map_param(int p)
{
	utils_val_name_t	*pn;

	for (pn = param_names; pn->u_name != NULL; pn++)
		if (pn->u_val == p)
			return (pn->u_name);
	return (NULL);
}

/*
 * prt_bitmap -- print out ascii strings associated with bit numbers.
 */
char *
prt_bitmap(int bitmap, char *str, char *buf, int size)
{
	char	*p		= NULL;
	char	*start		= buf;
	int	do_put		= 0;

	/*
	 * The maximum space required will if the bitmap was all 1's which
	 * would cause the octal characters to be replaced by '|'. So make
	 * sure the buffer has enough space.
	 */
	if (size < strlen(str))
		return ("No room");

	for (p = str; size--; p++) {
		if (*p < 0x20) {

			/*
			 * if we have been putting out stuff add separator
			 */
			if (do_put)
				*buf++ = '|';

			do_put = ((1 << *p) & bitmap);
			bitmap &= ~(1 << *p);

		} else if (do_put)
			*buf++ = *p;
	}

	/* ---- remove the last separator if it was added ---- */
	if ((buf > start) && (*(buf - 1) == '|'))
		buf--;
	*buf = '\0';
	return (start);
}

/*
 * parse_addr_port_tpgt - Used to parse addr, port and tpgt from string
 *
 * This function is used to parse addr, port and tpgt from a string.  Callers
 * of this function are the sendtargets and login redirection code.  The
 * caller must be aware that this function will modify the callers string
 * to insert NULL terminators if required.  Port and TPGT are optional.
 */
boolean_t
parse_addr_port_tpgt(char *in, char **addr, int *type, char **port, char **tpgt)
{
	char	*t_port, *t_tpgt;

	/* default return values if requested */
	if (addr == NULL) {
		return (B_FALSE);
	} else {
		*addr = NULL;
	}
	if (port != NULL) {
		*port = NULL;
	}
	if (tpgt != NULL) {
		*tpgt = NULL;
	}

	/* extract ip or domain name */
	if (*in == '[') {
		/* IPV6 */
		*type = AF_INET6;
		*addr = ++in;
		in = strchr(*addr, ']');
		if (in == NULL)
			return (B_FALSE);
		*in++ = '\0';
	} else {
		/* IPV4 or domainname */
		*type = AF_INET;
		*addr = in;
	}

	/* extract port */
	if (port != NULL) {
		t_port = strchr(in, ':');
		if (t_port != NULL) {
			*t_port++ = '\0';
			*port = in = t_port;
		}
	}

	/* exact tpgt */
	if (tpgt != NULL) {
		t_tpgt = strchr(in, ',');
		if (t_tpgt != NULL) {
			*t_tpgt++ = '\0';
			*tpgt = in = t_tpgt;
		}
	}

	return (B_TRUE);
}

#ifndef _KERNEL
/*
 * []--------------------------------------------------------------[]
 * | reverse_fqdn -- given a fully qualified domain name reverse it |
 * |                                                                |
 * | The routine has the obvious problem that it can only handle a  |
 * | name with 5 or less dots. This needs to be fixed by counting   |
 * | the number of dots in the incoming name, calloc'ing an array   |
 * | of the appropriate size and then handling the pointers.	    |
 * []--------------------------------------------------------------[]
 */
static boolean_t
/* LINTED E_FUNC_ARG_UNUSED for 3rd arg size */
reverse_fqdn(const char *domain, char *buf, int size)
{
	char	*ptrs[5];
	char	*dp;
	char	*dp1;
	char	*p;
	int	v = 4;

	if ((dp = dp1 = malloc(strlen(domain) + 1)) == NULL)
		return (B_FALSE);
	(void) strcpy(dp, domain);
	while ((p = (char *)strchr(dp, '.')) != NULL) {
		*p = '\0';
		if (v < 0) {
			free(dp1);
			return (B_FALSE);
		}
		ptrs[v--] = dp;
		dp = p + 1;
	}
	(void) strcpy(buf, dp);
	for (v++; v < 5; v++) {
		(void) strcat(buf, ".");
		(void) strcat(buf, ptrs[v]);
	}
	free(dp1);
	return (B_TRUE);
}

/*
 * []------------------------------------------------------------------[]
 * | utils_iqn_create -- returns an iqn name for the machine		|
 * |									|
 * | The information found in the iqn is not correct. The year and	|
 * | date should be flexible. Currently this is hardwired to the	|
 * | current year and month of this project.				|
 * []------------------------------------------------------------------[]
 */
boolean_t
utils_iqn_create(char *iqn_buf, int size)
{
	struct utsname	uts_info;
	char		domainname[256];
	char		*temp = NULL;
	char		*p;
	char		*pmet = NULL; /* temp reversed .. get it */
	int		len;
	boolean_t	rval = B_FALSE; /* Default */

	if (uname(&uts_info) == -1) {
		goto out;
	}

	if (getdomainname(domainname, sizeof (domainname))) {
		goto out;
	}

	if ((temp = malloc(strlen(uts_info.nodename) +
	    strlen(domainname) + 2)) == NULL) {
		goto out;
	}

	/*
	 * getdomainname always returns something in the order of
	 * host.domainname so we need to skip over that portion of the
	 * host name because we don't care about it.
	 */
	if ((p = strchr(domainname, '.')) == NULL)
		p = domainname;
	else
		p++;

	/* ---- Create Fully Qualified Domain Name ---- */
	(void) snprintf(temp, strlen(p), "%s.%s", uts_info.nodename, p);

	/* ---- According to the spec, names must be lower case ---- */
	for (p = temp; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);

	len = strlen(temp) + 1;
	if ((pmet = malloc(len)) == NULL) {
		goto out;
	}

	if (reverse_fqdn(temp, pmet, len) == B_FALSE) {
		goto out;
	}

	/*
	 * Now use the template with the reversed domainname to create
	 * an iSCSI name using the IQN format. Only count it a success
	 * if the number of characters formated is less than the buffer
	 * size.
	 */
	if (snprintf(iqn_buf, size, iqn_template, pmet) <= size)
		rval = B_TRUE;
out:
	if (temp)
		free(temp);
	if (pmet)
		free(pmet);

	return (rval);
}
#endif /* !_KERNEL */
