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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains a function for printing objects to standard out.
 */

#include "mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include "nis_local.h"

#define	ZVAL zattr_val.zattr_val_val
#define	ZLEN zattr_val.zattr_val_len
#define	nilstring(s)	((s) ? (s) : "(nil)")
#define	CTBSIZE		26


/*
 * forward function prototypes.
 */

void nis_print_server(nis_server *);

void
nis_print_rights(uint_t	r)
{
	int s;
	for (s = 24; s >= 0; s -= 8) {
		if (r & (NIS_READ_ACC << s))
			(void) printf("r");
		else
			(void) printf("-");
		if (r & (NIS_MODIFY_ACC << s))
			(void) printf("m");
		else
			(void) printf("-");
		if (r & (NIS_CREATE_ACC << s))
			(void) printf("c");
		else
			(void) printf("-");
		if (r & (NIS_DESTROY_ACC << s))
			(void) printf("d");
		else
			(void) printf("-");
	}
}

void
nis_print_server(nis_server *s)
{
	int		i;
	int		nkeys;			/* number of keys */
	extdhkey_t	*key_info = NULL;	/* info for all public keys */

	(void) printf("\tName       : %s\n", nilstring(s->name));
	switch (s->key_type) {
	case NIS_PK_DHEXT :
		nkeys = __nis_dhext_extract_keyinfo(s, &key_info);
		(void) printf("%s",
			nkeys > 1 ? "\tPublic Keys : " : "\tPublic Key : ");
		(void) printf("Diffie-Hellman (");
		for (i = 0; i < nkeys; i++) {
			if (i > 0)
				(void) printf(", ");
			(void) printf("%d", key_info[i].keylen);
			if (key_info[i].algtype > 0)
				(void) printf("-%d", key_info[i].algtype);
		}
		(void) printf(" bits)\n");
		if (key_info)
			free(key_info);
		break;
	case NIS_PK_DH :
		(void) printf("\tPublic Key : ");
		(void) printf("Diffie-Hellman (%d bits)\n",
			(int)strlen(s->pkey.n_bytes) * 4);
		break;
	case NIS_PK_RSA :
		(void) printf("\tPublic Key : ");
		(void) printf("RSA (%d bits)\n", s->pkey.n_len * 4);
		break;
	case NIS_PK_NONE :
		(void) printf("None.\n");
		break;
	default :
		(void) printf("Unknown (type = %d, bits = %d)\n", s->key_type,
					s->pkey.n_len * 4);
	}

	(void) printf("\tUniversal addresses (%d)\n", s->ep.ep_len);
	for (i = 0; i < s->ep.ep_len; i++)
		(void) printf("\t[%d] - %s, %s, %s\n", i+1,
		    s->ep.ep_val[i].proto, s->ep.ep_val[i].family,
		    s->ep.ep_val[i].uaddr);
}

void __nis_print_directory_exptime(directory_obj *, uint32_t);

void
nis_print_directory(directory_obj *r)
{
	__nis_print_directory_exptime(r, 0);
}

void
__nis_print_directory_exptime(directory_obj *r, uint32_t exptime)
{
	int		i;
	uint32_t	do_ttl;


	(void) printf("Name : '%s'\n", nilstring(r->do_name));
	(void) printf("Type : ");
	switch (r->do_type) {
		case NIS :
			(void) printf("NIS\n");
			break;
		case SUNYP :
			(void) printf("YP\n");
			break;
		case DNS :
			(void) printf("DNS\n");
			break;
		default :
			(void) printf("%d\n", r->do_type);
	}
	for (i = 0; i < r->do_servers.do_servers_len; i++) {
		if (i == 0)
			(void) printf("Master Server :\n");
		else
			(void) printf("Replicate : \n");

		nis_print_server(&(r->do_servers.do_servers_val[i]));
	}
	do_ttl = r->do_ttl;
	if (exptime > 0) {
		struct timeval tp;
		if (gettimeofday(&tp, 0) != -1) {
			if (exptime > tp.tv_sec) {
				do_ttl = exptime - tp.tv_sec;
			} else {
				do_ttl = 0;
			}
		}
	}
	(void) printf("Time to live : %d:%d:%d\n", do_ttl/3600,
			(do_ttl - (do_ttl/3600)*3600)/60,
			(do_ttl % 60));
	(void) printf("Default Access rights :\n");
	for (i = 0; i < r->do_armask.do_armask_len; i++) {
		switch (r->do_armask.do_armask_val[i].oa_otype) {
			case NIS_GROUP_OBJ :
				(void) printf("\t\tGROUP Objects     : ");
				break;
			case NIS_ENTRY_OBJ :
				(void) printf("\t\tENTRY Objects     : ");
				break;
			case NIS_LINK_OBJ :
				(void) printf("\t\tLINK Objects      : ");
				break;
			case NIS_DIRECTORY_OBJ :
				(void) printf("\t\tDIRECTORY Objects : ");
				break;
			case NIS_TABLE_OBJ :
				(void) printf("\t\tTABLE Objects     : ");
				break;
			case NIS_BOGUS_OBJ :
				(void) printf("\t\tBOGUS Objects     : ");
				break;
			default :
				(void) printf("\t\tUnknown Objects   : ");
		}
		nis_print_rights(OARIGHTS(r, i));
		(void) printf("\n");
	}
}

void
nis_print_group(group_obj *g)
{
	int		i;

	(void) printf("Group Flags : ");
	if (g->gr_flags & NEGMEM_GROUPS)
		(void) printf("\tNegative Memberships allowed\n");
	if (g->gr_flags & IMPMEM_GROUPS)
		(void) printf("\tImplicit Membership allowed\n");
	if (g->gr_flags & RECURS_GROUPS)
		(void) printf("\tRecursive Memberships allowed\n");
	if (! g->gr_flags)
		(void) printf("\n");

	(void) printf("Group Members :\n");
	for (i = 0; i < g->gr_members.gr_members_len; i++)
		(void) printf("\t%s\n",
		    nilstring(g->gr_members.gr_members_val[i]));
}

static void
print_column(int n, table_col *col)
{

	(void) printf("\t[%d]\tName          : ", n);
	(void) printf("%s\n", nilstring(col->tc_name));
	(void) printf("\t\tAttributes    : (");
	if (col->tc_flags & TA_SEARCHABLE)
		(void) printf("SEARCHABLE, ");
	if ((col->tc_flags & TA_BINARY) == 0) {
		(void) printf("TEXTUAL DATA");
		if (col->tc_flags & TA_SEARCHABLE) {
			if (col->tc_flags & TA_CASE)
				(void) printf(", CASE INSENSITIVE");
			else
				(void) printf(", CASE SENSITIVE");
		}
	} else {
		(void) printf("BINARY DATA");
		if (col->tc_flags & TA_XDR)
			(void) printf(", XDR ENCODED");
		if (col->tc_flags & TA_ASN1)
			(void) printf(", ASN.1 ENCODED");
	}
	(void) printf(")\n");
	(void) printf("\t\tAccess Rights : ");
	nis_print_rights(col->tc_rights);
	(void) printf("\n");
}

void
nis_print_table(table_obj *t)
{
	int		i;

	(void) printf("Table Type          : %s\n", nilstring(t->ta_type));
	(void) printf("Number of Columns   : %d\n", t->ta_maxcol);
	(void) printf("Character Separator : %c\n", t->ta_sep);
	(void) printf("Search Path         : %s\n", nilstring(t->ta_path));
	(void) printf("Columns             :\n");
	for (i = 0; i < t->ta_cols.ta_cols_len; i++) {
		print_column(i, &(t->ta_cols.ta_cols_val[i]));
	}
}

void
nis_print_link(link_obj	*l)
{
	int		i;
	(void) printf("Linked Object Type : ");
	switch (l->li_rtype) {
		case NIS_DIRECTORY_OBJ :
			(void) printf("DIRECTORY\n");
			break;
		case NIS_TABLE_OBJ :
			(void) printf("TABLE\n");
			break;
		case NIS_ENTRY_OBJ :
			(void) printf("ENTRY\n");
			break;
		case NIS_GROUP_OBJ :
			(void) printf("GROUP\n");
			break;
		case NIS_LINK_OBJ :
			(void) printf("LINK\n");
			break;
		case NIS_PRIVATE_OBJ :
			(void) printf("PRIVATE\n");
			break;
		default :
			(void) printf("(UNKNOWN) [%d]\n", l->li_rtype);
			break;
	}
	(void) printf("Link to : ");
	if (l->li_attrs.li_attrs_len) {
		(void) printf("[");
		for (i = 0; i < (l->li_attrs.li_attrs_len-1); i++)
			(void) printf("%s=%s, ",
			    nilstring(l->li_attrs.li_attrs_val[i].zattr_ndx),
			    nilstring(l->li_attrs.li_attrs_val[i].ZVAL));
		(void) printf("%s=%s ] ",
			nilstring(l->li_attrs.li_attrs_val[i].zattr_ndx),
			nilstring(l->li_attrs.li_attrs_val[i].ZVAL));
	}
	(void) printf("%s\n", nilstring(l->li_name));
}

void
nis_print_entry(entry_obj *edata)
{
	int		i, j;
	entry_col	*col;

	(void) printf("\tEntry data of type %s\n", nilstring(edata->en_type));
	for (i = 0, col = edata->en_cols.en_cols_val;
			i < edata->en_cols.en_cols_len; i++, col++) {
		(void) printf("\t[%d] - [%d bytes] ", i,
				col->ec_value.ec_value_len);
		if (col->ec_flags & EN_CRYPT) {
			(void) printf("Encrypted data\n");
			continue;
		}
		if (col->ec_flags & EN_XDR) {
			(void) printf("XDR'd Data\n");
			continue;
		}
		if (col->ec_flags & EN_BINARY) {
			for (j = 0; j < col->ec_value.ec_value_len; j++) {
				if (((j % 8) == 0) && (j != 0)) {
					(void) printf("\n\t      ");
				}
				(void) printf("0x%02x ",
				    (uchar_t)*(col->ec_value.ec_value_val+j));
			}
			(void) printf("\n");
			continue;
		} else {
			(void) printf("'%s'\n",
			    nilstring(col->ec_value.ec_value_val));
			continue;
		}
	}
}

#define	_dot(c)	(isprint(c) ? c : '.')

static void
nis_print_private(objdata *u)
{
	char	pbuf[80],
		buf1[5],
		buf2[20],
		buf3[20],
		buf4[20];
	uchar_t	*data;
	int	len, i, j;

	/*
	 * dump private data as a formatted dump using format :
	 * "1234: 0011223344556677 8899aabbccddeeff ................\n"
	 */
	data = (uchar_t *)(u->objdata_u.po_data.po_data_val);
	len  = u->objdata_u.po_data.po_data_len;

	for (i = 0; (i+15) < len; i += 16) {
		(void) sprintf(buf1, "%04x", (uint_t)(i));
		(void) sprintf(buf2, "%02x%02x%02x%02x%02x%02x%02x%02x",
			*(data+i), *(data+i+1), *(data+i+2), *(data+i+3),
			*(data+i+4), *(data+i+5), *(data+i+6), *(data+i+7));
		(void) sprintf(buf3, "%02x%02x%02x%02x%02x%02x%02x%02x",
			*(data+i+8), *(data+i+9), *(data+i+10), *(data+i+11),
			*(data+i+12), *(data+i+13), *(data+i+14), *(data+i+15));
		(void) sprintf(buf4, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
			_dot(*(data+i)), _dot(*(data+i+1)), _dot(*(data+i+2)),
			_dot(*(data+i+3)), _dot(*(data+i+4)),
			_dot(*(data+i+5)), _dot(*(data+i+6)), _dot(*(data+i+7)),
			_dot(*(data+i+8)), _dot(*(data+i+9)),
			_dot(*(data+i+10)), _dot(*(data+i+11)),
			_dot(*(data+i+12)), _dot(*(data+i+13)),
			_dot(*(data+i+14)), _dot(*(data+i+15)));
		(void) printf("\t%s: %s %s %s\n", buf1, buf2, buf3, buf4);
	}
	if (i < len) {
		(void) sprintf(pbuf, "%04x: ", (uint_t)(i));
		buf4[0] = '\0';
		for (j = 0; j < 16; j++) {
			if (i+j < len) {
				(void) sprintf(buf3, "%02x", *(data+i+j));
				(void) strcat(pbuf, buf3);
				if (j == 7)
					(void) strcat(pbuf, " ");
				(void) sprintf(buf3, "%c", _dot(*(data+i+j)));
				(void) strcat(buf4, buf3);
			} else {
				(void) strcat(pbuf, "  ");
				if (j == 8)
					(void) strcat(pbuf, " ");
			}

		}
		(void) printf("\t%s %s\n", pbuf, buf4);
	}
}

void
nis_print_object(nis_object *o)
{

	/*
	 * Temporary p_time introduced for the LP64 world since int and
	 * long are not the same size, and time_t is a long.
	 */

	time_t p_time;
	char   buf[CTBSIZE];

	(void) printf("Object Name   : \"%s\"\n", nilstring(o->zo_name));
	(void) printf("Directory     : \"%s\"\n", nilstring(o->zo_domain));
	(void) printf("Owner         : \"%s\"\n", nilstring(o->zo_owner));
	(void) printf("Group	      : \"%s\"\n", nilstring(o->zo_group));
	(void) printf("Access Rights : ");
	nis_print_rights(o->zo_access);
	(void) printf("\n");
	(void) printf("Time to Live  : %d:%d:%d\n", o->zo_ttl/3600,
			(o->zo_ttl - (o->zo_ttl/3600)*3600)/60,
			(o->zo_ttl % 60));
	p_time = (time_t)o->zo_oid.ctime;
	(void) printf("Creation Time : %s", ctime_r(&p_time, buf, CTBSIZE));
	p_time = (time_t)o->zo_oid.mtime;
	(void) printf("Mod. Time     : %s", ctime_r(&p_time, buf, CTBSIZE));
	(void) printf("Object Type   : ");
	switch (__type_of(o)) {
		case NIS_NO_OBJ :
			(void) printf("NONE\n");
			break;
		case NIS_DIRECTORY_OBJ :
			(void) printf("DIRECTORY\n");
			nis_print_directory(&(o->DI_data));
			break;
		case NIS_TABLE_OBJ :
			(void) printf("TABLE\n");
			nis_print_table(&(o->TA_data));
			break;
		case NIS_ENTRY_OBJ :
			(void) printf("ENTRY\n");
			nis_print_entry(&(o->EN_data));
			break;
		case NIS_GROUP_OBJ :
			(void) printf("GROUP\n");
			nis_print_group(&(o->GR_data));
			break;
		case NIS_LINK_OBJ :
			(void) printf("LINK\n");
			nis_print_link(&(o->LI_data));
			break;
		case NIS_PRIVATE_OBJ :
			(void) printf("PRIVATE\n");
			nis_print_private(&(o->zo_data));
			break;
		default :
			(void) printf("(UNKNOWN) [%d]\n", __type_of(o));
			break;
	}
}

void
nis_print_bound_endpoint(nis_bound_endpoint *bep)
{
	(void) printf("\tgeneration = %d\n", bep->generation);
	(void) printf("\tendpoint = (%s, %s, %s)\n",
			nilstring(bep->ep.family),
			nilstring(bep->ep.proto),
			nilstring(bep->ep.uaddr));
	(void) printf("\trank       = %d\n", bep->rank);
	(void) printf("\tflags       = 0x%x\n", bep->flags);
	(void) printf("\thost num   = %d\n", bep->hostnum);
	(void) printf("\tendpoint num = %d\n", bep->epnum);
	(void) printf("\tserver addr = %s\n", nilstring(bep->uaddr));
	(void) printf("\tcallback addr = (%s, %s, %s)\n",
			nilstring(bep->cbep.family),
			nilstring(bep->cbep.proto),
			nilstring(bep->cbep.uaddr));
}

void
nis_print_binding(nis_bound_directory *binding)
{
	int i;

	(void) printf("Directory Name : %s\n",
	    nilstring(binding->dobj.do_name));
	(void) printf("Generation     : %d\n", binding->generation);
	(void) printf("Directory Object:\n");
	nis_print_directory(&binding->dobj);
	(void) printf("Bound Endpoints:\n");
	for (i = 0; i < binding->bep_len; i++)
		nis_print_bound_endpoint(&binding->bep_val[i]);
}
