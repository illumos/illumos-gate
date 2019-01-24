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

#include <sys/sysinfo.h>
#include <sys/nvpair.h>
#include <sys/nvpair_impl.h>

#include <ctype.h>
#include <mdb/mdb_modapi.h>

#include "nvpair.h"

#define	NVPAIR_VALUE_INDENT	4
#define	NELEM(a)		(sizeof (a) / sizeof ((a)[0]))

/*
 * nvpair walker
 */
int
nvpair_walk_init(mdb_walk_state_t *wsp)
{
	nvlist_t nvlist;
	nvpriv_t nvpriv;
	i_nvp_t *tmp;

	if (wsp->walk_addr == 0) {
		mdb_warn("nvpair does not support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&nvlist, sizeof (nvlist), wsp->walk_addr) == -1) {
		mdb_warn("failed to read nvlist at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_vread(&nvpriv, sizeof (nvpriv), nvlist.nvl_priv) == -1) {
		mdb_warn("failed to read nvpriv at %p", nvlist.nvl_priv);
		return (WALK_ERR);
	}

	tmp = (i_nvp_t *)nvpriv.nvp_list;
	wsp->walk_addr = (uintptr_t)tmp;
	return (WALK_NEXT);
}

int
nvpair_walk_step(mdb_walk_state_t *wsp)
{
	int	status;
	nvpair_t *nvpair;
	i_nvp_t i_nvp, *tmp;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&i_nvp, sizeof (i_nvp), wsp->walk_addr) == -1) {
		mdb_warn("failed to read i_nvp at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	nvpair = &((i_nvp_t *)wsp->walk_addr)->nvi_nvp;
	status = wsp->walk_callback((uintptr_t)nvpair, NULL, wsp->walk_cbdata);

	tmp = i_nvp.nvi_next;
	wsp->walk_addr = (uintptr_t)tmp;
	return (status);
}

/*
 * ::nvlist [-v]
 *
 * Print out an entire nvlist.  This is shorthand for '::walk nvpair |
 * ::nvpair -rq'.  The '-v' option invokes '::nvpair' without the "-q" option.
 */
/*ARGSUSED*/
int
print_nvlist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int verbose = B_FALSE;
	mdb_arg_t v;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	v.a_type = MDB_TYPE_STRING;
	if (verbose)
		v.a_un.a_str = "-r";
	else
		v.a_un.a_str = "-rq";

	return (mdb_pwalk_dcmd("nvpair", "nvpair", 1, &v, addr));
}

/*
 * ::nvpair [-rq]
 *
 *	-r	Recursively print any nvlist elements
 *	-q	Quiet mode; print members only as "name=value"
 *
 * Prints out a single nvpair.  By default, all information is printed.  When
 * given the '-q' option, the type of elements is hidden, and elements are
 * instead printed simply as 'name=value'.
 */
typedef struct {
	data_type_t	type;
	int		elem_size;
	char		*type_name;
} nvpair_info_t;

nvpair_info_t nvpair_info[] =  {
	{ DATA_TYPE_BOOLEAN,		1, "boolean" },
	{ DATA_TYPE_BOOLEAN_VALUE,	4, "boolean_value" },
	{ DATA_TYPE_BYTE,		1, "byte" },
	{ DATA_TYPE_INT8,		1, "int8" },
	{ DATA_TYPE_UINT8,		1, "uint8" },
	{ DATA_TYPE_INT16,		2, "int16" },
	{ DATA_TYPE_UINT16,		2, "uint16" },
	{ DATA_TYPE_INT32,		4, "int32" },
	{ DATA_TYPE_UINT32,		4, "uint32" },
	{ DATA_TYPE_INT64,		8, "int64" },
	{ DATA_TYPE_UINT64,		8, "uint64" },
	{ DATA_TYPE_STRING,		0, "string" },
	{ DATA_TYPE_NVLIST,		0, "nvpair_list" },
	{ DATA_TYPE_HRTIME,		8, "hrtime" },
	{ DATA_TYPE_BOOLEAN_ARRAY,	4, "boolean_array" },
	{ DATA_TYPE_BYTE_ARRAY,		1, "byte_array" },
	{ DATA_TYPE_INT8_ARRAY,		1, "int8_array" },
	{ DATA_TYPE_UINT8_ARRAY,	1, "uint8_array" },
	{ DATA_TYPE_INT16_ARRAY,	2, "int16_array" },
	{ DATA_TYPE_UINT16_ARRAY,	2, "uint16_array" },
	{ DATA_TYPE_INT32_ARRAY,	4, "int32_array" },
	{ DATA_TYPE_UINT32_ARRAY,	4, "uint32_array" },
	{ DATA_TYPE_INT64_ARRAY,	8, "int64_array" },
	{ DATA_TYPE_UINT64_ARRAY,	8, "uint64_array" },
	{ DATA_TYPE_STRING_ARRAY,	0, "string_array" },
	{ DATA_TYPE_NVLIST_ARRAY,	0, "nvpair list_array" }
};

static void
nvpair_print_value(char *data, int32_t elem_size, int32_t nelem,
    data_type_t type)
{
	int32_t i;

	if (elem_size == 0) {
		char *p = data;

		/* print out all the strings */
		for (i = 0; i < nelem - 1; i++) {
			mdb_printf("'%s' + ", p);
			p += strlen(p) + 1;
		}
		mdb_printf("'%s'", p);
	} else if (type == DATA_TYPE_BOOLEAN_VALUE ||
	    type == DATA_TYPE_BOOLEAN_ARRAY) {
		/* LINTED - pointer alignment */
		boolean_t *p = (boolean_t *)data;

		for (i = 0; i < nelem; i++) {
			if (i > 0)
				mdb_printf(".");
			mdb_printf("%d", p[i]);
		}
	} else {
		unsigned char	*p = (unsigned char *)data;
		int		size = elem_size * nelem;

		/*
		 * if elem_size != 0 then we are printing out an array
		 * where each element is of elem_size
		 */
		mdb_nhconvert(p, p, elem_size);
		mdb_printf("%02x", *p);
		for (i = 1; i < size; i++) {
			if ((i % elem_size) == 0) {
				mdb_nhconvert(&p[i], &p[i], elem_size);
				mdb_printf(".");
			}
			mdb_printf("%02x", p[i]);
		}
	}
	mdb_printf("\n");
}

/*ARGSUSED*/
int
nvpair_print(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nvpair_t	nvpair_tmp, *nvpair;
	int32_t		i, size, nelem, elem_size = 0;
	char		*data = NULL, *data_end = NULL;
	char		*type_name = NULL;
	data_type_t	type = DATA_TYPE_UNKNOWN;
	int		quiet = FALSE;
	int		recurse = FALSE;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'r', MDB_OPT_SETBITS, TRUE, &recurse,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    NULL) != argc)
		return (DCMD_USAGE);

	/* read in the nvpair header so we can get the size */
	if (mdb_vread(&nvpair_tmp, sizeof (nvpair), addr) == -1) {
		mdb_warn("failed to read nvpair at %p", addr);
		return (DCMD_ERR);
	}
	size = NVP_SIZE(&nvpair_tmp);
	if (size == 0) {
		mdb_warn("nvpair of size zero at %p", addr);
		return (DCMD_OK);
	}

	/* read in the entire nvpair */
	nvpair = mdb_alloc(size, UM_SLEEP | UM_GC);
	if (mdb_vread(nvpair, size, addr) == -1) {
		mdb_warn("failed to read nvpair and data at %p", addr);
		return (DCMD_ERR);
	}

	/* lookup type decoding information for this nvpair */
	type = NVP_TYPE(nvpair);
	nelem = NVP_NELEM(nvpair);
	for (i = 0; i < NELEM(nvpair_info); i++) {
		if (nvpair_info[i].type == type) {
			elem_size = nvpair_info[i].elem_size;
			type_name = nvpair_info[i].type_name;
			break;
		}
	}

	if (quiet) {
		mdb_printf("%s", NVP_NAME(nvpair));
	} else {
		/* print out the first line of nvpair info */
		mdb_printf("name='%s'", NVP_NAME(nvpair));
		if (type_name != NULL) {
			mdb_printf(" type=%s", type_name);
		} else {
			/*
			 * If the nvpair type is unknown we print the type
			 * number
			 */
			mdb_printf(" type=0x%x", type);
		}
		mdb_printf(" items=%d\n", nelem);
	}

	/* if there is no data and the type is known then we're done */
	if ((nelem == 0) && (type_name != NULL)) {
		if (quiet)
			mdb_printf("(unknown)\n");
		return (DCMD_OK);
	}

	/* get pointers to the data to print out */
	data = (char *)NVP_VALUE(nvpair);
	data_end = (char *)nvpair + NVP_SIZE(nvpair);

	/*
	 * The value of the name-value pair for a single embedded
	 * list is the nvlist_t structure for the embedded list.
	 * So we print that address out (computed as an offset from
	 * the nvpair address we received as addr).
	 *
	 * The value of the name-value pair for an array of embedded
	 * lists is nelem pointers to nvlist_t structures followed
	 * by the structures themselves.  We display the list
	 * of pointers as the pair's value.
	 */
	if (type == DATA_TYPE_NVLIST) {
		char *p = (char *)addr + (data - (char *)nvpair);
		if (recurse) {
			if (quiet)
				mdb_printf("\n");
			mdb_inc_indent(NVPAIR_VALUE_INDENT);
			if (mdb_pwalk_dcmd("nvpair", "nvpair", argc, argv,
			    (uintptr_t)p) != DCMD_OK)
				return (DCMD_ERR);
			mdb_dec_indent(NVPAIR_VALUE_INDENT);
		} else {
			if (!quiet) {
				mdb_inc_indent(NVPAIR_VALUE_INDENT);
				mdb_printf("value", p);
			}
			mdb_printf("=%p\n", p);
			if (!quiet)
				mdb_dec_indent(NVPAIR_VALUE_INDENT);
		}
		return (DCMD_OK);

	} else if (type == DATA_TYPE_NVLIST_ARRAY) {
		if (recurse) {
			for (i = 0; i < nelem; i++,
			    data += sizeof (nvlist_t *)) {
				nvlist_t **nl = (nvlist_t **)(void *)data;
				if (quiet && i != 0)
					mdb_printf("%s", NVP_NAME(nvpair));
				mdb_printf("[%d]\n", i);
				mdb_inc_indent(NVPAIR_VALUE_INDENT);
				if (mdb_pwalk_dcmd("nvpair", "nvpair", argc,
				    argv, (uintptr_t)*nl) != DCMD_OK)
					return (DCMD_ERR);
				mdb_dec_indent(NVPAIR_VALUE_INDENT);
			}
		} else {
			if (!quiet) {
				mdb_inc_indent(NVPAIR_VALUE_INDENT);
				mdb_printf("value");
			}
			mdb_printf("=");
			for (i = 0; i < nelem; i++,
			    data += sizeof (nvlist_t *)) {
				nvlist_t **nl = (nvlist_t **)(void *)data;
				mdb_printf("%c%p", " "[i == 0], *nl);
			}
			mdb_printf("\n");
			if (!quiet)
				mdb_dec_indent(NVPAIR_VALUE_INDENT);
		}
		return (DCMD_OK);
	}

	/* if it's a string array, skip the index pointers */
	if (type == DATA_TYPE_STRING_ARRAY)
		data += (sizeof (int64_t) * nelem);

	/* if the type is unknown, treat the data as a byte array */
	if (type_name == NULL) {
		elem_size = 1;
		nelem = data_end - data;
	}

	/*
	 * if the type is of strings, make sure they are printable
	 * otherwise print them out as byte arrays
	 */
	if (elem_size == 0) {
		int32_t	count = 0;

		i = 0;
		while ((&data[i] < data_end) && (count < nelem)) {
			if (data[i] == '\0')
				count++;
			else if (!isprint(data[i]))
				break;
			i++;
		}
		if (count != nelem) {
			/* there is unprintable data, output as byte array */
			elem_size = 1;
			nelem =  data_end - data;
		}
	}

	if (!quiet) {
		mdb_inc_indent(NVPAIR_VALUE_INDENT);
		mdb_printf("value=");
	} else {
		mdb_printf("=");
	}
	nvpair_print_value(data, elem_size, nelem, type);
	if (!quiet)
		mdb_dec_indent(NVPAIR_VALUE_INDENT);

	return (DCMD_OK);
}
