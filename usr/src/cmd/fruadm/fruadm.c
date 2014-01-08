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
 * Copyright (c) 2014 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <libfru.h>
#include <errno.h>
#include <math.h>
#include <alloca.h>
#include <assert.h>
#include <sys/systeminfo.h>

#define	NUM_OF_SEGMENT	1
#define	SEGMENT_NAME_SIZE	2

#define	FD_SEGMENT_SIZE	2949

static char  *command, *customer_data = NULL, *frupath = NULL, **svcargv;

/* DataElement supported in the customer operation */
static  char    *cust_data_list[] = {"Customer_DataR"};

/* DataElement supported in the service operation */
static  char    *serv_data_list[] = {"InstallationR", "ECO_CurrentR"};

/* currently supported segment name */
static  char    *segment_name[] = {"FD"};

static int   found_frupath = 0, list_only = 0, recursive = 0,
    service_mode = 0, svcargc, update = 0;


static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("Usage:  %s [ -l ] | [ [ -r ] frupath [ text ] ]\n"),
	    command);
}

static int
validate_fieldnames(int argc, char *argv[])
{
	static int	num = sizeof (serv_data_list)/sizeof (*serv_data_list);

	char		*fieldname;

	int		i, j, match, status;

	fru_elemdef_t	definition;


	for (i = 0; i < argc; i += 2) {
		if (argv[i][0] == '/') {
			fieldname = &argv[i][1];
		} else {
			fieldname = &argv[i][0];
		}

		match = 0;
		for (j = 0; j < num; j++) {
			if (strncmp(fieldname, serv_data_list[j],
			    strlen(serv_data_list[j])) == 0) {
				match = 1;
			}
		}
		if (!match) {
			(void) fprintf(stderr,
			    gettext("\"%s\" is not a supported field\n"),
			    argv[i]);
			return (1);
		}

		if ((status = fru_get_definition(argv[i], &definition))
		    != FRU_SUCCESS) {
			(void) fprintf(stderr, gettext("\"%s\":  %s\n"),
			    argv[i],
			    fru_strerror(status));
			return (1);
		} else if ((definition.data_type == FDTYPE_Record) ||
		    (definition.data_type == FDTYPE_UNDEFINED)) {
			(void) fprintf(stderr,
			    gettext("\"%s\" is not a field\n"), argv[i]);
			return (1);
		}
	}

	return (0);
}

static int
pathmatch(const char *path)
{
	char  *match;

	if ((frupath != NULL) &&
	    ((match = strstr(path, frupath)) != NULL) &&
	    ((match + strlen(frupath)) == (path + strlen(path))) &&
	    ((match == path) || (*(match - 1) == '/'))) {
		found_frupath = 1;
		return (1);
	}
	return (0);
}

static void
displayBinary(unsigned char *data, size_t length, fru_elemdef_t *def)
{
	int	i = 0;
	uint64_t	lldata;
	uint64_t	mask;

	if (def->disp_type == FDISP_Hex) {
		for (i = 0; i < length; i++) {
			(void) printf("%02X", data[i]);
		}
		return;
	}

	(void) memcpy(&lldata, data, sizeof (lldata));
	switch (def->disp_type) {
		case FDISP_Binary:
		{
			mask = 0x8000000000000000ULL;
			for (i = 0; i < (sizeof (uint64_t) *8); i++) {
				if (lldata & (mask >> i)) {
					(void) printf("1");
				} else {
					(void) printf("0");
				}
			}
			return;
		}
		case FDISP_Octal:
		{
			(void) printf("%llo", lldata);
			return;
		}
		case FDISP_Decimal:
		{
			(void) printf("%lld", lldata);
			return;
		}
		case FDISP_Time:
		{
			char buffer[PATH_MAX];
			time_t time;
			time = (time_t)lldata;
			(void) strftime(buffer, PATH_MAX, "%+",
			    localtime(&time));
			(void) printf("%s", buffer);
			return;
		}
	}
}

static void
displayBAasBinary(unsigned char *data, size_t length)
{
	int i;
	unsigned char mask;

	for (i = 0; i < length; i++) {
		/*
		 * make a mask for the high order bit and adjust down through
		 * all the bits.
		 */
		for (mask = 0x80; mask > 0; mask /= 2) {
			if ((data[i] & mask) != 0) /* bit must be on */
				(void) printf("1");
			else /* bit is off... */
				(void) printf("0");
		}
	}
	(void) printf("\n");
}

static void
display_data(unsigned char *data, size_t length, fru_elemdef_t *def)
{
	int i = 0;
	uint64_t	lldata;

	if (data == 0x00) {
		(void) printf("\n");
		return;
	}

	switch (def->data_type) {
	case FDTYPE_Binary:
	{
		displayBinary(data, length, def);
		return;
	}

	case FDTYPE_ByteArray:
	{
		switch (def->disp_type) {
		case FDISP_Binary:
			displayBAasBinary(data, length);
			return;
		case FDISP_Hex:
			for (i = 0; i < length; i++) {
				(void) printf("%02X", data[i]);
			}
			return;
		}
		return;
	}
	case FDTYPE_Unicode:
		assert(gettext("Unicode not yet supported") == 0);
		break;
	case FDTYPE_ASCII:
	{
		char *disp_str = (char *)alloca(length+1);
		for (i = 0; i < length; i++)
			disp_str[i] = data[i];
			disp_str[i] = '\0';
			(void) printf("%s", disp_str);
			return;
	}

	case FDTYPE_Enumeration:
	{
		lldata = strtoull((const char *)data, NULL, 0);
		for (i = 0; i < def->enum_count; i++) {
			if (def->enum_table[i].value == lldata) {
			/* strdup such that map_... can realloc if necessary. */
				char *tmp = strdup(def->enum_table[i].text);
				(void) printf("%s", tmp);
				free(tmp);
				return;
			}
		}
		(void) printf(gettext("Unrecognized Value:  0x"));
		for (i = 0; i < sizeof (uint64_t); i++)
			(void) printf("%02X", data[i]);
		break;
	}
	default:
		break;
	}
}

static void
print_node_data(fru_nodehdl_t cont_hdl)
{
	int	iter_cnt = 0;
	int	iter;
	int	numseg;
	int	list_cnt;
	unsigned char	*data;
	size_t	dataLen;
	int	total_cnt;
	char	*found_path = NULL;
	fru_elemdef_t	 def, def1;
	int	instance = 0;
	char	**ptr;
	char	**tmp_ptr;
	int	count = 0;
	char	elem_name[PATH_MAX];

	if (service_mode) {
		total_cnt = sizeof (serv_data_list)/sizeof (*serv_data_list);
		ptr = serv_data_list;
	} else {
		total_cnt = sizeof (cust_data_list)/sizeof (*cust_data_list);
		ptr = cust_data_list;
	}
	tmp_ptr = ptr;

	for (numseg = 0; numseg < NUM_OF_SEGMENT; numseg++) {
		ptr = tmp_ptr;
		for (list_cnt = 0; list_cnt < total_cnt; list_cnt++) {
			if ((fru_get_definition(*ptr, &def)) != FRU_SUCCESS) {
				continue;
			}
			if ((fru_get_num_iterations(cont_hdl,
			    &segment_name[numseg], 0, *ptr,
			    &iter_cnt, NULL)) != FRU_SUCCESS) {
				iter_cnt = 0;
			}
			iter = 0;
			do {
				for (count = 0; count < def.enum_count;
				    count++) {
					if (def.iteration_type !=
					    FRU_NOT_ITERATED) {
						(void) snprintf(elem_name,
						    sizeof (elem_name),
			"/%s[%d]/%s", *ptr, iter, def.enum_table[count].text);
					} else {
						(void) snprintf(elem_name,
						    sizeof (elem_name),
			"/%s/%s", *ptr, def.enum_table[count].text);
					}

					if ((fru_read_field(cont_hdl,
					    &segment_name[numseg], instance,
					    elem_name, (void**)&data, &dataLen,
					    &found_path)) != FRU_SUCCESS) {
						break;
					}

					if ((fru_get_definition(
			def.enum_table[count].text, &def1)) != FRU_SUCCESS) {
						break;
					}
					(void) printf("	%s:  ",\
					    elem_name);
					display_data(data, dataLen, &def1);
					(void) printf("\n");
				}
				iter ++;
			} while (iter < iter_cnt);
			ptr++;
		}
	}
}

static char *
convertBinaryToDecimal(char *ptr)
{
	int	cnt = 0;
	char	*data;
	int	str_len;
	char	*ret = NULL;
	uint64_t	result = 0;

	str_len = strlen(ptr);
	data = ptr;

	while (str_len >= 1) {
		str_len -= 1;
		if (data[str_len] == '0') {
			result += (0 * pow(2, cnt));
		}
		if (data[str_len] == '1') {
			result += (1 * pow(2, cnt));
		}
		cnt++;
	}
	ret = (char *)lltostr(result, "\n");
	return (ret);
}

/*
 * called update_field() to update the field with specific field value.
 * nodehdl represents the fru, segment represents the segment name in the fru.
 * field_name represents the field to be updated with the value field_value.
 */

static int
convert_update(fru_nodehdl_t nodehdl, char *segment, char *field_name,
							char *field_value)
{
	uint64_t num = 0;
	fru_elemdef_t def;
	fru_errno_t	err;
	void    *data = NULL;
	size_t  dataLen = 0;
	int	i;

	if ((err = fru_get_definition(field_name, &def)) != FRU_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Failed to get definition %s:  %s\n"),
		    field_name, fru_strerror(err));
		return (1);
	}

	if (field_value == NULL) {
		return (1);
	}

	switch (def.data_type) {
		case    FDTYPE_Binary:
			if (def.disp_type != FDISP_Time) {
				if (field_value[0] == 'b') {
					field_value =
					    convertBinaryToDecimal((field_value
					    +1));
				}
				num = strtoll(field_value, (char **)NULL, 0);
				if ((num == 0) && (errno == 0)) {
					return (1);
				}
				data = (void*)&num;
				dataLen = sizeof (uint64_t);
			}
			break;
		case    FDTYPE_ByteArray:
			return (1);
		case    FDTYPE_Unicode:
			return (1);
		case    FDTYPE_ASCII:
			data = (void *) field_value;
			dataLen = strlen(field_value);
			if (dataLen < def.data_length) {
				dataLen++;
			}
			break;
		case    FDTYPE_Enumeration:
			for (i = 0; i < def.enum_count; i++) {
				if (strcmp(def.enum_table[i].text,
				    field_value) == 0) {
					data = (void *)(uintptr_t)
					    def.enum_table[i].value;
					dataLen = sizeof (uint64_t);
					break;
				}
			}
			return (1);
		case    FDTYPE_Record:
			if (def.iteration_count == 0) {
				return (1);
			}
			data = NULL;
			dataLen = 0;
			break;
		case    FDTYPE_UNDEFINED:
			return (1);
	}

	if ((err = fru_update_field(nodehdl, segment, 0, field_name, data,
	    dataLen)) != FRU_SUCCESS) {
		(void) fprintf(stderr, gettext("fru_update_field():  %s\n"),
		    fru_strerror(err));
		return (1);
	}
	return (0);
}
/*
 * called by update_field() when a new data element is created.
 * it updates the UNIX_Timestamp32 field with the current system time.
 */

static int
update_unixtimestamp(fru_nodehdl_t nodehdl, char *segment, char **ptr)
{
	char	*field_name;
	time_t	clock;
	struct	tm *sp_tm;
	fru_errno_t	err = FRU_SUCCESS;
	uint64_t	time_data;
	size_t		len;

	len = strlen(*ptr) + strlen("UNIX_Timestamp32") + 3;
	field_name = alloca(len);

	(void) snprintf(field_name, len, "/%s/UNIX_Timestamp32", *ptr);

	clock = time(NULL);
	sp_tm = localtime(&clock);
	time_data = (uint64_t)mktime(sp_tm);

	if ((err = fru_update_field(nodehdl, segment, 0, field_name,
	    (void *)&time_data, sizeof (time_data))) != FRU_SUCCESS) {
		(void) fprintf(stderr, gettext("fru_update_field():  %s\n"),
		    fru_strerror(err));
		return (1);
	}
	return (0);
}

/*
 * create segment on the specified fru represented by nodehdl.
 */

static int
create_segment(fru_nodehdl_t nodehdl)
{
	fru_segdesc_t	seg_desc;
	fru_segdef_t	def;
	int	cnt;
	int	status;

	(void) memset(&seg_desc, 0, sizeof (seg_desc));
	seg_desc.field.field_perm = 0x6;
	seg_desc.field.operations_perm = 0x6;
	seg_desc.field.engineering_perm = 0x6;
	seg_desc.field.repair_perm = 0x6;

	(void) memset(&def, 0, sizeof (def));
	def.address = 0;
	def.desc.raw_data = seg_desc.raw_data;
	def.hw_desc.all_bits = 0;

	for (cnt = 0; cnt < NUM_OF_SEGMENT; cnt++) {
		(void) strncpy(def.name, segment_name[cnt], SEGMENT_NAME_SIZE);
		if (cnt == 0) {
			def.size = FD_SEGMENT_SIZE;
		}
		if ((status = fru_create_segment(nodehdl, &def))
		    != FRU_SUCCESS) {
			continue;
		}
		return (cnt);
	}
	if (status != FRU_SUCCESS)
		(void) fprintf(stderr, gettext("fru_create_segment():  %s\n"),
		    fru_strerror(status));
	return (1);
}

/*
 * called from update_field() when service flag is ON. currently
 * supported iterated record is InstallationR and fields supported for
 * update are Geo_North, Geo_East, Geo_Alt, Geo_Location.
 */

static int
updateiter_record(fru_nodehdl_t nodehdl, int cnt, char **ptr,
			char *field_name, char  *field_value)
{
	int	iter_cnt  = 0;
	char	rec_name[512];
	void	*data = NULL;
	char	*tmpptr = NULL;
	size_t	dataLen = 0;
	char	**elem_ptr;
	int	found = 0;
	int	index;
	int	total_cnt;
	fru_errno_t	err;

	static  char    *elem_list[] = {"/Geo_North", "/Geo_East",\
				"/Geo_Alt", "/Geo_Location"};

	elem_ptr = elem_list;
	total_cnt = sizeof (elem_list)/sizeof (*elem_list);

	for (index = 0; index < total_cnt; index++) {
		tmpptr = strrchr(field_name, '/');
		if (tmpptr == NULL) {
			(void) fprintf(stderr,
			    gettext("Error:  Data Element not known\n"));
			return (1);
		}
		if ((strncmp(*elem_ptr, tmpptr, strlen(*elem_ptr)) != 0)) {
			elem_ptr++;
			continue;
		}
		found = 1;
		break;
	}

	if (found == 0) {
		(void) fprintf(stderr,
		    gettext("Error:  Update not allowed for field:  %s\n"),
		    field_name);
		return (1);
	}

	if ((fru_get_num_iterations(nodehdl, &segment_name[cnt], 0,
	    *ptr, &iter_cnt, NULL)) != FRU_SUCCESS) {
		return (1);
	}

	/* add a new Iterated Record if complete path is not given */
	if (iter_cnt == 0) {
		(void) snprintf(rec_name, sizeof (rec_name), "/%s[+]", *ptr);
		if ((err = fru_update_field(nodehdl, segment_name[cnt], 0,
		    rec_name, data, dataLen)) != FRU_SUCCESS) {
			(void) fprintf(stderr,
			gettext("fru_update_field():  %s\n"),
			    fru_strerror(err));
		return (1);
		}

		iter_cnt = 1;
	}

	(void) snprintf(rec_name, sizeof (rec_name), "/%s[%d]%s",
	    *ptr, iter_cnt-1, strrchr(field_name, '/'));

	if ((convert_update(nodehdl, segment_name[cnt], rec_name,
	    field_value)) != 0) {
		return (1);
	}

	/* update success  now update the unix timestamp */

	(void) snprintf(rec_name, sizeof (rec_name), "/%s[%d]",
	    *ptr, iter_cnt-1);
	tmpptr = rec_name;

	/* update UNIX_Timestamp32 with creation time */
	if ((update_unixtimestamp(nodehdl, segment_name[cnt],
	    &tmpptr)) != 0) {
		return (1);
	}

	return (0);
}

static int
update_field(fru_nodehdl_t nodehdl, char *field_name, char *field_value)
{
	fru_elemdef_t	def;
	unsigned char	*data;
	size_t	dataLen;
	char	*found_path = NULL;
	int	cnt;
	char	**ptr;
	fru_strlist_t	elem;
	int	elem_cnt;
	int	add_flag = 1;
	int	total_cnt;
	int	status;

	if (service_mode) {
		ptr = serv_data_list;
		total_cnt = sizeof (serv_data_list)/sizeof (*serv_data_list);

		for (cnt = 0; cnt < total_cnt; cnt++) {
			if ((strncmp(*ptr, &field_name[1], strlen(*ptr)) \
			    != 0) && (strncmp(*ptr, &field_name[0],
			    strlen(*ptr)) != 0)) {
				ptr++;
				add_flag = 0;
				continue;
			}
			add_flag = 1;
			break;
		}
	} else {
		ptr = cust_data_list;
	}

	/* look for the field in either of the segment if found update it */
	for (cnt = 0; cnt < NUM_OF_SEGMENT; cnt++) {
		if ((fru_read_field(nodehdl, &segment_name[cnt], 0, field_name,
		    (void **) &data, &dataLen, &found_path)) != FRU_SUCCESS) {
			continue;
		}
		if ((fru_get_definition(*ptr, &def)) == FRU_SUCCESS) {
			if (def.iteration_count != 0) {
				if ((updateiter_record(nodehdl, cnt, ptr,
				    field_name, field_value)) != 0) {
					return (1);
				}
				return (0);
			}
		}

		if ((convert_update(nodehdl, segment_name[cnt],
		    field_name, field_value)) != 0) {
			return (1);
		}

		/* update UNIX_Timestamp32 with update time */
		if ((update_unixtimestamp(nodehdl, segment_name[cnt],
		    ptr)) != 0) {
			return (1);
		}
		return (0);
	}

	elem.num = 0;

	/* field not found add the the record in one of the segment */
	for (cnt = 0; cnt < NUM_OF_SEGMENT; cnt++) {
		(void) fru_list_elems_in(nodehdl, segment_name[cnt], &elem);
		for (elem_cnt = 0; elem_cnt < elem.num; elem_cnt++) {
			if ((strcmp(*ptr, elem.strs[elem_cnt])) == 0) {
				add_flag = 0;
			}
		}

		if (add_flag) {
			if ((fru_add_element(nodehdl, segment_name[cnt],
			    *ptr)) != FRU_SUCCESS) {
				continue;
			}
		}

		if ((fru_get_definition(*ptr, &def)) == FRU_SUCCESS) {
			if (def.iteration_count != 0) {
				if ((updateiter_record(nodehdl, cnt, ptr,
				    field_name, field_value)) != 0) {
					return (1);
				}
				return (0);
			}
		}

		/* update UNIX_Timestamp32 with creation time */
		if ((update_unixtimestamp(nodehdl, segment_name[cnt],
		    ptr)) != 0) {
			return (1);
		}

		/* record added update the field with the value */
		if ((convert_update(nodehdl, segment_name[cnt], field_name,
		    field_value)) != 0) {
			return (1);
		}
		return (0);
	}

	/* segment not present, create one and add the record */
	cnt = create_segment(nodehdl);
	if (cnt == 1) {
		return (1);
	}

	if ((status = fru_add_element(nodehdl, segment_name[cnt], *ptr))
	    != FRU_SUCCESS) {
		(void) fprintf(stderr, gettext("fru_add_element():  %s\n"),
		    fru_strerror(status));
		return (1);
	}

	if ((fru_get_definition(*ptr, &def)) == FRU_SUCCESS) {
		if (def.iteration_count != 0) {
			if ((updateiter_record(nodehdl,  cnt, ptr,
			    field_name, field_value)) != 0) {
				return (1);
			}
			return (0);
		}
	}

	/* update UNIX_Timestamp32 with creation time */
	if ((update_unixtimestamp(nodehdl, segment_name[cnt],
	    ptr)) != 0) {
		return (1);
	}

	if ((convert_update(nodehdl, segment_name[cnt], field_name,
	    field_value)) != 0) {
		return (1);
	}
	return (0);
}

static int
update_node_data(fru_nodehdl_t node)
{
	int	i;
	int	status = 0;

	if (service_mode) {
		for (i = 0; i < svcargc; i += 2)
			if (update_field(node, svcargv[i], svcargv[i + 1])) {
				status = 1;
			}
	} else {
		status = update_field(node, "/Customer_DataR/Cust_Data",
		    customer_data);
	}
	return (status);
}

static void
walk_tree(fru_nodehdl_t node, const char *prior_path, int process_tree)
{
	char	*name, path[PATH_MAX];
	int	process_self = process_tree, status, update_status = 0;
	fru_nodehdl_t	 next_node;
	fru_node_t	type;

	if ((status = fru_get_node_type(node, &type)) != FRU_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Error getting FRU tree node type:  %s\n"),
		    fru_strerror(status));
		exit(1);
	}

	if ((status = fru_get_name_from_hdl(node, &name)) != FRU_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Error getting name of FRU tree node:  %s\n"),
		    fru_strerror(status));
		exit(1);
	}


	/*
	 * Build the current path
	 */
	if (snprintf(path, sizeof (path), "%s/%s", prior_path, name)
	    >= sizeof (path)) {
		(void) fprintf(stderr,
		    gettext("FRU tree path would overflow buffer\n"));
		exit(1);
	}

	free(name);

	/*
	 * Process the node
	 */
	if (list_only) {
		(void) printf("%s%s\n", path, ((type == FRU_NODE_FRU) ?
		    " (fru)" : ((type == FRU_NODE_CONTAINER) ?
		    " (container)" : "")));
	} else if ((process_tree || (process_self = pathmatch(path))) &&
	    (type == FRU_NODE_CONTAINER)) {
		(void) printf("%s\n", path);
		if (update) {
			status = update_node_data(node);
			update_status = status;
		}
		print_node_data(node);
		if (!recursive) {
			exit(status);
		}
	} else if (process_self && !recursive) {
		(void) fprintf(stderr,
		    gettext("\"%s\" is not a container\n"), path);
		exit(1);
	}


	/*
	 * Recurse
	 */
	if (fru_get_child(node, &next_node) == FRU_SUCCESS)
		walk_tree(next_node, path, process_self);

	if (fru_get_peer(node, &next_node) == FRU_SUCCESS)
		walk_tree(next_node, prior_path, process_tree);

	/*
	 * when update_node_data failed, need to exit with return value 1
	 */
	if (update_status)
		exit(1);
}

int
main(int argc, char *argv[])
{
	int	process_tree = 0, option, status;

	fru_nodehdl_t  root;


	command = argv[0];

	opterr = 0;	/*  "getopt" should not print to "stderr"  */
	while ((option = getopt(argc, argv, "lrs")) != EOF) {
	switch (option) {
		case 'l':
			list_only = 1;
			break;
		case 'r':
			recursive = 1;
			break;
		case 's':
			service_mode = 1;
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		process_tree   = 1;
		recursive = 1;
	} else {
		if (list_only) {
			usage();
			return (1);
		}

		frupath = argv[0];
		if (*frupath == 0) {
			usage();
			(void) fprintf(stderr,
			    gettext("\"frupath\" should not be empty\n"));
			return (1);
		}

		argc--;
		argv++;

		if (argc > 0) {
			update = 1;
			if (service_mode) {
				if ((argc % 2) != 0) {
					(void) fprintf(stderr,
					    gettext("Must specify "
					    "field-value pairs "
					    "for update\n"));
					return (1);
				}

				if (validate_fieldnames(argc, argv) != 0) {
					return (1);
				}

				svcargc = argc;
				svcargv = argv;
			} else if (argc == 1)
				customer_data = argv[0];
			else {
				usage();
				return (1);
			}
		}
	}

	if ((status = fru_open_data_source("picl", NULL)) != FRU_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Unable to access FRU data source: 	%s\n"),
		    fru_strerror(status));
		return (1);
	}

	if ((status = fru_get_root(&root)) == FRU_NODENOTFOUND) {
		(void) fprintf(stderr,
		    gettext("This system does not support PICL "
		    "infrastructure to provide FRUID data\n"
		    "Please use the platform SP to access the FRUID "
		    "information\n"));
		return (1);
	} else if (status != FRU_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("Unable to access FRU ID data "
		    "due to data source error\n"));
		return (1);
	}

	walk_tree(root, "", process_tree);

	if ((frupath != NULL) && (!found_frupath)) {
		(void) fprintf(stderr,
		    gettext("\"%s\" not found\n"),
		    frupath);
		return (1);
	}

	return (0);
}
