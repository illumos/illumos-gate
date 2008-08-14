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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <libpq-fe.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include <libxml/parser.h>
#include "mm_db.h"
#include "mm.h"
#include "mm_util.h"
#include "mm_commands.h"
#include "mm_sql.h"
#include "mm_sql_impl.h"
#include "mm_task.h"
#include "mm_path.h"

static char *_SrcFile = __FILE__;

typedef struct mm_type_library mm_type_library_t;
struct mm_type_library {
	mms_list_node_t	mm_library_list_next;
	mms_list_t		mm_library_name_list;
	mms_list_t		mm_shape_name_list;
};

typedef struct mm_type_data mm_type_data_t;
struct mm_type_data {
	int		mm_error;
	int		mm_level;
	int		mm_once;
	mms_list_t		mm_drive_name_list;
	mms_list_t		mm_cart_name_list;
	mms_list_t		mm_library_list;

	mm_type_library_t *cur_lib;
};
static void mm_check_drive_string(char *drive_name);
static void mm_check_cartridge_string(char *cartridge_name);
static void mm_check_cartridgetype_string(char *cartridge_name);
static void mm_check_library_string(char *library_name);
static void mm_check_slottype_string(char *cartridgeshape_name,
    char *cur_library_name);
static int mm_verify_types(mm_type_data_t *type_data);
static int mm_parse_types(mm_type_data_t *type_data, char *fn);
static void mm_parse_type_start_elements(void *xml_type_data,
    const xmlChar *xml_name, const xmlChar **xml_atts);
static void mm_parse_type_end_elements(void *xml_type_data,
    const xmlChar *xml_name);

static mm_db_t *db;


static PGresult *drive_results;
static int num_drive;
static PGresult *cartridge_results;
static int num_cartridge;
static PGresult *library_results;
static int num_library;
static PGresult *slottype_results;
static int num_slottype;
static PGresult *carttype_results;
static int num_carttype;

static void
mm_library_list_destroy(mms_list_t *list) {
	mm_type_library_t *lib_list;
	mm_type_library_t *next_lib_list;

	for (lib_list = mms_list_head(list);
	    lib_list != NULL;
	    lib_list = next_lib_list) {

		mm_char_list_destroy(&lib_list->mm_library_name_list);
		mm_char_list_destroy(&lib_list->mm_shape_name_list);

		next_lib_list =
			mms_list_next(list,
				lib_list);
		mms_list_remove(list,
			    lib_list);
		free(lib_list);
	}

}

static
mm_type_library_t *
mm_alloc_lib_struct() {
	mm_type_library_t *lib;
	lib = (mm_type_library_t *)calloc(1, sizeof (mm_type_library_t));

	if (lib == NULL) {
		printf("could not allocate mem for lib struct");
		exit(1);
	}

	mms_list_create(&lib->mm_library_name_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&lib->mm_shape_name_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));

	return (lib);
}


int
mm_init_types(mm_data_t *mm_data, char *fn)
{
	mm_type_data_t	type_data;

	mms_trace(MMS_DEVP, "types init %s", fn);

	db = &mm_data->mm_db;




	/* Get existing drives/carts/library/slottypes */
	if (mm_db_exec(HERE, db,
	    "select \"DriveString\" "
	    "from \"DRIVELIST\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error getting drive strings");
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		drive_results = db->mm_db_results;
		num_drive = PQntuples(drive_results);
	}
	if (mm_db_exec(HERE, db,
	    "select \"CartridgeString\" "
	    "from \"CARTRIDGELIST\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error getting cartridge strings");
		mm_clear_db(&drive_results);
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		cartridge_results = db->mm_db_results;
		num_cartridge = PQntuples(cartridge_results);
	}
	if (mm_db_exec(HERE, db,
	    "select \"LibraryString\" "
	    "from \"LIBRARYLIST\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error getting library strings");
		mm_clear_db(&drive_results);
		mm_clear_db(&cartridge_results);
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		library_results = db->mm_db_results;
		num_library = PQntuples(library_results);
	}
	if (mm_db_exec(HERE, db,
	    "select \"SlotTypeName\", \"CartridgeShapeName\" "
	    "from \"SLOTTYPE\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error getting slottype strings");
		mm_clear_db(&drive_results);
		mm_clear_db(&cartridge_results);
		mm_clear_db(&library_results);
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		slottype_results = db->mm_db_results;
		num_slottype = PQntuples(slottype_results);
	}

	if (mm_db_exec(HERE, db,
	    "select \"CartridgeTypeName\", \"CartridgeShapeName\" "
	    "from \"CARTRIDGETYPE\";") != MM_DB_DATA) {
		mms_trace(MMS_ERR,
		    "db error getting CARTRIDGETYPE strings");
		mm_clear_db(&drive_results);
		mm_clear_db(&cartridge_results);
		mm_clear_db(&library_results);
		mm_clear_db(&slottype_results);
		mm_clear_db(&db->mm_db_results);
		return (1);
	} else {
		carttype_results = db->mm_db_results;
		num_carttype = PQntuples(carttype_results);
	}


	memset(&type_data, 0, sizeof (mm_type_data_t));

	/* Create drive cart and library lists */
	mms_list_create(&type_data.mm_drive_name_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&type_data.mm_cart_name_list, sizeof (mm_char_list_t),
	    offsetof(mm_char_list_t, mm_char_list_next));
	mms_list_create(&type_data.mm_library_list, sizeof (mm_type_library_t),
	    offsetof(mm_type_library_t, mm_library_list_next));


	type_data.mm_error = 0;

	if (mm_parse_types(&type_data, fn)) {
		mm_clear_db(&drive_results);
		mm_clear_db(&cartridge_results);
		mm_clear_db(&library_results);
		mm_clear_db(&slottype_results);
		mm_clear_db(&carttype_results);
		mm_char_list_destroy(&type_data.mm_drive_name_list);
		mm_char_list_destroy(&type_data.mm_cart_name_list);
		mm_library_list_destroy(&type_data.mm_library_list);

		return (1);
	}


	mms_trace(MMS_DEVP,
	    "parsing types done, verify now");

	if (mm_verify_types(&type_data)) {
		mms_trace(MMS_ERR,
		    "error verifying types");
		mm_clear_db(&drive_results);
		mm_clear_db(&cartridge_results);
		mm_clear_db(&library_results);
		mm_clear_db(&slottype_results);
		mm_clear_db(&carttype_results);

		mm_char_list_destroy(&type_data.mm_drive_name_list);
		mm_char_list_destroy(&type_data.mm_cart_name_list);
		mm_library_list_destroy(&type_data.mm_library_list);
		return (1);
	}

	mms_trace(MMS_DEVP,
	    "types verified successfully, "
	    "type init done");

	mm_clear_db(&drive_results);
	mm_clear_db(&cartridge_results);
	mm_clear_db(&library_results);
	mm_clear_db(&slottype_results);
	mm_clear_db(&carttype_results);

	mm_char_list_destroy(&type_data.mm_drive_name_list);
	mm_char_list_destroy(&type_data.mm_cart_name_list);
	mm_library_list_destroy(&type_data.mm_library_list);

	return (0);
}

static void
mm_types_delete_drive(mm_type_data_t *type_data) {
	mm_char_list_t *node;
	mm_char_list_t *next;

	char		*buf = NULL;

	int		found_one = 0;

	buf = mms_strapp(buf,
	    "delete from \"DRIVELIST\" where ");

	for (node = mms_list_head(&type_data->mm_drive_name_list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(&type_data->mm_drive_name_list, node);
		if (found_one != 0) {
			buf = mms_strapp(buf, " and ");
		}
		found_one = 1;
		buf = mms_strapp(buf, "(\"DriveString\" != '%s') ",
		    node->text);
	}

	if (found_one) {
		buf = mms_strapp(buf, ";");
		if (mm_db_exec(HERE, db, buf) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_types_delete_drive: "
			    "db error deleting from drivelist");
		}
	}
	free(buf);

}

static void
mm_types_delete_cart(mm_type_data_t *type_data) {
	mm_char_list_t *node;
	mm_char_list_t *next;

	char		*buf = NULL;

	int		found_one = 0;

	buf = mms_strapp(buf,
	    "delete from \"CARTRIDGELIST\" where ");

	for (node = mms_list_head(&type_data->mm_cart_name_list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(&type_data->mm_cart_name_list, node);
		if (found_one != 0) {
			buf = mms_strapp(buf, " and ");
		}
		found_one = 1;
		buf = mms_strapp(buf, "(\"CartridgeString\" != '%s') ",
		    node->text);
	}

	if (found_one) {
		buf = mms_strapp(buf, ";");
		if (mm_db_exec(HERE, db, buf) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_types_delete_cart: "
			    "db error deleting from cartlist");
		}

	}
	free(buf);

}

static void
mm_types_delete_library(mm_type_data_t *type_data) {

	mm_type_library_t *lib_list;
	mm_type_library_t *next_lib_list;

	mm_char_list_t *node;
	mm_char_list_t *next;

	mm_char_list_t *node2;
	mm_char_list_t *next2;

	char *lib_buf = NULL;
	char *slottype_buf = NULL;

	int		found_one_lib = 0;
	int		found_one_slottype = 0;

	lib_buf = mms_strapp(lib_buf,
	    "delete from \"LIBRARYLIST\" where ");

	slottype_buf = mms_strapp(slottype_buf,
	    "delete from \"SLOTTYPE\" where ");

	for (lib_list = mms_list_head(&type_data->mm_library_list);
	    lib_list != NULL;
	    lib_list = next_lib_list) {
		next_lib_list =
		    mms_list_next(&type_data->mm_library_list,
		    lib_list);


		for (node = mms_list_head(&lib_list->mm_library_name_list);
		    node != NULL;
		    node = next) {
			next = mms_list_next(&lib_list->
			    mm_library_name_list,
			    node);

			if (found_one_lib != 0) {
				lib_buf = mms_strapp(lib_buf, " and ");
			}
			found_one_lib = 1;
			lib_buf = mms_strapp(lib_buf,
			    "(\"LibraryString\" != '%s') ",
			    node->text);



			for (node2 = mms_list_head(&lib_list->
			    mm_shape_name_list);
			    node2 != NULL;
			    node2 = next2) {
				next2 = mms_list_next(&lib_list->
				    mm_shape_name_list, node2);

				if (found_one_slottype != 0) {
					slottype_buf =
					    mms_strapp(slottype_buf, " and ");
				}
				found_one_slottype = 1;
				slottype_buf = mms_strapp(slottype_buf,
				    "((\"SlotTypeName\" != '%s') and "
				    "(\"CartridgeShapeName\" != '%s')) ",
				    node->text,
				    node2->text);
			}
		}
	}

	if (found_one_lib) {
		lib_buf = mms_strapp(lib_buf, ";");
		if (mm_db_exec(HERE, db, lib_buf) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_types_delete_library: "
			    "db error deleting from librarylist");
		}


	}
	if (found_one_slottype) {
		slottype_buf = mms_strapp(slottype_buf, ";");
		if (mm_db_exec(HERE, db, slottype_buf) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "mm_types_delete_library: "
			    "db error deleting from slottype");
		}
	}
	free(lib_buf);
	free(slottype_buf);

}



static int
mm_verify_types(mm_type_data_t *type_data)
{
	mm_type_library_t *lib_list;
	mm_type_library_t *next_lib_list;

	mm_char_list_t *node;
	mm_char_list_t *next;

	mm_char_list_t *node2;
	mm_char_list_t *next2;


	int		print = 0;
	/* Print out what we have in the lists */
	if (print) {
		mms_trace(MMS_DEVP,
		    "Drive Strings:");
		mm_print_char_list(&type_data->
		    mm_drive_name_list);
	}
	for (node = mms_list_head(&type_data->mm_drive_name_list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(&type_data->mm_drive_name_list, node);
		mm_check_drive_string(node->text);
	}


	if (print) {
		mms_trace(MMS_DEVP,
		    "Cartridge Strings:");
		mm_print_char_list(&type_data->
		    mm_cart_name_list);
	}
	for (node = mms_list_head(&type_data->mm_cart_name_list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(&type_data->mm_cart_name_list, node);
		mm_check_cartridge_string(node->text);
	}


	for (lib_list = mms_list_head(&type_data->mm_library_list);
	    lib_list != NULL;
	    lib_list = next_lib_list) {
		next_lib_list =
		    mms_list_next(&type_data->mm_library_list,
		    lib_list);
		if (print) {
			mms_trace(MMS_DEVP,
			    "Library Strings:");
			mm_print_char_list(&lib_list->
			    mm_library_name_list);
			mms_trace(MMS_DEVP,
			    "Slottype Strings:");
			mm_print_char_list(&lib_list->
			    mm_shape_name_list);
		}

		for (node = mms_list_head(&lib_list->mm_library_name_list);
		    node != NULL;
		    node = next) {
			next = mms_list_next(&lib_list->
			    mm_library_name_list,
			    node);
			mm_check_library_string(node->text);

			for (node2 = mms_list_head(&lib_list->
			    mm_shape_name_list);
			    node2 != NULL;
			    node2 = next2) {
				next2 = mms_list_next(&lib_list->
				    mm_shape_name_list, node2);
				mm_check_slottype_string(node2->text,
				    node->text);

			}
		}

	}

	/* Create the Side1Name column for default types */
	if (mm_db_exec(HERE, db,
	    "ALTER TABLE \"CARTRIDGETYPE\" "
	    "ADD \"Side1Name\" text;") != MM_DB_OK) {
		/* If there is an error ignore it */
		mm_clear_db(&db->mm_db_results);
	}

	for (node = mms_list_head(&type_data->mm_cart_name_list);
	    node != NULL;
	    node = next) {
		next = mms_list_next(&type_data->mm_cart_name_list, node);
		mm_check_cartridgetype_string(node->text);
	}

	/* All strings in xml are now in db */
	/* now delete any strings that are not in the xml */
	mm_types_delete_drive(type_data);
	mm_types_delete_cart(type_data);
	mm_types_delete_library(type_data);


	return (0);
}

static int
mm_parse_types(mm_type_data_t *type_data, char *fn)
{
	xmlSAXHandler	handler;
	memset(&handler, 0, sizeof (xmlSAXHandler));
	handler.startElement = mm_parse_type_start_elements;
	handler.endElement = mm_parse_type_end_elements;
	xmlDefaultSAXHandlerInit();
	xmlSAXUserParseFile(&handler, type_data, fn);
	if (type_data->mm_once == 0) {
		type_data->mm_error = __LINE__;
	}
	if (type_data->mm_error) {
		mms_trace(MMS_ERR, "%s parse - error %d level %d",
		    fn,
		    type_data->mm_error,
		    type_data->mm_level);
	}
	return (type_data->mm_error);


}


static void
mm_check_drive_string(char *drive_name) {
	int i;
	char *cur_drive;
	int matched_drive = 0;

	for (i = 0; i < num_drive; i++) {
		cur_drive = PQgetvalue(drive_results,
		    i, 0);
		if (strcmp(drive_name, cur_drive) == 0) {
			/* already have this drive name */
			matched_drive = 1;
		}
	}

	if (matched_drive == 0) {
		/* Need to add this drive to drive list */
		if (mm_db_exec(HERE, db,
		    "insert into \"DRIVELIST\" "
		    "(\"DriveString\") values('%s');",
		    drive_name) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "error inserting %s "
			    "into DRIVELIST",
			    drive_name);
			mm_clear_db(&db->mm_db_results);
		}
	}
}
static void
mm_check_cartridge_string(char *cartridge_name) {
	int i;
	char *cur_cartridge;
	int matched_cartridge = 0;

	for (i = 0; i < num_cartridge; i++) {
		cur_cartridge = PQgetvalue(cartridge_results,
		    i, 0);
		if (strcmp(cartridge_name, cur_cartridge) == 0) {
			/* already have this cartridge name */
			matched_cartridge = 1;
		}
	}

	if (matched_cartridge == 0) {
		/* Need to add this cartridge to cartridge list */
		if (mm_db_exec(HERE, db,
		    "insert into \"CARTRIDGELIST\" "
		    "(\"CartridgeString\") values('%s');",
		    cartridge_name) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "error inserting %s "
			    "into CARTRIDGELIST",
			    cartridge_name);
			mm_clear_db(&db->mm_db_results);
		}
	}
}

static void
mm_check_cartridgetype_string(char *cartridgeshape_name) {
	int i;
	char *cur_carttype;
	char *cur_cartshape;
	int matched_cartridge = 0;

	for (i = 0; i < num_carttype; i++) {
		cur_carttype = PQgetvalue(carttype_results,
		    i, 0);
		cur_cartshape = PQgetvalue(carttype_results,
		    i, 1);
		if ((strcmp(cartridgeshape_name, cur_carttype) == 0) &&
		    (strcmp(cartridgeshape_name, cur_cartshape) == 0)) {
			/* already have this cartridge name */
			matched_cartridge = 1;
		}
	}

	if (matched_cartridge == 0) {
		/* Need to add this cartridge to cartridge list */
		if (mm_db_exec(HERE, db,
		    "insert into \"CARTRIDGETYPE\" "
		    "(\"CartridgeTypeName\", "
		    "\"CartridgeShapeName\", "
		    "\"Side1Name\", "
		    "\"CartridgeTypeMediaType\") values('%s',"
		    "'%s', 'side 1', 'data');",
		    cartridgeshape_name,
		    cartridgeshape_name) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "error inserting %s "
			    "into CARTRIDGETYPE",
			    cartridgeshape_name);
			mm_clear_db(&db->mm_db_results);
		}
	}
}

static void
mm_check_library_string(char *library_name) {
	int i;
	char *cur_library;
	int matched_library = 0;

	for (i = 0; i < num_library; i++) {
		cur_library = PQgetvalue(library_results,
		    i, 0);
		if (strcmp(library_name, cur_library) == 0) {
			/* already have this library name */
			matched_library = 1;
		}
	}

	if (matched_library == 0) {
		/* Need to add this library to library list */
		if (mm_db_exec(HERE, db,
		    "insert into \"LIBRARYLIST\" "
		    "(\"LibraryString\") values('%s');",
		    library_name) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "error inserting %s "
			    "into LIBRARYLIST",
			    library_name);
			mm_clear_db(&db->mm_db_results);
		}
	}

}

static void
mm_check_slottype_string(char *cartridgeshape_name,
    char *cur_library_name) {
	int i;
	char *cur_slottype;
	char *cur_cartridgeshape;
	int matched_slottype = 0;

	for (i = 0; i < num_slottype; i++) {
		cur_slottype = PQgetvalue(slottype_results,
		    i, 0);
		cur_cartridgeshape = PQgetvalue(slottype_results,
		    i, 1);
		if ((strcmp(cur_library_name, cur_slottype) == 0) &&
		    (strcmp(cartridgeshape_name, cur_cartridgeshape) == 0)) {
			/* already have this slottype name */
			matched_slottype = 1;
		}
	}

	if (matched_slottype == 0) {
		/* Need to add this slottype to slottype list */
		if (mm_db_exec(HERE, db,
		    "insert into \"SLOTTYPE\" "
		    "(\"SlotTypeName\", \"CartridgeShapeName\") "
		    "values('%s', '%s');",
		    cur_library_name,
		    cartridgeshape_name) != MM_DB_OK) {
			mms_trace(MMS_ERR,
			    "error inserting %s, %s "
			    "into SLOTTYPE",
			    cur_library_name,
			    cartridgeshape_name);
		}
	}
}



static void
mm_parse_type_start_elements(void *xml_type_data, const xmlChar *xml_name,
    const xmlChar **xml_atts)
{
	mm_type_data_t	*type_data = (mm_type_data_t *)xml_type_data;
	char		*name = (char *)xml_name;
	char		**atts = (char **)xml_atts;

	mm_type_library_t *new_lib;

	if (type_data->mm_error) {
		return;
	}

	if (type_data->mm_once == 0) {
		type_data->mm_once = 1;
	}

	if (type_data->mm_level == 0 &&
	    strcmp(name, "mm_types") == 0) {
		type_data->mm_level = 1;
		return;
	}

	if (type_data->mm_level == 1 &&
	    strcmp(name, "mm_drive_list") == 0) {
		type_data->mm_level = 2;
		return;
	}
	if (type_data->mm_level == 1 &&
	    strcmp(name, "mm_cartridge_list") == 0) {
		type_data->mm_level = 2;
		return;
	}
	if (type_data->mm_level == 1 &&
	    strcmp(name, "mm_library_list") == 0) {
		type_data->mm_level = 2;
		return;
	}
	if (type_data->mm_level == 2 &&
	    strcmp(name, "mm_library") == 0) {
		type_data->mm_level = 3;
		new_lib = mm_alloc_lib_struct();
		mms_list_insert_tail(&type_data->mm_library_list,
		    new_lib);
		type_data->cur_lib = new_lib;
		return;
	}
	if (type_data->mm_level == 3 &&
	    strcmp(name, "mm_slottype_list") == 0) {
		type_data->mm_level = 4;
		return;
	}
	if (type_data->mm_level == 3 &&
	    strcmp(name, "mm_cartridgeshape_list") == 0) {
		type_data->mm_level = 4;
		return;
	}


	if (type_data->mm_level == 2 &&
	    strcmp(name, "mm_drive_string") == 0) {
		if (atts[0] == NULL || strcmp(atts[0], "value") != 0) {
			type_data->mm_error = __LINE__;
		} else if (atts[1] != NULL) {
			mms_trace(MMS_DEVP,
			    "    mm_drive_string=%s",
			    atts[1]);
			if (mm_add_char(atts[1],
			    &type_data->mm_drive_name_list)) {
				mms_trace(MMS_ERR,
				    "mm_parse_type_start_elements: "
				    "out of mem adding to drive list");
			}

		}
		return;
	}
	if (type_data->mm_level == 2 &&
	    strcmp(name, "mm_cartridge_string") == 0) {
		if (atts[0] == NULL || strcmp(atts[0], "value") != 0) {
			type_data->mm_error = __LINE__;
		} else if (atts[1] != NULL) {
			mms_trace(MMS_DEVP,
			    "    mm_cartridge_string=%s",
			    atts[1]);
			if (mm_add_char(atts[1],
			    &type_data->mm_cart_name_list)) {
				mms_trace(MMS_ERR,
				    "mm_parse_type_start_elements: "
				    "out of mem adding to cart list");
			}

		}
		return;
	}

	if (type_data->mm_level == 4 &&
	    strcmp(name, "mm_slottype") == 0) {
		if (atts[0] == NULL || strcmp(atts[0], "name") != 0) {
			type_data->mm_error = __LINE__;
		} else if (atts[1] != NULL) {
			mms_trace(MMS_DEVP,
			    "    mm_slottype name=%s",
			    atts[1]);
			if (mm_add_char(atts[1],
			    &type_data->cur_lib->mm_library_name_list)) {
				mms_trace(MMS_ERR,
				    "mm_parse_type_start_elements: "
				    "out of mem adding to library list");
			}

		}
		return;
	}
	if (type_data->mm_level == 4 &&
	    strcmp(name, "mm_cartridgeshape") == 0) {
		if (atts[0] == NULL || strcmp(atts[0], "name") != 0) {
			type_data->mm_error = __LINE__;
		} else if (atts[1] != NULL) {
			mms_trace(MMS_DEVP,
			    "    mm_cartridgeshape name=%s",
			    atts[1]);
			if (mm_add_char(atts[1],
			    &type_data->cur_lib->mm_shape_name_list)) {
				mms_trace(MMS_ERR,
				    "mm_parse_type_start_elements: "
				    "out of mem adding to shape list");
			}
		}
		return;
	}

	type_data->mm_error = __LINE__;
}

static void
mm_parse_type_end_elements(void *xml_type_data, const xmlChar *xml_name)
{
	mm_type_data_t	*type_data = (mm_type_data_t *)xml_type_data;
	char		*name = (char *)xml_name;



	if (type_data->mm_level == 2 &&
	    strcmp(name, "mm_drive_list") == 0) {
		type_data->mm_level = 1;
		return;
	}
	if (type_data->mm_level == 2 &&
	    strcmp(name, "mm_cartridge_list") == 0) {
		type_data->mm_level = 1;
		return;
	}
	if (type_data->mm_level == 2 &&
	    strcmp(name, "mm_library_list") == 0) {
		type_data->mm_level = 1;
		return;
	}
	if (type_data->mm_level == 3 &&
	    strcmp(name, "mm_library") == 0) {
		type_data->mm_level = 2;
		type_data->cur_lib = NULL;
		return;
	}
	if (type_data->mm_level == 4 &&
	    strcmp(name, "mm_slottype_list") == 0) {
		type_data->mm_level = 3;
		return;
	}
	if (type_data->mm_level == 4 &&
	    strcmp(name, "mm_cartridgeshape_list") == 0) {
		type_data->mm_level = 3;
		return;
	}

}
