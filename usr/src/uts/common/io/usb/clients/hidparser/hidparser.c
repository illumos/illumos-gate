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
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hidparser/hidparser.h>
#include <sys/usb/clients/hidparser/hid_parser_driver.h>
#include <sys/usb/clients/hidparser/hidparser_impl.h>

/*
 * hidparser: Parser to generate parse tree for Report Descriptors
 * in HID devices.
 */

uint_t hparser_errmask = (uint_t)PRINT_MASK_ALL;
uint_t	hparser_errlevel = (uint_t)USB_LOG_L1;
static usb_log_handle_t hparser_log_handle;

/*
 * Array used to store corresponding strings for the
 * different item types for debugging.
 */
char		*items[500];	/* Print items */

/*
 * modload support
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"HID Parser"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void	*)&modlmisc, NULL
};

int
_init(void)
{
	int rval = mod_install(&modlinkage);

	if (rval == 0) {
		hparser_log_handle = usb_alloc_log_hdl(NULL, "hidparser",
		    &hparser_errlevel, &hparser_errmask, NULL, 0);
	}

	return (rval);
}

int
_fini()
{
	int rval = mod_remove(&modlinkage);

	if (rval == 0) {
		usb_free_log_hdl(hparser_log_handle);
	}

	return (rval);
}

int
_info(struct modinfo *modinfop)
{

	return (mod_info(&modlinkage, modinfop));
}

/*
 * These functions are used internally in the parser.
 * local declarations
 */
static void			hidparser_scan(hidparser_tok_t	*);
static int			hidparser_Items(hidparser_tok_t *);
static int			hidparser_LocalItem(hidparser_tok_t *);
static int			hidparser_GlobalItem(hidparser_tok_t *);
static int			hidparser_ItemList(entity_item_t **,
					hidparser_tok_t *);
static int			hidparser_ReportDescriptor(entity_item_t **,
					hidparser_tok_t *);
static int			hidparser_ReportDescriptorDash(entity_item_t **,
					hidparser_tok_t *);
static int			hidparser_MainItem(entity_item_t **,
					hidparser_tok_t *);
static void			hidparser_free_attribute_list(
					entity_attribute_t *);
static entity_item_t		*hidparser_allocate_entity(hidparser_tok_t *);
static void			hidparser_add_attribute(hidparser_tok_t	*);
static entity_attribute_t	*hidparser_cp_attribute_list(
				entity_attribute_t *);
static entity_attribute_t	*hidparser_find_attribute_end(
				entity_attribute_t *);
static entity_attribute_t	*hidparser_alloc_attrib_list(int);
static void			hidparser_report_err(int, int,
					int, int, char *);
static int			hidparser_isvalid_item(int);
static entity_attribute_t	*hidparser_lookup_attribute(entity_item_t *,
					int);
static void			hidparser_global_err_check(entity_item_t *);
static void			hidparser_local_err_check(entity_item_t *);
static void			hidparser_mainitem_err_check(entity_item_t *);
static unsigned int		hidparser_find_unsigned_val(
					entity_attribute_t *);
static int			hidparser_find_signed_val(
					entity_attribute_t *);
static void			hidparser_check_correspondence(
					entity_item_t *, int, int, int,
					int, char *, char *);
static void			hidparser_check_minmax_val(entity_item_t *,
					int, int, int, int);
static void			hidparser_check_minmax_val_signed(
					entity_item_t *,
					int, int, int, int);
static void			hidparser_error_delim(entity_item_t *, int);
static int			hidparser_get_usage_attribute_report_des(
					entity_item_t *,
					uint32_t, uint32_t, uint32_t,
					uint32_t, uint32_t, int32_t *);
static int			hidparser_get_packet_size_report_des(
					entity_item_t *, uint32_t, uint32_t,
					uint32_t *);
static int			hidparser_get_main_item_data_descr_main(
					entity_item_t *, uint32_t,
					uint32_t, uint32_t, uint32_t,
					uint32_t	*);
static void			hidparser_print_entity(
					entity_item_t *entity,
					int indent_level);
static void			hidparser_print_this_attribute(
					entity_attribute_t *attribute,
					char *ident_space);
static int			hidparser_main(unsigned char *, size_t,
					entity_item_t **);
static void			hidparser_initialize_items();
static void			hidparser_free_report_descr_handle(
					entity_item_t *);
static int			hidparser_print_report_descr_handle(
					entity_item_t	*handle,
					int		indent_level);
static int			hidparser_get_usage_list_in_order_internal(
					entity_item_t *parse_handle,
					uint_t collection_usage,
					uint_t report_id,
					uint_t main_item_type,
					hidparser_rpt_t *rpt);
static void			hidparser_fill_usage_info(
					hidparser_usage_info_t *ui,
					entity_attribute_t *attribute);
static int			hidparser_get_report_id_list_internal(
					entity_item_t *parser_handle,
					uint_t main_item_type,
					hidparser_report_id_list_t *id_lst);

/*
 * The hidparser_lookup_first(N) of a non-terminal N is stored as an array of
 * integer tokens, terminated by 0. Right now there is only one element.
 */
static hidparser_terminal_t	first_Items[] = {
	R_ITEM_USAGE_PAGE, R_ITEM_LOGICAL_MINIMUM, R_ITEM_LOGICAL_MAXIMUM, \
	R_ITEM_PHYSICAL_MINIMUM, R_ITEM_PHYSICAL_MAXIMUM, R_ITEM_UNIT, \
	R_ITEM_EXPONENT, R_ITEM_REPORT_SIZE, R_ITEM_REPORT_COUNT, \
	R_ITEM_REPORT_ID, \
	R_ITEM_USAGE, R_ITEM_USAGE_MIN, R_ITEM_USAGE_MAX, \
	R_ITEM_DESIGNATOR_INDEX, \
	R_ITEM_DESIGNATOR_MIN, R_ITEM_STRING_INDEX, R_ITEM_STRING_MIN, \
	R_ITEM_STRING_MAX, \
	R_ITEM_SET_DELIMITER, \
	0
};


/*
 * Each non-terminal is represented by a function. In a top-down parser,
 * whenever a non-terminal is encountered on the state diagram, the
 * corresponding function is called. Because of the grammar, there is NO
 * backtracking. If there is an error in the middle, the parser returns
 * HIDPARSER_FAILURE
 */
static hidparser_terminal_t *hid_first_list[] = {
	first_Items
};


/*
 * hidparser_parse_report_descriptor:
 *	Calls the main parser routine
 */
int
hidparser_parse_report_descriptor(unsigned char *descriptor, size_t size,
    usb_hid_descr_t *hid_descriptor, hidparser_handle_t *parse_handle)
{
	int	error = 0;
	entity_item_t	*root;

	hidparser_initialize_items();

	error = hidparser_main(descriptor, size, &root);

	if (error != HIDPARSER_SUCCESS) {

		return (HIDPARSER_FAILURE);
	} else {
		*parse_handle = kmem_zalloc(
		    sizeof (hidparser_handle), KM_SLEEP);
		(*parse_handle)->hidparser_handle_hid_descr = hid_descriptor;
		(*parse_handle)->hidparser_handle_parse_tree = root;

		return (HIDPARSER_SUCCESS);
	}
}


/*
 * hidparser_free_report_descriptor_handle:
 *	Frees the parse_handle which consists of a pointer to the parse
 *	tree and a pointer to the Hid descriptor structure
 */
int
hidparser_free_report_descriptor_handle(hidparser_handle_t parse_handle)
{
	if (parse_handle != NULL) {
		hidparser_free_report_descr_handle(
		    parse_handle->hidparser_handle_parse_tree);
		if (parse_handle != NULL) {
			kmem_free(parse_handle, sizeof (hidparser_handle));
		}
	}

	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_get_country_code:
 *	Return the bCountryCode from the Hid Descriptor
 *	to the hid module.
 */
int
hidparser_get_country_code(hidparser_handle_t parser_handle,
    uint16_t *country_code)
{
	if ((parser_handle == NULL) ||
	    (parser_handle->hidparser_handle_hid_descr == NULL)) {

		return (HIDPARSER_FAILURE);
	}

	*country_code =
	    parser_handle->hidparser_handle_hid_descr->bCountryCode;

	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_get_packet_size:
 *	Get the packet size(sum of REPORT_SIZE * REPORT_COUNT)
 *	corresponding to a report id and an item type
 */
int
hidparser_get_packet_size(hidparser_handle_t parser_handle,
    uint_t report_id, uint_t main_item_type, uint_t *size)
{
	if ((parser_handle == NULL) || (parser_handle->
	    hidparser_handle_parse_tree == NULL)) {

		return (HIDPARSER_FAILURE);
	}

	*size = 0;

	return (hidparser_get_packet_size_report_des(
	    parser_handle->hidparser_handle_parse_tree,
	    report_id, main_item_type, size));
}


/*
 * hidparser_get_packet_size_report_des:
 *	Get the packet size(sum of REPORT_SIZE * REPORT_COUNT)
 *	corresponding to a report id and an item type
 */
int
hidparser_get_packet_size_report_des(entity_item_t *parser_handle,
    uint32_t report_id, uint32_t main_item_type, uint32_t *size)
{
	entity_item_t	*current = parser_handle;
	entity_attribute_t *attribute;
	uint32_t temp;
	uchar_t	foundsize, foundcount, foundreportid, right_report_id;

	foundsize = 0;
	foundcount = 0;
	right_report_id = 0;

	while (current) {
		if (current->entity_item_type == R_ITEM_COLLECTION) {
			(void) hidparser_get_packet_size_report_des(
			    current->info.child, report_id, main_item_type,
			    size);
		} else if (current->entity_item_type == main_item_type) {
			temp = 1;
			foundsize = 0;
			foundcount = 0;

			foundreportid = 0;
			attribute = current->entity_item_attributes;
			while (attribute != NULL) {
				if (attribute->entity_attribute_tag ==
				    R_ITEM_REPORT_ID) {
					foundreportid = 1;
					if ((attribute->
					    entity_attribute_value[0]) ==
					    report_id) {
						right_report_id = 1;
					}
				} else if (attribute->entity_attribute_tag ==
				    R_ITEM_REPORT_SIZE) {
					foundsize = 1;
					temp *= hidparser_find_unsigned_val(
					    attribute);
					if (foundcount == 1) {
						if (report_id &&
						    right_report_id) {
							break;
						}
					}
				} else if (attribute->entity_attribute_tag ==
				    R_ITEM_REPORT_COUNT) {
					foundcount = 1;
					temp *= hidparser_find_unsigned_val(
					    attribute);
					if (foundsize == 1) {
						if (report_id &&
						    right_report_id) {
							break;
						}
					}
				}
				attribute = attribute->entity_attribute_next;
			} /* end while */

			if (foundreportid) {
				if (right_report_id) {
					*size = *size + temp;
				}
			} else if (report_id == HID_REPORT_ID_UNDEFINED) {
				/* Just sanity checking */
				*size = *size + temp;
			}
			right_report_id = 0;
		} /* end else if */

		current = current->entity_item_right_sibling;
	} /* end while current */


	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_get_usage_attribute:
 *	Get the attribute value corresponding to a particular
 *	report id, main item and usage
 */
int
hidparser_get_usage_attribute(hidparser_handle_t parser_handle,
    uint_t report_id, uint_t main_item_type, uint_t usage_page,
    uint_t usage_id, uint_t usage_attribute, int *usage_attribute_value)
{

	return (hidparser_get_usage_attribute_report_des(
	    parser_handle->hidparser_handle_parse_tree,
	    report_id, main_item_type, usage_page,
	    usage_id, usage_attribute, usage_attribute_value));
}


/*
 * hidparser_get_usage_attribute_report_des:
 *	Called by the wrapper function hidparser_get_usage_attribute()
 */
static int
hidparser_get_usage_attribute_report_des(entity_item_t *parser_handle,
    uint_t report_id, uint_t main_item_type, uint_t usage_page,
    uint_t usage_id, uint_t usage_attribute, int *usage_attribute_value)
{
	entity_item_t *current = parser_handle;
	entity_attribute_t *attribute;
	uchar_t found_page, found_ret_value, found_usage_id;
	uchar_t foundreportid, right_report_id;
	uint32_t usage;
	short attvalue;

	found_page = 0;
	found_ret_value = 0;
	found_usage_id = 0;
	foundreportid = 0;
	right_report_id = 0;

	while (current) {
		if (usage_id == HID_USAGE_UNDEFINED) {
			found_usage_id = 1;
		}
		if (current->entity_item_type == R_ITEM_COLLECTION) {

			if (hidparser_get_usage_attribute_report_des(
			    current->info.child, report_id, main_item_type,
			    usage_page, usage_id, usage_attribute,
			    usage_attribute_value) ==
			    HIDPARSER_SUCCESS) {

				return (HIDPARSER_SUCCESS);
			}

		} else if (current->entity_item_type == main_item_type) {
			/* Match Item Type */
			attribute = current->entity_item_attributes;

			while (attribute != NULL) {
				if (attribute->entity_attribute_tag ==
				    R_ITEM_USAGE) {
					usage = hidparser_find_unsigned_val(
					    attribute);
					if (usage_id == HID_USAGE_ID(usage)) {

						found_usage_id = 1;
					} else {
						/*
						 * If we are trying to find out
						 * say, report size of usage =
						 * 0, a m.i with a valid usage
						 * will not contain that
						 */
						if (usage_id ==
						    HID_USAGE_UNDEFINED) {
							found_usage_id = 0;
						}
					}

					if (found_usage_id && attribute->
					    entity_attribute_length == 3) {
						/*
						 * This is an extended usage ie.
						 * usage page in upper 16 bits
						 * or-ed with usage in the lower
						 * 16 bits.
						 */
						if (HID_USAGE_PAGE(usage) &&
						    HID_USAGE_PAGE(usage) ==
						    usage_page) {

							found_page = 1;
						} else {

							found_usage_id = 0;
						}
					}
				} else if (attribute->entity_attribute_tag ==
				    R_ITEM_USAGE_PAGE) {
					if (attribute->
					    entity_attribute_value[0] ==
					    usage_page) {
						/* Match Usage Page */
						found_page = 1;
					}
				} else if (attribute->entity_attribute_tag ==
				    R_ITEM_REPORT_ID) {
					foundreportid = 1;
					if (attribute->
					    entity_attribute_value[0] ==
					    report_id) {
						right_report_id = 1;
					}
				}
				if (attribute->entity_attribute_tag ==
				    usage_attribute) {
					/* Match attribute */
					found_ret_value = 1;
					*usage_attribute_value =
					    *attribute->entity_attribute_value;
					if (attribute->
					    entity_attribute_length == 2) {
						attvalue =
						    (attribute->
						    entity_attribute_value[0] &
						    0xff) |
						    (attribute->
						    entity_attribute_value[1] <<
						    8);
						*usage_attribute_value =
						    attvalue;
					}
				}
				attribute = attribute->entity_attribute_next;
			}

			if (found_usage_id && found_page && found_ret_value) {

				if (foundreportid) {
					if (right_report_id) {

						return (HIDPARSER_SUCCESS);
					} else if (report_id ==
					    HID_REPORT_ID_UNDEFINED) {

						return (HIDPARSER_SUCCESS);
					}
				} else {

					return (HIDPARSER_SUCCESS);
				}
			}
		}

		/*
		 * search the next main item, right sibling of this one
		 */
		if (current->entity_item_right_sibling != NULL) {

			current = current->entity_item_right_sibling;
			found_usage_id = found_page = found_ret_value = 0;
			/* Don't change foundreportid */
			right_report_id = 0;
		} else {

			break;
		}
	}
	/* Don't give junk result */
	*usage_attribute_value = 0;

	return (HIDPARSER_NOT_FOUND);
}


/*
 * hidparser_get_main_item_data_descr:
 *	Get the data value corresponding to a particular
 *	Main Item (Input, Output, Feature)
 */
int
hidparser_get_main_item_data_descr(hidparser_handle_t parser_handle,
    uint_t report_id, uint_t main_item_type, uint_t usage_page,
    uint_t usage_id, uint_t *main_item_descr_value)
{

	return hidparser_get_main_item_data_descr_main(
	    parser_handle->hidparser_handle_parse_tree,
	    report_id, main_item_type, usage_page, usage_id,
	    main_item_descr_value);
}


/*
 * hidparser_get_main_item_data_descr_main:
 *	Called by the wrapper function hidparser_get_main_item_data_descr()
 */
static int
hidparser_get_main_item_data_descr_main(entity_item_t *parser_handle,
    uint_t report_id, uint_t main_item_type, uint_t usage_page,
    uint_t usage_id, uint_t *main_item_descr_value)
{
	entity_item_t *current = parser_handle;
	entity_attribute_t *attribute;

	uchar_t found_page, found_usage_id;
	uchar_t foundreportid, right_report_id;
	uint32_t usage;

	found_page = 0;
	found_usage_id = 0;
	foundreportid = 0;
	right_report_id = 0;

	while (current) {
		if (usage_id == HID_USAGE_UNDEFINED) {
			found_usage_id = 1;
		}
		if (current->entity_item_type == R_ITEM_COLLECTION) {

			if (hidparser_get_main_item_data_descr_main(
			    current->info.child, report_id, main_item_type,
			    usage_page, usage_id, main_item_descr_value) ==
			    HIDPARSER_SUCCESS) {

				return (HIDPARSER_SUCCESS);
			}
		} else if (current->entity_item_type == main_item_type) {
			/* Match Item Type */
			attribute = current->entity_item_attributes;

			if (report_id == HID_REPORT_ID_UNDEFINED) {
				foundreportid = right_report_id = 1;
			}

			while (attribute != NULL) {
				if (attribute->entity_attribute_tag ==
				    R_ITEM_USAGE) {
					usage = hidparser_find_unsigned_val(
					    attribute);
					if (usage_id == HID_USAGE_ID(usage)) {
						found_usage_id = 1;
						if (attribute->
						    entity_attribute_length ==
						    3) {
							if (HID_USAGE_PAGE(
							    usage) &&
							    HID_USAGE_PAGE(
							    usage) ==
							    usage_page) {

								found_page = 1;
							} else {

							found_usage_id = 0;
							}
						}

						if (found_usage_id &&
						    found_page &&
						    foundreportid &&
						    right_report_id) {
						*main_item_descr_value =
						    current->
						    entity_item_params[0];
						break;
						}
					}
				} else if ((attribute->entity_attribute_tag ==
				    R_ITEM_USAGE_PAGE) &&
				    (attribute->entity_attribute_value[0] ==
				    usage_page)) {

					/* Match Usage Page */
					found_page = 1;
					if (found_usage_id && foundreportid &&
					    right_report_id) {
						*main_item_descr_value =
						    current->
						    entity_item_params[0];
						break;
					}
				} else if (attribute->entity_attribute_tag ==
				    R_ITEM_REPORT_ID) {
					foundreportid = 1;
					if (attribute->
					    entity_attribute_value[0] ==
					    report_id) {
						right_report_id = 1;
					} else {
						break;
					}
				}

				attribute = attribute->entity_attribute_next;
			}

			if (foundreportid) {
				if (right_report_id) {
					if (found_usage_id && found_page) {

						return (HIDPARSER_SUCCESS);
					}
				}
			}
		}

		/*
		 * search the next main item, right sibling of this one
		 */
		if (current->entity_item_right_sibling != NULL) {

			current = current->entity_item_right_sibling;
			found_page = found_usage_id = right_report_id = 0;
		} else {

			break;
		}
	}

	*main_item_descr_value = 0;

	return (HIDPARSER_NOT_FOUND);
}

/*
 * hidparser_lookup_usage_collection:
 *	Look up the collection specified by the usage page and usage id
 */
int
hidparser_lookup_usage_collection(hidparser_handle_t parse_handle,
    uint_t lusage_page, uint_t lusage_id)
{
	entity_item_t *current;
	entity_attribute_t *attribute;
	int found_usage_id = 0;
	int found_page = 0;
	uint32_t usage;
	uint_t usage_page;
	uint_t usage_id;

	if ((parse_handle == NULL) ||
	    (parse_handle->hidparser_handle_parse_tree == NULL))
		return (HIDPARSER_FAILURE);

	current = parse_handle->hidparser_handle_parse_tree;
	while (current != NULL) {

		if (current->entity_item_type != R_ITEM_COLLECTION) {
			current = current->entity_item_right_sibling;
			continue;
		}

		attribute = current->entity_item_attributes;
		found_usage_id = 0;
		found_page = 0;

		while (attribute != NULL) {
			if (attribute->entity_attribute_tag == R_ITEM_USAGE) {
				found_usage_id = 1;
				usage = hidparser_find_unsigned_val(attribute);
				usage_id = HID_USAGE_ID(usage);
				if (attribute->entity_attribute_length == 3) {
					if (HID_USAGE_PAGE(usage)) {
						found_page = 1;
						usage_page =
						    HID_USAGE_PAGE(usage);
					}
				}
				if (found_page) {
					goto check_usage;
				}
			} else if (attribute->entity_attribute_tag ==
			    R_ITEM_USAGE_PAGE) {
				found_page = 1;
				usage_page =
				    attribute->entity_attribute_value[0];
				if (found_usage_id) {
					goto check_usage;
				}
			}
			attribute = attribute->entity_attribute_next;
		}
check_usage:
		if ((usage_page == lusage_page) && (usage_id == lusage_id))
			return (HIDPARSER_SUCCESS);
		else
			current = current->entity_item_right_sibling;
	}

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_get_top_level_collection_usage:
 *	Get the usage page and usage for the top level collection item
 */
int
hidparser_get_top_level_collection_usage(hidparser_handle_t parse_handle,
    uint_t *usage_page, uint_t *usage_id)
{
	entity_item_t *current;
	entity_attribute_t *attribute;
	int found_usage_id = 0;
	int found_page = 0;
	uint32_t usage;

	if ((parse_handle == NULL) ||
	    (parse_handle->hidparser_handle_parse_tree == NULL))

		return (HIDPARSER_FAILURE);

	current = parse_handle->hidparser_handle_parse_tree;

	if (current->entity_item_type != R_ITEM_COLLECTION) {

		return (HIDPARSER_FAILURE);
	}
	attribute = current->entity_item_attributes;
	while (attribute != NULL) {
		if (attribute->entity_attribute_tag == R_ITEM_USAGE) {
			found_usage_id = 1;
			usage = hidparser_find_unsigned_val(attribute);
			*usage_id = HID_USAGE_ID(usage);
			if (attribute->entity_attribute_length == 3) {
				if (HID_USAGE_PAGE(usage)) {
					found_page = 1;
					*usage_page = HID_USAGE_PAGE(usage);
				}
			}
			if (found_usage_id && found_page) {

				return (HIDPARSER_SUCCESS);
			}
		} else if (attribute->entity_attribute_tag ==
		    R_ITEM_USAGE_PAGE) {
			found_page = 1;
			*usage_page = attribute->entity_attribute_value[0];
			if (found_usage_id && found_page) {

				return (HIDPARSER_SUCCESS);
			}
		}
		attribute = attribute->entity_attribute_next;
	}

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_get_usage_list_in_order:
 *	Find all the usages corresponding to a main item and report id.
 *	Note that only short items are supported.
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	report id:
 *		report id of the particular report where the usages belong to
 *	main_item_type:
 *		type of report, either Input, Output, or Feature
 *	usage_list:
 *		Filled in with the pointer to the first element of the
 *		usage list
 *
 * Return values:
 *	HIDPARSER_SUCCESS - returned success
 *	HIDPARSER_NOT_FOUND - usage specified by the parameters was not found
 *	HIDPARSER_FAILURE - unspecified failure
 */
int
hidparser_get_usage_list_in_order(hidparser_handle_t parser_handle,
    uint_t report_id, uint_t main_item_type, hidparser_rpt_t *rpt)
{

	if ((parser_handle == NULL) ||
	    (parser_handle->hidparser_handle_parse_tree == NULL)) {

		return (HIDPARSER_FAILURE);
	}

	rpt->no_of_usages = 0;

	return (hidparser_get_usage_list_in_order_internal(
	    parser_handle->hidparser_handle_parse_tree, HID_USAGE_UNDEFINED,
	    report_id, main_item_type, rpt));
}


static int
hidparser_get_usage_list_in_order_internal(entity_item_t *parser_handle,
    uint_t collection_usage, uint_t report_id, uint_t main_item_type,
    hidparser_rpt_t *rpt)
{

	/* setup wrapper function */
	entity_item_t *current = parser_handle;
	entity_attribute_t *attribute;
	uchar_t foundreportid, right_report_id, valid_usage;
	uchar_t found_usage_min, found_usage_max, found_usage;
	int i, j;
	int rval;
	uint32_t usage, usage_min, usage_max, usage_id[USAGE_MAX];
	hidparser_usage_info_t *ui;

	found_usage_min = 0;
	found_usage_max = 0;
	foundreportid = 0;
	right_report_id = 0;

	while (current) {

		if (current->entity_item_type == R_ITEM_COLLECTION) {

			/*
			 * find collection usage information for this
			 * collection
			 */
			valid_usage = 0;

			attribute = current->entity_item_attributes;

			while (attribute != NULL) {
				if (attribute->entity_attribute_tag ==
				    R_ITEM_USAGE) {
					usage = hidparser_find_unsigned_val(
					    attribute);
					valid_usage = 1;
				}
				attribute = attribute->entity_attribute_next;
			}

			if (!valid_usage) {
				usage = HID_USAGE_UNDEFINED;
			}

			rval = hidparser_get_usage_list_in_order_internal(
			    current->info.child, usage,
			    report_id, main_item_type, rpt);
			if (rval != HIDPARSER_SUCCESS) {

				return (rval);
			}

		} else if (current->entity_item_type == main_item_type) {
			/* Match Item Type */

			foundreportid = 0;
			right_report_id = 0;
			found_usage_min = 0;
			found_usage_max = 0;
			found_usage = 0;
			valid_usage = 0;

			attribute = current->entity_item_attributes;

			while (attribute != NULL) {
				switch (attribute->entity_attribute_tag) {
				case R_ITEM_REPORT_ID:
					foundreportid = 1;

					if (attribute->
					    entity_attribute_value[0] ==
					    report_id) {
						right_report_id = 1;
					} else {
						/* different report id */
						valid_usage = 1;
					}

					break;
				case R_ITEM_USAGE:
					if (found_usage >= USAGE_MAX) {

						return (HIDPARSER_FAILURE);
					}
					usage = hidparser_find_unsigned_val(
					    attribute);
					if (usage) {
						usage_id[found_usage] = usage;
						found_usage++;
					}

					break;
				case R_ITEM_USAGE_MIN:
					found_usage_min = 1;
					usage_min = hidparser_find_unsigned_val(
					    attribute);

					break;
				case R_ITEM_USAGE_MAX:
					found_usage_max = 1;
					usage_max = hidparser_find_unsigned_val(
					    attribute);

					break;
				case R_ITEM_SET_DELIMITER:
					/* skip over alternate usages */
					do {
						attribute = attribute->
						    entity_attribute_next;
					} while (attribute->
					    entity_attribute_tag !=
					    R_ITEM_SET_DELIMITER);

					break;
				}

				attribute = attribute->entity_attribute_next;
			}

			/*
			 * If we have a report id match (or report ids
			 * are not present), and have a usage item or
			 * usage min&max, put the usage item into the
			 * list. Don't put undefined usage items
			 * (HID_USAGE_UNDEFINED, 0) into the list;
			 * a 0 usage item is used to match padding
			 * fields that don't have an attached usage.
			 */
			if (!foundreportid ||
			    (foundreportid && right_report_id)) {

				for (j = 0; j < found_usage; j++) {

					/* Put in usage list */
					if (rpt->no_of_usages >= USAGE_MAX) {

						return (HIDPARSER_FAILURE);
					}

					i = rpt->no_of_usages++;
					ui = &(rpt->usage_descr[i]);

					hidparser_fill_usage_info(ui,
					    current->entity_item_attributes);

					ui->rptcnt /= found_usage;
					ui->collection_usage = collection_usage;
					ui->usage_id = HID_USAGE_ID(
					    usage_id[j]);

					/*
					 * This is an extended usage ie.
					 * usage page in upper 16 bits
					 * or-ed with usage in the lower
					 * 16 bits.
					 */
					if (usage_id[j] >> 16) {
						ui->usage_page =
						    HID_USAGE_PAGE(usage_id[j]);
					}

					rpt->report_id = report_id;
					valid_usage = 1;
				}

				if (found_usage_min && found_usage_max) {

					/* Put in usage list */
					if (rpt->no_of_usages >= USAGE_MAX) {

						return (HIDPARSER_FAILURE);
					}

					if (found_usage) {

						/* handle duplication */
						ui->usage_min = HID_USAGE_ID(
						    usage_min);
						ui->usage_max = HID_USAGE_ID(
						    usage_max);
					} else {
						i = rpt->no_of_usages++;
						ui = &(rpt->usage_descr[i]);

						hidparser_fill_usage_info(ui,
						    current->
						    entity_item_attributes);

						ui->collection_usage =
						    collection_usage;
						ui->usage_min = HID_USAGE_ID(
						    usage_min);
						ui->usage_max = HID_USAGE_ID(
						    usage_max);

						rpt->report_id = report_id;
						valid_usage = 1;
					}

					/*
					 * This is an extended usage ie.
					 * usage page in upper 16 bits
					 * or-ed with usage_max in the lower
					 * 16 bits.
					 */
					if (usage_max >> 16) {
						ui->usage_page =
						    HID_USAGE_PAGE(usage_max);
					}
				}
			}

			/*
			 * This main item contains no usage
			 * Fill in with usage "UNDEFINED".
			 * If report id is valid, only the
			 * main item with matched report id
			 * can be filled in.
			 */
			if (!valid_usage) {

				if (rpt->no_of_usages >= USAGE_MAX) {

					return (HIDPARSER_FAILURE);
				}

				i = rpt->no_of_usages++;
				ui = &(rpt->usage_descr[i]);

				hidparser_fill_usage_info(ui,
				    current->entity_item_attributes);

				ui->collection_usage = collection_usage;
				ui->usage_id = HID_USAGE_UNDEFINED;

				rpt->report_id = report_id;
			}

		}

		current = current->entity_item_right_sibling;

	} /* end while current */

	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_fill_usage_info():
 *	Fill in the mandatory item information for a main item.
 *	See HID 6.2.2.
 */
static void
hidparser_fill_usage_info(hidparser_usage_info_t *ui,
    entity_attribute_t *attribute)
{
	bzero(ui, sizeof (*ui));

	while (attribute) {
		switch (attribute->entity_attribute_tag) {
		case R_ITEM_LOGICAL_MINIMUM:
			ui->lmin = hidparser_find_signed_val(attribute);

			break;
		case R_ITEM_LOGICAL_MAXIMUM:
			ui->lmax = hidparser_find_signed_val(attribute);

			break;
		case R_ITEM_REPORT_COUNT:
			ui->rptcnt = hidparser_find_unsigned_val(attribute);

			break;
		case R_ITEM_REPORT_SIZE:
			ui->rptsz = hidparser_find_unsigned_val(attribute);

			break;
		case R_ITEM_USAGE_PAGE:
			ui->usage_page = hidparser_find_unsigned_val(attribute)
			    & 0xffff;

			break;
		}

		attribute = attribute->entity_attribute_next;
	}
}


/*
 * hidparser_get_report_id_list:
 *	Return a list of all report ids used for descriptor items
 *	corresponding to a main item.
 *
 * Arguments:
 *	parser_handle:
 *		hid parser handle
 *	main_item_type:
 *		type of report, either Input, Output, or Feature
 *	report_id_list:
 *		Filled in with a list of report ids found in the descriptor
 *
 * Return values:
 *	HIDPARSER_SUCCESS - returned success
 *	HIDPARSER_FAILURE - unspecified failure
 */
int
hidparser_get_report_id_list(hidparser_handle_t parser_handle,
    uint_t main_item_type, hidparser_report_id_list_t *report_id_list)
{

	if ((parser_handle == NULL) ||
	    (parser_handle->hidparser_handle_parse_tree == NULL)) {

		return (HIDPARSER_FAILURE);
	}

	report_id_list->no_of_report_ids = 0;

	return (hidparser_get_report_id_list_internal(
	    parser_handle->hidparser_handle_parse_tree,
	    main_item_type, report_id_list));
}


/*
 * hidparser_get_report_id_list_internal:
 *	internal function that generates list of all report ids
 */
int
hidparser_get_report_id_list_internal(entity_item_t *parser_handle,
    uint_t main_item_type, hidparser_report_id_list_t *id_lst)
{
	/* setup wrapper function */
	entity_item_t *current = parser_handle;
	entity_attribute_t *attribute;
	uint_t report_id = 0;
	int i = 0;
	int rval;

	while (current) {

		if (current->entity_item_type == R_ITEM_COLLECTION) {

			rval = hidparser_get_report_id_list_internal(
			    current->info.child, main_item_type, id_lst);
			if (rval != HIDPARSER_SUCCESS) {

				return (rval);
			}

		} else if (current->entity_item_type == main_item_type) {
			/* Match Item Type */
			attribute = current->entity_item_attributes;

			while (attribute != NULL) {

				if (attribute->entity_attribute_tag ==
				    R_ITEM_REPORT_ID) {

					/* Found a Report ID */
					report_id = attribute->
					    entity_attribute_value[0];

					/* Report ID already in list? */
					for (i = 0;
					    i < id_lst->no_of_report_ids;
					    i++) {
						if (report_id == id_lst->
						    report_id[i]) {

							break;
						}
					}

					if (i >= id_lst->no_of_report_ids) {
						/*
						 * New Report ID found, put
						 * in list
						 */
						if (i >= REPORT_ID_MAX) {

							return
							    (HIDPARSER_FAILURE);
						}

						id_lst->report_id[i] =
						    report_id;
						id_lst->no_of_report_ids++;
					}
				}

				attribute = attribute->entity_attribute_next;
			}
		}

		current = current->entity_item_right_sibling;

	} /* end while current */

	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_print_report_descr_handle:
 *	Functions to print the parse tree. Currently not
 *	being called.
 */
static int
hidparser_print_report_descr_handle(entity_item_t *handle, int indent_level)
{
	entity_item_t *current = handle;

	while (current) {
		if (current->info.child) {
			hidparser_print_entity(current, indent_level);
			/* do children */
			(void) hidparser_print_report_descr_handle(
			    current->info.child, indent_level+1);
		} else /* just a regular entity */ {
			hidparser_print_entity(current, indent_level);
		}
		current = current->entity_item_right_sibling;
	}

	return (HIDPARSER_SUCCESS);
}


#define	SPACE_PER_LEVEL 5

/*
 * hidparser_print_entity ;
 * Prints the entity items recursively
 */
static void
hidparser_print_entity(entity_item_t *entity, int indent_level)
{
	char indent_space[256];
	int count;
	entity_attribute_t *attr;

	indent_level *= SPACE_PER_LEVEL;

	for (count = 0; indent_level--; count++)
		indent_space[count] = ' ';

	indent_space[count] = 0;

	attr = entity->entity_item_attributes;
	while (attr) {
		hidparser_print_this_attribute(attr, indent_space);
		attr = attr->entity_attribute_next;
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, hparser_log_handle, "%s%s(0x%x)",
	    indent_space, items[entity->entity_item_type],
	    (entity->entity_item_params_leng ?
	    entity->entity_item_params[0] & 0xFF : 0x00));
}


/*
 * hidparser_print_this_attribute:
 *	Prints the attribute passed in the argument
 */
static void
hidparser_print_this_attribute(entity_attribute_t *attribute, char *ident_space)
{
	if (ident_space == NULL) {

		USB_DPRINTF_L3(PRINT_MASK_ALL, hparser_log_handle,
		    "%s(0x%X)",
		    items[attribute->entity_attribute_tag],
		    hidparser_find_unsigned_val(attribute));
	} else {
		USB_DPRINTF_L3(PRINT_MASK_ALL, hparser_log_handle,
		    "%s%s(0x%X)", ident_space,
		    items[attribute->entity_attribute_tag],
		    hidparser_find_unsigned_val(attribute));

	}
}


/*
 * The next few functions will be used for parsing using the
 * grammar:
 *
 *	Start			-> ReportDescriptor <EOF>
 *
 *	ReportDescriptor	-> ItemList
 *
 *	ItemList		-> Items MainItem ItemList
 *				   | epsilon
 *
 *	MainItem		-> BeginCollection ItemList  EndCollection
 *				  | Input
 *				  | Output
 *				  | Feature
 *
 *	Items			-> GlobalItem  Items
 *				   | LocalItem Items
 *				   | SetDelimiterOpen LocalItemList
 *					SetDelimiterClose Items
 *				   | epsilon
 *
 *	LocalItemList		-> LocalItem Temp2
 *
 *	Temp2			-> LocalItem Temp2
 *				   | epsilon
 *
 *	GlobalItem		-> UsagePage
 *				   | LogicalMinimum
 *				   | LogicalMaximum
 *				   | PhysicalMinimum
 *				   | PhysicalMaximum
 *				   | Unit
 *				   | Exponent
 *				   | ReportSize
 *				   | ReportCount
 *				   | ReportID
 *
 *	LocalItem		-> Usage
 *				   | UsageMinimum
 *				   | UsageMaximum
 *				   | DesignatorIndex
 *				   | DesignatorMinimum
 *				   | StringIndex
 *				   | StringMinimum
 *				   | StringMaximum
 *
 */


/*
 * hidparser_lookup_first:
 *	Looks up if token belongs to the FIRST of the function tag
 *	that is passed through the first argument
 */
static int
hidparser_lookup_first(int func_index, int token)
{
	int	*itemp;

	itemp = hid_first_list[func_index];
	while (*itemp != 0) {
		/* get the next terminal on the list */
		if (*itemp == token) {

			return (HIDPARSER_SUCCESS);
		}
		itemp++;
	}

	/* token is not on the FIRST list */

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_main:
 *	Function called from hidparser_parse_report_descriptor()
 *	to parse the Report Descriptor
 */
static int
hidparser_main(unsigned char *descriptor, size_t size, entity_item_t **item_ptr)
{
	hidparser_tok_t	*scan_ifp;
	int retval;

	scan_ifp = kmem_zalloc(sizeof (hidparser_tok_t), KM_SLEEP);
	scan_ifp->hidparser_tok_text =
	    kmem_zalloc(HIDPARSER_TEXT_LENGTH, KM_SLEEP);
	scan_ifp->hidparser_tok_max_bsize = size;
	scan_ifp->hidparser_tok_entity_descriptor = descriptor;

	*item_ptr = NULL;
	retval =  hidparser_ReportDescriptorDash(item_ptr, scan_ifp);

	/*
	 * Free the Local & Global item list
	 * It maybe the case that no tree has been built
	 * up but there have been allocation in the attribute
	 * & control lists
	 */
	if (scan_ifp->hidparser_tok_gitem_head) {
		hidparser_free_attribute_list(
		    scan_ifp->hidparser_tok_gitem_head);
	}

	if (scan_ifp->hidparser_tok_litem_head) {
		hidparser_free_attribute_list(
		    scan_ifp->hidparser_tok_litem_head);
	}
	kmem_free(scan_ifp->hidparser_tok_text, HIDPARSER_TEXT_LENGTH);
	kmem_free(scan_ifp, sizeof (hidparser_tok_t));

	return (retval);
}


/*
 * hidparser_ReportDescriptorDash:
 *	Synthetic start symbol, implements
 *	hidparser_ReportDescriptor <EOF>
 */
static int
hidparser_ReportDescriptorDash(entity_item_t **item_ptr,
    hidparser_tok_t *scan_ifp)
{

	if ((hidparser_ReportDescriptor(item_ptr, scan_ifp) ==
	    HIDPARSER_SUCCESS) && (scan_ifp->hidparser_tok_token == 0)) {

		return (HIDPARSER_SUCCESS);
	}

	/*
	 * In case of failure, free the kernel memory
	 * allocated for partial building of the tree,
	 * if any
	 */
	if (*item_ptr != NULL) {
		(void) hidparser_free_report_descr_handle(*item_ptr);
	}

	*item_ptr = NULL;

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_ReportDescriptor:
 *	Implements the Rule:
 *	ReportDescriptor -> ItemList
 */
static int
hidparser_ReportDescriptor(entity_item_t **item_ptr, hidparser_tok_t *scan_ifp)
{
	hidparser_scan(scan_ifp);

	/*
	 * We do not search for the token in FIRST(ReportDescriptor)
	 * since -
	 *
	 * FIRST(ReportDescriptor) == FIRST(ItemList)
	 * ReportDescriptor ----> ItemList
	 */
	if (hidparser_ItemList(item_ptr, scan_ifp) == HIDPARSER_SUCCESS) {

		return (HIDPARSER_SUCCESS);
	}

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_ItemList:
 *	Implements the Rule:
 *	ItemList -> Items MainItem ItemList | epsilon
 *
 *	This function constructs the tree on which depends the "hidparser"
 *	consumer functions. Basically the structure of the tree is
 *
 *	C--[RS]->EC--[RS]->C--[RS]->EC..(and so on)
 *	|
 *    [CH] <== This relationship is true for other "C's"
 *	|      also.
 *	v
 *     C/-------------/I/O/F <== [ Any of these ]
 *     |	      ------
 *     |		|
 *     v		v
 *    [CH      | RS]  [ RS ]
 *     C/I/O/F | EC    I/O/F
 *     |
 *     |
 *    and so on...
 *
 *	where	 C = Collection
 *		EC = EndCollection
 *		 I = Input
 *		 O = Output
 *		 F = Feature "Main" Items.
 *
 *	and the relationships are  [RS] for right sibling and [CH] for
 *	child. [CH | RS ] stands for "child or right sibling" with the
 *	possible values below it.
 */
static int
hidparser_ItemList(entity_item_t **item_ptr, hidparser_tok_t *scan_ifp)
{
	entity_item_t	*curr_ei, *cache_ei, *prev_ei, *tmp_ei;
	boolean_t	root_coll = B_FALSE;

	curr_ei = cache_ei = prev_ei = tmp_ei = NULL;

	while (scan_ifp->hidparser_tok_token != 0) {
		if (hidparser_Items(scan_ifp) == HIDPARSER_FAILURE) {

			return (HIDPARSER_FAILURE);
		}

		if (hidparser_MainItem(&curr_ei, scan_ifp) ==
		    HIDPARSER_FAILURE) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    hparser_log_handle,
			    "Invalid MAIN item 0x%x in input stream",
			    scan_ifp->hidparser_tok_token);

			return (HIDPARSER_FAILURE);
		}
		if (curr_ei->entity_item_type == R_ITEM_COLLECTION) {
			if (root_coll == B_FALSE) {
				*item_ptr = curr_ei;
				root_coll = B_TRUE;
			}
			curr_ei->prev_coll = cache_ei;
			cache_ei = curr_ei;

			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    hparser_log_handle,
			    "Start Collection:cache_ei = 0x%p,"
			    " curr_ei = 0x%p",
			    (void *)cache_ei, (void *)curr_ei);

			if (prev_ei == NULL) {
				prev_ei = curr_ei;

				continue;
			}
			if (prev_ei->entity_item_type ==
			    R_ITEM_COLLECTION) {
				prev_ei->info.child = curr_ei;
			} else {
				prev_ei->entity_item_right_sibling =
				    curr_ei;
			}
		} else if (curr_ei->entity_item_type ==
		    R_ITEM_END_COLLECTION) {
			tmp_ei = cache_ei->prev_coll;
			cache_ei->entity_item_right_sibling = curr_ei;
			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    hparser_log_handle,
			    "End Collection: cache_ei = 0x%p, "
			    "curr_ei = 0x%p",
			    (void *)cache_ei, (void *)curr_ei);
			if (tmp_ei != NULL) {
				/*
				 * As will be the case for final end
				 * collection.
				 */
				cache_ei = tmp_ei;
			}
			tmp_ei = NULL;
		} else {
			if (prev_ei == NULL) {
				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    hparser_log_handle,
				    "Invalid First MAIN item 0x%x",
				    scan_ifp->hidparser_tok_token);

				return (HIDPARSER_FAILURE);
			}
			if (prev_ei->entity_item_type ==
			    R_ITEM_COLLECTION) {
				USB_DPRINTF_L3(PRINT_MASK_ALL,
				    hparser_log_handle,
				    "Main Item: token = 0x%x, "
				    "curr_ei = 0x%p "
				    "will be the child of prev_ei "
				    "= 0x%p, "
				    "cache_ei being 0x%p",
				    curr_ei->entity_item_type,
				    (void *)curr_ei, (void *)prev_ei,
				    (void *)cache_ei);
				prev_ei->info.child = curr_ei;
			} else {
				USB_DPRINTF_L3(PRINT_MASK_ALL,
				    hparser_log_handle,
				    "Main Item: token = 0x%x, "
				    "curr_ei = 0x%p "
				    "will be the right sibling of "
				    "prev_ei = 0x%p, "
				    "cache_ei being 0x%p",
				    curr_ei->entity_item_type,
				    (void *)curr_ei, (void *)prev_ei,
				    (void *)cache_ei);
				prev_ei->entity_item_right_sibling =
				    curr_ei;
			}
		}
		prev_ei = curr_ei;
	}
	if (*item_ptr != cache_ei) {
		/* Something wrong happened */
		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "Failed to parse report descriptor");

		return (HIDPARSER_FAILURE);
	}
	(void) hidparser_print_report_descr_handle(cache_ei, 0);

	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_MainItem:
 *	Implements the Rule:
 *	MainItem ->	BeginCollection ItemList  EndCollection
 *			| Input
 *			| Output
 *			| Feature
 */
static int
hidparser_MainItem(entity_item_t **item_ptr, hidparser_tok_t *scan_ifp)
{
	switch (scan_ifp->hidparser_tok_token) {
		case R_ITEM_INPUT:
			/* FALLTHRU */
		case R_ITEM_OUTPUT:
			/* FALLTHRU */
		case R_ITEM_FEATURE:
		case R_ITEM_COLLECTION:
		case R_ITEM_END_COLLECTION:
			*item_ptr = hidparser_allocate_entity(scan_ifp);
			USB_DPRINTF_L4(PRINT_MASK_ALL, hparser_log_handle,
			    "hidparser_MainItem:index = 0x%lx token = 0x%x",
			    scan_ifp->hidparser_tok_index -
			    (*item_ptr)->entity_item_params_leng - 1,
			    scan_ifp->hidparser_tok_token);
			hidparser_scan(scan_ifp);
			hidparser_global_err_check(*item_ptr);
			hidparser_local_err_check(*item_ptr);
			hidparser_mainitem_err_check(*item_ptr);

			return (HIDPARSER_SUCCESS);

		default:
			break;
	}

	*item_ptr = NULL;

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_Items:
 *	Implements the Rule:
 *	Items ->	GlobalItem  Items
 *			| LocalItem Items
 *			| SetDelimiterOpen LocalItemList
 *				SetDelimiterClose Items
 *			| epsilon
 */
static int
hidparser_Items(hidparser_tok_t *scan_ifp)
{
	boolean_t delim_pre = B_FALSE;

	int	token = scan_ifp->hidparser_tok_token;

	while (hidparser_lookup_first(HIDPARSER_ITEMS, token) ==
	    HIDPARSER_SUCCESS) {
		if (token == R_ITEM_SET_DELIMITER) {
			if (delim_pre == B_FALSE) {
				if (scan_ifp->hidparser_tok_text[0] != 1) {
					hidparser_error_delim(NULL,
					    HIDPARSER_DELIM_ERR1);
				} else {
					delim_pre = B_TRUE;
				}
			} else {
				if (scan_ifp->hidparser_tok_text[0] !=
				    0) {
					hidparser_error_delim(NULL,
					    HIDPARSER_DELIM_ERR2);
				} else {
					delim_pre = B_FALSE;
				}
			}
			(void) hidparser_LocalItem(scan_ifp);
			token = scan_ifp->hidparser_tok_token;
		} else if (hidparser_GlobalItem(scan_ifp) ==
		    HIDPARSER_SUCCESS) {
			token = scan_ifp->hidparser_tok_token;
		} else if (hidparser_LocalItem(scan_ifp) == HIDPARSER_SUCCESS) {
			token = scan_ifp->hidparser_tok_token;
		}
	}

	return (HIDPARSER_SUCCESS);	/* epsilon */
}


/*
 * hidparser_GlobalItem:
 *	Implements the Rule:
 *	GlobalItem ->	UsagePage
 *			| LogicalMinimum
 *			| LocgicalMaximum
 *			| PhysicalMinimum
 *			| PhysicalMaximum
 *			| Unit
 *			| Exponent
 *			| ReportSize
 *			| ReportCount
 *			| ReportID
 */
static int
hidparser_GlobalItem(hidparser_tok_t *scan_ifp)
{

	int i;
	entity_attribute_stack_t	*elem;

	switch (scan_ifp->hidparser_tok_token) {
		case R_ITEM_USAGE_PAGE:
			/* Error check */
			for (i = 0; i < scan_ifp->hidparser_tok_leng; i++) {
				/* Undefined data value: 0 */
				if (scan_ifp->hidparser_tok_text[i] == 0) {
					hidparser_report_err(
					    HIDPARSER_ERR_WARN,
					    HIDPARSER_ERR_STANDARD,
					    R_ITEM_USAGE_PAGE,
					    0,
					    "Data field should be non-Zero");
				}
				/* Reserved values 0x0A-0xFE */
				else if ((scan_ifp->hidparser_tok_text[i] >=
				    0x0a) &&
				    (scan_ifp->hidparser_tok_text[i] <=
				    0xFE)) {
					hidparser_report_err(
					    HIDPARSER_ERR_WARN,
					    HIDPARSER_ERR_STANDARD,
					    R_ITEM_USAGE_PAGE,
					    1,
					    "Data field should not use "
					    "reserved values");
				}
			}
			break;
		case R_ITEM_UNIT:
			/* FALLTHRU */
		case R_ITEM_EXPONENT:
			/*
			 * Error check:
			 * Nibble 7 should be zero
			 */
			if (scan_ifp->hidparser_tok_leng == 4) {
				if ((scan_ifp->hidparser_tok_text[3] &
				    0xf0) != 0) {
					hidparser_report_err(
					    HIDPARSER_ERR_WARN,
					    HIDPARSER_ERR_STANDARD,
					    scan_ifp->hidparser_tok_token,
					    0,
					    "Data field reserved bits should "
					    "be Zero");
				}
			}
			break;
		case R_ITEM_REPORT_COUNT:
			/*
			 * Error Check:
			 * Report Count should be nonzero
			 */
			for (i = 0; i < scan_ifp->hidparser_tok_leng; i++) {
				if (scan_ifp->hidparser_tok_text[i])
					break;
			}
			if (i == scan_ifp->hidparser_tok_leng) {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    R_ITEM_REPORT_COUNT,
				    0,
				    "Report Count = 0");
			}
			break;
		case R_ITEM_REPORT_ID:
			/*
			 * Error check:
			 * Report Id should be nonzero & <= 255
			 */
			if (scan_ifp->hidparser_tok_leng != 1)	{
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    R_ITEM_REPORT_ID,
				    1,
				    "Must be contained in a byte");
			}
			if (!scan_ifp->hidparser_tok_text[0]) {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    R_ITEM_REPORT_ID,
				    0,
				    "Report Id must be non-zero");
			}
			break;
		case R_ITEM_LOGICAL_MINIMUM:
			break;
		case R_ITEM_LOGICAL_MAXIMUM:
			break;
		case R_ITEM_PHYSICAL_MINIMUM:
			break;
		case R_ITEM_PHYSICAL_MAXIMUM:
			break;
		case R_ITEM_REPORT_SIZE:
			break;
		case R_ITEM_PUSH:
			if (scan_ifp->hidparser_tok_leng != 0)	{
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    scan_ifp->hidparser_tok_token,
				    0,
				    "Data Field size should be zero");
			} else {
				elem = (entity_attribute_stack_t *)kmem_zalloc(
				    sizeof (entity_attribute_stack_t),
				    KM_SLEEP);

				elem->list = hidparser_cp_attribute_list(
				    scan_ifp->hidparser_tok_gitem_head);
				if (scan_ifp->hidparser_head) {
					elem->next = scan_ifp->hidparser_head;
				}
				scan_ifp->hidparser_head = elem;
			}

			break;
		case R_ITEM_POP:
			if (scan_ifp->hidparser_tok_leng != 0)	{
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    scan_ifp->hidparser_tok_token,
				    0,
				    "Data Field size should be zero");
			} else {
				/* Free the current global list */
				hidparser_free_attribute_list(scan_ifp->
				    hidparser_tok_gitem_head);
				scan_ifp->hidparser_tok_gitem_head =
				    scan_ifp->hidparser_head->list;
				scan_ifp->hidparser_head->list = NULL;
				elem = scan_ifp->hidparser_head;
				scan_ifp->hidparser_head = elem->next;
				kmem_free(elem,
				    sizeof (entity_attribute_stack_t));
			}

			break;
		default:

			return (HIDPARSER_FAILURE);

			/*NOTREACHED*/
	}

	hidparser_add_attribute(scan_ifp);
	USB_DPRINTF_L4(PRINT_MASK_ALL, hparser_log_handle,
	    "hidparser_GlobalItem:index = 0x%lx token = 0x%x",
	    scan_ifp->hidparser_tok_index -
	    scan_ifp->hidparser_tok_leng - 1,
	    scan_ifp->hidparser_tok_token);
	hidparser_scan(scan_ifp);

	return (HIDPARSER_SUCCESS);
}


/*
 * hidparser_LocalItem:
 *	Implements the Rule:
 *	LocalItem ->	Usage
 *			| UsageMinimum
 *			| UsageMaximum
 *			| DesignatorIndex
 *			| DesignatorMinimum
 *			| StringIndex
 *			| StringMinimum
 *			| StringMaximum
 */
static int
hidparser_LocalItem(hidparser_tok_t *scan_ifp)
{
	int i;

	switch (scan_ifp->hidparser_tok_token) {
		case R_ITEM_USAGE:
			/*
			 * Error Check:
			 * Data Field should be nonzero
			 */
			for (i = 0; i < scan_ifp->hidparser_tok_leng; i++) {
				if (scan_ifp->hidparser_tok_text[i])
					break;
			}
			if (i == scan_ifp->hidparser_tok_leng) {
				hidparser_report_err(
				    HIDPARSER_ERR_WARN,
				    HIDPARSER_ERR_STANDARD,
				    R_ITEM_USAGE,
				    0,
				    "Data Field should be non-zero");
			}
			/* FALLTHRU */
		case R_ITEM_USAGE_MIN:
			/* FALLTHRU */
		case R_ITEM_USAGE_MAX:
			/* FALLTHRU */
		case R_ITEM_DESIGNATOR_INDEX:
			/* FALLTHRU */
		case R_ITEM_DESIGNATOR_MIN:
			/* FALLTHRU */
		case R_ITEM_STRING_INDEX:
			/* FALLTHRU */
		case R_ITEM_STRING_MIN:
			/* FALLTHRU */
		case R_ITEM_STRING_MAX:
			/* FALLTHRU */
		case R_ITEM_SET_DELIMITER:
			hidparser_add_attribute(scan_ifp);
			USB_DPRINTF_L4(PRINT_MASK_ALL, hparser_log_handle,
			    "hidparser_LocalItem:index = 0x%lx token = 0x%x",
			    scan_ifp->hidparser_tok_index -
			    scan_ifp->hidparser_tok_leng - 1,
			    scan_ifp->hidparser_tok_token);
			hidparser_scan(scan_ifp);

			return (HIDPARSER_SUCCESS);

			/*NOTREACHED*/
		default:
			break;
	}

	return (HIDPARSER_FAILURE);
}


/*
 * hidparser_allocate_entity:
 *	Allocate Item of type 'type', length 'leng' and
 *	params 'text'. Fill in the attributes allocated
 *	so far from both the local and global item lists.
 *	Make the child and sibling of the item NULL.
 */
static entity_item_t *
hidparser_allocate_entity(hidparser_tok_t *scan_ifp)
{
	entity_item_t *entity;
	entity_attribute_t *aend;

	int	entity_type = scan_ifp->hidparser_tok_token;
	unsigned char	*text = scan_ifp->hidparser_tok_text;
	int	len = scan_ifp->hidparser_tok_leng;

	entity = kmem_zalloc(sizeof (entity_item_t), KM_SLEEP);
	entity->entity_item_type = entity_type;
	entity->entity_item_params_leng = len;

	if (len != 0) {
		entity->entity_item_params = kmem_zalloc(len, KM_SLEEP);
		(void) bcopy(text, entity->entity_item_params, len);
	}

	/*
	 * Copy attributes from entity attribute state table if not
	 * end collection.
	 */
	if (entity_type != R_ITEM_END_COLLECTION) {
		entity->entity_item_attributes = hidparser_cp_attribute_list(
		    scan_ifp->hidparser_tok_gitem_head);

		/*
		 * append the control attributes, then clear out the control
		 * attribute state table list
		 */
		if (entity->entity_item_attributes) {
			aend = hidparser_find_attribute_end(
			    entity->entity_item_attributes);
			aend->entity_attribute_next =
			    scan_ifp->hidparser_tok_litem_head;
			scan_ifp->hidparser_tok_litem_head = NULL;
		} else {
			entity->entity_item_attributes =
			    scan_ifp->hidparser_tok_litem_head;
			scan_ifp->hidparser_tok_litem_head = NULL;
		}
	}

	entity->info.child = entity->entity_item_right_sibling = 0;

	return (entity);
}


/*
 * hidparser_add_attribute:
 *	Add an attribute to the global or local item list
 *	If the last 4th bit from right is 1, add to the local item list
 *	Else add to the global item list
 */
static void
hidparser_add_attribute(hidparser_tok_t	*scan_ifp)
{
	entity_attribute_t *newattrib, **previous, *elem;
	int	entity = scan_ifp->hidparser_tok_token;
	unsigned char	*text = scan_ifp->hidparser_tok_text;
	int	len = scan_ifp->hidparser_tok_leng;

	if (len == 0) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "hidparser_add_attribute: len = 0 for item = 0x%x",
		    entity);

		return;
	}

	if (entity & HIDPARSER_ISLOCAL_MASK) {
		previous = &scan_ifp->hidparser_tok_litem_head;
	} else {
		previous = &scan_ifp->hidparser_tok_gitem_head;
	}

	elem = *previous;

	/*
	 * remove attribute if it is already on list, except
	 * for control attributes(local items), as we could have
	 * multiple usages...
	 * unless we want to hassle with checking for unique parameters.
	 */
	while (elem) {
		if (elem->entity_attribute_tag == entity &&
		    !(entity & HIDPARSER_ISLOCAL_MASK)) {
			*previous = elem->entity_attribute_next;
			kmem_free(elem->entity_attribute_value,
			    elem->entity_attribute_length);
			kmem_free(elem, sizeof (entity_attribute_t));
			elem = *previous;
		} else {
			previous = &elem->entity_attribute_next;
			elem = elem->entity_attribute_next;
		}
	}

	/* create new attribute for this entry */
	newattrib = hidparser_alloc_attrib_list(1);
	newattrib->entity_attribute_tag = entity;
	newattrib->entity_attribute_value = kmem_zalloc(len, KM_SLEEP);
	(void) bcopy(text, newattrib->entity_attribute_value, len);
	newattrib->entity_attribute_length = len;

	/* attach to end of list */
	*previous = newattrib;
}


/*
 * hidparser_alloc_attrib_list:
 *	Allocate space for n attributes , create a linked list and
 *	return the head
 */
static entity_attribute_t *
hidparser_alloc_attrib_list(int count)
{
	entity_attribute_t *head, *current;

	if (count <= 0) {

		return (NULL);
	}

	head = kmem_zalloc(sizeof (entity_attribute_t), KM_SLEEP);
	count--;
	current = head;
	while (count--) {
		current->entity_attribute_next = kmem_zalloc(
		    sizeof (entity_attribute_t), KM_SLEEP);
		current = current->entity_attribute_next;
	}
	current->entity_attribute_next = NULL;

	return (head);
}


/*
 * hidparser_cp_attribute_list:
 *	Copies the Global item list pointed to by head
 *	We create a clone of the global item list here
 *	because we want to retain the Global items to
 *	the next Main Item.
 */
static entity_attribute_t *
hidparser_cp_attribute_list(entity_attribute_t *head)
{
	entity_attribute_t *return_value, *current_src, *current_dst;

	if (!head) {

		return (NULL);
	}

	current_src = head;
	current_dst = return_value = hidparser_alloc_attrib_list(1);

	while (current_src) {
		current_dst->entity_attribute_tag =
		    current_src->entity_attribute_tag;
		current_dst->entity_attribute_length =
		    current_src->entity_attribute_length;
		current_dst->entity_attribute_value = kmem_zalloc(
		    current_dst->entity_attribute_length, KM_SLEEP);
		(void) bcopy(current_src->entity_attribute_value,
		    current_dst->entity_attribute_value,
		    current_src->entity_attribute_length);
		if (current_src->entity_attribute_next) {
			current_dst->entity_attribute_next =
			    hidparser_alloc_attrib_list(1);
		} else {
			current_dst->entity_attribute_next = NULL;
		}
		current_src = current_src->entity_attribute_next;
		current_dst = current_dst->entity_attribute_next;
	}

	return (return_value);
}


/*
 * hidparser_find_attribute_end:
 *	Find the last item in the attribute list pointed to by head
 */
static entity_attribute_t *
hidparser_find_attribute_end(entity_attribute_t *head)
{
	if (head == NULL) {

		return (NULL);
	}
	while (head->entity_attribute_next != NULL) {
		head = head->entity_attribute_next;
	}

	return (head);
}


/*
 * hidparser_free_report_descr_handle:
 *	Free the parse tree pointed to by handle
 */
static void
hidparser_free_report_descr_handle(entity_item_t *handle)
{
	entity_item_t *next, *current, *child;

	current = handle;

	while (current) {
		child = current->info.child;
		next = current->entity_item_right_sibling;
		if (current->entity_item_type == R_ITEM_COLLECTION) {
			if (current->entity_item_params != NULL)
				kmem_free(current->entity_item_params,
				    current->entity_item_params_leng);
			if (current->entity_item_attributes != NULL)
				hidparser_free_attribute_list(
				    current->entity_item_attributes);
			USB_DPRINTF_L4(PRINT_MASK_ALL, hparser_log_handle,
			    "FREE 1: %s",
			    items[current->entity_item_type]);
			kmem_free(current, sizeof (entity_item_t));
			(void) hidparser_free_report_descr_handle(child);
		} else {
			if (current->entity_item_params != NULL) {
				kmem_free(current->entity_item_params,
				    current->entity_item_params_leng);
			}
			if (current->entity_item_attributes != NULL) {
				hidparser_free_attribute_list(
				    current->entity_item_attributes);
			}
			USB_DPRINTF_L4(PRINT_MASK_ALL,
			    hparser_log_handle, "FREE 2: %s",
			    items[current->entity_item_type]);
			kmem_free(current, sizeof (entity_item_t));
		}
		current = next;
	}

}


/*
 * hidparser_free_attribute_list:
 *	Free the attribute list pointed to by head
 */
static void
hidparser_free_attribute_list(entity_attribute_t *head)
{
	entity_attribute_t *next, *current;

	current = head;

	while (current) {
		next = current->entity_attribute_next;
		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    hparser_log_handle, "FREE: %s value_length = %d",
		    items[current->entity_attribute_tag],
		    current->entity_attribute_length);

		if (current->entity_attribute_value != NULL) {
			USB_DPRINTF_L4(PRINT_MASK_ALL,
			    hparser_log_handle,
			    "\tvalue = 0x%x",
			    current->entity_attribute_value[0]);
			kmem_free(current->entity_attribute_value,
			    current->entity_attribute_length);
		}

		kmem_free(current, sizeof (entity_attribute_t));
		current = next;
	}
}


/*
 * hidparser_initialize_items:
 *	Initialize items array before start scanning and parsing.
 *	This array of strings are used for printing purpose.
 */
static void
hidparser_initialize_items(void)
{
	items[R_ITEM_USAGE] = "Usage";
	items[R_ITEM_USAGE_MIN] = "Usage Minimum";
	items[R_ITEM_USAGE_MAX] = "Usage Maximum";
	items[R_ITEM_DESIGNATOR_INDEX] = "Designator Index";
	items[R_ITEM_DESIGNATOR_MIN] = "Designator Minimum";
	items[R_ITEM_DESIGNATOR_MAX] = "Designator Maximum";
	items[R_ITEM_STRING_INDEX] = "String Index";
	items[R_ITEM_STRING_MIN] = "String Minimum";
	items[R_ITEM_STRING_MAX] = "String Maximum";


	items[R_ITEM_USAGE_PAGE] = "Usage Page";
	items[R_ITEM_LOGICAL_MINIMUM] = "Logical Minimum";
	items[R_ITEM_LOGICAL_MAXIMUM] = "Logical Maximum";
	items[R_ITEM_PHYSICAL_MINIMUM] = "Physical Minimum";
	items[R_ITEM_PHYSICAL_MAXIMUM] = "Physical Maximum";
	items[R_ITEM_EXPONENT] = "Exponent";
	items[R_ITEM_UNIT] = "Unit";
	items[R_ITEM_REPORT_SIZE] = "Report Size";
	items[R_ITEM_REPORT_ID] = "Report Id";
	items[R_ITEM_REPORT_COUNT] = "Report Count";
	items[R_ITEM_PUSH] = "Push";
	items[R_ITEM_POP] = "Pop";


	items[R_ITEM_INPUT] = "Input";
	items[R_ITEM_OUTPUT] = "Output";
	items[R_ITEM_COLLECTION] = "Collection";
	items[R_ITEM_FEATURE] = "Feature";
	items[R_ITEM_END_COLLECTION] = "End Collection";

	items[R_ITEM_SET_DELIMITER] = "Delimiter";
}


/*
 * hidparser_scan:
 *	This function scans the input entity descriptor, sees the data
 *	length, returns the next token, data bytes and length in the
 *	scan_ifp structure.
 */
static void
hidparser_scan(hidparser_tok_t	*scan_ifp)
{
	int count;
	int ch;
	int parsed_length;
	unsigned char *parsed_text;
	unsigned char *entity_descriptor;
	char err_str[32];
	size_t	entity_buffer_size, index;

	index = scan_ifp->hidparser_tok_index;
	entity_buffer_size = scan_ifp->hidparser_tok_max_bsize;
	parsed_length = 0;
	parsed_text = scan_ifp->hidparser_tok_text;
	entity_descriptor = scan_ifp->hidparser_tok_entity_descriptor;

next_item:
	if (index <= entity_buffer_size -1) {

		ch = 0xFF & entity_descriptor[index];
		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    hparser_log_handle, "scanner: index  = 0x%lx ch = 0x%x",
		    index, ch);

		index++;

		/*
		 * Error checking:
		 * Unrecognized items should be passed over
		 * by the parser.
		 * Section 5.4
		 */
		if (!(hidparser_isvalid_item(ch))) {
			(void) sprintf(err_str, "%s: 0x%2x",
			    "Unknown or reserved item", ch);
			hidparser_report_err(HIDPARSER_ERR_ERROR,
			    HIDPARSER_ERR_STANDARD, 0, 0x3F, err_str);
			goto next_item;
		}

		if (ch == EXTENDED_ITEM) {
			parsed_length = entity_descriptor[index++];
			ch = entity_descriptor[index++];
			hidparser_report_err(HIDPARSER_ERR_WARN,
			    HIDPARSER_ERR_STANDARD,
			    0,
			    0x3E,
			    "Long item defined");
		} else {
			parsed_length = ch & 0x03;
			USB_DPRINTF_L4(PRINT_MASK_ALL,
			    hparser_log_handle,
			    "scanner: parsed_length = %x", parsed_length);
			/* 3 really means 4.. see p.21 HID */
			if (parsed_length == 3)
				parsed_length++;
		}
		for (count = 0; count < parsed_length; count++) {
			parsed_text[count] = entity_descriptor[index];
			USB_DPRINTF_L4(PRINT_MASK_ALL, hparser_log_handle,
			    "scanner: parsed_text[%d] = 0x%x,"
			    "index = 0x%lx",
			    count, parsed_text[count], index);
			index++;
		}

		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    hparser_log_handle, "scanner: lexical analyzer found 0x%x "
		    "before translation", ch);

		scan_ifp->hidparser_tok_index = index;
		scan_ifp->hidparser_tok_leng = parsed_length;
		scan_ifp->hidparser_tok_token = ch & 0xFC;
		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    hparser_log_handle, "scanner: aindex  = 0x%lx", index);
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    hparser_log_handle, "scanner: eindex  = 0x%lx", index);
		scan_ifp->hidparser_tok_leng = 0;
		scan_ifp->hidparser_tok_token = 0;	/* EOF */
	}
}


/*
 * hidparser_report_err:
 *	Construct and print the error code
 *	Ref: Hidview error check list
 */
static void
hidparser_report_err(int err_level, int err_type, int tag, int subcode,
    char *msg)
{
	unsigned int	BmParserErrorCode = 0;

	if (err_level) {
		BmParserErrorCode |= HIDPARSER_ERR_ERROR;
	}
	if (err_type) {
		BmParserErrorCode |= HIDPARSER_ERR_STANDARD;
	}
	BmParserErrorCode |= (tag << 8) & HIDPARSER_ERR_TAG_MASK;
	BmParserErrorCode |= subcode & HIDPARSER_ERR_SUBCODE_MASK;

	if (err_level) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "err code = 0x%4x, err str = %s",
		    BmParserErrorCode, msg);

	} else {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "wrn code = 0x%4x, wrn str = %s",
		    BmParserErrorCode, msg);
	}
}


/*
 * hidparser_isvalid_item:
 *	Find if the item tag is a valid one
 */
static int
hidparser_isvalid_item(int tag)
{
	if (tag == EXTENDED_ITEM) {

		return (1);
	}

	tag &= 0xFC;
	if ((tag == R_ITEM_INPUT) ||
	    (tag == R_ITEM_OUTPUT) ||
	    (tag == R_ITEM_COLLECTION) ||
	    (tag == R_ITEM_FEATURE) ||
	    (tag == R_ITEM_END_COLLECTION) ||
	    (tag == R_ITEM_USAGE_PAGE) ||
	    (tag == R_ITEM_LOGICAL_MINIMUM) ||
	    (tag == R_ITEM_LOGICAL_MAXIMUM) ||
	    (tag == R_ITEM_PHYSICAL_MINIMUM) ||
	    (tag == R_ITEM_PHYSICAL_MAXIMUM) ||
	    (tag == R_ITEM_EXPONENT) ||
	    (tag == R_ITEM_UNIT) ||
	    (tag == R_ITEM_REPORT_SIZE) ||
	    (tag == R_ITEM_REPORT_ID) ||
	    (tag == R_ITEM_REPORT_COUNT) ||
	    (tag == R_ITEM_PUSH) ||
	    (tag == R_ITEM_POP) ||
	    (tag == R_ITEM_USAGE) ||
	    (tag == R_ITEM_USAGE_MIN) ||
	    (tag == R_ITEM_USAGE_MAX) ||
	    (tag == R_ITEM_DESIGNATOR_INDEX) ||
	    (tag == R_ITEM_DESIGNATOR_MIN) ||
	    (tag == R_ITEM_DESIGNATOR_MAX) ||
	    (tag == R_ITEM_STRING_INDEX) ||
	    (tag == R_ITEM_STRING_MIN) ||
	    (tag == R_ITEM_STRING_MAX) ||
	    (tag == R_ITEM_SET_DELIMITER)) {

		return (1);
	} else {

		return (0);
	}
}


/*
 * hidparser_lookup_attribute:
 *	Takes an item pointer(report structure) and a tag(e.g Logical
 *	Min) as input. Returns the corresponding attribute structure.
 *	Presently used for error checking only.
 */
static entity_attribute_t *
hidparser_lookup_attribute(entity_item_t *item, int attr_tag)
{
	entity_attribute_t *temp;

	if (item == NULL) {

		return (NULL);
	}

	temp = item->entity_item_attributes;
	while (temp != NULL) {
		if (temp->entity_attribute_tag == attr_tag) {

			return (temp);
		}

		temp = temp->entity_attribute_next;
	}

	return (NULL);
}


/*
 * hidparser_global_err_check:
 *	Error checking for Global Items that need to be
 *	performed in MainItem
 */
static void
hidparser_global_err_check(entity_item_t *mainitem)
{
	hidparser_check_minmax_val_signed(mainitem, R_ITEM_LOGICAL_MINIMUM,
	    R_ITEM_LOGICAL_MAXIMUM, 0, 0);
	hidparser_check_minmax_val_signed(mainitem, R_ITEM_PHYSICAL_MINIMUM,
	    R_ITEM_PHYSICAL_MAXIMUM, 0, 0);
	hidparser_check_correspondence(mainitem, R_ITEM_PHYSICAL_MINIMUM,
	    R_ITEM_PHYSICAL_MAXIMUM, 0, 0,
	    "Must have a corresponding Physical min",
	    "Must have a corresponding Physical max");
	hidparser_check_correspondence(mainitem, R_ITEM_PUSH, R_ITEM_POP,
	    1, 0, "Should have a corresponding Pop",
	    "Must have a corresponding Push");

}


/*
 * hidparser_mainitem_err_check:
 *	Error checking for Main Items
 */
static void
hidparser_mainitem_err_check(entity_item_t *mainitem)
{
	int	itemmask = 0;
	entity_attribute_t *attr;

	attr = mainitem->entity_item_attributes;

	if (attr != NULL) {
		while (attr) {
			switch (attr->entity_attribute_tag) {
				case R_ITEM_LOGICAL_MINIMUM:
					itemmask |= 0x01;
					break;
				case R_ITEM_LOGICAL_MAXIMUM:
					itemmask |= 0x02;
					break;
				case R_ITEM_REPORT_SIZE:
					itemmask |= 0x04;
					break;
				case R_ITEM_REPORT_COUNT:
					itemmask |= 0x08;
					break;
				case R_ITEM_USAGE_PAGE:
					itemmask |= 0x10;
					break;
				default:
					break;
			} /* switch */
			attr = attr->entity_attribute_next;
		} /* while */
	} /* if */

	if ((mainitem->entity_item_type == R_ITEM_COLLECTION) ||
	    (mainitem->entity_item_type == R_ITEM_END_COLLECTION)) {

		return;
	}
	if (itemmask != 0x1f) {
			hidparser_report_err(
			    HIDPARSER_ERR_ERROR,
			    HIDPARSER_ERR_STANDARD,
			    mainitem->entity_item_type,
			    0,
			    "Required Global/Local items must be defined");
	}
}


/*
 * hidparser_local_err_check:
 *	Error checking for Local items that is done when a MainItem
 *	is encountered
 */
static void
hidparser_local_err_check(entity_item_t *mainitem)
{
	hidparser_check_correspondence(mainitem, R_ITEM_USAGE_MIN,
	    R_ITEM_USAGE_MAX, 0, 0,
	    "Must have a corresponding Usage Min",
	    "Must have a corresponding Usage Max");
	hidparser_check_minmax_val(mainitem, R_ITEM_USAGE_MIN,
	    R_ITEM_USAGE_MAX, 1, 1);
	hidparser_check_correspondence(mainitem, R_ITEM_DESIGNATOR_MIN,
	    R_ITEM_DESIGNATOR_MAX, 0, 0,
	    "Must have a corresponding Designator min",
	    "Must have a corresponding Designator Max");
	hidparser_check_minmax_val(mainitem, R_ITEM_DESIGNATOR_MIN,
	    R_ITEM_DESIGNATOR_MAX, 1, 1);
	hidparser_check_correspondence(mainitem, R_ITEM_STRING_MIN,
	    R_ITEM_STRING_MAX, 0, 0,
	    "Must have a corresponding String min",
	    "Must have a corresponding String Max");
	hidparser_check_minmax_val(mainitem, R_ITEM_STRING_MIN,
	    R_ITEM_STRING_MAX, 1, 1);
}


/*
 * hidparser_find_unsigned_val:
 *	Find the value for multibyte data
 *	Ref: Section 5.8 of HID Spec 1.0
 */
static unsigned int
hidparser_find_unsigned_val(entity_attribute_t *attr)
{
	char *text;
	int len, i;
	unsigned int ret = 0;

	text = attr->entity_attribute_value;
	len = attr->entity_attribute_length;
	for (i = 0; i < len; i++) {
		ret |= ((text[i] & 0xff) << (8*i));
	}

	return (ret);
}


/*
 * hidparser_find_signed_val:
 *	Find the value for signed multibyte data
 *	Ref: Section 5.8 of HID Spec 1.0
 */
static signed int
hidparser_find_signed_val(entity_attribute_t *attr)
{
	char *text;
	int len, i;
	int ret = 0;

	text = attr->entity_attribute_value;
	len = attr->entity_attribute_length;

	for (i = 0; i < len - 1; i++) {
		ret |= ((text[i] & 0xff) << (8 * i));
	}

	if (len > 0) {
		ret |= (text[i] << (8 * i));
	}

	return (ret);
}


/*
 * hidparser_check_correspondence:
 *	Check if the item item2 corresponding to item1 exists and vice versa
 *	If not report the appropriate error
 */
static void
hidparser_check_correspondence(entity_item_t *mainitem, int item_tag1,
    int item_tag2, int val1, int val2, char *str1, char *str2)
{
	entity_attribute_t *temp1, *temp2;

	temp1 = hidparser_lookup_attribute(mainitem, item_tag1);
	temp2 = hidparser_lookup_attribute(mainitem, item_tag2);
	if ((temp1 != NULL) && (temp2 == NULL)) {
		hidparser_report_err(
		    HIDPARSER_ERR_ERROR,
		    HIDPARSER_ERR_STANDARD,
		    item_tag1,
		    val1,
		    str1);
	}
	if ((temp2 != NULL) && (temp1 == NULL)) {
		hidparser_report_err(
		    HIDPARSER_ERR_ERROR,
		    HIDPARSER_ERR_STANDARD,
		    item_tag2,
		    val2,
		    str2);
	}
}


/*
 * hidparser_check_minmax_val:
 *	Check if the Min value <= Max and vice versa
 *	Print for warnings and errors have been taken care separately.
 */
static void
hidparser_check_minmax_val(entity_item_t *mainitem, int item_tag1,
    int item_tag2, int val1, int val2)
{
	entity_attribute_t *temp1, *temp2;

	temp1 = hidparser_lookup_attribute(mainitem, item_tag1);
	temp2 = hidparser_lookup_attribute(mainitem, item_tag2);
	if ((temp1 != NULL) && (temp2 != NULL)) {
		if (hidparser_find_unsigned_val(temp1) >
		    hidparser_find_unsigned_val(temp2)) {
			if ((item_tag1 == R_ITEM_LOGICAL_MINIMUM) ||
			    (item_tag1 == R_ITEM_PHYSICAL_MINIMUM)) {
				hidparser_report_err(
				    HIDPARSER_ERR_WARN,
				    HIDPARSER_ERR_STANDARD,
				    item_tag1,
				    val1,
				    "unsigned: Min should be <= to Max");
			} else {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    item_tag1,
				    val1,
				    "Min must be <= to Max");
			}
		}
		if (hidparser_find_unsigned_val(temp2) <
		    hidparser_find_unsigned_val(temp1)) {
			if ((item_tag2 == R_ITEM_LOGICAL_MAXIMUM) ||
			    (item_tag2 == R_ITEM_PHYSICAL_MAXIMUM)) {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    item_tag2,
				    val2,
				    "unsigned: Max should be >= to Min");
			} else {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    item_tag2,
				    val2,
				    "Max must be >= to Min");
			}
		}
	}	/* if (temp1 != NULL) && (temp2 != NULL) */
}


/*
 * hidparser_check_minmax_val_signed:
 *	Check if the Min value <= Max and vice versa
 *	Print for warnings and errors have been taken care separately.
 */
static void
hidparser_check_minmax_val_signed(entity_item_t *mainitem, int item_tag1,
    int item_tag2, int val1, int val2)
{
	entity_attribute_t *temp1, *temp2;

	temp1 = hidparser_lookup_attribute(mainitem, item_tag1);
	temp2 = hidparser_lookup_attribute(mainitem, item_tag2);
	if ((temp1 != NULL) && (temp2 != NULL)) {
		if (hidparser_find_signed_val(temp1) >
		    hidparser_find_signed_val(temp2)) {
			if ((item_tag1 == R_ITEM_LOGICAL_MINIMUM) ||
			    (item_tag1 == R_ITEM_PHYSICAL_MINIMUM)) {
				hidparser_report_err(
				    HIDPARSER_ERR_WARN,
				    HIDPARSER_ERR_STANDARD,
				    item_tag1,
				    val1,
				    "signed: Min should be <= to Max");
			} else {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    item_tag1,
				    val1,
				    "Min must be <= to Max");
			}
		}
		if (hidparser_find_signed_val(temp2) <
		    hidparser_find_signed_val(temp1)) {
			if ((item_tag2 == R_ITEM_LOGICAL_MAXIMUM) ||
			    (item_tag2 == R_ITEM_PHYSICAL_MAXIMUM)) {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    item_tag2,
				    val2,
				    "signed: Max should be >= to Min");
			} else {
				hidparser_report_err(
				    HIDPARSER_ERR_ERROR,
				    HIDPARSER_ERR_STANDARD,
				    item_tag2,
				    val2,
				    "Max must be >= to Min");
			}
		}
	}	/* if (temp1 != NULL) && (temp2 != NULL) */
}


/*
 * hidparser_error_delim:
 *	Error check for Delimiter Sets
 */
static void
hidparser_error_delim(entity_item_t *item, int err)
{
	entity_attribute_t *attr;
	switch (err) {
		case HIDPARSER_DELIM_ERR1:
			hidparser_report_err(
			    HIDPARSER_ERR_ERROR,
			    HIDPARSER_ERR_STANDARD,
			    R_ITEM_SET_DELIMITER,
			    0,
			    "Must be Delimiter Open");

			break;
		case HIDPARSER_DELIM_ERR2:
			hidparser_report_err(
			    HIDPARSER_ERR_ERROR,
			    HIDPARSER_ERR_STANDARD,
			    R_ITEM_SET_DELIMITER,
			    0,
			    "Must be Delimiter Close");

			break;
		case HIDPARSER_DELIM_ERR3:
			attr = item->entity_item_attributes;
			while (attr != NULL) {
				if ((attr->entity_attribute_tag !=
				    R_ITEM_USAGE) &&
				    (attr->entity_attribute_tag !=
				    R_ITEM_USAGE_MIN) &&
				    (attr->entity_attribute_tag !=
				    R_ITEM_USAGE_MAX)) {
					hidparser_report_err(
					    HIDPARSER_ERR_ERROR,
					    HIDPARSER_ERR_STANDARD,
					    R_ITEM_SET_DELIMITER,
					    3,
					    "May only contain Usage, "
					    "Usage Min and Usage Max");
				}
				attr = attr->entity_attribute_next;
			}

			break;
		default:

			break;
	}
}


/*
 * hidparser_find_max_packet_size_from_report_descriptor:
 *	find packet size of the largest report in the report descriptor
 */
void
hidparser_find_max_packet_size_from_report_descriptor(
			hidparser_handle_t hparser_handle,
			hidparser_packet_info_t *hpack)
{

	int				rval, i;
	uint_t				packet_size;
	uint_t				max_packet_size;
	uint_t				max_report_id;
	hidparser_report_id_list_t	report_id_list;

	USB_DPRINTF_L4(PRINT_MASK_ALL, hparser_log_handle,
	    "hidparser_find_max_packet_size_from_report_descriptor");

	/* get a list of input reports */
	rval = hidparser_get_report_id_list(hparser_handle,
	    R_ITEM_INPUT, &report_id_list);
	if (rval != HIDPARSER_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "No report id used");
	} else {
		USB_DPRINTF_L3(PRINT_MASK_ALL, hparser_log_handle,
		    "%d unique report IDs found in hid report descriptor",
		    report_id_list.no_of_report_ids);

		for (i = 0; i < (report_id_list.no_of_report_ids); i++) {
			USB_DPRINTF_L3(PRINT_MASK_ALL, hparser_log_handle,
			    "report_id: %d", report_id_list.report_id[i]);
		}
	}

	if ((rval != HIDPARSER_SUCCESS) ||
	    (report_id_list.no_of_report_ids == 0)) {
		/*
		 * since no report id is used, get the packet size
		 * for the only report available
		 */
		(void) hidparser_get_packet_size(hparser_handle,
		    0, R_ITEM_INPUT, &packet_size);
		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "Not using report id prefix. HID packet size = %d",
		    packet_size);

		hpack->max_packet_size = packet_size;
		hpack->report_id = HID_REPORT_ID_UNDEFINED;
	} else {
		/*
		 * hid device uses multiple reports with report id prefix byte.
		 * Find the longest input report.
		 * See HID 8.4.
		 */
		max_packet_size = 0;
		max_report_id = 0;

		for (i = 0; i < (report_id_list.no_of_report_ids); i++) {
			(void) hidparser_get_packet_size(hparser_handle,
			    report_id_list.report_id[i], R_ITEM_INPUT,
			    &packet_size);
			if (packet_size > max_packet_size) {
				max_packet_size = packet_size;
				max_report_id = report_id_list.report_id[i];
			}
			USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
			    "Report ID %d has a packet size of %d",
			    report_id_list.report_id[i], packet_size);
		}

		hpack->max_packet_size = max_packet_size;
		hpack->report_id = max_report_id;

		USB_DPRINTF_L2(PRINT_MASK_ALL, hparser_log_handle,
		    "Report ID %d has the maximum packet size of %d",
		    max_report_id, max_packet_size);
	}
}
