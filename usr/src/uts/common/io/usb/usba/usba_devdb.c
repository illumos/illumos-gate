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
 * Copyright 2019, Joyent, Inc.
 */


#define	USBA_FRAMEWORK
#include <sys/ksynch.h>
#include <sys/strsun.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/usba_devdb_impl.h>

static usb_log_handle_t	usba_devdb_log_handle;
uint_t	usba_devdb_errlevel = USB_LOG_L4;
uint_t	usba_devdb_errmask = (uint_t)-1;

boolean_t	usba_build_devdb = B_FALSE;

avl_tree_t	usba_devdb;		/* tree of records */
static krwlock_t usba_devdb_lock;	/* lock protecting the tree */

_NOTE(RWLOCK_PROTECTS_DATA(usba_devdb_lock, usba_devdb))

/*
 * Reader Writer locks have problem with warlock. warlock is unable to
 * decode that the structure is local and doesn't need locking
 */
_NOTE(SCHEME_PROTECTS_DATA("unshared", usba_devdb_info))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usba_configrec))

/* function prototypes */
static int usb_devdb_compare_pathnames(char *, char *);
static int usba_devdb_compare(const void *, const void *);
static int usba_devdb_build_device_database();
static void usba_devdb_destroy_device_database();

/*
 * usba_devdb_initialization
 *	Initialize this module that builds the usb device database
 */
void
usba_devdb_initialization()
{
	usba_devdb_log_handle = usb_alloc_log_hdl(NULL, "devdb",
	    &usba_devdb_errlevel, &usba_devdb_errmask, NULL, 0);

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_initialization");

	rw_init(&usba_devdb_lock, NULL, RW_DRIVER, NULL);

	rw_enter(&usba_devdb_lock, RW_WRITER);

	usba_build_devdb = B_TRUE;

	/* now create the avl tree */
	avl_create(&usba_devdb, usba_devdb_compare,
	    sizeof (usba_devdb_info_t),
	    offsetof(struct usba_devdb_info, avl_link));

	(void) usba_devdb_build_device_database();

	usba_build_devdb = B_FALSE;

	rw_exit(&usba_devdb_lock);
}


/*
 * usba_devdb_destroy
 *	Free up all the resources being used by this module
 */
void
usba_devdb_destroy()
{
	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_destroy");

	rw_enter(&usba_devdb_lock, RW_WRITER);

	usba_devdb_destroy_device_database();

	rw_exit(&usba_devdb_lock);

	rw_destroy(&usba_devdb_lock);

	usb_free_log_hdl(usba_devdb_log_handle);
}


/*
 * usba_devdb_get_var_type:
 *	returns the field from the token
 */
static config_field_t
usba_devdb_get_var_type(char *str)
{
	usba_cfg_var_t	*cfgvar;

	cfgvar = &usba_cfg_varlist[0];
	while (cfgvar->field != USB_NONE) {
		if (strcasecmp(cfgvar->name, str) == 0) {
			break;
		} else {
			cfgvar++;
		}
	}

	return (cfgvar->field);
}


/*
 * usba_devdb_get_conf_rec:
 *	Fetch one record from the file
 */
static token_t
usba_devdb_get_conf_rec(struct _buf *file, usba_configrec_t **rec)
{
	token_t		token;
	char		tokval[MAXPATHLEN];
	usba_configrec_t	*cfgrec;
	config_field_t	cfgvar = USB_NONE;
	u_longlong_t	llptr;
	u_longlong_t	value;
	enum {
		USB_NEWVAR, USB_CONFIG_VAR, USB_VAR_EQUAL, USB_VAR_VALUE,
		    USB_ERROR
	} parse_state = USB_NEWVAR;

	cfgrec = (usba_configrec_t *)kmem_zalloc(
	    sizeof (usba_configrec_t), KM_SLEEP);
	cfgrec->idVendor = cfgrec->idProduct = cfgrec->cfg_index = -1;

	token = kobj_lex(file, tokval, sizeof (tokval));
	while ((token != EOF) && (token != SEMICOLON)) {
		switch (token) {
		case STAR:
		case POUND:
			/* skip comments */
			kobj_find_eol(file);
			break;
		case NEWLINE:
			kobj_newline(file);
			break;
		case NAME:
		case STRING:
			switch (parse_state) {
			case USB_NEWVAR:
				cfgvar = usba_devdb_get_var_type(tokval);
				if (cfgvar == USB_NONE) {
					parse_state = USB_ERROR;
					kobj_file_err(CE_WARN, file,
					    "Syntax Error: Invalid field %s",
					    tokval);
				} else {
					parse_state = USB_CONFIG_VAR;
				}
				break;
			case USB_VAR_VALUE:
				if ((cfgvar == USB_VENDOR) ||
				    (cfgvar == USB_PRODUCT) ||
				    (cfgvar == USB_CFGNDX)) {
					parse_state = USB_ERROR;
					kobj_file_err(CE_WARN, file,
					    "Syntax Error: Invalid value %s"
					    " for field: %s\n", tokval,
					    usba_cfg_varlist[cfgvar].name);
				} else if (kobj_get_string(&llptr, tokval)) {
					switch (cfgvar) {
					case USB_SELECTION:
						cfgrec->selection =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					case USB_SRNO:
						cfgrec->serialno =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					case USB_PATH:
						cfgrec->pathname =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					case USB_DRIVER:
						cfgrec->driver =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					default:
						parse_state = USB_ERROR;
					}
				} else {
					parse_state = USB_ERROR;
					kobj_file_err(CE_WARN, file,
					    "Syntax Error: Invalid value %s"
					    " for field: %s\n", tokval,
					    usba_cfg_varlist[cfgvar].name);
				}
				break;
			case USB_ERROR:
				/* just skip */
				break;
			default:
				parse_state = USB_ERROR;
				kobj_file_err(CE_WARN, file,
				    "Syntax Error: at %s", tokval);
				break;
			}
			break;
		case EQUALS:
			if (parse_state == USB_CONFIG_VAR) {
				if (cfgvar == USB_NONE) {
					parse_state = USB_ERROR;
					kobj_file_err(CE_WARN, file,
					    "Syntax Error: unexpected '='");
				} else {
					parse_state = USB_VAR_VALUE;
				}
			} else if (parse_state != USB_ERROR) {
				kobj_file_err(CE_WARN, file,
				    "Syntax Error: unexpected '='");
				parse_state = USB_ERROR;
			}
			break;
		case HEXVAL:
		case DECVAL:
			if ((parse_state == USB_VAR_VALUE) && (cfgvar !=
			    USB_NONE)) {
				(void) kobj_getvalue(tokval, &value);
				switch (cfgvar) {
				case USB_VENDOR:
					cfgrec->idVendor = (int)value;
					parse_state = USB_NEWVAR;
					break;
				case USB_PRODUCT:
					cfgrec->idProduct = (int)value;
					parse_state = USB_NEWVAR;
					break;
				case USB_CFGNDX:
					cfgrec->cfg_index = (int)value;
					parse_state = USB_NEWVAR;
					break;
				default:
					kobj_file_err(CE_WARN, file,
					    "Syntax Error: Invalid value for "
					    "%s",
					    usba_cfg_varlist[cfgvar].name);
				}
			} else if (parse_state != USB_ERROR) {
				parse_state = USB_ERROR;
				kobj_file_err(CE_WARN, file, "Syntax Error:"
				    "unexpected hex/decimal: %s", tokval);
			}
			break;
		default:
			kobj_file_err(CE_WARN, file, "Syntax Error: at: %s",
			    tokval);
			parse_state = USB_ERROR;
			break;
		}
		token = kobj_lex(file, tokval, sizeof (tokval));
	}
	*rec = cfgrec;

	return (token);
}


/*
 * usba_devdb_free_rec:
 *	Free the record allocated in usba_devdb_get_conf_rec.
 *	We use kobj_free_string as kobj_get_string allocates memory
 *	in mod_sysfile_arena.
 */
static void
usba_devdb_free_rec(usba_configrec_t *rec)
{
	if (rec->selection) {
		kobj_free_string(rec->selection, strlen(rec->selection) + 1);
	}
	if (rec->serialno) {
		kobj_free_string(rec->serialno, strlen(rec->serialno) + 1);
	}
	if (rec->pathname) {
		kobj_free_string(rec->pathname, strlen(rec->pathname) + 1);
	}
	if (rec->driver) {
		kobj_free_string(rec->driver, strlen(rec->driver) + 1);
	}
	kmem_free(rec, sizeof (usba_configrec_t));
}



/*
 * usb_devdb_compare_pathnames:
 *	Compare the two pathnames. If we are building the tree, we do a
 *	straight string compare to enable correct tree generation. If we
 *	are searching for a matching node, we compare only the selected
 *	portion of the pathname to give a correct match.
 */
static int
usb_devdb_compare_pathnames(char *p1, char *p2)
{
	int	rval;
	char	*ustr, *hstr;

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usb_devdb_compare_pathnames: p1=0x%p p2=0x%p",
	    (void *)p1, (void *)p2);

	if (p1 && p2) {
		if (usba_build_devdb == B_TRUE) {
			/* this is a straight string compare */
			rval = strcmp(p1, p2);
			if (rval < 0) {

				return (-1);
			} else if (rval > 0) {

				return (+1);
			} else {

				return (0);
			}
		} else {
			/*
			 * Comparing on this is tricky.
			 * p1 is the string hubd is looking for &
			 * p2 is the string in the device db.
			 * At this point hubd knows: ../hubd@P/device@P
			 * while user will specify  ..../hubd@P/keyboard@P
			 * First compare till .../hubd@P
			 * Second compare is just P in "device@P"
			 */
			ustr = strrchr(p2, '/');
			hstr = strrchr(p1, '/');
			rval = strncmp(p1, p2,
			    MAX(_PTRDIFF(ustr, p2),
			    _PTRDIFF(hstr, p1)));
			if (rval < 0) {

				return (-1);
			} else if (rval > 0) {

				return (+1);
			} else {
				/* now compare the ports */
				hstr = p1 + strlen(p1) -1;
				ustr = p2 + strlen(p2) -1;

				if (*hstr < *ustr) {

					return (-1);
				} else if (*hstr > *ustr) {

					return (+1);
				} else {
					/* finally got a match */

					return (0);
				}
			}
		}
	} else if ((p1 == NULL) && (p2 == NULL)) {

		return (0);
	} else {
		if (p1 == NULL) {

			return (-1);
		} else {

			return (+1);
		}
	}
}


/*
 * usba_devdb_compare
 *	Compares the two nodes. Returns -1 when p1 < p2, 0 when p1 == p2
 *	and +1 when p1 > p2. This function is invoked by avl_find
 *	Here p1 is always the node that we are trying to insert or match in
 *	the device database.
 */
static int
usba_devdb_compare(const void *p1, const void *p2)
{
	usba_configrec_t	*u1, *u2;
	int	rval;

	u1 = ((usba_devdb_info_t *)p1)->usb_dev;
	u2 = ((usba_devdb_info_t *)p2)->usb_dev;

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_compare: p1=0x%p u1=0x%p p2=0x%p u2=0x%p",
	    p1, (void *)u1, p2, (void *)u2);

	/* first match vendor id */
	if (u1->idVendor < u2->idVendor) {

		return (-1);
	} else if (u1->idVendor > u2->idVendor) {

		return (+1);
	} else {
		/* idvendor match, now check idproduct */
		if (u1->idProduct < u2->idProduct) {

			return (-1);
		} else if (u1->idProduct > u2->idProduct) {

			return (+1);
		} else {
			/* idproduct match, now check serial no. */
			if (u1->serialno && u2->serialno) {
				rval = strcmp(u1->serialno, u2->serialno);
				if (rval > 0) {

					return (+1);
				} else if (rval < 0) {

					return (-1);
				} else {
					/* srno. matches */

					return (usb_devdb_compare_pathnames(
					    u1->pathname, u2->pathname));
				}
			} else if ((u1->serialno == NULL) &&
			    (u2->serialno == NULL)) {

				return (usb_devdb_compare_pathnames(
				    u1->pathname, u2->pathname));
			} else {
				if (u1->serialno == NULL) {

					return (-1);
				} else {

					return (+1);
				}
			}
		}
	}
}


/*
 * usba_devdb_build_device_database
 *	Builds a height balanced tree of all the records present in the file.
 *	Records that are "not enabled" and are duplicate are discarded.
 */
static int
usba_devdb_build_device_database()
{
	struct _buf	*file;
	usba_configrec_t	*user_rec;
	avl_index_t	where;
	usba_devdb_info_t	*dbnode;
	token_t		token;

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_build_device_database: Start");

	file = kobj_open_file(usbconf_file);
	if (file != (struct _buf *)-1) {

		do {
			user_rec = NULL;
			token = usba_devdb_get_conf_rec(file, &user_rec);

			if (user_rec != NULL) {

				if ((user_rec->selection == NULL) ||
				    (strcasecmp(user_rec->selection,
				    "enable") != 0)) {
					/* we don't store disabled entries */
					usba_devdb_free_rec(user_rec);

					continue;
				}

				dbnode = (usba_devdb_info_t *)kmem_zalloc(
				    sizeof (usba_devdb_info_t), KM_SLEEP);
				dbnode->usb_dev = user_rec;

				if (avl_find(&usba_devdb, dbnode, &where) ==
				    NULL) {
					/* insert new node */
					avl_insert(&usba_devdb, dbnode, where);
				} else {
					/*
					 * we don't maintain duplicate entries
					 */
					usba_devdb_free_rec(user_rec);
					kmem_free(dbnode,
					    sizeof (usba_devdb_info_t));
				}
			}

		} while (token != EOF);

		kobj_close_file(file);
	}

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_build_device_database: End");

	/* XXX: return the no. of errors encountered */
	return (0);
}


/*
 * usba_devdb_destroy_device_database
 *	Destory all records in the tree
 */
static void
usba_devdb_destroy_device_database()
{
	usba_devdb_info_t	*dbnode;
	void			*cookie = NULL;

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_destroy_device_database");

	/* while there are nodes in the tree, keep destroying them */
	while ((dbnode = (usba_devdb_info_t *)
	    avl_destroy_nodes(&usba_devdb, &cookie)) != NULL) {
		/*
		 * destroy record
		 * destroy tree node
		 */
		usba_devdb_free_rec(dbnode->usb_dev);
		kmem_free(dbnode, sizeof (usba_devdb_info_t));
	}
	avl_destroy(&usba_devdb);
}


/*
 * usba_devdb_get_user_preferences
 *	Returns configrec structure to the caller that contains user
 *	preferences for the device pointed by the parameters.
 *	The first search is for a record that has serial number and/or
 *	a pathname. If search fails, we search for a rule that is generic
 *	i.e. without serial no. and pathname.
 */
usba_configrec_t *
usba_devdb_get_user_preferences(int idVendor, int idProduct, char *serialno,
    char *pathname)
{
	usba_configrec_t		*req_rec;
	usba_devdb_info_t	*req_node, *dbnode;
	avl_index_t		where;

	USB_DPRINTF_L4(DPRINT_MASK_DEVDB, usba_devdb_log_handle,
	    "usba_devdb_get_user_preferences");

	req_rec = kmem_zalloc(sizeof (usba_configrec_t), KM_SLEEP);
	req_node = kmem_zalloc(sizeof (usba_devdb_info_t), KM_SLEEP);

	/* fill in the requested parameters */
	req_rec->idVendor = idVendor;
	req_rec->idProduct = idProduct;
	req_rec->serialno = serialno;
	req_rec->pathname = pathname;

	req_node->usb_dev = req_rec;

	rw_enter(&usba_devdb_lock, RW_READER);

	/* try to find a perfect match in the device database */
	dbnode = (usba_devdb_info_t *)avl_find(&usba_devdb, req_node, &where);
#ifdef __lock_lint
	(void) usba_devdb_compare(req_node, dbnode);
#endif
	if (dbnode == NULL) {
		/* look for a generic rule */
		req_rec->serialno = req_rec->pathname = NULL;
		dbnode = (usba_devdb_info_t *)avl_find(&usba_devdb, req_node,
		    &where);
#ifdef __lock_lint
		(void) usba_devdb_compare(req_node, dbnode);
#endif
	}
	rw_exit(&usba_devdb_lock);

	kmem_free(req_rec, sizeof (usba_configrec_t));
	kmem_free(req_node, sizeof (usba_devdb_info_t));

	if (dbnode) {
		return (dbnode->usb_dev);
	} else {
		return (NULL);
	}
}


/*
 * usba_devdb_refresh
 *	Reinitializes the device database. It destroys the old one and creates
 *	a new one by re-reading the file.
 */
int
usba_devdb_refresh()
{
	rw_enter(&usba_devdb_lock, RW_WRITER);

	usba_build_devdb = B_TRUE;

	/* destroy all nodes in the existing database */
	usba_devdb_destroy_device_database();

	/* now build a new one */
	(void) usba_devdb_build_device_database();

	usba_build_devdb = B_FALSE;

	rw_exit(&usba_devdb_lock);

	return (0);
}
