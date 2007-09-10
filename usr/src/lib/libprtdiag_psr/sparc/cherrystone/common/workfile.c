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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Cherrystone platform-specific functions that aren't platform specific
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <psvc_objects.h>
#include <libprtdiag.h>
#include <sys/mc.h>

/* prtdiag exit codes */
#define	PD_SUCCESS		0
#define	PD_SYSTEM_FAILURE	1
#define	PD_INTERNAL_FAILURE	2

static int exit_code = PD_SUCCESS;

static Prom_node *dev_next_node_by_compat(Prom_node *root, char *model);
static Prom_node *dev_find_node_by_compat(Prom_node *root, char *model);

void	print_us3_memory_line(int portid,
				int bank_id,
				uint64_t bank_size,
				char *bank_status,
				uint64_t dimm_size,
				uint32_t intlv,
				int seg_id);

void	add_node(Sys_tree *root, Prom_node *pnode);
int	do_prominfo(int syserrlog,
		    char *pgname,
		    int log_flag,
		    int prt_flag);

void	*get_prop_val(Prop *prop);
Prop	*find_prop(Prom_node *pnode, char *name);
char	*get_node_name(Prom_node *pnode);
char	*get_node_type(Prom_node *pnode);

void	fill_pci_card_list(Prom_node *pci_instance,
			    Prom_node *pci_card_node,
			    struct io_card *pci_card,
			    struct io_card **pci_card_list,
			    char **pci_slot_name_arr);

static Prom_node	*next_pci_card(Prom_node *curr_card, int *is_bridge,
				int is_pcidev, Prom_node *curr_bridge,
				Prom_node * parent_bridge, Prom_node *pci);

#define	HZ_TO_MHZ(x)	(((x) + 500000) / 1000000)

/*
 * Start from the current node and return the next node besides
 * the current one which has the requested model property.
 */
static Prom_node *
dev_next_node_by_compat(Prom_node *root, char *compat)
{
	Prom_node *node;

	if (root == NULL)
		return (NULL);

	/* look at your children first */
	if ((node = dev_find_node_by_compat(root->child, compat)) != NULL)
		return (node);

	/* now look at your siblings */
	if ((node = dev_find_node_by_compat(root->sibling, compat)) != NULL)
		return (node);

	return (NULL);  /* not found */
}

/*
 * Do a depth-first walk of a device tree and
 * return the first node with the matching model.
 */
static Prom_node *
dev_find_node_by_compat(Prom_node *root, char *compat)
{
	Prom_node	*node;
	char		*compatible;
	char		*name;

	if (root == NULL)
		return (NULL);

	if (compat == NULL)
		return (NULL);

	name = get_node_name(root);
	if (name == NULL)
		name = "";

	compatible = (char *)get_prop_val(find_prop(root, "compatible"));

	if (compatible == NULL)
		return (NULL);

	if ((strcmp(name, "pci") == 0) && (compatible != NULL) &&
	    (strcmp(compatible, compat) == 0)) {
		return (root); /* found a match */
	}

	/* look at your children first */
	if ((node = dev_find_node_by_compat(root->child, compat)) != NULL)
		return (node);

	/* now look at your siblings */
	if ((node = dev_find_node_by_compat(root->sibling, compat)) != NULL)
		return (node);

	return (NULL);  /* not found */
}

int32_t
find_child_device(picl_nodehdl_t parent, char *child_name,
		picl_nodehdl_t *child)
{
	int32_t		err;
	char		name[PICL_PROPNAMELEN_MAX];

	err = picl_get_propval_by_name(parent, PICL_PROP_CHILD, &(*child),
	    sizeof (picl_nodehdl_t));
	switch (err) {
	case PICL_SUCCESS:
		break;
	case PICL_PROPNOTFOUND:
		err = PICL_INVALIDHANDLE;
		return (err);
	default:
#ifdef WORKFILE_DEBUG
		log_printf(dgettext(TEXT_DOMAIN,
		    "Failed picl_get_propval_by_name with %s\n"),
		    picl_strerror(err));
#endif
		return (err);
	}

	err = picl_get_propval_by_name(*child, PICL_PROP_NAME, name,
	    PICL_PROPNAMELEN_MAX);

#ifdef WORKFILE_DEBUG
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "failed the get name for root\n"));
		log_printf(dgettext(TEXT_DOMAIN, "%s\n"), picl_strerror(err));
	}
#endif

	if (strcmp(name, child_name) == 0)
		return (err);

	while (err != PICL_PROPNOTFOUND) {
#ifdef WORKFILE_DEBUG
		log_printf(dgettext(TEXT_DOMAIN, "child name is %s\n"), name);
#endif
		err = picl_get_propval_by_name(*child, PICL_PROP_PEER,
		    &(*child), sizeof (picl_nodehdl_t));
		switch (err) {
		case PICL_SUCCESS:
			err = picl_get_propval_by_name(*child, PICL_PROP_NAME,
			    name, PICL_PROPNAMELEN_MAX);
			if (strcmp(name, child_name) == 0)
				return (err);
			break;
		case PICL_PROPNOTFOUND:
			break;
		default:
#ifdef WORKFILE_DEBUG
			log_printf(dgettext(TEXT_DOMAIN,
			    "Failed picl_get_propval_by_name with %s\n"),
			    picl_strerror(err));
#endif
			return (err);
		}
	}
	err = PICL_INVALIDHANDLE;
	return (err);
}

int32_t
fill_device_from_id(picl_nodehdl_t device_id, char *assoc_id,
		picl_nodehdl_t *device)
{
	int32_t		err;
	picl_prophdl_t	tbl_hdl;
	picl_prophdl_t	reference_property;

	err = picl_get_propval_by_name(device_id, assoc_id, &tbl_hdl,
	    sizeof (picl_prophdl_t));
	if (err != PICL_SUCCESS) {
#ifdef WORKFILE_DEBUG
		if (err != PICL_INVALIDHANDLE) {
			log_printf(dgettext(TEXT_DOMAIN,
			"fill_device_from_id failure in "
			"picl_get_propval_by_name err is %s\n"),
			    picl_strerror(err));
		}
#endif
		return (err);
	}

	err = picl_get_next_by_row(tbl_hdl, &reference_property);
	if (err != PICL_SUCCESS) {
#ifdef WORKFILE_DEBUG
		log_printf(dgettext(TEXT_DOMAIN,
		    "fill_device_from_id failure in picl_get_next_by_row"
		    " err is %s\n"), picl_strerror(err));
#endif
		return (err);
	}

	/* get node associated with reference property */
	err = picl_get_propval(reference_property, &(*device),
	    sizeof (picl_nodehdl_t));

#ifdef WORKFILE_DEBUG
	if (err != 0) {
		log_printf(dgettext(TEXT_DOMAIN,
		"fill_device_from_id failure in picl_get_propval"
		" err is %s\n"), picl_strerror(err));
	}
#endif

	return (err);
}

int32_t
fill_device_array_from_id(picl_nodehdl_t device_id, char *assoc_id,
	int32_t *number_of_devices, picl_nodehdl_t *device_array[])
{
	int32_t		err;
	int		i;
	picl_prophdl_t	tbl_hdl;
	picl_prophdl_t	entry;
	int		devs = 0;

	err = picl_get_propval_by_name(device_id, assoc_id, &tbl_hdl,
	    sizeof (picl_prophdl_t));
	if ((err != PICL_SUCCESS) && (err != PICL_INVALIDHANDLE)) {
#ifdef WORKFILE_DEBUG
		log_printf(dgettext(TEXT_DOMAIN,
		    "fill_device_array_from_id failure in "
		    "picl_get_propval_by_name err is %s\n"),
		    picl_strerror(err));
#endif
		return (err);
	}

	entry = tbl_hdl;
	while (picl_get_next_by_row(entry, &entry) == 0)
		++devs;

	*device_array = calloc((devs), sizeof (picl_nodehdl_t));
	if (*device_array == NULL) {

#ifdef WORFILE_DEBUG
		log_printf(dgettext(TEXT_DOMAIN,
		"fill_device_array_from_id failure getting memory"
		" for array\n"));
#endif
		return (PICL_FAILURE);
	}

	entry = tbl_hdl;
	for (i = 0; i < devs; i++) {
		err = picl_get_next_by_row(entry, &entry);
		if (err != 0) {
#ifdef WORKFILE_DEBUG
			log_printf(dgettext(TEXT_DOMAIN,
			"fill_device_array_from_id failure in "
			"picl_get_next_by_row err is %s\n"),
			    picl_strerror(err));
#endif
			return (err);
		}

		/* get node associated with reference property */
		err = picl_get_propval(entry, &((*device_array)[i]),
		    sizeof (picl_nodehdl_t));
		if (err != 0) {
#ifdef WORKFILE_DEBUG
			log_printf(dgettext(TEXT_DOMAIN,
			"fill_device_array_from_id failure in "
			"picl_get_propval err is %s\n"), picl_strerror(err));
#endif

			return (err);
		}
	}
	*number_of_devices = devs;
	return (err);
}

/*
 * add_node
 *
 * This function adds a board node to the board structure where that
 * that node's physical component lives.
 */
void
add_node(Sys_tree *root, Prom_node *pnode)
{
	int	board	= -1;
	int	portid	= -1;

	void		*value	= NULL;
	Board_node	*bnode	= NULL;
	Prom_node	*p	= NULL;

	/* Get the board number of this board from the portid prop */
	value = get_prop_val(find_prop(pnode, "portid"));
	if (value != NULL) {
		portid = *(int *)value;
	}

	board = CHERRYSTONE_GETSLOT(portid);

	if ((bnode = find_board(root, board)) == NULL) {
		bnode = insert_board(root, board);
	}

	/* now attach this prom node to the board list */
	/* Insert this node at the end of the list */
	pnode->sibling = NULL;
	if (bnode->nodes == NULL)
		bnode->nodes = pnode;
	else {
		p = bnode->nodes;
		while (p->sibling != NULL)
			p = p->sibling;
		p->sibling = pnode;
	}
}

/*
 * This function provides formatting of the memory config
 * information that get_us3_mem_regs() and display_us3_banks() code has
 * gathered. It overrides the generic print_us3_memory_line() code
 * which prints an error message.
 */
void
print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
	char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id)
{
	log_printf(dgettext(TEXT_DOMAIN,
	    "\n %-1c   %2d    %2d      %4lldMB   %11-s  %4lldMB "
	    "   %2d-way        %d"),
	    CHERRYSTONE_GETSLOT_LABEL(portid), portid,
	    (bank_id % 4), bank_size, bank_status, dimm_size,
	    intlv, seg_id, 0);
}

/*
 * We call do_devinfo() in order to use the libdevinfo device tree instead of
 * OBP's device tree. Ignore its return value and use our exit_code instead.
 * Its return value comes from calling error_check() which is not implemented
 * because the device tree does not keep track of the status property for the
 * 480/490. The exit_code we return is set while do_devinfo() calls our local
 * functions to gather/print data. That way we can report both internal and
 * device failures.
 */
int
do_prominfo(int syserrlog, char *pgname, int log_flag, int prt_flag)
{
	(void) do_devinfo(syserrlog, pgname, log_flag, prt_flag);
	return (exit_code);
}

/*
 * return the property value for the Prop
 * passed in. (When using libdevinfo)
 */
void *
get_prop_val(Prop *prop)
{
	if (prop == NULL)
		return (NULL);

	return ((void *)(prop->value.val_ptr));
}

/*
 * Search a Prom node and retrieve the property with the correct
 * name. (When using libdevinfo)
 */
Prop *
find_prop(Prom_node *pnode, char *name)
{
	Prop *prop;

	if (pnode  == NULL)
		return (NULL);

	if (pnode->props == NULL)
		return (NULL);

	prop = pnode->props;
	if (prop == NULL)
		return (NULL);

	if (prop->name.val_ptr == NULL)
		return (NULL);

	while ((prop != NULL) && (strcmp((char *)(prop->name.val_ptr), name))) {
		prop = prop->next;
	}
	return (prop);
}

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the name property.
 * (When using libdevinfo)
 */
char *
get_node_name(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL) {
		return (NULL);
	}

	prop = pnode->props;
	while (prop != NULL) {
		if (strcmp("name", (char *)prop->name.val_ptr) == 0)
			return (prop->value.val_ptr);
		prop = prop->next;
	}
	return (NULL);
}

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the device_type property.
 * (When using libdevinfo)
 */
char *
get_node_type(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL) {
		return (NULL);
	}

	prop = pnode->props;
	while (prop != NULL) {
		if (strcmp("device_type", (char *)prop->name.val_ptr) == 0)
			return (prop->value.val_ptr);
		prop = prop->next;
	}
	return (NULL);
}


/*
 * Fills in the i/o card list to be displayed later in display_pci();
 */
void
fill_pci_card_list(Prom_node * pci_instance, Prom_node * pci_card_node,
			struct io_card *pci_card,
			struct io_card **pci_card_list, char **slot_name_arr)
{
	Prom_node	*pci_bridge_node;
	Prom_node	*pci_parent_bridge;
	int		*int_val;
	int		pci_bridge = FALSE;
	int		pci_bridge_dev_no = -1;
	int		portid;
	int		pci_bus;
	char		buf[MAXSTRLEN];
	char		*slot_name = NULL;	/* info in "slot-names" prop */
	char		*child_name;
	char		*name;
	char		*type;
	void		*value;

	while (pci_card_node != NULL) {
		int is_pci = FALSE;
		type = NULL;
		name = NULL;
		/* If it doesn't have a name, skip it */
		name = (char *)get_prop_val(
		    find_prop(pci_card_node, "name"));
		if (name == NULL) {
			pci_card_node = pci_card_node->sibling;
			continue;
		}

		/*
		 * Get the portid of the schizo that this card
		 * lives under.
		 */
		portid = -1;
		value = get_prop_val(find_prop(pci_instance, "portid"));
		if (value != NULL) {
			portid = *(int *)value;
		}
		pci_card->schizo_portid = portid;
		if (pci_card->schizo_portid != 8) {
			/*
			 * Schizo0 (portid 8) has no slots on Cherrystone.
			 * So if that's who we're looking at, we're done.
			 */
			return;
		}

		/*
		 * Find out whether this is PCI bus A or B
		 * using the 'reg' property.
		 */
		int_val = (int *)get_prop_val(find_prop(pci_instance, "reg"));

		if (int_val != NULL) {
			int_val++; /* skip over first integer */
			pci_bus = ((*int_val) & 0x7f0000);
			if (pci_bus == 0x600000)
				pci_card->pci_bus = 'A';
			else if (pci_bus == 0x700000)
				pci_card->pci_bus = 'B';
			else {
				assert(0); /* should never happen */
				pci_card->pci_bus = '-';
			}
		} else {
			assert(0); /* should never happen */
			pci_card->pci_bus = '-';
		}

		/*
		 * get dev# and func# for this card from the
		 * 'reg' property.
		 */
		int_val = (int *)get_prop_val(
		    find_prop(pci_card_node, "reg"));
		if (int_val != NULL) {
			pci_card->dev_no = (((*int_val) & 0xF800) >> 11);
			pci_card->func_no = (((*int_val) & 0x700) >> 8);
		} else {
			pci_card->dev_no = -1;
			pci_card->func_no = -1;
		}

		switch (pci_card->pci_bus) {
		case 'A':
			if ((pci_card->dev_no < 1 || pci_card->dev_no > 2) &&
			    (!pci_bridge)) {
				pci_card_node = pci_card_node->sibling;
				continue;
			}
			break;
		case 'B':
			if ((pci_card->dev_no < 2 || pci_card->dev_no > 5) &&
			    (!pci_bridge)) {
				pci_card_node = pci_card_node->sibling;
				continue;
			}
			break;
		default:
			pci_card_node = pci_card_node->sibling;
			continue;
		}

		type = (char *)get_prop_val(
		    find_prop(pci_card_node, "device_type"));
		/*
		 * If this is a pci-bridge, then store its dev#
		 * as its children nodes need this to get their slot#.
		 * We set the pci_bridge flag so that we know we are
		 * looking at a pci-bridge node. This flag gets reset
		 * every time we enter this while loop.
		 */

		/*
		 * Check for a PCI-PCI Bridge for PCI and cPCI
		 * IO Boards using the name and type properties.
		 */
		if ((type != NULL) && (strncmp(name, "pci", 3) == 0) &&
		    (strcmp(type, "pci") == 0)) {
			pci_bridge_node = pci_card_node;
			is_pci = TRUE;
			if (!pci_bridge) {
				pci_bridge_dev_no = pci_card->dev_no;
				pci_parent_bridge = pci_bridge_node;
				pci_bridge = TRUE;
			}
		}

		/*
		 * Get slot-names property from slot_names_arr.
		 * If we are the child of a pci_bridge we use the
		 * dev# of the pci_bridge as an index to get
		 * the slot number. We know that we are a child of
		 * a pci-bridge if our parent is the same as the last
		 * pci_bridge node found above.
		 */
		if (pci_card->dev_no != -1) {
			/*
			 * We compare this cards parent node with the
			 * pci_bridge_node to see if it's a child.
			 */
			if (pci_card_node->parent != pci_instance &&
			    pci_bridge) {
				/* use dev_no of pci_bridge */
				if (pci_card->pci_bus == 'B') {
					slot_name =
					    slot_name_arr[pci_bridge_dev_no -2];
				} else {
					slot_name =
					    slot_name_arr[pci_bridge_dev_no -1];
				}
			} else {
				if (pci_card->pci_bus == 'B') {
				slot_name =
				    slot_name_arr[pci_card->dev_no-2];
				} else {
				slot_name =
				    slot_name_arr[pci_card->dev_no-1];
				}
			}

			if (slot_name != NULL &&
			    strlen(slot_name) != 0) {
				/* Slot num is last char in string */
				(void) snprintf(pci_card->slot_str, MAXSTRLEN,
				    "%c", slot_name[strlen(slot_name) - 1]);
			} else {
				(void) snprintf(pci_card->slot_str, MAXSTRLEN,
				    "-");
			}

		} else {
			(void) snprintf(pci_card->slot_str, MAXSTRLEN,
			    "%c", '-');
		}

		/*
		 * Check for failed status.
		 */
		if (node_failed(pci_card_node))
			(void) strcpy(pci_card->status, "fail");
		else
			(void) strcpy(pci_card->status, "ok");

		/* Get the model of this pci_card */
		value = get_prop_val(find_prop(pci_card_node, "model"));
		if (value == NULL)
			pci_card->model[0] = '\0';
		else {
			(void) snprintf(pci_card->model, MAXSTRLEN, "%s",
			    (char *)value);
		}
		/*
		 * The card may have a "clock-frequency" but we
		 * are not interested in that. Instead we get the
		 * "clock-frequency" of the PCI Bus that the card
		 * resides on. PCI-A can operate at 33Mhz or 66Mhz
		 * depending on what card is plugged into the Bus.
		 * PCI-B always operates at 33Mhz.
		 */
		int_val = get_prop_val(find_prop(pci_instance,
		    "clock-frequency"));
		if (int_val != NULL) {
			pci_card->freq = HZ_TO_MHZ(*int_val);
		} else {
			pci_card->freq = -1;
		}

		/*
		 * Figure out how we want to display the name
		 */
		value = get_prop_val(find_prop(pci_card_node,
		    "compatible"));
		if (value != NULL) {
			/* use 'name'-'compatible' */
			(void) snprintf(buf, MAXSTRLEN, "%s-%s", name,
			    (char *)value);
		} else {
			/* just use 'name' */
			(void) snprintf(buf, MAXSTRLEN, "%s", name);
		}
		name = buf;

		/*
		 * If this node has children, add the device_type
		 * of the child to the name value of this pci_card->
		 */
		child_name = (char *)get_node_name(pci_card_node->child);
		if ((pci_card_node->child != NULL) &&
		    (child_name != NULL)) {
			value = get_prop_val(find_prop(pci_card_node->child,
			    "device_type"));
			if (value != NULL) {
				/* add device_type of child to name */
				(void) snprintf(pci_card->name, MAXSTRLEN,
				    "%s/%s (%s)", name, child_name,
				    (char *)value);
			} else {
				/* just add childs name */
				(void) snprintf(pci_card->name, MAXSTRLEN,
				    "%s/%s", name, child_name);
			}
		} else {
			(void) snprintf(pci_card->name, MAXSTRLEN, "%s",
			    (char *)name);
		}

		/*
		 * If this is a pci-bridge, then add the word
		 * 'pci-bridge' to its model.  If we can't find
		 * a model, then we just describe what the device
		 * is based on some properties.
		 */
		if (pci_bridge) {
			if (strlen(pci_card->model) == 0) {
				if (pci_card_node->parent == pci_bridge_node)
					(void) snprintf(pci_card->model,
					    MAXSTRLEN,
					    "%s", "device on pci-bridge");
				else if (pci_card_node->parent
				    == pci_parent_bridge)
					(void) snprintf(pci_card->model,
					    MAXSTRLEN,
					    "%s", "pci-bridge/pci-bridge");
				else
					(void) snprintf(pci_card->model,
					    MAXSTRLEN,
					    "%s", "PCI-BRIDGE");
			}
			else
				(void) snprintf(pci_card->model, MAXSTRLEN,
				    "%s/pci-bridge", pci_card->model);
		}
		/* insert this pci_card in the list to be displayed later */

		*pci_card_list = insert_io_card(*pci_card_list, pci_card);

		/*
		 * If we are dealing with a pci-bridge, we need to move
		 * down to the children of this bridge if there are any.
		 *
		 * If we are not, we are either dealing with a regular
		 * card (in which case we move onto the sibling of this
		 * card) or we are dealing with a child of a pci-bridge
		 * (in which case we move onto the child's siblings or
		 * if there are no more siblings for this child, we
		 * move onto the parents siblings).
		 */
		pci_card_node = next_pci_card(pci_card_node, &pci_bridge,
		    is_pci, pci_bridge_node,
		    pci_parent_bridge, pci_instance);
	} /* end-while */
}

/*
 * Helper function for fill_pci_card_list().  Indicates which
 * card node to go to next.
 * Parameters:
 * -----------
 * Prom_node * curr_card: pointer to the current card node
 *
 * int * is_bridge: indicates whether or not the card (is | is on)
 *                  a pci bridge
 *
 * int is_pcidev: indicates whether or not the current card
 *                is a pci bridge
 *
 * Prom_node * curr_bridge: pointer to the current pci bridge.  Eg:
 *                          curr_card->parent.
 *
 * Prom_node * parent_bridge: pointer to the first pci bridge encountered.
 *			      we could have nested pci bridges, this would
 *			      be the first one.
 *
 * Prom_node * pci: pointer to the pci instance that we are attached to.
 *		    This would be parent_bridge->parent, or
 *		    curr_node->parent, if curr_node is not on a pci bridge.
 */
static Prom_node *
next_pci_card(Prom_node *curr_card, int *is_bridge, int is_pcidev,
		Prom_node *curr_bridge, Prom_node *parent_bridge,
		Prom_node *pci)
{
	Prom_node * curr_node = curr_card;
	if (*is_bridge) {
		/*
		 * is_pcidev is used to prevent us from following the
		 * children of something like a scsi device.
		 */
		if (curr_node->child != NULL && is_pcidev) {
			curr_node = curr_node->child;
		} else {
			curr_node = curr_node->sibling;
			if (curr_node == NULL) {
				curr_node = curr_bridge->sibling;
				while (curr_node == NULL &&
				    curr_bridge != parent_bridge &&
				    curr_bridge != NULL) {
					curr_node =
					    curr_bridge->parent->sibling;
					curr_bridge = curr_bridge->parent;
					if (curr_node != NULL &&
					    curr_node->parent == pci)
						break;
				}
				if (curr_bridge == NULL ||
				    curr_node == NULL ||
				    curr_node->parent == pci ||
				    curr_bridge == parent_bridge ||
				    curr_node == parent_bridge) {
					*is_bridge = FALSE;
				}
			}
		}

	} else {
		curr_node = curr_node->sibling;
	}
	return (curr_node);
}
