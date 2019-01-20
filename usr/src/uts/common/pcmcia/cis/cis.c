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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This is a collection of routines that make up the Card Information
 *	Structure (CIS) interpreter.  The algorigthms used are based
 *	on the Release 2.01 PCMCIA standard.
 *
 * Note that a bunch of comments are not indented correctly with the
 *	code that they are commenting on. This is because cstyle is
 *	inflexible concerning 4-column indenting.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/callb.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>
#include <pcmcia/sys/cis_protos.h>
#include <pcmcia/sys/cs_stubs.h>

/*
 * Function declarations
 */
void *CISParser(int function, ...);
static int (*cis_card_services)(int, ...) = NULL;

static int cis_process_longlink(cistpl_callout_t *, cistpl_t *,
						cis_info_t *, cisparse_t *);
static int cis_create_cis_chain(cs_socket_t *, cistpl_callout_t *,
					cisptr_t *, cis_info_t *, cisparse_t *);
static void cis_store_cis_addr(cistpl_t *, cisptr_t *);

extern cistpl_callout_t cistpl_std_callout[];
extern cistpl_devspeed_struct_t cistpl_devspeed_struct;

#ifdef	CIS_DEBUG
int	cis_debug = 0;
#endif

/*
 * cisp_init - initialize the CIS parser
 */
void
cisp_init()
{
#ifdef	XXX
	csregister_t csr;

	/*
	 * Fill out the function for CISSetAddress
	 */
	csr.cs_magic = PCCS_MAGIC;
	csr.cs_version = PCCS_VERSION;
	csr.cs_event = (f_t *)CISParser;

	/*
	 * We have to call SS instead of CS to register because we
	 *	can't do a _depends_on for CS
	 */
	SocketServices(CISSetAddress, &csr);
#endif	/* XXX */
}

/*
 * cis_deinit - deinitialize the CIS parser
 */
void
cis_deinit()
{

	/*
	 * Tell CS that we're gone.
	 */
	if (cis_card_services)
	    CIS_CARD_SERVICES(CISUnregister);

	return;

}

/*
 * CISParser - this is the entrypoint for all of the CIS Interpreter
 *		functions
 */
void *
CISParser(int function, ...)
{
	va_list arglist;
	void *retcode = (void *)CS_UNSUPPORTED_FUNCTION;

#if defined(CIS_DEBUG)
	if (cis_debug > 1) {
	    cmn_err(CE_CONT, "CISParser: called with function 0x%x\n",
				function);
	}
#endif

	va_start(arglist, function);

	/*
	 * ...and here's the CIS Interpreter waterfall
	 */
	switch (function) {
	    case CISP_CIS_SETUP: {
		csregister_t *csr;
		cisregister_t cisr;

		    csr = va_arg(arglist, csregister_t *);
		    cis_card_services = csr->cs_card_services;

		    cisr.cis_magic = PCCS_MAGIC;
		    cisr.cis_version = PCCS_VERSION;
		    cisr.cis_parser = NULL;	/* let the framework do this */
		    cisr.cistpl_std_callout = cistpl_std_callout;

			/*
			 * Tell CS that we're here and what our
			 *	entrypoint address is.
			 */
		    CIS_CARD_SERVICES(CISRegister, &cisr);
		} /* CISP_CIS_SETUP */
		break;
	    case CISP_CIS_LIST_CREATE: {
		cistpl_callout_t *cistpl_callout;
		cs_socket_t *sp;

		    cistpl_callout = va_arg(arglist, cistpl_callout_t *);
		    sp = va_arg(arglist, cs_socket_t *);

		    retcode = (void *)
			(uintptr_t)cis_list_create(cistpl_callout, sp);
		}
		break;
	    case CISP_CIS_LIST_DESTROY: {
		cs_socket_t *sp;

		    sp = va_arg(arglist, cs_socket_t *);

		    retcode = (void *)(uintptr_t)cis_list_destroy(sp);
		}
		break;
	    case CISP_CIS_GET_LTUPLE: {
		cistpl_t *tp;
		cisdata_t type;
		int flags;

		    tp = va_arg(arglist, cistpl_t *);
		    type = va_arg(arglist, uint_t);
		    flags = va_arg(arglist, int);

		    retcode = (void *)cis_get_ltuple(tp, type, flags);
		}
		break;

	    case CISP_CIS_PARSE_TUPLE: {
		cistpl_callout_t *co;
		cistpl_t *tp;
		int flags;
		void *arg;
		cisdata_t subtype;

		co = va_arg(arglist, cistpl_callout_t *);
		tp = va_arg(arglist, cistpl_t *);
		flags = va_arg(arglist, int);
		arg = va_arg(arglist, void *);
		subtype = va_arg(arglist, uint_t);

		retcode = (void *)(uintptr_t)cis_tuple_handler(co, tp,
		    flags, arg, subtype);
		}
		break;

	    case CISP_CIS_CONV_DEVSPEED:
		retcode = (void *)(uintptr_t)cis_convert_devspeed(
				va_arg(arglist, convert_speed_t *));
		break;

	    case CISP_CIS_CONV_DEVSIZE:
		retcode = (void *)(uintptr_t)cis_convert_devsize(
				va_arg(arglist, convert_size_t *));
		break;

	    default:
		break;
	}

	va_end(arglist);

	return (retcode);
}

/*
 * cis_list_lcreate - read a PC card's CIS and create a local linked CIS list
 *
 *	cistpl_callout_t *cistpl_callout - pointer to callout structure
 *				array to use to find tuples.
 *	cisptr_t cisptr - pointer to a structure containing the handle and
 *				offset from where we should start reading
 *				CIS bytes as well as misc flags.
 *	cis_info_t *cis_info - pointer to a cis_info_t structure; pass
 *				the cis_info->cis member as a NULL pointer
 *				if you want to create a new list.
 *	cisparse_t *cisparse - pointer to a cisparse_t struture to put
 *				parsed longlink tuple data into.
 *      cs_socket_t *sp - pointer to a cs_socket_t structure that describes
 *				 the socket and card in this socket.
 *
 * We return the a count of the number of tuples that we saw, not including
 *	any CISTPL_END or CISTPL_NULL tuples if there were no problems
 *	processing the CIS.  If a tuple handler returns an error, we
 *	immediately return with the error code from the handler. An
 *	error return code will always have the HANDTPL_ERROR bit set
 *	to allow the caller to distinguish an error from a valid tuple
 *	count.
 *
 * The nchains and ntuples counters in  the cis_info_t structure are also
 *	updated to reflect the number of chains and number of tuples in
 *	this chain.
 *
 * XXX need to add CISTPL_END and CISTPL_NULL tuples to the list, and need
 *	to be sure that the tuple count reflects these tuples
 *
 * If we attempt to read beyond the end of the mapped in CIS address space,
 *	the BAD_CIS_ADDR error code is returned.
 *
 * This function only interprets the CISTPL_END and CISTPL_NULL tuples as
 *	well as any tuple with a link field of CISTPL_END.
 *
 * Tuples of type CISTPL_END or CISTPL_NULL are not added to the list.
 *
 * To append tuples to end of a local linked CIS list, pass a pointer to the
 *	address of the last element in the list that you want tuples appended
 *	to. This pointer should be passed in cis_info->cis.
 *
 * To process tuple chains with any long link targets, call this routine
 *	for each tuple chain you want to process using the list append method
 *	described above.  The caller is responsible for vaildating any link
 *	target tuples to be sure that they describe a valid CIS chain.
 *
 * The cis_info->flags member is updated as follows:
 *
 *		CW_VALID_CIS - if the CIS is valid
 *		CW_LONGLINK_MFC_FOUND - if a CISTPL_LONGLINK_MFC tuple
 *					was seen
 *		CW_LONGLINK_A_FOUND - if a CISTPL_LONGLINK_A tuple was
 *					seen
 *		CW_LONGLINK_C_FOUND - if a CISTPL_LONGLINK_C tuple was
 *					seen
 *
 *	If a CISTPL_LONGLINK_MFC, CISTPL_LONGLINK_A or CISTPL_LONGLINK_C
 *	tuple is seen, the *cisparse argument will return an appropriate
 *	parsed longlink structure as follows:
 *
 *		CW_LONGLINK_MFC_FOUND:
 *			*cisparse --> cistpl_longlink_mfc_t *
 *		CW_LONGLINK_A_FOUND, CW_LONGLINK_C_FOUND:
 *			*cisparse --> cistpl_longlink_ac_t *
 *
 *	These flags are set and the tuples are parsed so that the caller does
 *	not have to traverse the CIS list to find out if any of these tuples
 *	have been seen.
 *
 * For each tuple that we see, the following flags in the tuple_t->flags member
 *	are set/cleared:
 *
 *		CISTPLF_COPYOK - OK to copy tuple data
 *		CISTPLF_GLOBAL_CIS - tuple from global CIS
 *		CISTPLF_MF_CIS - tuple from MF CIS chain
 *		CISTPLF_FROM_AM - tuple read from AM space
 *		CISTPLF_FROM_CM - tuple read from CM space
 *		CISTPLF_LINK_INVALID - tuple link is invalid
 *		CISTPLF_PARAMS_INVALID - tuple body is invalid
 *		CISTPLF_AM_SPACE - this tuple is in AM space
 *		CISTPLF_CM_SPACE - this tuple is in CM space
 *		CISTPLF_LM_SPACE - this tuple is in local memory
 */
uint32_t
cis_list_lcreate(cistpl_callout_t *cistpl_callout, cisptr_t *cisptr,
    cis_info_t *cis_info, cisparse_t *cisparse, cs_socket_t *sp)
{
	cistpl_t *cp, *tp = NULL;
	cisdata_t tl, td, *dp;
	int done = 0, err;
	get_socket_t get_socket;


	/*
	 * If we were passed a non-NULL list base, that means that we should
	 *	parse the CIS and add any tuples we find to the end of the list
	 *	we were handed a pointer to.
	 */
	if (cis_info->cis) {
		tp = cis_info->cis;
	}

	get_socket.socket = sp->socket_num;
	if (SocketServices(SS_GetSocket, &get_socket) != SUCCESS) {
		cmn_err(CE_CONT,
		    "cis_list_lcreate: socket %d SS_GetSocket failed\n",
		    sp->socket_num);
		return (CS_BAD_SOCKET);
	}

	/*
	 * If this is primary CIS chain, the first tuple must be one
	 *	from the following list.
	 * Ref. PC Card 95, Metaformat Specification, Page 7.
	 * XXX Need to think this out a bit more to deal with 3.3V
	 *	cards and the description of where a CISTPL_DEVICE
	 *	can show up.
	 */

#if defined(CIS_DEBUG)
	if (cis_debug > 1) {
		cmn_err(CE_CONT, "cis_list_lcreate: td=0x%x cisptr=%p\n",
		    GET_CIS_DATA(cisptr), (void *)cisptr);
		cmn_err(CE_CONT, "\t flags=0x%x CW_CHECK_PRIMARY_CHAIN=0x%x\n",
		    cis_info->flags,  CW_CHECK_PRIMARY_CHAIN);
		cmn_err(CE_CONT, "\t IFType=0x%x IF_MEMORY=0x%x\n",
		    get_socket.IFType, IF_MEMORY);
	}
#endif

	if (cis_info->flags & CW_CHECK_PRIMARY_CHAIN) {
	switch (td = GET_CIS_DATA(cisptr)) {
		case CISTPL_DEVICE:
		case CISTPL_END:
		case CISTPL_LINKTARGET:
		    break;
		case CISTPL_NULL:
		/*
		 * Magicram memory cards without attribute memory
		 * do not have a CIS and return CISTPL_NULL.
		 */
		    if (get_socket.IFType == IF_MEMORY)
			return (0);
		    break;

		default:
		    return (0);
	    } /* switch */
	} /* CW_CHECK_PRIMARY_CHAIN */

	/*
	 * Update the number of chains counter
	 */
	cis_info->nchains++;

	/*
	 * The main tuple processing loop.  We'll exit this loop when either
	 *	a tuple's link field is CISTPL_END or we've seen a tuple type
	 *	field of CISTPL_END.
	 *
	 * Note that we also silently throw away CISTPL_NULL tuples, and don't
	 *	include them in the tuple count that we return.
	 */
	while (!done && ((td = GET_CIS_DATA(cisptr)) !=
						(cisdata_t)CISTPL_END)) {

#if defined(CIS_DEBUG)
		if ((cis_debug > 1) && (td != 0)) {
			cmn_err(CE_CONT, "cis_list_lcreate: td=0x%x cisptr=%p"
			    "offset=0x%x\n",
			    td, (void *)cisptr, cisptr->offset);
		}
#endif

		/*
		 * Ignore CISTPL_NULL tuples
		 */
		if (td != (cisdata_t)CISTPL_NULL) {
			/*
			 * point to tuple link field and get the link value
			 */
			if (!NEXT_CIS_ADDR(cisptr))
			    return ((uint32_t)BAD_CIS_ADDR);
			tl = GET_CIS_DATA(cisptr);
		/*
		 * This is an ugly PCMCIA hack - ugh! since the standard allows
		 *	a link byte of CISTPL_END to signify that this is the
		 *	last tuple.  The problem is that this tuple might
		 *	actually contain useful information, but we don't know
		 *	the size of it.
		 * We do know that it can't be more than CIS_MAX_TUPLE_DATA_LEN
		 *	bytes in length, however.  So, we pretend that the link
		 *	byte is CIS_MAX_TUPLE_DATA_LEN and also set a flag so
		 *	that when we're done processing this tuple, we will
		 *	break out of the while loop.
		 */
			if (tl == (cisdata_t)CISTPL_END) {
				tl = CIS_MAX_TUPLE_DATA_LEN;
				done = 1;
			}

		/*
		 * point to first byte of tuple data, allocate a new list
		 *	element and diddle with the list base and list
		 *	control pointers
		 */
			if (!NEXT_CIS_ADDR(cisptr))
			    return ((uint32_t)BAD_CIS_ADDR);
			cp = (cistpl_t *)CIS_MEM_ALLOC(sizeof (cistpl_t));
			cp->next = NULL;
			/*
			 * if we're not the first in the list, point to our
			 *	next
			 */
			if (tp)
				tp->next = cp;
			/*
			 * will be NULL if we're the first element of the
			 *	list
			 */
			cp->prev = tp;
			tp = cp;
			/*
			 * if this is the first element, save it's address
			 */
			if (!cis_info->cis)
				cis_info->cis = tp;
			tp->type = td;
			tp->len = tl;

			/*
			 * Save the address in CIS space that this tuple
			 *	begins at, as well as set tuple flags.
			 */
			cis_store_cis_addr(tp, cisptr);

			/*
			 * If this tuple has tuple data, we might need to
			 *	copy it.
			 * Note that the tuple data pointer (tp->data) will
			 *	be set to NULL for a tuple with no data.
			 */
#ifdef	XXX
			if (tl) {
#endif
			/*
			 * Read the data in the tuple and store it
			 *	away locally if we're allowed to. If
			 *	the CISTPLF_COPYOK flag is set, it means
			 *	that it's OK to touch the data portion
			 *	of the tuple.
			 *
			 * We need to make this check since some
			 *	tuples might contain active registers
			 *	that can alter the device state if they
			 *	are read before the card is correctly
			 *	initialized.  What a stupid thing to
			 *	allow in a standard, BTW.
			 *
			 * We first give the tuple handler a chance
			 *	to set any tuple flags that it wants
			 *	to, then we (optionally) do the data
			 *	copy, and give the tuple handler another
			 *	shot at the tuple.
			 *
			 * ref. PC Card Standard Release 2.01 in the
			 *	Card Metaformat section, section 5.2.6,
			 *	page 5-12.
			 */
			if ((err = cis_tuple_handler(cistpl_callout, tp,
						HANDTPL_SET_FLAGS, NULL, 0)) &
								HANDTPL_ERROR)
			    return (err);

			if (tl > (unsigned)0) {

				/*
				 * if we're supposed to make a local copy of
				 *	the tuple data, allocate space for it,
				 *	otherwise just record the PC card
				 *	starting address of this tuple.
				 * The address was saved by cis_store_cis_addr.
				 */
				if (tp->flags & CISTPLF_COPYOK) {
				    tp->data = (cisdata_t *)CIS_MEM_ALLOC(tl);
				    dp = tp->data;
				} else {
				    tp->data = GET_CIS_ADDR(tp);
				}

				while (tl--) {
				    if (tp->flags & CISTPLF_COPYOK)
					*dp++ = GET_CIS_DATA(cisptr);
				    if (!NEXT_CIS_ADDR(cisptr))
					return ((uint32_t)BAD_CIS_ADDR);
				}

				/*
				 * If we made a local copy of the tuple data,
				 *	then clear the AM and CM flags; if the
				 *	tuple data is still on the card, then
				 *	leave the flags alone.
				 */
				if (tp->flags & CISTPLF_COPYOK) {
				    tp->flags &= ~CISTPLF_SPACE_MASK;
				    tp->flags |= CISTPLF_LM_SPACE;
				}

			/*
			 * This is a tuple with no data in it's body, so
			 *	we just set the data pointer to NULL.
			 */
			} else {

			    tp->data = NULL;
				/*
				 * tp->flags &= ~(CISTPLF_SPACE_MASK |
				 *		CISTPLF_FROM_MASK);
				 */

			} /* if (tl > 0) */

			/*
			 * The main idea behind this call is to give
			 *	the handler a chance to validate the
			 *	tuple.
			 */
			if ((err = cis_tuple_handler(cistpl_callout, tp,
						HANDTPL_COPY_DONE, NULL, 0)) &
								HANDTPL_ERROR)
			    return (err);

#ifdef	XXX
			} else { /* if (tl) */
			    tp->data = NULL;
			}
#endif

			/*
			 * Check to see if this is a longlink tuple and if
			 *	so, do the necessary processing.
			 */
			if ((err = cis_process_longlink(cistpl_callout, tp,
								cis_info,
								cisparse)) &
								HANDTPL_ERROR)
			    return (err);

			cis_info->ntuples++;
		} else { /* if (td == CISTPL_NULL) */
			/*
			 * If we're a CISTPL_NULL we need to skip to
			 *	the beginning of the next tuple.
			 */
			if (!NEXT_CIS_ADDR(cisptr))
			    return ((uint32_t)BAD_CIS_ADDR);
		}
	} /* while (!done && !CISTPL_END) */

#if defined(CIS_DEBUG)
	if (cis_debug > 1) {
	    cmn_err(CE_CONT, "cis_list_lcreate: exit nchains=%x ntuples=%x\n",
		cis_info->nchains, cis_info->ntuples);
	}
#endif

	return (cis_info->ntuples);
}

/*
 * cis_process_longlink - processes longlink tuples
 *
 *	This function examines the passed-in tuple type and if it is a
 *	longlink tuple, the tuple is parsed and the appropriate flags in
 *	cis_info->flags are set.
 *
 *	If there is an error parsing the tuple, HANDTPL_ERROR is returned
 *	and the CW_LONGLINK_FOUND flags in cis_info->flags are cleared.
 */
static int
cis_process_longlink(cistpl_callout_t *cistpl_callout, cistpl_t *tp,
				cis_info_t *cis_info, cisparse_t *cisparse)
{
	/*
	 * If this is a CISTPL_LONGLINK_A, CISTPL_LONGLINK_C
	 *	or CISTPL_LONGLINK_MFC tuple, parse the tuple
	 *	and set appropriate CW_LONGLINK_XXX_FOUND flags.
	 * If this is a CISTPL_NO_LINK tuple, or if there is an
	 *	error parsing the tuple, clear all the
	 *	CW_LONGLINK_XXX_FOUND flags.
	 */
	switch (tp->type) {
	    case CISTPL_LONGLINK_A:
	    case CISTPL_LONGLINK_C:
	    case CISTPL_LONGLINK_MFC:
		cis_info->flags &= ~CW_LONGLINK_FOUND;
		if (cis_tuple_handler(cistpl_callout, tp,
						HANDTPL_PARSE_LTUPLE,
						cisparse, 0) &
							HANDTPL_ERROR)
		    return (HANDTPL_ERROR);
		switch (tp->type) {
		    case CISTPL_LONGLINK_A:
			cis_info->flags |= CW_LONGLINK_A_FOUND;
			break;
		    case CISTPL_LONGLINK_C:
			cis_info->flags |= CW_LONGLINK_C_FOUND;
			break;
		    case CISTPL_LONGLINK_MFC:
			cis_info->flags |= CW_LONGLINK_MFC_FOUND;
			break;
		} /* switch (tp->type) */
		break;
	    case CISTPL_NO_LINK:
		cis_info->flags &= ~CW_LONGLINK_FOUND;
		break;
	} /* switch (tp->type) */

	return (HANDTPL_NOERROR);
}

/*
 * cis_list_ldestroy - function to destroy a linked tuple list
 *
 *	cistpl_t *cistplbase - pointer to a pointer to the base of a
 *				local linked CIS list to destroy; the
 *				data that this pointer points to is
 *				also destroyed
 *
 * Once this function returns, cistplbase is set to NULL.
 */
uint32_t
cis_list_ldestroy(cistpl_t **cistplbase)
{
	cistpl_t *cp, *tp;
	int tpcnt = 0;

	/*
	 * First, check to see if we've got a
	 *	non-NULL list pointer.
	 */
	if ((tp = *cistplbase) == NULL)
	    return (0);

	while (tp) {
		/*
		 * Free any data that may be allocated
		 */
	    if ((tp->flags & CISTPLF_COPYOK) &&
			(tp->flags & CISTPLF_LM_SPACE) &&
						(tp->data))
		CIS_MEM_FREE((caddr_t)tp->data);

	    cp = tp->next;

		/*
		 * Free this tuple
		 */
	    CIS_MEM_FREE((caddr_t)tp);

	    tp = cp;

	    tpcnt++;
	}

	/*
	 * Now clear the pointer to the non-existant
	 *	linked list.
	 */
	*cistplbase = NULL;

	return (tpcnt);

}

/*
 * cis_get_ltuple - function to walk local linked CIS list and return
 *			a tuple based on various criteria
 *
 *	cistpl_t *tp - pointer to any valid tuple in the list
 *	cisdata_t type - type of tuple to search for
 *	int flags - type of action to perform (each is mutually exclusive)
 *		GET_FIRST_LTUPLEF, GET_LAST_LTUPLEF:
 *		    Returns the {first|last} tuple in the list.
 *		FIND_LTUPLE_FWDF, FIND_LTUPLE_BACKF:
 *		FIND_NEXT_LTUPLEF, FIND_PREV_LTUPLEF:
 *		    Returns the first tuple that matches the passed tuple type,
 *			searching the list {forward|backward}.
 *		GET_NEXT_LTUPLEF, GET_PREV_LTUPLEF:
 *		    Returns the {next|previous} tuple in the list.
 *
 *	    The following bits can be set in the flags parameter:
 *		CIS_GET_LTUPLE_IGNORE - return tuples with
 *				CISTPLF_IGNORE_TUPLE set in cistpl_t->flags
 *
 * Note on searching:
 *	When using the FIND_LTUPLE_FWDF and FIND_LTUPLE_BACKF flags,
 *	the search starts at the passed tuple.  Continually calling this
 *	function with a tuple that is the same type as the passed type will
 *	continually return the same tuple.
 *
 *	When using the FIND_NEXT_LTUPLEF and FIND_PREV_LTUPLEF flags,
 *	the search starts at the {next|previous} tuple from the passed tuple.
 *
 * returns:
 *	cistpl_t * - pointer to tuple in list
 *	NULL - if error while processing list or tuple not found
 */
#define	GET_NEXT_LTUPLE(tp)	((tp->next)?tp->next:NULL)
#define	GET_PREV_LTUPLE(tp)	((tp->prev)?tp->prev:NULL)
cistpl_t *
cis_get_ltuple(cistpl_t *tp, cisdata_t type, uint32_t flags)
{
	cistpl_t *ltp = NULL;

	if (!tp)
	    return (NULL);

	switch (flags & CIS_GET_LTUPLE_OPMASK) {
	    case GET_FIRST_LTUPLEF:	/* return first tuple in list */
		do {
			ltp = tp;
		} while ((tp = GET_PREV_LTUPLE(tp)) != NULL);

		if (!(flags & CIS_GET_LTUPLE_IGNORE))
		    while (ltp && (ltp->flags & CISTPLF_IGNORE_TUPLE))
			ltp = GET_NEXT_LTUPLE(ltp);
		break;
	    case GET_LAST_LTUPLEF:	/* return last tuple in list */
		do {
			ltp = tp;
		} while ((tp = GET_NEXT_LTUPLE(tp)) != NULL);

		if (!(flags & CIS_GET_LTUPLE_IGNORE))
		    while (ltp && (ltp->flags & CISTPLF_IGNORE_TUPLE))
			ltp = GET_PREV_LTUPLE(ltp);
		break;
	    case FIND_LTUPLE_FWDF:	/* find tuple, fwd search from tp */
		do {
			if (tp->type == type)
			    if ((flags & CIS_GET_LTUPLE_IGNORE) ||
					(!(tp->flags & CISTPLF_IGNORE_TUPLE)))
				return (tp);	/* note return here */
		} while ((tp = GET_NEXT_LTUPLE(tp)) != NULL);
		break;
	    case FIND_LTUPLE_BACKF:
		/* find tuple, backward search from tp */
		do {
			if (tp->type == type)
			    if ((flags & CIS_GET_LTUPLE_IGNORE) ||
					(!(tp->flags & CISTPLF_IGNORE_TUPLE)))
				return (tp);	/* note return here */
		} while ((tp = GET_PREV_LTUPLE(tp)) != NULL);
		break;
	    case FIND_NEXT_LTUPLEF:	/* find tuple, fwd search from tp+1 */
		while ((tp = GET_NEXT_LTUPLE(tp)) != NULL) {
			if (tp->type == type)
			    if ((flags & CIS_GET_LTUPLE_IGNORE) ||
					(!(tp->flags & CISTPLF_IGNORE_TUPLE)))
				return (tp);	/* note return here */
		} /* while */
		break;
	    case FIND_PREV_LTUPLEF:
		/* find tuple, backward search from tp-1 */
		while ((tp = GET_PREV_LTUPLE(tp)) != NULL) {
			if (tp->type == type)
			    if ((flags & CIS_GET_LTUPLE_IGNORE) ||
					(!(tp->flags & CISTPLF_IGNORE_TUPLE)))
				return (tp);	/* note return here */
		} /* while */
		break;
	    case GET_NEXT_LTUPLEF:	/* return next tuple in list */
		ltp = tp;
		while (((ltp = GET_NEXT_LTUPLE(ltp)) != NULL) &&
				(!(flags & CIS_GET_LTUPLE_IGNORE)) &&
					(ltp->flags & CISTPLF_IGNORE_TUPLE))
			;
		break;
	    case GET_PREV_LTUPLEF:	/* return prev tuple in list */
		ltp = tp;
		while (((ltp = GET_PREV_LTUPLE(ltp)) != NULL) &&
				(!(flags & CIS_GET_LTUPLE_IGNORE)) &&
					(ltp->flags & CISTPLF_IGNORE_TUPLE))
			;
		break;
	    default:	/* ltp is already NULL in the initialization */
		break;
	} /* switch */

	return (ltp);
}

/*
 * cis_convert_devspeed - converts a devspeed value to nS or nS
 *				to a devspeed entry
 */
uint32_t
cis_convert_devspeed(convert_speed_t *cs)
{
	cistpl_devspeed_struct_t *cd = &cistpl_devspeed_struct;
	unsigned exponent = 0, mantissa = 0;

	/*
	 * Convert nS to a devspeed value
	 */
	if (cs->Attributes & CONVERT_NS_TO_DEVSPEED) {
	    unsigned tnS, tmanv = 0, i;

	/*
	 * There is no device speed code for 0nS
	 */
	    if (!cs->nS)
		return (CS_BAD_SPEED);

	/*
	 * Handle any nS value below 10nS specially since the code
	 *	below only works for nS values >= 10.  Now, why anyone
	 *	would want to specify a nS value less than 10 is
	 *	certainly questionable, but it is allowed by the spec.
	 */
	    if (cs->nS < 10) {
		tmanv = cs->nS * 10;
		mantissa = CISTPL_DEVSPEED_MAX_MAN;
	    }

	    /* find the exponent */
	    for (i = 0; i < CISTPL_DEVSPEED_MAX_EXP; i++) {
		if ((!(tnS = ((cs->nS)/10))) ||
				(mantissa == CISTPL_DEVSPEED_MAX_MAN)) {
		    /* find the mantissa */
		    for (mantissa = 0; mantissa < CISTPL_DEVSPEED_MAX_MAN;
								mantissa++) {
			if (cd->mantissa[mantissa] == tmanv) {
			    cs->devspeed = ((((mantissa<<3) |
				(exponent & (CISTPL_DEVSPEED_MAX_EXP - 1)))));
			    return (CS_SUCCESS);
			}
		    } /* for (mantissa<CISTPL_DEVSPEED_MAX_MAN) */
		} else {
		    exponent = i + 1;
		    tmanv = cs->nS;
		    cs->nS = tnS;
		} /* if (!tnS) */
	    } /* for (i<CISTPL_DEVSPEED_MAX_EXP) */
	/*
	 * Convert a devspeed value to nS
	 */
	} else if (cs->Attributes & CONVERT_DEVSPEED_TO_NS) {
	    exponent = (cs->devspeed & (CISTPL_DEVSPEED_MAX_TBL - 1));
	    if ((mantissa = (((cs->devspeed)>>3) &
				(CISTPL_DEVSPEED_MAX_MAN - 1))) == 0) {
		if ((cs->nS = cd->table[exponent]) == 0)
		    return (CS_BAD_SPEED);
		return (CS_SUCCESS);
	    } else {
		if ((cs->nS = ((cd->mantissa[mantissa] *
					cd->exponent[exponent]) / 10)) == 0)
		    return (CS_BAD_SPEED);
		return (CS_SUCCESS);
	    }
	} else {
	    return (CS_BAD_ATTRIBUTE);
	}

	return (CS_BAD_SPEED);
}

/*
 * This array is for the cis_convert_devsize function.
 */
static uint32_t cistpl_device_size[8] =
	{ 512, 2*1024, 8*1024, 32*1024, 128*1024, 512*1024, 2*1024*1024, 0 };

/*
 * cis_convert_devsize - converts a devsize value to a size in bytes value
 *				or a size in bytes value to a devsize value
 */
uint32_t
cis_convert_devsize(convert_size_t *cs)
{
	int i;

	if (cs->Attributes & CONVERT_BYTES_TO_DEVSIZE) {
	    if ((cs->bytes < cistpl_device_size[0]) ||
				(cs->bytes > (cistpl_device_size[6] * 32)))
	    return (CS_BAD_SIZE);

	    for (i = 6; i >= 0; i--)
		if (cs->bytes >= cistpl_device_size[i])
		    break;

	    cs->devsize = ((((cs->bytes/cistpl_device_size[i]) - 1) << 3) |
								(i & 7));

	} else if (cs->Attributes & CONVERT_DEVSIZE_TO_BYTES) {
	    if ((cs->devsize & 7) == 7)
		return (CS_BAD_SIZE);
	    cs->bytes =
		cistpl_device_size[cs->devsize & 7] * ((cs->devsize >> 3) + 1);
	} else {
	    return (CS_BAD_ATTRIBUTE);
	}

	return (CS_SUCCESS);
}

/*
 * cis_list_create - reads the card's CIS and creates local CIS lists for
 *			each function on the card
 *
 * This function will read the CIS on the card, follow all CISTPL_LONGLINK_A,
 *	CISTPL_LONGLINK_C and CISTPL_LONGLINK_MFC tuples and create local CIS
 *	lists for each major CIS chain on the card.
 *
 * If there are no errors, the parameters returned are:
 *	For a non-multifunction card:
 *		sp->cis_flags - CW_VALID_CIS set
 *		sp->nfuncs - set to 0x0
 *		sp->cis[CS_GLOBAL_CIS] - contains CIS list
 *		sp->cis[CS_GLOBAL_CIS].cis_flags - CW_VALID_CIS set
 *
 *	For a multifunction card:
 *	    Global CIS values:
 *		sp->cis_flags - CW_VALID_CIS & CW_MULTI_FUNCTION_CIS set
 *		sp->nfuncs - set to number of functions specified in
 *				the CISTPL_LONGLINK_MFC tuple
 *		sp->cis[CS_GLOBAL_CIS] - contains global CIS list
 *		sp->cis[CS_GLOBAL_CIS].cis_flags - CW_VALID_CIS set
 *	    Function-specific CIS values:
 *		sp->cis[0..sp->nfuncs-1] - contains function-specific CIS lists
 *		sp->cis[0..sp->nfuncs-1].cis_flags - CW_VALID_CIS &
 *						CW_MULTI_FUNCTION_CIS set
 *
 *	returns:
 *		CS_SUCCESS - if no errors
 *		CS_NO_CIS - if no CIS on card
 *		CS_BAD_WINDOW or CS_GENERAL_FAILURE - if CIS window could
 *				not be setup
 *		CS_BAD_CIS - if error creating CIS chains
 *		CS_BAD_OFFSET - if cis_list_lcreate tried to read past the
 *				boundries of the allocated CIS window
 */
extern cistpl_ignore_list_t cistpl_ignore_list[];
uint32_t
cis_list_create(cistpl_callout_t *cistpl_callout, cs_socket_t *sp)
{
	cisptr_t cisptr;
	cisparse_t cisparse;
	cis_info_t *cis_info;
	cistpl_longlink_ac_t *cistpl_longlink_ac;
	cistpl_longlink_mfc_t cistpl_longlink_mfc, *mfc;
	cistpl_ignore_list_t *cil;
	int fn, ret;

	/*
	 * Initialize the CIS structures
	 */
	bzero((caddr_t)&sp->cis, ((sizeof (cis_info_t)) * CS_MAX_CIS));

	/*
	 * Start reading the primary CIS chain at offset 0x0 of AM. Assume
	 *	that there is a CISTPL_LONGLINK_C tuple that points to
	 *	offset 0x0 of CM space.
	 * Since this is the primary CIS chain, set CW_CHECK_PRIMARY_CHAIN
	 *	so that we'll check for a valid first tuple.
	 */
	cis_info = &sp->cis[CS_GLOBAL_CIS];
	cis_info->flags = (CW_LONGLINK_C_FOUND | CW_CHECK_PRIMARY_CHAIN);
	cisptr.flags = (CISTPLF_AM_SPACE | CISTPLF_GLOBAL_CIS);
	cisptr.size = sp->cis_win_size - 1;
	cisptr.offset = 0;
	cistpl_longlink_ac = (cistpl_longlink_ac_t *)&cisparse;
	cistpl_longlink_ac->flags = CISTPL_LONGLINK_AC_CM;
	cistpl_longlink_ac->tpll_addr = 0;

	if ((ret = cis_create_cis_chain(sp, cistpl_callout, &cisptr,
						cis_info, &cisparse)) !=
								CS_SUCCESS) {
	    return (ret);
	} /* cis_create_cis_chain */

	/*
	 * If there are no tuples in the primary CIS chain, it means that
	 *	this card doesn't have a CIS on it.
	 */
	if (cis_info->ntuples == 0)
	    return (CS_NO_CIS);

	/*
	 * Mark this CIS list as being valid.
	 */
	cis_info->flags |= CW_VALID_CIS;

	/*
	 * Mark this socket as having at least one valid CIS chain.
	 */
	sp->cis_flags |= CW_VALID_CIS;
	sp->nfuncs = 0;

	/*
	 * If the primary CIS chain specified that there are function-specific
	 *	CIS chains, we need to create each of these chains. If not,
	 *	then we're all done and we can return.
	 */
	if (!(cis_info->flags & CW_LONGLINK_MFC_FOUND))
	    return (CS_SUCCESS);

	/*
	 * Mark this socket as having a multi-function CIS.
	 */
	sp->cis_flags |= CW_MULTI_FUNCTION_CIS;

	/*
	 * At this point, cis_create_cis_chain has told us that the primary
	 *	CIS chain says that there are function-specific CIS chains
	 *	on the card that we need to follow. The cisparse variable now
	 *	contains the parsed output of the CISTPL_LONGLINK_MFC
	 *	tuple. We need to save that information and then process
	 *	each function-specific CIS chain.
	 */
	bcopy((caddr_t)&cisparse, (caddr_t)&cistpl_longlink_mfc,
					sizeof (cistpl_longlink_mfc_t));
	mfc = &cistpl_longlink_mfc;
	sp->nfuncs = mfc->nregs;

	/*
	 * Go through and create a CIS list for each function-specific
	 *	CIS chain on the card. Set CW_CHECK_LINKTARGET since all
	 *	function-specific CIS chains must begin with a valid
	 *	CISTPL_LINKTARGET tuple. Also set CW_RET_ON_LINKTARGET_ERROR
	 *	since we want to return an error if the CISTPL_LINKTARGET
	 *	tuple is invalid or missing.
	 */
	for (fn = 0; fn < sp->nfuncs; fn++) {
	    cis_info = &sp->cis[fn];
	    cis_info->flags = (CW_CHECK_LINKTARGET |
					CW_RET_ON_LINKTARGET_ERROR);
		/*
		 * If the function-specific CIS chain starts
		 *	in AM space, then multiply address by
		 *	2 since only even bytes are counted in
		 *	the CIS when AM addresses are specified,
		 *	otherwise use the
		 *	address as specified.
		 */
	    if (mfc->function[fn].tas == CISTPL_LONGLINK_MFC_TAS_AM) {
		cisptr.flags = (CISTPLF_AM_SPACE | CISTPLF_MF_CIS);
		cisptr.offset = mfc->function[fn].addr * 2;
	    } else {
		cisptr.flags = (CISTPLF_CM_SPACE | CISTPLF_MF_CIS);
		cisptr.offset = mfc->function[fn].addr;
	    }

	    if ((ret = cis_create_cis_chain(sp, cistpl_callout, &cisptr,
						cis_info, &cisparse)) !=
								CS_SUCCESS) {
		cmn_err(CE_CONT,
		    "cis_list_create: socket %d ERROR_MFC = 0x%x\n",
		    sp->socket_num, ret);
		return (ret);
	    } /* cis_create_cis_chain */

		/*
		 * Mark this CIS list as being valid and as being a
		 *	function-specific CIS list.
		 */
	    cis_info->flags |= (CW_VALID_CIS | CW_MULTI_FUNCTION_CIS);

		/*
		 * Check for tuples that we want to ignore
		 *	in the global CIS.  If the tuple exists
		 *	in the global CIS and in at least one
		 *	of the function-specific CIS lists, then
		 *	we flag the tuple
		 *	in the global CIS to be ignored.
		 */
	    cil = &cistpl_ignore_list[0];
	    while (cil->type != CISTPL_NULL) {
		if (cis_get_ltuple(sp->cis[fn].cis, cil->type,
					FIND_LTUPLE_FWDF |
					CIS_GET_LTUPLE_IGNORE) != NULL) {
		    cistpl_t *gtp = sp->cis[CS_GLOBAL_CIS].cis;
		    while ((gtp = cis_get_ltuple(gtp, cil->type,
					FIND_LTUPLE_FWDF |
					CIS_GET_LTUPLE_IGNORE)) != NULL) {
			gtp->flags |= CISTPLF_IGNORE_TUPLE;
			gtp = cis_get_ltuple(gtp, 0, GET_NEXT_LTUPLEF |
							CIS_GET_LTUPLE_IGNORE);
		    } /* while */
		} /* if (cis_get_ltuple(cis[fn])) */
		cil++;
	    } /* while */
	} /* for */

	return (CS_SUCCESS);
}

/*
 * cis_create_cis_chain - creates a single CIS chain
 *
 * This function reads the CIS on a card and follows any CISTPL_LONGLINK_A
 *	and CISTPL_LONGLINK_C link tuples to create a single CIS chain. We
 *	keep reading the CIS and following any CISTPL_LONGLINK_A and
 *	CISTPL_LONGLINK_C tuples until we don't see anymore. If we see a
 *	CISTPL_LONGLINK_MFC tuple, we return - the caller is responsible
 *	for following CIS chains on a per-function level.
 *
 * The following parameters must be initialized by the caller:
 *
 *	sp - pointer to a cs_socket_t structure that describes the socket
 *			and card in this socket
 *	cistpl_callout - pointer to a cistpl_callout_t array of structures
 *	cisptr->flags - either CISTPLF_AM_SPACE or CISTPLF_CM_SPACE
 *	cisptr->size - size of CIS window
 *	cisptr->offset - offset in AM or CM space on card to start
 *			reading tuples from
 *	cis_info - pointer to a cis_info_t structure where this list will
 *			be anchored on
 *	cisparse - pointer to a cisparse_t structure where the last longlink
 *			parsed tuple data will be returned
 *
 * To check the CISTPL_LINKTARGET tuple at the beginning of the first
 *	CIS chain that this function encounters, set CW_CHECK_LINKTARGET
 *	in cis_info->flags before calling this function.
 *
 * This function returns:
 *
 *	CS_SUCCESS - if CIS chain was created sucessfully or there
 *			were no tuples found on the first CIS chain
 *	CS_BAD_WINDOW or CS_GENERAL_FAILURE - if CIS window could
 *			not be setup
 *	CS_BAD_CIS - if error creating CIS chain
 *	CS_BAD_OFFSET - if cis_list_lcreate tried to read past the
 *			boundries of the allocated CIS window
 *
 * Note that if the first tuple of the target CIS chain is supposed
 *	to contain a CISTPL_LINKTARGET and the target chain does not
 *	contain that tuple (or that tuple is invalid in some way) and
 *	the CW_RET_ON_LINKTARGET_ERROR flag is not set, we don't flag
 *	this as an error, we just return. This is to handle the case
 *	where the target chain is in uninitialized memory and will be
 *	initialized later.
 * To return an error if an invalid CISTPL_LINKTARGET tuple is seen,
 *	set the CW_RET_ON_LINKTARGET_ERROR flag in cis_info->flags
 *	before calling this function.
 */
static int
cis_create_cis_chain(cs_socket_t *sp, cistpl_callout_t *cistpl_callout,
				cisptr_t *cisptr, cis_info_t *cis_info,
							cisparse_t *cisparse)
{
	cistpl_t *tps = NULL;
	uint32_t ret;

	do {
	    if ((ret = CIS_CARD_SERVICES(InitCISWindow, sp, &cisptr->offset,
				&cisptr->handle, cisptr->flags)) != CS_SUCCESS)
		return (ret);

		/*
		 * If we're pointing at a CIS chain that
		 *	is the target of a longlink tuple,
		 *	we need to validate the target chain
		 *	before we try to process it. If the
		 *	CISTPL_LINKTARGET tuple is invalid,
		 *	and the CW_RET_ON_LINKTARGET_ERROR
		 *	is not set, don't flag it as an error,
		 *	just return.
		 */
	    if (cis_info->flags & CW_CHECK_LINKTARGET) {
		cis_info->flags &= ~CW_CHECK_LINKTARGET;
		if (cis_validate_longlink_acm(cisptr) != CISTPLF_NOERROR) {
		    if (tps != NULL)
			cis_info->cis = tps;
		    if (cis_info->flags & CW_RET_ON_LINKTARGET_ERROR) {
			cis_info->flags &= ~CW_RET_ON_LINKTARGET_ERROR;
			return (CS_BAD_CIS);
		    } else {
			return (CS_SUCCESS);
		    } /* CW_RET_ON_LINKTARGET_ERROR */
		} /* cis_validate_longlink_acm */
	    } /* CW_CHECK_LINKTARGET */

	    ret = cis_list_lcreate(cistpl_callout, cisptr, cis_info, cisparse,
		sp);

#if defined(CIS_DEBUG)
	    if (cis_debug > 1) {
		cmn_err(CE_CONT, "cis_create_cis_chain: ret=0x%x"
		    " BAD_CIS_ADDR=0x%x CS_BAD_SOCKET=0x%x\n",
		    ret, BAD_CIS_ADDR, CS_BAD_SOCKET);
	    }
#endif


	    if ((ret & HANDTPL_ERROR) || (ret == (uint32_t)BAD_CIS_ADDR)) {
		if (tps != NULL)
		    cis_info->cis = tps;
		if (ret == (uint32_t)BAD_CIS_ADDR)
		    return (CS_BAD_OFFSET);
		else
		    return (CS_BAD_CIS);
	    }

		/*
		 * If we're creating the primary CIS chain
		 *	and we haven't seen any tuples,
		 *	then return CS_SUCCESS. The caller will
		 *	have to check cis_info->ntuples to find
		 *	out if any tuples were found.
		 * If we're processing the target of a longlink
		 *	tuple, then by now we have already validated
		 *	the CISTPL_LINKTARGET tuple so that we
		 *	know we'll have at least one tuple in
		 *	our list.
		 */
	    if (cis_info->ntuples == 0)
		return (CS_SUCCESS);

		/*
		 * If we've just created a new list, we need to
		 *	save the pointer to the start of the list.
		 */
	    if (tps == NULL)
		tps = cis_info->cis;

	    switch (cis_info->flags & CW_LONGLINK_FOUND) {
		cistpl_longlink_ac_t *cistpl_longlink_ac;

		case CW_LONGLINK_A_FOUND:
		    cistpl_longlink_ac = (cistpl_longlink_ac_t *)cisparse;
		    cisptr->flags &= ~(CISTPLF_SPACE_MASK | CISTPLF_FROM_MASK);
		    cisptr->flags |= CISTPLF_AM_SPACE;
			/*
			 * Multiply address by 2 since only
			 *	even bytes are counted in the CIS
			 *	when AM addresses are specified.
			 */
		    cisptr->offset = cistpl_longlink_ac->tpll_addr * 2;
		    cis_info->flags |= CW_CHECK_LINKTARGET;

			/*
			 * Point to the last tuple in the list.
			 */
		    cis_info->cis = cis_get_ltuple(cis_info->cis, 0,
							GET_LAST_LTUPLEF);
		    break;
		case CW_LONGLINK_C_FOUND:
		    cistpl_longlink_ac = (cistpl_longlink_ac_t *)cisparse;
		    cisptr->flags &= ~(CISTPLF_SPACE_MASK | CISTPLF_FROM_MASK);
		    cisptr->flags |= CISTPLF_CM_SPACE;
		    cisptr->offset = cistpl_longlink_ac->tpll_addr;
		    cis_info->flags |= CW_CHECK_LINKTARGET;

			/*
			 * Point to the last tuple in the list.
			 */
		    cis_info->cis = cis_get_ltuple(cis_info->cis, 0,
							GET_LAST_LTUPLEF);
		    break;
		case CW_LONGLINK_MFC_FOUND:
		    break;
		default:
		    break;
	    } /* switch (cis_info->flags) */

	} while (cis_info->flags & (CW_LONGLINK_A_FOUND | CW_LONGLINK_C_FOUND));

	/*
	 * If we needed to save a pointer to the start of the list because
	 *	we saw a longlink tuple, restore the list head pointer now.
	 */
	if (tps != NULL)
	    cis_info->cis = tps;

	return (CS_SUCCESS);
}

/*
 * cis_list_destroy - destroys the local CIS list
 */
uint32_t
cis_list_destroy(cs_socket_t *sp)
{
	int fn;

	/*
	 * Destroy any CIS list that we may have created. It's OK to pass
	 *	a non-existant CIS list pointer to cis_list_ldestroy since
	 *	that function will not do anything if there is nothing in
	 *	the passed CIS list to cleanup.
	 */
	for (fn = 0; fn < CS_MAX_CIS; fn++)
	    (void) cis_list_ldestroy(&sp->cis[fn].cis);

	/*
	 * Clear out any remaining state.
	 */
	bzero((caddr_t)&sp->cis, ((sizeof (cis_info_t)) * CS_MAX_CIS));
	sp->cis_flags = 0;
	sp->nfuncs = 0;

	return (CS_SUCCESS);
}

/*
 * cis_store_cis_addr - saves the current CIS address and space type
 *	of the beginning of the tuple into the passed linked list element.
 *	Note that this function will decrement the CIS address by two
 *	elements prior to storing it to the linked list element to point
 *	to the tuple type byte.
 *
 * This function also sets the following flags in tp->flags if they are set
 *	in ptr->flags:
 *
 *		CISTPLF_GLOBAL_CIS - tuple in global CIS
 *		CISTPLF_MF_CIS - tuple in function-specific CIS
 */
static void
cis_store_cis_addr(cistpl_t *tp, cisptr_t *ptr)
{

	if (ptr->flags & CISTPLF_AM_SPACE)
	    tp->offset = ptr->offset - 4;
	else
	    tp->offset = ptr->offset - 2;

	tp->flags &= ~(CISTPLF_SPACE_MASK | CISTPLF_FROM_MASK |
					CISTPLF_GLOBAL_CIS | CISTPLF_MF_CIS);
	tp->flags |= (ptr->flags & (CISTPLF_SPACE_MASK |
					CISTPLF_GLOBAL_CIS | CISTPLF_MF_CIS));

	if (tp->flags & CISTPLF_AM_SPACE)
	    tp->flags |= CISTPLF_FROM_AM;

	if (tp->flags & CISTPLF_CM_SPACE)
	    tp->flags |= CISTPLF_FROM_CM;
}
