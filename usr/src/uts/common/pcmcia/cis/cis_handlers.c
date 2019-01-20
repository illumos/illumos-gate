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

/*
 * This file contains the tuple handlers that are called by the CIS
 *	parser.
 *
 * XXX - how about a better explaination??
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
#include <sys/ddi_impldefs.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/callb.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>
#include <pcmcia/sys/cis_protos.h>

/*
 * Function prototypes
 */
static void cistpl_pd_parse(cistpl_t *, cistpl_cftable_entry_pwr_t *);
static void cis_return_name(cistpl_callout_t *, cistpl_get_tuple_name_t *);

/*
 * Fetch data functions.
 */
uint16_t
cis_get_short(cistpl_t *tp)
{
	uint16_t result;

	if (tp->flags & CISTPLF_AM_SPACE) {
		result = GET_AM_BYTE(tp);
		result |= GET_AM_BYTE(tp) << 8;
	} else {
		result = GET_CM_BYTE(tp);
		result |= GET_CM_BYTE(tp) << 8;
	}
	return (result);
}

uint16_t
cis_get_be_short(cistpl_t *tp)
{
	uint16_t result;

	if (tp->flags & CISTPLF_AM_SPACE) {
		result = GET_AM_BYTE(tp) << 8;
		result |= GET_AM_BYTE(tp);
	} else {
		result = GET_CM_BYTE(tp) << 8;
		result |= GET_CM_BYTE(tp);
	}
	return (result);
}

uint32_t
cis_get_int24(cistpl_t *tp)
{
	uint32_t result = cis_get_short(tp);

	result |= GET_BYTE(tp) << 16;
	return (result);
}

uint32_t
cis_get_long(cistpl_t *tp)
{
	uint32_t result = cis_get_short(tp);

	result |= cis_get_short(tp) << 16;
	return (result);
}

/*
 * cis_tuple_handler - call the handler for the tuple described by the
 *				tuple pointer
 *
 *	cistpl_callout_t *co - pointer to callout structure
 *				array to use to find this tuple
 *	cistpl_t *tp - pointer to a tuple structure
 *	int flags - action for the handler to perform
 * XXX - we need a description of the flags passed to the tuple handler
 *	void *arg - argument to pass on to tuple handler
 *
 * If the tuple is not recognized but is is a vendor-specific tuple, we
 *	set the CISTPLF_VENDOR_SPECIFIC flag in the tuple.
 *
 * We return CISTPLF_UNKNOWN if this is an unrecognized	tuple as well as
 *	set the CISTPLF_UNKNOWN flag in the tuple list structure.  Note
 *	that encountering an unknown tuple is not necessarily an error,
 *	so we don't set the HANDTPL_ERROR flag on the return code.  It
 *	is up to the caller to determine what an unrecognized tuple means.
 *
 * If this is a recognized tuple, the apropriate tuple handler is called and
 *	the return value from the handler is returned directly to the caller.
 *
 * The void *arg is optional, and it's meaning is dependent on the
 *	particular tuple handler called and the flags parameter.
 *
 * For the special case of HANDTPL_RETURN_NAME, we don't bother calling the
 *	tuple handler and just return the tuple name to the caller.
 */
uint32_t
cis_tuple_handler(cistpl_callout_t *co, cistpl_t *tp, uint32_t flags,
					void *arg, cisdata_t subtype)
{
	/*
	 * Check to see if this is a vendor-specific tuple.
	 */
	if (CISTPL_IS_VENDOR_SPECIFIC(tp->type))
	    tp->flags |= CISTPLF_VENDOR_SPECIFIC;

	/*
	 * Scan the callout list until we find the tuple passed to us, or we
	 *	encounter a CISTPL_END in the callout list, which signals that
	 *	there are no more tuples in the callout list.
	 */
	while (co->type != (cisdata_t)CISTPL_END) {
	    if (co->type == tp->type &&
		((tp->type != CISTPL_FUNCE) ||
		    (tp->type == CISTPL_FUNCE && co->subtype == subtype))) {
			tp->flags &= ~CISTPLF_UNKNOWN;
			if (flags & HANDTPL_RETURN_NAME) {
			    cis_return_name(co, (cistpl_get_tuple_name_t *)arg);
			    return (CISTPLF_NOERROR);
			} else {
			    return ((*co->handler) (co, tp, flags, arg));
			} /* HANDTPL_RETURN_NAME */
	    } /* if */
	    co++;
	} /* while */

	/*
	 * If we didn't recognize the tuple and the caller wants the tuple
	 *	name back, then return the "unknown tuple" string. At this
	 *	point, "co" will be pointing to the last entry in the
	 *	callout list. It's not an error to not recognize the tuple
	 *	when the operation is HANDTPL_RETURN_NAME.
	 */
	if (flags & HANDTPL_RETURN_NAME) {
	    cis_return_name(co, (cistpl_get_tuple_name_t *)arg);
	    return (CISTPLF_NOERROR);
	}

	tp->flags |= CISTPLF_UNKNOWN;
	return (CISTPLF_UNKNOWN);
}

/*
 * cis_no_tuple_handler - this generic tuple handler is used if no special
 *				tuple processing is required for the passed
 *				tuple
 *
 *	cistpl_callout_t *co - pointer to this tuple's entry in the
 *				tuple callout structure
 *	cistpl_t *tp - pointer to this tuple's entry in the local linked list
 *	int flags - action to perform
 *
 * This handler will set the CISTPLF_COPYOK flag if the tuple link is greater
 *	than zero, indicating that it's OK to copy the tuple data body. It
 *	will also set whatever flags are specified in the callout structure.
 *
 * We always set the CISTPLF_VALID when we're called with HANDTPL_COPY_DONE.
 *
 * We return CISTPLF_UNKNOWN if we're being called to parse the tuple.
 *
 * We return CISTPLF_NOERROR in every other case to indicate that this is a
 *	recognized tuple.
 */
/*ARGSUSED*/
uint32_t
cis_no_tuple_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	if (flags & HANDTPL_SET_FLAGS) {
		tp->flags |= co->flags;	/* XXX - is = the right thing here? */
		if (tp->len > 0)
			tp->flags |= CISTPLF_COPYOK;
	}

	if (flags & HANDTPL_COPY_DONE)
		tp->flags |= CISTPLF_VALID;

	if (flags & HANDTPL_PARSE_LTUPLE)
	    return (CISTPLF_UNKNOWN);

	return (CISTPLF_NOERROR);
}

/*
 * cis_unknown_tuple_handler - this generic tuple handler is used if we don't
 *				understand this tuple
 *
 *	cistpl_callout_t *co - pointer to this tuple's entry in the
 *				tuple callout structure
 *	cistpl_t *tp - pointer to this tuple's entry in the local linked list
 *	int flags - action to perform
 *
 * This handler will not set the CISTPLF_COPYOK flag since we don't know the
 *	contents of a vendor-specific tuple.
 *
 * We always set the CISTPLF_VALID when we're called with HANDTPL_COPY_DONE
 *	to specify that we understand this tuple's code, but not it's data
 *	body.
 *
 * We return CISTPLF_UNKNOWN if we're being called to parse the tuple or to
 *	perform any other operation.
 */
/*ARGSUSED*/
uint32_t
cis_unknown_tuple_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	if (flags & HANDTPL_SET_FLAGS) {
		tp->flags |= co->flags;	/* XXX - is = the right thing here? */
		return (CISTPLF_NOERROR);
	}

	if (flags & HANDTPL_COPY_DONE) {
		tp->flags |= CISTPLF_VALID;
		return (CISTPLF_NOERROR);
	}

	return (CISTPLF_UNKNOWN);
}

/*
 * cistpl_vers_1_handler - handler for the CISTPL_VERS_1 tuple
 *
 *	void *arg - points to a cistpl_vers_1_t * where the
 *			information is stuffed into
 */
uint32_t
cistpl_vers_1_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_vers_1_t *cs = (cistpl_vers_1_t *)arg;


		RESET_TP(tp);

		cs->major = GET_BYTE(tp);
		cs->minor = GET_BYTE(tp);
		for (cs->ns = 0; GET_LEN(tp) > 0 &&
				/* CSTYLED */
				cs->ns < CISTPL_VERS_1_MAX_PROD_STRINGS; ) {
			(void) strcpy(cs->pi[cs->ns++], cis_getstr(tp));
		} /* for */
	} /* HANDTPL_PARSE_LTUPLE */

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_config_handler - handler for the CISTPL_CONFIG tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 *
 * For the first ten config registers we set the present flags in the
 *	cistpl_config_t if the register exists.  The flags that we use
 *	for this are the same as the flags reguired for the Card Services
 *	RequestConfiguration function and they can be used by clients
 *	directly without requiring any remapping of values.
 *
 * XXX we don't handle TPCC_SBTPL subtuples yet
 */

uint32_t	config_regs_present_map[] = {
	CONFIG_OPTION_REG_PRESENT,	/* COR present */
	CONFIG_STATUS_REG_PRESENT,	/* STAT reg present */
	CONFIG_PINREPL_REG_PRESENT,	/* PRR present */
	CONFIG_COPY_REG_PRESENT,	/* COPY reg present */
	CONFIG_EXSTAT_REG_PRESENT,	/* EXSTAT reg present */
	CONFIG_IOBASE0_REG_PRESENT,	/* IOBASE0 reg present */
	CONFIG_IOBASE1_REG_PRESENT,	/* IOBASE1 reg present */
	CONFIG_IOBASE2_REG_PRESENT,	/* IOBASE2 reg present */
	CONFIG_IOBASE3_REG_PRESENT,	/* IOBASE3 reg present */
	CONFIG_IOLIMIT_REG_PRESENT,	/* IOLIMIT reg present */
};

uint32_t
cistpl_config_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	cisdata_t tpcc_sz;
	int i, n, nrb, na, hr = 0;

	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_config_t *cr = (cistpl_config_t *)arg;
		int crn = 0;

		RESET_TP(tp);

		tpcc_sz = GET_BYTE(tp);		/* config regs size fields */
		cr->last = GET_BYTE(tp);	/* last config index */

		na = (tpcc_sz&3)+1;		/* config regs address bytes */
		nrb = ((tpcc_sz>>2)&0x0f)+1;	/* number of bytes in config */
						/*	regs presence mask */

		/*
		 * Construct the base offset address for the config registers.
		 *	We jump through these hoops because the base address
		 *	can be between one and four bytes in length.
		 */
		cr->base = 0;
		n = na;
		while (n--)
			cr->base |= ((GET_BYTE(tp) & 0x0ff) <<
							(8 * (na - (n+1))));

		/*
		 * Go through the config register presense mask bit by bit and
		 *	figure out which config registers are present and which
		 *	aren't.
		 * For the first ten config registers, set the appropriate
		 *	bits in the cr->present member so that the caller
		 *	doesn't have to do this.
		 */
		cr->nr = 0;
		cr->present = 0;
		n = nrb;
		while (n--) {
			for (i = 0; i < 8; i++, crn++) {
				if (LOOK_BYTE(tp) & (1<<i)) {
				    if (crn < (sizeof (config_regs_present_map)/
							sizeof (uint32_t)))
					cr->present |=
						config_regs_present_map[crn];
				    cr->nr++;
				    cr->hr = hr;
				    cr->regs[hr] = MAKE_CONFIG_REG_ADDR(
								cr->base, hr);
				} /* LOOK_BYTE */
				hr++;
			} /* for */
			(void) GET_BYTE(tp);
		} /* while */
	}

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_device_handler - handler for the CISTPL_DEVICE, CISTPL_DEVICE_A,
 *				CISTPL_DEVICE_OC and CISTPL_DEVICE_OA tuples
 *
 *	void *arg - points to a cistpl_device_t * where the
 *			information is stuffed into
 *
 * XXX - we only handle CISTPL_DEVICE_MAX_DEVICES device descriptions
 *		described in the tuple
 */
uint32_t
cistpl_device_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	cisdata_t dev_id;

	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		convert_speed_t convert_speed;
		cistpl_device_t *dt = (cistpl_device_t *)arg;
		cistpl_device_node_t *cdn;

		/*
		 * XXX - fix this to look for more than one device definition
		 * XXX - fix this to handle the OC fields for
		 *	CISTPL_DEVICE_OC and CISTPL_DEVICE_OA
		 */
		dt->num_devices = 1;
		cdn = &dt->devnode[0];

		cdn->flags = 0;

		RESET_TP(tp);

		dev_id = GET_BYTE(tp);

		/*
		 * Get the device speed code.  If it's 7, then there is an
		 *	extended speed code table in use, so parse that.
		 *	If it's anything else, get the speed information
		 *	directly from the device speed code.
		 */
		if ((dev_id & 7) == 7) {
		    cdn->nS_speed = cistpl_devspeed(tp, 0, CISTPL_DEVSPEED_EXT);
		} else {
		    cdn->nS_speed = cistpl_devspeed(NULL, dev_id,
							CISTPL_DEVSPEED_TABLE);
		}

		/*
		 * Convert the speed in nS to a device speed code.
		 * XXX -  should check return code from cis_convert_devspeed()
		 */
		convert_speed.Attributes = CONVERT_NS_TO_DEVSPEED;
		convert_speed.nS = cdn->nS_speed;
		(void) cis_convert_devspeed(&convert_speed);
		cdn->speed = convert_speed.devspeed;

		if (dev_id & 8)
			cdn->flags |= CISTPL_DEVICE_WPS;

		/*
		 * Set the device type.  Note that we take the raw value
		 *	from the tuple and pass it back to the caller.
		 *	If the device type codes in the standard change,
		 *	we will have to change our flags as well.
		 */
		cdn->type = (dev_id>>4) & 0x0f;

		/*
		 * XXX - what about the device_size byte?  Is the spec wrong?
		 */
		cdn->size = GET_BYTE(tp);
		/* check for end of list */
		if (cdn->size != 0x0ff) {
		    convert_size_t convert_size;

		    convert_size.devsize = cdn->size;
		    convert_size.Attributes = CONVERT_DEVSIZE_TO_BYTES;
		    (void) cis_convert_devsize(&convert_size);
		    cdn->size_in_bytes = convert_size.bytes;
		}
	}

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_cftable_handler - handler for the CISTPL_CFTABLE_ENTRY tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 *
 *    Return:	CISTPLF_NOERROR - if no error parsing tuple
 *		HANDTPL_ERROR - if error parsing tuple
 */
extern uint32_t cistpl_cftable_io_size_table[];
extern uint32_t cistpl_cftable_shift_table[];

uint32_t
cistpl_cftable_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	cisdata_t tpce_indx, tpce_fs, tpce_td, sf, tpce_io, nr;
	cisdata_t ior_desc, tpce_ir, tpce_msd;
	int i, j;

	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_cftable_entry_t *ce = (cistpl_cftable_entry_t *)arg;

		RESET_TP(tp);

		/*
		 * Check to see if we have an interface description byte.  If
		 *	we do, grab it and give it directly to the caller, and
		 *	set a flag so the caller knows that it's there.
		 * We also setup the appropriate values in the ce->pin member
		 *	so that clients can feed this value directly to the
		 *	Card Services RequestConfiguration call.
		 */
		if ((tpce_indx = GET_BYTE(tp)) & CISTPL_CFTABLE_TPCE_IFM) {
			ce->ifc = GET_BYTE(tp);

			ce->pin = 0;

			if (ce->ifc & CISTPL_CFTABLE_TPCE_IF_BVD)
			    ce->pin |= (PRR_BVD1_STATUS | PRR_BVD2_STATUS |
					PRR_BVD1_EVENT | PRR_BVD2_EVENT);
			if (ce->ifc & CISTPL_CFTABLE_TPCE_IF_WP)
			    ce->pin |= (PRR_WP_STATUS | PRR_WP_EVENT);
			if (ce->ifc & CISTPL_CFTABLE_TPCE_IF_RDY)
			    ce->pin |= (PRR_READY_STATUS | PRR_READY_EVENT);

			ce->flags |= CISTPL_CFTABLE_TPCE_IF;
		}

		/*
		 * Return the configuration index to the caller, and set the
		 *	default configuration flag if this is a default
		 *	configuration.
		 */
		ce->index = tpce_indx & CISTPL_CFTABLE_TPCE_CFGENTRYM;
		if (tpce_indx & CISTPL_CFTABLE_TPCE_DEFAULTM)
			ce->flags |= CISTPL_CFTABLE_TPCE_DEFAULT;

		/*
		 * Feature selection flags.
		 */
		tpce_fs = GET_BYTE(tp);

		/*
		 * See what types of power information are available,
		 *	and if there is any, set the global power
		 *	information flag as well as a flag for each
		 *	power description available.
		 */
		if (tpce_fs & CISTPL_CFTABLE_TPCE_FS_PWRM) {
		    cistpl_cftable_entry_pd_t *pd = &ce->pd;

		    ce->flags |= CISTPL_CFTABLE_TPCE_FS_PWR;

		    switch (tpce_fs & CISTPL_CFTABLE_TPCE_FS_PWRM) {
			case CISTPL_CFTABLE_TPCE_FS_PWR_VPP2M:
				pd->flags |= CISTPL_CFTABLE_TPCE_FS_PWR_VPP2;
				/* FALLTHROUGH */
			case CISTPL_CFTABLE_TPCE_FS_PWR_VPP1M:
				pd->flags |= CISTPL_CFTABLE_TPCE_FS_PWR_VPP1;
				/* FALLTHROUGH */
			case CISTPL_CFTABLE_TPCE_FS_PWR_VCCM:
				pd->flags |= CISTPL_CFTABLE_TPCE_FS_PWR_VCC;
		    } /* switch */
		} /* if (CISTPL_CFTABLE_TPCE_FS_PWRM) */

		/*
		 * Set up the global memory information flag.
		 */
		if (tpce_fs & CISTPL_CFTABLE_TPCE_FS_MEMM)
			ce->flags |= CISTPL_CFTABLE_TPCE_FS_MEM;

		/*
		 * Parse the various power description structures.
		 */
		if (ce->flags & CISTPL_CFTABLE_TPCE_FS_PWR) {
			cistpl_cftable_entry_pd_t *pd = &ce->pd;
			cistpl_cftable_entry_pwr_t *pwr;
			/*
			 * Collect any Vcc information.
			 */
			if (pd->flags & CISTPL_CFTABLE_TPCE_FS_PWR_VCC) {
				pwr = &pd->pd_vcc;
				cistpl_pd_parse(tp, pwr);
			}
			/*
			 * Collect any Vpp1 information.
			 */
			if (pd->flags & CISTPL_CFTABLE_TPCE_FS_PWR_VPP1) {
				pwr = &pd->pd_vpp1;
				cistpl_pd_parse(tp, pwr);
			}
			/*
			 * Collect any Vpp2 information.
			 */
			if (pd->flags & CISTPL_CFTABLE_TPCE_FS_PWR_VPP2) {
				pwr = &pd->pd_vpp2;
				cistpl_pd_parse(tp, pwr);
			}
		} /* if (CISTPL_CFTABLE_TPCE_FS_PWR) */

		/*
		 * Check to see if there's any timing information, and if
		 *	so, parse the tuple data and store it in the
		 *	caller's structure.  Set a flag in the global
		 *	flag field indicating that there is timing information.
		 */
		if (tpce_fs & CISTPL_CFTABLE_TPCE_FS_TDM) {
			convert_speed_t convert_speed;
			cistpl_cftable_entry_speed_t *sp = &ce->speed;
			ce->flags |= CISTPL_CFTABLE_TPCE_FS_TD;
			tpce_td = GET_BYTE(tp);
			/*
			 * Parse TPCE_TD to get the various timing
			 *	scale factors. Each scale factor has
			 *	a value that indicates that the particular
			 *	timing parameter doesn't exist.
			 */
			if ((sf = (tpce_td &
					CISTPL_CFTABLE_TPCE_FS_TD_WAITM)) !=
			    CISTPL_CFTABLE_TPCE_FS_TD_WAITM) {
				sp->nS_wait = cistpl_devspeed(tp,
						GET_TPCE_FS_TD_WAITS(sf),
						CISTPL_DEVSPEED_EXT);
				convert_speed.Attributes =
							CONVERT_NS_TO_DEVSPEED;
				convert_speed.nS = sp->nS_wait;
				(void) cis_convert_devspeed(&convert_speed);
				sp->wait = convert_speed.devspeed;
				sp->flags |= CISTPL_CFTABLE_TPCE_FS_TD_WAIT;
			}

			if ((sf = (tpce_td & CISTPL_CFTABLE_TPCE_FS_TD_RDYM)) !=
			    CISTPL_CFTABLE_TPCE_FS_TD_RDYM) {
				sp->nS_rdybsy = cistpl_devspeed(tp,
						GET_TPCE_FS_TD_RDYS(sf),
						CISTPL_DEVSPEED_EXT);
				convert_speed.Attributes =
							CONVERT_NS_TO_DEVSPEED;
				convert_speed.nS = sp->nS_rdybsy;
				(void) cis_convert_devspeed(&convert_speed);
				sp->rdybsy = convert_speed.devspeed;
				sp->flags |= CISTPL_CFTABLE_TPCE_FS_TD_RDY;
			}

			if ((sf = (tpce_td &
					CISTPL_CFTABLE_TPCE_FS_TD_RSVDM)) !=
			    CISTPL_CFTABLE_TPCE_FS_TD_RSVDM) {
				sp->nS_rsvd = cistpl_devspeed(tp,
						GET_TPCE_FS_TD_RSVDS(sf),
						CISTPL_DEVSPEED_EXT);
				convert_speed.Attributes =
							CONVERT_NS_TO_DEVSPEED;
				convert_speed.nS = sp->nS_rsvd;
				(void) cis_convert_devspeed(&convert_speed);
				sp->rsvd = convert_speed.devspeed;
				sp->flags |= CISTPL_CFTABLE_TPCE_FS_TD_RSVD;
			}
		} /* if (CISTPL_CFTABLE_TPCE_FS_TDM) */


		/*
		 * Parse any I/O address information.  If there is I/O
		 *	inforamtion, set a flag in the global flag field
		 *	to let the caller know.
		 */
		if (tpce_fs & CISTPL_CFTABLE_TPCE_FS_IOM) {
			cistpl_cftable_entry_io_t *io = &ce->io;

			ce->flags |= CISTPL_CFTABLE_TPCE_FS_IO;
			tpce_io = GET_BYTE(tp);
			/*
			 * Pass any I/O flags that are in the tuple directly
			 *	to the caller.
			 */
			io->flags = tpce_io;
			io->addr_lines = tpce_io &
						CISTPL_CFTABLE_TPCE_FS_IO_ALM;
			/*
			 * If there are any ranges, extract the number of
			 *	ranges and the range descriptions.
			 */
			if (tpce_io & CISTPL_CFTABLE_TPCE_FS_IO_RANGEM) {
				cistpl_cftable_entry_io_range_t *ior;
				ior_desc = GET_BYTE(tp);
				/*
				 * Number of I/O ranges is the value specified
				 *	in the tuple plus one, so there's
				 *	always at least one I/O range if the
				 *	CISTPL_CFTABLE_TPCE_FS_IO_RANGEM bit
				 *	in the I/O flags register is set.
				 */
				nr = (ior_desc & 0x0f) + 1;
				io->ranges = nr;
				/*
				 * Cycle through each I/O range.
				 */
				for (i = 0; i < (int)nr; i++) {
					ior = &io->range[i];
					ior->addr = 0;
					ior->length = 0;
					/*
					 * Gather the address information.
					 *	It's OK if there's no address
					 *	information in which case this
					 *	loop will never execute.
					 */
					for (j = 0; j <
						cistpl_cftable_io_size_table[
							(ior_desc>>4)&3];
									j++)
						ior->addr |= (GET_BYTE(tp) <<
						cistpl_cftable_shift_table[j]);
					/*
					 * Gather the length information.
					 *	It's OK if there's no length
					 *	information in which case this
					 *	loop will never execute.
					 */
					for (j = 0; j <
						cistpl_cftable_io_size_table[
							(ior_desc>>6)&3];
									j++)
						ior->length |= (GET_BYTE(tp) <<
						cistpl_cftable_shift_table[j]);
				} /* for (nr) */
			} /* if (CISTPL_CFTABLE_TPCE_FS_IO_RANGEM) */
		} /* if (CISTPL_CFTABLE_TPCE_FS_IOM) */

		/*
		 * Parse any IRQ information.  If there is IRQ inforamtion,
		 *	set a flag in the global flag field to let the
		 *	caller know.
		 */
		if (tpce_fs & CISTPL_CFTABLE_TPCE_FS_IRQM) {
			cistpl_cftable_entry_irq_t *irq = &ce->irq;

			ce->flags |= CISTPL_CFTABLE_TPCE_FS_IRQ;
			tpce_ir = GET_BYTE(tp);
			/*
			 * Pass any IRQ flags that are in the tuple directly
			 *	to the caller.
			 */
			irq->flags = tpce_ir;
			/*
			 * Check for and parse the extended IRQ bitmask
			 *	if it exists.
			 */
			if (tpce_ir & CISTPL_CFTABLE_TPCE_FS_IRQ_MASKM) {
				irq->irqs = GET_BYTE(tp) & 0x0ff;
				irq->irqs |= (GET_BYTE(tp) << 8)&0x0ff00;
			} else {
				irq->irqs = (1<< (tpce_ir&0x0f));
			}
		} /* if (CISTPL_CFTABLE_TPCE_FS_IRQM) */

		/*
		 * Parse any memory information.
		 *
		 * XXX - should be a cleaner way to parse this information.
		 */
		if (ce->flags & CISTPL_CFTABLE_TPCE_FS_MEM) {
			cistpl_cftable_entry_mem_t *mem = &ce->mem;
			cistpl_cftable_entry_mem_window_t *win;
			/*
			 * Switch on the type of memory description
			 *	information that is available.
			 */
			switch (tpce_fs & CISTPL_CFTABLE_TPCE_FS_MEMM) {
				/*
				 * variable length memory space description
				 */
			case CISTPL_CFTABLE_TPCE_FS_MEM3M:
				mem->flags |= CISTPL_CFTABLE_TPCE_FS_MEM3;
				/* memory space descriptor */
				tpce_msd = GET_BYTE(tp);
				mem->windows = ((tpce_msd &
					(CISTPL_CFTABLE_ENTRY_MAX_MEM_WINDOWS -
								1)) + 1);
				/*
				 * If there's host address information, let
				 *	the caller know.
				 */
				if (tpce_msd & CISTPL_CFTABLE_TPCE_FS_MEM_HOSTM)
					mem->flags |=
						CISTPL_CFTABLE_TPCE_FS_MEM_HOST;
				/*
				 * Cycle through each window space description
				 *	and collect all the interesting bits.
				 */
				for (i = 0; i < mem->windows; i++) {
					win = &mem->window[i];
					win->length = 0;
					win->card_addr = 0;
					win->host_addr = 0;
					/*
					 * Gather the length information.
					 *	It's OK if there's no length
					 *	information in which case this
					 *	loop will never execute.
					 */
					for (j = 0; j <
						(int)((tpce_msd>>3)&3); j++)
						win->length |= (GET_BYTE(tp) <<
						cistpl_cftable_shift_table[j]);
					/*
					 * Gather the card address information.
					 *	It's OK if there's no card
					 *	address information in which
					 *	case this loop will never
					 *	execute.
					 */
					for (j = 0; j <
						(int)((tpce_msd>>5)&3); j++)
						win->card_addr |=
							(GET_BYTE(tp) <<
						cistpl_cftable_shift_table[j]);
					/*
					 * If there's a host address
					 *	description, grab that
					 *	as well.
					 */
					if (mem->flags &
					    CISTPL_CFTABLE_TPCE_FS_MEM_HOST) {
						/*
						 * Gather the host address
						 *	information.  It's OK
						 *	if there's no host
						 *	address information in
						 *	which case this loop
						 *	will never execute.
						 * Note that we use the card
						 *	address size to
						 *	determine how many
						 *	bytes of host address
						 *	are present.
						 */
						for (j = 0; j <
							(int)((tpce_msd>>5)&3);
									j++)
							win->host_addr |=
							(GET_BYTE(tp) <<
						cistpl_cftable_shift_table[j]);
					} else {
						/*
						 * No host address information,
						 *	so the host address is
						 *	equal to the card
						 *	address.
						 */
						win->host_addr = win->card_addr;
					}
				} /* for (i<mem->windows) */
				break;
				/*
				 * single length and card base address specified
				 */
			case CISTPL_CFTABLE_TPCE_FS_MEM2M:
				mem->flags |= CISTPL_CFTABLE_TPCE_FS_MEM2;
				win = &mem->window[0];
				mem->windows = 1;
				/*
				 * Construct the size of the window.
				 */
				win->length = GET_BYTE(tp);
				win->length |= (GET_BYTE(tp)<<8);
				win->length *=
					CISTPL_CFTABLE_TPCE_FS_MEM_PGSIZE;

				/*
				 * Construct the card base address.
				 */
				win->card_addr = GET_BYTE(tp);
				win->card_addr |= (GET_BYTE(tp)<<8);
				win->card_addr *=
					CISTPL_CFTABLE_TPCE_FS_MEM_PGSIZE;

				/*
				 * In this mode, both the host base address
				 *	and the card base address are equal.
				 */
				win->host_addr = win->card_addr;
				break;
				/*
				 * single length specified
				 */
			case CISTPL_CFTABLE_TPCE_FS_MEM1M:
				mem->flags |= CISTPL_CFTABLE_TPCE_FS_MEM1;
				win = &mem->window[0];
				mem->windows = 1;
				win->card_addr = 0;
				win->host_addr = 0;
				/*
				 * Construct the size of the window.
				 */
				win->length = GET_BYTE(tp);
				win->length |= (GET_BYTE(tp)<<8);
				win->length *=
					CISTPL_CFTABLE_TPCE_FS_MEM_PGSIZE;
				break;
			} /* switch (CISTPL_CFTABLE_TPCE_FS_MEMM) */
		} /* if (CISTPL_CFTABLE_TPCE_FS_MEM) */

		/*
		 * Check for and parse any miscellaneous information.
		 *
		 * We only understand how to parse the first
		 *	CISTPL_CFTABLE_TPCE_FS_MISC_MAX extension
		 *	bytes specified in the PC Card 95 standard;
		 *	we throw away any other extension bytes that
		 *	are past these bytes.
		 * XXX Note that the assumption here is that the
		 *	size of cistpl_cftable_entry_misc_t->flags
		 *	is at least CISTPL_CFTABLE_TPCE_FS_MISC_MAX
		 *	bytes in length.
		 */
		if (tpce_fs & CISTPL_CFTABLE_TPCE_FS_MISCM) {
		    cistpl_cftable_entry_misc_t *misc = &ce->misc;
		    int mb = CISTPL_CFTABLE_TPCE_FS_MISC_MAX;

		    ce->flags |= CISTPL_CFTABLE_TPCE_FS_MISC;
		    misc->flags = 0;

		    do {
			if (mb) {
			    misc->flags = (misc->flags << 8) | LOOK_BYTE(tp);
			    mb--;
			}
		    } while ((GET_BYTE(tp) & CISTPL_EXT_BIT) &&
				(!(tp->flags & CISTPLF_MEM_ERR)));

			/*
			 * Check to see if we tried to read past the
			 *	end of the tuple data; if we have,
			 *	there's no point in trying to parse
			 *	any more of the tuple.
			 */
		    if (tp->flags & CISTPLF_MEM_ERR)
			return (HANDTPL_ERROR);
		} /* if (CISTPL_CFTABLE_TPCE_FS_MISCM) */

		/*
		 * Check for and parse any additional subtuple
		 *	information. We know that there is
		 *	additional information if we haven't
		 *	reached the end of the tuple data area
		 *	and if the additional information is
		 *	in standard tuple format.
		 * If we don't recognize the additional info,
		 *	then just silently ignore it, don't
		 *	flag it as an error.
		 */
#ifdef	PARSE_STCE_TUPLES
		if (GET_LEN(tp) > 0) {

		ce->flags |= CISTPL_CFTABLE_TPCE_FS_STCE_EV
		ce->flags |= CISTPL_CFTABLE_TPCE_FS_STCE_PD
#endif

	} /* if (HANDTPL_PARSE_LTUPLE) */

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_pd_parse - read and parse a power description structure
 *
 *	cisdata_t **ddp - pointer to pointer tuple data area
 *	cistpl_cftable_entry_pwr_t *pd - pointer to local power description
 *					structure
 */
static void
cistpl_pd_parse(cistpl_t *tp, cistpl_cftable_entry_pwr_t *pd)
{
	cisdata_t pdesc;

	pdesc = GET_BYTE(tp);	/* power description selector */

	/* nominal supply voltage */
	if (pdesc & CISTPL_CFTABLE_PD_NOMV) {
		pd->nomV = cistpl_expd_parse(tp, &pd->nomV_flags) / 100;
		pd->nomV_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}

	/* minimum supply voltage */
	if (pdesc & CISTPL_CFTABLE_PD_MINV) {
		pd->minV = cistpl_expd_parse(tp, &pd->minV_flags) / 100;
		pd->minV_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}

	/* maximum supply voltage */
	if (pdesc & CISTPL_CFTABLE_PD_MAXV) {
		pd->maxV = cistpl_expd_parse(tp, &pd->maxV_flags) / 100;
		pd->maxV_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}

	/* continuous supply current */
	if (pdesc & CISTPL_CFTABLE_PD_STATICI) {
		pd->staticI_flags |= CISTPL_CFTABLE_PD_MUL10;
		pd->staticI = cistpl_expd_parse(tp, &pd->staticI_flags);
		pd->staticI_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}

	/* maximum current required averaged over 1 second */
	if (pdesc & CISTPL_CFTABLE_PD_AVGI) {
		pd->avgI_flags |= CISTPL_CFTABLE_PD_MUL10;
		pd->avgI = cistpl_expd_parse(tp, &pd->avgI_flags);
		pd->avgI_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}

	/* maximum current required averaged over 10mS */
	if (pdesc & CISTPL_CFTABLE_PD_PEAKI) {
		pd->peakI_flags |= CISTPL_CFTABLE_PD_MUL10;
		pd->peakI = cistpl_expd_parse(tp, &pd->peakI_flags);
		pd->peakI_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}

	/* power down supply curent required */
	if (pdesc & CISTPL_CFTABLE_PD_PDOWNI) {
		pd->pdownI_flags |= CISTPL_CFTABLE_PD_MUL10;
		pd->pdownI = cistpl_expd_parse(tp, &pd->pdownI_flags);
		pd->pdownI_flags |= (pdesc | CISTPL_CFTABLE_PD_EXISTS);
	}
}

/*
 * cistpl_expd_parse - read and parse an extended power description structure
 *
 *	cistpl_t *tp - pointer to pointer tuple data area
 *	int *flags - flags that get for this parameter:
 *			CISTPL_CFTABLE_PD_NC_SLEEP - no connection on
 *							sleep/power down
 *			CISTPL_CFTABLE_PD_ZERO - zero value required
 *			CISTPL_CFTABLE_PD_NC - no connection ever
 *
 * The power consumption is returned in the following units:
 *
 *				voltage - milliVOLTS
 *				current - microAMPS
 */
extern cistpl_pd_struct_t cistpl_pd_struct;

uint32_t
cistpl_expd_parse(cistpl_t *tp, uint32_t *flags)
{
	cisdata_t pdesc;
	uint32_t exponent, mantisa, val, digits = 0;

	/*
	 * Get the power description parameter byte and break it up
	 *	into mantissa and exponent.
	 */
	pdesc = GET_BYTE(tp);
	exponent = pdesc&7;
	mantisa = (pdesc>>3)&0x0f;

	if (pdesc & CISTPL_EXT_BIT) {
		do {
			if (LOOK_BYTE(tp) <= 0x63)
				digits = LOOK_BYTE(tp);
			if (LOOK_BYTE(tp) == CISTPL_CFTABLE_PD_NC_SLEEPM)
				*flags |= CISTPL_CFTABLE_PD_NC_SLEEP;
			if (LOOK_BYTE(tp) == CISTPL_CFTABLE_PD_ZEROM)
				*flags |= CISTPL_CFTABLE_PD_ZERO;
			if (LOOK_BYTE(tp) == CISTPL_CFTABLE_PD_NCM)
				*flags |= CISTPL_CFTABLE_PD_NC;
		} while (GET_BYTE(tp) & CISTPL_EXT_BIT);
	}

	val = CISTPL_PD_MAN(mantisa) * CISTPL_PD_EXP(exponent);

	/*
	 * If we have to multiply the power value by ten, then just
	 *	don't bother dividing.
	 */
	if (! (*flags & CISTPL_CFTABLE_PD_MUL10))
		val = val/10;	/* do this since our mantissa table is X 10 */

	/*
	 * If we need to add some digits to the right of the decimal, do
	 *	that here.
	 */
	if (exponent)
		val = val + (digits * CISTPL_PD_EXP(exponent-1));

	val /= 1000;

	return (val);
}

/*
 * cistpl_devspeed - returns device speed in nS
 *
 *	cistpl_t *tp - tuple pointer.
 *	cisdata_t spindex - device speed table index
 *	int flags - operation flags
 *		CISTPL_DEVSPEED_TABLE:
 *		    Use the spindex argument as an index into a simple
 *			device speed table. ref: PCMCIA Release 2.01
 *			Card Metaformat pg. 5-14 table 5-12.
 *		    When this flag is set, the spindex argument is ignored.
 *		CISTPL_DEVSPEED_EXT:
 *		    Use the tp argument to access the
 *			tuple data area containing an extended speed
 *			code table.  ref: PCMCIA Release 2.01 Card
 *			Metaformat pg. 5-15 table 5-13.
 *		    The tp->read argument must point to the first byte of
 *			an extended speed code table.
 *		    When this flag is set, the spindex argument is
 *			used as a power-of-10 scale factor.  We only allow
 *			a maximum scale factor of 10^16.
 *
 * The device speed is returned in nS for all combinations of flags and
 *	speed table entries.
 *
 * Note if you pass the CISTPL_DEVSPEED_TABLE with a spindex index that
 *	refers to an extended speed table, you will get back an undefined
 *	speed value.
 */
extern cistpl_devspeed_struct_t cistpl_devspeed_struct;

uint32_t
cistpl_devspeed(cistpl_t *tp, cisdata_t spindex, uint32_t flags)
{
	int scale = 1, first;
	cisdata_t exspeed;
	int exponent, mantisa;
	uint32_t speed;

	switch (flags) {
	case CISTPL_DEVSPEED_TABLE:
		speed = CISTPL_DEVSPEED_TBL(spindex);
		break;
	case CISTPL_DEVSPEED_EXT:
		do {
			exspeed = GET_BYTE(tp);
			first = 1;
			if (first) {
				/*
				 * XXX - ugh! we don't understand additional
				 *	exspeed bytes
				 */
				first = 0;
				exponent = (exspeed & 0x07);
				mantisa = (exspeed >> 3) & 0x0f;
				spindex &= 0x0f;	/* only allow 10^16 */
				while (spindex--)
					scale *= 10;
			} /* if (first) */
		} while (exspeed & CISTPL_EXT_BIT);
		speed = scale * CISTPL_DEVSPEED_MAN(mantisa) *
						CISTPL_DEVSPEED_EXP(exponent);
		speed = speed/10;	/* XXX - mantissa table is all X 10 */
		break;
	default:
		break;
	}

	return (speed);
}

/*
 * cistpl_vers_2_handler - handler for the CISTPL_VERS_2 tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_vers_2_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_vers_2_t *cs = (cistpl_vers_2_t *)arg;

		RESET_TP(tp);

		cs->vers = GET_BYTE(tp);
		cs->comply = GET_BYTE(tp);
		cs->dindex = GET_SHORT(tp);

		cs->reserved = GET_SHORT(tp);

		cs->vspec8 = GET_BYTE(tp);
		cs->vspec9 = GET_BYTE(tp);
		cs->nhdr = GET_BYTE(tp);

		(void) strcpy(cs->oem, cis_getstr(tp));

		if (GET_LEN(tp) > 0)
		    (void) strcpy(cs->info, cis_getstr(tp));
		else
		    (void) strcpy(cs->info, "(no info)");
	}

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_jedec_handler - handler for JEDEC C and JEDEC A tuples
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_jedec_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		int nid;
		cistpl_jedec_t *cs = (cistpl_jedec_t *)arg;

		RESET_TP(tp);

		for (nid = 0; GET_LEN(tp) > 0 &&
					nid < CISTPL_JEDEC_MAX_IDENTIFIERS &&
					LOOK_BYTE(tp) != 0xFF; nid++) {
			cs->jid[nid].id = GET_BYTE(tp);
			cs->jid[nid].info = GET_BYTE(tp);
		}
		cs->nid = nid;
	}

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_format_handler - handler for the CISTPL_FORMAT and
 *				CISTPL_FORMAT_A tuples
 */
uint32_t
cistpl_format_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_format_t *cs = (cistpl_format_t *)arg;

		RESET_TP(tp);

		cs->type = GET_BYTE(tp);
		cs->edc_length = LOOK_BYTE(tp) & EDC_LENGTH_MASK;
		cs->edc_type = ((uint32_t)GET_BYTE(tp) >> EDC_TYPE_SHIFT) &
								EDC_TYPE_MASK;
		cs->offset = GET_LONG(tp);
		cs->nbytes = GET_LONG(tp);

		switch (cs->type) {
		case TPLFMTTYPE_DISK:
			cs->dev.disk.bksize = GET_SHORT(tp);
			cs->dev.disk.nblocks = GET_LONG(tp);
			cs->dev.disk.edcloc = GET_LONG(tp);
			break;

		case TPLFMTTYPE_MEM:
			cs->dev.mem.flags = GET_BYTE(tp);
			cs->dev.mem.reserved = GET_BYTE(tp);
			cs->dev.mem.address = (caddr_t)(uintptr_t)GET_LONG(tp);
			cs->dev.disk.edcloc = GET_LONG(tp);
			break;
		default:
			/* don't know about any other type */
			break;
		}
	}

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_geometry_handler - handler for the CISTPL_GEOMETRY tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_geometry_handler(cistpl_callout_t *co, cistpl_t *tp, uint32_t flags,
								void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_geometry_t *cs = (cistpl_geometry_t *)arg;

		RESET_TP(tp);
		cs->spt = GET_BYTE(tp);
		cs->tpc = GET_BYTE(tp);
		cs->ncyl = GET_SHORT(tp);
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_byteorder_handler - handler for the CISTPL_BYTEORDER tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_byteorder_handler(cistpl_callout_t *co, cistpl_t *tp, uint32_t flags,
								void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_byteorder_t *cs = (cistpl_byteorder_t *)arg;

		RESET_TP(tp);
		cs->order = GET_BYTE(tp);
		cs->map = GET_BYTE(tp);
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_date_handler - handler for CISTPL_DATE card format tuple
 *
 *	void *arg - points to a cistpl_date_t * where the
 *			information is stuffed into
 */
uint32_t
cistpl_date_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_date_t *cs = (cistpl_date_t *)arg;

		RESET_TP(tp);
		cs->time = GET_SHORT(tp);
		cs->day = GET_SHORT(tp);
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_battery_handler - handler for CISTPL_BATTERY battery replacement
 *				date tuple
 *
 *	void *arg - points to a cistpl_battery_t * where the
 *			information is stuffed into
 */
uint32_t
cistpl_battery_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_battery_t *cs = (cistpl_battery_t *)arg;

		RESET_TP(tp);
		cs->rday = GET_SHORT(tp);
		cs->xday = GET_SHORT(tp);
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_org_handler - handler for CISTPL_ORG data organization tuple
 *
 *	void *arg - points to a cistpl_org_t * where the
 *			information is stuffed into
 */
uint32_t
cistpl_org_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_org_t *cs = (cistpl_org_t *)arg;

		RESET_TP(tp);
		cs->type = GET_BYTE(tp);

		(void) strcpy(cs->desc, cis_getstr(tp));
	}

	return (CISTPLF_NOERROR);
}


/*
 * cistpl_manfid_handler - handler for CISTPL_MANFID, the manufacturer ID tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_manfid_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_manfid_t *cs = (cistpl_manfid_t *)arg;

		RESET_TP(tp);
		cs->manf = GET_SHORT(tp);
		cs->card = GET_SHORT(tp);
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_funcid_handler - handler for CISTPL_FUNCID
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_funcid_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_funcid_t *cs = (cistpl_funcid_t *)arg;

		RESET_TP(tp);

		cs->function = GET_BYTE(tp);
		cs->sysinit = GET_BYTE(tp);
	}
	return (CISTPLF_NOERROR);
}


/*
 * cistpl_funce_serial_handler - handler for the CISTPL_FUNCE/SERIAL tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_funce_serial_handler(cistpl_callout_t *co, cistpl_t *tp,
						uint32_t flags, void *arg)
{
	int subfunction;

	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		cistpl_funce_t *cs = (cistpl_funce_t *)arg;

		RESET_TP(tp);

		cs->function = TPLFUNC_SERIAL;
		cs->subfunction = subfunction = GET_BYTE(tp);
		switch (subfunction & 0xF) {
		case TPLFE_SUB_SERIAL:
		case TPLFE_CAP_SERIAL_DATA:
		case TPLFE_CAP_SERIAL_FAX:
		case TPLFE_CAP_SERIAL_VOICE:
			cs->data.serial.ua = GET_BYTE(tp);
			cs->data.serial.uc = GET_SHORT(tp);
			break;
		case TPLFE_SUB_MODEM_COMMON:
		case TPLFE_CAP_MODEM_DATA:
		case TPLFE_CAP_MODEM_FAX:
		case TPLFE_CAP_MODEM_VOICE:
			cs->data.modem.fc = GET_BYTE(tp);
			cs->data.modem.cb = (GET_BYTE(tp) + 1) * 4;
			cs->data.modem.eb = GET_INT24(tp);
			cs->data.modem.tb = GET_INT24(tp);
			break;
		case TPLFE_SUB_MODEM_DATA:
			cs->data.data_modem.ud = GET_BE_SHORT(tp) * 75;
			cs->data.data_modem.ms = GET_SHORT(tp);
			cs->data.data_modem.em = GET_BYTE(tp);
			cs->data.data_modem.dc = GET_BYTE(tp);
			cs->data.data_modem.cm = GET_BYTE(tp);
			cs->data.data_modem.ex = GET_BYTE(tp);
			cs->data.data_modem.dy = GET_BYTE(tp);
			cs->data.data_modem.ef = GET_BYTE(tp);
			for (cs->data.data_modem.ncd = 0;
				GET_LEN(tp) > 0 && cs->data.data_modem.ncd < 16;
						cs->data.data_modem.ncd++)
				if (LOOK_BYTE(tp) != 255) {
					cs->data.data_modem.cd[
						cs->data.data_modem.ncd] =
								GET_BYTE(tp);
				} else {
					GET_BYTE(tp);
					break;
				}
			break;
		case TPLFE_SUB_MODEM_FAX:
			cs->data.fax.uf = GET_BE_SHORT(tp) * 75;
			cs->data.fax.fm = GET_BYTE(tp);
			cs->data.fax.fy = GET_BYTE(tp);
			cs->data.fax.fs = GET_SHORT(tp);
			for (cs->data.fax.ncf = 0;
				GET_LEN(tp) > 0 && cs->data.fax.ncf < 16;
							cs->data.fax.ncf++)
				if (LOOK_BYTE(tp) != 255) {
					cs->data.fax.cf[cs->data.fax.ncf] =
								GET_BYTE(tp);
				} else {
					GET_BYTE(tp);
					break;
				}
			break;
		case TPLFE_SUB_VOICE:
			cs->data.voice.uv = GET_BE_SHORT(tp) * 75;
			for (cs->data.voice.nsr = 0; LOOK_BYTE(tp) != 0 &&
				GET_LEN(tp) >= 2;
						cs->data.voice.nsr++) {
				cs->data.voice.sr[cs->data.voice.nsr] =
					GET_BYTE(tp) * 1000;
				cs->data.voice.sr[cs->data.voice.nsr] +=
					GET_BYTE(tp) * 100;
			}
			for (cs->data.voice.nss = 0; LOOK_BYTE(tp) != 0 &&
				GET_LEN(tp) >= 2;
						cs->data.voice.nss++) {
				cs->data.voice.ss[cs->data.voice.nss] =
					GET_BYTE(tp) * 10;
				cs->data.voice.ss[cs->data.voice.nss] +=
								GET_BYTE(tp);
			}
			for (cs->data.voice.nsc = 0; LOOK_BYTE(tp) != 0 &&
				GET_LEN(tp) >= 1;
						cs->data.voice.nsc++) {
				cs->data.voice.sc[cs->data.voice.nsc] =
								GET_BYTE(tp);
			}
			break;
		default:
			break;
		}
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_funce_lan_handler - handler for the CISTPL_FUNCE/LAN tuple
 *
 *	void *arg - points to a XXX where the information is stuffed into
 */
uint32_t
cistpl_funce_lan_handler(cistpl_callout_t *co, cistpl_t *tp, uint32_t flags,
								void *arg)
{
	int subfunction;

	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * We don't currently validate this tuple. This call will
	 *	always set tp->flags |= CISTPLF_VALID.
	 */
	if (flags & HANDTPL_COPY_DONE)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	if (flags & HANDTPL_PARSE_LTUPLE) {
		int i;
		cistpl_funce_t *cs = (cistpl_funce_t *)arg;

		RESET_TP(tp);

		cs->function = TPLFUNC_LAN;
		cs->subfunction = subfunction = GET_BYTE(tp);

		switch (subfunction) {
		case TPLFE_NETWORK_INFO:
			cs->data.lan.tech = GET_BYTE(tp);
			cs->data.lan.speed = GET_BYTE(tp);
			i = GET_BYTE(tp);
			if (i < 24) {
				cs->data.lan.speed <<= i;
			} else {
				/*
				 * if speed is too large a value
				 * to hold in a uint32 flag it and
				 * store as [mantissa][exponent]
				 * in least significant 16 bits
				 */
				cs->data.lan.speed = 0x80000000 |
					(cs->data.lan.speed << 8) | i;
			}
			cs->data.lan.media = GET_BYTE(tp);
			cs->data.lan.con = GET_BYTE(tp);
			cs->data.lan.id_sz = GET_BYTE(tp);
			if (cs->data.lan.id_sz <= 16) {
				for (i = 0; i < cs->data.lan.id_sz; i++)
					cs->data.lan.id[i] = GET_BYTE(tp);
			}
			break;
		default:
				/* unknown LAN tuple type */
			return (CISTPLF_UNKNOWN);
		}
	}
	return (CISTPLF_NOERROR);
}

/*
 * cistpl_linktarget_handler - handler for CISTPL_LINKTARGET tuple
 *
 *	void *arg - points to a cistpl_linktarget_t * where the
 *			information is stuffed into
 *
 *	If HANDTPL_COPY_DONE is set, we just validate the tuple but
 *		do not return any values.
 *	If HANDTPL_PARSE_LTUPLE is set, we validate the tuple and
 *		return the parsed tuple data if the tuple is valid.
 *
 *	If the tuple link field is invalid, the CISTPLF_LINK_INVALID flag
 *		will be set in the tp->flags field and HANDTPL_ERROR
 *		will be returned.
 *
 *	If the tuple data body is invalid, the CISTPLF_PARAMS_INVALID flag
 *		will be set in the tp->flags field and HANDTPL_ERROR
 *		will be returned.
 *
 *	The tuple is considered invalid if it's link field is less than
 *		MIN_LINKTARGET_LENGTH or if the data body of the tuple
 *		does not contain the pattern CISTPL_LINKTARGET_MAGIC.
 *
 * XXX At some point we should revisit this to see if we can call
 *	cis_validate_longlink_acm instead of doing the validation
 *	in both places.
 */
uint32_t
cistpl_linktarget_handler(cistpl_callout_t *co, cistpl_t *tp, uint32_t flags,
								void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * Validate the tuple for both the HANDTPL_COPY_DONE case and
	 *	the HANDTPL_PARSE_LTUPLE case. Only return data in
	 *	the HANDTPL_PARSE_LTUPLE case.
	 */
	if (flags & (HANDTPL_COPY_DONE | HANDTPL_PARSE_LTUPLE)) {
		uchar_t *cp;
		cisdata_t tl;

		if ((tl = tp->len) >= (cisdata_t)MIN_LINKTARGET_LENGTH) {
			cisdata_t *ltm = (cisdata_t *)CISTPL_LINKTARGET_MAGIC;
			int i;

			RESET_TP(tp);

			/*
			 * Save the start address of this string in case
			 *	the tuple turns out to be OK since we
			 *	need to pass this address to the caller.
			 */
			cp = GET_BYTE_ADDR(tp);

			/*
			 * Check each byte of the tuple body to see if it
			 *	matches what should be in a valid tuple.
			 *	Note that we can't assume that this magic
			 *	pattern is a string and we also only need
			 *	to be sure that MIN_LINKTARGET_LENGTH bytes
			 *	match; all bytes following this magic number
			 *	in this tuple are ignored.
			 */
			for (i = 0; i < MIN_LINKTARGET_LENGTH; i++) {
				if (GET_BYTE(tp) != *ltm++) {
					tp->flags |= CISTPLF_PARAMS_INVALID;
					return (HANDTPL_ERROR);
				}
			} /* MIN_LINKTARGET_LENGTH */

			/*
			 * This tuple is valid.
			 */
			if (flags & HANDTPL_COPY_DONE)
				tp->flags |= CISTPLF_VALID;

			/*
			 * If we're also parsing this tuple, then
			 *	setup the return values.
			 */
			if (flags & HANDTPL_PARSE_LTUPLE) {
				cistpl_linktarget_t *cs =
						(cistpl_linktarget_t *)arg;

				cs->length = tl;
				(void) strncpy(cs->tpltg_tag, (char *)cp,
								cs->length);
				cs->tpltg_tag[cs->length] = '\0';

			} /* HANDTPL_PARSE_LTUPLE */

		} else {

			tp->flags |= CISTPLF_LINK_INVALID;
			return (HANDTPL_ERROR);

		} /* CISTPL_LINKTARGET */

	} /* (HANDTPL_COPY_DONE | HANDTPL_PARSE_LTUPLE) */

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_longlink_ac_handler - handler for CISTPL_LONGLINK_A and
 *				CISTPL_LONGLINK_C tuples
 *
 *	void *arg - points to a cistpl_longlink_ac_t * where the
 *			information is stuffed into
 *
 *	If the passed in tuple is CISTPL_LONGLINK_A the CISTPL_LONGLINK_AC_AM
 *		flag in cistpl_longlink_ac_t->flags is set.
 *	If the passed in tuple is CISTPL_LONGLINK_C the CISTPL_LONGLINK_AC_CM
 *		flag in cistpl_longlink_ac_t->flags is set.
 *
 *	If HANDTPL_COPY_DONE is set, we just validate the tuple but
 *		do not return any values.
 *	If HANDTPL_PARSE_LTUPLE is set, we validate the tuple and
 *		return the parsed tuple data if the tuple is valid.
 *
 *	If the tuple link field is invalid, the CISTPLF_LINK_INVALID flag
 *		will be set in the tp->flags field and HANDTPL_ERROR
 *		will be returned.
 *
 *	The tuple is considered invalid if it's link field is less than
 *		MIN_LONGLINK_AC_LENGTH.
 */
uint32_t
cistpl_longlink_ac_handler(cistpl_callout_t *co, cistpl_t *tp, uint32_t flags,
								void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * Validate the tuple for both the HANDTPL_COPY_DONE case and
	 *	the HANDTPL_PARSE_LTUPLE case. Only return data in
	 *	the HANDTPL_PARSE_LTUPLE case.
	 */
	if (flags & (HANDTPL_COPY_DONE | HANDTPL_PARSE_LTUPLE)) {

		if (tp->len >= (cisdata_t)MIN_LONGLINK_AC_LENGTH) {

			/*
			 * This tuple is valid.
			 */
			if (flags & HANDTPL_COPY_DONE)
				tp->flags |= CISTPLF_VALID;

			if (flags & HANDTPL_PARSE_LTUPLE) {
				cistpl_longlink_ac_t *cs =
						(cistpl_longlink_ac_t *)arg;

				switch (tp->type) {
				    case CISTPL_LONGLINK_A:
					cs->flags = CISTPL_LONGLINK_AC_AM;
					break;

				    case CISTPL_LONGLINK_C:
					cs->flags = CISTPL_LONGLINK_AC_CM;
					break;
				    default:
					break;
				} /* switch */

				RESET_TP(tp);

				cs->tpll_addr = GET_LONG(tp);

			} /* HANDTPL_PARSE_LTUPLE */

		} else {
			tp->flags |= CISTPLF_LINK_INVALID;
			return (HANDTPL_ERROR);
		} /* MIN_LONGLINK_AC_LENGTH */

	} /* (HANDTPL_COPY_DONE | HANDTPL_PARSE_LTUPLE) */

	return (CISTPLF_NOERROR);
}

/*
 * cistpl_longlink_mfc_handler - handler for CISTPL_LONGLINK_MFC tuples
 *
 *	void *arg - points to a cistpl_longlink_mfc_t * where the
 *			information is stuffed into
 *
 *	If HANDTPL_COPY_DONE is set, we just validate the tuple but
 *		do not return any values.
 *	If HANDTPL_PARSE_LTUPLE is set, we validate the tuple and
 *		return the parsed tuple data if the tuple is valid.
 *
 *	If the tuple link field is invalid, the CISTPLF_LINK_INVALID flag
 *		will be set in the tp->flags field and HANDTPL_ERROR
 *		will be returned.
 *
 *	If the number of register sets is invalid, the CISTPLF_PARAMS_INVALID
 *		flag be set in the tp->flags field and HANDTPL_ERROR will be
 *		returned.
 *
 *	The tuple is considered invalid if it's link field is less than
 *		MIN_LONGLINK_MFC_LENGTH or if the number of register sets
 *		is not in the range [MIN_LONGLINK_MFC_NREGS..CIS_MAX_FUNCTIONS]
 */
uint32_t
cistpl_longlink_mfc_handler(cistpl_callout_t *co, cistpl_t *tp,
					uint32_t flags, void *arg)
{
	/*
	 * nothing special about our flags, so just call the
	 *	generic handler for this
	 */
	if (flags & HANDTPL_SET_FLAGS)
		return (cis_no_tuple_handler(co, tp, flags, arg));

	/*
	 * Validate the tuple for both the HANDTPL_COPY_DONE case and
	 *	the HANDTPL_PARSE_LTUPLE case. Only return data in
	 *	the HANDTPL_PARSE_LTUPLE case.
	 */
	if (flags & (HANDTPL_COPY_DONE | HANDTPL_PARSE_LTUPLE)) {

		if (tp->len >= (cisdata_t)MIN_LONGLINK_MFC_LENGTH) {

			/*
			 * This tuple is valid.
			 */
			if (flags & HANDTPL_COPY_DONE)
				tp->flags |= CISTPLF_VALID;

			if (flags & HANDTPL_PARSE_LTUPLE) {
				cistpl_longlink_mfc_t *cs =
						(cistpl_longlink_mfc_t *)arg;
				int fn;

				RESET_TP(tp);

				/*
				 * Get the number of register sets described
				 *	by this tuple. The number of register
				 *	sets must be greter than or equal to
				 *	MIN_LONGLINK_MFC_NREGS and less than
				 *	CIS_MAX_FUNCTIONS.
				 * Note that the number of functions is equal
				 *	to the number of register sets.
				 */
				cs->nregs = GET_BYTE(tp);
				cs->nfuncs = cs->nregs;

				if ((cs->nregs < MIN_LONGLINK_MFC_NREGS) ||
					(cs->nregs > CIS_MAX_FUNCTIONS)) {
				    tp->flags |= CISTPLF_PARAMS_INVALID;
				    return (HANDTPL_ERROR);
				}

				/*
				 * Cycle through each function and setup
				 *	the appropriate parameter values.
				 */
				for (fn = 0; fn < cs->nregs; fn++) {
				    cs->function[fn].tas = GET_BYTE(tp);
				    cs->function[fn].addr = GET_LONG(tp);
				} /* for (fn) */

			} /* HANDTPL_PARSE_LTUPLE */

		} else {
			tp->flags |= CISTPLF_LINK_INVALID;
			return (HANDTPL_ERROR);
		} /* MIN_LONGLINK_MFC_LENGTH */

	} /* (HANDTPL_COPY_DONE | HANDTPL_PARSE_LTUPLE) */

	return (CISTPLF_NOERROR);
}

/*
 * cis_validate_longlink_acm - Validates the secondary tuple chain pointed
 *				to by cisptr and specified by a previous
 *				CISTPL_LONGLINK_A, CISTPL_LONGLINK_C or
 *				CISTPL_LONGLINK_MFC tuple.
 *
 *	cisptr->offset must be the offset to the first byte in the secondary
 *		tuple chain to validate
 *	cisptr->flags must be setup to specify the correct address space
 *
 * The cisptr->offset member is not updated after this function returns.
 *
 *	BAD_CIS_ADDR is returned is the raw CIS data cound not be read.
 *	HANDTPL_ERROR is returned if the secondary tuple chain does not
 *		contain a valid CISTPL_LINKTARGET tuple.
 */
uint32_t
cis_validate_longlink_acm(cisptr_t *cisptr)
{
	uchar_t cb[MIN_LINKTARGET_LENGTH + LINKTARGET_AC_HEADER_LENGTH];
	cisptr_t t_cisptr, *cpt;
	int tl;

	/*
	 * Since the NEXT_CIS_ADDR macro increments the cisptr_t->offset
	 *	member, make a local copy of the cisptr and use the local
	 *	copy to read data from the card.
	 */
	cpt = &t_cisptr;
	bcopy((caddr_t)cisptr, (caddr_t)cpt, sizeof (cisptr_t));

	for (tl = 0; tl < MIN_LINKTARGET_LENGTH +
					LINKTARGET_AC_HEADER_LENGTH; tl++) {

		cb[tl] = GET_CIS_DATA(cpt);
		if (!NEXT_CIS_ADDR(cpt))
			return ((uint32_t)BAD_CIS_ADDR);

	} /* for */

	if ((cb[0] == CISTPL_LINKTARGET) && (cb[1] >= MIN_LINKTARGET_LENGTH)) {
		cisdata_t *ltm = (cisdata_t *)CISTPL_LINKTARGET_MAGIC;

		for (tl = 0; tl < MIN_LINKTARGET_LENGTH; tl++, ltm++) {
			if (cb[tl + LINKTARGET_AC_HEADER_LENGTH] != *ltm)
				return (HANDTPL_ERROR);
		}
		return (CISTPLF_NOERROR);

	} /* if */

	return (HANDTPL_ERROR);
}

/*
 * cis_getstr (tp)
 *	we want the address of the first character returned
 *	but need to skip past the string in the cistpl_t structure
 */
char *
cis_getstr(cistpl_t *tp)
{
	uchar_t *cp, *cpp;
	uchar_t x;

	cp = tp->read.byte;
	cpp = cp;

	while ((x = LOOK_BYTE(tp)) != 0 && x != 0xff) {
		x = GET_BYTE(tp);
	}

	(void) GET_BYTE(tp);	/* get past that last byte */

	while ((*cpp != 0) && (*cpp != 0xff))
	    cpp++;

	*cpp = '\0';

	return ((char *)cp);
}

/*
 * cis_return_name - returns name of tuple
 *
 *    calling:	co - pointer to cistpl_callout_t entry that contains
 *			tuple name to return
 *		gtn - pointer to cistpl_get_tuple_name_t to return
 *			name into
 */
static void
cis_return_name(cistpl_callout_t *co, cistpl_get_tuple_name_t *gtn)
{
	(void) strncpy(gtn->name, co->text, CIS_MAX_TUPLE_NAME_LEN);
	gtn->name[CIS_MAX_TUPLE_NAME_LEN - 1] = '\0';
}

/*
 * cis_malloc/cis_free
 *	wrappers around kmem_alloc()/kmem_free() that
 *	provide malloc/free style usage
 */

caddr_t
cis_malloc(size_t len)
{
	caddr_t addr;

	addr = kmem_zalloc(len + sizeof (size_t), KM_SLEEP);
	*(size_t *)addr = len + sizeof (size_t);
	addr += sizeof (size_t);
	return (addr);
}

void
cis_free(caddr_t addr)
{
	size_t len;
	addr -= sizeof (size_t);
	len = *(size_t *)addr;
	kmem_free(addr, len);
}
