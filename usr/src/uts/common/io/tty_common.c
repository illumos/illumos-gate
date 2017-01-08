/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/termio.h>
#include <sys/ttold.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/tty.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>

/*
 * The default (sane) set of termios values, unless
 * otherwise set by the user.
 */
static struct termios default_termios = {
	BRKINT|ICRNL|IXON|IMAXBEL,		/* c_iflag */
	OPOST|ONLCR|TAB3,			/* c_oflag */
	B9600|CS8|CREAD,			/* c_cflag */
	ISIG|ICANON|IEXTEN|ECHO|ECHOK|ECHOE|ECHOKE|ECHOCTL, /* c_lflag */
	{
		CINTR,
		CQUIT,
		CERASE,
		CKILL,
		CEOF,
		CEOL,
		CEOL2,
		CNSWTCH,
		CSTART,
		CSTOP,
		CSUSP,
		CDSUSP,
		CRPRNT,
		CFLUSH,
		CWERASE,
		CLNEXT,
		CSTATUS,
		CERASE2
	}
};


static int termioval(char **, uint_t *, char *);

void
ttycommon_close(tty_common_t *tc)
{
	mutex_enter(&tc->t_excl);
	tc->t_flags &= ~TS_XCLUDE;
	tc->t_readq = NULL;
	tc->t_writeq = NULL;
	if (tc->t_iocpending != NULL) {
		mblk_t *mp;

		mp = tc->t_iocpending;
		tc->t_iocpending = NULL;
		mutex_exit(&tc->t_excl);
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(mp);
	} else
		mutex_exit(&tc->t_excl);
}

/*
 * A "line discipline" module's queue is full.
 * Check whether IMAXBEL is set; if so, output a ^G, otherwise send an M_FLUSH
 * upstream flushing all the read queues.
 */
void
ttycommon_qfull(tty_common_t *tc, queue_t *q)
{
	mblk_t *mp;

	if (tc->t_iflag & IMAXBEL) {
		if (canput(WR(q))) {
			if ((mp = allocb(1, BPRI_HI)) != NULL) {
				*mp->b_wptr++ = CTRL('g');
				(void) putq(WR(q), mp);
			}
		}
	} else {
		flushq(q, FLUSHDATA);
		(void) putnextctl1(q, M_FLUSH, FLUSHR);
	}
}

/*
 * Process an "ioctl" message sent down to us, and return a reply message,
 * even if we don't understand the "ioctl".  Our client may want to use
 * that reply message for its own purposes if we don't understand it but
 * they do, and may want to modify it if we both understand it but they
 * understand it better than we do.
 * If the "ioctl" reply requires additional data to be passed up to the
 * caller, and we cannot allocate an mblk to hold the data, we return the
 * amount of data to be sent, so that our caller can do a "bufcall" and try
 * again later; otherwise, we return 0.
 */
size_t
ttycommon_ioctl(tty_common_t *tc, queue_t *q, mblk_t *mp, int *errorp)
{
	struct iocblk *iocp;
	size_t ioctlrespsize;
	mblk_t *tmp;

	*errorp = 0;	/* no error detected yet */

	iocp = (struct iocblk *)mp->b_rptr;

	if (iocp->ioc_count == TRANSPARENT) {
		*errorp = -1;	/* we don't understand it, maybe they do */
		return (0);
	}

	switch (iocp->ioc_cmd) {

	case TCSETSF:
		/*
		 * Flush the driver's queue, and send an M_FLUSH upstream
		 * to flush everybody above us.
		 */
		flushq(RD(q), FLUSHDATA);
		(void) putnextctl1(RD(q), M_FLUSH, FLUSHR);
		/* FALLTHROUGH */

	case TCSETSW:
	case TCSETS: {
		struct termios *cb;

		if (miocpullup(mp, sizeof (struct termios)) != 0) {
			*errorp = -1;
			break;
		}

		/*
		 * The only information we look at are the iflag word,
		 * the cflag word, and the start and stop characters.
		 */
		cb = (struct termios *)mp->b_cont->b_rptr;
		mutex_enter(&tc->t_excl);
		tc->t_iflag = cb->c_iflag;
		tc->t_cflag = cb->c_cflag;
		tc->t_stopc = cb->c_cc[VSTOP];
		tc->t_startc = cb->c_cc[VSTART];
		mutex_exit(&tc->t_excl);
		break;
	}

	case TCSETAF:
		/*
		 * Flush the driver's queue, and send an M_FLUSH upstream
		 * to flush everybody above us.
		 */
		flushq(RD(q), FLUSHDATA);
		(void) putnextctl1(RD(q), M_FLUSH, FLUSHR);
		/* FALLTHROUGH */

	case TCSETAW:
	case TCSETA: {
		struct termio *cb;

		if (miocpullup(mp, sizeof (struct termio)) != 0) {
			*errorp = -1;
			break;
		}

		/*
		 * The only information we look at are the iflag word
		 * and the cflag word.  Don't touch the unset portions.
		 */
		cb = (struct termio *)mp->b_cont->b_rptr;
		mutex_enter(&tc->t_excl);
		tc->t_iflag = (tc->t_iflag & 0xffff0000 | cb->c_iflag);
		tc->t_cflag = (tc->t_cflag & 0xffff0000 | cb->c_cflag);
		mutex_exit(&tc->t_excl);
		break;
	}

	case TIOCSWINSZ: {
		struct winsize *ws;

		if (miocpullup(mp, sizeof (struct winsize)) != 0) {
			*errorp = -1;
			break;
		}

		/*
		 * If the window size changed, send a SIGWINCH.
		 */
		ws = (struct winsize *)mp->b_cont->b_rptr;
		mutex_enter(&tc->t_excl);
		if (bcmp(&tc->t_size, ws, sizeof (struct winsize)) != 0) {
			tc->t_size = *ws;
			mutex_exit(&tc->t_excl);
			(void) putnextctl1(RD(q), M_PCSIG, SIGWINCH);
		} else
			mutex_exit(&tc->t_excl);
		break;
	}

	/*
	 * Prevent more opens.
	 */
	case TIOCEXCL:
		mutex_enter(&tc->t_excl);
		tc->t_flags |= TS_XCLUDE;
		mutex_exit(&tc->t_excl);
		break;

	/*
	 * Permit more opens.
	 */
	case TIOCNXCL:
		mutex_enter(&tc->t_excl);
		tc->t_flags &= ~TS_XCLUDE;
		mutex_exit(&tc->t_excl);
		break;

	/*
	 * Set or clear the "soft carrier" flag.
	 */
	case TIOCSSOFTCAR:
		if (miocpullup(mp, sizeof (int)) != 0) {
			*errorp = -1;
			break;
		}

		mutex_enter(&tc->t_excl);
		if (*(int *)mp->b_cont->b_rptr)
			tc->t_flags |= TS_SOFTCAR;
		else
			tc->t_flags &= ~TS_SOFTCAR;
		mutex_exit(&tc->t_excl);
		break;

	/*
	 * The permission checking has already been done at the stream
	 * head, since it has to be done in the context of the process
	 * doing the call.
	 */
	case TIOCSTI: {
		mblk_t *bp;

		if (miocpullup(mp, sizeof (char)) != 0) {
			*errorp = -1;
			break;
		}

		/*
		 * Simulate typing of a character at the terminal.
		 */
		if ((bp = allocb(1, BPRI_MED)) != NULL) {
			if (!canput(tc->t_readq->q_next))
				freemsg(bp);
			else {
				*bp->b_wptr++ = *mp->b_cont->b_rptr;
				putnext(tc->t_readq, bp);
			}
		}
		break;
	}
	}

	/*
	 * Turn the ioctl message into an ioctl ACK message.
	 */
	iocp->ioc_count = 0;	/* no data returned unless we say so */
	mp->b_datap->db_type = M_IOCACK;

	switch (iocp->ioc_cmd) {

	case TCSETSF:
	case TCSETSW:
	case TCSETS:
	case TCSETAF:
	case TCSETAW:
	case TCSETA:
	case TIOCSWINSZ:
	case TIOCEXCL:
	case TIOCNXCL:
	case TIOCSSOFTCAR:
	case TIOCSTI:
		/*
		 * We've done all the important work on these already;
		 * just reply with an ACK.
		 */
		break;

	case TCGETS: {
		struct termios *cb;
		mblk_t *datap;

		if ((datap = allocb(sizeof (struct termios),
		    BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (struct termios);
			goto allocfailure;
		}
		cb = (struct termios *)datap->b_wptr;
		/*
		 * The only information we supply is the cflag word.
		 * Our copy of the iflag word is just that, a copy.
		 */
		bzero(cb, sizeof (struct termios));
		cb->c_cflag = tc->t_cflag;
		datap->b_wptr += sizeof (struct termios);
		iocp->ioc_count = sizeof (struct termios);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		break;
	}

	case TCGETA: {
		struct termio *cb;
		mblk_t *datap;

		if ((datap = allocb(sizeof (struct termio), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (struct termio);
			goto allocfailure;
		}

		cb = (struct termio *)datap->b_wptr;
		/*
		 * The only information we supply is the cflag word.
		 * Our copy of the iflag word is just that, a copy.
		 */
		bzero(cb, sizeof (struct termio));
		cb->c_cflag = tc->t_cflag;
		datap->b_wptr += sizeof (struct termio);
		iocp->ioc_count = sizeof (struct termio);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		break;
	}

	/*
	 * Get the "soft carrier" flag.
	 */
	case TIOCGSOFTCAR: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (int);
			goto allocfailure;
		}
		if (tc->t_flags & TS_SOFTCAR)
			*(int *)datap->b_wptr = 1;
		else
			*(int *)datap->b_wptr = 0;
		datap->b_wptr += sizeof (int);
		iocp->ioc_count = sizeof (int);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		break;
	}

	case TIOCGWINSZ: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (struct winsize),
		    BPRI_HI)) == NULL) {
			ioctlrespsize = sizeof (struct winsize);
			goto allocfailure;
		}
		/*
		 * Return the current size.
		 */
		*(struct winsize *)datap->b_wptr = tc->t_size;
		datap->b_wptr += sizeof (struct winsize);
		iocp->ioc_count = sizeof (struct winsize);
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		break;
	}

	default:
		*errorp = -1;	/* we don't understand it, maybe they do */
		break;
	}
	return (0);

allocfailure:

	mutex_enter(&tc->t_excl);
	tmp = tc->t_iocpending;
	tc->t_iocpending = mp;	/* hold this ioctl */
	mutex_exit(&tc->t_excl);
	/*
	 * We needed to allocate something to handle this "ioctl", but
	 * couldn't; save this "ioctl" and arrange to get called back when
	 * it's more likely that we can get what we need.
	 * If there's already one being saved, throw it out, since it
	 * must have timed out.
	 */
	if (tmp != NULL)
		freemsg(tmp);
	return (ioctlrespsize);
}

#define	NFIELDS	22	/* 18 control characters + 4 sets of modes */

/*
 * Init routine run from main at boot time.
 * Creates a property in the "options" node that is
 * the default set of termios modes upon driver open.
 * If the property already existed, then it was
 * defined in the options.conf file.  In this case we
 * need to convert this string (stty -g style) to an
 * actual termios structure and store the new property
 * value.
 */

void
ttyinit()
{
	dev_info_t *dip;
	struct termios new_termios;
	struct termios *tp;
	char *property = "ttymodes";
	char **modesp, *cp;
	int i;
	uint_t val;
	uint_t len;


	/*
	 * If the termios defaults were NOT set up by the
	 * user via the options.conf file, create it using the
	 * "sane" set of termios modes.
	 * Note that if the property had been created via the
	 * options.conf file, it would have been created as
	 * a string property.  Since we would like to store
	 * a structure (termios) in this property, we need
	 * to change the property type to byte array.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    property, (char ***)&modesp, &len) != DDI_PROP_SUCCESS) {

		if ((dip = ddi_find_devinfo("options", -1, 0)) == NULL) {
			cmn_err(CE_PANIC,
			    "ttyinit: Can't find options node!\n");
		}
		/*
		 * Create the property.
		 */
		if (ddi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
		    property, (uchar_t *)&default_termios,
		    sizeof (struct termios)) != DDI_PROP_SUCCESS) {
			cmn_err(CE_PANIC, "ttyinit: can't create %s property\n",
			    property);
		}
		return;
	}

	/*
	 * This property was already set in the options.conf
	 * file.  We must convert it from a "stty -g" string
	 * to an actual termios structure.
	 */
	bzero(&new_termios, sizeof (struct termios));
	tp = &new_termios;
	cp = *modesp;
	for (i = 0; i < NFIELDS; i++) {
		/*
		 * Check for bad field/string.
		 */
		if (termioval(&cp, &val, *modesp+strlen(*modesp)) == -1) {
			cmn_err(CE_WARN,
			    "ttyinit: property '%s' %s\n", property,
			    "set incorrectly, using sane value");
			tp = &default_termios;
			break;
		}
		switch (i) {
		case 0:
			new_termios.c_iflag = (tcflag_t)val;
			break;
		case 1:
			new_termios.c_oflag = (tcflag_t)val;
			break;
		case 2:
			new_termios.c_cflag = (tcflag_t)val;
			break;
		case 3:
			new_termios.c_lflag = (tcflag_t)val;
			break;
		default:
			new_termios.c_cc[i - 4] = (cc_t)val;
		}
	}
	if ((dip = ddi_find_devinfo("options", -1, 0)) == NULL) {
		cmn_err(CE_PANIC, "ttyinit: Can't find options node!\n");
	}

	/*
	 * We need to create ttymode property as a byte array
	 * since it will be interpreted as a termios struct.
	 * The property was created as a string by default.
	 * So remove the old property and add the new one -
	 * otherwise we end up with two ttymodes properties.
	 */
	if (e_ddi_prop_remove(DDI_DEV_T_NONE, dip, property)
	    != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "ttyinit: cannot remove '%s' property\n",
		    property);
	}
	/*
	 * Store the new defaults.  Since, this property was
	 * autoconfig'ed, we must use e_ddi_prop_update_byte_array().
	 */
	if (e_ddi_prop_update_byte_array(DDI_DEV_T_NONE, dip, property,
	    (uchar_t *)tp, sizeof (struct termios)) != DDI_PROP_SUCCESS) {
		cmn_err(CE_PANIC, "ttyinit: cannot modify '%s' property\n",
		    property);
	}
	ddi_prop_free(modesp);
}

/*
 * Convert hex string representation of termios field
 * to a uint_t.  Increments string pointer to the next
 * field, and assigns value. Returns -1 if no more fields
 * or an error.
 */

static int
termioval(char **sp, uint_t *valp, char *ep)
{
	char *s = *sp;
	uint_t digit;

	if (s == 0)
		return (-1);
	*valp = 0;
	while (s < ep) {
		if (*s >= '0' && *s <= '9')
			digit = *s++ - '0';
		else if (*s >= 'a' && *s <= 'f')
			digit = *s++ - 'a' + 10;
		else if (*s >= 'A' && *s <= 'F')
			digit = *s++ - 'A' + 10;
		else if (*s == ':' || *s == '\0')
			break;
		else
			return (-1);
		*valp = (*valp * 16) + digit;
	}
	/*
	 * Null string or empty field.
	 */
	if (s == *sp)
		return (-1);

	if (s < ep && *s == ':')
		s++;

	*sp = s;
	return (0);
}
