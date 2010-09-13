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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include "lp.h"
#include "printers.h"
#include <locale.h>

/**
 ** usage() - PRINT COMMAND USAGE
 **/

void			usage ()
{
#if	defined(CAN_DO_MODULES)
	(void) printf (gettext(
"usage:\n"
"\n"
"  (add printer)\n\n"
"    lpadmin -p printer {-v device | -U dial-info | -s system[!printer]} [options]\n"
"	[-s system[!printer]]			(remote system/printer name)\n"
"	[-v device]				(printer port name)\n"
"	[-U dial-info]				(phone # or sys. name)\n"
"	[-T type-list]				(printer types)\n"
"	[-c class | -r class]			(add to/del from class)\n"
"	[-A mail|write|quiet|showfault|cmd [-W interval]]\n"
"						(alert definition)\n"
"	[-A none]				(no alerts)\n"
"	[-A list]				(examine alert)\n"
"	[-D comment]				(printer description)\n"
"	[-e printer | -i interface | -m model]	(interface program)\n"
"	[-l | -h]				(is/isn't login tty)\n"
"	[-f allow:forms-list | deny:forms-list]	(forms allowed)\n"
"	[-u allow:user-list | deny:user-list]	(who's allowed to use)\n"
"	[-S char-set-maps | print-wheels]	(list of avail. fonts)\n"
"	[-I content-type-list]			(file types accepted\n"
"	[-F beginning|continue|wait]		(fault recovery)\n"
"	[-o stty='stty-options']		(port characteristics)\n"
"	[-o cpi=scaled-number]			(character pitch)\n"
"	[-o lpi=scaled-number]			(line pitch)\n"
"	[-o width=scaled-number]		(page width)\n"
"	[-o length=scaled-number]		(page length)\n"
"	[-o nobanner]				(allow no banner)\n\n"
"	[-P paper-list]				(add paper type)\n"
"	[-P ~paper-list]			(remove paper type)\n"
"	[-t number-of-trays]			(number of paper trays)\n"
"	[-H module,...|keep|default|none]	(STREAMS modules to push)\n\n"
"  (delete printer or class)\n"
"    lpadmin -x printer-or-class\n\n"
"  (define default destination)\n"
"    lpadmin -d printer-or-class\n\n"
"  (mount form, printwheel)\n"
"    lpadmin -p printer -M {options}\n"
"	[-f form [-a [-o filebreak]] [-t tray-number]]\n"
"						(mount (align) form (on tray))\n"
"	[-S print-wheel]			(mount print wheel)\n\n"
"  (define print-wheel mount alert)\n"
"    lpadmin -S print-wheel {options}\n"
"	[-A mail|write|quiet|cmd [-W interval] [-Q queue-size]]\n"
"	[-A none]				(no alerts)\n"
"	[-A list]				(examine alert)\n "));
#else
	(void) printf (gettext(
"usage:\n"
"\n"
"  (add printer)\n\n"
"    lpadmin -p printer {-v device | -U dial-info | -s system[!printer]} [options]\n"
"	[-s system[!printer]]			(remote system/printer name)\n"
"	[-v device]				(printer port name)\n"
"	[-U dial-info]				(phone # or sys. name)\n"
"	[-T type-list]				(printer types)\n"
"	[-c class | -r class]			(add to/del from class)\n"
"	[-A mail|write|quiet|showfault|cmd [-W interval]]\n"
"						(alert definition)\n"
"	[-A none]				(no alerts)\n"
"	[-A list]				(examine alert)\n"
"	[-D comment]				(printer description)\n"
"	[-e printer | -i interface | -m model]	(interface program)\n"
"	[-l | -h]				(is/isn't login tty)\n"
"	[-f allow:forms-list | deny:forms-list]	(forms allowed)\n"
"	[-u allow:user-list | deny:user-list]	(who's allowed to use)\n"
"	[-S char-set-maps | print-wheels]	(list of avail. fonts)\n"
"	[-I content-type-list]			(file types accepted\n"
"	[-F beginning|continue|wait]		(fault recovery)\n"
"	[-o stty='stty-options']		(port characteristics)\n"
"	[-o cpi=scaled-number]			(character pitch)\n"
"	[-o lpi=scaled-number]			(line pitch)\n"
"	[-o width=scaled-number]		(page width)\n"
"	[-o length=scaled-number]		(page length)\n"
"	[-o nobanner]				(allow no banner)\n\n"
"	[-P paper-list]				(add paper type)\n"
"	[-P ~paper-list]			(remove paper type)\n"
"	[-t number-of-trays]			(number of paper trays)\n"
"  (delete printer or class)\n"
"    lpadmin -x printer-or-class\n\n"
"  (define default destination)\n"
"    lpadmin -d printer-or-class\n\n"
"  (mount form, printwheel)\n"
"    lpadmin -p printer -M {options}\n"
"	[-f form [-a [-o filebreak]] [-t tray-number]]\n"
"						(mount (align) form (on tray))\n"
"	[-S print-wheel]			(mount print wheel)\n\n"
"  (define print-wheel mount alert)\n"
"    lpadmin -S print-wheel {options}\n"
"	[-A mail|write|quiet|cmd [-W interval] [-Q queue-size]]\n"
"	[-A none]				(no alerts)\n"
"	[-A list]				(examine alert)\n "));
#endif

	return;
}
