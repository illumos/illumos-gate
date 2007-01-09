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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promimpl.h>
#include <sys/sunndi.h>
#include <sys/pci/pci_obj.h>
#include <sys/pci/pcisch.h>

/*
 * These functions implement master interrupt functionality as defined
 * in Section 3.2. 'Consolidated 1275 Bindings for Safari Interconnect'
 */

/*
 * reset to B_TRUE during initialization _if_ the platform supports
 * master-interrupt.
 */
static boolean_t pci_mi_supported = B_FALSE;

typedef struct sch_arg {
	uint64_t ino_btmapA;	/* leaf A's ino-bitmap property */
	uintptr_t clr_regsA;	/* leaf A's va of interrupt clear registers */
	uint64_t ino_btmapB;	/* leaf B's ino-bitmap property */
	uintptr_t clr_regsB;	/* leaf B's va of interrupt clear registers */
	uint32_t pci_id;	/* mid/portid */
} sch_arg_t;

#define	NAGENTS	1024

static sch_arg_t *sch_intr_table[NAGENTS];

static char define_sch_interrupt_handler[] =

"struct "
"  /x	field	>ino-btmapA "
"  /x	field	>clr-regsA "
"  /x	field	>ino-btmapB "
"  /x	field	>clr-regsB "
"  /l	field	>pci-id "
"constant /sch-arg-t "

": sch-reset-bits         ( btmap' clr_p -- true ) "
"   swap h# 40 0 do       ( clr_p btmap' ) "
"     dup 1 and if        ( clr_p btmap' ) "
"        over i 8 * + %lu ( clr_p btmap' clr_p' pci_mi_intr_clr ) "
"        swap x!          ( clr_p btmap' ) "
"     then 1 rshift       ( clr_p btmap' ) "
"   loop 2drop true       ( true ) "
"; "

": sch-reset-interrupts    ( btmap' clr_p -- true|false ) "
"   swap ?dup if           ( clr_p btmap' ) "
"    swap ?dup if          ( btmap' clr_p ) "
"      sch-reset-bits exit ( true ) "
"    then                  ( btmap' ) "
"   then                   ( clr_p|bitmap' "
"   drop false             ( false ) "
"; "

/* PUBLIC: Number of entries */
"variable /sch-intr-table h# %x /sch-intr-table ! "

/* PUBLIC: Pointer to kmem_allocd space */
"variable sch-intr-table h# %p sch-intr-table ! "

/* PRIVATE: to resend-mondo */
"variable handled? "

": sch-srch-table>arg_p           ( mid -- arg_p ) "
"   dup 0 /sch-intr-table within  ( mid true|false ) "
"   sch-intr-table @ 0> and if    ( mid ) "
"     sch-intr-table @ swap na+ @ ( arg_p ) "
"   else                          ( mid ) "
"     drop 0                      ( 0 ) "
"   then                          ( arg_p|0 ) "
"; "

": sch-interrupt-handler        ( mid btmap -- [mid btmap false] | true ) "
"   over sch-srch-table>arg_p   ( mid btmap arg_p ) "
"   ?dup if                     ( mid btmap arg_p ) "
"     >r                        ( mid btmap ) ( r: arg_p ) "
"     handled? off              ( mid btmap ) ( r: arg_p ) "

"     dup r@ >ino-btmapA @ and  ( mid btmap btmap' ) ( r: arg_p ) "
"     r@ >clr-regsA @           ( mid btmap btmap' clrA_p ) ( r: arg_p ) "
"     sch-reset-interrupts      ( mid btmap true|false ) ( r: arg_p ) "
"     handled? tuck @ or        ( mid btmap &handled? handled? ) ( r: arg_p ) "
"     swap !                    ( mid btmap ) ( r: arg_p ) "

"     dup r@ >ino-btmapB @ and  ( mid btmap btmap' ) ( r: arg_p ) "
"     r> >clr-regsB @           ( mid btmap btmap' clrB_p ) ( r: ) "
"     sch-reset-interrupts      ( mid btmap true|false ) "
"     handled? tuck @ or        ( mid btmap &handled? handled? ) "
"     swap !                    ( mid btmap ) "

"     handled? @ if             ( mid btmap ) "
"       2drop true exit         ( true ) "
"     then                      ( mid btmap ) "
"   then                        ( mid btmap ) "
	/* Fallback to OBP. */
"   false                       ( mid btmap false ) "
"; "

/* Arm (take over) interrupt handler */
"' sch-interrupt-handler to unix-interrupt-handler "

;


#define	BUF_LEN	80

/*
 * ripped off from obp_timestamp().
 *
 * format is "OBP x.y.z YYYY/MM/DD HH:MM", but we're interested in only the
 * major number where x == 4; otherwise, unix-interrupt-handler is not
 * supported
 */
static int
pci_check_obp_ver()
{
	char v[BUF_LEN];
	char *c;
	int rc;

	rc = prom_version_name(v, BUF_LEN);
	if (rc < 0)
		return (-1);

	if (v[0] != 'O' || v[1] != 'B' || v[2] != 'P')
		return (-1);

	c = v + 3;

	/* Find first non-space character after OBP */
	while (*c != '\0' && (*c == ' ' || *c == '\t'))
		c++;
	if (prom_strlen(c) < 5)	/* need at least "x.y.z" */
		return (-1);

	if (*c == '4') {
		/* 4.y.x OBP supports master interrupt */
		return (0);
	} else {
		/* 5.y.x i.e. COBP, does not support master interrupt */
		return (-1);
	}
}

/*
 * This gets called exactly once on sun4u schizo/xmits/tomatillo platforms
 * during the first pcisch attach, thus before any schizo/xmits/tomatillo
 * interrupts are enabled.
 */
static void
pci_mi_init(pci_t *pci_p)
{
	static char uih_deferword[] = "unix-interrupt-handler";

	static char install_sch_interrupt_handler[
	    sizeof (define_sch_interrupt_handler) + 80];

	char buf[80];
	int is_defined = 0;
	static	boolean_t initialized = B_FALSE;

	ASSERT(MUTEX_HELD(&pci_global_mutex));

	/* master-interrupt initialization is performed only once! */
	if (initialized == B_TRUE)
		return;

	initialized = B_TRUE;

	/*
	 * master-interrupt framework hasn't been initialized yet;
	 * therefore, perform the necessary checks and initialize
	 * the framework if the platform satisfies the criteria.
	 */

	/*
	 * is master-interrupt functionality turned off via /etc/system
	 */
	if (pci_mi_enable == 0)
		return;

	/*
	 * supported on only 4.y.x OBP (i.e. COBP 5.y.z is not supported)
	 */
	if (pci_check_obp_ver() != 0)
		return;

	/*
	 * unix-interrupt-handler must be defined
	 */
	(void) sprintf(buf, "p\" %s\" find nip swap l! ", uih_deferword);
	prom_interpret(buf, (uintptr_t)(&is_defined), 0, 0, 0, 0);
	if (!is_defined)
		return;

	/*
	 * Check if "ino-bitmap" property exists.
	 */
	if (!ddi_prop_exists(DDI_DEV_T_NONE, pci_p->pci_dip, DDI_PROP_DONTPASS,
	    "ino-bitmap"))
		return;

	/* Check /etc/system tunable for proper boundaries */
	switch (pci_mi_intr_clr) {
	case COMMON_CLEAR_INTR_REG_IDLE:
	case COMMON_CLEAR_INTR_REG_RECEIVED:
		break;
	default:
		pci_mi_intr_clr = COMMON_CLEAR_INTR_REG_RECEIVED;
		break;
	}

	/*
	 * Define new interrupt handler
	 * Set interrupt handler table size and pointer
	 * Arm (take over) interrupt handler
	 */
	(void) sprintf(install_sch_interrupt_handler,
	    define_sch_interrupt_handler, pci_mi_intr_clr,
	    NAGENTS, sch_intr_table);
	prom_interpret(install_sch_interrupt_handler, 0, 0, 0, 0, 0);

	pci_mi_supported = B_TRUE;
}

static uint64_t
pci_mi_get_ino_bitmap(pci_t *pci_p)
{
	uint64_t ino_bitmap = 0;
	uint32_t *ino_buf;
	int ino_buf_len;
	char *pbuf;
	dev_info_t *dip = pci_p->pci_dip;

	/*
	 * fetch this PBM's ino-bitmap which must exist or we panic
	 * because the new interrupt handler defer-word is installed
	 * by this point and we can't backout now
	 */
	if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "ino-bitmap", (caddr_t)&ino_buf, &ino_buf_len) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "%s%d: no ino-bitmap property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}

	/*
	 * switch order of hi and low due to safari spec errata
	 */
	pbuf = (char *)&ino_bitmap;
	bcopy(&ino_buf[0], pbuf + sizeof (uint32_t), sizeof (uint32_t));
	bcopy(&ino_buf[1], pbuf, sizeof (uint32_t));
	kmem_free(ino_buf, ino_buf_len);

	return (ino_bitmap);
}


/*
 * Add a PBM leaf to master-interrupt handler table based on mid
 * and leaf side (A or B)
 */
void
pci_mi_setup(pci_t *pci_p)
{
	sch_arg_t *cp, **head;

	ASSERT(MUTEX_HELD(&pci_global_mutex));

	pci_mi_init(pci_p);

	if (pci_mi_supported == B_FALSE)
		return;

	head = &sch_intr_table[pci_p->pci_id];
	cp = *head;
	if (cp == NULL) {
		cp = kmem_zalloc(sizeof (sch_arg_t), KM_SLEEP);
		cp->pci_id = pci_p->pci_id;
		*head = cp;
	}

	if ((va_to_pa(pci_p->pci_address[0])) & PCI_SIDE_ADDR_MASK) {
		/* leaf B */
		ASSERT(cp->clr_regsB == 0ull);
		cp->clr_regsB = pci_p->pci_ib_p->ib_slot_clear_intr_regs;
		cp->ino_btmapB = pci_mi_get_ino_bitmap(pci_p);
	} else {
		/* leaf A */
		ASSERT(cp->clr_regsA == 0ull);
		cp->clr_regsA = pci_p->pci_ib_p->ib_slot_clear_intr_regs;
		cp->ino_btmapA = pci_mi_get_ino_bitmap(pci_p);
	}
}


/*
 * Remove a PBM leaf from master-interrupt handler table based on mid
 * and leaf side (A or B)
 */
void
pci_mi_destroy(pci_t *pci_p)
{
	sch_arg_t *cp, **head;

	ASSERT(MUTEX_HELD(&pci_global_mutex));

	if (pci_mi_supported == B_FALSE)
		return;

	head = &sch_intr_table[pci_p->pci_id];
	cp = *head;
	if (cp == NULL)
		return;

	if ((va_to_pa(pci_p->pci_address[0])) & PCI_SIDE_ADDR_MASK) {
		/* leaf B */
		ASSERT(cp->clr_regsB ==
		    pci_p->pci_ib_p->ib_slot_clear_intr_regs);
		cp->clr_regsB =  0ull;
		cp->ino_btmapB = 0ull;
	} else {
		/* leaf A */
		ASSERT(cp->clr_regsA ==
		    pci_p->pci_ib_p->ib_slot_clear_intr_regs);
		cp->clr_regsA = 0ull;
		cp->ino_btmapA = 0ull;
	}

	if (cp->clr_regsA == 0ull && cp->clr_regsB == 0ull) {
		*head = NULL;
		kmem_free(cp, sizeof (sch_arg_t));
	}
}

int
pci_mi_check(void)
{
	return (pci_mi_supported == B_TRUE &&
		pci_mi_intr_clr == COMMON_CLEAR_INTR_REG_IDLE);
}
