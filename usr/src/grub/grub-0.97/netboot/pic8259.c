/*
 * Basic support for controlling the 8259 Programmable Interrupt Controllers.
 *
 * Initially written by Michael Brown (mcb30).
 */

#include <etherboot.h>
#include <pic8259.h>

#ifdef DEBUG_IRQ
#define DBG(...) printf ( __VA_ARGS__ )
#else
#define DBG(...)
#endif

/* Install a handler for the specified IRQ.  Address of previous
 * handler will be stored in previous_handler.  Enabled/disabled state
 * of IRQ will be preserved across call, therefore if the handler does
 * chaining, ensure that either (a) IRQ is disabled before call, or
 * (b) previous_handler points directly to the place that the handler
 * picks up its chain-to address.
 */

int install_irq_handler ( irq_t irq, segoff_t *handler,
			  uint8_t *previously_enabled,
			  segoff_t *previous_handler ) {
	segoff_t *irq_vector = IRQ_VECTOR ( irq );
	*previously_enabled = irq_enabled ( irq );

	if ( irq > IRQ_MAX ) {
		DBG ( "Invalid IRQ number %d\n" );
		return 0;
	}

	previous_handler->segment = irq_vector->segment;
	previous_handler->offset = irq_vector->offset;
	if ( *previously_enabled ) disable_irq ( irq );
	DBG ( "Installing handler at %hx:%hx for IRQ %d, leaving %s\n",
		  handler->segment, handler->offset, irq,
		  ( *previously_enabled ? "enabled" : "disabled" ) );
	DBG ( "...(previous handler at %hx:%hx)\n",
		  previous_handler->segment, previous_handler->offset );
	irq_vector->segment = handler->segment;
	irq_vector->offset = handler->offset;
	if ( *previously_enabled ) enable_irq ( irq );
	return 1;
}

/* Remove handler for the specified IRQ.  Routine checks that another
 * handler has not been installed that chains to handler before
 * uninstalling handler.  Enabled/disabled state of the IRQ will be
 * restored to that specified by previously_enabled.
 */

int remove_irq_handler ( irq_t irq, segoff_t *handler,
			 uint8_t *previously_enabled,
			 segoff_t *previous_handler ) {
	segoff_t *irq_vector = IRQ_VECTOR ( irq );

	if ( irq > IRQ_MAX ) {
		DBG ( "Invalid IRQ number %d\n" );
		return 0;
	}
	if ( ( irq_vector->segment != handler->segment ) ||
	     ( irq_vector->offset != handler->offset ) ) {
		DBG ( "Cannot remove handler for IRQ %d\n" );
		return 0;
	}

	DBG ( "Removing handler for IRQ %d\n", irq );
	disable_irq ( irq );
	irq_vector->segment = previous_handler->segment;
	irq_vector->offset = previous_handler->offset;
	if ( *previously_enabled ) enable_irq ( irq );
	return 1;
}

/* Send specific EOI(s).
 */

void send_specific_eoi ( irq_t irq ) {
	DBG ( "Sending specific EOI for IRQ %d\n", irq );
	outb ( ICR_EOI_SPECIFIC | ICR_VALUE(irq), ICR_REG(irq) );
	if ( irq >= IRQ_PIC_CUTOFF ) {
		outb ( ICR_EOI_SPECIFIC | ICR_VALUE(CHAINED_IRQ),
		       ICR_REG(CHAINED_IRQ) );
	}
}

/* Dump current 8259 status: enabled IRQs and handler addresses.
 */

#ifdef DEBUG_IRQ
void dump_irq_status (void) {
	int irq = 0;
	
	for ( irq = 0; irq < 16; irq++ ) {
		if ( irq_enabled ( irq ) ) {
			printf ( "IRQ%d enabled, ISR at %hx:%hx\n", irq,
				 IRQ_VECTOR(irq)->segment,
				 IRQ_VECTOR(irq)->offset );
		}
	}
}
#endif

/********************************************************************
 * UNDI interrupt handling
 * This essentially follows the defintion of the trivial interrupt
 * handler routines. The text is assumed to locate in base memory.
 */
void (*undi_irq_handler)P((void)) = _undi_irq_handler;
uint16_t volatile *undi_irq_trigger_count = &_undi_irq_trigger_count;
segoff_t *undi_irq_chain_to = &_undi_irq_chain_to;
uint8_t *undi_irq_chain = &_undi_irq_chain;
irq_t undi_irq_installed_on = IRQ_NONE;

/* UNDI entry point and irq, used by interrupt handler
 */
segoff_t *pxenv_undi_entrypointsp = &_pxenv_undi_entrypointsp;
uint8_t *pxenv_undi_irq = &_pxenv_undi_irq;

/* Previous trigger count for undi IRQ handler */
static uint16_t undi_irq_previous_trigger_count = 0;

/* Install the undi IRQ handler. Don't test as UNDI has not be opened.
 */

int install_undi_irq_handler ( irq_t irq, segoff_t entrypointsp ) {
	segoff_t undi_irq_handler_segoff = SEGOFF(undi_irq_handler);
	
	if ( undi_irq_installed_on != IRQ_NONE ) {
		DBG ( "Can install undi IRQ handler only once\n" );
		return 0;
	}
	if ( SEGMENT(undi_irq_handler) > 0xffff ) {
		DBG ( "Trivial IRQ handler not in base memory\n" );
		return 0;
	}

	DBG ( "Installing undi IRQ handler on IRQ %d\n", irq );
	*pxenv_undi_entrypointsp = entrypointsp;
	*pxenv_undi_irq = irq;
	if ( ! install_irq_handler ( irq, &undi_irq_handler_segoff,
				     undi_irq_chain,
				     undi_irq_chain_to ) )
		return 0;
	undi_irq_installed_on = irq;

	DBG ( "Disabling undi IRQ %d\n", irq );
	disable_irq ( irq );
	*undi_irq_trigger_count = 0;
	undi_irq_previous_trigger_count = 0;
	DBG ( "UNDI IRQ handler installed successfully\n" );
	return 1;
}

/* Remove the undi IRQ handler.
 */

int remove_undi_irq_handler ( irq_t irq ) {
	segoff_t undi_irq_handler_segoff = SEGOFF(undi_irq_handler);

	if ( undi_irq_installed_on == IRQ_NONE ) return 1;
	if ( irq != undi_irq_installed_on ) {
		DBG ( "Cannot uninstall undi IRQ handler from IRQ %d; "
		      "is installed on IRQ %d\n", irq,
		      undi_irq_installed_on );
		return 0;
	}

	if ( ! remove_irq_handler ( irq, &undi_irq_handler_segoff,
				    undi_irq_chain,
				    undi_irq_chain_to ) )
		return 0;

	if ( undi_irq_triggered ( undi_irq_installed_on ) ) {
		DBG ( "Sending EOI for unwanted undi IRQ\n" );
		send_specific_eoi ( undi_irq_installed_on );
	}

	undi_irq_installed_on = IRQ_NONE;
	return 1;
}

/* Safe method to detect whether or not undi IRQ has been
 * triggered.  Using this call avoids potential race conditions.  This
 * call will return success only once per trigger.
 */

int undi_irq_triggered ( irq_t irq ) {
	uint16_t undi_irq_this_trigger_count = *undi_irq_trigger_count;
	int triggered = ( undi_irq_this_trigger_count -
			  undi_irq_previous_trigger_count );
	
	/* irq is not used at present, but we have it in the API for
	 * future-proofing; in case we want the facility to have
	 * multiple undi IRQ handlers installed simultaneously.
	 *
	 * Avoid compiler warning about unused variable.
	 */
	if ( irq == IRQ_NONE ) {};	
	undi_irq_previous_trigger_count = undi_irq_this_trigger_count;
	return triggered ? 1 : 0;
}
