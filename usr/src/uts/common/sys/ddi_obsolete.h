/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef	_SYS_DDI_OBSOLETE_H
#define	_SYS_DDI_OBSOLETE_H

/*
 * Obsoleted DDI Interfaces
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/sunldi.h>


#ifdef	__cplusplus
extern "C" {
#endif


#ifndef	_DDI_STRICT

extern long strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);

uint8_t ddi_mem_get8(ddi_acc_handle_t handle, uint8_t *host_addr);
uint16_t ddi_mem_get16(ddi_acc_handle_t handle, uint16_t *host_addr);
uint32_t ddi_mem_get32(ddi_acc_handle_t handle, uint32_t *host_addr);
uint64_t ddi_mem_get64(ddi_acc_handle_t handle, uint64_t *host_addr);
void ddi_mem_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value);
void ddi_mem_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value);
void ddi_mem_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value);
void ddi_mem_put64(ddi_acc_handle_t handle, uint64_t *dev_addr, uint64_t value);

void ddi_mem_rep_get8(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_get16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_get32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_get64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put8(ddi_acc_handle_t handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put16(ddi_acc_handle_t handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put32(ddi_acc_handle_t handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void ddi_mem_rep_put64(ddi_acc_handle_t handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

uint8_t ddi_io_get8(ddi_acc_handle_t handle, uint8_t *dev_addr);
uint16_t ddi_io_get16(ddi_acc_handle_t handle, uint16_t *dev_addr);
uint32_t ddi_io_get32(ddi_acc_handle_t handle, uint32_t *dev_addr);
void ddi_io_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value);
void ddi_io_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value);
void ddi_io_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value);

void ddi_io_rep_get8(ddi_acc_handle_t handle,
    uint8_t *host_addr, uint8_t *dev_addr, size_t repcount);
void ddi_io_rep_get16(ddi_acc_handle_t handle,
    uint16_t *host_addr, uint16_t *dev_addr, size_t repcount);
void ddi_io_rep_get32(ddi_acc_handle_t handle,
    uint32_t *host_addr, uint32_t *dev_addr, size_t repcount);
void ddi_io_rep_put8(ddi_acc_handle_t handle,
    uint8_t *host_addr, uint8_t *dev_addr, size_t repcount);
void ddi_io_rep_put16(ddi_acc_handle_t handle,
    uint16_t *host_addr, uint16_t *dev_addr, size_t repcount);
void ddi_io_rep_put32(ddi_acc_handle_t handle,
    uint32_t *host_addr, uint32_t *dev_addr, size_t repcount);

/* Obsolete LDI event interfaces */
extern int ldi_get_eventcookie(ldi_handle_t, char *,
    ddi_eventcookie_t *);
extern int ldi_add_event_handler(ldi_handle_t, ddi_eventcookie_t,
    void (*handler)(ldi_handle_t, ddi_eventcookie_t, void *, void *),
    void *, ldi_callback_id_t *);
extern int ldi_remove_event_handler(ldi_handle_t, ldi_callback_id_t);


#endif /* not _DDI_STRICT */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_OBSOLETE_H */
