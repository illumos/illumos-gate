/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Argo Technology East
 */

/*
 * Userland interface to UEFI variables.
 *
 * Each variable is identified by a (vendor GUID, name) pair. Names in
 * UEFI are CHAR16 strings; this library accepts and returns UTF-8 and
 * converts to and from UTF-16 internally, including the full BMP and
 * surrogate pairs.
 *
 * All routines return 0 on success or -1 with errno set. Notable errno
 * values: ENOENT means the variable does not exist (or, for the
 * iterator, that there are no more entries); EPERM means /dev/efi
 * gated the request (the global zone and PRIV_SYS_CONFIG are required);
 * ENXIO means the efi driver is not attached, i.e. UEFI Runtime
 * Services are not available on this system.
 */

#ifndef	_LIBEFIVAR_H
#define	_LIBEFIVAR_H

#include <sys/types.h>
#include <uuid/uuid.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct uuid efi_guid_t;

/*
 * UEFI 2.10 variable attribute bits used by callers that need to
 * preserve them across a get/set.
 */
#define	EFI_VARIABLE_NON_VOLATILE			0x00000001
#define	EFI_VARIABLE_BOOTSERVICE_ACCESS			0x00000002
#define	EFI_VARIABLE_RUNTIME_ACCESS			0x00000004
#define	EFI_VARIABLE_HARDWARE_ERROR_RECORD		0x00000008
#define	EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS		0x00000010
#define	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
							0x00000020
#define	EFI_VARIABLE_APPEND_WRITE			0x00000040

/*
 * Quick probe: returns 0 if /dev/efi is openable and the kernel reports
 * UEFI Runtime Services as available, -1 with errno otherwise. Useful
 * for utilities that want to fail early on legacy-BIOS systems.
 */
extern int efi_variables_supported(void);

/*
 * Read a variable.  On success, *data is a malloc()ed buffer of
 * *datasize bytes that the caller must free(); *attrib (if non-NULL)
 * receives the UEFI attribute mask. On ENOENT *data is left
 * unchanged.
 */
extern int efi_get_variable(efi_guid_t vendor, const char *name,
    uint8_t **data, size_t *datasize, uint32_t *attrib);

/*
 * Write a variable. A datasize of 0 deletes the variable per UEFI
 * 8.2.3.
 */
extern int efi_set_variable(efi_guid_t vendor, const char *name,
    const uint8_t *data, size_t datasize, uint32_t attrib);

/*
 * Delete a variable. Equivalent to efi_set_variable(..., NULL, 0, 0).
 */
extern int efi_del_variable(efi_guid_t vendor, const char *name);

/*
 * Iterate the firmware's variable namespace. On the first call *name
 * must be NULL; on subsequent calls pass the values returned by the
 * previous call. The library frees the previous *name and replaces it
 * with a freshly malloc()ed UTF-8 name. End of iteration is reported
 * by -1 with errno == ENOENT, at which point *name is freed and set to
 * NULL. The caller is responsible for free()ing *name when aborting
 * iteration early.
 */
extern int efi_get_next_variable_name(efi_guid_t *vendor, char **name);

/*
 * EFI_LOAD_OPTION (the on-disk shape of a Boot####, Driver####,
 * SysPrep#### variable, see UEFI 2.10 section 3.1.3) is a packed
 * record:
 *
 *	uint32_t  Attributes
 *	uint16_t  FilePathListLength
 *	CHAR16    Description[];
 *	uint8_t   FilePathList[FilePathListLength];
 *	uint8_t   OptionalData[];
 *
 * efi_load_option_t holds the unpacked form. Strings are UTF-8;
 * device_path is the raw EFI_DEVICE_PATH byte stream from the
 * variable (or that should be written into one).
 */
typedef struct efi_load_option {
	uint32_t	elo_attributes;
	char		*elo_description;
	uint8_t		*elo_device_path;
	size_t		elo_device_path_size;
	uint8_t		*elo_optional_data;
	size_t		elo_optional_data_size;
} efi_load_option_t;

/*
 * Bits in the OsIndications / OsIndicationsSupported variables (UEFI
 * 2.10 section 8.5.4). The first one is the only one userland tools
 * usually touch: setting it before reboot causes the firmware to
 * enter its setup UI on the next boot.
 */
#define	EFI_OS_INDICATIONS_BOOT_TO_FW_UI		0x0000000000000001ULL

/* EFI_LOAD_OPTION attribute bits we care about. */
#define	EFI_LOAD_OPTION_ACTIVE		0x00000001U
#define	EFI_LOAD_OPTION_FORCE_RECONNECT	0x00000002U
#define	EFI_LOAD_OPTION_HIDDEN		0x00000008U
#define	EFI_LOAD_OPTION_CATEGORY	0x00001f00U
#define	EFI_LOAD_OPTION_CATEGORY_BOOT	0x00000000U
#define	EFI_LOAD_OPTION_CATEGORY_APP	0x00000100U

/*
 * Parse a Boot####/Driver####/SysPrep#### value into an
 * efi_load_option_t. Internal pointers are malloc()ed; release them
 * with efi_load_option_clear().
 */
extern int efi_load_option_parse(const uint8_t *data, size_t datasize,
    efi_load_option_t *out);

/*
 * Encode an efi_load_option_t back into the on-disk form. *out is
 * malloc()ed and must be free()d by the caller.
 */
extern int efi_load_option_build(const efi_load_option_t *in,
    uint8_t **out, size_t *outsize);

/*
 * Free the buffers an efi_load_option_t owns and zero the structure.
 * Safe on a zeroed efi_load_option_t.
 */
extern void efi_load_option_clear(efi_load_option_t *opt);

/*
 * Pretty-print an EFI_DEVICE_PATH as the efibootmgr(8)/Linux text
 * form: e.g. "HD(1,GPT,<guid>,0x800,0x100000)/File(\EFI\loader.efi)".
 * Unknown node types render as "Unk(<type>,<subtype>,<len>)".  *out
 * is malloc()ed.
 */
extern int efi_devpath_to_string(const uint8_t *path, size_t pathsize,
    char **out);

/*
 * Builder for an EFI_DEVICE_PATH byte stream.  Use efi_devpath_new()
 * to allocate, append nodes one by one and finalise with
 * efi_devpath_finalize() which appends the End-Of-Hardware-Device-Path
 * terminator and hands back a malloc()ed buffer.  efi_devpath_free()
 * releases an unfinalised builder.
 */
typedef struct efi_devpath_builder efi_devpath_builder_t;

extern efi_devpath_builder_t *efi_devpath_new(void);
extern void efi_devpath_free(efi_devpath_builder_t *);

#define	EFI_DEVPATH_HD_MBR_TYPE_PCAT	0x01
#define	EFI_DEVPATH_HD_MBR_TYPE_GPT	0x02
#define	EFI_DEVPATH_HD_SIG_TYPE_NONE	0x00
#define	EFI_DEVPATH_HD_SIG_TYPE_MBR	0x01
#define	EFI_DEVPATH_HD_SIG_TYPE_GUID	0x02

extern int efi_devpath_append_hd(efi_devpath_builder_t *,
    uint32_t partnum, uint64_t partstart, uint64_t partsize,
    const uint8_t signature[16], uint8_t mbr_type, uint8_t signature_type);

extern int efi_devpath_append_file(efi_devpath_builder_t *,
    const char *utf8_path);

extern int efi_devpath_finalize(efi_devpath_builder_t *,
    uint8_t **out, size_t *outsize);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBEFIVAR_H */
