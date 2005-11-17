/*******************************************************************************
 *
 * Module Name: rsmem24 - Memory resource descriptors
 *              $Revision: 1.31 $
 *
 ******************************************************************************/

/******************************************************************************
 *
 * 1. Copyright Notice
 *
 * Some or all of this work - Copyright (c) 1999 - 2005, Intel Corp.
 * All rights reserved.
 *
 * 2. License
 *
 * 2.1. This is your license from Intel Corp. under its intellectual property
 * rights.  You may have additional license terms from the party that provided
 * you this software, covering your right to use that party's intellectual
 * property rights.
 *
 * 2.2. Intel grants, free of charge, to any person ("Licensee") obtaining a
 * copy of the source code appearing in this file ("Covered Code") an
 * irrevocable, perpetual, worldwide license under Intel's copyrights in the
 * base code distributed originally by Intel ("Original Intel Code") to copy,
 * make derivatives, distribute, use and display any portion of the Covered
 * Code in any form, with the right to sublicense such rights; and
 *
 * 2.3. Intel grants Licensee a non-exclusive and non-transferable patent
 * license (with the right to sublicense), under only those claims of Intel
 * patents that are infringed by the Original Intel Code, to make, use, sell,
 * offer to sell, and import the Covered Code and derivative works thereof
 * solely to the minimum extent necessary to exercise the above copyright
 * license, and in no event shall the patent license extend to any additions
 * to or modifications of the Original Intel Code.  No other license or right
 * is granted directly or by implication, estoppel or otherwise;
 *
 * The above copyright and patent license is granted only if the following
 * conditions are met:
 *
 * 3. Conditions
 *
 * 3.1. Redistribution of Source with Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification with rights to further distribute source must include
 * the above Copyright Notice, the above License, this list of Conditions,
 * and the following Disclaimer and Export Compliance provision.  In addition,
 * Licensee must cause all Covered Code to which Licensee contributes to
 * contain a file documenting the changes Licensee made to create that Covered
 * Code and the date of any change.  Licensee must include in that file the
 * documentation of any changes made by any predecessor Licensee.  Licensee
 * must include a prominent statement that the modification is derived,
 * directly or indirectly, from Original Intel Code.
 *
 * 3.2. Redistribution of Source with no Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification without rights to further distribute source must
 * include the following Disclaimer and Export Compliance provision in the
 * documentation and/or other materials provided with distribution.  In
 * addition, Licensee may not authorize further sublicense of source of any
 * portion of the Covered Code, and must include terms to the effect that the
 * license from Licensee to its licensee is limited to the intellectual
 * property embodied in the software Licensee provides to its licensee, and
 * not to intellectual property embodied in modifications its licensee may
 * make.
 *
 * 3.3. Redistribution of Executable. Redistribution in executable form of any
 * substantial portion of the Covered Code or modification must reproduce the
 * above Copyright Notice, and the following Disclaimer and Export Compliance
 * provision in the documentation and/or other materials provided with the
 * distribution.
 *
 * 3.4. Intel retains all right, title, and interest in and to the Original
 * Intel Code.
 *
 * 3.5. Neither the name Intel nor any other trademark owned or controlled by
 * Intel shall be used in advertising or otherwise to promote the sale, use or
 * other dealings in products derived from or relating to the Covered Code
 * without prior written authorization from Intel.
 *
 * 4. Disclaimer and Export Compliance
 *
 * 4.1. INTEL MAKES NO WARRANTY OF ANY KIND REGARDING ANY SOFTWARE PROVIDED
 * HERE.  ANY SOFTWARE ORIGINATING FROM INTEL OR DERIVED FROM INTEL SOFTWARE
 * IS PROVIDED "AS IS," AND INTEL WILL NOT PROVIDE ANY SUPPORT,  ASSISTANCE,
 * INSTALLATION, TRAINING OR OTHER SERVICES.  INTEL WILL NOT PROVIDE ANY
 * UPDATES, ENHANCEMENTS OR EXTENSIONS.  INTEL SPECIFICALLY DISCLAIMS ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * 4.2. IN NO EVENT SHALL INTEL HAVE ANY LIABILITY TO LICENSEE, ITS LICENSEES
 * OR ANY OTHER THIRD PARTY, FOR ANY LOST PROFITS, LOST DATA, LOSS OF USE OR
 * COSTS OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, OR FOR ANY INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THIS AGREEMENT, UNDER ANY
 * CAUSE OF ACTION OR THEORY OF LIABILITY, AND IRRESPECTIVE OF WHETHER INTEL
 * HAS ADVANCE NOTICE OF THE POSSIBILITY OF SUCH DAMAGES.  THESE LIMITATIONS
 * SHALL APPLY NOTWITHSTANDING THE FAILURE OF THE ESSENTIAL PURPOSE OF ANY
 * LIMITED REMEDY.
 *
 * 4.3. Licensee shall not export, either directly or indirectly, any of this
 * software or system incorporating such software without first obtaining any
 * required license or other approval from the U. S. Department of Commerce or
 * any other agency or department of the United States Government.  In the
 * event Licensee exports any such software from the United States or
 * re-exports any such software from a foreign destination, Licensee shall
 * ensure that the distribution and export/re-export of the software is in
 * compliance with all laws, regulations, orders, or other restrictions of the
 * U.S. Export Administration Regulations. Licensee agrees that neither it nor
 * any of its subsidiaries will export/re-export any technical data, process,
 * software, or service, directly or indirectly, to any country for which the
 * United States government or any agency thereof requires an export license,
 * other governmental approval, or letter of assurance, without first obtaining
 * such license, approval or letter.
 *
 *****************************************************************************/

#define __RSMEMORY_C__

#include "acpi.h"
#include "acresrc.h"

#define _COMPONENT          ACPI_RESOURCES
        ACPI_MODULE_NAME    ("rsmemory")


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetMemory24
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetMemory24 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetMemory24");


    /* Get the Read/Write bit */

    Resource->Data.Memory24.ReadWriteAttribute =
        (Aml->Memory24.Information & 0x01);

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Minimum Base Address
     * Maximum Base Address
     * Address Base Alignment
     * Range Length
     */
    AcpiRsMoveData (&Resource->Data.Memory24.Minimum,
        &Aml->Memory24.Minimum, 4, ACPI_MOVE_TYPE_16_TO_32);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_MEMORY24;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_MEMORY24);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetMemory24
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetMemory24 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetMemory24");


    /* Set the Information Byte */

    Aml->Memory24.Information = (UINT8)
        (Resource->Data.Memory24.ReadWriteAttribute & 0x01);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Minimum Base Address
     * Maximum Base Address
     * Address Base Alignment
     * Range Length
     */
    AcpiRsMoveData (&Aml->Memory24.Minimum,
        &Resource->Data.Memory24.Minimum, 4, ACPI_MOVE_TYPE_32_TO_16);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_MEMORY24,
        sizeof (AML_RESOURCE_MEMORY24), Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetMemory32
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetMemory32 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetMemory32");


    /* Get the Read/Write bit */

    Resource->Data.Memory32.ReadWriteAttribute =
        (Aml->Memory32.Information & 0x01);

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Minimum Base Address
     * Maximum Base Address
     * Address Base Alignment
     * Range Length
     */
    AcpiRsMoveData (&Resource->Data.Memory32.Minimum,
        &Aml->Memory32.Minimum, 4, ACPI_MOVE_TYPE_32_TO_32);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_MEMORY32;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_MEMORY32);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetMemory32
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetMemory32 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetMemory32");


    /* Set the Information Byte */

    Aml->Memory32.Information = (UINT8)
        (Resource->Data.Memory32.ReadWriteAttribute & 0x01);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Minimum Base Address
     * Maximum Base Address
     * Address Base Alignment
     * Range Length
     */
    AcpiRsMoveData (&Aml->Memory32.Minimum,
        &Resource->Data.Memory32.Minimum, 4, ACPI_MOVE_TYPE_32_TO_32);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_MEMORY32,
        sizeof (AML_RESOURCE_MEMORY32), Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetFixedMemory32
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetFixedMemory32 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetFixedMemory32");


    /* Get the Read/Write bit */

    Resource->Data.FixedMemory32.ReadWriteAttribute =
        (Aml->FixedMemory32.Information & 0x01);

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Base Address
     * Range Length
     */
    ACPI_MOVE_32_TO_32 (&Resource->Data.FixedMemory32.Address,
        &Aml->FixedMemory32.Address);
    ACPI_MOVE_32_TO_32 (&Resource->Data.FixedMemory32.AddressLength,
        &Aml->FixedMemory32.AddressLength);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_FIXED_MEMORY32;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_FIXED_MEMORY32);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetFixedMemory32
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetFixedMemory32 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetFixedMemory32");


    /* Set the Information Byte */

    Aml->FixedMemory32.Information = (UINT8)
        (Resource->Data.FixedMemory32.ReadWriteAttribute & 0x01);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Base Address
     * Range Length
     */
    ACPI_MOVE_32_TO_32 (&Aml->FixedMemory32.Address,
        &Resource->Data.FixedMemory32.Address);
    ACPI_MOVE_32_TO_32 (&Aml->FixedMemory32.AddressLength,
        &Resource->Data.FixedMemory32.AddressLength);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_FIXED_MEMORY32,
        sizeof (AML_RESOURCE_FIXED_MEMORY32), Aml);
    return_ACPI_STATUS (AE_OK);
}

