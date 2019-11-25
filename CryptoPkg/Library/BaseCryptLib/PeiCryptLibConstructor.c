/** @file
  Constructor to initialize CPUID data for assembly operations.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>

extern void OPENSSL_cpuid_setup (void);

/**
  Constructor routine for CryptLib.

  The constructor function calls OpenSSL crypto init, which uses CPUID
  feature flags to enable various native crypto algorithms.

  @param  ImageHandle   The firmware allocated handle for the EFI image.
  @param  SystemTable   A pointer to the EFI System Table.

  @retval EFI_SUCCESS         The construction succeeded.
  @retval EFI_LOAD_ERROR      Failed to initialize OpenSSL.

**/
EFI_STATUS
EFIAPI
CryptLibConstructor (
  IN       EFI_PEI_FILE_HANDLE       FileHandle,
  IN CONST EFI_PEI_SERVICES          **PeiServices
  )
{
  OPENSSL_cpuid_setup ();

  return EFI_SUCCESS;
}

