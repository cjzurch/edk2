/** @file
  OpenSSL Library API hooks.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

VOID *
__imp_RtlVirtualUnwind (
  VOID *    Args
  )
{
  return NULL;
}

