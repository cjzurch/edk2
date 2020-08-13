/** @file
  EVP MD Wrapper Null Library.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Allocates and initializes one EVP_MD_CTX context for subsequent EVP_MD use.

  Return FALSE to indicate this interface is not supported.

  @param[in]    DigestName    Pointer to the digest name.

  @return NULL  This interface is not supported.

**/
VOID *
EFIAPI
EvpMdInit (
  IN  CONST CHAR8   *DigestName
  )
{
  ASSERT (FALSE);
  return NULL;
}

/**
  Makes a copy of an existing EVP_MD context.

  Return FALSE to indicate this interface is not supported.

  @param[in]  EvpMdContext     Pointer to EVP_MD context being copied.
  @param[out] NewEvpMdContext  Pointer to new EVP_MD context.

  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
EvpMdDuplicate (
  IN  CONST VOID    *EvpMdContext,
  OUT VOID          *NewEvpMdContext
  )
{
  ASSERT (FALSE);
  return FALSE;
}

/**
  Digests the input data and updates EVP_MD context.

  Return FALSE to indicate this interface is not supported.

  @param[in, out]  EvpMdContext       Pointer to the EVP_MD context.
  @param[in]       Data               Pointer to the buffer containing the data to be digested.
  @param[in]       DataSize           Size of Data buffer in bytes.

  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
EvpMdUpdate (
  IN OUT  VOID        *EvpMdContext,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

/**
  Completes computation of the EVP digest value.
  Releases the specified EVP_MD_CTX context.

  Return FALSE to indicate this interface is not supported.

  @param[in, out]  EvpMdContext   Pointer to the EVP context.
  @param[out]      Digest         Pointer to a buffer that receives the EVP digest value.

  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
EvpMdFinal (
  IN OUT  VOID   *EvpMdContext,
  OUT     UINT8  *DigestValue
  )
{
  ASSERT (FALSE);
  return FALSE;
}

/**
  Computes the message digest of an input data buffer.

  Return FALSE to indicate this interface is not supported.

  @param[in]    DigestName    Pointer to the digest name.
  @param[in]    Data          Pointer to the buffer containing the data to be hashed.
  @param[in]    DataSize      Size of Data buffer in bytes.
  @param[out]   HashValue     Pointer to a buffer that receives the digest value.

  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
EvpMdHashAll (
  IN  CONST CHAR8   *DigestName,
  IN  CONST VOID    *Data,
  IN  UINTN         DataSize,
  OUT UINT8         *HashValue
  )
{
  ASSERT (FALSE);
  return FALSE;
}
