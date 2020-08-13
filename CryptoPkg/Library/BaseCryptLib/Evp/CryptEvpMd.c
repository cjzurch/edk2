/** @file
  EVP MD Wrapper Implementation for OpenSSL.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>

/**
  Allocates and initializes one EVP_MD_CTX context for subsequent EVP_MD use.

  If DigestName is NULL, then return FALSE.

  @param[in]    DigestName    Pointer to the digest name.

  @return  Pointer to the EVP_MD_CTX context that has been allocated and initialized.
           If DigestName is invalid, returns NULL.
           If the allocations fails, returns NULL.
           If initialization fails, returns NULL.

**/
VOID *
EFIAPI
EvpMdInit (
  IN  CONST CHAR8   *DigestName
  )
{
  EVP_MD    *Digest;
  VOID      *EvpMdContext;

  //
  // Check input parameters.
  //
  if (DigestName == NULL) {
    return NULL;
  }

  //
  // Allocate EVP_MD_CTX Context
  //
  EvpMdContext = EVP_MD_CTX_new ();
  if (EvpMdContext == NULL) {
    return NULL;
  }

  Digest = EVP_get_digestbyname (DigestName);
  if (Digest == NULL) {
    return NULL;
  }

  //
  // Initialize Context
  //
  if (EVP_DigestInit_ex (EvpMdContext, Digest, NULL) != 1) {
    EVP_MD_CTX_free (EvpMdContext);
    return NULL;
  }

  return EvpMdContext;
}

/**
  Makes a copy of an existing EVP_MD context.

  If EvpMdContext is NULL, then return FALSE.
  If NewEvpMdContext is NULL, then return FALSE.

  @param[in]  EvpMdContext     Pointer to EVP_MD context being copied.
  @param[out] NewEvpMdContext  Pointer to new EVP_MD context.

  @retval TRUE   EVP_MD context copy succeeded.
  @retval FALSE  EVP_MD context copy failed.

**/
BOOLEAN
EFIAPI
EvpMdDuplicate (
  IN  CONST VOID    *EvpMdContext,
  OUT VOID          *NewEvpMdContext
  )
{
  //
  // Check input parameters.
  //
  if (EvpMdContext == NULL || NewEvpMdContext == NULL) {
    return FALSE;
  }

  if (EVP_MD_CTX_copy (NewEvpMdContext, EvpMdContext) != 1) {
    return FALSE;
  }

  return TRUE;
}

/**
  Digests the input data and updates EVP_MD context.

  This function performs EVP digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  EVP_MD context should be already correctly initialized by EvpMdInit(), and should not
  be finalized by EvpMdFinal(). Behavior with invalid context is undefined.

  If EvpMdContext is NULL, then return FALSE.
  If Data is NULL and DataSize is not zero, return FALSE.

  @param[in, out]  EvpMdContext       Pointer to the EVP_MD context.
  @param[in]       Data               Pointer to the buffer containing the data to be digested.
  @param[in]       DataSize           Size of Data buffer in bytes.

  @retval TRUE   EVP data digest succeeded.
  @retval FALSE  EVP data digest failed.

**/
BOOLEAN
EFIAPI
EvpMdUpdate (
  IN OUT  VOID        *EvpMdContext,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  //
  // Check input parameters.
  //
  if (EvpMdContext == NULL) {
    return FALSE;
  }

  //
  // Check invalid parameters, in case only DataLength was checked in OpenSSL
  //
  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }

  //
  // OpenSSL EVP digest update
  //
  if (EVP_DigestUpdate (EvpMdContext, Data, DataSize) != 1) {
    return FALSE;
  }

  return TRUE;
}

/**
  Completes computation of the EVP digest value.
  Releases the specified EVP_MD_CTX context.

  This function completes EVP hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the EVP context cannot
  be used again.
  EVP context should be already correctly initialized by EvpMdInit(), and should
  not be finalized by EvpMdFinal(). Behavior with invalid EVP context is undefined.

  If EvpMdContext is NULL, then return FALSE.
  If DigestValue is NULL, free the Context then return FALSE.

  @param[in, out]  EvpMdContext   Pointer to the EVP context.
  @param[out]      Digest         Pointer to a buffer that receives the EVP digest value.

  @retval TRUE   EVP digest computation succeeded.
  @retval FALSE  EVP digest computation failed.

**/
BOOLEAN
EFIAPI
EvpMdFinal (
  IN OUT  VOID   *EvpMdContext,
  OUT     UINT8  *DigestValue
  )
{
  UINT32    Length;
  BOOLEAN   ReturnValue;

  ReturnValue = TRUE;

  //
  // Check input parameters.
  //
  if (EvpMdContext == NULL) {
    return FALSE;
  }
  if (DigestValue == NULL) {
    EVP_MD_CTX_free (EvpMdContext);
    return FALSE;
  }

  //
  // OpenSSL EVP digest finalization
  //
  if (EVP_DigestFinal_ex (EvpMdContext, DigestValue, &Length) != 1) {
    ReturnValue = FALSE;
  }

  //
  // Free OpenSSL EVP_MD_CTX Context
  //
  EVP_MD_CTX_free (EvpMdContext);

  return ReturnValue;
}

/**
  Computes the message digest of an input data buffer.

  This function performs the message digest of a given data buffer, and places
  the digest value into the specified memory.

  If DigestName is NULL, return FALSE.
  If Data is NULL and DataSize is not zero, return FALSE.
  If HashValue is NULL, return FALSE.

  @param[in]    DigestName    Pointer to the digest name.
  @param[in]    Data          Pointer to the buffer containing the data to be hashed.
  @param[in]    DataSize      Size of Data buffer in bytes.
  @param[out]   HashValue     Pointer to a buffer that receives the digest value.

  @retval TRUE   Digest computation succeeded.
  @retval FALSE  Digest computation failed.

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
  BOOLEAN   Result;
  VOID      *EvpMdContext;

  EvpMdContext = EvpMdInit (DigestName);
  if (EvpMdContext == NULL) {
    return FALSE;
  }

  Result = EvpMdUpdate (EvpMdContext, Data, DataSize);
  if (Result == FALSE) {
    EvpMdFinal (EvpMdContext, NULL);
    return FALSE;
  }

  Result = EvpMdFinal (EvpMdContext, HashValue);

  return Result;
}
