/** @file
  This module implements Hash2 Protocol.

(C) Copyright 2015 Hewlett-Packard Development Company, L.P.<BR>
Copyright (c) 2015 - 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Protocol/Hash2.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>

#include "Driver.h"

typedef struct {
  EFI_GUID                  *Guid;
  UINT32                    HashSize;
  CONST CHAR8               *DigestName;
} EFI_HASH_INFO;

EFI_HASH_INFO  mHashInfo[] = {
  {&gEfiHashAlgorithmMD5Guid,     sizeof(EFI_MD5_HASH2),    "MD5"},
  {&gEfiHashAlgorithmSha1Guid,    sizeof(EFI_SHA1_HASH2),   "SHA1"},
  {&gEfiHashAlgorithmSha256Guid,  sizeof(EFI_SHA256_HASH2), "SHA256"},
  {&gEfiHashAlgorithmSha384Guid,  sizeof(EFI_SHA384_HASH2), "SHA384"},
  {&gEfiHashAlgorithmSha512Guid,  sizeof(EFI_SHA512_HASH2), "SHA512"},
};

/**
  Returns hash information.

  @param[in]  HashAlgorithm         Points to the EFI_GUID which identifies the algorithm to use.

  @return Hash information.
**/
EFI_HASH_INFO *
GetHashInfo (
  IN CONST EFI_GUID              *HashAlgorithm
  )
{
  UINTN      Index;

  for (Index = 0; Index < sizeof(mHashInfo)/sizeof(mHashInfo[0]); Index++) {
    if (CompareGuid (HashAlgorithm, mHashInfo[Index].Guid)) {
      return &mHashInfo[Index];
    }
  }
  return NULL;
}

/**
  Returns the size of the hash which results from a specific algorithm.

  @param[in]  This                  Points to this instance of EFI_HASH2_PROTOCOL.
  @param[in]  HashAlgorithm         Points to the EFI_GUID which identifies the algorithm to use.
  @param[out] HashSize              Holds the returned size of the algorithm's hash.

  @retval EFI_SUCCESS           Hash size returned successfully.
  @retval EFI_INVALID_PARAMETER This or HashSize is NULL.
  @retval EFI_UNSUPPORTED       The algorithm specified by HashAlgorithm is not supported by this driver
                                or HashAlgorithm is null.

**/
EFI_STATUS
EFIAPI
BaseCrypto2GetHashSize (
  IN  CONST EFI_HASH2_PROTOCOL     *This,
  IN  CONST EFI_GUID              *HashAlgorithm,
  OUT UINTN                       *HashSize
  )
{
  EFI_HASH_INFO *HashInfo;

  if ((This == NULL) || (HashSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (HashAlgorithm == NULL) {
    return EFI_UNSUPPORTED;
  }

  HashInfo = GetHashInfo (HashAlgorithm);
  if (HashInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  *HashSize = HashInfo->HashSize;
  return EFI_SUCCESS;
}

/**
  Creates a hash for the specified message text. The hash is not extendable.
  The output is final with any algorithm-required padding added by the function.

  @param[in]  This          Points to this instance of EFI_HASH2_PROTOCOL.
  @param[in]  HashAlgorithm Points to the EFI_GUID which identifies the algorithm to use.
  @param[in]  Message       Points to the start of the message.
  @param[in]  MessageSize   The size of Message, in bytes.
  @param[in,out]  Hash      On input, points to a caller-allocated buffer of the size
                              returned by GetHashSize() for the specified HashAlgorithm.
                            On output, the buffer holds the resulting hash computed from the message.

  @retval EFI_SUCCESS           Hash returned successfully.
  @retval EFI_INVALID_PARAMETER This or Hash is NULL.
  @retval EFI_UNSUPPORTED       The algorithm specified by HashAlgorithm is not supported by this driver
                                or HashAlgorithm is Null.
  @retval EFI_OUT_OF_RESOURCES  Some resource required by the function is not available
                                or MessageSize is greater than platform maximum.

**/
EFI_STATUS
EFIAPI
BaseCrypto2Hash (
  IN CONST EFI_HASH2_PROTOCOL      *This,
  IN CONST EFI_GUID                *HashAlgorithm,
  IN CONST UINT8                   *Message,
  IN UINTN                         MessageSize,
  IN OUT EFI_HASH2_OUTPUT          *Hash
  )
{
  EFI_STATUS               Status;

  Status = EFI_SUCCESS;

  if ((This == NULL) || (Hash == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (HashAlgorithm == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status = This->HashInit (This, HashAlgorithm);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = This->HashUpdate (This, Message, MessageSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = This->HashFinal (This, Hash);

  return Status;
}

/**
  This function must be called to initialize a digest calculation to be subsequently performed using the
  EFI_HASH2_PROTOCOL functions HashUpdate() and HashFinal().

  @param[in]  This          Points to this instance of EFI_HASH2_PROTOCOL.
  @param[in]  HashAlgorithm Points to the EFI_GUID which identifies the algorithm to use.

  @retval EFI_SUCCESS           Initialized successfully.
  @retval EFI_INVALID_PARAMETER This is NULL.
  @retval EFI_UNSUPPORTED       The algorithm specified by HashAlgorithm is not supported by this driver
                                or HashAlgorithm is Null.
  @retval EFI_OUT_OF_RESOURCES  Process failed due to lack of required resource.
  @retval EFI_ALREADY_STARTED   This function is called when the operation in progress is still in processing Hash(),
                                or HashInit() is already called before and not terminated by HashFinal() yet on the same instance.

**/
EFI_STATUS
EFIAPI
BaseCrypto2HashInit (
  IN CONST EFI_HASH2_PROTOCOL      *This,
  IN CONST EFI_GUID                *HashAlgorithm
  )
{
  EFI_HASH_INFO            *HashInfo;
  VOID                     *HashCtx;
  HASH2_INSTANCE_DATA      *Instance;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (HashAlgorithm == NULL) {
    return EFI_UNSUPPORTED;
  }

  HashInfo = GetHashInfo (HashAlgorithm);
  if (HashInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  //
  // Consistency Check
  //
  Instance = HASH2_INSTANCE_DATA_FROM_THIS (This);
  if (Instance->HashContext != NULL) {
    return EFI_ALREADY_STARTED;
  }

  //
  // Start hash sequence
  //
  HashCtx = EvpMdInit (HashInfo->DigestName);
  if (HashCtx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Setup the context
  //
  Instance->HashContext = HashCtx;
  Instance->Updated = FALSE;

  return EFI_SUCCESS;
}

/**
  Updates the hash of a computation in progress by adding a message text.

  @param[in]  This          Points to this instance of EFI_HASH2_PROTOCOL.
  @param[in]  Message       Points to the start of the message.
  @param[in]  MessageSize   The size of Message, in bytes.

  @retval EFI_SUCCESS           Digest in progress updated successfully.
  @retval EFI_INVALID_PARAMETER This or Hash is NULL.
  @retval EFI_OUT_OF_RESOURCES  Some resource required by the function is not available
                                or MessageSize is greater than platform maximum.
  @retval EFI_NOT_READY         This call was not preceded by a valid call to HashInit(),
                                or the operation in progress was terminated by a call to Hash() or HashFinal() on the same instance.

**/
EFI_STATUS
EFIAPI
BaseCrypto2HashUpdate (
  IN CONST EFI_HASH2_PROTOCOL      *This,
  IN CONST UINT8                   *Message,
  IN UINTN                         MessageSize
  )
{
  VOID                     *HashCtx;
  BOOLEAN                  Ret;
  HASH2_INSTANCE_DATA      *Instance;

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Consistency Check
  //
  Instance = HASH2_INSTANCE_DATA_FROM_THIS(This);
  if (Instance->HashContext == NULL) {
    return EFI_NOT_READY;
  }
  HashCtx  = Instance->HashContext;

  Ret = EvpMdUpdate (HashCtx, Message, MessageSize);
  if (!Ret) {
    return EFI_OUT_OF_RESOURCES;
  }

  Instance->Updated = TRUE;

  return EFI_SUCCESS;
}

/**
  Finalizes a hash operation in progress and returns calculation result.
  The output is final with any necessary padding added by the function.
  The hash may not be further updated or extended after HashFinal().

  @param[in]  This          Points to this instance of EFI_HASH2_PROTOCOL.
  @param[in,out]  Hash      On input, points to a caller-allocated buffer of the size
                              returned by GetHashSize() for the specified HashAlgorithm specified in preceding HashInit().
                            On output, the buffer holds the resulting hash computed from the message.

  @retval EFI_SUCCESS           Hash returned successfully.
  @retval EFI_INVALID_PARAMETER This or Hash is NULL.
  @retval EFI_NOT_READY         This call was not preceded by a valid call to HashInit() and at least one call to HashUpdate(),
                                or the operation in progress was canceled by a call to Hash() on the same instance.

**/
EFI_STATUS
EFIAPI
BaseCrypto2HashFinal (
  IN CONST EFI_HASH2_PROTOCOL      *This,
  IN OUT EFI_HASH2_OUTPUT          *Hash
  )
{
  BOOLEAN                  Ret;
  HASH2_INSTANCE_DATA      *Instance;

  if ((This == NULL) || (Hash == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Consistency Check
  //
  Instance = HASH2_INSTANCE_DATA_FROM_THIS(This);
  if ((Instance->HashContext == NULL) ||
      (!Instance->Updated)) {
    return EFI_NOT_READY;
  }

  Ret = EvpMdFinal (Instance->HashContext, (UINT8 *)Hash->Sha1Hash);

  //
  // Cleanup the context
  //
  Instance->HashContext = NULL;
  Instance->Updated = FALSE;

  if (!Ret) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

EFI_HASH2_PROTOCOL mHash2Protocol = {
  BaseCrypto2GetHashSize,
  BaseCrypto2Hash,
  BaseCrypto2HashInit,
  BaseCrypto2HashUpdate,
  BaseCrypto2HashFinal,
};
