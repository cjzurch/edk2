#! /bin/bash
if
  [ $# != 1 ]; then
  echo "Pass TOOL_CHAIN_TAG as only argument!"
  echo "VS2015x86"
  echo "CLANGPDB"
  echo "GCC5"
else
  time qemu-system-x86_64 -bios Build/OvmfX64/DEBUG_$@/FV/OVMF.fd -serial file:bios.log -nic none
fi
