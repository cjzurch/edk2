@echo off
if "%1" == "" (
  echo Pass TOOL_CHAIN_TAG as only argument!
  echo   VS2015x86
  echo   CLANGPDB
) else (
  py -2 BaseTools\Source\Python\build\build.py -DDEBUG_ON_SERIAL_PORT=TRUE -t %*
)
