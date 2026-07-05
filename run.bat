@echo off
:: Portable launcher — %~dp0 resolves to this batch file's own directory.
:: Teammates do not need to edit this file; setup.bat regenerates it with the
:: Python interpreter detected on their machine.
pushd "%~dp0"
py server.py
popd
