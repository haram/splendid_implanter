@echo off

SET "VS_LOC="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe""

IF EXIST "%VS_LOC%" (goto compile) else (SET "VS_LOC="C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"" goto compile)

:compile
%VS_LOC% /build release splendid_implanter.sln