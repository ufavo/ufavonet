@echo off

setlocal
set PATH=%PATH%;C:\mingw\bin;C:\mingw\msys\1.0\bin

if [%1] == [] goto :all
if [%1] == [tests] goto :tests
if [%1] == [clean] goto :clean

:all
gcc .\src\net.c .\src\netmsg.c .\src\packet.c -std=c99 -pedantic -Wall -Wextra -O3 -march=x86-64 -shared -fPIC -o ufavonet.dll -lws2_32
exit

:tests
gcc .\src\net.c .\src\netmsg.c .\src\packet.c -std=c99 -pedantic -Wall -Wextra -O3 -march=x86-64 -shared -fPIC -o ufavonet.dll -lws2_32
gcc tests.c -std=gnu99 -pedantic -O3 -Wno-unused-parameter -march=x86-64 -o tests.exe -lws2_32 -L.\ -lufavonet
.\tests.exe
exit

:clean
del ufavonet.dll
del tests.exe
