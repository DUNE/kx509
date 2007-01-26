rem @echo off

if exist i386_nt35 rmdir /s /q i386_nt35 >nul
mkdir i386_nt35

cd i386_nt35

rem --------------------------------------------------
rem if mkdir fails because it "already exists" but
rem is "not" already there, it's probably because
rem you're running something that is referencing it
rem like Visual C++ ...
rem --------------------------------------------------

mkdir kx509
copy ..\src\kx509.dsw kx509 >nul

rem --------------------------------------------------
rem Select local project directory for KX509
rem --------------------------------------------------
set p=D:\project\kx509

rem --------------------------------------------------
rem Select root of KX509 -- used for /I in kx509.dsp
rem --------------------------------------------------
rem set b=t:\kwc\temp-checkout\kx509
rem set b=X:\kx509
set b=H:\b\kx509

rem --------------------------------------------------
rem Select version of OpenSSL to build with
rem --------------------------------------------------
rem set o=X:\openssl-0.9.6
set o=H:\b\openssl-0.9.6a

set mitk4=""
rem --------------------------------------------------
rem To use MIT Kerberos4, uncomment the line below
rem --------------------------------------------------
rem set mitk4="--mitk4dir=C:\Kerberos\V5\kfw-2.1"

set mitk5=""
rem --------------------------------------------------
rem To use MIT Kerberos5, uncomment the line below
rem --------------------------------------------------
rem set mitk5="--mitk5dir=C:\Kerberos\V5\kfw-2.1"
rem set mitk5="--mitk5dir=C:\Project\kfw-2.5"
set mitk5="--mitk5dir=C:\Program Files\MIT\Kerberos"

set withmsk5=""
rem --------------------------------------------------
rem To use Microsoft Kerberos5, uncomment the line below
rem --------------------------------------------------
rem set withmsk5="--withmsk5"

perl ..\src\configure.win32 --kx509proj=%p% --kx509dir=%b% --openssldir=%o% %mitk5% %mitk4% %withmsk5%

cd ..
