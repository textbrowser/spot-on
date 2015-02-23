--------------------------------------------------------------------------------
Copyright (C) 2008 by CO-CONV, Corp., Kyoto, Japan.
Copyright (C) 2010 by Bruce Cran.

Developed by co-research between CO-CONV, Corp. and WIDE Project.
--------------------------------------------------------------------------------

Operating System:
 - Windows XP
 - Windows Vista
 - Windows 7


Install:
Double click SctpDrv-1.1.x.msi, which is a Windows Installer package for SctpDrv.
A kernel driver (sctpdrv.sys) and DLLs (sctpsp.dll and sctpmon.dll) are installed
into your system.
There is no need to reboot your system.

If you run SctpDrv on Vista or newer, a firewall rule will be added during installation
which allows all inbound SCTP traffic. This rule will be named "SCTP" in the Windows Firewall
control panel. If a rule is already present which handles SCTP (protocol 132) then no rule will
be added or modified during installation. Upon uninstall, no firewall reconfiguration is done.

If you're either running Windows XP or Windows 2003, or are using a 3rd-party firewall, you need to
allow SCTP (protocol 132) through the firewall. The Windows XP firewall doesn't support protocols
other than TCP and UDP so in order to use SCTP you must disable the firewall.

In order to use SctpDrv on a 64-bit version of Windows, you either need to disable driver signing
on every boot by pressing F8 and selecting "Disable Driver Signature Enforcement", or install the
SctpDrv test certificate and enable test signing.

To install the SctpDrv test certificate:

1. Click the Start menu and type "mmc" into the Run box.  The MMC snap-in should run and display an
   empty tree labelled "Console Root".
2. Select "File" -> "Add/Remove Snap-in...", select "Certificates" and click "Add".
3. In the dialog that appears, select "Computer account", press "Next" followed by "Finish".
   Press "OK" to dismiss the Add/Remove dialog box.
4. Expand the "Certificates (Local Computer)" node, then click on "Trusted Root Certification Authorities"
5. Click "Action" -> "All Tasks" -> "Import..."
6. Select C:\Program Files\SctpDrv\SctpDrv.pfx (you need to change the file type selector to be
   able to see the .pfx file).
7. In the next step, when prompted for the password, enter "Stream Control Transmission Protocol".
8. Continue accepting the defaults until told the import was successful.
9. Repeat steps 5 to 8 after clicking on the "Trusted Publishers" node.
10.Finally, enable test signing itself by running and elevated Command Prompt and running the command:
   bcdedit /set testsigning on

Uninstall:
You can uninstall SctpDrv via the "Add or Remove Programs" control panel applet on XP,
or through the "Programs and Features" control panel applet on Vista or newer.

Installed Files:
After the installation, the below files will be installed into your system.

--------------------------------------------------------------------------------
c:\Program Files\SctpDrv\
	\bin
		\echo_client.exe	Sample application
		\echo_server.exe	Sample application
		\iperf.exe		Performance measurement tool - not installed on XP
		\sctpsp.dll		SCTP API DLL and Winsock provider
		\sptpmon.dll		NetShell helper DLL
		\sctp.sys		SCTP kernel driver
	\inc
		\ws2sctp.h		SCTP header files
	\lib
		\sctpsp.lib		Import library for use of SCTP API
		\libsctpsp.a		Cygwin/MinGW import library for use of SCTP API
	\src
		\echo_client.c		One-to-one client sample
		\echo_server.c		One-to-one model server sample
		\echo_server2.c		One-to-many model server sample
--------------------------------------------------------------------------------


Use of SCTP:
In order to use all the capabilities of SCTP, you have to append the directory of ws2sctp.h
into the Include Path of your compiler and link sctpsp.lib into your application. If however
you just need to use SCTP as an alternative to TCP without using the new API or features, you
can just change IPPROTO_TCP to IPPROTO_SCTP and use the standard headers: Microsoft ships
Winsock with the IPPROTO_SCTP definition included.

In the case of Visual C++ compiler,
prompt>cl /D__Windows__ /I "c:\Program Files\SctpDrv\inc" echo_client.c \
	ws2_32.lib "c:\Program Files\SctpDrv\lib\sctpsp.lib"

Limitations and known bugs:
 - On XP, updating route information may be slow.

Development of SctpDrv:
You can access the SctpDrv source code under the modified BSD license.
	Main SctpDrv web page: http://www.bluestop.org/SctpDrv
	Subversion repository: https://svn.bluestop.org/svn/sctpDrv/
	Web interface to the repository: https://svn.bluestop.org/viewvc/repos/sctpDrv/
	Bug Tracker, Forums etc. are on the Sourceforce project page:
		http://www.sourceforge.net/projects/sctpdrv

If you encounter a trouble with SctpDrv, please contact Bruce Cran at sctpdrv@bluestop.org

--------------------------------------------------------------------------------


Happy SCTPing!
