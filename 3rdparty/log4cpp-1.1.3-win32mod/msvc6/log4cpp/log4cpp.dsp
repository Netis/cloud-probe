# Microsoft Developer Studio Project File - Name="log4cpp" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=log4cpp - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "log4cpp.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "log4cpp.mak" CFG="log4cpp - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "log4cpp - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "log4cpp - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "log4cpp - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
MTL=midl.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GR /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "LOG4CPP_HAS_DLL" /D "LOG4CPP_BUILD_DLL" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "log4cpp - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
MTL=midl.exe
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GR /GX /ZI /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "LOG4CPP_HAS_DLL" /D "LOG4CPP_BUILD_DLL" /FR /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"Debug\log4cppD.lib"

!ENDIF 

# Begin Target

# Name "log4cpp - Win32 Release"
# Name "log4cpp - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\src\AbortAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Appender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\AppenderSkeleton.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\BasicConfigurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\BasicLayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Category.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\CategoryStream.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Configurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\DummyThreads.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\FactoryParams.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\FileAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Filter.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\FixedContextCategory.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\HierarchyMaintainer.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\IdsaAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\LayoutAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Localtime.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\LoggingEvent.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\MSThreads.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\NDC.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\NTEventLogAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\OmniThreads.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\OstreamAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\PatternLayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\PortabilityImpl.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Priority.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Properties.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\PropertyConfigurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\PropertyConfiguratorImpl.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\PThreads.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\RemoteSyslogAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\DailyRollingFileAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\RollingFileAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\SimpleConfigurator.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\SimpleLayout.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\StringQueueAppender.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\StringUtil.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\TimeStamp.cpp
# End Source File
# Begin Source File

SOURCE=..\..\src\Win32DebugAppender.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hh;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\include\log4cpp\Appender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\AppenderSkeleton.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\BasicConfigurator.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\BasicLayout.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\threading\BoostThreads.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Category.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\CategoryStream.hh
# End Source File
# Begin Source File

SOURCE="..\..\include\log4cpp\config-win32.h"
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Configurator.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\ConfiguratorSkeleton.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\threading\DummyThreads.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Export.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\FileAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Filter.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\FixedContextCategory.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\HierarchyMaintainer.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\IdsaAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Layout.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\LayoutAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\LoggingEvent.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\threading\MSThreads.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\NDC.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\NTEventLogAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\threading\OmniThreads.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\OstreamAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\PatternLayout.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Portability.hh
# End Source File
# Begin Source File

SOURCE=..\src\PortabilityImpl.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Priority.hh
# End Source File
# Begin Source File

SOURCE=..\..\src\Properties.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\PropertyConfigurator.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\RemoteSyslogAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\RollingFileAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\DailyRollingFileAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\SimpleConfigurator.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\SimpleLayout.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\StringQueueAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\SyslogAppender.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\threading\Threading.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\TimeStamp.hh
# End Source File
# Begin Source File

SOURCE=..\..\include\log4cpp\Win32DebugAppender.hh
# End Source File
# End Group
# Begin Source File

SOURCE=..\NTEventLogCategories.mc

!IF  "$(CFG)" == "log4cpp - Win32 Release"

# Begin Custom Build
OutDir=.\Release
ProjDir=.
InputPath=..\NTEventLogCategories.mc
InputName=NTEventLogCategories

"$(OutDir)\NTEventLogAppender.dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	if not exist $(OutDir) md $(OutDir) 
	"$(MSDEVDIR)\..\..\VC98\Bin\mc.exe" -h $(OutDir) -r $(OutDir) $(projdir)\..\$(InputName).mc 
	"$(MSDEVDIR)\Bin\RC.exe" -r -fo $(OutDir)\$(InputName).res $(OutDir)\$(InputName).rc 
	"$(MSDEVDIR)\..\..\VC98\Bin\link.exe" /MACHINE:IX86 -dll -noentry -out:$(OutDir)\NTEventLogAppender.dll $(OutDir)\$(InputName).res 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "log4cpp - Win32 Debug"

# Begin Custom Build
OutDir=.\Debug
ProjDir=.
InputPath=..\NTEventLogCategories.mc
InputName=NTEventLogCategories

"$(OutDir)\NTEventLogAppender.dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	if not exist $(OutDir) md $(OutDir) 
	"$(MSDEVDIR)\..\..\VC98\Bin\mc.exe" -h $(OutDir) -r $(OutDir) $(projdir)\..\$(InputName).mc 
	"$(MSDEVDIR)\Bin\RC.exe" -r -fo $(OutDir)\$(InputName).res $(OutDir)\$(InputName).rc 
	"$(MSDEVDIR)\..\..\VC98\Bin\link.exe" /MACHINE:IX86 -dll -noentry -out:$(OutDir)\NTEventLogAppender.dll $(OutDir)\$(InputName).res 
	
# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
