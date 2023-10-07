# ---------------------------------------------------------------------------
!if !$d(BCB)
BCB = $(MAKEDIR)\..
!endif

# ---------------------------------------------------------------------------
# IDE SECTION
# ---------------------------------------------------------------------------
# The following section of the project makefile is managed by the BCB IDE.
# It is recommended to use the IDE to change any of the values in this
# section.
# ---------------------------------------------------------------------------

VERSION = BCB.05.03
# ---------------------------------------------------------------------------
PROJECT = log4cpp.dll
OBJFILES = \
    Appender.obj \
    AppenderSkeleton.obj \
    BasicConfigurator.obj \
    BasicLayout.obj \
    Category.obj \
    CategoryStream.obj \
    FileAppender.obj  \
    Filter.obj \
    FixedContextCategory.obj  \
    HierarchyMaintainer.obj \
    IdsaAppender.obj \
    LayoutAppender.obj  \
    LoggingEvent.obj \
    NDC.obj \
    OstreamAppender.obj  \
    PortabilityImpl.obj \
    PatternLayout.obj	 \
    Priority.obj \
    RemoteSyslogAppender.obj  \
    RollingFileAppender.obj  \
    Configurator.obj \
    ConfiguratorSkeleton.obj \
    SimpleConfigurator.obj \
    PropertyConfigurator.obj \
    SimpleLayout.obj \
    StringQueueAppender.obj \
    Win32DebugAppender.obj \
    SyslogAppender.obj \
    TimeStamp.obj \
    DummyThreads.obj \
    MSThreads.obj \
    OmniThreads.obj \
    PThreads.obj
RESFILES = 
MAINSOURCE = log4cpp.bpf
RESDEPEN = $(RESFILES)
LIBFILES = 
IDLFILES = 
IDLGENFILES = 
LIBRARIES = 
PACKAGES = Vcl50.bpi Vclx50.bpi bcbsmp50.bpi dclocx50.bpi bcb97axserver50.bpi \
    QRPT50.bpi VCLDB50.bpi VCLBDE50.bpi NMFast50.bpi
SPARELIBS = 
DEFFILE = 
# ---------------------------------------------------------------------------
PATHCPP = .;..\..\src
PATHASM = .;
PATHPAS = .;
PATHRC = .;
DEBUGLIBPATH = $(BCB)\lib\debug
RELEASELIBPATH = $(BCB)\lib\release
USERDEFINES = _DEBUG;LOG4CPP_HAS_DLL;LOG4CPP_BUILD_DLL
SYSDEFINES = NO_STRICT;_NO_VCL;_RTLDLL
INCLUDEPATH = ..\..\src;$(BCB)\include;..\..\include
LIBPATH = ..\..\src;$(BCB)\lib\obj;$(BCB)\lib
WARNINGS= -w-par
# ---------------------------------------------------------------------------
CFLAG1 = -WD -Od -Vx -Ve -X- -r- -a8 -b- -k -y -v -vi- -tWD -tWM -c
IDLCFLAGS = 
PFLAGS = -N2. -N0. -$YD -$W -$O- -v -JPHNE -M
RFLAGS = 
AFLAGS = /mx /w2 /zd
LFLAGS = -I. -D"" -aa -Tpd -x -Gn -Gi -v
# ---------------------------------------------------------------------------
ALLOBJ = c0d32.obj $(OBJFILES)
ALLRES = $(RESFILES)
ALLLIB = $(LIBFILES) $(LIBRARIES) import32.lib cw32mti.lib
# ---------------------------------------------------------------------------
!ifdef IDEOPTIONS

[Version Info]
IncludeVerInfo=0
AutoIncBuild=0
MajorVer=1
MinorVer=0
Release=0
Build=0
Debug=0
PreRelease=0
Special=0
Private=0
DLL=0

[Version Info Keys]
CompanyName=
FileDescription=
FileVersion=1.0.0.0
InternalName=
LegalCopyright=
LegalTrademarks=
OriginalFilename=
ProductName=
ProductVersion=1.0.0.0
Comments=

[Debugging]
DebugSourceDirs=$(BCB)\source\vcl

!endif





# ---------------------------------------------------------------------------
# MAKE SECTION
# ---------------------------------------------------------------------------
# This section of the project file is not used by the BCB IDE.  It is for
# the benefit of building from the command-line using the MAKE utility.
# ---------------------------------------------------------------------------

.autodepend
# ---------------------------------------------------------------------------
!if "$(USERDEFINES)" != ""
AUSERDEFINES = -d$(USERDEFINES:;= -d)
!else
AUSERDEFINES =
!endif

!if !$d(BCC32)
BCC32 = bcc32
!endif

!if !$d(CPP32)
CPP32 = cpp32
!endif

!if !$d(DCC32)
DCC32 = dcc32
!endif

!if !$d(TASM32)
TASM32 = tasm32
!endif

!if !$d(LINKER)
LINKER = ilink32
!endif

!if !$d(BRCC32)
BRCC32 = brcc32
!endif


# ---------------------------------------------------------------------------
!if $d(PATHCPP)
.PATH.CPP = $(PATHCPP)
.PATH.C   = $(PATHCPP)
!endif

!if $d(PATHPAS)
.PATH.PAS = $(PATHPAS)
!endif

!if $d(PATHASM)
.PATH.ASM = $(PATHASM)
!endif

!if $d(PATHRC)
.PATH.RC  = $(PATHRC)
!endif
# ---------------------------------------------------------------------------
$(PROJECT): $(IDLGENFILES) $(OBJFILES) $(RESDEPEN) $(DEFFILE)
    $(BCB)\BIN\$(LINKER) @&&!
    $(LFLAGS) -L$(LIBPATH) +
    $(ALLOBJ), +
    $(PROJECT),, +
    $(ALLLIB), +
    $(DEFFILE), +
    $(ALLRES)
!
# ---------------------------------------------------------------------------
.pas.hpp:
    $(BCB)\BIN\$(DCC32) $(PFLAGS) -U$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -O$(INCLUDEPATH) --BCB {$< }

.pas.obj:
    $(BCB)\BIN\$(DCC32) $(PFLAGS) -U$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -O$(INCLUDEPATH) --BCB {$< }

.cpp.obj:
    $(BCB)\BIN\$(BCC32) $(CFLAG1) $(WARNINGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -n$(@D) {$< }

.c.obj:
    $(BCB)\BIN\$(BCC32) $(CFLAG1) $(WARNINGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -n$(@D) {$< }

.c.i:
    $(BCB)\BIN\$(CPP32) $(CFLAG1) $(WARNINGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -n. {$< }

.cpp.i:
    $(BCB)\BIN\$(CPP32) $(CFLAG1) $(WARNINGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -n. {$< }

.asm.obj:
    $(BCB)\BIN\$(TASM32) $(AFLAGS) -i$(INCLUDEPATH:;= -i) $(AUSERDEFINES) -d$(SYSDEFINES:;= -d) $<, $@

.rc.res:
    $(BCB)\BIN\$(BRCC32) $(RFLAGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -fo$@ $<
# ---------------------------------------------------------------------------




