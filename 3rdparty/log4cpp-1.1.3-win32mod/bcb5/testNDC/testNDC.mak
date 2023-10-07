!if !$d(BCB)
BCB = $(MAKEDIR)\..
!endif

PROJECT = testNDC.exe
OBJFILES = testNDC.obj
LIBFILES = ..\log4cpp\log4cpp.lib
# ---------------------------------------------------------------------------
PATHCPP = .;..\..\tests
USERDEFINES = _DEBUG;LOG4CPP_HAS_DLL
SYSDEFINES = NO_STRICT;_NO_VCL;_RTLDLL
INCLUDEPATH = ..\..\tests;$(BCB)\include;..\..\include
LIBPATH = ..\..\tests;$(BCB)\lib\obj;$(BCB)\lib
WARNINGS= -w-par
# ---------------------------------------------------------------------------
CFLAG1 = -Od -Vx -Ve -X- -r- -a8 -b- -k -y -v -vi- -tWC -tWM -c
LFLAGS = -I. -D"" -ap -Tpe -x -Gn -v
# ---------------------------------------------------------------------------
ALLOBJ = c0x32.obj $(OBJFILES)
ALLRES = $(RESFILES)
ALLLIB = $(LIBFILES) $(LIBRARIES) import32.lib cw32mti.lib
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

!if !$d(LINKER)
LINKER = ilink32
!endif

# ---------------------------------------------------------------------------
!if $d(PATHCPP)
.PATH.CPP = $(PATHCPP)
.PATH.C   = $(PATHCPP)
!endif

$(PROJECT): $(OBJFILES)
    $(BCB)\BIN\$(LINKER) @&&!
    $(LFLAGS) -L$(LIBPATH) +
    $(ALLOBJ), +
    $(PROJECT),, +
    $(ALLLIB), +
    , +
    $(ALLRES)
!

.cpp.obj:
    $(BCB)\BIN\$(BCC32) $(CFLAG1) $(WARNINGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -n$(@D) {$< }

.c.obj:
    $(BCB)\BIN\$(BCC32) $(CFLAG1) $(WARNINGS) -I$(INCLUDEPATH) -D$(USERDEFINES);$(SYSDEFINES) -n$(@D) {$< }

