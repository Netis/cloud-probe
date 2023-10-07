lib_LTLIBRARIES = liblog4cpp.la

INCLUDES = -I$(top_srcdir)/include

noinst_HEADERS = snprintf.c Localtime.hh

liblog4cpp_la_SOURCES = \
	Appender.cpp \
	AppenderSkeleton.cpp \
	AppendersFactory.cpp \
	BufferingAppender.cpp \
	FactoryParams.cpp \
	LayoutsFactory.cpp \
	LevelEvaluator.cpp \
	Localtime.cpp	\
	PassThroughLayout.cpp \
	TriggeringEventEvaluatorFactory.cpp \
	LayoutAppender.cpp \
	FileAppender.cpp \
	DailyRollingFileAppender.cpp \
	RollingFileAppender.cpp \
	FixedContextCategory.cpp \
	IdsaAppender.cpp \
	OstreamAppender.cpp \
	StringQueueAppender.cpp \
	SyslogAppender.cpp \
	SimpleLayout.cpp \
	BasicLayout.cpp \
	PatternLayout.cpp \
	Category.cpp \
	CategoryStream.cpp \
	HierarchyMaintainer.cpp \
	Configurator.cpp \
	BasicConfigurator.cpp \
	SimpleConfigurator.cpp \
	PropertyConfigurator.cpp \
	PropertyConfiguratorImpl.hh \
	PropertyConfiguratorImpl.cpp \
	LoggingEvent.cpp \
	Priority.cpp \
	NDC.cpp \
	Filter.cpp \
	TimeStamp.cpp \
	StringUtil.hh \
	StringUtil.cpp \
	Properties.hh \
	Properties.cpp \
	Win32DebugAppender.cpp \
	NTEventLogAppender.cpp \
	DllMain.cpp \
	DummyThreads.cpp \
	MSThreads.cpp \
	OmniThreads.cpp \
	PThreads.cpp \
	PortabilityImpl.hh \
	PortabilityImpl.cpp \
	AbortAppender.cpp

if !DISABLE_REMOTE_SYSLOG
liblog4cpp_la_SOURCES += RemoteSyslogAppender.cpp
endif

if !DISABLE_SMTP
liblog4cpp_la_SOURCES += SmtpAppender.cpp
endif

liblog4cpp_la_LDFLAGS = -version-info @LT_VERSION@
