#include <log4cpp/Category.hh>

LOG4CPP_LOGGER("c_test");
LOG4CPP_LOGGER_N(named_logger, "n_logger");

int main()
{
   LOG4CPP_EMERG(logger, "emerg");
   LOG4CPP_FATAL(logger, "fatal");
   LOG4CPP_ALERT(logger, "alert");
   LOG4CPP_CRIT(logger, "crit");
   LOG4CPP_ERROR(logger, "error");
   LOG4CPP_WARN(logger, "warn");
   LOG4CPP_NOTICE(logger, "notice");
   LOG4CPP_INFO(logger, "info");
   LOG4CPP_DEBUG(logger, "debug");

   LOG4CPP_INFO(named_logger, "this is named logger");

   LOG4CPP_EMERG_S(logger)  << "emerg";
   LOG4CPP_FATAL_S(logger)  << "fatal";
   LOG4CPP_ALERT_S(logger)  << "alert";
   LOG4CPP_CRIT_S(logger)   << "crit";
   LOG4CPP_ERROR_S(logger)  << "error";
   LOG4CPP_WARN_S(logger)   << "warn";
   LOG4CPP_NOTICE_S(logger) << "notice";
   LOG4CPP_INFO_S(logger)   << "info";
   LOG4CPP_DEBUG_S(logger)  << "debug";


   LOG4CPP_EMERG_SD()  << "emerg";
   LOG4CPP_FATAL_SD()  << "fatal";
   LOG4CPP_ALERT_SD()  << "alert";
   LOG4CPP_CRIT_SD()   << "crit";
   LOG4CPP_ERROR_SD()  << "error";
   LOG4CPP_WARN_SD()   << "warn";
   LOG4CPP_NOTICE_SD() << "notice";
   LOG4CPP_INFO_SD()   << "info";
   LOG4CPP_DEBUG_SD()  << "debug";

   return 0;
}