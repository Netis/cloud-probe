/*
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#include <log4cpp/LevelEvaluator.hh>
#include <log4cpp/FactoryParams.hh>
#include <memory>

namespace log4cpp
{
   std::auto_ptr<TriggeringEventEvaluator> create_level_evaluator(const FactoryParams& params)
   {
      std::string level;
      params.get_for("level evaluator").required("level", level);

      return std::auto_ptr<TriggeringEventEvaluator>(new LevelEvaluator(Priority::getPriorityValue(level)));
   }
}

