#ifndef CPAGENT_OUTPUT_GRE_H
#define CPAGENT_OUTPUT_GRE_H

#include <stdint.h>

#include "output.h"
#include "taskconf.h"

typedef struct GreOutput
{
} gre_output_t;

output_base_t *new_gre_output_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);

#endif /* CPAGENT_OUTPUT_GRE_H */