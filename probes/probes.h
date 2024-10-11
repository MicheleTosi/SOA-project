#ifndef PROBES_H
#define PROBES_H

#include <linux/kprobes.h>

int register_probes(void);

void unregister_probes(void);

void enable_probes(void);

void disable_probes(void);

#endif
