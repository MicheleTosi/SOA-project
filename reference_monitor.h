#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#include <linux/list.h>

#include "utils/constants.h"
#include "crypto/sha256.h"
#include "utils/utils.h"
#include "probes/probes.h"
#include "path_list/path_list.h"

//nodi path bloccati
typedef struct path_node{
	char *path;
	struct list_head list;
}path_node;

// Definizione di una struttura per path_info
typedef struct path_info {
    char *absolute_path;
    char *tmp;
}path_info;

// Enumerazione per gli stati del reference monitor
typedef enum reference_monitor_state {
    ON,             // Operazioni abilitate
    OFF,            // Operazioni disabilitate
    REC_ON,         // Può essere riconfigurato in modalita' ON
    REC_OFF,        // Può essere riconfigurato in modalita' OFF
}rm_state;

// Configurazione attuale reference monitor
typedef struct reference_monitor_config {
    rm_state rm_state;                      // Stato corrente reference monitor
    u8 password[HASH_SIZE];		// Password per riconfigurare il reference monitor
    struct list_head head;
    //path_node *head;     					// Lista path non accessibili in scrittura
} rm_config;

extern rm_config config;

extern char *the_file;

//extern char *module_name;

extern spinlock_t RM_lock;

#endif
