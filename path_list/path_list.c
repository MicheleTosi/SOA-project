#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>

#include "path_list.h"
#include "../reference_monitor.h"

struct mutex path_mutex;

int check_list(char *abs_path) {
    path_node *curr;
    
    // Scorro la lista di percorsi bloccati per vedere se è presente il path passato in input	
    list_for_each_entry(curr, &config.head, list) {
        if (strcmp(curr->path, abs_path) == 0) {
            printk(KERN_INFO "Path already exists: %s\n", abs_path);
            return 1; // Path trovato
        }
    }
    
    return 0; // Path non trovato
}

int add_path(char *path) {
    path_info info;
    path_node *new_node;
    
    if (config.rm_state != REC_ON && config.rm_state != REC_OFF) {
        printk(KERN_ERR "%s: state must be REC_ON or REC_OFF\n", MOD_NAME);
        return -EINVAL;
    }
    
    info = get_absolute_path(path); // Convert path to absolute path
    
    if (info.absolute_path == NULL) {
        printk(KERN_ERR "%s: could not resolve absolute path\n", MOD_NAME);
        return -EINVAL;
    }
    
    if (the_file && strncmp(info.absolute_path, the_file, strlen(the_file)) == 0) {
        printk(KERN_ERR "Error: cannot protect the log file path\n");
        kfree(info.tmp);
        return -EINVAL;
    }
    
    mutex_lock(&path_mutex);
    
    if (check_list(info.absolute_path)) {
        printk("%s: path already exists\n", MOD_NAME);
        kfree(info.tmp);
        mutex_unlock(&path_mutex);
        return -EINVAL;
    }
    
    // Creation of the new node
    new_node = kmalloc(sizeof(path_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Failed to allocate memory for new node\n");
        kfree(info.tmp);
        mutex_unlock(&path_mutex);
        return -ENOMEM;
    }
    
    new_node->path = kmalloc(strlen(info.absolute_path) + 1, GFP_KERNEL);
    if (!new_node->path) {
        printk(KERN_ERR "Failed to allocate memory for new_node->path\n");
        kfree(new_node);
        kfree(info.tmp);
        mutex_unlock(&path_mutex);
        return -ENOMEM;
    }
    strlcpy(new_node->path, info.absolute_path, strlen(info.absolute_path) + 1);
    
    printk(KERN_INFO "%s: aggiunto il path: %s", MOD_NAME, info.absolute_path);
    
    // Aggiungi il nodo alla lista
    list_add_tail(&new_node->list, &config.head);
    
    kfree(info.tmp);
    mutex_unlock(&path_mutex);
    
    return 0;
}

int rm_path(char *path) {
    path_info info;
    path_node *curr, *tmp;

    if (config.rm_state != REC_ON && config.rm_state != REC_OFF) {
        printk(KERN_ERR "%s: state must be REC_ON or REC_OFF\n", MOD_NAME);
        return -EINVAL;
    }

    info = get_absolute_path(path); // Convert path to absolute path
    
    if (info.absolute_path == NULL) {
        printk(KERN_ERR "%s: could not resolve absolute path\n", MOD_NAME);
        return -EINVAL;
    }
    
    mutex_lock(&path_mutex);
    
    // Scorro la lista di percorsi bloccati per vedere se è presente il path passato in input	
    list_for_each_entry_safe(curr, tmp, &config.head, list) {
        if (strcmp(curr->path, info.absolute_path) == 0) {
            // Rimuovi il nodo dalla lista
            list_del(&curr->list);
            kfree(curr->path); // Libera la memoria allocata per il path
            kfree(curr);       // Libera la memoria del nodo
            kfree(info.tmp);   // Libera eventuali risorse temporanee
            mutex_unlock(&path_mutex);
            return 0; // Nodo rimosso
        }
    }

    kfree(info.tmp); // Libera eventuali risorse temporanee
    mutex_unlock(&path_mutex);
    
    return 0; // Nodo non trovato, quindi niente da rimuovere
}

void cleanup_list(void) {
    path_node *curr, *tmp;

    // Itera su ogni nodo della lista e rimuovilo
    list_for_each_entry_safe(curr, tmp, &config.head, list) {
        // Rimuove il nodo dalla lista
        list_del(&curr->list);

        // Libera la memoria allocata per il path
        kfree(curr->path);

        // Libera la memoria allocata per il nodo stesso
        kfree(curr);
    }
    
    return;
}
