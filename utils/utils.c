#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>    // Per kmalloc e kfree

#include "constants.h"
#include "../reference_monitor.h"
#include "utils.h"
#include "../probes/probes.h"

/**
 * get_absolute_path - Ottiene il percorso assoluto di un file
 * @filename: il percorso del file passato come stringa
 *
 * Ritorna il percorso assoluto come stringa o NULL in caso di errore.
 * La memoria allocata per il risultato deve essere liberata con kfree() dal chiamante.
 */
char *get_absolute_path(const char *filename)
{
	struct path path;
	char *absolute_path;
	char *tmp;
	int err;


	if (!filename){
		printk(KERN_ERR "empty filename passato\n");
		return NULL;
	}

	// Risolvi il percorso del file passato come stringa
	err = kern_path(filename, LOOKUP_FOLLOW, &path);
	if (err){
		printk(KERN_ERR "errore in kern_path %int\n", err);
		return NULL;
	}

	// Allocazione temporanea per il percorso
	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		printk(KERN_ERR "%s: errore nell'allocazione della memoria per tmp\n", MOD_NAME);
		return NULL;
	}
	
	memset(tmp, 0, PATH_MAX);

	// Ottieni il percorso assoluto
	absolute_path = d_path(&path, tmp, PATH_MAX);

	if (IS_ERR(absolute_path)) {
 		printk(KERN_ERR "%s: Errore d_path: %ld\n", MOD_NAME, PTR_ERR(absolute_path));
		kfree(tmp);  // Libera la memoria in caso di errore
		return NULL;
	}

	printk(KERN_INFO "%s: path: %s", MOD_NAME, absolute_path);
	return absolute_path;  // Ritorna il percorso assoluto
}

/*Ottiene, dato un path, il percorso padre*/
char *get_dir_parent(char *path) {
    static char parent[PATH_MAX];
    int len;
    int i;
    len = strlen(path);

    // Copia il percorso originale in parent
    strncpy(parent, path, PATH_MAX);
    // Cerca l'ultimo slash nel percorso
    for (i= len - 1; i >= 0; i--) {
        if (parent[i] == '/') {
            // Termina la stringa dopo l'ultimo slash per ottenere la directory padre
            parent[i] = '\0';
            break;
        }
    }
    return parent;
}

// Funzione per ottenere la directory corrente
char* get_cwd(void) {
    struct path pwd;    
    char *cwd;
    char *buf;

    // Alloca un buffer per il percorso
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "%s: Errore: impossibile allocare memoria\n", MOD_NAME);
        return NULL; // Restituisce NULL in caso di errore
    }

    // Ottiene il percorso della directory di lavoro corrente
    get_fs_pwd(current->fs, &pwd);

    // Ottieni il percorso della directory corrente
    cwd = d_path(&pwd, buf, PATH_MAX);
    if (IS_ERR(cwd)) {
        printk(KERN_ERR "%s: Errore: impossibile ottenere la directory corrente %ld\n", MOD_NAME, PTR_ERR(cwd));
        kfree(buf); // Libera il buffer in caso di errore
        return NULL;
    }

    return cwd; // Restituisce il percorso della directory corrente
}

int temp_file(char *str){
	size_t len = strlen(str);
    
    // Verifica se la lunghezza della stringa è maggiore di 0 e se l'ultimo carattere è '~'
    if ((len > 0 && str[len - 1] == '~') ||
    // se è maggiore di 4 e termina con '.swp'
     (len >4 &&	(str[len - 1]=='p' &&  str[len - 2]=='w' &&str[len - 3]=='s' &&str[len - 4]=='.'))||
     //maggiore di 5 e termina con '.spwx'
    	(len >5 && str[len - 1]=='x' && str[len - 2]=='p' && str[len - 3]=='w' &&str[len - 4]=='s' &&str[len - 6]=='.')) {
        return 1; // file temporaneo
    }
    
    return 0; // non file temporaneo
}

void change_rm_state(rm_state state){
    rm_state current_state;
    
    printk("%s: changing reference monitor state\n", MOD_NAME);

	spin_lock(&RM_lock);	
	
	current_state=config.rm_state;

    printk("%s: initial state is %d\n", MOD_NAME, current_state);

    if((current_state==OFF || current_state==REC_OFF) && (state==ON || state==REC_ON)){

        enable_probes();

    }else if ((current_state==ON || current_state==REC_ON) && (state==OFF || state==REC_OFF)){

        disable_probes();

    }

    config.rm_state=state;

    printk("%s: new state is %d\n", MOD_NAME, config.rm_state);
    spin_unlock(&RM_lock);

    return;
}

int rm_on(void){

    change_rm_state(ON);

    return 0;
}

int rm_off(void){

    change_rm_state(OFF);

    return 0;
}

int rm_rec_on(void){

    change_rm_state(REC_ON);

    return 0;
}

int rm_rec_off(void){

    change_rm_state(REC_OFF);

    return 0;
}
