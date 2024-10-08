#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>    // Per kmalloc e kfree

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
	int len;
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
	tmp = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		printk(KERN_ERR "errore nell'allocazione della memoria per tmp\n");
		path_put(&path);  // Libera risorse se l'allocazione fallisce
		return NULL;
	}

	// Ottieni il percorso assoluto
	absolute_path = d_path(&path, tmp, PATH_MAX);
	path_put(&path);  // Libera risorse per il path

	if (IS_ERR(absolute_path)) {
 		printk(KERN_ERR "errore d_path\n");
		kfree(tmp);  // Libera la memoria in caso di errore
		return NULL;
	}

	printk(KERN_INFO "path: %s", absolute_path);
    
	return absolute_path;  // Ritorna il percorso assoluto
}
