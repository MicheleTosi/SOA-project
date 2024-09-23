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

    if (!filename)
        return NULL;

    // Risolvi il percorso del file passato come stringa
    err = kern_path(filename, LOOKUP_FOLLOW, &path);
    if (err)
        return NULL;

    // Allocazione temporanea per il percorso
    absolute_path = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!absolute_path) {
        path_put(&path);  // Libera risorse se l'allocazione fallisce
        return NULL;
    }

    // Ottieni il percorso assoluto
    tmp = d_path(&path, absolute_path, PATH_MAX);
    path_put(&path);  // Libera risorse per il path

    if (IS_ERR(tmp)) {
        kfree(absolute_path);  // Libera la memoria in caso di errore
        return NULL;
    }

    // Calcola la lunghezza del percorso e rialloca la memoria alla giusta dimensione
    len = strlen(tmp) + 1;
    absolute_path = krealloc(absolute_path, len, GFP_KERNEL);
    if (!absolute_path)
        return NULL;  // In caso di errore nella riallocazione

    return absolute_path;  // Ritorna il percorso assoluto
}
