#ifndef _UTILS_H
#define _UTILS_H

extern char *get_absolute_path(const char *filename);
extern char *get_dir_parent(char *path);
extern char* get_cwd(void);
extern int temp_file(char *name);

int check_list(char *abs_path);

int rm_on(void);
int rm_off(void);
int rm_rec_on(void);
int rm_rec_off(void);

int set_password(char *);

/*Ottiene il percorso del file eseguibile del processo corrente
 see: https://stackoverflow.com/questions/18862057/get-the-absolute-path-of-current-running-program-in-kernel
      https://elixir.bootlin.com/linux/v5.0.21/source/fs/d_path.c#L256
 */

char *get_current_proc_path(void);

#endif
