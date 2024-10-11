#ifndef _UTILS_H
#define _UTILS_H

extern char *get_absolute_path(const char *filename);
extern char *get_dir_parent(char *path);
extern char* get_cwd(void);
extern int temp_file(char *name);

#endif
