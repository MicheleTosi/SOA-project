#ifndef _SHA256_H
#define _SHA256_H

int calculate_sha256(const char *password, size_t password_len, u8 *hashed_password);

int calculate_sha256_file_content(struct file *filp, u8 *hash);

int verify_password(const char *input_password);

void print_hash(const u8 *password);

char *u8_to_string(const u8 *input);

#endif // SHA256_H
