#include <crypto/hash.h>

#include "sha256.h"
#include "../utils/constants.h"

int calculate_sha256(const char *password, size_t password_len, u8 *hashed_password) {
    struct crypto_shash *tfm;
    struct shash_desc *shash;
    int ret;

    // Alloca la trasformazione hash SHA-256
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Errore nell'allocazione della trasformazione hash SHA-256\n");
        return PTR_ERR(tfm);
    }

    // Alloca la struttura shash_desc
    shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!shash) {
        pr_err("Errore nell'allocazione della struttura shash_desc\n");
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    shash->tfm = tfm;

    // Calcola l'hash SHA-256 della password
    ret = crypto_shash_digest(shash, password, password_len, hashed_password);
    if (ret) {
        pr_err("Errore nel calcolo dell'hash della password\n");
    }

    // Libera le risorse
    kfree(shash);
    crypto_free_shash(tfm);

    return ret;
}

// Funzione per verificare la password fornita dall'utente
int verify_password(const char *input_password, size_t input_password_len, const u8 *stored_hash) {
    u8 input_hash[PASSWORD_HASH_SIZE];
    
    // Hash della password fornita dall'utente
    if (calculate_sha256(input_password, input_password_len, input_hash) == 0) {
        // Confronta l'hash calcolato con l'hash memorizzato
        if (memcmp(input_hash, stored_hash, PASSWORD_HASH_SIZE) == 0) {
            pr_info("Password corretta\n");
            return 1;  // Password verificata correttamente
        } else {
            pr_info("Password errata\n");
            return 0;  // La password non corrisponde
        }
    } else {
        pr_err("Errore nell'hashing della password\n");
        return 0;
    }
}

// Stampa l'hash per verifica (solo a scopo dimostrativo)
void print_hash(const u8 *password){
    int i;
    
    pr_info("Password hash: ");
    for (i = 0; i < SHA256_LENGTH; i++) {
        pr_cont("%02x", password[i] & 0xff);
    }
    pr_cont("\n");
}
