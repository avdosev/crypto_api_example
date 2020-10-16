#ifndef CRYPTO_LAB2_CRYPTO_PROVIDER_H
#define CRYPTO_LAB2_CRYPTO_PROVIDER_H

#include <utility>
#include <vector>
#include <memory>
#include <optional>
#include "Windows.h"
#include "Wincrypt.h"

class CryptoProvider {
public:
    using key_type = std::vector<BYTE>;

    CryptoProvider() {}

    std::optional<key_type> export_key() {
        DWORD count = 0;

        // Получение размера массива, используемого для экспорта ключа
        if (!CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, nullptr, &count)) {
            printf("Export error\n");
            return std::nullopt;
        }

        // массив с экспортируемым ключом
        auto raw_key = std::vector<BYTE>(count);

        // Экспорт ключа шифрования
        if (!CryptExportKey(hKey, hPublicKey, SIMPLEBLOB, 0, raw_key.data(), &count)) {
            printf("Export error 2\n");
            return std::nullopt;
        }

        return raw_key;
    }

    bool import_key(key_type key) {
        return CryptImportKey(hCryptProv, key.data(), key.size(), hPublicKey, 0, &hKey);
    }

    std::optional<std::vector<BYTE>> decrypt_data(std::vector<BYTE> raw) {
        auto crypted_data = std::move(raw);
        DWORD dwDataLen = crypted_data.size();

        bool encrypted = CryptDecrypt(hKey, 0, TRUE, 0, crypted_data.data(), &dwDataLen);

        if (encrypted) {
            return crypted_data;
        } else {
            return std::nullopt;
        }
    }

    std::optional<std::vector<BYTE>> encrypt_data(std::vector<BYTE> raw) {
        auto crypted_data = std::move(raw);
        DWORD dwDataLen = crypted_data.size(), dwBuffLen = crypted_data.size();

        bool encrypted = CryptEncrypt(hKey, 0, TRUE, 0, crypted_data.data(), &dwDataLen, dwBuffLen);

        if (encrypted) {
            return crypted_data;
        } else {
            return std::nullopt;
        }
    }

    bool close() {
        if (closed) return true;
        closed = true;

        // По окончании работы все дескрипторы должны быть удалены.
        if (!CryptDestroyKey(hKey)) // удаление дескриптора ключа
        {
            printf("Error during CryptDestroyKey.\n");
            return false;
        }

        if (CryptReleaseContext(hCryptProv,0)) { // удаление дескриптора криптопровайдера
            printf("The handle has been released.\n");
        } else {
            printf("The handle could not be released.\n");
            return false;
        }

        return true;
    }

    bool init() {
        // Инициализация криптопровайдера, получение дескриптора криптопровайдера
        if(CryptAcquireContext(
                &hCryptProv, // дескриптор криптопровайдера
                UserName, // название ключевого контейнера
                nullptr, // используем криптопровайдер по-умолчанию (Microsoft)
                PROV_RSA_FULL, // тип провайдера
                0)) // значение флага (выставляется в 0, чтобы предоставить
            // возможность открывать существующий ключевой контейнер)
        {
            printf("A cryptographic context with the %s key container \n",
                   UserName);
            printf("has been acquired.\n\n");
        } else {
            // Возникла ошибка при инициализации криптопровайдера. Это может
            // означать, что ключевой контейнер не был открыт, либо не существует.
            // В этом случае функция получения дескриптора криптопровайдера может быть
            // вызвана повторно, с измененным значением флага, что позволит создать
            // новый ключевой контейнер.Коды ошибок определены в Winerror.h.
            if (GetLastError() == NTE_BAD_KEYSET) {
                if(CryptAcquireContext(
                        &hCryptProv,
                        UserName,
                        nullptr,
                        PROV_RSA_FULL,
                        CRYPT_NEWKEYSET)) {
                    printf("A new key container has been created.\n");
                } else {
                    printf("Could not create a new key container.\n");
                    return false;
                }
            } else {
                printf("A cryptographic service handle could not be "
                       "acquired.\n");
                return false;
            }
        }

        if(CryptGenKey(
                hCryptProv,
                CALG_RC4,
                CRYPT_EXPORTABLE | CRYPT_ENCRYPT,
                &hKey)) {
            printf("A session key has been created.\n");
        } else {
            printf("Error during CryptGenKey.\n");
            exit(1);
        }

        // Получение ключа для экспорта ключа шифрования
        if (CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hPublicKey)) {
            printf("Public key received\n\n", hPublicKey);
        } else {
            printf("Error during PublicKey\n\n");
            out_error(GetLastError());
            return 1;
        }

        closed = false;
    }

    ~CryptoProvider() {
        close();
    }

private:
    void out_error(DWORD err) {
#define CHECK(c) { if (err == c) printf(#c"\n"); }
        CHECK(ERROR_INVALID_HANDLE)
        CHECK(ERROR_INVALID_PARAMETER)
        CHECK(NTE_BAD_KEY)
        CHECK(NTE_BAD_UID)
        CHECK(NTE_NO_KEY)
#undef CHECK
    }

    bool closed = true;
    HCRYPTPROV hCryptProv = NULL; // дескриптор криптопровайдера
    LPCSTR UserName = "MyKeyContainer"; // название ключевого контейнера
    HCRYPTKEY hKey = 0; // дескриптор ключа
    HCRYPTKEY hPublicKey = 0, hNewKey = 0;
};

#endif //CRYPTO_LAB2_CRYPTO_PROVIDER_H
