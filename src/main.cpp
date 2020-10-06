#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <memory>

#include "crypto_provider.h"



const std::string_view suffix = ".crypt";

std::string add_crypto_suffix(std::string path) {
    path += suffix;
    return path;
}

int encrypt_file(std::string, std::string);
int decrypt_file(std::string, std::string);

int main(int argc, char* argv[]) {
    bool encrypt = false;
    std::string in_filename = "test.txt";

    if (encrypt) {
        std::string out_filename = add_crypto_suffix(in_filename);
        int res = encrypt_file(in_filename, out_filename);
        return res;
    } else {
        std::string out_filename = add_crypto_suffix(in_filename);
        int res = decrypt_file(out_filename, in_filename+".out");
        return res;
    }
}

int encrypt_file(std::string src, std::string dest) {
    CryptoProvider crypto_provider;
    crypto_provider.init();

    std::ifstream fp(src, std::ios_base::binary);
    auto file_size = std::filesystem::file_size(src);
    std::vector<BYTE> raw_file(file_size);
    fp.read(reinterpret_cast<char *>(raw_file.data()), file_size);

    auto crypted_file = crypto_provider.encrypt_data(std::move(raw_file));
    if (crypted_file.has_value()) {
        printf("Data encrypted\n");
        raw_file = std::move(crypted_file.value());
    } else {
        printf("Data not encrypted\n");
        return -1;
    }

    auto maybe_raw_key = crypto_provider.export_key();
    if (!maybe_raw_key.has_value())
        return -1;

    auto raw_key = std::move(maybe_raw_key.value());

    std::ofstream writeFile(dest, std::ios_base::binary);
    writeFile << raw_key.size();
    writeFile.write(reinterpret_cast<char *>(raw_key.data()), raw_key.size());
    writeFile.write(reinterpret_cast<char *>(raw_file.data()), raw_file.size());
    writeFile.close();

    return 0;
}

int decrypt_file(std::string src, std::string dest) {
    CryptoProvider crypto_provider;
    crypto_provider.init();

    std::ifstream fp(src, std::ios_base::binary);
    auto file_size = std::filesystem::file_size(src);
    CryptoProvider::key_type::size_type key_size;
    fp >> key_size;
    CryptoProvider::key_type key(key_size);
    fp.read(reinterpret_cast<char *>(key.data()), file_size);

    std::vector<BYTE> raw_file(file_size-sizeof(key_size)-sizeof(CryptoProvider::key_type::value_type)*key_size);
    fp.read(reinterpret_cast<char *>(raw_file.data()), file_size);

    auto crypted_file = crypto_provider.encrypt_data(std::move(raw_file));
    if (crypted_file.has_value()) {
        printf("Data decrypted\n");
        raw_file = std::move(crypted_file.value());
    } else {
        printf("Data not decrypted\n");
        return -1;
    }

    auto maybe_raw_key = crypto_provider.export_key();
    if (!maybe_raw_key.has_value())
        return -1;

    auto raw_key = std::move(maybe_raw_key.value());

    std::ofstream writeFile(dest, std::ios_base::binary);
    writeFile.write(reinterpret_cast<char *>(raw_file.data()), raw_file.size());
    writeFile.close();

    return 0;
}
