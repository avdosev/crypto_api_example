#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstdio>
#include <memory>
#include <span>
#include <string_view>

#include "crypto_provider.h"


const std::string_view suffix = ".crypt";

std::string add_crypto_suffix(std::string path) {
    path += suffix;
    return path;
}

int encrypt_file(std::string, std::string);
int decrypt_file(std::string, std::string);

int main(int argc, char* argv[]) {
    std::cout << "Encrypt? (0 or 1):" << std::endl;
    bool encrypt = false;
//    bool encrypt = true;
//    std::cin >> encrypt;
    std::string in_filename = "test.txt";
    int res;
    if (encrypt) {
        std::string out_filename = add_crypto_suffix(in_filename);
        res = encrypt_file(in_filename, out_filename);
    } else {
        std::string out_filename = add_crypto_suffix(in_filename);
        res = decrypt_file(out_filename, in_filename+".out");
    }

    if (res == 0) {
        std::cout << "Successful!" << std::endl;
    }

    return res;
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
    auto s = raw_key.size();
    writeFile.write((char*)(&s), sizeof(s));
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
    fp.read((char*)(&key_size), sizeof(key_size));
    file_size -= sizeof(key_size);

    CryptoProvider::key_type key(key_size);
    fp.read(reinterpret_cast<char *>(key.data()), key_size);
    file_size -= key_size;

    if (crypto_provider.import_key(key)) {
        printf("Key imported\n");
    } else {
        printf("Key not imported\n");
        return -1;
    }

    std::vector<BYTE> raw_file(file_size);
    fp.read(reinterpret_cast<char *>(raw_file.data()), file_size);

    auto crypted_file = crypto_provider.decrypt_data(std::move(raw_file));
    if (crypted_file.has_value()) {
        printf("Data decrypted\n");
        raw_file = std::move(crypted_file.value());
    } else {
        printf("Data not decrypted\n");
        return -1;
    }

    std::ofstream writeFile(dest, std::ios_base::binary);
    if (!writeFile.is_open()) {
        printf("Write file not open\n");
        return -1;
    }

    writeFile.write(reinterpret_cast<char *>(raw_file.data()), raw_file.size());

    return 0;
}
