#include <Windows.h>
#include <wincrypt.h>
#include <iostream>

#pragma comment(lib, "crypt32.lib")

std::string CalculateFileHash(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open file: " << filePath.c_str() << "\n";
        return "";
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]; // SHA256 is 32 bytes
    DWORD hashLen = 32;
    std::string hashStr;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE buffer[4096];
            DWORD bytesRead;

            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }

            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                char hex[65] = { 0 };
                for (DWORD i = 0; i < hashLen; i++) {
                    sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
                }
                hashStr = hex;
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }

    CloseHandle(hFile);
    return hashStr;
}

int main() {
    std::wstring filePath = L"C:\\Projects\\CheckerDLL\\x64\\Debug\\CheckerDLL.dll";

    std::string hash = CalculateFileHash(filePath);
    if (!hash.empty()) {
        std::cout << "[+] SHA256 Hash: " << hash << std::endl;
    }
    else {
        std::cerr << "[!] Failed to calculate hash.\n";
    }

    return 0;
}

