#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <limits>
#include <windows.h>
#include <wincrypt.h>
#include <commdlg.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")

#ifndef CALG_SHA256
#define CALG_SHA256 0x0000800c
#endif

// Прототипы функций
std::string ComputeSHA256(const std::string& filePath);
std::string OpenFileDialog();
void ShowMenu();
void ProcessFile(const std::string& filePath);
void CopyToClipboard(const std::string& text);
void ClearInputBuffer();
void WaitForEnter();
std::string CleanFilePath(std::string filePath);

int main() {
    int choice = 0;
    std::string filePath;

    while (true) {
        ShowMenu();
        std::cin >> choice;
        ClearInputBuffer();

        switch (choice) {
        case 1: {
            std::cout << "Opening file dialog... Please select a file." << std::endl;
            filePath = OpenFileDialog();

            if (filePath.empty()) {
                std::cout << "File selection cancelled." << std::endl;
                break;
            }

            std::cout << "Selected file: " << filePath << std::endl;
            ProcessFile(filePath);
            break;
        }

        case 2: {
            std::cout << "Enter file path: ";
            std::getline(std::cin, filePath);

            if (filePath.empty()) {
                std::cout << "No file path entered." << std::endl;
                break;
            }

            filePath = CleanFilePath(filePath);
            ProcessFile(filePath);
            break;
        }

        case 3:
            std::cout << "Goodbye!" << std::endl;
            return 0;

        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
            break;
        }

        if (choice != 3) {
            WaitForEnter();
        }
    }

    return 0;
}

std::string ComputeSHA256(const std::string& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE buffer[4096];
    DWORD bytesRead = 0;
    std::stringstream ss;

    // Acquire cryptographic context
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed. Error: " << GetLastError() << std::endl;
        return "";
    }

    // Create hash object
    if (!CryptCreateHash(hProv, CALG_SHA256, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed. Error: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Open and read file
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file: " << filePath << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Process file content
    while (file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) {
        bytesRead = static_cast<DWORD>(file.gcount());
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            std::cerr << "CryptHashData failed. Error: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    // Process remaining data
    bytesRead = static_cast<DWORD>(file.gcount());
    if (bytesRead > 0 && !CryptHashData(hHash, buffer, bytesRead, 0)) {
        std::cerr << "CryptHashData failed for last block. Error: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Get hash size
    DWORD hashSize = 0;
    DWORD hashSizeLen = sizeof(hashSize);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashSize), &hashSizeLen, 0)) {
        std::cerr << "CryptGetHashParam failed. Error: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Get hash value
    std::vector<BYTE> hashBytes(hashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0)) {
        std::cerr << "CryptGetHashParam failed. Error: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Convert hash to hex string
    for (BYTE b : hashBytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return ss.str();
}

std::string OpenFileDialog() {
    OPENFILENAMEA ofn;
    char szFile[MAX_PATH] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    return (GetOpenFileNameA(&ofn) == TRUE) ? ofn.lpstrFile : "";
}

void ShowMenu() {
    std::cout << "\n====================================" << std::endl;
    std::cout << "    FILE INTEGRITY CHECKER" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << "1. Select file using file dialog" << std::endl;
    std::cout << "2. Enter file path manually" << std::endl;
    std::cout << "3. Exit" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << "Choose an option (1-3): ";
}

void ProcessFile(const std::string& filePath) {
    std::cout << "Computing SHA-256 hash..." << std::endl;

    std::string hash = ComputeSHA256(filePath);

    if (!hash.empty()) {
        std::cout << "\n====================================" << std::endl;
        std::cout << "FILE: " << filePath << std::endl;
        std::cout << "SHA-256: " << hash << std::endl;
        std::cout << "====================================" << std::endl;

        CopyToClipboard(hash);
    }
    else {
        std::cerr << "Failed to compute hash." << std::endl;
    }
}

void CopyToClipboard(const std::string& text) {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hGlob) {
            char* pGlob = static_cast<char*>(GlobalLock(hGlob));
            if (pGlob) {
                strcpy_s(pGlob, text.size() + 1, text.c_str());
                GlobalUnlock(hGlob);
                SetClipboardData(CF_TEXT, hGlob);
                std::cout << "Hash copied to clipboard!" << std::endl;
            }
        }
        CloseClipboard();
    }
}

void ClearInputBuffer() {
    std::cin.clear();
    // Просто игнорируем до 1000 символов или до новой строки
    std::cin.ignore(1000, '\n');
}

void WaitForEnter() {
    std::cout << "\nPress Enter to continue...";
    ClearInputBuffer();
}

std::string CleanFilePath(std::string filePath) {
    // Remove surrounding quotes if present
    if (filePath.size() >= 2 && filePath.front() == '"' && filePath.back() == '"') {
        return filePath.substr(1, filePath.size() - 2);
    }
    return filePath;
}