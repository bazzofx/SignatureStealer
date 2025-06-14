#include "steal.h"
#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstddef>

static inline uint64_t align8(uint64_t x) {
    return (x + 7) & ~7ULL;
}

bool copy_signature(const std::string& src_path, const std::string& dst_path) {
    std::ifstream src(src_path, std::ios::binary);
    if (!src) {
        std::cerr << "Failed to open source file: " << src_path << "\n";
        return false;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dos = {};
    src.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature in source file.\n";
        return false;
    }

    // Read NT Headers
    src.seekg(dos.e_lfanew, std::ios::beg);
    DWORD nt_sig = 0;
    src.read(reinterpret_cast<char*>(&nt_sig), sizeof(nt_sig));
    if (nt_sig != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT signature in source file.\n";
        return false;
    }

    IMAGE_FILE_HEADER fileHeader = {};
    src.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    IMAGE_OPTIONAL_HEADER64 optionalHeader = {};
    src.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

    if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "Unsupported (non-64-bit) PE file.\n";
        return false;
    }

    IMAGE_DATA_DIRECTORY certDir = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (certDir.VirtualAddress == 0 || certDir.Size == 0) {
        std::cerr << "No digital signature found in source file.\n";
        return false;
    }

    // Read certificate blob (located at a file offset, not RVA)
    std::vector<char> certBlob(certDir.Size);
    src.seekg(certDir.VirtualAddress, std::ios::beg);
    src.read(certBlob.data(), certDir.Size);
    if (!src) {
        std::cerr << "Failed to read certificate data.\n";
        return false;
    }
    src.close();

    // Open destination file for update
    std::fstream dst(dst_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!dst) {
        std::cerr << "Failed to open destination file: " << dst_path << "\n";
        return false;
    }

    // Read and validate destination headers
    dst.seekg(0, std::ios::beg);
    dst.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS signature in destination file.\n";
        return false;
    }

    dst.seekg(dos.e_lfanew, std::ios::beg);
    dst.read(reinterpret_cast<char*>(&nt_sig), sizeof(nt_sig));
    if (nt_sig != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT signature in destination file.\n";
        return false;
    }

    dst.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
    dst.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));

    // Align to 8-byte boundary at EOF
    dst.seekg(0, std::ios::end);
    uint64_t eof = dst.tellg();
    uint64_t writeOffset = align8(eof);

    if (writeOffset > eof) {
        std::vector<char> padding(writeOffset - eof, 0);
        dst.write(padding.data(), padding.size());
    }

    dst.seekp(writeOffset, std::ios::beg);
    dst.write(certBlob.data(), certBlob.size());
    if (!dst) {
        std::cerr << "Failed to write certificate data to destination.\n";
        return false;
    }

    // Update the IMAGE_DIRECTORY_ENTRY_SECURITY in destination PE headers
    uint32_t ddBase = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    uint32_t dd4 = ddBase + IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY);
    uint32_t va = static_cast<uint32_t>(writeOffset);
    uint32_t sz = static_cast<uint32_t>(certBlob.size());

    dst.seekp(dd4, std::ios::beg);
    dst.write(reinterpret_cast<char*>(&va), sizeof(va));
    dst.write(reinterpret_cast<char*>(&sz), sizeof(sz));

    dst.close();

    std::cout << "Signature successfully copied from \"" << src_path << "\" to \"" << dst_path << "\"\n";
    return true;
}

// Copy VERSIONINFO resource from src to dst
bool copy_version_resource(const std::wstring& src_path, const std::wstring& dst_path) {
    // Load source DLL as datafile
    HMODULE hSrc = LoadLibraryExW(src_path.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!hSrc) {
        std::wcerr << L"Failed to load source DLL: " << src_path << L"\n";
        return false;
    }

    HRSRC hRes = FindResourceW(hSrc, MAKEINTRESOURCEW(VS_VERSION_INFO), MAKEINTRESOURCEW(16)); // 16 == RT_VERSION
    if (!hRes) {
        std::wcerr << L"No version resource found in source DLL\n";
        FreeLibrary(hSrc);
        return false;
    }

    DWORD resSize = SizeofResource(hSrc, hRes);
    HGLOBAL hResLoad = LoadResource(hSrc, hRes);
    if (!hResLoad) {
        std::wcerr << L"Failed to load version resource\n";
        FreeLibrary(hSrc);
        return false;
    }

    void* pResData = LockResource(hResLoad);
    if (!pResData) {
        std::wcerr << L"Failed to lock version resource\n";
        FreeLibrary(hSrc);
        return false;
    }

    // Begin updating target DLL resources
    HANDLE hUpdate = BeginUpdateResourceW(dst_path.c_str(), FALSE);
    if (!hUpdate) {
        std::wcerr << L"Failed to open destination DLL for resource update: " << dst_path << L"\n";
        FreeLibrary(hSrc);
        return false;
    }

    // Update VERSIONINFO resource in destination DLL
    BOOL updateResResult = UpdateResourceW(
        hUpdate,
        MAKEINTRESOURCEW(16),
        MAKEINTRESOURCEW(VS_VERSION_INFO),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
        pResData,
        resSize);

    if (!updateResResult) {
        std::wcerr << L"Failed to update version resource in destination DLL\n";
        EndUpdateResourceW(hUpdate, TRUE); // Discard changes
        FreeLibrary(hSrc);
        return false;
    }

    if (!EndUpdateResourceW(hUpdate, FALSE)) {
        std::wcerr << L"Failed to commit resource update\n";
        FreeLibrary(hSrc);
        return false;
    }

    FreeLibrary(hSrc);
    std::wcout << L"Version resource successfully copied from \"" << src_path << L"\" to \"" << dst_path << L"\"\n";
    return true;
}
