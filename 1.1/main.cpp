#include "steal.h"
#include <iostream>
#include <string>
#include <windows.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: SignatureKid.exe <signed.dll> <unsigned.dll>\n";
        return 1;
    }

    std::string src = argv[1];
    std::string dst = argv[2];

    if (!copy_signature(src, dst)) {
        std::cerr << "Failed to copy digital signature.\n";
        return 1;
    }

    // Convert paths to wide strings for resource functions
    std::wstring wsrc(src.begin(), src.end());
    std::wstring wdst(dst.begin(), dst.end());

    if (!copy_version_resource(wsrc, wdst)) {
        std::cerr << "Failed to copy version resource.\n";
        return 1;
    }

    std::cout << "Successfully copied signature and version info resource.\n";
    return 0;
}
