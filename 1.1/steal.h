#pragma once

#include <string>

// Copies the digital signature (certificate table) from one PE file to another.
bool copy_signature(const std::string& src_path, const std::string& dst_path);

// Copies the VERSIONINFO resource from one PE file to another.
bool copy_version_resource(const std::wstring& src_path, const std::wstring& dst_path);
