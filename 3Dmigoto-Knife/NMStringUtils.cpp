#include "NMStringUtils.h"
#include <filesystem>


std::wstring getFolderPathFromFilePath(std::wstring filePath) {
    std::size_t lastSlash = filePath.find_last_of(L"\\/");
    std::wstring path = filePath.substr(0, lastSlash);
    return path;
}


std::wstring to_wide_string(std::string input) {
    if (input.empty()) return L"";

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, NULL, 0);
    if (size_needed == 0) {
        // Handle error appropriately
        throw std::runtime_error("Failed in MultiByteToWideChar conversion.");
    }

    std::wstring wstrTo(size_needed, L'\0');
    int chars_converted = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &wstrTo[0], size_needed);
    if (chars_converted == 0) {
        // Handle error appropriately
        throw std::runtime_error("Failed in MultiByteToWideChar conversion.");
    }

    // Remove the null terminator as it is implicitly handled in std::wstring
    wstrTo.pop_back();

    return wstrTo;
}


std::string to_byte_string(std::wstring input) {
    if (input.empty()) return "";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
    if (size_needed == 0) {
        // Handle error appropriately
        throw std::runtime_error("Failed in WideCharToMultiByte conversion.");
    }

    std::string strTo(size_needed, '\0');
    int bytes_converted = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &strTo[0], size_needed, NULL, NULL);
    if (bytes_converted == 0) {
        // Handle error appropriately
        throw std::runtime_error("Failed in WideCharToMultiByte conversion.");
    }

    // Remove the null terminator as it is implicitly handled in std::string
    strTo.pop_back();

    return strTo;
}


std::vector <std::wstring> NMString_splitString(std::wstring originalStr, std::wstring delimiter) {
    std::vector<std::wstring> result;
    std::wstring str = originalStr;
    size_t pos = 0;
    while ((pos = str.find(delimiter)) != std::wstring::npos) {
        std::wstring token = str.substr(0, pos);
        result.push_back(token);
        str.erase(0, pos + delimiter.length());
    }
    result.push_back(str);
    return result;
}
