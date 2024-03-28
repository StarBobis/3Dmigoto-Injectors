#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>

// 根据文件完整路径获取文件所在目录路径
std::wstring getFolderPathFromFilePath(std::wstring filePath);

//string转换为wstring
std::wstring to_wide_string(std::string input);

//wstring转换为string
std::string to_byte_string(std::wstring input);

//纯C++实现分割字符串，因为Boost库无法正常以L"=="作为分隔符
std::vector<std::wstring> NMString_splitString(std::wstring,std::wstring);

