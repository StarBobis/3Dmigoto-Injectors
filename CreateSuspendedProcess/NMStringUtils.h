#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>

// �����ļ�����·����ȡ�ļ�����Ŀ¼·��
std::wstring getFolderPathFromFilePath(std::wstring filePath);

//stringת��Ϊwstring
std::wstring to_wide_string(std::string input);

//wstringת��Ϊstring
std::string to_byte_string(std::wstring input);

//��C++ʵ�ַָ��ַ�������ΪBoost���޷�������L"=="��Ϊ�ָ���
std::vector<std::wstring> NMString_splitString(std::wstring,std::wstring);
