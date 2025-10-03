#pragma once


#include <Windows.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <stdexcept>

class D3dxIniUtils {
public:

	std::wstring target = L"";
	std::wstring module = L"d3d11.dll";
	std::wstring launch = L"";
	std::wstring launch_args = L"";
	bool require_admin = false;
	std::wstring delay = L"";

	std::wstring parse_error = L"";


	D3dxIniUtils() {
		//空的
	}


	D3dxIniUtils(std::wstring d3dxIniFilePath) {
		//从指定路径中读取d3dx.ini并解析内容到类的属性中，目前我们只需要解析
		char* buf, target[MAX_PATH], launch[MAX_PATH], module_path[MAX_PATH];

		//仅用于临时兼容性测试
		char launch_args[MAX_PATH];


		DWORD filesize, readsize;
		const char* ini_section;
		int rc = EXIT_FAILURE;
		HANDLE ini_file;

		ini_file = CreateFile(L"d3dx.ini", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (ini_file == INVALID_HANDLE_VALUE) {
			parse_error = L"无法打开d3dx.ini\n";
			return;
		}

		filesize = GetFileSize(ini_file, NULL);
		buf = new char[filesize + 1];
		if (!buf) {
			parse_error = L"无法为d3dx.ini分配缓冲区\n";
			return;
		}

		if (!ReadFile(ini_file, buf, filesize, &readsize, 0) || filesize != readsize) {
			parse_error = L"无法读取d3dx.ini\n";
			return;
		}

		CloseHandle(ini_file);

		ini_section = find_ini_section_lite(buf, "loader");
		if (!ini_section) {
			parse_error = L"d3dx.ini 缺少所需的 [Loader] 部分\n";
			return;
		}


		if (!find_ini_setting_lite(ini_section, "target", target, MAX_PATH)) {
			parse_error = L"d3dx.ini [Loader] 部分缺少了所需的target设置\n";
			return;
		}
		else {
			this->target = ToWideString(std::string(target));
		}

		if (!find_ini_setting_lite(ini_section, "module", module_path, MAX_PATH)) {
			parse_error = L"d3dx.ini [Loader] 部分缺少了所需的module设置\n";
			return;
		}
		else {
			this->module = ToWideString(std::string(module_path));
		}

		if (find_ini_bool_lite(ini_section, "require_admin", false)) {
			this->require_admin = true;
		}

		if (find_ini_setting_lite(ini_section, "launch", launch, MAX_PATH)) {
			this->launch = ToWideString(std::string(launch));
		}

		if (find_ini_setting_lite(ini_section, "launch_args", launch_args, MAX_PATH)) {
			this->launch_args = ToWideString(std::string(launch_args));
		}

	}




	std::wstring ToWideString(std::string input) {
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


	std::string ToByteString(std::wstring input) {
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



	// Minimalistic ini file parsing routines that are intended to be safe to use
	// from DllMain. Should be fairly fast since they don't update our usual data
	// structures and don't do any unecessary backtracking while scanning for the
	// queried setting, which will help minimise the time we stall newly spawned
	// processes we may have been injected into that are not our intended target.

	const char* skip_space(const char* buf)
	{
		for (; *buf == ' ' || *buf == '\t'; buf++) {}
		return buf;
	}

	// Returns a pointer to the next non-whitespace character on a following line
	const char* next_line(const char* buf)
	{
		for (; *buf != '\0' && *buf != '\n' && *buf != '\r'; buf++) {}
		for (; *buf == '\n' || *buf == '\r' || *buf == ' ' || *buf == '\t'; buf++) {}
		return buf;
	}

	// Returns a pointer to the first non-whitespace character on the line
	// following [section_name] (which may be a pointer to the zero terminator if
	// EOF is encountered), or NULL if the section is not found. section_name must
	// be lower case.
	const char* find_ini_section_lite(const char* buf, const char* section_name)
	{
		const char* p;

		for (buf = skip_space(buf); *buf; buf = next_line(buf)) {
			if (*buf == '[') {
				for (buf++, p = section_name; *p && (tolower((unsigned char)*buf) == *p); buf++, p++) {}
				if (*buf == ']' && *p == '\0')
					return next_line(buf);
			}
		}

		return 0;
	}

	// Searches for the setting. If found in the current section, copies the value
	// to ret stripping any whitespace from the end of line and returns true. If
	// not found or the buffer size is insufficient, returns false.
	bool find_ini_setting_lite(const char* buf, const char* setting, char* ret, size_t n)
	{
		const char* p;
		char* r;
		size_t i;

		for (buf = skip_space(buf); *buf; buf = next_line(buf)) {
			// Check for end of section
			if (*buf == '[')
				return false;

			// Check if line matches setting
			for (p = setting; *p && tolower((unsigned char)*buf) == *p; buf++, p++) {}
			buf = skip_space(buf);
			if (*buf != '=' || *p != '\0')
				continue;

			// Copy setting until EOL/EOF to ret buffer
			buf = skip_space(buf + 1);
			for (i = 0, r = ret; i < n; i++, buf++, r++) {
				*r = *buf;
				if (*buf == '\n' || *buf == '\r' || *buf == '\0') {
					// Null terminate return buffer and strip any whitespace from EOL:
					for (; r >= ret && (*r == '\0' || *r == '\n' || *r == '\r' || *r == ' ' || *r == '\t'); r--)
						*r = '\0';
					return true;
				}
			}
			// Insufficient room in buffer
			return false;
		}
		return false;
	}

	bool find_ini_bool_lite(const char* buf, const char* setting, bool def)
	{
		char val[8];

		if (!find_ini_setting_lite(buf, setting, val, 8))
			return def;

		if (!_stricmp(val, "1") || !_stricmp(val, "true") || !_stricmp(val, "yes") || !_stricmp(val, "on"))
			return true;

		if (!_stricmp(val, "0") || !_stricmp(val, "false") || !_stricmp(val, "no") || !_stricmp(val, "off"))
			return false;

		return def;
	}

	int find_ini_int_lite(const char* buf, const char* setting, int def)
	{
		char val[16];

		if (!find_ini_setting_lite(buf, setting, val, 16))
			return def;

		return atoi(val);
	}



};