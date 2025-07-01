
#include <iostream>
#include "./mb.h"
#include <stdio.h>
#include <string>
#include <synchapi.h>
#include <unordered_map>
#include <functional>
#include "./windows.h"
#include <windowsx.h>  // 添加GET_X_LPARAM和GET_Y_LPARAM宏定义
#include <string.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <zlib.h>  // 添加zlib头文件用于gzip解压
#include <chrono>  // 添加时间相关头文件
#include <iomanip> // 添加格式化输出头文件
#include <regex>   // 添加正则表达式头文件
#include <algorithm> // 添加算法头文件，用于std::replace
#include <curl/curl.h> // 使用libcurl替代URLDownloadToFile
#include <set>
#include <tlhelp32.h> // 添加进程快照相关头文件
#include <psapi.h>    // 添加进程API头文件
#include <thread>     // 添加线程支持
#include <mutex>      // 添加互斥锁支持
#include <queue>      // 添加队列支持
#include <map>        // 添加映射支持
#include <memory>     // 添加智能指针支持
#include <nlohmann/json.hpp> // 添加nlohmann/json库

#pragma comment(lib, "zlib.lib")  // 链接zlib库
#pragma comment(lib, "libcurl.lib") // 链接libcurl库

using json = nlohmann::json; // 简化json命名空间

// 全局变量用于存储原始窗口过程和WebView
WNDPROC g_originalWndProc = nullptr;
mbWebView g_mbView = 0;  // mbWebView是long long类型，使用0初始化

// 英雄数据结构
struct HeroData {
	std::string alt;  // 英雄标识
	bool selected;    // 是否选中
	int ownedCount;   // 已有数量

	// 构造函数初始化成员变量
	HeroData() : selected(false), ownedCount(0) {}
	HeroData(const std::string& a, bool s = false, int c = 0) : alt(a), selected(s), ownedCount(c) {}
};

// 全局变量用于英雄数据管理
std::queue<HeroData> g_heroInputBuffer;  // 输入缓冲区（前端写入选中数据）
std::map<std::string, int> g_heroOutputCache; // 输出缓存（后台线程写入数量数据）
std::mutex g_inputMutex;   // 输入缓冲区互斥锁
std::mutex g_outputMutex;  // 输出缓存互斥锁

// 后台内存读写线程相关变量
bool g_memoryThreadRunning = false; // 内存读写线程运行标志
std::thread g_memoryThread; // 内存读写线程
std::queue<HeroData> g_memoryProcessQueue; // 内存处理队列
std::mutex g_memoryQueueMutex; // 内存处理队列互斥锁

template<typename... Args>
void logInfoF(const char* format, Args... args);

// JSON解析器类 - 用于解析pattern_results_.json文件
class PatternJsonParser {
private:
	json patternData;
	bool isLoaded = false;

public:
	// 加载JSON文件
	bool loadFromFile(const std::string& filePath) {
		try {
			std::ifstream file(filePath);
			if (!file.is_open()) {
				logInfoF("无法打开JSON文件: %s", filePath.c_str());
				return false;
			}

			file >> patternData;
			isLoaded = true;
			logInfoF("成功加载JSON文件: %s", filePath.c_str());
			return true;
		}
		catch (const json::exception& e) {
			logInfoF("JSON解析错误: %s", e.what());
			isLoaded = false;
			return false;
		}
	}

	// 根据name获取final_result
	std::string getFinalResultByName(const std::string& name) {
		if (!isLoaded) {
			logInfoF("JSON数据未加载");
			return "";
		}

		try {
			if (patternData.contains("patterns") && patternData["patterns"].is_array()) {
				for (const auto& pattern : patternData["patterns"]) {
					if (pattern.contains("name") && pattern["name"] == name) {
						if (pattern.contains("final_result")) {
							std::string result = pattern["final_result"];
							logInfoF("找到 %s 的final_result: %s", name.c_str(), result.c_str());
							return result;
						}
					}
				}
			}

			logInfoF("未找到名称为 %s 的pattern", name.c_str());
			return "";
		}
		catch (const json::exception& e) {
			logInfoF("获取final_result时发生错误: %s", e.what());
			return "";
		}
	}

	// 获取process_info中的指定字段
	std::string getProcessInfo(const std::string& key) {
		if (!isLoaded) {
			logInfoF("JSON数据未加载");
			return "";
		}

		try {
			if (patternData.contains("process_info") && patternData["process_info"].contains(key)) {
				std::string result = patternData["process_info"][key];
				logInfoF("找到 process_info.%s: %s", key.c_str(), result.c_str());
				return result;
			}

			logInfoF("未找到 process_info.%s", key.c_str());
			return "";
		}
		catch (const json::exception& e) {
			logInfoF("获取process_info时发生错误: %s", e.what());
			return "";
		}
	}

	// 获取所有可用的pattern名称
	std::vector<std::string> getAllPatternNames() {
		std::vector<std::string> names;

		if (!isLoaded) {
			logInfoF("JSON数据未加载");
			return names;
		}

		try {
			if (patternData.contains("patterns") && patternData["patterns"].is_array()) {
				for (const auto& pattern : patternData["patterns"]) {
					if (pattern.contains("name")) {
						names.push_back(pattern["name"]);
					}
				}
			}
		}
		catch (const json::exception& e) {
			logInfoF("获取pattern名称时发生错误: %s", e.what());
		}

		return names;
	}

	// 将十六进制字符串转换为数值
	static uintptr_t hexStringToAddress(const std::string& hexStr) {
		if (hexStr.empty()) return 0;

		try {
			// 移除0x前缀（如果存在）
			std::string cleanHex = hexStr;
			if (cleanHex.substr(0, 2) == "0x" || cleanHex.substr(0, 2) == "0X") {
				cleanHex = cleanHex.substr(2);
			}

			return std::stoull(cleanHex, nullptr, 16);
		}
		catch (const std::exception& e) {
			logInfoF("十六进制转换错误: %s", e.what());
			return 0;
		}
	}
};

// 游戏内存地址数据结构 - 包含所有pattern的地址
struct GameMemoryAddresses {
	// 标识指针类
	uintptr_t identifierPtr1 = 0x60;          // 标识指针1
	uintptr_t identifierPtr2 = 0x10;          // 标识指针2

	// 对局名称类
	uintptr_t gameName1 = 0x120;              // 对局名称1
	uintptr_t gameName2 = 0x78;               // 对局名称2
	uintptr_t gameName3 = 0x858;              // 对局名称3
	uintptr_t gameName4 = 0x28;               // 对局名称4
	uintptr_t gameName5 = 0x0;                // 对局名称5
	uintptr_t gameName6 = 0xA8;               // 对局名称6

	// 回合偏移类
	uintptr_t roundOffset1 = 0x8;             // 回合偏移1
	uintptr_t roundOffset2 = 0x20;            // 回合偏移2

	// 坐标相关
	uintptr_t coordBase = 0x254;              // 坐标基址
	uintptr_t coordAddress = 0x254;           // 坐标地址

	// 小怪相关
	uintptr_t minionsOffset = 0x18;           // 小怪偏移
	uintptr_t minionsBase = 0x1924C9163;      // 小怪基址

	// 阵营相关
	uintptr_t campOffsetText = 0x2F0;         // 阵营偏移文本
	uintptr_t campPointer = 0x2F0;            // 阵营指针

	// 数组相关
	uintptr_t arrayStart = 0x8;               // 数组开始
	uintptr_t arrayEnd = 0x10;                // 数组结束
	uintptr_t arrayPointer = 0x141C5C4C0;     // 数组指针

	// 金币相关
	uintptr_t goldOffset = 0x524;             // 金币偏移

	// 拿牌相关
	uintptr_t cardTaken = 0x238;              // 是否已拿
	uintptr_t canTakeCard = 0x90;             // 是否可拿牌
	uintptr_t takeCardCall = 0x1409A6F70;     // 拿牌CALL
	uintptr_t takeCardOffset = 0x220;         // 拿牌偏移
	uintptr_t takeCardCall1Text = 0x250;      // 拿牌call1文本
	uintptr_t takeCardOffsetText = 0x230;     // 拿牌偏移文本
	uintptr_t takeCardCall1 = 0x240;          // 拿牌call1

	// 商店相关
	uintptr_t shopCardPrice = 0x244;          // 商店牌价格
	uintptr_t shopCoord = 0x258;              // 商店坐标
	uintptr_t shopPosition2 = 0x268;          // 商店位置2
	uintptr_t shopPosition3 = 0xA70;          // 商店位置3

	// 排名相关
	uintptr_t rankMultiplyText = 0x68;        // 排名乘文本
	uintptr_t rankMultiplyAddText = 0x14;     // 排名乘加文本
	uintptr_t rankRegEcxAdd1Text = 0x8;       // 排名寄存器ecx加1常量文本
	uintptr_t rankRegEcxAdd2Text = 0x70;      // 排名寄存器ecx加2常量文本

	// 基址相关
	uintptr_t getCurrentBaseText = 0x2F0;     // 拿当前基址位置常量文本
	uintptr_t playerBase = 0x141C8A030;       // 人物基址
	uintptr_t preparationBase = 0x141C6F690;  // 备战
	uintptr_t tftData = 0x141CAA370;          // 云顶数据
	uintptr_t gameBase = 0x141CAA3A8;         // 对局基址
	uintptr_t matrixBase = 0x141CF0280;       // 矩阵基址

	// 名称和星级相关
	uintptr_t nameOffset = 0x42E8;            // 名称偏移
	uintptr_t starPointer = 0x4C54;           // 星级指针
	uintptr_t starPointer2 = 0x17;            // 星级指针2

	// 血量相关
	uintptr_t healthAddress = 0x1088;         // 血量地址

	// 已满相关
	uintptr_t fullOffset = 0x80C4;            // 已满偏移

	// 模块信息
	uintptr_t moduleBase = 0x140000000;       // 模块基址
	uintptr_t moduleSize = 0x1EA1000;         // 模块大小

	bool isLoaded = true;                      // 标记已硬编码加载
};

// 全局内存地址变量
GameMemoryAddresses g_memoryAddresses;

// 全局JSON解析器实例
PatternJsonParser g_patternParser;

// 预加载所有内存地址数据函数（已硬编码，无需动态加载）
void preloadMemoryAddresses() {
	logInfoF("内存地址数据已硬编码，直接使用预设值");

	logInfoF("内存地址预加载完成! 共硬编码了45个pattern地址和模块信息");
	logInfoF("主要地址汇总:");
	logInfoF("  模块基址: 0x%llX", g_memoryAddresses.moduleBase);
	logInfoF("  人物基址: 0x%llX", g_memoryAddresses.playerBase);
	logInfoF("  对局基址: 0x%llX", g_memoryAddresses.gameBase);
	logInfoF("  金币偏移: 0x%llX", g_memoryAddresses.goldOffset);
	logInfoF("  坐标基址: 0x%llX", g_memoryAddresses.coordBase);
	logInfoF("  拿牌CALL: 0x%llX", g_memoryAddresses.takeCardCall);
	logInfoF("  标识指针1: 0x%llX", g_memoryAddresses.identifierPtr1);
	logInfoF("  对局名称1: 0x%llX", g_memoryAddresses.gameName1);
	logInfoF("  回合偏移1: 0x%llX", g_memoryAddresses.roundOffset1);
	logInfoF("  小怪基址: 0x%llX", g_memoryAddresses.minionsBase);
}

// 模拟获取英雄已有数量的函数（基于alt生成固定数量）
int getHeroOwnedCountByAlt(const std::string& alt) {
	// 返回固定数量200进行测试
	return 0;
}

// 进程读取测试函数
void testProcessRead() {
	const char* processName = "League of Legends.exe";
	DWORD processId = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		logInfoF("创建进程快照失败");
		return;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// 查找进程PID
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (wcscmp(pe32.szExeFile, L"League of Legends.exe") == 0) {
				processId = pe32.th32ProcessID;
				logInfoF("找到进程 %s，PID: %d", processName, processId);
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);

	if (processId == 0) {
		logInfoF("未找到进程 %s", processName);
		return;
	}

	// 打开进程
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess == NULL) {
		logInfoF("打开进程失败，错误代码: %d", GetLastError());
		return;
	}

	// 获取模块地址
	HMODULE hMods[1024];
	DWORD cbNeeded;
	MODULEINFO modInfo;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		// 获取主模块（第一个模块）信息
		if (GetModuleInformation(hProcess, hMods[0], &modInfo, sizeof(modInfo))) {
			LPVOID baseAddress = modInfo.lpBaseOfDll;
			logInfoF("模块基址: 0x%p，大小: %d 字节", baseAddress, modInfo.SizeOfImage);

			// 读取8字节整数
			long long value = 0;
			SIZE_T bytesRead = 0;

			if (ReadProcessMemory(hProcess, baseAddress, &value, sizeof(value), &bytesRead)) {
				logInfoF("成功读取8字节数据: 0x%llX (%lld)，读取字节数: %zu", value, value, bytesRead);
			}
			else {
				logInfoF("读取进程内存失败，错误代码: %d", GetLastError());
			}

			// 读取4字节整数 (int)
			int intValue = 0;
			if (ReadProcessMemory(hProcess, baseAddress, &intValue, sizeof(intValue), &bytesRead)) {
				logInfoF("成功读取4字节整数: 0x%X (%d)，读取字节数: %zu", intValue, intValue, bytesRead);
			}
			else {
				logInfoF("读取4字节整数失败，错误代码: %d", GetLastError());
			}

			// 读取2字节短整数 (short)
			short shortValue = 0;
			if (ReadProcessMemory(hProcess, baseAddress, &shortValue, sizeof(shortValue), &bytesRead)) {
				logInfoF("成功读取2字节短整数: 0x%X (%d)，读取字节数: %zu", shortValue, shortValue, bytesRead);
			}
			else {
				logInfoF("读取2字节短整数失败，错误代码: %d", GetLastError());
			}

			// 读取1字节 (byte)
			unsigned char byteValue = 0;
			if (ReadProcessMemory(hProcess, baseAddress, &byteValue, sizeof(byteValue), &bytesRead)) {
				logInfoF("成功读取1字节: 0x%02X (%d)，读取字节数: %zu", byteValue, byteValue, bytesRead);
			}
			else {
				logInfoF("读取1字节失败，错误代码: %d", GetLastError());
			}

			// 读取4字节浮点数 (float)
			float floatValue = 0.0f;
			if (ReadProcessMemory(hProcess, baseAddress, &floatValue, sizeof(floatValue), &bytesRead)) {
				logInfoF("成功读取4字节浮点数: %f，读取字节数: %zu", floatValue, bytesRead);
			}
			else {
				logInfoF("读取4字节浮点数失败，错误代码: %d", GetLastError());
			}

			// 读取8字节双精度浮点数 (double)
			double doubleValue = 0.0;
			if (ReadProcessMemory(hProcess, baseAddress, &doubleValue, sizeof(doubleValue), &bytesRead)) {
				logInfoF("成功读取8字节双精度浮点数: %lf，读取字节数: %zu", doubleValue, bytesRead);
			}
			else {
				logInfoF("读取8字节双精度浮点数失败，错误代码: %d", GetLastError());
			}

			// 读取16字节数据块
			unsigned char buffer[16] = { 0 };
			if (ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(buffer), &bytesRead)) {
				logInfoF("成功读取16字节数据块，读取字节数: %zu", bytesRead);
				// 以十六进制格式输出前8个字节
				logInfoF("前8字节十六进制: %02X %02X %02X %02X %02X %02X %02X %02X",
					buffer[0], buffer[1], buffer[2], buffer[3],
					buffer[4], buffer[5], buffer[6], buffer[7]);
			}
			else {
				logInfoF("读取16字节数据块失败，错误代码: %d", GetLastError());
			}

			// 读取指针值 (在64位系统上是8字节)
			void* pointerValue = nullptr;
			if (ReadProcessMemory(hProcess, baseAddress, &pointerValue, sizeof(pointerValue), &bytesRead)) {
				logInfoF("成功读取指针值: 0x%p，读取字节数: %zu", pointerValue, bytesRead);
			}
			else {
				logInfoF("读取指针值失败，错误代码: %d", GetLastError());
			}

			// 尝试读取不同偏移位置的数据
			logInfoF("=== 尝试读取不同偏移位置的数据 ===");
			for (int offset = 0; offset < 64; offset += 8) {
				long long offsetValue = 0;
				LPVOID offsetAddress = (LPVOID)((BYTE*)baseAddress + offset);
				if (ReadProcessMemory(hProcess, offsetAddress, &offsetValue, sizeof(offsetValue), &bytesRead)) {
					logInfoF("偏移+%d: 0x%llX (%lld)", offset, offsetValue, offsetValue);
				}
				else {
					logInfoF("偏移+%d: 读取失败，错误代码: %d", offset, GetLastError());
				}
			}
		}
		else {
			logInfoF("获取模块信息失败，错误代码: %d", GetLastError());
		}
	}
	else {
		logInfoF("枚举进程模块失败，错误代码: %d", GetLastError());
	}

	CloseHandle(hProcess);
}

// 自定义窗口过程函数，用于捕获滚轮消息
LRESULT CALLBACK CustomWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_MOUSEWHEEL: {
		if (g_mbView) {
			// 获取鼠标位置
			POINT pt;
			pt.x = GET_X_LPARAM(lParam);
			pt.y = GET_Y_LPARAM(lParam);

			// 转换为客户端坐标
			ScreenToClient(hwnd, &pt);

			// 获取滚轮增量值
			short delta = GET_WHEEL_DELTA_WPARAM(wParam);

			// 获取修饰键状态
			DWORD flags = 0;
			if (GET_KEYSTATE_WPARAM(wParam) & MK_LBUTTON) flags |= MB_LBUTTON;
			if (GET_KEYSTATE_WPARAM(wParam) & MK_RBUTTON) flags |= MB_RBUTTON;
			if (GET_KEYSTATE_WPARAM(wParam) & MK_MBUTTON) flags |= MB_MBUTTON;
			if (GET_KEYSTATE_WPARAM(wParam) & MK_SHIFT) flags |= MB_SHIFT;
			if (GET_KEYSTATE_WPARAM(wParam) & MK_CONTROL) flags |= MB_CONTROL;

			// 转发滚轮事件给miniblink
			BOOL result = mbFireMouseWheelEvent(g_mbView, pt.x, pt.y, delta, flags);

			logInfoF("滚轮事件转发: x=%d, y=%d, delta=%d, flags=%d, 返回值=%d", pt.x, pt.y, delta, flags, result);
			return 0; // 消息已处理
		}
		break;
	}
	}

	// 调用原始窗口过程处理其他消息
	if (g_originalWndProc) {
		return CallWindowProc(g_originalWndProc, hwnd, uMsg, wParam, lParam);
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// libcurl写入回调函数
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t totalSize = size * nmemb;
	std::string* response = static_cast<std::string*>(userp);
	response->append(static_cast<char*>(contents), totalSize);
	return totalSize;
}

// libcurl文件写入回调函数
static size_t WriteFileCallback(void* contents, size_t size, size_t nmemb, FILE* file) {
	return fwrite(contents, size, nmemb, file);
}



// 使用libcurl下载文件
// 使用libcurl下载文件
CURLcode downloadFileWithCurl(const std::string& url, const std::string& outputPath, int taskId) {
	CURL* curl;
	CURLcode res;
	FILE* file;

	curl = curl_easy_init();
	if (!curl) {
		logInfoF("[任务%d] libcurl初始化失败", taskId);
		return CURLE_FAILED_INIT;
	}

	// 打开文件用于写入
	errno_t err = fopen_s(&file, outputPath.c_str(), "wb");
	if (err != 0 || !file) {
		logInfoF("[任务%d] 无法创建文件: %s", taskId, outputPath.c_str());
		curl_easy_cleanup(curl);
		return CURLE_WRITE_ERROR;
	}

	// 设置libcurl选项
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // 跟随重定向
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // 30秒超时
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L); // 10秒连接超时
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"); // 设置User-Agent
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // 跳过SSL证书验证
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // 跳过主机名验证
	curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate"); // 自动处理gzip压缩

	// 执行下载
	res = curl_easy_perform(curl);

	// 获取HTTP响应码
	long response_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

	fclose(file);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		logInfoF("[任务%d] libcurl下载失败: %s (错误码: %d) 连接: %s", taskId, curl_easy_strerror(res), res, url.c_str());
		DeleteFileA(outputPath.c_str()); // 删除不完整的文件
		return res;
	}

	if (response_code != 200) {
		logInfoF("[任务%d] HTTP错误: %ld 连接: %s", taskId, response_code, url.c_str());
		DeleteFileA(outputPath.c_str()); // 删除不完整的文件
		return CURLE_HTTP_RETURNED_ERROR;
	}

	return CURLE_OK;
}

// 下载任务结构体
struct DownloadTask {
	std::string imageUrl;
	std::string localPath;
	std::string fileName;
	int taskId;
};

// 全局变量用于统计
static int g_totalTasks = 0;
static int g_completedTasks = 0;
static int g_successfulDownloads = 0;
static int g_skippedFiles = 0;
static CRITICAL_SECTION g_statsLock;

// 将JSON数据中的图片URL转换为相对路径
std::string convertImageUrlsToRelativePaths(const std::string& jsonData) {
	std::string result = jsonData;

	// 使用多个正则表达式匹配不同格式的图片URL
	std::vector<std::string> patterns = {
		"https?://[^\"\\s]+\\.png",           // 标准PNG URL
		"https?://[^\"\\s]+\\.jpg",           // JPG图片
		"https?://[^\"\\s]+\\.jpeg",          // JPEG图片
		"\"(https?://[^\"]+\\.(png|jpg|jpeg))\"", // 带引号的图片URL
		"'(https?://[^']+\\.(png|jpg|jpeg))'",   // 带单引号的图片URL
	};

	for (const std::string& pattern : patterns) {
		try {
			std::regex imageRegex(pattern, std::regex_constants::icase);
			std::sregex_iterator iter(result.begin(), result.end(), imageRegex);
			std::sregex_iterator end;

			// 收集所有匹配项，避免在替换过程中迭代器失效
			std::vector<std::pair<std::string, std::string>> replacements;

			for (; iter != end; ++iter) {
				std::string fullMatch = iter->str();
				std::string imageUrl;

				// 根据不同的正则表达式提取URL
				if (iter->size() > 1) {
					// 有捕获组的情况
					imageUrl = (*iter)[1].str();
				}
				else {
					// 没有捕获组的情况
					imageUrl = fullMatch;
				}

				// 从URL中提取文件名
				size_t lastSlash = imageUrl.find_last_of('/');
				std::string fileName;
				if (lastSlash != std::string::npos && lastSlash < imageUrl.length() - 1) {
					fileName = imageUrl.substr(lastSlash + 1);
					//logInfoF("从URL提取文件名: %s -> %s", imageUrl.c_str(), fileName.c_str());
				}
				else {
					fileName = "unknown.png";
					logInfoF("无法从URL提取文件名，使用默认名称: %s -> %s", imageUrl.c_str(), fileName.c_str());
				}

				// 从URL中提取子目录结构
				std::string subDirectory = "";
				if (lastSlash != std::string::npos) {
					// 查找倒数第二个斜杠来获取父目录名
					size_t secondLastSlash = imageUrl.find_last_of('/', lastSlash - 1);
					if (secondLastSlash != std::string::npos) {
						subDirectory = imageUrl.substr(secondLastSlash + 1, lastSlash - secondLastSlash - 1);
					}
				}

				// 构建相对路径 (使用正斜杠避免JSON中的Unicode转义问题)
				std::string relativePath;
				if (!subDirectory.empty()) {
					relativePath = "./img/downloaded/" + subDirectory + "/" + fileName;
				}
				else {
					relativePath = "./img/downloaded/" + fileName;
				}

				// 根据原始匹配的格式构建替换字符串
				std::string replacement;
				if (fullMatch.front() == '"' && fullMatch.back() == '"') {
					replacement = "\"" + relativePath + "\"";
				}
				else if (fullMatch.front() == '\'' && fullMatch.back() == '\'') {
					replacement = "'" + relativePath + "'";
				}
				else {
					replacement = relativePath;
				}

				replacements.push_back({ fullMatch, replacement });
			}

			// 执行替换
			for (const auto& replacement : replacements) {
				size_t pos = 0;
				while ((pos = result.find(replacement.first, pos)) != std::string::npos) {
					result.replace(pos, replacement.first.length(), replacement.second);
					pos += replacement.second.length();
				}
			}

		}
		catch (const std::exception& e) {
			logInfoF("图片URL转换正则表达式错误: %s", e.what());
		}
	}

	return result;
}

void downloadPngImagesFromJson(const std::string& jsonData) {

	// 统计变量
	int totalTasks = 0;
	int successfulDownloads = 0;
	int skippedFiles = 0;
	int taskId = 1;

	// 文件名去重集合
	std::set<std::string> processedFiles;


	// 使用多个正则表1达式匹配不同格式的图片URL
	std::vector<std::string> patterns = {
		"https?://[^\"\\s]+\\.png",           // 标准PNG URL
		"https?://[^\"\\s]+\\.jpg",           // JPG图片
		"https?://[^\"\\s]+\\.jpeg",          // JPEG图片
		"\"(https?://[^\"]+\\.(png|jpg|jpeg))\"", // 带引号的图片URL
		"'(https?://[^']+\\.(png|jpg|jpeg))'",   // 带单引号的图片URL
	};

	std::set<std::string> processedUrls; // 添加URL去重集合

	for (const std::string& pattern : patterns) {
		try {
			std::regex imageRegex(pattern, std::regex_constants::icase);
			std::sregex_iterator iter(jsonData.begin(), jsonData.end(), imageRegex);
			std::sregex_iterator end;

			int foundInThisPattern = 0;
			for (; iter != end; ++iter) {
				std::string imageUrl;

				// 根据不同的正则表达式提取URL
				if (iter->size() > 1) {
					// 有捕获组的情况
					imageUrl = (*iter)[1].str();
				}
				else {
					// 没有捕获组的情况
					imageUrl = iter->str();
				}

				// 检查URL是否已经处理过
				if (processedUrls.find(imageUrl) != processedUrls.end()) {
					continue; // 跳过重复的URL
				}
				processedUrls.insert(imageUrl); // 添加到已处理集合

				foundInThisPattern++;
				//logInfoF("找到图片URL [%d]: %s", foundInThisPattern, imageUrl.c_str());

				// 从URL中提取文件名
				size_t lastSlash = imageUrl.find_last_of('/');
				std::string fileName = (lastSlash != std::string::npos) ?
					imageUrl.substr(lastSlash + 1) :
					"image_" + std::to_string(taskId) + ".png";

				// 确保文件名有扩展名
				if (fileName.find('.') == std::string::npos) {
					fileName += ".png";
				}

				// 从URL中提取子目录结构
				std::string subDirectory = "";
				if (lastSlash != std::string::npos) {
					// 查找倒数第二个斜杠来获取父目录名
					size_t secondLastSlash = imageUrl.find_last_of('/', lastSlash - 1);
					if (secondLastSlash != std::string::npos) {
						subDirectory = imageUrl.substr(secondLastSlash + 1, lastSlash - secondLastSlash - 1);
						//logInfoF("[任务%d] 提取子目录: %s", taskId, subDirectory.c_str());
					}
				}

				// 检查文件名是否已经处理过（去重）


				// 添加到已处理文件集合
				processedFiles.insert(fileName);

				// 构建包含子目录的本地路径
				std::string localPath;
				if (!subDirectory.empty()) {
					localPath = "vuejianjie\\img\\downloaded\\" + subDirectory + "\\" + fileName;
					// 创建子目录
					std::string dirPath = "vuejianjie\\img\\downloaded\\" + subDirectory;
					CreateDirectoryA(dirPath.c_str(), NULL);
					//logInfoF("[任务%d] 创建目录: %s", taskId, dirPath.c_str());
				}
				else {
					localPath = "vuejianjie\\img\\downloaded\\" + fileName;
				}

				// 检查文件是否已存在
				if (GetFileAttributesA(localPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
					skippedFiles++;
					//logInfoF("[任务%d] [跳过] 文件已存在: %s", taskId, localPath.c_str());
					taskId++;
					continue;
				}

				// 同步下载文件
				totalTasks++;
				CURLcode result = downloadFileWithCurl(imageUrl, localPath, taskId);

				if (result == CURLE_OK) {
					successfulDownloads++;
					//logInfoF("[任务%d] [成功] 下载成功: 连接: %s -> 目录: %s", taskId, imageUrl.c_str(), targetDir.c_str());
				}
				else {
					logInfoF("[任务%d] [失败] 下载失败: 连接: %s (错误码: %d)", taskId, imageUrl.c_str(), result);
				}

				taskId++;
			}


		}
		catch (const std::exception& e) {
			logInfoF("正则表达式错误: %s", e.what());
		}
	}



	if (totalTasks == 0) {
		logInfoF("警告: 没有找到任何图片URL！请检查JSON数据格式");
		return;
	}


}

// 获取当前时间字符串
std::string getCurrentTimeString() {
	auto now = std::chrono::system_clock::now();
	auto time_t = std::chrono::system_clock::to_time_t(now);
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		now.time_since_epoch()) % 1000;

	std::stringstream ss;
	// 使用localtime_s替代localtime以避免安全警告
	struct tm timeinfo;
	localtime_s(&timeinfo, &time_t);
	ss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S");
	ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
	return ss.str();
}




// 日志输出函数 - 同时输出到控制台和文件
void logOutput(const std::string& message) {
	std::string timestamp = getCurrentTimeString();
	std::string levelStr = "INFO";
	std::string logMessage = "[" + timestamp + "] [" + levelStr + "] " + message;


	std::cout << logMessage << std::endl;


	// 写入日志文件
	std::ofstream logFile("application.log", std::ios::app);
	if (logFile.is_open()) {
		logFile << logMessage << std::endl;
		logFile.close();
	}
}
// 便捷的日志函数重载
void logInfo(const std::string& message) {
	logOutput(message);
}
// 支持格式化字符串的日志函数
template<typename... Args>
void logInfoF(const char* format, Args... args) {
	char buffer[1024];
	snprintf(buffer, sizeof(buffer), format, args...);
	logInfo(std::string(buffer));
}

// gzip解压函数
std::string decompressGzip(const std::string& compressedData) {
	if (compressedData.empty()) {
		return "";
	}

	z_stream zs;
	memset(&zs, 0, sizeof(zs));

	// 初始化zlib用于gzip解压 (windowBits = 15 + 16 for gzip)
	if (inflateInit2(&zs, 15 + 16) != Z_OK) {
		return "ERROR: Failed to initialize gzip decompression";
	}

	zs.next_in = (Bytef*)compressedData.data();
	zs.avail_in = static_cast<uInt>(compressedData.size());

	int ret;
	const size_t bufferSize = 32768;
	std::unique_ptr<char[]> outbuffer(new char[bufferSize]);
	std::string decompressed;

	do {
		zs.next_out = reinterpret_cast<Bytef*>(outbuffer.get());
		zs.avail_out = bufferSize;

		ret = inflate(&zs, 0);

		if (decompressed.size() < zs.total_out) {
			decompressed.append(outbuffer.get(), zs.total_out - decompressed.size());
		}
	} while (ret == Z_OK);

	inflateEnd(&zs);

	if (ret != Z_STREAM_END) {
		return "ERROR: Gzip decompression failed";
	}

	return decompressed;
}

// 注意：libcurl会自动处理gzip压缩，不再需要手动检查和解压

// 使用libcurl的HTTP请求函数，支持gzip解压
std::string httpGet(const std::string& url) {
	CURL* curl;
	CURLcode res;
	std::string response;

	curl = curl_easy_init();
	if (!curl) {
		return "ERROR: Failed to initialize libcurl";
	}

	// 设置libcurl选项
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // 跟随重定向
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // 30秒超时
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L); // 10秒连接超时
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"); // 设置User-Agent
	curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate"); // 自动处理gzip压缩
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // 跳过SSL验证（如果需要）
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	// 执行HTTP请求
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		std::string error = "ERROR: libcurl请求失败: ";
		error += curl_easy_strerror(res);
		curl_easy_cleanup(curl);
		return error;
	}

	// 获取HTTP响应码
	long response_code;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

	curl_easy_cleanup(curl);

	if (response_code != 200) {
		return "ERROR: HTTP错误码: " + std::to_string(response_code);
	}

	return response;
}

void onJsQuery(mbWebView webView, void* param, mbJsExecState es, int64_t queryId, int customMsg, const utf8* request) {
	// 判断请求是否是 "getdata"
	if (strcmp((const char*)request, "getdata") == 0) {


		// 从HTTP接口获取数据
		std::string jsonData = httpGet("http://127.0.0.1:3000/data");

		if (jsonData.find("ERROR:") == 0) {
			logInfoF("HTTP请求失败: %s ", jsonData.c_str());
			mbResponseQuery(webView, queryId, customMsg, jsonData.c_str());
			return;
		}
		downloadPngImagesFromJson(jsonData);

		// 将图片URL转换为相对路径
		std::string modifiedJsonData = convertImageUrlsToRelativePaths(jsonData);

		// 将modifiedJsonData写入文件
		std::string outputPath = "vuejianjie\\debug_modified_json.txt";
		std::ofstream outputFile(outputPath);
		if (outputFile.is_open()) {
			outputFile << modifiedJsonData;
			outputFile.close();
			logInfoF("已将修改后的JSON数据写入文件: %s", outputPath.c_str());
		}
		else {
			logInfoF("无法创建文件: %s", outputPath.c_str());
		}

		// 返回给 JS
		mbResponseQuery(webView, queryId, customMsg, modifiedJsonData.c_str());
	}
	else if (strcmp((const char*)request, "xunhuan") == 0) {
		logInfoF("循环过来了我我我");
		testProcessRead(); // 调用进程读取测试函数
		std::string modifiedJsonData = "我知道了";

		mbResponseQuery(webView, queryId, customMsg, modifiedJsonData.c_str());
	}
	else if (strncmp((const char*)request, "sendAllHeroes:", 14) == 0) {
		// 高优先级处理：无延迟响应
		std::string heroJsonData = std::string((const char*)request + 14);

		try {
			// 解析JSON数组
			json heroArray = json::parse(heroJsonData);

			// 快速写入内存处理队列（异步处理）
			{
				std::lock_guard<std::mutex> lock(g_memoryQueueMutex);
				// 清空旧数据
				while (!g_memoryProcessQueue.empty()) {
					g_memoryProcessQueue.pop();
				}

				// 遍历所有英雄对象，写入处理队列
				for (const auto& heroObj : heroArray) {
					if (heroObj.contains("alt") && heroObj["alt"].is_string()) {
						HeroData heroData;
						heroData.alt = heroObj["alt"].get<std::string>();
						heroData.selected = false;

						// 获取选中状态
						if (heroObj.contains("selected") && heroObj["selected"].is_boolean()) {
							heroData.selected = heroObj["selected"].get<bool>();
						}

						if (!heroData.alt.empty()) {
							g_memoryProcessQueue.push(heroData);
						}
					}
				}
				//logInfoF("已将 %d 个英雄数据写入内存处理队列", (int)g_memoryProcessQueue.size());
			}
		}
		catch (const json::exception& e) {
			logInfoF("JSON解析错误: %s", e.what());
		}

		// 立即从输出缓存读取数据返回（无延迟）
		json heroCountsJson;
		{
			std::lock_guard<std::mutex> lock(g_outputMutex);
			for (const auto& pair : g_heroOutputCache) {
				heroCountsJson[pair.first] = pair.second;
			}
		}

		std::string result = heroCountsJson.dump();
		//logInfoF("无延迟返回缓存数据，包含 %d 个英雄", (int)heroCountsJson.size());

		mbResponseQuery(webView, queryId, customMsg, result.c_str());
	}
}
HWND g_gameWindow = NULL;
DWORD g_gameProcessId = 0;

// 函数声明
int getGameStatus();
uintptr_t getPlayerArray();
uintptr_t getWholeArrayPointer();
uintptr_t getSinglePointer(uintptr_t param1, int i);
int getTotalCount(uintptr_t param1);
uintptr_t getStartAddress(uintptr_t param1);
std::string getPlayerName(uintptr_t targetPointer);  // 取人名
std::string getPlayerIdentifier(uintptr_t targetPointer);  // 取标识
bool isTFTMinion(const std::string& playerName);  // 检查是否为TFT小怪格式

// 获取当前回合数函数
int getCurrentRound() {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return -1;
	}
	int result = -1;
	try {
		// 对应易语言: tmp ＝ 内存读整数型 (, 备战常量, )
		uintptr_t tmp = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)g_memoryAddresses.preparationBase, &tmp, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取备战基址失败");
			CloseHandle(hProcess);
			return -1;
		}
		logInfoF("第一步读取: 备战基址=0x%llX, 读取结果=0x%llX", g_memoryAddresses.preparationBase, tmp);

		// 对应易语言: tmp ＝ 内存读整数型 (, tmp ＋ 8, )
		uintptr_t address2 = tmp + 8;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address2, &tmp, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取第二级地址失败 (地址: 0x%llX)", address2);
			CloseHandle(hProcess);
			return -1;
		}
		logInfoF("第二步读取: 地址=0x%llX, 读取结果=0x%llX", address2, tmp);

		// 对应易语言: tmp ＝ 内存读整数型 (, tmp ＋ 48, )
		uintptr_t address3 = tmp + 32;
		int roundValue = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address3, &roundValue, sizeof(int), nullptr)) {
			logInfoF("错误: 读取回合数失败 (地址: 0x%llX)", address3);
			CloseHandle(hProcess);
			return -1;
		}

		result = roundValue;
		logInfoF("第三步读取: 地址=0x%llX, 当前回合数=%d", address3, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取当前回合数时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取游戏状态的函数
// 返回值说明: 0是加载游戏 1是选秀准备开始 2是正在选秀 3是选秀完的瞬间 4是回来的瞬间 备战5 准备战斗7 6是去的瞬间 开始战斗8 9是结束战斗的瞬间
int getGameStatus() {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return -1;
	}
	int result = -1;
	try {
		// 对应易语言: tmp ＝ 内存读整数型 (, 备战常量, )
		uintptr_t tmp = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)g_memoryAddresses.preparationBase, &tmp, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取备战基址失败");
			CloseHandle(hProcess);
			return -1;
		}
		logInfoF("第一步读取: 备战基址=0x%llX, 读取结果=0x%llX", g_memoryAddresses.preparationBase, tmp);

		// 对应易语言: tmp ＝ 内存读整数型 (, tmp ＋ 8, )
		uintptr_t address2 = tmp + 8;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address2, &tmp, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取第二级地址失败 (地址: 0x%llX)", address2);
			CloseHandle(hProcess);
			return -1;
		}
		logInfoF("第二步读取: 地址=0x%llX, 读取结果=0x%llX", address2, tmp);

		// 对应易语言: tmp ＝ 内存读整数型 (, tmp ＋ 52, )
		uintptr_t address3 = tmp + 36;
		int statusValue = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address3, &statusValue, sizeof(int), nullptr)) {
			logInfoF("错误: 读取游戏状态失败 (地址: 0x%llX)", address3);
			CloseHandle(hProcess);
			return -1;
		}

		result = statusValue;
		logInfoF("第三步读取: 地址=0x%llX, 当前游戏状态=%d", address3, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取游戏状态时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取本人数组函数
// 对应易语言: 取本人数组
uintptr_t getPlayerArray() {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return -1;
	}
	uintptr_t result = -1;
	try {
		// 对应易语言: 内存读整数型 (, 人物基址常量, )
		uintptr_t playerArrayValue = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)g_memoryAddresses.playerBase, &playerArrayValue, sizeof(int), nullptr)) {
			logInfoF("错误: 读取人物基址失败 (地址: 0x%llX)", g_memoryAddresses.playerBase);
			CloseHandle(hProcess);
			return -1;
		}

		result = playerArrayValue;
		logInfoF("读取本人数组: 地址=0x%llX, 数组值=%d", g_memoryAddresses.playerBase, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取本人数组时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取整个数组指针函数
// 对应易语言: 取整个数组指针
uintptr_t getWholeArrayPointer() {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return 0;
	}
	uintptr_t result = 0;
	try {
		// 对应易语言: 内存读长整数型 (, 数组指针常量, )
		uintptr_t arrayPointerValue = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)g_memoryAddresses.arrayPointer, &arrayPointerValue, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取数组指针失败 (地址: 0x%llX)", g_memoryAddresses.arrayPointer);
			CloseHandle(hProcess);
			return 0;
		}

		result = arrayPointerValue;
		logInfoF("读取整个数组指针: 地址=0x%llX, 指针值=0x%llX", g_memoryAddresses.arrayPointer, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取整个数组指针时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取单个指针函数
// 对应易语言: 取单个指针
uintptr_t getSinglePointer(uintptr_t param1, int i) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return 0;
	}
	uintptr_t result = 0;
	try {
		// 对应易语言: 内存读长整数型 (, 参数1 ＋ (i － 1) × 8, )
		uintptr_t address = param1 + (i - 1) * 8;
		uintptr_t pointerValue = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address, &pointerValue, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取单个指针失败 (地址: 0x%llX, 索引: %d)", address, i);
			CloseHandle(hProcess);
			return 0;
		}

		result = pointerValue;
		//logInfoF("读取单个指针: 基址=0x%llX, 索引=%d, 计算地址=0x%llX, 指针值=0x%llX", param1, i, address, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取单个指针时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取总数量函数
// 对应易语言: 取结束地址
int getTotalCount(uintptr_t param1) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return -1;
	}
	int result = -1;
	try {
		// 对应易语言: 内存读整数型 (, 参数1 ＋ 结束地址常量, ) - 返回总数量
		uintptr_t address = param1 + g_memoryAddresses.arrayEnd;
		int totalCount = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address, &totalCount, sizeof(int), nullptr)) {
			logInfoF("错误: 读取总数量失败 (地址: 0x%llX)", address);
			CloseHandle(hProcess);
			return -1;
		}

		result = totalCount;
		logInfoF("读取总数量: 基址=0x%llX, 偏移=0x%llX, 计算地址=0x%llX, 总数量=%d", param1, g_memoryAddresses.arrayEnd, address, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取总数量时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取开始地址函数
// 对应易语言: 取开始地址
uintptr_t getStartAddress(uintptr_t param1) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return 0;
	}
	uintptr_t result = 0;
	try {
		// 对应易语言: 内存读长整数型 (, 参数1 ＋ 开始地址常量, )
		uintptr_t address = param1 + g_memoryAddresses.arrayStart;
		uintptr_t startValue = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)address, &startValue, sizeof(uintptr_t), nullptr)) {
			logInfoF("错误: 读取开始地址失败 (地址: 0x%llX)", address);
			CloseHandle(hProcess);
			return 0;
		}

		result = startValue;
		logInfoF("读取开始地址: 基址=0x%llX, 偏移=0x%llX, 计算地址=0x%llX, 开始值=0x%llX", param1, g_memoryAddresses.arrayStart, address, result);

	}
	catch (const std::exception& e) {
		logInfoF("获取开始地址时发生异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 获取游戏窗口句柄的函数
HWND getGameWindowHandle() {
	// 通过窗口类名和标题查找窗口
	HWND hwnd = FindWindowA("RiotWindowClass", "League of Legends (TM) Client");
	if (hwnd == NULL) {
		// 如果精确匹配失败，尝试部分匹配标题
		hwnd = FindWindowA("RiotWindowClass", NULL);
		if (hwnd != NULL) {
			char windowTitle[256];
			GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
			if (strstr(windowTitle, "League of Legends") == NULL) {
				hwnd = NULL;
			}
		}
	}

	if (hwnd != NULL) {
		logInfoF("找到游戏窗口句柄: 0x%p", hwnd);
	}
	else {
		logInfoF("未找到游戏窗口");
	}

	return hwnd;
}
// 后台内存读写线程函数（死循环处理）
// 取人名函数
std::string getPlayerName(uintptr_t targetPointer) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return "";
	}

	std::string result = "";
	try {
		// 读取长度: 内存读整数型(, 目标指针 + 目标名称常量 + 16, )
		uintptr_t lengthAddress = targetPointer + g_memoryAddresses.nameOffset + 16;
		int length = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)lengthAddress, &length, sizeof(int), nullptr)) {
			logInfoF("错误: 读取名称长度失败 (地址: 0x%llX)", lengthAddress);
			CloseHandle(hProcess);
			return "";
		}

		uintptr_t dataAddress;
		if (length > 15) {
			// TMP = 内存读长整数型(, 目标指针 + 目标名称常量, )
			uintptr_t tmpAddress = targetPointer + g_memoryAddresses.nameOffset;
			if (!ReadProcessMemory(hProcess, (LPCVOID)tmpAddress, &dataAddress, sizeof(uintptr_t), nullptr)) {
				logInfoF("错误: 读取名称指针失败 (地址: 0x%llX)", tmpAddress);
				CloseHandle(hProcess);
				return "";
			}
		}
		else {
			// TMP = 目标指针 + 目标名称常量
			dataAddress = targetPointer + g_memoryAddresses.nameOffset;
		}

		// 读取UTF-8字符串数据
		char buffer[128] = { 0 };
		if (!ReadProcessMemory(hProcess, (LPCVOID)dataAddress, buffer, 128, nullptr)) {
			logInfoF("错误: 读取名称数据失败 (地址: 0x%llX)", dataAddress);
			CloseHandle(hProcess);
			return "";
		}

		// 转换UTF-8到ANSI (简化处理，直接返回字符串)
		result = std::string(buffer);
		//logInfoF("读取人名: 目标指针=0x%llX, 长度=%d, 数据地址=0x%llX, 名称=%s", targetPointer, length, dataAddress, result.c_str());

	}
	catch (const std::exception& e) {
		logInfoF("读取人名异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 取标识函数
std::string getPlayerIdentifier(uintptr_t targetPointer) {
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_gameProcessId);
	if (!hProcess) {
		logInfoF("错误: 无法打开游戏进程");
		return "";
	}

	std::string result = "";
	try {
		// 读取长度: 内存读整数型(, 目标指针 + 标识常量 + 16, )
		uintptr_t lengthAddress = targetPointer + g_memoryAddresses.identifierPtr1 + 16;
		int length = 0;
		if (!ReadProcessMemory(hProcess, (LPCVOID)lengthAddress, &length, sizeof(int), nullptr)) {
			logInfoF("错误: 读取标识长度失败 (地址: 0x%llX)", lengthAddress);
			CloseHandle(hProcess);
			return "";
		}

		uintptr_t dataAddress;
		if (length >= 16) {
			// TMP = 内存读长整数型(, 目标指针 + 标识常量, )
			uintptr_t tmpAddress = targetPointer + g_memoryAddresses.identifierPtr1;
			if (!ReadProcessMemory(hProcess, (LPCVOID)tmpAddress, &dataAddress, sizeof(uintptr_t), nullptr)) {
				logInfoF("错误: 读取标识指针失败 (地址: 0x%llX)", tmpAddress);
				CloseHandle(hProcess);
				return "";
			}
		}
		else {
			// TMP = 目标指针 + 标识常量
			dataAddress = targetPointer + g_memoryAddresses.identifierPtr1;
		}

		// 读取UTF-8字符串数据
		char buffer[128] = { 0 };
		if (!ReadProcessMemory(hProcess, (LPCVOID)dataAddress, buffer, 128, nullptr)) {
			logInfoF("错误: 读取标识数据失败 (地址: 0x%llX)", dataAddress);
			CloseHandle(hProcess);
			return "";
		}

		// 转换UTF-8到ANSI (简化处理，直接返回字符串)
		result = std::string(buffer);
		//logInfoF("读取标识: 目标指针=0x%llX, 长度=%d, 数据地址=0x%llX, 标识=%s", targetPointer, length, dataAddress, result.c_str());

	}
	catch (const std::exception& e) {
		logInfoF("读取标识异常: %s", e.what());
	}

	CloseHandle(hProcess);
	return result;
}

// 检查是否为TFT小怪格式 (TFT14_ 或 TFT14b_)
bool isTFTMinion(const std::string& playerName) {
	// 检查基本长度和前缀
	if (playerName.length() < 6 || playerName.substr(0, 3) != "TFT") {
		return false;
	}

	// 检查第4和第5个字符是否为数字
	if (!std::isdigit(playerName[3]) || !std::isdigit(playerName[4])) {
		return false;
	}

	// 检查两种格式: TFT??b_ 或 TFT??_
	if (playerName.length() >= 7 && playerName.substr(5, 2) == "b_") {
		// TFT??b_ 格式 (如 TFT14b_KogMaw)
		return true;
	} else if (playerName.length() >= 6 && playerName[5] == '_') {
		// TFT??_ 格式 (如 TFT14_KogMaw)
		return true;
	}

	return false;
}

void memoryReadWriteThread() {
	logInfoF("内存读写线程启动");

	while (g_memoryThreadRunning) {
		std::vector<HeroData> processBatch;

		// 从内存处理队列获取数据
		{
			std::lock_guard<std::mutex> lock(g_memoryQueueMutex);
			while (!g_memoryProcessQueue.empty()) {
				processBatch.push_back(g_memoryProcessQueue.front());
				g_memoryProcessQueue.pop();
			}
		}

		if (!processBatch.empty()) {
			//logInfoF("内存线程处理 %d 个英雄数据", (int)processBatch.size());

			// 批量处理英雄数据（内存读写操作）

			//-------------------------------------------------

			std::map<std::string, int> memoryResults;
			for (const auto& heroData : processBatch) {
				// 实际的内存读写操作（替换为真实的内存读取逻辑）

				int ownedCount = getHeroOwnedCountByAlt(heroData.alt);
				memoryResults[heroData.alt] = ownedCount;
				if (heroData.selected)
				{
					//logInfoF("内存读取英雄: %s -> %d (选中: %s)", heroData.alt.c_str(), ownedCount, heroData.selected ? "是" : "否");
				}

			}


			//-------------内存功能都写到这里------------------------------------
			//需要在这写个逻辑,如果窗口存在就获取窗口句柄以及进程PID,然后对他进行内存读取,如果不存在就循环获取


			if (IsWindow(g_gameWindow) == 0) {
				//句柄无效,则走获取句柄的代码
				g_gameWindow = getGameWindowHandle();

				if (IsWindow(g_gameWindow) != 0) {
					GetWindowThreadProcessId(g_gameWindow, &g_gameProcessId);
					logInfoF("获取到游戏进程ID: %d", g_gameProcessId);
					//preloadMemoryAddresses();
				}

			}
			else {
				//句柄有效 则开始获取游戏数据内存读取

				// 预加载所有内存地址数据

				int CurrentRound = getCurrentRound();
				if (CurrentRound >= 1) {
					//现在才算开始游戏
					int GameStatus = getGameStatus();
					uintptr_t PlayerArray = getPlayerArray();
					uintptr_t ArrayPointer = getWholeArrayPointer();
					logInfoF("当前回合: %d, 游戏状态: %d, 本人数组: %d, 数组指针: 0x%llX", CurrentRound, GameStatus, PlayerArray, ArrayPointer);

					//这样数据才获取正确
					// 测试新封装的三个函数

					uintptr_t startAddr = getStartAddress(ArrayPointer);  // 获取开始地址
					uintptr_t singlePtr = getSinglePointer(startAddr, 1);  // 获取第1个指针
					int totalCount = getTotalCount(ArrayPointer);  // 获取总数量
					//logInfoF("单个指针(索引1): 0x%llX, 总数量: %d, 开始地址: 0x%llX", singlePtr, totalCount, startAddr);
					//实体数量 ＝ 右移 (结束地址 － 开始地址, 3)

					//logInfoF("实体数量: %d", totalCount);

					// 遍历获取所有指针
					for (int i = 1; i <= totalCount; i++) {
						uintptr_t singlePtr = getSinglePointer(startAddr, i);  // 获取第i个指针
						//logInfoF("第%d个指针: 0x%llX", i, singlePtr);

						// 测试获取人名和标识
						if (singlePtr != 0) {
							std::string playerName = getPlayerName(singlePtr);
							std::string playerIdentifier = getPlayerIdentifier(singlePtr);

							//对比playerName前面三个是否为TFT
							if (playerName.substr(0, 3) == "TFT")
							{
								
								if (playerName == "TFTChampion") {
									//这个对象是英雄
									logInfoF("英雄英雄英雄英雄%d个实体 - 人名: %s, 标识: %s", i, playerName.c_str(), playerIdentifier.c_str());

								}
								else if (isTFTMinion(playerName)) {
									//小怪
									logInfoF("小怪小怪小怪小怪%d个实体 - 人名: %s, 标识: %s", i, playerName.c_str(), playerIdentifier.c_str());
                                    

								}
								else if (playerName == "TFT_BoardSlot") {
									//站位
									//logInfoF("站位站位站位站位%d个实体 - 人名: %s, 标识: %s", i, playerName.c_str(), playerIdentifier.c_str());


								}
								else
								{
									//logInfoF("未知未知未知未知%d个实体 - 人名: %s, 标识: %s", i, playerName.c_str(), playerIdentifier.c_str());

								}



							}
						}
					}

				}
			}








			//-------------内存功能都写到这里------------------------------------
			// 将结果写入输出缓存供前端读取
			{
				std::lock_guard<std::mutex> lock(g_outputMutex);
				for (const auto& result : memoryResults) {
					g_heroOutputCache[result.first] = result.second;
				}
			}

			//logInfoF("内存处理完成，已更新 %d 个英雄数据到缓存", (int)memoryResults.size());
		}

		// 短暂休眠避免CPU占用过高
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	logInfoF("内存读写线程结束");
}

int main()
{
	// 地址已硬编码，无需加载JSON文件
	logInfoF("使用硬编码地址，跳过JSON文件加载");
	logInfoF("已硬编码 45 个pattern地址");
	logInfoF("对局名称1的地址: 0x%llX (十进制: %llu)", g_memoryAddresses.gameName1, g_memoryAddresses.gameName1);

	// 初始化libcurl
	CURLcode curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (curl_init_result != CURLE_OK) {
		logInfoF("libcurl初始化失败: %s", curl_easy_strerror(curl_init_result));
		return 1;
	}


	HANDLE hMutex = CreateMutex(NULL, TRUE, L"Global\\MiniAppMutexxjhsgw");
	if (hMutex == NULL) {
		MessageBoxW(NULL, L"应用初始化失败！", L"错误", MB_ICONERROR);
		logInfoF("应用初始化失败！");
		curl_global_cleanup();
		return 1;
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		curl_global_cleanup();
		return 1;
	}

	WCHAR currentDir[MAX_PATH];
	if (!GetCurrentDirectoryW(MAX_PATH, currentDir)) {
		MessageBoxW(NULL, L"获取当前目录失败", L"错误", MB_OK | MB_ICONERROR);
		logInfoF("获取当前目录失败");
		return 1;
	}
	std::wstring dllPath = std::wstring(currentDir) + L"\\mb132_x64.dll";
	DWORD attr = GetFileAttributesW(dllPath.c_str());
	if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
		MessageBoxW(NULL, L"找不到 mb132_x64.dll", L"错误", MB_OK | MB_ICONERROR);
		logInfoF("找不到 mb132_x64.dll");
		return 1;
	}
	mbSetMbMainDllPath(dllPath.c_str());
	mbInit(nullptr);
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);
	mbWebView mbView = mbCreateWebWindow(MB_WINDOW_TYPE_TRANSPARENT, NULL, -2560, 0, screenWidth, screenHeight);

	// 保存WebView到全局变量
	g_mbView = mbView;

	// 获取miniblink创建的窗口句柄
	HWND mbHwnd = mbGetHostHWND(mbView);
	if (mbHwnd) {
		// 子类化窗口以捕获滚轮消息
		g_originalWndProc = (WNDPROC)SetWindowLongPtr(mbHwnd, GWLP_WNDPROC, (LONG_PTR)CustomWndProc);
		if (g_originalWndProc) {
			logInfoF("成功子类化miniblink窗口，窗口句柄: 0x%p", mbHwnd);
		}
		else {
			logInfoF("子类化miniblink窗口失败，错误码: %d", GetLastError());
		}
	}
	else {
		logInfoF("无法获取miniblink窗口句柄");
	}

	mbOnJsQuery(mbView, onJsQuery, NULL);

	// 启动内存读写线程
	g_memoryThreadRunning = true;
	g_memoryThread = std::thread(memoryReadWriteThread);
	logInfoF("内存读写线程已启动");

	std::wstring vuePath = std::wstring(currentDir) + L"\\vuejianjie\\index.html";
	std::string vuePathUtf8(vuePath.begin(), vuePath.end());

	mbLoadURL(mbView, vuePathUtf8.c_str());

	mbShowWindow(mbView, true);

	mbRunMessageLoop();

	// 停止内存读写线程
	g_memoryThreadRunning = false;
	if (g_memoryThread.joinable()) {
		g_memoryThread.join();
	}
	logInfoF("内存读写线程已停止");

	// 恢复原始窗口过程
	if (g_originalWndProc && g_mbView) {
		HWND mbHwnd = mbGetHostHWND(g_mbView);
		if (mbHwnd) {
			SetWindowLongPtr(mbHwnd, GWLP_WNDPROC, (LONG_PTR)g_originalWndProc);
			logInfoF("已恢复原始窗口过程");
		}
	}

	ReleaseMutex(hMutex);
	CloseHandle(hMutex);

	// 清理libcurl
	curl_global_cleanup();


	return 0;
}
