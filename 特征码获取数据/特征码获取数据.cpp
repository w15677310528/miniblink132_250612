#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <memory>
#include <chrono>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <fstream>
#include <cstring>

// 开源库
// 禁用第三方库的警告
#pragma warning(push)
#pragma warning(disable: 26495) // 未初始化变量警告
#pragma warning(disable: 26498) // constexpr警告
#pragma warning(disable: 26800) // 使用已移动对象警告
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <fmt/format.h>
#include <fmt/chrono.h>
#pragma warning(pop)

using json = nlohmann::json;
using namespace std::chrono;

// 为了兼容性，使用简化的optional实现
template<typename T>
class simple_optional {
private:
	bool has_value_;
	alignas(T) char storage_[sizeof(T)]{}; // 初始化storage_数组

public:
	simple_optional() : has_value_(false) {
		// 显式初始化storage_
		std::memset(storage_, 0, sizeof(storage_));
	}

	simple_optional(const T& value) : has_value_(true) {
		// 初始化storage_数组
		std::memset(storage_, 0, sizeof(storage_));
		new(storage_) T(value);
	}

	simple_optional(T&& value) : has_value_(true) {
		// 初始化storage_数组
		std::memset(storage_, 0, sizeof(storage_));
		new(storage_) T(std::move(value));
	}

	~simple_optional() {
		if (has_value_) {
			reinterpret_cast<T*>(storage_)->~T();
		}
	}

	simple_optional(const simple_optional& other) : has_value_(other.has_value_) {
		// 初始化storage_数组
		std::memset(storage_, 0, sizeof(storage_));
		if (has_value_) {
			new(storage_) T(*reinterpret_cast<const T*>(other.storage_));
		}
	}

	simple_optional& operator=(const simple_optional& other) {
		if (this != &other) {
			if (has_value_) {
				reinterpret_cast<T*>(storage_)->~T();
			}
			has_value_ = other.has_value_;
			// 初始化storage_数组
			std::memset(storage_, 0, sizeof(storage_));
			if (has_value_) {
				new(storage_) T(*reinterpret_cast<const T*>(other.storage_));
			}
		}
		return *this;
	}

	bool has_value() const { return has_value_; }
	operator bool() const { return has_value_; }

	T& operator*() { return *reinterpret_cast<T*>(storage_); }
	const T& operator*() const { return *reinterpret_cast<const T*>(storage_); }

	T* operator->() { return reinterpret_cast<T*>(storage_); }
	const T* operator->() const { return reinterpret_cast<const T*>(storage_); }
};

#define std_optional simple_optional

// 推荐使用的开源库 (需要通过vcpkg或其他包管理器安装)
// #include <nlohmann/json.hpp>     // JSON处理: vcpkg install nlohmann-json
// #include <spdlog/spdlog.h>       // 日志库: vcpkg install spdlog
// #include <fmt/format.h>          // 格式化库: vcpkg install fmt
// #include <range/v3/all.hpp>      // 范围库: vcpkg install range-v3

// 临时使用简化的JSON实现 (生产环境建议使用nlohmann/json)
#include <sstream>
#include <map>
#include <fstream>
#include <algorithm>
#include <stdexcept>
#include <utility>

using namespace std::chrono;

// logInfoF函数定义 (用户要求的调试输出函数)
template<typename... Args>
void logInfoF(const char* format, Args&&... args) {
	auto now = system_clock::now();
	auto time_t = system_clock::to_time_t(now);
	auto tm = *std::localtime(&time_t);

	printf("[%04d-%02d-%02d %02d:%02d:%02d] [INFO] ",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	printf(format, std::forward<Args>(args)...);
	printf("\n");
}

// 现代化的日志类 (建议替换为spdlog)
// 现代化日志管理器
class ModernLogger {
public:
	static void init() {
		try {
			// 创建控制台和文件输出
			auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
			auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("pattern_search.log", true);

			std::vector<spdlog::sink_ptr> sinks{ console_sink, file_sink };
			auto logger = std::make_shared<spdlog::logger>("pattern_search", sinks.begin(), sinks.end());

			spdlog::set_default_logger(logger);
			spdlog::set_level(spdlog::level::info);
			spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");
		}
		catch (const spdlog::spdlog_ex& ex) {
			std::cout << "日志初始化失败: " << ex.what() << std::endl;
		}
	}

	template<typename... Args>
	static void info(const std::string& format, Args&&... args) {
		spdlog::info(fmt::format(format, std::forward<Args>(args)...));
	}

	template<typename... Args>
	static void error(const std::string& format, Args&&... args) {
		spdlog::error(fmt::format(format, std::forward<Args>(args)...));
	}
};

// 为了兼容性，保留Logger别名
using Logger = ModernLogger;

// 现代化的特征码信息结构
struct PatternInfo {
	std::string name;
	std::string pattern;
	std::vector<uint8_t> bytes;
	std::vector<bool> mask;
	std::vector<uintptr_t> results;
	int relativeOffset = 0;
	int instructionLength = 0;
	bool calculateRelative = false;
	int matchIndex = 0;
	std_optional<uintptr_t> finalResult;
	std::string errorMessage; // 错误信息

	// 默认构造函数
	PatternInfo() = default;

	// 使用现代C++构造函数
	PatternInfo(std::string name, std::string pattern, int relativeOffset = 0,
		int instructionLength = 0, bool calculateRelative = false, int matchIndex = 1)
		: name(std::move(name)), pattern(std::move(pattern)), relativeOffset(relativeOffset),
		instructionLength(instructionLength), calculateRelative(calculateRelative), matchIndex(matchIndex) {
	}
};

// RAII风格的进程句柄管理
class ProcessHandle {
private:
	HANDLE handle_;

public:
	explicit ProcessHandle(HANDLE handle) : handle_(handle) {}

	~ProcessHandle() {
		if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
			CloseHandle(handle_);
		}
	}

	// 禁用拷贝，允许移动
	ProcessHandle(const ProcessHandle&) = delete;
	ProcessHandle& operator=(const ProcessHandle&) = delete;

	ProcessHandle(ProcessHandle&& other) noexcept : handle_(other.handle_) {
		other.handle_ = nullptr;
	}

	ProcessHandle& operator=(ProcessHandle&& other) noexcept {
		if (this != &other) {
			if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
				CloseHandle(handle_);
			}
			handle_ = other.handle_;
			other.handle_ = nullptr;
		}
		return *this;
	}

	HANDLE get() const { return handle_; }
	operator bool() const { return handle_ && handle_ != INVALID_HANDLE_VALUE; }
};

// 现代化的特征码管理器
class PatternManager {
private:
	std::vector<PatternInfo> patterns_;
	std::unique_ptr<ProcessHandle> process_;
	uintptr_t moduleBase_ = 0;
	size_t moduleSize_ = 0;

	static constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1MB

public:
	PatternManager() = default;

	// 使用现代C++的方法签名
	bool addPattern(std::string name, int offsetLength = 0, int matchIndex = 1, bool calculateRelative = false, std::string pattern = "") {
		PatternInfo info(std::move(name), std::move(pattern), offsetLength,
			offsetLength, calculateRelative, matchIndex);

		if (!parsePattern(info.pattern, info.bytes, info.mask)) {
			Logger::error("解析特征码失败: {}", info.name);
			return false;
		}

		patterns_.emplace_back(std::move(info));
		Logger::info("添加特征码: {} -> {}", patterns_.back().name, patterns_.back().pattern);
		return true;
	}

	// 使用simple_optional返回值
	std_optional<uint32_t> getProcessId(const std::wstring& processName) {
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return std_optional<uint32_t>();
		}

		// RAII风格的句柄管理
		struct HandleDeleter {
			void operator()(HANDLE h) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
		};
		std::unique_ptr<void, HandleDeleter> guard(snapshot, HandleDeleter{});

		PROCESSENTRY32W pe32{};
		pe32.dwSize = sizeof(PROCESSENTRY32W);

		if (Process32FirstW(snapshot, &pe32)) {
			do {
				if (processName == pe32.szExeFile) {
					return pe32.th32ProcessID;
				}
			} while (Process32NextW(snapshot, &pe32));
		}

		return std_optional<uint32_t>();
	}

	bool initialize(const std::wstring& processName) {
		auto processId = getProcessId(processName);
		if (!processId) {
			Logger::error("未找到进程: {}", std::string(processName.begin(), processName.end()));
			return false;
		}

		auto handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, *processId);
		if (!handle) {
			Logger::error("打开进程失败，错误代码: {}", GetLastError());
			return false;
		}

		process_ = std::make_unique<ProcessHandle>(handle);

		if (!getMainModuleInfo(*processId)) {
			Logger::error("获取主模块信息失败");
			return false;
		}

		Logger::info("成功初始化进程，模块基址: 0x{:x}，大小: 0x{:x}",
			moduleBase_, moduleSize_);
		return true;
	}

	void searchAllPatterns() {
		if (!process_ || moduleBase_ == 0) {
			Logger::error("进程未初始化");
			return;
		}

		Logger::info("开始搜索 {} 个特征码...", patterns_.size());

		// 使用现代C++的范围for循环
		for (auto& pattern : patterns_) {
			Logger::info("正在搜索特征码: {}", pattern.name);
			searchPattern(pattern);
		}

		printSearchSummary();
	}

	// 使用现代C++的JSON生成 (建议替换为nlohmann/json)
	std::string toJson() const {
		json result;
		result["timestamp"] = getCurrentTimeString();

		// 进程信息
		result["process_info"]["module_base"] = fmt::format("0x{:X}", moduleBase_);
		result["process_info"]["module_size"] = fmt::format("0x{:X}", moduleSize_);

		// 特征码结果 - 包含错误信息
		json patterns_array = json::array();
		for (const auto& pattern : patterns_) {
			json pattern_json;
			pattern_json["name"] = pattern.name;
			pattern_json["final_result"] = pattern.finalResult ?
				fmt::format("0x{:X}", *pattern.finalResult) : "0x0";
			
			// 添加匹配状态和错误信息
			pattern_json["success"] = pattern.finalResult.has_value();
			pattern_json["match_count"] = pattern.results.size();
			if (!pattern.errorMessage.empty()) {
				pattern_json["error"] = pattern.errorMessage;
			}

			patterns_array.push_back(pattern_json);
		}

		result["patterns"] = patterns_array;
		return result.dump(2); // 美化输出，缩进2个空格
	}

bool saveToJsonFile(const std::string& filename) const {
    try {
        // 使用UTF-8编码保存文件
        std::ofstream file(filename, std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            Logger::error("无法创建JSON文件: {}", filename);
            return false;
        }

        // 写入UTF-8 BOM（可选，但有助于确保正确识别编码）
        const char utf8_bom[] = "\xEF\xBB\xBF";
        file.write(utf8_bom, 3);
        
        // 获取JSON字符串并确保以UTF-8编码写入
        std::string jsonStr = toJson();
        file.write(jsonStr.c_str(), jsonStr.length());
        
        file.close();
        Logger::info("结果已保存到JSON文件 (UTF-8编码): {}", filename);
        return true;
    }
    catch (const std::exception& e) {
        Logger::error("保存JSON文件时发生异常: {}", e.what());
        return false;
    }
}

	const std::vector<PatternInfo>& getPatterns() const {
		return patterns_;
	}

	// 使用模板和现代C++特性的内存读取
	template<typename T>
	std_optional<T> readMemory(uintptr_t address) const {
		if (!process_) return std_optional<T>();

		T value{};
		SIZE_T bytesRead = 0;

		if (ReadProcessMemory(process_->get(), reinterpret_cast<LPCVOID>(address),
			&value, sizeof(T), &bytesRead) && bytesRead == sizeof(T)) {
			return value;
		}

		return std_optional<T>();
	}

	std_optional<std::string> readString(uintptr_t address, size_t maxLength = 256) const {
		if (!process_) return std_optional<std::string>();

		std::vector<char> buffer(maxLength);
		SIZE_T bytesRead = 0;

		if (ReadProcessMemory(process_->get(), reinterpret_cast<LPCVOID>(address),
			buffer.data(), maxLength - 1, &bytesRead)) {
			buffer[bytesRead] = '\0';
			return std::string(buffer.data());
		}

		return std_optional<std::string>();
	}

	// 自定义函数：添加简单的name和final_result数据
	void addCustomResult(const std::string& name, const std::string& final_result) {
		Logger::info("添加自定义结果: {} -> {}", name, final_result);

		// 创建一个简单的PatternInfo用于存储自定义数据
		PatternInfo customInfo;
		customInfo.name = name;
		customInfo.pattern = "自定义数据";
		customInfo.relativeOffset = 0;
		customInfo.instructionLength = 0;
		customInfo.calculateRelative = false;
		customInfo.matchIndex = 1;
		// 自定义数据不需要bytes和mask，设置为空
		customInfo.bytes.clear();
		customInfo.mask.clear();

		// 解析十六进制地址字符串
		if (final_result.substr(0, 2) == "0x" || final_result.substr(0, 2) == "0X") {
			try {
				uintptr_t addr = std::stoull(final_result.substr(2), nullptr, 16);
				customInfo.finalResult = addr;
				customInfo.results.push_back(addr);
			}
			catch (const std::exception& e) {
				Logger::error("解析地址失败: {}", e.what());
				customInfo.finalResult = std_optional<uintptr_t>();
			}
		}
		else {
			customInfo.finalResult = std_optional<uintptr_t>();
		}

		patterns_.emplace_back(std::move(customInfo));
	}

private:
	bool parsePattern(const std::string& pattern, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
		std::istringstream iss(pattern);
		std::string token;

		bytes.clear();
		mask.clear();

		while (iss >> token) {
			if (token == "?" || token == "??" || token == "*") {
				bytes.push_back(0x00);
				mask.push_back(false);
			}
			else {
				try {
					auto byte = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
					bytes.push_back(byte);
					mask.push_back(true);
				}
				catch (const std::exception&) {
					Logger::error("无效的十六进制值: %s", token.c_str());
					return false;
				}
			}
		}

		return !bytes.empty();
	}

	bool getMainModuleInfo(uint32_t processId) {
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return false;
		}

		struct HandleDeleter {
			void operator()(HANDLE h) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
		};
		std::unique_ptr<void, HandleDeleter> guard(snapshot, HandleDeleter{});

		MODULEENTRY32W me32{};
		me32.dwSize = sizeof(MODULEENTRY32W);

		if (Module32FirstW(snapshot, &me32)) {
			moduleBase_ = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
			moduleSize_ = me32.modBaseSize;
			return true;
		}

		return false;
	}

	void searchPattern(PatternInfo& pattern) {
		// 如果是自定义数据，跳过搜索过程
		if (pattern.pattern == "自定义数据") {
			Logger::info("跳过自定义数据搜索: {}", pattern.name);
			return;
		}

		pattern.results.clear();

		std::vector<uint8_t> buffer(CHUNK_SIZE);
		size_t totalRead = 0;
		uintptr_t currentAddress = moduleBase_;

		while (totalRead < moduleSize_) {
			size_t bytesToRead = std::min(CHUNK_SIZE, moduleSize_ - totalRead);
			SIZE_T bytesRead = 0;

			if (ReadProcessMemory(process_->get(), reinterpret_cast<LPCVOID>(currentAddress),
				buffer.data(), bytesToRead, &bytesRead)) {

				// 使用现代C++的算法
				for (size_t i = 0; i <= bytesRead - pattern.bytes.size(); ++i) {
					if (matchPattern(buffer.data() + i, pattern.bytes, pattern.mask)) {
						uintptr_t foundAddress = currentAddress + i;

						if (pattern.calculateRelative) {
							if (auto relativeAddr = calculateRelativeAddress(foundAddress,
								pattern.relativeOffset, pattern.instructionLength)) {
								pattern.results.push_back(*relativeAddr);
								//Logger::info("找到匹配: 0x%p -> 相对地址: 0x%p", reinterpret_cast<void*>(foundAddress),  reinterpret_cast<void*>(*relativeAddr));


							}
						}
						else {
							if (auto offsetValue = readMemory<uint32_t>(foundAddress + pattern.relativeOffset)) {
								//Logger::info("找到拿牌偏移值: 0x{:08X} (地址: 0x{:p})", *offsetValue, reinterpret_cast<void*>(foundAddress));
								pattern.results.push_back(*offsetValue);  // 存储偏移值而不是地址
							}
						}
					}
				}

				totalRead += bytesRead;
				currentAddress += bytesRead;

				// 显示进度
				if (totalRead % (10 * 1024 * 1024) == 0 || totalRead >= moduleSize_) {
					double progress = static_cast<double>(totalRead) / moduleSize_ * 100.0;
					Logger::info("搜索进度: {:.1f}% ({}/{})", progress, totalRead, moduleSize_);
				}
			}
			else {
				currentAddress += bytesToRead;
				totalRead += bytesToRead;
			}
		}

		Logger::info("特征码 '{}' 搜索完成，找到 {} 个匹配", pattern.name, pattern.results.size());

		// 选择最终结果
		selectFinalResult(pattern);
	}

	void selectFinalResult(PatternInfo& pattern) {
		if (pattern.results.empty()) {
			pattern.finalResult = std_optional<uintptr_t>();
			pattern.errorMessage = "未找到匹配的特征码";
			Logger::error("特征码 '{}' 匹配失败: 未找到匹配的特征码", pattern.name);
			return;
		}

		if (pattern.matchIndex == -1) {
			pattern.finalResult = std_optional<uintptr_t>();
			Logger::info("使用所有匹配结果");
		}
		else if (pattern.matchIndex >= 1 &&
			pattern.matchIndex <= static_cast<int>(pattern.results.size())) {
			pattern.finalResult = pattern.results[pattern.matchIndex - 1];
			Logger::info("选择第 {} 个匹配: 0x{:x}", pattern.matchIndex,
				*pattern.finalResult);
		}
		else {
			pattern.finalResult = std_optional<uintptr_t>();
			pattern.errorMessage = fmt::format("匹配索引 {} 超出范围 (1-{})", pattern.matchIndex, pattern.results.size());
			Logger::error("特征码 '{}' 匹配失败: {}", pattern.name, pattern.errorMessage);
		}
	}

	bool matchPattern(const uint8_t* data, const std::vector<uint8_t>& pattern,
		const std::vector<bool>& mask) const {
		for (size_t i = 0; i < pattern.size(); ++i) {
			if (mask[i] && data[i] != pattern[i]) {
				return false;
			}
		}
		return true;
	}

	std_optional<uintptr_t> calculateRelativeAddress(uintptr_t instructionAddress,
		int offset, int instructionLength) const {
		auto relativeOffset = readMemory<int32_t>(instructionAddress + offset);
		if (!relativeOffset) {
			return std_optional<uintptr_t>();
		}

		return instructionAddress + instructionLength + *relativeOffset + 4;
	}

	void printSearchSummary() const {
		Logger::info("\n=== 搜索结果摘要 ===");

		size_t totalMatches = 0;
		for (const auto& pattern : patterns_) {
			if (pattern.pattern == "自定义数据") {
				// 自定义数据直接显示最终结果
				if (pattern.finalResult) {
					Logger::info("{}: 0x{:X} (自定义结果)", pattern.name, *pattern.finalResult);
				}
				else {
					Logger::info("{}: 无效地址 (自定义结果)", pattern.name);
				}
			}
			else {
				Logger::info("特征码: {} -> {} 个匹配", pattern.name, pattern.results.size());

				// 显示前5个匹配地址
				size_t displayCount = std::min(static_cast<size_t>(5), pattern.results.size());
				for (size_t i = 0; i < displayCount; ++i) {
					Logger::info("  [{}] 0x{:x}", i + 1, pattern.results[i]);
				}

				if (pattern.results.size() > 5) {
					Logger::info("  ... 还有 {} 个匹配", pattern.results.size() - 5);
				}
				totalMatches += pattern.results.size();
			}
		}

		Logger::info("总计: {} 个特征码，{} 个匹配", patterns_.size(), totalMatches);
	}

	static std::string getCurrentTimeString() {
		auto now = system_clock::now();
		auto time_t = system_clock::to_time_t(now);
		auto tm = *std::localtime(&time_t);

		std::ostringstream oss;
		oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
		return oss.str();
	}
};

int main() {
	try {
		// 设置控制台编码为UTF-8，解决中文乱码问题
		SetConsoleOutputCP(CP_UTF8);
		SetConsoleCP(CP_UTF8);

		// 初始化现代化日志系统
		Logger::init();
		Logger::info("=== 现代化多特征码搜索工具 ===");

		PatternManager manager;

		// 使用现代C++的方法调用
		manager.addCustomResult("标识指针1", "0x60");
		manager.addCustomResult("标识指针2", "0x10");
		manager.addCustomResult("对局名称1", "0x120");
		manager.addCustomResult("对局名称2", "0x78");
		manager.addCustomResult("对局名称3", "0x858");
		manager.addCustomResult("对局名称4", "0x28");
		manager.addCustomResult("对局名称5", "0x0");
		manager.addCustomResult("对局名称6", "0xA8");

		manager.addCustomResult("回合偏移1", "0x8");
		manager.addCustomResult("回合偏移2", "0x20");


		manager.addCustomResult("坐标基址", "0x254");
		manager.addCustomResult("小怪偏移", "0x18");

		manager.addCustomResult("阵营偏移文本", "0x2F0");

		manager.addCustomResult("数组开始", "0x8");
		manager.addCustomResult("数组结束", "0x10");
		manager.addCustomResult("金币偏移", "0x524");
		manager.addCustomResult("是否已拿", "0x238");
		manager.addCustomResult("是否可拿牌", "0x90");
		manager.addCustomResult("商店牌价格", "0x244");
		manager.addCustomResult("商店坐标", "0x258");
		manager.addCustomResult("商店位置2", "0x268");
		manager.addCustomResult("商店位置3", "0xA70");
		manager.addCustomResult("拿牌call1文本", "0x250");
		manager.addCustomResult("拿牌偏移文本", "0x230");
		manager.addCustomResult("排名乘文本", "0x68");
		manager.addCustomResult("排名乘加文本", "0x14");
		manager.addCustomResult("排名寄存器ecx加1常量文本", "0x8");
		manager.addCustomResult("排名寄存器ecx加2常量文本", "0x70");
		manager.addCustomResult("拿当前基址位置常量文本", "0x2F0");




		manager.addPattern("数组指针", 18, 1, true, "74 0D 48 8B 06 BA 01 00 00 00 48 8B CE FF 10");
		manager.addPattern("人物基址", 3, 1, true, "48 8b 0d ?? ?? ?? ?? 48 8d 54 24 ?? 48 8b 3d ?? ?? ?? ?? 48 81 c1 ?? ?? ?? ?? 48 8b 01 ff 50 ?? 48 8d 8e");
		manager.addPattern("备战", 3, 1, true, "48 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? E8");
		manager.addPattern("云顶数据", 3, 1, true, "48 89 35 ?? ?? ?? ?? E8 ?? ?? ?? ?? 45 33 E4");
		manager.addPattern("拿牌CALL", 16, 1, true, "48 8b 0d ?? ?? ?? ?? 45 33 c9 48 83 c4");
		manager.addPattern("拿牌偏移", 3, 1, false, "48 8b 8b ?? ?? ?? ?? 48 85 c9 74 ?? 8b 93 ?? ?? ?? ?? e8 ?? ?? ?? ?? c6 83");

		manager.addPattern("名称偏移", 3, 1, false, "48 8B 8B ?? ?? 00 00 48 FF C2 48 81 FA 00 10 00 00 72 1C 48 8B 79 F8 48 83 C2 27 48 2B CF 48 8D 41 F8 48 83 F8 1F 0F 87");
		manager.addPattern("星级指针", 3, 1, false, "48 8d 91 ?? 4C 00 00 33 c9 0f b6 42 ?? 44 0f b6 42 ?? 44 8b 4c 82 ?? 44 89 0c 24 4d 85 c0 0f 84 ?? ?? ?? ?? 49 83 f8 ?? 0f 82 ?? ?? ?? ?? 48 8d 42 ?? 4a 8d 04 c0 4c 8d 14 24 4e 8d 4c c4 ?? 4c 3b d0 77 ?? 4c 3b ca 0f 83 ?? ?? ?? ?? 4d 8b d8 48 89 5c 24 ?? 49 83 e3 ?? 48 89 7c 24 ?? 66 0f 6f 15 ?? ?? ?? ?? 48 8d 04 24 4c 8d 54 24 ?? 48 2b c2 4c 2b d2 48 8d 1c 24 48 2b da 4c 8d 4a ?? f3 42 0f 6f 44 08 ?? 48 83 c1 ?? f3 41 0f 6f 49 ?? 4d 8d 49 ?? 0f 55 ca 0f 57 c8 f3 42 0f 7f 4c 08 ??");
		manager.addCustomResult("星级指针2", "0x17");

		manager.addPattern("对局基址", 38, 1, true, "75 1A 48 8D 4F");
		manager.addPattern("小怪基址", 37, 1, true, "48 ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 83 78 ?? ?? 0F 85 ?? ?? ?? ??");
		manager.addPattern("矩阵基址", 3, 1, true, "48 8D 0D ?? ?? ?? ?? 0F 10 00");

		manager.addPattern("是否已满", 3, 1, true, "48 8B 1D ?? ?? ?? ?? 48 85 DB 0f 84 ** ** ** ** ** 8B ** 10");
		manager.addPattern("总人数基址", 3, 1, true, "“48 8B 0D ?? ?? ?? ?? 48 8D 55 ?? E8 ?? ?? ?? ?? 0F B6");



		manager.addPattern("拿牌call1", -4, 1, false, "48 8b 0d ?? ?? ?? ?? 45 33 c9 48 83 c4");
		manager.addPattern("坐标地址", 3, 1, false, "48 81 C2 ?? 02 00 00 48 8B D9");
		manager.addPattern("阵营指针", 2, 1, false, "FF 90 ?? ?? ?? ?? 48 83 C3 08 49 3B DE 0F 85 ?? ?? ?? ?? 48");
		manager.addPattern("血量地址", 3, 1, false, "49 8D 8F ?? 10 00 00 F3 41 0F 11 87 ?? 0F 00 00 33 C0");
		manager.addPattern("已满偏移", 20, 1, false, "F3 0F 11 87 ?? ?? 00 00 C7 87");
        


		if (!manager.initialize(L"League of Legends.exe")) {
			Logger::error("初始化失败，程序退出");
			system("pause");
			return 1;
		}

		manager.searchAllPatterns();

		// 输出JSON格式结果
		Logger::info("\n=== JSON格式结果 ===");
		std::cout << manager.toJson() << std::endl;

		// 保存结果到JSON文件
		auto now = system_clock::now();
		auto time_t = system_clock::to_time_t(now);
		auto tm = *std::localtime(&time_t);

		std::ostringstream filename;
		filename << "pattern_results_" << ".json";
		manager.saveToJsonFile(filename.str());

		// 展示最终结果摘要
		Logger::info("\n=== 最终结果摘要 ===");
		for (const auto& pattern : manager.getPatterns()) {
			if (pattern.pattern == "自定义数据") {
				// 自定义数据直接显示结果
				if (pattern.finalResult) {
					Logger::info("{}: 0x{:X} (自定义结果)",
						pattern.name,
						*pattern.finalResult);
				}
				else {
					Logger::info("{}: 无效地址 (自定义结果)", pattern.name);
				}
			}
			else {
				if (pattern.finalResult) {
					Logger::info("{}: 0x{:X} (第{}个匹配，共{}个)",
						pattern.name,
						*pattern.finalResult,
						pattern.matchIndex,
						pattern.results.size());
				}
				else if (pattern.matchIndex == -1 && !pattern.results.empty()) {
					Logger::info("{}: 使用所有{}个匹配",
						pattern.name,
						pattern.results.size());
				}
				else {
					Logger::info("{}: 未找到有效结果", pattern.name);
				}
			}
		}

		Logger::info("\n搜索完成，结果已保存到: {}", filename.str());
		Logger::info("按任意键退出...");
		system("pause");

	}
	catch (const std::exception& e) {
		Logger::error("程序发生异常: {}", e.what());
		system("pause");
		return 1;
	}

	return 0;
}

/*
推荐的开源库和改进建议：

1. JSON处理: nlohmann/json
   - 替换手动JSON字符串拼接
   - 类型安全，易于使用
   - 安装: vcpkg install nlohmann-json

2. 日志库: spdlog
   - 高性能异步日志
   - 多种输出格式和目标
   - 安装: vcpkg install spdlog

3. 格式化库: fmt
   - 类型安全的字符串格式化
   - C++20 std::format的基础
   - 安装: vcpkg install fmt

4. 范围库: range-v3
   - 函数式编程风格
   - 更简洁的算法操作
   - 安装: vcpkg install range-v3

5. 命令行参数解析: CLI11
   - 现代C++命令行解析
   - 安装: vcpkg install cli11

6. 配置文件: toml++
   - 现代配置文件格式
   - 安装: vcpkg install tomlplusplus

使用vcpkg安装依赖:
```bash
vcpkg install nlohmann-json spdlog fmt range-v3 cli11 tomlplusplus
```

主要改进:
- 使用RAII管理资源
- 现代C++特性 (auto, std::optional, 智能指针)
- 异常安全
- 类型安全
- 更好的错误处理
- 模板化的内存读取
- 标准库算法
*/
