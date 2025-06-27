
#include <iostream>
#include "./mb.h"
#include <stdio.h>
#include <string>
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

#pragma comment(lib, "zlib.lib")  // 链接zlib库
#pragma comment(lib, "libcurl.lib") // 链接libcurl库

// 全局变量用于存储原始窗口过程和WebView
WNDPROC g_originalWndProc = nullptr;
mbWebView g_mbView = 0;  // mbWebView是long long类型，使用0初始化

template<typename... Args>
void logInfoF(const char* format, Args... args);

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
            } else {
                logInfoF("读取进程内存失败，错误代码: %d", GetLastError());
            }
            
            // 读取4字节整数 (int)
            int intValue = 0;
            if (ReadProcessMemory(hProcess, baseAddress, &intValue, sizeof(intValue), &bytesRead)) {
                logInfoF("成功读取4字节整数: 0x%X (%d)，读取字节数: %zu", intValue, intValue, bytesRead);
            } else {
                logInfoF("读取4字节整数失败，错误代码: %d", GetLastError());
            }
            
            // 读取2字节短整数 (short)
            short shortValue = 0;
            if (ReadProcessMemory(hProcess, baseAddress, &shortValue, sizeof(shortValue), &bytesRead)) {
                logInfoF("成功读取2字节短整数: 0x%X (%d)，读取字节数: %zu", shortValue, shortValue, bytesRead);
            } else {
                logInfoF("读取2字节短整数失败，错误代码: %d", GetLastError());
            }
            
            // 读取1字节 (byte)
            unsigned char byteValue = 0;
            if (ReadProcessMemory(hProcess, baseAddress, &byteValue, sizeof(byteValue), &bytesRead)) {
                logInfoF("成功读取1字节: 0x%02X (%d)，读取字节数: %zu", byteValue, byteValue, bytesRead);
            } else {
                logInfoF("读取1字节失败，错误代码: %d", GetLastError());
            }
            
            // 读取4字节浮点数 (float)
            float floatValue = 0.0f;
            if (ReadProcessMemory(hProcess, baseAddress, &floatValue, sizeof(floatValue), &bytesRead)) {
                logInfoF("成功读取4字节浮点数: %f，读取字节数: %zu", floatValue, bytesRead);
            } else {
                logInfoF("读取4字节浮点数失败，错误代码: %d", GetLastError());
            }
            
            // 读取8字节双精度浮点数 (double)
            double doubleValue = 0.0;
            if (ReadProcessMemory(hProcess, baseAddress, &doubleValue, sizeof(doubleValue), &bytesRead)) {
                logInfoF("成功读取8字节双精度浮点数: %lf，读取字节数: %zu", doubleValue, bytesRead);
            } else {
                logInfoF("读取8字节双精度浮点数失败，错误代码: %d", GetLastError());
            }
            
            // 读取16字节数据块
            unsigned char buffer[16] = {0};
            if (ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(buffer), &bytesRead)) {
                logInfoF("成功读取16字节数据块，读取字节数: %zu", bytesRead);
                // 以十六进制格式输出前8个字节
                logInfoF("前8字节十六进制: %02X %02X %02X %02X %02X %02X %02X %02X", 
                    buffer[0], buffer[1], buffer[2], buffer[3], 
                    buffer[4], buffer[5], buffer[6], buffer[7]);
            } else {
                logInfoF("读取16字节数据块失败，错误代码: %d", GetLastError());
            }
            
            // 读取指针值 (在64位系统上是8字节)
            void* pointerValue = nullptr;
            if (ReadProcessMemory(hProcess, baseAddress, &pointerValue, sizeof(pointerValue), &bytesRead)) {
                logInfoF("成功读取指针值: 0x%p，读取字节数: %zu", pointerValue, bytesRead);
            } else {
                logInfoF("读取指针值失败，错误代码: %d", GetLastError());
            }
            
            // 尝试读取不同偏移位置的数据
            logInfoF("=== 尝试读取不同偏移位置的数据 ===");
            for (int offset = 0; offset < 64; offset += 8) {
                long long offsetValue = 0;
                LPVOID offsetAddress = (LPVOID)((BYTE*)baseAddress + offset);
                if (ReadProcessMemory(hProcess, offsetAddress, &offsetValue, sizeof(offsetValue), &bytesRead)) {
                    logInfoF("偏移+%d: 0x%llX (%lld)", offset, offsetValue, offsetValue);
                } else {
                    logInfoF("偏移+%d: 读取失败，错误代码: %d", offset, GetLastError());
                }
            }
        } else {
            logInfoF("获取模块信息失败，错误代码: %d", GetLastError());
        }
    } else {
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
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    std::string *response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

// libcurl文件写入回调函数
static size_t WriteFileCallback(void *contents, size_t size, size_t nmemb, FILE *file) {
    return fwrite(contents, size, nmemb, file);
}



// 使用libcurl下载文件
// 使用libcurl下载文件
CURLcode downloadFileWithCurl(const std::string& url, const std::string& outputPath, int taskId) {
    CURL *curl;
    CURLcode res;
    FILE *file;
    
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
                } else {
                    // 没有捕获组的情况
                    imageUrl = fullMatch;
                }
                
                // 从URL中提取文件名
                size_t lastSlash = imageUrl.find_last_of('/');
                std::string fileName;
                if (lastSlash != std::string::npos && lastSlash < imageUrl.length() - 1) {
                    fileName = imageUrl.substr(lastSlash + 1);
                    //logInfoF("从URL提取文件名: %s -> %s", imageUrl.c_str(), fileName.c_str());
                } else {
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
                } else {
                    relativePath = "./img/downloaded/" + fileName;
                }
                
                // 根据原始匹配的格式构建替换字符串
                std::string replacement;
                if (fullMatch.front() == '"' && fullMatch.back() == '"') {
                    replacement = "\"" + relativePath + "\"";
                } else if (fullMatch.front() == '\'' && fullMatch.back() == '\'') {
                    replacement = "'" + relativePath + "'";
                } else {
                    replacement = relativePath;
                }
                
                replacements.push_back({fullMatch, replacement});
            }
            
            // 执行替换
            for (const auto& replacement : replacements) {
                size_t pos = 0;
                while ((pos = result.find(replacement.first, pos)) != std::string::npos) {
                    result.replace(pos, replacement.first.length(), replacement.second);
                    pos += replacement.second.length();
                }
            }
            
        } catch (const std::exception& e) {
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
                } else {
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
                } else {
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
                } else {
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
void logOutput( const std::string& message) {
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
    char outbuffer[32768];
    std::string decompressed;

    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (decompressed.size() < zs.total_out) {
            decompressed.append(outbuffer, zs.total_out - decompressed.size());
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
    CURL *curl;
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

void onJsQuery(mbWebView webView, void* param,mbJsExecState es, int64_t queryId,int customMsg, const utf8* request) {
    // 判断请求是否是 "getdata"
    if (strcmp((const char*)request, "getdata") == 0) {

        
       // 从HTTP接口获取数据
       std::string jsonData = httpGet("http://127.0.0.1:3000/data");
    
       if (jsonData.find("ERROR:") == 0) {
        logInfoF("HTTP请求失败: %s ",jsonData.c_str());
           mbResponseQuery(webView, queryId, customMsg, jsonData.c_str());
           return;
       }
       downloadPngImagesFromJson(jsonData);

        // 将图片URL转换为相对路径
        std::string modifiedJsonData = convertImageUrlsToRelativePaths(jsonData);

        // 返回给 JS
        mbResponseQuery(webView, queryId, customMsg, modifiedJsonData.c_str());
    }if (strcmp((const char*)request, "xunhuan") == 0) {
        logInfoF("循环过来了");
        testProcessRead(); // 调用进程读取测试函数
        std::string modifiedJsonData = "我知道了";
        
        mbResponseQuery(webView, queryId, customMsg, modifiedJsonData.c_str());
    }
}



int main()
{
    
    
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
        } else {
            logInfoF("子类化miniblink窗口失败，错误码: %d", GetLastError());
        }
    } else {
        logInfoF("无法获取miniblink窗口句柄");
    }

    mbOnJsQuery(mbView, onJsQuery,NULL);


    std::wstring vuePath = std::wstring(currentDir) + L"\\vuejianjie\\index.html";
    std::string vuePathUtf8(vuePath.begin(), vuePath.end());
    
    mbLoadURL(mbView, vuePathUtf8.c_str());
   
    mbShowWindow(mbView, true);

    mbRunMessageLoop();
    
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
