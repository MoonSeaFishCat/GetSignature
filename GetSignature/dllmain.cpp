#include <iostream>
#include <string>
#include <sodium.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

using json = nlohmann::json;

// 全局静态变量，用于确保 libsodium 只初始化一次
static bool sodiumInitialized = false;

// 辅助函数：将字节数组转换为十六进制字符串
std::string bytesToHex(const unsigned char* bytes, int len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

// 记录日志到桌面上的日志文件
void logError(const std::string& errorMessage) {
    try {
        char* userProfilePath = nullptr;
        size_t len = 0;

        if (_dupenv_s(&userProfilePath, &len, "USERPROFILE") != 0 || userProfilePath == nullptr) {
            throw std::runtime_error("Failed to get USERPROFILE environment variable.");
        }

        std::string desktopPath = (std::filesystem::path(userProfilePath) / "Desktop" / "signature_log.txt").string();

        free(userProfilePath);

        std::ofstream logFile(desktopPath, std::ios_base::app);
        if (logFile.is_open()) {
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            struct tm timeInfo;
            localtime_s(&timeInfo, &now);
            logFile << std::put_time(&timeInfo, "%Y-%m-%d %H:%M:%S") << " - " << errorMessage << std::endl;
            logFile.close();
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to write log: " << e.what() << std::endl;
    }
}

// 使用弹窗显示错误信息（Windows 平台）
void showError(const std::string& errorMessage) {
#ifdef _WIN32
    MessageBoxA(nullptr, errorMessage.c_str(), "Error", MB_ICONERROR | MB_OK);
#else
    std::cerr << errorMessage << std::endl;
#endif
}

// 生成签名的函数，返回十六进制签名字符串
std::string getSignatureImpl(const std::string& plainToken, const std::string& eventTs, const std::string& botSecret) {
    if (!sodiumInitialized) {
        throw std::runtime_error("libsodium is not initialized.");
    }

    if (plainToken.empty() || eventTs.empty() || botSecret.empty()) {
        throw std::invalid_argument("One or more input parameters are empty.");
    }

    // 确保种子长度符合要求
    std::string seed = botSecret;
    while (seed.length() < crypto_sign_SEEDBYTES) {
        seed += seed;
    }
    seed = seed.substr(0, crypto_sign_SEEDBYTES);

    // 生成密钥对
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];

    if (crypto_sign_seed_keypair(pk, sk, reinterpret_cast<const unsigned char*>(seed.c_str())) != 0) {
        throw std::runtime_error("Failed to generate key pair.");
    }

    // 组合消息
    std::stringstream msgStream;
    msgStream << eventTs << plainToken;
    std::string message = msgStream.str();

    // 创建签名
    unsigned char signature[crypto_sign_BYTES];
    if (crypto_sign_detached(signature, nullptr, reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), sk) != 0) {
        throw std::runtime_error("Failed to create signature.");
    }

    // 返回签名的十六进制表示
    return bytesToHex(signature, crypto_sign_BYTES);
}

// DLL 入口点
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        if (sodium_init() >= 0) {
            sodiumInitialized = true;
        }
        else {
            MessageBoxA(nullptr, "Failed to initialize libsodium.", "Error", MB_ICONERROR | MB_OK);
            return FALSE;  // 初始化失败，阻止 DLL 加载
        }
        break;
    case DLL_PROCESS_DETACH:
        // 可以在这里做清理工作
        break;
    }
    return TRUE;
}

extern "C" {
    // 导出函数：返回包含 plain_token 和 signature 的 JSON 字符串
    EXPORT const char* GetSignature(const char* plainToken, const char* eventTs, const char* botSecret) {
        try {
            // 获取签名
            std::string signature = getSignatureImpl(std::string(plainToken), std::string(eventTs), std::string(botSecret));

            // 创建包含 plain_token 和 signature 的 JSON 对象
            json resultJson;
            resultJson["plain_token"] = plainToken;
            resultJson["signature"] = signature;

            // 将 JSON 转为字符串
            std::string resultStr = resultJson.dump();

            // 分配内存并返回
            char* result = new char[resultStr.length() + 1];
            strcpy_s(result, resultStr.length() + 1, resultStr.c_str());
            return result;
        }
        catch (const std::exception& e) {
            std::string errorMsg = "Error in GetSignature: " + std::string(e.what());
            showError(errorMsg);
            logError(errorMsg);
            return nullptr;
        }
        catch (...) {
            std::string errorMsg = "An unknown error occurred in GetSignature.";
            showError(errorMsg);
            logError(errorMsg);
            return nullptr;
        }
    }

    // 提供释放内存的函数，供调用方使用
    EXPORT void FreeSignature(const char* signature) {
        if (signature) {
            delete[] signature;
        }
    }
}