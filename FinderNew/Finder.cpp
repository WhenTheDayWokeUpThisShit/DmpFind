#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <filesystem>
#include <string>
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <regex>
#include <Aclapi.h>
#include <AccCtrl.h>
#include <map>

namespace fs = std::filesystem;

enum class Lang { TR, EN };

Lang systemLang = Lang::EN;

// Lang MAP
std::map<std::string, std::string> tr = {
    {"ask", "Olay raporlari eklensin mi?\n1 - Evet\n2 - Hayir\nSeciminiz: "},
    {"invalid", "Gecersiz secim, varsayilan olarak Hayir seçildi.\n"},
    {"desktop_not_found", "Masaustu yolu bulunamadi."},
    {"report_fail", "Rapor dosyasý olusturulamadý."},
    {"copy_success", " dosyasi kopyalandi."},
    {"copy_fail", "Kopyalama hatasi: "},
    {"log_copy", " log dosyasi kopyalandi."},
    {"log_copy_fail", "Log kopyalama hatasi: "},
    {"log_missing", " bulunamadi."},
    {"log_filter_fail", " loglari filtrelenirken hata olustu."},
    {"log_filter_ok", " loglari filtrelenip dosyasina kaydedildi."},
    {"report_summary", "Taranan .dmp dosyalari DumpFinder klasorune kopyalanmýstir.\n"},
    {"report_with_logs", "Ayrýca Application, System ve Security log dosyalari DmpGunluk klasörüne kopyalanmýstir ve kritik olaylar filtrelenmistir.(Beta)\n"},
    {"report_complete", "Tum islemler tamamlandi. Rapor olusturuldu: "}
};

std::map<std::string, std::string> en = {
    {"ask", "Include event logs?\n1 - Yes\n2 - No\nYour choice: "},
    {"invalid", "Invalid selection, defaulting to No.\n"},
    {"desktop_not_found", "Desktop path could not be found."},
    {"report_fail", "Failed to create report file."},
    {"copy_success", " file copied."},
    {"copy_fail", "Copy error: "},
    {"log_copy", " log file copied."},
    {"log_copy_fail", "Log copy error: "},
    {"log_missing", " not found."},
    {"log_filter_fail", " log filtering failed."},
    {"log_filter_ok", " log filtered and saved to file."},
    {"report_summary", "Scanned .dmp files copied to DumpFinder folder.\n"},
    {"report_with_logs", "Also copied Application, System, and Security logs and filtered critical events. (Beta)\n"},
    {"report_complete", "All operations completed. Report created: "}
};

std::string msg(const std::string& key) {
    return systemLang == Lang::TR ? tr[key] : en[key];
}

Lang DetectSystemLanguage() {
    LANGID langId = GetUserDefaultUILanguage();
    if (PRIMARYLANGID(langId) == LANG_TURKISH) {
        return Lang::TR;
    }
    return Lang::EN;
}

void SetFullControlPermissions(const std::string& filePath) {
    DWORD result = SetNamedSecurityInfoA(
        const_cast<char*>(filePath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (result != ERROR_SUCCESS) {
        std::cerr << "Permission error: " << result << std::endl;
    }
}

std::string GetNewDumpFolderName(const std::string& basePath) {
    int index = 1;
    std::string folderName;
    do {
        folderName = basePath + "_" + std::to_string(index);
        ++index;
    } while (fs::exists(folderName));
    return folderName;
}

int main() {
    systemLang = DetectSystemLanguage();

    int secim = 0;
    std::cout << msg("ask");
    std::cin >> secim;
    if (secim != 1 && secim != 2) {
        std::cout << msg("invalid");
        secim = 2;
    }

    std::string paths[] = {
        "%SystemRoot%\\Minidumps",
        "%SystemRoot%\\Minidump",
        "%SystemRoot%\\MEMORY.dmp"
    };

    char* systemRootCStr;
    size_t size;
    _dupenv_s(&systemRootCStr, &size, "SystemRoot");
    std::string systemRoot(systemRootCStr ? systemRootCStr : "");
    if (systemRootCStr) free(systemRootCStr);
    if (!systemRoot.empty() && systemRoot.back() != '\\') systemRoot += '\\';

    char desktopPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath) != S_OK) {
        std::cerr << msg("desktop_not_found") << std::endl;
        return 1;
    }

    std::string baseDumpFolder = std::string(desktopPath) + "\\DumpFinder";
    std::string destinationFolder = fs::exists(baseDumpFolder) ? GetNewDumpFolderName(baseDumpFolder) : baseDumpFolder;
    std::string logFolder = destinationFolder + "\\DmpGunluk";
    std::string reportFilePath = destinationFolder + "\\Rapor.txt";
    std::ofstream reportFile;

    try {
        fs::create_directory(destinationFolder);
        if (secim == 1) fs::create_directory(logFolder);

        reportFile.open(reportFilePath, std::ios::out);
        if (!reportFile.is_open()) {
            std::cerr << msg("report_fail") << std::endl;
            return 1;
        }

        for (auto& path : paths) {
            std::string fullPath = std::regex_replace(path, std::regex("%SystemRoot%"), systemRoot);
            if (fs::exists(fullPath)) {
                if (fs::is_directory(fullPath)) {
                    for (const auto& entry : fs::directory_iterator(fullPath)) {
                        if (entry.path().extension() == ".dmp") {
                            try {
                                SetFullControlPermissions(entry.path().string());
                                auto dest = destinationFolder + "\\" + entry.path().filename().string();
                                fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing);
                                std::cout << entry.path().filename().string() << msg("copy_success") << std::endl;
                                reportFile << entry.path().filename().string() << " copied." << std::endl;
                            }
                            catch (const std::exception& e) {
                                std::cerr << msg("copy_fail") << e.what() << std::endl;
                            }
                        }
                    }
                }
                else if (fs::path(fullPath).extension() == ".dmp") {
                    try {
                        SetFullControlPermissions(fullPath);
                        auto dest = destinationFolder + "\\" + fs::path(fullPath).filename().string();
                        fs::copy_file(fullPath, dest, fs::copy_options::overwrite_existing);
                        std::cout << fs::path(fullPath).filename().string() << msg("copy_success") << std::endl;
                        reportFile << fs::path(fullPath).filename().string() << " copied." << std::endl;
                    }
                    catch (const std::exception& e) {
                        std::cerr << msg("copy_fail") << e.what() << std::endl;
                    }
                }
            }
            else {
                std::cerr << fullPath << msg("log_missing") << std::endl;
            }
        }

        if (secim == 1) {
            std::string eventLogPath = systemRoot + "System32\\winevt\\Logs\\";
            std::string evtxLogs[] = { "Application.evtx", "System.evtx", "Security.evtx" };

            for (const auto& log : evtxLogs) {
                std::string src = eventLogPath + log;
                if (fs::exists(src)) {
                    try {
                        fs::copy_file(src, logFolder + "\\" + log, fs::copy_options::overwrite_existing);
                        std::cout << log << msg("log_copy") << std::endl;
                        reportFile << log << " copied." << std::endl;
                    }
                    catch (const std::exception& e) {
                        std::cerr << msg("log_copy_fail") << e.what() << std::endl;
                    }
                }
                else {
                    std::cerr << log << msg("log_missing") << std::endl;
                }
            }

            std::string logs[] = { "Application", "System", "Security" };
            for (const auto& log : logs) {
                std::string outFile = logFolder + "\\" + log + "_Filtered.txt";
                std::string cmd = "wevtutil qe " + log + " /q:\"*[System[(Level=1 or Level=2 or Level=3)]]\" /f:xml > \"" + outFile + "\"";
                int ret = system(cmd.c_str());
                if (ret != 0) {
                    std::cerr << log << msg("log_filter_fail") << std::endl;
                }
                else {
                    std::cout << log << msg("log_filter_ok") << outFile << std::endl;
                    reportFile << log << " filtered -> " << outFile << std::endl;
                }
            }
        }
        else {
            reportFile << (systemLang == Lang::TR ? "Olay raporlari eklenmedi, sadece dump dosyalarý kopyalandi." : "No event logs included, only dump files copied.") << std::endl;
        }

        reportFile << "\n" << msg("report_summary");
        if (secim == 1)
            reportFile << msg("report_with_logs");

        reportFile.close();
        std::cout << "\n" << msg("report_complete") << reportFilePath << std::endl;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Hata: " << e.what() << std::endl;
        if (reportFile.is_open()) reportFile.close();
        return 1;
    }

    system("pause");
    return 0;
}
