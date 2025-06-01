#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <filesystem>
#include <string>
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <map>
#include <Aclapi.h>

namespace fs = std::filesystem;

enum class Lang { TR, EN };
Lang systemLang = Lang::EN;

std::map<std::string, std::string> tr = {
    {"ask", "Sadece System olaylarini filtrele.\n1 - Evet\n2 - Hayir\nSeciminiz: "},
    {"invalid", "Gecersiz secim, varsayilan olarak Hayir secildi.\n"},
    {"desktop_not_found", "Masaustu yolu bulunamadi."},
    {"report_fail", "Rapor dosyasi olusturulamadi."},
    {"copy_success", " dosyasi kopyalandi."},
    {"copy_fail", "Kopyalama hatasi: "},
    {"log_copy", " log dosyasi kopyalandi."},
    {"log_copy_fail", "Log kopyalama hatasi: "},
    {"log_missing", " bulunamadi."},
    {"log_filter_fail", " loglari filtrelenirken hata olustu."},
    {"log_filter_ok", " log filtrelenip dosyasina kaydedildi."},
    {"report_summary", ".dmp dosyalari DumpFinder klasorune kopyalandi.\n"},
    {"report_with_logs", "System log dosyasi ve kritik olaylar filtrelendi.\n"},
    {"report_complete", "Islem tamamlandi. Rapor olusturuldu: "}
};

std::map<std::string, std::string> en = {
    {"ask", "Only filter System logs?\n1 - Yes\n2 - No\nYour choice: "},
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
    {"report_summary", "Dump files copied to DumpFinder folder.\n"},
    {"report_with_logs", "System log copied and critical events filtered.\n"},
    {"report_complete", "Operation completed. Report created: "}
};

std::string msg(const std::string& key) {
    return systemLang == Lang::TR ? tr[key] : en[key];
}

Lang DetectSystemLanguage() {
    LANGID langId = GetUserDefaultUILanguage();
    return (PRIMARYLANGID(langId) == LANG_TURKISH) ? Lang::TR : Lang::EN;
}

void SetFullControlPermissions(const std::string& filePath) {
    DWORD result = SetNamedSecurityInfoA(
        const_cast<char*>(filePath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL
    );
    if (result != ERROR_SUCCESS) {
        std::cerr << "Permission error: " << result << std::endl;
    }
}

std::string GetNewDumpFolderName(const fs::path& basePath) {
    int index = 1;
    fs::path newPath;
    do {
        newPath = basePath.string() + "_" + std::to_string(index++);
    } while (fs::exists(newPath));
    return newPath.string();
}

int main() {
    systemLang = DetectSystemLanguage();

    int choice = 0;
    std::cout << msg("ask");
    std::cin >> choice;
    if (choice != 1 && choice != 2) {
        std::cout << msg("invalid");
        choice = 2;
    }

    char* sysRootCStr;
    size_t size;
    _dupenv_s(&sysRootCStr, &size, "SystemRoot");
    fs::path systemRoot = sysRootCStr ? fs::path(sysRootCStr) : fs::path("C:\\Windows");
    free(sysRootCStr);

    char desktopPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath) != S_OK) {
        std::cerr << msg("desktop_not_found") << std::endl;
        return 1;
    }

    fs::path baseFolder = fs::path(desktopPath) / "DumpFinder";
    fs::path dumpFolder = fs::exists(baseFolder) ? GetNewDumpFolderName(baseFolder) : baseFolder;
    fs::path logFolder = dumpFolder / "DmpGunluk";
    fs::path reportFilePath = dumpFolder / "Rapor.txt";

    try {
        fs::create_directories(dumpFolder);
        if (choice == 1) fs::create_directories(logFolder);

        std::ofstream reportFile(reportFilePath);
        if (!reportFile.is_open()) {
            std::cerr << msg("report_fail") << std::endl;
            return 1;
        }

        std::vector<fs::path> dumpPaths = {
            systemRoot / "Minidumps",
            systemRoot / "Minidump",
            systemRoot / "MEMORY.dmp"
        };

        for (const auto& dumpPath : dumpPaths) {
            if (fs::exists(dumpPath)) {
                if (fs::is_directory(dumpPath)) {
                    for (const auto& entry : fs::directory_iterator(dumpPath)) {
                        if (entry.path().extension() == ".dmp") {
                            try {
                                SetFullControlPermissions(entry.path().string());
                                fs::copy_file(entry.path(), dumpFolder / entry.path().filename(), fs::copy_options::overwrite_existing);
                                std::cout << entry.path().filename().string() << msg("copy_success") << std::endl;
                                reportFile << entry.path().filename().string() << " copied." << std::endl;
                            }
                            catch (const std::exception& e) {
                                std::cerr << msg("copy_fail") << e.what() << std::endl;
                            }
                        }
                    }
                }
                else if (dumpPath.extension() == ".dmp") {
                    try {
                        SetFullControlPermissions(dumpPath.string());
                        fs::copy_file(dumpPath, dumpFolder / dumpPath.filename(), fs::copy_options::overwrite_existing);
                        std::cout << dumpPath.filename().string() << msg("copy_success") << std::endl;
                        reportFile << dumpPath.filename().string() << " copied." << std::endl;
                    }
                    catch (const std::exception& e) {
                        std::cerr << msg("copy_fail") << e.what() << std::endl;
                    }
                }
            }
            else {
                std::cerr << dumpPath.string() << msg("log_missing") << std::endl;
            }
        }

        if (choice == 1) {
            fs::path systemEvtx = systemRoot / R"(System32\winevt\Logs\System.evtx)";
            if (fs::exists(systemEvtx)) {
                try {
                    fs::copy_file(systemEvtx, logFolder / "System.evtx", fs::copy_options::overwrite_existing);
                    std::cout << "System.evtx" << msg("log_copy") << std::endl;
                    reportFile << "System.evtx copied." << std::endl;
                }
                catch (const std::exception& e) {
                    std::cerr << msg("log_copy_fail") << e.what() << std::endl;
                }

                std::string outFile = (logFolder / "System_Filtered.txt").string();
                std::string cmd = "wevtutil qe System /q:\"*[System[(Level=1 or Level=2 or Level=3)]]\" /f:xml > \"" + outFile + "\"";
                int ret = system(cmd.c_str());
                if (ret != 0) {
                    std::cerr << "System" << msg("log_filter_fail") << std::endl;
                }
                else {
                    std::cout << "System" << msg("log_filter_ok") << outFile << std::endl;
                    reportFile << "System filtered -> " << outFile << std::endl;
                }
            }
            else {
                std::cerr << "System.evtx" << msg("log_missing") << std::endl;
            }
        }
        else {
            reportFile << (systemLang == Lang::TR ? "Sadece dump dosyalari kopyalandi." : "Only dump files copied.") << std::endl;
        }

        reportFile << "\n" << msg("report_summary");
        if (choice == 1) reportFile << msg("report_with_logs");

        reportFile.close();
        std::cout << "\n" << msg("report_complete") << reportFilePath.string() << std::endl;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Hata: " << e.what() << std::endl;
        return 1;
    }

    system("pause");
    return 0;
}
