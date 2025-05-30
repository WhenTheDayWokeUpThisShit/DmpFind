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

namespace fs = std::filesystem;

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
        std::cerr << "Erisim izinleri ayarlanamadi: " << result << std::endl;
    }
}

// Finder_1, Finder_2
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
    // Choose?
    int secim = 0;
    std::cout << "Olay raporlari eklensin mi?\n1 - Evet\n2 - Hayir\nSeciminiz: ";
    std::cin >> secim;
    if (secim != 1 && secim != 2) {
        std::cout << "Gecersiz secim, varsayilan olarak Hayir seçildi.\n";
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

    if (!systemRoot.empty() && systemRoot.back() != '\\') {
        systemRoot += '\\';
    }

    char desktopPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath) != S_OK) {
        std::cerr << "Masaustu yolu bulunamadi." << std::endl;
        return 1;
    }

    // Finder_1, Finder_2
    std::string baseDumpFolder = std::string(desktopPath) + "\\DumpFinder";
    std::string destinationFolder = baseDumpFolder;
    if (fs::exists(destinationFolder)) {
        destinationFolder = GetNewDumpFolderName(baseDumpFolder);
    }

    std::string logFolder = destinationFolder + "\\DmpGunluk";
    std::string reportFilePath = destinationFolder + "\\Rapor.txt";
    std::ofstream reportFile;

    try {
        if (!fs::exists(destinationFolder))
            fs::create_directory(destinationFolder);

        if (secim == 1) { // only LOG
            if (!fs::exists(logFolder))
                fs::create_directory(logFolder);
        }

        reportFile.open(reportFilePath, std::ios::out);
        if (!reportFile.is_open()) {
            std::cerr << "Rapor dosyasý oluþturulamadý." << std::endl;
            return 1;
        }

        for (auto& path : paths) {
            std::string fullPath = std::regex_replace(path, std::regex("%SystemRoot%"), systemRoot);

            if (fs::exists(fullPath)) {
                if (fs::is_directory(fullPath)) {
                    for (const auto& entry : fs::directory_iterator(fullPath)) {
                        if (entry.path().extension() == ".dmp") {
                            try {
                                std::string filename = entry.path().filename().string();
                                SetFullControlPermissions(entry.path().string());

                                std::string destinationFilePath = destinationFolder + "\\" + filename;
                                fs::copy_file(entry.path(), destinationFilePath, fs::copy_options::overwrite_existing);

                                reportFile << filename << " dosyasi bulundu (Minidump klasöründe)." << std::endl;
                                std::cout << filename << " dosyasi kopyalandi." << std::endl;
                            }
                            catch (const std::exception& e) {
                                std::cerr << "Kopyalama hatasi: " << e.what() << std::endl;
                            }
                        }
                    }
                }
                else {
                    if (fs::path(fullPath).extension() == ".dmp") {
                        try {
                            SetFullControlPermissions(fullPath);
                            std::string actualFileName = fs::path(fullPath).filename().string();
                            std::string destinationFilePath = destinationFolder + "\\" + actualFileName;
                            fs::copy_file(fullPath, destinationFilePath, fs::copy_options::overwrite_existing);

                            reportFile << actualFileName << " dosyasi bulundu (Muhtemelen MEMORY.DMP dosyasýdýr)." << std::endl;
                            std::cout << actualFileName << " dosyasi kopyalandý." << std::endl;
                        }
                        catch (const std::exception& e) {
                            std::cerr << "Kopyalama hatasi: " << e.what() << std::endl;
                        }
                    }
                }
            }
            else {
                std::cerr << fullPath << " yolu bulunamadý." << std::endl;
            }
        }

        if (secim == 1) { // Log
            std::string eventLogPath = systemRoot + "System32\\winevt\\Logs\\";

            // App, Sys, Sec logs
            std::string evtxLogFiles[] = { "Application.evtx", "System.evtx", "Security.evtx" };

            for (const auto& logName : evtxLogFiles) {
                std::string fullLogPath = eventLogPath + logName;
                if (fs::exists(fullLogPath)) {
                    try {
                        std::string destinationLogPath = logFolder + "\\" + logName;
                        fs::copy_file(fullLogPath, destinationLogPath, fs::copy_options::overwrite_existing);

                        reportFile << logName << " log dosyasi kopyalandi (DmpGunluk klasorune)." << std::endl;
                        std::cout << logName << " log dosyasi kopyalandi." << std::endl;
                    }
                    catch (const std::exception& e) {
                        std::cerr << "Log kopyalama hatasi: " << e.what() << std::endl;
                    }
                }
                else {
                    std::cerr << logName << " bulunamadi." << std::endl;
                }
            }

            // Not sure
            std::string logs[] = { "Application", "System", "Security" };
            for (const auto& logName : logs) {
                std::string outputFile = logFolder + "\\" + logName + "_Filtered.txt";
                std::string command = "wevtutil qe " + logName + " /q:\"*[System[(Level=1 or Level=2 or Level=3)]]\" /f:text > \"" + outputFile + "\"";

                int ret = system(command.c_str());
                if (ret != 0) {
                    std::cerr << logName << " loglari filtrelenirken hata olustu." << std::endl;
                }
                else {
                    reportFile << logName << " loglari filtrelenip " << outputFile << " dosyasina kaydedildi." << std::endl;
                    std::cout << logName << " loglari filtrelenip " << outputFile << " dosyasina kaydedildi." << std::endl;
                }
            }
        }
        else {
            reportFile << "Olay raporlarý eklenmedi, sadece dump dosyalarý kopyalandi." << std::endl;
        }

        reportFile << "\nTaranan .dmp dosyalari DumpFinder klasorune kopyalanmýstir.\n";
        if (secim == 1)
            reportFile << "Ayrýca Application, System ve Security log dosyalari DmpGunluk klasörüne kopyalanmýstir ve kritik olaylar filtrelenmistir.(Beta)\n";

        reportFile.close();

        std::cout << "\nTum islemler tamamlandi. Rapor olusturuldu: " << reportFilePath << std::endl;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Bir hata olustu: " << e.what() << std::endl;
        if (reportFile.is_open()) reportFile.close();
        return 1;
    }

    system("pause");
    return 0;
}
