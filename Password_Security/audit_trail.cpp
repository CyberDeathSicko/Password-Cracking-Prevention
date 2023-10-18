#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <mutex>

std::mutex logMutex;  

void logEvent(const std::string& event) {
    try {
        std::ofstream logFile("audit_trail.txt", std::ios::app);
        if (logFile.is_open()) {
            time_t currentTime;
            time(&currentTime);
            tm* localTime = localtime(&currentTime);

            std::stringstream timestamp;
            timestamp << "[" << std::setfill('0') << std::setw(2) << (localTime->tm_mon + 1) << "/";
            timestamp << std::setfill('0') << std::setw(2) << localTime->tm_mday << "/";
            timestamp << (localTime->tm_year + 1900) << " ";
            timestamp << std::setfill('0') << std::setw(2) << localTime->tm_hour << ":";
            timestamp << std::setfill('0') << std::setw(2) << localTime->tm_min << ":";
            timestamp << std::setfill('0') << std::setw(2) << localTime->tm_sec << "] ";

            std::lock_guard<std::mutex> lock(logMutex);
            logFile << timestamp.str() << event << std::endl;
        } else {
            std::cerr << "Error: Failed to open the audit trail file for logging." << std::endl;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}
