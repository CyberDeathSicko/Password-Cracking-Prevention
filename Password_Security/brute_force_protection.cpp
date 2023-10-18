#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <regex>
#include <bcrypt/BCrypt.hpp>
#include <random>
#include <fstream>

struct User {
    std::string username;
    std::string hashedPassword;
    std::string salt;
    bool isLocked = false;
    int failedAttempts = 0;
    time_t lockoutTime = 0;
};

std::vector<User> userDatabase;

// Function to generate a cryptographically secure random salt
std::string generateSalt() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    std::string salt;
    for (int i = 0; i < 16; ++i) { // Generate a 16-byte salt
        salt.push_back(static_cast<char>(dis(gen)));
    }

    return salt;
}

std::string hashPassword(const std::string& password, const std::string& salt) {
    return BCrypt::generateHash(password, salt);
}

bool isAccountLocked(const std::string& username) {
    for (User& user : userDatabase) {
        if (user.username == username) {
            if (user.isLocked) {
                time_t currentTime;
                time(&currentTime);
                if (difftime(currentTime, user.lockoutTime) > 300) {
                    user.isLocked = false;
                    user.failedAttempts = 0;
                }
            }
            return user.isLocked;
        }
    }
    return false;
}

bool isPasswordValid(const std::string& password) {
    const std::string complexityRegex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z\\d]).{12,}$";
    return std::regex_match(password, std::regex(complexityRegex));
}

bool login(const std::string& username, const std::string& password) {
    for (User& user : userDatabase) {
        if (user.username == username) {
            if (user.isLocked) {
                std::cout << "Account is locked. Please try again later.\n";
                return false;
            }

            if (BCrypt::validatePassword(password, user.hashedPassword)) {
                std::cout << "Login successful. Welcome, " << username << "!\n";
                user.failedAttempts = 0;
                return true;
            }

            user.failedAttempts++;

            if (user.failedAttempts >= 3) {
                user.isLocked = true;
                user.failedAttempts = 0;
                time(&user.lockoutTime);
                std::cout << "Too many failed login attempts. Account locked for 5 minutes.\n";
            } else {
                std::cout << "Login failed. Please try again.\n";
            }
        }
    }

    std::cout << "User not found. Please check the username.\n";
    return false;
}

std::string getCurrentDateTime() {
    const time_t now = time(0);
    tm ltm;
    localtime_s(&ltm, &now);
    std::stringstream ss;
    ss << std::setw(2) << std::setfill('0') << ltm.tm_hour << ":";
    ss << std::setw(2) << std::setfill('0') << ltm.tm_min << " ";
    ss << std::setw(2) << std::setfill('0') << ltm.tm_mday << "/";
    ss << std::setw(2) << std::setfill('0') << ltm.tm_mon + 1 << "/";
    ss << ltm.tm_year + 1900;
    return ss.str();
}

int main() {
    // Simulate user registration - This should be handled securely with a registration process.
    User user1;
    user1.username = "user1";
    user1.salt = generateSalt();
    user1.hashedPassword = hashPassword("StrongP@ssw0rd123", user1.salt); // Replace with a secure password
    userDatabase.push_back(user1);

    std::string username, password;
    for (int i = 0; i < 5; i++) {
        std::cout << "Enter username: ";
        std::cin >> username;

        std::string buffer;
        char c;
        std::cout << "Enter password: ";
        while ((c = std::cin.get()) != '\n') {
            buffer += c;
        }
        password = buffer;

        if (isPasswordValid(password)) {
            std::cout << "Password meets complexity requirements.\n";
            std::cout << getCurrentDateTime() << " - ";
            if (!isAccountLocked(username)) {
                login(username, password);
            }
        } else {
            std::cout << "Password does not meet complexity requirements.\n";
        }
    }

    return 0;
}