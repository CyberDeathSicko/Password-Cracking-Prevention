#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <mutex>
#include <chrono>
#include <regex>
#include <cstring>
#include <openssl/hmac.h>

struct User {
    std::string username;
    std::string hashedPassword;
    std::string salt;
    bool isLocked = false;
    int failedAttempts = 0;
    time_t lockoutTime = 0;
};

std::vector<User> userDatabase;

class RateLimiter {
public:
    RateLimiter(int capacity, int rateLimit) : capacity(capacity), rateLimit(rateLimit), tokens(capacity) {
        lastRefillTime = std::chrono::steady_clock::now();
    }

    bool allowRequest() {
        std::lock_guard<std::mutex> lock(tokenMutex);
        refillTokens();
        if (tokens > 0) {
            tokens--;
            return true;
        }
        return false;
    }

private:
    void refillTokens() {
        auto currentTime = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsedSeconds = currentTime - lastRefillTime;
        int tokensToAdd = static_cast<int>(elapsedSeconds.count() * rateLimit);
        if (tokensToAdd > 0) {
            tokens = std::min(capacity, tokens + tokensToAdd);
            lastRefillTime = currentTime;
        }
    }

    int capacity;  
    int rateLimit; 
    int tokens;    
    std::chrono::steady_clock::time_point lastRefillTime;
    std::mutex tokenMutex;
};

RateLimiter loginRateLimiter(10, 2); 

bool isPasswordValid(const std::string& password) {
    const std::string complexityRegex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z\\d]).{12,}$";
    return std::regex_match(password, std::regex(complexityRegex));
}

bool isAccountLocked(const std::string& username) {
    for (const User& user : userDatabase) {
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

bool login(const std::string& username, const std::string& password) {
    if (!loginRateLimiter.allowRequest()) {
        std::cout << "Login attempts rate exceeded. Please try again later.\n";
        return false;
    }

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

int main() {
    User user1;
    user1.username = "user1";
    user1.salt = "random_salt";
    user1.hashedPassword = "hashedPassword123";
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
            login(username, password);
        } else {
            std::cout << "Password does not meet complexity requirements.\n";
        }
    }

    return 0;
}
