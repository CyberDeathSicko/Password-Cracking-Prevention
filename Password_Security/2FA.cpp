#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <cmath>

const std::string secretKey = "yourSecretKey";
const int timeStep = 30;

std::string generateTOTP(const std::string& secret, time_t timestamp) {
    const int digits = 6;
    const int secretLength = secret.length();
    unsigned char hash[SHA_DIGEST_LENGTH] = {0}; 

    timestamp /= timeStep;
    for (int i = 7; i >= 0; i--) {
        hash[i] = static_cast<unsigned char>(timestamp & 0xFF);
        timestamp >>= 8;
    }

    unsigned char result[SHA_DIGEST_LENGTH];
    HMAC(EVP_sha1(), secret.c_str(), secretLength, hash, SHA_DIGEST_LENGTH, result, nullptr);
    int offset = result[SHA_DIGEST_LENGTH - 1] & 0x0F;
    int binary = (result[offset] & 0x7F) << 24 | (result[offset + 1] & 0xFF) << 16 |
                 (result[offset + 2] & 0xFF) << 8 | (result[offset + 3] & 0xFF);
    int otp = binary % static_cast<int>(std::pow(10, digits));

    std::ostringstream otpStream;
    otpStream << std::setfill('0') << std::setw(digits) << otp;
    return otpStream.str();
}

int main() {
    time_t currentTime = time(0);
    std::string userOTP;

    std::cout << "Enter your OTP: ";
    std::cin >> userOTP;

    std::string totp = generateTOTP(secretKey, currentTime);

    if (userOTP == totp) {
        std::cout << "2FA verification successful. Welcome!\n";
    } else {
        std::cout << "2FA verification failed. Access denied.\n";
    }

    return 0;
}
