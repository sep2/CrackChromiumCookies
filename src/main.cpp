#include <iostream>

#include "CrackChromiumCookies.h"

int main(int argc, char* argv[])
{
    const auto decrypted_cookies = sep2::ChromiumCookies::crack({"taobao.com", "alibaba.com"});

    for (const auto& cookie : decrypted_cookies) {
        std::cout << cookie.first << " = " << cookie.second << std::endl;
    }

    return 0;
}
