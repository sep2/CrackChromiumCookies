// MIT License
//
// Copyright (c) 2018 LCZ (i at lcz dot link)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <algorithm>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <libsecret/secret.h>

#include "sqlite_modern_cpp.h"

namespace sep2 {
namespace ChromiumCookies {

struct DefaultConfiguration {
    using ByteType = unsigned char;
    using BytesType = std::vector<ByteType>;

    using GnomeStringType = std::string;
    using CookieNameType = std::string;
    using CookieValueType = std::string;
    using DecryptedCookiesType = std::multimap<CookieNameType, CookieValueType>;
    using EncryptedCookiesType = std::multimap<CookieNameType, BytesType>;

    static constexpr const char* kCookiesPath = ".config/chromium/Default/Cookies";
    static constexpr const char* kSecretName = "Chromium Safe Storage";
    static constexpr const size_t kAESKeySize = 16;
    static constexpr const int kIteration = 1;
    static constexpr const ByteType kSalt[] = {'s','a','l','t', 'y', 's', 'a', 'l', 't'};
    static constexpr const ByteType kEncryptedHead[] = {'v', '1', '1'};
    static constexpr const size_t kInitVectorSize = 16;
    static constexpr const ByteType kInitVectorValue = ' ';

    struct Error {
        struct Exception : public std::exception {};
        struct SecretNotFound : public Exception {};
        struct SecretHMACError : public Exception {};
        struct AESKeySizeError : public Exception {};
        struct HomeDirNotFound : public Exception {};
    };
};

template<typename Config> class Crack;

////////////////////////////////////////////////////////////////////////////////
// simple interface
////////////////////////////////////////////////////////////////////////////////
/*! One function to get all cookies you want.
 */
template<typename Config = DefaultConfiguration>
typename Config::DecryptedCookiesType crack(const std::vector<const char*>& host_key_like) {
    return Crack<Config>::decrypt_cookies(Crack<Config>::get_encrypted_cookies(host_key_like));
}
////////////////////////////////////////////////////////////////////////////////



template<typename Config = DefaultConfiguration>
class Crack {
public:
////////////////////////////////////////////////////////////////////////////////
// full interface
////////////////////////////////////////////////////////////////////////////////
    static typename Config::BytesType get_key() {
        const auto secret = get_secret_from_gnome_keyrings(Config::kSecretName);
        return decrypt_secret(secret);
    }

    template<typename SQL, typename Binders, typename Callback>
    static void execute_sqlite(SQL&& sql, Binders&& binders, Callback&& callback) {
        const auto cookies_filepath = std::string(get_homedir()) + "/" + Config::kCookiesPath;
        sqlite::database db(cookies_filepath, sqlite::sqlite_config{.flags = sqlite::OpenFlags::READONLY});
        auto binder = db << std::forward<SQL>(sql);
        for (const auto& arg : std::forward<Binders>(binders)) {
            binder << arg;
        }
        binder >> std::forward<Callback>(callback);
    }

    static typename Config::CookieValueType decrypt_value(const typename Config::BytesType& encrypted_value, const typename Config::BytesType& key) {
        // check for encryption head
        if (std::lexicographical_compare(std::begin(Config::kEncryptedHead), std::end(Config::kEncryptedHead), std::begin(encrypted_value), std::end(encrypted_value))) {
            const auto stripped_encrypted_value = typename Config::BytesType(std::begin(encrypted_value) + sizeof(Config::kEncryptedHead), std::end(encrypted_value)); // strip of the head
            return aes_cbc_decrypt(key, stripped_encrypted_value);
        } else {
            // do not decrypt
            return typename Config::CookieValueType(std::begin(encrypted_value), std::end(encrypted_value));
        }
    }
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// implementation
////////////////////////////////////////////////////////////////////////////////
private:
    friend typename Config::DecryptedCookiesType crack<Config>(const std::vector<const char*>& host_key_like);

    static typename Config::DecryptedCookiesType decrypt_cookies(const typename Config::EncryptedCookiesType& encrypted_cookies) {
        const auto key = get_key();
        typename Config::DecryptedCookiesType decrypted_cookies;
        for (const auto& encrypted_cookie : encrypted_cookies) {
            decrypted_cookies.emplace(encrypted_cookie.first, decrypt_value(encrypted_cookie.second, key));
        }
        return decrypted_cookies;
    }

    static typename Config::EncryptedCookiesType get_encrypted_cookies(const std::vector<const char*>& host_key_like) {
        auto sql = std::string("SELECT name, value, encrypted_value FROM cookies WHERE 0 ");
        for (unsigned i = 0; i < host_key_like.size(); ++i) {
            sql += " OR instr(host_key, ?) > 0 ";
        }
        if (host_key_like.empty()) {
            sql += " OR 1 "; // allow empty vector to get all the cookies
        }
        sql += " ORDER BY name ASC, length(host_key) ASC;";

        typename Config::EncryptedCookiesType cookies;
        execute_sqlite(sql, host_key_like,
            [&](typename Config::CookieNameType name, typename Config::BytesType value, typename Config::BytesType encrypted_value){
                if (value.empty()) {
                    if (encrypted_value.empty()) {
                        return;
                    } else {
                        cookies.emplace(move(name), move(encrypted_value));
                    }
                } else {
                    cookies.emplace(move(name), move(value));
                }
            }
        );

        return cookies;
    }

    static typename Config::GnomeStringType get_secret_from_gnome_keyrings(const char* secret_name) {
        std::shared_ptr<SecretService> secret_service(
                secret_service_get_sync(SECRET_SERVICE_LOAD_COLLECTIONS, nullptr, nullptr),
                [](SecretService*){secret_service_disconnect();}
            );

        std::shared_ptr<GList> gnome_keyrings(
                secret_service_get_collections(secret_service.get()),
                g_list_free
            );

        std::shared_ptr<GList> unlocked_keyrings(
                [&]{
                    GList* t = nullptr;
                    secret_service_unlock_sync(secret_service.get(), gnome_keyrings.get(), nullptr, &t, nullptr);
                    return t;
                }(),
                g_list_free
            );

        for (auto sc = unlocked_keyrings.get(); sc; sc = sc->next) {
            const auto secret_collection = reinterpret_cast<SecretCollection*>(sc->data);
            std::shared_ptr<GList> items(secret_collection_get_items(secret_collection), g_list_free);

            for (auto it = items.get(); it; it = it->next) {
                const auto item = reinterpret_cast<SecretItem*>(it->data);
                std::shared_ptr<gchar> item_label(secret_item_get_label(item), g_free);

                if (item_label.get() == typename Config::GnomeStringType(secret_name)) {
                    secret_item_load_secret_sync(item, nullptr, nullptr);

                    std::shared_ptr<SecretValue> secret_value(secret_item_get_secret(item), secret_value_unref);
                    if (secret_value_get_content_type(secret_value.get()) == typename Config::GnomeStringType("text/plain")) {
                        return secret_value_get_text(secret_value.get());
                    }
                }
            }
        }

        throw typename Config::Error::SecretNotFound();
    }

    static typename Config::BytesType decrypt_secret(const typename Config::GnomeStringType& secret) {
        typename Config::BytesType key(Config::kAESKeySize, 0x00);

        if (PKCS5_PBKDF2_HMAC_SHA1(secret.data(), secret.size(), Config::kSalt, sizeof(Config::kSalt), Config::kIteration, key.size(), &key[0]) == 0) {
            throw typename Config::Error::SecretHMACError();
        }

        return key;
    }

    static const char * get_homedir() {
        if (const auto home_dir = getenv("HOME")) {
            return home_dir;
        }
        throw typename Config::Error::HomeDirNotFound();
    }

    static typename Config::CookieValueType aes_cbc_decrypt(const typename Config::BytesType& aes_key, const typename Config::BytesType& encrypted_value) {
        if (aes_key.size() != Config::kAESKeySize) {
            throw typename Config::Error::AESKeySizeError();
        }

        typename Config::ByteType iv[Config::kInitVectorSize];
        memset(iv, Config::kInitVectorValue, Config::kInitVectorSize);

        typename Config::BytesType out(encrypted_value.size(), 0x00);

        AES_KEY dec_key;
        AES_set_decrypt_key(aes_key.data(), aes_key.size() * 8, &dec_key);
        AES_cbc_encrypt(encrypted_value.data(), &out[0], encrypted_value.size(), &dec_key, iv, AES_DECRYPT);

        // clean padding
        // last byte indicates the number of padding should be stripped off
        return typename Config::CookieValueType(std::begin(out), std::begin(out) + [&]{
            const auto padding_size = static_cast<size_t>(out.back());
            if (padding_size > out.size()) {
                return out.size();
            } else {
                return out.size() - padding_size;
            }
        }());
    }
////////////////////////////////////////////////////////////////////////////////
}; // Crack

} // namespace ChromiumCookies
} // namespace sep2
