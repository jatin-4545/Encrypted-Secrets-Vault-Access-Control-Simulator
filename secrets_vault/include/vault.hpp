#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace vault {

enum class Role { ADMIN, USER, GUEST };
std::string role_to_string(Role r);
Role role_from_string(const std::string& s);

struct User {
    std::string username;
    Role role{Role::USER};
    std::vector<unsigned char> salt;
    std::vector<unsigned char> password_hash;
};

struct SecretMeta {
    std::string id;
    std::string owner;
    std::string created_at;
    std::string updated_at;
};

class AuditLogger {
public:
    explicit AuditLogger(const std::string& fallback_path);
    void log(const std::string& user, const std::string& action, const std::string& detail);
private:
    std::string fallback_path_;
    int fd_{-1};
};

class Vault {
public:
    explicit Vault(const std::string& root);
    ~Vault();
    bool initialize();
    bool create_user(const std::string& username, Role role, const std::string& password);
    bool authenticate(const std::string& username, const std::string& password);
    bool change_password(const std::string& username, const std::string& old_pw, const std::string& new_pw);
    bool put_secret(const std::string& username, const std::string& id, const std::string& secret);
    std::optional<std::string> get_secret(const std::string& username, const std::string& id);
    bool delete_secret(const std::string& username, const std::string& id);
    std::vector<SecretMeta> list_secrets(const std::string& username) const;
    std::optional<User> get_user(const std::string& username) const;
    const std::string& root() const { return root_; }
    AuditLogger& audit() { return audit_; }
private:
    std::string root_;
    std::string users_file_;
    std::string meta_file_;
    AuditLogger audit_;
    std::vector<User> users_;
    std::vector<SecretMeta> metas_;
    std::string current_user_;
    bool load();
    bool save_users() const;
    bool save_meta() const;
    User* find_user(const std::string& username);
    const User* find_user(const std::string& username) const;
    SecretMeta* find_meta(const std::string& id);
    const SecretMeta* find_meta(const std::string& id) const;
    bool can_read(const User& u, const SecretMeta& m) const;
    bool can_write(const User& u, const std::string& id) const;
};

std::string now_string();
std::string trim(const std::string& s);
std::string random_id();

} // namespace vault
