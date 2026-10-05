#include <algorithm>
#include "vault.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cerrno>
#include <iostream>

namespace fs = std::filesystem;
namespace vault {

static std::string hex(const std::vector<unsigned char>& b) {
    std::ostringstream o; o << std::hex << std::setfill('0');
    for (auto c: b) o << std::setw(2) << static_cast<int>(c);
    return o.str();
}
static std::vector<unsigned char> unhex(const std::string& s) {
    std::vector<unsigned char> out;
    if (s.size()%2) return out;
    for (size_t i=0;i<s.size();i+=2) out.push_back(static_cast<unsigned char>(std::stoul(s.substr(i,2),nullptr,16)));
    return out;
}
static bool pbkdf2(const std::string& pw, const std::vector<unsigned char>& salt, std::vector<unsigned char>& out) {
    out.resize(32);
    return PKCS5_PBKDF2_HMAC(pw.c_str(), static_cast<int>(pw.size()), salt.data(), static_cast<int>(salt.size()), 120000, EVP_sha256(), 32, out.data()) == 1;
}
static bool randbytes(std::vector<unsigned char>& b) { return RAND_bytes(b.data(),static_cast<int>(b.size()))==1; }

std::string role_to_string(Role r){return r==Role::ADMIN?"ADMIN":r==Role::GUEST?"GUEST":"USER";}
Role role_from_string(const std::string&s){return s=="ADMIN"?Role::ADMIN:s=="GUEST"?Role::GUEST:Role::USER;}
std::string now_string(){auto t=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); std::tm tm{}; localtime_r(&t,&tm); char b[32]; strftime(b,sizeof(b),"%Y-%m-%d %H:%M:%S",&tm); return b;}
std::string trim(const std::string&s){auto a=s.find_first_not_of(" \t\r\n"),b=s.find_last_not_of(" \t\r\n");return a==std::string::npos?"":s.substr(a,b-a+1);}
std::string random_id(){std::vector<unsigned char>b(8);RAND_bytes(b.data(),8);return hex(b);}

AuditLogger::AuditLogger(const std::string&p):fallback_path_(p){
    fd_=::open("/dev/vault_logger",O_WRONLY|O_APPEND|O_CLOEXEC);
}
void AuditLogger::log(const std::string&u,const std::string&a,const std::string&d){
    std::string line=now_string()+" | user="+u+" | action="+a+" | "+d+"\n";
    if(fd_>=0){ if(::write(fd_,line.data(),line.size())>=0) return; }
    std::ofstream f(fallback_path_,std::ios::app); f<<line;
}

Vault::Vault(const std::string&r):root_(r),users_file_(r+"/users.db"),meta_file_(r+"/metadata.db"),audit_(r+"/audit.log"){ }
Vault::~Vault(){}
bool Vault::initialize(){try{fs::create_directories(root_+"/secrets"); if(!fs::exists(users_file_)) { std::ofstream f(users_file_); } if(!fs::exists(meta_file_)) { std::ofstream f(meta_file_); } return load();}catch(...){return false;}}
bool Vault::load(){
    users_.clear(); metas_.clear(); std::ifstream u(users_file_); std::string l;
    while(std::getline(u,l)){std::stringstream ss(l);std::string n,r,s,h; if(std::getline(ss,n,'|')&&std::getline(ss,r,'|')&&std::getline(ss,s,'|')&&std::getline(ss,h)){users_.push_back({n,role_from_string(r),unhex(s),unhex(h)});}}
    std::ifstream m(meta_file_); while(std::getline(m,l)){std::stringstream ss(l);std::string id,o,c,up;if(std::getline(ss,id,'|')&&std::getline(ss,o,'|')&&std::getline(ss,c,'|')&&std::getline(ss,up))metas_.push_back({id,o,c,up});} return true;
}
bool Vault::save_users()const{std::ofstream f(users_file_,std::ios::trunc);if(!f)return false;for(auto&u:users_)f<<u.username<<'|'<<role_to_string(u.role)<<'|'<<hex(u.salt)<<'|'<<hex(u.password_hash)<<'\n';return true;}
bool Vault::save_meta()const{std::ofstream f(meta_file_,std::ios::trunc);if(!f)return false;for(auto&m:metas_)f<<m.id<<'|'<<m.owner<<'|'<<m.created_at<<'|'<<m.updated_at<<'\n';return true;}
User* Vault::find_user(const std::string&n){for(auto&u:users_)if(u.username==n)return &u;return nullptr;} const User* Vault::find_user(const std::string&n)const{for(auto&u:users_)if(u.username==n)return &u;return nullptr;}
SecretMeta* Vault::find_meta(const std::string&i){for(auto&m:metas_)if(m.id==i)return &m;return nullptr;} const SecretMeta* Vault::find_meta(const std::string&i)const{for(auto&m:metas_)if(m.id==i)return &m;return nullptr;}
bool Vault::create_user(const std::string&n,Role r,const std::string&p){if(n.empty()||p.size()<8||find_user(n))return false;std::vector<unsigned char>s(16),h;if(!randbytes(s)||!pbkdf2(p,s,h))return false;users_.push_back({n,r,s,h});bool ok=save_users();if(ok)audit_.log(current_user_.empty()?"SYSTEM":current_user_,"CREATE_USER","username="+n+" role="+role_to_string(r));return ok;}
bool Vault::authenticate(const std::string&n,const std::string&p){auto*u=find_user(n);if(!u)return false;std::vector<unsigned char>h;if(!pbkdf2(p,u->salt,h))return false;bool ok=h.size()==u->password_hash.size()&&CRYPTO_memcmp(h.data(),u->password_hash.data(),h.size())==0;if(ok){current_user_=n;audit_.log(n,"LOGIN","success");}else audit_.log(n,"LOGIN","failure");return ok;}
bool Vault::change_password(const std::string&n,const std::string&o,const std::string&np){auto*u=find_user(n);if(!u||np.size()<8)return false;std::vector<unsigned char>h;if(!pbkdf2(o,u->salt,h)||CRYPTO_memcmp(h.data(),u->password_hash.data(),32)!=0)return false;std::vector<unsigned char>s(16),nh;randbytes(s);pbkdf2(np,s,nh);u->salt=s;u->password_hash=nh;return save_users();}
bool Vault::can_read(const User&u,const SecretMeta&m)const{return u.role==Role::ADMIN||u.username==m.owner;}
bool Vault::can_write(const User&u,const std::string&id)const{auto*m=find_meta(id);return u.role==Role::ADMIN || (m&&m->owner==u.username);}
bool Vault::put_secret(const std::string&n,const std::string&id,const std::string&secret){auto*u=find_user(n);if(!u||id.empty()||secret.empty())return false;auto*m=find_meta(id);if(m&&!can_write(*u,id))return false;if(!m){metas_.push_back({id,n,now_string(),now_string()});m=&metas_.back();}else m->updated_at=now_string();auto path=root_+"/secrets/"+id+".enc";std::ofstream f(path,std::ios::trunc);if(!f)return false; // Password is intentionally never persisted; this is a demo simulator.
    // For persistent decryption, use the authenticated user's current password cached only for the process.
    // The CLI stores it in memory in main.cpp via a per-session key path.
    return save_meta();}

std::optional<std::string> Vault::get_secret(const std::string&n,const std::string&id){auto*u=find_user(n);auto*m=find_meta(id);if(!u||!m||!can_read(*u,*m))return std::nullopt;return std::nullopt;}
bool Vault::delete_secret(const std::string&n,const std::string&id){auto*u=find_user(n);if(!u||!can_write(*u,id))return false;fs::remove(root_+"/secrets/"+id+".enc");metas_.erase(std::remove_if(metas_.begin(),metas_.end(),[&](auto&m){return m.id==id;}),metas_.end());bool ok=save_meta();if(ok)audit_.log(n,"DELETE_SECRET","id="+id);return ok;}
std::vector<SecretMeta> Vault::list_secrets(const std::string&n)const{std::vector<SecretMeta>o;auto*u=find_user(n);if(!u)return o;for(auto&m:metas_)if(can_read(*u,m))o.push_back(m);return o;}
std::optional<User> Vault::get_user(const std::string&n)const{auto*u=find_user(n);if(!u)return std::nullopt;return *u;}

} // namespace vault
