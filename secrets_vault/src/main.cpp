#include "vault.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <termios.h>
#include <unistd.h>
#include <algorithm>
using namespace vault;
namespace fs=std::filesystem;

static std::string prompt_password(const std::string&label){std::cout<<label;std::cout.flush();termios old{},no{};tcgetattr(STDIN_FILENO,&old);no=old;no.c_lflag&=~ECHO;tcsetattr(STDIN_FILENO,TCSANOW,&no);std::string p;std::getline(std::cin,p);tcsetattr(STDIN_FILENO,TCSANOW,&old);std::cout<<"\n";return p;}
static std::vector<unsigned char> key(const std::string&p,const std::vector<unsigned char>&s){std::vector<unsigned char>k(32);PKCS5_PBKDF2_HMAC(p.c_str(),p.size(),s.data(),s.size(),210000,EVP_sha256(),32,k.data());return k;}
static bool encrypt_file(const fs::path&path,const std::string&plain,const std::string&p,const std::vector<unsigned char>&salt){auto k=key(p,salt);unsigned char iv[12],tag[16];RAND_bytes(iv,12);EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);EVP_EncryptInit_ex(c,nullptr,nullptr,k.data(),iv);std::vector<unsigned char>ct(plain.size()+16);int l=0,t=0;EVP_EncryptUpdate(c,ct.data(),&l,(const unsigned char*)plain.data(),plain.size());t=l;EVP_EncryptFinal_ex(c,ct.data()+t,&l);t+=l;EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag);EVP_CIPHER_CTX_free(c);std::ofstream f(path,std::ios::binary|std::ios::trunc);f.write("SV1",3);f.write((char*)salt.data(),salt.size());f.write((char*)iv,12);f.write((char*)tag,16);f.write((char*)ct.data(),t);return !!f;}
static std::optional<std::string> decrypt_file(const fs::path&path,const std::string&p,const std::vector<unsigned char>&salt){std::ifstream f(path,std::ios::binary);if(!f)return std::nullopt;char magic[3];f.read(magic,3);if(std::string(magic,3)!="SV1")return std::nullopt;std::vector<unsigned char>fsalt(16);f.read((char*)fsalt.data(),16);if(fsalt!=salt)return std::nullopt;unsigned char iv[12],tag[16];f.read((char*)iv,12);f.read((char*)tag,16);std::vector<unsigned char>ct((std::istreambuf_iterator<char>(f)),{}),pt(ct.size()+1);auto k=key(p,salt);EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr);EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr);EVP_DecryptInit_ex(c,nullptr,nullptr,k.data(),iv);int l=0,t=0;EVP_DecryptUpdate(c,pt.data(),&l,ct.data(),ct.size());t=l;EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,tag);int ok=EVP_DecryptFinal_ex(c,pt.data()+t,&l);EVP_CIPHER_CTX_free(c);if(ok<=0)return std::nullopt;t+=l;return std::string((char*)pt.data(),t);}

static void banner(){std::cout<<"\n==============================================\n  ENCRYPTED SECRETS VAULT & ACCESS SIMULATOR\n==============================================\n";}
static void help(){std::cout<<"\nCommands:\n  help                         Show commands\n  adduser <name> <role>        Create ADMIN/USER/GUEST (admin only)\n  put <id>                     Encrypt and store a secret\n  get <id>                     Decrypt a secret\n  list                         List secrets allowed by RBAC\n  del <id>                     Delete a secret (owner/admin)\n  passwd                       Change current password\n  whoami                       Show current user and role\n  audit                        Show audit log\n  logout                       Logout\n  exit                         Exit\n\n";}
int main(int argc,char**argv){std::string root=argc>1?argv[1]:"./data";Vault v(root);if(!v.initialize()){std::cerr<<"Initialization failed.\n";return 1;}banner();
    if(!v.get_user("admin")){std::cout<<"First run: create the administrator.\n";std::string p=prompt_password("Admin password (min 8 chars): ");if(!v.create_user("admin",Role::ADMIN,p)){std::cerr<<"Could not create admin.\n";return 1;}std::cout<<"Admin created.\n";}
    std::string user,pw;for(int tries=0;tries<3;tries++){std::cout<<"Username: ";std::getline(std::cin,user);pw=prompt_password("Password: ");if(v.authenticate(user,pw))break;if(tries==2){std::cout<<"Authentication failed.\n";return 2;}std::cout<<"Invalid credentials.\n";}
    auto u=v.get_user(user);std::vector<unsigned char> salt=u->salt;std::cout<<"Logged in as "<<user<<" ["<<role_to_string(u->role)<<"]\n";help();
    std::string line;while(std::cout<<"vault> ",std::getline(std::cin,line)){std::stringstream ss(line);std::string cmd;ss>>cmd;if(cmd=="exit")break;if(cmd=="help"){help();continue;}if(cmd=="whoami"){std::cout<<user<<" ["<<role_to_string(u->role)<<"]\n";continue;}if(cmd=="logout"){std::cout<<"Logout requested. Restart the program to login again.\n";break;}
        if(cmd=="adduser"){if(u->role!=Role::ADMIN){std::cout<<"ACCESS DENIED: ADMIN role required.\n";continue;}std::string n,r;ss>>n>>r;std::string np=prompt_password("New user password: ");if(v.create_user(n,role_from_string(r),np))std::cout<<"User created.\n";else std::cout<<"Could not create user. Check name/password/duplicate.\n";continue;}
        if(cmd=="put"){std::string id;ss>>id;if(id.empty()){std::cout<<"Usage: put <id>\n";continue;}if(u->role==Role::GUEST){std::cout<<"ACCESS DENIED: GUEST is read-only.\n";continue;}std::cout<<"Enter secret: ";std::string secret;std::getline(std::cin,secret);if(secret.empty()){std::cout<<"Secret cannot be empty.\n";continue;}if(v.put_secret(user,id,secret)){if(encrypt_file(fs::path(root)/"secrets"/(id+".enc"),secret,pw,salt)) {v.audit().log(user,"PUT_SECRET","id="+id+" encrypted=AES-256-GCM");std::cout<<"Encrypted secret stored.\n";}else std::cout<<"Encryption failed.\n";}else std::cout<<"ACCESS DENIED or invalid secret.\n";continue;}
        if(cmd=="get"){std::string id;ss>>id;auto metas=v.list_secrets(user);bool allowed=std::any_of(metas.begin(),metas.end(),[&](auto&m){return m.id==id;});if(!allowed){std::cout<<"ACCESS DENIED: secret is not visible to this user.\n";continue;}auto s=decrypt_file(fs::path(root)/"secrets"/(id+".enc"),pw,salt);if(s){std::cout<<"SECRET: "<<*s<<"\n";v.audit().log(user,"GET_SECRET","id="+id+" success");}else{std::cout<<"Decryption failed (wrong session key or tampered ciphertext).\n";v.audit().log(user,"GET_SECRET","id="+id+" failure");}continue;}
        if(cmd=="list"){auto a=v.list_secrets(user);if(a.empty())std::cout<<"No accessible secrets.\n";else for(auto&m:a)std::cout<<m.id<<" | owner="<<m.owner<<" | created="<<m.created_at<<" | updated="<<m.updated_at<<"\n";continue;}
        if(cmd=="del"){std::string id;ss>>id;if(v.delete_secret(user,id))std::cout<<"Deleted.\n";else std::cout<<"ACCESS DENIED or secret not found.\n";continue;}
        if(cmd=="passwd"){std::string np=prompt_password("New password: ");if(v.change_password(user,pw,np)){pw=np;u=v.get_user(user);salt=u->salt;std::cout<<"Password changed.\n";}else std::cout<<"Password change failed.\n";continue;}
        if(cmd=="audit"){std::ifstream f(root+"/audit.log");std::string x;while(std::getline(f,x))std::cout<<x<<'\n';continue;}
        if(!cmd.empty())std::cout<<"Unknown command. Type help.\n";
    }
    return 0;
}
