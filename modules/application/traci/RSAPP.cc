#include <gmpxx.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include "veins/modules/application/traci/RSAPP.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
#include <chrono>
#include<openssl/rand.h>
#include <openssl/pem.h>
#include <unistd.h>
#include <limits.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>
#include "Interfaces.pb.h"                       // 包含自动生成的 Protobuf 头文件
#include <google/protobuf/util/json_util.h>       // JSON 工具

using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::Status;

using namespace veins;

Define_Module(veins::RSAPP);


// Helper Function: Initialize the encryption environment.
// It creates a random generator and generates a Paillier key pair
// with a fixed seed to ensure consistent keys.
RSAPP::~RSAPP() {
    cancelAndDelete(sendMessageEvent);

}
// Base64 解码函数，使用 OpenSSL 的 BIO 接口
std::vector<unsigned char> base64Decode(const std::string &input) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    bio = BIO_push(b64, bio);
    // 不要自动换行
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // 输出缓冲区的大小可能小于输入字符串
    std::vector<unsigned char> buffer(input.size());
    int decodedLen = BIO_read(bio, buffer.data(), static_cast<int>(input.size()));
    BIO_free_all(bio);

    if (decodedLen < 0)
        return std::vector<unsigned char>();

    buffer.resize(decodedLen);
    return buffer;
}

bool verify_ca(const std::string &ca_sign) {
    if (ca_sign.empty()) {
        std::cout << "Failed to load public key." << std::endl;
        return false;
    }

    // 1. 读取 CA 证书文件
    FILE *fp = fopen("file/pca_x509_cert.crt", "rb");
    if (!fp) {
        std::cout << "Could not open CA certificate file." << std::endl;
        return false;
    }
    X509 *ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ca_cert) {
        std::cout << "Failed to load CA certificate." << std::endl;
        return false;
    }

    // 2. 解析 Protobuf 消息（假设 ca_sign 为序列化后的字符串）
    interfaces::msgPsnymCertFormat new_psnym_response;
    if (!new_psnym_response.ParseFromString(ca_sign)) {
        std::cout << "Failed to parse CA sign." << std::endl;
        X509_free(ca_cert);
        return false;
    }

    // 获取需要验证的数据和签名
    std::string psnym_cert;
    if (!new_psnym_response.stcertificate().SerializeToString(&psnym_cert)) {
        std::cout << "Failed to serialize certificate field." << std::endl;
        X509_free(ca_cert);
        return false;
    }
    std::string psnym_cert1 = new_psnym_response.stsign().strsignature();

    // 3. Base64 解码签名
    std::vector<unsigned char> decodedSignature = base64Decode(psnym_cert1);
    if (decodedSignature.empty()) {
        std::cout << "Base64 decoding failed." << std::endl;
        X509_free(ca_cert);
        return false;
    }

    // 4. 获取 CA 证书中的公钥
    EVP_PKEY *pubkey = X509_get_pubkey(ca_cert);
    if (!pubkey) {
        std::cout << "Failed to get public key from CA certificate." << std::endl;
        X509_free(ca_cert);
        return false;
    }

    // 5. 使用 EVP 接口验证签名（假设使用 ECDSA + SHA256）
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cout << "Failed to create EVP_MD_CTX." << std::endl;
        EVP_PKEY_free(pubkey);
        X509_free(ca_cert);
        return false;
    }
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
        std::cout << "EVP_DigestVerifyInit failed." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        X509_free(ca_cert);
        return false;
    }
    if (EVP_DigestVerifyUpdate(mdctx, psnym_cert.data(), psnym_cert.size()) != 1) {
        std::cout << "EVP_DigestVerifyUpdate failed." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pubkey);
        X509_free(ca_cert);
        return false;
    }
    int verifyResult = EVP_DigestVerifyFinal(mdctx, decodedSignature.data(), decodedSignature.size());

    // 清理资源
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);
    X509_free(ca_cert);

    if (verifyResult != 1) {
        std::cout << "Invalid" << std::endl;
        return false;
    }
    return true;
}
void RSAPP::initialize(int stage)
{
    std::cout <<myId << std::endl;
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        std::ifstream input_file("file/Pseudonym_cert1.txt", std::ios::binary);


        // 将文件内容读入字符串
        std::stringstream buffer;
        buffer << input_file.rdbuf();
        std::string file_contents = buffer.str();

        // 解析二进制数据为 Protobuf 消息
        interfaces::msgPsnymCertFormat psnym_response;
        if (!psnym_response.ParseFromString(file_contents)) {
            std::cerr << "解析二进制数据失败." << std::endl;
        }

        // 将 Protobuf 消息转换为 JSON 字符串
        std::string psnym_response_json;
        Status status = MessageToJsonString(psnym_response, &psnym_response_json);


        // 通过 JSON 字符串解析到一个新的 Protobuf 消息对象中
        interfaces::msgPsnymCertFormat new_psnym_response;
        status = JsonStringToMessage(psnym_response_json, &new_psnym_response);

        std::string serialized_message = new_psnym_response.SerializeAsString();

        // 调用 verify_ca 函数进行验证
        bool verification_result = verify_ca(serialized_message);
        if (verification_result) {
            std::cout << "验证成功." << std::endl;
        } else {
            std::cout << "验证失败." << std::endl;
        }

        // 输出 JSON 字符串（可选）

        static int runCount = 0;  // 运行计数器
        runCount++;  // 每次运行增加


        std::string publicKeyPath = "key" + std::to_string(runCount) + "_public.pem";
        std::string privateKeyPath = "key" + std::to_string(runCount) + "_private.pem";

        FILE* fp_pub = fopen(publicKeyPath.c_str(), "r");

        rsa_public = PEM_read_RSA_PUBKEY(fp_pub, NULL, NULL, NULL);
        fclose(fp_pub);


        FILE* fp_priv = fopen(privateKeyPath.c_str(), "r");

        rsa_private = PEM_read_RSAPrivateKey(fp_priv, NULL, NULL, NULL);
        fclose(fp_priv);


        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = -1;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 1.0, sendMessageEvent);
    }
    else if (stage == 1) {
        // Initialization dependent on other modules.
    }
}



void RSAPP::finish()
{
    DemoBaseApplLayer::finish();

    if (encryptionCount > 0) {
        double avgEncryptionTime = totalEncryptionTime / encryptionCount;
        std::cout << "平均加密时间: " << avgEncryptionTime << " ms" << std::endl;
    }
    if (decryptionCount > 0) {
        double avgDecryptionTime = totalDecryptionTime / decryptionCount;
        std::cout << "平均解密时间: " << avgDecryptionTime << " ms" << std::endl;
    }

}


void RSAPP::onBSM(DemoSafetyMessage* bsm)
{
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void RSAPP::onWSM(BaseFrame1609_4* wsm)
{
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string receivedStr = receivedWSM->getDemoData();

    // 解析消息格式，查找 "PUBKEY:" 和 ";DATA:" 标记
    size_t posPubkey = receivedStr.find("PUBKEY:");
    size_t posData = receivedStr.find(";DATA:");
    if (posPubkey == std::string::npos || posData == std::string::npos) {
        std::cerr << "消息格式错误" << std::endl;
        return;
    }
    // 提取公钥字符串
    std::string pubkeyStr = receivedStr.substr(posPubkey + 7, posData - (posPubkey + 7));
    // 提取密文十六进制字符串
    std::string ciphertext_hex = receivedStr.substr(posData + 6);

    // 利用内存 BIO 重建公钥 RSA 对象
    BIO* bio = BIO_new_mem_buf(pubkeyStr.data(), pubkeyStr.size());
    RSA* receivedRsaPublic = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!receivedRsaPublic) {
        std::cerr << "无法解析接收到的公钥" << std::endl;
        return;
    }

    // 将密文十六进制字符串转换为二进制数据
    std::vector<unsigned char> ciphertext;
    for (size_t i = 0; i < ciphertext_hex.length(); i += 2) {
        std::string byteString = ciphertext_hex.substr(i, 2);
        ciphertext.push_back(static_cast<unsigned char>(
            strtol(byteString.c_str(), nullptr, 16)));
    }

    // 使用接收到的公钥进行解密（验证签名）
    auto dec_start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> plaintext(RSA_size(receivedRsaPublic));
    int decrypt_len = RSA_public_decrypt(
        ciphertext.size(),
        ciphertext.data(),
        plaintext.data(),
        receivedRsaPublic,
        RSA_PKCS1_PADDING
    );
    auto dec_end = std::chrono::high_resolution_clock::now();
    RSA_free(receivedRsaPublic);

    if (decrypt_len <= 0) {
        std::cerr << "解密失败" << std::endl;
        return;
    }

    // 将解密后的字节转换为字符串
    std::string decrypted_str(reinterpret_cast<char*>(plaintext.data()), decrypt_len);

    // 解析坐标数据
    size_t s_pos = decrypted_str.find("s:");
    size_t d_pos = decrypted_str.find(",d:");
    if (s_pos != std::string::npos && d_pos != std::string::npos) {
        try {
            std::string s_str = decrypted_str.substr(s_pos + 2, d_pos - (s_pos + 2));
            std::string d_str = decrypted_str.substr(d_pos + 3);
            double s = std::stod(s_str);
            double d = std::stod(d_str);
            std::cout << "解密后的坐标: s=" << s << ", d=" << d << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "解析坐标失败: " << e.what() << std::endl;
        }
    }
    else {
        std::cerr << "无效的坐标格式" << std::endl;
    }

    // 更新解密统计数据
    std::chrono::duration<double, std::milli> dec_duration = dec_end - dec_start;
    totalDecryptionTime += dec_duration.count();
    decryptionCount++;
}



void RSAPP::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}


void RSAPP::handleSelfMsg(cMessage* msg)
{
    std::cout <<myId << std::endl;
    if (msg == sendMessageEvent) {

        Coord currentPos = mobility->getPositionAt(simTime());
        FrenetCoord frenet = getFrenetCoordinates(currentPos);

        // 准备明文数据（格式：s:123.4,d:56.7）
        std::ostringstream plaintext;
        plaintext << "s:" << std::fixed << std::setprecision(1) << frenet.s
                  << ",d:" << std::fixed << std::setprecision(1) << frenet.d;

        // 使用私钥加密数据（模拟签名）
        auto enc_start = std::chrono::high_resolution_clock::now();
        int rsa_len = RSA_size(rsa_private);
        std::vector<unsigned char> ciphertext(rsa_len);

        int encrypt_len = RSA_private_encrypt(
            plaintext.str().size(),
            reinterpret_cast<const unsigned char*>(plaintext.str().c_str()),
            ciphertext.data(),
            rsa_private,
            RSA_PKCS1_PADDING
        );
        auto enc_end = std::chrono::high_resolution_clock::now();

        // 更新统计信息
        std::chrono::duration<double, std::milli> enc_duration = enc_end - enc_start;
        totalEncryptionTime += enc_duration.count();
        encryptionCount++;

        // 转换密文为十六进制字符串
        std::stringstream hex_stream;
        hex_stream << std::hex << std::setfill('0');
        for (int i = 0; i < encrypt_len; ++i) {
            hex_stream << std::setw(2) << static_cast<int>(ciphertext[i]);
        }

        // 序列化公钥：将 rsa_public 写入内存 BIO，然后读取 PEM 格式的字符串
        BIO* bio = BIO_new(BIO_s_mem());
        if (!PEM_write_bio_RSA_PUBKEY(bio, rsa_public)) {
            std::cerr << "写入公钥到 BIO 失败" << std::endl;
            BIO_free(bio);
            return;
        }
        char* pubkey_data = nullptr;
        long pubkey_len = BIO_get_mem_data(bio, &pubkey_data);
        std::string pubkeyStr(pubkey_data, pubkey_len);
        BIO_free(bio);

        // 构造最终消息，格式为："PUBKEY:【公钥字符串】;DATA:【密文十六进制】"
        std::ostringstream final_message;
        final_message << "PUBKEY:" << pubkeyStr << ";DATA:" << hex_stream.str();

        // 创建并发送消息
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setDemoData(final_message.str().c_str());
        newWSM->setSenderAddress(myId);
        sendDown(newWSM);

        scheduleAt(simTime() + 1.0, sendMessageEvent);
    }
}





void RSAPP::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Initialize the encryption environment.


    // Get the current position and encrypt the coordinates.

}
