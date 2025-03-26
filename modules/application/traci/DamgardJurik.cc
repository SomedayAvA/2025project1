#include <gmpxx.h>
#include <libhcs.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include "veins/modules/application/traci/DamgardJurik.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
#include <chrono>
using namespace veins;

Define_Module(veins::DamgardJurik);


// Helper Function: Initialize the encryption environment.
// It creates a random generator and generates a Paillier key pair
// with a fixed seed to ensure consistent keys.
DamgardJurik::~DamgardJurik() {
    cancelAndDelete(sendMessageEvent);
}
void DamgardJurik::initEncryptionEnv() {
    hcs_random* hr_raw = hcs_init_random();
    hr.reset(hr_raw);
    pk.reset(djcs_init_public_key());
    vk.reset(djcs_init_private_key());
    unsigned long s = 1;
    djcs_generate_key_pair(pk.get(), vk.get(), hr.get(), s, 2048);
}

// Helper Function: Extract encrypted coordinates from a string.
// The expected format is "x:<number>, y:<number>".
// Returns a pair (x, y) as mpz_class objects.


void DamgardJurik::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = 22;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 1.0, sendMessageEvent);
        initEncryptionEnv();
    }
    else if (stage == 1) {
        // Initialization dependent on other modules.
    }
}


void DamgardJurik::finish()
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
    if (computationCount > 0) {
        double avgComputationTime = totalComputationTime / computationCount;
        std::cout << "平均计算时间: " << avgComputationTime << " ms" << std::endl;
    }

    // 你也可以在此处记录或保存其它统计数据
}


void DamgardJurik::onBSM(DemoSafetyMessage* bsm)
{
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void DamgardJurik::onWSM(BaseFrame1609_4* wsm) {
    // Initialize the encryption environment.

    // Cast the incoming message to our message type.
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string receivedData = receivedWSM->getDemoData();

    // If serial equals 1, this is a reply message containing encrypted differences.
    if (receivedWSM->getSerial() == 1) {
        std::cout << myId << std::endl;
        std::cout << myId << std::endl;
        size_t posS = receivedData.find("s:");
        size_t posD = receivedData.find(",d:");
        mpz_class enc_remoteX(receivedData.substr(posS + 2, posD - posS - 2).c_str());
        mpz_class enc_remoteY(receivedData.substr(posD + 3).c_str());
        mpz_class diff1 = enc_remoteX;
        mpz_class diff2 = enc_remoteY;
        auto dec_start = std::chrono::high_resolution_clock::now();
        // Decrypt the differences.
        djcs_decrypt(vk.get(), diff1.get_mpz_t(), diff1.get_mpz_t());
        djcs_decrypt(vk.get(), diff2.get_mpz_t(), diff2.get_mpz_t());
        auto dec_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> dec_duration = dec_end - dec_start;
        totalDecryptionTime += dec_duration.count();
        decryptionCount++;
        // Adjust if using a Z_n representation with negatives.


        // Calculate the Euclidean distance.
        long double d1 = diff1.get_d();
        long double d2 = diff2.get_d();
        std::cout <<  d1 << std::endl;
        long double distance = std::sqrt(d1 * d1 + d2 * d2);
        Coord currentPos = mobility->getPositionAt(simTime());
        FrenetCoord originalFrenet = getFrenetCoordinates(currentPos);
        const std::array<std::pair<double, double>, 4> candidates = {{
            {originalFrenet.s + d1, originalFrenet.d + d2}, // s+d1, d+d2
            {originalFrenet.s + d1, originalFrenet.d - d2}, // s+d1, d-d2
            {originalFrenet.s - d1, originalFrenet.d + d2}, // s-d1, d+d2
            {originalFrenet.s - d1, originalFrenet.d - d2}  // s-d1, d-d2
        }};
        double minDistance = std::numeric_limits<double>::max();
        Coord bestCoord;
        for (const auto& candidate : candidates) {
            double s_candidate = candidate.first;
            double d_candidate = candidate.second;
            Coord cartesianCandidate = getCartesianFromFrenet(s_candidate, d_candidate);

            double dx = cartesianCandidate.x - currentPos.x;
            double dy = cartesianCandidate.y - currentPos.y;
            double distance = std::hypot(dx, dy);
            if (distance < minDistance) {
                minDistance = distance;
                bestCoord = cartesianCandidate;
            }
        }

        std::cout << " distance: " << minDistance << std::endl;
        return;
    }

    // Otherwise, the message contains encrypted coordinates.
    size_t posS = receivedData.find("s:");
    size_t posD = receivedData.find(",d:");
    size_t posPK = receivedData.find(",pk:");

    mpz_class enc_remoteX(receivedData.substr(posS + 2, posD - posS - 2).c_str());
    mpz_class enc_remoteY(receivedData.substr(posD + 3, posPK - posD - 3).c_str());
    std::string remote_pk_json = receivedData.substr(posPK + 4);
    std::cout <<  remote_pk_json << std::endl;
    // 初始化公钥结构体
    std::unique_ptr<djcs_public_key, void(*)(djcs_public_key*)> remote_pk(
        djcs_init_public_key(),
        [](djcs_public_key* k) { djcs_free_public_key(k); }
    );

    // 导入公钥
    int ret = djcs_import_public_key(remote_pk.get(), remote_pk_json.c_str());
    if (ret != 0) {
        std::cerr << "公钥导入失败!" << std::endl;
        return;
    }




    std::cout << "Receiver Vehicle[" << myId << "] received encrypted coordinates from Vehicle["
              << receivedWSM->getSenderAddress() << "]: s = " << enc_remoteX
              << ", d = " << enc_remoteY << std::endl;

    // Encrypt the local vehicle's current coordinates.
    Coord currentPos = mobility->getPositionAt(simTime());
    FrenetCoord frenet = getFrenetCoordinates(currentPos);
    mpz_class localX(frenet.s), localY(frenet.d);
    mpz_class enc_localX = localX, enc_localY = localY;
    auto comp_start = std::chrono::high_resolution_clock::now();
    djcs_encrypt(remote_pk.get(), hr.get(), enc_localX.get_mpz_t(), enc_localX.get_mpz_t());
    djcs_encrypt(remote_pk.get(), hr.get(), enc_localY.get_mpz_t(), enc_localY.get_mpz_t());
    mpz_class modulus;
    mpz_pow_ui(modulus.get_mpz_t(), *(remote_pk->n), remote_pk->s + 1);
    // Compute the homomorphic difference:
    // Enc(remote - local) = Enc(remote) * (Enc(local))^{-1} mod n^2.
    mpz_class inv_enc_localX, inv_enc_localY;
    mpz_invert(inv_enc_localX.get_mpz_t(), enc_localX.get_mpz_t(), modulus.get_mpz_t());
    if (mpz_invert(inv_enc_localY.get_mpz_t(), enc_localY.get_mpz_t(), modulus.get_mpz_t()) == 0) {
        EV_ERROR << "Vehicle[" << myId << "]: Inversion for enc_localY failed!\n";
        return;
    }
    mpz_class enc_diffX, enc_diffY;
    mpz_mul(enc_diffX.get_mpz_t(), enc_remoteX.get_mpz_t(), inv_enc_localX.get_mpz_t());
    mpz_mod(enc_diffX.get_mpz_t(), enc_diffX.get_mpz_t(), modulus.get_mpz_t());
    mpz_mul(enc_diffY.get_mpz_t(), enc_remoteY.get_mpz_t(), inv_enc_localY.get_mpz_t());
    mpz_mod(enc_diffY.get_mpz_t(), enc_diffY.get_mpz_t(), modulus.get_mpz_t());
    auto comp_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> comp_duration = comp_end - comp_start;
    totalComputationTime += comp_duration.count();
    computationCount++;
    // Build a reply message containing the encrypted differences.
    std::ostringstream oss;
    oss << "s:" << enc_diffX << ",d:" << enc_diffY;
    std::string replyStr = oss.str();
    TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
    populateWSM(replyMsg);
    replyMsg->setDemoData(replyStr.c_str());
    replyMsg->setSenderAddress(myId);
    replyMsg->setSerial(1);  // Mark the message as a reply.
    std::cout << "Receiver Vehicle[" << myId << "] sending encrypted difference reply to Vehicle["
              << receivedWSM->getSenderAddress() << "]: " << replyStr << std::endl;
    sendDown(replyMsg);
}


void DamgardJurik::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}


void DamgardJurik::handleSelfMsg(cMessage* msg)
{
    if (msg == sendMessageEvent) {
        Coord currentPos = mobility->getPositionAt(simTime());
        FrenetCoord frenet = getFrenetCoordinates(currentPos);
        std::cout <<  myId << std::endl;
        std::cout << "s = " << std::fixed << std::setprecision(1) << frenet.s << std::endl;
        std::cout << "d = " << std::fixed << std::setprecision(1) << frenet.d << std::endl;
        mpz_class a1(frenet.s), a2(frenet.d);
        mpz_class enc_a1 = a1, enc_a2 = a2;

        // 开始计时 - 加密时间
        auto enc_start = std::chrono::high_resolution_clock::now();

        // 执行加密操作
        djcs_encrypt(pk.get(), hr.get(), enc_a1.get_mpz_t(), enc_a1.get_mpz_t());
        djcs_encrypt(pk.get(), hr.get(), enc_a2.get_mpz_t(), enc_a2.get_mpz_t());

        // 结束计时
        auto enc_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> enc_duration = enc_end - enc_start;

        // 累积加密时间和计数
        totalEncryptionTime += enc_duration.count();
        encryptionCount++;

        // 构造消息并发送
        char* pk_json = djcs_export_public_key(pk.get());
        std::string pk_str(pk_json);
        //free(pk_json);
        std::cout <<  pk_str << std::endl;
        std::ostringstream oss;
        oss << "s:" << enc_a1
            << ",d:" << enc_a2
            << ",pk:" << pk_str;
        std::string posStr = oss.str();
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setDemoData(posStr.c_str());
        newWSM->setSenderAddress(myId);
        sendDown(newWSM);
        scheduleAt(simTime() + 1.0, sendMessageEvent);

    }
}



void DamgardJurik::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Initialize the encryption environment.


    // Get the current position and encrypt the coordinates.

}
