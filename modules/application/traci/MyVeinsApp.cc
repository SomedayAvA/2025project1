#include <gmpxx.h>
#include <libhcs.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include "veins/modules/application/traci/MyVeinsApp.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
#include <chrono>
#include <openfhe/pke/openfhe.h>
using namespace veins;
using namespace bigintdyn;
Define_Module(veins::MyVeinsApp);


// Helper Function: Initialize the encryption environment.
// It creates a random generator and generates a Paillier key pair
// with a fixed seed to ensure consistent keys.
MyVeinsApp::~MyVeinsApp() {
    cancelAndDelete(sendMessageEvent);
}
void MyVeinsApp::initEncryptionEnv() {
    hcs_random* hr_raw = hcs_init_random();
    hr.reset(hr_raw);
    pk.reset(pcs_init_public_key());
    vk.reset(pcs_init_private_key());
    pcs_generate_key_pair(pk.get(), vk.get(), hr.get(), 2048);

}

// Helper Function: Extract encrypted coordinates from a string.
// The expected format is "x:<number>, y:<number>".
// Returns a pair (x, y) as mpz_class objects.
std::pair<mpz_class, mpz_class> MyVeinsApp::extractEncryptedCoordinates(const std::string &data)
{
    size_t posX = data.find("s:");
    size_t posY = data.find(", d:");
    std::string xStr = data.substr(posX + 2, posY - (posX + 2));
    std::string yStr = data.substr(posY + 4);
    return { mpz_class(xStr.c_str(), 10), mpz_class(yStr.c_str(), 10) };
}

void MyVeinsApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = 22;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 0.1, sendMessageEvent);
        initEncryptionEnv();
    }
    else if (stage == 1) {
        // Initialization dependent on other modules.
    }
}


void MyVeinsApp::finish()
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


void MyVeinsApp::onBSM(DemoSafetyMessage* bsm)
{
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void MyVeinsApp::onWSM(BaseFrame1609_4* wsm) {
    // Initialize the encryption environment.

    // Cast the incoming message to our message type.
    /*TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string receivedData = receivedWSM->getDemoData();

    // If serial equals 1, this is a reply message containing encrypted differences.
    if (receivedWSM->getSerial() == 1) {
        auto diffPair = extractEncryptedCoordinates(receivedData);
        mpz_class diff1 = diffPair.first;
        mpz_class diff2 = diffPair.second;
        auto dec_start = std::chrono::high_resolution_clock::now();
        // Decrypt the differences.
        pcs_decrypt(vk.get(), diff1.get_mpz_t(), diff1.get_mpz_t());
        pcs_decrypt(vk.get(), diff2.get_mpz_t(), diff2.get_mpz_t());
        auto dec_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> dec_duration = dec_end - dec_start;
        totalDecryptionTime += dec_duration.count();
        decryptionCount++;
        // Adjust if using a Z_n representation with negatives.
        mpz_class n_val(pk.get()->n);
        mpz_class half_n = n_val / 2;
        if(diff1 > half_n)
            diff1 -= n_val;
        if(diff2 > half_n)
            diff2 -= n_val;

        // Calculate the Euclidean distance.
        long double d1 = diff1.get_d();
        long double d2 = diff2.get_d();
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
        auto networkEndTimeChrono = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> networkDelayChrono = networkEndTimeChrono - networkStartTimeChrono;
        std::cout << "本次网络往返时延 (std::chrono): "
                  << networkDelayChrono.count() << " ms" << std::endl;
        return;
    }

    // Otherwise, the message contains encrypted coordinates.
    size_t posS    = receivedData.find("s:");
    size_t posD    = receivedData.find(",d:");
    size_t posN    = receivedData.find(",n:");
    size_t posG    = receivedData.find(",g:");



    mpz_class enc_remoteX(receivedData.substr(posS+2, posD-posS-2).c_str());
    mpz_class enc_remoteY(receivedData.substr(posD+3, posN-posD-3).c_str());
    mpz_class remote_n(receivedData.substr(posN+3, posG-posN-3).c_str());
    mpz_class remote_g(receivedData.substr(posG + 3).c_str());



    std::unique_ptr<pcs_public_key, void(*)(pcs_public_key*)> remote_pk(pcs_init_public_key(), [](pcs_public_key* k){ pcs_free_public_key(k); });
    mpz_set(remote_pk->n, remote_n.get_mpz_t());
    mpz_set(remote_pk->g, remote_g.get_mpz_t());
    mpz_pow_ui(remote_pk->n2, remote_pk->n, 2);

    std::cout << "Receiver Vehicle[" << myId << "] received encrypted coordinates from Vehicle["
              << receivedWSM->getSenderAddress() << "]: s = " << enc_remoteX
              << ", d = " << enc_remoteY << std::endl;

    // Encrypt the local vehicle's current coordinates.
    Coord currentPos = mobility->getPositionAt(simTime());
    FrenetCoord frenet = getFrenetCoordinates(currentPos);
    mpz_class localX(frenet.s), localY(frenet.d);
    mpz_class enc_localX = localX, enc_localY = localY;
    auto comp_start = std::chrono::high_resolution_clock::now();
    pcs_encrypt(remote_pk.get(), hr.get(), enc_localX.get_mpz_t(), enc_localX.get_mpz_t());
    pcs_encrypt(remote_pk.get(), hr.get(), enc_localY.get_mpz_t(), enc_localY.get_mpz_t());

    // Compute the homomorphic difference:
    // Enc(remote - local) = Enc(remote) * (Enc(local))^{-1} mod n^2.
    mpz_class inv_enc_localX, inv_enc_localY;
    mpz_invert(inv_enc_localX.get_mpz_t(), enc_localX.get_mpz_t(), remote_pk.get()->n2);
    if (mpz_invert(inv_enc_localY.get_mpz_t(), enc_localY.get_mpz_t(), remote_pk.get()->n2) == 0) {
        EV_ERROR << "Vehicle[" << myId << "]: Inversion for enc_localY failed!\n";
        return;
    }
    mpz_class enc_diffX, enc_diffY;
    mpz_mul(enc_diffX.get_mpz_t(), enc_remoteX.get_mpz_t(), inv_enc_localX.get_mpz_t());
    mpz_mod(enc_diffX.get_mpz_t(), enc_diffX.get_mpz_t(), remote_pk.get()->n2);
    mpz_mul(enc_diffY.get_mpz_t(), enc_remoteY.get_mpz_t(), inv_enc_localY.get_mpz_t());
    mpz_mod(enc_diffY.get_mpz_t(), enc_diffY.get_mpz_t(), remote_pk.get()->n2);
    auto comp_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> comp_duration = comp_end - comp_start;
    totalComputationTime += comp_duration.count();
    computationCount++;
    // Build a reply message containing the encrypted differences.
    std::ostringstream oss;
    oss << "s:" << enc_diffX << ", d:" << enc_diffY;
    std::string replyStr = oss.str();
    TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
    populateWSM(replyMsg);
    replyMsg->setDemoData(replyStr.c_str());
    replyMsg->setSenderAddress(myId);
    replyMsg->setSerial(1);  // Mark the message as a reply.
    //std::cout << "Receiver Vehicle[" << myId << "] sending encrypted difference reply to Vehicle["
    //          << receivedWSM->getSenderAddress() << "]: " << replyStr << std::endl;
    sendDown(replyMsg);*/
}


void MyVeinsApp::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}
#include <chrono>

void MyVeinsApp::handleSelfMsg(cMessage* msg)
{
    /*if (msg == sendMessageEvent) {
        uint32_t multDepth   = 1;
        uint32_t scaleModSize = 50;
        uint32_t batchSize    = 1;  // 我们这里只加密单个数字

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetBatchSize(batchSize);

        // 创建 CryptoContext，上下文会自动选择合适的环维度等参数
        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

        // 启用加密功能
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        // Step 2: 密钥生成
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);  // 生成重线性化密钥

        // Step 3: 加密前的编码
        // 使用单元素向量包装数字
        std::vector<double> vec5 = {5.0};
        std::vector<double> vec6 = {6.0};

        Plaintext ptxt5 = cc->MakeCKKSPackedPlaintext(vec5);
        Plaintext ptxt6 = cc->MakeCKKSPackedPlaintext(vec6);

        // Step 4: 加密
        auto ct5 = cc->Encrypt(keys.publicKey, ptxt5);
        auto ct6 = cc->Encrypt(keys.publicKey, ptxt6);

        // Step 5: 同态运算 - 计算差值：5 - 6
        auto ctDiff = cc->EvalSub(ct5, ct6);

        // Step 6: 解密并输出结果
        Plaintext result;
        cc->Decrypt(keys.secretKey, ctDiff, &result);
        result->SetLength(batchSize);

        std::cout << "5 - 6 = " << result->GetCKKSPackedValue()[0].real()  << std::endl;
        std::cout << myId << std::endl;
        double speed = mobility->getSpeed(); // 获取速度的模长
        std::cout << "Speed = " << speed << " m/s" << std::endl;

        Coord currentPos = mobility->getPositionAt(simTime());
        auto proj = projectPointOnPolyline(currentPos);
        auto offset = proj.second;

        // 存储所有的 Frenet 坐标，索引 0 对应当前坐标
        std::vector<FrenetCoord> frenetCoords;
        frenetCoords.reserve(10);
        frenetCoords.push_back(getFrenetCoordinates(currentPos));

        // 计算后续沿 polyline 的坐标
        for (int i = 1; i < 10; ++i) {
            auto coord = getCoordinateAtOffset(offset * i, speed);
            frenetCoords.push_back(getFrenetCoordinates(coord));
        }

        // 分别提取 s 和 d 分量
        std::vector<mpz_class> s_values, d_values;
        s_values.reserve(frenetCoords.size());
        d_values.reserve(frenetCoords.size());
        for (const auto& fc : frenetCoords) {
            s_values.push_back(fc.s);
            d_values.push_back(fc.d);
        }

        // 开始计时 - 加密时间
        auto enc_start = std::chrono::high_resolution_clock::now();

        // 对所有 s 和 d 值执行加密操作
        for (size_t i = 0; i < s_values.size(); ++i) {
            pcs_encrypt(pk.get(), hr.get(), s_values[i].get_mpz_t(), s_values[i].get_mpz_t());
            pcs_encrypt(pk.get(), hr.get(), d_values[i].get_mpz_t(), d_values[i].get_mpz_t());
        }


        // 结束计时
        auto enc_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> enc_duration = enc_end - enc_start;

        // 累积加密时间和计数
        totalEncryptionTime += enc_duration.count();
        encryptionCount++;

        // 构造消息并发送
        mpz_class pk_n(pk.get()->n), pk_g(pk.get()->g);
        std::ostringstream oss;
        oss << "s_values:[";
        for (size_t i = 0; i < s_values.size(); ++i) {
            oss << s_values[i];
            if (i != s_values.size() - 1)
                oss << ",";
        }
        oss << "], d_values:[";
        for (size_t i = 0; i < d_values.size(); ++i) {
            oss << d_values[i];
            if (i != d_values.size() - 1)
                oss << ",";
        }
        oss << "], n:" << pk_n.get_str()
            << ", g:" << pk_g.get_str();

        std::string posStr = oss.str();
        std::cout << posStr << std::endl;
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setDemoData(posStr.c_str());
        newWSM->setSenderAddress(myId);
        networkStartTimeChrono = std::chrono::high_resolution_clock::now();
        sendDown(newWSM);
        scheduleAt(simTime() + 0.1, sendMessageEvent);

    }*/
}



void MyVeinsApp::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // Initialize the encryption environment.


    // Get the current position and encrypt the coordinates.

}
