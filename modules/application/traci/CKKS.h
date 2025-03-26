#pragma once

#include "veins/veins.h"
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <memory>
#include <string>
#include <utility>
#include <gmpxx.h>
#include <openfhe/pke/openfhe.h>
#include <chrono>
using namespace omnetpp;
using namespace bigintdyn;
namespace veins {

class VEINS_API CKKS : public DemoBaseApplLayer {
public:

    virtual ~CKKS();
    CKKS()
        : hr(nullptr, hcs_free_random),
          pk(nullptr, pcs_free_public_key),
          vk(nullptr, pcs_free_private_key){}
    void initialize(int stage) override;
    void finish() override;

protected:
    void onBSM(DemoSafetyMessage* bsm) override;
    void onWSM(BaseFrame1609_4* wsm) override;
    void onWSA(DemoServiceAdvertisment* wsa) override;
    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;
    simtime_t lastDroveAt;
    bool sentMessage;
    int currentSubscribedServiceId;
    double totalErrorRate = 0.0;
    int errorRateCount = 0;
private:

    std::unique_ptr<hcs_random, decltype(&hcs_free_random)> hr;
    std::unique_ptr<pcs_public_key, decltype(&pcs_free_public_key)> pk;
    std::unique_ptr<pcs_private_key, decltype(&pcs_free_private_key)> vk;
    PublicKey<DCRTPoly> publicKey;
    PrivateKey<DCRTPoly> privateKey;

    void initEncryptionEnv();
    cMessage* sendMessageEvent;
    double totalEncryptionTime = 0.0;  // 累计加密时间（毫秒）
    size_t encryptionCount = 0;        // 加密次数

    double totalDecryptionTime = 0.0;  // 累计解密时间（毫秒）
    size_t decryptionCount = 0;        // 解密次数

    double totalComputationTime = 0.0; // 累计其他计算时间（毫秒）
    size_t computationCount = 0;
    double totalNetworkTime = 0.0; // 累计其他计算时间（毫秒）
    size_t networkCount = 0;
    std::chrono::time_point<std::chrono::high_resolution_clock> networkStartTimeChrono;

    std::pair<mpz_class, mpz_class> extractEncryptedCoordinates(const std::string &data);
};

} // namespace veins

