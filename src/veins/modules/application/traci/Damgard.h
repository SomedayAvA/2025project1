#pragma once

#include "veins/veins.h"
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include <memory>
#include <string>
#include <utility>
#include <gmpxx.h>


using namespace omnetpp;

namespace veins {

class VEINS_API Damgard : public DemoBaseApplLayer {
public:

    virtual ~Damgard();
    Damgard()
        : hr(nullptr, hcs_free_random),
          pk(nullptr, egcs_free_public_key),
          vk(nullptr, egcs_free_private_key){}
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
private:

    std::unique_ptr<hcs_random, decltype(&hcs_free_random)> hr;
    std::unique_ptr<egcs_public_key, decltype(&egcs_free_public_key)> pk;
    std::unique_ptr<egcs_private_key, decltype(&egcs_free_private_key)> vk;
    void initEncryptionEnv();
    cMessage* sendMessageEvent;
    double totalEncryptionTime = 0.0;  // 累计加密时间（毫秒）
    size_t encryptionCount = 0;        // 加密次数

    double totalDecryptionTime = 0.0;  // 累计解密时间（毫秒）
    size_t decryptionCount = 0;        // 解密次数

    double totalComputationTime = 0.0; // 累计其他计算时间（毫秒）
    size_t computationCount = 0;

    std::pair<mpz_class, mpz_class> extractEncryptedCoordinates(const std::string &data);
};

} // namespace veins

