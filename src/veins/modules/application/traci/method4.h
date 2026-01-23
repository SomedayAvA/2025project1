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

class VEINS_API method4 : public DemoBaseApplLayer {
public:

    virtual ~method4();
    method4()
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
    std::string serialized_message;

private:
    std::map<std::string, simtime_t> vehicleEntryTimes;
    std::vector<simtime_t> vehicleLifetimes;
    std::unique_ptr<hcs_random, decltype(&hcs_free_random)> hr;
    std::unique_ptr<pcs_public_key, decltype(&pcs_free_public_key)> pk;
    std::unique_ptr<pcs_private_key, decltype(&pcs_free_private_key)> vk;
    PublicKey<DCRTPoly> publicKey;
    PrivateKey<DCRTPoly> privateKey;
    std::unordered_set<int> collisionWarnings;
    std::unordered_set<int> decelerationResponsibles;
    void initEncryptionEnv();
    cMessage* sendMessageEvent;
    double totalEncryptionTime = 0.0;
    size_t encryptionCount = 0;

    double totalDecryptionTime = 0.0;
    size_t decryptionCount = 0;

    double totalComputationTime = 0.0;
    size_t computationCount = 0;
    double totalNetworkTime = 0.0;
    size_t networkCount = 0;
    std::chrono::time_point<std::chrono::high_resolution_clock> networkStartTimeChrono;

    std::pair<mpz_class, mpz_class> extractEncryptedCoordinates(const std::string &data);
};

} // namespace veins

