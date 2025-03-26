#include <gmpxx.h>
#include <libhcs.h>
#include <sstream>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include <random>
#include <utility>
#include <vector>
#include <array>
#include <chrono>
#include <string>
#include <limits>
#include <sstream>
#include <cppcodec/base64_default_rfc4648.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "veins/modules/application/traci/CKKS.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"

using namespace veins;
using namespace bigintdyn;

Define_Module(veins::CKKS);

// Global CKKS crypto context and initialization flag.
CryptoContext<DCRTPoly> cryptoContext;
int globalInitFlag = 0;
const int fixBatchSize = 16;


//----------------------------------------------------------------------------
// Helper: Compute new position using kinematics
//----------------------------------------------------------------------------
std::pair<double, double> computeNewPosition(double x, double y,
                                               double speed, double acceleration,
                                               double angleDeg, double t) {
    double angleRad = angleDeg * M_PI / 180.0;
    if (acceleration > 100)
        acceleration = 0;
    // s = v*t + 0.5*a*t^2
    double displacement = speed * t + 0.5 * acceleration * t * t;
    double deltaX = displacement * sin(angleRad);
    double deltaY = -displacement * cos(angleRad);
    return std::make_pair(x + deltaX, y + deltaY);
}

//----------------------------------------------------------------------------
// Helper: Check distance condition
//----------------------------------------------------------------------------
bool checkDistancesCondition(const std::array<double, fixBatchSize>& distances) {
    int minIndex = 0;
    double minValue = distances[0];
    for (int i = 1; i < distances.size(); i++) {
        if (distances[i] < minValue) {
            minValue = distances[i];
            minIndex = i;
        }
    }
    // Return false if minimum value is not less than threshold (1.8)
    if (minValue >= 1.8)
        return false;
    // Ensure left side is strictly decreasing
    for (int i = 1; i <= minIndex; i++) {
        if (distances[i] >= distances[i - 1])
            return false;
    }
    // Ensure right side is strictly increasing
    for (int i = minIndex + 1; i < distances.size(); i++) {
        if (distances[i] <= distances[i - 1])
            return false;
    }
    return true;
}
//----------------------------------------------------------------------------
// Base64 Utility Functions using OpenSSL
//----------------------------------------------------------------------------
std::string Base64Encode(const std::string& binary) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, binary.data(), binary.size());
    BIO_flush(bio);
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

std::string Base64Decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    std::vector<char> buffer(encoded.size());
    int decodedSize = BIO_read(bio, buffer.data(), encoded.size());
    std::string decoded(buffer.data(), decodedSize);
    BIO_free_all(bio);
    return decoded;
}

template <typename T>
T deserializeFromBase64(const std::string& encoded) {
    std::string decoded = Base64Decode(encoded);
    std::stringstream ss(decoded);
    T obj;
    lbcrypto::Serial::Deserialize(obj, ss, lbcrypto::SerType::SERBINARY());
    return obj;
}

template <typename T>
std::string serializeToBase64(const T& obj) {
    std::stringstream ss;
    lbcrypto::Serial::Serialize(obj, ss, lbcrypto::SerType::SERBINARY());
    return Base64Encode(ss.str());
}

//----------------------------------------------------------------------------
// CKKS Class Implementation
//----------------------------------------------------------------------------
CKKS::~CKKS() {
    cancelAndDelete(sendMessageEvent);
}
void CKKS::initEncryptionEnv() {

    // Set encryption parameters.
    if (globalInitFlag == 0) {
    uint32_t multDepth   = 1; //Defines maximum consecutive multiplications allowed, affecting noise growth and overall precision.
    uint32_t scaleModSize = 20; //Sets the bit-length of the scaling modulus for rescaling, influencing numerical precision and noise tolerance.
    uint32_t batchSize    = fixBatchSize; //Determines the number of plaintext values packed per ciphertext, enabling efficient parallel computations.

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

    cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    globalInitFlag++;
    }
    auto keys = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keys.secretKey);
    publicKey = keys.publicKey;
    privateKey = keys.secretKey;
    TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());

    traciVehicle.setSpeedMode(32);
}

// Called at different initialization stages of the simulation.
void CKKS::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = 22;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() +0.1 + uniform(-0.001, 0.001), sendMessageEvent);
        initEncryptionEnv();
    }
}


void CKKS::finish() {
    DemoBaseApplLayer::finish();
    if (errorRateCount > 0) {
        double avgError = totalErrorRate / errorRateCount;
        std::cout << "Average error rate: " << avgError << std::endl;
    }
    if (encryptionCount > 0) {
        double avgEncryptionTime = totalEncryptionTime / encryptionCount;
        std::cout << "Average Encryption Time: " << avgEncryptionTime << " ms" << std::endl;
    }
    if (decryptionCount > 0) {
        double avgDecryptionTime = totalDecryptionTime / decryptionCount;
        std::cout << "Average Decryption Time: " << avgDecryptionTime << " ms" << std::endl;
    }
    if (computationCount > 0) {
        double avgComputationTime = totalComputationTime / computationCount;
        std::cout << "Average Computation Time: " << avgComputationTime << " ms" << std::endl;
    }
    if (networkCount > 0) {
        double avgNetworkTime = totalNetworkTime / networkCount;
        std::cout << "Average Network Time: " << avgNetworkTime << " ms" << std::endl;
    }
}

void CKKS::onBSM(DemoSafetyMessage* bsm) {
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void CKKS::onWSM(BaseFrame1609_4* wsm) {
    // Cast the incoming message to our specific message type.
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);

    // If serial equals 1, this is a reply message containing encrypted differences.
    if (receivedWSM->getSerial() != 0) {
        if(receivedWSM->getSerial() == myId)
        {
        std::cout << mobility->getExternalId()<<":"<< mobility->getSpeed() << std::endl;
        // Deserialize the two ciphertexts from the received message.
        auto s1_deserialized = deserializeFromBase64<Ciphertext<DCRTPoly>>(receivedWSM->getS1Ciphertext());
        auto d1_deserialized = deserializeFromBase64<Ciphertext<DCRTPoly>>(receivedWSM->getD1Ciphertext());

        Plaintext result, result1;
        auto dec_start = std::chrono::high_resolution_clock::now();
        cryptoContext->Decrypt(privateKey, s1_deserialized, &result);

        result->SetLength(fixBatchSize);
        cryptoContext->Decrypt(privateKey, d1_deserialized, &result1);
        result1->SetLength(fixBatchSize);
        auto dec_end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> dec_duration = dec_end - dec_start;
        totalDecryptionTime += dec_duration.count();
        decryptionCount++;

        std::array<double, fixBatchSize> distances;
        Coord currentPos = mobility->getPositionAt(simTime());
        FrenetCoord originalFrenet = getFrenetCoordinates(currentPos);
        // For each of the first 10 decrypted values, compute the minimum distance.
        for (int i = 0; i < fixBatchSize; i++) {
            long double d1 = result->GetCKKSPackedValue()[i].real();
            long double d2 = result1->GetCKKSPackedValue()[i].real();

            const std::array<std::pair<double, double>, 4> candidates = {{
                {originalFrenet.s + d1, originalFrenet.d + d2},
                {originalFrenet.s + d1, originalFrenet.d - d2},
                {originalFrenet.s - d1, originalFrenet.d + d2},
                {originalFrenet.s - d1, originalFrenet.d - d2}
            }};
            double minDistance = std::numeric_limits<double>::max();
            if(i==0)
            {
            for (const auto& candidate : candidates) {
                Coord cartesianCandidate = getCartesianFromFrenet(candidate.first, candidate.second);
                double dx = cartesianCandidate.x - currentPos.x;
                double dy = cartesianCandidate.y - currentPos.y;
                double candidateDistance = std::hypot(dx, dy);
                if (candidateDistance < minDistance) {
                    minDistance = candidateDistance;
                }
            }
            }
            else {
                for (const auto& candidate : candidates) {
                    Coord candCart = getCartesianFromFrenet(candidate.first, candidate.second);
                    double candidateDistance = std::hypot(candCart.x - currentPos.x, candCart.y - currentPos.y);
                    // Candidate is valid if difference with previous is within 11.2
                    if (candidateDistance < minDistance && std::abs(candidateDistance - distances[i - 1]) <= 11.2)
                        minDistance = candidateDistance;
                }
                // Fallback: if no candidate meets the threshold, choose the overall minimum
                if (minDistance == std::numeric_limits<double>::max()) {
                    for (const auto& candidate : candidates) {
                        Coord candCart = getCartesianFromFrenet(candidate.first, candidate.second);
                        double candidateDistance = std::hypot(candCart.x - currentPos.x, candCart.y - currentPos.y);
                        if (candidateDistance < minDistance)
                            minDistance = candidateDistance;
                    }
                }
            }
            distances[i] = minDistance;
            std::cout << "Distance[" << i << "]: " << minDistance << std::endl;
        }

        // Get the plaintext distances sent from the sender.
        std::string plainDistancesStr = std::string(receivedWSM->getSValues());
        std::vector<double> distancesPlain;
        std::istringstream iss(plainDistancesStr);
        std::string token;
        while (std::getline(iss, token, ',')) {
            distancesPlain.push_back(std::stod(token));
        }

        // Compute the error rate for each index: |distances - distancesPlain| / distancesPlain.

        std::vector<double> errorRates;
        for (size_t i = 0; i < std::min(distancesPlain.size(), distances.size()); i++) {
            double error = std::abs(distances[i] - distancesPlain[i]) / distancesPlain[i];
            errorRates.push_back(error);
            // Accumulate global error values.
            totalErrorRate += error;
            errorRateCount++;
        }


        double demoDataValue = std::stod(std::string(receivedWSM->getDemoData()));
        if (checkDistancesCondition(distances) && (demoDataValue <= mobility->getSpeed())) {
            TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
            traciVehicle.slowDown(demoDataValue/2, 1);
            std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
            std::cout << "!!!!!!!!!!!!!!!! SLOW DOWN: " << mobility->getExternalId() << std::endl;
            std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;

        }
        auto networkEndTimeChrono = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> networkDelayChrono = networkEndTimeChrono - networkStartTimeChrono;
        totalNetworkTime += networkDelayChrono.count();
        networkCount++;
        return;
    }
        else
            return;
    }
    else
    {
    // Process a new message (not a reply).
    std::string senderSValuesStr = receivedWSM->getSValues();
    std::string senderDValuesStr = receivedWSM->getDValues();
    std::vector<double> senderSValues, senderDValues;

    {
        std::istringstream ss(senderSValuesStr);
        std::string token;
        while (std::getline(ss, token, ',')) {
            senderSValues.push_back(std::stod(token));
        }
    }
    {
        std::istringstream ss(senderDValuesStr);
        std::string token;
        while (std::getline(ss, token, ',')) {
            senderDValues.push_back(std::stod(token));
        }
    }
    std::vector<Coord> senderCoords;
    for (size_t i = 0; i < senderSValues.size(); i++) {
        Coord c = getCartesianFromFrenet(senderSValues[i], senderDValues[i]);
        senderCoords.push_back(c);
    }

    double speed = mobility->getSpeed();

    TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
    double acceleration = veh.getAcceleration();
    //std::cout << myId<<acceleration<< std::endl;
    Coord currentPos = mobility->getPositionAt(simTime());
    // Store all Frenet coordinates (index 0 is current position).
    std::vector<FrenetCoord> frenetCoords;
    frenetCoords.reserve(fixBatchSize);
    frenetCoords.push_back(getFrenetCoordinates(currentPos));

    // Calculate subsequent coordinates along the polyline.
    for (int i = 1; i < fixBatchSize; ++i) {
        double t = 0.1 * i;
        auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
        Coord newPos(newPosPair.first, newPosPair.second);
        frenetCoords.push_back(getFrenetCoordinates(newPos));
    }

    // Extract s and d components from the Frenet coordinates.
    std::vector<double> s_values, d_values;
    s_values.reserve(frenetCoords.size());
    d_values.reserve(frenetCoords.size());
    for (const auto& fc : frenetCoords) {
        s_values.push_back(fc.s);
        d_values.push_back(fc.d);
    }

    std::vector<Coord> localCoords;
    for (size_t i = 0; i < s_values.size(); i++) {
        Coord c = getCartesianFromFrenet(s_values[i], d_values[i]);
        localCoords.push_back(c);
    }
    std::vector<double> distancesPlain;
    for (size_t i = 0; i < std::min(senderCoords.size(), localCoords.size()); i++) {
        double dx = senderCoords[i].x - localCoords[i].x;
        double dy = senderCoords[i].y - localCoords[i].y;
        double d = std::hypot(dx, dy);
        distancesPlain.push_back(d);
    }

    Plaintext s_values1 = cryptoContext->MakeCKKSPackedPlaintext(s_values);
    Plaintext d_values1 = cryptoContext->MakeCKKSPackedPlaintext(d_values);

    // Deserialize the sender's public key.
    auto receivePublicKey = deserializeFromBase64<PublicKey<DCRTPoly>>(receivedWSM->getPublicKeyStr());

    auto comp_start = std::chrono::high_resolution_clock::now();
    // Encrypt the computed plaintexts using the received public key.
    Ciphertext<DCRTPoly> s2 = cryptoContext->Encrypt(receivePublicKey, s_values1);
    Ciphertext<DCRTPoly> d2 = cryptoContext->Encrypt(receivePublicKey, d_values1);

    // Deserialize the original ciphertexts from the received message.
    auto s1_deserialized = deserializeFromBase64<Ciphertext<DCRTPoly>>(receivedWSM->getS1Ciphertext());
    auto d1_deserialized = deserializeFromBase64<Ciphertext<DCRTPoly>>(receivedWSM->getD1Ciphertext());

    // Compute the differences between the received ciphertexts and the newly encrypted ones.
    Ciphertext<DCRTPoly> sSub = cryptoContext->EvalSub(s1_deserialized, s2);
    Ciphertext<DCRTPoly> dSub = cryptoContext->EvalSub(d1_deserialized, d2);
    auto comp_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> comp_duration = comp_end - comp_start;
    totalComputationTime += comp_duration.count();
    computationCount++;

    // Prepare and send the reply message with the computed differences.
    TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
    populateWSM(replyMsg);

    replyMsg->setS1Ciphertext(serializeToBase64(sSub).c_str());
    replyMsg->setD1Ciphertext(serializeToBase64(dSub).c_str());
    replyMsg->setSenderAddress(myId);
    replyMsg->setSerial(receivedWSM->getSenderAddress());
    std::string speedStr = std::to_string(speed);
    replyMsg->setDemoData(speedStr.c_str());
    std::ostringstream oss;
    for (size_t i = 0; i < distancesPlain.size(); i++) {
        oss << distancesPlain[i];
        if (i != distancesPlain.size() - 1)
            oss << ",";
    }
    std::string distancesPlainStr = oss.str();

    // Assuming your TraCIDemo11pMessage class has a field for plain distances.
    replyMsg->setSValues(distancesPlainStr.c_str());
    sendDown(replyMsg);
}
}


void CKKS::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}

// Handle self messages (timer events).
void CKKS::handleSelfMsg(cMessage* msg) {
    if (msg == sendMessageEvent) {
        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        double acceleration = veh.getAcceleration();
        Coord currentPos = mobility->getPositionAt(simTime());
        std::vector<FrenetCoord> frenetCoords;
        frenetCoords.reserve(fixBatchSize);
        frenetCoords.push_back(getFrenetCoordinates(currentPos));

        // Compute future positions using kinematics.
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.1 * i;
            auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
            Coord newPos(newPosPair.first, newPosPair.second);
            frenetCoords.push_back(getFrenetCoordinates(newPos));
        }
        // Extract s and d components.
        std::vector<double> s_values, d_values;
        s_values.reserve(frenetCoords.size());
        d_values.reserve(frenetCoords.size());
        for (const auto& fc : frenetCoords) {
            s_values.push_back(fc.s);
            d_values.push_back(fc.d);
        }
        Plaintext s_values1 = cryptoContext->MakeCKKSPackedPlaintext(s_values);
        Plaintext d_values1 = cryptoContext->MakeCKKSPackedPlaintext(d_values);
        auto enc_start = std::chrono::high_resolution_clock::now();
        Ciphertext<DCRTPoly> s1 = cryptoContext->Encrypt(publicKey, s_values1);
        Ciphertext<DCRTPoly> d1 = cryptoContext->Encrypt(publicKey, d_values1);
        auto enc_end = std::chrono::high_resolution_clock::now();
        totalEncryptionTime += std::chrono::duration<double, std::milli>(enc_end - enc_start).count();
        encryptionCount++;

        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setSenderAddress(myId);
        newWSM->setS1Ciphertext(serializeToBase64(s1).c_str());
        newWSM->setD1Ciphertext(serializeToBase64(d1).c_str());
        newWSM->setPublicKeyStr(serializeToBase64(publicKey).c_str());
        // Convert s and d values to comma-separated strings.
        std::ostringstream sStream, dStream;
        for (size_t i = 0; i < s_values.size(); i++) {
            sStream << s_values[i];
            if (i != s_values.size() - 1)
                sStream << ",";
        }
        for (size_t i = 0; i < d_values.size(); i++) {
            dStream << d_values[i];
            if (i != d_values.size() - 1)
                dStream << ",";
        }
        newWSM->setSValues(sStream.str().c_str());
        newWSM->setDValues(dStream.str().c_str());
        networkStartTimeChrono = std::chrono::high_resolution_clock::now();
        sendDown(newWSM);
        scheduleAt(simTime() + 0.1 + uniform(-0.001, 0.001), sendMessageEvent);
    }
}

void CKKS::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
