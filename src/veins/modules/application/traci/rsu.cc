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
#include<openssl/rand.h>
#include <openssl/pem.h>
#include "Interfaces.pb.h"
#include <google/protobuf/util/json_util.h>
#include "curve_utils.h"
#include "veins/modules/mac/ieee80211p/Mac1609_4.h"
#include "veins/modules/application/traci/rsu.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::Status;
using namespace veins;
using namespace bigintdyn;

Define_Module(veins::rsu);
// Intersection speed
// Global CKKS crypto context and initialization flag.

//----------------------------------------------------------------------------
// CKKS Class Implementation
//----------------------------------------------------------------------------
rsu::~rsu() {
    cancelAndDelete(sendMessageEvent);
}

// Called at different initialization stages of the simulation.
void rsu::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        std::string vehId = mobility->getExternalId();
        vehicleEntryTimes[vehId] = simTime();

        TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(vehId);
        traciVehicle.setSpeedMode(96);
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = 22;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}


void rsu::finish() {
    std::cout << a << std::endl;
    std::cout << b << std::endl;
    DemoBaseApplLayer::finish();

    std::string vehId = mobility->getExternalId();
    simtime_t exitTime = simTime();

    if (vehicleEntryTimes.find(vehId) != vehicleEntryTimes.end()) {
        simtime_t lifetime = exitTime - vehicleEntryTimes[vehId];
        vehicleLifetimes.push_back(lifetime);
    }

    // Original position recording (kept unchanged)
    auto pos = mobility->getPositionAt(simTime());
    std::cout << myId<<pos << std::endl;
        std::ofstream outFile("position.txt", std::ios::app);
        if (outFile.is_open()) {
            outFile << pos << std::endl;
            outFile.close();
        } else {
            std::cerr << "Cannot open file position.txt" << std::endl;
        }

    // Calculate average time and record to file
    double avgLifetime = 0.0;
    if (!vehicleLifetimes.empty()) {
        simtime_t sum = 0;
        for (auto& lt : vehicleLifetimes) sum += lt;
        avgLifetime = sum.dbl() / vehicleLifetimes.size();
    }

    std::ofstream timeFile("avg_vehicle_lifetime.txt", std::ios::app);
    if (timeFile.is_open()) {
        timeFile
                 << avgLifetime << "\n";
        timeFile.close();
    } else {
        std::cerr << "Cannot open file avg_vehicle_lifetime.txt" << std::endl;
    }
}


void rsu::onBSM(DemoSafetyMessage* bsm) {
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void rsu::onWSM(BaseFrame1609_4* wsm) {
    // Cast the received message to our specific message type
    //std::cout << "1111111111" << std::endl;
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    if(receivedWSM->getSenderAddress()!=myId&&receivedWSM->getmessagetype()==1)
    b++;
}



void rsu::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}

// Handle self messages (timer events).
void rsu::handleSelfMsg(cMessage* msg) {

    if (msg == sendMessageEvent) {

        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        double acceleration = veh.getAcceleration();
        Coord currentPos = mobility->getPositionAt(simTime());
        std::vector<double> predictedX;
        std::vector<double> predictedY;
        predictedX.push_back(currentPos.x);
        predictedY.push_back(currentPos.y);

        std::string vehId = mobility->getExternalId();
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            double s = speed * t + 0.5 * acceleration * t * t;
            auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
            currentPos.x = newPosPair.first;
            currentPos.y = newPosPair.second;
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }


        // Extract s and d components.
        std::ostringstream oss;
        for (size_t i = 0; i < predictedX.size(); ++i) {
            oss << predictedX[i] << "," << predictedY[i];
            if (i != predictedX.size() - 1) {
                oss << ";";
            }
        }

        std::string serializedData = oss.str();
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setSenderAddress(myId);
        newWSM->setDemoData(serializedData.c_str());
        newWSM->setmessagetype(0);

        sendDown(newWSM);
        a++;
        //std::cout << "(" << myId << ") send at "  << std::endl;
        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}

void rsu::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
