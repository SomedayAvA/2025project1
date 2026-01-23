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
#include "veins/modules/application/traci/pedestrian2.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::Status;
using namespace veins;
using namespace bigintdyn;

Define_Module(veins::pedestrian2);

// Global CKKS crypto context and initialization flag.

//----------------------------------------------------------------------------
// CKKS Class Implementation
//----------------------------------------------------------------------------
pedestrian2::~pedestrian2() {
    cancelAndDelete(sendMessageEvent);
}

// Called at different initialization stages of the simulation.
void pedestrian2::initialize(int stage) {
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        std::string vehId = mobility->getExternalId();
        vehicleEntryTimes[vehId] = simTime();
        std::string myType = traciVehicle->getVType();
        //if(myType=="pedestrian")
        //{
            TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
            traciVehicle.setSpeedMode(96);
        //    std::cout << "1111111111" << std::endl;
        //}
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = 22;
        sendMessageEvent = new cMessage("sendMessageEvent");
        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}


void pedestrian2::finish() {
    DemoBaseApplLayer::finish();

    std::string vehId = mobility->getExternalId();
    simtime_t exitTime = simTime();

    if (vehicleEntryTimes.find(vehId) != vehicleEntryTimes.end()) {
        simtime_t lifetime = exitTime - vehicleEntryTimes[vehId];
        vehicleLifetimes.push_back(lifetime);
    }

    // Original position recording (kept unchanged)
    auto pos = mobility->getPositionAt(simTime());
    std::cout << myId << pos << std::endl;
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

void pedestrian2::onBSM(DemoSafetyMessage* bsm) {
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void pedestrian2::onWSM(BaseFrame1609_4* wsm) {

    // Cast the received message to our specific message type
    // DEFAULT_VEHTYPE
    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);
    std::string myType = traciVehicle->getVType();
    // If serial is not 0, it is a reply message; process collision warning logic
    if (receivedWSM->getmessagetype() == 1 && receivedWSM->getSerial() == myId) {


            //std::cout << receivedWSM->getSenderAddress() <<  std::endl;
            // Parse string containing distance data (e.g., semicolon-separated numbers)
            const char* demoDataCStr = receivedWSM->getdistancearray();
            std::string demoDataStr(demoDataCStr);
            std::vector<double> distances;
            std::istringstream dataStream(demoDataStr);
            std::string token;
            TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());

            // Get remote vehicle ID (SenderAddress was stored when sending)
            int remoteID = receivedWSM->getSenderAddress();
            int i = 0;
            while (std::getline(dataStream, token, ';')) {
                try {
                    double d = std::stod(token);
                    //std::cout << i <<":" <<d << std::endl;
                    i++;
                    distances.push_back(d);
                } catch (const std::exception& e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
            bool collisionRisk = checkDistancesCondition(distances).first;
            if (collisionRisk && (decelerationResponsibles.find(remoteID) == decelerationResponsibles.end()))
            {
                //std::cout << "1111111111111111." << std::endl;
                Coord currentPos = mobility->getPositionAt(simTime());
                double speed = mobility->getSpeed();
                TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
                double acceleration = veh.getAcceleration();
                double t = 0.3;
                auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), checkDistancesCondition(distances).second*t);
                double dx = currentPos.x - newPosPair.first;
                double dy = currentPos.y - newPosPair.second;
                double distance = dx * dx + dy * dy;

                TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
                populateWSM(replyMsg);
                replyMsg->setSenderAddress(myId);
                replyMsg->setSerial(receivedWSM->getSenderAddress());
                replyMsg->setmessagetype(2);
                replyMsg->setx(newPosPair.first);
                replyMsg->sety(newPosPair.second);
                replyMsg->setdistance(distance);
                if(myType =="pedestrian")
                {
                    replyMsg->setvtype(1);
                }

                sendDelayed(replyMsg, uniform(0, 0.01), "lowerLayerOut");
            }
    }

    if (receivedWSM->getmessagetype() == 0) {
        simtime_t currentTime = simTime();

        const char* demoDataCStr = receivedWSM->getDemoData();
        std::string demoDataStr(demoDataCStr);

        // Parse point data containing x and y coordinates (assuming semicolon separator, comma between x,y)
        std::vector<double> x;
        std::vector<double> y;
        std::istringstream dataStream(demoDataStr);
        std::string pointStr;
        while (std::getline(dataStream, pointStr, ';')) {
            std::istringstream pointStream(pointStr);
            std::string xStr, yStr;
            if (std::getline(pointStream, xStr, ',') && std::getline(pointStream, yStr)) {
                try {
                    x.push_back(std::stod(xStr));
                    y.push_back(std::stod(yStr));
                } catch (const std::exception &e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
        }

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
        std::vector<double> distances;
        for (size_t i = 0; i < fixBatchSize; ++i) {
            double dx = predictedX[i] - x[i];
            double dy = predictedY[i] - y[i];
            double distance = std::sqrt(dx * dx + dy * dy);
            distances.push_back(distance);
        }
        // Construct reply message, send out predicted distance differences
        TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
        populateWSM(replyMsg);

        replyMsg->setSenderAddress(myId);
        replyMsg->setSerial(receivedWSM->getSenderAddress());
        // Send current vehicle speed as demoData

        std::ostringstream oss;
        for (size_t i = 0; i < distances.size(); ++i) {

            oss << distances[i];
            if (i != distances.size() - 1) {
                oss << ";";
            }
        }
        std::string distanceStr = oss.str();
        replyMsg->setdistancearray(distanceStr.c_str());
        replyMsg->setmessagetype(1);
        if(myType =="pedestrian")
        {
            replyMsg->setvtype(1);
        }
        sendDelayed(replyMsg, uniform(0, 0.01), "lowerLayerOut");
    }
    if (receivedWSM->getmessagetype() == 2 && receivedWSM->getSerial() == myId)
    {

        if(myType !="pedestrian" && receivedWSM->getvtype()==1)
        {
            return;
        }
        if(myType =="pedestrian" && receivedWSM->getvtype()==0)
        {
            TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
            double speed = mobility->getSpeed();
            if(speed > 2)
            {
                speed= speed - 2;
            }
            else
            {
                speed = 0;
            }
            traciVehicle.slowDown(speed, 1);
            //std::cout << "Pedestrian slowing down due to collision risk." << std::endl;
            return;
        }
        TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
        Coord currentPos = mobility->getPositionAt(simTime());
        double dx = currentPos.x - receivedWSM->getx();
        double dy = currentPos.y - receivedWSM->gety();
        double distance = dx * dx + dy * dy;

        int remoteID = receivedWSM->getSenderAddress();
        if (collisionWarnings.find(remoteID) == collisionWarnings.end()) {
            collisionWarnings.insert(remoteID);
        if(distance > receivedWSM->getdistance())
        {
           decelerationResponsibles.insert(remoteID);
        }
        }
        if (decelerationResponsibles.find(remoteID) != decelerationResponsibles.end()) {
        double speed = mobility->getSpeed();
        if(speed > 2)
        {
            speed= speed - 2;
        }
        else
        {
            speed = 0;
        }
        traciVehicle.slowDown(speed, 1);
        //std::cout << "(" << mobility->getExternalId() << ")" << myId << " slowing down due to collision risk with remote vehicle " << remoteID
        //       << "." << std::endl;
        }
    }
}



void pedestrian2::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}

// Handle self messages (timer events).
void pedestrian2::handleSelfMsg(cMessage* msg) {

    if (msg == sendMessageEvent) {

        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        double acceleration = veh.getAcceleration();
        Coord currentPos = mobility->getPositionAt(simTime());
        std::vector<double> predictedX;
        std::vector<double> predictedY;
        predictedX.push_back(currentPos.x);
        predictedY.push_back(currentPos.y);

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
        std::string myType = traciVehicle->getVType();

        if(myType =="pedestrian")
        {
            newWSM->setvtype(1);
        }
        sendDown(newWSM);


        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}

void pedestrian2::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
