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
#include "veins/modules/application/traci/method5.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::Status;
using namespace veins;
using namespace bigintdyn;

Define_Module(veins::method5);
// Two turn fixed distance
// Global CKKS crypto context and initialization flag.


//----------------------------------------------------------------------------
// CKKS Class Implementation
//----------------------------------------------------------------------------
method5::~method5() {
    cancelAndDelete(sendMessageEvent);
}

// Called at different initialization stages of the simulation.
void method5::initialize(int stage) {
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


void method5::finish() {
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

    // Calculate average lifetime and record to file
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


void method5::onBSM(DemoSafetyMessage* bsm) {
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void method5::onWSM(BaseFrame1609_4* wsm) {
    // Cast the received message to our specific message type

    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);

    // If serial is not 0, it indicates a reply message; process collision warning logic
    if (receivedWSM->getmessagetype() == 1 && receivedWSM->getSerial() == myId) {

            //std::cout << "(111111" << std::endl;
            //std::cout << receivedWSM->getSenderAddress() <<  std::endl;
            // Parse the string containing distance data (e.g., semicolon-separated numbers)
            const char* demoDataCStr = receivedWSM->getdistancearray();
            std::string demoDataStr(demoDataCStr);
            std::vector<double> distances;
            std::istringstream dataStream(demoDataStr);
            std::string token;
            TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());

            // Get the remote vehicle ID (Sender address was stored in SenderAddress)
            int remoteID = receivedWSM->getSenderAddress();
            int i = 0;
            while (std::getline(dataStream, token, ';')) {
                try {
                    double d = std::stod(token);
                    i++;
                    distances.push_back(d);
                } catch (const std::exception& e) {
                    std::cerr << "Error: " << e.what() << std::endl;
                }
            }
            bool collisionRisk = checkDistancesCondition(distances).first;
            if (collisionRisk && (decelerationResponsibles.find(remoteID) == decelerationResponsibles.end()))
            {

                Coord currentPos = mobility->getPositionAt(simTime());
                double speed = mobility->getSpeed();
                TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
                double acceleration = veh.getAcceleration();
                std::cout << "speed" << speed << std::endl;
                std::cout << "acceleration" << acceleration << std::endl;

                std::vector<double> cumDistances;
                cumDistances.push_back(0.0);
                for (size_t i = 1; i < curvePoints.size(); ++i) {
                    double d = distanceBetween(curvePoints[i-1], curvePoints[i]);
                    cumDistances.push_back(cumDistances.back() + d);
                }
                std::vector<double> cumDistances1;
                cumDistances1.push_back(0.0);
                for (size_t i = 1; i < curvePoints1.size(); ++i) {
                    double d = distanceBetween(curvePoints1[i-1], curvePoints1[i]);
                    cumDistances1.push_back(cumDistances1.back() + d);
                }
                std::string vehId = mobility->getExternalId();
                if (vehId.find("flow1") != std::string::npos) {
                for (int i = 0; i < checkDistancesCondition(distances).second; ++i) {
                    double t = 0.3 ;
                    if(!(currentPos.x>321.732&&currentPos.x<=330.906))
                    {
                        auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
                        currentPos.x = newPosPair.first;
                        currentPos.y = newPosPair.second;
                    }
                    else
                    {
                        double s = speed * t + 0.5 * acceleration * t * t;
                        double targetDistance = projectOntoCurve(curvePoints, cumDistances, currentPos) + s;
                        auto newPosPair = interpolateOnCurve(curvePoints, targetDistance, cumDistances);
                        currentPos.x = newPosPair.x;
                        currentPos.y = newPosPair.y;
                    }
                    speed = speed + t*acceleration;

                }
                }
                if (vehId.find("flow2") != std::string::npos) {
                    for (int i = 0; i < checkDistancesCondition(distances).second; ++i) {
                    double t = 0.3 ;
                    if(!(currentPos.x>=316.891&&currentPos.x<321.845))
                    {
                        auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
                        currentPos.x = newPosPair.first;
                        currentPos.y = newPosPair.second;
                    }
                    else
                    {
                        double s = speed * t + 0.5 * acceleration * t * t;
                        double targetDistance = projectOntoCurve(curvePoints1, cumDistances1, currentPos) + s;
                        auto newPosPair = interpolateOnCurve(curvePoints1, targetDistance, cumDistances1);
                        currentPos.x = newPosPair.x;
                        currentPos.y = newPosPair.y;
                    }
                    speed = speed + t*acceleration;
                }
                }
                Coord currentPos1 = mobility->getPositionAt(simTime());
                double dx = currentPos.x - currentPos1.x;
                double dy = currentPos.y - currentPos1.y;
                double distance = dx * dx + dy * dy;

                TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
                populateWSM(replyMsg);
                replyMsg->setSenderAddress(myId);
                replyMsg->setSerial(receivedWSM->getSenderAddress());
                replyMsg->setmessagetype(2);
                replyMsg->setx(currentPos.x);
                replyMsg->sety(currentPos.y);
                replyMsg->setdistance(distance);
                //sendDown(replyMsg);
                sendDelayed(replyMsg, uniform(0, 0.01), "lowerLayerOut");


            }
    }

    if (receivedWSM->getmessagetype() == 0) {
        //std::cout << "000000"<< std::endl;
        simtime_t currentTime = simTime();

        const char* demoDataCStr = receivedWSM->getDemoData();
        std::string demoDataStr(demoDataCStr);

        // Parse point data containing x and y coordinates (assuming semicolon separator, comma between x and y)
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

        std::vector<double> cumDistances;
        cumDistances.push_back(0.0);
        for (size_t i = 1; i < curvePoints.size(); ++i) {
            double d = distanceBetween(curvePoints[i-1], curvePoints[i]);
            cumDistances.push_back(cumDistances.back() + d);
        }
        std::vector<double> cumDistances1;
        cumDistances1.push_back(0.0);
        for (size_t i = 1; i < curvePoints1.size(); ++i) {
            double d = distanceBetween(curvePoints1[i-1], curvePoints1[i]);
            cumDistances1.push_back(cumDistances1.back() + d);
        }
        std::string vehId = mobility->getExternalId();
        if (vehId.find("flow1") != std::string::npos) {
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            if(!(currentPos.x>321.732&&currentPos.x<=330.906))
            {
                auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
                currentPos.x = newPosPair.first;
                currentPos.y = newPosPair.second;
            }
            else
            {
                double s = speed * t + 0.5 * acceleration * t * t;
                double targetDistance = projectOntoCurve(curvePoints, cumDistances, currentPos) + s;
                auto newPosPair = interpolateOnCurve(curvePoints, targetDistance, cumDistances);
                currentPos.x = newPosPair.x;
                currentPos.y = newPosPair.y;
            }
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }
        }
        if (vehId.find("flow2") != std::string::npos) {
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            if(!(currentPos.x>=316.891&&currentPos.x<321.845))
            {
                auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
                currentPos.x = newPosPair.first;
                currentPos.y = newPosPair.second;
            }
            else
            {
                double s = speed * t + 0.5 * acceleration * t * t;
                double targetDistance = projectOntoCurve(curvePoints1, cumDistances1, currentPos) + s;
                auto newPosPair = interpolateOnCurve(curvePoints1, targetDistance, cumDistances1);
                currentPos.x = newPosPair.x;
                currentPos.y = newPosPair.y;
            }
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }
        }
        std::vector<double> distances;
        for (size_t i = 0; i < fixBatchSize; ++i) {
            double dx = predictedX[i] - x[i];
            double dy = predictedY[i] - y[i];
            double distance = std::sqrt(dx * dx + dy * dy);
            distances.push_back(distance);
        }
        // Construct reply message, send out the predicted distance differences
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
        sendDelayed(replyMsg, uniform(0, 0.01), "lowerLayerOut");
    }
    if (receivedWSM->getmessagetype() == 2 && receivedWSM->getSerial() == myId)
    {
        //std::cout << "(222222" << std::endl;
        TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
        Coord currentPos = mobility->getPositionAt(simTime());
        double dx = currentPos.x - receivedWSM->getx();
        double dy = currentPos.y - receivedWSM->gety();
        std::cout << currentPos.x << std::endl;
        std::cout << currentPos.y << std::endl;
        std::cout << receivedWSM->getx() << std::endl;
        std::cout << receivedWSM->gety() << std::endl;
        double distance = dx * dx + dy * dy;
        int remoteID = receivedWSM->getSenderAddress();
        if (collisionWarnings.find(remoteID) == collisionWarnings.end()) {
            collisionWarnings.insert(remoteID);
        if(distance > receivedWSM->getdistance())
        {
           decelerationResponsibles.insert(remoteID);
           std::cout << distance << std::endl;
           std::cout << receivedWSM->getdistance() << std::endl;
        }
        }
        if (decelerationResponsibles.find(remoteID) != decelerationResponsibles.end()) {
        double speed = mobility->getSpeed();
        if(speed > 1)
        {
            speed= speed - 1;
        }
        else
        {
            speed = 0;
        }
        traciVehicle.slowDown(speed, 1);
        std::cout << "(" << mobility->getExternalId() << ")" << myId << " slowing down due to collision risk with remote vehicle " << remoteID
                << "." << std::endl;
        }
    }
}



void method5::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}

// Handle self messages (timer events).
void method5::handleSelfMsg(cMessage* msg) {

    if (msg == sendMessageEvent) {

        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());

        double acceleration = veh.getAcceleration();
        //std::cout << speed << ":" << acceleration << std::endl;
        Coord currentPos = mobility->getPositionAt(simTime());
        std::vector<double> cumDistances;
        cumDistances.push_back(0.0);
        for (size_t i = 1; i < curvePoints.size(); ++i) {
            double d = distanceBetween(curvePoints[i-1], curvePoints[i]);
            cumDistances.push_back(cumDistances.back() + d);
        }
        std::vector<double> cumDistances1;
        cumDistances1.push_back(0.0);
        for (size_t i = 1; i < curvePoints1.size(); ++i) {
            double d = distanceBetween(curvePoints1[i-1], curvePoints1[i]);
            cumDistances1.push_back(cumDistances1.back() + d);
        }
        std::vector<double> predictedX;
        std::vector<double> predictedY;
        predictedX.push_back(currentPos.x);
        predictedY.push_back(currentPos.y);
        double distance = (currentPos.x - 321.732)*(currentPos.x - 321.732)+(currentPos.y - 992.311)*(currentPos.y - 992.311);
        std::string vehId = mobility->getExternalId();
        if (vehId.find("flow1") != std::string::npos) {
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            if(!(currentPos.x>321.732&&currentPos.x<=330.906))
            {
                auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
                currentPos.x = newPosPair.first;
                currentPos.y = newPosPair.second;
            }
            else
            {
                double s = speed * t + 0.5 * acceleration * t * t;
                double targetDistance = projectOntoCurve(curvePoints, cumDistances, currentPos) + s;
                auto newPosPair = interpolateOnCurve(curvePoints, targetDistance, cumDistances);
                currentPos.x = newPosPair.x;
                currentPos.y = newPosPair.y;
            }
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }
        }
        if (vehId.find("flow2") != std::string::npos) {
        for (int i = 1; i < fixBatchSize; ++i) {
            double t = 0.3 ;
            if(!(currentPos.x>=316.891&&currentPos.x<321.845))
            {
                auto newPosPair = computeNewPosition(currentPos.x, currentPos.y, speed, acceleration, veh.getAngle(), t);
                currentPos.x = newPosPair.first;
                currentPos.y = newPosPair.second;
            }
            else
            {
                double s = speed * t + 0.5 * acceleration * t * t;
                double targetDistance = projectOntoCurve(curvePoints1, cumDistances1, currentPos) + s;
                auto newPosPair = interpolateOnCurve(curvePoints1, targetDistance, cumDistances1);
                currentPos.x = newPosPair.x;
                currentPos.y = newPosPair.y;
            }
            speed = speed + t*acceleration;
            predictedX.push_back(currentPos.x);
            predictedY.push_back(currentPos.y);
        }
        }
        // Extract s and d components.
        std::ostringstream oss;
        for (size_t i = 0; i < predictedX.size(); ++i) {
            oss << predictedX[i] << "," << predictedY[i];
            if (i != predictedX.size() - 1) {
                oss << ";";
            }
        }
        std::string strdistance = std::to_string(distance);
        std::string serializedData = oss.str();
        TraCIDemo11pMessage* newWSM = new TraCIDemo11pMessage();
        populateWSM(newWSM);
        newWSM->setSenderAddress(myId);
        newWSM->setdistancearray(strdistance.c_str());
        newWSM->setDemoData(serializedData.c_str());
        newWSM->setmessagetype(0);
        sendDown(newWSM);
        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}

void method5::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
