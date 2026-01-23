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
#include "veins/modules/application/traci/method2.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include "veins/modules/application/traci/FrenetUtils.h"
using google::protobuf::util::MessageToJsonString;
using google::protobuf::util::JsonStringToMessage;
using google::protobuf::util::Status;
using namespace veins;
using namespace bigintdyn;

Define_Module(veins::method2);
// two turn speed
// Global CKKS crypto context and initialization flag.

//----------------------------------------------------------------------------
// CKKS Class Implementation
//----------------------------------------------------------------------------
method2::~method2() {
    cancelAndDelete(sendMessageEvent);
}

// Called at different initialization stages of the simulation.
void method2::initialize(int stage) {
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


void method2::finish() {
    DemoBaseApplLayer::finish();

    std::string vehId = mobility->getExternalId();
    simtime_t exitTime = simTime();

    if (vehicleEntryTimes.find(vehId) != vehicleEntryTimes.end()) {
        simtime_t lifetime = exitTime - vehicleEntryTimes[vehId];
        vehicleLifetimes.push_back(lifetime);
    }

    // Record original position (kept unchanged)
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

void method2::onBSM(DemoSafetyMessage* bsm) {
    // Handle beacon messages from other vehicles or RSUs.
}

// Handle WSM (Wave Short Message) reception.
// Processes both encrypted coordinate messages and replies.
void method2::onWSM(BaseFrame1609_4* wsm) {
    // Cast the incoming message to our specific message type

    TraCIDemo11pMessage* receivedWSM = check_and_cast<TraCIDemo11pMessage*>(wsm);

    // If serial is not 0, this is a reply message; process collision warning logic
    if (receivedWSM->getSerial() != 0) {
        simtime_t currentTime1 = simTime();
           // Output simulation time directly (default format includes sub-second precision)
        //std::cout << "(" << myId << ") receive again " << currentTime1 <<"id"<<receivedWSM->getSenderAddress()<< std::endl;
        // Check if the message is a reply intended for this vehicle (Serial is used here to identify the destination vehicle)
        if (receivedWSM->getSerial() == myId) {
            //std::cout << receivedWSM->getSenderAddress() <<  std::endl;
            // Parse the string containing distance data (e.g., semicolon-separated numbers)
            const char* demoDataCStr = receivedWSM->getSValues();
            std::string demoDataStr(demoDataCStr);
            std::vector<double> distances;
            std::istringstream dataStream(demoDataStr);
            std::string token;
            int i = 0;
            double mySpeed = mobility->getSpeed();

            TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
            double acceleration = veh.getAcceleration();
            // Extract remote vehicle speed from demoData field (Note: Sender put their speed in this field)
            double remoteSpeed = std::stod(std::string(receivedWSM->getDemoData()));
            double remoteacceleration = std::stod(std::string(receivedWSM->getDValues()));
            // Get remote vehicle ID (Sender address was stored in SenderAddress)
            int remoteID = receivedWSM->getSenderAddress();
            while (std::getline(dataStream, token, ';')) {
                try {
                    double d = std::stod(token);
                    //std::cout << i <<":" <<d << std::endl;
                    i++;
                    distances.push_back(d);
                } catch (const std::exception& e) {
                    std::cerr << "Error converting distance: " << e.what() << std::endl;
                }
            }
            // Determine if collision risk exists (e.g., distance in decreasing interval is below a threshold)
            bool collisionRisk = checkDistancesCondition(distances).first;

            if (collisionRisk) {
                double a = mySpeed + checkDistancesCondition(distances).second*acceleration*0.1;
                double b = remoteSpeed+ checkDistancesCondition(distances).second*remoteacceleration*0.1;

                // If this is the first warning received from this remote vehicle, determine responsibility based on initial speeds
                if (collisionWarnings.find(remoteID) == collisionWarnings.end()) {
                    collisionWarnings.insert(remoteID);
                    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!first" << std::endl;
                    std::cout << "(" << mobility->getExternalId()<<"speed"<< mySpeed<<"id"<<myId<<std::endl;
                    /*for (int i = 0; i < 16; i++) {
                        std::cout << distances[i] << std::endl;
                    }*/
                    std::cout << a << std::endl;
                    std::cout << acceleration << std::endl;
                    std::cout << b << std::endl;
                    std::cout << remoteacceleration << std::endl;

                    std::cout <<checkDistancesCondition(distances).second<< std::endl;
                    std::cout <<mySpeed<< std::endl;
                    std::cout <<remoteSpeed<< std::endl;
                    std::cout << simTime()<< std::endl;
                    // If current vehicle speed is higher than the other, this vehicle is responsible for deceleration
                    if (mySpeed > remoteSpeed) {
                        decelerationResponsibles.insert(remoteID);
                    }
                }
                // If this vehicle is determined to be responsible for deceleration in this pair, execute deceleration
                if (decelerationResponsibles.find(remoteID) != decelerationResponsibles.end()) {
                    TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
                    // Deceleration logic can be adjusted here; example below reduces speed by 1 unit
                   //double newSpeed =(mySpeed * find(distances).first + 0.5 * acceleration * find(distances).first * find(distances).first)*2/find(distances).second -  mySpeed;
                    //std::cout << acceleration<< std::endl;
                    //std::cout << newSpeed<< std::endl;
                    //if (newSpeed < 0)
                    //    newSpeed = 0;
                    //std::cout << find(distances).first<<find(distances).second<< std::endl;
                    if(mySpeed > 1)
                    {
                        mySpeed= mySpeed - 1;
                    }
                    else
                    {
                        mySpeed = 0;
                    }
                    traciVehicle.slowDown(mySpeed, 1);
                    /*if(mySpeed == 0)
                        decelerationResponsibles.erase(remoteID);*/
                    std::cout << "(" << mobility->getExternalId() << ")"<<myId<<" slowing down due to collision risk with remote vehicle "
                              << remoteID << "." << std::endl;
                }
                else
                {
                    //collisionWarnings.erase(remoteID);
                    std::cout << "(Opponent "<<receivedWSM->getSenderAddress()<<" decelerating." << std::endl;
                }
             }

            /*if (collisionRisk) {
                if (mySpeed > remoteSpeed) {
                    if(mySpeed > 2)
                    {
                        mySpeed= mySpeed - 2;
                    }
                    else
                    {
                        mySpeed = 0;
                    }
                    TraCICommandInterface::Vehicle traciVehicle = traci->vehicle(mobility->getExternalId());
                    traciVehicle.slowDown(mySpeed, 1);
                    std::cout << "Vehicle (" << mobility->getExternalId() << ") slowing down due to collision risk with remote vehicle "
                              << remoteID << "." << std::endl;
                }
            }*/
            return;
        } else {
            return;
        }
    }

    else {
        //std::cout << "(" << myId << ") receive  "  <<"id"<<receivedWSM->getSenderAddress()<< std::endl;
        // Process new messages (non-reply messages) section (e.g., sending predicted position message)
        simtime_t currentTime = simTime();
        //std::cout << "Remote vehicle (" << receivedWSM->getSenderAddress() << ") receive at " << currentTime << std::endl;
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
                    std::cerr << "Conversion error: " << e.what() << std::endl;
                }
            }
        }

        double speed = mobility->getSpeed();
        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        double acceleration = veh.getAcceleration();
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
        int judge = 1;
        if (distance > receivedWSM->getdistance())
            judge = 0;
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
        // Construct reply message, send out predicted distance differences
        TraCIDemo11pMessage* replyMsg = new TraCIDemo11pMessage();
        populateWSM(replyMsg);

        replyMsg->setSenderAddress(myId);
        replyMsg->setSerial(receivedWSM->getSenderAddress());
        // Send current vehicle speed as demoData
        std::string speedStr = std::to_string(speed);
        replyMsg->setDemoData(speedStr.c_str());
        std::string accelerationStr = std::to_string(acceleration);
        replyMsg->setDValues(accelerationStr.c_str());
        std::ostringstream oss;
        for (size_t i = 0; i < distances.size(); ++i) {
            oss << distances[i];
            if (i != distances.size() - 1) {
                oss << ";";
            }
        }
        std::string distanceStr = oss.str();
        replyMsg->setSValues(distanceStr.c_str());
        replyMsg->setdistancearray(std::to_string(judge).c_str());
        sendDelayed(replyMsg, uniform(0, 0.01), "lowerLayerOut");



           // Output simulation time directly (default format includes sub-second precision)
        //std::cout << "Vehicle (" << myId << ") send at again " << currentTime1 << std::endl;
    }

}



void method2::onWSA(DemoServiceAdvertisment* wsa)
{
    // Process service advertisement messages here.
    // Refer to TraciDemo11p.cc for examples.
}

// Handle self messages (timer events).
void method2::handleSelfMsg(cMessage* msg) {

    if (msg == sendMessageEvent) {

        double speed = mobility->getSpeed();

        TraCICommandInterface::Vehicle veh = traci->vehicle(mobility->getExternalId());
        veh.setSpeedMode(96);
        double acceleration = veh.getAcceleration();
        std::cout <<speed<<":" <<acceleration << std::endl;
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
        sendDown(newWSM);
        simtime_t currentTime = simTime();

           // Output simulation time directly (default format includes sub-second precision)
        //std::cout << "(" << myId << ") send at " << currentTime << std::endl;
        scheduleAt(simTime() + 0.1 + uniform(-0.01, 0.01), sendMessageEvent);
    }
}

void method2::handlePositionUpdate(cObject* obj) {
    DemoBaseApplLayer::handlePositionUpdate(obj);
}
