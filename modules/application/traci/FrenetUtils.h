#ifndef FRENET_UTILS_H
#define FRENET_UTILS_H

#include <vector>
#include <cmath>
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
namespace veins {

struct FrenetCoord {
    double s;
    double d;
};

FrenetCoord getFrenetCoordinates(const Coord &pos);
Coord getCartesianFromFrenet(double s, double d);

} // namespace veins

#endif // FRENET_UTILS_H
