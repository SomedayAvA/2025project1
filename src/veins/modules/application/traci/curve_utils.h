// curve_utils.h
#ifndef CURVE_UTILS_H
#define CURVE_UTILS_H

#include <vector>
#include <utility>
#include <cmath>
#include <limits>
#include "veins/base/utils/Coord.h"

using veins::Coord;


extern int globalInitFlag;
extern const int fixBatchSize;
extern int p;
extern std::vector<Coord> curvePoints;
extern std::vector<Coord> curvePoints1;


double distanceBetween(const Coord& a, const Coord& b);
std::pair<double, double> computeNewPosition(double x, double y, double speed, double acceleration, double angleDeg, double t);
Coord interpolateOnCurve(const std::vector<Coord>& curve, double targetDistance, const std::vector<double>& cumDistances);
double projectOntoCurve(const std::vector<Coord>& curve, const std::vector<double>& cumDistances, const Coord& p);
std::pair<bool, int> checkDistancesCondition(const std::vector<double>& distances);
std::pair<double, double> find(const std::vector<double>& distances);

#endif
