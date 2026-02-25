#include <vector>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <iostream>
#include <queue>
#include <set>

struct Node {
    int x, y;
    double cost;
    Node* parent;

    Node(int x, int y, double cost, Node* parent = nullptr) : x(x), y(y), cost(cost), parent(parent) {}

    bool operator>(const Node& other) const {
        return cost > other.cost;
    }
};

class AStarPlanner {
protected:
    int width, height;
    std::vector<std::vector<int>> grid;

    double heuristic(int x1, int y1, int x2, int y2) {
        return std::abs(x1 - x2) + std::abs(y1 - y2);
    }

public:
    AStarPlanner(int w, int h, const std::vector<std::vector<int>>& g) : width(w), height(h), grid(g) {}

    virtual std::vector<Node> plan(int startX, int startY, int goalX, int goalY) {
        std::priority_queue<Node, std::vector<Node>, std::greater<Node>> openSet;
        openSet.emplace(startX, startY, 0);

        while (!openSet.empty()) {
            Node current = openSet.top();
            openSet.pop();

            if (current.x == goalX && current.y == goalY) {
                std::vector<Node> path;
                Node* node = &current;
                while (node) {
                    path.push_back(*node);
                    node = node->parent;
                }
                return path;
            }

            for (int dx = -1; dx <= 1; ++dx) {
                for (int dy = -1; dy <= 1; ++dy) {
                    if (dx * dy != 0 || (dx == 0 && dy == 0)) continue;
                    int nx = current.x + dx;
                    int ny = current.y + dy;
                    if (nx >= 0 && nx < width && ny >= 0 && ny < height && grid[nx][ny] == 0) {
                        double newCost = current.cost + 1 + heuristic(nx, ny, goalX, goalY);
                        openSet.emplace(nx, ny, newCost, new Node(current));
                    }
                }
            }
        }

        return {};
    }
};

struct DynamicObstacle {
    int x, y;
    DynamicObstacle(int x, int y) : x(x), y(y) {}
    void move(int dx, int dy) {
        x += dx;
        y += dy;
    }
};

class DynamicAStarPlanner : public AStarPlanner {
private:
    std::set<std::pair<int, int>> dynamicObstacles;

public:
    DynamicAStarPlanner(int w, int h, const std::vector<std::vector<int>>& g)
        : AStarPlanner(w, h, g) {}

    void addDynamicObstacle(int x, int y) {
        dynamicObstacles.insert({ x, y });
    }

    void moveObstacle(int oldX, int oldY, int newX, int newY) {
        dynamicObstacles.erase({ oldX, oldY });
        dynamicObstacles.insert({ newX, newY });
    }

    std::vector<Node> plan(int startX, int startY, int goalX, int goalY) override {
        std::priority_queue<Node, std::vector<Node>, std::greater<Node>> openSet;
        openSet.emplace(startX, startY, 0);

        while (!openSet.empty()) {
            Node current = openSet.top();
            openSet.pop();

            if (current.x == goalX && current.y == goalY) {
                std::vector<Node> path;
                Node* node = &current;
                while (node) {
                    path.push_back(*node);
                    node = node->parent;
                }
                return path;
            }

            for (int dx = -1; dx <= 1; ++dx) {
                for (int dy = -1; dy <= 1; ++dy) {
                    if (dx * dy != 0 || (dx == 0 && dy == 0)) continue;
                    int nx = current.x + dx;
                    int ny = current.y + dy;
                    if (nx >= 0 && nx < width && ny >= 0 && ny < height && grid[nx][ny] == 0 && dynamicObstacles.find({ nx, ny }) == dynamicObstacles.end()) {
                        double newCost = current.cost + 1 + heuristic(nx, ny, goalX, goalY);
                        openSet.emplace(nx, ny, newCost, new Node(current));
                    }
                }
            }
        }

        return {};
    }
};