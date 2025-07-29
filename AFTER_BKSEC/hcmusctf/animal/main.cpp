// g++ -o chall main.cpp -no-pie -s
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>

char FLAG[100] = {0};

class Animal {
protected:
    std::string name;
    int age;
    double weight;
public:
    Animal(const std::string& n, int a, double w) : name(n), age(a), weight(w) {}
    virtual ~Animal() = default;
    
    virtual void displayMenu() const {
        std::cout << "Generic Animal Menu:\n";
        std::cout << "1. Get Name\n";
        std::cout << "2. Get Age\n";
        std::cout << "3. Get Weight\n";
    }
    
    virtual void executeAction(int choice) {
        switch(choice) {
            case 1:
                std::cout << "Name: " << name << "\n";
                break;
            case 2:
                std::cout << "Age: " << age << "\n";
                break;
            case 3:
                std::cout << "Weight: " << weight << " kg\n";  // Added weight case
                break;
            default:
                std::cout << "Invalid choice\n";
        }
    }
};

class Fish : public Animal {
private:
    std::string breed;
    std::string color;
    std::string waterType;
public:
    Fish(const std::string& n, int a, double w, const std::string& b, const std::string &c, const std::string& wt) 
        : Animal(n, a, w), breed(b), color(c), waterType(wt) {}
    
    void displayMenu() const override {
        std::cout << "Fish Menu:\n";
        std::cout << "1. Get Name\n";
        std::cout << "2. Get Age\n";
        std::cout << "3. Get Weight\n";
        std::cout << "4. Get Breed\n";
        std::cout << "5. Get Color\n";
        std::cout << "6. Get Water Type\n";
        std::cout << "7. Swim\n";
    }
    
    void executeAction(int choice) override {
        switch(choice) {
            case 1:
            case 2:
            case 3:
                Animal::executeAction(choice);
                break;
            case 4:
                std::cout << "Breed: " << breed << "\n";
                break;
            case 5:
                std::cout << "Color: " << color << "\n";
                break;
            case 6:
                std::cout << "Water Type: " << waterType << "\n";
                break;
            case 7:
                swim();
                break;
            default:
                std::cout << "Invalid choice\n";
        }
    }

    void swim() const {
        std::cout << name << " swimming in " << waterType << std::endl;
    }
};

class Dog : public Animal {
private:
    std::string breed;
public:
    Dog(const std::string& n, int a, double w, const std::string& b) : Animal(n, a, w), breed(b) {}
    
    void displayMenu() const override {
        std::cout << "Dog Menu:\n";
        std::cout << "1. Get Name\n";
        std::cout << "2. Get Age\n";
        std::cout << "3. Get Weight\n";
        std::cout << "4. Get Breed\n";
        std::cout << "5. Bark\n";
    }
    
    void executeAction(int choice) override {
        switch(choice) {
            case 1:
            case 2:
            case 3:
                Animal::executeAction(choice);
                break;
            case 4:
                std::cout << "Breed: " << breed << "\n";
                break;
            case 5:
                bark();
                break;
            default:
                std::cout << "Invalid choice\n";
        }
    }

    void bark() const {
        std::cout << name << " say Woof Woof!" << std::endl;
    }
};

class Cat : public Animal {
public:
    Cat(const std::string& n, int a, double w) : Animal(n, a, w) {}
    
    void displayMenu() const override {
        std::cout << "Cat Menu:\n";
        std::cout << "1. Get Name\n";
        std::cout << "2. Get Age\n";
        std::cout << "3. Get Weight\n";  // Added weight option
        std::cout << "4. Meow\n";  // Shifted meow to option 4
    }
    
    void executeAction(int choice) override {
        switch(choice) {
            case 1:
            case 2:
            case 3:  // Handle weight from base class
                Animal::executeAction(choice);
                break;
            case 4:
                meow();
                break;
            default:
                std::cout << "Invalid choice\n";
        }
    }

    void meow() const {
        std::cout << name << " says: Meow!" << std::endl;
    }
};

class Bird : public Animal {
private:
    double wingSpan;
public:
    Bird(const std::string& n, int a, double w, double ws) : Animal(n, a, w), wingSpan(ws) {}
    
    void displayMenu() const override {
        std::cout << "Bird Menu:\n";
        std::cout << "1. Get Name\n";
        std::cout << "2. Get Age\n";
        std::cout << "3. Get Weight\n";
        std::cout << "4. Fly\n";
    }
    
    void executeAction(int choice) override {
        switch(choice) {
            case 1:
            case 2:
            case 3:
                Animal::executeAction(choice);
                break;
            case 4:
                fly();
                break;
            default:
                std::cout << "Invalid choice\n";
        }
    }

    void fly() const {
        std::cout << name << " is flying with wingspan of " << wingSpan << std::endl;
    }
};

void introduce() {
    std::string name;
    std::cout << "Hello, what's your name? > ";
    getline(std::cin, name);
    std::cout << "Hi, " <<  name << ". Have fun today!" << std::endl;
}

bool read_flag() {
    std::ifstream is("flag.txt");
    if (!is) {
        std::cerr << "flag.txt should be in the same folder!" << std::endl;
        return false;
    }
    is.getline(FLAG, sizeof(FLAG));
    if (is.fail() || FLAG[0] == '\0') {
        std::cerr << "Error: Failed to read flag or flag.txt is empty." << std::endl;
        is.close();
        return false;
    }
    is.close();
    char encoded[100] = {0};
    strncpy(encoded, FLAG, 100-1);
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return false;
    }
    char rand_bytes[99] = {0};
    if (read(fd, rand_bytes, 99) != 99) {
        std::cerr << "Failed to read from /dev/urandom" << std::endl;
        close(fd);
        return false;
    }

    for (int i = 0; i < 99; i++) {
        encoded[i] ^= rand_bytes[i];
        encoded[i] = ((unsigned char)(encoded[i]) % (0x7f - 0x21)) + 0x21;
    }
    encoded[99] = 0;
    close(fd);
    std::cout << "Here's your flag, gud luck with that lul: " << encoded << std::endl;
    return true;
}

int main() {
    if (!read_flag()) return EXIT_FAILURE;
    introduce();
    unsigned int type = 0;
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd == -1) {
        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return EXIT_FAILURE;
    }
    if (read(rand_fd, &type, 4) != 4) {
        std::cerr << "Failed to read from /dev/urandom" << std::endl;
        close(rand_fd);
        return EXIT_FAILURE;
    }
    close(rand_fd);
    type %= 4;
    Animal* animal;
    switch(type) {
        case 0: animal = new Dog("Pluto", 3, 25.5, "Mix"); break;
        case 1: animal = new Cat("Doraemon", 7, 129.3); break;
        case 2: animal = new Bird("Donald Duck", 20, 20.0, 120); break;
        case 3: animal = new Fish("Nemo", 2, 0.1, "Clownfish", "Orange", "Saltwater"); break;
    }
    
    std::cout << "\nI've created a random animal\nGuess the animal type:\n";
    std::cout << "1. Dog\n2. Cat\n3. Bird\n4. Fish\n5. Exit\n";
    std::cout << "Enter choice: ";
    
    int choice;
    if (!(std::cin >> choice)) {
        std::cout << "Invalid input. Please enter a number.\n";
        delete animal;
        return 1;
    }

    bool correct = true;

    switch(choice) {
        case 1: {
            Dog* dog = dynamic_cast<Dog*>(animal);
            if(dog) {
                std::cout << "Correct! It's a Dog!\n";
                dog->bark();
            } else {
                std::cout << "Wrong! It's not a Dog.\n";
                correct = false;
            }
            break;
        }
        case 2: {
            Cat* cat = dynamic_cast<Cat*>(animal);
            if(cat) {
                std::cout << "Correct! It's a Cat!\n";
                cat->meow();
            } else {
                std::cout << "Wrong! It's not a Cat.\n";
                correct = false;
            }
            break;
        }
        case 3: {
            Bird* bird = dynamic_cast<Bird*>(animal);
            if(bird) {
                std::cout << "Correct! It's a Bird!\n";
                bird->fly();
            } else {
                std::cout << "Wrong! It's not a Bird.\n";
                correct = false;
            }
            break;
        }
        case 4: {
            Fish* fish = dynamic_cast<Fish*>(animal);
            if(fish) {
                std::cout << "Correct! It's a Fish!\n";
                fish->swim();
            } else {
                std::cout << "Wrong! It's not a Fish.\n";
                correct = false;
            }
            break;
        }
        case 5:
            correct = false;
            break;
        case -1: {
            Dog* dog = reinterpret_cast<Dog*>(animal);
            if(dog) {
                std::cout << "Correct! It's a Dog!\n";
                dog->bark();
            } else {
                std::cout << "Wrong! It's not a Dog.\n";
                correct = false;
            }
            break;
        }
        case -2: {
            Cat* cat = reinterpret_cast<Cat*>(animal);
            if(cat) {
                std::cout << "Correct! It's a Cat!\n";
                cat->meow();
            } else {
                std::cout << "Wrong! It's not a Cat.\n";
                correct = false;
            }
            break;
        }
        case -3: {
            Bird* bird = reinterpret_cast<Bird*>(animal);
            if(bird) {
                std::cout << "Correct! It's a Bird!\n";
                bird->fly();
            } else {
                std::cout << "Wrong! It's not a Bird.\n";
                correct = false;
            }
            break;
        }
        case -4: {
            Fish* fish = reinterpret_cast<Fish*>(animal);
            if(fish) {
                std::cout << "Correct! It's a Fish!\n";
                fish->swim();
            } else {
                std::cout << "Wrong! It's not a Fish.\n";
                correct = false;
            }
            break;
        }
        default:
            std::cout << "Invalid choice\n";
    }
    if (correct) {
        animal->displayMenu();
        std::cout << "Select action: ";
        int action;
        if (!(std::cin >> action)) {
            std::cout << "Invalid input. Please enter a number.\n";
            delete animal;
            return 1;
        }
        animal->executeAction(action);
    }
    delete animal;
    return EXIT_SUCCESS;
}
