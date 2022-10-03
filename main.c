#include "userInterface.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
    printWelcomeMessage();
    doMainMenu(argc, argv);
    
    return 0;
}