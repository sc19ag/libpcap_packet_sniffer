#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "userInterface.h"
#include "sniffer.h"

void printWelcomeMessage() {
    printf("Welcome to a simple CLI packet analyser based on the C/C++ library libpcap\n");
}

void doMainMenu(int argc, char *argv[]) {
    int choice = 0;
        
    while(choice != 4) {
        printf("\nPlease type the number of your choice:\n");
        printf("1. Print packet details to the console\n");
        printf("2. Print packet details to a file\n");
        printf("3. Do both of the above\n");
        printf("4. Exit the application\n\n");

        /*
            Find a way to avoid a data type other than an integer being passed into choice from the user (via scanf here).
            Whenever a value of a different type is entered by the user here, the program automatically executes this while loop
            seemingly ad infinitum, due to a segmentation fault (in short, the program breaks/crashes ungracefully)
        */
        scanf("%d", &choice);

        switch(choice) {
            case 1:
            sniffToCli(argc, argv);
            break;

            case 2:
            doFileMenu(argc, argv);
            break;

            case 3:
            doFileMenu(argc, argv);
            sniffToCli(argc, argv);
            break;

            case 4:
            printf("\nBye!\n\n");
            exit(0);

            default:
            fprintf(stderr, "\nError: Invalid option\n");
            break;
        }
    }
}

void doFileMenu(int argc, char *argv[]) {
    int subChoice = 0;
    char buf[256];
    char *filePath;

    printf("\nPlease type the number of your choice:\n");
    printf("1. Enter file path\n");
    printf("2. Main menu\n\n");

    /*
        Find a way to avoid a data type other than an integer being passed into subchoice from the user (via scanfs here).
        Same problem as in doMainMenu.
    */
    scanf("%d", &subChoice);
    switch(subChoice) {
        case 1:
        printf("\nPlease write the path of the file you wish to print to: ");
        scanf("%s", &buf); // Try to understand why a compiler warning is triggered here aswell
        
        filePath = strcpy(filePath, buf); 
        sniffToFile(argc, argv, filePath);
        break;

        case 2:
        doMainMenu(argc, argv);
        break;

        default:
        fprintf(stderr, "Error: Invalid option");
        doFileMenu(argc, argv);
        break;
    }
}