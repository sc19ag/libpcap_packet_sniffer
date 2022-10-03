#include <stdio.h>
#include <string.h>
#include "userInterface.h"

void printWelcomeMessage() {
    printf("Welcome to a simple CLI packet analyser based on the C/C++ library libpcap\n");
}

void doMainMenu(int argc, char *argv[]) {
    int choice = 0;
        
    while(choice != 4) {
        printf("\nPlease type the number of your choice:\n");
        printf("1. Print packet details to the console");
        printf("2. Print packet details to a file");
        printf("3. Do both of the above");
        printf("4. Exit the application");

        scanf("%d", &choice);

        switch(choice) {
            case 1:
            sniffToCli(argc, argv);
            break;

            case 2:
            doFileMenu();
            break;

            case 3:
            doFileMenu();
            sniffToCli(argc, argv);
            break;

            case 4:
            printf("\nBye!");
            exit(0);

            default:
            fprintf(stderr, "\nError: Invalid option");
            break;
        }
    }
}

void doFileMenu(int argc, char *argv[]) {
    int subChoice = 0;
    char buf[256];
    const char *filePath;

    printf("\nPlease type the number of your choice:\n");
    printf("1. Enter file path");
    printf("2. Main menu");

    scanf("%d", &subChoice);
    switch(subChoice) {
        case 1:
        printf("Please write the path of the file you wish to print to:");
        scanf("%s", &buf);
        strcpy(filePath, buf); 
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