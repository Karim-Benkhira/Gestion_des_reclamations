#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_USERNAME 50
#define MAX_PASSSWD 50
#define MIN_PASSWD 8
#define MAX_ATTEMPTS 3
#define ROLE_SIZE 20
#define LOCK_TIME 900 

typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSSWD];
    char role[ROLE_SIZE];
    int locked;
    int attempts;
    time_t lock_time; 
} User;

int PasswdValidOrInvalid(const char *passwd, const char *username) {
    int P_Upper = 0, P_Lower = 0, P_Digit = 0, P_Special = 0;
    const char *specialChars = "!@#$%^&*";

    if (strlen(passwd) < MIN_PASSWD) return 0;

    for (int i = 0; passwd[i] != '\0'; i++) {
        if (isupper(passwd[i])) P_Upper = 1;
        if (islower(passwd[i])) P_Lower = 1;
        if (isdigit(passwd[i])) P_Digit = 1;
        if (strchr(specialChars, passwd[i])) P_Special = 1;
    }

    return P_Upper && P_Lower && P_Digit && P_Special && !strstr(passwd, username);
}

void signUp() {
    char Passwd[MAX_PASSSWD];
    char UserName[MAX_USERNAME];
    char Role[ROLE_SIZE];
    FILE *file;

    printf("=== Inscription ===\n");

    printf("Entrez votre identifiant : ");
    scanf("%s", UserName);
    printf("Entrez votre mot de passe : ");
    scanf("%s", Passwd);
    
    do {
        printf("Entrez votre rôle (Agent, Client) : ");
        scanf("%s", Role);
        if (strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0) {
            printf("Rôle invalide. Veuillez entrer 'Agent' ou 'Client'.\n");
        }
    } while (strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0);

    if (!PasswdValidOrInvalid(Passwd, UserName)) {
        printf("Mot de passe invalide. Veuillez réessayer.\n");
        return;
    }

    file = fopen("users.txt", "r");
    if (file != NULL) {
        User tempUser;
        while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempUser.password, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
            if (strcmp(UserName, tempUser.username) == 0) {
                printf("Identifiant déjà utilisé. Veuillez choisir un autre identifiant.\n");
                fclose(file);
                return;
            }
        }
        fclose(file);
    }

    file = fopen("users.txt", "a");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier.\n");
        return;
    }

    fprintf(file, "%s %s %s 0 0\n", UserName, Passwd, Role);
    fclose(file);

    printf("Inscription réussie !\n");
}

int signIn(char *currentRole) {
    char Passwd[MAX_PASSSWD];
    char UserName[MAX_USERNAME];
    User tempUser;
    int found = 0;
    int loginSuccess = 0;

    printf("=== Connexion ===\n");

    printf("Entrez votre identifiant : ");
    scanf("%s", UserName);
    printf("Entrez votre mot de passe : ");
    scanf("%s", Passwd);

    FILE *file = fopen("users.txt", "r");
    FILE *tempFile = fopen("temp.txt", "w");
    if (file == NULL || tempFile == NULL) {
        printf("Erreur d'ouverture du fichier.\n");
        if (file != NULL) fclose(file);
        if (tempFile != NULL) fclose(tempFile);
        return 0;
    }

    time_t current_time = time(NULL);

    while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempUser.password, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
        if (strcmp(UserName, tempUser.username) == 0) {
            found = 1;
            if (tempUser.lock_time > 0) {
                time_t current_time = time(NULL);
                
                if (difftime(current_time, tempUser.lock_time) < LOCK_TIME) {
                    printf("Compte verrouillé. Veuillez réessayer dans %.0f secondes.\n", LOCK_TIME - difftime(current_time, tempUser.lock_time));
                    fclose(file);
                    fclose(tempFile);
                    return 0;
                } else {
                    tempUser.lock_time = 0; 
                    tempUser.attempts = 0; 
                }
            }
            if (strcmp(Passwd, tempUser.password) == 0) {
                printf("Connexion réussie !\n");
                printf("Votre rôle est : %s\n", tempUser.role);
                strcpy(currentRole, tempUser.role);
                tempUser.attempts = 0; 
                loginSuccess = 1;
            } else {
                tempUser.attempts += 1;
                printf("Mot de passe incorrect.\n");
                if (tempUser.attempts >= MAX_ATTEMPTS) {
                    tempUser.lock_time = time(NULL); 
                    printf("Compte verrouillé après %d tentatives échouées.\n", MAX_ATTEMPTS);
                } else {
                    printf("Nombre de tentatives restantes : %d\n", MAX_ATTEMPTS - tempUser.attempts);
                }
            }
        }
        fprintf(tempFile, "%s %s %s %ld %d\n", tempUser.username, tempUser.password, tempUser.role, tempUser.lock_time, tempUser.attempts);
    }

    fclose(file);
    fclose(tempFile);

    remove("users.txt");
    rename("temp.txt", "users.txt");

    if (!found) {
        printf("Identifiant incorrect.\n");
    }

    return loginSuccess;
}

void addUser() {
    char Passwd[MAX_PASSSWD];
    char UserName[MAX_USERNAME];
    char Role[ROLE_SIZE];
    FILE *file, *tempFile;
    User tempUser;
    int found = 0;

    printf("=== Ajouter un nouvel utilisateur ===\n");

    printf("Entrez l'identifiant : ");
    scanf("%s", UserName);
    printf("Entrez le mot de passe : ");
    scanf("%s", Passwd);
    
    do {
        printf("Entrez le rôle (Administrateur, Agent, Client) : ");
        scanf("%s", Role);
        if (strcmp(Role, "Administrateur") != 0 && strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0) {
            printf("Rôle invalide. Veuillez entrer 'Administrateur', 'Agent' ou 'Client'.\n");
        }
    } while (strcmp(Role, "Administrateur") != 0 && strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0);

    if (!PasswdValidOrInvalid(Passwd, UserName)) {
        printf("Mot de passe invalide. Veuillez réessayer.\n");
        return;
    }

    file = fopen("users.txt", "r");
    if (file != NULL) {
        while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempUser.password, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
            if (strcmp(UserName, tempUser.username) == 0) {
                printf("Identifiant déjà utilisé. Veuillez choisir un autre identifiant.\n");
                fclose(file);
                return;
            }
        }
        fclose(file);
    }

    file = fopen("users.txt", "a");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier.\n");
        return;
    }

    fprintf(file, "%s %s %s 0 0\n", UserName, Passwd, Role);
    fclose(file);

    printf("Nouvel utilisateur ajouté avec succès !\n");
}

void manageRoles(const char *currentRole) {
    if (strcmp(currentRole, "Administrateur") != 0) {
        printf("Vous n'avez pas les droits pour gérer les utilisateurs.\n");
        return;
    }

    int choice;
    do {
        printf("\n=== Gestion des Utilisateurs ===\n");
        printf("1. Ajouter un nouvel utilisateur\n");
        printf("2. Retour au menu principal\n");
        printf("Choisissez une option : ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                addUser();
                break;
            case 2:
                printf("Retour au menu principal.\n");
                break;
            default:
                printf("Option invalide.\n");
        }

    } while (choice != 2);
}

int main() {
    int choice;
    char currentRole[ROLE_SIZE] = "";

    do {
        printf("\n=== Menu ===\n");
        printf("1. Inscription\n");
        printf("2. Connexion\n");
        printf("3. Quitter\n");
        printf("Choisissez une option : ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                signUp();
                break;
            case 2:
                if (signIn(currentRole)) {
                    manageRoles(currentRole);
                }
                break;
            case 3:
                printf("Au revoir !\n");
                break;
            default:
                printf("Option invalide.\n");
        }

    } while (choice != 3);

    return 0;
}
