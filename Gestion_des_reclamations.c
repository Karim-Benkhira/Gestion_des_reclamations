#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_USERNAME 50
#define MAX_PASSSWD 50
#define MIN_PASSWD 8
#define MAX_ATTEMPTS 5
#define ROLE_SIZE 20
#define LOCK_TIME 900 

/*====================== 1 =====================*/

typedef struct {
    char username[MAX_USERNAME];
    char password[MAX_PASSSWD];
    char role[ROLE_SIZE];
    int locked;
    int attempts;
    time_t lock_time; 
} User;
/*====================== 1 =====================*/

/*====================== 2 =====================*/
typedef struct 
{
    char id[30];
    char username[MAX_USERNAME];
    char motif[60];
    char description[300];
    char category[60];
    char status[20];
    char date[20];
    char notes[300];
    char priority[10];
}Complaint;




int PasswdValidOrInvalid(const char *passwd, const char *username);
void signUp();
int signIn(char *currentRole,char *currentUsername);
void addUser();
void manageRoles(const char *currentRole);
void changeUserRole();
void deleteUser();
void displayUsers();
int hasPermission(const char *currentRole, const char *requiredRole);

/*=================== Functions =======> 1 =====================*/

/*=================== Functions =======> 2 =====================*/

void addComplaint(const char *username);
void displayComplaints(const char *currentRole, const char *username);
void modifyComplaint();
void deleteComplaint();
void processComplaint();
void generateStatistics();
void generateDailyReport();
void searchUserOrComplaint();
void searchUserByName(const char *username);
void searchUserByRole(const char *role);
void searchComplaintByCategory(const char *category);


/*=================== Functions =======> 2 =====================*/

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

    printf("\n");
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║              ✦✦✦  INSCRIPTION  ✦✦✦             ║\n");
    printf("╠════════════════════════════════════════════════╣\n");
    printf("║ ➤ Entrez votre identifiant :                   ║\n");
    printf("╚════════════════════════════════════════════════╝\n");
    scanf("%s", UserName);
    printf("\n");
    printf("╔═════════════════════════════════════════════╗\n");
    printf("║ ➤ Entrez votre mot de passe :               ║\n");
    printf("╚═════════════════════════════════════════════╝\n");
    scanf("%s", Passwd);
    
    if (!PasswdValidOrInvalid(Passwd, UserName)) {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════╗\n");
        printf("║   ⚠️  Mot de passe invalide. Veuillez réessayer.   ⚠️        ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");

        return;
    }

    
    file = fopen("users.txt", "r");
    if (file != NULL) {
        User tempUser;
        char tempPasswd[MAX_PASSSWD];
        while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
            if (strcmp(UserName, tempUser.username) == 0) {
                printf("Identifiant déjà utilisé. Veuillez choisir un autre identifiant.\n");
                fclose(file);
                return;
            }
        }
        fclose(file);
    }

    
    do {
        printf("Entrez votre rôle (Agent, Client) : ");
        scanf("%s", Role);
        if (strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0) {
            printf("Rôle invalide. Veuillez entrer 'Agent' ou 'Client'.\n");
        }
    } while (strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0);

    
    file = fopen("users.txt", "a");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier...\n");
        return;
    }

    fprintf(file, "%s %s %s 0 0\n", UserName, Passwd, Role);
    fclose(file);

    printf("\n");
    printf("╔═════════════════════════════════════════════════════╗\n");
    printf("║   ✅  Félicitations ! Inscription réussie !  ✅     ║\n");
    printf("╚═════════════════════════════════════════════════════╝\n");

}

int signIn(char *currentRole,char *currentUsername) {
    char Passwd[MAX_PASSSWD];
    char UserName[MAX_USERNAME];
    User tempUser;
    char tempPasswd[MAX_PASSSWD];
    int found = 0;
    int loginSuccess = 0;

    printf("\n");
    printf("╔═════════════════════════════════════════════╗\n");
    printf("║            🔐  Connexion  🔐                ║\n");
    printf("╚═════════════════════════════════════════════╝\n");
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

    while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
        if (strcmp(UserName, tempUser.username) == 0) {
            found = 1;
            if (tempUser.lock_time > 0) {
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
            if (strcmp(Passwd, tempPasswd) == 0) {
                printf("\n");
                printf("╔════════════════════════════════════════════╗\n");
                printf("║ ✅  Connexion réussie !                    ║\n");
                printf("╚════════════════════════════════════════════╝\n");

                printf("Votre rôle est : %s\n", tempUser.role);
                strcpy(currentRole, tempUser.role);
                strcpy(currentUsername, tempUser.username);
                tempUser.attempts = 0; 
                loginSuccess = 1;
            } else {
                tempUser.attempts += 1;
                printf("\n");
                printf("╔═════════════════════════════════════════════════════╗\n");
                printf("║ ❌  Mot de passe incorrect.                         ║\n");
                if (tempUser.attempts >= MAX_ATTEMPTS) {
                    tempUser.lock_time = current_time;
                    printf("╠═════════════════════════════════════════════════════╣\n"); 
                    printf("║ 🔒  Compte verrouillé après %d tentatives échouées. ║\n", MAX_ATTEMPTS);
                } else {
                    printf("╠═════════════════════════════════════════════════════╣\n");
                    printf("║ ⚠️  Nombre de tentatives restantes : %d               ║\n", MAX_ATTEMPTS - tempUser.attempts);
                }
                printf("╚═════════════════════════════════════════════════════╝\n");
            }
        }
        fprintf(tempFile, "%s %s %s %ld %d\n", tempUser.username, tempPasswd, tempUser.role, tempUser.lock_time, tempUser.attempts);
    }

    fclose(file);
    fclose(tempFile);

    remove("users.txt");
    rename("temp.txt", "users.txt");

    if (!found) {
        printf("\n");
        printf("╔══════════════════════════════════════════╗\n");
        printf("║ ❌  Identifiant incorrect.               ║\n");
        printf("╚══════════════════════════════════════════╝\n");

    }

    return loginSuccess;
}

void addUser() {
    char Passwd[MAX_PASSSWD];
    char UserName[MAX_USERNAME];
    char Role[ROLE_SIZE];
    FILE *file;
    User tempUser;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║          ✦✦✦  Ajouter un nouvel utilisateur  ✦✦✦         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║ Entrez l'identifiant :                           ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    scanf("%s", UserName);
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║ Entrez le mot de passe :                         ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    scanf("%s", Passwd);
    
    if (!PasswdValidOrInvalid(Passwd, UserName))
    {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ❌  Mot de passe invalide. Veuillez réessayer.   ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        return;
    }

    
    file = fopen("users.txt", "r");
    if (file != NULL) {
        char tempPasswd[MAX_PASSSWD];
        while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
            if (strcmp(UserName, tempUser.username) == 0)
            {
                printf("\n");
                printf("╔══════════════════════════════════════════════════╗\n");
                printf("║ ❌  Identifiant déjà utilisé. Veuillez choisir   ║\n");
                printf("║      un autre identifiant.                       ║\n");
                printf("╚══════════════════════════════════════════════════╝\n");
                fclose(file);
                return;
            }
        }
        fclose(file);
    }

    
    do {
        printf("\n");
        printf("╔═══════════════════════════════════════════════════════╗\n");
        printf("║   ➤ Entrez le rôle : Administrateur / Agent / Client  ║\n");
        printf("╠═══════════════════════════════════════════════════════╣\n");
        printf("║ Rôle: ");
        scanf("%s", Role);
        printf("╚═══════════════════════════════════════════════════════╝\n");
        if (strcmp(Role, "Administrateur") != 0 && strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0)
        {
            printf("\n");
            printf("╔════════════════════════════════════════════════════════╗\n");
            printf("║ ❌  Rôle invalide. Veuillez entrer 'Administrateur',   ║\n");
            printf("║     'Agent' ou 'Client'.                               ║\n");
            printf("╚════════════════════════════════════════════════════════╝\n");
        }
    } while (strcmp(Role, "Administrateur") != 0 && strcmp(Role, "Agent") != 0 && strcmp(Role, "Client") != 0);

    
    file = fopen("users.txt", "a");
    if (file == NULL) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ⚠️ Erreur d'ouverture du fichier.                 ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        return;
    }

    fprintf(file, "%s %s %s 0 0\n", UserName, Passwd, Role);
    fclose(file);

    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║ ✅  Nouvel utilisateur ajouté avec succès !      ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
}

void changeUserRole()
{
    char usernameToChange[MAX_USERNAME];
    char newRole[ROLE_SIZE];
    FILE *file = fopen("users.txt", "r");
    FILE *tempFile = fopen("temp.txt", "w");
    if (file == NULL || tempFile == NULL)
    {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ⚠️  Erreur d'ouverture du fichier.                ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        if (file != NULL) fclose(file);
        if (tempFile != NULL) fclose(tempFile);
        return;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║ ➤ Entrez l'identifiant de l'utilisateur à changer :  ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    scanf("%s", usernameToChange);

    
    do {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════╗\n");
        printf("║ ➤ Entrez le nouveau rôle (Administrateur/Agent/Client) : ║\n");
        printf("╚══════════════════════════════════════════════════════════╝\n");
        scanf("%s", newRole);
        if (strcmp(newRole, "Administrateur") != 0 && strcmp(newRole, "Agent") != 0 && strcmp(newRole, "Client") != 0)
        {
            printf("\n");
            printf("╔════════════════════════════════════════════════════════╗\n");
            printf("║ ❌ Rôle invalide. Veuillez entrer 'Administrateur',    ║\n");
            printf("║    'Agent' ou 'Client'.                                ║\n");
            printf("╚════════════════════════════════════════════════════════╝\n");
        }
    } while (strcmp(newRole, "Administrateur") != 0 && strcmp(newRole, "Agent") != 0 && strcmp(newRole, "Client") != 0);

    User tempUser;
    char tempPasswd[MAX_PASSSWD];
    int found = 0;

    while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
        if (strcmp(tempUser.username, usernameToChange) == 0)
        {
            strcpy(tempUser.role, newRole);
            found = 1;
            printf("\n");
            printf("╔════════════════════════════════════════════════════════════╗\n");
            printf("║ ✅  Le rôle de %s a été changé en %s.\n", usernameToChange, newRole);
            printf("╚════════════════════════════════════════════════════════════╝\n");
        }
        fprintf(tempFile, "%s %s %s %ld %d\n", tempUser.username, tempPasswd, tempUser.role, tempUser.lock_time, tempUser.attempts);
    }

    fclose(file);
    fclose(tempFile);

    if (!found)
    {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ⚠️  Utilisateur %s non trouvé.                    ║\n", usernameToChange);
        printf("╚══════════════════════════════════════════════════╝\n");
        remove("temp.txt");
    } else {
        remove("users.txt");
        rename("temp.txt", "users.txt");
    }
}

void deleteUser() {
    char usernameToDelete[MAX_USERNAME];
    FILE *file = fopen("users.txt", "r");
    FILE *tempFile = fopen("temp.txt", "w");
    if (file == NULL || tempFile == NULL)
    {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ⚠️  Erreur d'ouverture du fichier.                ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        if (file != NULL) fclose(file);
        if (tempFile != NULL) fclose(tempFile);
        return;
    }

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║ ➤ Entrez l'identifiant de l'utilisateur à supprimer : ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    scanf("%s", usernameToDelete);

    User tempUser;
    char tempPasswd[MAX_PASSSWD];
    int found = 0;

    while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
        if (strcmp(tempUser.username, usernameToDelete) != 0) {
            fprintf(tempFile, "%s %s %s %ld %d\n", tempUser.username, tempPasswd, tempUser.role, tempUser.lock_time, tempUser.attempts);
        } else {
            found = 1;
            printf("\n");
            printf("╔═══════════════════════════════════════════════════════╗\n");
            printf("║ ✅  Utilisateur %s supprimé avec succès.  \n", usernameToDelete);
            printf("╚═══════════════════════════════════════════════════════╝\n");
        }
    }

    fclose(file);
    fclose(tempFile);

    if (!found)
    {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ⚠️  Utilisateur %s non trouvé.    \n", usernameToDelete);
        printf("╚══════════════════════════════════════════════════╝\n");
        remove("temp.txt");
    } else {
        remove("users.txt");
        rename("temp.txt", "users.txt");
    }
}

void displayUsers() {
    FILE *file = fopen("users.txt", "r");
    if (file == NULL)
    {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║ ⚠️  Erreur d'ouverture du fichier.                ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        return;
    }

    User tempUser;
    char tempPasswd[MAX_PASSSWD];
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║                ✦ Liste des Utilisateurs ✦             ║\n");
    printf("╠═══════════════════════════════════════════════════════╣\n");
    printf("║ %-15s %-15s %-10s %-10s ║\n", "Username", "Role", "Locked", "Attempts");
    printf("╠═══════════════════════════════════════════════════════╣\n");
    while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF)
    {
        printf("║ %-15s %-15s %-10d %-10d ║\n", tempUser.username, tempUser.role, (tempUser.lock_time > 0) ? 1 : 0, tempUser.attempts);
    }
    printf("╚═══════════════════════════════════════════════════════╝\n");
    fclose(file);
}


int hasPermission(const char *currentRole, const char *requiredRole) {
    if (strcmp(currentRole, "Administrateur") == 0) {
        return 1; 
    }
    if (strcmp(currentRole, requiredRole) == 0) {
        return 1;
    }
    return 0;
}

void searchUserOrComplaint() {
    char searchTerm[50];
    int searchOption;

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║               ✦ Recherche d'un utilisateur ou plainte ✦    ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ 1. ➤ Rechercher par nom d'utilisateur                      ║\n");
    printf("║ 2. ➤ Rechercher par rôle d'utilisateur                     ║\n");
    printf("║ 3. ➤ Rechercher par catégorie de plainte                   ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    scanf("%d", &searchOption);

    printf("\n");
    printf("Entrez le terme de recherche : ");
    scanf("%s", searchTerm);

    if (searchOption == 1) {
        
        searchUserByName(searchTerm);
    } else if (searchOption == 2) {
        
        searchUserByRole(searchTerm);
    } else if (searchOption == 3) {
        
        searchComplaintByCategory(searchTerm);
    } else {
        printf("Option invalide.\n");
    }
}

void searchUserByName(const char *username) {
    FILE *file = fopen("users.txt", "r");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier des utilisateurs.\n");
        return;
    }

    char tempUserName[MAX_USERNAME];
    char tempPasswd[MAX_PASSSWD];
    char tempRole[ROLE_SIZE];
    long lock_time;
    int attempts;

    int found = 0;
    while (fscanf(file, "%s %s %s %ld %d", tempUserName, tempPasswd, tempRole, &lock_time, &attempts) != EOF) {
        if (strcmp(username, tempUserName) == 0) {
            printf("\nUtilisateur trouvé : %s, Rôle : %s\n", tempUserName, tempRole);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("Utilisateur non trouvé.\n");
    }

    fclose(file);
}

void searchUserByRole(const char *role) {
    FILE *file = fopen("users.txt", "r");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier des utilisateurs.\n");
        return;
    }

    char tempUserName[MAX_USERNAME];
    char tempPasswd[MAX_PASSSWD];
    char tempRole[ROLE_SIZE];
    long lock_time;
    int attempts;

    int found = 0;
    printf("Utilisateurs avec le rôle %s :\n", role);
    while (fscanf(file, "%s %s %s %ld %d", tempUserName, tempPasswd, tempRole, &lock_time, &attempts) != EOF) {
        if (strcmp(role, tempRole) == 0) {
            printf("Utilisateur : %s\n", tempUserName);
            found = 1;
        }
    }

    if (!found) {
        printf("Aucun utilisateur trouvé avec ce rôle.\n");
    }

    fclose(file);
}

void searchComplaintByCategory(const char *category) {
    FILE *file = fopen("complaints.txt", "r");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier des plaintes.\n");
        return;
    }

    Complaint tempComplaint;

    int found = 0;
    printf("Plaintes dans la catégorie %s :\n", category);
    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n",
                  tempComplaint.id, tempComplaint.username, tempComplaint.motif,
                  tempComplaint.description, tempComplaint.category, tempComplaint.status,
                  tempComplaint.date, tempComplaint.priority) != EOF) {
        if (strcmp(category, tempComplaint.category) == 0) {
            printf("Plainte ID: %s, Utilisateur: %s, Motif: %s\n",
                   tempComplaint.id, tempComplaint.username, tempComplaint.motif);
            found = 1;
        }
    }

    if (!found) {
        printf("Aucune plainte trouvée dans cette catégorie.\n");
    }

    fclose(file);
}


void manageRoles(const char *currentRole) {
    if (strcmp(currentRole, "Administrateur") != 0) {
        printf("Vous n'avez pas les droits pour gérer les utilisateurs.\n");
        return;
    }

    int choice;
    do {
        printf("\n");
        printf("╔═════════════════════════════════════════════════════════════════╗\n");
        printf("║        ✦✦✦  GESTION DES UTILISATEURS ET DES PLAINTES  ✦✦✦       ║\n");
        printf("╠═════════════════════════════════════════════════════════════════╣\n");
        printf("║ 1.  ➤ Ajouter un nouvel utilisateur                             ║\n");
        printf("║ 2.  ➤ Changer le rôle d'un utilisateur                          ║\n");
        printf("║ 3.  ➤ Supprimer un utilisateur                                  ║\n");
        printf("║ 4.  ➤ Afficher la liste des utilisateurs                        ║\n");
        printf("║ 5.  ➤ Ajouter une nouvelle plainte                              ║\n");
        printf("║ 6.  ➤ Modifier une plainte                                      ║\n");
        printf("║ 7.  ➤ Supprimer une plainte                                     ║\n");
        printf("║ 8.  ➤ Afficher la liste des plaintes                            ║\n");
        printf("║ 9.  ➤ Traiter une plainte                                       ║\n");
        printf("║ 10. ➤ Générer les statistiques                                  ║\n");
        printf("║ 11. ➤ Générer un rapport quotidien                              ║\n");
        printf("║ 12. ➤ Rechercher un utilisateur ou une plainte                  ║\n");
        printf("║ 13. ➤ Retour au menu principal                                  ║\n");
        printf("╠═════════════════════════════════════════════════════════════════╣\n");
        printf("║ Choisissez une option :                                         ║\n");
        printf("╚═════════════════════════════════════════════════════════════════╝\n");
        scanf("%d", &choice);
        printf("Choice selected: %d\n", choice);

        switch (choice) {
            case 1:
                addUser();
                break;
            case 2:
                changeUserRole();
                break;
            case 3:
                deleteUser();
                break;
            case 4:
                displayUsers();
                break;
            case 5:
                addComplaint("Administrateur");
                break;
            case 6:
                modifyComplaint();
                break;
            case 7:
                deleteComplaint();
                break;
            case 8:
                displayComplaints("Administrateur", ""); 
                break;
            case 9:
                processComplaint();
                break;
            case 10:
                generateStatistics();
                break;
            case 11:
                generateDailyReport();
                break;
            case 12:
                searchUserOrComplaint();
            case 13:
                printf("\n");
                printf("╔══════════════════════════════════════╗\n");
                printf("║      🔙  Retour au menu principal    ║\n");
                printf("╚══════════════════════════════════════╝\n");
                break;
            default:
                printf("\n");
                printf("╔══════════════════════════════════╗\n");
                printf("║      ⚠️  Option invalide !        ║\n");
                printf("╚══════════════════════════════════╝\n");
        }

    } while (choice != 13);
}


/*-------------------------------------------------------*/

void addComplaint(const char *username)
{
    Complaint newComplaint;
    FILE *file = fopen("complaints.txt", "a");
    if(file == NULL)
    {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠     ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        return;
    }

    sprintf(newComplaint.id, "CMP%05d", rand() % 100000);
    strcpy(newComplaint.username,username);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                ✦ Ajouter une nouvelle plainte ✦            ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║ Entrez le motif de la plainte :                            ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    scanf(" %[^\n]s",newComplaint.motif);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║ Entrez la description de la plainte :                      ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    scanf(" %[^\n]",newComplaint.description);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║ Entrez la catégorie de la plainte :                        ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    scanf(" %[^\n]s",newComplaint.category);

    strcpy(newComplaint.status,"En cours...");
    strcpy(newComplaint.notes,"");

    time_t t = time(NULL);
    struct  tm tm = *localtime(&t);
    sprintf(newComplaint.date, "%04d-%02d-%02d",tm.tm_year + 1900 ,tm.tm_mon + 1 , tm.tm_mday );

    if(strstr(newComplaint.description,"urgent") || strstr(newComplaint.description,"danger"))
        strcpy(newComplaint.priority,"danger");
    else if(strstr(newComplaint.description,"problème") || strstr(newComplaint.description,"retard"))
        strcpy(newComplaint.priority,"Moyenne");
    else 
        strcpy(newComplaint.priority,"Basse");
    
    fprintf(file,"%s;%s;%s;%s;%s;%s;%s;%s\n",
            newComplaint.id,
            newComplaint.username,
            newComplaint.motif,
            newComplaint.description,
            newComplaint.category,
            newComplaint.status,
            newComplaint.date,
            newComplaint.priority);
    fclose(file);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║ ✦ Plainte ajoutée avec succès ! ID de la plainte : %s ✦     \n", newComplaint.id);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");
    
}

void displayComplaints(const char *currentRole, const char *username)
{
    FILE *file = fopen("complaints.txt","r");
    if(file == NULL)
    {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠     ║\n");
        printf("╚════════════════════════════════════════════════════════════╝\n");
        return;
    }

    Complaint tempComplaint;

    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                ✦ Liste des Plainte ✦                                                                              ║\n");
    printf("╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-10s %-15s %-15s %-40s %-20s %-20s %-20s %-15s║\n", 
           "ID", "Username", "Motif", "Description", "Category", "Status", "Date", "Priority");
    printf("╠═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣\n");

    

    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF)
                  {
                    if (strcmp(currentRole, "Administrateur") == 0 || strcmp(currentRole, "Agent") == 0 || 
                        (strcmp(currentRole, "Client") == 0 && strcmp(tempComplaint.username, username) == 0))
                        {
                            printf("║ %-10s %-15s %-15s %-40s %-20s %-20s %-20s %-15s║\n", 
                                tempComplaint.id, 
                                tempComplaint.username, 
                                tempComplaint.motif, 
                                tempComplaint.description, 
                                tempComplaint.category, 
                                tempComplaint.status, 
                                tempComplaint.date, 
                                tempComplaint.priority);
                        }
                  }
    printf("╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    fclose(file);

}

void modifyComplaint()
{
    char complaintId[20];
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║              ✦ Modification d'une Plainte ✦                    ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Entrez l'ID de la plainte à modifier : ");
    scanf("%s",complaintId);
    printf("╚════════════════════════════════════════════════════════════════╝\n");

    FILE *file = fopen("complaints.txt","r");
    FILE *tempFile = fopen("tem_swap.txt","w");
    if(file == NULL || tempFile == NULL)
    {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠         ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        if(file != NULL)
            fclose(file);
        if(tempFile != NULL)
            fclose(tempFile);
        return;
    }

    Complaint tempComplaint;
    int found = 0;

    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF)
                {
                    if(strcmp(tempComplaint.id, complaintId) == 0)
                    {
                        found = 1;
                    printf("\n");
                    printf("╔══════════════════════════════════════════════════════════════╗\n");
                    printf("║                ✦ Modification des détails ✦                  ║\n");
                    printf("╠══════════════════════════════════════════════════════════════╣\n");
                    printf("║ Motif actuel: %s\n", tempComplaint.motif);
                    printf("║ Nouveau motif: ");

                    char newMotif[50];
                    getchar();
                    fgets(newMotif,sizeof(newMotif),stdin);
                    newMotif[strcspn(newMotif, "\n")] = 0;
                    if(strlen(newMotif) > 0)
                    {
                        strcpy(tempComplaint.motif,newMotif);
                    }

                    printf("║ Description actuelle: %s\n", tempComplaint.description);
                    printf("║ Nouvelle description: ");
                    char newDescription[500];
                    fgets(newDescription,sizeof(newDescription),stdin);
                    newDescription[strcspn(newDescription, "\n")] = 0;
                    if(strlen(newDescription) > 0)
                        strcpy(tempComplaint.description,newDescription);

                    printf("║ Catégorie actuelle: %s\n",tempComplaint.category);
                    printf("║ Nouvelle catégorie: ");
                    char newCategory[50];
                    fgets(newCategory,sizeof(newCategory),stdin);
                    newCategory[strcspn(newCategory, "\n")] = 0;
                    if(strlen(newCategory) > 0)
                        strcpy(tempComplaint.category,newCategory);
                    
                    printf("║ Statut actuel: %s\n",tempComplaint.status);
                    printf("║ Nouveau statut (En cours/Résolue/Rejetée): ");
                    char newStatus[20];
                    fgets(newStatus,sizeof(newStatus),stdin);
                    newStatus[strcspn(newStatus, "\n")] = 0;
                    if(strlen(newStatus) > 0)
                        strcpy(tempComplaint.status,newStatus);
                    
                    printf("║ Notes actuelles: %s\n",tempComplaint.notes);
                    printf("║ Nouvelles notes: ");
                    char newNotes[300];
                    fgets(newNotes,sizeof(newNotes),stdin);
                    newNotes[strcspn(newNotes, "\n")] = 0;
                    if(strlen(newNotes) > 0)
                        strcpy(tempComplaint.notes,newNotes);
                    printf("╚══════════════════════════════════════════════════════════════╝\n");

                    if (strstr(tempComplaint.description, "urgent") || strstr(tempComplaint.description, "danger"))
                    {
                        strcpy(tempComplaint.priority, "Haute");
                    }else if (strstr(tempComplaint.description, "problème") || strstr(tempComplaint.description, "retard"))
                    {
                        strcpy(tempComplaint.priority, "Moyenne");
                    }else
                    {
                        strcpy(tempComplaint.priority, "Basse");
                    }
                    }
                    fprintf(tempFile, "%s;%s;%s;%s;%s;%s;%s;%s\n", 
                        tempComplaint.id, 
                        tempComplaint.username, 
                        tempComplaint.motif, 
                        tempComplaint.description, 
                        tempComplaint.category, 
                        tempComplaint.status, 
                        tempComplaint.date, 
                        tempComplaint.priority);

                }
    fclose(file);
    fclose(tempFile);
    if (found) {
        remove("complaints.txt");
        rename("tem_swap.txt", "complaints.txt");
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║          ✔ Plainte modifiée avec succès !                    ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
    } else {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║          ⚠ Plainte avec ID %s non trouvée !                ║\n", complaintId);
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        remove("tem_swap.txt");
    }

}

void deleteComplaint()
{
    char complaintId[20];
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                ✦ Suppression d'une Plainte ✦                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Entrez l'ID de la plainte à supprimer : ");
    scanf("%s", complaintId);
    printf("╚══════════════════════════════════════════════════════════════╝\n");


    FILE *file = fopen("complaints.txt", "r");
    FILE *tempFile = fopen("temp_temp.txt", "w");
    if (file == NULL || tempFile == NULL)
    {
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠       ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        if (file != NULL) fclose(file);
        if (tempFile != NULL) fclose(tempFile);
        return;
    }

    Complaint tempComplaint;
    int found = 0;

    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF) {
        if (strcmp(tempComplaint.id, complaintId) != 0) {
            fprintf(tempFile, "%s;%s;%s;%s;%s;%s;%s;%s\n", 
                    tempComplaint.id, 
                    tempComplaint.username, 
                    tempComplaint.motif, 
                    tempComplaint.description, 
                    tempComplaint.category, 
                    tempComplaint.status, 
                    tempComplaint.date, 
                    tempComplaint.priority);
        } else {
            found = 1;
            printf("\n");
            printf("╔═════════════════════════════════════════════════════════════════════╗\n");
            printf("║        ✔ Plainte avec ID %s supprimée avec succès !           \n", complaintId);
            printf("╚═════════════════════════════════════════════════════════════════════╝\n");
        }
    }

    fclose(file);
    fclose(tempFile);

    if (found) {
        remove("complaints.txt");
        rename("temp_temp.txt", "complaints.txt");
    } else {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Plainte avec ID %s non trouvée !                  \n", complaintId);
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        remove("temp_temp.txt");
    }
}

void processComplaint() 
{
    char complaintId[20];
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║             ✦ Traitement d'une Plainte ✦                     ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Entrez l'ID de la plainte à traiter : ");
    scanf("%s", complaintId);
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    FILE *file = fopen("complaints.txt", "r");
    FILE *tempFile = fopen("temp_temp.txt", "w");
    if (file == NULL || tempFile == NULL) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠       ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        if (file != NULL) fclose(file);
        if (tempFile != NULL) fclose(tempFile);
        return;
    }

    Complaint tempComplaint;
    int found = 0;

    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF) {
        if (strcmp(tempComplaint.id, complaintId) == 0) {
            found = 1;
            printf("╔══════════════════════════════════════════════════════════════╗\n");
            printf("║            ✔ Traitement de la plainte %s                      ║\n", complaintId);
            printf("╚══════════════════════════════════════════════════════════════╝\n");

            printf("Statut actuel: %s\n", tempComplaint.status);
            printf("Nouveau statut (En cours/Résolue/Rejetée): ");
            scanf(" %[^\n]s", tempComplaint.status);

            printf("Ajouter des notes: ");
            scanf(" %[^\n]", tempComplaint.notes);

            
            if (strstr(tempComplaint.description, "urgent") || strstr(tempComplaint.description, "danger")) {
                strcpy(tempComplaint.priority, "Haute");
            } else if (strstr(tempComplaint.description, "problème") || strstr(tempComplaint.description, "retard")) {
                strcpy(tempComplaint.priority, "Moyenne");
            } else {
                strcpy(tempComplaint.priority, "Basse");
            }
        }
        fprintf(tempFile, "%s;%s;%s;%s;%s;%s;%s;%s\n", 
                tempComplaint.id, 
                tempComplaint.username, 
                tempComplaint.motif, 
                tempComplaint.description, 
                tempComplaint.category, 
                tempComplaint.status, 
                tempComplaint.date, 
                tempComplaint.priority);
    }

    fclose(file);
    fclose(tempFile);

    if (found) {
        remove("complaints.txt");
        rename("temp_temp.txt", "complaints.txt");
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║           ✔ Plainte traitée avec succès !                    ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
    } else {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Plainte avec ID %s non trouvée !                   \n", complaintId);
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        remove("temp_temp.txt");
    }
}


void generateStatistics()
{
    FILE *file = fopen("complaints.txt", "r");
    if (file == NULL) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠       ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        return;
    }

    Complaint tempComplaint;
    int totalComplaints = 0;
    int resolvedComplaints = 0;
    double totalDays = 0.0;
    int resolvedCount = 0;

    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF) {
        totalComplaints++;
        if (strcmp(tempComplaint.status, "Résolue") == 0) {
            resolvedComplaints++;

            
            struct tm submitted;
            sscanf(tempComplaint.date, "%d-%d-%d", &submitted.tm_year, &submitted.tm_mon, &submitted.tm_mday);
            submitted.tm_year -= 1900; 
            submitted.tm_mon -= 1;
            submitted.tm_hour = 0;
            submitted.tm_min = 0;
            submitted.tm_sec = 0;

            
            time_t now = time(NULL);
            struct tm *current = localtime(&now);

            
            time_t submitted_time = mktime(&submitted);
            double diff = difftime(now, submitted_time) / (60 * 60 * 24); 
            totalDays += diff;
            resolvedCount++;
        }
    }

    fclose(file);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║             ✦ Statistiques des Plaintes ✦                    ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Nombre total de plaintes : %d\n", totalComplaints);
    printf("║ Nombre de plaintes résolues : %d\n", resolvedComplaints);

    if (resolvedCount > 0) {
        double average = totalDays / resolvedCount;
        printf("║ Temps moyen de traitement des plaintes : %.2lf jours\n", average);
    } else {
        printf("║ Aucune plainte résolue pour calculer le temps moyen.\n");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}



void generateDailyReport()
{
    FILE *file = fopen("complaints.txt", "r");
    if (file == NULL) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║         ⚠ Erreur d'ouverture du fichier des plaintes ⚠       ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        return;
    }

    Complaint tempComplaint;
    FILE *report = fopen("daily_report.txt", "w");
    if (report == NULL) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║            ⚠ Erreur de création du rapport quotidien ⚠       ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        fclose(file);
        return;
    }

    
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char today[20];
    sprintf(today, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);

    fprintf(report, "╔═════════════════════════════════════════════════════════════════════╗\n");
    fprintf(report, "║                📅 Rapport Quotidien - %s 📅                  \n", today);
    fprintf(report, "╚═════════════════════════════════════════════════════════════════════╝\n\n");
    fprintf(report, "Plainte(s) Nouvelle(s) :\n");
    fprintf(report, "═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(report, "%-10s %-15s %-15s %-20s %-10s %-15s %-12s %-10s\n", 
            "ID", "Username", "Motif", "Description", "Category", "Status", "Date", "Priority");
    fprintf(report, "═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");

    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF) {
        if (strcmp(tempComplaint.date, today) == 0) {
            fprintf(report, "%-10s %-15s %-15s %-20s %-10s %-15s %-12s %-10s\n", 
                    tempComplaint.id, 
                    tempComplaint.username, 
                    tempComplaint.motif, 
                    tempComplaint.description, 
                    tempComplaint.category, 
                    tempComplaint.status, 
                    tempComplaint.date, 
                    tempComplaint.priority);
        }
    }

    
    rewind(file);
    fprintf(report, "\nPlainte(s) Résolue(s) Aujourd'hui :\n");
    fprintf(report, "═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    fprintf(report, "%-10s %-15s %-15s\n", "ID", "Username", "Motif");
    fprintf(report, "═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    while (fscanf(file, "%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^;];%[^\n]\n", 
                  tempComplaint.id, 
                  tempComplaint.username, 
                  tempComplaint.motif, 
                  tempComplaint.description, 
                  tempComplaint.category, 
                  tempComplaint.status, 
                  tempComplaint.date, 
                  tempComplaint.priority) != EOF)
                  {
                if (strcmp(tempComplaint.date, today) == 0 && strcmp(tempComplaint.status, "Résolue") == 0) {
                fprintf(report, "%-10s %-15s %-15s\n", 
                tempComplaint.id, 
                tempComplaint.username, 
                tempComplaint.motif);
                }
    }
    fprintf(report, "═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");

    fclose(file);
    fclose(report);

    printf("\n");
    printf("╔═════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║       ✦ Rapport quotidien généré avec succès dans 'daily_report.txt' ✦      ║\n");
    printf("╚═════════════════════════════════════════════════════════════════════════════╝\n");
}


void menu()
{
    int choice;
    char currentRole[ROLE_SIZE] = "";
    char currentUsername[MAX_USERNAME] = ""; 

    do {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║               ☆☆☆  BIENVENUE  ☆☆☆                ║\n");
        printf("╠══════════════════════════════════════════════════╣\n");
        printf("║ 1. ✦ Inscription                                 ║\n");
        printf("║ 2. ✦ Connexion                                   ║\n");
        printf("║ 3. ✦ Quitter                                     ║\n");
        printf("╠══════════════════════════════════════════════════╣\n");
        printf("║ Veuillez choisir une option :                    ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                signUp();
                break;
            case 2:
                if (signIn(currentRole,currentUsername)) {
                    
                    FILE *file = fopen("users.txt", "r");
                    if (file != NULL) {
                        User tempUser;
                        char tempPasswd[MAX_PASSSWD];
                        while (fscanf(file, "%s %s %s %ld %d", tempUser.username, tempPasswd, tempUser.role, &tempUser.lock_time, &tempUser.attempts) != EOF) {
                            if (strcmp(tempUser.role, currentRole) == 0 && strcmp(tempUser.role, "Administrateur") == 0) {
                                strcpy(currentUsername, tempUser.username);
                                break;
                            }
                        }
                        fclose(file);
                    }

                    if (strcmp(currentRole, "Administrateur") == 0) {
                        manageRoles(currentRole);
                        
                    } else if (strcmp(currentRole, "Agent") == 0) {
                        
                        printf("\n");
                        printf("╔═══════════════════════════════════════════════════════════╗\n");
                        printf("║        ✦✦✦  Gestion des Plaintes pour Agent  ✦✦✦          ║\n");
                        printf("╚═══════════════════════════════════════════════════════════╝\n");
                        int agentChoice;
                        do {
                            printf("\n");
                            printf("╔══════════════════════════════════════════════════╗\n");
                            printf("║           ✦✦✦  GESTION DES PLAINTES  ✦✦✦         ║\n");
                            printf("╠══════════════════════════════════════════════════╣\n");
                            printf("║ 1. ➤ Ajouter une nouvelle plainte                ║\n");
                            printf("║ 2. ➤ Modifier une plainte                        ║\n");
                            printf("║ 3. ➤ Supprimer une plainte                       ║\n");
                            printf("║ 4. ➤ Afficher la liste des plaintes              ║\n");
                            printf("║ 5. ➤ Traiter une plainte                         ║\n");
                            printf("║ 6. ➤ Retour au menu principal                    ║\n");
                            printf("╠══════════════════════════════════════════════════╣\n");
                            printf("║ Choisissez une option :                          ║\n");
                            printf("╚══════════════════════════════════════════════════╝\n");
                            scanf("%d", &agentChoice);
                            printf("Choix sélectionné : %d\n", agentChoice); 

                            switch (agentChoice) {
                                case 1:
                                    addComplaint("Agent"); 
                                    break;
                                case 2:
                                    modifyComplaint();
                                    break;
                                case 3:
                                    deleteComplaint();
                                    break;
                                case 4:
                                    displayComplaints("Agent", ""); 
                                    break;
                                case 5:
                                    processComplaint();
                                    break;
                                case 6:
                                    printf("\n");
                                    printf("╔══════════════════════════════════════╗\n");
                                    printf("║      🔙  Retour au menu principal    ║\n");
                                    printf("╚══════════════════════════════════════╝\n");
                                    break;
                                default:
                                    printf("\n");
                                    printf("╔══════════════════════════════════╗\n");
                                    printf("║      ⚠️  Option invalide !        ║\n");
                                    printf("╚══════════════════════════════════╝\n");
                            }

                        } while (agentChoice != 6);
                    } else if (strcmp(currentRole, "Client") == 0) {
                        printf("\n");
                        printf("╔═══════════════════════════════════════════════════════════╗\n");
                        printf("║        ✦✦✦  Gestion des Plainte pour Client  ✦✦✦          ║\n");
                        printf("╚═══════════════════════════════════════════════════════════╝\n");
                        int clientChoice;
                        do {
                            printf("\n");
                            printf("╔══════════════════════════════════════════════════╗\n");
                            printf("║            ✦✦✦  GESTION DES PLAINTES  ✦✦✦        ║\n");
                            printf("╠══════════════════════════════════════════════════╣\n");
                            printf("║ 1. ➤ Ajouter une nouvelle plainte                ║\n");
                            printf("║ 2. ➤ Afficher mes plaintes                       ║\n");
                            printf("║ 3. ➤ Quitter                                     ║\n");
                            printf("╠══════════════════════════════════════════════════╣\n");
                            printf("║ Choisissez une option :                          ║\n");
                            printf("╚══════════════════════════════════════════════════╝\n");
                            scanf("%d", &clientChoice);
                            printf("Choix sélectionné : %d\n", clientChoice); 

                            switch (clientChoice) {
                                case 1:
                                    addComplaint(currentUsername);
                                    break;
                                case 2:
                                    displayComplaints("Client", currentUsername);
                                    break;
                                case 3:
                                    printf("\n");
                                    printf("╔══════════════════════════════════════╗\n");
                                    printf("║      🔙  Retour au menu principal    ║\n");
                                    printf("╚══════════════════════════════════════╝\n");
                                    break;
                                default:
                                    printf("\n");
                                    printf("╔══════════════════════════════════╗\n");
                                    printf("║      ⚠️  Option invalide !        ║\n");
                                    printf("╚══════════════════════════════════╝\n");
                            }

                        } while (clientChoice != 3);
                    }
                }
                break;
            case 3:
                printf("\n");
                printf("╔══════════════════════════════╗\n");
                printf("║        ✦ Au revoir ! ✦       ║\n");
                printf("╚══════════════════════════════╝\n");
                break;
            default:
                printf("\n");
                printf("╔══════════════════════════════════╗\n");
                printf("║      ⚠️  Option invalide !        ║\n");
                printf("╚══════════════════════════════════╝\n");

        }

    } while (choice != 3);


}

int main()
{
    menu();
    return 0;
}
