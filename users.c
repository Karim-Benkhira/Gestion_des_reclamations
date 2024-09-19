#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_USERNAME 50
#define MAX_PASSSWD 50
#define MIN_PASSWD 8

int PasswdValidOrInvalid(const char *passwd, const char *username)
{
    int P_Upper = 0, P_Lower = 0, P_Digit = 0, P_Special = 0;
    const char *specialChars = "!@#$%^&*";


    if (strlen(passwd) < MIN_PASSWD)
        return 0;
    

    for (int i = 0; passwd[i] != '\0'; i++)
    {
        if (isupper(passwd[i]))
            P_Upper = 1;
        if (islower(passwd[i]))
            P_Lower = 1;
        if (isdigit(passwd[i]))
            P_Digit = 1;
        if (strchr(specialChars, passwd[i]))
            P_Special = 1;
    }


    if (strstr(passwd, username) != NULL)
        return 0;

    return P_Upper && P_Lower && P_Digit && P_Special;
}

void singUp()
{
    char Passwd[MAX_PASSSWD];
    char UserName[MAX_USERNAME];

    printf("=== Inscription ===\n");


    printf("Entrez votre identifiant : ");
    scanf("%s", UserName);
    printf("Entrez votre mot de passe : ");
    scanf("%s", Passwd);


    if (!PasswdValidOrInvalid(Passwd, UserName))
    {
        printf("Mot de passe invalide. Veuillez réessayer.\n");
        return;
    }


    FILE *file = fopen("users.txt", "a");
    if (file == NULL) {
        printf("Erreur d'ouverture du fichier.\n");
        return;
    }

    fprintf(file, "%s %s\n", UserName, Passwd);
    fclose(file);

    printf("Inscription réussie !\n");
}
/*teeeeeeeeeeeeeeeeeeeeeest
int main()
{
    singUp();
    return 0;
}
*/