# Sécurité des réseaux sans fil
> Laboratoire: Labo2-MAC-2   
> Étudiants: Yimnaing Crescence, Siu Aurélien

### 1. Probe Request Evil Twin Attack


**Question : comment ça se fait que ces trames puissent être lues par tout le monde ? Ne serait-il pas plus judicieux de les chiffrer ?**
# TODO

**Question : pourquoi les dispositifs iOS et Android récents ne peuvent-ils plus être tracés avec cette méthode ?**

Car l'adresse MAC de ces périphériques est randomisée afin de les protéger

> Chemin du script : HEIGVD-SWI-Labo2-MAC-2/scripts/ProbeRequestEvilTwinAttack.py


![](images/deauthentification-screen.png)
  

### 2. Détection de clients et réseaux

# TODO




### 3. Hidden SSID reveal

__Question__ : expliquer en quelques mots la solution que vous avez trouvée pour ce problème ?

Nous récupérons dans un premier la liste des adresses MAC des APs ayant un SSID null. Le SSID se trouvant dans la Probe Response lorsque qu'un client se connecte à ce même réseau, nous pouvons le récupérer.

> Chemin du script : HEIGVD-SWI-Labo2-MAC-2/Scripts/UncoveredHiddenSSID.py


