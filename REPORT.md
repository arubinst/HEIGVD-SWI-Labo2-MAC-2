# SWI – Laboratoire 2

* **Date** : 16.03.2020
* **Auteurs** : Mickael Bonjour, Nikolaos Garanis.

## 1. Probe Request Evil Twin Attack

> Comment ça se fait que ces trames puissent être lues par tout le monde ? Ne serait-il pas plus judicieux de les chiffrer ?

Ces probes sont lancées pour essayer de trouver un WiFi, l'appareil n'est pas connecté à ce moment là. Cela implique qu'il n'y a pas de clé établie entre l'AP et l'appareil pour chiffrer.

> Pourquoi les dispositifs iOS et Android récents ne peuvent-ils plus être tracés avec cette méthode ?

Car lorsqu'ils cherche un Wifi auquel se connecter (probe request), l'adresse MAC de la frame est randomisée. Il n'est donc plus possible d'associer les probe requests à un appareil spécifique.

### Fonctionnement

![](images/1-probes-evil.png)

## 2. Détection de clients et réseaux

### Fonctionnement

![](images/2-probe-req.png)

![](images/2-sta-per-ap.png)

## 3. Hidden SSID reveal

> Expliquer en quelques mots la solution que vous avez trouvée pour ce problème.

Nous commençons par enregistrer les SSID qui émettent des beacons sans y indiquer les BSSIDs, cela nous indiques les Wifis cachés.
En même temps on récupères les trames de Probe response car c'est là que les Wifis indiquent leurs noms aux appareils qui le recherchent.

### Fonctionnement

![](images/3-evil-twin.png)
