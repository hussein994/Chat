# Algorithmes des réseaux

## Chat à deux utilisateurs

Complétez le programme `client-chat.c` pour réaliser un client d'un chat en mode texte pour deux utilisateurs. Le programme devra être double pile, c'est-à-dire être compatible avec des clients `IPv4` et `IPv6`. Le protocole `UDP` sera utilisé au niveau transport. 

Le programme `client-chat` admet en argument le numéro de port sur lequel le programme devra écouter (si aucun autre client n'est déjà en écoute) ou le numéro de port sur lequel joindre un client déjà présent :

    ./client-chat port_number

Les seuls numéros de port valides sont ceux contenus dans l'intervalle `[10000; 65000]`.

Le programme utilise un protocole simpliste en mode texte pour l'ouverture et la fermeture du salon de discussion. Les commandes admises sont : `/HELO` et `/QUIT` comme illusté sur le diagramme état transition sur la figure :

![state chart](protocol.svg)

Pour créer un socket unique compatible `IPv4` et `IPv6`, vous devez créer un socket `AF_INET6` et désactiver l'option `bindv6only` sur ce dernier via la primitive `setsockopt()` :

    int value = 0;
    CHECK (setsockopt (sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof value));

Dans le cas où aucun client n'est présent, il faut utiliser toutes les adresses de l'hôte lors de l'appel à `bind` via la variable `in6addr_any` :

    struct sockaddr *s       = (struct sockaddr *)     &ss;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &ss;
    in6->sin6_addr           = in6addr_any;

Pour écouter simultanément sur plusieurs descripteurs (ici l'entrée standard et le socket), vous devez utiliser la primitive :

    int poll (struct pollfd *fds, nfds_t nfds, int timeout);

L'ensemble des descripteurs à surveiller est présent dans une liste de structure `struct pollfd` :

    struct pollfd {
        int   fd;         /* descripteur */
        short events;     /* requested events */
        short revents;    /* returned events */
    };

Le champ `events` est un champ de bit correspondant aux événements à surveiller pour le descripteur `fd`. Le champ `revents` est également un champ de bits, complété par le noyau au retour de `poll()`, qui contient les événements surveillés pour le descripteur `fd` qui se sont réellement produits. Consulter le manuel utilisateur sur `poll()` pour découvrir la liste des événements possibles et plus généralement le fonctionnement de cette primitive.

Tout commit compile automatiquement votre programme et lance les tests dessus. Tous les tests doivent réussir avant de passer à l'exercice suivant.
