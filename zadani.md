# PCAP NetFlow v5 exportér 2024/2025

    Implementujte program p2nprobe, který bude extrahovat informace o tocích ze souboru PCAP a bude je odesílat na kolektor ve formátu NetFlow v5. Nástroj bude na vstupu načítat pakety ze zadaného PCAP souboru, agregovat je do toků. Toky bude odesílat pomocí protokolu UDP na NetFlow v5 kolektor, kde budou přijaty a dále zpracovány. Vaším úkolem je implementovat pouze exportér a omezit se pouze na export záznamů o tocích TCP, ostatní provoz nezpracováváte.

     

### Spuštění programu

    ./p2nprobe <host>:<port> <pcap_file_path> [-a <active_timeout> -i <inactive_timeout>]

    Pořadí parametrů je libovolné. Popis parametrů:

        <pcap_file_path> - zde bude uvedena cesta k souboru PCAP, který se má zpracovat;
        <host> - IP adresa nebo doménové jméno kolektoru;
        <port> - port kolektoru, kam budou zprávy odesílány;
        -a <active_timout> - počet sekund pro nastavení aktivního timeoutu exportu flow (defaultní hodnota při nepoužití parametru 60);
        -i <inactive_timeout> - počet sekund pro nastavení inaktivního timoutu exportu flow (defaultní hodnota při nepoužití parametru 60).

     

### Další informace

    Protokol NetFlow v5 je velmi rozšířený a známý, neexistuje pro něj však RFC. Informace k tomuto protokolu budete muset nalézt na internetu, například na stránkách společnosti CISCO, která za tímto protokolem stojí.

    Při implementaci můžete využít program nfcapd jako příjemce NetFlow v5 zpráv (kolektor). Dále můžete použít programy existujících NetFlow v5 exportérů jako je například softflowd (přepínač -v 5 pro export NetFlow v5) a prostudovat zachycenou komunikaci pomocí programu Wireshark.

    Při odesílání zpráv na kolektor se snažte být maximálně efektivní a využít počet exportovaných záznamů o tocích ve zprávě na maximum, pokud to bude možné.

    Při hodnocení bude dbáno na korektní výstup zpracovaného souboru, tedy počet exportovaných toků a součet statistických informací z toků (správný počet paketů a bytů), korektní identifikátory (IP, port, protokol), časové značky toku a další. Políčka v záznamu o toku, která nebude možné vyplnit, jako  například NextHop, SrcAS, DstAS a další, nechte prázdná, ostatní pole vypiště korektně.

    Prostudujte rozdíly mezi aktivním a neaktivním timeoutem a jejich vlivem na činnost exportéru a výsledné záznamy o tocích. Tuto funcionalitu pak správně implementujte.

     

### Implementační detaily
    Program implementujte v jazyce C/C++ pro prostředí Unixových systémů. Referenční prostředí pro překlad bude server merlin.fit.vutbr.cz.

    Je povoleno (a doporučeno) použít knihovnu libpcap. Dále můžete použít hlavičkové soubory pro práci se sokety a další obvyklé funkce používané v síťovém prostředí (jako je netinet/*, sys/*, arpa/* apod.), knihovnu pro práci s vlákny (pthread), signály, časem, stejně jako standardní knihovnu jazyka C (varianty ISO/ANSI i POSIX, všetně souvisejících hlavičkových souborů: ctype.h, string.h., aj), standardní knihovnu jazyka C++ a STL (včetně souvisejících hlaviček). Jiné knihovny nejsou povoleny, nestanoví-li vyučující jinak.

     

### Příklad spuštění

    ./p2nprobe  localhost:2055 muj_pcap.pcap -a 5 -i 30

    ./p2nprobe localhost:2055 muj_pcap.pcap

    Program v případě hladkého běhu nebude vypisovat žádné hlášky na standardní výstup, pouze případné chyby na standardní chybový výstup, pokud nastanou.