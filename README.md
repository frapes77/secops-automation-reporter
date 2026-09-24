# SecOps Automated Correlation Report

Script Python che genera un **report PDF esecutivo** correlando:

- **Zabbix**: criticità infrastrutturali attualmente attive (trigger in stato PROBLEM), filtrabili per priorità minima;
- **Wazuh**: vulnerabilità software e alert di sicurezza rilevati in una finestra temporale configurabile, con verifica automatica se ogni CVE risulta **ancora attiva oggi** o **già risolta**.

L'obiettivo principale dello script è superare il semplice concetto di "livello di severità" (Critical, High, Medium, Low), introducendo un algoritmo di prioritizzazione dinamico basato su minacce
reali e contesto aziendale, generando un report finale in formato PDF orizzontale (Landscape) pronto per il team di SecOps.


## Funzionalità Principali:

- Correlazione Multi-Piattaforma: Unifica in un unico documento gli allarmi infrastrutturali attivi di Zabbix e l'inventario delle vulnerabilità software (CVE) di Wazuh.
- Prioritizzazione Dinamica: Calcola un punteggio da 0 a 100 per ogni CVE per riordinare le vulnerabilità all'interno dello stesso livello di severità, mostrando visivamente classi di priorità 
  da P1 (urgente) a P4 (minore).
- Fonti Pubbliche e Gratuite: Sfrutta le API di FIRST (EPSS) e i feed di CISA (KEV) senza richiedere chiavi API private o iscrizioni a pagamento.
- Massima Privacy di Rete: Verso Internet vengono inviati esclusivamente gli identificativi CVE generici. Nessun dato sensibile sulla tua infrastruttura o sui tuoi host esce dalla rete locale.
- Robustezza d'Esecuzione: Lo script implementa meccanismi di caching locale per i feed e ripieghi (fallback) offline in caso di disconnessione internet, garantendo che il report venga generato in
  ogni situazione.
- Nessun Limite di Record: Supera il limite standard di 10.000 record di OpenSearch grazie all'integrazione nativa della Scroll API per la paginazione coerente dei dati.


## Come Viene Calcolata la Priorità:

Il motore dello script assegna a ogni vulnerabilità un punteggio combinando tre fattori principali: 
   1- EPSS (Peso 40%): La probabilità di sfruttamento pubblicata da FIRST. Poiché i valori EPSS sono storicamente sbilanciati verso lo zero, un valore pari o superiore al 20% viene 
                       automaticamente saturato al punteggio massimo. Le richieste vengono ottimizzate a blocchi di 80 CVE per non sovraccaricare i server. 
   2- CVSS (Peso 30%): Il punteggio di gravità standard ereditato direttamente dall'inventario di Wazuh. 
   3- Esposizione del Software (Peso 30%): Valutazione contestuale definita tramite regole interne (EXPOSURE_RULES) in base alla tipologia di software:
        - 1.0: Sistemi operativi e servizi esposti in rete (es. Windows, OpenSSH, Nginx, PostgreSQL).
        - 0.8: Applicativi locali che aprono file o contenuti esterni non fidati (es. Foxit, WinRAR, VLC, Chrome).
        - 0.5: Client di connessione verso l'esterno (es. PuTTY, WinSCP). 
        - 0.3: Strumenti di sviluppo o editor locali (es. Notepad++, Python). 


## Catalogo CISA KEV: 

Se una CVE è presente nel catalogo delle vulnerabilità attivamente sfruttate nei cyber-attacchi (CISA KEV), il punteggio sale immediatamente a un minimo di 90 punti, forzando la vulnerabilità 
in classe P1. 


##Soglie di Priorità:

    P1: Punteggio >= 75 (Massima urgenza) 
    P2: Punteggio >= 55 
    P3: Punteggio >= 35 
    P4: Punteggio <  35  


## Caratteristica principale: colonna "Stato"

Per ogni vulnerabilità Wazuh trovata nella finestra storica selezionata, lo script interroga anche lo **stato corrente** dell'inventario vulnerabilità (`wazuh-states-vulnerabilities-*`) e 
marca ogni riga con:

- 🟢 **Risolto** — la CVE era presente negli alert storici ma non risulta più nello stato attuale dell'host (tipicamente perché il pacchetto è stato aggiornato/patchato nel frattempo);
- 🔴 **Non Risolto** — la CVE è ancora presente nello stato attuale dell'host;
- ⚪ **N/D** — riga di alert generico (non associata a una CVE specifica, es. problemi dell'agent), lo stato risolto/non risolto non è applicabile.

Questo evita il problema di leggere come "attive" vulnerabilità già sanate nel frattempo, semplicemente perché rientrano ancora nella finestra temporale di analisi.


## Requisiti

- Python 3.8+
- Un Wazuh Indexer (OpenSearch) raggiungibile in rete, Wazuh **4.8+** (il modulo deve scrivere sull'indice wazuh-states-vulnerabilities-*).
- Un'istanza Zabbix con API JSON-RPC abilitata e un token API valido.
- Librerie Python: requests, reportlab
- Connessione di rete verso entrambi i servizi


## Installazione

git clone <url-del-repo>
cd <cartella-repo>
pip install -r requirements.txt


`requirements.txt`:
```
requests
reportlab
```


## Configurazione

All'interno dello script andranno inseriti gli IP delle macchine Wazuh e Zabbix, unitamente alla porta utilizzata per la connessione con Zabbix.

Cerca e completa le righe:

export WAZUH_INDEXER_URL="https://<IP_WAZUH_INDEXER>:9200"
export ZABBIX_API_URL="http://<IP_ZABBIX>:<PORTA>/api_jsonrpc.php"
export ZABBIX_API_TOKEN="il-tuo-token-zabbix"
```


## Nota Importante sulla Sicurezza (Zabbix API Token):

All'interno del codice è presente la variabile cablata ZABBIX_API_TOKEN:
- Uso Interno: Lo script è attualmente configurato per un utilizzo strettamente interno all'infrastruttura aziendale fidata.
- Condivisione o Server Esterni: Se desideri pubblicare lo script, condividerlo con terzi o comunicare con istanze Zabbix esterne, è fondamentale rimuovere il token dal codice sorgente. 
  Modifica lo script per caricare il token tramite una variabile d'ambiente


## Utilizzo

python3 Analisi_Wazuh_Zabbix_rev7.py
```

Lo script guida l'utente con alcune domande interattive:

1. **Giorni da analizzare a ritroso da oggi** (default 30)
2. **Livello minimo di severità** (1-Information, 2-Low, 3-Medium, 4-High \[consigliato\], 5-Critical)
3. **Host specifico** da analizzare (facoltativo, INVIO per l'intera infrastruttura)
4. **Username Wazuh Indexer** e relativa password

Al termine viene generato un PDF:
- `SecOps_Report_<HOST>_<AAAAMMGG>.pdf` se hai specificato un host;
- `SecOps_Executive_Report_<AAAAMMGG>.pdf` per l'intera infrastruttura.


## Cosa Troverai nel PDF:

Il report viene generato in formato PDF Orizzontale (Landscape) per facilitare la lettura di tabelle complesse e include:
  - Executive Summary: Un pannello riassuntivo con le statistiche reali dei dati filtrati e la situazione complessiva dei livelli di severità.
  - Tabella Zabbix: L'elenco ordinato delle criticità infrastrutturali e dei trigger attivi rilevati sui sistemi.
  - Tabella Wazuh con Priorità: Le vulnerabilità software ordinate, a parità di severità, dalla più urgente alla meno urgente. 
    La colonna "Priorità" mostrerà indicazioni chiare (Es: P1 · 86 KEV con il rispettivo valore EPSS 35.0%). 
      ...Nota per le nuove CVE: Se una CVE è appena stata pubblicata e non ha ancora un valore EPSS, il report mostrerà EPSS n/d applicando un valore prudenziale intermedio per l'ordinamento.
  - Legenda Esplicativa: Una sezione in calce alla tabella descrive la formula e il significato degli acronimi utilizzati.


## Limitazioni note:

- La verifica "Risolto/Non Risolto" fa match sul nome dell'agent (`agent.name`): se un host viene rinominato tra la data dell'alert storico e oggi, il match potrebbe non trovarlo e 
  la riga risulterebbe marcata come "Non Risolto" anche se in realtà è stata risolta.
- I problemi Zabbix restituiti sono per definizione quelli **attualmente attivi** (`filter: {value: 1, status: 0}`); il parametro giorni-indietro filtra solo la data di inizio del problema 
  (`lastchange`), non introduce quindi lo stesso tipo di falso positivo delle vulnerabilità Wazuh.
- Pensato per Wazuh **4.8+** (Vulnerability Detection su Indexer). Su versioni precedenti la logica di verifica dello stato corrente andrebbe riscritta usando l'API Manager.


## Taratura e Customizzazione:

Il sistema è progettato per essere cucito su misura per la mia infrastruttura. Al primo avvio reale su macchine di riferimento (es. PC_CED), analizza i primi 20 risultati. 
Se noti discrepanze nell'urgenza, puoi intervenire direttamente sulle variabili in cima al file:
    - PRIORITY_WEIGHTS: Per bilanciare l'impatto di EPSS, CVSS o esposizione software.
    - PRIORITY_THRESHOLDS: Per stringere o allargare le maglie delle classi P1-P4.
    - EXPOSURE_RULES: Per aggiungere software specifici della tua organizzazione o ridefinirne il livello di pericolosità.
    - ASSET_WEIGHT: Un dizionario utile a dare un peso maggiore a macchine critiche (es. i Server di produzione) rispetto alle normali postazioni di lavoro.


## Sicurezza

- Di default la verifica del certificato SSL è disabilitata (`verify=False`) sia per Wazuh che per Zabbix, per compatibilità con certificati self-signed tipici di ambienti on-premise. 
  Se i tuoi servizi hanno certificati validi, valuta di abilitare la verifica SSL nelle chiamate `requests`.
- Usa, se possibile, un account Zabbix/Wazuh dedicato con permessi in sola lettura per questo script.


## Clausola di Responsabilità:

Come per tutte le metriche automatizzate di sicurezza, il calcolo della priorità fornito da questo script serve come supporto alla decisione e come strumento di ottimizzazione del tempo. 
Non sostituisce in alcun modo il giudizio critico, l'esperienza e l'analisi finale dell'analista SecOps o dell'amministratore di sistema che esegue l'intervento.


## Licenza

Distribuito con licenza [MIT](LICENSE).
