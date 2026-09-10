# SecOps Automated Correlation Report

Script Python che genera un **report PDF esecutivo** correlando:

- **Zabbix**: criticità infrastrutturali attualmente attive (trigger in stato PROBLEM), filtrabili per priorità minima;
- **Wazuh**: vulnerabilità software e alert di sicurezza rilevati in una finestra temporale configurabile, con verifica automatica se ogni CVE risulta **ancora attiva oggi** o **già risolta**.

Il risultato è un unico PDF con un pannello *Executive Summary*, la tabella Zabbix e la tabella Wazuh, ordinate per gravità e data.

## Caratteristica principale: colonna "Stato"

Per ogni vulnerabilità Wazuh trovata nella finestra storica selezionata, lo script interroga anche lo **stato corrente** dell'inventario vulnerabilità (`wazuh-states-vulnerabilities-*`) e marca ogni riga con:

- 🟢 **Risolto** — la CVE era presente negli alert storici ma non risulta più nello stato attuale dell'host (tipicamente perché il pacchetto è stato aggiornato/patchato nel frattempo);
- 🔴 **Non Risolto** — la CVE è ancora presente nello stato attuale dell'host;
- ⚪ **N/D** — riga di alert generico (non associata a una CVE specifica, es. problemi dell'agent), lo stato risolto/non risolto non è applicabile.

Questo evita il problema di leggere come "attive" vulnerabilità già sanate nel frattempo, semplicemente perché rientrano ancora nella finestra temporale di analisi.

## Requisiti

- Python 3.8+
- Un Wazuh Indexer (OpenSearch) raggiungibile in rete, Wazuh **4.8+** (stessa dipendenza del modulo `wazuh_cve_report.py`)
- Un'istanza Zabbix con API JSON-RPC abilitata e un token API valido
- Connessione di rete verso entrambi i servizi

## Installazione

```bash
git clone <url-del-repo>
cd <cartella-repo>
pip install -r requirements.txt
```

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

## Utilizzo

```bash
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

## Come funziona (in breve)

1. `fetch_zabbix_problems()` interroga Zabbix per i trigger attualmente in stato PROBLEM, nati nella finestra di giorni selezionata, con priorità ≥ soglia scelta.
2. `fetch_wazuh_alerts()` interroga l'indice storico `wazuh-alerts*` per gli eventi (vulnerabilità o alert di regola) nella stessa finestra temporale.
3. `fetch_current_active_cves()` raccoglie tutte le CVE uniche trovate al punto 2 e verifica, con un'unica query sull'indice `wazuh-states-vulnerabilities-*`, quali coppie (host, CVE) sono **ancora attive oggi**.
4. `generate_pdf_report()` assembla il PDF finale, colorando ogni riga Wazuh in base allo stato calcolato.

## Limitazioni note

- La verifica "Risolto/Non Risolto" fa match sul nome dell'agent (`agent.name`): se un host viene rinominato tra la data dell'alert storico e oggi, il match potrebbe non trovarlo e la riga risulterebbe marcata come "Non Risolto" anche se in realtà è stata risolta.
- I problemi Zabbix restituiti sono per definizione quelli **attualmente attivi** (`filter: {value: 1, status: 0}`); il parametro giorni-indietro filtra solo la data di inizio del problema (`lastchange`), non introduce quindi lo stesso tipo di falso positivo delle vulnerabilità Wazuh.
- Pensato per Wazuh **4.8+** (Vulnerability Detection su Indexer). Su versioni precedenti la logica di verifica dello stato corrente andrebbe riscritta usando l'API Manager.
- Query Wazuh con `size: 10000`: con volumi di alert molto superiori andrebbe introdotta la paginazione.

## Sicurezza

- Di default la verifica del certificato SSL è disabilitata (`verify=False`) sia per Wazuh che per Zabbix, per compatibilità con certificati self-signed tipici di ambienti on-premise. Se i tuoi servizi hanno certificati validi, valuta di abilitare la verifica SSL nelle chiamate `requests`.
- Usa, se possibile, un account Zabbix/Wazuh dedicato con permessi in sola lettura per questo script.

## Licenza

Distribuito con licenza [MIT](LICENSE).
