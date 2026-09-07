# SecOps Automated Correlation Pipeline

![Python Version](https://shields.io)
![License](https://shields.io)

Una pipeline di automazione in **Python** progettata per centralizzare, correlare ed esportare in formato **PDF** gli alert critici provenienti da piattaforme di monitoraggio e sicurezza diverse: **Wazuh (SIEM/XDR)** e **Zabbix (Infrastructure Monitoring)**.

Questo strumento risolve il problema della frammentazione dei dati nei team SecOps, riducendo il *Mean Time to Respond* (MTTR) attraverso l'eliminazione dei controlli manuali tra console separate.

---

## Funzionalità

- **Integrazione API Multi-Piattaforma:** Interrogazione nativa di Wazuh Indexer tramite Query DSL (porta 9200) e di Zabbix API tramite protocollo JSON-RPC (porta 8091).
- **Reportistica Mirata o Globale:** Supporta la generazione di report sull'intera infrastruttura oppure focalizzati su un singolo endpoint specifico tramite input interattivo.
- **Filtro Host Flessibile (Fuzzy & Case-Insensitive):** Implementa una logica di matching parziale via codice Python. Se un host è registrato come `SERVER-PROD-01` su Wazuh e `server-prod-01.local` su Zabbix, lo script è in grado di correlare correttamente gli eventi ignorando discrepanze di maiuscole/minuscole o naming convention disallineate.
- **Prevenzione dei Loop e Gestione Eccezioni:** Architettura resiliente che garantisce la corretta stesura del report anche nel caso in cui l'host cercato sia monitorato su una sola delle due piattaforme (o non presenti allarmi attivi).
- **Visualizzazione Professionale:** Generazione automatica di documenti PDF pronti per la condivisione aziendale tramite la libreria `ReportLab`, con tabelle autowrap, colorazioni SecOps standard (Hex Palette) e impaginazione dinamica.

---

## Configurazione e Personalizzazione

Lo script è strutturato per essere pronto all'uso con una personalizzazione minima direttamente nel codice sorgente. Prima di avviarlo, apri il file dello script e inserisci i parametri della tua infrastruttura nelle apposite variabili all'inizio del file:

```python
# --- CONFIGURAZIONI INFRASTRUTTURA ---
WAZUH_INDEXER_URL = "https://<IL_TUO_IP_WAZUH>:9200"
ZABBIX_API_URL = "http://<IL_TUO_IP_ZABBIX>:8091/api_jsonrpc.php"

# --- TOKEN AUTOMATICO ZABBIX ---
ZABBIX_API_TOKEN = "<IL_TUO_TOKEN_ZABBIX_CREATO_SULLA_PIATTAFORMA>"
```

---

## Requisiti e Installazione

1. **Clonazione della Repository:**
   ```bash
   git clone https://github.com
   cd secops-automation-reporter
   ```

2. **Installazione delle Dipendenze:**
   Assicurati di installare le librerie necessarie prima di lanciare lo script:
   ```bash
   pip install requests reportlab
   ```

---

## Modalità d'Uso

Avvia lo script dal tuo terminale o IDE:
```bash
python Analisi-Wazuh-Zabbix_rev4.py
```

1. **Filtro Host:** Lo script ti chiederà il nome dell'host.
   - *Premi INVIO* per generare il report globale su tutta l'infrastruttura.
   - *Digita il nome (anche parziale o minuscolo)* di una macchina per estrarre solo i dati di quell'host.
2. **Autenticazione Wazuh:** Inserisci l'username e la password (che rimarrà nascosta a schermo durante la digitazione) per connetterti a Wazuh Indexer.
3. **Output:** Al termine dell'elaborazione verrà generato un file PDF pulito e strutturato, denominato `SecOps_Executive_Report.pdf` (globale) oppure `SecOps_Report_<nomehost>.pdf` (singolo).

---

## 📄 Licenza
Questo progetto è rilasciato sotto licenza MIT. Consulta il file `LICENSE` per ulteriori dettagli.
