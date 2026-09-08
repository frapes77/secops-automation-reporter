# SecOps Automated Correlation & Baseline Pipeline

![Python Version](https://shields.io)
![License](https://shields.io)

Una pipeline di automazione professionale in **Python** progettata per centralizzare, correlare ed esportare in formato **PDF** gli alert critici provenienti da piattaforme di monitoraggio e sicurezza disallineate: **Wazuh (SIEM/XDR)** e **Zabbix (Infrastructure Monitoring)**.

Questo strumento è specificamente orientato alle attività di **Vulnerability Management** e **Remediation (Patching)**, offrendo agli analisti SecOps la capacità di scattare "fotografie" storiche mirate dell'infrastruttura per valutare l'efficacia dei controlli di sicurezza nel tempo.

---

## Funzionalità Avanzate

- **Analisi Temporale Retrospettiva (Baseline Audit):** Consente di definire interattivamente una data di riferimento e una finestra temporale (es. 30, 60, 90 giorni) per analizzare lo stato dei sistemi a ritroso, isolando perfettamente i perimetri pre e post-patching.
- **Ereditarietà Cumulativa dei Livelli:** Menu di selezione della severità minima (da 1 a 5). Selezionando ad esempio il livello *High*, la pipeline estrae automaticamente sia gli eventi *High* che quelli a gravità superiore (*Critical* / *Disaster*), garantendo una visibilità cumulativa verso l'alto.
- **Deduplicazione Totale Multi-Livello:** Implementa un algoritmo in grado di accorpare i log ripetitivi e ridondanti (es. flooding di eventi di sistema simili nello stesso minuto), riducendo la dimensione dei report e mantenendo solo record storici unici.
- **Ordinamento Combinato Matematico:** Gli allarmi all'interno del report vengono organizzati secondo una doppia cernita: prioritizzati prima per peso di gravità (dal più pericoloso al meno pericoloso) e, a parità di livello, disposti in rigoroso ordine cronologico decrescente (dal più recente al meno recente).
- **Executive Summary Grafico con Palette SecOps:** Il PDF generato include un pannello iniziale con i KPI numerici degli alert suddivisi per livello, formattati con tag colore condizionali nativi (Rosso, Arancio, Giallo, Blu, Verde) per una valutazione immediata del rischio aziendale.

---

## Configurazione e Personalizzazione

Lo script isola le credenziali e i parametri di rete all'inizio del file sorgente per un deployment sicuro conforme agli standard Open Source. Prima di avviarlo, inserisci i parametri della tua infrastruttura nelle apposite variabili:

```python
# --- CONFIGURAZIONI INFRASTRUTTURA ---
WAZUH_INDEXER_URL = "https://<IL_TUO_IP_WAZUH>:9200"
ZABBIX_API_URL = "http://<IL_TUO_IP_ZABBIX>:PORTA/api_jsonrpc.php"

# --- TOKEN AUTOMATICO ZABBIX ---
ZABBIX_API_TOKEN = "<IL_TUO_TOKEN_DI_AUTENTICAZIONE_ZABBIX>"
```

---

## Requisiti e Installazione

1. **Clonazione della Repository:**
   ```bash
   git clone https://github.com
   cd secops-automation-reporter
   ```

2. **Installazione delle Dipendenze:**
   Assicurati di installare i moduli necessari prima di lanciare la pipeline:
   ```bash
   pip install requests reportlab
   ```

---

## Modalità d'Uso Interattiva

Avvia lo script dal tuo terminale o IDE:
```bash
python Analisi-Wazuh-Zabbix_rev5.py
```

L'interfaccia a riga di comando guiderà l'operatore nella configurazione del report attraverso quattro passaggi:
1. **Finestra Temporale:** Inserisci la data di riferimento (GG/MM/AAAA) per l'analisi a ritroso [Premere INVIO per partire da oggi]. Successivamente, definisci la durata in giorni della finestra [Default: 30 giorni].
2. **Filtro di Severità:** Seleziona il livello minimo di sbarramento (da 1 a 5) [Default: 4 - High].
3. **Filtro Host:** Digita il nome (anche parziale o case-insensitive) di una macchina specifica per isolare i suoi dati, oppure premi INVIO per generare un report globale sull'intera infrastruttura.
4. **Autenticazione:** Inserisci l'username e la password di Wazuh Indexer (la password rimarrà nascosta a schermo durante la digitazione per ragioni di sicurezza).

### Output Rilasciato
Al termine del processo verrà compilato un documento PDF executive denominato `SecOps_Report_<nomehost>_<data>.pdf` o `SecOps_Executive_Report_<data>.pdf`, strutturato a quattro colonne con layout responsive, tabelle autowrap e statistiche dei KPI in evidenza.

---

## Licenza
Questo progetto è rilasciato sotto licenza MIT. Consulta il file `LICENSE` per ulteriori dettagli.
