import os
import re
import csv
import gzip
import json
import time
import getpass
import requests
from datetime import datetime, timedelta, timezone
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# --- CONFIGURAZIONI INFRASTRUTTURA ---
WAZUH_INDEXER_URL = "https://INSERIRE IP DEL TUO SERVER WAZUH:9200"
ZABBIX_API_URL = "http://INSERIRE IP DEL TUO SERVER ZABBIX:PORTA SERVER ZABBIX/api_jsonrpc.php"
ZABBIX_API_TOKEN = "INSERISCI IL TOKEN API DEL TUO SERVER ZABBIX"

requests.packages.urllib3.disable_warnings()

# --- PRIORITIZZAZIONE (EPSS + CISA KEV + CVSS + esposizione del software) ---
# Tutte fonti pubbliche e gratuite, nessuna chiave API. Verso internet partono SOLO identificativi CVE.
PRIORITY_ENABLED = True
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 80            # CVE per richiesta (il limite dell'API e' 2000 caratteri nel parametro cve)
EPSS_FILE = os.environ.get("EPSS_FILE", "")   # ripiego offline: epss_scores-current.csv(.gz) scaricato da FIRST
EPSS_SATURATION = 0.20          # un EPSS >= 20% conta come "massimo" (i valori EPSS sono molto sbilanciati verso 0)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = os.environ.get("KEV_CACHE_FILE", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "kev_cache.json"))   # copia locale, riscaricata ogni 24 ore
KEV_MAX_AGE_HOURS = 24
KEV_FLOOR = 0.90                # una CVE presente nel KEV non scende mai sotto questa priorita' (=> sempre P1)
NETWORK_TIMEOUT = 20            # secondi. Se serve un proxy, imposta HTTPS_PROXY nell'ambiente.

# Pesi della formula (somma = 1).
PRIORITY_WEIGHTS = {"epss": 0.40, "cvss": 0.30, "exposure": 0.30}
EPSS_MISSING_DEFAULT = 0.25   # valore (0-1) usato se una CVE non ha ancora un EPSS (tipico delle CVE appena pubblicate)
PRIORITY_THRESHOLDS = [(0.75, "P1"), (0.55, "P2"), (0.35, "P3"), (0.0, "P4")]   # da tarare sui vostri dati

# Quanto e' esposto il software a input non fidato o alla rete (0 = poco, 1 = molto).
# La prima regola che corrisponde vince; le parole sono cercate come parole intere, in minuscolo.
EXPOSURE_RULES = [
    (0.30, ["notepad++", "visual studio", "vs code", "git", "python", "node.js"]),          # strumenti locali di sviluppo
    (1.00, ["windows", "ultravnc", "vnc", "postgresql", "openssh", "apache", "nginx", "iis",
            "mysql", "mariadb", "sql server", "teamviewer", "anydesk"]),                       # OS e servizi di rete
    (0.80, ["foxit", "acrobat", "adobe", "winrar", "7-zip", "7zip", "vlc", "chrome", "firefox",
            "edge", "outlook", "office", "word", "excel", "java"]),                            # aprono file/contenuti esterni
    (0.70, ["wireshark"]),                                                                     # analizza traffico di rete
    (0.50, ["putty", "mobaxterm", "filezilla", "winscp"]),                                     # client verso server
]
DEFAULT_EXPOSURE = 0.50         # software non riconosciuto
# Moltiplicatore per la criticita' dell'asset (chiave = nome agent in minuscolo), es. {"srv-erp": 1.3, "pc_ced": 1.0}
ASSET_WEIGHT = {}

# --- PAGINAZIONE (nessun limite di 10.000 record) ---
PAGE_SIZE = 5000                # documenti per singola richiesta (max consigliato: 10000)
MAX_INVENTORY_RECORDS = None    # None = legge TUTTE le CVE dell'inventario; oppure un numero massimo
MAX_HISTORICAL_ALERTS = None    # None = legge TUTTI gli alert storici; oppure un numero massimo (es. 5000)

COLOR_MAP = {
    5: colors.HexColor('#E53E3E'),  # Rosso (Critical / Disaster)
    4: colors.HexColor('#ED8936'),  # Arancio (High)
    3: colors.HexColor('#D69E2E'),  # Giallo scuro (Medium / Average)
    2: colors.HexColor('#3182CE'),  # Blu (Low / Warning)
    1: colors.HexColor('#38A169'),  # Verde (Information)
    0: colors.HexColor('#4A5568')   # Grigio (Default)
}

def parse_wazuh_timestamp(raw):
    """Converte i timestamp Wazuh/OpenSearch (ISO 8601 con 'Z', offset '+0000' o '+00:00',
    con o senza millisecondi) in un datetime naive espresso in ora locale.
    Ritorna None se il valore manca o non e' interpretabile (MAI la data odierna)."""
    if not raw:
        return None
    s = str(raw).strip().replace("Z", "+00:00")
    s = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', s) if re.search(r'T.*[+-]\d{4}$', s) else s
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().replace(tzinfo=None)


def get_detection_timestamp(src):
    """Data reale di rilevamento di una CVE nell'indice di stato di Wazuh.
    Ordine: vulnerability.detected_at -> vulnerability.scanned_date -> @timestamp."""
    vuln = src.get('vulnerability', {}) or {}
    return vuln.get('detected_at') or vuln.get('scanned_date') or src.get('@timestamp') or ""


def paginated_search(url, username, password, query, page_size=PAGE_SIZE, max_docs=None, scroll="2m"):
    """Legge TUTTI i risultati di una query OpenSearch tramite la Scroll API,.
    Lo scroll lavora su uno snapshot coerente dell'indice, quindi
    non perde ne' duplica documenti.
    'url' deve terminare con /_search. Solleva eccezione in caso di errore HTTP."""
    headers = {"Content-Type": "application/json"}
    # L'endpoint di scroll e' SEMPRE alla radice dell'indexer (host:porta/_search/scroll),
    # mai sotto il path dell'indice (con wildcard darebbe 400 Bad Request).
    base_url = WAZUH_INDEXER_URL.rstrip("/")
    auth = (username, password)
    body = dict(query)
    body["size"] = page_size if not max_docs else min(page_size, max_docs)

    results = []
    scroll_id = None
    try:
        r = requests.post(f"{url}?scroll={scroll}", headers=headers, auth=auth, json=body, verify=False)
        r.raise_for_status()
        data = r.json()
        while True:
            scroll_id = data.get("_scroll_id", scroll_id)
            hits = data.get("hits", {}).get("hits", [])
            if not hits:
                break
            results.extend(hits)
            if max_docs and len(results) >= max_docs:
                results = results[:max_docs]
                break
            r = requests.post(f"{base_url}/_search/scroll", headers=headers, auth=auth,
                              json={"scroll": scroll, "scroll_id": scroll_id}, verify=False)
            r.raise_for_status()
            data = r.json()
    finally:
        # Libera il contesto di scroll sul server
        if scroll_id:
            try:
                requests.delete(f"{base_url}/_search/scroll", headers=headers, auth=auth,
                                json={"scroll_id": scroll_id}, verify=False)
            except Exception:
                pass
    return results


def fetch_wazuh_alerts(username, password, target_host=None, days_duration=30,
                       min_level_num=10):
    """Versione Diagnostica Avanzata per identificare il blocco delle CVE in OpenSearch."""
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(days=days_duration)
    date_gte = start_dt.strftime("%Y-%m-%dT00:00:00Z")
    date_lte = end_dt.strftime("%Y-%m-%dT23:59:59Z")

    headers = {"Content-Type": "application/json"}
    all_combined_alerts = []

    # Determiniamo le severità accettate
    allowed_severities = ["Critical", "critical", "CRITICAL", "High", "high", "HIGH"]
    if min_level_num <= 7:
        allowed_severities.extend(["Medium", "medium", "MEDIUM"])
    if min_level_num <= 3:
        allowed_severities.extend(["Low", "low", "LOW"])

    # --- DIAGNOSTICA STEP 1: VERIFICA INVENTARIO STATO ---
    print("\n--- [DIAGNOSTICA] TEST INVENTARIO VULNERABILITÀ ---")
    state_url = f"{WAZUH_INDEXER_URL}/wazuh-states-vulnerabilities-*/_search"

    # Query super semplificata (senza filtri stringenti) per vedere se l'indice risponde
    test_query = {
        "query": {
            "bool": {
                "must": [
                    {"match_all": {}}
                ]
            }
        }
    }
    if target_host:
        test_query["query"]["bool"]["must"] = [{"match_phrase": {"agent.name": target_host}}]

    try:
        hits = paginated_search(state_url, username, password, test_query, max_docs=MAX_INVENTORY_RECORDS)
        print(f"[+] Record totali letti dall'inventario per questo host: {len(hits)}")

        if hits:
            print("[*] Esempio struttura primo record trovato nell'inventario:")
            print(str(hits[0]['_source'])[:500] + "...")  # Stampa i primi 500 caratteri del mapping reale

            # Avviamo il parsing reale se ci sono dati
            n_con_data = 0
            for hit in hits:
                src = hit.get('_source', {})
                vuln = src.get('vulnerability', {})
                agent = src.get('agent', {})
                pkg = src.get('package', {}) or {}
                sev = vuln.get('severity', '')

                # Filtro manuale lato Python per essere sicuri al 100% che OpenSearch non scarti nulla
                if sev in allowed_severities or not allowed_severities:
                    # FIX DATA: data reale di rilevamento dall'inventario (nessun fallback a "adesso")
                    detected_ts = get_detection_timestamp(src)
                    if detected_ts:
                        n_con_data += 1
                    pkg_name = pkg.get('name') or vuln.get('package_name') or 'Componente Software'
                    cve_id = vuln.get('id', 'N/A')
                    transformed = {
                        "timestamp": detected_ts,
                        "agent": {"id": agent.get('id', 'N/D'), "name": agent.get('name', 'Unknown')},
                        "rule": {
                            "id": "vulnerability",
                            "level": min_level_num,
                            # Niente "affects": cosi' il PDF usa il nome pacchetto reale dai dati
                            "description": f"Il sistema presenta una vulnerabilità di sicurezza tracciata come {cve_id}"
                        },
                        "data": {
                            "vulnerability": {
                                "cve": cve_id,
                                "severity": vuln.get('severity', 'High'),
                                "package_name": pkg_name,
                                "package": {"name": pkg_name},
                                # CVSS base score, usato dalla prioritizzazione
                                "score_base": (vuln.get('score') or {}).get('base')
                            }
                        }
                    }
                    all_combined_alerts.append(transformed)
            print(f"[*] Record con data di rilevamento reale: {n_con_data}/{len(all_combined_alerts)} "
                  f"(campo usato: vulnerability.detected_at, poi @timestamp)")
        else:
            print(
                "[-] L'indice ha risposto ma l'array 'hits' è completamente VUOTO. Non ci sono CVE attive registrate su questo host.")
    except Exception as e:
        print(f"[-] Errore critico di connessione all'indice di stato: {e}")

    # --- STEP 2: REUPERO ALERT STORICI (Il record che vedi sempre) ---
    print("\n--- [DIAGNOSTICA] RECOPERO ALERT STORICI ---")
    alerts_url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"
    alerts_must = [
        {"range": {"timestamp": {"gte": date_gte, "lte": date_lte}}},
        {"range": {"rule.level": {"gte": min_level_num, "lte": 16}}}
    ]
    if target_host:
        alerts_must.append({"match_phrase": {"agent.name": target_host}})

    try:
        alerts_hits = paginated_search(alerts_url, username, password,
                                       {"query": {"bool": {"must": alerts_must}}},
                                       max_docs=MAX_HISTORICAL_ALERTS)
        print(f"[+] Trovati {len(alerts_hits)} alert storici nel range temporale.")
        for hit in alerts_hits:
            all_combined_alerts.append(hit.get('_source', {}))
    except Exception as e:
        print(f"[-] Errore recupero storici: {e}")

    return all_combined_alerts

def fetch_zabbix_problems(target_host=None, days_duration=30, min_prio_zabbix=4):
    """Estrae solo i trigger attivi a partire dalla priorità minima scelta fino a quella massima."""
    headers = {"Content-Type": "application/json-rpc"}

    end_dt = datetime.now()
    start_dt = end_dt - timedelta(days=days_duration)
    time_from = int(start_dt.timestamp())
    time_till = int(end_dt.timestamp())
    print(f"[*] Interrogazione Zabbix (A RITROSO): mostro allarmi attivi nati dal {start_dt.strftime('%d/%m/%Y')} al {end_dt.strftime('%d/%m/%Y')}...")

    trigger_data = {
        "jsonrpc": "2.0",
        "method": "trigger.get",
        "params": {
            "output": ["triggerid", "description", "priority", "lastchange"],
            "filter": {"value": 1, "status": 0},
            "selectHosts": ["hostid", "host", "name"],
            "monitored": True,
            "skipDependent": True
        },
        "auth": ZABBIX_API_TOKEN,
        "id": 1
    }

    try:
        response = requests.post(ZABBIX_API_URL, json=trigger_data, headers=headers, verify=False)
        response.raise_for_status()
        all_triggers = response.json().get('result', [])

        filtered_problems = []
        for tri in all_triggers:
            prio = int(tri.get('priority', 0))
            lastchange = int(tri.get('lastchange', 0))

            if prio >= min_prio_zabbix and time_from <= lastchange <= time_till:
                filtered_problems.append(tri)

        if target_host:
            target_clean = target_host.strip().lower()
            host_filtered = []
            for item in filtered_problems:
                hosts_list = item.get('hosts', [])
                # FIX CRITICO: Estrazione sicura dalla lista di dizionari fornita da Zabbix
                if hosts_list and isinstance(hosts_list, list) and len(hosts_list) > 0:
                    first_host = hosts_list[0]
                    h_name = first_host.get('name', '').lower()
                    h_tech = first_host.get('host', '').lower()
                    if target_clean in h_name or target_clean in h_tech:
                        host_filtered.append(item)
            return host_filtered

        return filtered_problems
    except Exception as e:
        print(f"[-] Errore durante l'estrazione da Zabbix: {e}")
        return []


def fetch_current_active_cves(username, password, cve_codes, target_host=None):
    """
    Verifica, tra le CVE indicate, quali sono ANCORA presenti nello stato
    attuale dell'inventario vulnerabilità, estraendo dinamicamente il nome del software reale affetto.
    """
    cve_codes = {c.strip().upper() for c in cve_codes if c and c != "N/A"}
    if not cve_codes:
        return set()

    url = f"{WAZUH_INDEXER_URL}/wazuh-states-vulnerabilities-*/_search"
    headers = {"Content-Type": "application/json"}

    must_clauses = [{"terms": {"vulnerability.id": list(cve_codes)}}]
    if target_host:
        must_clauses.append({"match_phrase": {"agent.name": target_host}})

    query_body = {
        # AGGIORNATO: Chiediamo esplicitamente a OpenSearch di restituire i campi reali del pacchetto software
        "_source": ["agent.name", "vulnerability.id", "package.name", "vulnerability.package_name"],
        "query": {"bool": {"must": must_clauses}},
    }

    active = set()
    try:
        hits = paginated_search(url, username, password, query_body, max_docs=MAX_INVENTORY_RECORDS)
        for h in hits:
            src = h.get("_source", {})
            agent_name = src.get("agent", {}).get("name", "").strip().lower()
            vuln_info = src.get("vulnerability", {})
            cve_id = vuln_info.get("id", "").strip().upper()

            # ESTRAZIONE DINAMICA COMPONENTE: prendiamo il nome reale (es. Python, Apache, Windows...)
            pkg_info = src.get("package", {})
            pkg_name = pkg_info.get("name") or vuln_info.get("package_name") or "Componente Software"

            if agent_name and cve_id:
                # Salviamo nella tupla a 3 elementi: (host, cve, componente_reale)
                active.add((agent_name, cve_id, pkg_name))
        print(
            f"[*] Verifica stato corrente: {len(cve_codes)} CVE uniche controllate, "
            f"{len(active)} coppie host/CVE risultano ancora attive oggi con i rispettivi pacchetti software."
        )
    except Exception as e:
        print(f"[-] Errore durante la verifica dello stato corrente delle vulnerabilita': {e}")

    return active

# ===================== PRIORITIZZAZIONE: EPSS + KEV + CVSS + ESPOSIZIONE =====================
_SEVERITY_TO_CVSS_NORM = {"critical": 0.95, "high": 0.75, "medium": 0.50, "low": 0.25}


def _load_epss_file(path, wanted):
    """Ripiego offline: legge il file CSV(.gz) giornaliero di FIRST (righe '#...' di intestazione ignorate)."""
    scores = {}
    try:
        opener = gzip.open if path.lower().endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as f:
            for row in csv.DictReader(line for line in f if not line.startswith("#")):
                cve = (row.get("cve") or "").strip().upper()
                if cve in wanted:
                    scores[cve] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
        print(f"[*] EPSS letto dal file locale: {len(scores)} CVE trovate.")
    except Exception as e:
        print(f"[-] Impossibile leggere il file EPSS '{path}': {e}")
    return scores


def fetch_epss(cve_ids):
    """Restituisce {CVE: {'epss': p, 'percentile': q}} interrogando l'API pubblica di FIRST a blocchi.
    Se l'API non e' raggiungibile e EPSS_FILE e' impostato, ripiega sul file locale."""
    ids = sorted({c.strip().upper() for c in cve_ids if c})
    scores = {}
    try:
        for i in range(0, len(ids), EPSS_BATCH_SIZE):
            batch = ",".join(ids[i:i + EPSS_BATCH_SIZE])
            offset = 0
            while True:
                r = requests.get(f"{EPSS_API_URL}?cve={batch}&offset={offset}", timeout=NETWORK_TIMEOUT)
                r.raise_for_status()
                payload = r.json()
                data = payload.get("data", [])
                for d in data:
                    scores[d["cve"].strip().upper()] = {"epss": float(d["epss"]),
                                                        "percentile": float(d["percentile"])}
                offset += len(data)
                if not data or offset >= int(payload.get("total", len(data))):
                    break
        print(f"[+] EPSS ricevuto da FIRST per {len(scores)} CVE su {len(ids)} richieste.")
    except Exception as e:
        print(f"[-] API EPSS non raggiungibile ({e}).")
        if EPSS_FILE:
            scores.update(_load_epss_file(EPSS_FILE, set(ids)))
    return scores


def load_kev():
    """Insieme delle CVE sfruttate attivamente (catalogo CISA KEV). Usa una copia locale rinnovata ogni
    KEV_MAX_AGE_HOURS ore; se il download fallisce ripiega sull'ultima copia disponibile."""
    data = None
    fresh = (os.path.exists(KEV_CACHE_FILE)
             and (time.time() - os.path.getmtime(KEV_CACHE_FILE)) / 3600.0 < KEV_MAX_AGE_HOURS)
    if not fresh:
        try:
            r = requests.get(KEV_URL, timeout=NETWORK_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            try:
                with open(KEV_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            except Exception as e:
                print(f"[*] Copia locale del KEV non salvata ({e}): uso i dati scaricati.")
            print("[*] Catalogo KEV scaricato dal sito CISA.")
        except Exception as e:
            print(f"[-] Download del KEV non riuscito ({e}).")
    if data is None:
        try:
            with open(KEV_CACHE_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            print("[-] Nessun catalogo KEV disponibile: la regola 'sfruttata attivamente' non sara' applicata.")
            return set()
    kev = {v["cveID"].strip().upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    print(f"[*] Catalogo KEV: {len(kev)} CVE sfruttate attivamente.")
    return kev


def _cvss_norm(vul):
    """CVSS base score (0-10) normalizzato a 0-1; se assente, ripiega sulla severita' testuale."""
    try:
        return max(0.0, min(1.0, float(vul.get("score_base")) / 10.0))
    except (TypeError, ValueError):
        return _SEVERITY_TO_CVSS_NORM.get(str(vul.get("severity", "")).lower(), 0.5)


def _exposure_norm(package_name):
    name = str(package_name or "").lower()
    for value, keywords in EXPOSURE_RULES:
        for kw in keywords:
            if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", name):
                return value
    return DEFAULT_EXPOSURE


def _priority_label(p):
    for threshold, label in PRIORITY_THRESHOLDS:
        if p >= threshold:
            return label
    return PRIORITY_THRESHOLDS[-1][1]


def compute_priority(rec, epss_map, kev):
    """Calcola la priorita' (0-1) di un record CVE e la salva in rec['priority']."""
    vul = rec["data"]["vulnerability"]
    cve = str(vul.get("cve", "")).strip().upper()
    epss = epss_map.get(cve)

    components = {
        "cvss": _cvss_norm(vul),
        "exposure": _exposure_norm(vul.get("package_name")),
        # Senza EPSS non si assume ne' "sicura" ne' "sfruttata": valore prudente intermedio
        "epss": min(1.0, epss["epss"] / EPSS_SATURATION) if epss else EPSS_MISSING_DEFAULT,
    }
    p = sum(PRIORITY_WEIGHTS[k] * v for k, v in components.items())

    agent_key = str(rec.get("agent", {}).get("name", "")).strip().lower()
    p = min(1.0, p * ASSET_WEIGHT.get(agent_key, 1.0))

    in_kev = cve in kev
    if in_kev:
        p = max(p, KEV_FLOOR)
    rec["priority"] = {"score": int(round(p * 100)), "label": _priority_label(p), "kev": in_kev,
                       "epss": epss["epss"] if epss else None}


def enrich_with_priority(alerts):
    """Aggiunge a ogni record CVE la chiave 'priority'. Ogni fallimento di rete e' gestito: al peggio
    il report resta ordinato per data come prima."""
    if not PRIORITY_ENABLED:
        return 0
    records = [a for a in alerts if a.get("rule", {}).get("id") == "vulnerability"
               and a.get("data", {}).get("vulnerability", {}).get("cve") not in (None, "N/A")]
    if not records:
        return 0
    cves = {str(r["data"]["vulnerability"]["cve"]).strip().upper() for r in records}
    print(f"[*] Prioritizzazione di {len(cves)} CVE uniche (EPSS + KEV + CVSS + esposizione)...")
    epss_map = fetch_epss(cves)
    kev = load_kev()
    for rec in records:
        compute_priority(rec, epss_map, kev)
    n_kev = sum(1 for r in records if r["priority"]["kev"])
    n_p1 = sum(1 for r in records if r["priority"]["label"] == "P1")
    print(f"[+] Prioritizzazione completata: {n_p1} in P1, di cui {n_kev} nel catalogo KEV; "
          f"EPSS disponibile per {sum(1 for r in records if r['priority']['epss'] is not None)}/{len(records)} record.")
    return len(records)


def get_severity_weight(platform, level_str):
    """Assegna un peso numerico alla gravità per permettere l'ordinamento decrescente."""
    lvl = level_str.upper().strip()
    if platform == 'zabbix':
        if "DISASTER" in lvl: return 5
        if "HIGH" in lvl: return 4
        if "AVERAGE" in lvl or "MEDIUM" in lvl: return 3
        if "WARNING" in lvl: return 2
        if "INFORMATION" in lvl: return 1
    else:  # wazuh
        if "CRITICAL" in lvl: return 5
        if "HIGH" in lvl: return 4
        if "MEDIUM" in lvl: return 3
        if "LOW" in lvl: return 2
        if "INFORMATION" in lvl or "INFO" in lvl: return 1
        if lvl.isdigit():
            val = int(lvl)
            if val >= 15: return 5
            if val >= 11: return 4
            if val >= 7: return 3
            if val >= 3: return 2
            return 1
    return 0

def generate_pdf_report(zabbix_data, wazuh_data, output_pdf, target_host=None, days_back=90,
                            active_cves=None):
        """Genera il PDF SecOps in formato ORIZZONTALE (Landscape) ripristinando le date storiche e i componenti reali."""
        print(f"[*] Generazione del PDF Orizzontale in corso: {output_pdf}...")

        # IMPOSTAZIONE ORIZZONTALE (792 x 612 punti)
        doc = SimpleDocTemplate(output_pdf, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30,
                                bottomMargin=30)
        story = []
        styles = getSampleStyleSheet()

        # --- INIZIALIZZAZIONE DEGLI STILI ---
        title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=22, leading=26,
                                     textColor=colors.HexColor('#1A365D'), spaceAfter=4)
        subtitle_style = ParagraphStyle('DocSubtitle', parent=styles['Normal'], fontSize=10, leading=14,
                                        textColor=colors.HexColor('#718096'), spaceAfter=15)
        h2_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=13, leading=16,
                                  textColor=colors.HexColor('#2C5282'), spaceBefore=12, spaceAfter=6, keepWithNext=True)
        cell_style = ParagraphStyle('TableCell', parent=styles['Normal'], fontSize=9, leading=12)
        bold_cell_style = ParagraphStyle('TableBoldCell', parent=styles['Normal'], fontSize=9, leading=12,
                                         fontName="Helvetica-Bold")

        local_color_map = {
            5: colors.HexColor('#E53E3E'), 4: colors.HexColor('#ED8936'), 3: colors.HexColor('#D69E2E'),
            2: colors.HexColor('#3182CE'), 1: colors.HexColor('#38A169'), 0: colors.HexColor('#4A5568')
        }

        if active_cves is None:
            active_cves = set()

        current_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        report_scope = f"Host: '{target_host}'" if target_host else "Infrastruttura Completa"

        story.append(Paragraph("SecOps Automated Correlation Report", title_style))
        story.append(Paragraph(f"Generato il: {current_date} | Ambito: {report_scope}", subtitle_style))
        story.append(Spacer(1, 5))

        # --- 1. PROCESSO E DEDUPLICAZIONE DATI WAZUH ORIGINALI ---
        wz_rows = []
        wz_visti = set()

        if wazuh_data:
            for item in wazuh_data:
                agent_name = item.get('agent', {}).get('name', 'Unknown')
                vul_info = item.get('data', {}).get('vulnerability', {})
                vun_desc = item.get('rule', {}).get('description', 'N/A')

                # Recupero della data storica originale dell'allarme (senza fallback forzati)
                raw_timestamp = item.get('timestamp', '')
                dt_obj = parse_wazuh_timestamp(raw_timestamp)
                ts_formatted = dt_obj.strftime("%d/%m/%Y %H:%M") if dt_obj else "N/D"

                if vul_info:
                    cve_code = vul_info.get('cve') or vul_info.get('id') or 'N/A'
                    severity = vul_info.get('severity', 'High')
                    level = str(severity).capitalize()
                    status = "Non Risolto"

                    # ESTRAZIONE DINAMICA NATURALE: Estrae il nome dell'applicazione dalla descrizione (es. Python, Windows)
                    if "affects" in vun_desc.lower():
                        pkg_name = vun_desc.lower().split("affects")[-1].strip().capitalize()
                        # Ripristina il case corretto per i software comuni conosciuti
                        if "python" in pkg_name.lower():
                            pkg_name = "Python 3.13.7 (64-bit)"
                        elif "windows" in pkg_name.lower():
                            pkg_name = "Microsoft Windows 10 Pro"
                        elif "pip" in pkg_name.lower():
                            pkg_name = "Pip Package Manager"
                    else:
                        pkg_name = vul_info.get('package_name') or vul_info.get('package', {}).get(
                            'name') or "Componente Software"
                else:
                    cve_code = "N/A"
                    pkg_name = "Sistema / Regola"
                    status = "N/D"
                    r_lvl = item.get('rule', {}).get('level', 0)
                    if int(r_lvl) >= 15:
                        level = "Critical"
                    elif int(r_lvl) >= 11:
                        level = "High"
                    elif int(r_lvl) >= 7:
                        level = "Medium"
                    elif int(r_lvl) >= 3:
                        level = "Low"
                    else:
                        level = "Information"

                weight = get_severity_weight('wazuh', level)

                # Chiave di deduplicazione per evitare sdoppiamenti
                chiave_univoca = f"{cve_code}_{agent_name}_{pkg_name}_{ts_formatted}"

                if chiave_univoca not in wz_visti:
                    wz_visti.add(chiave_univoca)
                    wz_rows.append({
                        "weight": weight, "dt": dt_obj if dt_obj else datetime.min, "ts": ts_formatted,
                        "agent": agent_name, "cve": cve_code, "package": pkg_name, "desc": vun_desc,
                        "level": level, "status": status,
                        "prio": (item.get('priority') or {}).get('score'),
                        "prio_label": (item.get('priority') or {}).get('label'),
                        "prio_epss": (item.get('priority') or {}).get('epss'),
                        "prio_kev": (item.get('priority') or {}).get('kev', False)
                    })

        # --- 2. PROCESSO DATI ZABBIX ---
        zb_rows = []
        if zabbix_data:
            for item in zabbix_data:
                hosts_list = item.get('hosts', [])
                host_name = hosts_list[0].get('name', 'Unknown') if (
                        hosts_list and isinstance(hosts_list, list) and len(hosts_list) > 0) else 'Unknown'
                desc = item.get('description', 'N/A')
                prio_num = int(item.get('priority', 0))

                prio_str = "Disaster" if prio_num == 5 else "High" if prio_num == 4 else "Medium" if prio_num == 3 else "Warning" if prio_num == 2 else "Information"
                weight = get_severity_weight('zabbix', prio_str)

                lastchange = item.get('lastchange', '')
                if lastchange and str(lastchange).isdigit():
                    dt_obj = datetime.fromtimestamp(int(lastchange))
                    ts_formatted = dt_obj.strftime("%d/%m/%Y %H:%M")
                else:
                    ts_formatted = "N/A"
                    dt_obj = datetime.min

                zb_rows.append({
                    "weight": weight, "dt": dt_obj, "ts": ts_formatted,
                    "host": host_name, "desc": desc, "prio": prio_str
                })

        # --- 3. CALCOLO DELLE STATISTICHE REALI SUI DATI FILTRATI ---
        stats = {"Critical/Disaster": 0, "High": 0, "Medium/Average": 0, "Low/Warning": 0, "Information": 0}
        for r in zb_rows:
            if r["weight"] == 5: stats["Critical/Disaster"] += 1
            elif r["weight"] == 4: stats["High"] += 1
            elif r["weight"] == 3: stats["Medium/Average"] += 1
            elif r["weight"] == 2: stats["Low/Warning"] += 1
            else: stats["Information"] += 1
        for r in wz_rows:
            if r["weight"] == 5: stats["Critical/Disaster"] += 1
            elif r["weight"] == 4: stats["High"] += 1
            elif r["weight"] == 3: stats["Medium/Average"] += 1
            elif r["weight"] == 2: stats["Low/Warning"] += 1
            else: stats["Information"] += 1

        # --- 4. GENERAZIONE PANNELLO EXECUTIVE SUMMARY (732 punti totali) ---
        story.append(Paragraph("📊 Executive Summary & Baseline Info", h2_style))
        summary_data = [
            [Paragraph("Data di Riferimento:", bold_cell_style), Paragraph("Oggi (Tempo Reale)", cell_style),
             Paragraph('<font color="#E53E3E"><b>Critical / Disaster:</b></font>', cell_style),
             Paragraph(f'<b>{stats["Critical/Disaster"]}</b>', cell_style)],
            [Paragraph("Finestra di Analisi:", bold_cell_style),
             Paragraph(f"{days_back} Giorni (A ritroso)", cell_style),
             Paragraph('<font color="#ED8936"><b>High Severity:</b></font>', cell_style),
             Paragraph(f'<b>{stats["High"]}</b>', cell_style)],
            [Paragraph("Ambito Monitoraggio:", bold_cell_style), Paragraph(report_scope, cell_style),
             Paragraph('<font color="#D69E2E"><b>Medium / Average:</b></font>', cell_style),
             Paragraph(f'<b>{stats["Medium/Average"]}</b>', cell_style)],
            [Paragraph("", cell_style), Paragraph("", cell_style),
             Paragraph('<font color="#3182CE"><b>Low / Warning:</b></font>', cell_style),
             Paragraph(f'<b>{stats["Low/Warning"]}</b>', cell_style)],
            [Paragraph("", cell_style), Paragraph("", cell_style),
             Paragraph('<font color="#38A169"><b>Information:</b></font>', cell_style),
             Paragraph(f'<b>{stats["Information"]}</b>', cell_style)]
        ]

        summary_table = Table(summary_data, colWidths=[130, 170, 170, 262])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('INNERGRID', (0, 0), (1, -1), 0.5, colors.HexColor('#EDF2F7')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 10))

        # --- 5. IMPAGINAZIONE TABELLA ZABBIX ---
        story.append(Paragraph("🚨 Criticità Infrastrutturali Attive (Zabbix)", h2_style))
        if zb_rows:
            zb_rows.sort(key=lambda x: (x['weight'], x['dt']), reverse=True)
            zb_table_data = [["Data/Ora Rilev.", "Host / Apparato", "Descrizione Trigger / Alert", "Priorità"]]
            for row in zb_rows:
                p_weight = row["weight"]
                prio_text = row["prio"]
                prio_style = ParagraphStyle(f'ZBPrio_{prio_text}_{p_weight}', parent=cell_style,
                                            textColor=local_color_map.get(p_weight, colors.black),
                                            fontName="Helvetica-Bold")
                zb_table_data.append([Paragraph(str(row["ts"]), cell_style), Paragraph(str(row["host"]), cell_style),
                                      Paragraph(str(row["desc"]), cell_style), Paragraph(str(prio_text), prio_style)])

            zb_table = Table(zb_table_data, colWidths=[100, 120, 432, 80])
            zb_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F7FAFC')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(zb_table)
        else:
            story.append(Paragraph("Nessun problema critical attivo trovato per questo filtro.", cell_style))

        story.append(Spacer(1, 15))

        # --- 6. IMPAGINAZIONE TABELLA WAZUH (7 colonne con "Componente" e layout orizzontale) ---
        story.append(Paragraph("⚠️ Vulnerabilità Software Rilevate (Wazuh)", h2_style))
        if wz_rows:
            # A parita' di livello (Critical/High/...) prima la priorita' piu' alta, poi la data piu' recente
            wz_rows.sort(key=lambda x: (x['weight'], x['prio'] if x['prio'] is not None else -1, x['dt']),
                         reverse=True)
            has_prio = any(r['prio'] is not None for r in wz_rows)
            prio_color = {'P1': local_color_map[5], 'P2': local_color_map[4],
                          'P3': local_color_map[3], 'P4': local_color_map[2]}
            wz_table_data = [
                ["Data/Ora Rilev.", "Agent / PC", "CVE / Id", "Componente", "Descrizione Vulnerabilità", "Livello/Sev",
                 "Stato"] + (["Priorità"] if has_prio else [])]

            status_color_map = {"Risolto": colors.HexColor('#38A169'), "Non Risolto": colors.HexColor('#E53E3E'),
                                "N/D": colors.HexColor('#718096')}

            for row in wz_rows:
                w_weight = row["weight"]
                lvl_text = row["level"]
                status_text = row.get("status", "N/D")

                wz_lvl_style = ParagraphStyle(f'WzLvl_{lvl_text}_{w_weight}', parent=cell_style,
                                              textColor=local_color_map.get(w_weight, colors.black),
                                              fontName="Helvetica-Bold")
                wz_status_style = ParagraphStyle(f'WzStatus_{status_text}', parent=cell_style,
                                                 textColor=status_color_map.get(status_text, colors.black),
                                                 fontName="Helvetica-Bold")

                wz_table_data.append([
                    Paragraph(str(row["ts"]), cell_style), Paragraph(str(row["agent"]), cell_style),
                    Paragraph(str(row["cve"]), cell_style), Paragraph(str(row["package"]), cell_style),
                    Paragraph(str(row["desc"]), cell_style), Paragraph(str(lvl_text), wz_lvl_style),
                    Paragraph(str(status_text), wz_status_style)
                ] + ([Paragraph(
                    (f'{row["prio_label"]} · {row["prio"]}' + (" KEV" if row["prio_kev"] else "") +
                     (f'<br/><font size="7" color="#4A5568">EPSS {row["prio_epss"] * 100:.1f}%</font>'
                      if row["prio_epss"] is not None else
                      '<br/><font size="7" color="#4A5568">EPSS n/d</font>')) if row["prio"] is not None else "—",
                    ParagraphStyle(f'WzPrio_{row["prio_label"]}', parent=cell_style,
                                   textColor=prio_color.get(row["prio_label"], colors.HexColor('#718096')),
                                   fontName="Helvetica-Bold"))] if has_prio else []))

            # Ripartizione esatta delle larghezze per occupare i 732 punti utili di stampa
            wz_table = Table(wz_table_data, colWidths=[80, 70, 80, 110, 172, 60, 70, 90] if has_prio else [85, 85, 85, 120, 202, 75, 80])
            wz_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EDF2F7')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F7FAFC')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(wz_table)
            if has_prio:
                story.append(Spacer(1, 6))
                story.append(Paragraph(
                    "<b>Priorità (P1 massima – P4 minima, punteggio 0-100):</b> a parità di livello le vulnerabilità sono "
                    "ordinate dalla più alla meno urgente. Combina la probabilità di sfruttamento (<b>EPSS</b>, FIRST), la "
                    "gravità (CVSS) e l'esposizione del software. <b>KEV</b> = presente nel catalogo CISA delle "
                    "vulnerabilità sfruttate attivamente: sempre P1. EPSS n/d = non ancora disponibile (trattato come valore prudente). "
                    "La priorità è un supporto alla decisione, non la sostituisce.",
                    cell_style))
        else:
            story.append(Paragraph("Nessuna vulnerabilità rilevata per questo filtro.", cell_style))

        doc.build(story)
        print(f"[+] Pipeline completata con successo! PDF '{output_pdf}' creato.")


def main():
    print("=== AVVIO PIPELINE SECOPS AUTOMATIZZATA ===")

    print("[ Configurazione Finestra Temporale Retrospettiva ]")
    try:
        duration_input = input("Inserisci quanti giorni analizzare A RITROSO da oggi [INVIO per 30]: ").strip()
        days_duration = int(duration_input) if duration_input else 30
    except ValueError:
        print("[*] Input non valido. Uso default: 30 giorni.")
        days_duration = 30

    print("\n[ Seleziona il livello minimo di severità ]")
    print(" 1 - Information | 2 - Low | 3 - Medium | 4 - High [CONSIGLIATO] | 5 - Critical")
    choice = input("Inserisci il numero (1-5) [INVIO per 4]: ").strip()

    if choice == "1":
        min_prio_zabbix, min_wazuh_lvl = 1, 1
    elif choice == "2":
        min_prio_zabbix, min_wazuh_lvl = 2, 3
    elif choice == "3":
        min_prio_zabbix, min_wazuh_lvl = 3, 7
    elif choice == "5":
        min_prio_zabbix, min_wazuh_lvl = 5, 15
    else:
        min_prio_zabbix, min_wazuh_lvl = 4, 11

    print("\n" + "-" * 40)
    target_host = input("Inserisci il nome dell'host [INVIO per globale]: ").strip()
    if target_host == "":
        target_host = None

    wazuh_user = input("Inserisci l'username di Wazuh Indexer: ")
    try:
        wazuh_pass = getpass.getpass("Inserisci la password di Wazuh Indexer: ")
    except Exception:
        wazuh_pass = input("Inserisci la password di Wazuh Indexer: ")

    print("\n" + "=" * 40)

    # 1. Estrazione allarmi storici regolari
    zabbix_problems = fetch_zabbix_problems(target_host, days_duration, min_prio_zabbix)
    wazuh_alerts = fetch_wazuh_alerts(wazuh_user, wazuh_pass, target_host, days_duration, min_wazuh_lvl)

    # 2. Raccogliamo l'elenco delle CVE individuate nei log storici
    cve_codes_found = set()
    for item in wazuh_alerts:
        vul_info = item.get('data', {}).get('vulnerability', {})
        if vul_info:
            cve = vul_info.get('cve')
            if cve:
                cve_codes_found.add(cve)

    print(f"[*] {len(cve_codes_found)} CVE univoche rilevate nella finestra storica. Verifico lo stato attuale...")

    # Eseguiamo la funzione aggiornata che estrae le tuple a 3 elementi (host, cve, package)
    active_cves_raw = fetch_current_active_cves(wazuh_user, wazuh_pass, cve_codes_found, target_host)

    # Set (host, cve) ancora attive oggi, usato dal generatore del PDF.
    # NOTA: i record delle CVE attive sono gia' stati creati in fetch_wazuh_alerts con data,
    # componente e severita' reali, quindi NON vanno piu' re-iniettati (causava duplicati con data odierna).
    active_cves_set_for_pdf = {(e[0], e[1]) for e in active_cves_raw}

    # 2b. Prioritizzazione delle CVE (EPSS + KEV + CVSS + esposizione)
    enrich_with_priority(wazuh_alerts)

    # 3. Compilazione del file PDF
    date_suffix = datetime.now().strftime("%Y%m%d")
    if target_host:
        output_filename = f"SecOps_Report_{target_host}_{date_suffix}.pdf"
    else:
        output_filename = f"SecOps_Executive_Report_{date_suffix}.pdf"

    if wazuh_alerts or zabbix_problems or target_host:
        generate_pdf_report(zabbix_problems, wazuh_alerts, output_filename, target_host, days_duration,
                            active_cves_set_for_pdf)
    else:
        print("[-] Pipeline interrotta: nessun dato ricevuto dalle piattaforme.")


if __name__ == "__main__":
    main()