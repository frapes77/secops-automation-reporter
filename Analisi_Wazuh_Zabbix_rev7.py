import os
import getpass
import requests
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# --- CONFIGURAZIONI INFRASTRUTTURA ---
WAZUH_INDEXER_URL = "https://IP DELLA TUA MACCHINA WAZUH:9200"
ZABBIX_API_URL = "http://IP DELLA TUA MACCHINA ZABBIX:PORTA/api_jsonrpc.php"
ZABBIX_API_TOKEN = "INSERISCI L'API TOKEN DELLA TUA MACCHINA ZABBIX"

requests.packages.urllib3.disable_warnings()

COLOR_MAP = {
    5: colors.HexColor('#E53E3E'),  # Rosso (Critical / Disaster)
    4: colors.HexColor('#ED8936'),  # Arancio (High)
    3: colors.HexColor('#D69E2E'),  # Giallo scuro (Medium / Average)
    2: colors.HexColor('#3182CE'),  # Blu (Low / Warning)
    1: colors.HexColor('#38A169'),  # Verde (Information)
    0: colors.HexColor('#4A5568')   # Grigio (Default)
}


def fetch_wazuh_alerts(username, password, target_host=None, days_duration=30,
                       min_level_num=10):
    """Estrae gli alert da Wazuh a ritroso da oggi, applicando il filtro esatto .keyword richiesto dall'indexer."""
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(days=days_duration)
    date_gte = start_dt.strftime("%Y-%m-%dT00:00:00Z")
    date_lte = end_dt.strftime("%Y-%m-%dT23:59:59Z")
    print(
        f"[*] Query Wazuh attiva (A RITROSO): dal {start_dt.strftime('%d/%m/%Y')} al {end_dt.strftime('%d/%m/%Y')}...")

    full_search_url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"
    headers = {"Content-Type": "application/json"}

    # FIX LOGICO CRITICO: usiamo "term" e ".keyword" per forzare OpenSearch a leggere le CVE High/Critical
    vulnerability_should = [
        {"term": {"data.vulnerability.severity.keyword": "Critical"}},
        {"term": {"data.vulnerability.severity.keyword": "Critical"}},
        {"term": {"data.vulnerability.severity.keyword": "High"}},
        {"term": {"data.vulnerability.severity.keyword": "High"}}
    ]

    if min_level_num <= 7:
        vulnerability_should.extend([
            {"term": {"data.vulnerability.severity.keyword": "Medium"}},
            {"term": {"data.vulnerability.severity.keyword": "Medium"}}
        ])
    if min_level_num <= 3:
        vulnerability_should.extend([
            {"term": {"data.vulnerability.severity.keyword": "Low"}},
            {"term": {"data.vulnerability.severity.keyword": "Low"}},
            {"term": {"data.vulnerability.severity.keyword": "Information"}},
            {"term": {"data.vulnerability.severity.keyword": "Information"}}
        ])

    query_body = {
        "size": 10000,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "agent.id", "agent.name", "rule.id", "rule.level", "rule.description",
                    "data.vulnerability"],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": date_gte, "lte": date_lte}}},
                    {
                        "bool": {
                            "should": [
                                # Allarmi basati su regole numeriche
                                {"range": {"rule.level": {"gte": min_level_num, "lte": 16}}},
                                # CVE estratte correttamente tramite mappatura keyword term
                                {"bool": {
                                    "must": [{"bool": {"should": vulnerability_should, "minimum_should_match": 1}}]}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
    }

    try:
        response = requests.post(full_search_url, headers=headers, auth=(username, password), json=query_body,
                                 verify=False)
        response.raise_for_status()
        hits = response.json()['hits']['hits']
        all_alerts = [item['_source'] for item in hits]

        if target_host:
            target_clean = target_host.strip().lower()
            filtered_alerts = []
            for alert in all_alerts:
                agent_name = alert.get('agent', {}).get('name', '').lower()
                if target_clean in agent_name:
                    filtered_alerts.append(alert)
            return filtered_alerts

        return all_alerts
    except Exception as e:
        print(f"[-] Errore durante l'estrazione da Wazuh: {e}")
        return []


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
    attuale dell'inventario vulnerabilita' (wazuh-states-vulnerabilities-*),
    che riflette la situazione reale al momento dell'interrogazione (non lo
    storico degli alert).

    Ritorna un set di tuple (agent_name_lower, cve_code_upper) attualmente
    attive. Se una coppia (agent, CVE) non e' in questo set, significa che
    alla data odierna quella vulnerabilita' su quell'host risulta risolta
    (es. pacchetto aggiornato).
    """
    cve_codes = {c.strip().upper() for c in cve_codes if c and c != "N/A"}
    if not cve_codes:
        return set()

    url = f"{WAZUH_INDEXER_URL}/wazuh-states-vulnerabilities-*/_search"
    headers = {"Content-Type": "application/json"}

    must_clauses = [{"terms": {"vulnerability.id": list(cve_codes)}}]
    if target_host:
        must_clauses.append({"match": {"agent.name": target_host}})

    query_body = {
        "size": 10000,
        "_source": ["agent.name", "vulnerability.id"],
        "query": {"bool": {"must": must_clauses}},
    }

    active = set()
    try:
        response = requests.post(
            url, headers=headers, auth=(username, password), json=query_body, verify=False
        )
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
        for h in hits:
            src = h.get("_source", {})
            agent_name = src.get("agent", {}).get("name", "").strip().lower()
            cve_id = src.get("vulnerability", {}).get("id", "").strip().upper()
            if agent_name and cve_id:
                active.add((agent_name, cve_id))
        print(
            f"[*] Verifica stato corrente: {len(cve_codes)} CVE uniche controllate, "
            f"{len(active)} coppie host/CVE risultano ancora attive oggi."
        )
    except Exception as e:
        print(f"[-] Errore durante la verifica dello stato corrente delle vulnerabilita': {e}")
        print("[-] Le vulnerabilita' verranno marcate come 'Non Risolto' per precauzione.")

    return active


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

        """Genera il PDF SecOps applicando ordinamento combinato (Gravità + Data) e deduplicazione totale."""
        print(f"[*] Generazione del PDF in corso: {output_pdf}...")
        doc = SimpleDocTemplate(output_pdf, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40,
                                bottomMargin=40)
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

        # Mappa dei colori locale blindata
        local_color_map = {
            5: colors.HexColor('#E53E3E'),  # Rosso (Critical / Disaster)
            4: colors.HexColor('#ED8936'),  # Arancio (High)
            3: colors.HexColor('#D69E2E'),  # Giallo scuro (Medium / Average)
            2: colors.HexColor('#3182CE'),  # Blu (Low / Warning)
            1: colors.HexColor('#38A169'),  # Verde (Information)
            0: colors.HexColor('#4A5568')  # Grigio
        }

        if active_cves is None:
            active_cves = set()

        current_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        report_scope = f"Host: '{target_host}'" if target_host else "Infrastruttura Completa"

        story.append(Paragraph("SecOps Automated Correlation Report", title_style))
        story.append(Paragraph(f"Generato il: {current_date} | Ambito: {report_scope}", subtitle_style))
        story.append(Spacer(1, 5))

        # --- 1. PROCESSO E DEDUPLICAZIONE DATI WAZUH ---
        wz_rows = []
        wz_visti = set()  # Set globale di deduplicazione per Wazuh

        if wazuh_data:
            for item in wazuh_data:
                agent_name = item.get('agent', {}).get('name', 'Unknown')
                vul_info = item.get('data', {}).get('vulnerability', {})

                # Formattazione e parsing della data per l'ordinamento nativo
                raw_timestamp = item.get('timestamp', '')
                dt_obj = None
                ts_formatted = "N/A"
                if raw_timestamp:
                    try:
                        ts_clean = raw_timestamp.split('.')[0].replace('Z', '')
                        dt_obj = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
                        ts_formatted = dt_obj.strftime("%d/%m/%Y %H:%M")
                    except Exception:
                        ts_formatted = raw_timestamp[:16].replace('T', ' ')
                        try:
                            dt_obj = datetime.strptime(raw_timestamp[:16], "%Y-%m-%dT%H:%M")
                        except:
                            dt_obj = datetime.min

                if vul_info:
                    cve_code = vul_info.get('cve', 'N/A')
                    severity = vul_info.get('severity', '')
                    pkg_name = vul_info.get('package_name') or vul_info.get('package', {}).get(
                        'name') or 'Software Component'
                    vun_desc = f"{cve_code} affects {pkg_name}"
                    level = str(severity).capitalize() if severity else "High"

                    # Verifica se la CVE risulta ancora attiva OGGI su questo host,
                    # incrociando con lo stato corrente dell'inventario vulnerabilita'
                    key = (agent_name.strip().lower(), str(cve_code).strip().upper())
                    if cve_code and cve_code != 'N/A':
                        status = "Non Risolto" if key in active_cves else "Risolto"
                    else:
                        status = "N/D"
                else:
                    vun_desc = item.get('rule', {}).get('description', 'N/A')
                    cve_code = vun_desc
                    status = "N/D"  # Alert generico (non una CVE), lo stato non e' applicabile
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

                # CHIAVE DI DEDUPLICAZIONE TOTALE: blocca eventi uguali nello stesso minuto
                chiave_univoca = f"{vun_desc}_{ts_formatted}"

                if chiave_univoca not in wz_visti:
                    wz_visti.add(chiave_univoca)
                    wz_rows.append({
                        "weight": weight,
                        "dt": dt_obj if dt_obj else datetime.min,
                        "ts": ts_formatted,
                        "agent": agent_name,
                        "desc": vun_desc,
                        "level": level,
                        "status": status
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
                    "weight": weight,
                    "dt": dt_obj,
                    "ts": ts_formatted,
                    "host": host_name,
                    "desc": desc,
                    "prio": prio_str
                })

        # --- 3. CALCOLO DELLE STATISTICHE REALI SUI DATI FILTRATI ---
        stats = {"Critical/Disaster": 0, "High": 0, "Medium/Average": 0, "Low/Warning": 0, "Information": 0}
        for r in zb_rows:
            if r["weight"] == 5:stats["Critical/Disaster"] += 1
            elif r["weight"] == 4:stats["High"] += 1
            elif r["weight"] == 3:stats["Medium/Average"] += 1
            elif r["weight"] == 2:stats["Low/Warning"] += 1
            else:stats["Information"] += 1
        for r in wz_rows:
            if r["weight"] == 5:
                stats["Critical/Disaster"] += 1
            elif r["weight"] == 4:
                stats["High"] += 1
            elif r["weight"] == 3:
                stats["Medium/Average"] += 1
            elif r["weight"] == 2:
                stats["Low/Warning"] += 1
            else:
                stats["Information"] += 1

        # --- 4. GENERAZIONE PANNELLO EXECUTIVE SUMMARY ---
        story.append(Paragraph("📊 Executive Summary & Baseline Info", h2_style))
        summary_data = [
            [Paragraph("Data di Riferimento:", bold_cell_style),
             Paragraph("Oggi (Tempo Reale)", cell_style),
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

        summary_table = Table(summary_data, colWidths=[110, 140, 120, 140])
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
            # ORDINAMENTO COMBINATO: Prima per gravità (decrescente), poi per data/ora (decrescente)
            zb_rows.sort(key=lambda x: (x['weight'], x['dt']), reverse=True)

            zb_table_data = [["Data/Ora Rilev.", "Host / Apparato", "Descrizione Trigger / Alert", "Priorità"]]
            for row in zb_rows:
                p_weight = row["weight"]
                prio_text = row["prio"]
                prio_style = ParagraphStyle(f'ZBPrio_{prio_text}_{p_weight}', parent=cell_style,
                                            textColor=local_color_map.get(p_weight, colors.black),
                                            fontName="Helvetica-Bold")

                zb_table_data.append([
                    Paragraph(str(row["ts"]), cell_style), Paragraph(str(row["host"]), cell_style),
                    Paragraph(str(row["desc"]), cell_style), Paragraph(str(prio_text), prio_style)
                ])

            zb_table = Table(zb_table_data, colWidths=[95, 95, 260, 60])
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

         # --- 6. IMPAGINAZIONE TABELLA WAZUH ---

        story.append(Paragraph("⚠️ Vulnerabilità Software Rilevate (Wazuh)", h2_style))
        if wz_rows:
            # ORDINAMENTO COMBINATO: Prima per gravità (decrescente), poi per data/ora (decrescente)
            wz_rows.sort(key=lambda x: (x['weight'], x['dt']), reverse=True)

            wz_table_data = [["Data/Ora Rilev.", "Agent / PC", "Descrizione Vulnerabilità", "Livello/Sev", "Stato"]]

            status_color_map = {
                "Risolto": colors.HexColor('#38A169'),      # Verde
                "Non Risolto": colors.HexColor('#E53E3E'),  # Rosso
                "N/D": colors.HexColor('#718096'),          # Grigio (alert non-CVE)
            }

            for row in wz_rows:
                w_weight = row["weight"]
                lvl_text = row["level"]
                status_text = row.get("status", "N/D")

                wz_lvl_style = ParagraphStyle(f'WzLvl_{lvl_text}_{w_weight}', parent=cell_style,
                                              textColor=local_color_map.get(w_weight, colors.black), fontName="Helvetica-Bold")
                wz_status_style = ParagraphStyle(f'WzStatus_{status_text}', parent=cell_style,
                                                 textColor=status_color_map.get(status_text, colors.black),
                                                 fontName="Helvetica-Bold")

                wz_table_data.append([
                    Paragraph(str(row["ts"]), cell_style), Paragraph(str(row["agent"]), cell_style),
                    Paragraph(str(row["desc"]), cell_style), Paragraph(str(lvl_text), wz_lvl_style),
                    Paragraph(str(status_text), wz_status_style)
                ])

            wz_table = Table(wz_table_data, colWidths=[80, 80, 205, 55, 65])
            wz_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EDF2F7')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F7FAFC')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(wz_table)
        else:
            story.append(Paragraph("Nessuna vulnerabilità rilevata per questo filtro.", cell_style))

        # Chiusura e compilazione finale del documento PDF
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

    # Estrazione dati a ritroso da oggi
    zabbix_problems = fetch_zabbix_problems(target_host, days_duration, min_prio_zabbix)
    wazuh_alerts = fetch_wazuh_alerts(wazuh_user, wazuh_pass, target_host, days_duration, min_wazuh_lvl)

    # Estrae l'elenco delle CVE univoche rilevate negli alert storici, per poi
    # verificare quali di queste sono ANCORA presenti oggi nell'inventario
    # vulnerabilita' (wazuh-states-vulnerabilities-*).
    cve_codes_found = set()
    for item in wazuh_alerts:
        vul_info = item.get('data', {}).get('vulnerability', {})
        if vul_info:
            cve = vul_info.get('cve')
            if cve:
                cve_codes_found.add(cve)

    print(f"[*] {len(cve_codes_found)} CVE univoche rilevate nella finestra storica. Verifico lo stato attuale...")
    active_cves = fetch_current_active_cves(wazuh_user, wazuh_pass, cve_codes_found, target_host)

    # Generazione del suffisso data per il nome del file (Formato: AAAAMMGG)
    date_suffix = datetime.now().strftime("%Y%m%d")

    # Costruzione del nome del file PDF dinamico
    if target_host:
        output_filename = f"SecOps_Report_{target_host}_{date_suffix}.pdf"
    else:
        output_filename = f"SecOps_Executive_Report_{date_suffix}.pdf"

    if wazuh_alerts or zabbix_problems or target_host:
        generate_pdf_report(zabbix_problems, wazuh_alerts, output_filename, target_host, days_duration, active_cves)
    else:
        print("[-] Pipeline interrotta: nessun dato ricevuto dalle piattaforme.")


if __name__ == "__main__":
    main()
