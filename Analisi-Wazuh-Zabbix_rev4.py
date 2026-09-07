import requests
import json
import os
import getpass
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# --- CONFIGURAZIONI INFRASTRUTTURA ---
WAZUH_INDEXER_URL = "https://IL TUO IP:9200"
ZABBIX_API_URL = "http://IL TUO IP:PORTA/api_jsonrpc.php"

# --- TOKEN AUTOMATICO ZABBIX ---
ZABBIX_API_TOKEN = "INSERISCI IL TUO TOKEN CREATO SU ZABBIX"

requests.packages.urllib3.disable_warnings()

def fetch_wazuh_alerts(username, password, target_host=None):
    """Estrae gli alert critici da Wazuh Indexer negli ultimi 90 giorni e li filtra via codice."""
    print("[*] Interrogazione di Wazuh Indexer (Porta 9200)...")
    date_90_days_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")

    full_search_url = f"{WAZUH_INDEXER_URL}/wazuh-alerts*/_search"
    headers = {"Content-Type": "application/json"}

    query_body = {
        "size": 500,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "agent.id", "agent.name", "rule.id", "rule.level", "rule.description"],
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": 12, "lte": 16}}},
                    {"range": {"timestamp": {"gte": date_90_days_ago}}}
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

        # Filtro flessibile Python case-insensitive
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


def fetch_zabbix_problems(target_host=None):
    """Estrae i trigger attivi con priorità High/Disaster da Zabbix e li filtra via codice."""
    print("[*] Interrogazione di Zabbix API (Porta 8091)...")
    headers = {"Content-Type": "application/json-rpc"}

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

        critical_problems = []
        for tri in all_triggers:
            prio = int(tri.get('priority', 0))
            if prio == 4 or prio == 5:
                critical_problems.append(tri)

        # Filtro flessibile Python case-insensitive su Name e Hostname tecnico
        if target_host:
            target_clean = target_host.strip().lower()
            filtered_problems = []
            for item in critical_problems:
                hosts_list = item.get('hosts', [])
                if hosts_list and isinstance(hosts_list, list) and len(hosts_list) > 0:
                    h_name = hosts_list[0].get('name', '').lower()
                    h_tech = hosts_list[0].get('host', '').lower()
                    if target_clean in h_name or target_clean in h_tech:
                        filtered_problems.append(item)
            return filtered_problems

        return critical_problems
    except Exception as e:
        print(f"[-] Errore durante l'estrazione da Zabbix: {e}")
        return []


def generate_pdf_report(zabbix_data, wazuh_data, output_pdf, target_host=None):
    """Genera un PDF strutturato unendo i dati raccolti dalle due piattaforme."""
    print(f"[*] Generazione del PDF in corso: {output_pdf}...")
    doc = SimpleDocTemplate(output_pdf, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=22, leading=26,
                                 textColor=colors.HexColor('#1A365D'), spaceAfter=4)
    subtitle_style = ParagraphStyle('DocSubtitle', parent=styles['Normal'], fontSize=10, leading=14,
                                    textColor=colors.HexColor('#718096'), spaceAfter=15)
    h2_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontSize=13, leading=16,
                              textColor=colors.HexColor('#2C5282'), spaceBefore=12, spaceAfter=6, keepWithNext=True)
    cell_style = ParagraphStyle('TableCell', parent=styles['Normal'], fontSize=9, leading=12)

    current_date = datetime.now().strftime("%d/%m/%Y %H:%M")
    report_scope = f"Filtro Host: '{target_host}'" if target_host else "Infrastruttura Completa"

    story.append(Paragraph("SecOps Automated Correlation Report", title_style))
    story.append(Paragraph(f"Generato il: {current_date} | Ambito: {report_scope}", subtitle_style))
    story.append(Spacer(1, 10))

    # Tabella Zabbix
    story.append(Paragraph("Criticità Infrastrutturali Attive (Zabbix)", h2_style))
    if zabbix_data:
        zb_table_data = [["Host / Apparato", "Descrizione Trigger / Alert", "Priorità"]]
        for item in zabbix_data:
            hosts_list = item.get('hosts', [])
            host_name = hosts_list[0].get('name', 'Unknown') if hosts_list else 'Unknown'
            desc = item.get('description', 'N/A')
            prio = "Disaster" if item.get('priority') == "5" else "High"

            zb_table_data.append([
                Paragraph(host_name, cell_style),
                Paragraph(desc, cell_style),
                Paragraph(prio, cell_style)
            ])

        zb_table = Table(zb_table_data, colWidths=[120, 320, 70])
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
        story.append(Paragraph("Nessun problema critico attivo trovato per questo filtro.", cell_style))

    # Tabella Wazuh
    story.append(Paragraph("Vulnerabilità Software Rilevate (Wazuh)", h2_style))
    if wazuh_data:
        wz_table_data = [["Agent / PC", "Descrizione Vulnerabilità", "Livello"]]
        for item in wazuh_data:
            agent_name = item.get('agent', {}).get('name', 'Unknown')
            vun_desc = item.get('rule', {}).get('description', 'N/A')
            level = str(item.get('rule', {}).get('level', '0'))
            wz_table_data.append([
                Paragraph(agent_name, cell_style),
                Paragraph(vun_desc, cell_style),
                Paragraph(level, cell_style)
            ])

        wz_table = Table(wz_table_data, colWidths=[110, 340, 60])
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
        story.append(Paragraph("Nessuna vulnerabilità critica rilevata per questo filtro.", cell_style))

    doc.build(story)
    print(f"[+] PDF creato con successo.")


def main():
    print("=== AVVIO PIPELINE SECOPS AUTOMATIZZATA ===")

    target_host = input("Inserisci il nome dell'host (es. parziale o minuscolo) [INVIO per globale]: ").strip()
    if target_host == "":
        target_host = None

    wazuh_user = input("Inserisci l'username di Wazuh Indexer (es. admin): ")
    try:
        wazuh_pass = getpass.getpass("Inserisci la password di Wazuh Indexer: ")
    except Exception:
        wazuh_pass = input("Inserisci la password di Wazuh Indexer: ")

    print("\n" + "=" * 40)

    zabbix_problems = fetch_zabbix_problems(target_host)
    wazuh_alerts = fetch_wazuh_alerts(wazuh_user, wazuh_pass, target_host)

    # Genera comunque il report se hai cercato un host (anche se vuoto), per mostrare l'assenza di criticità
    if wazuh_alerts or zabbix_problems or target_host:
        output_filename = f"SecOps_Report_{target_host}.pdf" if target_host else "SecOps_Executive_Report.pdf"
        generate_pdf_report(zabbix_problems, wazuh_alerts, output_filename, target_host)
    else:
        print("[-] Pipeline interrotta: nessun dato globale ricevuto dalle piattaforme.")


if __name__ == "__main__":
    main()
