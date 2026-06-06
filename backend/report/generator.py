import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, inch
from reportlab.lib.colors import HexColor, black, white, Color
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Frame, PageTemplate, BaseDocTemplate, NextPageTemplate,
    KeepTogether, HRFlowable
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas

PAGE_W, PAGE_H = A4
MARGIN = 22 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

DARK_NAVY = HexColor('#0f172a')
MEDIUM_BLUE = HexColor('#1e293b')
LIGHT_BLUE = HexColor('#f0f4ff')
ACCENT_RED = HexColor('#ef4444')
ACCENT_AMBER = HexColor('#f59e0b')
ACCENT_GREEN = HexColor('#22c55e')
ACCENT_ORANGE = HexColor('#f97316')
LIGHT_BG = HexColor('#f8fafc')
MEDIUM_GRAY = HexColor('#94a3b8')
DARK_GRAY = HexColor('#334155')
TABLE_ALT = HexColor('#f1f5f9')
BORDER_COLOR = HexColor('#e2e8f0')

SEVERITY_COLORS = {
    'critical': ACCENT_RED,
    'high': ACCENT_ORANGE,
    'medium': ACCENT_AMBER,
    'low': HexColor('#eab308'),
    'info': MEDIUM_GRAY,
}

SEVERITY_BG = {
    'critical': HexColor('#fef2f2'),
    'high': HexColor('#fff7ed'),
    'medium': HexColor('#fefce8'),
    'low': HexColor('#f0fdf4'),
    'info': HexColor('#f8fafc'),
}

STATUS_COLORS = {
    'completed': ACCENT_GREEN,
    'running': HexColor('#3b82f6'),
    'failed': ACCENT_RED,
    'pending': MEDIUM_GRAY,
    'remediated': ACCENT_GREEN,
    'auto-remediated': HexColor('#10b981'),
}

styles_cache = {}

def _s(name, **kwargs):
    if name not in styles_cache:
        defaults = dict(name=name, fontName='Helvetica', fontSize=10, leading=14, textColor=HexColor('#1e293b'), spaceBefore=0, spaceAfter=0)
        defaults.update(kwargs)
        styles_cache[name] = ParagraphStyle(**defaults)
    return styles_cache[name]

def build_styles():
    _s('CoverTitle', fontName='Helvetica-Bold', fontSize=30, leading=36, textColor=white, spaceAfter=6*mm, alignment=TA_LEFT)
    _s('CoverSubtitle', fontName='Helvetica', fontSize=13, leading=17, textColor=HexColor('#94a3b8'), spaceAfter=8*mm, alignment=TA_LEFT)
    _s('CoverMeta', fontName='Helvetica', fontSize=9, leading=13, textColor=HexColor('#64748b'), alignment=TA_LEFT)
    _s('SectionTitle', fontName='Helvetica-Bold', fontSize=16, leading=20, textColor=DARK_NAVY, spaceBefore=10*mm, spaceAfter=4*mm)
    _s('SubSectionTitle', fontName='Helvetica-Bold', fontSize=12, leading=15, textColor=MEDIUM_BLUE, spaceBefore=6*mm, spaceAfter=3*mm)
    _s('SubSubSection', fontName='Helvetica-Bold', fontSize=10, leading=13, textColor=DARK_GRAY, spaceBefore=4*mm, spaceAfter=2*mm)
    _s('Body', fontName='Helvetica', fontSize=9.5, leading=14, textColor=HexColor('#334155'), alignment=TA_JUSTIFY, spaceAfter=3*mm)
    _s('BodyBold', fontName='Helvetica-Bold', fontSize=9.5, leading=14, textColor=HexColor('#334155'), spaceAfter=2*mm)
    _s('TableCell', fontName='Helvetica', fontSize=8, leading=11, textColor=HexColor('#1e293b'))
    _s('TableCellBold', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=HexColor('#1e293b'))
    _s('TableHeader', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=white)
    _s('SmallText', fontName='Helvetica', fontSize=7.5, leading=10, textColor=HexColor('#64748b'))
    _s('ThinkingText', fontName='Helvetica-Oblique', fontSize=8, leading=11, textColor=HexColor('#475569'), spaceAfter=2*mm)
    _s('CommandText', fontName='Courier', fontSize=7.5, leading=10, textColor=DARK_NAVY, spaceAfter=2*mm)
    _s('CommandOutput', fontName='Courier', fontSize=7, leading=9, textColor=HexColor('#475569'), spaceAfter=2*mm)
    _s('BulletBody', fontName='Helvetica', fontSize=9.5, leading=14, textColor=HexColor('#334155'), leftIndent=4*mm, bulletIndent=0, spaceAfter=2*mm)
    _s('ConclusionText', fontName='Helvetica-Oblique', fontSize=10, leading=15, textColor=DARK_GRAY, alignment=TA_JUSTIFY, spaceAfter=4*mm)
    _s('FooterStyle', fontName='Helvetica', fontSize=7.5, leading=10, textColor=MEDIUM_GRAY, alignment=TA_CENTER)


class SectionDivider(Flowable):
    def __init__(self, color=ACCENT_RED, width=None):
        Flowable.__init__(self)
        self.color = color
        self._width = width or CONTENT_W
        self.height = 2
        self.width = self._width

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(1.5)
        self.canv.line(0, 0, self.width, 0)


class ColorBlock(Flowable):
    def __init__(self, color, width, height):
        Flowable.__init__(self)
        self.color = color
        self.width = width
        self.height = height

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


class SeverityBadge(Flowable):
    def __init__(self, severity: str):
        Flowable.__init__(self)
        self.severity = severity.lower()
        self.color = SEVERITY_COLORS.get(self.severity, MEDIUM_GRAY)
        self.width = 14 * mm
        self.height = 4.5 * mm

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, 2, fill=1, stroke=0)
        self.canv.setFillColor(white)
        self.canv.setFont('Helvetica-Bold', 7)
        self.canv.drawCentredString(self.width / 2, self.height / 2 - 2.5, self.severity.upper())


class StatusBadge(Flowable):
    def __init__(self, status: str):
        Flowable.__init__(self)
        self.status = status.lower()
        self.color = STATUS_COLORS.get(self.status, MEDIUM_GRAY)
        self.width = 16 * mm
        self.height = 4.5 * mm

    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, 2, fill=1, stroke=0)
        self.canv.setFillColor(white)
        self.canv.setFont('Helvetica-Bold', 7)
        self.canv.drawCentredString(self.width / 2, self.height / 2 - 2.5, self.status.upper())


class CoverBackground(Flowable):
    def __init__(self):
        Flowable.__init__(self)
        self.width = PAGE_W
        self.height = PAGE_H

    def draw(self):
        self.canv.setFillColor(DARK_NAVY)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        for i in range(5):
            y = self.height * 0.5 + i * 25
            alpha = 0.03 - i * 0.005
            self.canv.setFillColor(HexColor('#f97316'))
            self.canv.setFillAlpha(max(0, alpha))
            self.canv.rect(0, y, self.width, 2, fill=1, stroke=0)
        self.canv.setFillAlpha(1)
        bar_h = 4 * mm
        bar_y = self.height * 0.58
        self.canv.setFillColor(ACCENT_RED)
        self.canv.rect(0, bar_y, 60 * mm, bar_h, fill=1, stroke=0)
        self.canv.setFillColor(ACCENT_AMBER)
        self.canv.rect(60 * mm, bar_y, 40 * mm, bar_h, fill=1, stroke=0)


class PageBackground(Flowable):
    def __init__(self):
        Flowable.__init__(self)
        self.width = PAGE_W
        self.height = PAGE_H

    def draw(self):
        self.canv.setFillColor(LIGHT_BG)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


class HeaderBar(Flowable):
    def __init__(self):
        Flowable.__init__(self)
        self.width = CONTENT_W
        self.height = 12

    def draw(self):
        self.canv.setFillColor(ACCENT_RED)
        self.canv.roundRect(0, 0, 3, self.height, 1.5, fill=1, stroke=0)


def make_table(headers: List[str], rows: List[List], col_widths: Optional[List[float]] = None, severity_col: Optional[int] = None) -> Table:
    def _style_cell(text, is_header=False):
        style = 'TableHeader' if is_header else 'TableCell'
        p = Paragraph(str(text), _s(style))
        return p

    header_row = [_style_cell(h, is_header=True) for h in headers]
    data = [header_row]
    for row in rows:
        data.append([_style_cell(c) for c in row])

    if col_widths is None:
        col_widths = [CONTENT_W / len(headers)] * len(headers)

    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.4, BORDER_COLOR),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]
    for i, row in enumerate(data[1:], 1):
        if i % 2 == 0:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), TABLE_ALT))
        else:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), white))
    style_cmds.append(('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY))
    t.setStyle(TableStyle(style_cmds))
    return t


def on_page(canvas_obj, doc):
    canvas_obj.saveState()
    if doc.page == 1:
        canvas_obj.setFillColor(DARK_NAVY)
        canvas_obj.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        canvas_obj.setFillColor(HexColor('#f97316'))
        for i in range(5):
            canvas_obj.setFillAlpha(max(0.02, 0.06 - i * 0.01))
            canvas_obj.rect(0, PAGE_H * 0.45 + i * 30, PAGE_W, 1.5, fill=1, stroke=0)
        canvas_obj.setFillAlpha(1)
        canvas_obj.setFillColor(ACCENT_RED)
        canvas_obj.rect(0, PAGE_H * 0.56, 58*mm, 3.5*mm, fill=1, stroke=0)
        canvas_obj.setFillColor(ACCENT_AMBER)
        canvas_obj.rect(58*mm, PAGE_H * 0.56, 38*mm, 3.5*mm, fill=1, stroke=0)
    else:
        canvas_obj.setStrokeColor(HexColor('#e2e8f0'))
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(MARGIN, PAGE_H - 12*mm, PAGE_W - MARGIN, PAGE_H - 12*mm)
        canvas_obj.setFont('Helvetica', 7)
        canvas_obj.setFillColor(MEDIUM_GRAY)
        canvas_obj.drawString(MARGIN, PAGE_H - 11*mm, 'K8s Attack & Remediation Platform — Security Assessment Report')
        canvas_obj.drawRightString(PAGE_W - MARGIN, PAGE_H - 11*mm, datetime.now().strftime('%Y-%m-%d'))
        canvas_obj.setStrokeColor(HexColor('#e2e8f0'))
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(MARGIN, 15*mm, PAGE_W - MARGIN, 15*mm)
        canvas_obj.setFont('Helvetica', 7.5)
        canvas_obj.setFillColor(MEDIUM_GRAY)
        canvas_obj.drawCentredString(PAGE_W / 2, 11*mm, f'Page {doc.page}')
    canvas_obj.restoreState()


def generate_report(data: Dict[str, Any]) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18*mm, bottomMargin=22*mm,
        title='K8s Attack & Remediation - Security Assessment Report',
        author='K8s Attack & Remediation Platform',
    )

    build_styles()
    story = []
    generated_at = datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')

    # COVER PAGE
    story.append(Spacer(1, 50*mm))
    story.append(Paragraph('K8s Attack & Remediation Platform', _s('CoverTitle')))
    story.append(Paragraph('Security Assessment Report', _s('CoverSubtitle')))
    story.append(SectionDivider(ACCENT_RED, 55*mm))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(f'Generated: {generated_at}', _s('CoverMeta')))
    story.append(Spacer(1, 15*mm))

    attacks = data.get('attacks', [])
    alerts = data.get('detection', {}).get('events', [])
    remediations = data.get('remediation', {}).get('sessions', [])
    critical_count = sum(1 for a in attacks if a.get('severity', '').lower() == 'critical')
    high_count = sum(1 for a in attacks if a.get('severity', '').lower() == 'high')
    completed = sum(1 for a in attacks if a.get('status', '').lower() in ('completed', 'success'))
    failed = sum(1 for a in attacks if a.get('status', '').lower() == 'failed')
    mitre_tactics = data.get('mitre', {}).get('tactics', [])

    cover_stats = [
        ['Total Attacks Executed', str(len(attacks))],
        ['Critical Severity', str(critical_count)],
        ['High Severity', str(high_count)],
        ['Completed Successfully', str(completed)],
        ['Failed', str(failed)],
        ['Detection Alerts Triggered', str(len(alerts))],
        ['Remediation Actions Taken', str(len(remediations))],
        ['MITRE ATT&CK Tactics Covered', str(len(mitre_tactics))],
    ]
    stat_table = Table(
        [[Paragraph(r[0], _s('CoverMeta')), Paragraph(r[1], _s('CoverMeta'))] for r in cover_stats],
        colWidths=[45*mm, 25*mm],
    )
    stat_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(stat_table)
    story.append(PageBreak())

    # EXECUTIVE SUMMARY
    story.append(Paragraph('1. Executive Summary', _s('SectionTitle')))
    story.append(SectionDivider())

    exec_data = data.get('executive_summary', {})
    exec_text = exec_data.get('summary', '') or (
        f'This report presents the findings of a comprehensive security assessment conducted '
        f'against a Kubernetes cluster using the K8s Attack & Remediation Platform. The assessment '
        f'executed {len(attacks)} real-world attack techniques mapped to the MITRE ATT&CK for '
        f'Containers framework, covering privilege escalation, container escape, credential access, '
        f'lateral movement, and resource hijacking scenarios across multiple Kubernetes control plane '
        f'and data plane components.'
    )
    story.append(Paragraph(exec_text, _s('Body')))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph('Key Findings', _s('SubSubSection')))
    story.append(Spacer(1, 1*mm))

    for key, val in exec_data.get('key_findings', {}).items():
        story.append(Paragraph(f'<bullet>&bull;</bullet>{val}', _s('BulletBody')))
    if not exec_data.get('key_findings'):
        findings = []
        if critical_count > 0:
            findings.append(f'{critical_count} critical-severity security issues identified, requiring immediate remediation attention.')
        if high_count > 0:
            findings.append(f'{high_count} high-severity issues identified, posing significant risk to cluster security posture.')
        if len(mitre_tactics) > 0:
            findings.append(f'{len(mitre_tactics)} MITRE ATT&CK tactics covered across {len(attacks)} distinct attack techniques.')
        if len(remediations) > 0:
            findings.append(f'{len(remediations)} automated remediation actions executed via AI-powered agent (Claude Sonnet 4), with step-by-step reasoning and command validation.')
        if failed > 0:
            findings.append(f'{failed} attacks failed to execute — potential false negatives requiring manual investigation.')
        for f in findings:
            story.append(Paragraph(f'<bullet>&bull;</bullet>{f}', _s('BulletBody')))

    if exec_data.get('risk_score'):
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(f'Overall Risk Score: {exec_data["risk_score"]}', _s('BodyBold')))

    story.append(PageBreak())

    # ATTACK SUMMARY
    story.append(Paragraph('2. Attack Summary', _s('SectionTitle')))
    story.append(SectionDivider())
    story.append(Paragraph(
        'The following table summarizes all attacks executed during the assessment, including their '
        'severity rating, status, and mapped MITRE ATT&CK technique.',
        _s('Body')
    ))
    story.append(Spacer(1, 3*mm))

    attack_rows = []
    for i, a in enumerate(attacks, 1):
        sev = a.get('severity', 'info').capitalize()
        st = a.get('status', 'unknown').capitalize()
        attack_rows.append([
            str(i),
            a.get('name', a.get('attack_id', 'Unknown')),
            sev,
            st,
            a.get('technique', a.get('mitre_technique', '—')),
        ])

    attack_table = make_table(
        ['#', 'Attack', 'Severity', 'Status', 'MITRE Technique'],
        attack_rows,
        col_widths=[8*mm, 50*mm, 18*mm, 20*mm, 54*mm],
    )
    story.append(attack_table)

    # MITRE COVERAGE
    story.append(Paragraph('3. MITRE ATT&CK Coverage', _s('SectionTitle')))
    story.append(SectionDivider())
    story.append(Paragraph(
        'The following matrix maps the executed attacks to the MITRE ATT&CK for Containers framework, '
        'demonstrating coverage across multiple tactics and techniques.',
        _s('Body')
    ))
    story.append(Spacer(1, 3*mm))

    mitre_rows = []
    for t in mitre_tactics:
        techniques = t.get('techniques', [])
        tech_names = ', '.join([tech.get('name', '') for tech in techniques])
        covered = len(techniques)
        mitre_rows.append([
            t.get('id', '—'),
            t.get('name', '—'),
            str(covered),
            tech_names,
        ])

    mitre_table = make_table(
        ['Tactic ID', 'Tactic Name', 'Techniques', 'Covered Techniques'],
        mitre_rows,
        col_widths=[20*mm, 35*mm, 18*mm, 77*mm],
    )
    story.append(mitre_table)

    if attacks:
        story.append(Paragraph('4. Detailed Attack Log', _s('SectionTitle')))
        story.append(SectionDivider())
        story.append(Paragraph(
            'The following section provides detailed information for each attack executed, including '
            'the attack methodology, findings, and impact assessment.',
            _s('Body')
        ))
        story.append(Spacer(1, 3*mm))

        for i, a in enumerate(attacks, 1):
            sev = a.get('severity', 'info').lower()
            story.append(KeepTogether([
                Paragraph(f'4.{i} {a.get("name", a.get("attack_id", f"Attack {i}"))}', _s('SubSectionTitle')),
                SeverityBadge(sev),
                Spacer(1, 2*mm),
            ]))
            story.append(Paragraph(f'<b>Attack ID:</b> {a.get("attack_id", "—")}', _s('Body')))
            story.append(Paragraph(f'<b>Severity:</b> {sev.capitalize()}', _s('Body')))
            story.append(Paragraph(f'<b>Status:</b> {a.get("status", "Unknown").capitalize()}', _s('Body')))
            story.append(Paragraph(f'<b>MITRE Technique:</b> {a.get("technique", a.get("mitre_technique", "—"))}', _s('Body')))
            if a.get('description'):
                story.append(Paragraph(f'<b>Description:</b> {a["description"]}', _s('Body')))
            if a.get('result'):
                story.append(Paragraph(f'<b>Result:</b> {a["result"]}', _s('Body')))
            if a.get('finding'):
                story.append(Paragraph(f'<b>Finding:</b> {a["finding"]}', _s('Body')))
            story.append(Spacer(1, 4*mm))

    # DETECTION ALERTS
    if alerts:
        story.append(PageBreak())
        story.append(Paragraph('5. Detection & Alerts', _s('SectionTitle')))
        story.append(SectionDivider())
        story.append(Paragraph(
            'The detection monitor continuously observes the cluster for signs of malicious activity. '
            'The following alerts were triggered during the assessment.',
            _s('Body')
        ))
        story.append(Spacer(1, 3*mm))

        alert_rows = []
        summary_counts = data.get('detection', {}).get('summary', {})
        if summary_counts:
            story.append(Paragraph(f'<b>Alert Summary:</b> {summary_counts.get("total", 0)} total alerts — '
                                   f'<font color="#ef4444">{summary_counts.get("critical", 0)} critical</font>, '
                                   f'<font color="#f97316">{summary_counts.get("high", 0)} high</font>, '
                                   f'<font color="#f59e0b">{summary_counts.get("medium", 0)} medium</font>, '
                                   f'<font color="#eab308">{summary_counts.get("low", 0)} low</font>',
                                   _s('Body')))
            story.append(Spacer(1, 3*mm))

        for alert in alerts:
            alert_rows.append([
                alert.get('rule_name', alert.get('rule', 'Unknown')),
                alert.get('severity', 'info').capitalize(),
                alert.get('resource', '—'),
                alert.get('timestamp', alert.get('time', '—')),
            ])

        if alert_rows:
            alert_table = make_table(
                ['Rule', 'Severity', 'Resource', 'Timestamp'],
                alert_rows,
                col_widths=[50*mm, 18*mm, 40*mm, 42*mm],
            )
            story.append(alert_table)

    # REMEDIATION ACTIONS
    if remediations:
        story.append(PageBreak())
        story.append(Paragraph('6. Remediation Actions', _s('SectionTitle')))
        story.append(SectionDivider())
        story.append(Paragraph(
            'The AI-powered remediation agent (Claude Sonnet 4) was triggered for high and critical '
            'severity incidents. Each remediation session includes the agent\'s reasoning and the '
            'commands executed to mitigate the identified threats.',
            _s('Body')
        ))
        story.append(Spacer(1, 3*mm))

        for j, session in enumerate(remediations, 1):
            incident = session.get('incident', {})
            story.append(Paragraph(f'6.{j} Remediation Session — {incident.get("attack_name", incident.get("name", session.get("session_id", f"Session {j}")))}', _s('SubSectionTitle')))
            story.append(Paragraph(f'<b>Session ID:</b> {session.get("session_id", "—")}', _s('Body')))
            story.append(Paragraph(f'<b>Status:</b> {session.get("status", "Unknown").capitalize()}', _s('Body')))
            story.append(Paragraph(f'<b>Triggered By:</b> {incident.get("severity", "Unknown").capitalize()} severity incident', _s('Body')))
            story.append(Spacer(1, 2*mm))

            steps = session.get('steps', [])
            if steps:
                story.append(Paragraph('Agent Reasoning & Commands:', _s('SubSubSection')))
                story.append(Spacer(1, 1*mm))
                for k, step in enumerate(steps, 1):
                    thinking = step.get('thinking', '')
                    command = step.get('command', '')
                    output = step.get('command_output', '')
                    if thinking:
                        story.append(Paragraph(f'<i>Step {k} — Reasoning:</i>', _s('SmallText')))
                        story.append(Paragraph(thinking[:500] + ('…' if len(thinking) > 500 else ''), _s('ThinkingText')))
                    if command:
                        story.append(Paragraph(f'<i>Command:</i>', _s('SmallText')))
                        story.append(Paragraph(f'<font face="Courier" size="7.5">{command}</font>', _s('CommandText')))
                    if output:
                        story.append(Paragraph(f'<i>Output:</i>', _s('SmallText')))
                        truncated = output[:300] + ('…' if len(output) > 300 else '')
                        story.append(Paragraph(f'<font face="Courier" size="7">{truncated}</font>', _s('CommandOutput')))
                story.append(Spacer(1, 2*mm))

            summary = session.get('summary')
            if summary:
                story.append(Paragraph(f'<b>Summary:</b> {summary}', _s('Body')))
            story.append(HRFlowable(width='100%', thickness=0.3, color=BORDER_COLOR, spaceAfter=3*mm, spaceBefore=3*mm))

    # CONCLUSION
    story.append(PageBreak())
    story.append(Paragraph('7. Conclusion', _s('SectionTitle')))
    story.append(SectionDivider())

    conclusion_text = data.get('conclusion', {}).get('text', '') or (
        f'This security assessment successfully demonstrated {len(attacks)} real-world Kubernetes attack '
        f'techniques across {len(mitre_tactics)} MITRE ATT&CK tactics. The assessment identified '
        f'{critical_count} critical and {high_count} high-severity vulnerabilities in the cluster configuration '
        f'that could be exploited by adversaries to compromise containerized workloads.'
    )
    story.append(Paragraph(conclusion_text, _s('ConclusionText')))
    story.append(Spacer(1, 4*mm))

    recs = data.get('conclusion', {}).get('recommendations', [])
    if not recs:
        recs = [
            'Enforce Pod Security Standards (restricted profile) to prevent privileged container deployment.',
            'Implement RBAC least-privilege policies — avoid cluster-admin bindings for service accounts.',
            'Disable hostPath volume mounts unless absolutely necessary; use CSI drivers with appropriate policies.',
            'Store secrets in external secrets management (HashiCorp Vault, AWS Secrets Manager) with automatic rotation.',
            'Enable audit logging and implement real-time threat detection for rapid incident response.',
            'Conduct regular security assessments to identify and remediate configuration drift.',
            'Implement network policies to enforce micro-segmentation and restrict east-west traffic.',
        ]
    story.append(Paragraph('Recommendations', _s('SubSectionTitle')))
    story.append(Spacer(1, 1*mm))
    for r in recs:
        story.append(Paragraph(f'<bullet>&bull;</bullet>{r}', _s('BulletBody')))
    story.append(Spacer(1, 6*mm))

    story.append(HRFlowable(width='100%', thickness=0.5, color=ACCENT_RED, spaceAfter=4*mm, spaceBefore=2*mm))
    story.append(Paragraph(
        '<i>This report was generated automatically by the K8s Attack & Remediation Platform. '
        'The findings reflect the state of the cluster at the time of assessment and should be '
        'used as part of a broader security review process.</i>',
        _s('SmallText')
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf
