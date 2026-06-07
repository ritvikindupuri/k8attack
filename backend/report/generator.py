import html
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

EVENT_TYPE_COLORS = {
    'info': MEDIUM_GRAY,
    'success': ACCENT_GREEN,
    'warning': ACCENT_AMBER,
    'error': ACCENT_RED,
    'detected': HexColor('#3b82f6'),
    'complete': ACCENT_GREEN,
    'critical': ACCENT_RED,
    'cmd': DARK_NAVY,
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
    _s('ConclusionText', fontName='Helvetica', fontSize=10, leading=15, textColor=DARK_GRAY, alignment=TA_JUSTIFY, spaceAfter=4*mm)
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


def make_table(headers: List[str], rows: List[List], col_widths: Optional[List[float]] = None) -> Table:
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


def _fmt_ts(epoch_secs: float) -> str:
    if not epoch_secs:
        return '—'
    return datetime.fromtimestamp(epoch_secs, tz=timezone.utc).strftime('%H:%M:%S')


def _fmt_duration(start: float, end: float) -> str:
    if not start or not end:
        return '—'
    d = end - start
    if d < 60:
        return f'{d:.1f}s'
    return f'{d/60:.1f}m {d%60:.0f}s'


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
        canvas_obj.drawString(MARGIN, PAGE_H - 11*mm, 'K8s Attack & Remediation Platform \u2014 Security Assessment Report')
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

    attacks = data.get('attacks', [])
    alerts = data.get('detection', {}).get('events', [])
    alert_summary = data.get('detection', {}).get('summary', {})
    remediations = data.get('remediation', {}).get('sessions', [])
    critical_count = sum(1 for a in attacks if a.get('severity', '').lower() == 'critical')
    high_count = sum(1 for a in attacks if a.get('severity', '').lower() == 'high')
    medium_count = sum(1 for a in attacks if a.get('severity', '').lower() == 'medium')
    low_count = sum(1 for a in attacks if a.get('severity', '').lower() == 'low')
    completed = sum(1 for a in attacks if a.get('status', '').lower() in ('completed', 'success'))
    failed = sum(1 for a in attacks if a.get('status', '').lower() == 'failed')
    mitre_tactics = data.get('mitre', {}).get('tactics', [])
    cluster_nodes = data.get('cluster', {}).get('nodes', [])

    total_techniques = sum(len(t.get('techniques', [])) for t in mitre_tactics)
    covered_techniques = sum(t.get('covered_count', len(t.get('techniques', []))) for t in mitre_tactics)

    # ── COVER PAGE ──────────────────────────────────────────────
    story.append(Spacer(1, 55*mm))
    story.append(Paragraph('K8s Attack & Remediation Platform', _s('CoverTitle')))
    story.append(Paragraph('Security Assessment Report', _s('CoverSubtitle')))
    story.append(SectionDivider(ACCENT_RED, 55*mm))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(f'Generated: {generated_at}', _s('CoverMeta')))
    story.append(PageBreak())

    # ── 1. EXECUTIVE SUMMARY ────────────────────────────────────
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
    story.append(Spacer(1, 2*mm))

    story.append(Paragraph(f'Assessment Overview', _s('SubSubSection')))
    story.append(Spacer(1, 1*mm))

    overview_rows = [
        ['Total Attacks', str(len(attacks)), 'Attacks executed against the cluster'],
        ['Passed', str(completed), 'Attacks that completed successfully'],
        ['Failed', str(failed), 'Attacks that failed during execution'],
        ['Critical Issues', str(critical_count), 'Critical-severity vulnerabilities identified'],
        ['High Issues', str(high_count), 'High-severity vulnerabilities identified'],
        ['Alerts Triggered', str(len(alerts)), 'Detection events from cluster monitoring'],
        ['Remediations', str(len(remediations)), 'AI-driven remediation actions performed'],
        ['MITRE Tactics', str(len(mitre_tactics)), 'ATT&CK tactics with covered techniques'],
    ]
    overview_table = make_table(
        ['Metric', 'Count', 'Description'],
        overview_rows,
        col_widths=[30*mm, 16*mm, 104*mm],
    )
    story.append(overview_table)
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
            findings.append(f'{len(mitre_tactics)} MITRE ATT&CK tactics covered across {len(attacks)} distinct attack techniques with {covered_techniques}/{total_techniques} techniques demonstrated.')
        if len(remediations) > 0:
            findings.append(f'{len(remediations)} automated remediation actions executed via AI-powered agent (Claude Sonnet 4), with step-by-step reasoning and command validation.')
        if failed > 0:
            findings.append(f'{failed} attacks failed to execute \u2014 potential false negatives requiring manual investigation.')
        for f in findings:
            story.append(Paragraph(f'<bullet>&bull;</bullet>{f}', _s('BulletBody')))

    if exec_data.get('risk_score'):
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(f'Overall Risk Score: {exec_data["risk_score"]}', _s('BodyBold')))

    story.append(PageBreak())

    # ── 2. ATTACK SUMMARY ───────────────────────────────────────
    story.append(Paragraph('2. Attack Summary', _s('SectionTitle')))
    story.append(SectionDivider())
    story.append(Paragraph(
        'The following table summarizes all attacks executed during the assessment, including their '
        'severity rating, status, MITRE ATT&CK mapping, execution time, and duration.',
        _s('Body')
    ))
    story.append(Spacer(1, 3*mm))

    attack_rows = []
    for i, a in enumerate(attacks, 1):
        sev = a.get('severity', 'info').capitalize()
        st = a.get('status', 'unknown').capitalize()
        result = a.get('result', {}) or a
        start = result.get('start_time', a.get('start_time', 0))
        end = result.get('end_time', a.get('end_time', 0))
        techniques = result.get('mitre_techniques', a.get('mitre_techniques', []))
        tech_str = ', '.join([t.get('name', '') for t in techniques]) if techniques else (a.get('technique', a.get('mitre_technique', '\u2014')))
        attack_rows.append([
            str(i),
            a.get('name', a.get('attack_id', 'Unknown')),
            sev,
            st,
            _fmt_ts(start),
            _fmt_duration(start, end),
            tech_str,
        ])

    attack_table = make_table(
        ['#', 'Attack', 'Severity', 'Status', 'Start', 'Duration', 'MITRE Technique'],
        attack_rows,
        col_widths=[6*mm, 40*mm, 14*mm, 16*mm, 14*mm, 14*mm, 46*mm],
    )
    story.append(attack_table)

    # ── 3. MITRE ATT&CK COVERAGE ────────────────────────────────
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
        covered = t.get('covered_count', len(techniques))
        total = len(techniques)
        tech_names = ', '.join([tech.get('name', '') for tech in techniques])
        mitre_rows.append([
            t.get('id', '\u2014'),
            t.get('name', '\u2014'),
            f'{covered}/{total}',
            tech_names,
        ])

    mitre_table = make_table(
        ['Tactic ID', 'Tactic Name', 'Covered', 'Techniques'],
        mitre_rows,
        col_widths=[18*mm, 38*mm, 16*mm, 78*mm],
    )
    story.append(mitre_table)

    # ── 4. CLUSTER INFRASTRUCTURE ───────────────────────────────
    if cluster_nodes:
        story.append(Paragraph('4. Cluster Infrastructure', _s('SectionTitle')))
        story.append(SectionDivider())
        story.append(Paragraph(
            'The assessment was conducted against a Kind-based Kubernetes cluster with the following nodes '
            'and infrastructure configuration.',
            _s('Body')
        ))
        story.append(Spacer(1, 3*mm))

        node_rows = []
        for n in cluster_nodes:
            cap = n.get('capacity', {})
            node_rows.append([
                n.get('name', '\u2014'),
                n.get('status', '\u2014'),
                cap.get('cpu', '?'),
                cap.get('memory', '?'),
                cap.get('pods', '?'),
                n.get('os', '\u2014'),
                n.get('kubelet', '\u2014'),
            ])

        node_table = make_table(
            ['Name', 'Status', 'CPU', 'Memory', 'Max Pods', 'OS', 'Kubelet'],
            node_rows,
            col_widths=[40*mm, 14*mm, 10*mm, 22*mm, 14*mm, 28*mm, 22*mm],
        )
        story.append(node_table)

    story.append(PageBreak())

    # ── 5. DETAILED ATTACK LOG ──────────────────────────────────
    if attacks:
        story.append(Paragraph('5. Detailed Attack Log', _s('SectionTitle')))
        story.append(SectionDivider())
        story.append(Paragraph(
            'The following section provides detailed information for each attack executed, including '
            'attack methodology, execution timeline, events, commands issued, infrastructure affected, '
            'and impact assessment.',
            _s('Body')
        ))
        story.append(Spacer(1, 3*mm))

        for i, a in enumerate(attacks, 1):
            sev = a.get('severity', 'info').lower()
            result = a.get('result', {}) or a
            events = result.get('events', a.get('events', []))
            infrastructure = result.get('infrastructure_affected', a.get('infrastructure_affected', []))
            techniques = result.get('mitre_techniques', a.get('mitre_techniques', []))
            start = result.get('start_time', a.get('start_time', 0))
            end = result.get('end_time', a.get('end_time', 0))
            status = a.get('status', 'unknown').lower()
            error = a.get('error', '')

            story.append(KeepTogether([
                Paragraph(f'5.{i} {a.get("name", a.get("attack_id", f"Attack {i}"))}', _s('SubSectionTitle')),
                SeverityBadge(sev),
                Spacer(1, 2*mm),
            ]))

            meta_rows = []
            meta_rows.append([Paragraph('<b>Attack ID</b>', _s('TableCellBold')), Paragraph(str(a.get('attack_id', '\u2014')), _s('TableCell'))])
            meta_rows.append([Paragraph('<b>Severity</b>', _s('TableCellBold')), Paragraph(sev.capitalize(), _s('TableCell'))])
            meta_rows.append([Paragraph('<b>Status</b>', _s('TableCellBold')), Paragraph(status.capitalize(), _s('TableCell'))])
            meta_rows.append([Paragraph('<b>Start Time</b>', _s('TableCellBold')), Paragraph(_fmt_ts(start), _s('TableCell'))])
            meta_rows.append([Paragraph('<b>Duration</b>', _s('TableCellBold')), Paragraph(_fmt_duration(start, end), _s('TableCell'))])
            if techniques:
                tech_names = '; '.join([f'{t.get("id", "")} {t.get("name", "")}' for t in techniques])
                meta_rows.append([Paragraph('<b>MITRE Techniques</b>', _s('TableCellBold')), Paragraph(tech_names, _s('TableCell'))])
            if a.get('description'):
                meta_rows.append([Paragraph('<b>Description</b>', _s('TableCellBold')), Paragraph(a['description'], _s('TableCell'))])

            meta_table = Table(
                meta_rows,
                colWidths=[28*mm, 120*mm],
            )
            meta_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 1.5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 2*mm))

            if error:
                story.append(Paragraph(f'<b>Error:</b> <font color="{ACCENT_RED.hexval()}">{error}</font>', _s('Body')))

            # Infrastructure affected
            if infrastructure:
                story.append(Paragraph('Infrastructure Affected', _s('SubSubSection')))
                story.append(Spacer(1, 1*mm))
                infra_rows = []
                for inf in infrastructure[:6]:
                    rtype = inf.get('resource_type', '\u2014')
                    rname = inf.get('name', inf.get('namespace', '\u2014'))
                    rnamespace = inf.get('namespace', '\u2014')
                    details = inf.get('details', {})
                    detail_str = ', '.join([f'{k}: {v}' for k, v in details.items() if not isinstance(v, (dict, list))])[:60]
                    infra_rows.append([rtype, rname, rnamespace, detail_str])
                if infra_rows:
                    infra_table = make_table(
                        ['Resource Type', 'Name', 'Namespace', 'Details'],
                        infra_rows,
                        col_widths=[30*mm, 35*mm, 25*mm, 60*mm],
                    )
                    story.append(infra_table)
                story.append(Spacer(1, 2*mm))

            # Events (commands and output)
            if events:
                cmd_events = [e for e in events if e.get('event_type') == 'cmd']
                key_events = [e for e in events if e.get('event_type') in ('info', 'success', 'warning', 'error', 'critical', 'detected', 'complete')]

                if key_events:
                    story.append(Paragraph('Execution Timeline', _s('SubSubSection')))
                    story.append(Spacer(1, 1*mm))
                    timeline_rows = []
                    for e in key_events[:8]:
                        etype = e.get('event_type', 'info')
                        emsg = e.get('message', '')
                        ets = _fmt_ts(e.get('timestamp', 0))
                        color = EVENT_TYPE_COLORS.get(etype, MEDIUM_GRAY)
                        icon = {'info': '\u2139', 'success': '\u2713', 'warning': '\u26a0', 'error': '\u2717', 'detected': '\u25c9', 'complete': '\u2713', 'critical': '\u26a0'}.get(etype, '\u2022')
                        timeline_rows.append([
                            f'<font color="{color.hexval()}">{icon}</font>',
                            ets,
                            etype.capitalize(),
                            emsg[:100],
                        ])
                    timeline_table = make_table(
                        ['', 'Time', 'Type', 'Event'],
                        timeline_rows,
                        col_widths=[6*mm, 16*mm, 18*mm, 110*mm],
                    )
                    story.append(timeline_table)
                    story.append(Spacer(1, 2*mm))

                if cmd_events:
                    story.append(Paragraph('Commands Executed', _s('SubSubSection')))
                    story.append(Spacer(1, 1*mm))
                    for ci, ce in enumerate(cmd_events[:4], 1):
                        cmd = ce.get('data', {}).get('command', ce.get('command', ''))
                        output = ce.get('data', {}).get('output', ce.get('output', ''))
                        if cmd:
                            story.append(Paragraph(f'<b>Command {ci}:</b>', _s('SmallText')))
                            story.append(Paragraph(html.escape(cmd), _s('CommandText')))
                        if output:
                            truncated = output[:250] + ('\u2026' if len(output) > 250 else '')
                            story.append(Paragraph(truncated, _s('CommandOutput')))
                    story.append(Spacer(1, 2*mm))

            story.append(HRFlowable(width='100%', thickness=0.3, color=BORDER_COLOR, spaceAfter=3*mm, spaceBefore=3*mm))

    # ── 6. DETECTION & ALERTS ───────────────────────────────────
    if alerts:
        story.append(PageBreak())
        story.append(Paragraph('6. Detection & Alerts', _s('SectionTitle')))
        story.append(SectionDivider())
        story.append(Paragraph(
            'The detection monitor continuously observes the cluster for signs of malicious activity using '
            'Kubernetes watch APIs. Alerts are generated when resources matching predefined alert rules are '
            'created or modified.',
            _s('Body')
        ))
        story.append(Spacer(1, 3*mm))

        if alert_summary:
            sc = alert_summary
            story.append(Paragraph(
                f'<b>Alert Summary:</b> {sc.get("total", 0)} total alerts \u2014 '
                f'<font color="{ACCENT_RED.hexval()}">{sc.get("critical", 0)} critical</font>, '
                f'<font color="{ACCENT_ORANGE.hexval()}">{sc.get("high", 0)} high</font>, '
                f'<font color="{ACCENT_AMBER.hexval()}">{sc.get("medium", 0)} medium</font>, '
                f'<font color="#eab308">{sc.get("low", 0)} low</font>',
                _s('Body')
            ))
            story.append(Spacer(1, 3*mm))

        alert_rows = []
        for alert in alerts:
            severity = alert.get('severity', 'info').lower()
            sev_display = severity.capitalize()
            rule = alert.get('rule_name', alert.get('rule', 'Unknown'))
            resource = alert.get('resource', '\u2014')
            ts = alert.get('timestamp', alert.get('time', '\u2014'))
            ns = alert.get('namespace', '')
            resource_display = f'{resource}' + (f' ({ns})' if ns else '')
            alert_rows.append([rule, sev_display, resource_display, ts])

        if alert_rows:
            alert_table = make_table(
                ['Rule', 'Severity', 'Resource', 'Timestamp'],
                alert_rows,
                col_widths=[50*mm, 16*mm, 50*mm, 34*mm],
            )
            story.append(alert_table)

    # ── 7. REMEDIATION ACTIONS ──────────────────────────────────
    if remediations:
        story.append(PageBreak())
        story.append(Paragraph('7. Remediation Actions', _s('SectionTitle')))
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
            story.append(Paragraph(f'7.{j} Remediation Session \u2014 {incident.get("attack_name", incident.get("name", session.get("session_id", f"Session {j}")))}', _s('SubSectionTitle')))
            story.append(Paragraph(f'<b>Session ID:</b> {session.get("session_id", "\u2014")}', _s('Body')))
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
                        story.append(Paragraph(f'Step {k} \u2014 Reasoning:', _s('SmallText')))
                        story.append(Paragraph(thinking[:500] + ('\u2026' if len(thinking) > 500 else ''), _s('ThinkingText')))
                    if command:
                        story.append(Paragraph(f'Command:', _s('SmallText')))
                        story.append(Paragraph(html.escape(command), _s('CommandText')))
                    if output:
                        story.append(Paragraph(f'Output:', _s('SmallText')))
                        truncated = output[:300] + ('\u2026' if len(output) > 300 else '')
                        story.append(Paragraph(html.escape(truncated), _s('CommandOutput')))
                story.append(Spacer(1, 2*mm))

            summary = session.get('summary')
            if summary:
                story.append(Paragraph(f'<b>Summary:</b> {summary}', _s('Body')))
            story.append(HRFlowable(width='100%', thickness=0.3, color=BORDER_COLOR, spaceAfter=3*mm, spaceBefore=3*mm))

    # ── 8. CONCLUSION & RECOMMENDATIONS ─────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('8. Conclusion', _s('SectionTitle')))
    story.append(SectionDivider())

    conclusion_text = data.get('conclusion', {}).get('text', '') or (
        f'This security assessment successfully executed {len(attacks)} real-world Kubernetes attack '
        f'techniques across {len(mitre_tactics)} MITRE ATT&CK tactics, demonstrating {covered_techniques} '
        f'out of {total_techniques} techniques ({int(covered_techniques/total_techniques*100) if total_techniques else 0}% coverage). '
        f'The assessment identified {critical_count} critical and {high_count} high-severity vulnerabilities '
        f'in the cluster configuration that could be exploited by adversaries to compromise containerized '
        f'workloads, escalate privileges, exfiltrate sensitive data, and disrupt cluster operations.'
        f'{" AI-powered remediation was triggered for " + str(len(remediations)) + " incidents, successfully mitigating identified threats through automated command execution." if remediations else ""}'
    )
    story.append(Paragraph(conclusion_text, _s('ConclusionText')))
    story.append(Spacer(1, 4*mm))

    recs = data.get('conclusion', {}).get('recommendations', [])
    if not recs:
        recs = [
            'Enforce Pod Security Standards (restricted profile) to prevent privileged container deployment and reduce the attack surface for container escape techniques.',
            'Implement RBAC least-privilege policies \u2014 avoid cluster-admin bindings for service accounts and use RoleBindings with scoped permissions instead of ClusterRoleBindings.',
            'Disable hostPath volume mounts unless absolutely necessary; use CSI drivers with appropriate policies and admission controllers to enforce restrictions.',
            'Store secrets in external secrets management solutions (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) with automatic rotation and audit logging, rather than Kubernetes-native Secrets.',
            'Enable Kubernetes audit logging to all control plane components and implement real-time threat detection using tools like Falco or Kubernetes monitoring solutions.',
            'Implement network policies to enforce micro-segmentation and restrict east-west traffic between pods, limiting lateral movement capabilities.',
            'Apply SecurityContext constraints at the pod level \u2014 drop all capabilities, run as non-root, use read-only root filesystems, and set seccomp profiles.',
            'Conduct regular security assessments and penetration testing to identify and remediate configuration drift and newly discovered vulnerabilities.',
        ]
    story.append(Paragraph('Recommendations', _s('SubSectionTitle')))
    story.append(Spacer(1, 1*mm))
    for r in recs:
        story.append(Paragraph(f'<bullet>&bull;</bullet>{r}', _s('BulletBody')))
    story.append(Spacer(1, 6*mm))

    story.append(HRFlowable(width='100%', thickness=0.5, color=ACCENT_RED, spaceAfter=4*mm, spaceBefore=2*mm))
    story.append(Paragraph(
        'This report was generated automatically by the K8s Attack & Remediation Platform. '
        'The findings reflect the state of the cluster at the time of assessment and should be '
        'used as part of a broader security review process.',
        _s('SmallText')
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    return buf
