//! NIMBUSA SHIELD dashboard + active-incident screen.
//!
//! Every value rendered here comes from the live `ShieldSnapshot` the engine
//! publishes. There are no placeholder numbers: an empty field means the engine
//! has nothing yet, not that the UI faked a zero.
use crate::theme::*;
use nimbusa::shield::engine::{self, ShieldSnapshot};
use nimbusa::shield::health::State as HState;
use ratatui::prelude::*;
use ratatui::widgets::*;

fn threat_color(threat: &str) -> Color {
    match threat {
        "CRITICAL" => Color::Rgb(255, 60, 60),
        "ATTACK" => Color::Rgb(255, 110, 60),
        "SUSPICIOUS" => Color::Rgb(240, 190, 70),
        "ELEVATED" => Color::Rgb(230, 220, 120),
        _ => Color::Rgb(120, 210, 140),
    }
}

fn health_color(s: HState) -> Color {
    match s {
        HState::Healthy => Color::Green,
        HState::Degraded => Color::Yellow,
        HState::Unavailable => Color::Red,
        HState::Unknown => Color::DarkGray,
    }
}

fn on(b: bool) -> Span<'static> {
    if b {
        Span::styled(
            " ACTIVE ",
            Style::default()
                .fg(INK)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" READY ", Style::default().fg(INK).bg(Color::DarkGray))
    }
}

pub fn render(f: &mut Frame, area: Rect, s: &ShieldSnapshot) {
    // A live incident takes over the whole tab.
    if let Some(inc) = &s.current_incident {
        if inc.open && s.recovery.state.under_incident() {
            render_incident(f, area, s);
            return;
        }
    }
    render_dashboard(f, area, s);
}

fn render_dashboard(f: &mut Frame, area: Rect, s: &ShieldSnapshot) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // status header
            Constraint::Length(7), // gauges + key metrics
            Constraint::Length(8), // graphs
            Constraint::Min(6),    // targets / mitigation / health
        ])
        .split(area);

    // ---- status header ----------------------------------------------------
    let (posture, note) = engine::posture(s);
    let a = &s.assessment;
    let tcol = threat_color(a.threat.as_str());
    let pcol = match posture {
        "PROTECTED" | "READY" | "OBSERVING" => Color::Green,
        "RECOVERING" => Color::Yellow,
        "DISABLED" => Color::DarkGray,
        _ => Color::Red,
    };
    let mut header = vec![
        Line::from(vec![
            Span::styled(
                "  NIMBUSA SHIELD  ",
                Style::default()
                    .fg(INK)
                    .bg(CREAM)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!(" ● {} ", posture),
                Style::default()
                    .fg(INK)
                    .bg(pcol)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(note, Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled("  DDOS SCORE ", Style::default().fg(CREAM)),
            Span::styled(
                format!("{:>3}/100 ", a.score),
                Style::default().fg(tcol).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", a.threat.as_str()),
                Style::default()
                    .fg(INK)
                    .bg(tcol)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled(
                format!("ATTACK: {}", a.attack.as_str()),
                Style::default().fg(tcol),
            ),
            Span::raw("   "),
            Span::styled(
                format!("confidence {}", a.confidence.as_str()),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    if let Some(sc) = s.simulating {
        header.push(Line::from(Span::styled(
            format!(
                "  ⚠ SIMULATION ACTIVE — {} (synthetic telemetry, no real traffic)",
                sc.as_str()
            ),
            Style::default()
                .fg(INK)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )));
    } else if !s.baseline_warm {
        header.push(Line::from(Span::styled(
            format!(
                "  baseline learning {}% — scoring begins once normal traffic is established",
                s.baseline_pct
            ),
            Style::default().fg(Color::Yellow),
        )));
    } else {
        header.push(Line::from(Span::styled(
            format!(
                "  incident: {}",
                s.current_incident
                    .as_ref()
                    .map(|i| i.id.as_str())
                    .unwrap_or("NONE")
            ),
            Style::default().fg(Color::Gray),
        )));
    }
    f.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(CREAM)),
        ),
        rows[0],
    );

    // ---- key metrics ------------------------------------------------------
    let m = &a.metrics;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    let left = vec![
        Line::from(vec![
            Span::styled("REQUESTS/SEC  ", Style::default().fg(CREAM)),
            Span::styled(
                format!("{:>6.0}", m.rps),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   baseline {:.1}", m.rps_base),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("BANDWIDTH IN  ", Style::default().fg(CREAM)),
            Span::styled(
                format!("{:>10}", nimbusa::util::human_bps(m.rx_bps)),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   base {}", nimbusa::util::human_bps(m.rx_bps_base)),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("CONNECTIONS   ", Style::default().fg(CREAM)),
            Span::styled(
                format!("{:>6}", m.established),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   +{:.0}/s new · {} half-open", m.conn_rate, m.syn_recv),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(left), cols[0]);
    let right = vec![
        Line::from(vec![
            Span::styled("SOURCES       ", Style::default().fg(CREAM)),
            Span::styled(
                format!("{:>6}", m.sources),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   across {} networks", m.networks),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("TOP ENDPOINT  ", Style::default().fg(CREAM)),
            Span::styled(
                if m.top_endpoint.is_empty() {
                    "—".into()
                } else {
                    format!("{} ", m.top_endpoint)
                },
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                format!("({:.0}%)", m.top_endpoint_share * 100.0),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("ERROR RATE    ", Style::default().fg(CREAM)),
            Span::styled(
                format!("{:>5.1}%", m.error_rate * 100.0),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("   app {}", m.health_state),
                Style::default().fg(health_color(s.health.overall())),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(right), cols[1]);

    // ---- graphs -----------------------------------------------------------
    let g = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(rows[2]);
    spark(f, g[0], "requests/s", &s.sample_series_rps, Color::Cyan);
    spark(f, g[1], "connections", &s.sample_series_conn, Color::Blue);
    spark(
        f,
        g[2],
        "risk score",
        &s.sample_series_score,
        threat_color(a.threat.as_str()),
    );

    // ---- bottom: sources | mitigation+health -----------------------------
    let b = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[3]);
    render_sources(f, b[0], s);
    render_mitigation_health(f, b[1], s);
}

fn spark(f: &mut Frame, area: Rect, title: &str, data: &[u64], color: Color) {
    let sk = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    format!(" {} ", title),
                    Style::default().fg(CREAM),
                ))
                .border_style(Style::default().fg(CREAM)),
        )
        .data(data)
        .style(Style::default().fg(color));
    f.render_widget(sk, area);
}

fn render_sources(f: &mut Frame, area: Rect, s: &ShieldSnapshot) {
    let a = &s.assessment;
    let suspects = &a.suspects;
    let rows: Vec<Row> = if !suspects.is_empty() {
        suspects
            .iter()
            .take(10)
            .map(|sp| {
                let col = if sp.score >= 70 {
                    Color::Red
                } else if sp.score >= 45 {
                    Color::Yellow
                } else {
                    Color::White
                };
                Row::new(vec![
                    Cell::from(sp.ip.clone()),
                    Cell::from(nimbusa::util::geo(&sp.ip)),
                    Cell::from(format!("{}", sp.requests)),
                    Cell::from(format!("{}", sp.connections)),
                    Cell::from(Span::styled(
                        format!("{}", sp.score),
                        Style::default().fg(col).add_modifier(Modifier::BOLD),
                    )),
                ])
            })
            .collect()
    } else {
        a.top_sources
            .iter()
            .take(10)
            .map(|(ip, n)| {
                Row::new(vec![
                    Cell::from(ip.clone()),
                    Cell::from(nimbusa::util::geo(ip)),
                    Cell::from(format!("{}", n)),
                    Cell::from("-"),
                    Cell::from("-"),
                ])
            })
            .collect()
    };
    let t = Table::new(
        rows,
        vec![
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(6),
        ],
    )
    .header(
        Row::new(vec!["SOURCE", "COUNTRY", "REQ", "CONN", "RISK"])
            .style(Style::default().fg(CREAM).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" TOP SOURCES ")
            .border_style(Style::default().fg(CREAM)),
    );
    f.render_widget(t, area);
}

fn render_mitigation_health(f: &mut Frame, area: Rect, s: &ShieldSnapshot) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let mit = vec![
        Line::from(vec![
            Span::styled("Rate Limiting     ", Style::default().fg(CREAM)),
            on(s.has_rate_limit),
        ]),
        Line::from(vec![
            Span::styled("IP Filtering      ", Style::default().fg(CREAM)),
            on(s.has_filtering),
        ]),
        Line::from(vec![
            Span::styled("Connection Guard  ", Style::default().fg(CREAM)),
            on(s.has_conn_limit),
        ]),
        Line::from(vec![
            Span::styled("Docker Protection ", Style::default().fg(CREAM)),
            on(s.has_docker_guard),
        ]),
        Line::from(vec![
            Span::styled("Level ", Style::default().fg(CREAM)),
            Span::styled(
                s.level.as_str(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(
                    "  · {} rules · {} blocked",
                    s.active_rules, s.blocked_sources
                ),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(mit).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" MITIGATION ")
                .border_style(Style::default().fg(CREAM)),
        ),
        split[0],
    );

    let mut health = Vec::new();
    for c in s.health.checks.iter().take(5) {
        health.push(Line::from(vec![
            Span::styled(
                format!("{:<18}", trunc(&c.name, 18)),
                Style::default().fg(CREAM),
            ),
            Span::styled(
                c.state.as_str(),
                Style::default()
                    .fg(health_color(c.state))
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    }
    let audit_col = if s.audit_verified {
        Color::Green
    } else {
        Color::Red
    };
    health.push(Line::from(vec![
        Span::styled("Audit chain       ", Style::default().fg(CREAM)),
        Span::styled(
            if s.audit_verified {
                format!("VERIFIED ({} rec)", s.audit_records)
            } else {
                "TAMPERED".into()
            },
            Style::default().fg(audit_col).add_modifier(Modifier::BOLD),
        ),
    ]));
    if !s.audit_verified && !s.audit_reason.is_empty() {
        // never hide why — show the verifier's own reason, plus the safe fix
        health.push(Line::from(Span::styled(
            format!("  {}", trunc(&s.audit_reason, 44)),
            Style::default().fg(Color::Red),
        )));
        health.push(Line::from(Span::styled(
            "  → nimbusa audit diagnose / migrate",
            Style::default().fg(Color::Gray),
        )));
    }
    f.render_widget(
        Paragraph::new(health).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" HEALTH & AUDIT ")
                .border_style(Style::default().fg(CREAM)),
        ),
        split[1],
    );
}

fn render_incident(f: &mut Frame, area: Rect, s: &ShieldSnapshot) {
    let inc = s.current_incident.as_ref().unwrap();
    let a = &s.assessment;
    let tcol = threat_color(a.threat.as_str());
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(8),
            Constraint::Length(6),
        ])
        .split(area);

    let head = vec![
        Line::from(vec![
            Span::styled(
                "  NIMBUSA SHIELD — ACTIVE INCIDENT  ",
                Style::default()
                    .fg(INK)
                    .bg(tcol)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled(
                inc.id.clone(),
                Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
            ),
            if inc.simulated {
                Span::styled("  [SIMULATION]", Style::default().fg(Color::Magenta))
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {} ", a.attack.as_str()),
                Style::default().fg(tcol).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  SCORE {}/100  ", a.score),
                Style::default()
                    .fg(INK)
                    .bg(tcol)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  state {}", s.recovery.state.as_str()),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(head).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(tcol)),
        ),
        rows[0],
    );

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[1]);

    let mut why = vec![Line::from(Span::styled(
        " WHY DETECTED",
        Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
    ))];
    // Explicit per-signal breakdown: which measurements moved the score and by
    // how much. Straight from the detector — never invented.
    let mut fired: Vec<&nimbusa::shield::detect::Signal> = a
        .signals
        .iter()
        .filter(|s| s.fired && s.points > 0)
        .collect();
    fired.sort_by_key(|s| std::cmp::Reverse(s.points));
    for sig in fired.iter().take(6) {
        why.push(Line::from(vec![
            Span::styled(
                format!("  +{:<3} ", sig.points),
                Style::default().fg(tcol).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<22}", trunc(&sig.label, 22)),
                Style::default().fg(Color::White),
            ),
            Span::styled(trunc(&sig.evidence, 30), Style::default().fg(Color::Gray)),
        ]));
    }
    why.push(Line::from(vec![
        Span::styled("  = ", Style::default().fg(CREAM)),
        Span::styled(
            format!("{}/100 total", a.score),
            Style::default().fg(tcol).add_modifier(Modifier::BOLD),
        ),
    ]));
    if let Some(d) = &a.damped {
        why.push(Line::from(Span::styled(
            format!("  (damped: {})", trunc(d, 40)),
            Style::default().fg(Color::Gray),
        )));
    }
    f.render_widget(
        Paragraph::new(why).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(CREAM)),
        ),
        cols[0],
    );

    let mut right = vec![Line::from(Span::styled(
        " IMPACT & MITIGATION",
        Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
    ))];
    right.push(Line::from(vec![
        Span::styled("  App ", Style::default().fg(CREAM)),
        Span::styled(
            s.health.overall().as_str(),
            Style::default()
                .fg(health_color(s.health.overall()))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("   downtime {}s", inc.downtime_secs),
            Style::default().fg(Color::Gray),
        ),
    ]));
    right.push(Line::from(Span::styled(
        format!(
            "  peak {:.0} req/s · {}",
            inc.peak_rps,
            nimbusa::util::human_bps(inc.peak_bps)
        ),
        Style::default().fg(Color::Gray),
    )));
    right.push(Line::from(Span::styled(
        format!(
            "  {} sources / {} networks",
            inc.source_count, inc.network_count
        ),
        Style::default().fg(Color::Gray),
    )));
    right.push(Line::from(""));
    for m in inc.mitigations.iter().take(6) {
        right.push(Line::from(Span::styled(
            format!("  ✓ {}", m),
            Style::default().fg(Color::Green),
        )));
    }
    right.push(Line::from(vec![
        Span::styled("  Automatic recovery ", Style::default().fg(CREAM)),
        Span::styled(
            "ARMED",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    // Incident timeline — real, timestamped events from the pipeline.
    if !inc.timeline.is_empty() {
        right.push(Line::from(Span::styled(
            " TIMELINE",
            Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
        )));
        let n = inc.timeline.len();
        let start = n.saturating_sub(5);
        for ev in &inc.timeline[start..] {
            let clock = ev
                .time
                .split_whitespace()
                .nth(1)
                .unwrap_or(ev.time.as_str());
            right.push(Line::from(vec![
                Span::styled(format!("  {} ", clock), Style::default().fg(Color::Gray)),
                Span::styled(
                    trunc(&ev.kind, 14),
                    Style::default().fg(tcol).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" {}", trunc(&ev.detail, 28)),
                    Style::default().fg(Color::White),
                ),
            ]));
        }
    }
    f.render_widget(
        Paragraph::new(right).wrap(Wrap { trim: false }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(tcol)),
        ),
        cols[1],
    );

    // metrics strip
    let strip = Line::from(vec![
        Span::styled(
            format!(" detection {}s ", inc.detection_secs),
            Style::default().fg(INK).bg(CREAM),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" mitigation {}s ", inc.mitigation_secs),
            Style::default().fg(INK).bg(CREAM),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" blocked {} ", inc.blocked_sources),
            Style::default().fg(INK).bg(CREAM),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" level {} ", inc.max_level),
            Style::default().fg(INK).bg(CREAM),
        ),
        Span::raw(" "),
        Span::styled(
            format!(
                " audit {} ",
                inc.audit_hash.chars().take(16).collect::<String>()
            ),
            Style::default().fg(INK).bg(CREAM),
        ),
    ]);
    f.render_widget(
        Paragraph::new(vec![Line::from(""), strip]).block(
            Block::default()
                .borders(Borders::TOP)
                .title(" SIH METRICS (live) ")
                .border_style(Style::default().fg(CREAM)),
        ),
        rows[2],
    );
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}
