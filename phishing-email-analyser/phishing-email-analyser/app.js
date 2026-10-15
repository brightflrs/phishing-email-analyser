/*
 * Phishing Email Analyser - page controller
 *
 * This file connects the buttons and text box on the page to the analysis engine (analyser.js).
 * It builds the results using safe DOM methods (createElement and textContent), so
 * pasted email text is shown as plain text and can never run as code on the page.
 * It makes no network requests.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var engine = window.PhishingAnalyser;

  // Small helper to build elements safely.
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'className') { node.className = attrs[k]; }
        else if (k === 'text') { node.textContent = attrs[k]; }
        else { node.setAttribute(k, attrs[k]); }
      });
    }
    (children || []).forEach(function (c) {
      if (c === null || c === undefined) { return; }
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  var BAND_MESSAGES = {
    high: 'Several strong warning signs were found. Treat this email as dangerous and do not interact with it.',
    suspicious: 'Some warning signs were found. Treat this email as unverified until you have checked it another way.',
    low: 'Few or no warning signs were found. This is not a guarantee that the email is safe.'
  };

  // ---------------------------------------------------------------------------
  // Setup
  // ---------------------------------------------------------------------------

  function setupSamples() {
    var select = $('sample-select');
    SAMPLE_EMAILS.forEach(function (s) {
      select.appendChild(el('option', { value: s.id, text: s.name }));
    });
    updateSampleSummary();
    select.addEventListener('change', updateSampleSummary);
    $('load-sample').addEventListener('click', function () {
      var s = findSample(select.value);
      if (!s) { return; }
      $('email-input').value = s.text;
      updateCount();
      hideMessage();
      analyse();
    });
  }

  function findSample(id) {
    return SAMPLE_EMAILS.filter(function (s) { return s.id === id; })[0];
  }

  function updateSampleSummary() {
    var s = findSample($('sample-select').value);
    $('sample-summary').textContent = s ? s.summary : '';
  }

  function buildRulesTable() {
    var tbody = $('rules-body');
    engine.ruleCatalogue().forEach(function (r) {
      var pts = r.points > 0 ? '+' + r.points : String(r.points);
      tbody.appendChild(el('tr', {}, [
        el('td', { text: r.title }),
        el('td', { className: 'num ' + (r.points < 0 ? 'pts-neg' : 'pts-pos'), text: pts }),
        el('td', { className: 'muted', text: r.description })
      ]));
    });
  }

  function updateCount() {
    var n = $('email-input').value.length;
    $('char-count').textContent = n.toLocaleString() + ' character' + (n === 1 ? '' : 's');
  }

  function showMessage(text) {
    var m = $('form-message');
    m.textContent = text;
    m.hidden = false;
  }

  function hideMessage() {
    $('form-message').hidden = true;
  }

  // ---------------------------------------------------------------------------
  // Results rendering
  // ---------------------------------------------------------------------------

  function buildGauge(score, bandKey) {
    var r = 52;
    var circ = 2 * Math.PI * r;
    var svgNS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', '0 0 120 120');
    svg.setAttribute('class', 'gauge-svg');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Risk score ' + score + ' out of 100');

    var track = document.createElementNS(svgNS, 'circle');
    track.setAttribute('cx', '60'); track.setAttribute('cy', '60'); track.setAttribute('r', String(r));
    track.setAttribute('class', 'gauge-track');
    svg.appendChild(track);

    var arc = document.createElementNS(svgNS, 'circle');
    arc.setAttribute('cx', '60'); arc.setAttribute('cy', '60'); arc.setAttribute('r', String(r));
    arc.setAttribute('class', 'gauge-arc gauge-' + bandKey);
    arc.setAttribute('stroke-dasharray', circ.toFixed(2));
    arc.setAttribute('stroke-dashoffset', circ.toFixed(2));
    arc.setAttribute('transform', 'rotate(-90 60 60)');
    svg.appendChild(arc);

    // Animate to the final value after the element is in the page
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        arc.setAttribute('stroke-dashoffset', (circ * (1 - score / 100)).toFixed(2));
      });
    });
    return svg;
  }

  function sectionTitle(text) {
    return el('h3', { className: 'result-title', text: text });
  }

  function renderFindingCard(f, kind) {
    var badgeText = (f.points > 0 ? '+' : '') + f.points;
    var children = [
      el('div', { className: 'finding-head' }, [
        el('span', { className: 'points ' + (kind === 'reassure' ? 'pts-neg' : 'pts-pos'), text: badgeText }),
        el('span', { className: 'finding-title', text: f.title })
      ]),
      el('p', { className: 'finding-explain muted', text: f.explanation })
    ];
    if (f.evidence && f.evidence.length) {
      var list = el('ul', { className: 'evidence' });
      f.evidence.forEach(function (e) { list.appendChild(el('li', { text: e })); });
      if (f.moreCount) {
        list.appendChild(el('li', { className: 'muted', text: '+' + f.moreCount + ' more similar' }));
      }
      children.push(list);
    }
    return el('div', { className: 'finding ' + (kind === 'reassure' ? 'finding-reassure' : '') }, children);
  }

  function renderResults(result) {
    var body = $('results-body');
    clear(body);

    // Hero: gauge + classification
    var hero = el('div', { className: 'result-hero band-' + result.band.key }, [
      el('div', { className: 'gauge' }, [
        buildGauge(result.score, result.band.key),
        el('div', { className: 'gauge-center' }, [
          el('span', { className: 'gauge-score', text: String(result.score) }),
          el('span', { className: 'gauge-of', text: 'out of 100' })
        ])
      ]),
      el('div', { className: 'result-summary' }, [
        el('span', { className: 'band-pill band-pill-' + result.band.key, text: result.band.label }),
        el('h2', { className: 'result-headline', text: 'Phishing risk score: ' + result.score + ' / 100' }),
        el('p', { className: 'muted', text: BAND_MESSAGES[result.band.key] })
      ])
    ]);
    body.appendChild(hero);

    // Score arithmetic (so nothing feels like a mystery number)
    var parts = result.findings.map(function (f) { return '+' + f.points; })
      .concat(result.reassurance.map(function (f) { return String(f.points); }));
    var math = parts.length
      ? 'How this was calculated: ' + parts.join(' ') + ' = ' + result.rawTotal +
        (result.rawTotal > 100 ? ', capped at 100.' : (result.rawTotal < 0 ? ', floored at 0.' : '.'))
      : 'How this was calculated: no warning signs were found, so the score is 0.';
    body.appendChild(el('p', { className: 'math small muted', text: math }));

    // Warning signs
    body.appendChild(sectionTitle('Why you received this score'));
    if (result.findings.length === 0) {
      body.appendChild(el('p', { className: 'muted', text: 'No warning signs from the rules in this tool were detected.' }));
    } else {
      var fl = el('div', { className: 'findings' });
      result.findings.forEach(function (f) { fl.appendChild(renderFindingCard(f, 'warn')); });
      body.appendChild(fl);
    }

    // Reassuring signs
    if (result.reassurance.length) {
      body.appendChild(sectionTitle('Reassuring signs (these lowered the score)'));
      var rl = el('div', { className: 'findings' });
      result.reassurance.forEach(function (f) { rl.appendChild(renderFindingCard(f, 'reassure')); });
      body.appendChild(rl);
    }

    // Links
    if (result.links.length) {
      body.appendChild(sectionTitle('Links found (not opened)'));
      var tbl = el('div', { className: 'table-wrap' }, [
        el('table', { className: 'links-table' }, [
          el('thead', {}, [el('tr', {}, [
            el('th', { text: 'Destination' }), el('th', { text: 'Shown text' }), el('th', { text: 'Flags' })
          ])]),
          el('tbody', {}, result.links.map(function (l) {
            return el('tr', {}, [
              el('td', { className: 'mono', text: l.host || '(unknown)' }),
              el('td', { text: l.shown ? l.shown : (l.source === 'text' ? '(plain link in text)' : '') }),
              el('td', {}, [l.flags.length
                ? el('ul', { className: 'flags' }, l.flags.map(function (f) { return el('li', { text: f }); }))
                : el('span', { className: 'muted', text: 'None' })])
            ]);
          }))
        ])
      ]);
      body.appendChild(tbl);
    }

    // Attachments
    if (result.attachments.length) {
      body.appendChild(sectionTitle('Attachment names found in the text'));
      var al = el('ul', { className: 'evidence' });
      result.attachments.forEach(function (a) { al.appendChild(el('li', { className: 'mono', text: a })); });
      body.appendChild(al);
    }

    // Header summary
    if (result.headerSummary) {
      body.appendChild(sectionTitle('Sender checks from pasted headers'));
      var hs = result.headerSummary;
      var rows = [
        ['From address', hs.from], ['Reply-To address', hs.replyTo], ['Return-Path address', hs.returnPath],
        ['SPF result', hs.spf], ['DKIM result', hs.dkim], ['DMARC result', hs.dmarc]
      ];
      body.appendChild(el('div', { className: 'table-wrap' }, [
        el('table', { className: 'kv-table' }, [el('tbody', {}, rows.map(function (r) {
          return el('tr', {}, [el('th', { text: r[0] }), el('td', { className: 'mono', text: r[1] })]);
        }))])
      ]));
    }

    // Notes
    if (result.notes.length) {
      body.appendChild(sectionTitle('Notes'));
      var nl = el('ul', { className: 'notes' });
      result.notes.forEach(function (n) { nl.appendChild(el('li', { text: n })); });
      body.appendChild(nl);
    }

    // Recommendations
    body.appendChild(sectionTitle('What you should do next'));
    var rec = el('ol', { className: 'recs' });
    result.recommendations.forEach(function (r) { rec.appendChild(el('li', { text: r })); });
    body.appendChild(rec);

    body.appendChild(el('p', { className: 'disclaimer small muted', text:
      'Reminder: this is an educational triage tool. It identifies warning signs and cannot determine whether this email is malicious. Verify important messages using official channels.' }));

    $('results-empty').hidden = true;
    body.hidden = false;
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  function analyse() {
    var text = $('email-input').value;
    if (!text.trim()) {
      showMessage('Please paste an email first, or load one of the fictional examples.');
      $('email-input').focus();
      return;
    }
    hideMessage();
    var result = engine.analyseEmail(text);
    renderResults(result);
    if (window.innerWidth < 900) {
      $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function clearAll() {
    $('email-input').value = '';
    updateCount();
    hideMessage();
    clear($('results-body'));
    $('results-body').hidden = true;
    $('results-empty').hidden = false;
    $('email-input').focus();
  }

  function init() {
    if (!engine || typeof SAMPLE_EMAILS === 'undefined') {
      document.body.insertBefore(
        el('p', { className: 'form-message', text: 'The analysis files did not load. Please refresh the page.' }),
        document.body.firstChild
      );
      return;
    }
    setupSamples();
    buildRulesTable();
    updateCount();
    $('email-input').addEventListener('input', function () { updateCount(); hideMessage(); });
    $('analyse-btn').addEventListener('click', analyse);
    $('clear-btn').addEventListener('click', clearAll);
    $('email-input').addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { analyse(); }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
