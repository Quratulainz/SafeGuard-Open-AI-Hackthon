"""Bounded evidence investigation with real optional sponsor adapters."""
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import re
import urllib.parse
import uuid

from engine import assess, inspect_url
from evidence_validation import current_risk_support, decide_from_evidence
from integrations import analyze_evidence, query_domain_evidence
from investigation_memory import InvestigationMemory
from website_assessment import assess_website, validate_page_context


def _now():
    return datetime.now(timezone.utc).isoformat()


def _domain(kind, value):
    candidate = value if kind == 'url' else next(iter(re.findall(r'https?://[^\s<>]+', value)), '')
    if not candidate:
        return None
    try:
        return urllib.parse.urlsplit(candidate.rstrip('.,;!?\"\'' )).hostname
    except ValueError:
        return None


def _evidence(result, zetaris, recalled, *, message_text=None, page_context=None):
    records = []
    def add(source, observation, **extra):
        records.append({'id': 'E' + str(len(records) + 1), 'source': source,
                        'observation': observation, 'checked_at': result.get('checked_at'), **extra})
    context_id = None
    if message_text is not None:
        add('submitted_content', {
            'text': message_text[:8000], 'truncated': len(message_text) > 8000,
            'original_length': len(message_text),
        }, evidence_type='text_observation', independently_verified=False)
        context_id = records[-1]['id']
    for finding in result.get('findings', []):
        add('predefined_phrase_match', finding, evidence_type='keyword_signal', derived=True,
            independently_verified=False, requires_context=True, establishes_risk=False,
            **({'derived_from': [context_id]} if context_id else {}))
    if result.get('retrieval'):
        add(result.get('source') or 'public_html',
            {'retrieval': result['retrieval'], 'title': result.get('page_title'),
             'excerpt': result.get('content_excerpt', ''), 'truncated': result.get('content_truncated', False),
             'page_features': result.get('page_features', {})}, evidence_type='page_retrieval',
            independently_verified=False)
    if page_context:
        add('browser_visible_page', {'url': page_context['url'], 'title': page_context['title'],
            'excerpt': page_context['text'], 'truncated': page_context['truncated'],
            'page_features': {key: page_context[key] for key in ('forms', 'forms_truncated') if key in page_context},
            'retrieval': {'status': 'User-triggered visible page observation'}},
            evidence_type='browser_page_observation', independently_verified=False)
    for item in result.get('ip_reputation', []):
        add(item.get('source') or 'blackips', item, evidence_type='ip_reputation',
            checked_at=item.get('checked_at') or result.get('checked_at'))
    for row in zetaris.get('rows', [])[:30]:
        add(zetaris.get('dataset') or 'zetaris', row, evidence_type='zetaris_record',
            query_id=zetaris.get('query_id'), retrieved_at=zetaris.get('checked_at'))
    if zetaris.get('status') != 'not_applicable':
        add('zetaris_lookup_status', {k: zetaris.get(k) for k in ('status', 'domain', 'error', 'limitation')},
            evidence_type='tool_status', establishes_safety=False)
    context = recalled.get('context')
    if context:
        add('hmem_historical_context', str(context)[:10000], evidence_type='historical_memory',
            historical_only=True, new_verification=False)
    if not records:
        add('submitted_content', {'findings': [], 'limitation': 'No predefined phrases matched.'},
            evidence_type='text_observation', establishes_safety=False)
    return records


def investigate(kind, value, *, data_dir=None, page_context=None):
    """One collection pass, one schema-validation retry at most, explicit partial states."""
    if kind not in ('url', 'message'):
        raise ValueError('Choose url or message.')
    value = str(value or '').strip()
    if not value or len(value) > 30000:
        raise ValueError('Supply up to 30,000 characters.')
    if page_context is not None and kind != 'url':
        raise ValueError('Browser page context is only valid for a URL check.')
    page_context = validate_page_context(page_context, value)
    mode = (os.getenv('SAFEGUARD_ANALYSIS_MODE') or 'rules').strip().lower()
    domain_provider = (os.getenv('SAFEGUARD_DOMAIN_PROVIDER') or 'none').strip().lower()
    memory_mode = (os.getenv('SAFEGUARD_MEMORY_MODE') or 'local').strip().lower()
    if mode not in ('rules', 'model') or domain_provider not in ('none', 'zetaris') or memory_mode not in ('local', 'hmem'):
        raise ValueError('Invalid analysis, domain provider, or memory mode.')
    directory = Path(data_dir or os.getenv('SAFEGUARD_DATA_DIR') or Path(__file__).parent / 'local-data')
    directory.mkdir(parents=True, exist_ok=True)
    run_id = 'run-' + uuid.uuid4().hex[:12]
    trace = []
    def event(step, status, **details):
        trace.append(dict(timestamp=_now(), step=step, status=status, **details))

    domain = _domain(kind, value)
    event('plan', 'complete', analysis_mode=mode,
          checks=(['public_html', 'ip_reputation'] if kind == 'url' else ['submitted_text'])
          + (['zetaris_domain_evidence'] if domain and domain_provider == 'zetaris' else [])
          + (['hmem_recall'] if memory_mode == 'hmem' else [])
          + (['nightshift_analysis'] if mode == 'model' else ['current_evidence_rules']) + ['validate'])
    # URL safety errors are not swallowed into a successful assessment.
    result = inspect_url(value) if kind == 'url' else assess(value, 'message')
    event('collect_content', result.get('retrieval', {}).get('status', 'complete'),
          signal_count=len(result.get('findings', [])))
    memory = InvestigationMemory(data_dir=directory / 'hmem') if memory_mode == 'hmem' else None
    recalled = memory.recall(value[:2000], limit=4) if memory else {
        'provider': 'hmem', 'status': 'disabled', 'reason': 'local_history_mode', 'matches': [], 'context': ''}
    event('hmem_recall', recalled.get('status', 'unknown'),
          match_count=len(recalled.get('matches', [])))
    zetaris = query_domain_evidence(domain) if domain and domain_provider == 'zetaris' else {
        'provider': 'zetaris', 'status': 'disabled', 'checked_at': _now(),
        'reason': 'domain_provider_none'} if domain else {
        'provider': 'zetaris', 'status': 'not_applicable', 'checked_at': _now(),
        'limitation': 'No URL/domain supplied for an evidence lookup.'}
    event('zetaris_query', zetaris['status'], query_id=zetaris.get('query_id'),
          row_count=len(zetaris.get('rows', [])), error=zetaris.get('error'))
    records = _evidence(result, zetaris, recalled, message_text=value if kind == 'message' else None,
                        page_context=page_context)
    rules_decision = decide_from_evidence(records)
    decision = rules_decision
    website_decision, website_check = assess_website(result, records, page_context) if kind == 'url' else (None, None)
    if website_decision:
        decision = website_decision
    if website_check:
        result['website_check'] = website_check
    analysis = analyze_evidence(records, subject=value[:2000]) if mode == 'model' else {
        'provider': 'nightshift', 'status': 'disabled', 'reason': 'rules_mode', 'checked_at': _now()}
    event('nightshift_analysis' if mode == 'model' else 'current_evidence_rules', analysis['status'] if mode == 'model' else 'complete', requested_model=analysis.get('requested_model'),
          reported_model=analysis.get('model'), error=analysis.get('error'))
    attempts = 1 if mode == 'model' else 0
    if analysis.get('status') == 'invalid_response':
        event('validate', 'rejected', reason=analysis.get('error'))
        analysis = analyze_evidence(records, subject=value[:2000], feedback=analysis.get('error', 'invalid_analysis_schema'))
        attempts += 1
        event('nightshift_refinement', analysis['status'], reported_model=analysis.get('model'),
              error=analysis.get('error'))
    if analysis.get('semantic_validation'):
        semantic = analysis['semantic_validation']
        event('validate_risk_support', semantic['status'],
              model_risk_level=semantic.get('model_risk_level'),
              reason=semantic.get('reason'),
              supported_observations=len(semantic.get('supported_risk_observations', [])))

    gaps = []
    if domain and domain_provider == 'zetaris' and zetaris['status'] != 'online':
        gaps.append('Zetaris evidence could not be queried.')
    if domain and zetaris['status'] == 'online' and not zetaris.get('rows'):
        gaps.append('Zetaris returned no matching domain records; this does not establish safety.')
    if mode == 'model' and analysis['status'] != 'online':
        gaps.append('Optional model unavailable; local evidence rules were used.')
    if kind == 'url' and result.get('retrieval', {}).get('status') in ('NOT VERIFIED', 'BLOCKED'):
        gaps.append('Public HTML could not be retrieved or its redirect was blocked; available IP evidence is retained.')
    if kind == 'url' and (not result.get('ip_reputation') or any(
            item.get('status') not in ('listed', 'not_listed') for item in result.get('ip_reputation', []))):
        gaps.append('IP reputation evidence was unavailable for one or more destination addresses.')
    if memory and recalled.get('status') != 'ready':
        gaps.append('H-MEM recall was unavailable; no historical context was used.')
    result.update(run_id=run_id, analysis_mode=mode, evidence=records, zetaris=zetaris, ai_analysis=analysis,
                  memory_recall=recalled, trace=trace, completeness='partial' if gaps else 'complete',
                  validation={'gaps': gaps, 'model_attempts': attempts,
                              'scope': 'Checks response schema, evidence references, bounded current risk support and tool availability; not independent fact verification.'})
    result['keyword_risk_level'] = result.get('keyword_risk_level', result['risk_level'])
    result['risk_level'] = decision['risk_level']
    result['summary'] = decision['summary']
    result['next_steps'] = decision['next_steps']
    result['limitations'] = list(decision['limitations'])
    if analysis['status'] == 'online':
        result['summary'] = analysis['analysis']['summary']
        result['ai_risk_level'] = analysis['analysis']['risk_level']
        result['risk_level'] = result['ai_risk_level']
        result['next_steps'] = analysis['analysis']['next_steps']
        result['status'] = 'Evidence-assisted AI analysis; not an independent safety certification'
        result['limitations'].extend(analysis['analysis'].get('uncertainties', []))
        decision = {'mode': 'model', 'risk_level': result['risk_level'], 'summary': result['summary'],
                    'reasons': [{'text': claim['text'], 'evidence_ids': claim['evidence_ids'], 'rule_id': 'validated_model_claim'}
                                for claim in analysis['analysis'].get('claims', [])[:3]],
                    'next_steps': result['next_steps'][:2], 'limitations': result['limitations']}
    else:
        result['status'] = 'Current evidence rules; not a safety certification'
        if mode == 'model':
            decision['fallback_from'] = 'model'
    # Model uncertainty cannot erase completed positive page checks. Conversely,
    # incomplete/unsafe page checks cannot be upgraded by unsupported model copy.
    if website_decision and result['risk_level'] in ('unknown', 'low'):
        decision = website_decision
        result.update(risk_level=decision['risk_level'], summary=decision['summary'],
                      next_steps=decision['next_steps'], limitations=list(decision['limitations']))
    behavior_floor = bool(kind == 'url' and result['risk_level'] in ('unknown', 'low')
                          and rules_decision['risk_level'] in ('caution', 'elevated')
                          and any(item['behavior'] != 'adverse_listing' for item in current_risk_support(records)))
    if behavior_floor:
        decision = rules_decision
        result.update(risk_level=decision['risk_level'], summary=decision['summary'],
                      next_steps=decision['next_steps'], limitations=list(decision['limitations']))
    # The public result uses the reviewed AI conclusion when available. Retain
    # the raw keyword observation separately, and never let AI unknown erase a
    # current structured adverse listing from an independent source.
    listings = [item for item in current_risk_support(records)
                if item['behavior'] == 'adverse_listing']
    floor_applied = bool(listings) and result['risk_level'] == 'unknown'
    if floor_applied:
        result['risk_level'] = 'caution'
        result['summary'] += (' A current source reports an adverse listing, so the overall '
                              'assessment remains caution. A listing does not establish fraud.')
    result['risk_basis'] = {
        'primary': 'current_website_checks' if website_decision and decision is website_decision else
                   'current_evidence_rules' if behavior_floor else
                   'validated_ai' if analysis['status'] == 'online' else 'current_evidence_rules',
        'behavior_floor_applied': behavior_floor,
        'listing_floor_applied': floor_applied,
        'listed_evidence_ids': list(dict.fromkeys(item['evidence_id'] for item in listings)),
    }
    event('resolve_risk', result['risk_level'], **result['risk_basis'])
    decision.update(risk_level=result['risk_level'], summary=result['summary'])
    decision['verdict'] = {'low': 'safe', 'elevated': 'danger'}.get(result['risk_level'], 'uncertain')
    decision['verdict_label'] = {'safe': 'Safe', 'uncertain': 'Uncertain', 'danger': 'Danger'}[decision['verdict']]
    if floor_applied:
        decision['reasons'] = (decision['reasons'] + decide_from_evidence(records)['reasons'])[:3]
    result['decision'] = decision
    result['limitations'] = list(dict.fromkeys(result['limitations'] + gaps))
    written = memory.remember(value[:2000], result) if memory else {
        'provider': 'hmem', 'status': 'disabled', 'reason': 'local_history_mode'}
    result['memory_write'] = written
    event('hmem_store', written.get('status', 'unknown'))
    if memory and written.get('status') != 'stored':
        gap = 'This investigation could not be saved to H-MEM for later recall.'
        gaps.append(gap)
        result['limitations'].append(gap)
        result['completeness'] = 'partial'
    event('validate', 'partial' if gaps else 'complete', gaps=gaps, model_attempts=attempts)
    log_dir = directory / 'logs'
    log_dir.mkdir(exist_ok=True)
    # Operational trace only: no submitted content, source payloads or credentials.
    (log_dir / (run_id + '.jsonl')).write_text(
        '\n'.join(json.dumps(x, ensure_ascii=False) for x in trace) + '\n', encoding='utf-8')
    return result
