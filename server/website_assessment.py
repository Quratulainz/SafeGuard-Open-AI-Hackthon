"""Scoped public-page checks, separate from business or domain identity verification."""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from evidence_validation import current_risk_support


def comparable_url(value):
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('Use a public HTTP or HTTPS page URL without embedded credentials.')
    port = parts.port
    host = parts.hostname.lower().rstrip('.')
    if ':' in host:
        host = '[' + host + ']'
    if port and port != (443 if parts.scheme == 'https' else 80):
        host += ':' + str(port)
    return urlunsplit((parts.scheme.lower(), host, parts.path or '/', parts.query, ''))


def validate_page_context(context, value):
    if context is None:
        return None
    if not isinstance(context, dict) or context.get('source') != 'browser_visible_page':
        raise ValueError('Invalid browser page context.')
    if not isinstance(context.get('url'), str) or comparable_url(context['url']) != comparable_url(value):
        raise ValueError('The browser page context must match the URL being checked.')
    if not isinstance(context.get('text'), str) or len(context['text']) > 16000:
        raise ValueError('Browser page text must contain at most 16,000 characters.')
    if not isinstance(context.get('title'), str) or len(context['title']) > 300:
        raise ValueError('Browser page title must contain at most 300 characters.')
    if not isinstance(context.get('truncated'), bool):
        raise ValueError('Browser page context must declare whether text was truncated.')
    clean = {key: context[key] for key in ('url', 'title', 'text', 'truncated', 'source')}
    if 'forms' in context:
        forms = context['forms']
        if not isinstance(forms, list) or len(forms) > 20 or not isinstance(context.get('forms_truncated'), bool):
            raise ValueError('Browser form inspection must contain at most 20 destinations and a truncation flag.')
        clean['forms'] = []
        for form in forms:
            flags = ('has_password', 'has_otp', 'invalid_action', 'has_embedded_credentials')
            if (not isinstance(form, dict) or any(not isinstance(form.get(key), bool) for key in flags)
                    or form.get('method') not in ('get', 'post', 'dialog')
                    or not isinstance(form.get('action'), str) or len(form['action']) > 4096):
                raise ValueError('Invalid browser form metadata.')
            item = {key: form[key] for key in flags}
            item.update(method=form['method'], action='')
            if form['action']:
                try:
                    parsed = urlsplit(form['action'])
                    item['has_embedded_credentials'] |= bool(parsed.username or parsed.password)
                    if parsed.scheme not in ('https', 'http') or not parsed.hostname or item['has_embedded_credentials']:
                        raise ValueError('Invalid destination')
                    parsed.port  # Validate the port before retaining the address.
                    item['action'] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, '', ''))
                except ValueError:
                    item['invalid_action'] = True
            elif not item['invalid_action']:
                raise ValueError('A form destination is missing.')
            clean['forms'].append(item)
        clean['forms_truncated'] = context['forms_truncated']
    return clean


def _page_address(value):
    # The collector redacts query strings from persisted transport metadata.
    parts = urlsplit(comparable_url(value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))


def _readable(title, content):
    text = re.sub(r'\s+', ' ', content or '').strip()
    if len(text) < 80 or sum(c.isalpha() for c in text) < 40:
        return False
    challenge = r'just a moment|access denied|attention required|checking your browser|verify (?:that )?you are human|robot check'
    if re.search(challenge, title or '', re.I):
        return False
    if re.search(r'^(?:404\b|403\b|page not found\b|not found\b|security verification\b)', (title or '').strip(), re.I):
        return False
    if re.search(challenge + r'|enable javascript(?: and cookies)? to continue', text[:400], re.I):
        return False
    return True


def assess_website(result, records, context=None):
    """Green means no warning signs in usable current checks, never official identity."""
    retrieval = result.get('retrieval') or {}
    final_url = retrieval.get('final_url') or result.get('source') or ''
    support = current_risk_support(records)
    page_records = [r for r in records if r.get('evidence_type') in ('page_retrieval', 'browser_page_observation')]
    ids = [r['id'] for r in page_records]
    concerns, missing, limits = [], [], []
    try:
        target = urlsplit(final_url)
        host = (target.hostname or '').lower().rstrip('.')
    except ValueError:
        target, host = urlsplit(''), ''
    if target.scheme != 'https':
        concerns.append('The final page does not use HTTPS.')
    if retrieval.get('tls_verified') is not True:
        missing.append('A verified HTTPS connection to the final page could not be confirmed.')
    if retrieval.get('status') == 'BLOCKED':
        concerns.append('The page request or redirect was blocked by the network safety check.')
    for hop in retrieval.get('redirect_chain') or []:
        if hop.get('blocked'):
            concerns.append('A redirect to a non-public destination was blocked.')
        if urlsplit(hop.get('from', '')).scheme == 'https' and urlsplit(hop.get('to', '')).scheme == 'http':
            concerns.append('The redirect chain downgraded from HTTPS to HTTP.')
    try:
        ipaddress.ip_address(host)
        concerns.append('The address uses an IP literal instead of an identifiable domain name.')
    except ValueError:
        pass
    if host and (any(ord(c) > 127 for c in host) or any(label.startswith('xn--') for label in host.split('.'))):
        concerns.append('The internationalized domain name needs an independent address check.')

    browser_ok = bool(context and _page_address(context['url']) == _page_address(final_url)
                      and _readable(context['title'], context['text']))
    fetched_ok = (retrieval.get('status') == 'Fetched accessible HTML'
                  and _readable(result.get('page_title'), result.get('content_excerpt')))
    source = 'browser_visible_page' if browser_ok else 'public_html' if fetched_ok else 'none'
    if source == 'none':
        missing.append('The readable page was unavailable, too short, or replaced by an access challenge.')
    elif source == 'browser_visible_page':
        limits.append('Visible text was supplied by an explicit browser scan; this is not independent identity verification.')
    if (context.get('truncated') if browser_ok else result.get('content_truncated')):
        limits.append('Only a bounded portion of the page text was checked; unread content was not assessed.')

    features = context if browser_ok and 'forms' in context else result.get('page_features') or {}
    if browser_ok and 'forms' not in context and not fetched_ok:
        missing.append('Form destinations were not inspected; scan the current page with the updated extension.')
    for form in features.get('forms') or []:
        if not (form.get('has_password') or form.get('has_otp')):
            continue
        if form.get('has_embedded_credentials') or form.get('invalid_action'):
            concerns.append('A credential form has an invalid or credential-bearing submission address.')
        try:
            action = urlsplit(form.get('action') or final_url)
        except ValueError:
            concerns.append('A credential form has an invalid submission address.')
            continue
        try:
            other_origin = ((action.scheme, (action.hostname or '').lower().rstrip('.'), action.port or 443)
                            != (target.scheme, host, target.port or 443))
        except ValueError:
            concerns.append('A credential form has an invalid submission address.')
            continue
        if action.scheme != 'https':
            concerns.append('A credential form submits without HTTPS.')
        elif other_origin:
            concerns.append('A credential form submits to a different destination; verify that sign-in provider before continuing.')
    if features.get('forms_truncated'):
        missing.append('The form inspection limit was reached; not every submission target was checked.')
    if source == 'browser_visible_page':
        limits.append('Only form structure and submission addresses were inspected; form values were not collected.')
    ip_records = result.get('ip_reputation') or []
    if not ip_records or any(r.get('status') not in ('listed', 'not_listed') for r in ip_records):
        limits.append('IP reputation coverage is incomplete. The result is based on the available page checks.')
    limits.append('This is a limited page-risk check, not confirmation of an official business, safe download, or payment destination.')
    actual = [s for s in support if s['behavior'] != 'adverse_listing']
    listing = any(s['behavior'] == 'adverse_listing' for s in support)
    if actual or listing:
        state = 'concern'
    elif concerns:
        state = 'concern'
    elif missing:
        state = 'incomplete'
    else:
        state = 'checked'
    metadata = {'status': state, 'source': source, 'final_url': final_url,
                'identity_verified': False, 'concerns': list(dict.fromkeys(concerns)),
                'missing_checks': list(dict.fromkeys(missing)), 'scope': 'Current public-page risk signals only'}
    if actual or listing:
        return None, metadata  # Existing evidence-based concern/danger decision wins.
    if state == 'checked':
        summary = 'No obvious warning signs were found in the checked page.'
        reasons = ['The final page was reached over a verified HTTPS connection.',
                   'No explicit credential-sharing or upfront-payment request was found in the checked page text.']
        if retrieval.get('redirect_chain'):
            reasons.append('The checked destination is ' + host + '; the redirect path is recorded in the details.')
        risk, verdict, step = 'low', 'safe', 'Confirm the address before signing in, downloading software, or paying.'
    else:
        summary = ('The page has a specific issue to verify.' if concerns else
                   'Could not complete the page check. This is not evidence that the website is suspicious.')
        reasons = list(dict.fromkeys(concerns + missing))[:3]
        risk, verdict, step = ('caution' if concerns else 'unknown'), 'uncertain', (
            'Review the stated issue before entering sensitive information.' if concerns else
            'Open the page normally and use Scan this page in the extension to check its visible content.')
    return {'mode': 'rules', 'risk_level': risk, 'verdict': verdict,
            'verdict_label': 'Safe' if verdict == 'safe' else 'Uncertain', 'summary': summary,
            'reasons': [{'text': r, 'evidence_ids': ids, 'rule_id': 'current_website_check'} for r in reasons[:3]],
            'next_steps': [step], 'limitations': limits}, metadata
