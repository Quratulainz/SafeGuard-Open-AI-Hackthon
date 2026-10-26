import re, html, json, ipaddress, socket, ssl, urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser
from datetime import datetime, timezone
from ip_reputation import is_public_global_ip, merge_ip_evidence, reputation_for_url
from evidence_validation import decide_from_evidence

PATTERNS = [
 ('upfront_fee',r'\b(registration fee|processing fee|activation fee|pay (?:a |the )?fee|security deposit|advance payment)\b','Requests an upfront fee',3),
 ('urgency',r'\b(within 24 hours|act now|limited time|immediately|urgent|today only|last chance)\b','Uses urgency or pressure',1),
 ('secret',r'\b(otp|one.time password|password|cvv|pin code|verification code)\b','Mentions sensitive credentials',2),
 ('guarantee',r'\b(guaranteed profit|100% guaranteed|risk.free investment|double your money)\b','Makes exceptional financial promises',3),
 ('off_platform',r'\b(telegram|whatsapp|gift card|crypto wallet|wire transfer)\b','References an off-platform contact or payment channel',1),
 ('trial',r'\b(free trial|auto.renew|recurring payment|billed monthly|subscription)\b','Mentions recurring billing or a trial',0),
]
MAX_HTML_BYTES = 1024 * 1024
MAX_VISIBLE_TEXT = 16000
MAX_FORMS = 20


def _structural_url(raw, base):
    """Resolve observed HTML metadata without fetching it or exposing URL secrets."""
    if not isinstance(raw, str) or len(raw) > 2048 or any(ord(char) < 32 for char in raw):
        return None, False, True
    try:
        value = urllib.parse.urlsplit(urllib.parse.urljoin(base or '', raw.strip()))
        embedded = value.username is not None or value.password is not None
        value.port
        invalid = value.scheme not in ('http', 'https') or not value.hostname
        if embedded or invalid:
            return None, embedded, True
        # Form URLs can carry CSRF tokens. Paths/origins are sufficient for
        # structural observations; query values and fragments are not returned.
        return urllib.parse.urlunsplit((value.scheme, value.netloc, value.path, '', '')), False, False
    except ValueError:
        return None, False, True


def _observed_url(value):
    """Return non-secret origin/path metadata, including for a rejected redirect."""
    try:
        parts = urllib.parse.urlsplit(value)
        netloc = parts.netloc.rsplit('@', 1)[-1]
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, '', ''))
    except ValueError:
        return None


class Extractor(HTMLParser):
    """Static HTML observations, not rendered visibility or proof a form is active."""
    VOID = {'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
    OTP = re.compile(r'(?:^|[^a-z])(?:otp|totp|one[-_ ]?time[-_ ]?code|verification[-_ ]?code|2fa[-_ ]?code|mfa[-_ ]?code)(?:$|[^a-z])', re.I)

    def __init__(self, document_url=None):
        super().__init__()
        self.text, self.title, self.stack = [], [], []
        self.document_url = document_url or ''
        self.base_url = self.document_url
        self.base_seen = self.base_invalid = self.base_credentials = False
        self.canonical_href = None
        self.forms, self.form_stack, self.form_ids, self.pending = [], [], {}, []
        self.submit_overrides = []
        self.forms_truncated = False
        self.has_password_inputs = self.has_otp_inputs = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        hidden = bool(self.stack and self.stack[-1][1]) or tag in ('script','style','noscript','template')
        hidden = hidden or 'hidden' in attrs or str(attrs.get('aria-hidden','')).lower() == 'true'
        hidden = hidden or bool(re.search(r'(?:display\s*:\s*none|visibility\s*:\s*hidden)', attrs.get('style') or '', re.I))
        if tag not in self.VOID:
            self.stack.append((tag, hidden))
        if tag == 'base' and not self.base_seen and attrs.get('href') is not None:
            self.base_seen = True
            value, self.base_credentials, self.base_invalid = _structural_url(attrs['href'], self.document_url)
            if value:
                self.base_url = value
        if tag == 'link' and self.canonical_href is None and 'canonical' in str(attrs.get('rel','')).lower().split():
            self.canonical_href = attrs.get('href')
        if tag == 'form':
            form = None
            if len(self.forms) < MAX_FORMS:
                method = str(attrs.get('method') or 'get').strip().lower()
                form = {'raw_action': attrs.get('action'), 'method': method if method in ('get','post','dialog') else 'get',
                        'has_password': False, 'has_otp': False, 'hidden': hidden,
                        'has_visible_password': False, 'has_visible_otp': False}
                self.forms.append(form)
                if attrs.get('id'):
                    self.form_ids[attrs['id']] = form
            else:
                self.forms_truncated = True
            self.form_stack.append(form)
        if tag in ('input', 'button') and attrs.get('formaction') is not None:
            kind = str(attrs.get('type') or ('submit' if tag == 'button' else 'text')).lower()
            if kind in ('submit', 'image'):
                owner = attrs.get('form') or (self.form_stack[-1] if self.form_stack else None)
                if len(self.submit_overrides) < 200:
                    self.submit_overrides.append((owner, attrs['formaction'], attrs.get('formmethod')))
                else:
                    self.forms_truncated = True
        if tag in ('input','textarea','select'):
            # Never retain or inspect the value attribute. Only control metadata
            # identifies password/OTP fields; no entered values leave the parser.
            kind = str(attrs.get('type') or '').lower()
            autocomplete = str(attrs.get('autocomplete') or '').lower().split()
            password = tag == 'input' and (kind == 'password' or any(x in autocomplete for x in ('current-password','new-password')))
            otp = 'one-time-code' in autocomplete or bool(self.OTP.search(' '.join(str(attrs.get(k) or '') for k in ('name','id'))))
            self.has_password_inputs |= password
            self.has_otp_inputs |= otp
            if not (password or otp):
                return
            if attrs.get('form'):
                if len(self.pending) < 200:
                    self.pending.append((attrs['form'], password, otp, hidden or kind == 'hidden'))
                else:
                    self.forms_truncated = True
            elif self.form_stack and self.form_stack[-1] is not None:
                self._mark(self.form_stack[-1], password, otp, hidden or kind == 'hidden')

    @staticmethod
    def _mark(form, password, otp, hidden):
        hidden = hidden or form['hidden']
        form['has_password'] |= password
        form['has_otp'] |= otp
        form['has_visible_password'] |= password and not hidden
        form['has_visible_otp'] |= otp and not hidden

    def handle_startendtag(self, tag, attributes):
        self.handle_starttag(tag, attributes)
        if tag not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == 'form' and self.form_stack:
            self.form_stack.pop()
        for index in range(len(self.stack)-1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if not self.stack or not self.stack[-1][1]:
            self.text.append(data)
            if any(tag == 'title' for tag, _ in self.stack):
                self.title.append(data)

    def features(self):
        for identity, password, otp, hidden in self.pending:
            if identity in self.form_ids:
                self._mark(self.form_ids[identity], password, otp, hidden)
        observations = list(self.forms)
        for owner, action, method in self.submit_overrides:
            form = self.form_ids.get(owner) if isinstance(owner, str) else owner
            if form is not None:
                variant = dict(form, raw_action=action, submit_override=True)
                if str(method or '').lower() in ('get', 'post', 'dialog'):
                    variant['method'] = method.lower()
                observations.append(variant)
        self.forms_truncated |= len(observations) > MAX_FORMS
        forms = []
        for observed in observations[:MAX_FORMS]:
            raw = observed['raw_action']
            action, embedded, invalid = _structural_url(self.document_url if not raw else raw,
                                                       self.base_url)
            if raw and not re.match(r'^[a-z][a-z0-9+.-]*:', raw.strip(), re.I) and not raw.startswith('//'):
                embedded |= self.base_credentials
                invalid |= self.base_invalid
            forms.append({key: value for key, value in observed.items() if key != 'raw_action'} |
                         {'action': action if not invalid else None, 'has_embedded_credentials': embedded,
                          'invalid_action': invalid})
        canonical, embedded, invalid = _structural_url(self.canonical_href, self.base_url)
        if self.canonical_href and not re.match(r'^[a-z][a-z0-9+.-]*:', self.canonical_href.strip(), re.I) and not self.canonical_href.startswith('//'):
            embedded |= self.base_credentials
            invalid |= self.base_invalid
            if invalid:
                canonical = None
        return {'forms': forms, 'forms_truncated': self.forms_truncated, 'canonical_url': canonical,
                'canonical_has_embedded_credentials': embedded,
                'canonical_invalid': invalid if self.canonical_href is not None else False,
                'base_url': _structural_url(self.base_url, self.document_url)[0],
                'base_invalid': self.base_invalid, 'has_password_inputs': self.has_password_inputs,
                'has_otp_inputs': self.has_otp_inputs, 'structure_only': True,
                'visibility_scope': 'Static HTML; external CSS and JavaScript are not evaluated.',
                'metadata_url_queries_removed': True}

def signals(text):
 out=[]
 for key,p,label,weight in PATTERNS:
  m=re.search(p,text,re.I)
  if m:out.append({'id':key,'finding':label,'observed':m.group(0),'weight':weight})
 return out

def assess(text,kind='message',source=None):
 text=(text or '')[:30000]
 sig=signals(text);risk=sum(x['weight'] for x in sig)
 level='elevated' if risk>=4 else 'caution' if risk>=2 else 'unknown'
 decision=decide_from_evidence([{'id':'E1','source':'submitted_content' if kind=='message' else 'public_html','evidence_type':'text_observation','observation':{'text':text[:8000],'truncated':len(text)>8000}}])
 return {'kind':kind,'source':source,'status':'Local evidence rules — NOT independently verified','risk_level':decision['risk_level'],
 'keyword_risk_level':level,'decision':decision,'summary':decision['summary'],
 'findings':sig, 'verified_facts':[], 'limitations':['Keyword observations do not prove fraud or legitimacy.','No authoritative company registration, transaction or identity verification was performed.'],
 'next_steps':decision['next_steps'],
 'checked_at':datetime.now(timezone.utc).isoformat()}

class UnsafeUrlError(ValueError):
 pass

def safe_url(raw):
 if any(ord(char)<32 for char in raw):raise UnsafeUrlError('Control characters are not allowed in URLs.')
 p=urllib.parse.urlsplit(raw.strip())
 if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:raise UnsafeUrlError('Enter a public http(s) URL without embedded credentials.')
 host=p.hostname.lower().rstrip('.')
 if host in ('localhost',) or host.endswith(('.localhost','.local','.internal')):raise UnsafeUrlError('Local addresses are not allowed.')
 infos=socket.getaddrinfo(host,p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)
 if not infos:raise UnsafeUrlError('No public destination address was found.')
 for info in infos:
  ip=ipaddress.ip_address(info[4][0]);
  if not is_public_global_ip(ip):raise UnsafeUrlError('Private, reserved, or local network URLs are blocked.')
 return p.geturl()

class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.chain = []
        self.last_response = None
        self.last_target = None

    def redirect_request(self,req,fp,code,msg,headers,newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        entry = {'from': _observed_url(req.full_url), 'to': _observed_url(target), 'status': code}
        self.last_response = {'final_url': _observed_url(req.full_url), 'http_status': code,
                              'tls_verified': urllib.parse.urlsplit(req.full_url).scheme == 'https'}
        try:
            normalized = safe_url(target)
        except (ValueError, OSError):
            entry['blocked'] = True
            self.chain.append(entry)
            raise
        self.chain.append(entry)
        self.last_target = normalized
        return super().redirect_request(req,fp,code,msg,headers,normalized)

def inspect_url(url):
    # Safety validation stays ahead of HTTP and applies to every redirect hop.
    retrieval = {'status': 'NOT VERIFIED', 'final_url': None, 'http_status': None,
                 'tls_verified': False, 'redirect_chain': [], 'byte_truncated': False,
                 'text_truncated': False}
    try:
        normalized = safe_url(url)
    except OSError as error:
        result = assess(url, 'url', source=url)
        retrieval.update(error_type=type(error).__name__, error='The public destination could not be resolved.')
        result.update(retrieval=retrieval, content_excerpt='', content_truncated=False,
                      page_features={'forms': [], 'canonical_url': None, 'structure_only': True})
        result['limitations'].append('Page could not be fetched; only URL text was analyzed.')
        return merge_ip_evidence(result, [])

    def host(value):
        return (urllib.parse.urlsplit(value).hostname or '').lower().rstrip('.')

    def ip_lookup(value, role):
        try:
            return [dict(row, queried_host=host(value), queried_url=_observed_url(value), destination_role=role)
                    for row in reputation_for_url(value)]
        except Exception:
            return []

    ip_records = ip_lookup(normalized, 'initial')
    redirect = RestrictedRedirect()
    retrieval['redirect_chain'] = redirect.chain
    final_lookup_done = False

    def record_response(response, status=None):
        nonlocal final_lookup_done, ip_records
        final_url = response.geturl()
        expected_url = redirect.last_target or normalized
        if final_url != expected_url:
            # Defensive check for a response handler returning an unexpected URL.
            safe_url(final_url)
        status = status if status is not None else getattr(response, 'status', None)
        if type(status) is not int:
            status = response.getcode()
        retrieval.update(final_url=_observed_url(final_url), http_status=status,
                         tls_verified=urllib.parse.urlsplit(final_url).scheme == 'https')
        if not final_lookup_done:
            if host(final_url) == host(normalized):
                ip_records = [dict(row, destination_role='initial_and_final') for row in ip_records]
            else:
                ip_records.extend(ip_lookup(final_url, 'final'))
            final_lookup_done = True

    result = assess(normalized, 'url', source=normalized)
    result.update(content_excerpt='', content_truncated=False,
                  page_features={'forms': [], 'canonical_url': None, 'structure_only': True})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirect,
                    urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request(normalized, headers={
            'User-Agent': 'SafeGuardAI-ResearchPrototype/0.2', 'Accept': 'text/html,application/xhtml+xml'})
        with opener.open(request, timeout=7) as response:
            record_response(response)
            content_type = response.headers.get('Content-Type', '').lower()
            if not any(kind in content_type for kind in ('text/html', 'application/xhtml+xml')):
                raise ValueError('Only HTML pages can be inspected.')
            payload = response.read(MAX_HTML_BYTES + 1)
            retrieval['byte_truncated'] = len(payload) > MAX_HTML_BYTES
            charset = response.headers.get_content_charset() or 'utf-8'
            try:
                page = payload[:MAX_HTML_BYTES].decode(charset, errors='replace')
            except LookupError:
                page = payload[:MAX_HTML_BYTES].decode('utf-8', errors='replace')
            parser = Extractor(response.geturl())
            parser.feed(page)
            parser.close()
            visible = ' '.join(' '.join(parser.text).split())
            excerpt = visible[:MAX_VISIBLE_TEXT]
            retrieval.update(status='Fetched accessible HTML', text_truncated=len(visible) > MAX_VISIBLE_TEXT,
                             limited_to='Static public HTML; no payment, session, login or rendered JavaScript evidence.')
            result = assess(excerpt, 'url', source=retrieval['final_url'])
            result.update(page_title=' '.join(' '.join(parser.title).split())[:200],
                          content_excerpt=excerpt, content_truncated=retrieval['byte_truncated'] or retrieval['text_truncated'],
                          page_features=parser.features())
    except urllib.error.HTTPError as error:
        try:
            record_response(error, error.code)
        except (ValueError, OSError) as validation_error:
            retrieval.update(status='BLOCKED', error_type=type(validation_error).__name__,
                             error='The response destination could not be validated.')
        else:
            retrieval.update(status='NOT VERIFIED', error_type='HTTPError',
                             error='The server returned an HTTP error or access challenge; page content was not verified.')
        finally:
            error.close()
    except Exception as error:
        blocked = isinstance(error, UnsafeUrlError)
        if not retrieval['final_url'] and redirect.last_response:
            retrieval.update(redirect.last_response)
        if isinstance(error, ssl.SSLError) or isinstance(getattr(error, 'reason', None), ssl.SSLError):
            retrieval['tls_verified'] = False
        retrieval.update(status='BLOCKED' if blocked else 'NOT VERIFIED', error_type=type(error).__name__,
                         error='A redirect to a non-public destination was blocked.' if blocked else 'Public HTML retrieval failed.')
    if retrieval['status'] != 'Fetched accessible HTML':
        result['limitations'].append('Page content was not verified. Available IP evidence was retained.')
    if retrieval['byte_truncated'] or retrieval['text_truncated']:
        result['content_truncated'] = True
        result['limitations'].append('Only a bounded excerpt of the public page was retained.')
    result['retrieval'] = retrieval
    return merge_ip_evidence(result, ip_records)
