"""Bounded support checks for risk conclusions; absence is unknown, never safe.

The model still analyzes the evidence. This guard prevents a phrase match,
missing lookup, historical result, or a warning against an action from being
the sole basis of a raised risk indicator. It is not a general fraud detector
or a complete natural-language entailment checker.
"""
import re
from datetime import datetime, timezone


CREDENTIAL = re.compile(
    r"\b(?:otp|one[ -]time password|password|passcode|verification code|security code|"
    r"pin(?: code)?|cvv|cvc|recovery phrase|seed phrase|private key|2fa code|authentication code)\b"
    r"|验证码|动态口令|一次性密码|密码|安全码|助记词|私钥", re.I)
DISCLOSE = re.compile(
    r"\b(?:send|share|give|provide|disclose|reveal|forward|submit|upload|email|text|tell|"
    r"read out|reply with|need|require|want|ask for)\b"
    r"|发送|发给|发来|发到|提供|透露|分享|告诉|转发|提交|告知|报给|报出|交出|需要|索取", re.I)
ENTER = re.compile(r"\b(?:enter|type|paste)\b|输入|填写|粘贴", re.I)
PAY = re.compile(r"\b(?:pay|transfer|wire|purchase|buy|send)\b|转账|汇款|支付|缴纳|交纳|充值|购买|付款|付费|交(?=\s*(?:押金|保证金|手续费))", re.I)
PAY_TARGET = re.compile(
    r"\b(?:fee|deposit|advance payment|money|funds|gift cards?|crypto(?:currency)?|bitcoin|wallet)\b"
    r"|费用|手续费|注册费|保证金|押金|礼品卡|加密货币|比特币|钱包|款项|转账", re.I)
UPFRONT = re.compile(r'\b(?:registration fee|processing fee|activation fee|advance payment)\b|(?:deposit|fee).{0,55}(?:before|unlock|job|interview|prize|withdraw)|(?:before|unlock|job|interview|prize|withdraw).{0,55}(?:deposit|fee)|(?:保证金|押金|手续费|注册费).{0,35}(?:入职|工作|领奖|退款|提现|解冻|才能)|(?:入职|领奖|提现|解冻).{0,35}(?:保证金|押金|费用)', re.I)
IRREVERSIBLE = re.compile(r'\b(?:gift cards?|crypto(?:currency)?|bitcoin|wallet)\b|礼品卡|加密货币|比特币|钱包', re.I)
PROMISE = re.compile(
    r"\b(?:guaranteed profit|risk[ -]free investment|double your money|100% guaranteed)\b"
    r"|稳赚不赔|保证收益|保证盈利|保本高收益|收益翻倍", re.I)
PRESSURE = re.compile(r"\b(?:act now|immediately|urgent|last chance|account.{0,20}(?:closed|suspended))\b|立即|马上|最后机会|账户.{0,10}(?:冻结|关闭)", re.I)
ACT = re.compile(r"\b(?:click|install|download|pay|transfer|send)\b|点击|安装|下载|转账|发送", re.I)
EN_NEGATION = re.compile(
    r"(?:\b(?:never|avoid|refuse|stop|without)|\bdo not|\bdon['’]t|\bmust not|\bshould not|"
    r"\bwill not|\bwon['’]t|\bcannot|\bcan['’]t|\bnot to|\bno need to|\bnot asking|\bnot requesting)"
    r"(?:\s+(?!(?:but|however|and)\b)[a-z'’-]+){0,6}\s*$", re.I)
ZH_NEGATION = re.compile(r"(?:不要|不能|不可|不得|别|切勿|无需|不用|不必|不|从不|绝不|不会|禁止|避免|拒绝)[^，。！？；]{0,9}$")
CLAUSE_SPLIT = re.compile(
    r"[.!?;\n。！？；]+|\b(?:but|however|instead|nevertheless|yet)\b|但是|然而|而是|不过|但|却|"
    r"[,，]\s*(?=(?:please\s+)?(?:send|give|share|provide)\s+(?:me|us)\b)|"
    r"\band\s+(?=(?:send|give|share|provide)\s+(?:me|us)\b)", re.I)
REPORTING = re.compile(r"\b(?:scammers?|fraudsters?|phishing examples?)\b|\bbeware of (?:anyone|people) who\b|骗子|诈骗者|诈骗示例|骗局示例", re.I)


def _negated(clause, start):
    prefix = clause[:start]
    return bool(EN_NEGATION.search(prefix[-100:]) or ZH_NEGATION.search(prefix[-22:]))


def _behavior_support(text):
    """Inspect each action locally; a prohibition never immunizes a later clause."""
    signals = []
    credential_context = bool(CREDENTIAL.search(text))
    for raw in CLAUSE_SPLIT.split(text):
        clause = raw.strip()
        if not clause:
            continue
        # A descriptive example about what scammers ask is not itself a request.
        # A later imperative after a contrast is checked independently.
        reporting = bool(REPORTING.search(clause))
        secret = bool(CREDENTIAL.search(clause))
        pronoun = credential_context and bool(re.search(
            r"\b(?:send|give|share|provide)\b.{0,35}\b(?:it|them|code)\b|把(?:它|该码|代码).{0,8}(?:给我|发来)", clause, re.I))
        if (secret or pronoun) and not reporting:
            for action in DISCLOSE.finditer(clause):
                # "passwords need protection" describes a need, not a demand
                # for a credential; request verbs must govern the credential.
                if action.group().lower() in ('need', 'require', 'want', 'ask for', '需要', '索取'):
                    if not CREDENTIAL.search(clause[action.end():]):
                        continue
                if not _negated(clause, action.start()):
                    signals.append(('credential_disclosure_request', clause))
                    break
            if re.search(r"\b(?:link|form|here)\b|链接|表单|这里", clause, re.I):
                for action in ENTER.finditer(clause):
                    if not _negated(clause, action.start()):
                        signals.append(('credential_entry_request', clause))
                        break
        if PAY_TARGET.search(clause) and not reporting and (UPFRONT.search(clause) or IRREVERSIBLE.search(clause)):
            for action in PAY.finditer(clause):
                if not _negated(clause, action.start()):
                    signals.append(('upfront_payment_request' if UPFRONT.search(clause) else 'payment_request', clause))
                    break
        for promise in PROMISE.finditer(clause):
            if not reporting and not _negated(clause, promise.start()):
                signals.append(('exceptional_financial_promise', clause))
        if PRESSURE.search(clause) and not reporting:
            for action in ACT.finditer(clause):
                if not _negated(clause, action.start()):
                    signals.append(('pressured_action', clause))
                    break
    return list(dict.fromkeys(signals))


def current_risk_support(records):
    support = []
    for record in records:
        kind = record.get('evidence_type')
        if (record.get('historical_only') or record.get('source') == 'hmem_historical_context'
                or kind in ('historical_memory', 'keyword_signal', 'tool_status')
                or record.get('freshness') in ('expired', 'stale', 'superseded', 'untrusted_timestamp')
                or record.get('usable_as_current_evidence') is False):
            continue
        observation = record.get('observation')
        if isinstance(observation, dict):
            if (observation.get('historical_only') or observation.get('usable_as_current_evidence') is False
                    or observation.get('freshness') in ('expired', 'stale', 'superseded', 'untrusted_timestamp')
                    or observation.get('record_kind') in ('demo', 'fixture', 'curated_demo_observation')):
                continue
            details = observation.get('details') or {}
            if details.get('stale') or details.get('usable_as_current_evidence') is False:
                continue
            expiry = (details.get('data_snapshot') or {}).get('refresh_by')
            if expiry:
                try:
                    stamp = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
                    if stamp.tzinfo is None or stamp <= datetime.now(timezone.utc):
                        continue
                except (ValueError, TypeError, AttributeError):
                    continue
        text = ''
        if kind == 'text_observation' and isinstance(observation, dict):
            text = observation.get('text', '')
        elif kind in ('page_retrieval', 'browser_page_observation') and isinstance(observation, dict):
            if observation.get('retrieval', {}).get('status') not in ('BLOCKED', 'NOT VERIFIED'):
                text = observation.get('excerpt', '')
        elif kind == 'zetaris_record' and isinstance(observation, dict):
            # An attributed dataset observation can support concern, not certify fraud.
            text = observation.get('observation') or observation.get('description') or ''
        if isinstance(text, str):
            for behavior, quote in _behavior_support(text):
                if kind in ('page_retrieval', 'browser_page_observation'):
                    # A normal login form is not an unsolicited request to send
                    # a credential to another person. Form destinations are
                    # evaluated separately by the website check.
                    if behavior == 'credential_entry_request':
                        continue
                    if behavior == 'credential_disclosure_request' and not re.search(
                            r'\b(?:send|share|give|provide|email|text|tell|forward|read out)\s+(?:me|us)\b'
                            r'|\b(?:email|text|forward|reply with|read out)\s+(?:(?:your|the|a|an)\s+)?(?:otp|password|verification code|one[ -]time password|code)\b'
                            r'|\b(?:to|with)\s+(?:(?:our|the|an?|your)\s+)?(?:me|us|agent|support|representative|operator)\b'
                            r'|(?:发给|告诉|交给|提供给|报给)(?:我|我们|客服|工作人员)', quote, re.I):
                        continue
                support.append({'evidence_id': record['id'], 'behavior': behavior,
                                'quote': quote[:500], 'source': record.get('source')})
        if kind in ('ip_reputation', 'zetaris_record') and isinstance(observation, dict):
            if observation.get('listed') is True and observation.get('status') == 'listed':
                support.append({'evidence_id': record['id'], 'behavior': 'adverse_listing',
                                'source': record.get('source'), 'max_risk': 'caution'})
    return support


def decide_from_evidence(records):
    """Deterministic, bounded decision from current observations, never keywords/history."""
    support = current_risk_support(records)
    labels = {
        'credential_disclosure_request': ('Requests a password or verification code.', 'Do not share the code or password.'),
        'credential_entry_request': ('Requests credentials through a supplied link or form.', 'Open the official service independently.'),
        'upfront_payment_request': ('Requests an upfront payment to obtain a promised benefit.', 'Verify the offer independently before paying.'),
        'payment_request': ('Requests payment through a hard-to-reverse channel.', 'Verify the recipient and payment purpose independently.'),
        'exceptional_financial_promise': ('Promises guaranteed or exceptional returns.', 'Verify the offer and its terms independently.'),
        'pressured_action': ('Pressures the reader to act urgently.', 'Pause and verify the request independently.'),
        'adverse_listing': ('A current IP snapshot reports an adverse listing.', 'Verify the destination through an independent source.'),
    }
    strong = {'credential_disclosure_request', 'upfront_payment_request'}
    level = 'elevated' if any(s['behavior'] in strong for s in support) else 'caution' if support else 'unknown'
    reasons, steps = [], []
    for item in sorted(support, key=lambda s: s['behavior'] not in strong):
        label, step = labels[item['behavior']]
        existing = next((r for r in reasons if r['rule_id'] == item['behavior']), None)
        if existing:
            if item['evidence_id'] not in existing['evidence_ids']:
                existing['evidence_ids'].append(item['evidence_id'])
        elif len(reasons) < 3:
            reasons.append({'text': label, 'evidence_ids': [item['evidence_id']], 'rule_id': item['behavior']})
        if step not in steps and len(steps) < 2:
            steps.append(step)
    if not support and _protective_reminder(records):
        return {'mode': 'rules', 'risk_level': 'low', 'verdict': 'safe', 'verdict_label': 'Safe',
                'summary': 'This is a protective reminder. No clear risk was found in the checked text.',
                'reasons': [{'text': 'The complete text advises protecting credentials, with no disclosure or payment request.',
                             'evidence_ids': [next(r['id'] for r in records if r.get('source') == 'submitted_content')],
                             'rule_id': 'explicit_protective_reminder'}],
                'next_steps': ['Keep codes and passwords private; verify the sender separately.'],
                'limitations': ['This assessment covers this reminder only; it does not authenticate a sender or certify a website.']}
    verdict = 'danger' if level == 'elevated' else 'uncertain'
    return {'mode': 'rules', 'risk_level': level, 'verdict': verdict,
            'verdict_label': 'Danger' if verdict == 'danger' else 'Uncertain',
            'summary': reasons[0]['text'] if reasons else 'The available evidence is insufficient to determine safety. Further verification is needed.',
            'reasons': reasons, 'next_steps': steps or ['Verify the sender or site through an independently located official channel.'],
            'limitations': ['This check does not guarantee safety or establish fraud.']}


def _protective_reminder(records):
    """Positive scope is deliberately narrow: complete credential-protection advice."""
    primary = [r for r in records if r.get('source') == 'submitted_content'
               and r.get('evidence_type') == 'text_observation' and not r.get('historical_only')]
    if len(primary) != 1:
        return False
    record = primary[0]
    observation = record.get('observation') or {}
    text = observation.get('text', '')
    if (not isinstance(text, str) or observation.get('truncated') or not text
            or record.get('usable_as_current_evidence') is False
            or record.get('freshness') in ('expired', 'stale', 'superseded')
            or not CREDENTIAL.search(text) or re.search(r'https?://|www\.|\d{5,}', text, re.I)):
        return False
    for item in records:
        value = item.get('observation')
        if item.get('evidence_type') in ('page_retrieval', 'ip_reputation', 'zetaris_record'):
            return False  # This rule never assigns green to a website investigation.
        if isinstance(value, dict) and (value.get('truncated') or value.get('listed') is True):
            return False
    clauses = [c.strip(' ,，:：') for part in CLAUSE_SPLIT.split(text)
               for c in re.split(r'[,，]|\band\b|并且|以及', part, flags=re.I) if c.strip(' ,，:：')]
    for clause in clauses:
        if any(not _negated(clause, action.start()) for pattern in (ACT, ENTER)
               for action in pattern.finditer(clause)):
            return False
        actions = list(DISCLOSE.finditer(clause))
        if actions and all(_negated(clause, action.start()) for action in actions):
            credential = r'(?:otp|one[ -]time password|verification codes?|passwords?|passcodes?|credentials|pin(?: code)?|security codes?|it|them)'
            advice = (r'(?:security reminder\s*:\s*)?(?:please\s+)?(?:never|do not|don[’\x27]t|avoid)\s+'
                      r'(?:send|share|give|provide|disclose|reveal|forward|submit)(?: or (?:send|share|provide))?\s+'
                      r'(?:(?:your|the|any)\s+)?' + credential
                      + r'(?:\s+(?:(?:with|to) (?:anyone|anybody|others|strangers)|publicly|online))?')
            policy = (r'(?:our\s+)?(?:support(?: team)?|we|(?:your|the) bank)\s+(?:will\s+)?'
                      r'(?:never|not)\s+(?:ask(?: you)?(?: for| to (?:send|share|provide))|request|need)\s+'
                      r'(?:(?:your|the|a|an)\s+)?' + credential)
            chinese = (r'(?:安全提醒[：:]?)?(?:请)?(?:不要|切勿|别|不可|不能)(?:发送|分享|提供|透露|转发)?'
                       r'(?:你的|您的|任何|自己的)?(?:短信)?(?:验证码|密码|动态口令)(?:给任何人|给他人|给别人)?'
                       r'|(?:请)?(?:不要|切勿|别)把(?:你的|您的)?(?:验证码|密码)(?:发给|告诉|透露给)(?:任何人|他人|别人)'
                       r'|(?:客服|我们|银行)(?:不会|从不|绝不)(?:索取|需要|要求你提供)(?:你的|您的)?(?:验证码|密码)')
            if re.fullmatch(advice, clause, re.I) or re.fullmatch(policy, clause, re.I) or re.fullmatch(chinese, clause):
                continue
            return False
        if re.fullmatch(r'(?:security reminder\s*:\s*)?(?:please\s+)?(?:keep .{0,50}(?:private|secret|secure|safe)|protect (?:your |the )?(?:passwords?|verification codes?|credentials))', clause, re.I):
            continue
        if re.fullmatch(r'(?:安全提醒[：:]?)?(?:请)?(?:保护好?.{0,12}(?:密码|验证码|凭据)|妥善保管.{0,12}(?:密码|验证码)|(?:验证码|密码).{0,6}(?:妥善保管|保密))', clause):
            continue
        return False
    return bool(clauses)


def validate_risk_conclusion(analysis, records):
    """Return a conservative correction plus an auditable, bounded rationale."""
    support = current_risk_support(records)
    original = analysis['risk_level']
    audit = {'status': 'supported' if support else 'no_supported_risk_observation',
             'model_risk_level': original, 'supported_risk_observations': support,
             'scope': 'Bounded checks for explicit current risky behavior; not a safety certification or full semantic verification.'}
    if original != 'unknown' and not support:
        corrected = dict(analysis)
        corrected.update(
            risk_level='unknown',
            summary='The current evidence does not substantiate a specific risky request or adverse finding. Risk remains unknown; this is not a safety confirmation.',
            claims=[],
            uncertainties=['The model proposed concern without a supported current risky action or adverse finding. The risk conclusion was withheld.',
                           'This bounded check cannot establish a sender’s identity or a website’s safety.'],
            next_steps=['Review the complete message and verify its sender through independently obtained official contact details.',
                        'Keep passwords and verification codes private.'],
        )
        audit['status'] = 'abstained'
        audit['reason'] = 'unsupported_risk_conclusion'
        return corrected, audit
    if original == 'elevated' and support and all(s.get('max_risk') == 'caution' for s in support):
        corrected = dict(analysis, risk_level='caution',
                         summary='A supplied source reports an adverse listing. This warrants checking, but does not establish that a person or business is fraudulent.',
                         claims=[{'text': 'A supplied source reports an address as listed.',
                                  'evidence_ids': [s['evidence_id']]} for s in support])
        audit.update(status='limited', reason='listing_does_not_establish_fraud')
        return corrected, audit
    return analysis, audit
