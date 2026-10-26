"""Present legacy generated copy in English without rewriting stored evidence.

Only exact, known application-generated strings are translated on read.
Original inputs, source observations, dates and decisions retain their values.
"""
from copy import deepcopy

LEGACY_COPY = {
    "\u8981\u6c42\u4f60\u63d0\u4f9b\u5bc6\u7801\u6216\u9a8c\u8bc1\u7801\u3002": "Requests a password or verification code.",
    "\u4e0d\u8981\u63d0\u4f9b\u9a8c\u8bc1\u7801\u6216\u5bc6\u7801\u3002": "Do not share the code or password.",
    "\u8981\u6c42\u5728\u63d0\u4f9b\u7684\u94fe\u63a5\u6216\u8868\u5355\u4e2d\u8f93\u5165\u51ed\u636e\u3002": "Requests credentials through a supplied link or form.",
    "\u81ea\u884c\u6253\u5f00\u5b98\u65b9\u670d\u52a1\u6838\u5b9e\u3002": "Open the official service independently.",
    "\u8981\u6c42\u5148\u4ed8\u6b3e\uff0c\u624d\u80fd\u83b7\u5f97\u627f\u8bfa\u7684\u5229\u76ca\u3002": "Requests an upfront payment to obtain a promised benefit.",
    "\u4ed8\u6b3e\u524d\uff0c\u901a\u8fc7\u72ec\u7acb\u6e20\u9053\u6838\u5b9e\u3002": "Verify the offer independently before paying.",
    "\u8981\u6c42\u4f7f\u7528\u96be\u4ee5\u8ffd\u56de\u7684\u65b9\u5f0f\u4ed8\u6b3e\u3002": "Requests payment through a hard-to-reverse channel.",
    "\u72ec\u7acb\u6838\u5b9e\u6536\u6b3e\u4eba\u548c\u4ed8\u6b3e\u7528\u9014\u3002": "Verify the recipient and payment purpose independently.",
    "\u627f\u8bfa\u4fdd\u672c\u6216\u5f02\u5e38\u9ad8\u7684\u56de\u62a5\u3002": "Promises guaranteed or exceptional returns.",
    "\u72ec\u7acb\u6838\u5b9e\u627f\u8bfa\u548c\u5177\u4f53\u6761\u6b3e\u3002": "Verify the offer and its terms independently.",
    "\u50ac\u4fc3\u4f60\u7acb\u5373\u884c\u52a8\u3002": "Pressures the reader to act urgently.",
    "\u5148\u6682\u505c\uff0c\u901a\u8fc7\u5b98\u65b9\u6e20\u9053\u6838\u5b9e\u3002": "Pause and verify the request independently.",
    "\u5f53\u524d IP \u5feb\u7167\u4e2d\u5b58\u5728\u9ed1\u540d\u5355\u8bb0\u5f55\u3002": "A current IP snapshot reports an adverse listing.",
    "\u901a\u8fc7\u72ec\u7acb\u6e20\u9053\u6838\u5b9e\u76ee\u6807\u7f51\u7ad9\u3002": "Verify the destination through an independent source.",
    "\u8fd9\u662f\u4e00\u6761\u4fdd\u62a4\u6027\u63d0\u9192\uff0c\u5f53\u524d\u68c0\u67e5\u672a\u53d1\u73b0\u660e\u663e\u98ce\u9669\u3002": "This is a protective reminder. No clear risk was found in the checked text.",
    "\u5b8c\u6574\u6587\u672c\u63d0\u9192\u4fdd\u62a4\u51ed\u636e\uff0c\u6ca1\u6709\u7d22\u53d6\u6216\u652f\u4ed8\u8981\u6c42\u3002": "The complete text advises protecting credentials, with no disclosure or payment request.",
    "\u7ee7\u7eed\u4fdd\u62a4\u9a8c\u8bc1\u7801\u548c\u5bc6\u7801\uff1b\u53e6\u884c\u6838\u5b9e\u53d1\u9001\u8005\u8eab\u4efd\u3002": "Keep codes and passwords private; verify the sender separately.",
    "\u4ec5\u8bc4\u4ef7\u8fd9\u6761\u63d0\u9192\uff0c\u4e0d\u8ba4\u8bc1\u53d1\u9001\u8005\u6216\u7f51\u7ad9\u5b89\u5168\u3002": "This assessment covers this reminder only; it does not authenticate a sender or certify a website.",
    "\u73b0\u6709\u8d44\u6599\u4e0d\u8db3\u4ee5\u5224\u65ad\u5b89\u5168\u6027\uff0c\u9700\u8981\u8fdb\u4e00\u6b65\u6838\u5b9e\u3002": "The available evidence is insufficient to determine safety. Further verification is needed.",
    "\u81ea\u884c\u6253\u5f00\u5b98\u65b9\u6e20\u9053\uff0c\u6838\u5b9e\u53d1\u9001\u8005\u6216\u7f51\u7ad9\u3002": "Verify the sender or site through an independently located official channel.",
    "\u672c\u6b21\u68c0\u67e5\u4e0d\u80fd\u4fdd\u8bc1\u5b89\u5168\uff0c\u4e5f\u4e0d\u80fd\u5355\u72ec\u8bc1\u660e\u8bc8\u9a97\u3002": "This check does not guarantee safety or establish fraud.",
    "\u5b89\u5168": "Safe",
    "\u5b58\u7591": "Uncertain",
    "\u5371\u9669": "Danger"
}


def english_saved_result(result):
    """Translate generated presentation fields only; do not rerun old checks."""
    value = deepcopy(result)
    if not isinstance(value, dict):
        return value

    def sentence(item):
        return LEGACY_COPY.get(item, item) if isinstance(item, str) else item

    def generated_fields(record):
        if not isinstance(record, dict):
            return
        for key in ('summary', 'verdict_label'):
            if key in record:
                record[key] = sentence(record[key])
        for key in ('next_steps', 'limitations'):
            if isinstance(record.get(key), list):
                record[key] = [sentence(item) for item in record[key]]
        if isinstance(record.get('reasons'), list):
            for reason in record['reasons']:
                if isinstance(reason, dict) and 'text' in reason:
                    reason['text'] = sentence(reason['text'])

    generated_fields(value)
    generated_fields(value.get('decision'))
    return value
