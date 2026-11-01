import payments
payments.PAY_TO = '0x05cc287fecab7461ee05914880167fc2b1f907d4'
"""Discovery adapter for the existing auditor; never signs or sends payments."""
import json
import server
import payments

BASE = server.config_base()
EXAMPLE = {'tx_hash': '0x389a08dba01e0d65999b775cd9724d73d82bd3908ae5666ae631ef87e4dfde99'}
INPUT = {
    'type': 'object',
    'properties': {
        'tx_hash': {'type': 'string', 'pattern': '^0x[0-9a-fA-F]{64}$'},
        'expected': {'type': 'object', 'description': 'Optional expected payment fields; see /guide.'},
    },
    'required': ['tx_hash'],
    'additionalProperties': False,
}
DESCRIPTION = ('Inspect a Base native-USDC EIP-3009 settlement: decode authorization calls, '
               'bind receipt logs, check historical nonce state and compare expected terms. '
               'Informational evidence, not proof of delivery or a security guarantee. '
               '0.01 USDC on Base per call. POST JSON; see /guide and /example.')
original_terms = server.terms


def terms():
    result = original_terms().replace('contact@speedbot.dev', 'sihu.shop@mail.grokbot.com')
    return result.replace('</main>',
        '<p>Hosting: free Render instance. The service can sleep or restart. Local payment '
        'results are ephemeral and may be lost on a restart or redeploy, including before '
        'the 30-day retention limit. Save your original authorization and receipt. '
        'Do not sign a second payment just to retry.</p></main>')


server.terms = terms
OPENAPI = {
    'openapi': '3.1.0',
    'info': {'title': 'Charlie Base USDC Settlement Auditor', 'version': '1.1.0-market',
             'description': DESCRIPTION, 'contact': {'email': 'sihu.shop@mail.grokbot.com'}},
    'servers': [{'url': BASE}],
    'paths': {'/v1/audit': {'post': {
        'operationId': 'auditBaseSettlement', 'summary': 'Audit a Base USDC settlement',
        'description': DESCRIPTION,
        'x-payment-info': {'protocols': ['x402'],
                           'price': {'mode': 'fixed', 'currency': 'USD', 'amount': '0.01'}},
        'requestBody': {'required': True, 'content': {'application/json': {'schema': INPUT, 'example': EXAMPLE}}},
        'responses': {'200': {'description': 'Paid audit, including negative or partial findings'},
                      '202': {'description': 'Pending settlement; retry the identical request'},
                      '400': {'description': 'Invalid input; not charged'},
                      '402': {'description': 'x402 v2 Base USDC payment required'}},
    }}},
}
original_challenge = payments.challenge


def discoverable_challenge(base_url, error='Payment required'):
    result = original_challenge(base_url, error)
    result['resource']['description'] = DESCRIPTION
    result['extensions'] = {'bazaar': {
        'info': {'input': {'type': 'http', 'method': 'POST', 'bodyType': 'json', 'body': EXAMPLE},
                 'output': {'type': 'json'}},
        'schema': {'type': 'object', 'properties': {
            'input': {'type': 'object', 'properties': {
                'type': {'const': 'http'}, 'method': {'const': 'POST'},
                'bodyType': {'const': 'json'}, 'body': INPUT},
                'required': ['type', 'method', 'bodyType', 'body']},
            'output': {'type': 'object'}}, 'required': ['input']},
    }}
    return result


payments.challenge = discoverable_challenge
original_process = payments.PaymentService.process


def process(self, obj, header):
    # Empty unpaid probes reveal price only; paid/invalid input follows original validation.
    if obj == {} and header is None:
        body = discoverable_challenge(self.base_url)
        return 402, body, {'PAYMENT-REQUIRED': payments.b64(body)}
    return original_process(self, obj, header)


payments.PaymentService.process = process
OriginalHandler = server.Handler


class Handler(OriginalHandler):
    def do_POST(self):
        if (self.path == '/v1/audit'
                and not self.headers.get_all('PAYMENT-SIGNATURE')
                and not self.headers.get_all('X-PAYMENT')
                and not self.headers.get('Transfer-Encoding')
                and self.headers.get('Content-Length', '0') == '0'):
            body = discoverable_challenge(BASE)
            return self.reply(402, body, {'PAYMENT-REQUIRED': payments.b64(body)})
        return super().do_POST()

    def do_GET(self):
        if self.path == '/openapi.json':
            return self.reply(200, OPENAPI)
        if self.path == '/.well-known/x402':
            return self.reply(200, {'version': 1, 'name': OPENAPI['info']['title'],
                                    'description': DESCRIPTION, 'resources': [BASE + '/v1/audit']})
        if self.path == '/llms.txt':
            text = (DESCRIPTION + '\nPOST ' + BASE + '/v1/audit\nExample: ' + json.dumps(EXAMPLE)
                    + '\nDocs: ' + BASE + '/guide\nOpenAPI: ' + BASE + '/openapi.json\n')
            return self.reply(200, {'name': OPENAPI['info']['title'], 'instructions': text})
        if self.path == '/v1/audit':
            body = discoverable_challenge(BASE)
            return self.reply(402, body, {'PAYMENT-REQUIRED': payments.b64(body)})
        return super().do_GET()


server.Handler = Handler

if __name__ == '__main__':
    server.main()
