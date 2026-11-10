import os, json, uuid, argparse, time, urllib.request
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--stage', choices=['before', 'fixed', 'no-credentials'], required=True)
parser.add_argument('--output-dir')
args = parser.parse_args()
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(args.output_dir) if args.output_dir else ROOT / 'docs/evidence/lr06'
OUT.mkdir(parents=True, exist_ok=True)
API = 'http://localhost:5086'
I1 = '20000000-0000-0000-0000-000000000001'
marker = (Path(__file__).parent / 'lab05-marker.txt').read_text(encoding='utf-8-sig').strip()
password = os.environ['SeedUsers__Password']
facts = {'stage': args.stage, 'checks': []}
created = []

for attempt in range(60):
    try:
        with urllib.request.urlopen(API+'/health', timeout=2) as ready:
            if ready.status == 200: break
    except Exception:
        time.sleep(1)
else:
    raise RuntimeError('Local API not ready on localhost:5086. Check Start-Lab06 output.')

def record(name, **data):
    facts['checks'].append({'name': name, **data})
    print(name + ': PASS', flush=True)

def login(context, user='alice', via_ui=False):
    if via_ui:
        login_page = context.new_page()
        login_page.goto(API+'/auth-lab.html')
        login_page.locator('#login [name=userName]').fill(user)
        login_page.locator('#login [name=password]').fill(password)
        with login_page.expect_response(lambda r: r.url.endswith('/api/auth/login') and r.request.method=='POST') as pending:
            login_page.locator('#login button').click()
        assert pending.value.status==204, 'Study UI login failed; credentials omitted'
        expect(login_page.locator('#profile')).to_contain_text('alice' if user=='alice' else user)
        login_page.locator('#login [name=password]').fill('')
        login_page.screenshot(path=str(OUT/(args.stage+'-login.png')),full_page=True)
        login_page.close()
    else:
        response = context.request.post(API+'/api/auth/login', data={'userName': user, 'password': password})
        assert response.status == 204, f'Local study login failed ({response.status}); credentials omitted'
    token_response = context.request.get(API+'/api/auth/csrf-token')
    assert token_response.status == 200
    context._csrf_token = token_response.json()['token']

def load(page, resource):
    page.goto(API+'/browser-lab.html')
    page.locator('#incident-id').fill(resource)
    page.locator('#load').click()
    expect(page.locator("#status")).to_have_text("GET: 200")
    page.wait_for_timeout(150)

def create(page, text):
    page.goto(API+'/browser-lab.html')
    page.locator('#edit [name=title]').fill('LR06-'+uuid.uuid4().hex[:12])
    page.locator('#edit [name=description]').fill(text)
    page.locator('#edit button').click()
    expect(page.locator("#status")).to_have_text("GET: 200")
    resource = page.locator('#incident-id').input_value()
    created.append(resource)
    page.wait_for_timeout(150)
    return resource

def dom(page, selector):
    return page.locator(selector).evaluate('e => ({text:e.textContent, elements:e.querySelectorAll("*").length, images:e.querySelectorAll("img").length})')

with sync_playwright() as p:
    browser = p.chromium.launch(channel='chrome', headless=True)
    facts['browser'] = browser.version
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    try:
        login(context, via_ui=True)
        page = context.new_page()
        if args.stage != 'no-credentials':
            resource = create(page, marker)
            response = context.request.get(API+'/api/incidents/'+resource)
            assert response.status == 200 and response.json()['description'] == marker
            if args.stage == 'before':
                expect(page.locator("#lab05-marker-target")).to_have_attribute("data-lab05-marker", "executed")
                assert dom(page, '#description')['images'] == 1
            else:
                assert dom(page, '#description') == {'text': marker, 'elements': 0, 'images': 0}
                assert page.locator('#lab05-marker-target').get_attribute('data-lab05-marker') is None
            record('description-marker', incidentId=resource, storedAndReturnedExactly=True,
                   dom=dom(page, '#description'), markerExecuted=page.locator('#lab05-marker-target').get_attribute('data-lab05-marker'))
            page.screenshot(path=str(OUT/(args.stage+'-description.png')), full_page=True)
            load(page, I1)
            if args.stage == 'before':
                expect(page.locator("#lab05-marker-target")).to_have_attribute("data-lab05-marker", "executed")
                assert page.locator('#comments img').count() == 1
            else:
                assert page.locator('#comments img').count() == 0
                assert marker in page.locator('#comments').inner_text()
                assert page.locator('#lab05-marker-target').get_attribute('data-lab05-marker') is None
            record('comment-marker', parentId=I1, images=page.locator('#comments img').count(),
                   markerExecuted=page.locator('#lab05-marker-target').get_attribute('data-lab05-marker'))
            page.screenshot(path=str(OUT/(args.stage+'-comment.png')), full_page=True)
            for user, expected in [('bob',404), ('morgan',200)]:
                other = browser.new_context()
                login(other,user)
                result = other.request.get(API+'/api/incidents/'+resource)
                assert result.status == expected
                record('authorization-'+user, status=result.status)
                other.close()
            if args.stage == 'fixed':
                for label, value in [('apostrophe',"Комп'ютер O'Brien"), ('quotes','"Подвійні" та \'одинарні\''),
                        ('html','<b>звичайний текст</b> </> &'), ('unicode','Україна — Київ 🙂'), ('maximum','Ж'*4000)]:
                    create(page,value)
                    result = dom(page,'#description')
                    assert result == {'text':value,'elements':0,'images':0}
                    record('legitimate-'+label, length=len(value), exactText=True, elements=0)
                # Confirm the DOM fix even without CSP enforcement; never expose this test setting in the API.
                no_csp = browser.new_context(bypass_csp=True)
                login(no_csp)
                probe = no_csp.new_page()
                load(probe,resource)
                assert dom(probe,'#description') == {'text':marker,'elements':0,'images':0}
                load(probe,I1)
                assert probe.locator('#comments img').count()==0
                assert probe.locator('#lab05-marker-target').get_attribute('data-lab05-marker') is None
                record('safe-dom-with-csp-bypassed', descriptionElements=0, commentImages=0, markerExecuted=False)
                no_csp.close()

        # Full CSRF sequence in an actual browser, without printing credential material.
        load(page,resource)
        sequence=page.evaluate("""async () => {
            const id=document.querySelector('#incident-id').value;
            const route='/api/incidents/'+id;
            const before=await (await fetch(route)).json();
            const body=JSON.stringify({title:before.title,description:'LR06 browser accepted change'});
            const denied=await fetch(route,{method:'PUT',headers:{'Content-Type':'application/json'},body});
            const afterDenied=await (await fetch(route)).json();
            const csrf=await import('/csrf.js');
            const accepted=await csrf.csrfFetch(route,{method:'PUT',headers:{'Content-Type':'application/json'},body});
            const after=await (await fetch(route)).json();
            return {denied:denied.status,unchanged:before.description===afterDenied.description,
                accepted:accepted.status,changed:after.description==='LR06 browser accepted change'};
        }""")
        assert sequence=={'denied':400,'unchanged':True,'accepted':204,'changed':True}
        record('REG-CSRF-01-browser',**sequence)
        page.reload();page.locator('#incident-id').fill(resource);page.locator('#load').click()
        expect(page.locator('#description')).to_have_text('LR06 browser accepted change')
        page.screenshot(path=str(OUT/'csrf-after.png'),full_page=True)
        # Reload creates a fresh helper; the next form action must lazily fetch its token.
        create(page,'LR06 mutation after F5')
        record('mutation-after-reload',status=201)
        page.goto(API+'/auth-lab.html')
        page.locator('#logout').click()
        expect(page.locator('#logout-result')).to_contain_text('HTTP 204')
        expect(page.locator('#logout-result')).to_contain_text('HTTP 401')
        login(context,via_ui=True)
        create(page,'LR06 mutation after logout and new login')
        record('mutation-after-new-login',status=201)

        for port in [4173,4174]:
            probe = context.new_page()
            probe.goto(f'http://localhost:{port}/')
            events = []
            def on_response(r):
                if r.url.startswith(API):
                    headers = r.headers
                    events.append({'method':r.request.method,'path':r.url.split(API)[1], 'status':r.status,
                        'allowOrigin':headers.get('access-control-allow-origin'),
                        'allowCredentials':headers.get('access-control-allow-credentials'),
                        'allowMethods':headers.get('access-control-allow-methods'),
                        'allowHeaders':headers.get('access-control-allow-headers')})
            probe.on('response',on_response)
            cdp = context.new_cdp_session(probe)
            cdp.send('Network.enable')
            wire=[]
            wire_requests={}
            wire_extra=[]
            def request_seen(e):
                r=e['request']
                if r['url'].startswith(API):
                    wire_requests.setdefault(e['requestId'],{}).update({'method':r['method'],'url':r['url']})
            def request_extra(e):
                headers={k.lower():v for k,v in e['headers'].items()}
                wire_requests.setdefault(e['requestId'],{}).update({'cookiePresent':'cookie' in headers})
            cdp.on('Network.requestWillBeSent',request_seen)
            cdp.on('Network.requestWillBeSentExtraInfo',request_extra)
            cdp.on('Network.responseReceivedExtraInfo',lambda e: wire_extra.append({'status':e['statusCode'],
                'headers':{k:v for k,v in e['headers'].items() if k.lower().startswith('access-control-')}}))
            cdp.on('Network.responseReceived',lambda e: wire.append({'methodHint':e['type'],'url':e['response']['url'],
                'status':e['response']['status'], 'headers':{k:v for k,v in e['response']['headers'].items() if k.lower().startswith('access-control-')}}))
            # CDP records preflight responses, which high-level Playwright may omit.
            for kind in ['simple','preflight','cookie']:
                events.clear(); wire.clear(); wire_requests.clear(); wire_extra.clear()
                result=probe.evaluate('''async ({api,kind}) => {
                    const options = kind === 'preflight' ? {headers:{'X-Lab-Cors-Probe':'stage-3'}} :
                        kind === 'cookie' ? {credentials:'include'} : {};
                    try { const r=await fetch(api+(kind==='cookie'?'/api/incidents':'/health')+'?probe='+Date.now(),options);
                        return {readable:true,status:r.status,body:await r.json()}; }
                    catch { return {readable:false}; }
                }''',{'api':API,'kind':kind})
                probe.wait_for_timeout(200)
                allowed = args.stage != 'before' and port==4173 and not (args.stage=='no-credentials' and kind=='cookie')
                assert result['readable'] == allowed, (port,kind,result)
                if allowed: assert result['status']==200
                record(f'cors-{port}-{kind}', readable=result['readable'], status=result.get('status'),
                       responses=list(events), network=list(wire), networkResponseFacts=list(wire_extra),
                       requestFacts=[v for v in wire_requests.values() if 'url' in v])
            probe.close()

        direct = context.request.get(API+'/health',headers={'Origin':'http://localhost:4174'})
        assert direct.status==200 and direct.json()['status']=='ready'
        assert 'access-control-allow-origin' not in direct.headers
        record('direct-http-disallowed-origin',status=200,body=direct.json(),allowOrigin=None)
        if args.stage=='fixed':
            anonymous=browser.new_context()
            probe=anonymous.new_page(); probe.goto('http://localhost:4173/')
            result=probe.evaluate('''async api => {const r=await fetch(api+'/api/incidents',{credentials:'include'});return {status:r.status};}''',API)
            assert result['status']==401
            record('anonymous-cookie-probe',javascriptReadable=True,status=401)
            anonymous.close()
            for route in ['/','/browser-lab.html','/auth-lab.html']:
                errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                response=page.goto(API+route)
                headers=response.headers
                assert response.status==200
                assert headers['x-content-type-options']=='nosniff'
                assert headers['referrer-policy']=='no-referrer'
                assert "frame-ancestors 'none'" in headers['content-security-policy']
                assert 'unsafe-inline' not in headers['content-security-policy']
                assert 'content-security-policy-report-only' not in headers
                page.wait_for_timeout(200)
                assert not errors
                record('headers-'+route,status=200,headers={k:v for k,v in headers.items() if k in ['content-security-policy','x-content-type-options','referrer-policy']})
            page.evaluate("window.violations=[];document.addEventListener('securitypolicyviolation',e=>violations.push({directive:e.effectiveDirective,disposition:e.disposition,blockedURI:e.blockedURI}));new Image().src='http://localhost:4173/x.png';")
            page.wait_for_timeout(500)
            violation=page.evaluate('window.violations')
            assert any(v['disposition']=='enforce' and v['directive']=='img-src' for v in violation)
            record('csp-image-blocked',violations=violation)
    finally:
        for resource in created:
            r=context.request.delete(API+'/api/incidents/'+resource,headers={'X-CSRF-TOKEN':context._csrf_token})
            assert r.status==204, 'Fixture cleanup failed'
        facts['createdFixturesCleaned']=len(created)
        (OUT/(args.stage+'-browser.json')).write_text(json.dumps(facts,ensure_ascii=False,indent=2),encoding='utf-8')
        context.close();browser.close()
