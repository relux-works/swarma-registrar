#!/usr/bin/env python3
"""Independent offline verifier for the published contract fixtures.

The parser, strict points, loader phases, admission ordering and state transitions
are implemented here, independently of Go. Trust/clock/sink/signer results in a
fixture are external inputs; this is not service or deployment qualification.
"""
import argparse
import base64
import copy
import datetime as dt
import functools
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
N = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
SAFE = 2**53 - 1
IDENTITY = (0, 1, 1, 0)
HOST = re.compile(r'[a-z0-9-]{1,32}\Z')
STRUCTURED = re.compile(r'([a-z0-9-]{1,32})_[a-z0-9][a-z0-9-]{0,31}_[a-z0-9]{1,32}(?:-[a-z0-9]{1,16})?\Z')
LEGACY = re.compile(r'[a-z0-9][a-z0-9._=\-]{0,254}\Z')

class Rejected(Exception):
    pass

def require(condition, message='malformed'):
    if not condition:
        raise Rejected(message)

def b64(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]*', value) is not None, 'base64url alphabet')
    try:
        result = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except Exception as exc:
        raise Rejected('base64url length') from exc
    require(enc(result) == value, 'base64url trailing bits')
    return result

def enc(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate decoded object key')
        result[key] = value
    return result

def integer(token):
    require(token != '-0', 'negative zero')
    value = int(token)
    require(abs(value) <= SAFE, 'integer bounds')
    return value

def bad_number(_):
    raise Rejected('non-integer number token')

def parse(raw):
    require(not raw.startswith(b'\xef\xbb\xbf'), 'BOM')
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=bad_number, parse_constant=bad_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Rejected('invalid JSON/UTF-8') from exc
    def walk(v, depth):
        if isinstance(v,(dict,list)):
            depth+=1
            require(depth <= 16, 'depth bound')
        if isinstance(v, str):
            require(not any(0xd800 <= ord(c) <= 0xdfff for c in v), 'lone surrogate')
        elif isinstance(v, dict):
            for k, child in v.items():
                walk(k, depth)
                walk(child, depth)
        elif isinstance(v, list):
            for child in v:
                walk(child, depth)
    walk(value, 0)
    return value

def ccj(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

def preimage(body, domain):
    return ('swarma-registrar ' + domain + '\n').encode('ascii') + ccj(body)

def derived_id(body, domain):
    return 'sha256:' + hashlib.sha256(preimage(body, domain)).hexdigest()

def add(a, b):
    x,y,z,t = a
    xx,yy,zz,tt = b
    aa = (y-x)*(yy-xx) % P
    bb = (y+x)*(yy+xx) % P
    c = 2*D*t*tt % P
    d = 2*z*zz % P
    e,f,g,h = bb-aa,d-c,d+c,bb+aa
    return e*f%P,g*h%P,f*g%P,e*h%P

def multiply(a, scalar):
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = add(result, a)
        a = add(a, a)
        scalar >>= 1
    return result

@functools.lru_cache(maxsize=4096)
def decode_ed_point(raw):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, 'little') & (2**255-1)
    sign = raw[31] >> 7
    if y >= P:
        return None
    denominator = (D*y*y+1) % P
    if denominator == 0:
        return None
    square = (y*y-1)*pow(denominator,-1,P) % P
    x = pow(square,(P+3)//8,P)
    if x*x % P != square:
        x = x*pow(2,(P-1)//4,P) % P
    if x*x % P != square or (x == 0 and sign):
        return None
    if x & 1 != sign:
        x = P-x
    return x,y,1,x*y%P

def is_identity(point):
    return point[0] % P == 0 and (point[1]-point[2]) % P == 0

@functools.lru_cache(maxsize=4096)
def strict_ed_point(raw):
    point=decode_ed_point(raw)
    return point is not None and not is_identity(point) and is_identity(multiply(point,L))

def key_parts(text):
    require(isinstance(text,str) and text.isascii() and len(text) <= 128)
    prefix,sep,value = text.partition(':')
    require(sep and prefix in ('ed25519','p256'), 'key prefix')
    return prefix,b64(value)

def point_key(text):
    prefix,raw = key_parts(text)
    if prefix == 'ed25519':
        require(strict_ed_point(raw), 'Ed25519 strict point')
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    require(len(raw) == 33 and raw[0] in (2,3), 'P-256 compressed encoding')
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),raw)
    except ValueError as exc:
        raise Rejected('P-256 invalid point') from exc

def signature_verdict(text, signature, message, invalid, allow_high_s=False):
    try:
        key = point_key(text)
        require(len(signature)==64, 'raw signature length')
        if isinstance(key,ed25519.Ed25519PublicKey):
            require(strict_ed_point(signature[:32]), 'Ed25519 strict R')
            require(int.from_bytes(signature[32:],'little') < L, 'Ed25519 scalar range')
            key.verify(signature,message)
        else:
            r = int.from_bytes(signature[:32],'big')
            s = int.from_bytes(signature[32:],'big')
            require(1 <= r < N and 1 <= s < N, 'P-256 scalar range')
            if s > N//2 and not allow_high_s:
                return 'signature_high_s'
            key.verify(utils.encode_dss_signature(r,s),message,ec.ECDSA(hashes.SHA256()))
        return 'accept'
    except (Rejected, InvalidSignature, ValueError):
        return invalid

def timestamp(text):
    require(isinstance(text,str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',text,flags=re.ASCII))
    try:
        value = dt.datetime.strptime(text,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise Rejected('timestamp calendar') from exc
    require(value.year >= 1970)
    return int(value.timestamp())

def basic_envelope(raw):
    require(len(raw) <= 65536, 'envelope bytes')
    env = parse(raw)
    require(isinstance(env,dict) and set(env)=={'body','id','sig'})
    require(isinstance(env['body'],dict))
    require(isinstance(env['id'],str) and re.fullmatch(r'sha256:[0-9a-f]{64}',env['id']))
    require(len(b64(env['sig']))==64)
    return env

def name_fits(name,audience):
    return isinstance(name,str) and len(name.encode('utf-8'))+len(audience.encode('ascii'))+2 <= 255

def legacy_syntax(name,audience):
    return name_fits(name,audience) and LEGACY.fullmatch(name) is not None

def syntax(name,audience):
    return name_fits(name,audience) and (STRUCTURED.fullmatch(name) is not None or LEGACY.fullmatch(name) is not None)

def content_type_supported(value):
    # Surrounding whitespace is open for content review; no committed vector or fixture depends on it.
    return isinstance(value,str) and re.fullmatch(
        r'[ \t]*application/json(?:[ \t]*;[ \t]*charset=utf-8)?[ \t]*',
        value,flags=re.IGNORECASE|re.ASCII) is not None

def permitted(name,body):
    structured = STRUCTURED.fullmatch(name)
    if structured:
        return structured[1]==body['host'] and name.startswith(body['names']['prefix'])
    return name in body['names']['explicit']

def registration_shape(body):
    require(set(body)=={'type','key','name','aud','nonce','iat','exp'})
    require(body['type']=='registration/1')
    key_parts(body['key'])
    require(isinstance(body['name'],str) and len(body['name'].encode('utf-8'))<=255)
    require(isinstance(body['aud'],str) and body['aud'].isascii() and 1<=len(body['aud'])<=255)
    require(len(b64(body['nonce']))==16)
    iat,exp = timestamp(body['iat']),timestamp(body['exp'])
    require(0 < exp-iat <= 120)
    return iat,exp

def enrollment_shape(body,fixture):
    require({'type','host','keys','names','seq','state'} <= set(body) <= {'type','host','keys','names','seq','state','uid_map'})
    require(body['type']=='enrollment/1' and isinstance(body['host'],str) and HOST.fullmatch(body['host']))
    require(type(body['seq']) is int and 1<=body['seq']<=SAFE and body['state'] in ('active','revoked'))
    keys = body['keys']
    require(isinstance(keys,list) and 1<=len(keys)<=16)
    seen = set()
    for key in keys:
        require(isinstance(key,dict) and set(key)=={'key','not_before','not_after'})
        point_key(key['key'])
        require(key['key'] not in seen)
        seen.add(key['key'])
        require(timestamp(key['not_before']) < timestamp(key['not_after']))
    names = body['names']
    require(isinstance(names,dict) and set(names)=={'prefix','explicit'} and names['prefix']==body['host']+'_')
    explicit = names['explicit']
    require(isinstance(explicit,list) and len(explicit)<=256)
    require(all(legacy_syntax(n,fixture['audience']) for n in explicit))
    require(len(explicit)==len(set(explicit)))
    stations = fixture['registry']['station_hosts']
    if body['host'] in stations:
        require('uid_map' in body)
    if 'uid_map' not in body:
        return
    rows=body['uid_map']
    require(isinstance(rows,list) and 1<=len(rows)<=256)
    uids,assigned=set(),set()
    for row in rows:
        require(isinstance(row,dict) and {'uid','names'} <= set(row) <= {'uid','names','exe'})
        require(type(row['uid']) is int and 1<=row['uid']<=4294967294 and row['uid'] not in uids)
        uids.add(row['uid'])
        require(isinstance(row['names'],list) and 1<=len(row['names'])<=64)
        for name in row['names']:
            require(syntax(name,fixture['audience']) and permitted(name,body) and name not in assigned)
            assigned.add(name)
        if 'exe' in row:
            exe=row['exe']
            require(isinstance(exe,str) and 1<=len(exe.encode('utf-8'))<=4096 and exe.startswith('/'))
            require('\\' not in exe and all(ord(c)>=32 and ord(c)!=127 for c in exe))
            require(all(c not in ('','.','..') for c in exe.split('/')[1:]))

def file_entries(registry, previous=False):
    entries=[]
    for file in registry['previous_files' if previous else 'files']:
        raw=b64(file['bytes_base64'])
        for i in range(file['repeat']):
            path=file['path_template'] % i if 'path_template' in file else file['path']
            entries.append((path,file['kind'],raw))
    return sorted(entries,key=lambda x:x[0].encode('utf-8'))

def registry_verdict(fixture):
    rg=fixture['registry']
    if not all(rg[k] for k in ('available','commit_signature_valid','approved','pin_is_exact','rollback_state_available')) or rg['publisher_key'] is None:
        return 'registry_unavailable',{}
    entries=file_entries(rg)
    if rg['previous_files'] and rg['revision']==rg.get('previous_revision'):
        require(rg['descendant'] and entries==file_entries(rg,previous=True),'same revision must identify the same immutable snapshot')
    if len(entries)>10000 or sum(len(raw) for _,_,raw in entries)>16*1024*1024 or any(kind!='regular' for _,kind,_ in entries):
        return 'registry_unavailable',{}
    try:
        envelopes=[basic_envelope(raw) for _,_,raw in entries]
    except Rejected:
        return 'enrollment_malformed',{}
    if any('sigs' in e['body'] for e in envelopes):
        return 'enrollment_sigs_unsupported',{}
    for env in envelopes:
        label=env['body'].get('host')
        if isinstance(label,str) and HOST.fullmatch(label) and label not in rg['station_hosts']+rg.get('nonstation_hosts',[]):
            return 'registry_unavailable',{}
    try:
        for env in envelopes:
            enrollment_shape(env['body'],fixture)
    except (Rejected,TypeError,KeyError):
        return 'enrollment_malformed',{}
    for env in envelopes:
        if env['id']!=derived_id(env['body'],'enrollment/1'):
            return 'enrollment_id_mismatch',{}
    for env in envelopes:
        if signature_verdict(rg['publisher_key'],b64(env['sig']),preimage(env['body'],'enrollment/1'),'enrollment_signature_invalid')!='accept':
            return 'enrollment_signature_invalid',{}
    positions,keys,names={}, {}, {}
    for env in envelopes:
        body=env['body'];label=body['host'];position=(label,body['seq'])
        if position in positions:
            return 'registry_conflict',{}
        positions[position]=env
        for key in body['keys']:
            if key['key'] in keys and keys[key['key']]!=label:
                return 'registry_conflict',{}
            keys[key['key']]=label
        for name in body['names']['explicit']:
            structured=STRUCTURED.fullmatch(name)
            if (structured and structured[1]!=label) or (name in names and names[name]!=label):
                return 'registry_conflict',{}
            names[name]=label
    current={}
    revoked=set()
    for (label,_),env in sorted(positions.items()):
        body=env['body']
        if label in revoked and body['state']=='active':
            return 'registry_rollback',{}
        if body['state']=='revoked':
            revoked.add(label)
        current[label]=body
    if not rg['descendant']:
        return 'registry_rollback',{}
    for _,_,raw in file_entries(rg,previous=True):
        old=basic_envelope(raw);b=old['body'];position=(b['host'],b['seq'])
        if position not in positions or positions[position]['id']!=old['id']:
            return 'registry_rollback',{}
    if not rg['persist_available']:
        return 'registry_unavailable',{}
    return 'accept',current

class Admission:
    def __init__(self,fixture,jwt_seed):
        self.f=copy.deepcopy(fixture)
        self.jwt_key=ed25519.Ed25519PrivateKey.from_private_bytes(jwt_seed)
        self.cache=copy.deepcopy(fixture['nonce_cache'])
        self.events=copy.deepcopy(fixture['limiter_events'])
        self.audit=[]
        self.fenced=fixture['clock_fenced'] or not fixture['startup_verified']
        self.healthy=fixture['clock_healthy']
        self.barrier=fixture['start_barrier']
        require(self.barrier==fixture['actual_start_millis']//1000+31,'fixture barrier assignment')
        self.signer=fixture['signer_available']
        self.generation=fixture['signing_generation']
        self.last_admission=None
        self.revocation=False

    def transition(self,item):
        event=item['event']
        if event=='clock':
            self.healthy=item['healthy']
            if not self.healthy:
                self.fenced=True
        elif event=='restart':
            if item['startup_verified'] and self.last_admission is not None:
                require(self.last_admission<=item['actual_start_millis']//1000,'synchronized-start ordering premise')
            self.cache=[];self.events=[]
            self.healthy=item['startup_verified'];self.fenced=not self.healthy
            self.barrier=item['actual_start_millis']//1000+31
        elif event=='signer':
            self.signer=item['available']
        else:
            require(event=='request','unknown fixture transition')
            code,jwt=self.request(b64(item['bytes_base64']),item['now'])
            compare_outcome(item['expected'],code,jwt)

    def refuse(self,code):
        if self.f['audit']['local_available']:
            self.audit.append(code)
            return code,None
        return 'audit_unavailable',None

    def request(self,raw,now,main=False):
        f=self.f;http=f['http']
        if not self.healthy:
            self.fenced=True
        if http['path']!='/v1/registration':return self.refuse('endpoint_not_found')
        if http['method']!='POST':return self.refuse('method_not_allowed')
        if len(raw)>65536:return self.refuse('request_too_large')
        if not content_type_supported(http['content_type']) or http['content_encoding'] not in ('','identity'):
            return self.refuse('unsupported_media_type')
        try:
            env=basic_envelope(raw);body=env['body'];iat,exp=registration_shape(body)
        except (Rejected,TypeError,KeyError,UnicodeError):
            return self.refuse('registration_malformed')
        if env['id']!=derived_id(body,'registration/1'):return self.refuse('registration_id_mismatch')
        verdict=signature_verdict(body['key'],b64(env['sig']),preimage(body,'registration/1'),'registration_signature_invalid')
        if verdict!='accept':return self.refuse(verdict)
        code,current=registry_verdict(f)
        if code!='accept':return self.refuse('registry_unavailable')
        owners=[b for b in current.values() if any(k['key']==body['key'] for k in b['keys'])]
        if not owners:return self.refuse('key_not_enrolled')
        owner=owners[0];key=next(k for k in owner['keys'] if k['key']==body['key'])
        if not (timestamp(key['not_before'])<=iat<timestamp(key['not_after']) and timestamp(key['not_before'])<=now<timestamp(key['not_after'])):return self.refuse('key_not_valid_now')
        if owner['state']!='active':return self.refuse('host_revoked')
        if not syntax(body['name'],f['audience']):return self.refuse('name_invalid')
        if not permitted(body['name'],owner):return self.refuse('name_not_permitted')
        if body['aud']!=f['audience']:return self.refuse('audience_mismatch')
        if self.fenced or not self.healthy or iat<self.barrier:return self.refuse('clock_skew')
        if iat>now+30:return self.refuse('request_not_yet_valid')
        if now>=exp+30:return self.refuse('request_expired')
        require(1<=f['key_capacity']<=10 and 1<=f['name_capacity']<=3,'fixture capacities')
        self.events=[e for e in self.events if e['at']>f['monotonic_now']-60]
        key_events=sum(e['key']==body['key'] for e in self.events)
        name_events=sum(e['name']==body['name'] for e in self.events)
        if key_events>=f['key_capacity'] or name_events>=f['name_capacity']:return self.refuse('rate_limited')
        self.events.append({'at':f['monotonic_now'],'key':body['key'],'name':body['name']})
        if any(e['key']==body['key'] and b64(e['nonce'])==b64(body['nonce']) for e in self.cache):return self.refuse('nonce_replayed')
        self.cache.append({'key':body['key'],'nonce':body['nonce'],'expires':exp+30})
        if main and f.get('final_revoked'):
            code,new=registry_verdict({**f,'registry':f['scheduled_registry']})
            require(code=='accept' and new[owner['host']]['state']=='revoked','scheduled revocation validity')
            self.revocation=True
            return self.refuse('host_revoked')
        if main and f.get('final_now',now)>=exp+30:return self.refuse('request_expired')
        if not self.signer:return self.refuse('service_unavailable')
        if not f['audit']['local_available']:return self.refuse('audit_unavailable')
        self.audit.append('issued')
        if not f['audit']['remote_ack']:return self.refuse('audit_unavailable')
        if main and f.get('post_audit_revoked'):
            code,new=registry_verdict({**f,'registry':f['scheduled_registry']})
            require(code=='accept' and new[owner['host']]['state']=='revoked','post-audit revocation validity')
            self.revocation=True
            return self.refuse('host_revoked')
        if main and 'post_audit_generation' in f:
            self.generation=f['post_audit_generation']
            if self.generation!=f['signing_generation']:return self.refuse('service_unavailable')
        header={'alg':'EdDSA','typ':'JWT'}
        claims={'iss':'swarma-registrar','aud':[f['audience']],'sub':body['name'],'iat':now,'nbf':now,'exp':now+120,'jti':env['id']}
        message=enc(ccj(header))+'.'+enc(ccj(claims))
        signature=enc(self.jwt_key.sign(message.encode('ascii')))
        self.last_admission=now
        return 'accept',{'header':header,'claims':claims,'signature':signature,'compact':message+'.'+signature}

    def state(self):
        f=self.f
        return {'nonce_cache':self.cache,'limiter_events':self.events,'audit_outcomes':self.audit,
                'clock_fenced':self.fenced,'start_barrier':self.barrier,'signer_ready':self.signer,
                'audit_ready':f['audit']['local_available'] and f['audit']['remote_ack'],'registry_ready':f['registry']['available'],
                'signing_generation':self.generation,'scheduled_revocation_applied':self.revocation,
                'authority':authority(f['scheduled_registry'] if self.revocation else f['registry'])}

def authority(registry,previous=False):
    ids=sorted(parse(raw)['id'] for _,_,raw in file_entries(registry,previous))
    return {'revision':registry.get('previous_revision') if previous else registry['revision'], 'record_ids':ids}

def compare_outcome(expected,code,jwt):
    require(expected['code']==code,f'outcome disagreement: computed {code}, stored {expected["code"]}')
    if code=='accept':
        require(expected.get('jwt')==jwt,'exact deterministic JWT disagreement')
    else:
        require('jwt' not in expected and jwt is None,'refusal leaks JWT')


def ordinary_ed_equation(public,signature,message):
    # Separate arithmetic witness; library rejection may include its own point policy.
    a=decode_ed_point(public);r=decode_ed_point(signature[:32])
    if a is None or r is None or len(signature)!=64:
        return False
    base=decode_ed_point(bytes.fromhex('58'+'66'*31))
    scalar=int.from_bytes(signature[32:],'little')
    if scalar>=L:
        return False
    h=int.from_bytes(hashlib.sha512(signature[:32]+public+message).digest(),'little')%L
    left=multiply(base,scalar);right=add(r,multiply(a,h))
    return (left[0]*right[2]-right[0]*left[2])%P==0 and (left[1]*right[2]-right[1]*left[2])%P==0

def verify_witness(vector):
    # These case-specific assertions establish the named defect, beyond its HTTP verdict.
    row=vector['row'];raw=b64(vector['input']['bytes_base64'])
    media_rows={'R136':'app lication/json','R137':'application/j son',
                'PR30':'Application/JSON;Charset=UtF-8'}
    if row in media_rows:
        require(vector['fixture']['http']['content_type']==media_rows[row],'exact media-token witness')
    name_rows={'R134','R135','PR28','PR29','E112','E113','E114','PE14','PE15'}
    if row in name_rows:
        f=vector['fixture'];env=parse(raw)
        enrollment=vector['domain']=='enrollment/1'
        if enrollment:
            require(f['registry'].get('first_use') is True,'explicit bootstrap fixture input')
        owner=env['body'] if enrollment else parse(b64(f['registry']['files'][0]['bytes_base64']))['body']
        require(owner['host']=='-node' and owner['names']['prefix']=='-node_','leading-hyphen owner witness')
        require('-node' in f['registry']['station_hosts'],'leading-hyphen station witness')
        explicit=['legacy.dev','-node_project_role'] if row=='E113' else ['legacy.dev']
        require(owner['names']['explicit']==explicit,'legacy-only explicit neighbor witness')
        name='-node_project_rolex' if row in ('R134','E112') else '-node_p_' if row in ('R135','E114') else '-node_project_role'
        require(owner['uid_map']==[{'uid':1001,'names':[name if enrollment else 'legacy.dev']}],'UID-map witness')
        if not enrollment:
            require(env['body']['name']==name and env['body']['aud']==f['audience'],'request-name witness')
        audience='.'.join(['a'*63,'b'*63,'c'*63,'d'*43]) if row in ('R134','PR29','E112','PE15') else 'example.org'
        require(f['audience']==audience,'configured-audience witness')
        if row in ('R134','PR29','E112','PE15'):
            require(len(('@'+name+':'+audience).encode())==(256 if row in ('R134','E112') else 255),'exact mxid-boundary witness')
    if row in ('R18','E18','PC3'):
        def container_depth(v):
            if isinstance(v,dict):return 1+max((container_depth(x) for x in v.values()),default=0)
            if isinstance(v,list):return 1+max((container_depth(x) for x in v),default=0)
            return 0
        require(container_depth(json.loads(raw))==(16 if row=='PC3' else 17),'exact depth-boundary witness')
    if re.fullmatch(r'[RE](?:0[1-9]|10|17|18)',row):
        reasons={1:'duplicate',2:'duplicate',3:'invalid JSON/UTF-8',4:'lone surrogate',
                 5:'non-integer',6:'non-integer',7:'non-integer',8:'negative zero',
                 9:'integer bounds',10:'integer bounds',17:'BOM',18:'depth bound'}
        number=int(row[1:])
        try:
            parse(raw)
        except Rejected as exc:
            require(reasons[number] in str(exc),'CCJ witness failed for another reason')
        else:
            raise Rejected('CCJ defect was not rejected by codec')
    crypto_rows={'R38','R39','R40','R41','R42','R43','R44','R45','R46','R47','R48','R49',
                 'R50','R51','R52','R53','R54','R55','R56','R107','R108','R109','R102','E44','E87'}
    if row not in crypto_rows:
        return
    env=parse(raw);body=env['body'];sig=b64(env['sig'])
    if row=='E87':
        require(int.from_bytes(sig[32:],'little')==L,'publisher S=L witness')
        return
    if row=='E44':
        require(body['keys'][0]['key'].startswith('p256:') and len(b64(body['keys'][0]['key'].split(':')[1]))==32,'enrollment relabelled Ed25519 key')
        return
    prefix,k=key_parts(body['key'])
    if row=='R38':require(prefix=='p256' and len(k)==32,'relabelled-key witness')
    elif row=='R39':
        require(len(k)==65 and k[0]==4,'uncompressed-point witness')
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),k)
    elif row=='R40':require(len(k)==33 and k[0]==4,'bad SEC1 prefix witness')
    elif row=='R41':require(len(k)==33 and int.from_bytes(k[1:],'big')==int('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',16),'field-prime witness')
    elif row=='R42':
        prime=int('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',16)
        b=int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',16)
        x=int.from_bytes(k[1:],'big')
        require(len(k)==33 and k[0] in (2,3) and x<prime and pow((x**3-3*x+b)%prime,(prime-1)//2,prime)==prime-1,'nonsquare decompression witness')
    elif row in ('R43','R44','R45','R46','R47','R49','R102'):
        r=int.from_bytes(sig[:32],'big');scalar=int.from_bytes(sig[32:],'big')
        if row=='R43':require(r==0 and 1<=scalar<=N//2,'r=0 witness')
        elif row=='R44':require(r==N and 1<=scalar<=N//2,'r=N witness')
        elif row=='R45':require(1<=r<N and scalar==0,'s=0 witness')
        elif row=='R46':require(1<=r<N and scalar==N,'s=N witness')
        elif row in ('R47','R102'):
            require(N//2<scalar<N,'high-S witness')
            require(signature_verdict(body['key'],sig,preimage(body,'registration/1'),'invalid',allow_high_s=True)=='accept','high-S witness is not a valid equation')
        else:
            require(1<=r<N and 1<=scalar<=N//2,'low-S in-range witness')
            require(signature_verdict(body['key'],sig,preimage(body,'registration/1'),'invalid')=='invalid','invalid equation witness')
    elif row=='R48':
        require(len(sig)==70,'70-byte DER witness')
        point_key(body['key']).verify(sig,preimage(body,'registration/1'),ec.ECDSA(hashes.SHA256()))
    elif row=='R50':require(int.from_bytes(sig[32:],'little')==L,'Ed25519 S=L witness')
    elif row in ('R51','R52','R53','R55','R108'):
        if row in ('R51','R52','R53'):
            require(ordinary_ed_equation(k,sig,preimage(body,'registration/1')),'weak-key witness must satisfy ordinary equation')
        point=decode_ed_point(sig[:32] if row in ('R55','R108') else k)
        require(point is not None,'weak/mixed point must decode canonically')
        if row=='R51':require(is_identity(point),'identity witness')
        elif row in ('R52','R55'):require(not is_identity(point) and is_identity(multiply(point,8)),'nonidentity small-order witness')
        else:require(not is_identity(multiply(point,8)) and not is_identity(multiply(point,L)) and is_identity(multiply(point,8*L)),'mixed-order witness')
    elif row in ('R54','R107'):
        require(decode_ed_point(sig[:32] if row=='R107' else k) is None,'noncanonical-point witness')
    elif row=='R56':
        require(strict_ed_point(k) and strict_ed_point(sig[:32]) and int.from_bytes(sig[32:],'little')<L,'canonical Ed25519 equation witness')
        require(signature_verdict(body['key'],sig,preimage(body,'registration/1'),'invalid')=='invalid','bad Ed25519 equation witness')
    elif row=='R109':require(prefix=='p256' and k==bytes([0]),'SEC1 infinity witness')

OBSERVATIONS={'ids':0,'signatures':0}

def verify_envelopes(vector):
    # Independently check derivable hashes/equations even when an earlier gate wins.
    # Malformed CCJ, absent/ill-shaped fields and missing public pins have no
    # normative hash or raw-signature verdict; their ordered rejection is checked separately.
    if vector['mode'].startswith('codec'):
        return
    row=vector['row'];f=vector['fixture'];rg=f['registry']
    entries=[]
    domain=vector['domain']
    key=rg['publisher_key'] if domain=='enrollment/1' else None
    entries.append(('input',b64(vector['input']['bytes_base64']),domain,key,True))
    for group_name,current in (('files',True),('previous_files',False)):
        for item in rg[group_name]:
            pub=rg['publisher_key'] if current else rg.get('previous_publisher_key',rg['publisher_key'])
            entries.append((item['path'],b64(item['bytes_base64']),'enrollment/1',pub,vector['mode']=='registry' and current))
    for item in vector.get('before',[])+vector.get('after',[]):
        if item['event']=='request':
            entries.append(('trace',b64(item['bytes_base64']),'registration/1',None,False))
    if 'scheduled_registry' in f:
        for item in f['scheduled_registry']['files']:
            entries.append(('scheduled',b64(item['bytes_base64']),'enrollment/1',f['scheduled_registry']['publisher_key'],False))
    for path,raw,domain,key,defect in entries:
        try:
            env=parse(raw)
        except Rejected:
            continue
        if not isinstance(env,dict) or not isinstance(env.get('body'),dict):
            continue
        body=env['body']
        if isinstance(env.get('id'),str) and re.fullmatch(r'sha256:[0-9a-f]{64}',env['id']):
            mismatch=defect and row in ('R32','R101','R106','E32')
            require((env['id']!=derived_id(body,domain))==mismatch,'independent envelope-id witness')
            OBSERVATIONS['ids']+=1
        try:
            signature=b64(env.get('sig'))
            require(len(signature)==64)
            if domain=='registration/1':
                key=body.get('key')
                key_parts(key)
            else:
                require(key is not None)
                key_parts(key)
        except Rejected:
            continue
        wanted='accept'
        invalid_rows={'R33','R34','R35','R38','R39','R40','R41','R42','R43','R44','R45','R46','R49','R50','R51','R52','R53','R54','R55','R56','R101','R107','R108','R109','R121','E33','E34','E35','E87'}
        if defect and row in invalid_rows:
            wanted='invalid'
        if defect and row in ('R47','R102'):
            wanted='signature_high_s'
        if defect and ((row=='E107' and path=='enrollments/a.json') or (row=='E108' and path=='enrollments/z.json') or (row=='E107' and path=='input')):
            wanted='invalid'
        actual=signature_verdict(key,signature,preimage(body,domain),'invalid')
        require(actual==wanted,f'independent signature witness: {row}/{path}: {actual} != {wanted}')
        OBSERVATIONS['signatures']+=1

def verify(vector,seeds):
    mode=vector['mode'];f=vector['fixture'];raw=b64(vector['input']['bytes_base64']);expected=vector['expected']
    verify_witness(vector)
    verify_envelopes(vector)
    if mode in ('codec','codec-extract'):
        value=parse(raw)
        if mode=='codec-extract':value=value['body']
        require(expected['code']=='accept' and b64(expected['canonical_bytes_base64'])==ccj(value),'CCJ canonical bytes disagreement')
        return
    if mode=='registry':
        code,_=registry_verdict(f)
        require(expected['code']==code,f'loader disagreement: computed {code}, stored {expected["code"]}')
        require(raw==file_entries(f['registry'])[0][2],'primary input differs from first snapshot entry')
        state={'authority_installed':code=='accept','prior_authority_preserved':code!='accept','admission_ready':code=='accept',
               'nonce_cache':f['nonce_cache'],'limiter_events':f['limiter_events'],'audit_outcomes':[],
               'authority':authority(f['registry'],code!='accept')}
        require(expected['state']==state,'registry failure/installation state disagreement')
        return
    require(mode=='admission','unknown vector mode')
    model=Admission(f,bytes.fromhex(seeds['registrar_jwt']))
    for item in vector['before']:model.transition(item)
    code,jwt=model.request(raw,f['now'],main=True)
    compare_outcome(expected,code,jwt)
    for item in vector['after']:model.transition(item)
    require(expected['state']==model.state(),'admission final-state disagreement')
    if 'audit_line_base64' in expected:
        line=b64(expected['audit_line_base64'])
        require(line.endswith(b'\n') and ccj(parse(line)) + b'\n'==line,'audit CCJ/LF')
        require(hashlib.sha256(line).hexdigest()==expected['audit_line_sha256'],'audit hash')
        audit=parse(line)
        fields={'v','seq','at','instance','jti','key_id','host','name','outcome','code','http_status','registry_revision','jwt_iat','jwt_exp','request_bytes','prev_hash'}
        require(set(audit)==fields and audit['v']==1 and audit['seq']==1,'audit fields')
        require(audit['outcome']=='issued' and audit['code']=='issued' and audit['http_status']==200,'audit outcome')
        require(audit['jti']==jwt['claims']['jti'] and audit['jwt_iat']==f['now'] and audit['jwt_exp']==f['now']+120,'audit JWT correlation')
        require(audit['request_bytes']==len(raw) and audit['prev_hash']=='0'*64,'audit byte count/chain')
        require(len(b64(audit['instance']))==16 and timestamp(audit['at'])==f['now'],'audit instance/time')
        env=parse(raw);require(audit['key_id']=='sha256:'+hashlib.sha256(env['body']['key'].encode()).hexdigest(),'audit key fingerprint')
        require(audit['host']=='host-a' and audit['name']==jwt['claims']['sub'] and audit['registry_revision']==f['registry']['revision'],'audit authority fields')


def verify_test_keys(root,seeds):
    # Fixed published material only: no file can silently substitute an operational seed.
    known={
        'host_ed25519':'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
        'enrollment_publisher':'4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
        'registrar_jwt':'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
        'host_p256':'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721'}
    require(all(seeds.get(k)==v for k,v in known.items()),'unpublished test seed')
    manifest=parse((root/'keys/public-keys.json').read_bytes())
    require(manifest['test_only'] is True and manifest['derived_from']=='host_ed25519','key manifest provenance')
    expected={}
    for name,value in known.items():
        if name=='host_p256':
            key=ec.derive_private_key(int(value,16),ec.SECP256R1()).public_key()
            expected[name]='p256:'+enc(key.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.CompressedPoint))
        else:
            key=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value)).public_key()
            expected[name]='ed25519:'+enc(key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    require(manifest['primary_public_keys']==expected,'primary test key derivation')
    labels=set()
    for item in manifest['derivations']:
        require(item['label'] not in labels,'duplicate key label')
        labels.add(item['label'])
        seed=hashlib.sha256(bytes.fromhex(seeds['host_ed25519'])+item['label'].encode('ascii')).digest()
        public=ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        require(item['seed_hex']==seed.hex() and item['public_key']=='ed25519:'+enc(public),'derived public test key')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--vectors',type=Path,default=Path('vectors'))
    args=parser.parse_args()
    seeds=json.loads((args.vectors/'keys/seeds.json').read_text())
    verify_test_keys(args.vectors,seeds)
    require(seeds['test_only'] is True,'test-key label')
    table=Path('spec/registrar.md').read_text().split('## Appendix B.',1)[1].split('### B.1',1)[0]
    plan={}
    for line in table.splitlines():
        columns=[v.strip() for v in line.split('|')[1:-1]]
        if len(columns)==6 and columns[1] in ('registration/1','enrollment/1'):
            plan[columns[0]]=columns
    found={}
    loaded_paths=set()
    counts={}
    for domain in ('registration-1','enrollment-1'):
        for group in ('0-negative','1-positive'):
            files=sorted((args.vectors/domain/group).glob('*.json'))
            counts[(domain,group)]=len(files)
            for path in files:
                loaded_paths.add(path)
                v=parse(path.read_bytes());row=v['row']
                require(row not in found and path.stem==row and row in plan,'row id/inventory')
                found[row]=str(path)
                p=plan[row]
                require(v['domain']==p[1] and v['positive_control']==p[5],'domain/control mismatch')
                require((group=='1-positive')==row.startswith('P'),'negative-first grouping')
                require(v['positive_control'] in plan and v['positive_control'].startswith('P'),'unresolved positive control')
                try:
                    verify(v,seeds)
                    planned_code=p[4].split(';',1)[0].strip()
                    if planned_code.startswith('accept'):planned_code='accept'
                    require(v['expected']['code']==planned_code,'normative plan outcome mismatch')
                except (Rejected,KeyError,TypeError,ValueError,InvalidSignature) as exc:
                    raise Rejected(f'{row}: {exc}') from exc
    require(set(found)==set(plan),'missing/extra planned rows')
    all_paths={p for domain in ('registration-1','enrollment-1') for p in (args.vectors/domain).rglob('*.json')}
    require(loaded_paths==all_paths,'unexpected vector JSON path')
    require({p.name for p in (args.vectors/'keys').glob('*.json')}=={'seeds.json','public-keys.json'},'unexpected test-key JSON file')
    for domain in ('registration-1','enrollment-1'):
        print(f'{domain}: {counts[domain,"0-negative"]} negative / {counts[domain,"1-positive"]} positive')
    print(f'PASS: {len(found)} independently checked vectors, exact outcomes, deterministic JWTs and state oracles')
    print(f'Envelope observations: {OBSERVATIONS["ids"]} derivable ids; {OBSERVATIONS["signatures"]} raw signature verdicts')
    print('LIMIT: external trust, clock-health and sink results are fixture inputs; no live service or deployment qualification')

if __name__=='__main__':
    try:
        main()
    except (Rejected,KeyError,TypeError,ValueError,InvalidSignature) as exc:
        print('FAIL:',exc,file=sys.stderr)
        sys.exit(1)
