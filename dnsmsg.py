# Naive simple DNS messenger example
# using dnskv.com dns key value storage
from os import urandom, popen, mkdir as os_mkdir, \
  name as os_name, path, listdir, remove as os_remove
from hashlib import blake2b
from time import sleep, strftime, time
import json
import argparse
from zlib import compress, decompress
try:
  import dns.resolver as lib_dns_resolver
except ModuleNotFoundError:
  lib_dns_resolver = None

global args
args = None

ID_LEN = 16
UPDATE_LEN = 10
FILENAME_LEN = 8
BLOCK_LEN = 40
MAX_MSG_LEN = 4096
MESSAGE_INTERVAL = 0.1
DEFAULT_CHECK_INTERVAL = 60 * 60
DOMAIN = 'dnskv.com'
STATE_MAX_AGE = 60 * 60 * 7
STATE_DIR = 'state'

def base36_dumps(input):
  symbols = '0123456789abcdefghijklmnopqrstuvwxyz'
  output = []
  while input != 0:
    input, index = divmod(input, 36)
    output.append(symbols[index])
  output.reverse()
  return ''.join(output) or '0'

def base36_loads(value):
  return int(value, 36)

def int_to_bytes(input, length=0):
  output = bytearray()
  while input != 0:
    input, value = divmod(input, 256)
    output.append(value)
  output += b'\0' * (length- len(output))
  output.reverse()
  return bytes(output) or b'\0'

def bytes_to_int(input):
  value = 0
  for index, char in enumerate(input):
    value = value * 256 + char
  return value

def hash(data, key, salt=b'dnsmsg'):
  return blake2b(data, key=key, salt=salt).digest()

def bytes_to_b36(data):
  return base36_dumps(bytes_to_int(data))

def b36_to_bytes(data, length=BLOCK_LEN):
  return int_to_bytes(base36_loads(data), length)

def xor(a, b):
  output = bytearray(len(a))
  for index, char in enumerate(a):
    output[index] = char ^ b[index]
  return output

def block_id_key(msg_key, seq):
  b_seq = seq.to_bytes(1, 'big')
  block_id = hash(msg_key, b'id', b_seq)[:ID_LEN]
  block_key = hash(msg_key, b'key', b_seq)
  return block_id, block_key

def encode_message(message, channel_key, prev_message=''):
  if prev_message:
    message += prev_message + b'\1'
  else:
    message += b'\0'
  message = compress(message)
  message = len(message).to_bytes(2, 'big') + message
  output = []
  msg_key = hash(urandom(64) + channel_key, urandom(64), b'dnsmsg_msgkey')[:BLOCK_LEN]
  for seq, pos in enumerate(range(0, len(message) + 1, BLOCK_LEN)):
    block = message[pos: pos + BLOCK_LEN]
    block_id, block_key = block_id_key(msg_key, seq)
    if len(block) < BLOCK_LEN:
      block = block + b'\xff' * (BLOCK_LEN - len(block))
    dns_lookup(bytes_to_b36(block_id), bytes_to_b36(xor(block, block_key)))
  return bytes_to_b36(xor(msg_key, channel_key))

def decode_message(channel_key, msg_key):
  output = []
  msg_key = xor(msg_key, channel_key)
  seq, message_len = 0, 2**32
  while message_len + 2 > (seq * BLOCK_LEN):
    block_id, block_key = block_id_key(msg_key, seq)
    block = dns_lookup(bytes_to_b36(block_id))
    if not block:
      break
    output.append(xor(b36_to_bytes(block), block_key))
    if not seq:
      message_len = int.from_bytes(b''.join(output)[:2], 'big')
    seq += 1
  if not output:
    return b'', b''
  message = b''.join(output)[2:][:message_len]
  message = decompress(message)
  if message[-1]:
    prev_message = message[-BLOCK_LEN - 1:-1]
    message = message[:-BLOCK_LEN - 1]
  else:
    prev_message = b''
    message = message[:-1]
  return message, prev_message

def channel_id_key(channel):
  return bytes_to_b36(hash(channel.encode('utf-8'), b'dnsmsg_channel_id')[:ID_LEN]), hash(channel.encode('utf-8'), b'dnsmsg_channel_key')

def encode_update_key(channel, update_key):
  return bytes_to_b36(hash(channel.encode('utf-8'), (hash(update_key.encode('utf-8'), b'dnsmsg_update')))[:UPDATE_LEN])

dns_dict = {}

def dns(name):

  def dns_resolver(name):
    try:
      r = lib_dns_resolver.resolve(name, 'TXT')
    except Exception as e:
      exception_type = str(type(e))
      if 'NoAnswer' in exception_type or 'NXDOMAIN' in exception_type:
        return
      return str(e)
    if r:
      for i in r:
        if hasattr(i, 'data'):
          r = (str(i.data[1:])[2:-1],)
          break
      return str(r[0]).strip('"')

  def resolve_dnsname(name):
    resolve_json = (popen(f'PowerShell -c "Resolve-DnsName -Name {name} -Type TXT | ConvertTo-JSON"')).read()
    if ': DNS name does not exist' in resolve_json:
      return
    try:
      resolved = json.loads(resolve_json)
    except json.decoder.JSONDecodeError as e:
      raise ValueError(f'Powershell / Resolve-DnsName issue: {e}')
    for i in resolved:
      if 'Text' in i:
        return(''.join(i['Text']))

  def dig(name):
    q = f'dig +short txt {name} @ns.dnskv.com' # FIX ME!
    res = popen(q).read().strip('"\n')
    return res

  status(f'DNS REQUEST : {name}', True)
  if lib_dns_resolver:
    res = dns_resolver(name)
  elif os_name == 'nt':
    res = resolve_dnsname(name)
  elif os_name == 'posix':
    res = dig(name)
  else:
    status('No known DNS resolution solution. No dns.resolver (pip install dnsresolver) me. System OS:', os_name)
    raise ValueError('Unknown system name / platform identifier')
  status(f'DNS RESPONSE: {res}', True)
  return res

def dns_lookup(key, value=None, opt=None):
  internal_dictionary = False
  if internal_dictionary:
    if value:
      dns_dict[key] = value
    else:
      return dns_dict.get(key, '')
  else:
    name = []
    if opt:
      name.append(opt)
    if value:
      name.append(value)
    if not key:
      raise ValueError()
    name.append(key)
    name.append(args.domain)
    name = '.'.join(name)
    res = dns(name)
    if value and res != "ok":
      raise ValueError(f"DNS query didn't return expected response: {res}")
    sleep(MESSAGE_INTERVAL)
    return res

def status(msg, verbose_only=False):
  if args.quiet or verbose_only and not args.verbose: return
  print(f'*** {msg} ***')

def mkdir(directory):
  try:
    os_mkdir(STATE_DIR)
  except FileExistsError:
    pass

def state_store_cleanup():
  state_files = listdir(STATE_DIR)
  for fn in state_files:
    fn = path.join(STATE_DIR, fn)
    if path.getmtime(fn) + STATE_MAX_AGE < time() :
      os_remove(fn)

def state_store(channel, message_key=None):
  if args.nostate:
    return
  mkdir(STATE_DIR)
  state_filename = path.join(STATE_DIR, channel)
  try:
    state = open(path.join(state_filename), 'r').readline()
    if not message_key:
      status(f'Restored state: {state}', True)
  except FileNotFoundError:
    state = b''
  if message_key and message_key != state:
    open(state_filename, 'w').write(message_key)
    status(f'Stored state: {message_key}', True)
  return state

def send_message(channel, message, update_key, expire, ttl):
  channel_id, channel_key = channel_id_key(channel + '@' + args.domain)
  perv_message = state_store(channel)
  if update_key and args.nostate and not perv_message:
    perv_message = dns_lookup(channel_id)
  if perv_message:
    perv_message = b36_to_bytes(perv_message)
  msg_key = encode_message(message, channel_key, perv_message)
  opt = []
  if expire:
    opt.append(f'e{expire}h')
  if ttl:
    opt.append(f't{ttl}m')
  opt_str = '-'.join(opt)
  if update_key:
    opt.append('u' + encode_update_key(channel_id, update_key))
  dns_lookup(channel_id, msg_key, '-'.join(opt))
  status(f'Message successfully sent to {channel}')
  state_store(channel, msg_key)

def get_messages(channel, binary):
  messages = []
  channel_id, channel_key = channel_id_key(channel + '@' + args.domain)
  last_received_message = state_store(channel)
  if last_received_message:
    last_received_message = b36_to_bytes(last_received_message)
  last_message = dns_lookup(channel_id)
  if last_message:
    last_message = b36_to_bytes(last_message)
  else:
    status(f'Channel {channel} not found / active')
    return
  prev_message = last_message
  while prev_message and prev_message != last_received_message:
    message, prev_message = decode_message(channel_key, prev_message)
    if message:
      messages.insert(0, message)
    if not binary:
      try:
        print(message.decode())
      except UnicodeDecodeError:
        print(message)
        status('Binary? Save to file using -b -f ')
    else:
      status(f'{len(messages)} binary messages retrieved')
  if prev_message == last_received_message:
    status(f'Channel: {channel} All messages successfully retrieved')
  state_store(channel, bytes_to_b36(last_message))
  return messages

def save_messages(channel, messages):
  if not args.binary:
    f = open(args.file, 'ba')
    for m in messages:
      f.write(m + b'\n-----\n')
    f.close()
  else:
    for m in messages:
      for retry in range(10):
        try:
          f = open(f'{args.file}_{channel}_{bytes_to_b36(urandom(FILENAME_LEN))}', 'xb')
          f.write(m)
          f.close()
          break
        except FileExistsError:
          pass

def read_channels(fn):
  channels = []
  for c in open(fn, 'r').readlines():
    for i in c.split(','):
      if i:=i.strip():
        channels.append(i)
  return channels

def send():
  if args.message:
    args.message = args.message.encode('utf-8')
  if args.file:
    args.message = open(args.file, 'rb').read(MAX_MSG_LEN + 1)
  if len(args.message) > MAX_MSG_LEN:
    parser.error("message file or message too long max 4096 bytes")
  send_message(args.channel, args.message, args.key, args.expire, args.ttl)

def receive():
  if args.channels:
    channels = read_channels(args.channels)
    status(f"Channels {', '.join(channels)}")
  else:
    channels = args.channel.split(',')
  while True:
    for channel in channels:
      status(f'Checking {channel}')
      messages = get_messages(channel, args.binary)
      if args.file and messages:
        save_messages(channel, messages)
    if not args.receive:
      break
    else:
      status('Last check: ' + strftime('%T'))
      sleep(args.ttl * 60 if args.ttl else DEFAULT_CHECK_INTERVAL)

def main():
  parser = argparse.ArgumentParser(description='dnsmsg - DNS Messenger ')
  parser.add_argument('-v', '--verbose', action='count', help='verbose DNS lookups and results')
  parser.add_argument('-s', '--send', action='count', help='send message / file, to static channel')
  parser.add_argument('-r', '--receive', action='count', help='receive continuously, checks new messages hourly')
  parser.add_argument('-b', '--binary', action='count', help='binary mode, only one message per output file')
  parser.add_argument('-n', '--nostate', action='count', help='do not create state file, use DNS only')
  parser.add_argument('-q', '--quiet', action='count', help='no other output than message(s)')
  parser.add_argument('-e', '--expire', type=int, help='expire (hours), message expiry only')
  parser.add_argument('-t', '--ttl', type=int, help='channel TTL / check interval (minutes)')
  parser.add_argument('-k', '--key', type=str, help='update key to post messages to dynamic channel')
  parser.add_argument('-c', '--channels', type=str, help='filename for list of channel keys to use')
  parser.add_argument('-m', '--message', type=str, help='message to be sent')
  parser.add_argument('-f', '--file', type=str, help='message file name path / prefix (for binary files)')
  parser.add_argument('-d', '--domain', type=str, help='use alternate domain', default=DOMAIN)
  parser.add_argument('channel', nargs='?', help='channel key, can be comma separated list')

  global args
  args = parser.parse_args()
  if not args.channel and not args.channels:
    parser.error("Channel is required use -h for help")
  if (args.file and args.message):
    parser.error("Can't combine file and message")
  if not (args.key or args.send) and args.message:
    parser.error("Please specify -s static or dynamic channel using -k key")
  if args.key or args.send:
    send()
  else:
    if args.nostate and args.receive:
      parser.error("Can't combine nostate with receive")
    receive()
  state_store_cleanup()

if __name__ == '__main__':
  main()
