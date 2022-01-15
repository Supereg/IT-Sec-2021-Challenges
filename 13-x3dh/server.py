import asyncio
import collections
import json
import random
import re
import secrets
import solution # No need to duplicate the implementation, just use the correct solution!
import subprocess
import sys
import typing

random = random.SystemRandom()

TAMPER_PROBABILITY = 0.1
SOLUTION_CLIENT = 'Alice'
FAILED_TO_VALIDATE = re.compile('(Incoming|Outgoing) message (\d+) failed to validate')
VERBOSE = '--verbose' in sys.argv[1:]

verbose = print if VERBOSE else (lambda *args, **kwargs: None)


# Networking API to make things a little cleaner
async def send(writer, message):
    writer.write(message.encode() + b'\n')
    await writer.drain()

async def receive(reader):
    return (await reader.readline()).decode()

async def send_obj(writer, obj):
    await send(writer, json.dumps(obj))

async def receive_obj(reader):
    return json.loads(await receive(reader))


# Simulated users
class simulated_user_api(solution.server_api):
    '''Acts just like the server_api you use, but without networking'''
    def __init__(self, name: str, handler: typing.Any):
        super().__init__(None)
        self._name = name
        self._handler = handler

    def _request(self, operation: str, args: typing.Any) -> str:
        ok, response = self._handler(operation, args)
        assert ok, f'Simulated client did something wrong: {response}'
        return response.strip() if isinstance(response, str) else json.dumps(response)


# Tampering functions
def tamper_key(ik, spk, sig, otk):
    return ik, secrets.token_hex(len(spk) // 2), secrets.token_hex(len(sig) // 2), otk

def tamper_message(message):
    tampers = {
        'ik':    lambda message: message | {'ik': secrets.token_hex(len(message['ik']) // 2)},
        'ek':    lambda message: message | {'ek': secrets.token_hex(len(message['ek']) // 2)},
        'nonce': lambda message: message | {'nonce': secrets.token_hex(len(message['nonce']) // 2)},
        'ct':    lambda message: message | {'ct': secrets.token_hex(len(message['ct']) // 2)},
        'tag':   lambda message: message | {'tag': secrets.token_hex(len(message['tag']) // 2)},
    }
    return tampers[random.choice(list(tampers))](message)


# Handle client requests
async def handle_request(reader, writer):
    client_addr = '{}:{}'.format(*writer.get_extra_info('peername'))
    print(f'{client_addr}: Connected')
    # Storage for this connection
    keys = {}
    messages = collections.defaultdict(list)
    known_eks = collections.defaultdict(set)
    keys_tampered = collections.defaultdict(bool)
    message_tampered = collections.defaultdict(bool)
    def handler(op, args, client_name=SOLUTION_CLIENT, tamper_probability=TAMPER_PROBABILITY, once=False):
        nonlocal keys, messages, known_eks, keys_tampered, message_tampered
        if op != 'incoming' or messages[client_name] or client_name == SOLUTION_CLIENT:
            # Don't log "incoming" requests from simulated users or admin if no messages are there to fetch
            verbose(f'{client_addr}: Handling "{op}" from {"simulated user" if once else "user"} "{client_name}"')
        if op == 'publish':
            if not isinstance(args.get('name'), str) or \
               not isinstance(args.get('ik'), str) or \
               not isinstance(args.get('spk'), str) or \
               not isinstance(args.get('sig'), str) or \
               not isinstance(args.get('otks'), list) or \
               any(not isinstance(e, str) for e in args['otks']):
                return False, 'Your keys are not in the correct format!'
            if len(args['otks']) != len(set(args['otks'])):
                return False, 'Your OTKs are not distinct!'
            if not once and len(args['otks']) < solution.NUM_OTKS:
                # This requirement is bypassed for use-only-once users
                return False, f'You should publish at least {solution.NUM_OTKS} OTKs'
            elif once:
                # Use this user only once, so only one OTK!
                args['otks'] = [args['otks'][0]]
            if args.get('name') != client_name:
                # Your client will always be 'Alice'...
                return False, f'Your name isn\'t {args["name"]}!'
            if args['name'] in keys:
                return False, 'You already published your keys!'
            keys[args['name']] = args
            return True, 'OK'
        elif op == 'keys':
            if not isinstance(args, str):
                return False, 'Invalid key request'
            if args not in keys:
                return False, 'No such user'
            usable_otks = [(index, otk) for index, otk in enumerate(keys[args]['otks']) if otk]
            if not usable_otks:
                return False, 'No OTKs left for that user - did you query their keys too often?'
            ik = keys[args]['ik']
            spk = keys[args]['spk']
            sig = keys[args]['sig']
            bundle_index, otk = random.choice(usable_otks)
            if random.random() < tamper_probability and args not in {'admin', client_name}: # Don't tamper with admin or your own keys
                print(f'{client_addr}: Tampering with keys')
                keys_tampered[args] = True
                ik, spk, sig, otk = tamper_key(ik, spk, sig, otk)
            else:
                keys_tampered[args] = False
            keys[args]['otks'][bundle_index] = None # OTK used
            return True, { 'ik': ik, 'spk': spk, 'otk': otk, 'sig': sig, 'bundle': bundle_index }
        elif op == 'incoming':
            if client_name not in messages or not messages[client_name]:
                return False, 'No message for you'
            msg = messages[client_name].pop(0)
            if random.random() < tamper_probability and msg['may_tamper']: # Only tamper with messages from once-only users
                print(f'{client_addr}: Tampering with message from "{msg["from"]}"')
                message_tampered[msg['from']] = True
                msg = tamper_message(msg)
            else:
                message_tampered[msg['from']] = False
            del msg['may_tamper'], msg['from'] # Drop things that were only added internally
            return True, msg
        elif op == 'message':
            if not isinstance(args.get('user'), str) or \
               not isinstance(args.get('ik'), str) or \
               not isinstance(args.get('ek'), str) or \
               not isinstance(args.get('bundle'), int) or \
               not isinstance(args.get('nonce'), str) or \
               not isinstance(args.get('ct'), str) or \
               not isinstance(args.get('tag'), str):
                return False, 'Invalid message'
            if args['user'] not in keys:
                return False, 'Unknown user'
            if client_name not in keys:
                return False, 'Unknown sender'
            if args['ik'] != keys[client_name]['ik']:
                return False, 'Mismatched IK'
            if args['ek'] in known_eks[client_name]:
                return False, 'Reuse of EK is not permitted'
            known_eks[client_name].add(args['ek'])
            args['may_tamper'] = once # Only tamper with messages that are not from Alice or the admin
            args['from'] = client_name
            messages[args['user']].append(args)
            return True, 'OK'

    # Create simulated users (NUM_OTKS - 1, since we need to keep one for the flag)
    print(f'{client_addr}: Creating users')
    users = {
        name: simulated_user_api(
                  name,
                  lambda op, args, name=name: handler(op, args, name, -1, name != 'admin')
              ) for name in (['admin'] + [secrets.token_hex(12) for _ in range(solution.NUM_OTKS - 1)])
    }

    # First, create and publish keys for all users
    for name, api in users.items():
        solution.publish_keys(api)

    # Test the user implementation
    more_challenges = True
    expected_user, expected_secret = 'admin', 'Let\'s go!'
    prev_expected_user = None
    used_users = {'admin'}
    try:
        print(f'{client_addr}: Beginning challenges')
        while True:
            request = await receive_obj(reader)
            op, args = request['op'], request['args']
            ok, result = handler(op, args)
            # Process all pending messages for inbound users
            for name, user in users.items():
                if sum(len(queue) for queue in messages.values()) > 1:
                    ok, result = False, 'Too many pending messages!'
                    break

                def send_next():
                    nonlocal prev_expected_user, expected_user, expected_secret, used_users, user
                    prev_expected_user = expected_user
                    if len(users) == len(used_users):
                        # No new secret, send flag
                        print(f'{client_addr}: Sending flag')
                        expected_user = expected_secret = None
                        flag = subprocess.check_output("/bin/flag").decode().strip()
                        solution.send_message_to(users['admin'], SOLUTION_CLIENT, f'flag:{flag}')
                        return False
                    else:
                        expected_user = random.choice(list(users.keys() - used_users))
                        expected_secret = secrets.token_hex(32)
                        used_users.add(expected_user)
                        solution.send_message_to(user, SOLUTION_CLIENT, f'{expected_user}:{expected_secret}')
                        return True

                try:
                    # ValidationError bails out above!
                    message = solution.receive_message(user)
                    print(f'{client_addr}: Message "{message}" for user "{name}"')
                    if name == expected_user and message == expected_secret:
                        # New message from client with correct secret, or start message.
                        # Create a new message, and answer from that user.
                        if message_tampered[prev_expected_user] or keys_tampered[expected_user]:
                            # Shouldn't have been able to get this message!
                            ok, result = False, 'Failed to detect tampered message or keys'
                            break
                        more_challenges = send_next()
                    elif name == 'admin' and (m := FAILED_TO_VALIDATE.match(message)):
                        # We tampered with a message from/to the expected user
                        if not message_tampered[prev_expected_user] and not keys_tampered[expected_user]:
                            ok, result = False, 'Client incorrectly claimed tampering'
                            break
                        elif m.group(1) == 'Incoming' and not message_tampered[prev_expected_user]:
                            ok, result = False, 'Message incorrectly rejected for message tampering'
                            break
                        elif m.group(1) == 'Outgoing' and not keys_tampered[expected_user]:
                            ok, result = False, 'Message incorrectly rejected for key tampering'
                            break
                        more_challenges = send_next()
                    else:
                        # Unexpected message
                        ok, result = False, 'Unexpected message'
                        break
                except AssertionError as err:
                    # Skip the error that occurs if no message is there
                    if err.args[0] != 'Simulated client did something wrong: No message for you':
                        raise
            await (send(writer, result) if isinstance(result, str) else send_obj(writer, result))
            if not ok:
                print(f'{client_addr}: Incorrect behavior ({result})')
                break # Terminating on error
            elif op == 'incoming' and not more_challenges:
                print(f'{client_addr}: Flag fetched')
                break # Flag was sent and fetched successfully
            else:
                verbose(f'{client_addr}: Handled ({result if isinstance(result, str) else "with result object"})')

    except solution.ValidationError:
        # Client sent malformed message!
        await send(writer, 'Malformed message (failed to validate)')
    except json.JSONDecodeError:
        await send(writer, 'Malformed message (not JSON)')
    except UnicodeDecodeError:
        await send(writer, 'Malformed message (not UTF-8)')
    writer.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_request, "0.0.0.0", 1024, loop=loop)
    server = loop.run_until_complete(coro)

    print("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Stopping server")
