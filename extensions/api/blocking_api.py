import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import numpy as np

from extensions.api.safe_transfer import decrypt_message, encrypt_server_side
from extensions.api.util import build_parameters, try_start_cloudflared
from modules import shared
from modules.chat import generate_chat_reply
from modules.LoRA import add_lora_to_model
from modules.logging_colors import logger
from modules.models import load_model, unload_model
from modules.models_settings import get_model_metadata, update_model_parameters
from modules.text_generation import (
    encode,
    generate_reply,
    stop_everything_event
)
from modules.utils import get_available_models


def get_model_info():
    return {
        'model_name': shared.model_name,
        'lora_names': shared.lora_names,
        # dump
        'shared.settings': shared.settings,
        'shared.args': vars(shared.args),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        return

    def send_OK_json_response(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def send_internal_failure_json_response(self):
        self.send_response(500)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = decrypt_message(self.rfile.read(content_length).decode('utf-8'))
        if body is None:
            return

        if self.path == '/api/v1/generate':
            # No model
            if shared.model_name == 'None' or shared.model is None:
                self.send_internal_failure_json_response()

                response = json.dumps(encrypt_server_side({
                    'error': 'No model is loaded!'
                }))

                self.wfile.write(response.encode('utf-8'))
                return

            self.send_OK_json_response()

            prompt = body['prompt']
            generate_params = build_parameters(body)
            stopping_strings = generate_params.pop('stopping_strings')
            generate_params['stream'] = False

            generator = generate_reply(
                prompt, generate_params, stopping_strings=stopping_strings, is_chat=False)

            answer = ''
            for a in generator:
                answer = a

            response = json.dumps(encrypt_server_side({
                'results': [{
                    'text': answer
                }]
            }))


            self.wfile.write(response.encode('utf-8'))

        elif self.path == '/api/v1/chat':
            self.send_OK_json_response()

            user_input = body['user_input']
            regenerate = body.get('regenerate', False)
            _continue = body.get('_continue', False)

            generate_params = build_parameters(body, chat=True)
            generate_params['stream'] = False

            generator = generate_chat_reply(
                user_input, generate_params, regenerate=regenerate, _continue=_continue, loading_message=False)

            answer = generate_params['history']
            for a in generator:
                answer = a

            response = json.dumps(encrypt_server_side({
                'results': [{
                    'history': answer
                }]
            }))

            self.wfile.write(response.encode('utf-8'))

        elif self.path == '/api/v1/stop-stream':
            self.send_OK_json_response()

            stop_everything_event()

            response = json.dumps(encrypt_server_side({
                'results': 'success'
            }))

            self.wfile.write(response.encode('utf-8'))

        elif self.path == '/api/v1/model':
            self.send_OK_json_response()

            # Actions: info, load, list, unload
            action = body.get('action', 'info')

            if action == 'load':
                model_name = body['model_name']
                args = body.get('args', {})

                shared.model_name = model_name
                unload_model()

                model_settings = get_model_metadata(shared.model_name)
                shared.settings.update({k: v for k, v in model_settings.items() if k in shared.settings})
                update_model_parameters(model_settings, initial=True)

                for k in args:
                    setattr(shared.args, k, args[k])

                if shared.settings['mode'] != 'instruct':
                    shared.settings['instruction_template'] = None

                try:
                    shared.model, shared.tokenizer = load_model(shared.model_name)
                    if shared.args.lora:
                        add_lora_to_model(shared.args.lora)  # list

                except Exception as e:
                    response = json.dumps(encrypt_server_side({'error': {'message': repr(e)}}))

                    self.wfile.write(response.encode('utf-8'))
                    raise e

                shared.args.model = shared.model_name

                result = get_model_info()

            elif action == 'unload':
                unload_model()
                shared.model_name = None
                shared.args.model = None
                result = get_model_info()

            elif action == 'list':
                result = get_available_models()

            elif action == 'info':
                result = get_model_info()
            else:
                return

            response = json.dumps(encrypt_server_side({
                'result': result,
            }))

            self.wfile.write(response.encode('utf-8'))

        elif self.path == '/api/v1/token-count':
            self.send_OK_json_response()

            tokens = encode(body['prompt'])[0]
            response = json.dumps(encrypt_server_side({
                'results': [{
                    'tokens': len(tokens)
                }]
            }))

            self.wfile.write(response.encode('utf-8'))
        elif self.path == '/api/v1/tokenize':
            self.send_OK_json_response()

            tokens: np.ndarray = encode(body['prompt'])[0]

            response = json.dumps(encrypt_server_side({
                'results': [{
                    'tokens': tokens.tolist(),
                    'shape': list(tokens.shape)
                }]
            }))

            self.wfile.write(response.encode('utf-8'))
        else:
            # No error send, to stop probing attacks
            return

    def do_OPTIONS(self):
        return

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()


def _run_server(port: int, share: bool = False, tunnel_id=str):
    address = '0.0.0.0' if shared.args.listen else '127.0.0.1'

    server = ThreadingHTTPServer((address, port), Handler)

    def on_start(public_url: str):
        print(f'Starting non-streaming server at public url {public_url}/api')

    if share:
        try:
            try_start_cloudflared(port, tunnel_id, max_attempts=3, on_start=on_start)
        except Exception:
            pass
    else:
        print(
            f'Starting API at http://{address}:{port}/api')

    server.serve_forever()


def start_server(port: int, share: bool = False, tunnel_id=str):
    Thread(target=_run_server, args=[port, share, tunnel_id], daemon=True).start()
